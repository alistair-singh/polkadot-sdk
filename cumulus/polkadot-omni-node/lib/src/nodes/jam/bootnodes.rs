// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The bootnodes of other paras, read from JAM (`--jam-bootnodes-from`).
//!
//! A para running `pallet-bootnodes` publishes a [`BootnodeRecord`] to its JAM key-value store
//! under [`BOOTNODES_KEY`]. For every para this node exchanges messages with, it runs a client-mode
//! Kademlia instance on that para's DHT, seeded with the record's addresses, to find its peers.
//!
//! The reader follows JAM's finalized chain, so it never acts on a value that is later reverted.
//! It opens the instance when a record first appears, and a new one when a record names another
//! genesis hash or fork id. When the para clears its record, the reader closes the instance and
//! forgets the para's peers, the ones it found included: a para that withdraws its bootnodes
//! withdraws the way to reach it. Peers it banned stay banned. If the para publishes a record
//! again, the reader opens a new instance and starts over.
//!
//! The peers it finds are kept in an [`AddressRecord`], for the messaging layer to dial through
//! [`Peers`]: the record's bootnodes, and up to [`MAX_DISCOVERED_PEERS`] peers found on the DHT.
//! The messaging layer reports how each request went, and a peer that fails is removed.
//!
//! `pallet-bootnodes` checks what it publishes, and the record's genesis hash can only be checked
//! there. The reader still skips what it could not use, since the other para's runtime is not
//! ours: a record whose fork id [`pallet_bootnodes::is_valid_fork_id`] rejects, an address
//! [`pallet_bootnodes::multiaddr::validate`] rejects, and unless `--allow-private-ip` applies an
//! address with a non-global IP. An address a DHT reports for a peer must have the same shape,
//! the `/p2p/<peer id>` being optional but, if there, that peer's.

use super::LOG_TARGET;
use codec::DecodeAll;
use futures::{Stream, StreamExt};
use ip_network::IpNetwork;
use jam_interface::{JamChainSource, JamStateSource, ServiceId};
use pallet_bootnodes::{BootnodeRecord, ForkId, BOOTNODES_KEY};
use sc_network::{
	config::{ClientKademlia, Litep2pKademliaEvent, Litep2pKademliaHandle},
	multiaddr::Protocol,
	Multiaddr, PeerId,
};
use std::{
	collections::{HashSet, VecDeque},
	future::Future,
	sync::{Arc, Mutex, MutexGuard, PoisonError},
	time::Duration,
};

/// How often the reader asks a para's DHT for more of its peers.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// The most peers of a para found on its DHT that are kept. The record's bootnodes don't count.
const MAX_DISCOVERED_PEERS: usize = 20;

/// The most addresses kept for a peer: as many as a record may list.
const MAX_ADDRESSES_PER_PEER: usize = pallet_bootnodes::MAX_BOOTNODES as usize;

/// The most banned peers of a para remembered; the earliest banned is forgotten first.
const MAX_BANNED: usize = 1024;

/// Failures in a row after which a discovered peer is removed.
// TODO: open question; one failure may be too few.
const FAILURES_TO_REMOVE: u32 = 1;

/// The paras of `from` to follow, each once and without `own`, ours.
pub(crate) fn paras_to_follow(from: &[u32], own: u32) -> Vec<u32> {
	let mut paras = from.to_vec();
	paras.sort_unstable();
	paras.dedup();
	paras.retain(|&para_id| {
		if para_id == own {
			tracing::warn!(target: LOG_TARGET, para_id, "Not following the bootnodes of our own para.");
		}
		para_id != own
	});
	paras
}

/// How a request to one of a para's peers went, as the messaging layer reports it.
// The messaging layer that reports these does not exist yet; only the tests do.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
	/// The peer answered with data that passed the root check.
	Success,
	/// The peer was connected but the request failed.
	RequestFailed,
	/// The peer could not be dialled.
	DialFailed,
	/// The peer answered with data that failed the root check.
	Garbage,
}

/// A peer found on the DHT.
struct Discovered {
	peer_id: PeerId,
	addresses: Vec<Multiaddr>,
	/// Failed requests and dials since the last success.
	failures: u32,
}

/// Up to [`MAX_BANNED`] peers, forgetting the earliest banned first.
#[derive(Default)]
struct Banned {
	order: VecDeque<PeerId>,
	set: HashSet<PeerId>,
}

impl Banned {
	fn insert(&mut self, peer_id: PeerId) {
		if !self.set.insert(peer_id) {
			return;
		}
		self.order.push_back(peer_id);
		if self.order.len() > MAX_BANNED {
			if let Some(earliest) = self.order.pop_front() {
				self.set.remove(&earliest);
			}
		}
	}

	fn contains(&self, peer_id: &PeerId) -> bool {
		self.set.contains(peer_id)
	}
}

/// The peers of a para this node knows, each with its addresses: the bootnodes of the latest
/// record, and up to [`MAX_DISCOVERED_PEERS`] peers found on the para's DHT.
///
/// A peer found on the DHT only takes a free slot, and never pushes out another. It loses its slot
/// once it fails [`FAILURES_TO_REMOVE`] times in a row, and may come back if found again. One
/// that returns garbage is banned, unless the record lists it or listed it before the latest
/// clear.
struct AddressRecord {
	para_id: u32,
	allow_private_ip: bool,
	/// The bootnodes of the latest record, apart from the discovered peers.
	bootnodes: Vec<(PeerId, Vec<Multiaddr>)>,
	/// The bootnodes the latest clear forgot.
	cleared_bootnodes: HashSet<PeerId>,
	/// In the order they were found.
	discovered: Vec<Discovered>,
	banned: Banned,
}

impl AddressRecord {
	fn new(para_id: u32, allow_private_ip: bool) -> Self {
		Self {
			para_id,
			allow_private_ip,
			bootnodes: Vec::new(),
			cleared_bootnodes: HashSet::new(),
			discovered: Vec::new(),
			banned: Banned::default(),
		}
	}

	/// Replace the bootnodes with `seeds`, keeping the discovered peers. A discovered peer that is
	/// now a bootnode leaves its slot.
	fn set_bootnodes(&mut self, seeds: Vec<(PeerId, Multiaddr)>) {
		let mut bootnodes: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();
		for (peer_id, addr) in seeds {
			match bootnodes.iter_mut().find(|(known, _)| *known == peer_id) {
				Some((_, addresses)) => merge(addresses, [addr]),
				None => bootnodes.push((peer_id, vec![addr])),
			}
		}
		self.discovered
			.retain(|peer| !bootnodes.iter().any(|(bootnode, _)| *bootnode == peer.peer_id));
		self.bootnodes = bootnodes;
	}

	/// Forget the bootnodes and the discovered peers. The banned peers stay banned.
	fn clear(&mut self) {
		self.cleared_bootnodes = self.bootnodes.drain(..).map(|(peer_id, _)| peer_id).collect();
		self.discovered.clear();
	}

	/// Note `peer_id` found on the DHT at `addresses`. Of those, only the ones [`is_dialable`]
	/// accepts are kept. A known peer gets the new addresses; a new one with any is added if a slot
	/// is free and it is not banned. Returns whether it was added.
	fn discovered(
		&mut self,
		peer_id: PeerId,
		addresses: impl IntoIterator<Item = Multiaddr>,
	) -> bool {
		if self.banned.contains(&peer_id) || self.is_bootnode(&peer_id) {
			return false;
		}
		let allow_private_ip = self.allow_private_ip;
		let usable = addresses
			.into_iter()
			.filter(|addr| is_dialable(addr, &peer_id, allow_private_ip));
		if let Some(known) = self.discovered.iter_mut().find(|peer| peer.peer_id == peer_id) {
			merge(&mut known.addresses, usable);
			return false;
		}
		let mut addresses = Vec::new();
		merge(&mut addresses, usable);
		if addresses.is_empty() || self.is_full() {
			return false;
		}
		tracing::debug!(target: LOG_TARGET, para_id = self.para_id, %peer_id, "Discovered a peer of the para.");
		self.discovered.push(Discovered { peer_id, addresses, failures: 0 });
		true
	}

	/// Whether every slot for a discovered peer is taken.
	fn is_full(&self) -> bool {
		self.discovered.len() >= MAX_DISCOVERED_PEERS
	}

	/// Act on how a request to `peer_id` went.
	fn report(&mut self, peer_id: PeerId, outcome: Outcome) {
		let para_id = self.para_id;
		let Some(index) = self.discovered.iter().position(|peer| peer.peer_id == peer_id) else {
			if outcome == Outcome::Garbage {
				if self.is_bootnode(&peer_id) || self.cleared_bootnodes.contains(&peer_id) {
					// TODO: open question; governance listed the bootnode, so it is not banned.
					tracing::error!(target: LOG_TARGET, para_id, %peer_id, "A bootnode of the para returned data that fails the root check.");
				} else {
					// A peer that already left the record, e.g. after a failure, is banned too.
					tracing::error!(target: LOG_TARGET, para_id, %peer_id, "A former peer of the para returned data that fails the root check; banning it.");
					self.banned.insert(peer_id);
				}
			}
			// A bootnode stays until a record replaces or clears it.
			return;
		};
		match outcome {
			Outcome::Success => self.discovered[index].failures = 0,
			Outcome::RequestFailed | Outcome::DialFailed => {
				let peer = &mut self.discovered[index];
				peer.failures += 1;
				if peer.failures >= FAILURES_TO_REMOVE {
					tracing::debug!(target: LOG_TARGET, para_id, %peer_id, ?outcome, "Removing a peer of the para.");
					self.discovered.remove(index);
				}
			},
			Outcome::Garbage => {
				tracing::error!(target: LOG_TARGET, para_id, %peer_id, "A peer of the para returned data that fails the root check; banning it.");
				self.discovered.remove(index);
				self.banned.insert(peer_id);
			},
		}
	}

	/// The peers to dial, each with its addresses: the bootnodes first, then the discovered peers.
	fn peers(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
		let discovered = self.discovered.iter().map(|peer| (peer.peer_id, peer.addresses.clone()));
		self.bootnodes.iter().cloned().chain(discovered).collect()
	}

	fn is_bootnode(&self, peer_id: &PeerId) -> bool {
		self.bootnodes.iter().any(|(bootnode, _)| bootnode == peer_id)
	}
}

/// Add each of `new` to `addresses`, or move it to the end if `addresses` has it. Beyond
/// [`MAX_ADDRESSES_PER_PEER`], the address that has gone longest without being added again is
/// dropped.
fn merge(addresses: &mut Vec<Multiaddr>, new: impl IntoIterator<Item = Multiaddr>) {
	for addr in new {
		addresses.retain(|known| *known != addr);
		if addresses.len() >= MAX_ADDRESSES_PER_PEER {
			addresses.remove(0);
		}
		addresses.push(addr);
	}
}

/// A para's [`AddressRecord`], shared by the reader that fills it and the messaging layer that
/// dials its peers.
#[derive(Clone)]
pub(crate) struct Peers(Arc<Mutex<AddressRecord>>);

impl Peers {
	fn new(para_id: u32, allow_private_ip: bool) -> Self {
		Self(Arc::new(Mutex::new(AddressRecord::new(para_id, allow_private_ip))))
	}

	fn lock(&self) -> MutexGuard<'_, AddressRecord> {
		// The record is left consistent by every method, so one that panicked left it usable.
		self.0.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Report how a request to `peer_id` went.
	// The messaging layer that calls this does not exist yet; only the tests do.
	#[allow(dead_code)]
	pub(crate) fn report(&self, peer_id: PeerId, outcome: Outcome) {
		self.lock().report(peer_id, outcome)
	}

	/// The peers to dial, each with its addresses: the bootnodes first, then the discovered peers.
	// The messaging layer that calls this does not exist yet; only the tests do.
	#[allow(dead_code)]
	pub(crate) fn peers(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
		self.lock().peers()
	}
}

/// Opens client-mode Kademlia instances: [`ClientKademlia`], or a stand-in in the tests.
trait Join {
	/// Open an instance on the DHT of the chain with `genesis` and `fork_id`; `None` if it
	/// cannot be opened.
	fn join(
		&self,
		genesis: &[u8],
		fork_id: Option<&str>,
		allow_private_ip: bool,
	) -> impl Future<Output = Option<Litep2pKademliaHandle>> + Send;
}

impl Join for ClientKademlia {
	fn join(
		&self,
		genesis: &[u8],
		fork_id: Option<&str>,
		allow_private_ip: bool,
	) -> impl Future<Output = Option<Litep2pKademliaHandle>> + Send {
		self.open(genesis, fork_id, allow_private_ip)
	}
}

/// A client-mode Kademlia instance on a para's DHT.
struct Dht {
	handle: Litep2pKademliaHandle,
	/// The genesis hash and fork id of the record the instance was opened for.
	genesis: [u8; 32],
	fork_id: ForkId,
}

impl Dht {
	/// Whether `record` names the DHT this instance is on.
	fn serves(&self, record: &BootnodeRecord) -> bool {
		self.genesis == record.genesis && self.fork_id == record.fork_id
	}

	/// Add `seeds` to the routing table.
	async fn seed(&mut self, seeds: &[(PeerId, Multiaddr)]) {
		for (peer_id, addr) in seeds {
			self.handle.add_known_peer((*peer_id).into(), vec![addr.clone().into()]).await;
		}
	}
}

/// The record in a published value; `None` when nothing is published.
fn decode(value: Option<&[u8]>) -> Result<Option<BootnodeRecord>, codec::Error> {
	value.map(|mut value| BootnodeRecord::decode_all(&mut value)).transpose()
}

/// The nodes of `record` to seed a DHT with.
fn seeds(record: &BootnodeRecord, allow_private_ip: bool) -> Vec<(PeerId, Multiaddr)> {
	record
		.addresses
		.iter()
		.filter_map(|address| known_bootnode(address, allow_private_ip))
		.collect()
}

/// The peer `address` names and the address itself, or `None` for one this node should not use.
fn known_bootnode(address: &[u8], allow_private_ip: bool) -> Option<(PeerId, Multiaddr)> {
	if let Err(error) = pallet_bootnodes::multiaddr::validate(address) {
		tracing::debug!(target: LOG_TARGET, ?error, "Skipping a bootnode: its address is not one a bootnode may list.");
		return None;
	}
	let addr = match Multiaddr::try_from(address.to_vec()) {
		Ok(addr) => addr,
		Err(error) => {
			tracing::debug!(target: LOG_TARGET, ?error, "Skipping a bootnode: its address is no multiaddr.");
			return None;
		},
	};
	if !allow_private_ip && !is_global(&addr) {
		tracing::debug!(target: LOG_TARGET, %addr, "Skipping a bootnode: its address is not global.");
		return None;
	}
	let Some(peer_id) = PeerId::try_from_multiaddr(&addr) else {
		tracing::debug!(target: LOG_TARGET, %addr, "Skipping a bootnode: its address names no peer.");
		return None;
	};
	Some((peer_id, addr))
}

/// Whether `addr`, reported for `peer_id`, has the shape of a bootnode's address with the
/// `/p2p/<peer id>` optional, names no other peer, and unless `allow_private_ip` is global.
fn is_dialable(addr: &Multiaddr, peer_id: &PeerId, allow_private_ip: bool) -> bool {
	pallet_bootnodes::multiaddr::validate_without_peer_id(&addr.to_vec()).is_ok() &&
		PeerId::try_from_multiaddr(addr).is_none_or(|named| named == *peer_id) &&
		(allow_private_ip || is_global(addr))
}

/// Whether the host `addr` starts with is a global IP or a DNS name. An address that starts with
/// no host is not global.
fn is_global(addr: &Multiaddr) -> bool {
	match addr.iter().next() {
		Some(Protocol::Ip4(ip)) => IpNetwork::from(ip).is_global(),
		Some(Protocol::Ip6(ip)) => IpNetwork::from(ip).is_global(),
		Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) => true,
		_ => false,
	}
}

/// The next event of `dht`, or never without one.
async fn next_event(dht: &mut Option<Dht>) -> Option<Litep2pKademliaEvent> {
	match dht {
		Some(dht) => dht.handle.next().await,
		None => futures::future::pending().await,
	}
}

/// Follow `para_id`'s published record at JAM's finalized block, and discover the para's peers on
/// its DHT. Returns when the subscription ends.
pub(crate) async fn follow<Jam: JamChainSource + JamStateSource + ?Sized>(
	jam: Arc<Jam>,
	parachain_service: ServiceId,
	para_id: u32,
	allow_private_ip: bool,
	kademlia: ClientKademlia,
) {
	let key = pallet_jam_kv::kv_storage_key(para_id, BOOTNODES_KEY);
	// Subscribed before reading the current value, so that no change in between is missed.
	let values = match jam.service_value_stream(parachain_service, &key, true).await {
		Ok(values) => values.map(|update| update.value),
		Err(error) => {
			tracing::error!(target: LOG_TARGET, para_id, ?error, "Unable to follow the para's bootnodes on JAM.");
			return;
		},
	};
	let current = match jam.finalized_block().await {
		Ok(finalized) => jam.service_value(finalized.header_hash, parachain_service, &key).await,
		Err(error) => Err(error),
	};
	let current = match current {
		Ok(current) => current,
		Err(error) => {
			tracing::error!(target: LOG_TARGET, para_id, ?error, "Unable to read the para's bootnodes on JAM.");
			return;
		},
	};
	tracing::info!(target: LOG_TARGET, para_id, "Following the para's bootnodes on JAM.");

	discover(current, values, para_id, allow_private_ip, kademlia).await;
	tracing::warn!(target: LOG_TARGET, para_id, "The subscription to the para's bootnodes ended.");
}

/// Act on the `current` published value and then on each of `values`, while discovering the
/// para's peers on the DHT the latest record names. Returns when `values` ends.
async fn discover(
	current: Option<Vec<u8>>,
	mut values: impl Stream<Item = Option<Vec<u8>>> + Unpin,
	para_id: u32,
	allow_private_ip: bool,
	kademlia: impl Join,
) {
	// Outlives evictions from the routing table and changes of DHT, for the messaging layer.
	// TODO: hand it to the messaging layer once there is one.
	let peers = Peers::new(para_id, allow_private_ip);
	let mut dht = None;
	on_value(&mut dht, &kademlia, &peers, para_id, allow_private_ip, current).await;

	let mut discovery = tokio::time::interval(DISCOVERY_INTERVAL);
	// A DHT opened late is queried once, not once for every interval it missed.
	discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		tokio::select! {
			value = values.next() => {
				let Some(value) = value else { break };
				if on_value(&mut dht, &kademlia, &peers, para_id, allow_private_ip, value).await {
					discovery.reset_immediately();
				}
			},
			event = next_event(&mut dht) => match event {
				Some(Litep2pKademliaEvent::FindNodeSuccess { peers: found, .. }) => {
					let mut record = peers.lock();
					for (peer, addresses) in found {
						record.discovered(peer.into(), addresses.into_iter().map(Multiaddr::from));
					}
				},
				Some(_) => {},
				None => {
					tracing::warn!(target: LOG_TARGET, para_id, "The instance on the para's DHT ended; the next record joins it again.");
					dht = None;
				},
			},
			_ = discovery.tick(), if dht.is_some() => {
				let full = peers.lock().is_full();
				if let Some(dht) = dht.as_mut().filter(|_| !full) {
					dht.handle.find_node(PeerId::random().into()).await;
				}
			},
		}
	}
}

/// Seed `dht` with the record in `value`, opening an instance first if the record names a DHT
/// `dht` is not on, and make the record's nodes the bootnodes in `peers`. A cleared record closes
/// the instance and forgets the para's peers, except the banned ones. A value that does not
/// decode or has an invalid fork id, or an instance that cannot be opened, leaves both as they
/// are. Returns whether an instance was opened.
async fn on_value(
	dht: &mut Option<Dht>,
	kademlia: &impl Join,
	peers: &Peers,
	para_id: u32,
	allow_private_ip: bool,
	value: Option<Vec<u8>>,
) -> bool {
	let record = match decode(value.as_deref()) {
		Ok(Some(record)) => record,
		Ok(None) => {
			if let Some(previous) = dht.take() {
				tracing::info!(target: LOG_TARGET, para_id, "The para cleared its bootnodes; left its DHT.");
				// Waits until the instance has released its protocol names, so that a record
				// published again can reopen the same DHT.
				previous.handle.shutdown().await;
			}
			peers.lock().clear();
			return false;
		},
		Err(error) => {
			tracing::warn!(target: LOG_TARGET, para_id, ?error, "The para's bootnode record does not decode; keeping the DHT as it is.");
			return false;
		},
	};
	if !pallet_bootnodes::is_valid_fork_id(&record.fork_id) {
		tracing::warn!(target: LOG_TARGET, para_id, fork_id = ?record.fork_id, "The para's bootnode record has an invalid fork id; keeping the DHT as it is.");
		return false;
	}
	let mut opened = false;
	if !dht.as_ref().is_some_and(|dht| dht.serves(&record)) {
		let fork_id = core::str::from_utf8(&record.fork_id).expect("a valid fork id is ASCII; qed");
		let fork_id = Some(fork_id).filter(|id| !id.is_empty());
		let Some(handle) = kademlia.join(&record.genesis, fork_id, allow_private_ip).await else {
			tracing::warn!(target: LOG_TARGET, para_id, "Unable to join the para's DHT; keeping the DHT as it is.");
			return false;
		};
		tracing::info!(target: LOG_TARGET, para_id, "Joined the para's DHT.");
		let new = Dht { handle, genesis: record.genesis, fork_id: record.fork_id.clone() };
		if let Some(previous) = dht.replace(new) {
			// Waits until the instance has released its protocol names.
			previous.handle.shutdown().await;
		}
		opened = true;
	}
	let seeds = seeds(&record, allow_private_ip);
	if let Some(dht) = dht {
		dht.seed(&seeds).await;
	}
	peers.lock().set_bootnodes(seeds);
	opened
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use sp_core::{ed25519, Pair as _};

	fn peer(seed: u8) -> PeerId {
		let pair = ed25519::Pair::from_seed(&[seed; 32]);
		PeerId::from_ed25519(&pair.public().0).expect("an ed25519 key is a peer id; qed")
	}

	fn address(seed: u8, addr: &str) -> Multiaddr {
		format!("{addr}/p2p/{}", peer(seed))
			.parse()
			.expect("the test's addresses parse; qed")
	}

	fn record_of(addresses: Vec<Vec<u8>>) -> BootnodeRecord {
		let addresses = addresses
			.into_iter()
			.map(|address| address.try_into().expect("the test's addresses are short; qed"))
			.collect::<Vec<_>>()
			.try_into()
			.expect("the tests list few addresses; qed");
		BootnodeRecord { genesis: [1; 32], fork_id: Default::default(), addresses }
	}

	fn record(addresses: &[(u8, &str)]) -> BootnodeRecord {
		record_of(addresses.iter().map(|(seed, addr)| address(*seed, addr).to_vec()).collect())
	}

	#[test]
	fn a_value_that_is_no_record_is_an_error() {
		assert_eq!(decode(None), Ok(None));
		assert!(decode(Some(&[0x04, 0xff])).is_err());
		let mut trailing = record(&[(1, "/ip4/8.8.8.8/tcp/1")]).encode();
		trailing.push(0);
		assert!(decode(Some(&trailing)).is_err());
	}

	/// The other para's runtime is not ours, so what it publishes is not trusted to be usable.
	#[test]
	fn addresses_the_pallet_would_reject_are_skipped() {
		let no_peer = "/ip4/8.8.8.8/tcp/1".parse::<Multiaddr>().unwrap().to_vec();
		let udp = address(2, "/ip4/8.8.8.8/udp/1/quic-v1").to_vec();
		let good = address(4, "/ip4/8.8.8.8/tcp/1");
		let record = record_of(vec![no_peer, vec![0xff, 0xff], udp, good.to_vec()]);

		assert_eq!(seeds(&record, true), vec![(peer(4), good)]);
	}

	#[test]
	fn a_non_global_ip_is_skipped_unless_allowed() {
		let global = address(6, "/ip4/8.8.8.8/tcp/1");
		let hostname = address(7, "/dns/b.example.org/tcp/1");
		let record = record(&[
			(1, "/ip4/127.0.0.1/tcp/1"),
			(2, "/ip4/10.0.0.1/tcp/1"),
			(3, "/ip6/::1/tcp/1"),
			(6, "/ip4/8.8.8.8/tcp/1"),
			(7, "/dns/b.example.org/tcp/1"),
		]);

		assert_eq!(seeds(&record, false), vec![(peer(6), global), (peer(7), hostname)]);
		assert_eq!(seeds(&record, true).len(), 5);
	}

	/// A network configuration whose backend never runs, and its handle. While the configuration
	/// lives, opening an instance waits forever; once it is dropped, opening fails.
	type Block = sp_runtime::generic::Block<
		sp_runtime::generic::Header<u32, sp_runtime::traits::BlakeTwo256>,
		sp_runtime::OpaqueExtrinsic,
	>;
	type Config = sc_network::config::FullNetworkConfiguration<
		Block,
		sp_core::H256,
		sc_network::Litep2pNetworkBackend,
	>;

	fn kademlia() -> (Config, ClientKademlia) {
		let mut config = Config::new(&sc_network::config::NetworkConfiguration::new_local(), None);
		let kademlia = config.client_kademlia();
		(config, kademlia)
	}

	/// Garbage and a cleared record open no instance, so this run reaches the end of the stream
	/// although opening one would wait forever.
	#[tokio::test]
	async fn garbage_and_cleared_values_open_no_dht() {
		let (_config, kademlia) = kademlia();
		let values = futures::stream::iter([None, Some(vec![0x04, 0xff])]);

		let run = discover(Some(vec![0xff]), values, 0, true, kademlia);
		tokio::time::timeout(Duration::from_secs(5), run)
			.await
			.expect("no instance is opened");
	}

	/// A DHT that cannot be joined is logged and skipped, so this run reaches the end of the
	/// stream.
	#[tokio::test]
	async fn a_record_whose_dht_cannot_be_joined_is_skipped() {
		let (config, kademlia) = kademlia();
		drop(config);
		let record = record(&[(1, "/ip4/8.8.8.8/tcp/1")]).encode();
		let values = futures::stream::iter([Some(record.clone())]);

		let run = discover(Some(record), values, 0, true, kademlia);
		tokio::time::timeout(Duration::from_secs(5), run).await.expect("the run ends");
	}

	/// A global address of a discovered peer; Kademlia reports addresses without the peer id.
	fn at(port: u16) -> Multiaddr {
		format!("/ip4/8.8.8.8/tcp/{port}")
			.parse()
			.expect("the test's addresses parse; qed")
	}

	fn ids(record: &AddressRecord) -> Vec<PeerId> {
		record.peers().into_iter().map(|(peer_id, _)| peer_id).collect()
	}

	/// A record with the discovered peers of seeds `10..10 + MAX_DISCOVERED_PEERS`.
	fn full(allow_private_ip: bool) -> AddressRecord {
		let mut record = AddressRecord::new(0, allow_private_ip);
		for seed in 10..10 + MAX_DISCOVERED_PEERS as u8 {
			assert!(record.discovered(peer(seed), [at(1)]));
		}
		record
	}

	#[test]
	fn discovered_peers_stop_at_20_and_new_ones_are_ignored() {
		let mut record = full(false);
		let first = ids(&record);
		assert_eq!(first.len(), 20);

		assert!(!record.discovered(peer(100), [at(1)]));
		assert_eq!(ids(&record), first, "no peer was pushed out");
		// A known peer still gets new addresses.
		assert!(!record.discovered(peer(10), [at(2)]));
		assert_eq!(record.peers()[0].1, vec![at(1), at(2)]);
	}

	#[test]
	fn bootnodes_do_not_count_toward_the_cap() {
		let mut record = AddressRecord::new(0, false);
		let bootnodes = (1..=8).map(|seed| (peer(seed), address(seed, "/ip4/8.8.8.8/tcp/1")));
		record.set_bootnodes(bootnodes.collect());
		for seed in 10..10 + MAX_DISCOVERED_PEERS as u8 {
			assert!(record.discovered(peer(seed), [at(1)]));
		}
		assert!(!record.discovered(peer(100), [at(1)]));

		let peers = ids(&record);
		assert_eq!(peers.len(), 8 + MAX_DISCOVERED_PEERS);
		assert_eq!(peers[..8], (1..=8).map(peer).collect::<Vec<_>>(), "bootnodes come first");
		// A bootnode found on the DHT takes no slot.
		assert!(!record.discovered(peer(1), [at(1)]));
		assert_eq!(ids(&record), peers);
	}

	#[test]
	fn a_failed_or_undialable_peer_frees_its_slot() {
		let mut record = full(false);
		record.report(peer(10), Outcome::Success);
		record.report(peer(11), Outcome::RequestFailed);
		record.report(peer(12), Outcome::DialFailed);
		let peers = ids(&record);
		assert_eq!(peers.len(), MAX_DISCOVERED_PEERS - 2);
		assert!(peers.contains(&peer(10)));
		assert!(!peers.contains(&peer(11)) && !peers.contains(&peer(12)));

		assert!(record.discovered(peer(100), [at(1)]));
		// A removed peer comes back when found again.
		assert!(record.discovered(peer(11), [at(1)]));
		assert!(!record.discovered(peer(12), [at(1)]), "the record is full again");

		// Failures of a bootnode leave it in place.
		record.set_bootnodes(vec![(peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]);
		record.report(peer(1), Outcome::RequestFailed);
		record.report(peer(1), Outcome::DialFailed);
		assert_eq!(ids(&record)[0], peer(1));
	}

	#[test]
	fn a_peer_that_returns_garbage_is_banned_and_not_added_again() {
		let mut record = full(false);
		record.report(peer(10), Outcome::Garbage);
		assert!(!ids(&record).contains(&peer(10)));

		assert!(!record.discovered(peer(10), [at(1)]), "a banned peer is not added again");
		assert!(record.discovered(peer(100), [at(1)]), "its slot is free");
		record.report(peer(100), Outcome::RequestFailed);
		assert!(!record.discovered(peer(10), [at(1)]), "even into a free slot");

		// A peer that has already left the record is banned too.
		record.report(peer(11), Outcome::DialFailed);
		assert!(!ids(&record).contains(&peer(11)));
		record.report(peer(11), Outcome::Garbage);
		assert!(!record.discovered(peer(11), [at(1)]), "a former peer that returned garbage");

		// A bootnode that returns garbage is not banned.
		record.set_bootnodes(vec![(peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]);
		record.report(peer(1), Outcome::Garbage);
		assert_eq!(ids(&record)[0], peer(1));
		record.set_bootnodes(Vec::new());
		assert!(record.discovered(peer(1), [at(1)]));
	}

	#[test]
	fn only_global_addresses_are_kept_unless_private_ips_are_allowed() {
		let private: Multiaddr = "/ip4/10.0.0.1/tcp/1".parse().expect("parses; qed");
		let loopback: Multiaddr = "/ip6/::1/tcp/1".parse().expect("parses; qed");
		let dns: Multiaddr = "/dns/b.example.org/tcp/1".parse().expect("parses; qed");

		let mut record = AddressRecord::new(0, false);
		assert!(!record.discovered(peer(10), [private.clone(), loopback.clone()]));
		assert!(record.discovered(peer(11), [private.clone(), at(1), dns.clone(), at(1)]));
		assert_eq!(
			record.peers(),
			vec![(peer(11), vec![dns.clone(), at(1)])],
			"a repeat moves last"
		);

		let mut record = AddressRecord::new(0, true);
		assert!(record.discovered(peer(10), [private.clone(), loopback.clone(), private.clone()]));
		assert_eq!(record.peers(), vec![(peer(10), vec![loopback, private])]);

		// Addresses are bounded per peer, also across merges.
		assert!(record.discovered(peer(11), (1..=6).map(at)));
		assert!(!record.discovered(peer(11), (5..=12).map(at)));
		assert_eq!(record.peers()[1].1, (5..=12).map(at).collect::<Vec<_>>());
		assert_eq!(record.peers()[1].1.len(), MAX_ADDRESSES_PER_PEER);
	}

	fn parse(addr: &str) -> Multiaddr {
		addr.parse().expect("the test's addresses parse; qed")
	}

	/// A DHT responder must not get this node to dial other transports, hosts or peers.
	#[test]
	fn a_discovered_address_needs_a_bootnodes_shape_and_no_other_peer_id() {
		let own = address(10, "/ip4/8.8.8.8/tcp/2");
		let wss = parse("/dns/b.example.org/tcp/1/wss");
		let rejected = [
			parse("/ip4/8.8.8.8/udp/1/quic-v1"),
			parse("/ip4/8.8.8.8/tcp/1/p2p-circuit"),
			parse("/memory/1"),
			parse("/ip4/8.8.8.8/tcp/0"),
			parse("/dns/localhost/tcp/1"),
			address(11, "/ip4/8.8.8.8/tcp/3"),
		];

		let mut record = AddressRecord::new(0, true);
		assert!(!record.discovered(peer(10), rejected.clone()));
		let found = rejected.into_iter().chain([at(1), own.clone(), wss.clone()]);
		assert!(record.discovered(peer(10), found));
		assert_eq!(record.peers(), vec![(peer(10), vec![at(1), own, wss])]);
	}

	#[test]
	fn an_address_without_a_host_is_not_global() {
		assert!(!is_global(&parse("/memory/1")));
		assert!(!is_global(&parse("/tcp/1")));
		assert!(is_global(&at(1)));
		assert!(is_global(&parse("/dns4/b.example.org/tcp/1")));
	}

	/// A responder that fills a peer's addresses with bogus ones is displaced by later reports.
	#[test]
	fn new_addresses_of_a_known_peer_push_out_its_oldest() {
		let mut record = AddressRecord::new(0, false);
		assert!(record.discovered(peer(10), (1..=MAX_ADDRESSES_PER_PEER as u16).map(at)));
		// An address reported again counts as new.
		assert!(!record.discovered(peer(10), [at(100), at(2)]));

		let mut expected = (3..=MAX_ADDRESSES_PER_PEER as u16).map(at).collect::<Vec<_>>();
		expected.extend([at(100), at(2)]);
		assert_eq!(record.peers()[0].1, expected);
	}

	#[test]
	fn the_banned_peers_are_bounded_and_the_earliest_is_forgotten_first() {
		let mut banned = Banned::default();
		let ids = (0..=MAX_BANNED).map(|_| PeerId::random()).collect::<Vec<_>>();
		for id in &ids {
			banned.insert(*id);
		}
		banned.insert(ids[1]);

		assert!(!banned.contains(&ids[0]));
		assert!(ids[1..].iter().all(|id| banned.contains(id)));
		assert_eq!((banned.order.len(), banned.set.len()), (MAX_BANNED, MAX_BANNED));
	}

	#[test]
	fn a_bootnode_forgotten_by_the_latest_clear_is_not_banned() {
		let mut record = AddressRecord::new(0, false);
		record.set_bootnodes(vec![(peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]);
		record.clear();
		record.report(peer(1), Outcome::Garbage);
		assert!(record.discovered(peer(1), [at(1)]));

		// Only until the next clear, which forgets no bootnode.
		record.clear();
		record.report(peer(1), Outcome::Garbage);
		assert!(!record.discovered(peer(1), [at(1)]));
	}

	#[test]
	fn the_paras_to_follow_are_deduplicated_without_our_own() {
		assert_eq!(paras_to_follow(&[3, 1, 3, 2, 1], 2), vec![1, 3]);
		assert_eq!(paras_to_follow(&[2, 2], 2), Vec::<u32>::new());
	}

	/// Joins every DHT at once, with a handle whose instance never runs.
	#[derive(Default)]
	struct Joined(Mutex<Vec<([u8; 32], Option<String>)>>);

	impl Join for Joined {
		fn join(
			&self,
			genesis: &[u8],
			fork_id: Option<&str>,
			_allow_private_ip: bool,
		) -> impl Future<Output = Option<Litep2pKademliaHandle>> + Send {
			let genesis = genesis.try_into().expect("a genesis hash has 32 bytes; qed");
			self.0
				.lock()
				.expect("no test panics while holding it; qed")
				.push((genesis, fork_id.map(Into::into)));
			// The configuration is dropped, so shutting the handle down returns at once.
			let (_config, handle) =
				litep2p::protocol::libp2p::kademlia::ConfigBuilder::new().build();
			futures::future::ready(Some(handle))
		}
	}

	impl Join for &Joined {
		fn join(
			&self,
			genesis: &[u8],
			fork_id: Option<&str>,
			allow_private_ip: bool,
		) -> impl Future<Output = Option<Litep2pKademliaHandle>> + Send {
			(**self).join(genesis, fork_id, allow_private_ip)
		}
	}

	fn joins(joined: &Joined) -> Vec<([u8; 32], Option<String>)> {
		joined.0.lock().expect("no test panics while holding it; qed").clone()
	}

	/// The instances [`Joined`] opens end at once. The run drops each instead of polling it again,
	/// and joins the DHT again for the next record, the same one.
	#[tokio::test]
	async fn an_instance_that_ended_is_dropped_and_the_next_record_joins_again() {
		let joined = Joined::default();
		let published = record(&[(1, "/ip4/8.8.8.8/tcp/1")]).encode();
		let again = published.clone();
		let values = Box::pin(futures::stream::once(async move {
			tokio::time::sleep(Duration::from_millis(100)).await;
			Some(again)
		}));

		let run = discover(Some(published), values, 0, false, &joined);
		tokio::time::timeout(Duration::from_secs(5), run).await.expect("the run ends");
		assert_eq!(joins(&joined), vec![([1; 32], None), ([1; 32], None)]);
	}

	#[tokio::test]
	async fn a_record_with_an_invalid_fork_id_is_skipped() {
		let joined = Joined::default();
		let peers = Peers::new(0, false);
		let mut dht = None;
		let with_fork_id = |fork_id: &[u8]| {
			let fork_id = fork_id.to_vec().try_into().expect("a short fork id; qed");
			BootnodeRecord { fork_id, ..record(&[(1, "/ip4/8.8.8.8/tcp/1")]) }.encode()
		};
		for invalid in [&b"a/b"[..], &[0xff], b"a.b"] {
			let value = Some(with_fork_id(invalid));
			assert!(!on_value(&mut dht, &joined, &peers, 0, false, value).await);
		}
		assert!(dht.is_none());
		assert_eq!(peers.peers(), vec![]);
		assert_eq!(joins(&joined), vec![]);

		let valid = Some(with_fork_id(b"fork-1_a"));
		assert!(on_value(&mut dht, &joined, &peers, 0, false, valid).await);
		// An invalid one later leaves the DHT as it is.
		assert!(!on_value(&mut dht, &joined, &peers, 0, false, Some(with_fork_id(b"a/b"))).await);
		assert_eq!(joins(&joined), vec![([1; 32], Some("fork-1_a".into()))]);
		assert!(dht.is_some());
	}

	#[tokio::test]
	async fn a_cleared_record_closes_the_dht_and_forgets_the_peers() {
		let joined = Joined::default();
		let peers = Peers::new(0, false);
		let mut dht = None;
		let published = record(&[(1, "/ip4/8.8.8.8/tcp/1")]);
		on_value(&mut dht, &joined, &peers, 0, false, Some(published.encode())).await;
		peers.lock().discovered(peer(10), [at(1)]);
		peers.lock().discovered(peer(11), [at(2)]);
		peers.report(peer(11), Outcome::Garbage);

		on_value(&mut dht, &joined, &peers, 0, false, None).await;
		assert!(dht.is_none());
		assert_eq!(peers.peers(), vec![]);
		// A banned peer stays banned.
		assert!(!peers.lock().discovered(peer(11), [at(2)]));

		// Published again on the same DHT, the record opens a new instance.
		on_value(&mut dht, &joined, &peers, 0, false, Some(published.encode())).await;
		let joined = joins(&joined);
		assert_eq!(joined, vec![([1; 32], None), ([1; 32], None)]);
		assert!(dht.is_some_and(|dht| dht.serves(&published)));
		assert_eq!(peers.peers(), vec![(peer(1), vec![address(1, "/ip4/8.8.8.8/tcp/1")])]);
	}

	#[tokio::test]
	async fn discovered_peers_survive_a_change_of_dht() {
		let joined = Joined::default();
		let peers = Peers::new(0, false);
		let mut dht = None;
		let first = record(&[(1, "/ip4/8.8.8.8/tcp/1")]);
		on_value(&mut dht, &joined, &peers, 0, false, Some(first.encode())).await;
		peers.lock().discovered(peer(10), [at(1)]);

		let fork_id = b"fork".to_vec().try_into().expect("a short fork id; qed");
		let second = BootnodeRecord { fork_id, ..record(&[(2, "/ip4/8.8.8.8/tcp/2")]) };
		on_value(&mut dht, &joined, &peers, 0, false, Some(second.encode())).await;

		let joined = joins(&joined);
		assert_eq!(joined, vec![([1; 32], None), ([1; 32], Some("fork".into()))]);
		assert!(dht.is_some_and(|dht| dht.serves(&second)));
		assert_eq!(
			peers.peers(),
			vec![(peer(2), vec![address(2, "/ip4/8.8.8.8/tcp/2")]), (peer(10), vec![at(1)])],
		);

		// Reports through the shared handle reach the record.
		peers.report(peer(10), Outcome::DialFailed);
		assert_eq!(peers.peers().len(), 1);
	}
}
