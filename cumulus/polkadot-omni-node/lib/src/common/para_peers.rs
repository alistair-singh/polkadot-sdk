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

//! The peers of other paras, found on their DHTs.
//!
//! For every para this node exchanges messages with, a source of [`BootnodeRecord`]s names the
//! para's DHT and some of its nodes: on JAM the record the para publishes to its key-value store,
//! on Polkadot one built from the para's providers on the relay chain DHT (RFC-0008). [`discover`]
//! runs a client-mode Kademlia instance on the DHT the latest record names, seeded with the
//! record's addresses, to find more of the para's peers.
//!
//! It opens the instance when a record first appears, and a new one when a record names another
//! genesis hash or fork id. When the record is cleared, it closes the instance and forgets the
//! para's peers, the ones it found included. Peers it banned stay banned. If a record appears
//! again, it opens a new instance and starts over.
//!
//! The peers it finds are kept in an [`AddressRecord`], for the messaging layer to dial through
//! [`Peers`]: the record's bootnodes, and up to [`MAX_DISCOVERED_PEERS`] peers found on the DHT.
//! The messaging layer reports how each request went, and a peer that fails
//! [`FAILURES_TO_REMOVE`] times in a row is removed.
//!
//! The record's source is not trusted, so this skips what it could not use: a record whose fork
//! id [`pallet_bootnodes::is_valid_fork_id`] rejects, an address
//! [`pallet_bootnodes::multiaddr::validate`] rejects, and unless `--allow-private-ip` applies an
//! address with a non-global IP. An address a DHT reports for a peer must have the same shape,
//! the `/p2p/<peer id>` being optional but, if there, that peer's.

use codec::DecodeAll;
use futures::{Stream, StreamExt};
use ip_network::IpNetwork;
use pallet_bootnodes::{BootnodeRecord, ForkId};
use sc_network::{
	config::{ClientKademlia, Litep2pKademliaEvent, Litep2pKademliaHandle, Litep2pKademliaQueryId},
	multiaddr::Protocol,
	Multiaddr, NetworkStateInfo, PeerId,
};
use std::{
	collections::{HashSet, VecDeque},
	future::Future,
	sync::{Arc, Mutex, MutexGuard, PoisonError},
	time::Duration,
};
use tokio::{
	sync::{OwnedSemaphorePermit, Semaphore},
	time::Instant,
};

/// Log target for this module.
pub(crate) const LOG_TARGET: &str = "para-peers";

/// How often the reader asks a para's DHT for more of its peers: one discovery round.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// The most peers of a para found on its DHT that are kept, bootnodes not counted: enough to
/// survive a few going away between rounds, few enough to keep the dials they cost small.
const MAX_DISCOVERED_PEERS: usize = 20;

/// The most new peers one discovery round adds, so that one response cannot fill the record and
/// the slots fill from the answers of several rounds.
const MAX_NEW_PEERS_PER_ROUND: usize = 5;

/// The most bootnodes a record lists, and so the most seeded into a DHT.
const MAX_BOOTNODES: usize = pallet_bootnodes::MAX_BOOTNODES as usize;

/// The most addresses kept for a peer: as many as a record may list.
const MAX_ADDRESSES_PER_PEER: usize = MAX_BOOTNODES;

/// The most banned peers of a para remembered; the earliest banned is forgotten first.
const MAX_BANNED: usize = 1024;

/// Failures in a row after which a discovered peer is removed: one timeout does not cost a peer
/// its slot, while a dead one is gone after a few requests.
const FAILURES_TO_REMOVE: u32 = 3;

/// The most other paras followed, each with its own instance and connections: more than a para
/// exchanges messages with, few enough to bound what following them costs.
const MAX_FOLLOWED_PARAS: usize = 16;

/// The least time between two joins of a para's DHT, so that a para changing its record's DHT
/// often, or clearing and publishing it again, opens at most one instance a minute here.
const MIN_REJOIN_INTERVAL: Duration = Duration::from_secs(60);

/// The most discovery queries in flight across all followed paras, as each query dials the peers
/// it asks: a quarter of [`MAX_FOLLOWED_PARAS`], as a query mostly ends well within a round.
const MAX_DISCOVERY_QUERIES_IN_FLIGHT: usize = 4;

/// The paras of `from` to follow, each once, without `own`, ours, and at most
/// [`MAX_FOLLOWED_PARAS`] of them, the lowest ids first.
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
	if paras.len() > MAX_FOLLOWED_PARAS {
		let skipped = paras.split_off(MAX_FOLLOWED_PARAS);
		tracing::warn!(target: LOG_TARGET, ?skipped, max = MAX_FOLLOWED_PARAS, "Too many paras to follow the bootnodes of; skipping those with the highest ids.");
	}
	paras
}

/// The permits for discovery queries, shared by the followers of all paras.
pub(crate) fn discovery_queries() -> Arc<Semaphore> {
	Arc::new(Semaphore::new(MAX_DISCOVERY_QUERIES_IN_FLIGHT))
}

/// How a request to one of a para's peers went, as the messaging layer reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
	/// The peer answered with data that passed the root check.
	Success,
	/// The peer was connected but the request failed.
	RequestFailed,
	/// The peer could not be dialled.
	// The spec-msg fetcher reports every failed request as `RequestFailed`, as it does not tell
	// the two apart; the record counts both the same.
	#[allow(dead_code)]
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
/// record, and up to [`MAX_DISCOVERED_PEERS`] peers found on the para's DHT, never this node.
///
/// A peer found on the DHT only takes a free slot, and never pushes out another; at most
/// [`MAX_NEW_PEERS_PER_ROUND`] take one per discovery round. It loses its slot once it fails
/// [`FAILURES_TO_REMOVE`] times in a row, and may come back if found again. One that returns
/// garbage is banned, unless the record lists it or listed it before the latest clear.
struct AddressRecord {
	para_id: u32,
	allow_private_ip: bool,
	local_peer_id: PeerId,
	/// This node's own addresses, without `/p2p`, as last told.
	own_addresses: HashSet<Multiaddr>,
	/// The bootnodes of the latest record, apart from the discovered peers.
	bootnodes: Vec<(PeerId, Vec<Multiaddr>)>,
	/// The bootnodes the latest clear forgot.
	cleared_bootnodes: HashSet<PeerId>,
	/// In the order they were found.
	discovered: Vec<Discovered>,
	/// Discovered peers added since the current discovery round started.
	added_this_round: usize,
	banned: Banned,
}

impl AddressRecord {
	fn new(para_id: u32, allow_private_ip: bool, local_peer_id: PeerId) -> Self {
		Self {
			para_id,
			allow_private_ip,
			local_peer_id,
			own_addresses: HashSet::new(),
			bootnodes: Vec::new(),
			cleared_bootnodes: HashSet::new(),
			discovered: Vec::new(),
			added_this_round: 0,
			banned: Banned::default(),
		}
	}

	/// Replace the bootnodes with the first [`MAX_BOOTNODES`] peers of `seeds` other than this
	/// node, keeping the discovered peers. A discovered peer that is now a bootnode leaves its
	/// slot.
	fn set_bootnodes(&mut self, seeds: Vec<(PeerId, Multiaddr)>) {
		let mut bootnodes: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();
		for (peer_id, addr) in
			seeds.into_iter().filter(|(peer_id, _)| *peer_id != self.local_peer_id)
		{
			if let Some((_, addresses)) = bootnodes.iter_mut().find(|(known, _)| *known == peer_id)
			{
				merge(addresses, [addr]);
			} else if bootnodes.len() < MAX_BOOTNODES {
				bootnodes.push((peer_id, vec![addr]));
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

	/// Make `addresses` this node's own, which no discovered peer keeps.
	fn set_own_addresses(&mut self, addresses: impl IntoIterator<Item = Multiaddr>) {
		self.own_addresses = addresses.into_iter().map(without_peer_id).collect();
	}

	/// Start a discovery round, in which up to [`MAX_NEW_PEERS_PER_ROUND`] peers may be added.
	fn start_round(&mut self) {
		self.added_this_round = 0;
	}

	/// Note `peer_id` found on the DHT at `addresses`. Of those, only the ones [`is_dialable`]
	/// accepts and that are not this node's own are kept. A known peer gets the new addresses; a
	/// new one with any is added if a slot is free, this round has added fewer than
	/// [`MAX_NEW_PEERS_PER_ROUND`], and it is neither banned nor this node. Returns whether it was
	/// added.
	fn discovered(
		&mut self,
		peer_id: PeerId,
		addresses: impl IntoIterator<Item = Multiaddr>,
	) -> bool {
		if peer_id == self.local_peer_id ||
			self.banned.contains(&peer_id) ||
			self.is_bootnode(&peer_id)
		{
			return false;
		}
		let usable = addresses
			.into_iter()
			.filter(|addr| {
				is_dialable(addr, &peer_id, self.allow_private_ip) &&
					!self.own_addresses.contains(&without_peer_id(addr.clone()))
			})
			.collect::<Vec<_>>();
		if let Some(known) = self.discovered.iter_mut().find(|peer| peer.peer_id == peer_id) {
			merge(&mut known.addresses, usable);
			return false;
		}
		let mut addresses = Vec::new();
		merge(&mut addresses, usable);
		if addresses.is_empty() ||
			self.is_full() ||
			self.added_this_round >= MAX_NEW_PEERS_PER_ROUND
		{
			return false;
		}
		tracing::debug!(target: LOG_TARGET, para_id = self.para_id, %peer_id, "Discovered a peer of the para.");
		self.discovered.push(Discovered { peer_id, addresses, failures: 0 });
		self.added_this_round += 1;
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
					// A peer that already left the record, e.g. after failures, is banned too.
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

/// `addr` without a trailing `/p2p/<peer id>`.
fn without_peer_id(mut addr: Multiaddr) -> Multiaddr {
	if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
		addr.pop();
	}
	addr
}

/// A para's [`AddressRecord`], shared by the reader that fills it and the messaging layer that
/// dials its peers.
#[derive(Clone)]
pub(crate) struct Peers(Arc<Mutex<AddressRecord>>);

impl Peers {
	/// The peers of `para_id`, never `local_peer_id`, keeping non-global addresses only with
	/// `allow_private_ip`.
	pub(crate) fn new(para_id: u32, allow_private_ip: bool, local_peer_id: PeerId) -> Self {
		Self(Arc::new(Mutex::new(AddressRecord::new(para_id, allow_private_ip, local_peer_id))))
	}

	fn lock(&self) -> MutexGuard<'_, AddressRecord> {
		// The record is left consistent by every method, so one that panicked left it usable.
		self.0.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Report how a request to `peer_id` went.
	pub(crate) fn report(&self, peer_id: PeerId, outcome: Outcome) {
		self.lock().report(peer_id, outcome)
	}

	/// The peers to dial, each with its addresses: the bootnodes first, then the discovered peers.
	pub(crate) fn peers(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
		self.lock().peers()
	}
}

/// Opens client-mode Kademlia instances: [`ClientKademlia`], or a stand-in in the tests.
pub(crate) trait Join {
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
	/// The discovery query in flight, holding one of the shared permits until it ends.
	query: Option<(Litep2pKademliaQueryId, OwnedSemaphorePermit)>,
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

	/// Ask the DHT for more peers if one of `queries`' permits is free. A query of this instance
	/// that has not ended by now is given up on, and its permit freed.
	async fn query(&mut self, queries: &Arc<Semaphore>, para_id: u32) {
		self.query = None;
		match queries.clone().try_acquire_owned() {
			Ok(permit) => {
				let query_id = self.handle.find_node(PeerId::random().into()).await;
				self.query = Some((query_id, permit));
			},
			Err(_) => {
				tracing::debug!(target: LOG_TARGET, para_id, "Skipping a discovery round: too many discovery queries in flight.")
			},
		}
	}

	/// Note that the query `query_id` ended.
	fn ended(&mut self, query_id: Litep2pKademliaQueryId) {
		if self.query.as_ref().is_some_and(|(id, _)| *id == query_id) {
			self.query = None;
		}
	}
}

/// What a published value would do to the DHT the reader is on.
#[derive(Debug, PartialEq, Eq)]
enum Change {
	/// Open an instance on another DHT, or on one after a clear.
	Join,
	/// Seed the DHT it is on, or clear the record.
	Update,
	/// Nothing: the value does not decode or has an invalid fork id.
	Skip,
}

fn change(dht: &Option<Dht>, value: Option<&[u8]>) -> Change {
	match decode(value) {
		Ok(Some(record)) if !pallet_bootnodes::is_valid_fork_id(&record.fork_id) => Change::Skip,
		Ok(Some(record)) if !dht.as_ref().is_some_and(|dht| dht.serves(&record)) => Change::Join,
		Ok(_) => Change::Update,
		Err(_) => Change::Skip,
	}
}

/// The joins of a para's DHT, at most one per [`MIN_REJOIN_INTERVAL`]. A record that would join
/// sooner waits, and a later value replaces it.
#[derive(Default)]
struct Rejoins {
	/// When the latest join was attempted.
	last: Option<Instant>,
	/// The latest record that would have joined too soon after `last`.
	pending: Option<Vec<u8>>,
}

impl Rejoins {
	/// Whether to act on `value` now, as `dht` is; if not, it is kept until [`Self::due`].
	fn admit(&mut self, dht: &Option<Dht>, value: &Option<Vec<u8>>, now: Instant) -> bool {
		match change(dht, value.as_deref()) {
			Change::Join if self.last.is_some_and(|last| now < last + MIN_REJOIN_INTERVAL) => {
				self.pending = value.clone();
				return false;
			},
			Change::Join => self.last = Some(now),
			Change::Update => {},
			Change::Skip => return true,
		}
		self.pending = None;
		true
	}

	/// When the pending record may join, if there is one.
	fn due(&self) -> Option<Instant> {
		self.pending.as_ref().and(self.last).map(|last| last + MIN_REJOIN_INTERVAL)
	}

	/// The pending record, to join with now.
	fn take(&mut self, now: Instant) -> Option<Vec<u8>> {
		let pending = self.pending.take()?;
		self.last = Some(now);
		Some(pending)
	}
}

/// The record in a published value; `None` when nothing is published.
fn decode(value: Option<&[u8]>) -> Result<Option<BootnodeRecord>, codec::Error> {
	value.map(|mut value| BootnodeRecord::decode_all(&mut value)).transpose()
}

/// The nodes of `record` to seed a DHT with, at most [`MAX_BOOTNODES`] and never `local_peer_id`.
fn seeds(
	record: &BootnodeRecord,
	allow_private_ip: bool,
	local_peer_id: &PeerId,
) -> Vec<(PeerId, Multiaddr)> {
	record
		.addresses
		.iter()
		.take(MAX_BOOTNODES)
		.filter_map(|address| known_bootnode(address, allow_private_ip))
		.filter(|(peer_id, _)| peer_id != local_peer_id)
		.collect()
}

/// The peer `address` names and the address itself, or `None` for one this node should not use.
pub(crate) fn known_bootnode(
	address: &[u8],
	allow_private_ip: bool,
) -> Option<(PeerId, Multiaddr)> {
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

/// Wait until `at`, or forever without it.
async fn until(at: Option<Instant>) {
	match at {
		Some(at) => tokio::time::sleep_until(at).await,
		None => futures::future::pending().await,
	}
}

/// Act on the `current` published value and then on each of `values`, while discovering the
/// para's peers on the DHT the latest record names. Returns when `values` ends.
/// `peers` outlives evictions from the routing table, changes of DHT and this run, for the
/// messaging layer; its para and `allow_private_ip` are the run's.
pub(crate) async fn discover(
	peers: Peers,
	current: Option<Vec<u8>>,
	mut values: impl Stream<Item = Option<Vec<u8>>> + Unpin,
	kademlia: impl Join,
	local: impl NetworkStateInfo,
	queries: Arc<Semaphore>,
) {
	let (para_id, allow_private_ip) = {
		let record = peers.lock();
		(record.para_id, record.allow_private_ip)
	};
	let mut dht = None;
	let mut rejoins = Rejoins::default();
	rejoins.admit(&dht, &current, Instant::now());
	on_value(&mut dht, &kademlia, &peers, para_id, allow_private_ip, current).await;

	let mut discovery = tokio::time::interval(DISCOVERY_INTERVAL);
	// A DHT opened late is queried once, not once for every interval it missed.
	discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		let value = tokio::select! {
			value = values.next() => {
				let Some(value) = value else { break };
				if !rejoins.admit(&dht, &value, Instant::now()) {
					tracing::info!(target: LOG_TARGET, para_id, "Joining the para's DHT later: the last join was too recent.");
					continue;
				}
				value
			},
			_ = until(rejoins.due()) => match rejoins.take(Instant::now()) {
				Some(pending) => Some(pending),
				None => continue,
			},
			event = next_event(&mut dht) => {
				match event {
					Some(Litep2pKademliaEvent::FindNodeSuccess { query_id, peers: found, .. }) => {
						if let Some(dht) = dht.as_mut() {
							dht.ended(query_id);
						}
						let mut record = peers.lock();
						record.set_own_addresses(
							local.listen_addresses().into_iter().chain(local.external_addresses()),
						);
						for (peer, addresses) in found {
							let addresses = addresses.into_iter().map(Multiaddr::from);
							record.discovered(peer.into(), addresses);
						}
					},
					Some(Litep2pKademliaEvent::QueryFailed { query_id }) => {
						if let Some(dht) = dht.as_mut() {
							dht.ended(query_id);
						}
					},
					Some(_) => {},
					None => {
						tracing::warn!(target: LOG_TARGET, para_id, "The instance on the para's DHT ended; the next record joins it again.");
						dht = None;
					},
				}
				continue;
			},
			_ = discovery.tick(), if dht.is_some() => {
				let full = {
					let mut record = peers.lock();
					record.start_round();
					record.is_full()
				};
				if let Some(dht) = dht.as_mut().filter(|_| !full) {
					dht.query(&queries, para_id).await;
				}
				continue;
			},
		};
		if on_value(&mut dht, &kademlia, &peers, para_id, allow_private_ip, value).await {
			discovery.reset_immediately();
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
		let new =
			Dht { handle, genesis: record.genesis, fork_id: record.fork_id.clone(), query: None };
		if let Some(previous) = dht.replace(new) {
			// Waits until the instance has released its protocol names.
			previous.handle.shutdown().await;
		}
		opened = true;
	}
	let local_peer_id = peers.lock().local_peer_id;
	let seeds = seeds(&record, allow_private_ip, &local_peer_id);
	if let Some(dht) = dht {
		dht.seed(&seeds).await;
	}
	peers.lock().set_bootnodes(seeds);
	opened
}

#[cfg(test)]
mod tests {
	use super::*;

	/// [`super::discover`] into a record of its own, as the tests ran it before it took one.
	async fn discover(
		current: Option<Vec<u8>>,
		values: impl Stream<Item = Option<Vec<u8>>> + Unpin,
		para_id: u32,
		allow_private_ip: bool,
		kademlia: impl Join,
		local: impl NetworkStateInfo,
		queries: Arc<Semaphore>,
	) {
		let peers = Peers::new(para_id, allow_private_ip, local.local_peer_id());
		super::discover(peers, current, values, kademlia, local, queries).await
	}
	use codec::Encode;
	use sp_core::{ed25519, Pair as _};

	fn peer(seed: u32) -> PeerId {
		let mut secret = [0; 32];
		secret[..4].copy_from_slice(&seed.to_le_bytes());
		let pair = ed25519::Pair::from_seed(&secret);
		PeerId::from_ed25519(&pair.public().0).expect("an ed25519 key is a peer id; qed")
	}

	/// A peer seed above those of the peers a test fills a record with.
	const NEW: u32 = 1 << 20;

	/// This node's peer.
	fn ours() -> PeerId {
		peer(u32::MAX)
	}

	/// This node's network: [`ours`], listening on [`at`] port 1000, reachable at port 1001.
	struct Local;

	impl NetworkStateInfo for Local {
		fn external_addresses(&self) -> Vec<Multiaddr> {
			vec![at(1001).with(Protocol::P2p(ours().into()))]
		}

		fn listen_addresses(&self) -> Vec<Multiaddr> {
			vec![at(1000)]
		}

		fn local_peer_id(&self) -> PeerId {
			ours()
		}
	}

	impl AddressRecord {
		/// [`Self::discovered`] in a round of its own.
		fn found(
			&mut self,
			peer_id: PeerId,
			addresses: impl IntoIterator<Item = Multiaddr>,
		) -> bool {
			self.start_round();
			self.discovered(peer_id, addresses)
		}
	}

	fn address_record(allow_private_ip: bool) -> AddressRecord {
		AddressRecord::new(0, allow_private_ip, ours())
	}

	fn shared_peers() -> Peers {
		Peers::new(0, false, ours())
	}

	fn address(seed: u32, addr: &str) -> Multiaddr {
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

	fn record(addresses: &[(u32, &str)]) -> BootnodeRecord {
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

		assert_eq!(seeds(&record, true, &ours()), vec![(peer(4), good)]);
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

		assert_eq!(seeds(&record, false, &ours()), vec![(peer(6), global), (peer(7), hostname)]);
		assert_eq!(seeds(&record, true, &ours()).len(), 5);
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

		let run = discover(Some(vec![0xff]), values, 0, true, kademlia, Local, discovery_queries());
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

		let run = discover(Some(record), values, 0, true, kademlia, Local, discovery_queries());
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
		let mut record = address_record(allow_private_ip);
		for seed in 10..10 + MAX_DISCOVERED_PEERS as u32 {
			assert!(record.found(peer(seed), [at(1)]));
		}
		record
	}

	#[test]
	fn discovered_peers_stop_at_the_cap_and_new_ones_are_ignored() {
		let mut record = full(false);
		let first = ids(&record);
		assert_eq!(first.len(), MAX_DISCOVERED_PEERS);

		assert!(!record.found(peer(NEW), [at(1)]));
		assert_eq!(ids(&record), first, "no peer was pushed out");
		// A known peer still gets new addresses.
		assert!(!record.found(peer(10), [at(2)]));
		assert_eq!(record.peers()[0].1, vec![at(1), at(2)]);
	}

	#[test]
	fn bootnodes_do_not_count_toward_the_cap() {
		let mut record = address_record(false);
		let bootnodes = (1..=MAX_BOOTNODES as u32)
			.map(|seed| (peer(seed), address(seed, "/ip4/8.8.8.8/tcp/1")));
		record.set_bootnodes(bootnodes.collect());
		for seed in 10..10 + MAX_DISCOVERED_PEERS as u32 {
			assert!(record.found(peer(seed), [at(1)]));
		}
		assert!(!record.found(peer(NEW), [at(1)]));

		let peers = ids(&record);
		assert_eq!(peers.len(), MAX_BOOTNODES + MAX_DISCOVERED_PEERS);
		let bootnodes = (1..=MAX_BOOTNODES as u32).map(peer).collect::<Vec<_>>();
		assert_eq!(peers[..MAX_BOOTNODES], bootnodes, "bootnodes come first");
		// A bootnode found on the DHT takes no slot.
		assert!(!record.found(peer(1), [at(1)]));
		assert_eq!(ids(&record), peers);
	}

	/// Report `outcome` for `peer_id` `times` times.
	fn report(record: &mut AddressRecord, peer_id: PeerId, outcome: Outcome, times: u32) {
		for _ in 0..times {
			record.report(peer_id, outcome);
		}
	}

	#[test]
	fn a_peer_that_fails_too_often_in_a_row_frees_its_slot() {
		let mut record = full(false);
		record.report(peer(10), Outcome::Success);
		report(&mut record, peer(11), Outcome::RequestFailed, FAILURES_TO_REMOVE);
		report(&mut record, peer(12), Outcome::DialFailed, FAILURES_TO_REMOVE);
		let peers = ids(&record);
		assert_eq!(peers.len(), MAX_DISCOVERED_PEERS - 2);
		assert!(peers.contains(&peer(10)));
		assert!(!peers.contains(&peer(11)) && !peers.contains(&peer(12)));

		assert!(record.found(peer(NEW), [at(1)]));
		// A removed peer comes back when found again.
		assert!(record.found(peer(11), [at(1)]));
		assert!(!record.found(peer(12), [at(1)]), "the record is full again");

		// Failures of a bootnode leave it in place.
		record.set_bootnodes(vec![(peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]);
		report(&mut record, peer(1), Outcome::RequestFailed, FAILURES_TO_REMOVE);
		report(&mut record, peer(1), Outcome::DialFailed, FAILURES_TO_REMOVE);
		assert_eq!(ids(&record)[0], peer(1));
	}

	#[test]
	fn a_peer_is_removed_on_its_last_failure_in_a_row_and_a_success_starts_over() {
		let mut record = address_record(false);
		assert!(record.found(peer(10), [at(1)]));
		report(&mut record, peer(10), Outcome::RequestFailed, FAILURES_TO_REMOVE - 1);
		assert_eq!(ids(&record), vec![peer(10)], "one failure short");

		record.report(peer(10), Outcome::Success);
		report(&mut record, peer(10), Outcome::DialFailed, FAILURES_TO_REMOVE - 1);
		assert_eq!(ids(&record), vec![peer(10)], "the success started the count over");

		// Both kinds of failure count toward the same run.
		record.report(peer(10), Outcome::RequestFailed);
		assert_eq!(ids(&record), vec![]);
	}

	#[test]
	fn a_peer_that_returns_garbage_is_banned_and_not_added_again() {
		let mut record = full(false);
		record.report(peer(10), Outcome::Garbage);
		assert!(!ids(&record).contains(&peer(10)));

		assert!(!record.found(peer(10), [at(1)]), "a banned peer is not added again");
		assert!(record.found(peer(NEW), [at(1)]), "its slot is free");
		report(&mut record, peer(NEW), Outcome::RequestFailed, FAILURES_TO_REMOVE);
		assert!(!record.found(peer(10), [at(1)]), "even into a free slot");

		// A peer that has already left the record is banned too.
		report(&mut record, peer(11), Outcome::DialFailed, FAILURES_TO_REMOVE);
		assert!(!ids(&record).contains(&peer(11)));
		record.report(peer(11), Outcome::Garbage);
		assert!(!record.found(peer(11), [at(1)]), "a former peer that returned garbage");

		// A bootnode that returns garbage is not banned.
		record.set_bootnodes(vec![(peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]);
		record.report(peer(1), Outcome::Garbage);
		assert_eq!(ids(&record)[0], peer(1));
		record.set_bootnodes(Vec::new());
		assert!(record.found(peer(1), [at(1)]));
	}

	#[test]
	fn only_global_addresses_are_kept_unless_private_ips_are_allowed() {
		let private: Multiaddr = "/ip4/10.0.0.1/tcp/1".parse().expect("parses; qed");
		let loopback: Multiaddr = "/ip6/::1/tcp/1".parse().expect("parses; qed");
		let dns: Multiaddr = "/dns/b.example.org/tcp/1".parse().expect("parses; qed");

		let mut record = address_record(false);
		assert!(!record.found(peer(10), [private.clone(), loopback.clone()]));
		assert!(record.found(peer(11), [private.clone(), at(1), dns.clone(), at(1)]));
		assert_eq!(
			record.peers(),
			vec![(peer(11), vec![dns.clone(), at(1)])],
			"a repeat moves last"
		);

		let mut record = address_record(true);
		assert!(record.found(peer(10), [private.clone(), loopback.clone(), private.clone()]));
		assert_eq!(record.peers(), vec![(peer(10), vec![loopback, private])]);

		// Addresses are bounded per peer, also across merges.
		assert!(record.found(peer(11), (1..=6).map(at)));
		assert!(!record.found(peer(11), (5..=12).map(at)));
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

		let mut record = address_record(true);
		assert!(!record.found(peer(10), rejected.clone()));
		let found = rejected.into_iter().chain([at(1), own.clone(), wss.clone()]);
		assert!(record.found(peer(10), found));
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
		let mut record = address_record(false);
		assert!(record.found(peer(10), (1..=MAX_ADDRESSES_PER_PEER as u16).map(at)));
		// An address reported again counts as new.
		assert!(!record.found(peer(10), [at(100), at(2)]));

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
		let mut record = address_record(false);
		record.set_bootnodes(vec![(peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]);
		record.clear();
		record.report(peer(1), Outcome::Garbage);
		assert!(record.found(peer(1), [at(1)]));

		// Only until the next clear, which forgets no bootnode.
		record.clear();
		record.report(peer(1), Outcome::Garbage);
		assert!(!record.found(peer(1), [at(1)]));
	}

	#[test]
	fn the_paras_to_follow_are_deduplicated_without_our_own() {
		assert_eq!(paras_to_follow(&[3, 1, 3, 2, 1], 2), vec![1, 3]);
		assert_eq!(paras_to_follow(&[2, 2], 2), Vec::<u32>::new());
	}

	#[test]
	fn the_paras_to_follow_stop_at_the_cap_lowest_ids_first() {
		let max = MAX_FOLLOWED_PARAS as u32;
		let from = (0..max + 3).rev().collect::<Vec<_>>();
		assert_eq!(paras_to_follow(&from, u32::MAX), (0..max).collect::<Vec<_>>());
		// Our own para takes no place.
		assert_eq!(paras_to_follow(&from, 0), (1..=max).collect::<Vec<_>>());
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
	/// and joins the DHT again for the next record, the same one, once [`MIN_REJOIN_INTERVAL`] has
	/// passed.
	#[tokio::test(start_paused = true)]
	async fn an_instance_that_ended_is_dropped_and_the_next_record_joins_again() {
		let joined = Joined::default();
		let published = record(&[(1, "/ip4/8.8.8.8/tcp/1")]).encode();
		let again = published.clone();
		let values = Box::pin(
			futures::stream::once(async move {
				tokio::time::sleep(Duration::from_millis(100)).await;
				Some(again)
			})
			.chain(
				futures::stream::once(tokio::time::sleep(2 * MIN_REJOIN_INTERVAL))
					.filter_map(|()| futures::future::ready(None)),
			),
		);

		let run = discover(Some(published), values, 0, false, &joined, Local, discovery_queries());
		tokio::time::timeout(3 * MIN_REJOIN_INTERVAL, run).await.expect("the run ends");
		assert_eq!(joins(&joined), vec![([1; 32], None), ([1; 32], None)]);
	}

	#[tokio::test]
	async fn a_record_with_an_invalid_fork_id_is_skipped() {
		let joined = Joined::default();
		let peers = shared_peers();
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
		let peers = shared_peers();
		let mut dht = None;
		let published = record(&[(1, "/ip4/8.8.8.8/tcp/1")]);
		on_value(&mut dht, &joined, &peers, 0, false, Some(published.encode())).await;
		peers.lock().found(peer(10), [at(1)]);
		peers.lock().found(peer(11), [at(2)]);
		peers.report(peer(11), Outcome::Garbage);

		on_value(&mut dht, &joined, &peers, 0, false, None).await;
		assert!(dht.is_none());
		assert_eq!(peers.peers(), vec![]);
		// A banned peer stays banned.
		assert!(!peers.lock().found(peer(11), [at(2)]));

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
		let peers = shared_peers();
		let mut dht = None;
		let first = record(&[(1, "/ip4/8.8.8.8/tcp/1")]);
		on_value(&mut dht, &joined, &peers, 0, false, Some(first.encode())).await;
		peers.lock().found(peer(10), [at(1)]);

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
		for _ in 0..FAILURES_TO_REMOVE {
			peers.report(peer(10), Outcome::DialFailed);
		}
		assert_eq!(peers.peers().len(), 1);
	}

	#[test]
	fn our_own_peer_is_never_a_bootnode_or_discovered() {
		let own = at(1).with(Protocol::P2p(ours().into()));
		let record = record_of(vec![own.to_vec(), address(1, "/ip4/8.8.8.8/tcp/1").to_vec()]);
		assert_eq!(
			seeds(&record, false, &ours()),
			vec![(peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]
		);

		let mut record = address_record(false);
		record.set_bootnodes(vec![(ours(), own), (peer(1), address(1, "/ip4/8.8.8.8/tcp/1"))]);
		assert!(!record.found(ours(), [at(2)]));
		assert_eq!(ids(&record), vec![peer(1)]);
	}

	#[test]
	fn our_own_addresses_are_not_kept_for_a_discovered_peer() {
		let mut record = address_record(false);
		record.set_own_addresses(
			Local.listen_addresses().into_iter().chain(Local.external_addresses()),
		);
		let reported = [at(1000), at(1001), address(10, "/ip4/8.8.8.8/tcp/1001")];
		assert!(!record.found(peer(10), reported.clone()), "no address is left");
		assert!(record.found(peer(10), reported.into_iter().chain([at(2)])));
		assert_eq!(record.peers(), vec![(peer(10), vec![at(2)])]);
	}

	#[test]
	fn a_discovery_round_adds_a_bounded_number_of_new_peers() {
		let mut record = address_record(false);
		record.start_round();
		for seed in 0..MAX_NEW_PEERS_PER_ROUND as u32 {
			assert!(record.discovered(peer(10 + seed), [at(1)]));
		}
		assert!(!record.discovered(peer(NEW), [at(1)]), "the round added its share");
		// A known peer still gets new addresses.
		assert!(!record.discovered(peer(10), [at(2)]));
		assert_eq!(record.peers()[0].1, vec![at(1), at(2)]);

		record.start_round();
		assert!(record.discovered(peer(NEW), [at(1)]), "the next round adds more");
		assert_eq!(ids(&record).len(), MAX_NEW_PEERS_PER_ROUND + 1);
	}

	/// A [`Dht`] whose instance never runs, on the DHT of [`record`].
	fn dht() -> Dht {
		let (_config, handle) = litep2p::protocol::libp2p::kademlia::ConfigBuilder::new().build();
		Dht { handle, genesis: [1; 32], fork_id: Default::default(), query: None }
	}

	#[tokio::test]
	async fn discovery_queries_across_paras_share_a_bounded_number_of_permits() {
		let queries = discovery_queries();
		let mut dhts = (0..=MAX_DISCOVERY_QUERIES_IN_FLIGHT).map(|_| dht()).collect::<Vec<_>>();
		for dht in &mut dhts {
			dht.query(&queries, 0).await;
		}
		let (last, querying) = dhts.split_last_mut().expect("there are several; qed");
		assert!(querying.iter().all(|dht| dht.query.is_some()));
		assert!(last.query.is_none(), "every permit is taken");

		// A query that ends frees its permit, and one that has not ended by the next round too.
		let (query_id, _) = querying[0].query.as_ref().expect("it queries; qed");
		let query_id = *query_id;
		querying[0].ended(query_id);
		last.query(&queries, 0).await;
		assert!(last.query.is_some(), "it took the permit the ended query freed");
		last.query(&queries, 0).await;
		assert!(last.query.is_some(), "it took the permit its own query freed");
		assert!(querying[0].query.is_none());
		assert_eq!(queries.available_permits(), 0);
	}

	#[tokio::test]
	async fn only_a_change_of_dht_waits_for_the_rejoin_interval() {
		let joined = Joined::default();
		let peers = shared_peers();
		let mut dht = None;
		let mut rejoins = Rejoins::default();
		let start = Instant::now();
		let first = Some(record(&[(1, "/ip4/8.8.8.8/tcp/1")]).encode());
		assert!(rejoins.admit(&dht, &first, start));
		assert!(on_value(&mut dht, &joined, &peers, 0, false, first).await);

		let reseed = Some(record(&[(2, "/ip4/8.8.8.8/tcp/2")]).encode());
		assert!(rejoins.admit(&dht, &reseed, start + Duration::from_secs(1)), "the same DHT");
		let other = |fork_id: &[u8]| {
			let fork_id = fork_id.to_vec().try_into().expect("a short fork id; qed");
			Some(BootnodeRecord { fork_id, ..record(&[(3, "/ip4/8.8.8.8/tcp/3")]) }.encode())
		};
		assert!(!rejoins.admit(&dht, &other(b"a"), start + Duration::from_secs(2)));
		assert!(!rejoins.admit(&dht, &other(b"b"), start + Duration::from_secs(3)));
		assert!(rejoins.admit(&dht, &Some(vec![0xff]), start + Duration::from_secs(4)));
		assert_eq!(rejoins.due(), Some(start + MIN_REJOIN_INTERVAL), "garbage leaves it waiting");
		assert_eq!(rejoins.take(start + MIN_REJOIN_INTERVAL), other(b"b"), "the latest waits");
		assert_eq!(rejoins.due(), None);

		// A clear is not held back, and drops a record waiting to join.
		let later = start + MIN_REJOIN_INTERVAL + Duration::from_secs(1);
		assert!(!rejoins.admit(&dht, &other(b"c"), later));
		assert!(rejoins.admit(&dht, &None, later));
		assert_eq!(rejoins.due(), None);
	}

	/// A record naming another DHT that arrives too soon after a join is joined once
	/// [`MIN_REJOIN_INTERVAL`] has passed, and only the latest of those arriving in between.
	#[tokio::test(start_paused = true)]
	async fn a_change_of_dht_arriving_too_soon_is_joined_when_the_interval_has_passed() {
		let joined = Joined::default();
		let (sender, values) = futures::channel::mpsc::unbounded();
		let with_fork_id = |fork_id: &[u8]| {
			let fork_id = fork_id.to_vec().try_into().expect("a short fork id; qed");
			Some(BootnodeRecord { fork_id, ..record(&[(1, "/ip4/8.8.8.8/tcp/1")]) }.encode())
		};
		let second = Duration::from_secs(1);
		let drive = async {
			sender.unbounded_send(with_fork_id(b"a")).expect("the run is on; qed");
			tokio::time::sleep(second).await;
			sender.unbounded_send(with_fork_id(b"b")).expect("the run is on; qed");
			sender.unbounded_send(with_fork_id(b"c")).expect("the run is on; qed");
			tokio::time::sleep(MIN_REJOIN_INTERVAL - 2 * second).await;
			assert_eq!(joins(&joined), vec![([1; 32], Some("a".into()))]);
			tokio::time::sleep(2 * second).await;
			drop(sender);
		};

		futures::join!(
			discover(None, values, 0, false, &joined, Local, discovery_queries()),
			drive
		);
		assert_eq!(joins(&joined), vec![([1; 32], Some("a".into())), ([1; 32], Some("c".into()))]);
	}
}
