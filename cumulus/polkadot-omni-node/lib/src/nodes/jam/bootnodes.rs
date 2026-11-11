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
//! genesis hash or fork id.
//!
//! `pallet-bootnodes` checks what it publishes, and the record's genesis hash can only be checked
//! there. The reader still skips what it could not use, since the other para's runtime is not
//! ours: an address [`pallet_bootnodes::multiaddr::validate`] rejects, and unless
//! `--allow-private-ip` applies an address with a non-global IP.

use super::LOG_TARGET;
use codec::DecodeAll;
use futures::{Stream, StreamExt};
use ip_network::IpNetwork;
use jam_interface::{JamChainSource, JamStateSource, ServiceId};
use pallet_bootnodes::{BootnodeRecord, BOOTNODES_KEY};
use sc_network::{
	config::{ClientKademlia, Litep2pKademliaEvent, Litep2pKademliaHandle},
	multiaddr::Protocol,
	Multiaddr, PeerId,
};
use std::{collections::HashSet, sync::Arc, time::Duration};

/// How often the reader asks a para's DHT for more of its peers.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// A client-mode Kademlia instance on a para's DHT.
struct Dht {
	handle: Litep2pKademliaHandle,
	/// The record the instance was opened for.
	record: BootnodeRecord,
}

impl Dht {
	/// Whether `record` names the DHT this instance is on.
	fn serves(&self, record: &BootnodeRecord) -> bool {
		self.record.genesis == record.genesis && self.record.fork_id == record.fork_id
	}

	/// Add the nodes of `record` to the routing table.
	async fn seed(&mut self, record: &BootnodeRecord, allow_private_ip: bool) {
		for (peer_id, addr) in seeds(record, allow_private_ip) {
			self.handle.add_known_peer(peer_id.into(), vec![addr.into()]).await;
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

/// Whether `addr` has no non-global IP. A DNS host counts as global.
fn is_global(addr: &Multiaddr) -> bool {
	addr.iter().all(|protocol| match protocol {
		Protocol::Ip4(ip) => IpNetwork::from(ip).is_global(),
		Protocol::Ip6(ip) => IpNetwork::from(ip).is_global(),
		_ => true,
	})
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
	kademlia: ClientKademlia,
) {
	let mut dht = None;
	on_value(&mut dht, &kademlia, para_id, allow_private_ip, current).await;

	// Outlives evictions from the routing table, for the offchain-messaging requests to come.
	// TODO: cap the set. A responder can return fresh peer ids on every query.
	let mut discovered = HashSet::new();
	let mut discovery = tokio::time::interval(DISCOVERY_INTERVAL);
	// A DHT opened late is queried once, not once for every interval it missed.
	discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		tokio::select! {
			value = values.next() => {
				let Some(value) = value else { break };
				on_value(&mut dht, &kademlia, para_id, allow_private_ip, value).await;
			},
			event = next_event(&mut dht) => {
				let Some(Litep2pKademliaEvent::FindNodeSuccess { peers, .. }) = event else { continue };
				for (peer, addresses) in peers {
					let peer_id = PeerId::from(peer);
					let usable = allow_private_ip ||
						addresses.into_iter().any(|addr| is_global(&Multiaddr::from(addr)));
					if usable && discovered.insert(peer_id) {
						tracing::info!(target: LOG_TARGET, para_id, %peer_id, "Discovered a peer of para {para_id}.");
					}
				}
			},
			_ = discovery.tick(), if dht.is_some() => {
				if let Some(dht) = &mut dht {
					dht.handle.find_node(PeerId::random().into()).await;
				}
			},
		}
	}
}

/// Seed `dht` with the record in `value`, opening an instance first if the record names a DHT
/// `dht` is not on. A value that does not decode, a cleared record, or an instance that cannot be
/// opened leaves `dht` as it is.
async fn on_value(
	dht: &mut Option<Dht>,
	kademlia: &ClientKademlia,
	para_id: u32,
	allow_private_ip: bool,
	value: Option<Vec<u8>>,
) {
	let record = match decode(value.as_deref()) {
		Ok(Some(record)) => record,
		Ok(None) => return,
		Err(error) => {
			tracing::warn!(target: LOG_TARGET, para_id, ?error, "The para's bootnode record does not decode; keeping the DHT as it is.");
			return;
		},
	};
	if !dht.as_ref().is_some_and(|dht| dht.serves(&record)) {
		let fork_id = core::str::from_utf8(&record.fork_id).ok().filter(|id| !id.is_empty());
		let Some(handle) = kademlia.open(&record.genesis, fork_id).await else {
			tracing::warn!(target: LOG_TARGET, para_id, "Unable to join the para's DHT; keeping the DHT as it is.");
			return;
		};
		tracing::info!(target: LOG_TARGET, para_id, "Joined the para's DHT.");
		// Dropping the previous instance stops it.
		*dht = Some(Dht { handle, record: record.clone() });
	}
	if let Some(dht) = dht {
		dht.seed(&record, allow_private_ip).await;
	}
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
}
