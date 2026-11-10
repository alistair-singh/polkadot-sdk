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
//! litep2p starts Kademlia instances only when the network is created, so the records are read
//! once before that. A para without a record at that point gets no instance, and a record that
//! later needs a new one is a [`todo!`]: adding an instance at runtime needs litep2p support.
//!
//! The reader follows JAM's finalized chain, so it never acts on a value that is later reverted.
//!
//! `pallet-bootnodes` checks what it publishes, and the record's genesis hash can only be checked
//! there. The reader still skips what it could not use, since the other para's runtime is not
//! ours: an address [`pallet_bootnodes::multiaddr::validate`] rejects, and unless
//! `--allow-private-ip` applies an address with a non-global IP.

use super::LOG_TARGET;
use codec::DecodeAll;
use futures::StreamExt;
use ip_network::IpNetwork;
use jam_interface::{JamChainSource, JamStateSource, ServiceId};
use jam_rpc_interface::JamRpcInterface;
use pallet_bootnodes::{BootnodeRecord, BOOTNODES_KEY};
use sc_network::{
	config::{Litep2pKademliaEvent, Litep2pKademliaHandle},
	multiaddr::Protocol,
	Multiaddr, PeerId,
};
use std::{
	collections::{HashMap, HashSet},
	sync::Arc,
	time::Duration,
};

/// How often the reader asks a para's DHT for more of its peers.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// A client-mode Kademlia instance on a para's DHT.
pub(crate) struct Dht {
	handle: Litep2pKademliaHandle,
	/// The record the instance was opened for.
	record: BootnodeRecord,
}

impl Dht {
	/// Open an instance on the DHT `record` names, through `add`.
	pub(crate) fn open(
		record: BootnodeRecord,
		add: impl FnOnce(&[u8; 32], Option<&str>) -> Litep2pKademliaHandle,
	) -> Self {
		let fork_id = core::str::from_utf8(&record.fork_id).ok().filter(|id| !id.is_empty());
		let handle = add(&record.genesis, fork_id);
		Self { handle, record }
	}

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

/// The records of `paras` at JAM's finalized block, to open their DHTs before the network starts.
/// A para with no record, or that cannot be read, is left out.
pub(crate) fn records_at_startup(
	rpc_urls: &[url::Url],
	parachain_service: ServiceId,
	paras: &[u32],
	tokio_handle: tokio::runtime::Handle,
) -> HashMap<u32, BootnodeRecord> {
	if paras.is_empty() {
		return HashMap::new();
	}
	let read = async {
		let (jam, worker) = JamRpcInterface::new(rpc_urls.to_vec()).await?;
		tokio_handle.spawn(worker);
		let at = jam.finalized_block().await?.header_hash;
		let mut records = HashMap::new();
		for &para_id in paras {
			let key = pallet_jam_kv::kv_storage_key(para_id, BOOTNODES_KEY);
			let value = jam.service_value(at, parachain_service, &key).await?;
			match decode(value.as_deref()) {
				Ok(Some(record)) => {
					records.insert(para_id, record);
				},
				Ok(None) => {
					tracing::warn!(target: LOG_TARGET, para_id, "The para has no bootnode record yet, so this node cannot join its DHT.");
				},
				Err(error) => {
					tracing::warn!(target: LOG_TARGET, para_id, ?error, "The para's bootnode record does not decode, so this node cannot join its DHT.");
				},
			}
		}
		Ok::<_, Box<dyn std::error::Error>>(records)
	};
	match tokio::task::block_in_place(|| tokio_handle.block_on(read)) {
		Ok(records) => records,
		Err(error) => {
			tracing::error!(target: LOG_TARGET, %error, "Unable to read the bootnode records from JAM.");
			HashMap::new()
		},
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

/// Follow `para_id`'s published record at JAM's finalized block, and discover the para's peers
/// through `dht`, its open instance if any. Returns when the subscription ends.
///
/// A value that does not decode, or a cleared record, leaves the DHT as it is.
pub(crate) async fn follow<Jam: JamStateSource + ?Sized>(
	jam: Arc<Jam>,
	parachain_service: ServiceId,
	para_id: u32,
	allow_private_ip: bool,
	mut dht: Option<Dht>,
) {
	let key = pallet_jam_kv::kv_storage_key(para_id, BOOTNODES_KEY);
	let mut values = match jam.service_value_stream(parachain_service, &key, true).await {
		Ok(values) => values,
		Err(error) => {
			tracing::error!(target: LOG_TARGET, para_id, ?error, "Unable to follow the para's bootnodes on JAM.");
			return;
		},
	};
	tracing::info!(target: LOG_TARGET, para_id, "Following the para's bootnodes on JAM.");

	// The subscription only reports changes, so the record the instance was opened for seeds it.
	if let Some(dht) = &mut dht {
		let record = dht.record.clone();
		dht.seed(&record, allow_private_ip).await;
	}

	// Outlives evictions from the routing table, for the offchain-messaging requests to come.
	// TODO: cap the set. A responder can return fresh peer ids on every query.
	let mut discovered = HashSet::new();
	let mut discovery = tokio::time::interval(DISCOVERY_INTERVAL);
	loop {
		tokio::select! {
			update = values.next() => {
				let Some(update) = update else { break };
				let record = match decode(update.value.as_deref()) {
					Ok(Some(record)) => record,
					Ok(None) => continue,
					Err(error) => {
						tracing::warn!(target: LOG_TARGET, para_id, at = ?update.header_hash, ?error, "The para's bootnode record does not decode; keeping the DHT as it is.");
						continue;
					},
				};
				match &mut dht {
					Some(dht) if dht.serves(&record) => dht.seed(&record, allow_private_ip).await,
					_ => todo!("adding a Kademlia instance at runtime needs litep2p support"),
				}
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
	tracing::warn!(target: LOG_TARGET, para_id, "The subscription to the para's bootnodes ended.");
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

	/// A JAM source with scripted value updates. It records whether the reader asked for the
	/// finalized chain.
	#[derive(Default)]
	struct ScriptedJam {
		values: std::sync::Mutex<Vec<jam_interface::ChainSubUpdate<Option<Vec<u8>>>>>,
		finalized: std::sync::Mutex<Option<bool>>,
	}

	#[async_trait::async_trait]
	impl JamStateSource for ScriptedJam {
		async fn service_value_stream(
			&self,
			_service: ServiceId,
			_key: &[u8],
			finalized: bool,
		) -> jam_interface::Result<
			jam_interface::BoxStream<'static, jam_interface::ChainSubUpdate<Option<Vec<u8>>>>,
		> {
			*self.finalized.lock().unwrap() = Some(finalized);
			let updates = std::mem::take(&mut *self.values.lock().unwrap());
			// The value stream ends after its updates, which ends the reader.
			Ok(futures::stream::iter(updates).boxed())
		}

		async fn state_value(
			&self,
			_: jam_interface::HeaderHash,
			_: jam_interface::StorageKey,
		) -> jam_interface::Result<Option<Vec<u8>>> {
			unimplemented!("the reader only subscribes")
		}

		async fn state_value_stream(
			&self,
			_: jam_interface::StorageKey,
			_: bool,
		) -> jam_interface::Result<
			jam_interface::BoxStream<'static, jam_interface::ChainSubUpdate<Option<Vec<u8>>>>,
		> {
			unimplemented!("the reader only reads service values")
		}

		async fn state_proof(
			&self,
			_: jam_interface::HeaderHash,
			_: jam_interface::StorageKey,
			_: jam_interface::StorageKey,
			_: u32,
		) -> jam_interface::Result<jam_interface::RangeProof> {
			unimplemented!("the reader reads no proofs")
		}

		async fn service_value(
			&self,
			_: jam_interface::HeaderHash,
			_: ServiceId,
			_: &[u8],
		) -> jam_interface::Result<Option<Vec<u8>>> {
			unimplemented!("the reader only subscribes")
		}
	}

	impl ScriptedJam {
		fn with_values(values: impl IntoIterator<Item = Option<Vec<u8>>>) -> Arc<Self> {
			let values = values
				.into_iter()
				.map(|value| jam_interface::ChainSubUpdate {
					header_hash: Default::default(),
					slot: 0,
					value,
				})
				.collect();
			Arc::new(Self { values: std::sync::Mutex::new(values), ..Default::default() })
		}
	}

	/// A value that is later reverted must never be acted on. Garbage and a cleared record leave
	/// things as they are, so this run reaches the end of the stream.
	#[tokio::test]
	async fn the_reader_follows_finalized_jam_and_ignores_garbage() {
		let jam = ScriptedJam::with_values([None, Some(vec![0x04, 0xff])]);

		follow(jam.clone(), 1337, 0, true, None).await;
		assert_eq!(*jam.finalized.lock().unwrap(), Some(true));
	}
}
