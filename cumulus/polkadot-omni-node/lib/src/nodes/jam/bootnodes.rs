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
//! under [`BOOTNODES_KEY`]. The reader follows that value on the parachain service and hands every
//! address in it to the network as a known address, so this node can dial the other para's nodes.
//!
//! It follows JAM's finalized chain, so it never acts on a value that is later reverted. That
//! only delays a change to the record by JAM's finality lag: connections already made stay up.
//!
//! `pallet-bootnodes` checks what it publishes, and the record's genesis hash can only be checked
//! there. The reader still skips what it could not dial, since the other para's runtime is not
//! ours: an address [`pallet_bootnodes::multiaddr::validate`] rejects, and unless
//! `--allow-private-ip` is set an address with a non-global IP.

use super::LOG_TARGET;
use codec::DecodeAll;
use futures::StreamExt;
use ip_network::IpNetwork;
use jam_interface::{JamStateSource, ServiceId};
use pallet_bootnodes::{BootnodeRecord, BOOTNODES_KEY};
use sc_network::{multiaddr::Protocol, Multiaddr, PeerId};
use std::sync::Arc;

/// A listed node, as the network dials it.
pub(crate) type KnownBootnode = (PeerId, Multiaddr);

/// The record in a published value; `None` when nothing is published.
pub(crate) fn decode(value: Option<&[u8]>) -> Result<Option<BootnodeRecord>, codec::Error> {
	value.map(|mut value| BootnodeRecord::decode_all(&mut value)).transpose()
}

/// The nodes of `record` to dial.
pub(crate) fn dialable(
	record: Option<&BootnodeRecord>,
	allow_private_ip: bool,
) -> Vec<KnownBootnode> {
	record
		.into_iter()
		.flat_map(|record| record.addresses.iter())
		.filter_map(|address| known_bootnode(address, allow_private_ip))
		.collect()
}

/// The peer `address` names and the address itself, or `None` for one this node should not dial.
fn known_bootnode(address: &[u8], allow_private_ip: bool) -> Option<KnownBootnode> {
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

/// What one update of a para's record changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Change {
	pub added: Vec<KnownBootnode>,
	pub removed: Vec<KnownBootnode>,
}

/// The nodes of one para the reader has handed to the network.
#[derive(Debug, Default)]
pub(crate) struct Listed(Vec<KnownBootnode>);

impl Listed {
	/// Replace the listed nodes with `now`, and say which were added and which are gone.
	pub(crate) fn update(&mut self, now: Vec<KnownBootnode>) -> Change {
		let added = now.iter().filter(|node| !self.0.contains(node)).cloned().collect();
		let removed = self.0.iter().filter(|node| !now.contains(node)).cloned().collect();
		self.0 = now;
		Change { added, removed }
	}
}

/// Follow `para_id`'s published record at JAM's finalized block and pass every newly listed node to
/// `add_known_address`. Returns when the subscription ends.
///
/// A node that drops off the record is only logged: the network has no way to forget an address. A
/// value that does not decode keeps the nodes listed before.
pub(crate) async fn follow<Jam: JamStateSource + ?Sized>(
	jam: Arc<Jam>,
	parachain_service: ServiceId,
	para_id: u32,
	allow_private_ip: bool,
	add_known_address: impl Fn(PeerId, Multiaddr),
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

	let mut listed = Listed::default();
	while let Some(update) = values.next().await {
		let record = match decode(update.value.as_deref()) {
			Ok(record) => record,
			Err(error) => {
				tracing::warn!(target: LOG_TARGET, para_id, at = ?update.header_hash, ?error, "The para's bootnode record does not decode; keeping the nodes listed before.");
				continue;
			},
		};
		let Change { added, removed } = listed.update(dialable(record.as_ref(), allow_private_ip));
		for (peer_id, addr) in added {
			tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = update.slot, "Learned a bootnode of para {para_id}.");
			add_known_address(peer_id, addr);
		}
		for (peer_id, addr) in removed {
			tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = update.slot, "A bootnode of para {para_id} is no longer listed.");
		}
	}
	tracing::warn!(target: LOG_TARGET, para_id, "The subscription to the para's bootnodes ended.");
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use sp_core::{ed25519, Pair as _};

	/// The para the tests follow.
	const PARA: u32 = 0;

	fn peer(seed: u8) -> PeerId {
		let pair = ed25519::Pair::from_seed(&[seed; 32]);
		PeerId::from_ed25519(&pair.public().0).expect("an ed25519 key is a peer id; qed")
	}

	fn address(seed: u8, addr: &str) -> Multiaddr {
		format!("{addr}/p2p/{}", peer(seed))
			.parse()
			.expect("the test's addresses parse; qed")
	}

	fn known(seed: u8, addr: &str) -> KnownBootnode {
		(peer(seed), address(seed, addr))
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

	fn value(addresses: &[(u8, &str)]) -> Option<Vec<u8>> {
		Some(record(addresses).encode())
	}

	#[test]
	fn every_address_is_dialed_as_the_peer_it_names() {
		let record = record(&[(1, "/ip4/8.8.8.8/tcp/30333"), (2, "/dns/b.example.org/tcp/1/ws")]);

		assert_eq!(
			dialable(Some(&record), false),
			vec![known(1, "/ip4/8.8.8.8/tcp/30333"), known(2, "/dns/b.example.org/tcp/1/ws")],
		);
	}

	#[test]
	fn no_value_is_no_record() {
		assert_eq!(decode(None), Ok(None));
		assert_eq!(dialable(None, false), vec![]);
	}

	#[test]
	fn a_value_that_is_no_record_is_an_error() {
		assert!(decode(Some(&[0x04, 0xff])).is_err());
		let mut trailing = record(&[(1, "/ip4/8.8.8.8/tcp/1")]).encode();
		trailing.push(0);
		assert!(decode(Some(&trailing)).is_err());
	}

	/// The other para's runtime is not ours, so what it publishes is not trusted to be dialable.
	#[test]
	fn addresses_the_pallet_would_reject_are_skipped() {
		let no_peer = "/ip4/8.8.8.8/tcp/1".parse::<Multiaddr>().unwrap().to_vec();
		let udp = address(2, "/ip4/8.8.8.8/udp/1/quic-v1").to_vec();
		let localhost = address(3, "/dns/localhost/tcp/1").to_vec();
		let good = address(4, "/ip4/8.8.8.8/tcp/1");
		let record = record_of(vec![no_peer, vec![0xff, 0xff], udp, localhost, good.to_vec()]);

		assert_eq!(dialable(Some(&record), true), vec![(peer(4), good)]);
	}

	#[test]
	fn a_non_global_ip_is_skipped_unless_allowed() {
		let private = [
			(1, "/ip4/127.0.0.1/tcp/1"),
			(2, "/ip4/10.0.0.1/tcp/1"),
			(3, "/ip4/192.168.1.1/tcp/1/ws"),
			(4, "/ip6/::1/tcp/1"),
			(5, "/ip6/fe80::1/tcp/1"),
		];
		let global = (6, "/ip4/8.8.8.8/tcp/1");
		let hostname = (7, "/dns/b.example.org/tcp/1");
		let record =
			record(&[private[0], private[1], private[2], private[3], private[4], global, hostname]);

		assert_eq!(
			dialable(Some(&record), false),
			vec![known(global.0, global.1), known(hostname.0, hostname.1)],
		);
		assert_eq!(dialable(Some(&record), true).len(), 7);
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

	/// Run the reader over `jam`'s scripted updates; the nodes it handed to the network, in order.
	async fn learned(jam: Arc<ScriptedJam>) -> Vec<KnownBootnode> {
		let learned = std::sync::Mutex::new(Vec::new());
		follow(jam, 1337, PARA, true, |peer_id, addr| {
			learned.lock().unwrap().push((peer_id, addr))
		})
		.await;
		learned.into_inner().unwrap()
	}

	/// A value that is later reverted must never be dialed.
	#[tokio::test]
	async fn the_reader_follows_finalized_jam() {
		let jam = ScriptedJam::with_values([value(&[(1, "/ip4/127.0.0.1/tcp/1")])]);

		assert_eq!(learned(jam.clone()).await, vec![known(1, "/ip4/127.0.0.1/tcp/1")]);
		assert_eq!(*jam.finalized.lock().unwrap(), Some(true));
	}

	/// Message delivery matters more than which node delivers: a value that does not decode
	/// keeps the nodes listed before, so the reader does not forget peers it can still use.
	#[tokio::test]
	async fn a_value_that_does_not_decode_keeps_the_nodes_listed_before() {
		let (a, b) = ((1, "/ip4/127.0.0.1/tcp/1"), (2, "/ip4/127.0.0.1/tcp/2"));
		let jam = ScriptedJam::with_values([value(&[a]), Some(vec![0x04, 0xff]), value(&[a, b])]);

		// Had the garbage cleared the set, the last update would hand `a` to the network again.
		assert_eq!(learned(jam).await, vec![known(a.0, a.1), known(b.0, b.1)]);
	}

	/// The reader hands each node to the network once, and names the ones that left the set.
	#[test]
	fn an_update_reports_what_it_added_and_removed() {
		let (a, b) = (known(1, "/ip4/127.0.0.1/tcp/1"), known(2, "/ip4/127.0.0.1/tcp/2"));
		let a_moved = known(1, "/ip4/127.0.0.1/tcp/9");
		let mut listed = Listed::default();

		assert_eq!(
			listed.update(vec![a.clone()]),
			Change { added: vec![a.clone()], removed: vec![] }
		);
		assert_eq!(
			listed.update(vec![a.clone(), b.clone()]),
			Change { added: vec![b.clone()], removed: vec![] },
		);
		assert_eq!(
			listed.update(vec![a_moved.clone(), b.clone()]),
			Change { added: vec![a_moved.clone()], removed: vec![a] },
		);
		assert_eq!(listed.update(vec![]), Change { added: vec![], removed: vec![a_moved, b] });
		assert_eq!(listed.update(vec![]), Change::default());
	}
}
