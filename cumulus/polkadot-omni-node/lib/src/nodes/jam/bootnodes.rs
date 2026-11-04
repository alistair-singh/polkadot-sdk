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
//! A para running `pallet-bootnodes` publishes its set to its JAM key-value store under
//! [`BOOTNODES_KEY`]. The reader follows that value on the parachain service and hands every
//! listed node to the network as a known address, `addr/p2p/<peer id of node_key>`, so this
//! node can dial the other para's nodes.
//!
//! Entries are not checked yet: the proof of possession and `expiry_slot` are ignored, so a
//! reader trusts whatever the other para's admin listed. Only entries that cannot be dialed at
//! all are skipped.

use super::LOG_TARGET;
use codec::Decode;
use futures::StreamExt;
use jam_interface::{JamStateSource, ServiceId};
use pallet_bootnodes::BOOTNODES_KEY;
use sc_network::{multiaddr::Protocol, Multiaddr, PeerId};
use std::sync::Arc;

/// The address bound the reader decodes with. A runtime's own `MaxAddrLen` is smaller: the whole
/// set has to fit one key-value entry.
type Bootnode = pallet_bootnodes::Bootnode<sp_core::ConstU32<4096>>;

/// A listed node, as the network dials it.
pub(crate) type KnownBootnode = (PeerId, Multiaddr);

/// The dialable nodes of a published set; `None` is the empty set.
pub(crate) fn dialable(value: Option<&[u8]>) -> Result<Vec<KnownBootnode>, codec::Error> {
	let Some(mut value) = value else { return Ok(Vec::new()) };
	let set = Vec::<Bootnode>::decode(&mut value)?;
	Ok(set.iter().filter_map(known_bootnode).collect())
}

/// `addr/p2p/<peer id of node_key>`, or `None` for an entry no node could dial.
fn known_bootnode(bootnode: &Bootnode) -> Option<KnownBootnode> {
	let Some(peer_id) = PeerId::from_ed25519(&bootnode.node_key.0) else {
		tracing::debug!(target: LOG_TARGET, node_key = ?bootnode.node_key, "Skipping a bootnode: its node key is no ed25519 key.");
		return None;
	};
	let addr = match Multiaddr::try_from(bootnode.addr.to_vec()) {
		Ok(addr) => addr,
		Err(error) => {
			tracing::debug!(target: LOG_TARGET, %peer_id, ?error, "Skipping a bootnode: its address is no multiaddr.");
			return None;
		},
	};
	if addr.iter().any(|protocol| matches!(protocol, Protocol::P2p(_))) {
		tracing::debug!(target: LOG_TARGET, %peer_id, %addr, "Skipping a bootnode: the peer id comes from the node key, not the address.");
		return None;
	}
	Some((peer_id, addr.with(Protocol::P2p(peer_id.into()))))
}

/// What one update of a para's set changed.
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

/// Follow `para_id`'s published set at JAM's best block and pass every newly listed node to
/// `add_known_address`. Returns when the subscription ends.
///
/// A node that drops off the set is only logged: the network has no way to forget an address.
pub(crate) async fn follow<Jam: JamStateSource + ?Sized>(
	jam: Arc<Jam>,
	parachain_service: ServiceId,
	para_id: u32,
	add_known_address: impl Fn(PeerId, Multiaddr),
) {
	let key = pallet_jam_kv::kv_storage_key(para_id, BOOTNODES_KEY);
	let mut updates = match jam.service_value_stream(parachain_service, &key, false).await {
		Ok(updates) => updates,
		Err(error) => {
			tracing::error!(target: LOG_TARGET, para_id, ?error, "Unable to follow the para's bootnodes on JAM.");
			return;
		},
	};
	tracing::info!(target: LOG_TARGET, para_id, "Following the para's bootnodes on JAM.");

	let mut listed = Listed::default();
	while let Some(update) = updates.next().await {
		let now = match dialable(update.value.as_deref()) {
			Ok(now) => now,
			Err(error) => {
				tracing::warn!(target: LOG_TARGET, para_id, at = ?update.header_hash, ?error, "The para's bootnode set does not decode; keeping the nodes listed before.");
				continue;
			},
		};
		let Change { added, removed } = listed.update(now);
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

	fn entry(seed: u8, addr: &str) -> Bootnode {
		let pair = ed25519::Pair::from_seed(&[seed; 32]);
		let addr: Multiaddr = addr.parse().expect("the test's addresses parse; qed");
		Bootnode {
			addr: addr.to_vec().try_into().expect("the test's addresses are short; qed"),
			node_key: pair.public(),
			expiry_slot: 0,
			sig: ed25519::Signature::from_raw([0; 64]),
		}
	}

	fn peer(seed: u8) -> PeerId {
		let public = ed25519::Pair::from_seed(&[seed; 32]).public();
		PeerId::from_ed25519(&public.0).expect("an ed25519 key is a peer id; qed")
	}

	fn known(seed: u8, addr: &str) -> KnownBootnode {
		let addr: Multiaddr = format!("{addr}/p2p/{}", peer(seed)).parse().expect("valid; qed");
		(peer(seed), addr)
	}

	#[test]
	fn every_entry_is_dialed_at_its_address_and_node_key() {
		let set = vec![entry(1, "/ip4/127.0.0.1/tcp/30333"), entry(2, "/dns/b.example/tcp/1/ws")];

		assert_eq!(
			dialable(Some(&set.encode())),
			Ok(vec![known(1, "/ip4/127.0.0.1/tcp/30333"), known(2, "/dns/b.example/tcp/1/ws")]),
		);
	}

	#[test]
	fn no_value_is_the_empty_set() {
		assert_eq!(dialable(None), Ok(vec![]));
	}

	#[test]
	fn a_value_that_is_no_set_is_an_error() {
		assert!(dialable(Some(&[0x04, 0xff])).is_err());
	}

	/// The reader checks nothing yet, but it can only dial what parses, and the peer id has to be
	/// the one the node key gives: an address naming its own would be dialed as someone else.
	#[test]
	fn entries_no_node_could_dial_are_skipped() {
		let mut garbage = entry(1, "/ip4/127.0.0.1/tcp/1");
		garbage.addr = vec![0xff, 0xff].try_into().expect("short; qed");
		let with_peer_id = entry(2, &format!("/ip4/127.0.0.1/tcp/2/p2p/{}", peer(9)));
		let fine = entry(3, "/ip4/127.0.0.1/tcp/3");

		assert_eq!(
			dialable(Some(&vec![garbage, with_peer_id, fine].encode())),
			Ok(vec![known(3, "/ip4/127.0.0.1/tcp/3")]),
		);
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
