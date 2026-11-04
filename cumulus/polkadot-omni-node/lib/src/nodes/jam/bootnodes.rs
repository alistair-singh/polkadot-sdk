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
//! The reader checks each entry's address the way `pallet-bootnodes` does
//! ([`pallet_bootnodes::multiaddr::validate`]), since root on the other para can write the value
//! without the pallet. It drops an entry once JAM's slot is past its `expiry_slot`, the consent
//! lease the operator signed: the set is checked again on every JAM block, not only when it
//! changes, so an entry expires even if the other para never writes again. The proof of
//! possession is not checked yet.

use super::LOG_TARGET;
use codec::Decode;
use futures::StreamExt;
use jam_interface::{JamChainSource, JamStateSource, ServiceId, Slot};
use pallet_bootnodes::BOOTNODES_KEY;
use sc_network::{multiaddr::Protocol, Multiaddr, PeerId};
use std::sync::Arc;

/// The address bound the reader decodes with. A runtime's own `MaxAddrLen` is smaller: the whole
/// set has to fit one key-value entry.
type Bootnode = pallet_bootnodes::Bootnode<sp_core::ConstU32<4096>>;

/// A listed node, as the network dials it.
pub(crate) type KnownBootnode = (PeerId, Multiaddr);

/// A dialable node and the last JAM slot its operator consented to being listed in.
pub(crate) type Leased = (KnownBootnode, u32);

/// The dialable nodes of a published set, with their leases; `None` is the empty set.
pub(crate) fn dialable(value: Option<&[u8]>) -> Result<Vec<Leased>, codec::Error> {
	let Some(mut value) = value else { return Ok(Vec::new()) };
	let set = Vec::<Bootnode>::decode(&mut value)?;
	Ok(set
		.iter()
		.filter_map(|bootnode| Some((known_bootnode(bootnode)?, bootnode.expiry_slot)))
		.collect())
}

/// The nodes whose lease still holds at `now`: an entry counts up to and including its
/// `expiry_slot`, the slot "after which readers drop the entry".
pub(crate) fn unexpired(set: &[Leased], now: Slot) -> Vec<KnownBootnode> {
	set.iter()
		.filter(|(_, expiry_slot)| now <= *expiry_slot)
		.map(|(node, _)| node.clone())
		.collect()
}

/// `addr/p2p/<peer id of node_key>`, or `None` for an entry the pallet would not have accepted
/// or no node could dial.
fn known_bootnode(bootnode: &Bootnode) -> Option<KnownBootnode> {
	let Some(peer_id) = PeerId::from_ed25519(&bootnode.node_key.0) else {
		tracing::debug!(target: LOG_TARGET, node_key = ?bootnode.node_key, "Skipping a bootnode: its node key is no ed25519 key.");
		return None;
	};
	// Also rejects a `/p2p/` component: the peer id comes from the node key, not the address.
	if let Err(error) = pallet_bootnodes::multiaddr::validate(&bootnode.addr) {
		tracing::debug!(target: LOG_TARGET, %peer_id, ?error, "Skipping a bootnode: its address is not one a bootnode may list.");
		return None;
	}
	let addr = match Multiaddr::try_from(bootnode.addr.to_vec()) {
		Ok(addr) => addr,
		Err(error) => {
			tracing::debug!(target: LOG_TARGET, %peer_id, ?error, "Skipping a bootnode: its address is no multiaddr.");
			return None;
		},
	};
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

/// What the reader follows: the other para's value, and JAM's clock.
enum Event {
	Value(jam_interface::ChainSubUpdate<Option<Vec<u8>>>),
	Block(jam_interface::BlockDesc),
}

/// Follow `para_id`'s published set at JAM's best block and pass every newly listed node to
/// `add_known_address`. Returns when either subscription ends.
///
/// A node that drops off the set, or whose lease expires, is only logged: the network has no
/// way to forget an address.
pub(crate) async fn follow<Jam: JamStateSource + JamChainSource + ?Sized>(
	jam: Arc<Jam>,
	parachain_service: ServiceId,
	para_id: u32,
	add_known_address: impl Fn(PeerId, Multiaddr),
) {
	let key = pallet_jam_kv::kv_storage_key(para_id, BOOTNODES_KEY);
	let streams = futures::try_join!(
		jam.service_value_stream(parachain_service, &key, false),
		jam.best_block_stream(),
	);
	let (values, blocks) = match streams {
		Ok(streams) => streams,
		Err(error) => {
			tracing::error!(target: LOG_TARGET, para_id, ?error, "Unable to follow the para's bootnodes on JAM.");
			return;
		},
	};
	tracing::info!(target: LOG_TARGET, para_id, "Following the para's bootnodes on JAM.");
	let (mut values, mut blocks) = (values.fuse(), blocks.fuse());

	let (mut set, mut now, mut listed) = (Vec::new(), 0, Listed::default());
	loop {
		// Either stream ending ends the reader: without values there is nothing to follow, and
		// without blocks no lease could expire.
		let event = futures::select! {
			update = values.next() => update.map(Event::Value),
			block = blocks.next() => block.map(Event::Block),
		};
		let Some(event) = event else { break };
		match event {
			Event::Value(update) => {
				now = now.max(update.slot);
				match dialable(update.value.as_deref()) {
					Ok(dialable) => set = dialable,
					Err(error) => {
						tracing::warn!(target: LOG_TARGET, para_id, at = ?update.header_hash, ?error, "The para's bootnode set does not decode; keeping the nodes listed before.");
						continue;
					},
				}
			},
			Event::Block(block) => now = now.max(block.slot),
		}
		let Change { added, removed } = listed.update(unexpired(&set, now));
		for (peer_id, addr) in added {
			tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = now, "Learned a bootnode of para {para_id}.");
			add_known_address(peer_id, addr);
		}
		for node in removed {
			let (peer_id, addr) = &node;
			if set.iter().any(|(listed, _)| *listed == node) {
				tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = now, "A bootnode of para {para_id} expired.");
			} else {
				tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = now, "A bootnode of para {para_id} is no longer listed.");
			}
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

	/// The dialable nodes of `value`, leases aside.
	fn nodes(value: Option<&[u8]>) -> Result<Vec<KnownBootnode>, codec::Error> {
		dialable(value).map(|set| set.into_iter().map(|(node, _)| node).collect())
	}

	fn known(seed: u8, addr: &str) -> KnownBootnode {
		let addr: Multiaddr = format!("{addr}/p2p/{}", peer(seed)).parse().expect("valid; qed");
		(peer(seed), addr)
	}

	#[test]
	fn every_entry_is_dialed_at_its_address_and_node_key() {
		let set = vec![entry(1, "/ip4/127.0.0.1/tcp/30333"), entry(2, "/dns/b.example/tcp/1/ws")];

		assert_eq!(
			nodes(Some(&set.encode())),
			Ok(vec![known(1, "/ip4/127.0.0.1/tcp/30333"), known(2, "/dns/b.example/tcp/1/ws")]),
		);
	}

	#[test]
	fn no_value_is_the_empty_set() {
		assert_eq!(nodes(None), Ok(vec![]));
	}

	#[test]
	fn a_value_that_is_no_set_is_an_error() {
		assert!(nodes(Some(&[0x04, 0xff])).is_err());
	}

	/// Root on the other para can write any set, so the reader skips every address the pallet
	/// would have rejected and keeps the rest. An address naming its own peer id would be
	/// dialed as someone else.
	#[test]
	fn entries_the_pallet_would_reject_are_skipped() {
		let mut garbage = entry(1, "/ip4/127.0.0.1/tcp/1");
		garbage.addr = vec![0xff, 0xff].try_into().expect("short; qed");
		let with_peer_id = entry(2, &format!("/ip4/127.0.0.1/tcp/2/p2p/{}", peer(9)));
		let udp = entry(3, "/ip4/127.0.0.1/udp/3/quic-v1");
		let memory = entry(4, "/memory/4");
		// `/ip4/127.0.0.1/tcp/5` with the ip4 code as a non-minimal varint.
		let mut non_canonical = entry(5, "/ip4/127.0.0.1/tcp/5");
		non_canonical.addr = [&[0x84, 0x00][..], &non_canonical.addr[1..]]
			.concat()
			.try_into()
			.expect("short; qed");
		let fine = entry(6, "/ip4/127.0.0.1/tcp/6");
		let set = vec![garbage, with_peer_id, udp, memory, non_canonical, fine];

		assert_eq!(nodes(Some(&set.encode())), Ok(vec![known(6, "/ip4/127.0.0.1/tcp/6")]));
	}

	#[test]
	fn every_entry_keeps_its_lease() {
		let (mut a, mut b) = (entry(1, "/ip4/127.0.0.1/tcp/1"), entry(2, "/ip4/127.0.0.1/tcp/2"));
		(a.expiry_slot, b.expiry_slot) = (7, u32::MAX);

		assert_eq!(
			dialable(Some(&vec![a, b].encode())),
			Ok(vec![
				(known(1, "/ip4/127.0.0.1/tcp/1"), 7),
				(known(2, "/ip4/127.0.0.1/tcp/2"), u32::MAX)
			]),
		);
	}

	/// An entry counts up to and including its `expiry_slot`; `u32::MAX` never expires.
	#[test]
	fn a_lease_holds_through_its_expiry_slot() {
		let (a, forever) = (known(1, "/ip4/127.0.0.1/tcp/1"), known(2, "/ip4/127.0.0.1/tcp/2"));
		let set = vec![(a.clone(), 7), (forever.clone(), u32::MAX)];

		assert_eq!(unexpired(&set, 0), vec![a.clone(), forever.clone()]);
		assert_eq!(unexpired(&set, 7), vec![a, forever.clone()]);
		assert_eq!(unexpired(&set, 8), vec![forever.clone()]);
		assert_eq!(unexpired(&set, u32::MAX), vec![forever]);
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
