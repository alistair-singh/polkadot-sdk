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
//! It follows JAM's finalized chain, so it never acts on a value that is later reverted. That
//! only delays a change to the set by JAM's finality lag: connections already made stay up.
//!
//! The reader checks each entry the way `pallet-bootnodes` does, since root on the other para can
//! write the value without the pallet: the address ([`pallet_bootnodes::multiaddr::validate`]),
//! the lease and the proof of possession. The proof binds the JAM genesis hash, and the reader
//! checks it against its own para's value, read through the `BootnodesApi` runtime API: both paras
//! are on the same JAM. Without that value every entry is dropped. An entry is dropped once JAM's
//! slot is past its `expiry_slot`, the consent lease the operator signed. The set is checked again
//! on every finalized JAM block, not only when it changes, so an entry expires even if the other
//! para never writes again, and the reader picks up its own para's hash once root sets it.

use super::LOG_TARGET;
use codec::Decode;
use futures::StreamExt;
use jam_interface::{JamChainSource, JamStateSource, ServiceId, Slot};
use pallet_bootnodes::BOOTNODES_KEY;
use sc_network::{multiaddr::Protocol, Multiaddr, PeerId};
use sp_core::{ed25519, Pair as _, H256};
use std::sync::Arc;

/// The address bound the reader decodes with. A runtime's own `MaxAddrLen` is smaller: the whole
/// set has to fit one key-value entry.
type Bootnode = pallet_bootnodes::Bootnode<sp_core::ConstU32<4096>>;

/// A listed node, as the network dials it.
pub(crate) type KnownBootnode = (PeerId, Multiaddr);

/// The `BootnodesApi` method the reader calls on its own para.
pub(crate) const JAM_GENESIS_HASH_API: &str = "BootnodesApi_jam_genesis_hash";

/// The entries of a published set; `None` is the empty set.
pub(crate) fn decode(value: Option<&[u8]>) -> Result<Vec<Bootnode>, codec::Error> {
	let Some(mut value) = value else { return Ok(Vec::new()) };
	Vec::<Bootnode>::decode(&mut value)
}

/// The nodes of `para_id`'s `set` to dial at JAM slot `now`: the entries with a valid address, a
/// lease that still holds and a proof of possession under `jam_genesis_hash`.
pub(crate) fn dialable(
	set: &[Bootnode],
	para_id: u32,
	jam_genesis_hash: &H256,
	now: Slot,
) -> Vec<KnownBootnode> {
	set.iter()
		.filter(|bootnode| holds_at(bootnode, now))
		.filter(|bootnode| proves_possession(bootnode, para_id, jam_genesis_hash))
		.filter_map(known_bootnode)
		.collect()
}

/// Whether `bootnode`'s lease holds at `now`: an entry counts up to and including its
/// `expiry_slot`, the slot "after which readers drop the entry".
fn holds_at(bootnode: &Bootnode, now: Slot) -> bool {
	now <= bootnode.expiry_slot
}

/// Whether `bootnode.sig` is its node's signature over the payload `pallet-bootnodes` defines.
fn proves_possession(bootnode: &Bootnode, para_id: u32, jam_genesis_hash: &H256) -> bool {
	let payload = pallet_bootnodes::pop_payload(
		jam_genesis_hash,
		para_id,
		&bootnode.addr,
		bootnode.expiry_slot,
	);
	let valid = ed25519::Pair::verify(&bootnode.sig, &payload, &bootnode.node_key);
	if !valid {
		tracing::debug!(target: LOG_TARGET, para_id, node_key = ?bootnode.node_key, "Skipping a bootnode: its proof of possession does not verify.");
	}
	valid
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

/// Follow `para_id`'s published set at JAM's finalized block and pass every newly listed node to
/// `add_known_address`. Returns when either subscription ends.
///
/// `own_jam_genesis_hash` reads this node's own para's JAM genesis hash, the value proofs of
/// possession are checked against; it is called on every event, so a hash set after launch takes
/// effect.
///
/// A node that drops off the set, whose lease expires or whose proof stops verifying is only
/// logged: the network has no way to forget an address.
pub(crate) async fn follow<Jam: JamStateSource + JamChainSource + ?Sized>(
	jam: Arc<Jam>,
	parachain_service: ServiceId,
	para_id: u32,
	own_jam_genesis_hash: impl Fn() -> Option<H256>,
	add_known_address: impl Fn(PeerId, Multiaddr),
) {
	let key = pallet_jam_kv::kv_storage_key(para_id, BOOTNODES_KEY);
	let streams = futures::try_join!(
		jam.service_value_stream(parachain_service, &key, true),
		jam.finalized_block_stream(),
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
	let mut had_hash = true;
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
				match decode(update.value.as_deref()) {
					Ok(decoded) => set = decoded,
					Err(error) => {
						tracing::warn!(target: LOG_TARGET, para_id, at = ?update.header_hash, ?error, "The para's bootnode set does not decode; keeping the nodes listed before.");
						continue;
					},
				}
			},
			Event::Block(block) => now = now.max(block.slot),
		}
		let jam_genesis_hash = own_jam_genesis_hash();
		if jam_genesis_hash.is_some() != had_hash {
			had_hash = jam_genesis_hash.is_some();
			if had_hash {
				tracing::info!(target: LOG_TARGET, para_id, "This para's JAM genesis hash is set; checking the para's bootnodes against it.");
			} else {
				tracing::warn!(target: LOG_TARGET, para_id, "This para has no JAM genesis hash to check proofs of possession against; dropping every bootnode of the para.");
			}
		}
		let current = jam_genesis_hash
			.map(|hash| dialable(&set, para_id, &hash, now))
			.unwrap_or_default();
		let Change { added, removed } = listed.update(current);
		for (peer_id, addr) in added {
			tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = now, "Learned a bootnode of para {para_id}.");
			add_known_address(peer_id, addr);
		}
		for node in removed {
			let (peer_id, addr) = &node;
			let still_listed =
				set.iter().find(|bootnode| known_bootnode(bootnode).as_ref() == Some(&node));
			match still_listed {
				None => {
					tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = now, "A bootnode of para {para_id} is no longer listed.")
				},
				Some(bootnode) if !holds_at(bootnode, now) => {
					tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = now, "A bootnode of para {para_id} expired.")
				},
				Some(_) => {
					tracing::info!(target: LOG_TARGET, para_id, %peer_id, %addr, slot = now, "A bootnode of para {para_id} no longer proves possession.")
				},
			}
		}
	}
	tracing::warn!(target: LOG_TARGET, para_id, "The subscription to the para's bootnodes ended.");
}

/// This node's own para's JAM genesis hash, from `BootnodesApi` at its finalized block. `None`
/// when the runtime has no such API or no hash set.
pub(crate) fn own_jam_genesis_hash<Block, Client>(client: &Client) -> Option<H256>
where
	Block: sp_runtime::traits::Block,
	Client: sc_client_api::ExecutorProvider<Block> + sp_blockchain::HeaderBackend<Block>,
{
	use sc_client_api::CallExecutor as _;
	let at = client.info().finalized_hash;
	let call = client.executor().call(
		at,
		JAM_GENESIS_HASH_API,
		&[],
		sp_core::traits::CallContext::Offchain,
	);
	match call {
		Ok(raw) => Option::<H256>::decode(&mut &raw[..]).ok().flatten(),
		Err(error) => {
			tracing::trace!(target: LOG_TARGET, ?error, "This para's runtime has no {JAM_GENESIS_HASH_API}.");
			None
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;

	/// The JAM genesis hash and source para the tests sign for.
	const HASH: H256 = H256::repeat_byte(0x4a);
	const PARA: u32 = 0;

	fn pair(seed: u8) -> ed25519::Pair {
		ed25519::Pair::from_seed(&[seed; 32])
	}

	/// An entry for `seed`'s key over the raw `addr`, with a valid proof of possession for [`PARA`]
	/// under [`HASH`].
	fn signed_raw(seed: u8, addr: Vec<u8>, expiry_slot: u32) -> Bootnode {
		let addr: sp_runtime::BoundedVec<u8, sp_core::ConstU32<4096>> =
			addr.try_into().expect("the test's addresses are short; qed");
		let payload = pallet_bootnodes::pop_payload(&HASH, PARA, &addr, expiry_slot);
		Bootnode {
			addr,
			node_key: pair(seed).public(),
			expiry_slot,
			sig: pair(seed).sign(&payload),
		}
	}

	fn entry_until(seed: u8, addr: &str, expiry_slot: u32) -> Bootnode {
		let addr: Multiaddr = addr.parse().expect("the test's addresses parse; qed");
		signed_raw(seed, addr.to_vec(), expiry_slot)
	}

	/// A signed entry whose lease never ends.
	fn entry(seed: u8, addr: &str) -> Bootnode {
		entry_until(seed, addr, u32::MAX)
	}

	fn peer(seed: u8) -> PeerId {
		PeerId::from_ed25519(&pair(seed).public().0).expect("an ed25519 key is a peer id; qed")
	}

	/// The nodes of `value` to dial at slot 0, for [`PARA`] under [`HASH`].
	fn nodes(value: Option<&[u8]>) -> Result<Vec<KnownBootnode>, codec::Error> {
		decode(value).map(|set| dialable(&set, PARA, &HASH, 0))
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
		assert!(decode(Some(&[0x04, 0xff])).is_err());
	}

	/// Root on the other para can write any set, so the reader skips every address the pallet
	/// would have rejected and keeps the rest. Each entry's proof is valid, over its own bytes.
	/// An address naming its own peer id would be dialed as someone else.
	#[test]
	fn entries_the_pallet_would_reject_are_skipped() {
		let address = |addr: &str| addr.parse::<Multiaddr>().expect("valid; qed").to_vec();
		let garbage = signed_raw(1, vec![0xff, 0xff], u32::MAX);
		let with_peer_id = entry(2, &format!("/ip4/127.0.0.1/tcp/2/p2p/{}", peer(9)));
		let udp = entry(3, "/ip4/127.0.0.1/udp/3/quic-v1");
		let memory = entry(4, "/memory/4");
		// `/ip4/127.0.0.1/tcp/5` with the ip4 code as a non-minimal varint.
		let non_canonical = address("/ip4/127.0.0.1/tcp/5");
		let non_canonical =
			signed_raw(5, [&[0x84, 0x00][..], &non_canonical[1..]].concat(), u32::MAX);
		let fine = entry(6, "/ip4/127.0.0.1/tcp/6");
		let set = vec![garbage, with_peer_id, udp, memory, non_canonical, fine];

		assert_eq!(nodes(Some(&set.encode())), Ok(vec![known(6, "/ip4/127.0.0.1/tcp/6")]));
	}

	/// The proof must be the node's own signature, for the source para, under this para's JAM
	/// genesis hash, with the domain separator.
	#[test]
	fn entries_without_a_valid_proof_of_possession_are_skipped() {
		let good = entry(1, "/ip4/127.0.0.1/tcp/1");
		let sign = |payload: &[u8]| pair(2).sign(payload);
		let pop = |hash: &H256, para: u32| {
			pallet_bootnodes::pop_payload(hash, para, &good.addr, good.expiry_slot)
		};

		let mut another_key = entry(2, "/ip4/127.0.0.1/tcp/2");
		another_key.sig = pair(3).sign(&pop(&HASH, PARA));
		let mut another_para = entry(2, "/ip4/127.0.0.1/tcp/2");
		another_para.sig =
			sign(&pallet_bootnodes::pop_payload(&HASH, PARA + 1, &another_para.addr, u32::MAX));
		let mut another_chain = entry(2, "/ip4/127.0.0.1/tcp/2");
		another_chain.sig = sign(&pallet_bootnodes::pop_payload(
			&H256::zero(),
			PARA,
			&another_chain.addr,
			u32::MAX,
		));
		let mut no_domain = entry(2, "/ip4/127.0.0.1/tcp/2");
		no_domain.sig = sign(&(HASH, PARA, no_domain.addr.to_vec(), u32::MAX).encode());

		for bad in [another_key, another_para, another_chain, no_domain] {
			let set = vec![bad, good.clone()];
			assert_eq!(nodes(Some(&set.encode())), Ok(vec![known(1, "/ip4/127.0.0.1/tcp/1")]));
		}
	}

	/// An entry counts up to and including its `expiry_slot`; `u32::MAX` never expires.
	#[test]
	fn a_lease_holds_through_its_expiry_slot() {
		let set = vec![entry_until(1, "/ip4/127.0.0.1/tcp/1", 7), entry(2, "/ip4/127.0.0.1/tcp/2")];
		let (a, forever) = (known(1, "/ip4/127.0.0.1/tcp/1"), known(2, "/ip4/127.0.0.1/tcp/2"));
		let at = |now| dialable(&set, PARA, &HASH, now);

		assert_eq!(at(0), vec![a.clone(), forever.clone()]);
		assert_eq!(at(7), vec![a, forever.clone()]);
		assert_eq!(at(8), vec![forever.clone()]);
		assert_eq!(at(u32::MAX), vec![forever]);
	}

	/// A JAM source with scripted value updates. It records whether the reader asked for the
	/// finalized chain, and fails the test if the reader asks for the best one.
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

	#[async_trait::async_trait]
	impl JamChainSource for ScriptedJam {
		async fn finalized_block_stream(
			&self,
		) -> jam_interface::Result<jam_interface::BoxStream<'static, jam_interface::BlockDesc>>
		{
			Ok(futures::stream::pending().boxed())
		}

		async fn best_block_stream(
			&self,
		) -> jam_interface::Result<jam_interface::BoxStream<'static, jam_interface::BlockDesc>>
		{
			panic!("the reader must follow JAM's finalized chain, not its best block");
		}

		async fn best_block(&self) -> jam_interface::Result<jam_interface::BlockDesc> {
			unimplemented!()
		}

		async fn finalized_block(&self) -> jam_interface::Result<jam_interface::BlockDesc> {
			unimplemented!()
		}

		async fn parent(
			&self,
			_: jam_interface::HeaderHash,
		) -> jam_interface::Result<jam_interface::BlockDesc> {
			unimplemented!()
		}

		async fn header(&self, _: jam_interface::HeaderHash) -> jam_interface::Result<Vec<u8>> {
			unimplemented!()
		}

		async fn state_root(
			&self,
			_: jam_interface::HeaderHash,
		) -> jam_interface::Result<jam_interface::StateRootHash> {
			unimplemented!()
		}

		async fn beefy_root(
			&self,
			_: jam_interface::HeaderHash,
		) -> jam_interface::Result<jam_interface::MmrPeakHash> {
			unimplemented!()
		}

		async fn parameters(&self) -> jam_interface::Result<jam_interface::VersionedParameters> {
			unimplemented!()
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

	/// Run the reader over `jam`'s scripted updates, with this para's hash from `own_hash`; the
	/// nodes it handed to the network, in order.
	async fn learned_with(
		jam: Arc<ScriptedJam>,
		own_hash: impl Fn() -> Option<H256>,
	) -> Vec<KnownBootnode> {
		let learned = std::sync::Mutex::new(Vec::new());
		follow(jam, 1337, PARA, own_hash, |peer_id, addr| {
			learned.lock().unwrap().push((peer_id, addr))
		})
		.await;
		learned.into_inner().unwrap()
	}

	async fn learned(jam: Arc<ScriptedJam>) -> Vec<KnownBootnode> {
		learned_with(jam, || Some(HASH)).await
	}

	/// A value that is later reverted must never be dialed, so the reader subscribes to the
	/// finalized chain, for the value and for the clock its leases are checked against.
	#[tokio::test]
	async fn the_reader_follows_finalized_jam() {
		let jam = ScriptedJam::with_values([Some(vec![entry(1, "/ip4/127.0.0.1/tcp/1")].encode())]);

		assert_eq!(learned(jam.clone()).await, vec![known(1, "/ip4/127.0.0.1/tcp/1")]);
		assert_eq!(*jam.finalized.lock().unwrap(), Some(true));
	}

	/// Message delivery matters more than which node delivers: a value that does not decode
	/// keeps the nodes listed before, so the reader does not forget peers it can still use.
	#[tokio::test]
	async fn a_value_that_does_not_decode_keeps_the_nodes_listed_before() {
		let (a, b) = (entry(1, "/ip4/127.0.0.1/tcp/1"), entry(2, "/ip4/127.0.0.1/tcp/2"));
		let jam = ScriptedJam::with_values([
			Some(vec![a.clone()].encode()),
			Some(vec![0x04, 0xff]),
			Some(vec![a, b].encode()),
		]);

		// Had the garbage cleared the set, the last update would hand `a` to the network again.
		assert_eq!(
			learned(jam).await,
			vec![known(1, "/ip4/127.0.0.1/tcp/1"), known(2, "/ip4/127.0.0.1/tcp/2")],
		);
	}

	/// Without its own para's JAM genesis hash the reader cannot check a proof, so it dials
	/// nothing; once root sets the hash, the same set is checked against it.
	#[tokio::test]
	async fn the_reader_needs_its_own_jam_genesis_hash() {
		let set = Some(vec![entry(1, "/ip4/127.0.0.1/tcp/1")].encode());
		assert_eq!(learned_with(ScriptedJam::with_values([set.clone()]), || None).await, vec![]);

		// The hash is set between the first and the second update of an unchanged set.
		let calls = std::sync::atomic::AtomicUsize::new(0);
		let own_hash = || {
			let call = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			(call > 0).then_some(HASH)
		};
		let jam = ScriptedJam::with_values([set.clone(), set]);
		assert_eq!(learned_with(jam, own_hash).await, vec![known(1, "/ip4/127.0.0.1/tcp/1")]);
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
