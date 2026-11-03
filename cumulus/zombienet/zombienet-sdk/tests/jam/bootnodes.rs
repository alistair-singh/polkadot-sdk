// This file is part of Cumulus.

// Copyright (C) Parity Technologies (UK) Ltd.
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

//! A para's bootnode set is published to JAM and can be read back.
//!
//! Every `Bootnodes::add_bootnode` / `remove_bootnode` publishes the SCALE-encoded set through
//! `JamKv` under [`BOOTNODES_KEY`], or removes the key once the set is empty. The test lists two
//! bootnodes with sudo, replaces one, removes both, and after each change waits for
//! `serviceValue` on the Parachain Service to hold exactly the set the para now stores.
//!
//! `pallet-bootnodes` does not check entries yet. The entries are signed under the runtime's
//! placeholder JAM genesis hash, `H256::zero()`, so they stop verifying once the runtime uses the
//! real hash; the test must then sign under that hash.

use anyhow::Context;
use codec::Encode;
use cumulus_jam_zombienet_tests::{
	network::wait_for_collators,
	para::{Para, DEADLINE, PARACHAIN_SERVICE_ID, TINY_CORES},
	spawn::{spawn, JamNetwork, SpawnOptions},
};
use cumulus_zombienet_sdk_helpers::{
	coretime::sudo_call, submit_extrinsic_and_wait_for_best_block_success,
};
use pallet_bootnodes::BOOTNODES_KEY;
use pallet_jam_kv::kv_storage_key;
use sp_core::{ed25519, Pair as _, H256};
use std::time::{Duration, Instant};
use zombienet_sdk::{
	subxt::{dynamic::Value, tx::dynamic},
	subxt_signer::sr25519::dev,
};

/// The runtime's `MAX_BOOTNODE_ADDR_LEN`, checked against its metadata before the test starts.
const MAX_ADDR_LEN: u32 = 128;

/// A bootnode entry. The address bound only matters for decoding; the encoding is the runtime's.
type Bootnode = pallet_bootnodes::Bootnode<frame_support::traits::ConstU32<MAX_ADDR_LEN>>;

const EXPIRY_SLOT: u32 = 1_000_000;

/// The para must be producing blocks before a call can land in one.
const BLOCKS: u64 = 5;
const FINALIZED: u64 = 2;

/// Budget for a change to reach JAM: inclusion, refine, availability and accumulation.
const KV_BUDGET: Duration = Duration::from_secs(4 * 60);

#[tokio::test(flavor = "multi_thread")]
async fn bootnodes_are_published_to_jam() -> Result<(), anyhow::Error> {
	let para = Para::single(1);
	let paras = std::slice::from_ref(&para);
	let jam = spawn("bootnodes_are_published_to_jam", paras, SpawnOptions::new(TINY_CORES)).await?;
	let result = async {
		wait_for_collators(&jam.network, paras, BLOCKS, FINALIZED, DEADLINE.as_secs()).await?;
		check_max_addr_len(&jam, &para).await?;
		let key = kv_storage_key(para.id, BOOTNODES_KEY);
		let (alpha, beta) = (node_key(1), node_key(2));

		let alpha_entry = signed(&alpha, para.id, "/ip4/127.0.0.1/tcp/30333");
		add_bootnode(&jam, &para, &alpha_entry).await?;
		wait_for_set(&jam, &key, &[&alpha_entry]).await?;

		let beta_entry = signed(&beta, para.id, "/dns/beta.example.org/tcp/30334/ws");
		add_bootnode(&jam, &para, &beta_entry).await?;
		wait_for_set(&jam, &key, &[&alpha_entry, &beta_entry]).await?;

		// The same node key replaces its entry in place.
		let alpha_moved = signed(&alpha, para.id, "/ip4/127.0.0.1/tcp/40333");
		add_bootnode(&jam, &para, &alpha_moved).await?;
		wait_for_set(&jam, &key, &[&alpha_moved, &beta_entry]).await?;

		remove_bootnode(&jam, &para, &alpha.public()).await?;
		wait_for_set(&jam, &key, &[&beta_entry]).await?;

		// Removing the last entry removes the key.
		remove_bootnode(&jam, &para, &beta.public()).await?;
		wait_for_set(&jam, &key, &[]).await
	}
	.await;

	jam.destroy().await;
	result
}

fn node_key(seed: u8) -> ed25519::Pair {
	ed25519::Pair::from_seed(&[seed; 32])
}

/// An entry for `pair` at `addr`, signed for `para_id` under the runtime's placeholder JAM
/// genesis hash.
fn signed(pair: &ed25519::Pair, para_id: u32, addr: &str) -> Bootnode {
	let addr: multiaddr::Multiaddr = addr.parse().expect("the test's addresses parse; qed");
	let addr: frame_support::BoundedVec<u8, _> =
		addr.to_vec().try_into().expect("the test's addresses are short; qed");
	let sig = pair.sign(&pallet_bootnodes::pop_payload(&H256::zero(), para_id, &addr, EXPIRY_SLOT));
	Bootnode { addr, node_key: pair.public(), expiry_slot: EXPIRY_SLOT, sig }
}

async fn add_bootnode(jam: &JamNetwork, para: &Para, entry: &Bootnode) -> anyhow::Result<()> {
	let bootnode = Value::named_composite([
		("addr", Value::from_bytes(entry.addr.as_slice())),
		("node_key", Value::from_bytes(entry.node_key)),
		("expiry_slot", Value::u128(entry.expiry_slot.into())),
		("sig", Value::from_bytes(entry.sig)),
	]);
	submit_bootnodes(jam, para, "add_bootnode", vec![bootnode]).await
}

async fn remove_bootnode(
	jam: &JamNetwork,
	para: &Para,
	node_key: &ed25519::Public,
) -> anyhow::Result<()> {
	submit_bootnodes(jam, para, "remove_bootnode", vec![Value::from_bytes(node_key)]).await
}

/// Fail if the runtime's address bound is not the one [`Bootnode`] uses.
async fn check_max_addr_len(jam: &JamNetwork, para: &Para) -> anyhow::Result<()> {
	let name = para.collators.first().context("the para has no collator")?;
	let client = jam.collator_client(name).await?;
	let max_addr_len = client
		.constants()
		.at(&zombienet_sdk::subxt::dynamic::constant("Bootnodes", "MaxAddrLen"))?
		.to_value()?
		.as_u128();
	anyhow::ensure!(
		max_addr_len == Some(MAX_ADDR_LEN.into()),
		"the runtime's Bootnodes::MaxAddrLen is {max_addr_len:?}, the test uses {MAX_ADDR_LEN}",
	);
	Ok(())
}

/// Submit `Bootnodes::<call>(fields)` as sudo through the para's first collator.
async fn submit_bootnodes(
	jam: &JamNetwork,
	para: &Para,
	call: &str,
	fields: Vec<Value>,
) -> anyhow::Result<()> {
	let name = para.collators.first().context("the para has no collator")?;
	let client = jam.collator_client(name).await?;
	let block = submit_extrinsic_and_wait_for_best_block_success(
		&client,
		&sudo_call(dynamic("Bootnodes", call, fields)),
		&dev::alice(),
	)
	.await?;
	log::info!("Bootnodes::{call} included in para block {block:?}");
	Ok(())
}

/// Poll `serviceValue` at JAM's best block until the service stores exactly `set` under `key`,
/// or nothing if `set` is empty.
async fn wait_for_set(jam: &JamNetwork, key: &[u8], set: &[&Bootnode]) -> anyhow::Result<()> {
	let expected = (!set.is_empty()).then(|| set.encode());
	let started = Instant::now();
	loop {
		let at = jam.jam_rpc.best_block_hash().await?;
		let stored = jam.jam_rpc.service_value(&at, PARACHAIN_SERVICE_ID, key).await?;
		if stored == expected {
			log::info!(
				"serviceValue({PARACHAIN_SERVICE_ID}, 0x{}) holds {} bootnodes after {:?}",
				hex::encode(key),
				set.len(),
				started.elapsed(),
			);
			return Ok(());
		}
		anyhow::ensure!(
			started.elapsed() < KV_BUDGET,
			"serviceValue({PARACHAIN_SERVICE_ID}, 0x{}) is {:?} after {KV_BUDGET:?}, expected {} \
			 bootnodes",
			hex::encode(key),
			stored.as_deref().map(decode_set),
			set.len(),
		);
		tokio::time::sleep(Duration::from_secs(6)).await;
	}
}

/// The stored value as a bootnode set, for error messages.
fn decode_set(mut value: &[u8]) -> Result<Vec<Bootnode>, codec::Error> {
	codec::Decode::decode(&mut value)
}
