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

//! A para's key/value storage round-trips through JAM.
//!
//! `JamKv::set_kv` sends a `SetKV` upward message that only the PVF delivers, so the value can
//! appear in the Parachain Service's storage only after JAM refined and accumulated the block that
//! carried the call. The test writes a value with sudo, reads it back with `serviceValue` under
//! `0x08 ‖ para_id ‖ key`, then removes it and waits for the entry to go. This is the path the
//! bootnode record will be published on.
//!
//! After each change the test also proves the entry the way a trustless reader would: it fetches
//! `stateRoot` and `stateProof` at one JAM block and checks the proof with the Parachain Service's
//! own `verify`, for the value after `set_kv` and for its absence after `remove_kv`.

use anyhow::Context;
use codec::Encode;
use cumulus_jam_zombienet_tests::{
	network::wait_for_collators,
	para::{Para, DEADLINE, PARACHAIN_SERVICE_ID, TINY_CORES},
	spawn::{spawn, JamNetwork, SpawnOptions},
};
use cumulus_zombienet_sdk_helpers::{
	coretime::sudo_call, submit_extrinsic_and_wait_for_best_block_success, PARA_BLOCK_METRIC,
};
use pallet_jam_kv::kv_storage_key;
use std::time::{Duration, Instant};
use zombienet_sdk::{
	subxt::{dynamic::Value, tx::dynamic},
	subxt_signer::sr25519::dev,
};

const KEY: &[u8] = b"jam-kv-roundtrip";
const VALUE: &[u8] = b"value written by the para runtime";

/// The para must be producing blocks before a call can land in one.
const BLOCKS: u64 = 5;
const FINALIZED: u64 = 2;

/// Budget for a write to reach JAM: inclusion, refine, availability and accumulation.
const KV_BUDGET: Duration = Duration::from_secs(4 * 60);

/// Budget for a sudo call to land in a best block of the collator it was submitted to.
const SUBMIT_BUDGET: Duration = Duration::from_secs(2 * 60);

#[tokio::test(flavor = "multi_thread")]
async fn kv_round_trip_works() -> Result<(), anyhow::Error> {
	let para = Para::single(1);
	let jam =
		spawn("kv_round_trip_works", &[Para::single(1)], SpawnOptions::new(TINY_CORES)).await?;
	let result = async {
		wait_for_collators(&jam.network, &[Para::single(1)], BLOCKS, FINALIZED, DEADLINE.as_secs())
			.await?;
		let key = kv_storage_key(para.id, KEY);

		submit_jam_kv(
			&jam,
			&para,
			"set_kv",
			vec![Value::from_bytes(KEY), Value::from_bytes(VALUE)],
		)
		.await?;
		wait_for_value(&jam, &key, Some(VALUE)).await?;
		assert_proven(&jam, &key, Some(VALUE)).await?;

		// The key with a SCALE length prefix, as a reader might wrongly build it, finds nothing.
		let prefixed = kv_storage_key(para.id, &KEY.to_vec().encode());
		let at = jam.jam_rpc.best_block_hash().await?;
		let stored = jam.jam_rpc.service_value(&at, PARACHAIN_SERVICE_ID, &prefixed).await?;
		anyhow::ensure!(stored.is_none(), "the length-prefixed key found {stored:?}");

		submit_jam_kv(&jam, &para, "remove_kv", vec![Value::from_bytes(KEY)]).await?;
		wait_for_value(&jam, &key, None).await?;
		assert_proven(&jam, &key, None).await
	}
	.await;

	jam.destroy().await;
	result
}

/// A block that writes to the KV store imports on every collator, not only on its author: each
/// collator re-executes the others' blocks, so a write that only works while authoring forks the
/// para at the first block carrying one.
#[tokio::test(flavor = "multi_thread")]
async fn kv_writes_import_on_every_collator() -> Result<(), anyhow::Error> {
	let para = Para::single(2);
	let paras = std::slice::from_ref(&para);
	let jam =
		spawn("kv_writes_import_on_every_collator", paras, SpawnOptions::new(TINY_CORES)).await?;
	let result = async {
		wait_for_collators(&jam.network, paras, BLOCKS, FINALIZED, DEADLINE.as_secs()).await?;
		let key = kv_storage_key(para.id, KEY);

		submit_jam_kv(
			&jam,
			&para,
			"set_kv",
			vec![Value::from_bytes(KEY), Value::from_bytes(VALUE)],
		)
		.await?;
		wait_for_value(&jam, &key, Some(VALUE)).await?;

		let name = para.collators.first().context("the para has no collator")?;
		let written_at = jam.network.get_node(name.as_str())?.reports(PARA_BLOCK_METRIC).await?;
		let past = written_at + IMPORTED_PAST as f64;
		for name in &para.collators {
			let node = jam.network.get_node(name.as_str())?;
			node.wait_metric_with_timeout(
				PARA_BLOCK_METRIC,
				|best| best >= past,
				KV_BUDGET.as_secs(),
			)
			.await
			.map_err(|error| {
				anyhow::anyhow!(
					"{name} stopped below #{past} after the write at #{written_at}: {error}"
				)
			})?;
			let failed: Vec<String> = node
				.logs()
				.await?
				.lines()
				.filter(|line| line.contains("Error importing block"))
				.map(str::to_string)
				.collect();
			anyhow::ensure!(failed.is_empty(), "{name} failed to import: {failed:#?}");
		}
		Ok(())
	}
	.await;

	jam.destroy().await;
	result
}

/// How many blocks past the one carrying the write every collator must import.
const IMPORTED_PAST: u64 = 3;

/// Submit `JamKv::<call>(fields)` as sudo through the para's first collator.
async fn submit_jam_kv(
	jam: &JamNetwork,
	para: &Para,
	call: &str,
	fields: Vec<Value>,
) -> anyhow::Result<()> {
	let name = para.collators.first().context("the para has no collator")?;
	let client = jam.collator_client(name).await?;
	let (sudo, alice) = (sudo_call(dynamic("JamKv", call, fields)), dev::alice());
	let submit = submit_extrinsic_and_wait_for_best_block_success(&client, &sudo, &alice);
	// The helper waits forever for a block that never comes, e.g. when the collator stalls.
	let block = tokio::time::timeout(SUBMIT_BUDGET, submit).await.map_err(|_| {
		anyhow::anyhow!("JamKv::{call} not in a best block after {SUBMIT_BUDGET:?}")
	})??;
	log::info!("JamKv::{call} included in para block {block:?}");
	Ok(())
}

/// Poll `serviceValue` at JAM's best block until the service stores `expected` under `key`.
async fn wait_for_value(
	jam: &JamNetwork,
	key: &[u8],
	expected: Option<&[u8]>,
) -> anyhow::Result<()> {
	let started = Instant::now();
	loop {
		let at = jam.jam_rpc.best_block_hash().await?;
		let stored = jam.jam_rpc.service_value(&at, PARACHAIN_SERVICE_ID, key).await?;
		if stored.as_deref() == expected {
			log::info!(
				"serviceValue({PARACHAIN_SERVICE_ID}, 0x{}) is {:?} after {:?}",
				hex::encode(key),
				expected.map(String::from_utf8_lossy),
				started.elapsed(),
			);
			return Ok(());
		}
		anyhow::ensure!(
			started.elapsed() < KV_BUDGET,
			"serviceValue({PARACHAIN_SERVICE_ID}, 0x{}) is {stored:?} after {KV_BUDGET:?}, \
			 expected {expected:?}",
			hex::encode(key),
		);
		tokio::time::sleep(Duration::from_secs(6)).await;
	}
}

/// Prove what the service stores under `key` at JAM's best block: fetch the block's state root
/// and a proof of the entry's state key, and check the proof with the service's own `verify`.
async fn assert_proven(
	jam: &JamNetwork,
	key: &[u8],
	expected: Option<&[u8]>,
) -> anyhow::Result<()> {
	let state_key = parachain_service_core::service_value_state_key(PARACHAIN_SERVICE_ID, key);
	let at = jam.jam_rpc.best_block_hash().await?;
	let state_root = jam.jam_rpc.state_root(&at).await?;
	let proof = jam.jam_rpc.state_proof(&at, &state_key).await?;
	let proven = parachain_service_core::verify(&proof, &state_root, &state_key)
		.map_err(|error| anyhow::anyhow!("the stateProof does not verify: {error:?}"))?;
	anyhow::ensure!(
		proven.as_deref() == expected,
		"the proof at {at} proves {proven:?}, expected {expected:?}"
	);
	log::info!(
		"stateProof at {at}: {} nodes prove {:?} under state key 0x{}",
		proof.nodes.len(),
		expected.map(String::from_utf8_lossy),
		hex::encode(state_key),
	);
	Ok(())
}
