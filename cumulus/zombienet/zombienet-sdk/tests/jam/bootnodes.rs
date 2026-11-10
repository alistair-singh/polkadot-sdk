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

//! A para's bootnode record is published to JAM and can be read back.
//!
//! `Bootnodes::set_bootnodes` publishes a SCALE-encoded `BootnodeRecord` through `JamKv` under
//! [`BOOTNODES_KEY`], and `clear_bootnodes` removes the key. The first test sets and replaces the
//! record with sudo, and after each change waits for `serviceValue` on the Parachain Service to
//! hold exactly the expected record, including the para's real genesis hash.
//!
//! A second test runs two paras. Para A lists only its collator `alpha`. Para B's collator
//! follows A's record (`--jam-bootnodes-from`), joins A's DHT through `alpha` and from there finds
//! and connects to `beta`, which no record names. A publishes its record after `gamma` has started,
//! so `gamma` joins A's DHT while running.

use anyhow::Context;
use codec::Encode;
use cumulus_jam_zombienet_tests::{
	network::{free_port, wait_for_collators},
	para::{Para, DEADLINE, PARACHAIN_SERVICE_ID, TINY_CORES},
	spawn::{spawn, CollatorOptions, JamNetwork, SpawnOptions},
};
use cumulus_zombienet_sdk_helpers::{
	coretime::sudo_call, submit_extrinsic_and_wait_for_best_block_success,
};
use pallet_bootnodes::{BootnodeRecord, BOOTNODES_KEY};
use pallet_jam_kv::kv_storage_key;
use sp_core::{ed25519, Pair as _};
use std::{
	collections::HashMap,
	time::{Duration, Instant},
};
use zombienet_sdk::{
	subxt::{dynamic::Value, tx::dynamic},
	subxt_signer::sr25519::dev,
};

/// The para must be producing blocks before a call can land in one.
const BLOCKS: u64 = 5;
const FINALIZED: u64 = 2;

/// Budget for a change to reach JAM: inclusion, refine, availability and accumulation.
const KV_BUDGET: Duration = Duration::from_secs(4 * 60);

/// Budget for a node to connect to a para's bootnode and find its peers.
const DISCOVERY_BUDGET: Duration = Duration::from_secs(2 * 60);

/// Budget for a sudo call to land in a best block of the collator it was submitted to.
const SUBMIT_BUDGET: Duration = Duration::from_secs(2 * 60);

#[tokio::test(flavor = "multi_thread")]
async fn bootnodes_are_published_to_jam() -> Result<(), anyhow::Error> {
	let para = Para::single(1);
	let paras = std::slice::from_ref(&para);
	let jam = spawn("bootnodes_are_published_to_jam", paras, SpawnOptions::new(TINY_CORES)).await?;
	let result = async {
		wait_for_collators(&jam.network, paras, BLOCKS, FINALIZED, DEADLINE.as_secs()).await?;
		let genesis = genesis_hash(&jam, &para).await?;
		let key = kv_storage_key(para.id, BOOTNODES_KEY);
		let alpha = address(&node_key(1), "/ip4/127.0.0.1/tcp/30333");
		let beta = address(&node_key(2), "/dns/beta.example.org/tcp/30334/ws");

		set_bootnodes(&jam, &para, &[&alpha], Some("fork-1")).await?;
		wait_for_record(&jam, &key, Some(record(genesis, "fork-1", &[&alpha]))).await?;

		// A new call replaces the whole record.
		set_bootnodes(&jam, &para, &[&beta, &alpha], None).await?;
		wait_for_record(&jam, &key, Some(record(genesis, "", &[&beta, &alpha]))).await?;

		// Clearing the record removes the key.
		submit(&jam, &para, "Bootnodes", "clear_bootnodes", vec![]).await?;
		wait_for_record(&jam, &key, None).await
	}
	.await;

	jam.destroy().await;
	result
}

#[tokio::test(flavor = "multi_thread")]
async fn another_para_finds_peers_through_the_listed_bootnode() -> Result<(), anyhow::Error> {
	let (a, b) = (Para::new(0, 0, &["alpha", "beta"]), Para::new(1, 1, &["gamma"]));
	let alpha_port = free_port()?;
	let mut options = SpawnOptions::new(TINY_CORES);
	// The spec is a `Live` chain, so without this para 0's nodes keep each other's loopback
	// addresses out of their DHT, and alpha has no peer to tell gamma about.
	let discover_local = || vec!["--discover-local".into()];
	options.collators = HashMap::from([
		(
			"alpha".to_string(),
			CollatorOptions {
				p2p_port: Some(alpha_port),
				args: discover_local(),
				..Default::default()
			},
		),
		("beta".to_string(), CollatorOptions { args: discover_local(), ..Default::default() }),
		(
			"gamma".to_string(),
			CollatorOptions {
				args: vec![
					("--jam-bootnodes-from", a.id.to_string().as_str()).into(),
					// The connections this test waits for are only logged at trace.
					"-llitep2p::transport-manager=trace".into(),
				],
				..Default::default()
			},
		),
	]);
	let paras = [a.clone(), b];
	let jam =
		spawn("another_para_finds_peers_through_the_listed_bootnode", &paras, options).await?;
	let result = async {
		wait_for_collators(&jam.network, &paras, BLOCKS, FINALIZED, DEADLINE.as_secs()).await?;
		let genesis = genesis_hash(&jam, &a).await?;
		let (alpha, beta) = (network_key("alpha"), network_key("beta"));
		let (alpha_peer, beta_peer) = (peer_id(&alpha), peer_id(&beta));

		// zombienet's nodes listen on WebSocket only (`--listen-addr .../ws`).
		let alpha_addr = format!("/ip4/127.0.0.1/tcp/{alpha_port}/ws");
		let listed = address(&alpha, &alpha_addr);
		// No record names para 0's DHT yet, so gamma has no way to reach its nodes.
		for peer in [&alpha_peer, &beta_peer] {
			anyhow::ensure!(
				log_lines_with(&jam, "gamma", &[CONNECTED, peer]).await?.is_empty(),
				"gamma reached {peer} before para 0 published its bootnodes",
			);
		}
		set_bootnodes(&jam, &a, &[&listed], None).await?;
		let key = kv_storage_key(a.id, BOOTNODES_KEY);
		let expected = record(genesis, "", &[&listed]);
		wait_for_record(&jam, &key, Some(expected)).await?;

		// The record appeared after gamma started, so gamma joins the DHT while running.
		wait_for_log(&jam, "gamma", &["Joined the para's DHT."]).await?;
		let dialed = format!("endpoint=Dialer {{ address: {alpha_addr}/p2p/{alpha_peer}");
		wait_for_log(&jam, "gamma", &[CONNECTED, &dialed]).await?;
		wait_for_log(&jam, "gamma", &["Discovered a peer of para 0.", &beta_peer]).await?;
		// The lookup that found beta also queried it, so gamma dialled it too.
		wait_for_log(&jam, "gamma", &[CONNECTED, "endpoint=Dialer", &beta_peer]).await
	}
	.await;

	jam.destroy().await;
	result
}

/// What litep2p logs at trace level for an established connection.
const CONNECTED: &str = "on connection established completed";

/// The network key zombienet derives from a node's name.
fn network_key(name: &str) -> ed25519::Pair {
	ed25519::Pair::from_seed(&sp_crypto_hashing::sha2_256(name.as_bytes()))
}

/// The base58 peer id of the node whose network key is `pair`.
fn peer_id(pair: &ed25519::Pair) -> String {
	sc_network_types::PeerId::from_ed25519(&pair.public().0)
		.expect("an ed25519 key is a peer id; qed")
		.to_base58()
}

/// The lines of `name`'s log that carry every one of `needles`.
async fn log_lines_with(
	jam: &JamNetwork,
	name: &str,
	needles: &[&str],
) -> anyhow::Result<Vec<String>> {
	let log = jam.network.get_node(name)?.logs().await?;
	Ok(log
		.lines()
		.filter(|line| needles.iter().all(|needle| line.contains(needle)))
		.map(str::to_string)
		.collect())
}

/// Poll `name`'s log until a line carries every one of `needles`.
async fn wait_for_log(jam: &JamNetwork, name: &str, needles: &[&str]) -> anyhow::Result<()> {
	let started = Instant::now();
	while log_lines_with(jam, name, needles).await?.is_empty() {
		anyhow::ensure!(
			started.elapsed() < DISCOVERY_BUDGET,
			"no line of {name}'s log carries {needles:?} after {DISCOVERY_BUDGET:?}",
		);
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
	Ok(())
}

fn node_key(seed: u8) -> ed25519::Pair {
	ed25519::Pair::from_seed(&[seed; 32])
}

/// `addr` with the peer id of `pair` appended, as `set_bootnodes` takes it.
fn address(pair: &ed25519::Pair, addr: &str) -> String {
	format!("{addr}/p2p/{}", peer_id(pair))
}

/// The record `set_bootnodes` should publish for the text `addresses`.
fn record(genesis: [u8; 32], fork_id: &str, addresses: &[&String]) -> BootnodeRecord {
	let addresses = addresses
		.iter()
		.map(|address| {
			let address: multiaddr::Multiaddr = address.parse().expect("valid; qed");
			address.to_vec().try_into().expect("the test's addresses are short; qed")
		})
		.collect::<Vec<_>>()
		.try_into()
		.expect("the test lists few addresses; qed");
	let fork_id = fork_id.as_bytes().to_vec().try_into().expect("short; qed");
	BootnodeRecord { genesis, fork_id, addresses }
}

/// The para's genesis hash, as its collator reports it.
async fn genesis_hash(jam: &JamNetwork, para: &Para) -> anyhow::Result<[u8; 32]> {
	let name = para.collators.first().context("the para has no collator")?;
	Ok(jam.collator_client(name).await?.genesis_hash().0)
}

async fn set_bootnodes(
	jam: &JamNetwork,
	para: &Para,
	addresses: &[&String],
	fork_id: Option<&str>,
) -> anyhow::Result<()> {
	let addresses = addresses.iter().map(|address| Value::from_bytes(address.as_bytes()));
	let fork_id = match fork_id {
		Some(id) => Value::unnamed_variant("Some", [Value::from_bytes(id.as_bytes())]),
		None => Value::unnamed_variant("None", []),
	};
	let fields = vec![Value::unnamed_composite(addresses), fork_id];
	submit(jam, para, "Bootnodes", "set_bootnodes", fields).await
}

/// Submit `<pallet>::<call>(fields)` as sudo through the para's first collator.
async fn submit(
	jam: &JamNetwork,
	para: &Para,
	pallet: &str,
	call: &str,
	fields: Vec<Value>,
) -> anyhow::Result<()> {
	let name = para.collators.first().context("the para has no collator")?;
	let client = jam.collator_client(name).await?;
	let (sudo, alice) = (sudo_call(dynamic(pallet, call, fields)), dev::alice());
	let submit = submit_extrinsic_and_wait_for_best_block_success(&client, &sudo, &alice);
	// The helper waits forever for a block that never comes, e.g. when the collator stalls.
	let block = tokio::time::timeout(SUBMIT_BUDGET, submit).await.map_err(|_| {
		anyhow::anyhow!("{pallet}::{call} not in a best block after {SUBMIT_BUDGET:?}")
	})??;
	log::info!("{pallet}::{call} included in para block {block:?}");
	Ok(())
}

/// Poll `serviceValue` at JAM's finalized block, which the reader follows, until the service stores
/// exactly `record` under `key`, or nothing if `record` is `None`.
async fn wait_for_record(
	jam: &JamNetwork,
	key: &[u8],
	record: Option<BootnodeRecord>,
) -> anyhow::Result<()> {
	let expected = record.as_ref().map(Encode::encode);
	let started = Instant::now();
	loop {
		let at = jam.jam_rpc.finalized_header_hash().await?;
		let stored = jam.jam_rpc.service_value(&at, PARACHAIN_SERVICE_ID, key).await?;
		if stored == expected {
			log::info!(
				"serviceValue({PARACHAIN_SERVICE_ID}, 0x{}) holds the expected value after {:?}",
				hex::encode(key),
				started.elapsed(),
			);
			return Ok(());
		}
		anyhow::ensure!(
			started.elapsed() < KV_BUDGET,
			"serviceValue({PARACHAIN_SERVICE_ID}, 0x{}) is {:?} after {KV_BUDGET:?}, expected \
			 {record:?}",
			hex::encode(key),
			stored
				.as_deref()
				.map(|mut value| <BootnodeRecord as codec::Decode>::decode(&mut value)),
		);
		tokio::time::sleep(Duration::from_secs(6)).await;
	}
}
