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
//! A second test runs two paras. Para B's collator follows para A's set (`--jam-bootnodes-from`)
//! and, once A lists its collator `alpha`, dials it. The two run different chains, so `alpha`
//! refuses B's sync protocol; the connection itself is what shows B found A through JAM: B has
//! no other way to learn `alpha`'s address, and the handshake checks the peer id. Root on A then
//! writes a set past the pallet with `JamKv::set_kv`, and B dials only the entries the pallet
//! would have accepted.
//!
//! `pallet-bootnodes` does not check the proof of possession yet. The entries are signed under the
//! runtime's placeholder JAM genesis hash, `H256::zero()`, so they stop verifying once the runtime
//! uses the real hash; the test must then sign under that hash.

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
use pallet_bootnodes::BOOTNODES_KEY;
use pallet_jam_kv::kv_storage_key;
use sp_core::{ed25519, Pair as _, H256};
use std::{
	collections::HashMap,
	time::{Duration, Instant},
};
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

/// Budget for a sudo call to land in a best block of the collator it was submitted to.
const SUBMIT_BUDGET: Duration = Duration::from_secs(2 * 60);

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

#[tokio::test(flavor = "multi_thread")]
async fn another_para_dials_the_listed_bootnodes() -> Result<(), anyhow::Error> {
	let (a, b) = (Para::new(0, 0, &["alpha", "beta"]), Para::new(1, 1, &["gamma"]));
	let (alpha_port, beta_port) = (free_port()?, free_port()?);
	let mut options = SpawnOptions::new(TINY_CORES);
	options.collators = HashMap::from([
		("alpha".to_string(), CollatorOptions { p2p_port: Some(alpha_port), ..Default::default() }),
		("beta".to_string(), CollatorOptions { p2p_port: Some(beta_port), ..Default::default() }),
		(
			"gamma".to_string(),
			CollatorOptions {
				args: vec![
					("--jam-bootnodes-from", a.id.to_string().as_str()).into(),
					// The connection this test waits for is only logged at trace.
					"-llitep2p::transport-manager=trace".into(),
				],
				..Default::default()
			},
		),
	]);
	let paras = [a.clone(), b];
	let jam = spawn("another_para_dials_the_listed_bootnodes", &paras, options).await?;
	let result = async {
		wait_for_collators(&jam.network, &paras, BLOCKS, FINALIZED, DEADLINE.as_secs()).await?;
		check_max_addr_len(&jam, &a).await?;
		wait_for_log(&jam, "gamma", &["Following the para's bootnodes on JAM."]).await?;

		let (alpha, beta) = (network_key("alpha"), network_key("beta"));
		let (alpha_peer, beta_peer) = (peer_id(&alpha), peer_id(&beta));
		for peer in [&alpha_peer, &beta_peer] {
			anyhow::ensure!(
				connections_to(&jam, "gamma", peer).await?.is_empty(),
				"gamma reached {peer} before para 0 listed it",
			);
		}

		// zombienet's nodes listen on WebSocket only (`--listen-addr .../ws`).
		let entry = signed(&alpha, a.id, &format!("/ip4/127.0.0.1/tcp/{alpha_port}/ws"));
		add_bootnode(&jam, &a, &entry).await?;
		wait_for_set(&jam, &kv_storage_key(a.id, BOOTNODES_KEY), &[&entry]).await?;
		wait_for_log(&jam, "gamma", &["Learned a bootnode of para 0.", &alpha_peer]).await?;
		wait_for_connection(&jam, "gamma", &alpha_peer).await?;

		remove_bootnode(&jam, &a, &alpha.public()).await?;
		wait_for_log(&jam, "gamma", &["A bootnode of para 0 is no longer listed.", &alpha_peer])
			.await?;

		// Root writes the set past the pallet: an entry the pallet would reject, then `beta`.
		let rejected_key = node_key(9);
		let rejected = signed(&rejected_key, a.id, "/ip4/127.0.0.1/udp/30333/quic-v1");
		let beta_entry = signed(&beta, a.id, &format!("/ip4/127.0.0.1/tcp/{beta_port}/ws"));
		// A `Vec`, not an array: SCALE gives arrays no length prefix.
		let set = vec![&rejected, &beta_entry];
		set_kv(&jam, &a, BOOTNODES_KEY, &set.encode()).await?;
		wait_for_set(&jam, &kv_storage_key(a.id, BOOTNODES_KEY), &set).await?;
		// Both entries come from one update, so once `beta` is learned the other was skipped.
		wait_for_log(&jam, "gamma", &["Learned a bootnode of para 0.", &beta_peer]).await?;
		let rejected_peer = peer_id(&rejected_key);
		anyhow::ensure!(
			log_lines_with(&jam, "gamma", &["Learned a bootnode", &rejected_peer])
				.await?
				.is_empty(),
			"gamma learned the entry the pallet would reject",
		);
		wait_for_connection(&jam, "gamma", &beta_peer).await
	}
	.await;

	jam.destroy().await;
	result
}

/// How long a node may take to dial a peer it just learned: its peerset fills free slots every
/// second or so.
const DIAL_BUDGET: Duration = Duration::from_secs(60);

/// The network key zombienet derives from a node's name.
fn network_key(name: &str) -> ed25519::Pair {
	ed25519::Pair::from_seed(&sp_crypto_hashing::sha2_256(name.as_bytes()))
}

/// Poll `name`'s log until litep2p established a connection with `peer`.
async fn wait_for_connection(jam: &JamNetwork, name: &str, peer: &str) -> anyhow::Result<()> {
	let started = Instant::now();
	while connections_to(jam, name, peer).await?.is_empty() {
		anyhow::ensure!(started.elapsed() < DIAL_BUDGET, "{name} never connected to {peer}");
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
	log::info!("{name} connected to {peer} after {:?}", started.elapsed());
	Ok(())
}

/// The base58 peer id of the node whose network key is `pair`.
fn peer_id(pair: &ed25519::Pair) -> String {
	sc_network_types::PeerId::from_ed25519(&pair.public().0)
		.expect("an ed25519 key is a peer id; qed")
		.to_base58()
}

/// The lines of `name`'s log where litep2p established a connection with `peer`.
async fn connections_to(jam: &JamNetwork, name: &str, peer: &str) -> anyhow::Result<Vec<String>> {
	log_lines_with(jam, name, &["on connection established completed", peer]).await
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
			started.elapsed() < KV_BUDGET,
			"no line of {name}'s log carries {needles:?} after {KV_BUDGET:?}",
		);
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
	Ok(())
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
	submit(jam, para, "Bootnodes", "add_bootnode", vec![bootnode]).await
}

async fn remove_bootnode(
	jam: &JamNetwork,
	para: &Para,
	node_key: &ed25519::Public,
) -> anyhow::Result<()> {
	submit(jam, para, "Bootnodes", "remove_bootnode", vec![Value::from_bytes(node_key)]).await
}

/// Write `value` under the para's `key` with `JamKv::set_kv`, past `pallet-bootnodes`.
async fn set_kv(jam: &JamNetwork, para: &Para, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
	let fields = vec![Value::from_bytes(key), Value::from_bytes(value)];
	submit(jam, para, "JamKv", "set_kv", fields).await
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
