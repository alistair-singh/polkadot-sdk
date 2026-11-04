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
//! no other way to learn `alpha`'s address, and the handshake checks the peer id. `alpha` is
//! listed at a dead port first and then moved, so the connection also shows the reader follows a
//! replaced entry. Root on A then writes a set past the pallet with `JamKv::set_kv`, and B dials
//! only the entries the pallet would have accepted, whose node signed them and whose lease holds:
//! an entry that expired before it was written is never learned, nor one signed by another key,
//! and `beta`'s short lease expires on B without A writing again.
//!
//! JAM's genesis embeds each para's genesis head, so no para can carry the JAM genesis hash in its
//! genesis. Each test first sets it with sudo on every para, from the genesis header in the JAM
//! chain spec, checked against JAM itself; entries are signed under it. Para B's reader checks
//! A's entries against B's own hash.

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

/// A lease that never ends: JAM slots count from the JAM epoch, so they are already in the
/// millions.
const EXPIRY_SLOT: u32 = u32::MAX;

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
		let signer = Signer::new(set_jam_genesis_hash(&jam, paras).await?, para.id);
		let key = kv_storage_key(para.id, BOOTNODES_KEY);
		let (alpha, beta) = (node_key(1), node_key(2));

		let alpha_entry = signer.entry(&alpha, "/ip4/127.0.0.1/tcp/30333");
		add_bootnode(&jam, &para, &alpha_entry).await?;
		wait_for_set(&jam, &key, &[&alpha_entry]).await?;

		let beta_entry = signer.entry(&beta, "/dns/beta.example.org/tcp/30334/ws");
		add_bootnode(&jam, &para, &beta_entry).await?;
		wait_for_set(&jam, &key, &[&alpha_entry, &beta_entry]).await?;

		// The same node key replaces its entry in place.
		let alpha_moved = signer.entry(&alpha, "/ip4/127.0.0.1/tcp/40333");
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
		let signer = Signer::new(set_jam_genesis_hash(&jam, &paras).await?, a.id);
		wait_for_log(&jam, "gamma", &["Following the para's bootnodes on JAM."]).await?;

		let (alpha, beta) = (network_key("alpha"), network_key("beta"));
		let (alpha_peer, beta_peer) = (peer_id(&alpha), peer_id(&beta));
		for peer in [&alpha_peer, &beta_peer] {
			anyhow::ensure!(
				connections_to(&jam, "gamma", peer).await?.is_empty(),
				"gamma reached {peer} before para 0 listed it",
			);
		}

		// `alpha` is listed first at a port nothing listens on, then moved to its own: the
		// reader passes the new address on, and `gamma` dials `alpha` there.
		// zombienet's nodes listen on WebSocket only (`--listen-addr .../ws`).
		let key = kv_storage_key(a.id, BOOTNODES_KEY);
		let stale_addr = format!("/ip4/127.0.0.1/tcp/{}/ws", free_port()?);
		let stale = signer.entry(&alpha, &stale_addr);
		add_bootnode(&jam, &a, &stale).await?;
		wait_for_set(&jam, &key, &[&stale]).await?;
		wait_for_log(&jam, "gamma", &["Learned a bootnode of para 0.", &stale_addr]).await?;

		let alpha_addr = format!("/ip4/127.0.0.1/tcp/{alpha_port}/ws");
		let entry = signer.entry(&alpha, &alpha_addr);
		add_bootnode(&jam, &a, &entry).await?;
		wait_for_set(&jam, &key, &[&entry]).await?;
		wait_for_log(&jam, "gamma", &["Learned a bootnode of para 0.", &alpha_addr]).await?;
		wait_for_log(&jam, "gamma", &["A bootnode of para 0 is no longer listed.", &stale_addr])
			.await?;
		wait_for_connection(&jam, "gamma", &alpha_peer, &alpha_addr).await?;

		remove_bootnode(&jam, &a, &alpha.public()).await?;
		wait_for_log(&jam, "gamma", &["A bootnode of para 0 is no longer listed.", &alpha_peer])
			.await?;

		// Root writes the set past the pallet: an entry the pallet would reject, one whose lease
		// is already over, one whose node never signed it, and `beta` with a lease of
		// `BETA_LEASE` slots.
		let (rejected_key, expired_key, forged_key) = (node_key(9), node_key(8), node_key(7));
		let rejected = signer.entry(&rejected_key, "/ip4/127.0.0.1/udp/30333/quic-v1");
		let expired = signer.until(&expired_key, "/ip4/127.0.0.1/tcp/1/ws", 1);
		// Signed by another key: root lists a node that did not consent.
		let mut forged = signer.entry(&forged_key, "/ip4/127.0.0.1/tcp/2/ws");
		forged.sig = signer.entry(&node_key(6), "/ip4/127.0.0.1/tcp/2/ws").sig;
		let beta_expiry = u32::try_from(jam.jam_rpc.finalized_slot().await?)? + BETA_LEASE;
		let beta_addr = format!("/ip4/127.0.0.1/tcp/{beta_port}/ws");
		let beta_entry = signer.until(&beta, &beta_addr, beta_expiry);
		// A `Vec`, not an array: SCALE gives arrays no length prefix.
		let set = vec![&rejected, &expired, &forged, &beta_entry];
		set_kv(&jam, &a, BOOTNODES_KEY, &set.encode()).await?;
		wait_for_set(&jam, &key, &set).await?;
		// All entries come from one update, so once `beta` is learned the others were skipped.
		wait_for_log(&jam, "gamma", &["Learned a bootnode of para 0.", &beta_peer]).await?;
		let skipped = [
			(&rejected_key, "the pallet would reject"),
			(&expired_key, "had expired"),
			(&forged_key, "its node never signed"),
		];
		for (node, why) in skipped {
			let peer = peer_id(node);
			let learned = log_lines_with(&jam, "gamma", &["Learned a bootnode", &peer]).await?;
			anyhow::ensure!(learned.is_empty(), "gamma learned the entry that {why}");
		}
		wait_for_connection(&jam, "gamma", &beta_peer, &beta_addr).await?;

		// The value does not change again; `beta` drops off once JAM passes its expiry slot.
		wait_for_log(&jam, "gamma", &["A bootnode of para 0 expired.", &beta_peer]).await?;
		let at = jam.jam_rpc.finalized_slot().await?;
		anyhow::ensure!(
			at + 1 >= u64::from(beta_expiry),
			"gamma dropped beta at finalized slot {at}, before its expiry slot {beta_expiry}",
		);
		Ok(())
	}
	.await;

	jam.destroy().await;
	result
}

/// `beta`'s lease in the `set_kv` phase, in JAM slots (6 s each): long enough for the set to reach
/// JAM and `gamma` to dial it, short enough to expire within [`KV_BUDGET`].
const BETA_LEASE: u32 = 15;

/// How long a node may take to dial a peer it just learned: its peerset fills free slots every
/// second or so.
const DIAL_BUDGET: Duration = Duration::from_secs(60);

/// The network key zombienet derives from a node's name.
fn network_key(name: &str) -> ed25519::Pair {
	ed25519::Pair::from_seed(&sp_crypto_hashing::sha2_256(name.as_bytes()))
}

/// Poll `name`'s log until litep2p established a connection it dialed to `peer` at `addr`.
async fn wait_for_connection(
	jam: &JamNetwork,
	name: &str,
	peer: &str,
	addr: &str,
) -> anyhow::Result<()> {
	let dialed = format!("endpoint=Dialer {{ address: {addr}/p2p/{peer}");
	let needles = ["on connection established completed", dialed.as_str()];
	let started = Instant::now();
	while log_lines_with(jam, name, &needles).await?.is_empty() {
		anyhow::ensure!(
			started.elapsed() < DIAL_BUDGET,
			"{name} never connected to {peer} at {addr}",
		);
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
	log::info!("{name} connected to {peer} at {addr} after {:?}", started.elapsed());
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

/// Signs entries for one para under the JAM genesis hash the test set.
struct Signer {
	jam_genesis_hash: H256,
	para_id: u32,
}

impl Signer {
	fn new(jam_genesis_hash: H256, para_id: u32) -> Self {
		Self { jam_genesis_hash, para_id }
	}

	/// An entry for `pair` at `addr`, with a lease past the test's end.
	fn entry(&self, pair: &ed25519::Pair, addr: &str) -> Bootnode {
		self.until(pair, addr, EXPIRY_SLOT)
	}

	/// An entry for `pair` at `addr`, with the lease ending at `expiry_slot`.
	fn until(&self, pair: &ed25519::Pair, addr: &str, expiry_slot: u32) -> Bootnode {
		let addr: multiaddr::Multiaddr = addr.parse().expect("the test's addresses parse; qed");
		let addr: frame_support::BoundedVec<u8, _> =
			addr.to_vec().try_into().expect("the test's addresses are short; qed");
		let payload =
			pallet_bootnodes::pop_payload(&self.jam_genesis_hash, self.para_id, &addr, expiry_slot);
		Bootnode { addr, node_key: pair.public(), expiry_slot, sig: pair.sign(&payload) }
	}
}

/// Set the JAM genesis hash on every para with sudo, and return it.
///
/// It comes from the genesis header in the JAM chain spec the test wrote, and is checked once
/// against the hash JAM itself reports for its genesis block.
async fn set_jam_genesis_hash(jam: &JamNetwork, paras: &[Para]) -> anyhow::Result<H256> {
	let spec_path = jam.work_dir.join("zombienet/jam_spec.json");
	let spec: serde_json::Value = serde_json::from_slice(
		&std::fs::read(&spec_path).with_context(|| format!("reading {}", spec_path.display()))?,
	)?;
	let header = spec["genesis_header"].as_str().context("the JAM spec has no genesis_header")?;
	let header = hex::decode(header.trim_start_matches("0x")).context("genesis_header")?;
	let hash = H256(sp_crypto_hashing::blake2_256(&header));
	let reported = H256(jam.jam_rpc.genesis_header_hash().await?);
	anyhow::ensure!(
		hash == reported,
		"the JAM spec's genesis header hashes to {hash:?}, JAM reports genesis {reported:?}",
	);
	for para in paras {
		submit(jam, para, "Bootnodes", "set_jam_genesis_hash", vec![Value::from_bytes(hash)])
			.await?;
	}
	Ok(hash)
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
