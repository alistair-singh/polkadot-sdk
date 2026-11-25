// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! How speculative messaging finds the other chain's nodes, end to end.
//!
//! No node is told a peer. The receiver follows each para its runtime's channels name, finds that
//! para's nodes on the relay chain DHT (RFC-0008 provider records, then `/paranode`), and joins
//! the para's own DHT as a client to find the nodes no provider record names.
//!
//! These tests read the receiver's discovery logs (`relay-peers`, `para-peers`), and check
//! delivery with [`super`]'s helpers.

use super::*;
use std::{
	path::Path,
	process::{Child, Command, Stdio},
};

/// How long the receiver may take to log a discovery step. A relay chain DHT round runs every five
/// minutes once it has found a record, and the para's DHT is walked every 30 s.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(12 * 60);

/// The para peer id zombienet gives the node `name`: it derives the node key from the name.
fn peer_id_of(name: &str) -> Result<String, anyhow::Error> {
	let (_, peer_id) = zombienet_orchestrator::generators::generate_node_identity(name)
		.map_err(|e| anyhow!("peer id of {name}: {e}"))?;
	Ok(peer_id)
}

/// Wait until `node` has logged a line matching the regex `pattern` at least `at_least` times.
async fn logged(
	network: &Network<LocalFileSystem>,
	node: &str,
	pattern: &str,
	at_least: u32,
) -> Result<(), anyhow::Error> {
	log::info!("Waiting for {node} to log \"{pattern}\" {at_least} times");
	let options = LogLineCountOptions::new(move |n| n >= at_least, DISCOVERY_TIMEOUT, false);
	let count = network
		.get_node(node)?
		.wait_log_line_count_with_timeout(pattern, false, options)
		.await?;
	anyhow::ensure!(count.success(), "{node} did not log \"{pattern}\" {at_least} times");
	log::info!("Done: {node} logged \"{pattern}\"");
	Ok(())
}

/// Whether `node` has logged a line matching the regex `pattern` exactly `times` times so far.
async fn logged_exactly(
	network: &Network<LocalFileSystem>,
	node: &str,
	pattern: &str,
	times: u32,
) -> Result<bool, anyhow::Error> {
	let options = LogLineCountOptions::new(move |n| n == times, Duration::from_secs(1), false);
	let count = network
		.get_node(node)?
		.wait_log_line_count_with_timeout(pattern, false, options)
		.await?;
	Ok(count.success())
}

/// With the receiver paused, send an XCM and let `node`, a sender-chain node other than the
/// collator, import and finalize it. Then pause the sender collator and resume the receiver: only
/// `node` can serve the message, so the receiver executing it shows it fetched from `node`.
async fn served_by_while_collator_paused(
	network: &Network<LocalFileSystem>,
	node: &str,
) -> Result<(), anyhow::Error> {
	let sender: OnlineClient<PolkadotConfig> =
		network.get_node(SENDER_COLLATOR)?.wait_client().await?;
	let other: OnlineClient<PolkadotConfig> = network.get_node(node)?.wait_client().await?;
	let receiver_node = network.get_node(RECEIVER_COLLATOR)?;
	let collator = network.get_node(SENDER_COLLATOR)?;

	receiver_node.pause().await?;
	log::info!("Paused {RECEIVER_COLLATOR}, the receiver's collator");
	let sent = async {
		let (sent_at, ids) = submit_sudo(&sender, send_xcm_to(RECEIVER), true).await?;
		let [id] = ids.as_slice() else { return Err(anyhow!("expected one send")) };
		let number = sender.blocks().at(sent_at).await?.number();
		log::info!("{SENDER} block #{number} sent an XCM; waiting for {node} to finalize it");
		wait_for("the other sender node to finalize the send", || async {
			Ok(finalized_number(&other).await? >= number)
		})
		.await?;
		Ok(id.clone())
	}
	.await;
	let id = match sent {
		Ok(id) => id,
		Err(error) => {
			receiver_node.resume().await?;
			return Err(error);
		},
	};

	collator.pause().await?;
	receiver_node.resume().await?;
	log::info!(
		"Paused {SENDER_COLLATOR} and resumed {RECEIVER_COLLATOR}: only {node} serves {SENDER}"
	);
	let receiver: OnlineClient<PolkadotConfig> = receiver_node.wait_client().await?;
	let blocks = receiver.blocks().subscribe_finalized().await?;
	let delivered =
		check_destination(blocks, RECEIVER, &BTreeMap::from([(id, (SENDER, RECEIVER))])).await;
	collator.resume().await?;
	delivered?;
	log::info!("{RECEIVER} executed the XCM {node} served");
	Ok(())
}

/// Run `test` on a fresh network built in `mode`, under a time limit, and tear the network down.
async fn on_network<F, Fut>(mode: NetworkMode, minutes: u64, test: F) -> Result<(), anyhow::Error>
where
	F: FnOnce(Network<LocalFileSystem>) -> Fut,
	Fut: Future<Output = Result<Network<LocalFileSystem>, anyhow::Error>>,
{
	let _ = env_logger::try_init_from_env(
		env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
	);
	let network = initialize_network(build_network_config(mode)?).await?;
	let result = tokio::time::timeout(Duration::from_secs(minutes * 60), test(network)).await;
	match result {
		Ok(Ok(network)) => {
			network.destroy().await?;
			Ok(())
		},
		Ok(Err(error)) => Err(error),
		Err(_) => Err(anyhow!("the test exceeded {minutes} minutes")),
	}
}

/// Open the channel `SENDER -> RECEIVER` and wait until the receiver follows the sender and has
/// joined its DHT.
async fn open_and_join(network: &Network<LocalFileSystem>) -> Result<(), anyhow::Error> {
	let sender: OnlineClient<PolkadotConfig> =
		network.get_node(SENDER_COLLATOR)?.wait_client().await?;
	let receiver: OnlineClient<PolkadotConfig> =
		network.get_node(RECEIVER_COLLATOR)?.wait_client().await?;
	let start = (finalized_number(&sender).await?, finalized_number(&receiver).await?);
	wait_for("both chains to finalize a block", || {
		advanced(&sender, &receiver, (start.0 + 1, start.1 + 1))
	})
	.await?;
	open_spec_msg_channel(&sender, &receiver, SENDER, RECEIVER).await?;
	logged(network, RECEIVER_COLLATOR, &format!("Following {SENDER} on the relay chain DHT"), 1)
		.await?;
	logged(network, RECEIVER_COLLATOR, &format!("Joined the para's DHT. para_id={SENDER}"), 1).await
}

/// A sender node that publishes no provider record is found on the sender's own DHT, and serves
/// the receiver while the sender collator, the only node the relay chain DHT names, is paused.
#[tokio::test(flavor = "multi_thread")]
async fn spec_msg_finds_peer_no_provider_names() -> Result<(), anyhow::Error> {
	on_network(NetworkMode::HiddenSenderNode, 25, |network| async move {
		open_and_join(&network).await?;
		let hidden = peer_id_of(HIDDEN_NODE)?;
		logged(&network, RECEIVER_COLLATOR, &format!("Discovered a peer of the para.*{hidden}"), 1)
			.await?;
		served_by_while_collator_paused(&network, HIDDEN_NODE).await?;
		Ok(network)
	})
	.await
}

/// A sender node added after the channel opened is found, and serves the receiver while the
/// sender collator is paused.
#[tokio::test(flavor = "multi_thread")]
async fn spec_msg_rediscovers_after_sender_node_change() -> Result<(), anyhow::Error> {
	on_network(NetworkMode::Ordinary, 25, |mut network| async move {
		open_and_join(&network).await?;
		let args: Vec<zombienet_sdk::Arg> =
			vec![("-lspec-msg=debug,para-peers=debug").into(), ("--enable-spec-msg").into()];
		let options = AddCollatorOptions {
			is_validator: false,
			args,
			p2p_port: Some(HIDDEN_P2P_PORT),
			rpc_port: Some(HIDDEN_RPC_PORT),
			..Default::default()
		};
		network.add_collator(HIDDEN_NODE, options, SENDER).await?;
		log::info!("Added {HIDDEN_NODE} to {SENDER}");
		// Found on the sender's DHT or in the next relay chain DHT round, whichever comes first.
		let added = peer_id_of(HIDDEN_NODE)?;
		logged(
			&network,
			RECEIVER_COLLATOR,
			&format!("Discovered a peer of the para.*{added}|Found 2 nodes of {SENDER}"),
			1,
		)
		.await?;
		served_by_while_collator_paused(&network, HIDDEN_NODE).await?;
		Ok(network)
	})
	.await
}

/// Closing the channel stops the receiver following the sender, which leaves the sender's DHT.
/// Opening it again follows and joins it again, and delivers.
#[tokio::test(flavor = "multi_thread")]
async fn spec_msg_closed_channel_forgets_and_reopened_rejoins() -> Result<(), anyhow::Error> {
	on_network(NetworkMode::Ordinary, 25, |network| async move {
		open_and_join(&network).await?;
		let sender: OnlineClient<PolkadotConfig> =
			network.get_node(SENDER_COLLATOR)?.wait_client().await?;
		let receiver: OnlineClient<PolkadotConfig> =
			network.get_node(RECEIVER_COLLATOR)?.wait_client().await?;
		reopen_and_follow(&sender, &receiver).await?;
		logged(&network, RECEIVER_COLLATOR, &format!("No longer following {SENDER}"), 1).await?;
		logged(
			&network,
			RECEIVER_COLLATOR,
			&format!("Following {SENDER} on the relay chain DHT"),
			2,
		)
		.await?;
		logged(&network, RECEIVER_COLLATOR, &format!("Joined the para's DHT. para_id={SENDER}"), 2)
			.await?;
		Ok(network)
	})
	.await
}

/// A node that names a different genesis for the sender's para, and publishes a provider record
/// under the sender's key, is left out: the receiver keeps the sender's DHT and delivers.
///
/// The liar is a stock `polkadot-parachain` run outside zombienet on a copy of the sender's chain
/// spec with one extra genesis storage entry: the same para id, another genesis hash.
#[tokio::test(flavor = "multi_thread")]
async fn spec_msg_ignores_lying_provider() -> Result<(), anyhow::Error> {
	on_network(NetworkMode::Ordinary, 30, |network| async move {
		open_and_join(&network).await?;
		let _liar = Liar::spawn(&network)?;
		logged(
			&network,
			RECEIVER_COLLATOR,
			&format!("1 of 2 nodes of {SENDER} name another DHT or none; left them out"),
			1,
		)
		.await?;
		let joined = format!("Joined the para's DHT. para_id={SENDER}");
		anyhow::ensure!(
			logged_exactly(&network, RECEIVER_COLLATOR, &joined, 1).await?,
			"the receiver joined {SENDER}'s DHT again: the liar's genesis was followed"
		);

		let relay: OnlineClient<PolkadotConfig> = network.get_node("alice")?.wait_client().await?;
		let sender: OnlineClient<PolkadotConfig> =
			network.get_node(SENDER_COLLATOR)?.wait_client().await?;
		let receiver: OnlineClient<PolkadotConfig> =
			network.get_node(RECEIVER_COLLATOR)?.wait_client().await?;
		send_and_follow(&relay, &sender, &receiver).await?;
		Ok(network)
	})
	.await
}

/// A sender-chain node with another genesis, killed when dropped.
struct Liar(Child);

const LIAR_P2P_PORT: u16 = 30_503;
const LIAR_RELAY_P2P_PORT: u16 = 30_504;
const LIAR_RPC_PORT: u16 = 30_514;

impl Liar {
	fn spawn(network: &Network<LocalFileSystem>) -> Result<Self, anyhow::Error> {
		let collator = network.get_node(SENDER_COLLATOR)?;
		let cfg = collator.base_dir().join("cfg");
		let dir = collator
			.base_dir()
			.parent()
			.ok_or_else(|| anyhow!("{SENDER_COLLATOR}'s directory has no parent"))?
			.join("liar");
		std::fs::create_dir_all(&dir)?;
		let spec = Self::lying_spec(&cfg.join(format!("{SENDER}.json")), &dir)?;
		let alice = network.get_node("alice")?.multiaddr().to_string();
		let log = std::fs::File::create(dir.join("liar.log"))?;
		let child = Command::new("polkadot-parachain")
			.arg("--chain")
			.arg(&spec)
			.arg("--base-path")
			.arg(dir.join("data"))
			.args(["--name", "liar", "--no-prometheus", "--no-telemetry"])
			.args(["--listen-addr", &format!("/ip4/0.0.0.0/tcp/{LIAR_P2P_PORT}/ws")])
			.args(["--rpc-port", &LIAR_RPC_PORT.to_string()])
			.arg("--")
			.arg("--chain")
			.arg(cfg.join("rococo-local.json"))
			.arg("--base-path")
			.arg(dir.join("relay-data"))
			.args(["--port", &LIAR_RELAY_P2P_PORT.to_string(), "--no-prometheus"])
			.args(["--bootnodes", &alice])
			.stdout(Stdio::from(log.try_clone()?))
			.stderr(Stdio::from(log))
			.spawn()?;
		log::info!("Started the liar, logging to {}", dir.join("liar.log").display());
		Ok(Self(child))
	}

	/// The sender's raw chain spec with one extra genesis storage entry, written under `dir`.
	fn lying_spec(spec: &Path, dir: &Path) -> Result<std::path::PathBuf, anyhow::Error> {
		let mut json: serde_json::Value = serde_json::from_slice(&std::fs::read(spec)?)?;
		let top = json
			.pointer_mut("/genesis/raw/top")
			.and_then(|top| top.as_object_mut())
			.ok_or_else(|| anyhow!("{} has no raw genesis", spec.display()))?;
		top.insert("0x6c69617200".into(), "0x01".into());
		let out = dir.join("liar.json");
		std::fs::write(&out, serde_json::to_vec(&json)?)?;
		Ok(out)
	}
}

impl Drop for Liar {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}
