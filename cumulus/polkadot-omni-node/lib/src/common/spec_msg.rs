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

//! Speculative messaging in `NodeSpec::start_node`.
//!
//! Every node with `--enable-spec-msg` archives the own chain's sends and serves them over
//! `/spec-msg/fetch/1`. A collator also runs the receiver: it fetches from the source chains,
//! feeds the messaging inherent and assembles the lifts of each collation. All of it stays idle
//! while the runtime has no `SpecMsgApi`.
//!
//! No peer is configured. The paras to fetch from are the ones the runtime's channels name, and
//! their peers are found through the relay chain DHT and each para's own DHT ([`RelayPeers`]).
//! The own chain's peers, which the archive backfills from, are the ones sync is connected to.

use crate::common::{
	para_peers,
	relay_peers::{RelayPeers, RelayPeersParams},
	types::{ParachainBackend, ParachainClient},
	ConstructNodeRuntimeApi, NodeBlock,
};
use cumulus_client_spec_msg::{
	fetch_protocol_config, run_archiver, run_receiver, run_request_handler, run_watermark_reader,
	Archive, AuxArchiveStore, Budget, NetworkTransport, Outcome, Receiver, RelayFinalizedRoots,
	Transport,
};
use cumulus_primitives_core::{ParaId, SpecMsgApi};
use cumulus_primitives_spec_messaging::StreamId;
use cumulus_relay_chain_interface::RelayChainInterface;
use futures::StreamExt;
use parachains_common_types::Hash;
use sc_client_api::BlockchainEvents;
use sc_network::{
	config::{ClientKademlia, FullNetworkConfiguration, IncomingRequest},
	service::traits::NetworkService,
	Multiaddr, NetworkBackend, PeerId,
};
use sc_network_sync::SyncingService;
use sc_service::TaskManager;
use sp_api::ProvideRuntimeApi;
use std::{
	collections::{BTreeMap, BTreeSet, HashSet},
	sync::Arc,
	time::Duration,
};

const LOG_TARGET: &str = "spec-msg";

/// How often the own chain's peers are read from sync.
const OWN_PEERS_INTERVAL: Duration = Duration::from_secs(30);

/// Speculative messaging configuration.
#[derive(Clone, Debug, Default)]
pub struct SpecMsgConfig {}

/// What [`start`] needs from the node beyond the parachain client.
pub(crate) struct SpecMsgNetwork<Block: NodeBlock> {
	/// The parachain network.
	pub network: Arc<dyn NetworkService>,
	/// The parachain network's sync, whose peers are the own chain's.
	pub sync_service: Arc<SyncingService<Block>>,
	/// The relay chain network, whose DHT names the other paras' nodes.
	pub relay_chain_network: Arc<dyn NetworkService>,
	pub relay_chain_fork_id: Option<String>,
	/// Opens instances on the other paras' DHTs.
	pub kademlia: ClientKademlia,
	pub allow_private_ip: bool,
}
/// The receiver a collator feeds its inherent and collations from.
pub(crate) type SpecMsgReceiver = Arc<Receiver<Hash, dyn Transport>>;

/// Register `/spec-msg/fetch/1` in the network configuration. Returns the inbound requests
/// for [`start`].
pub(crate) fn register_protocol<Block: NodeBlock, Net: NetworkBackend<Block, Hash>>(
	net_config: &mut FullNetworkConfiguration<Block, Hash, Net>,
) -> async_channel::Receiver<IncomingRequest> {
	let (config, requests) = fetch_protocol_config::<Block, Net>();
	net_config.add_request_response_protocol(config);
	requests
}

/// Spawn the archiver and the request handler and, on a collator, the receiver.
pub(crate) fn start<Block, RuntimeApi>(
	_config: &SpecMsgConfig,
	client: Arc<ParachainClient<Block, RuntimeApi>>,
	backend: Arc<ParachainBackend<Block>>,
	net: SpecMsgNetwork<Block>,
	relay_chain_interface: Arc<dyn RelayChainInterface>,
	task_manager: &TaskManager,
	requests: async_channel::Receiver<IncomingRequest>,
	para_id: ParaId,
	collator: bool,
) -> Option<SpecMsgReceiver>
where
	Block: NodeBlock,
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
{
	let archive =
		Arc::new(parking_lot::RwLock::new(Archive::open(AuxArchiveStore::new(client.clone()))));
	let watermarks = Arc::new(parking_lot::Mutex::new(BTreeMap::new()));

	let spawner = task_manager.spawn_handle();
	let relay_peers = RelayPeers::new(RelayPeersParams {
		own: para_id,
		relay_chain_interface: relay_chain_interface.clone(),
		relay_chain_network: net.relay_chain_network,
		relay_chain_fork_id: net.relay_chain_fork_id,
		parachain_network: net.network.clone(),
		kademlia: net.kademlia,
		allow_private_ip: net.allow_private_ip,
		spawner: spawner.clone(),
	});
	let own_peers = Arc::new(parking_lot::Mutex::new(Vec::new()));
	spawner.spawn(
		"spec-msg-own-peers",
		Some("spec-msg"),
		read_own_peers(net.sync_service, own_peers.clone()),
	);
	spawner.spawn(
		"spec-msg-followed-paras",
		Some("spec-msg"),
		follow_channel_paras::<Block, _>(client.clone(), relay_peers.clone(), collator),
	);
	let transport: Arc<dyn Transport> = Arc::new(DiscoveredTransport {
		us: para_id,
		network: net.network.clone(),
		requests: NetworkTransport::new(net.network, BTreeMap::new()),
		relay_peers,
		own_peers,
		known: Default::default(),
	});

	spawner.spawn_blocking(
		"spec-msg-archiver",
		Some("spec-msg"),
		run_archiver::<Block, _, _>(
			client.clone(),
			backend.clone(),
			archive.clone(),
			watermarks.clone(),
		),
	);
	spawner.spawn(
		"spec-msg-watermark-reader",
		Some("spec-msg"),
		run_watermark_reader::<Block, _, _, _, _>(
			client.clone(),
			archive.clone(),
			watermarks,
			para_id,
			transport.clone(),
			Arc::new(RelayFinalizedRoots(relay_chain_interface.clone())),
		),
	);
	spawner.spawn_blocking(
		"spec-msg-request-handler",
		Some("spec-msg"),
		run_request_handler(archive, requests),
	);
	if !collator {
		return None;
	}

	let receiver: SpecMsgReceiver = Arc::new(Receiver::new(para_id, Budget::default(), transport));
	spawner.spawn(
		"spec-msg-receiver",
		Some("spec-msg"),
		run_receiver::<Block, _, _, _>(client, backend, relay_chain_interface, receiver.clone()),
	);
	Some(receiver)
}

/// [`Transport`] to the peers [`RelayPeers`] found for other paras, and to the own chain's sync
/// peers.
struct DiscoveredTransport {
	us: ParaId,
	network: Arc<dyn NetworkService>,
	requests: NetworkTransport,
	relay_peers: RelayPeers,
	own_peers: Arc<parking_lot::Mutex<Vec<PeerId>>>,
	/// The addresses already given to the network, so each is given once.
	known: parking_lot::Mutex<HashSet<(PeerId, Multiaddr)>>,
}

#[async_trait::async_trait]
impl Transport for DiscoveredTransport {
	fn peers(&self, source: ParaId) -> Vec<PeerId> {
		if source == self.us {
			return self.own_peers.lock().clone();
		}
		let Some(peers) = self.relay_peers.peers(source) else { return Vec::new() };
		let peers = peers.peers();
		let mut known = self.known.lock();
		for (peer_id, addresses) in &peers {
			for addr in addresses {
				if known.insert((*peer_id, addr.clone())) {
					self.network.add_known_address(*peer_id, addr.clone());
				}
			}
		}
		peers.into_iter().map(|(peer_id, _)| peer_id).collect()
	}

	async fn request(&self, peer: PeerId, request: Vec<u8>) -> Result<Vec<u8>, String> {
		self.requests.request(peer, request).await
	}

	fn report(&self, source: ParaId, peer: PeerId, outcome: Outcome) {
		if source == self.us {
			return;
		}
		if let Some(peers) = self.relay_peers.peers(source) {
			peers.report(
				peer,
				match outcome {
					Outcome::Served => para_peers::Outcome::Success,
					Outcome::Failed => para_peers::Outcome::RequestFailed,
					Outcome::Bad => para_peers::Outcome::Garbage,
				},
			);
		}
	}
}

/// Keep `own_peers` at the peers sync is connected to.
async fn read_own_peers<Block: NodeBlock>(
	sync_service: Arc<SyncingService<Block>>,
	own_peers: Arc<parking_lot::Mutex<Vec<PeerId>>>,
) {
	let mut interval = tokio::time::interval(OWN_PEERS_INTERVAL);
	loop {
		interval.tick().await;
		match sync_service.peers_info().await {
			Ok(peers) => *own_peers.lock() = peers.into_iter().map(|(peer, _)| peer).collect(),
			Err(_) => return,
		}
	}
}

/// The other paras the runtime's channels at `at` name: the recipients of the outbound
/// channels, whose registers the watermark reader reads, and on a collator the paras the
/// receiver consumes from.
fn channel_paras<Block, RuntimeApi>(
	client: &ParachainClient<Block, RuntimeApi>,
	at: Block::Hash,
	collator: bool,
) -> Option<BTreeSet<ParaId>>
where
	Block: NodeBlock,
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
{
	use sp_api::ApiExt;
	let api = client.runtime_api();
	if !api.has_api::<dyn SpecMsgApi<Block>>(at).ok()? {
		return None;
	}
	let mut paras = BTreeSet::new();
	for (stream, _) in api.outbound_frontiers(at).ok()? {
		if let StreamId::Channel { recipient, .. } = stream {
			paras.insert(recipient);
		}
	}
	if collator {
		let consumed = api.consumed_streams(at).ok()?;
		paras.extend(consumed.channels.keys().map(|id| id.sender));
		paras.extend(consumed.registers.keys().map(|id| id.recipient));
		paras.extend(consumed.events.keys().map(|id| id.sender));
	}
	Some(paras)
}

/// Follow the paras [`channel_paras`] names at each new best block.
async fn follow_channel_paras<Block, RuntimeApi>(
	client: Arc<ParachainClient<Block, RuntimeApi>>,
	relay_peers: RelayPeers,
	collator: bool,
) where
	Block: NodeBlock,
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
{
	let mut imports = client.import_notification_stream();
	let mut current = None;
	while let Some(import) = imports.next().await {
		if !import.is_new_best {
			continue;
		}
		let Some(paras) = channel_paras(&client, import.hash, collator) else { continue };
		if current.as_ref() != Some(&paras) {
			log::debug!(target: LOG_TARGET, "Channels name the paras {paras:?}");
			relay_peers.follow(&paras);
			current = Some(paras);
		}
	}
}
