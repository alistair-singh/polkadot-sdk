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

//! The peers of other paras, found through the relay chain DHT (RFC-0008).
//!
//! On Polkadot no para publishes a bootnode record. This builds one per discovery round from the
//! para's providers on the relay chain DHT ([`SourceDiscovery`]), and hands each change of it to
//! [`para_peers::discover`], which joins the para's DHT as on JAM.
//!
//! Nothing tells this node which genesis hash and fork id the para has, and every `/paranode`
//! answer is untrusted. A record names the genesis hash and fork id most answering nodes agree on,
//! and lists only those nodes. Lying providers can at worst lead this node to another DHT, which
//! costs liveness: every message fetched from a peer is checked against the para's root on the
//! relay chain, and a peer whose data fails the check is banned.
//!
//! [`RelayPeers`] follows the paras this node exchanges messages with. A para it stops following
//! has its record cleared, which closes the instance and forgets the para's peers, as when a para
//! on JAM clears its record; the peers it banned stay banned.

use crate::common::para_peers::{self, Peers};
use codec::Encode;
use cumulus_client_bootnodes::{ParanodeAnswer, SourceDiscovery};
use cumulus_primitives_core::ParaId;
use cumulus_relay_chain_interface::RelayChainInterface;
use futures::{channel::oneshot, FutureExt, Stream};
use pallet_bootnodes::{BootnodeRecord, ForkId, MAX_BOOTNODES};
use sc_network::{
	config::ClientKademlia, multiaddr::Protocol, service::traits::NetworkService, Multiaddr, PeerId,
};
use sc_service::SpawnTaskHandle;
use std::{
	collections::{BTreeMap, BTreeSet},
	sync::Arc,
	time::Duration,
};
use tokio::sync::Semaphore;

const LOG_TARGET: &str = "relay-peers";

/// How long one discovery round on the relay chain DHT waits for answers.
const ROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// The time between two rounds while the para has peers: the relay DHT changes its key once an
/// epoch, and the para's DHT finds new peers on its own.
const ROUND_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The time between two rounds while the para has no usable record yet, or no peer left.
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// The DHT a `/paranode` answer names, if the names are of a shape this node could join.
fn dht_of(answer: &ParanodeAnswer) -> Option<([u8; 32], ForkId)> {
	let genesis = answer.genesis_hash.as_slice().try_into().ok()?;
	let fork_id = answer.fork_id.clone().unwrap_or_default().into_bytes();
	if !pallet_bootnodes::is_valid_fork_id(&fork_id) {
		return None;
	}
	Some((genesis, fork_id.try_into().ok()?))
}

/// `addr` of `peer_id` as a bootnode lists it, with `/p2p/<peer id>` at its end, if it has a
/// bootnode's shape and names no other peer.
fn bootnode_address(addr: &Multiaddr, peer_id: &PeerId, allow_private_ip: bool) -> Option<Vec<u8>> {
	let mut addr = addr.clone();
	match addr.iter().last() {
		Some(Protocol::P2p(named)) if PeerId::from_multihash(named).ok() != Some(*peer_id) => {
			return None
		},
		Some(Protocol::P2p(_)) => {},
		_ => addr.push(Protocol::P2p((*peer_id).into())),
	}
	let bytes = addr.to_vec();
	let (named, _) = para_peers::known_bootnode(&bytes, allow_private_ip)?;
	(named == *peer_id).then_some(bytes)
}

/// The record a discovery round's `answers` make: the DHT most answering nodes name, and up to
/// [`MAX_BOOTNODES`] addresses of those nodes, one per node before any node gets a second. Of DHTs
/// named equally often, `previous`'s is kept, or else the lowest. `None` without a usable answer.
pub(crate) fn record_from(
	answers: &[ParanodeAnswer],
	previous: Option<&BootnodeRecord>,
	allow_private_ip: bool,
) -> Option<BootnodeRecord> {
	let mut by_dht = BTreeMap::<([u8; 32], ForkId), Vec<(PeerId, Vec<Vec<u8>>)>>::new();
	for answer in answers {
		let Some(dht) = dht_of(answer) else {
			log::debug!(target: LOG_TARGET, "Skipping node {}: unusable genesis hash or fork id", answer.peer_id);
			continue;
		};
		let addresses = answer
			.addresses
			.iter()
			.filter_map(|addr| bootnode_address(addr, &answer.peer_id, allow_private_ip))
			.collect::<Vec<_>>();
		if addresses.is_empty() {
			continue;
		}
		let nodes = by_dht.entry(dht).or_default();
		if !nodes.iter().any(|(peer_id, _)| *peer_id == answer.peer_id) {
			nodes.push((answer.peer_id, addresses));
		}
	}
	let most = by_dht.values().map(Vec::len).max()?;
	let previous = previous.map(|record| (record.genesis, record.fork_id.clone()));
	let tied = by_dht.iter().filter(|(_, nodes)| nodes.len() == most).map(|(dht, _)| dht);
	let chosen = tied
		.clone()
		.find(|dht| Some(*dht) == previous.as_ref())
		.or_else(|| tied.min())?
		.clone();
	if by_dht.len() > 1 {
		log::debug!(
			target: LOG_TARGET,
			"Nodes disagree on the para's DHT; following the one {most} of them name",
		);
	}
	let mut nodes = by_dht.remove(&chosen)?;
	nodes.sort_by_key(|(peer_id, _)| peer_id.to_bytes());

	let mut addresses = Vec::new();
	let deepest = nodes.iter().map(|(_, addresses)| addresses.len()).max().unwrap_or_default();
	'fill: for depth in 0..deepest {
		for (_, node_addresses) in &nodes {
			if addresses.len() >= MAX_BOOTNODES as usize {
				break 'fill;
			}
			if let Some(addr) = node_addresses.get(depth) {
				addresses.push(addr.clone().try_into().ok()?);
			}
		}
	}
	Some(BootnodeRecord {
		genesis: chosen.0,
		fork_id: chosen.1,
		addresses: addresses.try_into().ok()?,
	})
}

/// What [`records`] waits on between rounds.
struct Rounds {
	discovery: SourceDiscovery,
	peers: Peers,
	local_para_peer: PeerId,
	allow_private_ip: bool,
	previous: Option<BootnodeRecord>,
	stop: futures::future::Fuse<oneshot::Receiver<()>>,
	first: bool,
	stopped: bool,
}

/// The values [`para_peers::discover`] follows for one para: each change of the record its rounds
/// build, and once `stop` fires or is dropped a cleared record, after which the stream ends.
fn records(rounds: Rounds) -> impl Stream<Item = Option<Vec<u8>>> + Unpin {
	Box::pin(futures::stream::unfold(rounds, |mut rounds| async move {
		if rounds.stopped {
			return None;
		}
		loop {
			if !rounds.first {
				let wait = if rounds.previous.is_none() || rounds.peers.peers().is_empty() {
					RETRY_INTERVAL
				} else {
					ROUND_INTERVAL
				};
				futures::select! {
					_ = futures_timer::Delay::new(wait).fuse() => {},
					_ = &mut rounds.stop => {
						rounds.stopped = true;
						return Some((None, rounds));
					},
				}
			}
			rounds.first = false;
			let para_id = rounds.discovery.para_id();
			let round = rounds.discovery.round(ROUND_TIMEOUT, rounds.local_para_peer).fuse();
			let answers = futures::select! {
				answers = Box::pin(round) => answers,
				_ = &mut rounds.stop => {
					rounds.stopped = true;
					return Some((None, rounds));
				},
			};
			let answers = match answers {
				Ok(answers) => answers,
				Err(error) => {
					log::warn!(target: LOG_TARGET, "Discovery round of {para_id:?} failed: {error}");
					continue;
				},
			};
			let Some(record) =
				record_from(&answers, rounds.previous.as_ref(), rounds.allow_private_ip)
			else {
				log::debug!(target: LOG_TARGET, "No usable node of {para_id:?} on the relay chain DHT yet");
				continue;
			};
			let chosen = Some((record.genesis, record.fork_id.clone()));
			let dissenting = answers.iter().filter(|answer| dht_of(answer) != chosen).count();
			if dissenting > 0 {
				log::info!(
					target: LOG_TARGET,
					"{dissenting} of {} nodes of {para_id:?} name another DHT or none; left them out",
					answers.len(),
				);
			}
			if rounds.previous.as_ref() == Some(&record) {
				continue;
			}
			log::info!(
				target: LOG_TARGET,
				"Found {} nodes of {para_id:?} on the relay chain DHT; its record has {} addresses",
				answers.len(),
				record.addresses.len(),
			);
			let value = record.encode();
			rounds.previous = Some(record);
			return Some((Some(value), rounds));
		}
	}))
}

/// A para followed by [`RelayPeers`].
struct Followed {
	/// Its peers, kept after it is no longer followed so that the peers it banned stay banned.
	peers: Peers,
	/// Dropped to stop following it.
	stop: Option<oneshot::Sender<()>>,
}

/// The paras this node follows on the relay chain DHT, and their peers.
#[derive(Clone)]
pub(crate) struct RelayPeers {
	own: ParaId,
	relay_chain_interface: Arc<dyn RelayChainInterface>,
	relay_chain_network: Arc<dyn NetworkService>,
	relay_chain_fork_id: Option<String>,
	parachain_network: Arc<dyn NetworkService>,
	kademlia: ClientKademlia,
	allow_private_ip: bool,
	queries: Arc<Semaphore>,
	spawner: SpawnTaskHandle,
	followed: Arc<parking_lot::Mutex<BTreeMap<ParaId, Followed>>>,
}

/// What [`RelayPeers::new`] needs.
pub(crate) struct RelayPeersParams {
	pub own: ParaId,
	pub relay_chain_interface: Arc<dyn RelayChainInterface>,
	pub relay_chain_network: Arc<dyn NetworkService>,
	pub relay_chain_fork_id: Option<String>,
	pub parachain_network: Arc<dyn NetworkService>,
	pub kademlia: ClientKademlia,
	pub allow_private_ip: bool,
	pub spawner: SpawnTaskHandle,
}

impl RelayPeers {
	pub(crate) fn new(params: RelayPeersParams) -> Self {
		Self {
			own: params.own,
			relay_chain_interface: params.relay_chain_interface,
			relay_chain_network: params.relay_chain_network,
			relay_chain_fork_id: params.relay_chain_fork_id,
			parachain_network: params.parachain_network,
			kademlia: params.kademlia,
			allow_private_ip: params.allow_private_ip,
			queries: para_peers::discovery_queries(),
			spawner: params.spawner,
			followed: Default::default(),
		}
	}

	/// The peers of `para`, if it was ever followed.
	pub(crate) fn peers(&self, para: ParaId) -> Option<Peers> {
		self.followed.lock().get(&para).map(|followed| followed.peers.clone())
	}

	/// Follow exactly `paras`, as far as [`para_peers::paras_to_follow`] allows: start the ones not
	/// followed yet, and stop the others.
	pub(crate) fn follow(&self, paras: &BTreeSet<ParaId>) {
		let wanted = para_peers::paras_to_follow(
			&paras.iter().copied().map(u32::from).collect::<Vec<_>>(),
			self.own.into(),
		)
		.into_iter()
		.map(ParaId::from)
		.collect::<BTreeSet<_>>();
		let mut followed = self.followed.lock();
		for (para, entry) in followed.iter_mut() {
			if !wanted.contains(para) && entry.stop.take().is_some() {
				log::info!(target: LOG_TARGET, "No longer following {para:?}");
			}
		}
		for para in wanted {
			let local = self.parachain_network.local_peer_id();
			let entry = followed.entry(para).or_insert_with(|| Followed {
				peers: Peers::new(para.into(), self.allow_private_ip, local),
				stop: None,
			});
			if entry.stop.is_some() {
				continue;
			}
			let (stop, stopped) = oneshot::channel();
			entry.stop = Some(stop);
			log::info!(target: LOG_TARGET, "Following {para:?} on the relay chain DHT");
			self.spawner.spawn(
				"spec-msg-relay-peers",
				Some("spec-msg"),
				self.clone().run(para, entry.peers.clone(), stopped),
			);
		}
	}

	async fn run(self, para: ParaId, peers: Peers, stop: oneshot::Receiver<()>) {
		let discovery = match SourceDiscovery::new(
			para,
			self.relay_chain_interface.clone(),
			self.relay_chain_network.clone(),
			self.relay_chain_fork_id.clone(),
		)
		.await
		{
			Ok(discovery) => discovery,
			Err(error) => {
				log::error!(target: LOG_TARGET, "Unable to discover {para:?}: {error}");
				return;
			},
		};
		let values = records(Rounds {
			discovery,
			peers: peers.clone(),
			local_para_peer: self.parachain_network.local_peer_id(),
			allow_private_ip: self.allow_private_ip,
			previous: None,
			stop: stop.fuse(),
			first: true,
			stopped: false,
		});
		para_peers::discover(
			peers,
			None,
			values,
			self.kademlia.clone(),
			self.parachain_network.clone(),
			self.queries.clone(),
		)
		.await;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn answer(
		peer_id: PeerId,
		addrs: &[&str],
		genesis: u8,
		fork_id: Option<&str>,
	) -> ParanodeAnswer {
		ParanodeAnswer {
			provider: PeerId::random(),
			peer_id,
			addresses: addrs
				.iter()
				.map(|addr| addr.parse().expect("a test address; qed"))
				.collect(),
			genesis_hash: vec![genesis; 32],
			fork_id: fork_id.map(Into::into),
		}
	}

	fn ed25519_peer() -> PeerId {
		use sp_core::Pair as _;
		let key = sp_core::ed25519::Pair::generate().0;
		PeerId::from_ed25519(&key.public().0).expect("an ed25519 key; qed")
	}

	fn peers_of(record: &BootnodeRecord) -> Vec<PeerId> {
		let mut peers = record
			.addresses
			.iter()
			.filter_map(|addr| Multiaddr::try_from(addr.to_vec()).ok())
			.filter_map(|addr| PeerId::try_from_multiaddr(&addr))
			.collect::<Vec<_>>();
		peers.dedup();
		peers
	}

	#[test]
	fn the_dht_most_nodes_name_wins_and_dissenters_are_left_out() {
		let (a, b, liar) = (ed25519_peer(), ed25519_peer(), ed25519_peer());
		let answers = [
			answer(a, &["/ip4/8.8.8.8/tcp/1"], 1, None),
			answer(liar, &["/ip4/8.8.4.4/tcp/1"], 2, None),
			answer(b, &["/ip4/1.1.1.1/tcp/1"], 1, None),
		];
		let record = record_from(&answers, None, false).expect("two nodes agree; qed");
		assert_eq!(record.genesis, [1; 32]);
		assert!(record.fork_id.is_empty());
		let peers = peers_of(&record);
		assert!(peers.contains(&a) && peers.contains(&b) && !peers.contains(&liar));
	}

	#[test]
	fn a_tie_keeps_the_previous_dht_or_else_the_lowest() {
		let (a, b) = (ed25519_peer(), ed25519_peer());
		let answers = [
			answer(a, &["/ip4/8.8.8.8/tcp/1"], 2, None),
			answer(b, &["/ip4/1.1.1.1/tcp/1"], 1, None),
		];
		assert_eq!(record_from(&answers, None, false).unwrap().genesis, [1; 32]);
		let previous = record_from(&answers[..1], None, false).unwrap();
		assert_eq!(record_from(&answers, Some(&previous), false).unwrap().genesis, [2; 32]);
	}

	#[test]
	fn an_answer_with_an_unusable_dht_is_left_out() {
		let peer = ed25519_peer();
		let bad_fork = answer(peer, &["/ip4/8.8.8.8/tcp/1"], 1, Some("a/b"));
		let short_genesis = ParanodeAnswer { genesis_hash: vec![1; 31], ..bad_fork.clone() };
		assert_eq!(record_from(&[bad_fork, short_genesis], None, false), None);
		let fork = answer(peer, &["/ip4/8.8.8.8/tcp/1"], 1, Some("fork-1"));
		assert_eq!(record_from(&[fork], None, false).unwrap().fork_id.to_vec(), b"fork-1".to_vec());
	}

	#[test]
	fn addresses_get_the_nodes_peer_id_and_other_peers_or_private_ips_are_dropped() {
		let (node, other) = (ed25519_peer(), ed25519_peer());
		let foreign = format!("/ip4/8.8.4.4/tcp/2/p2p/{other}");
		let answers = [answer(
			node,
			&["/ip4/8.8.8.8/tcp/1", "/ip4/127.0.0.1/tcp/1", foreign.as_str()],
			1,
			None,
		)];
		let record = record_from(&answers, None, false).unwrap();
		let expected = format!("/ip4/8.8.8.8/tcp/1/p2p/{node}").parse::<Multiaddr>().unwrap();
		let listed = record.addresses.iter().map(|addr| addr.to_vec()).collect::<Vec<_>>();
		assert_eq!(listed, vec![expected.to_vec()]);

		let with_private = record_from(&answers, None, true).unwrap();
		assert_eq!(with_private.addresses.len(), 2);
	}

	#[test]
	fn a_node_without_a_usable_address_does_not_count() {
		let (a, b, c) = (ed25519_peer(), ed25519_peer(), ed25519_peer());
		let answers = [
			answer(a, &["/ip4/127.0.0.1/tcp/1"], 2, None),
			answer(b, &["/ip4/127.0.0.1/tcp/1"], 2, None),
			answer(c, &["/ip4/8.8.8.8/tcp/1"], 1, None),
		];
		assert_eq!(record_from(&answers, None, false).unwrap().genesis, [1; 32]);
	}

	#[test]
	fn every_node_gets_one_address_before_any_gets_a_second() {
		let nodes = (0..5).map(|_| ed25519_peer()).collect::<Vec<_>>();
		let answers = nodes
			.iter()
			.map(|node| {
				answer(
					*node,
					&["/ip4/8.8.8.8/tcp/1", "/ip4/8.8.8.8/tcp/2", "/ip4/8.8.8.8/tcp/3"],
					1,
					None,
				)
			})
			.collect::<Vec<_>>();
		let record = record_from(&answers, None, false).unwrap();
		assert_eq!(record.addresses.len(), MAX_BOOTNODES as usize);
		let mut peers = peers_of(&record);
		peers.sort();
		peers.dedup();
		assert_eq!(peers.len(), nodes.len());
	}

	#[test]
	fn no_usable_answer_makes_no_record() {
		assert_eq!(record_from(&[], None, false), None);
	}
}
