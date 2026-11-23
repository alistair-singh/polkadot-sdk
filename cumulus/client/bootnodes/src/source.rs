// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus. If not, see <https://www.gnu.org/licenses/>.

//! Discovery of another para's nodes on the relay chain DHT (RFC-0008), by a node that is not one
//! of them.
//!
//! [`crate::discovery`] finds the nodes of this node's own para, and so knows the genesis hash and
//! fork id a `/paranode` answer must name. A node of another para does not. [`SourceDiscovery`]
//! therefore returns every answer of a round, genesis hash and fork id included, and leaves it to
//! the caller to choose which to trust.
//!
//! A round is [`SourceDiscovery::round`]: look up the para's providers under the current epoch's
//! key, ask each over `/paranode`, and if a direct request fails find the provider on the relay
//! chain DHT first and ask once more, as [`crate::discovery`] does.

use crate::{
	config::{paranode_protocol_name, MAX_ADDRESSES},
	schema::Response,
};
use codec::{CompactRef, Decode, Encode};
use cumulus_primitives_core::{relay_chain::BlockId, ParaId};
use cumulus_relay_chain_interface::{RelayChainError, RelayChainInterface, RelayChainResult};
use futures::{
	channel::oneshot, future::BoxFuture, pin_mut, stream::FuturesUnordered, FutureExt, StreamExt,
};
use log::{debug, trace};
use num_traits::Zero;
use prost::Message;
use sc_network::{
	event::{DhtEvent, Event},
	request_responses::{IfDisconnected, RequestFailure},
	service::traits::NetworkService,
	KademliaKey, Multiaddr, PeerId, ProtocolName,
};
use sp_consensus_babe::Epoch;
use std::{collections::HashSet, sync::Arc, time::Duration};

const LOG_TARGET: &str = "bootnodes::source";

/// The most providers one round asks over `/paranode`. Anyone can publish a provider record under
/// a para's key, so a round asks a random sample of those found rather than all of them.
pub const MAX_PROVIDERS_ASKED: usize = 16;

/// The providers of `found` to ask next, in random order: those not yet `asked` and not
/// `local`, while fewer than [`MAX_PROVIDERS_ASKED`] have been asked. Each is added to `asked`.
fn to_ask(
	found: impl IntoIterator<Item = PeerId>,
	asked: &mut HashSet<PeerId>,
	local: &PeerId,
) -> Vec<PeerId> {
	use rand::seq::SliceRandom;
	let mut fresh: Vec<PeerId> =
		found.into_iter().filter(|p| p != local && !asked.contains(p)).collect();
	fresh.sort();
	fresh.dedup();
	fresh.shuffle(&mut rand::thread_rng());
	fresh.truncate(MAX_PROVIDERS_ASKED.saturating_sub(asked.len()));
	asked.extend(fresh.iter().copied());
	fresh
}

/// A `/paranode` answer from a provider of another para. Nothing in it is checked but its shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParanodeAnswer {
	/// The provider on the relay chain that answered.
	pub provider: PeerId,
	/// The para node the answer names.
	pub peer_id: PeerId,
	/// Its addresses on the para's network, at most [`MAX_ADDRESSES`].
	pub addresses: Vec<Multiaddr>,
	/// The genesis hash it claims for the para.
	pub genesis_hash: Vec<u8>,
	/// The fork id it claims for the para.
	pub fork_id: Option<String>,
}

/// The answer in `payload` from `provider`, or why it is unusable.
pub fn decode_answer(provider: PeerId, payload: &[u8]) -> Result<ParanodeAnswer, String> {
	let response = Response::decode(payload).map_err(|e| format!("not a response: {e}"))?;
	let peer_id = PeerId::from_bytes(&response.peer_id).map_err(|e| format!("bad peer id: {e}"))?;
	let addresses = response
		.addrs
		.into_iter()
		.take(MAX_ADDRESSES)
		.map(Multiaddr::try_from)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|e| format!("bad address: {e}"))?;
	Ok(ParanodeAnswer {
		provider,
		peer_id,
		addresses,
		genesis_hash: response.genesis_hash,
		fork_id: response.fork_id,
	})
}

type PendingResponse = BoxFuture<
	'static,
	(PeerId, Result<Result<(Vec<u8>, ProtocolName), RequestFailure>, oneshot::Canceled>),
>;

/// Finds the nodes of one other para on the relay chain DHT, a round at a time.
pub struct SourceDiscovery {
	para_id: ParaId,
	para_id_scale_compact: Vec<u8>,
	relay_chain_interface: Arc<dyn RelayChainInterface>,
	relay_chain_network: Arc<dyn NetworkService>,
	paranode_protocol_name: ProtocolName,
}

impl SourceDiscovery {
	/// Discovery of `para_id`'s nodes over `relay_chain_network`, whose chain has
	/// `relay_chain_fork_id`.
	pub async fn new(
		para_id: ParaId,
		relay_chain_interface: Arc<dyn RelayChainInterface>,
		relay_chain_network: Arc<dyn NetworkService>,
		relay_chain_fork_id: Option<String>,
	) -> RelayChainResult<Self> {
		let genesis = relay_chain_interface
			.header(BlockId::Number(Zero::zero()))
			.await?
			.ok_or_else(|| RelayChainError::GenericError("no relay chain genesis".into()))?
			.hash();
		Ok(Self {
			para_id,
			para_id_scale_compact: CompactRef(&para_id).encode(),
			relay_chain_interface,
			relay_chain_network,
			paranode_protocol_name: paranode_protocol_name(
				genesis.as_bytes(),
				relay_chain_fork_id.as_deref(),
			),
		})
	}

	/// The para this discovers.
	pub fn para_id(&self) -> ParaId {
		self.para_id
	}

	/// The provider key of the current epoch at the relay chain's best block.
	async fn current_key(&self) -> RelayChainResult<KademliaKey> {
		let best = self.relay_chain_interface.best_block_hash().await?;
		let epoch = self
			.relay_chain_interface
			.call_runtime_api("BabeApi_current_epoch", best, &[])
			.await?;
		let epoch = Epoch::decode(&mut &*epoch)?;
		Ok(self
			.para_id_scale_compact
			.iter()
			.copied()
			.chain(epoch.randomness)
			.collect::<Vec<_>>()
			.into())
	}

	fn request(&self, peer_id: PeerId, pending: &FuturesUnordered<PendingResponse>) {
		trace!(target: LOG_TARGET, "Asking {peer_id:?} for a node of {:?}", self.para_id);
		let (tx, rx) = oneshot::channel();
		self.relay_chain_network.start_request(
			peer_id,
			self.paranode_protocol_name.clone(),
			self.para_id_scale_compact.clone(),
			None,
			tx,
			IfDisconnected::TryConnect,
		);
		pending.push(async move { (peer_id, rx.await) }.boxed());
	}

	/// One round: every answer the para's providers give within `timeout`, at most one per para
	/// node, never one naming `local_para_peer`.
	pub async fn round(
		&self,
		timeout: Duration,
		local_para_peer: PeerId,
	) -> RelayChainResult<Vec<ParanodeAnswer>> {
		let para_id = self.para_id;
		// Subscribed before the lookup starts, so that none of its events is missed.
		let events = self
			.relay_chain_network
			.event_stream("parachain-source-discovery")
			.filter_map(|event| async move {
				match event {
					Event::Dht(event) => Some(event),
					_ => None,
				}
			})
			.fuse();
		pin_mut!(events);
		let key = self.current_key().await?;
		self.relay_chain_network.get_providers(key.clone());
		debug!(target: LOG_TARGET, "Looking up the providers of {para_id:?}");

		let local_relay_peer = self.relay_chain_network.local_peer_id();
		let mut looking_up = true;
		let mut asked = HashSet::new();
		let mut direct = HashSet::new();
		let mut finding = HashSet::new();
		let pending = FuturesUnordered::<PendingResponse>::new();
		pin_mut!(pending);
		let mut answers: Vec<ParanodeAnswer> = Vec::new();
		let deadline = tokio::time::sleep(timeout);
		pin_mut!(deadline);

		while looking_up || !pending.is_empty() || !finding.is_empty() {
			tokio::select! {
				_ = &mut deadline => {
					debug!(target: LOG_TARGET, "A discovery round of {para_id:?} timed out");
					break;
				},
				event = events.select_next_some() => match event {
					DhtEvent::ProvidersFound(found, providers) if found == key => {
						for provider in to_ask(providers, &mut asked, &local_relay_peer) {
							direct.insert(provider);
							self.request(provider, &pending);
						}
					},
					DhtEvent::NoMoreProviders(found) | DhtEvent::ProvidersNotFound(found)
						if found == key => looking_up = false,
					DhtEvent::ClosestPeersFound(target, peers) if finding.remove(&target) => {
						match peers.into_iter().find(|(peer, addrs)| *peer == target && !addrs.is_empty()) {
							Some((_, addrs)) => {
								for addr in addrs {
									self.relay_chain_network.add_known_address(target, addr);
								}
								self.request(target, &pending);
							},
							None => debug!(target: LOG_TARGET, "No addresses for provider {target:?} of {para_id:?}"),
						}
					},
					DhtEvent::ClosestPeersNotFound(target) if finding.remove(&target) =>
						debug!(target: LOG_TARGET, "No addresses for provider {target:?} of {para_id:?}"),
					_ => {},
				},
				(provider, result) = pending.select_next_some(), if !pending.is_empty() => {
					let was_direct = direct.remove(&provider);
					let payload = match result {
						Ok(Ok((payload, _))) => payload,
						Ok(Err(error)) if was_direct => {
							debug!(target: LOG_TARGET, "Provider {provider:?} of {para_id:?} did not answer ({error}); finding it on the DHT");
							finding.insert(provider);
							self.relay_chain_network.find_closest_peers(provider);
							continue;
						},
						Ok(Err(error)) => {
							debug!(target: LOG_TARGET, "Provider {provider:?} of {para_id:?} did not answer: {error}");
							continue;
						},
						Err(_) => continue,
					};
					match decode_answer(provider, &payload) {
						Ok(answer) if answer.peer_id == local_para_peer => {},
						Ok(answer) if answers.iter().any(|known| known.peer_id == answer.peer_id) => {},
						Ok(answer) => answers.push(answer),
						Err(error) => debug!(target: LOG_TARGET, "Unusable answer from {provider:?} for {para_id:?}: {error}"),
					}
				},
			}
		}
		debug!(target: LOG_TARGET, "Found {} nodes of {para_id:?} on the relay chain DHT", answers.len());
		Ok(answers)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_round_asks_at_most_max_providers_never_twice_nor_itself() {
		let local = PeerId::random();
		let found: Vec<PeerId> = (0..40).map(|_| PeerId::random()).collect();
		let mut asked = HashSet::new();

		let first =
			to_ask(found[..10].iter().copied().chain([local, found[0]]), &mut asked, &local);
		assert_eq!(first.len(), 10);
		assert!(!first.contains(&local));

		// A later batch repeats some of the first: only new ones are asked, up to the cap.
		let second = to_ask(found.iter().copied(), &mut asked, &local);
		assert_eq!(second.len(), MAX_PROVIDERS_ASKED - 10);
		assert!(second.iter().all(|p| !first.contains(p)));
		assert_eq!(asked.len(), MAX_PROVIDERS_ASKED);

		assert!(to_ask(found.iter().copied(), &mut asked, &local).is_empty());
	}

	fn response(peer_id: &PeerId, addrs: &[&str], genesis: u8, fork_id: Option<&str>) -> Vec<u8> {
		Response {
			peer_id: peer_id.to_bytes(),
			addrs: addrs.iter().map(|a| a.parse::<Multiaddr>().unwrap().to_vec()).collect(),
			genesis_hash: vec![genesis; 32],
			fork_id: fork_id.map(Into::into),
		}
		.encode_to_vec()
	}

	#[test]
	fn an_answer_keeps_what_the_provider_claims() {
		let (provider, node) = (PeerId::random(), PeerId::random());
		let payload = response(&node, &["/ip4/1.2.3.4/tcp/30333"], 7, Some("fork"));
		let answer = decode_answer(provider, &payload).unwrap();
		assert_eq!(answer.provider, provider);
		assert_eq!(answer.peer_id, node);
		assert_eq!(answer.addresses, vec!["/ip4/1.2.3.4/tcp/30333".parse().unwrap()]);
		assert_eq!(answer.genesis_hash, vec![7; 32]);
		assert_eq!(answer.fork_id.as_deref(), Some("fork"));
	}

	#[test]
	fn an_answer_keeps_at_most_the_protocols_addresses() {
		let node = PeerId::random();
		let addrs = vec!["/ip4/1.2.3.4/tcp/1"; MAX_ADDRESSES + 5];
		let answer = decode_answer(PeerId::random(), &response(&node, &addrs, 0, None)).unwrap();
		assert_eq!(answer.addresses.len(), MAX_ADDRESSES);
	}

	#[test]
	fn a_malformed_answer_is_unusable() {
		assert!(decode_answer(PeerId::random(), &[0xff, 0xff]).is_err());
		let bad_peer =
			Response { peer_id: vec![1, 2, 3], addrs: vec![], genesis_hash: vec![], fork_id: None }
				.encode_to_vec();
		assert!(decode_answer(PeerId::random(), &bad_peer).is_err());
		let bad_addr = Response {
			peer_id: PeerId::random().to_bytes(),
			addrs: vec![vec![0xff]],
			genesis_hash: vec![],
			fork_id: None,
		}
		.encode_to_vec();
		assert!(decode_answer(PeerId::random(), &bad_addr).is_err());
	}
}
