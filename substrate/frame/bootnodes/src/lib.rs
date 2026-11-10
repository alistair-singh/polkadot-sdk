// This file is part of Substrate.

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

//! # Bootnodes Pallet
//!
//! Publishes the bootnodes of a parachain to its key-value store in the Parachain Service, so that
//! nodes of other parachains can find this one's network from JAM state.
//!
//! The pallet keeps no storage. `BootnodesOrigin`, typically governance, calls `set_bootnodes` with
//! up to [`MAX_BOOTNODES`] multiaddresses as UTF-8 text, the form chain specs use. The pallet
//! checks them ([`multiaddr`]) and hands a SCALE-encoded [`BootnodeRecord`] to
//! [`Config::Publisher`]. On JAM the publisher writes it under [`BOOTNODES_KEY`].
//!
//! The record carries this chain's genesis hash, which a reader on another para has no way to
//! check. So it never comes from the caller: the pallet reads it from
//! `frame_system::Pallet::block_hash(0)`. That value is a placeholder until block 1 starts, which
//! is why a record cannot be seeded at genesis.
//!
//! Writing to the key-value store can be skipped by the Parachain Service without the para
//! learning of it, for instance on insufficient state balance. Governance watches the value on JAM
//! and calls `set_bootnodes` again if needed.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! - `set_bootnodes`: replace the published record. Requires `BootnodesOrigin`.
//! - `clear_bootnodes`: remove the published record. Requires `BootnodesOrigin`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
pub mod multiaddr;
#[cfg(test)]
mod tests;
pub mod weights;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use frame_support::{pallet_prelude::*, traits::ConstU32};
use scale_info::TypeInfo;
use sp_core::H256;

pub use pallet::*;
pub use weights::WeightInfo;

/// The key the record is published under in the para's key-value store.
pub const BOOTNODES_KEY: &[u8] = b"bootnodes/v1";

/// The most multiaddresses a record holds.
pub const MAX_BOOTNODES: u32 = 8;

/// The longest multiaddress accepted, as text and as bytes.
pub const MAX_ADDRESS_LEN: u32 = 512;

/// The longest fork id accepted.
pub const MAX_FORK_ID_LEN: u32 = 32;

/// The longest encoded [`BootnodeRecord`] the checks in [`multiaddr`] allow: the genesis hash, a
/// fork id with its one-byte length, the list's one-byte length, and for each address a two-byte
/// length and the longest address.
pub const MAX_RECORD_LEN: u32 =
	32 + 1 + MAX_FORK_ID_LEN + 1 + MAX_BOOTNODES * (2 + multiaddr::MAX_BINARY_LEN);

/// A multiaddress as UTF-8 text, as `address.to_string().into_bytes()` gives it.
pub type TextMultiAddr = BoundedVec<u8, ConstU32<MAX_ADDRESS_LEN>>;

/// The fork id of a chain. Empty for a chain without one.
pub type ForkId = BoundedVec<u8, ConstU32<MAX_FORK_ID_LEN>>;

/// Publishes the record, e.g. to the para's key-value store on JAM.
pub trait PublishBootnodes {
	/// Publish `record`, a SCALE-encoded [`BootnodeRecord`], or withdraw it with `None`. An error
	/// fails the call.
	fn publish(record: Option<&[u8]>) -> DispatchResult;
}

/// What a para publishes under [`BOOTNODES_KEY`].
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct BootnodeRecord {
	/// Genesis hash of the chain.
	pub genesis: [u8; 32],
	/// Fork id of the chain.
	pub fork_id: ForkId,
	/// Each multiaddress in its binary form (`address.to_vec()`).
	pub addresses: BoundedVec<BoundedVec<u8, ConstU32<MAX_ADDRESS_LEN>>, ConstU32<MAX_BOOTNODES>>,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::Zero;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>, Hash = H256> {
		/// Determines who can set the bootnode value.
		type BootnodesOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Receives the encoded record.
		type Publisher: PublishBootnodes;

		/// Weight information for the extrinsics of this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A record listing `count` addresses was published.
		BootnodesSet { count: u32 },
		/// The record was withdrawn.
		BootnodesCleared,
	}

	#[pallet::error]
	pub enum Error<T> {
		/// No address was given.
		NoAddresses,
		/// The same address was given twice.
		DuplicateAddress,
		/// An address is not `/<ip4|ip6|dns|dns4|dns6>/<host>/tcp/<port>[/ws|/wss]/p2p/<peer id>`,
		/// has an invalid port or DNS name, or names a peer id that is not an Ed25519 one.
		InvalidMultiaddr,
		/// The fork id holds something other than letters, digits, `-` and `_`.
		InvalidForkId,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Publish `addresses` as this chain's bootnodes, replacing the previous record.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_bootnodes())]
		pub fn set_bootnodes(
			origin: OriginFor<T>,
			addresses: BoundedVec<TextMultiAddr, ConstU32<MAX_BOOTNODES>>,
			fork_id: Option<ForkId>,
		) -> DispatchResult {
			T::BootnodesOrigin::ensure_origin(origin)?;
			let fork_id = fork_id.unwrap_or_default();
			ensure!(
				fork_id.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_'),
				Error::<T>::InvalidForkId
			);
			ensure!(!addresses.is_empty(), Error::<T>::NoAddresses);

			let mut binary = BoundedVec::new();
			for text in &addresses {
				let address = core::str::from_utf8(text)
					.ok()
					.and_then(|text| multiaddr::parse(text).ok())
					.and_then(|bytes: Vec<u8>| bytes.try_into().ok())
					.ok_or(Error::<T>::InvalidMultiaddr)?;
				ensure!(!binary.contains(&address), Error::<T>::DuplicateAddress);
				binary.try_push(address).map_err(|_| Error::<T>::InvalidMultiaddr)?;
			}

			let count = binary.len() as u32;
			let genesis = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero()).0;
			let record = BootnodeRecord { genesis, fork_id, addresses: binary };
			T::Publisher::publish(Some(&record.encode()))?;
			Self::deposit_event(Event::BootnodesSet { count });
			Ok(())
		}

		/// Withdraw the published record.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::clear_bootnodes())]
		pub fn clear_bootnodes(origin: OriginFor<T>) -> DispatchResult {
			T::BootnodesOrigin::ensure_origin(origin)?;
			T::Publisher::publish(None)?;
			Self::deposit_event(Event::BootnodesCleared);
			Ok(())
		}
	}
}
