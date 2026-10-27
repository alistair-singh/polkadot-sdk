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

//! Writes the para's key/value storage in the Parachain Service.
//!
//! On JAM every parachain owns a key/value map in the Parachain Service's storage (§3.1, §6.1).
//! [`Pallet::set_kv`] and [`Pallet::remove_kv`] write it by sending `SetKV` / `RemoveKV` upward
//! messages. Only the PVF delivers them: the service applies a message when it accumulates the
//! block that sent it, and the copy sent while authoring or importing is thrown away. A value is
//! therefore visible on JAM only once the block is accumulated, under
//! [`kv_storage_key`] of the service.
//!
//! The service aborts the whole refine on an empty key or value and on more than its per-refine
//! upward-message budget, which would make the block invalid. The pallet rejects such calls
//! instead: keys and values are bounded and non-empty, and the bytes it sends per block are capped
//! by [`Config::MaxBytesPerBlock`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use codec::Encode;
use parachain_service_core::{types::ParaId, upward_message::UpwardMessage, Tag};

/// The key the Parachain Service stores `key` of `para_id` under: `0x08 ‖ SCALE(para_id) ‖ key`,
/// the user key appended without a length prefix.
///
/// Mirrors the service's `state::kv::storage_key`; this is what a reader passes to `serviceValue`.
pub fn kv_storage_key(para_id: u32, key: &[u8]) -> Vec<u8> {
	[&[Tag::KeyValueStorage as u8][..], &ParaId::new(para_id).encode(), key].concat()
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{pallet_prelude::*, traits::EnsureOrigin};
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		#[allow(deprecated)]
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Who may write the para's key/value storage.
		type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// This para's id, which `RemoveKV` names.
		type SelfParaId: Get<u32>;

		/// The longest key accepted.
		#[pallet::constant]
		type MaxKeyLen: Get<u32>;

		/// The longest value accepted.
		#[pallet::constant]
		type MaxValueLen: Get<u32>;

		/// The encoded upward-message bytes this pallet sends in one block. Must leave room under
		/// the service's per-refine budget (`MAX_UPWARD_MESSAGE_BYTES`) for any other sender.
		#[pallet::constant]
		type MaxBytesPerBlock: Get<u32>;
	}

	/// The encoded upward-message bytes sent in the current block.
	#[pallet::storage]
	#[pallet::whitelist_storage]
	pub type SentBytes<T> = StorageValue<_, u32, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A `SetKV` was sent. The value is on JAM once this block is accumulated.
		KvSet { key: BoundedVec<u8, T::MaxKeyLen>, value_len: u32 },
		/// A `RemoveKV` was sent. The entry is gone once this block is accumulated.
		KvRemoved { key: BoundedVec<u8, T::MaxKeyLen> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The service aborts refine on an empty key.
		EmptyKey,
		/// The service aborts refine on an empty value.
		EmptyValue,
		/// The message would exceed [`Config::MaxBytesPerBlock`] for this block.
		BlockBudgetExhausted,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(_: BlockNumberFor<T>) -> Weight {
			SentBytes::<T>::kill();
			T::DbWeight::get().writes(1)
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Set `key` of this para's key/value storage to `value`.
		#[pallet::call_index(0)]
		#[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
		pub fn set_kv(
			origin: OriginFor<T>,
			key: BoundedVec<u8, T::MaxKeyLen>,
			value: BoundedVec<u8, T::MaxValueLen>,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			Self::do_set_kv(key, value)
		}

		/// Remove `key` from this para's key/value storage.
		#[pallet::call_index(1)]
		#[pallet::weight(T::DbWeight::get().reads_writes(1, 1))]
		pub fn remove_kv(
			origin: OriginFor<T>,
			key: BoundedVec<u8, T::MaxKeyLen>,
		) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			Self::do_remove_kv(key)
		}
	}

	impl<T: Config> Pallet<T> {
		/// Send `SetKV { key, value }`. For other pallets publishing into the para's storage.
		pub fn do_set_kv(
			key: BoundedVec<u8, T::MaxKeyLen>,
			value: BoundedVec<u8, T::MaxValueLen>,
		) -> DispatchResult {
			ensure!(!key.is_empty(), Error::<T>::EmptyKey);
			ensure!(!value.is_empty(), Error::<T>::EmptyValue);
			let value_len = value.len() as u32;
			let message =
				UpwardMessage::SetKV { key: key.clone().into_inner(), value: value.into_inner() };
			Self::send(&message)?;
			Self::deposit_event(Event::KvSet { key, value_len });
			Ok(())
		}

		/// Send `RemoveKV { para_id: self, key }`.
		pub fn do_remove_kv(key: BoundedVec<u8, T::MaxKeyLen>) -> DispatchResult {
			ensure!(!key.is_empty(), Error::<T>::EmptyKey);
			let message = UpwardMessage::RemoveKV {
				para_id: ParaId::new(T::SelfParaId::get()),
				key: key.clone().into_inner(),
			};
			Self::send(&message)?;
			Self::deposit_event(Event::KvRemoved { key });
			Ok(())
		}

		fn send(message: &UpwardMessage) -> DispatchResult {
			let encoded = message.encode();
			let sent = SentBytes::<T>::get().saturating_add(encoded.len() as u32);
			ensure!(sent <= T::MaxBytesPerBlock::get(), Error::<T>::BlockBudgetExhausted);
			SentBytes::<T>::put(sent);
			cumulus_jam_state_reader::jam_upward::send_upward_message(&encoded);
			Ok(())
		}
	}
}
