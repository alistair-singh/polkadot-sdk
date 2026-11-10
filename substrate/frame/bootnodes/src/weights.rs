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

//! Weights for `pallet_bootnodes`.
//!
//! These are hand-written placeholders. Regenerate them with the benchmark CLI
//! (`/cmd bench --pallet pallet_bootnodes`) before using the pallet in production.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for `pallet_bootnodes`.
pub trait WeightInfo {
	fn set_bootnodes() -> Weight;
	fn clear_bootnodes() -> Weight;
}

/// Weights for `pallet_bootnodes` using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: `System::BlockHash` (r:1 w:0)
	fn set_bootnodes() -> Weight {
		Weight::from_parts(70_000_000, 2_500)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	fn clear_bootnodes() -> Weight {
		Weight::from_parts(10_000_000, 0)
	}
}

// For backwards compatibility and tests.
impl WeightInfo for () {
	fn set_bootnodes() -> Weight {
		Weight::from_parts(70_000_000, 2_500)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
	}
	fn clear_bootnodes() -> Weight {
		Weight::from_parts(10_000_000, 0)
	}
}
