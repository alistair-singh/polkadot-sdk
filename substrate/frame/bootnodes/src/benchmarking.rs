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

//! Benchmarks for `pallet_bootnodes`.

use super::*;
use alloc::{format, string::String, vec};
use frame_benchmarking::v2::*;
use frame_support::traits::EnsureOrigin;

const PEER: &str = "12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp";

/// The longest text address accepted, distinct for each `index`.
fn longest_address(index: u32) -> TextMultiAddr {
	let label = String::from_utf8(vec![b'a'; 63]).expect("ASCII; qed");
	let last = String::from_utf8(vec![b'a'; 61]).expect("ASCII; qed");
	let address = format!("/dns/{index:0>63}.{label}.{label}.{last}/tcp/65535/wss/p2p/{PEER}");
	address.into_bytes().try_into().expect("shorter than MAX_ADDRESS_LEN; qed")
}

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn set_bootnodes() -> Result<(), BenchmarkError> {
		// Worst case: a full list of the longest addresses, each compared with those before it.
		let addresses: Vec<_> = (0..MAX_BOOTNODES).map(longest_address).collect();
		let addresses: BoundedVec<_, _> =
			addresses.try_into().map_err(|_| BenchmarkError::Stop("MAX_BOOTNODES"))?;
		let fork_id: ForkId = vec![b'a'; MAX_FORK_ID_LEN as usize]
			.try_into()
			.map_err(|_| BenchmarkError::Stop("MAX_FORK_ID_LEN"))?;
		let origin =
			T::BootnodesOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

		#[extrinsic_call]
		_(origin as T::RuntimeOrigin, addresses, Some(fork_id));

		Ok(())
	}

	#[benchmark]
	fn clear_bootnodes() -> Result<(), BenchmarkError> {
		let origin =
			T::BootnodesOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

		#[extrinsic_call]
		_(origin as T::RuntimeOrigin);

		Ok(())
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
