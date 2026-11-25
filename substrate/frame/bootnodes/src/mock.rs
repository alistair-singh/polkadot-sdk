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

//! Test runtime for `pallet_bootnodes`.

use crate as pallet_bootnodes;
use core::cell::{Cell, RefCell};
use frame_support::derive_impl;
use frame_system::EnsureRoot;
use sp_runtime::{BuildStorage, DispatchError, DispatchResult};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Bootnodes: pallet_bootnodes,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

impl pallet_bootnodes::Config for Test {
	type BootnodesOrigin = EnsureRoot<u64>;
	type Publisher = RecordingPublisher;
	type WeightInfo = ();
}

thread_local! {
	static PUBLISHED: RefCell<Vec<Option<Vec<u8>>>> = const { RefCell::new(Vec::new()) };
	static PUBLISH_FAILS: Cell<bool> = const { Cell::new(false) };
}

/// The error [`RecordingPublisher`] returns while [`fail_publishing`] is set.
pub const PUBLISH_FAILED: DispatchError = DispatchError::Other("publish failed");

/// Records every published record, or fails while [`fail_publishing`] is set.
pub struct RecordingPublisher;

impl pallet_bootnodes::PublishBootnodes for RecordingPublisher {
	fn publish(record: Option<&[u8]>) -> DispatchResult {
		if PUBLISH_FAILS.get() {
			return Err(PUBLISH_FAILED);
		}
		PUBLISHED.with_borrow_mut(|published| published.push(record.map(<[u8]>::to_vec)));
		Ok(())
	}
}

/// The records published since the last call, oldest first.
pub fn take_published() -> Vec<Option<Vec<u8>>> {
	PUBLISHED.take()
}

/// Make [`RecordingPublisher`] fail, or succeed again.
pub fn fail_publishing(fail: bool) {
	PUBLISH_FAILS.set(fail);
}

/// The hash block 1 is built on, so what `block_hash(0)` returns in [`new_test_ext`].
pub const GENESIS_HASH: sp_core::H256 = sp_core::H256::repeat_byte(0x4a);

/// Test externalities inside block 1.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let storage = RuntimeGenesisConfig::default().build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(storage);
	ext.execute_with(|| System::initialize(&1, &GENESIS_HASH, &Default::default()));
	ext
}
