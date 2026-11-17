// This file is part of Cumulus.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

use crate::{self as pallet_jam_kv, kv_storage_key, Error, Event, SentBytes};
use codec::Encode;
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types, BoundedVec};
use frame_system::EnsureRoot;
use parachain_service_core::{types::ParaId, upward_message::UpwardMessage};
use sp_runtime::{traits::BadOrigin, BuildStorage};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		JamKv: pallet_jam_kv,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

parameter_types! {
	pub const SelfParaId: u32 = 2000;
	pub const MaxBytesPerBlock: u32 = 64;
}

impl pallet_jam_kv::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type AdminOrigin = EnsureRoot<u64>;
	type SelfParaId = SelfParaId;
	type MaxKeyLen = frame_support::traits::ConstU32<16>;
	type MaxValueLen = frame_support::traits::ConstU32<32>;
	type MaxBytesPerBlock = MaxBytesPerBlock;
	type ReservedKeys = OnlyReserved;
}

/// Reserves the key `reserved`.
pub struct OnlyReserved;

impl frame_support::traits::Contains<BoundedVec<u8, frame_support::traits::ConstU32<16>>>
	for OnlyReserved
{
	fn contains(key: &BoundedVec<u8, frame_support::traits::ConstU32<16>>) -> bool {
		key.as_slice() == b"reserved"
	}
}

fn new_test_ext() -> sp_io::TestExternalities {
	let storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(storage);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

fn bounded<S: frame_support::traits::Get<u32>>(bytes: &[u8]) -> BoundedVec<u8, S> {
	bytes.to_vec().try_into().expect("test input fits its bound; qed")
}

#[test]
fn kv_storage_key_works() {
	// 0x08, para 2000 as SCALE u32 (LE), then the key as sent.
	assert_eq!(kv_storage_key(2000, b"k"), [0x08, 0xd0, 0x07, 0x00, 0x00, b'k']);
}

#[test]
fn set_kv_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(JamKv::set_kv(RuntimeOrigin::root(), bounded(b"key"), bounded(b"value")));
		System::assert_last_event(Event::KvSet { key: bounded(b"key"), value_len: 5 }.into());
		let sent = UpwardMessage::SetKV { key: b"key".to_vec(), value: b"value".to_vec() };
		assert_eq!(SentBytes::<Test>::get(), sent.encode().len() as u32);
	});
}

#[test]
fn remove_kv_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(JamKv::remove_kv(RuntimeOrigin::root(), bounded(b"key")));
		System::assert_last_event(Event::KvRemoved { key: bounded(b"key") }.into());
		let sent = UpwardMessage::RemoveKV { para_id: ParaId::new(2000), key: b"key".to_vec() };
		assert_eq!(SentBytes::<Test>::get(), sent.encode().len() as u32);
	});
}

#[test]
fn signed_origin_errors() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			JamKv::set_kv(RuntimeOrigin::signed(1), bounded(b"key"), bounded(b"value")),
			BadOrigin
		);
		assert_noop!(JamKv::remove_kv(RuntimeOrigin::signed(1), bounded(b"key")), BadOrigin);
	});
}

#[test]
fn empty_key_or_value_errors() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			JamKv::set_kv(RuntimeOrigin::root(), bounded(b""), bounded(b"value")),
			Error::<Test>::EmptyKey
		);
		assert_noop!(
			JamKv::set_kv(RuntimeOrigin::root(), bounded(b"key"), bounded(b"")),
			Error::<Test>::EmptyValue
		);
		assert_noop!(
			JamKv::remove_kv(RuntimeOrigin::root(), bounded(b"")),
			Error::<Test>::EmptyKey
		);
	});
}

#[test]
fn block_budget_errors() {
	new_test_ext().execute_with(|| {
		let value = [0xaa; 32];
		// Each message is 1 (variant) + 1 + 16 (key) + 1 + 32 (value) = 51 bytes; two exceed 64.
		assert_ok!(JamKv::set_kv(RuntimeOrigin::root(), bounded(&[1; 16]), bounded(&value)));
		assert_noop!(
			JamKv::set_kv(RuntimeOrigin::root(), bounded(&[2; 16]), bounded(&value)),
			Error::<Test>::BlockBudgetExhausted
		);
	});
}

#[test]
fn block_budget_resets_works() {
	new_test_ext().execute_with(|| {
		let value = [0xaa; 32];
		assert_ok!(JamKv::set_kv(RuntimeOrigin::root(), bounded(&[1; 16]), bounded(&value)));
		<JamKv as frame_support::traits::Hooks<u64>>::on_initialize(2);
		assert_ok!(JamKv::set_kv(RuntimeOrigin::root(), bounded(&[2; 16]), bounded(&value)));
	});
}

#[test]
fn the_calls_refuse_a_reserved_key_but_its_owner_can_write_it() {
	new_test_ext().execute_with(|| {
		let key = || bounded(b"reserved");
		frame_support::assert_noop!(
			JamKv::set_kv(RuntimeOrigin::root(), key(), bounded(b"value")),
			Error::<Test>::ReservedKey
		);
		frame_support::assert_noop!(
			JamKv::remove_kv(RuntimeOrigin::root(), key()),
			Error::<Test>::ReservedKey
		);

		frame_support::assert_ok!(JamKv::do_set_kv(key(), bounded(b"value")));
		frame_support::assert_ok!(JamKv::do_remove_kv(key()));
	});
}
