//! Tests for `pallet_bootnodes`.

use crate::{
	mock::*, BootnodeRecord, Error, Event, ForkId, TextMultiAddr, MAX_BOOTNODES, MAX_RECORD_LEN,
};
use codec::{Decode, Encode};
use frame_support::{assert_noop, assert_ok, traits::ConstU32, BoundedVec};
use multiaddr::Multiaddr;
use sp_runtime::DispatchError;

const PEER: &str = "12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp";

fn with_peer(addr: &str) -> String {
	format!("{addr}/p2p/{PEER}")
}

fn addresses(addresses: &[&str]) -> BoundedVec<TextMultiAddr, ConstU32<MAX_BOOTNODES>> {
	addresses
		.iter()
		.map(|addr| TextMultiAddr::try_from(addr.as_bytes().to_vec()).unwrap())
		.collect::<Vec<_>>()
		.try_into()
		.unwrap()
}

fn fork(id: &str) -> Option<ForkId> {
	Some(id.as_bytes().to_vec().try_into().unwrap())
}

fn binary(addr: &str) -> BoundedVec<u8, ConstU32<{ crate::MAX_ADDRESS_LEN }>> {
	addr.parse::<Multiaddr>().unwrap().to_vec().try_into().unwrap()
}

fn set(list: &[&str], fork_id: Option<ForkId>) -> sp_runtime::DispatchResult {
	Bootnodes::set_bootnodes(RuntimeOrigin::root(), addresses(list), fork_id)
}

fn published_record() -> BootnodeRecord {
	match take_published().as_slice() {
		[Some(encoded)] => BootnodeRecord::decode(&mut &encoded[..]).unwrap(),
		other => panic!("expected one record, got {other:?}"),
	}
}

/// Readers on other paras decode the value under `bootnodes/v1` with their own copy of the type,
/// so its encoding must not change without a new key name.
#[test]
fn the_v1_record_encoding_is_fixed() {
	let record = BootnodeRecord {
		genesis: [1; 32],
		fork_id: b"ab".to_vec().try_into().unwrap(),
		addresses: vec![vec![4, 1, 2, 3, 4].try_into().unwrap()].try_into().unwrap(),
	};
	let expected = [
		"0x",
		// `genesis`.
		&"01".repeat(32),
		// `fork_id`: 2 bytes.
		"08",
		"6162",
		// One address of 5 bytes.
		"04",
		"14",
		"0401020304",
	]
	.concat();

	assert_eq!(sp_core::bytes::to_hex(&record.encode(), false), expected);
	let bytes = sp_core::bytes::from_hex(&expected).unwrap();
	assert_eq!(BootnodeRecord::decode(&mut &bytes[..]).unwrap(), record);
}

#[test]
fn set_bootnodes_publishes_the_binary_addresses_in_order() {
	new_test_ext().execute_with(|| {
		let (a, b) =
			(with_peer("/ip4/1.2.3.4/tcp/30333"), with_peer("/dns/b.example.org/tcp/1/ws"));
		assert_ok!(set(&[&a, &b], fork("fork-1_a")));

		let record = published_record();
		assert_eq!(record.fork_id.to_vec(), b"fork-1_a".to_vec());
		assert_eq!(record.addresses.to_vec(), vec![binary(&a), binary(&b)]);
		System::assert_last_event(Event::BootnodesSet { count: 2 }.into());
	});
}

/// A reader cannot check the genesis hash, so it comes from the chain and not from the caller.
#[test]
fn the_record_carries_this_chains_genesis_hash() {
	new_test_ext().execute_with(|| {
		assert_ok!(set(&[&with_peer("/ip4/1.2.3.4/tcp/1")], None));
		assert_eq!(published_record().genesis, GENESIS_HASH.0);
	});
}

#[test]
fn without_a_fork_id_the_record_has_an_empty_one() {
	new_test_ext().execute_with(|| {
		assert_ok!(set(&[&with_peer("/ip4/1.2.3.4/tcp/1")], None));
		assert!(published_record().fork_id.is_empty());
	});
}

#[test]
fn set_and_clear_require_the_bootnodes_origin() {
	new_test_ext().execute_with(|| {
		let list = addresses(&[&with_peer("/ip4/1.2.3.4/tcp/1")]);
		assert_noop!(
			Bootnodes::set_bootnodes(RuntimeOrigin::signed(1), list.clone(), None),
			DispatchError::BadOrigin
		);
		assert_noop!(
			Bootnodes::set_bootnodes(RuntimeOrigin::none(), list, None),
			DispatchError::BadOrigin
		);
		assert_noop!(
			Bootnodes::clear_bootnodes(RuntimeOrigin::signed(1)),
			DispatchError::BadOrigin
		);
		assert_eq!(take_published(), vec![]);
	});
}

#[test]
fn at_least_one_address_is_needed() {
	new_test_ext().execute_with(|| {
		assert_noop!(set(&[], None), Error::<Test>::NoAddresses);
	});
}

#[test]
fn addresses_must_be_unique() {
	new_test_ext().execute_with(|| {
		let a = with_peer("/ip4/1.2.3.4/tcp/1");
		assert_noop!(
			set(&[&a, &with_peer("/ip4/1.2.3.5/tcp/1"), &a], None),
			Error::<Test>::DuplicateAddress
		);
		// Two spellings of one IPv6 address are the same address.
		assert_noop!(
			set(&[&with_peer("/ip6/::1/tcp/1"), &with_peer("/ip6/0:0:0:0:0:0:0:1/tcp/1")], None),
			Error::<Test>::DuplicateAddress
		);
	});
}

#[test]
fn every_address_is_checked() {
	new_test_ext().execute_with(|| {
		let good = with_peer("/ip4/1.2.3.4/tcp/1");
		for bad in [
			"not a multiaddr".to_string(),
			"/ip4/1.2.3.4/tcp/1".to_string(),
			with_peer("/ip4/1.2.3.4/tcp/0"),
			with_peer("/dns/localhost/tcp/1"),
			with_peer("/ip4/1.2.3.4/udp/1"),
		] {
			assert_noop!(set(&[&good, &bad], None), Error::<Test>::InvalidMultiaddr);
		}
		let not_utf8 = vec![TextMultiAddr::try_from(vec![0xff, 0xfe]).unwrap()].try_into().unwrap();
		assert_noop!(
			Bootnodes::set_bootnodes(RuntimeOrigin::root(), not_utf8, None),
			Error::<Test>::InvalidMultiaddr
		);
	});
}

#[test]
fn the_fork_id_holds_only_letters_digits_dash_and_underscore() {
	new_test_ext().execute_with(|| {
		let list = [with_peer("/ip4/1.2.3.4/tcp/1")];
		for bad in ["a/b", "a b", "é", "a.b"] {
			assert_noop!(set(&[&list[0]], fork(bad)), Error::<Test>::InvalidForkId);
		}
	});
}

#[test]
fn a_full_list_of_the_longest_addresses_fits_max_record_len() {
	new_test_ext().execute_with(|| {
		let name =
			|i: u32| format!("{i:0>63}.{}.{}.{}", "a".repeat(63), "a".repeat(63), "a".repeat(61));
		let list: Vec<_> = (0..MAX_BOOTNODES)
			.map(|i| with_peer(&format!("/dns/{}/tcp/65535/wss", name(i))))
			.collect();
		let list: Vec<&str> = list.iter().map(String::as_str).collect();
		assert_ok!(set(&list, fork(&"f".repeat(32))));

		assert_eq!(
			take_published().pop().flatten().map(|encoded| encoded.len() as u32),
			Some(MAX_RECORD_LEN)
		);
	});
}

#[test]
fn clear_bootnodes_withdraws_the_record() {
	new_test_ext().execute_with(|| {
		assert_ok!(Bootnodes::clear_bootnodes(RuntimeOrigin::root()));
		assert_eq!(take_published(), vec![None]);
		System::assert_last_event(Event::BootnodesCleared.into());
	});
}

#[test]
fn a_failed_publish_fails_the_call() {
	new_test_ext().execute_with(|| {
		fail_publishing(true);
		assert_noop!(set(&[&with_peer("/ip4/1.2.3.4/tcp/1")], None), PUBLISH_FAILED);
		assert_noop!(Bootnodes::clear_bootnodes(RuntimeOrigin::root()), PUBLISH_FAILED);
		fail_publishing(false);
		assert_eq!(take_published(), vec![]);
	});
}
