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

//! Multiaddresses of bootnodes, as text and in binary form.
//!
//! The runtime cannot use the `multiaddr` crate. [`parse`] turns the text form into the binary
//! one, and [`validate`] checks the binary form. Both accept exactly:
//!
//! `/(ip4|ip6|dns|dns4|dns6)/<host>/tcp/<port>[/ws|/wss]/p2p/<peer id>`
//!
//! The port is in 1 to 65535. A DNS host is a valid name, and neither `localhost` nor an IP
//! address. The peer id is an Ed25519 one.
//!
//! Protocol codes and payload layouts follow the multiformats protocol table as implemented by
//! the `multiaddr` crate, version 0.18.

use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

/// Why an address was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
	/// The address is empty.
	Empty,
	/// A protocol code or length prefix is not a valid, minimal, unsigned varint.
	InvalidVarint,
	/// A component's payload runs past the end of the address.
	UnexpectedEnd,
	/// A protocol other than ip4, ip6, dns, dns4, dns6, tcp, ws, wss or p2p.
	UnsupportedProtocol(u32),
	/// A host is not an address of its protocol.
	InvalidHost,
	/// A DNS name is not valid, is `localhost`, or is an IP address.
	InvalidDnsName,
	/// The port is not in 1 to 65535.
	InvalidPort,
	/// The peer id is not an Ed25519 one.
	InvalidPeerId,
	/// The components are not `host/tcp`, optionally `ws` or `wss`, and then `p2p`.
	InvalidLayout,
}

const IP4: u32 = 4;
const TCP: u32 = 6;
const IP6: u32 = 41;
const DNS: u32 = 53;
const DNS4: u32 = 54;
const DNS6: u32 = 55;
const P2P: u32 = 421;
const WS: u32 = 477;
const WSS: u32 = 478;

/// The longest DNS name accepted.
const MAX_DNS_LEN: usize = 253;

/// The start of the multihash of an Ed25519 peer id: an identity multihash of 36 bytes, holding
/// the protobuf encoding of a public key of type Ed25519 and 32 bytes of data.
const ED25519_PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

/// The length of the multihash of an Ed25519 peer id.
const ED25519_PEER_ID_LEN: usize = ED25519_PEER_ID_PREFIX.len() + 32;

/// The longest binary address [`validate`] accepts: a DNS host with a two-byte length, the port, a
/// WebSocket layer and the peer id.
pub const MAX_BINARY_LEN: u32 = 1 + 2 + MAX_DNS_LEN as u32 + 3 + 2 + 3 + ED25519_PEER_ID_LEN as u32;

fn is_valid_dns_name(name: &str) -> bool {
	let label_is_valid = |label: &str| {
		(1..=63).contains(&label.len()) &&
			label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') &&
			!label.starts_with('-') &&
			!label.ends_with('-')
	};
	name.len() <= MAX_DNS_LEN &&
		name.split('.').all(label_is_valid) &&
		!name
			.rsplit('.')
			.next()
			.is_some_and(|last| last.eq_ignore_ascii_case("localhost")) &&
		name.parse::<Ipv4Addr>().is_err()
}

fn is_ed25519_peer_id(multihash: &[u8]) -> bool {
	multihash.len() == ED25519_PEER_ID_LEN && multihash.starts_with(&ED25519_PEER_ID_PREFIX)
}

fn push_varint(mut value: u32, out: &mut Vec<u8>) {
	while value >= 0x80 {
		out.push((value as u8 & 0x7f) | 0x80);
		value >>= 7;
	}
	out.push(value as u8);
}

/// The binary form of the text address `text`, which [`validate`] accepts.
pub fn parse(text: &str) -> Result<Vec<u8>, Error> {
	if text.is_empty() {
		return Err(Error::Empty);
	}
	let mut parts = text.strip_prefix('/').ok_or(Error::InvalidLayout)?.split('/');
	let mut next = || parts.next().ok_or(Error::InvalidLayout);
	let mut out = Vec::new();

	match (next()?, next()?) {
		("ip4", host) => {
			let ip: Ipv4Addr = host.parse().map_err(|_| Error::InvalidHost)?;
			push_varint(IP4, &mut out);
			out.extend(ip.octets());
		},
		("ip6", host) => {
			let ip: Ipv6Addr = host.parse().map_err(|_| Error::InvalidHost)?;
			push_varint(IP6, &mut out);
			out.extend(ip.octets());
		},
		(protocol @ ("dns" | "dns4" | "dns6"), host) => {
			push_varint(
				match protocol {
					"dns" => DNS,
					"dns4" => DNS4,
					_ => DNS6,
				},
				&mut out,
			);
			push_varint(host.len() as u32, &mut out);
			out.extend(host.as_bytes());
		},
		_ => return Err(Error::InvalidLayout),
	}

	if next()? != "tcp" {
		return Err(Error::InvalidLayout);
	}
	let port = next()?;
	if !port.bytes().all(|c| c.is_ascii_digit()) {
		return Err(Error::InvalidPort);
	}
	let port: u16 = port.parse().map_err(|_| Error::InvalidPort)?;
	push_varint(TCP, &mut out);
	out.extend(port.to_be_bytes());

	let mut protocol = next()?;
	if let "ws" | "wss" = protocol {
		push_varint(if protocol == "ws" { WS } else { WSS }, &mut out);
		protocol = next()?;
	}
	if protocol != "p2p" {
		return Err(Error::InvalidLayout);
	}
	let peer_id = bs58::decode(next()?).into_vec().map_err(|_| Error::InvalidPeerId)?;
	push_varint(P2P, &mut out);
	push_varint(peer_id.len() as u32, &mut out);
	out.extend(peer_id);

	if parts.next().is_some() {
		return Err(Error::InvalidLayout);
	}
	validate(&out)?;
	Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Component {
	/// ip4, ip6, dns, dns4 or dns6.
	Host,
	/// tcp.
	Tcp,
	/// ws or wss.
	WebSocket,
	/// p2p.
	PeerId,
}

/// Read an unsigned LEB128 varint fitting in a `u32`, returning it and the remaining input.
///
/// Non-minimal encodings (a zero continuation byte, e.g. `0x80 0x00`) are rejected.
fn read_varint(input: &[u8]) -> Result<(u32, &[u8]), Error> {
	let mut value: u32 = 0;
	for (i, &byte) in input.iter().enumerate().take(5) {
		let bits = u32::from(byte & 0x7f);
		// Four full bytes carry 28 bits; the fifth may only carry the remaining four.
		if i == 4 && bits > 0x0f {
			return Err(Error::InvalidVarint);
		}
		value |= bits << (7 * i);
		if byte & 0x80 == 0 {
			if i > 0 && bits == 0 {
				return Err(Error::InvalidVarint);
			}
			return Ok((value, &input[i + 1..]));
		}
	}
	Err(Error::InvalidVarint)
}

/// Read a length-prefixed payload, returning it and the remaining input.
fn read_sized(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
	let (len, rest) = read_varint(input)?;
	let payload = rest.get(..len as usize).ok_or(Error::UnexpectedEnd)?;
	Ok((payload, &rest[payload.len()..]))
}

/// Read one component, returning its kind and the remaining input.
fn read_component(input: &[u8]) -> Result<(Component, &[u8]), Error> {
	let (code, rest) = read_varint(input)?;
	let (component, payload_len) = match code {
		IP4 => (Component::Host, 4),
		IP6 => (Component::Host, 16),
		DNS | DNS4 | DNS6 => {
			let (name, rest) = read_sized(rest)?;
			let name = core::str::from_utf8(name).map_err(|_| Error::InvalidDnsName)?;
			if !is_valid_dns_name(name) {
				return Err(Error::InvalidDnsName);
			}
			return Ok((Component::Host, rest));
		},
		TCP => {
			if rest.get(..2).ok_or(Error::UnexpectedEnd)? == [0, 0] {
				return Err(Error::InvalidPort);
			}
			(Component::Tcp, 2)
		},
		WS | WSS => (Component::WebSocket, 0),
		P2P => {
			let (multihash, rest) = read_sized(rest)?;
			if !is_ed25519_peer_id(multihash) {
				return Err(Error::InvalidPeerId);
			}
			return Ok((Component::PeerId, rest));
		},
		other => return Err(Error::UnsupportedProtocol(other)),
	};
	let rest = rest.get(payload_len..).ok_or(Error::UnexpectedEnd)?;
	Ok((component, rest))
}

/// What may come next while walking an address.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
	Host,
	Tcp,
	WebSocketOrPeerId,
	PeerId,
	End,
}

/// Check that the binary address `addr` has the form this module describes.
pub fn validate(addr: &[u8]) -> Result<(), Error> {
	if addr.is_empty() {
		return Err(Error::Empty);
	}
	let mut rest = addr;
	let mut expect = Expect::Host;
	while !rest.is_empty() {
		let (component, after) = read_component(rest)?;
		expect = match (expect, component) {
			(Expect::Host, Component::Host) => Expect::Tcp,
			(Expect::Tcp, Component::Tcp) => Expect::WebSocketOrPeerId,
			(Expect::WebSocketOrPeerId, Component::WebSocket) => Expect::PeerId,
			(Expect::WebSocketOrPeerId | Expect::PeerId, Component::PeerId) => Expect::End,
			_ => return Err(Error::InvalidLayout),
		};
		rest = after;
	}
	if expect == Expect::End {
		Ok(())
	} else {
		Err(Error::InvalidLayout)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::{format, string::String, vec};
	use multiaddr::Multiaddr;

	const PEER: &str = "12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp";
	/// A valid peer id whose key is not an Ed25519 one.
	const RSA_PEER: &str = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

	fn with_peer(addr: &str) -> String {
		format!("{addr}/p2p/{PEER}")
	}

	fn bytes(addr: &str) -> Vec<u8> {
		addr.parse::<Multiaddr>().expect("valid test address").to_vec()
	}

	/// The accepted shapes, in the form the `multiaddr` crate prints them.
	const ACCEPTED: [&str; 8] = [
		"/ip4/127.0.0.1/tcp/30333",
		"/ip4/10.0.0.1/tcp/30333/ws",
		"/ip4/10.0.0.1/tcp/1/wss",
		"/ip6/::1/tcp/30333",
		"/ip6/2001:db8::1/tcp/65535/wss",
		"/dns/boot.example.org/tcp/30333",
		"/dns4/boot.example.org/tcp/30333/ws",
		"/dns6/boot-1.example.org/tcp/30333/wss",
	];

	/// `parse` must produce exactly what readers decode with the `multiaddr` crate.
	#[test]
	fn parse_agrees_with_the_multiaddr_crate() {
		for addr in ACCEPTED {
			let addr = with_peer(addr);
			assert_eq!(parse(&addr), Ok(bytes(&addr)), "{addr}");
			assert_eq!(validate(&bytes(&addr)), Ok(()), "{addr}");
		}
	}

	#[test]
	fn an_address_needs_a_peer_id_at_its_end() {
		for addr in ["/ip4/1.2.3.4/tcp/30333", "/dns/boot.example.org/tcp/30333/ws"] {
			assert_eq!(parse(addr), Err(Error::InvalidLayout), "{addr}");
			assert_eq!(validate(&bytes(addr)), Err(Error::InvalidLayout), "{addr}");
		}
		let mut trailing = bytes(&with_peer("/ip4/1.2.3.4/tcp/30333"));
		trailing.extend(bytes("/ws"));
		assert_eq!(validate(&trailing), Err(Error::InvalidLayout));
		assert_eq!(
			parse(&format!("{}/ws", with_peer("/ip4/1.2.3.4/tcp/1"))),
			Err(Error::InvalidLayout)
		);
	}

	#[test]
	fn the_peer_id_must_be_an_ed25519_one() {
		let addr = format!("/ip4/1.2.3.4/tcp/30333/p2p/{RSA_PEER}");
		assert_eq!(parse(&addr), Err(Error::InvalidPeerId));
		assert_eq!(validate(&bytes(&addr)), Err(Error::InvalidPeerId));
		assert_eq!(parse("/ip4/1.2.3.4/tcp/30333/p2p/not-base58!"), Err(Error::InvalidPeerId));
	}

	#[test]
	fn the_port_must_be_in_range() {
		for port in ["0", "65536", "", "+1", "http"] {
			let addr = with_peer(&format!("/ip4/1.2.3.4/tcp/{port}"));
			assert_eq!(parse(&addr), Err(Error::InvalidPort), "{addr}");
		}
		assert_eq!(validate(&bytes(&with_peer("/ip4/1.2.3.4/tcp/0"))), Err(Error::InvalidPort));
	}

	#[test]
	fn dns_hosts_must_be_valid_names() {
		let long_label = "a".repeat(64);
		let longest =
			[&"a".repeat(63)[..], &"a".repeat(63), &"a".repeat(63), &"a".repeat(61)].join(".");
		let too_long = format!("a{longest}");
		for host in [
			"localhost",
			"LOCALHOST",
			"node.localhost",
			"1.2.3.4",
			"",
			"-a.example.org",
			"a-.example.org",
			"a..example.org",
			"example.org.",
			"under_score.org",
			long_label.as_str(),
			too_long.as_str(),
		] {
			let addr = with_peer(&format!("/dns/{host}/tcp/1"));
			assert_eq!(parse(&addr), Err(Error::InvalidDnsName), "{host:?}");
		}
		assert_eq!(parse(&with_peer(&format!("/dns/{longest}/tcp/1"))).map(|_| ()), Ok(()));
	}

	#[test]
	fn ip_hosts_must_parse() {
		for addr in ["/ip4/1.2.3/tcp/1", "/ip4/::1/tcp/1", "/ip6/1.2.3.4/tcp/1"] {
			assert_eq!(parse(&with_peer(addr)), Err(Error::InvalidHost), "{addr}");
		}
	}

	#[test]
	fn other_layouts_and_transports_are_rejected() {
		assert_eq!(parse(""), Err(Error::Empty));
		for addr in [
			"ip4/1.2.3.4/tcp/1",
			"/ip4/1.2.3.4",
			"/ip4/1.2.3.4/udp/1",
			"/tcp/30333",
			"/ip4/1.2.3.4/tcp/30333/quic-v1",
			"/ip4/1.2.3.4/tcp/30333/ws/wss",
			"/memory/1",
		] {
			assert_eq!(parse(&with_peer(addr)), Err(Error::InvalidLayout), "{addr}");
		}
		assert_eq!(
			parse(&format!("{}/x", with_peer("/ip4/1.2.3.4/tcp/1"))),
			Err(Error::InvalidLayout)
		);
		assert_eq!(
			validate(&bytes(&with_peer("/ip4/1.2.3.4/udp/30333/quic-v1"))),
			Err(Error::UnsupportedProtocol(273))
		);
		assert_eq!(validate(&bytes(&with_peer("/tcp/30333"))), Err(Error::InvalidLayout));
	}

	#[test]
	fn malformed_binary_addresses_are_rejected() {
		assert_eq!(validate(&[]), Err(Error::Empty));
		assert_eq!(validate(&[4, 127, 0, 0]), Err(Error::UnexpectedEnd));
		assert_eq!(validate(&[4, 127, 0, 0, 1, 6, 0x76]), Err(Error::UnexpectedEnd));
		assert_eq!(validate(&[53, 5, b'a', b'b']), Err(Error::UnexpectedEnd));
		assert_eq!(validate(&[0x80]), Err(Error::InvalidVarint));
		// Non-minimal encoding of code 4.
		assert_eq!(validate(&[0x84, 0x00, 1, 2, 3, 4]), Err(Error::InvalidVarint));
		assert_eq!(validate(&[0xff, 0xff, 0xff, 0xff, 0x7f]), Err(Error::InvalidVarint));
		// A DNS name that is not UTF-8, which the `multiaddr` crate cannot decode either.
		let bad = vec![53, 2, 0xff, 0xfe, 6, 0x76, 0x7d];
		assert!(Multiaddr::try_from(bad.clone()).is_err());
		assert_eq!(validate(&bad), Err(Error::InvalidDnsName));
	}

	#[test]
	fn the_longest_address_fits_max_binary_len() {
		let longest =
			[&"a".repeat(63)[..], &"a".repeat(63), &"a".repeat(63), &"a".repeat(61)].join(".");
		let binary = parse(&with_peer(&format!("/dns/{longest}/tcp/65535/wss"))).unwrap();
		assert_eq!(binary.len() as u32, MAX_BINARY_LEN);
	}
}
