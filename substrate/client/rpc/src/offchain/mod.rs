// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Substrate offchain API.

#[cfg(test)]
mod tests;

use self::error::Error;
use jsonrpsee::{core::async_trait, Extensions};
use parking_lot::RwLock;
use sc_rpc_api::check_if_safe;
/// Re-export the API for backward compatibility.
pub use sc_rpc_api::offchain::*;
use sp_core::{
	offchain::{OffchainStorage, StorageKind},
	Bytes,
};
use std::sync::Arc;

/// Offchain API
#[derive(Debug)]
pub struct Offchain<T: OffchainStorage> {
	/// Offchain storage
	storage: Arc<RwLock<T>>,
}

impl<T: OffchainStorage> Offchain<T> {
	/// Create new instance of Offchain API.
	pub fn new(storage: T) -> Self {
		Offchain { storage: Arc::new(RwLock::new(storage)) }
	}
}

#[async_trait]
impl<T: OffchainStorage + 'static> OffchainApiServer for Offchain<T> {
	fn set_local_storage(
		&self,
		ext: &Extensions,
		kind: StorageKind,
		key: Bytes,
		value: Bytes,
	) -> Result<(), Error> {
		check_if_safe(ext)?;

		let prefix = match kind {
			StorageKind::PERSISTENT => sp_offchain::STORAGE_PREFIX,
			StorageKind::LOCAL => return Err(Error::UnavailableStorageKind),
		};
		self.storage.write().set(prefix, &key, &value);
		Ok(())
	}

	fn clear_local_storage(
		&self,
		ext: &Extensions,
		kind: StorageKind,
		key: Bytes,
	) -> Result<(), Error> {
		check_if_safe(ext)?;

		let prefix = match kind {
			StorageKind::PERSISTENT => sp_offchain::STORAGE_PREFIX,
			StorageKind::LOCAL => return Err(Error::UnavailableStorageKind),
		};
		self.storage.write().remove(prefix, &key);

		Ok(())
	}

	fn get_local_storage(
		&self,
		ext: &Extensions,
		kind: StorageKind,
		key: Bytes,
	) -> Result<Option<Bytes>, Error> {
		check_if_safe(ext)?;

		let prefix = match kind {
			StorageKind::PERSISTENT => sp_offchain::STORAGE_PREFIX,
			StorageKind::LOCAL => return Err(Error::UnavailableStorageKind),
		};

		Ok(self.storage.read().get(prefix, &key).map(Into::into))
	}
}
