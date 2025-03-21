// Smoldot
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Inherents, together with transactions, form the body of a block.
//!
//! The body of a block consists of a list of what is called extrinsics. An extrinsic can be
//! either a transaction, when it was submitted by a user, or an inherent, which is what this
//! module is about.
//!
//! When a block is authored, one of the first steps is for the block author to generate the list
//! of inherents. This is done by calling a runtime function, passing as parameter an encoded
//! [`InherentData`].
//!
//! When a block is later verified, the inherents are verified by calling a runtime function and
//! passing as parameter an encoded [`InherentData`] as well.

/// Values of the inherents to pass to the runtime.
///
/// Historically, the inherent data included an Aura or Babe slot number, using the identifiers
/// `auraslot` or `babeslot`. The runtime-side verification of the slot number has been removed in
/// May 2021, and all the checks performed by the runtime are now performed by the client instead.
/// Older runtime versions still require the slot number. For this reason, verifying the inherents
/// (calling `BlockBuilder_check_inherents`) of blocks that are using older runtime versions will
/// lead to errors concerning the Aura or Babe modules that should simply be ignored. Authoring
/// blocks using older runtime versions is not supported anymore.
#[derive(Debug)]
pub struct InherentData {
    /// Number of milliseconds since the UNIX epoch when the block is generated, ignoring leap
    /// seconds.
    ///
    /// Its identifier passed to the runtime is: `timstap0`.
    pub timestamp: u64,
    // TODO: parachain-related inherents are missing
}

impl InherentData {
    /// Turns this list of inherents into a list that can be passed as parameter to the runtime.
    pub fn as_raw_list(
        &self,
    ) -> impl ExactSizeIterator<Item = ([u8; 8], impl AsRef<[u8]> + Clone)> + Clone {
        [(*b"timstap0", self.timestamp.to_le_bytes())].into_iter()
    }

    /// Turns this list of inherents into a list that can be passed as parameter to the runtime.
    pub fn into_raw_list(
        self,
    ) -> impl ExactSizeIterator<Item = ([u8; 8], impl AsRef<[u8]> + Clone)> + Clone {
        // TODO: DRY
        [(*b"timstap0", self.timestamp.to_le_bytes())].into_iter()
    }
}
