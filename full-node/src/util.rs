// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

/// Implementation of the `BuildHasher` trait for the sip hasher.
///
/// Contrary to the one in the standard library, a seed is explicitly passed here, making the
/// hashing predictable. This is a good thing for tests and no-std compatibility.
pub struct SipHasherBuild([u8; 16]);

impl SipHasherBuild {
    pub fn new(seed: [u8; 16]) -> SipHasherBuild {
        SipHasherBuild(seed)
    }
}

impl core::hash::BuildHasher for SipHasherBuild {
    type Hasher = siphasher::sip::SipHasher13;

    fn build_hasher(&self) -> Self::Hasher {
        siphasher::sip::SipHasher13::new_with_key(&self.0)
    }
}
