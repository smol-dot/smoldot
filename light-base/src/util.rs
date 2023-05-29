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

use core::{
    fmt::{self, Write as _},
    hash::{BuildHasher, Hasher},
    marker,
};

/// Returns an opaque object implementing the `fmt::Display` trait. Truncates the given `char`
/// yielding iterator to the given number of elements, and if the limit is reached adds a `…` at
/// the end.
pub fn truncated_str<'a>(
    input: impl Iterator<Item = char> + Clone + 'a,
    limit: usize,
) -> impl fmt::Display + 'a {
    struct Iter<I>(I, usize);

    impl<I: Iterator<Item = char> + Clone> fmt::Display for Iter<I> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut counter = 0;
            for c in self.0.clone() {
                f.write_char(c)?;

                counter += 1;
                if counter >= self.1 {
                    f.write_char('…')?;
                    break;
                }
            }

            Ok(())
        }
    }

    Iter(input, limit)
}

/// Exactly the same as `BuildHasherDefault` from the standard library, except without the missing
/// `new` `const` function that somehow requires needs a new language construct or something.
// TODO remove after https://github.com/rust-lang/rust/issues/87864
pub struct BuildHasherDefault<H>(marker::PhantomData<fn() -> H>);

impl<H> BuildHasherDefault<H> {
    pub const fn new() -> Self {
        BuildHasherDefault(marker::PhantomData)
    }
}

impl<H> fmt::Debug for BuildHasherDefault<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuildHasherDefault").finish()
    }
}

impl<H: Default + Hasher> BuildHasher for BuildHasherDefault<H> {
    type Hasher = H;

    fn build_hasher(&self) -> H {
        H::default()
    }
}

impl<H> Clone for BuildHasherDefault<H> {
    fn clone(&self) -> BuildHasherDefault<H> {
        BuildHasherDefault(marker::PhantomData)
    }
}

impl<H> Default for BuildHasherDefault<H> {
    fn default() -> BuildHasherDefault<H> {
        BuildHasherDefault(marker::PhantomData)
    }
}

impl<H> PartialEq for BuildHasherDefault<H> {
    fn eq(&self, _other: &BuildHasherDefault<H>) -> bool {
        true
    }
}

impl<H> Eq for BuildHasherDefault<H> {}

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
    type Hasher = siphasher::sip::SipHasher;

    fn build_hasher(&self) -> Self::Hasher {
        siphasher::sip::SipHasher::new_with_key(&self.0)
    }
}
