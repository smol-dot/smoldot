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

//! A multihash is a small data structure containing a code (an integer) and data. The format of
//! the data depends on the code.
//!
//! See <https://github.com/multiformats/multihash>

use alloc::vec::Vec;
use core::fmt;

use crate::util;

/// A multihash made of a code and a slice of data.
///
/// This type contains a generic parameter `T` that stores the multihash itself, for example
/// `Vec<u8>` or `&[u8]`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Multihash<T = Vec<u8>>(T);

impl<T: AsRef<[u8]>> Multihash<T> {
    /// Returns the code stored in this multihash.
    pub fn hash_algorithm_code(&self) -> u32 {
        decode(&self.0.as_ref()).unwrap().0
    }

    /// Returns the data stored in this multihash.
    pub fn data(&self) -> &[u8] {
        decode(&self.0.as_ref()).unwrap().1
    }

    /// Checks whether `input` is a valid multihash.
    pub fn from_bytes(input: T) -> Result<Self, (FromBytesError, T)> {
        if let Err(err) = decode(input.as_ref()) {
            return Err((err, input));
        }

        Ok(Multihash(input))
    }

    /// Destroys the [`Multihash`] and returns the underlying buffer.
    pub fn into_bytes(self) -> T {
        self.0
    }
}

impl<'a> Multihash<&'a [u8]> {
    /// Checks whether `input` is a valid multihash.
    ///
    /// Contrary to [`Multihash::from_bytes`], doesn't return an error if the slice is too long
    /// but returns the remainder.
    pub fn from_bytes_partial(
        input: &'a [u8],
    ) -> Result<(Multihash<&'a [u8]>, &'a [u8]), FromBytesError> {
        match multihash::<nom::error::Error<&[u8]>>(input) {
            Ok((rest, _)) => Ok((Multihash(&input.as_ref()[..rest.len()]), rest)),
            Err(_) => Err(FromBytesError::DecodeError),
        }
    }
}

impl Multihash<Vec<u8>> {
    /// Builds a multihash from the "identity" hash algorithm code and the provided data.
    ///
    /// Calling [`Multihash::data`] on the returned value will always yield back the same data
    /// as was passed as parameter.
    pub fn identity<'a>(data: &'a [u8]) -> Self {
        let mut out = Vec::with_capacity(data.len() + 8);
        out.extend(util::leb128::encode(0u32));
        out.extend(util::leb128::encode_usize(data.len()));
        out.extend_from_slice(data);
        Multihash(out)
    }
}

impl<T> AsRef<T> for Multihash<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// Error when turning bytes into a [`Multihash`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum FromBytesError {
    /// The multihash is invalid.
    DecodeError,
}

impl<T: AsRef<[u8]>> fmt::Debug for Multihash<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Multihash<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base58 = bs58::encode(self.0.as_ref()).into_string();
        write!(f, "{base58}")
    }
}

fn decode<'a>(bytes: &'a [u8]) -> Result<(u32, &'a [u8]), FromBytesError> {
    match nom::combinator::all_consuming(multihash::<nom::error::Error<&[u8]>>)(bytes) {
        Ok((_rest, multihash)) => {
            debug_assert!(_rest.is_empty());
            Ok(multihash)
        }
        Err(_) => Err(FromBytesError::DecodeError),
    }
}

fn multihash<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], (u32, &'a [u8]), E> {
    nom::sequence::tuple((
        nom::combinator::map_opt(crate::util::leb128::nom_leb128_usize, |c| {
            u32::try_from(c).ok()
        }),
        nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
    ))(bytes)
}
