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

//! Little Endian Base 128
//!
//! The LEB128 encoding is used throughout the networking code. This module provides utilities for
//! encoding/decoding this format.
//!
//! See <https://en.wikipedia.org/wiki/LEB128>.

/// Returns an LEB128-encoded integer as a list of bytes.
///
/// This function accepts as parameter an `Into<u64>`. As such, one can also pass a `u8`, `u16`,
/// or `u32` for example. Use [`encode_usize`] for the `usize` equivalent.
pub fn encode(value: impl Into<u64>) -> impl ExactSizeIterator<Item = u8> + Clone {
    #[derive(Clone)]
    struct EncodeIter {
        value: u64,
        finished: bool,
    }

    impl Iterator for EncodeIter {
        type Item = u8;

        fn next(&mut self) -> Option<Self::Item> {
            if self.finished {
                return None;
            }

            if self.value < (1 << 7) {
                self.finished = true;
                return Some(u8::try_from(self.value).unwrap());
            }

            let ret = (1 << 7) | u8::try_from(self.value & 0b111_1111).unwrap();
            self.value >>= 7;
            Some(ret)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let len = self.clone().count();
            (len, Some(len))
        }
    }

    impl ExactSizeIterator for EncodeIter {}

    EncodeIter {
        value: value.into(),
        finished: false,
    }
}

/// Returns an LEB128-encoded `usize` as a list of bytes.
///
/// See also [`encode`].
pub fn encode_usize(value: usize) -> impl ExactSizeIterator<Item = u8> + Clone {
    // `encode_usize` can leverage `encode` thanks to the property checked in this debug_assert.
    #[cfg(not(any(
        target_pointer_width = "16",
        target_pointer_width = "32",
        target_pointer_width = "64"
    )))]
    compile_error!("usize must be <= u64");
    encode(u64::try_from(value).unwrap())
}

/// Decodes a LEB128-encoded `usize`.
///
/// > **Note**: When using this function outside of a `nom` "context", you might have to explicit
/// >           the type of `E`. Use `nom::error::Error<&[u8]>`.
pub(crate) fn nom_leb128_usize<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], usize, E> {
    // `nom_leb128_usize` can leverage `nom_leb128_u64` thanks to the property checked in this
    // debug_assert.
    #[cfg(not(any(
        target_pointer_width = "16",
        target_pointer_width = "32",
        target_pointer_width = "64"
    )))]
    compile_error!("usize must be <= u64");
    let (rest, value) = nom_leb128_u64(bytes)?;

    let value = match usize::try_from(value) {
        Ok(v) => v,
        Err(_) => {
            return Err(nom::Err::Error(nom::error::make_error(
                bytes,
                nom::error::ErrorKind::LengthValue,
            )));
        }
    };

    Ok((rest, value))
}

/// Decodes a LEB128-encoded `u64`.
///
/// > **Note**: When using this function outside of a `nom` "context", you might have to explicit
/// >           the type of `E`. Use `nom::error::Error<&[u8]>`.
pub(crate) fn nom_leb128_u64<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], u64, E> {
    let mut out = 0u64;

    for (n, byte) in bytes.iter().enumerate() {
        if (7 * n) >= usize::try_from(u64::BITS).unwrap() {
            return Err(nom::Err::Error(nom::error::make_error(
                bytes,
                nom::error::ErrorKind::LengthValue,
            )));
        }

        match u64::from(*byte & 0b111_1111).checked_mul(1 << (7 * n)) {
            Some(o) => out |= o,
            None => {
                return Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::LengthValue,
                )))
            }
        };

        if (*byte & 0x80) == 0 {
            // We want to avoid LEB128 numbers such as `[0x81, 0x0]`.
            if n >= 1 && *byte == 0x0 {
                return Err(nom::Err::Error(nom::error::make_error(
                    bytes,
                    nom::error::ErrorKind::Verify,
                )));
            }

            return Ok((&bytes[(n + 1)..], out));
        }
    }

    Err(nom::Err::Incomplete(nom::Needed::Unknown))
}

#[cfg(test)]
mod tests {
    #[test]
    fn basic_encode() {
        let obtained = super::encode(0x123_4567_89ab_cdef_u64).collect::<Vec<_>>();
        assert_eq!(obtained, &[239, 155, 175, 205, 248, 172, 209, 145, 1]);
    }

    #[test]
    fn encode_zero() {
        let obtained = super::encode(0u64).collect::<Vec<_>>();
        assert_eq!(obtained, &[0x0u8]);
    }

    #[test]
    fn exact_size_iterator() {
        for _ in 0..128 {
            let iter = super::encode(rand::random::<u64>());
            let expected = iter.len();
            let obtained = iter.count();
            assert_eq!(expected, obtained);
        }
    }

    #[test]
    fn decode_large_value() {
        // Carefully crafted LEB128 that overflows the left shift before overflowing the
        // encoded size.
        let encoded = (0..256).map(|_| 129).collect::<Vec<_>>();
        assert!(super::nom_leb128_usize::<nom::error::Error<&[u8]>>(&encoded).is_err());
    }

    // TODO: more tests
}
