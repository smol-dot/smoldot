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

use super::nibble;
use alloc::vec::Vec;
use core::{cmp, fmt, iter, slice};

/// Encodes the components of a node value into the node value itself.
///
/// This function returns an iterator of buffers. The actual node value is the concatenation of
/// these buffers put together.
///
/// > **Note**: The returned iterator might contain a reference to the storage value and children
/// >           values in the [`Decoded`]. By returning an iterator of buffers, we avoid copying
/// >           these storage value and children values.
///
/// This encoding is independent of the trie version.
pub fn encode<'a>(
    decoded: Decoded<
        'a,
        impl ExactSizeIterator<Item = nibble::Nibble> + Clone,
        impl AsRef<[u8]> + Clone + 'a,
    >,
) -> Result<impl Iterator<Item = impl AsRef<[u8]> + 'a + Clone> + Clone + 'a, EncodeError> {
    // The return value is composed of three parts:
    // - Before the storage value.
    // - The storage value (which can be empty).
    // - The children nodes.

    // Contains the encoding before the storage value.
    let mut before_storage_value: Vec<u8> = Vec::with_capacity(decoded.partial_key.len() / 2 + 32);

    let has_children = decoded.children.iter().any(Option::is_some);

    // We first push the node header.
    // See https://spec.polkadot.network/#defn-node-header
    {
        let (first_byte_msb, pk_len_first_byte_bits): (u8, _) =
            match (has_children, decoded.storage_value) {
                (false, StorageValue::Unhashed(_)) => (0b01, 6),
                (true, StorageValue::None) => (0b10, 6),
                (true, StorageValue::Unhashed(_)) => (0b11, 6),
                (false, StorageValue::Hashed(_)) => (0b001, 5),
                (true, StorageValue::Hashed(_)) => (0b0001, 4),
                (false, StorageValue::None) => {
                    if decoded.partial_key.len() != 0 {
                        return Err(EncodeError::PartialKeyButNoChildrenNoStorageValue);
                    } else {
                        (0, 6)
                    }
                }
            };

        let max_representable_in_first_byte = (1 << pk_len_first_byte_bits) - 1;
        let first_byte = (first_byte_msb << pk_len_first_byte_bits)
            | u8::try_from(cmp::min(
                decoded.partial_key.len(),
                max_representable_in_first_byte,
            ))
            .unwrap();
        before_storage_value.push(first_byte);

        // Note that if the partial key length is exactly equal to `pk_len_first_byte_bits`, we
        // need to push a `0` afterwards in order to avoid an ambiguity. Similarly, if
        // `remain_pk_len` is at any point equal to 255, we must push an additional `0`
        // afterwards.
        let mut remain_pk_len = decoded
            .partial_key
            .len()
            .checked_sub(max_representable_in_first_byte);
        while let Some(pk_len_inner) = remain_pk_len {
            before_storage_value.push(u8::try_from(cmp::min(pk_len_inner, 255)).unwrap());
            remain_pk_len = pk_len_inner.checked_sub(255);
        }
    }

    // We then push the partial key.
    before_storage_value.extend(nibble::nibbles_to_bytes_prefix_extend(
        decoded.partial_key.clone(),
    ));

    // After the partial key, the node value optionally contains a bitfield of child nodes.
    if has_children {
        before_storage_value.extend_from_slice(&decoded.children_bitmap().to_le_bytes());
    }

    // Then, the storage value.
    let storage_value = match decoded.storage_value {
        StorageValue::Hashed(hash) => &hash[..],
        StorageValue::None => &[][..],
        StorageValue::Unhashed(storage_value) => {
            before_storage_value.extend_from_slice(
                crate::util::encode_scale_compact_usize(storage_value.len()).as_ref(),
            );
            storage_value
        }
    };

    // Finally, the children node values.
    let children_nodes = decoded
        .children
        .into_iter()
        .flatten()
        .flat_map(|child_value| {
            let size = crate::util::encode_scale_compact_usize(child_value.as_ref().len());
            [either::Left(size), either::Right(child_value)].into_iter()
        });

    // The return value is the combination of these components.
    Ok(iter::once(either::Left(before_storage_value))
        .chain(iter::once(either::Right(storage_value)))
        .map(either::Left)
        .chain(children_nodes.map(either::Right)))
}

/// Error potentially returned by [`encode`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum EncodeError {
    /// Nodes that have no children nor storage value are invalid unless they are the root node.
    PartialKeyButNoChildrenNoStorageValue,
}

/// Encodes the components of a node value into the node value itself.
///
/// This is a convenient wrapper around [`encode`]. See the documentation of [`encode`] for more
/// details.
pub fn encode_to_vec(
    decoded: Decoded<
        '_,
        impl ExactSizeIterator<Item = nibble::Nibble> + Clone,
        impl AsRef<[u8]> + Clone,
    >,
) -> Result<Vec<u8>, EncodeError> {
    let capacity = decoded.partial_key.len() / 2
        + match decoded.storage_value {
            StorageValue::Hashed(_) => 32,
            StorageValue::None => 0,
            StorageValue::Unhashed(v) => v.len(),
        }
        + 16 * 32
        + 32; // The last `+ 32` is an arbitrary margin, for length prefixes and the header.

    let result = encode(decoded)?.fold(Vec::with_capacity(capacity), |mut a, b| {
        a.extend_from_slice(b.as_ref());
        a
    });

    // Check that `capacity` was calculated correctly and that no re-allocation has happened.
    debug_assert_eq!(result.capacity(), capacity);

    Ok(result)
}

/// Calculates the Merkle value of the given node.
///
/// `is_root_node` must be `true` if the encoded node is the root node of the trie.
///
/// This is similar to [`encode`], except that the encoding is then optionally hashed.
///
/// Hashing is performed if the encoded value is 32 bytes or more, or if `is_root_node` is `true`.
/// This is the reason why `is_root_node` must be provided.
pub fn calculate_merkle_value(
    decoded: Decoded<
        '_,
        impl ExactSizeIterator<Item = nibble::Nibble> + Clone,
        impl AsRef<[u8]> + Clone,
    >,
    is_root_node: bool,
) -> Result<MerkleValueOutput, EncodeError> {
    /// The Merkle value of a node is defined as either the hash of the node value, or the node value
    /// itself if it is shorted than 32 bytes (or if we are the root).
    ///
    /// This struct serves as a helper to handle these situations. Rather than putting intermediary
    /// values in buffers then hashing the node value as a whole, we push the elements of the node
    /// value to this struct which automatically switches to hashing if the value exceeds 32 bytes.
    enum HashOrInline {
        Inline(arrayvec::ArrayVec<u8, 31>),
        Hasher(blake2_rfc::blake2b::Blake2b),
    }

    let mut merkle_value_sink = if is_root_node {
        HashOrInline::Hasher(blake2_rfc::blake2b::Blake2b::new(32))
    } else {
        HashOrInline::Inline(arrayvec::ArrayVec::new())
    };

    for buffer in encode(decoded)? {
        let buffer = buffer.as_ref();
        match &mut merkle_value_sink {
            HashOrInline::Inline(curr) => {
                if curr.try_extend_from_slice(buffer).is_ok() {
                    continue;
                }

                let mut hasher = blake2_rfc::blake2b::Blake2b::new(32);
                hasher.update(curr);
                hasher.update(buffer);
                merkle_value_sink = HashOrInline::Hasher(hasher);
            }
            HashOrInline::Hasher(hasher) => {
                hasher.update(buffer);
            }
        }
    }

    Ok(MerkleValueOutput {
        inner: match merkle_value_sink {
            HashOrInline::Inline(b) => MerkleValueOutputInner::Inline(b),
            HashOrInline::Hasher(h) => MerkleValueOutputInner::Hasher(h.finalize()),
        },
    })
}

/// Output of the calculation.
#[derive(Clone)]
pub struct MerkleValueOutput {
    inner: MerkleValueOutputInner,
}

#[derive(Clone)]
enum MerkleValueOutputInner {
    Inline(arrayvec::ArrayVec<u8, 31>),
    Hasher(blake2_rfc::blake2b::Blake2bResult),
    Bytes(arrayvec::ArrayVec<u8, 32>),
}

impl MerkleValueOutput {
    /// Builds a [`MerkleValueOutput`] from a slice of bytes.
    ///
    /// # Panic
    ///
    /// Panics if `bytes.len() > 32`.
    ///
    pub fn from_bytes(bytes: &[u8]) -> MerkleValueOutput {
        assert!(bytes.len() <= 32);
        MerkleValueOutput {
            inner: MerkleValueOutputInner::Bytes({
                let mut v = arrayvec::ArrayVec::new();
                v.try_extend_from_slice(bytes).unwrap();
                v
            }),
        }
    }
}

impl AsRef<[u8]> for MerkleValueOutput {
    fn as_ref(&self) -> &[u8] {
        match &self.inner {
            MerkleValueOutputInner::Inline(a) => a.as_slice(),
            MerkleValueOutputInner::Hasher(a) => a.as_bytes(),
            MerkleValueOutputInner::Bytes(a) => a.as_slice(),
        }
    }
}

impl TryFrom<MerkleValueOutput> for [u8; 32] {
    type Error = (); // TODO: proper error?

    fn try_from(output: MerkleValueOutput) -> Result<Self, Self::Error> {
        if output.as_ref().len() == 32 {
            let mut out = [0; 32];
            out.copy_from_slice(output.as_ref());
            Ok(out)
        } else {
            Err(())
        }
    }
}

impl fmt::Debug for MerkleValueOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), f)
    }
}

/// Decodes a node value found in a proof into its components.
///
/// This can decode nodes no matter their version.
pub fn decode(mut node_value: &'_ [u8]) -> Result<Decoded<DecodedPartialKey<'_>, &'_ [u8]>, Error> {
    if node_value.is_empty() {
        return Err(Error::Empty);
    }

    // See https://spec.polkadot.network/#defn-node-header
    let (has_children, storage_value_hashed, pk_len_first_byte_bits) = match node_value[0] >> 6 {
        0b00 => {
            if (node_value[0] >> 5) == 0b001 {
                (false, Some(true), 5)
            } else if (node_value[0] >> 4) == 0b0001 {
                (true, Some(true), 4)
            } else if node_value[0] == 0 {
                (false, None, 6)
            } else {
                return Err(Error::InvalidHeaderBits);
            }
        }
        0b10 => (true, None, 6),
        0b01 => (false, Some(false), 6),
        0b11 => (true, Some(false), 6),
        _ => unreachable!(),
    };

    // Length of the partial key, in nibbles.
    let pk_len = {
        let mut accumulator = usize::from(node_value[0] & ((1 << pk_len_first_byte_bits) - 1));
        node_value = &node_value[1..];
        let mut continue_iter = accumulator == ((1 << pk_len_first_byte_bits) - 1);
        while continue_iter {
            if node_value.is_empty() {
                return Err(Error::PartialKeyLenTooShort);
            }
            continue_iter = node_value[0] == 255;
            accumulator = accumulator
                .checked_add(usize::from(node_value[0]))
                .ok_or(Error::PartialKeyLenOverflow)?;
            node_value = &node_value[1..];
        }
        accumulator
    };

    // No children and no storage value can only indicate the root of an empty trie, in which case
    // a non-empty partial key is invalid.
    if pk_len != 0 && !has_children && storage_value_hashed.is_none() {
        return Err(Error::EmptyTrieWithPartialKey);
    }

    // Iterator to the partial key found in the node value of `proof_iter`.
    let partial_key = {
        // Length of the partial key, in bytes.
        let pk_len_bytes = if pk_len == 0 {
            0
        } else {
            1 + ((pk_len - 1) / 2)
        };
        if node_value.len() < pk_len_bytes {
            return Err(Error::PartialKeyTooShort);
        }

        let pk = &node_value[..pk_len_bytes];
        node_value = &node_value[pk_len_bytes..];

        if (pk_len % 2) == 1 && (pk[0] & 0xf0) != 0 {
            return Err(Error::InvalidPartialKeyPadding);
        }

        pk
    };

    // After the partial key, the node value optionally contains a bitfield of child nodes.
    let children_bitmap = if has_children {
        if node_value.len() < 2 {
            return Err(Error::ChildrenBitmapTooShort);
        }
        let val = u16::from_le_bytes(<[u8; 2]>::try_from(&node_value[..2]).unwrap());
        if val == 0 {
            return Err(Error::ZeroChildrenBitmap);
        }
        node_value = &node_value[2..];
        val
    } else {
        0
    };

    // Now at the value that interests us.
    let storage_value = match storage_value_hashed {
        Some(false) => {
            let (node_value_update, len) = crate::util::nom_scale_compact_usize(node_value)
                .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::StorageValueLenDecode)?;
            node_value = node_value_update;
            if node_value.len() < len {
                return Err(Error::StorageValueTooShort);
            }
            let storage_value = &node_value[..len];
            node_value = &node_value[len..];
            StorageValue::Unhashed(storage_value)
        }
        Some(true) => {
            if node_value.len() < 32 {
                return Err(Error::StorageValueTooShort);
            }
            let storage_value_hash = <&[u8; 32]>::try_from(&node_value[..32]).unwrap();
            node_value = &node_value[32..];
            StorageValue::Hashed(storage_value_hash)
        }
        None => StorageValue::None,
    };

    let mut children = [None; 16];
    for (n, child) in children.iter_mut().enumerate() {
        if children_bitmap & (1 << n) == 0 {
            continue;
        }

        // Find the Merkle value of that child in `node_value`.
        let (node_value_update, len) = crate::util::nom_scale_compact_usize(node_value)
            .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::ChildLenDecode)?;
        if len > 32 {
            return Err(Error::ChildTooLarge);
        }
        node_value = node_value_update;
        if node_value.len() < len {
            return Err(Error::ChildrenTooShort);
        }

        *child = Some(&node_value[..len]);
        node_value = &node_value[len..];
    }

    if !node_value.is_empty() {
        return Err(Error::TooLong);
    }

    Ok(Decoded {
        partial_key: if (pk_len % 2) == 1 {
            DecodedPartialKey::from_bytes_skip_first(partial_key)
        } else {
            DecodedPartialKey::from_bytes(partial_key)
        },
        children,
        storage_value,
    })
}

/// Decoded node value. Returned by [`decode`] or passed as parameter to [`encode`].
#[derive(Debug, Clone)]
pub struct Decoded<'a, I, C> {
    /// Iterator to the nibbles of the partial key of the node.
    pub partial_key: I,

    /// All 16 possible children. `Some` if a child is present, and `None` otherwise. The `&[u8]`
    /// can be:
    ///
    /// - Of length 32, in which case the slice is the hash of the node value of the child (also
    ///   known as the Merkle value).
    /// - Empty when decoding a compact trie proof.
    /// - Of length inferior to 32, in which case the slice is directly the node value.
    ///
    pub children: [Option<C>; 16],

    /// Storage value of this node.
    pub storage_value: StorageValue<'a>,
}

impl<'a, I, C> Decoded<'a, I, C> {
    /// Returns a bits map of the children that are present, as found in the node value.
    pub fn children_bitmap(&self) -> u16 {
        let mut out = 0u16;
        for n in 0..16 {
            if self.children[n].is_none() {
                continue;
            }
            out |= 1 << n;
        }
        out
    }
}

/// See [`Decoded::storage_value`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum StorageValue<'a> {
    /// Storage value of the item is present in the node value.
    Unhashed(&'a [u8]),
    /// BLAKE2 hash of the storage value of the item is present in the node value.
    Hashed(&'a [u8; 32]),
    /// Item doesn't have any storage value.
    None,
}

/// Iterator to the nibbles of the partial key. See [`Decoded::partial_key`].
#[derive(Clone)]
pub struct DecodedPartialKey<'a> {
    inner: nibble::BytesToNibbles<iter::Copied<slice::Iter<'a, u8>>>,
    skip_first: bool,
}

impl<'a> DecodedPartialKey<'a> {
    /// Returns a [`DecodedPartialKey`] iterator that produces the nibbles encoded as the given
    /// bytes. Each byte is turned into two nibbles.
    ///
    /// > **Note**: This function is a convenient wrapper around [`nibble::bytes_to_nibbles`].
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        DecodedPartialKey {
            inner: nibble::bytes_to_nibbles(bytes.iter().copied()),
            skip_first: false,
        }
    }

    /// Equivalent to [`DecodedPartialKey::from_bytes`], but skips the first nibble.
    ///
    /// This is useful for situations where the partial key contains a `0` prefix that exists for
    /// alignment but doesn't actually represent a nibble.
    ///
    /// > **Note**: This is equivalent to `from_bytes(bytes).skip(1)`. The possibility to skip the
    /// >           first nibble is built into this code due to how frequent it is necessary.
    pub fn from_bytes_skip_first(bytes: &'a [u8]) -> Self {
        DecodedPartialKey {
            inner: nibble::bytes_to_nibbles(bytes.iter().copied()),
            skip_first: true,
        }
    }
}

impl<'a> Iterator for DecodedPartialKey<'a> {
    type Item = nibble::Nibble;

    fn next(&mut self) -> Option<nibble::Nibble> {
        loop {
            let nibble = self.inner.next()?;
            if self.skip_first {
                debug_assert_eq!(u8::from(nibble), 0);
                self.skip_first = false;
                continue;
            }
            break Some(nibble);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut len = self.inner.len();
        if self.skip_first {
            len -= 1;
        }
        (len, Some(len))
    }
}

impl<'a> ExactSizeIterator for DecodedPartialKey<'a> {}

impl<'a> fmt::Debug for DecodedPartialKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const HEX_TABLE: &[u8] = b"0123456789abcdef";
        write!(f, "0x")?;
        for nibble in self.clone() {
            let chr = HEX_TABLE[usize::from(u8::from(nibble))];
            write!(f, "{}", char::from(chr))?;
        }
        Ok(())
    }
}

/// Possible error returned by [`decode`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Node value is empty.
    Empty,
    /// Bits in the header have an invalid format.
    InvalidHeaderBits,
    /// Node value ends while parsing partial key length.
    PartialKeyLenTooShort,
    /// Length of partial key is too large to be reasonable.
    PartialKeyLenOverflow,
    /// Node value ends within partial key.
    PartialKeyTooShort,
    /// If partial key is of uneven length, then it must be padded with `0`.
    InvalidPartialKeyPadding,
    /// End of data within the children bitmap.
    ChildrenBitmapTooShort,
    /// The children bitmap is equal to 0 despite the header indicating the presence of children.
    ZeroChildrenBitmap,
    /// Error while decoding length of child.
    ChildLenDecode,
    /// Node value ends within a child value.
    ChildrenTooShort,
    /// Child value is superior to 32 bytes.
    ChildTooLarge,
    /// Error while decoding length of storage value.
    StorageValueLenDecode,
    /// Node value ends within the storage value.
    StorageValueTooShort,
    /// Node value is longer than expected.
    TooLong,
    /// Node value indicates that it is the root of an empty trie but contains a non-empty partial
    /// key.
    EmptyTrieWithPartialKey,
}

#[cfg(test)]
mod tests {
    use super::super::nibble;

    #[test]
    fn basic() {
        let encoded_bytes = &[
            194, 99, 192, 0, 0, 128, 129, 254, 111, 21, 39, 188, 215, 18, 139, 76, 128, 157, 108,
            33, 139, 232, 34, 73, 0, 21, 202, 54, 18, 71, 145, 117, 47, 222, 189, 93, 119, 68, 128,
            108, 211, 105, 98, 122, 206, 246, 73, 77, 237, 51, 77, 26, 166, 1, 52, 179, 173, 43,
            89, 219, 104, 196, 190, 208, 128, 135, 177, 13, 185, 111, 175,
        ];

        let decoded = super::decode(encoded_bytes).unwrap();

        assert_eq!(
            super::encode(decoded.clone())
                .unwrap()
                .fold(Vec::new(), |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                }),
            encoded_bytes
        );
        assert_eq!(
            decoded.partial_key.clone().collect::<Vec<_>>(),
            vec![
                nibble::Nibble::try_from(0x6).unwrap(),
                nibble::Nibble::try_from(0x3).unwrap()
            ]
        );
        assert_eq!(
            decoded.storage_value,
            super::StorageValue::Unhashed(&[][..])
        );

        assert_eq!(decoded.children.iter().filter(|c| c.is_some()).count(), 2);
        assert_eq!(
            decoded.children[6],
            Some(
                &[
                    129, 254, 111, 21, 39, 188, 215, 18, 139, 76, 128, 157, 108, 33, 139, 232, 34,
                    73, 0, 21, 202, 54, 18, 71, 145, 117, 47, 222, 189, 93, 119, 68
                ][..]
            )
        );
        assert_eq!(
            decoded.children[7],
            Some(
                &[
                    108, 211, 105, 98, 122, 206, 246, 73, 77, 237, 51, 77, 26, 166, 1, 52, 179,
                    173, 43, 89, 219, 104, 196, 190, 208, 128, 135, 177, 13, 185, 111, 175
                ][..]
            )
        );

        assert_eq!(super::encode_to_vec(decoded).unwrap(), encoded_bytes);
    }

    #[test]
    fn no_children_no_storage_value() {
        assert!(matches!(
            super::encode(super::Decoded {
                children: [None::<&'static [u8]>; 16],
                storage_value: super::StorageValue::None,
                partial_key: core::iter::empty()
            }),
            Ok(_)
        ));

        assert!(matches!(
            super::encode(super::Decoded {
                children: [None::<&'static [u8]>; 16],
                storage_value: super::StorageValue::None,
                partial_key: core::iter::once(nibble::Nibble::try_from(2).unwrap())
            }),
            Err(super::EncodeError::PartialKeyButNoChildrenNoStorageValue)
        ));
    }
}
