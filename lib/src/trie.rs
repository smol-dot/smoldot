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

//! Radix-16 Merkle-Patricia trie.
//!
//! This Substrate/Polkadot-specific radix-16 Merkle-Patricia trie is a data structure that
//! associates keys with values, and that allows efficient verification of the integrity of the
//! data.
//!
//! # Overview
//!
//! The key-value storage that the blockchain maintains is represented by
//! [a tree](https://en.wikipedia.org/wiki/Tree_data_structure), where each key-value pair in the
//! storage corresponds to a node in that tree.
//!
//! Each node in this tree has what is called a Merkle value associated to it. This Merkle value
//! consists, in its essence, in the combination of the storage value associated to that node and
//! the Merkle values of all of the node's children. If the resulting Merkle value would be too
//! long, it is first hashed.
//!
//! Since the Merkle values of a node's children depend, in turn, of the Merkle value of their
//! own children, we can say that the Merkle value of a node depends on all of the node's
//! descendants.
//!
//! Consequently, the Merkle value of the root node of the tree depends on the storage values of
//! all the nodes in the tree.
//!
//! See also [the Wikipedia page for Merkle tree for a different
//! explanation](https://en.wikipedia.org/wiki/Merkle_tree).
//!
//! ## Efficient updates
//!
//! When a storage value gets modified, the Merkle value of the root node of the tree also gets
//! modified. Thanks to the tree layout, we don't need to recalculate the Merkle value of the
//! entire tree, but only of the ancestors of the node which has been modified.
//!
//! If the storage consists of N entries, recalculating the Merkle value of the trie root requires
//! on average only `log16(N)` operations.
//!
//! ## Proof of storage entry
//!
//! In the situation where we want to know the storage value associated to a node, but we only
//! know the Merkle value of the root of the trie, it is possible to ask a third-party for the
//! unhashed Merkle values of the desired node and all its ancestors. This is called a Merkle
//! proof.
//!
//! After having verified that the third-party has provided correct values, and that they match
//! the expected root node Merkle value known locally, we can extract the storage value from the
//! Merkle value of the desired node.
//!
//! # Details
//!
//! This data structure is a tree composed of nodes, each node being identified by a key. A key
//! consists in a sequence of 4-bits values called *nibbles*. Example key: `[3, 12, 7, 0]`.
//!
//! Some of these nodes contain a value.
//!
//! A node A is an *ancestor* of another node B if the key of A is a prefix of the key of B. For
//! example, the node whose key is `[3, 12]` is an ancestor of the node whose key is
//! `[3, 12, 8, 9]`. B is a *descendant* of A.
//!
//! Nodes exist only either if they contain a value, or if their key is the longest shared prefix
//! of two or more nodes that contain a value. For example, if nodes `[7, 2, 9, 11]` and
//! `[7, 2, 14, 8]` contain a value, then node `[7, 2]` also exist, because it is the longest
//! prefix shared between the two.
//!
//! The *Merkle value* of a node is composed, amongst other things, of its associated value and of
//! the Merkle value of its descendants. As such, modifying a node modifies the Merkle value of
//! all its ancestors. Note, however, that modifying a node modifies the Merkle value of *only*
//! its ancestors. As such, the time spent calculating the Merkle value of the root node of a trie
//! mostly depends on the number of modifications that are performed on it, and only a bit on the
//! size of the trie.
//!
//! ## Trie entry version
//!
//! In the Substrate/Polkadot trie, each trie node that contains a value also has a version
//! associated to it.
//!
//! This version changes the way the hash of the node is calculated and how the Merkle proof is
//! generated. Version 1 leads to more succinct Merkle proofs, which is important when these proofs
//! are sent over the Internet.
//!
//! Note that most of the time all the entries of the trie have the same version. However, it is
//! possible for the trie to be in a hybrid state where some entries have a certain version and
//! other entries a different version. For this reason, most of the trie-related APIs require you
//! to provide a trie entry version alongside with the value.
//!

use crate::util;

use core::{array, cmp, iter};

mod nibble;

pub mod branch_search;
pub mod calculate_root;
pub mod prefix_proof;
pub mod proof_decode;
pub mod proof_encode;
pub mod trie_node;
pub mod trie_structure;

pub use nibble::{
    all_nibbles, bytes_to_nibbles, nibbles_to_bytes_prefix_extend, nibbles_to_bytes_suffix_extend,
    nibbles_to_bytes_truncate, BytesToNibbles, Nibble, NibbleFromU8Error,
};

/// The format of the nodes of trie has two different versions.
///
/// As a summary of the difference between versions, in `V1` the value of the item in the trie is
/// hashed if it is too large. This isn't the case in `V0` where the value of the item is always
/// unhashed.
///
/// An encoded node value can be decoded unambiguously no matter whether it was encoded using `V0`
/// or `V1`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TrieEntryVersion {
    V0,
    V1,
}

impl TryFrom<u8> for TrieEntryVersion {
    type Error = (); // TODO: better error?

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TrieEntryVersion::V0),
            1 => Ok(TrieEntryVersion::V1),
            _ => Err(()),
        }
    }
}

impl From<TrieEntryVersion> for u8 {
    fn from(v: TrieEntryVersion) -> u8 {
        match v {
            TrieEntryVersion::V0 => 0,
            TrieEntryVersion::V1 => 1,
        }
    }
}

/// Returns the Merkle value of the root of an empty trie.
pub fn empty_trie_merkle_value() -> [u8; 32] {
    trie_node::calculate_merkle_value(
        trie_node::Decoded {
            children: [None::<&'static [u8]>; 16],
            partial_key: iter::empty(),
            storage_value: trie_node::StorageValue::None,
        },
        true,
    )
    .unwrap_or_else(|_| panic!())
    .try_into()
    // Guaranteed to never panic when `is_root_node` is `true`.
    .unwrap_or_else(|_| panic!())
}

/// Returns the Merkle value of a trie containing the entries passed as parameter. The entries
/// passed as parameter are `(key, value)`.
///
/// The complexity of this method is `O(n²)` where `n` is the number of entries.
// TODO: improve complexity?
pub fn trie_root(
    version: TrieEntryVersion,
    entries: &[(impl AsRef<[u8]>, impl AsRef<[u8]>)],
) -> [u8; 32] {
    // Stack of nodes whose value is currently being calculated.
    let mut stack: Vec<Node> = Vec::with_capacity(8);
    #[derive(Debug)]
    struct Node {
        /// Partial key of the node currently being calculated.
        partial_key: Vec<Nibble>,
        /// Merkle values of the children of the node. Filled up to 16 elements, then popped. Each
        /// element is `Some` or `None` depending on whether a child exists.
        children: arrayvec::ArrayVec<Option<trie_node::MerkleValueOutput>, 16>,
    }

    loop {
        // Full key of the node currently being calculated.
        let iter_node_full_node = stack
            .iter()
            .flat_map(|node| {
                let child_nibble = if node.children.len() == 16 {
                    None
                } else {
                    Some(Nibble::try_from(u8::try_from(node.children.len()).unwrap()).unwrap())
                };

                node.partial_key
                    .iter()
                    .copied()
                    .chain(child_nibble.into_iter())
            })
            .collect::<Vec<_>>();

        // If all the children of the node at the end of the stack are known, calculate the Merkle
        // value of that node.
        if stack.last().map_or(false, |node| node.children.len() == 16) {
            let calculated_elem = stack.pop().unwrap();

            // Find the storage value of this element, if any.
            // TODO: O(n) complexity
            let storage_value = entries
                .iter()
                .find(|(k, _)| {
                    bytes_to_nibbles(k.as_ref().iter().copied())
                        .eq(iter_node_full_node.iter().copied())
                })
                .map(|(_, v)| v);

            // Due to some borrow checker troubles, we need to calculate the storage value
            // hash ahead of time if relevant.
            let storage_value_hash =
                if let (Some(value), TrieEntryVersion::V1) = (storage_value, version) {
                    if value.as_ref().len() >= 33 {
                        Some(blake2_rfc::blake2b::blake2b(32, &[], value.as_ref()))
                    } else {
                        None
                    }
                } else {
                    None
                };

            // Calculate the Merkle value of the node.
            let merkle_value = trie_node::calculate_merkle_value(
                trie_node::Decoded {
                    children: array::from_fn(|n| calculated_elem.children[n].as_ref()),
                    partial_key: calculated_elem.partial_key.iter().copied(),
                    storage_value: match (storage_value, storage_value_hash.as_ref()) {
                        (_, Some(storage_value_hash)) => trie_node::StorageValue::Hashed(
                            <&[u8; 32]>::try_from(storage_value_hash.as_bytes())
                                .unwrap_or_else(|_| unreachable!()),
                        ),
                        (Some(value), _) => trie_node::StorageValue::Unhashed(value.as_ref()),
                        (None, _) => trie_node::StorageValue::None,
                    },
                },
                stack.is_empty(),
            )
            .unwrap_or_else(|_| unreachable!());

            // Insert Merkle value into the stack, or, if no parent, we have our result!
            if let Some(parent) = stack.last_mut() {
                parent.children.push(Some(merkle_value));
            } else {
                // Because we pass `is_root_node: true` in the calculation above, it is guaranteed
                // that the Merkle value is always 32 bytes.
                break *<&[u8; 32]>::try_from(merkle_value.as_ref()).unwrap();
            }

            continue;
        }

        // Need to find the closest descendant to the first unknown child at the top of the stack.
        let closest_descendant = {
            let mut search = branch_search::start_branch_search(branch_search::Config {
                key_before: iter_node_full_node.iter().copied(),
                or_equal: true,
                prefix: iter_node_full_node.iter().copied(),
                no_branch_search: false,
            });

            loop {
                match search {
                    branch_search::BranchSearch::Found {
                        branch_trie_node_key,
                    } => break branch_trie_node_key,
                    branch_search::BranchSearch::NextKey(next_key) => {
                        let mut maybe_next = None;
                        // TODO: O(n)
                        for (k, _) in entries {
                            if maybe_next
                                .as_ref()
                                .map_or(false, |m| AsRef::as_ref(*m) <= k.as_ref())
                            {
                                continue;
                            }
                            match k.as_ref().iter().copied().cmp(next_key.key_before()) {
                                cmp::Ordering::Less => continue,
                                cmp::Ordering::Equal if !next_key.or_equal() => continue,
                                _ => {}
                            }
                            maybe_next = Some(k);
                        }
                        if maybe_next.map_or(false, |m| {
                            m.as_ref()
                                .iter()
                                .copied()
                                .zip(next_key.prefix())
                                .any(|(a, b)| a != b)
                        }) {
                            maybe_next = None;
                        }
                        search = next_key.inject(maybe_next.map(util::as_ref_iter));
                    }
                }
            }
        };

        // Add the closest descendant to the stack.
        if let Some(closest_descendant) = closest_descendant {
            let partial_key = closest_descendant.skip(iter_node_full_node.len()).collect();
            stack.push(Node {
                partial_key,
                children: arrayvec::ArrayVec::new(),
            })
        } else if let Some(stack_top) = stack.last_mut() {
            stack_top.children.push(None);
        } else {
            // Trie is completely empty.
            debug_assert!(entries.is_empty());
            break empty_trie_merkle_value();
        }
    }
}

/// Returns the Merkle value of a trie containing the entries passed as parameter, where the keys
/// are the SCALE-codec-encoded indices of these entries.
///
/// > **Note**: In isolation, this function seems highly specific. In practice, it is notably used
/// >           in order to build the trie root of the list of extrinsics of a block.
pub fn ordered_root(version: TrieEntryVersion, entries: &[impl AsRef<[u8]>]) -> [u8; 32] {
    const USIZE_COMPACT_BYTES: usize = 1 + (usize::BITS as usize) / 8;

    let mut calculation = calculate_root::root_merkle_value(None);

    loop {
        match calculation {
            calculate_root::RootMerkleValueCalculation::Finished { hash, .. } => {
                return hash;
            }
            calculate_root::RootMerkleValueCalculation::AllKeys(keys) => {
                calculation = keys.inject((0..entries.len()).map(|num| {
                    arrayvec::ArrayVec::<u8, USIZE_COMPACT_BYTES>::try_from(
                        util::encode_scale_compact_usize(num).as_ref(),
                    )
                    .unwrap()
                    .into_iter()
                }));
            }
            calculate_root::RootMerkleValueCalculation::StorageValue(value) => {
                let key = value
                    .key()
                    .collect::<arrayvec::ArrayVec<u8, USIZE_COMPACT_BYTES>>();
                let (_, key) =
                    util::nom_scale_compact_usize::<nom::error::Error<&[u8]>>(&key).unwrap();
                calculation = value.inject(entries.get(key).map(move |v| (v, version)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_trie() {
        let obtained = super::empty_trie_merkle_value();
        let expected = blake2_rfc::blake2b::blake2b(32, &[], &[0x0]);
        assert_eq!(obtained, expected.as_bytes());
    }

    #[test]
    fn trie_root_example_v0() {
        let obtained = super::trie_root(
            super::TrieEntryVersion::V0,
            &[(&b"foo"[..], &b"bar"[..]), (&b"foobar"[..], &b"baz"[..])],
        );

        assert_eq!(
            obtained,
            [
                166, 24, 32, 181, 251, 169, 176, 26, 238, 16, 181, 187, 216, 74, 234, 128, 184, 35,
                3, 24, 197, 232, 202, 20, 185, 164, 148, 12, 118, 224, 152, 21
            ]
        );
    }

    #[test]
    fn trie_root_example_v1() {
        let obtained = super::trie_root(
            super::TrieEntryVersion::V1,
            &[
                (&b"bar"[..], &b"foo"[..]),
                (&b"barfoo"[..], &b"hello"[..]),
                (&b"anotheritem"[..], &b"anothervalue"[..]),
            ],
        );

        assert_eq!(
            obtained,
            [
                68, 24, 7, 195, 69, 202, 122, 223, 136, 189, 33, 171, 27, 60, 186, 219, 21, 97,
                106, 187, 137, 22, 126, 185, 254, 40, 93, 213, 206, 205, 4, 200
            ]
        );
    }
}
