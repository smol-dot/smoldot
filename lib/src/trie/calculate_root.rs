// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

//! Freestanding function that calculates the root of a radix-16 Merkle-Patricia trie.
//!
//! See the parent module documentation for an explanation of what the trie is.
//!
//! This module is meant to be used in situations where all the nodes of the trie that have a
//! storage value associated to them are known and easily accessible, and that no cache is
//! available.
//!
//! # Usage
//!
//! Calling the [`root_merkle_value`] function creates a [`RootMerkleValueCalculation`] object
//! which you have to drive to completion.
//!
//! Example:
//!
//! ```
//! use std::{collections::BTreeMap, ops::Bound};
//! use smoldot::trie::{TrieEntryVersion, calculate_root};
//!
//! // In this example, the storage consists in a binary tree map.
//! let mut storage = BTreeMap::<Vec<u8>, (Vec<u8>, TrieEntryVersion)>::new();
//! storage.insert(b"foo".to_vec(), (b"bar".to_vec(), TrieEntryVersion::V1));
//!
//! let trie_root = {
//!     let mut calculation = calculate_root::root_merkle_value();
//!     loop {
//!         match calculation {
//!             calculate_root::RootMerkleValueCalculation::Finished { hash, .. } => break hash,
//!             calculate_root::RootMerkleValueCalculation::NextKey(next_key) => {
//!                 let key_before = next_key.key_before().collect::<Vec<_>>();
//!                 let lower_bound = if next_key.or_equal() {
//!                     Bound::Included(key_before)
//!                 } else {
//!                     Bound::Excluded(key_before)
//!                 };
//!                 let outcome = storage
//!                     .range((lower_bound, Bound::Unbounded))
//!                     .next()
//!                     .filter(|(k, _)| {
//!                         k.iter()
//!                             .copied()
//!                             .zip(next_key.prefix())
//!                             .all(|(a, b)| a == b)
//!                     })
//!                     .map(|(k, _)| k);
//!                 calculation = next_key.inject_key(outcome.map(|k| k.iter().copied()));
//!             }
//!             calculate_root::RootMerkleValueCalculation::StorageValue(value_request) => {
//!                 let key = value_request.key().collect::<Vec<u8>>();
//!                 calculation = value_request.inject(storage.get(&key).map(|(val, v)| (val, *v)));
//!             }
//!         }
//!     }
//! };
//!
//! assert_eq!(
//!     trie_root,
//!     [204, 86, 28, 213, 155, 206, 247, 145, 28, 169, 212, 146, 182, 159, 224, 82,
//!      116, 162, 143, 156, 19, 43, 183, 8, 41, 178, 204, 69, 41, 37, 224, 91]
//! );
//! ```
//!

use crate::trie::empty_trie_merkle_value;

use super::{
    branch_search,
    nibble::{nibbles_to_bytes_suffix_extend, Nibble},
    trie_node, TrieEntryVersion,
};

use alloc::vec::Vec;
use core::array;

/// Start calculating the Merkle value of the root node.
pub fn root_merkle_value() -> RootMerkleValueCalculation {
    CalcInner {
        stack: Vec::with_capacity(8),
    }
    .next()
}

/// Current state of the [`RootMerkleValueCalculation`] and how to continue.
#[must_use]
pub enum RootMerkleValueCalculation {
    /// The calculation is finished.
    Finished {
        /// Root hash that has been calculated.
        hash: [u8; 32],
    },

    /// Request to return the key that follows (in lexicographic order) a given one in the storage.
    /// Call [`NextKey::inject_key`] to indicate this list.
    NextKey(NextKey),

    /// Request the value of the node with a specific key. Call [`StorageValue::inject`] to
    /// indicate the value.
    StorageValue(StorageValue),
}

/// Calculation of the Merkle value is ready to continue.
/// Shared by all the public-facing structs.
struct CalcInner {
    /// Stack of nodes whose value is currently being calculated.
    stack: Vec<Node>,
}

#[derive(Debug)]
struct Node {
    /// Partial key of the node currently being calculated.
    partial_key: Vec<Nibble>,
    /// Merkle values of the children of the node. Filled up to 16 elements, then popped. Each
    /// element is `Some` or `None` depending on whether a child exists.
    children: arrayvec::ArrayVec<Option<trie_node::MerkleValueOutput>, 16>,
}

impl CalcInner {
    /// Returns the full key of the node currently being iterated.
    fn current_iter_node_full_key(&'_ self) -> impl Iterator<Item = Nibble> + '_ {
        self.stack.iter().flat_map(|node| {
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
    }

    /// Advances the calculation to the next step.
    fn next(mut self) -> RootMerkleValueCalculation {
        loop {
            // If all the children of the node at the end of the stack are known, calculate the Merkle
            // value of that node. To do so, we need to ask the user for the storage value.
            if self
                .stack
                .last()
                .map_or(false, |node| node.children.len() == 16)
            {
                // If the key has an even number of nibbles, we need to ask the user for the
                // storage value.
                if self.current_iter_node_full_key().count() % 2 == 0 {
                    break RootMerkleValueCalculation::StorageValue(StorageValue {
                        calculation: self,
                    });
                }

                // Otherwise we can calculate immediately.
                let calculated_elem = self.stack.pop().unwrap();

                // Calculate the Merkle value of the node.
                let merkle_value = trie_node::calculate_merkle_value(
                    trie_node::Decoded {
                        children: array::from_fn(|n| calculated_elem.children[n].as_ref()),
                        partial_key: calculated_elem.partial_key.iter().copied(),
                        storage_value: trie_node::StorageValue::None,
                    },
                    self.stack.is_empty(),
                )
                .unwrap_or_else(|_| unreachable!());

                // Insert Merkle value into the stack, or, if no parent, we have our result!
                if let Some(parent) = self.stack.last_mut() {
                    parent.children.push(Some(merkle_value));
                } else {
                    // Because we pass `is_root_node: true` in the calculation above, it is
                    // guaranteed that the Merkle value is always 32 bytes.
                    let hash = *<&[u8; 32]>::try_from(merkle_value.as_ref()).unwrap();
                    break RootMerkleValueCalculation::Finished { hash };
                }
            } else {
                // Need to find the closest descendant to the first unknown child at the top of the
                // stack.
                break RootMerkleValueCalculation::NextKey(NextKey {
                    branch_search: branch_search::start_branch_search(branch_search::Config {
                        key_before: self.current_iter_node_full_key(),
                        or_equal: true,
                        prefix: self.current_iter_node_full_key(),
                        no_branch_search: false,
                    }),
                    calculation: self,
                });
            }
        }
    }
}

/// Request to return the key that follows (in lexicographic order) a given one in the storage.
/// Call [`NextKey::inject_key`] to indicate this list.
#[must_use]
pub struct NextKey {
    calculation: CalcInner,

    /// Current branch search running to find the closest descendant to the node at the top of
    /// the trie.
    branch_search: branch_search::NextKey,
}

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key_before(&'_ self) -> impl Iterator<Item = u8> + '_ {
        self.branch_search.key_before()
    }

    /// If `true`, then the provided value must the one superior or equal to the requested key.
    /// If `false`, then the provided value must be strictly superior to the requested key.
    pub fn or_equal(&self) -> bool {
        self.branch_search.or_equal()
    }

    /// Returns the prefix the next key must start with. If the next key doesn't start with the
    /// given prefix, then `None` should be provided.
    pub fn prefix(&'_ self) -> impl Iterator<Item = u8> + '_ {
        self.branch_search.prefix()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(
        mut self,
        key: Option<impl Iterator<Item = u8>>,
    ) -> RootMerkleValueCalculation {
        match self.branch_search.inject(key) {
            branch_search::BranchSearch::NextKey(next_key) => {
                RootMerkleValueCalculation::NextKey(NextKey {
                    calculation: self.calculation,
                    branch_search: next_key,
                })
            }
            branch_search::BranchSearch::Found {
                branch_trie_node_key,
            } => {
                // Add the closest descendant to the stack.
                if let Some(branch_trie_node_key) = branch_trie_node_key {
                    let partial_key = branch_trie_node_key
                        .skip(self.calculation.current_iter_node_full_key().count())
                        .collect();
                    self.calculation.stack.push(Node {
                        partial_key,
                        children: arrayvec::ArrayVec::new(),
                    });
                    self.calculation.next()
                } else if let Some(stack_top) = self.calculation.stack.last_mut() {
                    stack_top.children.push(None);
                    self.calculation.next()
                } else {
                    // Trie is completely empty.
                    RootMerkleValueCalculation::Finished {
                        hash: empty_trie_merkle_value(),
                    }
                }
            }
        }
    }
}

/// Request the value of the node with a specific key. Call [`StorageValue::inject`] to indicate
/// the value.
#[must_use]
pub struct StorageValue {
    calculation: CalcInner,
}

impl StorageValue {
    /// Returns the key whose value is being requested.
    pub fn key(&'_ self) -> impl Iterator<Item = u8> + '_ {
        // This function can never be reached if the number of nibbles is uneven.
        debug_assert_eq!(self.calculation.current_iter_node_full_key().count() % 2, 0);
        nibbles_to_bytes_suffix_extend(self.calculation.current_iter_node_full_key())
    }

    /// Indicates the storage value and advances the calculation.
    pub fn inject(
        mut self,
        storage_value: Option<(impl AsRef<[u8]>, TrieEntryVersion)>,
    ) -> RootMerkleValueCalculation {
        let calculated_elem = self.calculation.stack.pop().unwrap();

        // Due to some borrow checker troubles, we need to calculate the storage value
        // hash ahead of time if relevant.
        let storage_value_hash = if let Some((value, TrieEntryVersion::V1)) = storage_value.as_ref()
        {
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
                storage_value: match (storage_value.as_ref(), storage_value_hash.as_ref()) {
                    (_, Some(storage_value_hash)) => trie_node::StorageValue::Hashed(
                        <&[u8; 32]>::try_from(storage_value_hash.as_bytes())
                            .unwrap_or_else(|_| unreachable!()),
                    ),
                    (Some((value, _)), _) => trie_node::StorageValue::Unhashed(value.as_ref()),
                    (None, _) => trie_node::StorageValue::None,
                },
            },
            self.calculation.stack.is_empty(),
        )
        .unwrap_or_else(|_| unreachable!());

        // Insert Merkle value into the stack, or, if no parent, we have our result!
        if let Some(parent) = self.calculation.stack.last_mut() {
            parent.children.push(Some(merkle_value));
            self.calculation.next()
        } else {
            // Because we pass `is_root_node: true` in the calculation above, it is guaranteed
            // that the Merkle value is always 32 bytes.
            let hash = *<&[u8; 32]>::try_from(merkle_value.as_ref()).unwrap();
            RootMerkleValueCalculation::Finished { hash }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::trie::TrieEntryVersion;
    use alloc::collections::BTreeMap;
    use core::ops::Bound;

    fn calculate_root(version: TrieEntryVersion, trie: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
        let mut calculation = super::root_merkle_value();

        loop {
            match calculation {
                super::RootMerkleValueCalculation::Finished { hash } => {
                    return hash;
                }
                super::RootMerkleValueCalculation::NextKey(next_key) => {
                    let lower_bound = if next_key.or_equal() {
                        Bound::Included(next_key.key_before().collect::<Vec<_>>())
                    } else {
                        Bound::Excluded(next_key.key_before().collect::<Vec<_>>())
                    };

                    let k = trie
                        .range((lower_bound, Bound::Unbounded))
                        .next()
                        .filter(|(k, _)| {
                            k.iter()
                                .copied()
                                .zip(next_key.prefix())
                                .all(|(a, b)| a == b)
                        })
                        .map(|(k, _)| k);

                    calculation = next_key.inject_key(k.map(|k| k.iter().copied()));
                }
                super::RootMerkleValueCalculation::StorageValue(value) => {
                    let key = value.key().collect::<Vec<u8>>();
                    calculation = value.inject(trie.get(&key).map(|v| (v, version)));
                }
            }
        }
    }

    #[test]
    fn trie_root_one_node() {
        let mut trie = BTreeMap::new();
        trie.insert(b"abcd".to_vec(), b"hello world".to_vec());

        let expected = [
            122, 177, 134, 89, 211, 178, 120, 158, 242, 64, 13, 16, 113, 4, 199, 212, 251, 147,
            208, 109, 154, 182, 168, 182, 65, 165, 222, 124, 63, 236, 200, 81,
        ];

        assert_eq!(calculate_root(TrieEntryVersion::V0, &trie), &expected[..]);
        assert_eq!(calculate_root(TrieEntryVersion::V1, &trie), &expected[..]);
    }

    #[test]
    fn trie_root_empty() {
        let trie = BTreeMap::new();
        let expected = blake2_rfc::blake2b::blake2b(32, &[], &[0x0]);
        assert_eq!(
            calculate_root(TrieEntryVersion::V0, &trie),
            expected.as_bytes()
        );
        assert_eq!(
            calculate_root(TrieEntryVersion::V1, &trie),
            expected.as_bytes()
        );
    }

    #[test]
    fn trie_root_single_tuple() {
        let mut trie = BTreeMap::new();
        trie.insert([0xaa].to_vec(), [0xbb].to_vec());

        let expected = blake2_rfc::blake2b::blake2b(
            32,
            &[],
            &[
                0x42,   // leaf 0x40 (2^6) with (+) key of 2 nibbles (0x02)
                0xaa,   // key data
                1 << 2, // length of value in bytes as Compact
                0xbb,   // value data
            ],
        );

        assert_eq!(
            calculate_root(TrieEntryVersion::V0, &trie),
            expected.as_bytes()
        );
        assert_eq!(
            calculate_root(TrieEntryVersion::V1, &trie),
            expected.as_bytes()
        );
    }

    #[test]
    fn trie_root_example() {
        let mut trie = BTreeMap::new();
        trie.insert([0x48, 0x19].to_vec(), [0xfe].to_vec());
        trie.insert([0x13, 0x14].to_vec(), [0xff].to_vec());

        let ex = vec![
            0x80,      // branch, no value (0b_10..) no nibble
            0x12,      // slots 1 & 4 are taken from 0-7
            0x00,      // no slots from 8-15
            0x05 << 2, // first slot: LEAF, 5 bytes long.
            0x43,      // leaf 0x40 with 3 nibbles
            0x03,      // first nibble
            0x14,      // second & third nibble
            0x01 << 2, // 1 byte data
            0xff,      // value data
            0x05 << 2, // second slot: LEAF, 5 bytes long.
            0x43,      // leaf with 3 nibbles
            0x08,      // first nibble
            0x19,      // second & third nibble
            0x01 << 2, // 1 byte data
            0xfe,      // value data
        ];

        let expected = blake2_rfc::blake2b::blake2b(32, &[], &ex);
        assert_eq!(
            calculate_root(TrieEntryVersion::V0, &trie),
            expected.as_bytes()
        );
        assert_eq!(
            calculate_root(TrieEntryVersion::V1, &trie),
            expected.as_bytes()
        );
    }
}
