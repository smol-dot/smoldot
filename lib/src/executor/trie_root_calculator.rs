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

//! Given as input a partial base trie and a diff, calculates the new root of the trie.
//!
//! # Implementation
//!
//! The algorithm for calculating the trie root is roughly:
//!
//! ```notrust
//! TrieRoot = ClosestDescendantMerkleValue(∅) || EmptyTrieRootHash
//!
//! ClosestDescendantMerkleValue(Key) =
//!     Btcd := BaseTrieClosestDescendant(Key)
//!     If DiffContainsEntryWithPrefix(Key)
//!         MaybeNodeKey := LongestCommonDenominator(Btcd, ...DiffInsertsNodesWithPrefix(Key))
//!         MaybeChildren := Array(ClosestDescendantMerkleValue(Concat(MaybeNodeKey, 0)), ..., ClosestDescendantMerkleValue(Concat(MaybeNodeKey, 15)))
//!         MaybeStorageValue := DiffInserts(MaybeNodeKey) || (BaseTrieStorageValue(MaybeNodeKey) - DiffErases(MaybeNodeKey))
//!
//!         If MaybeStorageValue = ∅ AND NumChildren(MaybeChildren) == 0
//!             ∅
//!         ElseIf MaybeStorageValue = ∅ AND NumChildren(MaybeChildren) == 1
//!             ChildThatExists(MaybeChildren)
//!         Else
//!             Encode(MaybeStorageValue, MaybeChildren)
//!
//!     Else
//!         BaseTrieMerkleValue(Btcd)
//! ```
//!
//! The public API functions are thus `BaseTrieClosestDescendant`, `BaseTrieMerkleValue`,
//! and `BaseTrieStorageValue`.
//!
//! They could be consolidated into `BaseTrieClosestDescendantMerkleValue` and
//! `BaseTrieClosestDescendantStorageValue`, but we.don't do so for API convenience.
//!
//! Furthermore, `BaseTrieMerkleValue` is allowed to return "unknown", in which case we switch
//! to the other branch of the `If` and recalculate the Merkle value ourselves.
//!
//! The algorithm above is recursive. In order to implement it, we instead maintain a stack of
//! nodes that are currently being calculated.
//!

use alloc::{boxed::Box, vec::Vec};
use core::{cmp, iter, ops};

use super::storage_diff::TrieDiff;
use crate::trie;

pub use trie::{Nibble, TrieEntryVersion};

mod tests;

/// Configuration for [`trie_root_calculator`].
pub struct Config {
    /// Diff that is being applied on top of the base trie.
    pub diff: TrieDiff,

    /// Version to use for the storage values written by [`Config::diff`].
    pub diff_trie_entries_version: TrieEntryVersion,

    /// Depth level of the deepest node whose value needs to be calculated. The root node has a
    /// depth level of 1, its children a depth level of 2, etc.
    ///
    /// Used as a hint to pre-allocate a container. Getting the value wrong has no ill
    /// consequence except a very small performance hit.
    pub max_trie_recalculation_depth_hint: usize,
}

/// Starts a new calculation.
pub fn trie_root_calculator(config: Config) -> InProgress {
    Box::new(Inner {
        stack: Vec::with_capacity(config.max_trie_recalculation_depth_hint),
        diff: config.diff,
        diff_trie_entries_version: config.diff_trie_entries_version,
    })
    .next()
}

/// Trie root calculation in progress.
pub enum InProgress {
    /// Calculation has successfully finished.
    Finished {
        /// Calculated trie root hash.
        trie_root_hash: [u8; 32],
    },
    /// See [`ClosestDescendant`].
    ClosestDescendant(ClosestDescendant),
    /// See [`StorageValue`].
    StorageValue(StorageValue),
    /// See [`MerkleValue`].
    MerkleValue(MerkleValue),
}

/// In order to continue the calculation, must find in the base trie the closest descendant
/// (including branch node) to a certain key in the trie. This can be equal to the requested key
/// itself.
pub struct ClosestDescendant(Box<Inner>);

impl ClosestDescendant {
    /// Returns an iterator of slices, which, when joined together, form the full key of the trie
    /// node whose closest descendant must be fetched.
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[Nibble]> + '_> + '_ {
        self.0.current_node_full_key()
    }

    /// Indicates the key of the closest descendant to the key indicated by
    /// [`ClosestDescendant::key`] and resume the calculation.
    pub fn inject(mut self, closest_descendant: Option<&[Nibble]>) -> InProgress {
        // We are after a call to `BaseTrieClosestDescendant`.
        debug_assert!(self.0.stack.last().map_or(true, |n| n.children.len() != 16));

        // Length of the key returned by `key()`.
        let self_key_len = self.key().fold(0, |acc, k| acc + k.as_ref().len());

        // Now calculate `DiffContainsEntryWithPrefix` and
        // `LongestCommonDenominator(DiffInsertsNodesWithPrefix)`.
        let mut diff_erases_a_descendant = false;
        let mut diff_inserts_lcd_partial_key = None::<&[u8]>;
        {
            // TODO: could be optimized?
            let prefix_nibbles = self.key().fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });
            let prefix = trie::nibbles_to_bytes_suffix_extend(prefix_nibbles.into_iter())
                .collect::<Vec<_>>();
            for (key, erases) in self.0.diff.diff_range_ordered::<[u8]>((
                ops::Bound::Included(&prefix[..]),
                ops::Bound::Unbounded,
            )) {
                if !key.starts_with(&prefix) {
                    break;
                }
                if erases {
                    diff_erases_a_descendant = true;
                } else {
                    let key_adjusted = &key[(self_key_len / 2)..];
                    diff_inserts_lcd_partial_key = match diff_inserts_lcd_partial_key.take() {
                        Some(v) => Some(&key_adjusted[..cmp::min(key_adjusted.len(), v.len())]),
                        None => Some(key_adjusted),
                    };
                }
            }
        };

        // If the base trie contains a descendant but the diff doesn't contain any descendant,
        // jump to calling `BaseTrieMerkleValue`.
        if let Some(closest_descendant) = closest_descendant {
            if !diff_erases_a_descendant && diff_inserts_lcd_partial_key.is_none() {
                self.0.stack.push(InProgressNode {
                    partial_key: closest_descendant[self_key_len..].to_vec(),
                    children: arrayvec::ArrayVec::new(),
                });
                return InProgress::MerkleValue(MerkleValue(self.0));
            }
        }

        // Find the value of `MaybeNode`.
        let maybe_node_partial_key = match (diff_inserts_lcd_partial_key, closest_descendant) {
            (Some(cpk), Some(d)) => {
                let d = &d[self_key_len..];
                d[..cmp::min(d.len(), cpk.len() * 2)].to_vec()
            }
            (Some(cpk), None) => trie::bytes_to_nibbles(cpk.iter().copied()).collect::<Vec<_>>(),
            (None, Some(d)) => d[self_key_len..].to_vec(),
            (None, None) => {
                // If neither the base trie nor the diff contain any descendant, then skip ahead.
                return if let Some(parent_node) = self.0.stack.last_mut() {
                    // If the element has a parent, indicate that the current iterated node doesn't
                    // exist and continue the algorithm.
                    debug_assert_ne!(parent_node.children.len(), 16);
                    parent_node.children.push(None);
                    self.0.next()
                } else {
                    // If the element doesn't have a parent, then the trie is completely empty.
                    InProgress::Finished {
                        trie_root_hash: trie::empty_trie_merkle_value(),
                    }
                };
            }
        };

        // Push `MaybeNode` onto the stack and continue the algorithm.
        self.0.stack.push(InProgressNode {
            partial_key: maybe_node_partial_key,
            children: arrayvec::ArrayVec::new(),
        });
        self.0.next()
    }
}

/// In order to continue, must fetch the storage value of the given key in the base trie.
pub struct StorageValue(Box<Inner>);

impl StorageValue {
    /// Returns an iterator of slices, which, when joined together, form the full key of the trie
    /// node whose storage value must be fetched.
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[Nibble]> + '_> + '_ {
        self.0.current_node_full_key()
    }

    /// Indicate the storage value and trie entry version of the trie node indicated by
    /// [`StorageValue::key`] and resume the calculation.
    pub fn inject_value(
        mut self,
        base_trie_storage_value: Option<(&[u8], TrieEntryVersion)>,
    ) -> InProgress {
        // We have finished obtaining `BaseTrieStorageValue` and we are at the last step of
        // `ClosestDescendantMerkleValue` in the algorithm shown at the top.

        // Remove the element that is being calculated from the stack, as we finish the
        // calculation down below.
        let calculated_elem = self.0.stack.pop().unwrap_or_else(|| panic!());
        debug_assert_eq!(calculated_elem.children.len(), 16);

        let node_num_children = calculated_elem
            .children
            .iter()
            .filter(|c| c.is_some())
            .count();

        let parent_node = self.0.stack.last_mut();
        debug_assert!(parent_node.map_or(true, |p| p.children.len() != 16));

        // Adjust the storage value to take the diff into account.
        // In other words, we calculate `MaybeStorageValue` from `BaseTrieStorageValue`.
        let maybe_storage_value = if self.key().count() % 2 == 0 {
            // TODO: could be optimized?
            let key_nibbles = self.key().fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });
            let key_as_u8 =
                trie::nibbles_to_bytes_suffix_extend(key_nibbles.into_iter()).collect::<Vec<_>>();
            if let Some((value, _)) = self.0.diff.diff_get(&key_as_u8) {
                value.map(|v| (v, self.0.diff_trie_entries_version))
            } else {
                base_trie_storage_value
            }
        } else {
            base_trie_storage_value
        };

        match (
            maybe_storage_value,
            node_num_children,
            self.0.stack.last_mut(),
        ) {
            (None, 0, Some(parent_node)) => {
                // Trie node no longer exists after the diff has been applied.
                // This path is only reached if the trie node has a parent, as otherwise the trie
                // node is the trie root and thus necessarily exists.
                parent_node.children.push(None);
                self.0.next()
            }
            (None, 1, parent_node) => {
                // Trie node no longer exists after the diff has been applied, but it has exactly
                // one child.
                let child_merkle_value = calculated_elem
                    .children
                    .into_iter()
                    .find_map(|c| c)
                    .unwrap_or_else(|| panic!());

                if let Some(parent_node) = parent_node {
                    // Trie node no longer exists, but from its parent's point of view it has been
                    // replaced in the trie with that one single child.
                    parent_node.children.push(Some(child_merkle_value));
                    self.0.next()
                } else {
                    // No more node in the stack means that this was the root node. The child is
                    // the trie root.
                    InProgress::Finished {
                        // Guaranteed to never panic for the root node.
                        trie_root_hash: child_merkle_value.try_into().unwrap_or_else(|_| panic!()),
                    }
                }
            }
            (_, _, parent_node) => {
                // Trie node still exists. Calculate its Merkle value.

                // Due to some borrow checker troubles, we need to calculate the storage value
                // hash ahead of time if relevant.
                let storage_value_hash =
                    if let Some((value, TrieEntryVersion::V1)) = maybe_storage_value {
                        Some(blake2_rfc::blake2b::blake2b(8, &[], value))
                    } else {
                        None
                    };
                let merkle_value = trie::trie_node::calculate_merkle_value(
                    trie::trie_node::Decoded {
                        children: <&[_; 16]>::try_from(calculated_elem.children.as_ref())
                            .unwrap_or_else(|_| panic!())
                            .clone(),
                        partial_key: calculated_elem.partial_key.iter().copied(),
                        storage_value: match maybe_storage_value {
                            Some((value, TrieEntryVersion::V0)) => {
                                trie::trie_node::StorageValue::Unhashed(value)
                            }
                            Some((_, TrieEntryVersion::V1)) => {
                                trie::trie_node::StorageValue::Hashed(
                                    <&[u8; 32]>::try_from(
                                        storage_value_hash.as_ref().unwrap().as_bytes(),
                                    )
                                    .unwrap_or_else(|_| panic!()),
                                )
                            }
                            None => trie::trie_node::StorageValue::None,
                        },
                    },
                    parent_node.is_none(),
                )
                .unwrap_or_else(|_| panic!());

                if let Some(parent_node) = parent_node {
                    parent_node.children.push(Some(merkle_value));
                    self.0.next()
                } else {
                    // No more node in the stack means that this was the root node. The calculated
                    // Merkle value is the trie root hash.
                    InProgress::Finished {
                        // Guaranteed to never panic for the root node.
                        trie_root_hash: merkle_value.try_into().unwrap_or_else(|_| panic!()),
                    }
                }
            }
        }
    }
}

/// In order to continue, must fetch the Merkle value of the given key in the base trie.
///
/// It is possible to continue the calculation even if the Merkle value is unknown, in which case
/// the calculation will walk down the trie in order to calculate the Merkle value manually.
pub struct MerkleValue(Box<Inner>);

impl MerkleValue {
    /// Returns an iterator of slices, which, when joined together, form the full key of the trie
    /// node whose Merkle value must be fetched.
    ///
    /// The key is guaranteed to have been injected through [`ClosestDescendant::inject`] earlier.
    pub fn key(&'_ self) -> impl Iterator<Item = impl AsRef<[Nibble]> + '_> + '_ {
        self.0.current_node_full_key()
    }

    /// Indicate that the value is unknown and resume the calculation.
    ///
    /// This function be used if you are unaware of the Merkle value. The algorithm will perform
    /// the calculation of this Merkle value manually, which takes more time.
    pub fn resume_unknown(self) -> InProgress {
        // The element currently being iterated was `Btcd`, and is now switched to being
        // `MaybeNodeKey`. Because a `MerkleValue` is only ever created if the diff doesn't
        // contain any entry below the currently iterated node, we know for sure that
        // `MaybeNodeKey` is equal to `Btcd` and thus have nothing to do.
        self.0.next()
    }

    /// Indicate the Merkle value of the trie node indicated by [`MerkleValue::key`] and resume
    /// the calculation.
    ///
    /// Note that there is no way to indicate that the trie node doesn't exist. This is because the
    /// node is guaranteed to have been injected through [`ClosestDescendant::inject`] earlier.
    pub fn inject_merkle_value(mut self, merkle_value: &[u8]) -> InProgress {
        // We are after a call to `BaseTrieMerkleValue` in the algorithm shown at the top.

        // Check with a debug_assert! that this is a valid Merkle value. While this algorithm
        // doesn't actually care about the content, providing a wrong value clearly indicates a
        // bug somewhere in the API user's code.
        debug_assert!(if merkle_value.len() < 32 {
            trie::trie_node::decode(merkle_value).is_ok()
        } else {
            true
        });

        // Pop the element at the top of the stack, as we know its Merkle value.
        self.0.stack.pop();

        if let Some(parent_node) = self.0.stack.last_mut() {
            // If the element has a parent, add the Merkle value to its children and resume the
            // algorithm.
            debug_assert_ne!(parent_node.children.len(), 16);
            parent_node
                .children
                .push(Some(trie::trie_node::MerkleValueOutput::from_bytes(
                    merkle_value,
                )));
            self.0.next()
        } else {
            // If the element doesn't have a parent, then the Merkle value is the root of trie!
            // This should only ever happen if the diff is empty.

            // The trie root hash is always 32 bytes. If not, it indicates a bug in the API user's
            // code.
            let trie_root_hash = <[u8; 32]>::try_from(merkle_value).unwrap_or_else(|_| panic!());
            InProgress::Finished { trie_root_hash }
        }
    }
}

struct Inner {
    /// Stack of node entries whose value is currently being calculated. Every time
    /// `BaseTrieClosestDescendant` returns we push an element here.
    ///
    /// The node currently being iterated is either `Btcd` or `MaybeNodeValue` depending on where
    /// we are in the algorithm.
    ///
    /// If the entry at the top of the stack has `children.len() == 16`, then the node currently
    /// being iterated is the one at the top of the stack, otherwise it's the child of the one at
    /// the top of the stack whose entry is past the end of `children`.
    stack: Vec<InProgressNode>,

    /// Same value as [`Config::diff`].
    diff: TrieDiff,

    /// Same value as [`Config::diff_trie_entries_version`].
    diff_trie_entries_version: TrieEntryVersion,
}

struct InProgressNode {
    /// Partial key of the node currently being calculated.
    partial_key: Vec<Nibble>,

    /// Merkle values of the children of the node. Filled up to 16 elements, then the storage
    /// value is requested. Each element is `Some` or `None` depending on whether a child exists.
    children: arrayvec::ArrayVec<Option<trie::trie_node::MerkleValueOutput>, 16>,
}

impl Inner {
    /// Analyzes the content of the [`Inner`] and progresses the algorithm.
    fn next(self: Box<Self>) -> InProgress {
        let Some(deepest_stack_elem) = self.stack.last() else {
            // Only reached at the very start of the calculation.
            return InProgress::ClosestDescendant(ClosestDescendant(self))
        };

        if deepest_stack_elem.children.len() == 16 {
            // Finished obtaining `MaybeChildren` and jumping to obtaining `MaybeStorageValue`.
            InProgress::StorageValue(StorageValue(self))
        } else {
            // Still obtaining `MaybeChildren`.
            InProgress::ClosestDescendant(ClosestDescendant(self))
        }
    }

    /// Iterator of arrays which, when joined together, form the full key of the node currently
    /// being iterated.
    fn current_node_full_key(&'_ self) -> impl Iterator<Item = impl AsRef<[Nibble]> + '_> + '_ {
        self.stack.iter().flat_map(move |node| {
            let maybe_child_nibble_u8 =
                u8::try_from(node.children.len()).unwrap_or_else(|_| unreachable!());
            let child_nibble = Nibble::try_from(maybe_child_nibble_u8).ok();

            iter::once(either::Right(&node.partial_key))
                .chain(child_nibble.map(|n| either::Left([n])).into_iter())
        })
    }
}
