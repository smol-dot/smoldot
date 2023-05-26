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
//! TrieRoot = TrieNodeValue(FindBaseTrieWithoutErases(∅))
//!
//! TrieNodeValue(Key) = Encode(StorageValue(Key), Child1(Key), ..., Child16(Key))
//!
//! ChildN(Key) = TrieNodeValue(
//!     LongestCommonDenominator(
//!         FindBaseTrieWithoutErases(Concat(Key, N),
//!         ...ClosestDescendantInDiffInserts(Concat(Key, N))
//!     )
//! )
//!
//! FindBaseTrieWithoutErases(Key) =
//!     Tmp = BaseTrieKeyGrEq(Key)
//!     If !StartsWith(Tmp, Key)
//!         ∅
//!     ElseIf DiffEraseContains(Tmp)
//!         FindBaseTrieWithoutErases(Next(Tmp))
//!     Else
//!         Tmp
//! ```
//!

use super::storage_diff::TrieDiff;
use crate::trie;

/// Configuration for [`trie_root_calculator`].
pub struct Config {
    pub diff: TrieDiff,

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
    })
    .next()
}

pub enum InProgress {
    Finished { trie_root_hash: [u8; 32] },
    BaseTrieGreaterOrEqual(BaseTrieGreaterOrEqual),
    StorageValue(StorageValue),
}

pub struct BaseTrieGreaterOrEqual {
    inner: Box<Inner>,
    /// If `None`, ask for the key according to `inner`. If `Some`, contains the key to ask the
    /// user.
    key_overwrite: Option<Vec<trie::Nibble>>,
}

impl BaseTrieGreaterOrEqual {
    pub fn key(&self) -> &[trie::Nibble] {
        if let Some(key_overwrite) = &self.key_overwrite {
            key_overwrite
        } else {
            todo!()
        }
    }

    pub fn prefix(&self) -> &[trie::Nibble] {
        todo!()
    }

    pub fn inject(mut self, base_trie_next_key: Option<&[trie::Nibble]>) -> InProgress {
        debug_assert!(self
            .inner
            .stack
            .last()
            .map_or(false, |n| n.children.len() != 16));

        // If the key that the user provided is found in the diff as a key that was removed,
        // skip it and ask the user again for the key afterwards.
        if let Some(base_trie_next_key) = base_trie_next_key {
            if matches!(
                self.inner.diff.diff_get(base_trie_next_key),
                Some((None, _))
            ) {
                let mut next_key = base_trie_next_key.to_owned();
                next_key.push(trie::Nibble::zero());
                self.key_overwrite = Some(next_key);
                return InProgress::BaseTrieGreaterOrEqual(self);
            }
        }

        // The user provides the closest descendant to the node at the end of the stack and that
        // is still in the final trie. Now find the same information in the diff.
        let diff_next_key: Option<&[u8]> = todo!();

        let closest_ancestor = match (base_trie_next_key, diff_next_key) {
            (None, None) => {
                self.inner
                    .stack
                    .last_mut()
                    .unwrap_or_else(|| panic!())
                    .children
                    .push(None);
                return self.inner.next();
            }
            (Some(k), None) => k,
            (None, Some(k)) => k,
            (Some(_), Some(_)) => todo!(),
        };

        self.inner.stack.push(InProgressNode {
            partial_key: todo!(),
            children: arrayvec::ArrayVec::new(),
        });
    }
}

pub struct StorageValue(Box<Inner>);

impl StorageValue {
    pub fn key(&self) {}

    pub fn inject_value(mut self, value: &[u8]) -> InProgress {
        let last_elem = self.0.stack.pop().unwrap_or_else(|| panic!());
        debug_assert_eq!(last_elem.children.len(), 16);

        let parent_node = self.0.stack.last();

        let merkle_value = trie::trie_node::calculate_merkle_value(
            trie::trie_node::Decoded {
                children: last_elem.children.try_into().unwrap(),
                partial_key: last_elem.partial_key.iter().copied(),
                storage_value: value,
            },
            parent_node.is_none(),
        )
        .unwrap_or_else(|_| panic!());

        if let Some(parent) = parent_node {
            debug_assert_ne!(parent.children.len(), 16);
            parent.children.push(Some(merkle_value));
            self.0.next()
        } else {
            // No more node in the stack means that this was the root node. The calculated  Merkle
            // value is the trie root hash.
            InProgress::Finished {
                // Guaranteed to never panic for the root node.
                trie_root_hash: merkle_value.try_into().unwrap_or_else(|_| panic!()),
            }
        }
    }
}

struct Inner {
    /// Stack of node keys that we know exist in the final tree.
    stack: Vec<InProgressNode>,
    diff: TrieDiff,
}

struct InProgressNode {
    partial_key: Vec<trie::Nibble>,
    children: arrayvec::ArrayVec<Option<trie::trie_node::MerkleValueOutput>, 16>,
}

impl Inner {
    fn next(self: Box<Self>) -> InProgress {
        let Some(deepest_stack_elem) = self.stack.last() else {
            return InProgress::BaseTrieGreaterOrEqual(BaseTrieGreaterOrEqual {
                inner: self,
                key_overwrite: None
            })
        };

        if deepest_stack_elem.children.len() == 16 {
            InProgress::StorageValue(StorageValue(self))
        } else {
            InProgress::BaseTrieGreaterOrEqual(BaseTrieGreaterOrEqual {
                inner: self,
                key_overwrite: None,
            })
        }
    }
}
