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

//! Allows searching for the closest branch node in a trie when only the storage trie nodes are
//! known.
//!
//! This module can be used in situations where only the list of trie nodes with a storage value
//! is known, such as in the form of a `BTreeMap`, and allows finding the list of branch nodes.

use core::iter;

use crate::trie;
use alloc::vec::{IntoIter, Vec};

pub use crate::trie::Nibble;

mod tests;

/// Configuration for [`start_branch_search`].
#[derive(Debug, Clone)]
pub struct Config<K, P> {
    /// The search will try to find the closest node whose key is strictly superior or superior
    /// or equal (see [`Config::or_equal`]) to the value in this field.
    pub key_before: K,

    /// If `true`, also include the node whose key is equal to [`Config::key_before`] (if any).
    /// If `false`, only nodes whose key is strictly superior will be searched.
    pub or_equal: bool,

    /// Only search nodes whose key starts with the list of nibbles given in this field.
    pub prefix: P,

    /// If `true`, only return nodes that have a storage value associated to them.
    ///
    /// > **Note**: This option is provided as a convenience. The entire point of this search
    /// >           is to find branch nodes when only storage nodes are known.
    pub no_branch_search: bool,
}

/// Start the search algorithm.
pub fn start_branch_search(
    config: Config<impl Iterator<Item = Nibble>, impl Iterator<Item = Nibble>>,
) -> BranchSearch {
    BranchSearch::NextKey(NextKey {
        prefix: config.prefix.collect(),
        key_before: config.key_before.collect(),
        or_equal: config.or_equal,
        inner: NextKeyInner::FirstFound {
            no_branch_search: config.no_branch_search,
        },
    })
}

/// Progress in the search algorithm.
pub enum BranchSearch {
    /// In order to continue, the API user must indicate the trie node with a storage value that
    /// immediately follows a given one.
    NextKey(NextKey),
    /// Search has finished successfully.
    Found {
        /// Result of the search. `None` if there is no branch/storage node after
        /// [`Config::key_before`] in the trie.
        branch_trie_node_key: Option<BranchTrieNodeKeyIter>,
    },
}

/// Implementation of `Iterator<Item = Nibble>`. See [`BranchSearch::Found::branch_trie_node_key`].
pub struct BranchTrieNodeKeyIter {
    inner: IntoIter<Nibble>,
}

impl Iterator for BranchTrieNodeKeyIter {
    type Item = Nibble;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for BranchTrieNodeKeyIter {}

/// In order to continue, the API user must indicate the trie node with a storage value that
/// immediately follows a given one.
pub struct NextKey {
    inner: NextKeyInner,
    /// Value passed as [`Config::key_before`].
    key_before: Vec<Nibble>,
    /// Value passed as [`Config::prefix`].
    prefix: Vec<Nibble>,
    /// Value passed as [`Config::or_equal`].
    or_equal: bool,
}

enum NextKeyInner {
    FirstFound {
        /// Value passed as [`Config::no_branch_search`].
        no_branch_search: bool,
    },
    FurtherRound {
        /// Must never be empty and must never contain only `f` nibbles.
        current_found_branch: Vec<Nibble>,
    },
}

impl NextKey {
    /// The API user must provide the trie node with a storage value whose key is the first one
    /// that is strictly superior or superior or equal to the key returned by this function.
    pub fn key_before(&'_ self) -> impl Iterator<Item = u8> + '_ {
        trie::nibbles_to_bytes_suffix_extend(match &self.inner {
            NextKeyInner::FirstFound { .. } => either::Left(self.key_before.iter().copied()),
            NextKeyInner::FurtherRound {
                current_found_branch,
            } => {
                let num_f_nibbles_to_pop = current_found_branch
                    .iter()
                    .rev()
                    .take_while(|n| **n == Nibble::max())
                    .count();
                debug_assert!(num_f_nibbles_to_pop < current_found_branch.len());

                let len = current_found_branch.len();
                let extra_nibble = current_found_branch[len - num_f_nibbles_to_pop - 1]
                    .checked_add(1)
                    .unwrap_or_else(|| unreachable!());

                either::Right(
                    current_found_branch
                        .iter()
                        .take(len - num_f_nibbles_to_pop - 1)
                        .copied()
                        .chain(iter::once(extra_nibble)),
                )
            }
        })
    }

    /// If `true`, if the key returned by [`NextKey::key_before`] corresponds to a trie node with
    /// a storage value, then the API user must indicate it. If `false`, it must indicate the key
    /// strictly superior.
    pub fn or_equal(&self) -> bool {
        match self.inner {
            NextKeyInner::FirstFound { .. } => {
                // If `key_before` is for example `0xa`, `key_before()` will return `0xa0` due to
                // the usage of `nibbles_to_bytes_suffix_extend`. For this reason, we have to
                // always return `true` if the number of nibbles in `key_before` is uneven.
                self.or_equal || (self.key_before.len() % 2 != 0)
            }
            NextKeyInner::FurtherRound { .. } => true,
        }
    }

    /// The API user must indicate a key that starts with the bytes returned by this function.
    /// If the first key doesn't start with these bytes, then the API user must indicate `None`.
    pub fn prefix(&'_ self) -> impl Iterator<Item = u8> + '_ {
        trie::nibbles_to_bytes_truncate(self.prefix.iter().copied())
    }

    /// Indicate the key. `None` must be passed if [`NextKey::key_before`] is the last key of
    /// the sub-trie that starts with [`NextKey::prefix`].
    pub fn inject(
        mut self,
        storage_trie_node_key: Option<impl Iterator<Item = u8>>,
    ) -> BranchSearch {
        match (self.inner, storage_trie_node_key) {
            // No matter what, if we're at the first round and the user injected `None`, that
            // means `key_before` is equal or superior to the last key of the trie and thus there
            // can't be any branch node after it.
            (NextKeyInner::FirstFound { .. }, None) => BranchSearch::Found {
                branch_trie_node_key: None,
            },

            // If `no_branch_search` is `true`, simply immediately return the value provided by
            // the user.
            (
                NextKeyInner::FirstFound {
                    no_branch_search: true,
                    ..
                },
                Some(storage_trie_node_key),
            ) => {
                let storage_trie_node_key =
                    trie::bytes_to_nibbles(storage_trie_node_key).collect::<Vec<_>>();
                debug_assert!(storage_trie_node_key >= self.key_before);

                // Due to our usage of `nibbles_to_bytes_truncate` in `prefix()`, we must check
                // whether the value provided by the user is still within the prefix.
                if !storage_trie_node_key.starts_with(&self.prefix) {
                    return BranchSearch::Found {
                        branch_trie_node_key: None,
                    };
                }

                BranchSearch::Found {
                    branch_trie_node_key: Some(BranchTrieNodeKeyIter {
                        inner: storage_trie_node_key.into_iter(),
                    }),
                }
            }

            (
                NextKeyInner::FirstFound {
                    no_branch_search: false,
                    ..
                },
                Some(storage_trie_node_key),
            ) => {
                let storage_trie_node_key =
                    trie::bytes_to_nibbles(storage_trie_node_key).collect::<Vec<_>>();
                debug_assert!(storage_trie_node_key >= self.key_before);

                // Due to our usage of `nibbles_to_bytes_truncate` in `prefix()`, we must check
                // whether the value provided by the user is still within the prefix.
                if !storage_trie_node_key.starts_with(&self.prefix) {
                    return BranchSearch::Found {
                        branch_trie_node_key: None,
                    };
                }

                if storage_trie_node_key.is_empty()
                    || storage_trie_node_key.iter().all(|n| *n == Nibble::max())
                {
                    return BranchSearch::Found {
                        branch_trie_node_key: Some(BranchTrieNodeKeyIter {
                            inner: storage_trie_node_key.into_iter(),
                        }),
                    };
                }

                self.inner = NextKeyInner::FurtherRound {
                    current_found_branch: storage_trie_node_key,
                };
                BranchSearch::NextKey(self)
            }

            (
                NextKeyInner::FurtherRound {
                    mut current_found_branch,
                },
                Some(storage_trie_node_key),
            ) => {
                let storage_trie_node_key = trie::bytes_to_nibbles(storage_trie_node_key);

                let num_common = storage_trie_node_key
                    .zip(current_found_branch.iter())
                    .take_while(|(a, b)| a == *b)
                    .count();

                // Check against infinite loops.
                debug_assert!(num_common < current_found_branch.len());

                if !current_found_branch[..num_common].starts_with(&self.prefix)
                    || &current_found_branch[..num_common] < &self.key_before
                    || (!self.or_equal && current_found_branch[..num_common] == self.key_before)
                {
                    return BranchSearch::Found {
                        branch_trie_node_key: Some(BranchTrieNodeKeyIter {
                            inner: current_found_branch.into_iter(),
                        }),
                    };
                }

                current_found_branch.truncate(num_common);

                if current_found_branch.is_empty()
                    || current_found_branch.iter().all(|n| *n == Nibble::max())
                {
                    return BranchSearch::Found {
                        branch_trie_node_key: Some(BranchTrieNodeKeyIter {
                            inner: current_found_branch.into_iter(),
                        }),
                    };
                }

                self.inner = NextKeyInner::FurtherRound {
                    current_found_branch,
                };
                BranchSearch::NextKey(self)
            }

            // If `current_found_branch` doesn't have any sibling or uncle after it, then we know
            // that there can't be any more branch node and the search is over.
            (
                NextKeyInner::FurtherRound {
                    current_found_branch,
                },
                None,
            ) => BranchSearch::Found {
                branch_trie_node_key: Some(BranchTrieNodeKeyIter {
                    inner: current_found_branch.into_iter(),
                }),
            },
        }
    }
}
