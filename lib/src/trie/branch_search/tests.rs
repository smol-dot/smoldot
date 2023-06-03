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

#![cfg(test)]

use super::{start_branch_search, BranchSearch, Config};
use crate::trie;

use rand::distributions::{Distribution as _, Uniform};

#[test]
fn fuzzing() {
    fn uniform_sample(min: u8, max: u8) -> u8 {
        Uniform::new_inclusive(min, max).sample(&mut rand::thread_rng())
    }

    // We run the test multiple times because of randomness.
    for _ in 0..2048 {
        // Generate a random trie structure.
        let mut trie = trie::trie_structure::TrieStructure::<()>::new();
        let mut list = vec![Vec::new()];
        for elem in list.clone().into_iter() {
            for _ in 0..uniform_sample(0, 4) {
                let mut elem = elem.clone();
                for _ in 0..uniform_sample(0, 3) {
                    elem.push(uniform_sample(0, 255));
                }
                list.push(elem);
            }
        }
        for elem in list {
            match trie.node(trie::bytes_to_nibbles(elem.iter().copied())) {
                trie::trie_structure::Entry::Vacant(e) => {
                    e.insert_storage_value().insert((), ());
                }
                trie::trie_structure::Entry::Occupied(
                    trie::trie_structure::NodeAccess::Branch(e),
                ) => {
                    e.insert_storage_value();
                }
                trie::trie_structure::Entry::Occupied(
                    trie::trie_structure::NodeAccess::Storage(_),
                ) => {}
            }
        }

        // Now perform random key search requests.
        for _ in 0..256 {
            // Generate random search parameters.
            let search_params = {
                let mut prefix = Vec::new();
                for _ in 0..uniform_sample(0, 2) {
                    prefix.push(trie::Nibble::try_from(uniform_sample(0, 15)).unwrap());
                }

                Config {
                    key_before: {
                        let mut key = prefix.clone();
                        for _ in 0..uniform_sample(0, 2) {
                            key.push(trie::Nibble::try_from(uniform_sample(0, 15)).unwrap());
                        }
                        key
                    },
                    no_branch_search: rand::random(),
                    or_equal: rand::random(),
                    prefix,
                }
            };

            // Find the expected value for these parameters.
            let expected = {
                trie.iter_ordered().find_map(|node_index| {
                    if !trie.is_storage(node_index) && search_params.no_branch_search {
                        return None;
                    }
                    let full_key = trie
                        .node_full_key_by_index(node_index)
                        .unwrap()
                        .collect::<Vec<_>>();
                    if full_key < search_params.key_before {
                        return None;
                    }
                    if full_key == search_params.key_before && !search_params.or_equal {
                        return None;
                    }
                    if !full_key.starts_with(&search_params.prefix) {
                        return None;
                    }
                    Some(full_key)
                })
            };

            // Now find the value using the branch searcher.
            let obtained = {
                let mut search = start_branch_search(Config {
                    key_before: search_params.key_before.iter().copied(),
                    or_equal: search_params.or_equal,
                    no_branch_search: search_params.no_branch_search,
                    prefix: search_params.prefix.iter().copied(),
                });

                loop {
                    match search {
                        BranchSearch::Found {
                            branch_trie_node_key,
                        } => break branch_trie_node_key.map(|k| k.collect::<Vec<_>>()),
                        BranchSearch::NextKey(req) => {
                            let key = trie.iter_ordered().find_map(|node_index| {
                                if !trie.is_storage(node_index) {
                                    return None;
                                }

                                let full_key = trie
                                    .node_full_key_by_index(node_index)
                                    .unwrap()
                                    .collect::<Vec<_>>();
                                if full_key
                                    < trie::bytes_to_nibbles(req.key_before()).collect::<Vec<_>>()
                                {
                                    return None;
                                }
                                if full_key
                                    == trie::bytes_to_nibbles(req.key_before()).collect::<Vec<_>>()
                                    && !req.or_equal()
                                {
                                    return None;
                                }
                                if !full_key.starts_with(
                                    &trie::bytes_to_nibbles(req.prefix()).collect::<Vec<_>>(),
                                ) {
                                    return None;
                                }

                                assert!(full_key.len() % 2 == 0);
                                Some(full_key)
                            });

                            search = req.inject(
                                key.map(|k| trie::nibbles_to_bytes_suffix_extend(k.into_iter())),
                            );
                        }
                    }
                }
            };

            // Compare them!
            if expected != obtained {
                panic!(
                    "\nexpected: {:?}\nobtained: {:?}\nsearch_params: {:?}\ntrie: {:?}",
                    expected, obtained, search_params, trie
                );
            }
        }
    }
}
