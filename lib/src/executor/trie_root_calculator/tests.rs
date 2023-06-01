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

use super::{trie_root_calculator, Config, InProgress, TrieEntryVersion};
use crate::{executor::storage_diff::TrieDiff, trie};
use core::{iter, ops};

use rand::distributions::{Distribution as _, Uniform};

#[test]
fn empty_trie_works() {
    let mut calculation = trie_root_calculator(Config {
        diff: TrieDiff::empty(),
        diff_trie_entries_version: TrieEntryVersion::V0,
        max_trie_recalculation_depth_hint: 8,
    });

    loop {
        match calculation {
            InProgress::Finished { trie_root_hash } => {
                assert_eq!(trie_root_hash, trie::empty_trie_merkle_value());
                return;
            }
            InProgress::ClosestDescendant(req) => {
                calculation = req.inject(None::<iter::Empty<_>>);
            }
            InProgress::MerkleValue(_) => {
                unreachable!()
            }
            InProgress::StorageValue(req) => {
                calculation = req.inject_value(None);
            }
        }
    }
}

#[test]
fn one_inserted_node_in_diff() {
    let mut diff = TrieDiff::empty();
    diff.diff_insert(vec![0xaa, 0xaa], b"foo".to_vec(), ());

    let mut calculation = trie_root_calculator(Config {
        diff,
        diff_trie_entries_version: TrieEntryVersion::V0,
        max_trie_recalculation_depth_hint: 8,
    });

    loop {
        match calculation {
            InProgress::Finished { trie_root_hash } => {
                let expected = trie::trie_node::calculate_merkle_value(
                    trie::trie_node::Decoded {
                        children: [None::<&'static [u8]>; 16],
                        partial_key: trie::bytes_to_nibbles(vec![0xaa, 0xaa].into_iter()),
                        storage_value: trie::trie_node::StorageValue::Unhashed(b"foo"),
                    },
                    true,
                )
                .unwrap();

                assert_eq!(trie_root_hash, expected.as_ref());
                return;
            }
            InProgress::ClosestDescendant(req) => {
                calculation = req.inject(None::<iter::Empty<_>>);
            }
            InProgress::MerkleValue(_) => {
                unreachable!()
            }
            InProgress::StorageValue(req) => {
                calculation = req.inject_value(None);
            }
        }
    }
}

#[test]
fn fuzzing() {
    fn uniform_sample(min: u8, max: u8) -> u8 {
        Uniform::new_inclusive(min, max).sample(&mut rand::thread_rng())
    }

    // We run the test multiple times because of randomness.
    for _ in 0..256 {
        // Create a random trie.
        // Each node contains a `Some` with the storage value or `None` for branch nodes, plus its
        // Merkle value as `Some` if already calculated.
        let mut trie_before_diff = trie::trie_structure::TrieStructure::<(
            Option<Vec<u8>>,
            Option<trie::trie_node::MerkleValueOutput>,
        )>::new();

        let mut list = vec![Vec::new()];
        for elem in list.clone().into_iter() {
            for _ in 0..uniform_sample(0, 4) {
                let mut elem = elem.clone();
                for _ in 0..uniform_sample(1, 3) {
                    elem.push(uniform_sample(0, 255));
                }
                list.push(elem);
            }
        }
        for elem in list {
            let mut storage_value = Vec::new();
            for _ in 0..uniform_sample(0, 3) {
                storage_value.push(uniform_sample(0, 255));
            }

            match trie_before_diff.node(trie::bytes_to_nibbles(elem.iter().copied())) {
                trie::trie_structure::Entry::Vacant(e) => {
                    e.insert_storage_value()
                        .insert((Some(storage_value), None), (None, None));
                }
                trie::trie_structure::Entry::Occupied(
                    trie::trie_structure::NodeAccess::Branch(mut e),
                ) => {
                    *e.user_data() = (Some(storage_value), None);
                    e.insert_storage_value();
                }
                trie::trie_structure::Entry::Occupied(
                    trie::trie_structure::NodeAccess::Storage(_),
                ) => unreachable!(),
            }
        }

        // Clone the trie and apply modifications to it. These modifications are also registered
        // in a diff.
        let mut trie_after_diff = trie_before_diff.clone();
        let mut diff = TrieDiff::empty();

        for _ in 0..5 {
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
                let mut storage_value = Vec::new();
                for _ in 0..uniform_sample(0, 3) {
                    storage_value.push(uniform_sample(0, 255));
                }

                match trie_after_diff.node(trie::bytes_to_nibbles(elem.iter().copied())) {
                    trie::trie_structure::Entry::Occupied(
                        trie::trie_structure::NodeAccess::Storage(mut e),
                    ) => {
                        e.user_data().0 = None;
                        e.remove();
                        diff.diff_insert_erase(elem, ());
                    }
                    trie::trie_structure::Entry::Occupied(
                        trie::trie_structure::NodeAccess::Branch(mut e),
                    ) => {
                        *e.user_data() = (Some(storage_value.clone()), None);
                        e.insert_storage_value();
                        diff.diff_insert(elem, storage_value, ());
                    }
                    trie::trie_structure::Entry::Vacant(e) => {
                        e.insert_storage_value()
                            .insert((Some(storage_value.clone()), None), (None, None));
                        diff.diff_insert(elem, storage_value, ());
                    }
                }
            }
        }

        // Use the trie_root_calculator to calculate the root of `trie_after_diff`.
        let obtained_hash = {
            let mut calculator = trie_root_calculator(Config {
                diff: diff.clone(),
                diff_trie_entries_version: TrieEntryVersion::V0, // TODO: test multiple trie versions?
                max_trie_recalculation_depth_hint: 8,
            });

            loop {
                match calculator {
                    InProgress::Finished { trie_root_hash } => break trie_root_hash,
                    InProgress::ClosestDescendant(req) => {
                        let mut next_node = trie_before_diff
                            .range_iter(
                                ops::Bound::Included(req.key_as_vec().into_iter()),
                                ops::Bound::Unbounded::<iter::Empty<trie::Nibble>>,
                            )
                            .next();
                        // Set `next_node` to `None` if it isn't a descendant of the demanded key.
                        if next_node.map_or(false, |n| {
                            !trie_before_diff
                                .node_full_key_by_index(n)
                                .unwrap()
                                .collect::<Vec<_>>()
                                .starts_with(&req.key_as_vec())
                        }) {
                            next_node = None;
                        }
                        calculator = req.inject(
                            next_node.map(|n| trie_before_diff.node_full_key_by_index(n).unwrap()),
                        );
                    }
                    InProgress::MerkleValue(req) => calculator = req.resume_unknown(), // TODO: maybe test this as well?
                    InProgress::StorageValue(req) => {
                        let value = if let trie::trie_structure::Entry::Occupied(
                            trie::trie_structure::NodeAccess::Storage(e),
                        ) = trie_before_diff.node(req.key_as_vec().into_iter())
                        {
                            Some(e.into_user_data().0.as_ref().unwrap().clone())
                        } else {
                            None
                        };

                        calculator =
                            req.inject_value(value.as_deref().map(|v| (v, TrieEntryVersion::V0)));
                    }
                }
            }
        };

        // Calculate the root of `trie_after_diff` separately through the `TrieStructure`.
        let expected_hash = {
            for node_index in trie_after_diff
                .iter_ordered()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                let mut node_access = trie_after_diff.node_by_index(node_index).unwrap();

                let children = core::array::from_fn::<_, 16, _>(|n| {
                    node_access
                        .child(trie::Nibble::try_from(u8::try_from(n).unwrap()).unwrap())
                        .map(|mut child| child.user_data().1.as_ref().unwrap().clone())
                });

                let is_root_node = node_access.is_root_node();
                let partial_key = node_access.partial_key().collect::<Vec<_>>().into_iter();

                let storage_value = match node_access.user_data().0.as_ref() {
                    Some(v) => trie::trie_node::StorageValue::Unhashed(&v[..]),
                    None => trie::trie_node::StorageValue::None,
                };

                let merkle_value = trie::trie_node::calculate_merkle_value(
                    trie::trie_node::Decoded {
                        children,
                        partial_key,
                        storage_value,
                    },
                    is_root_node,
                )
                .unwrap();

                node_access.into_user_data().1 = Some(merkle_value);
            }

            trie_after_diff
                .root_user_data()
                .map(|n| *<&[u8; 32]>::try_from(n.1.as_ref().unwrap().as_ref()).unwrap())
                .unwrap_or(trie::empty_trie_merkle_value())
        };

        // Actual test is here.
        if obtained_hash != expected_hash {
            panic!(
                "\nexpected = {:?}\ncalculated = {:?}\ntrie_before = {:?}\ndiff = {:?}",
                expected_hash, obtained_hash, trie_before_diff, diff
            );
        }
    }
}
