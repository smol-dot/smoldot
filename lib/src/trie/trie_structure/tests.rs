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

#![cfg(test)]

use super::{Nibble, TrieStructure};

use alloc::collections::{BTreeMap, BTreeSet};
use core::ops;
use rand::{
    distributions::{Distribution as _, Uniform},
    seq::SliceRandom as _,
};
use std::collections::HashSet;

#[test]
fn remove_turns_storage_into_branch() {
    let with_removal = {
        let mut trie = TrieStructure::new();

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
                Nibble::try_from(10).unwrap(),
                Nibble::try_from(11).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
                Nibble::try_from(12).unwrap(),
                Nibble::try_from(13).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_occupied()
        .unwrap()
        .into_storage()
        .unwrap()
        .remove();

        trie
    };

    let expected = {
        let mut trie = TrieStructure::new();

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
                Nibble::try_from(10).unwrap(),
                Nibble::try_from(11).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
                Nibble::try_from(12).unwrap(),
                Nibble::try_from(13).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie
    };

    assert!(with_removal.structure_equal(&expected));
}

#[test]
fn insert_in_between() {
    let order1 = {
        let mut trie = TrieStructure::new();

        trie.node([Nibble::try_from(1).unwrap()].iter().cloned())
            .into_vacant()
            .unwrap()
            .insert_storage_value()
            .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
                Nibble::try_from(4).unwrap(),
                Nibble::try_from(5).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie
    };

    let order2 = {
        let mut trie = TrieStructure::new();

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
                Nibble::try_from(4).unwrap(),
                Nibble::try_from(5).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node([Nibble::try_from(1).unwrap()].iter().cloned())
            .into_vacant()
            .unwrap()
            .insert_storage_value()
            .insert((), ());

        trie
    };

    let order3 = {
        let mut trie = TrieStructure::new();

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
                Nibble::try_from(4).unwrap(),
                Nibble::try_from(5).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

        trie.node([Nibble::try_from(1).unwrap()].iter().cloned())
            .into_vacant()
            .unwrap()
            .insert_storage_value()
            .insert((), ());

        trie
    };

    assert!(order1.structure_equal(&order2));
    assert!(order2.structure_equal(&order3));
    assert!(order1.structure_equal(&order3));
}

#[test]
fn insert_branch() {
    let mut trie = TrieStructure::new();

    trie.node([Nibble::try_from(1).unwrap()].iter().cloned())
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
            Nibble::try_from(4).unwrap(),
            Nibble::try_from(5).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());

    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
            Nibble::try_from(5).unwrap(),
            Nibble::try_from(6).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());

    assert!(!trie
        .node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_occupied()
        .unwrap()
        .has_storage_value());
}

#[test]
fn remove_prefix_basic() {
    let mut trie = TrieStructure::new();

    trie.node([Nibble::try_from(1).unwrap()].iter().cloned())
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());
    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());
    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(4).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());
    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(4).unwrap(),
            Nibble::try_from(5).unwrap(),
            Nibble::try_from(6).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());

    trie.remove_prefix(
        [Nibble::try_from(1).unwrap(), Nibble::try_from(2).unwrap()]
            .iter()
            .cloned(),
    );

    assert_eq!(trie.len(), 1);
    assert!(trie
        .node([Nibble::try_from(1).unwrap(),].iter().cloned(),)
        .into_occupied()
        .unwrap()
        .has_storage_value());
}

#[test]
fn remove_prefix_clear_all() {
    let mut trie = TrieStructure::new();

    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());
    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(4).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());
    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(4).unwrap(),
            Nibble::try_from(5).unwrap(),
            Nibble::try_from(6).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());

    trie.remove_prefix(
        [Nibble::try_from(1).unwrap(), Nibble::try_from(2).unwrap()]
            .iter()
            .cloned(),
    );

    assert!(trie.is_empty());
}

#[test]
fn remove_prefix_exact() {
    let mut trie = TrieStructure::new();

    trie.node([Nibble::try_from(1).unwrap()].iter().cloned())
        .into_vacant()
        .unwrap()
        .insert_storage_value()
        .insert((), ());

    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());
    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
            Nibble::try_from(4).unwrap(),
            Nibble::try_from(5).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());
    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
            Nibble::try_from(4).unwrap(),
            Nibble::try_from(6).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());

    trie.remove_prefix(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
        ]
        .iter()
        .cloned(),
    );

    assert_eq!(trie.len(), 1);
    assert!(trie
        .node([Nibble::try_from(1).unwrap(),].iter().cloned(),)
        .into_occupied()
        .unwrap()
        .has_storage_value());
}

#[test]
fn remove_prefix_doesnt_match_anything() {
    let mut trie = TrieStructure::new();

    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());

    trie.remove_prefix(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(5).unwrap(),
        ]
        .iter()
        .cloned(),
    );

    assert_eq!(trie.len(), 1);
    assert!(trie
        .node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_occupied()
        .unwrap()
        .has_storage_value());
}

#[test]
fn remove_prefix_nothing_to_remove() {
    let mut trie = TrieStructure::new();

    trie.node(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
        ]
        .iter()
        .cloned(),
    )
    .into_vacant()
    .unwrap()
    .insert_storage_value()
    .insert((), ());

    trie.remove_prefix(
        [
            Nibble::try_from(1).unwrap(),
            Nibble::try_from(2).unwrap(),
            Nibble::try_from(3).unwrap(),
            Nibble::try_from(4).unwrap(),
        ]
        .iter()
        .cloned(),
    );

    assert_eq!(trie.len(), 1);
    assert!(trie
        .node(
            [
                Nibble::try_from(1).unwrap(),
                Nibble::try_from(2).unwrap(),
                Nibble::try_from(3).unwrap(),
            ]
            .iter()
            .cloned(),
        )
        .into_occupied()
        .unwrap()
        .has_storage_value());
}

#[test]
fn fuzzing() {
    fn uniform_sample(min: u8, max: u8) -> u8 {
        Uniform::new_inclusive(min, max).sample(&mut rand::thread_rng())
    }

    // We run the test multiple times because of randomness.
    for _ in 0..256 {
        // Generate a set of keys that will find themselves in the tries in the end.
        let final_storage: HashSet<Vec<Nibble>> = {
            let mut list = vec![Vec::new()];
            for _ in 0..5 {
                for elem in list.clone().into_iter() {
                    for _ in 0..uniform_sample(0, 4) {
                        let mut elem = elem.clone();
                        for _ in 0..uniform_sample(0, 3) {
                            elem.push(Nibble::try_from(uniform_sample(0, 15)).unwrap());
                        }
                        list.push(elem);
                    }
                }
            }
            list.into_iter().skip(1).collect()
        };

        // Create multiple tries, each with a different order of insertion for the nodes.
        let mut tries = Vec::new();
        for _ in 0..16 {
            #[derive(Debug, Copy, Clone)]
            enum Op {
                Insert,
                Remove,
                ClearPrefix,
            }

            let mut operations = final_storage
                .iter()
                .map(|k| (k.clone(), Op::Insert))
                .collect::<Vec<_>>();
            operations.shuffle(&mut rand::thread_rng());

            // Insert in `operations` a tuple of an insertion and removal.
            for _ in 0..uniform_sample(0, 24) {
                let mut base_key = match operations.choose(&mut rand::thread_rng()) {
                    Some(op) => op.0.clone(),
                    None => continue,
                };

                for _ in 0..uniform_sample(0, 2) {
                    base_key.push(Nibble::try_from(uniform_sample(0, 15)).unwrap());
                }

                let max_remove_index = operations
                    .iter()
                    .position(|(k, _)| *k == base_key)
                    .unwrap_or(operations.len());

                let remove_index =
                    Uniform::new_inclusive(0, max_remove_index).sample(&mut rand::thread_rng());
                let insert_index =
                    Uniform::new_inclusive(0, remove_index).sample(&mut rand::thread_rng());
                operations.insert(remove_index, (base_key.clone(), Op::Remove));
                operations.insert(insert_index, (base_key, Op::Insert));
            }

            // Insert in `operations` a tuple of multiple insertions of the same prefix, and
            // removal of said prefix.
            for _ in 0..uniform_sample(0, 4) {
                let mut base_key = match operations.choose(&mut rand::thread_rng()) {
                    Some(op) => op.0.clone(),
                    None => continue,
                };

                for _ in 0..uniform_sample(0, 2) {
                    base_key.push(Nibble::try_from(uniform_sample(0, 15)).unwrap());
                }

                let max_remove_index = operations
                    .iter()
                    .position(|(k, _)| k.starts_with(&base_key))
                    .unwrap_or(operations.len());

                let mut remove_index =
                    Uniform::new_inclusive(0, max_remove_index).sample(&mut rand::thread_rng());
                operations.insert(remove_index, (base_key.clone(), Op::ClearPrefix));

                for _ in 0..uniform_sample(0, 12) {
                    let mut base_key = base_key.clone();
                    for _ in 0..uniform_sample(0, 8) {
                        base_key.push(Nibble::try_from(uniform_sample(0, 15)).unwrap());
                    }

                    if operations
                        .iter()
                        .take(remove_index)
                        .any(|(k, _)| *k == base_key)
                    {
                        continue;
                    }

                    let insert_index =
                        Uniform::new_inclusive(0, remove_index).sample(&mut rand::thread_rng());
                    operations.insert(insert_index, (base_key, Op::Insert));
                    remove_index += 1;
                }
            }

            // Create a trie and applies `operations` on it.
            let mut trie = TrieStructure::new();
            for (op_index, (key, op)) in operations.clone().into_iter().enumerate() {
                match op {
                    Op::Insert => match trie.node(key.into_iter()) {
                        super::Entry::Vacant(e) => {
                            e.insert_storage_value().insert((), ());
                        }
                        super::Entry::Occupied(super::NodeAccess::Branch(e)) => {
                            e.insert_storage_value();
                        }
                        super::Entry::Occupied(super::NodeAccess::Storage(_)) => {
                            unreachable!("index: {}\nops:{:?}", op_index, operations)
                        }
                    },
                    Op::Remove => match trie.node(key.into_iter()) {
                        super::Entry::Occupied(super::NodeAccess::Storage(e)) => {
                            e.remove();
                        }
                        super::Entry::Vacant(_) => {
                            unreachable!("index: {}\nops:{:?}", op_index, operations)
                        }
                        super::Entry::Occupied(super::NodeAccess::Branch(_)) => {
                            unreachable!("index: {}\nops:{:?}", op_index, operations)
                        }
                    },
                    Op::ClearPrefix => {
                        trie.remove_prefix(key.into_iter());
                    }
                }
            }

            tries.push(trie);
        }

        // Compare them to make sure they're equal.
        for trie in 1..tries.len() {
            tries[0].structure_equal(&tries[trie]);
        }
    }
}

#[test]
fn iter_properly_traverses() {
    let mut trie = TrieStructure::new();

    // Fill the trie with entries with randomly generated keys.
    for _ in 0..Uniform::new_inclusive(0, 32).sample(&mut rand::thread_rng()) {
        let mut key = Vec::new();
        for _ in 0..Uniform::new_inclusive(0, 12).sample(&mut rand::thread_rng()) {
            key.push(
                Nibble::try_from(Uniform::new_inclusive(0, 15).sample(&mut rand::thread_rng()))
                    .unwrap(),
            );
        }

        match trie.node(key.into_iter()) {
            super::Entry::Vacant(e) => {
                e.insert_storage_value().insert((), ());
            }
            super::Entry::Occupied(super::NodeAccess::Branch(e)) => {
                e.insert_storage_value();
            }
            super::Entry::Occupied(super::NodeAccess::Storage(_)) => {}
        }
    }

    assert_eq!(trie.all_nodes_ordered().count(), trie.nodes.len());
}

#[test]
fn range() {
    // This test makes sure that the `range` function works as expected.
    // It first builds a random tree structure, then puts all the nodes of the structure into
    // a `BTreeMap` (from the standard library), then compares whether `TreeStructure::range`
    // returns the same results as `BTreeMap::range`.

    fn uniform_sample(min: u8, max: u8) -> u8 {
        Uniform::new_inclusive(min, max).sample(&mut rand::thread_rng())
    }

    // We run the test multiple times because of randomness.
    for _ in 0..4096 {
        // Generate a set of random keys that will find themselves in the trie in the end.
        let final_storage: BTreeSet<Vec<Nibble>> = {
            let mut list = vec![Vec::new()];
            for _ in 0..4 {
                for elem in list.clone().into_iter() {
                    for _ in 0..uniform_sample(0, 4) {
                        let mut elem = elem.clone();
                        for _ in 0..uniform_sample(0, 3) {
                            elem.push(Nibble::try_from(uniform_sample(0, 15)).unwrap());
                        }
                        list.push(elem);
                    }
                }
            }
            list.into_iter().skip(1).collect()
        };

        // Create a trie and puts `final_storage` in it.
        let mut trie = TrieStructure::new();
        for key in &final_storage {
            match trie.node(key.iter().copied()) {
                super::Entry::Vacant(e) => {
                    e.insert_storage_value().insert((), ());
                }
                super::Entry::Occupied(super::NodeAccess::Branch(e)) => {
                    e.insert_storage_value();
                }
                super::Entry::Occupied(super::NodeAccess::Storage(_)) => {
                    unreachable!()
                }
            }
        }

        // Create a `BTreeMap` containins all the nodes of the trie.
        let btree_map = trie
            .iter_unordered()
            .map(|node_index| {
                let full_key = trie
                    .node_full_key_by_index(node_index)
                    .unwrap()
                    .collect::<Vec<_>>();
                (full_key, node_index)
            })
            .collect::<BTreeMap<_, _>>();

        // Randomly query ranges of the btree map and the trie.
        for _ in 0..64 {
            let mut start_key = Vec::new();
            for _ in 0..uniform_sample(0, 5) {
                start_key.push(Nibble::try_from(uniform_sample(0, 15)).unwrap());
            }

            let mut end_key = Vec::new();
            for _ in 0..uniform_sample(0, 5) {
                end_key.push(Nibble::try_from(uniform_sample(0, 15)).unwrap());
            }

            let (start_range_btree, start_range_trie) = match uniform_sample(0, 2) {
                0 => (
                    ops::Bound::Included(start_key.clone()),
                    ops::Bound::Included(start_key.iter().copied()),
                ),
                1 => (
                    ops::Bound::Excluded(start_key.clone()),
                    ops::Bound::Excluded(start_key.iter().copied()),
                ),
                2 => (ops::Bound::Unbounded, ops::Bound::Unbounded),
                _ => unreachable!(),
            };

            let (end_range_btree, end_range_trie) = match uniform_sample(0, 2) {
                0 => (
                    ops::Bound::Included(end_key.clone()),
                    ops::Bound::Included(end_key.iter().copied()),
                ),
                1 => (
                    ops::Bound::Excluded(end_key.clone()),
                    ops::Bound::Excluded(end_key.iter().copied()),
                ),
                2 => (ops::Bound::Unbounded, ops::Bound::Unbounded),
                _ => unreachable!(),
            };

            match (&start_range_btree, &end_range_btree) {
                (
                    ops::Bound::Included(start) | ops::Bound::Excluded(start),
                    ops::Bound::Included(end) | ops::Bound::Excluded(end),
                ) if start > end => {
                    let trie_result = trie
                        .range(start_range_trie, end_range_trie)
                        .collect::<Vec<_>>();
                    assert!(
                        trie_result.is_empty(),
                        "\nbtree: {:?}\ntrie_result: {:?}\nstart: {:?}\nend: {:?}",
                        btree_map,
                        trie_result,
                        start_range_btree,
                        end_range_btree
                    );
                    continue;
                }
                (ops::Bound::Excluded(start), ops::Bound::Excluded(end)) if start == end => {
                    let trie_result = trie
                        .range(start_range_trie, end_range_trie)
                        .collect::<Vec<_>>();
                    assert!(
                        trie_result.is_empty(),
                        "\nbtree: {:?}\ntrie_result: {:?}\nstart: {:?}\nend: {:?}",
                        btree_map,
                        trie_result,
                        start_range_btree,
                        end_range_btree
                    );
                    continue;
                }
                _ => {}
            }

            let btree_result = btree_map
                .range((start_range_btree.clone(), end_range_btree.clone()))
                .map(|(_, idx)| *idx)
                .collect::<Vec<_>>();
            let trie_result = trie
                .range(start_range_trie, end_range_trie)
                .collect::<Vec<_>>();
            assert_eq!(
                btree_result, trie_result,
                "\nbtree: {:?}\nbtree_result: {:?}\ntrie_result: {:?}\nstart: {:?}\nend: {:?}",
                btree_map, btree_result, trie_result, start_range_btree, end_range_btree
            );
        }
    }
}
