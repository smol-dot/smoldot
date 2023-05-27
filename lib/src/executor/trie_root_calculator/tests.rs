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

use rand::{
    distributions::{Distribution as _, Uniform},
    seq::SliceRandom as _,
};

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
                calculation = req.inject(None);
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

// TODO: finish
/*#[test]
fn fuzzing() {
    fn uniform_sample(min: u8, max: u8) -> u8 {
        Uniform::new_inclusive(min, max).sample(&mut rand::thread_rng())
    }

    // We run the test multiple times because of randomness.
    for _ in 0..256 {
        // Create a random trie.
        let mut trie_before_diff = trie::trie_structure::TrieStructure::new();
        for _ in 0..5 {
            let mut list = vec![Vec::new()];
            for elem in list.clone().into_iter() {
                for _ in 0..uniform_sample(0, 4) {
                    let mut elem = elem.clone();
                    for _ in 0..uniform_sample(0, 3) {
                        elem.push(trie::Nibble::try_from(uniform_sample(0, 15)).unwrap());
                    }
                    list.push(elem);
                }
            }
            for elem in list {
                trie_before_diff
                    .node(elem.into_iter())
                    .into_vacant()
                    .unwrap()
                    .insert_storage_value()
                    .insert(None, None);
            }
        }

        // Clone the trie and apply modifications to it. These modifications are also registered
        // in a diff.
        let mut trie_after_diff = trie_before_diff.clone();
        let mut diff = TrieDiff::empty();

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
            let mut trie = trie::trie_structure::TrieStructure::new();
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
}*/
