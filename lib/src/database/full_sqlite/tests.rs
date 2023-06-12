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

use super::{open, Config, ConfigTy, DatabaseOpen};
use crate::{chain::chain_information, header, trie};
use core::iter;

use rand::distributions::{Distribution as _, Uniform};

#[test]
fn empty_database_fill_then_query() {
    // Repeat the test many times due to randomness.
    for _ in 0..128 {
        let DatabaseOpen::Empty(empty_db) = open(Config {
            block_number_bytes: 4,
            cache_size: 2 * 1024 * 1024,
            ty: ConfigTy::Memory,
        })
        .unwrap() else { panic!() };

        fn uniform_sample(min: u8, max: u8) -> u8 {
            Uniform::new_inclusive(min, max).sample(&mut rand::thread_rng())
        }

        // Create a random trie.
        // Each node contains a `Some` with the storage value or `None` for branch nodes, plus its
        // Merkle value as `Some` if already calculated.
        let mut trie = trie::trie_structure::TrieStructure::<(
            Option<Vec<u8>>,
            Option<trie::trie_node::MerkleValueOutput>,
        )>::new();

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
            for _ in 0..uniform_sample(0, 24) {
                storage_value.push(uniform_sample(0, 255));
            }

            match trie.node(trie::bytes_to_nibbles(elem.iter().copied())) {
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
                ) => {}
            }
        }

        // Calculate the Merkle values of the nodes of the trie.
        for node_index in trie.iter_ordered().collect::<Vec<_>>().into_iter().rev() {
            let mut node_access = trie.node_by_index(node_index).unwrap();

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

        // Store the trie in the database.
        let open_db = {
            let trie_entries_linear = trie
                .iter_unordered()
                .filter_map(|n| {
                    let Some(value) = trie[n].0.as_ref() else { return None };
                    let key =
                        trie::nibbles_to_bytes_truncate(trie.node_full_key_by_index(n).unwrap())
                            .collect::<Vec<_>>();
                    Some((key, value))
                })
                .collect::<Vec<_>>();
            empty_db.initialize(
                chain_information::ChainInformationRef {
                    finalized_block_header: header::HeaderRef {
                        number: 0,
                        extrinsics_root: &[0; 32],
                        parent_hash: &[0; 32],
                        state_root: &{
                            trie.root_user_data()
                                .map(|n| {
                                    *<&[u8; 32]>::try_from(n.1.as_ref().unwrap().as_ref()).unwrap()
                                })
                                .unwrap_or(trie::empty_trie_merkle_value())
                        },
                        digest: header::DigestRef::empty(),
                    },
                    consensus: chain_information::ChainInformationConsensusRef::Unknown,
                    finality: chain_information::ChainInformationFinalityRef::Outsourced,
                },
                iter::empty(),
                None,
                trie_entries_linear.iter().map(|(k, v)| (&k[..], &v[..])),
                0,
            )
        }
        .unwrap();

        let block0_hash = open_db.finalized_block_hash().unwrap();

        // Ask random keys.
        for _ in 0..1024 {
            let key = (0..uniform_sample(0, 4))
                .map(|_| uniform_sample(0, 255))
                .collect::<Vec<_>>();
            let actual = open_db
                .block_storage_main_trie_get(&block0_hash, &key)
                .unwrap();
            let expected = trie
                .node_by_full_key(trie::bytes_to_nibbles(key.iter().copied()))
                .map(|n| (trie[n].0.as_ref().unwrap().clone(), 0u8));
            assert_eq!(
                actual,
                expected,
                "\nkey = {:?}\ntrie = {:?}",
                key.iter().map(|n| format!("{:x}", n)).collect::<String>(),
                trie
            );
        }

        // Ask random next keys.
        for _ in 0..1024 {
            let key = (0..uniform_sample(0, 8))
                .map(|_| trie::Nibble::try_from(uniform_sample(0u8, 15)).unwrap())
                .collect::<Vec<_>>();
            let branch_nodes = rand::random::<bool>();
            let actual = open_db
                .block_storage_main_trie_next_key(
                    &block0_hash,
                    key.iter().copied().map(u8::from),
                    branch_nodes,
                )
                .unwrap();
            let expected = trie
                .iter_ordered()
                .map(|n| trie.node_full_key_by_index(n).unwrap().collect::<Vec<_>>())
                .find(|n| *n >= key)
                .map(|k| k.iter().copied().map(u8::from).collect::<Vec<_>>());
            assert_eq!(
                actual,
                expected,
                "\nkey = {:?}\nbranch_nodes = {:?}\ntrie = {:?}",
                key.iter().map(|n| format!("{:x}", n)).collect::<String>(),
                branch_nodes,
                trie
            );
        }

        // Ask random closest descendant Merkle values.
        for _ in 0..1024 {
            let key = (0..uniform_sample(0, 8))
                .map(|_| trie::Nibble::try_from(uniform_sample(0u8, 15)).unwrap())
                .collect::<Vec<_>>();
            let actual = open_db
                .block_storage_main_trie_closest_descendant_merkle_value(
                    &block0_hash,
                    key.iter().copied().map(u8::from),
                )
                .unwrap();
            let expected = trie
                .iter_ordered()
                .find(|n| {
                    let full_key = trie.node_full_key_by_index(*n).unwrap().collect::<Vec<_>>();
                    full_key >= key && full_key.starts_with(&key)
                })
                .map(|n| trie[n].1.as_ref().unwrap().as_ref().to_vec());
            assert_eq!(
                actual,
                expected,
                "\nkey = {:?}\ntrie = {:?}",
                key.iter().map(|n| format!("{:x}", n)).collect::<String>(),
                trie
            );
        }
    }
}
