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

use super::{
    open, Config, ConfigTy, DatabaseOpen, InsertTrieNode, InsertTrieNodeStorageValue,
    StorageAccessError,
};
use crate::{chain::chain_information, header, trie};

use alloc::borrow::Cow;
use core::{array, iter};
use rand::distributions::{Distribution as _, Uniform};

#[test]
fn empty_database_fill_then_query() {
    // Repeat the test many times due to randomness.
    for _ in 0..1024 {
        let DatabaseOpen::Empty(empty_db) = open(Config {
            block_number_bytes: 4,
            cache_size: 2 * 1024 * 1024,
            ty: ConfigTy::Memory,
        })
        .unwrap() else {
            panic!()
        };

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
                trie::HashFunction::Blake2,
                is_root_node,
            )
            .unwrap();

            node_access.into_user_data().1 = Some(merkle_value);
        }

        // Store the trie in the database.
        let open_db = {
            let state_root = &trie
                .root_user_data()
                .map(|n| *<&[u8; 32]>::try_from(n.1.as_ref().unwrap().as_ref()).unwrap())
                .unwrap_or(trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE);

            let trie_entries_linear =
                trie.iter_unordered()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|node_index| {
                        let (storage_value, Some(merkle_value)) = &trie[node_index] else {
                            unreachable!()
                        };
                        let storage_value = if let Some(storage_value) = storage_value {
                            InsertTrieNodeStorageValue::Value {
                                value: Cow::Owned(storage_value.to_vec()),
                                references_merkle_value: false, // TODO: test this as well
                            }
                        } else {
                            InsertTrieNodeStorageValue::NoValue
                        };
                        let merkle_value = merkle_value.as_ref().to_owned();
                        let mut node_access = trie.node_by_index(node_index).unwrap();

                        InsertTrieNode {
                            storage_value,
                            merkle_value: Cow::Owned(merkle_value),
                            children_merkle_values: array::from_fn::<_, 16, _>(|n| {
                                let child_index =
                                    trie::Nibble::try_from(u8::try_from(n).unwrap()).unwrap();
                                if let Some(mut child) = node_access.child(child_index) {
                                    Some(Cow::Owned(
                                        child.user_data().1.as_ref().unwrap().as_ref().to_vec(),
                                    ))
                                } else {
                                    None
                                }
                            }),
                            partial_key_nibbles: Cow::Owned(
                                node_access.partial_key().map(u8::from).collect::<Vec<_>>(),
                            ),
                        }
                    });

            let db = empty_db
                .initialize(
                    chain_information::ChainInformationRef {
                        finalized_block_header: header::HeaderRef {
                            number: 0,
                            extrinsics_root: &[0; 32],
                            parent_hash: &[0; 32],
                            state_root,
                            digest: header::DigestRef::empty(),
                        },
                        consensus: chain_information::ChainInformationConsensusRef::Unknown,
                        finality: chain_information::ChainInformationFinalityRef::Outsourced,
                    },
                    iter::empty(),
                    None,
                )
                .unwrap();
            db.insert_trie_nodes(trie_entries_linear, 0).unwrap();
            db
        };

        let block0_hash = open_db.finalized_block_hash().unwrap();

        // Ask random keys.
        for _ in 0..1024 {
            let key = (0..uniform_sample(0, 4))
                .map(|_| uniform_sample(0, 255))
                .collect::<Vec<_>>();
            let actual = open_db
                .block_storage_get(
                    &block0_hash,
                    iter::empty::<iter::Empty<_>>(),
                    trie::bytes_to_nibbles(key.iter().copied()).map(u8::from),
                )
                .unwrap();
            let expected = trie
                .node_by_full_key(trie::bytes_to_nibbles(key.iter().copied()))
                .and_then(|n| Some((trie[n].0.as_ref()?.clone(), 0u8)));
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
            let prefix = (0..uniform_sample(0, 8))
                .map(|_| trie::Nibble::try_from(uniform_sample(0u8, 15)).unwrap())
                .collect::<Vec<_>>();
            let branch_nodes = rand::random::<bool>();
            let actual = open_db
                .block_storage_next_key(
                    &block0_hash,
                    iter::empty::<iter::Empty<_>>(),
                    key.iter().copied().map(u8::from),
                    prefix.iter().copied().map(u8::from),
                    branch_nodes,
                )
                .unwrap();
            let expected = trie
                .iter_ordered()
                .map(|n| trie.node_full_key_by_index(n).unwrap().collect::<Vec<_>>())
                .find(|n| *n >= key)
                .filter(|n| n.starts_with(&prefix))
                .map(|k| k.iter().copied().map(u8::from).collect::<Vec<_>>());
            assert_eq!(
                actual,
                expected,
                "\nkey = {:?}\nprefix = {:?}\nbranch_nodes = {:?}\ntrie = {:?}",
                key.iter().map(|n| format!("{:x}", n)).collect::<String>(),
                prefix
                    .iter()
                    .map(|n| format!("{:x}", n))
                    .collect::<String>(),
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
                .block_storage_closest_descendant_merkle_value(
                    &block0_hash,
                    iter::empty::<iter::Empty<_>>(),
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

#[test]
fn storage_get_partial() {
    let DatabaseOpen::Empty(empty_db) = open(Config {
        block_number_bytes: 4,
        cache_size: 2 * 1024 * 1024,
        ty: ConfigTy::Memory,
    })
    .unwrap() else {
        panic!()
    };

    let db = empty_db
        .initialize(
            chain_information::ChainInformationRef {
                finalized_block_header: header::HeaderRef {
                    number: 0,
                    extrinsics_root: &[0; 32],
                    parent_hash: &[0; 32],
                    state_root: &[1; 32],
                    digest: header::DigestRef::empty(),
                },
                consensus: chain_information::ChainInformationConsensusRef::Unknown,
                finality: chain_information::ChainInformationFinalityRef::Outsourced,
            },
            iter::empty(),
            None,
        )
        .unwrap();

    assert!(matches!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1].into_iter(),
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(matches!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 1, 1].into_iter(),
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(matches!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 2].into_iter(),
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(matches!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 2].into_iter(),
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    // The empty key is specifically tested due to SQLite having some weird behaviors mixing
    // null and empty bytes.
    assert!(matches!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [].into_iter(),
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    db.insert_trie_nodes(
        [InsertTrieNode {
            merkle_value: Cow::Borrowed(&[1; 32]),
            partial_key_nibbles: Cow::Borrowed(&[1, 1]),
            children_merkle_values: [
                None,
                Some(Cow::Borrowed(&[2; 32])),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            storage_value: InsertTrieNodeStorageValue::Value {
                value: Cow::Borrowed(b"hello"),
                references_merkle_value: false,
            },
        }]
        .into_iter(),
        0,
    )
    .unwrap();

    assert_eq!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1].into_iter(),
        )
        .unwrap()
        .unwrap()
        .0,
        b"hello"
    );

    assert!(matches!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 1, 1].into_iter(),
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(db
        .block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 2].into_iter(),
        )
        .unwrap()
        .is_none());

    assert!(matches!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 2].into_iter(),
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    db.insert_trie_nodes(
        [InsertTrieNode {
            merkle_value: Cow::Borrowed(&[2; 32]),
            partial_key_nibbles: Cow::Borrowed(&[1, 1]),
            children_merkle_values: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            storage_value: InsertTrieNodeStorageValue::Value {
                value: Cow::Borrowed(b"world"),
                references_merkle_value: false,
            },
        }]
        .into_iter(),
        0,
    )
    .unwrap();

    assert_eq!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1].into_iter(),
        )
        .unwrap()
        .unwrap()
        .0,
        b"hello"
    );

    assert_eq!(
        db.block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 1, 1].into_iter(),
        )
        .unwrap()
        .unwrap()
        .0,
        b"world"
    );

    assert!(db
        .block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 2].into_iter(),
        )
        .unwrap()
        .is_none());

    assert!(db
        .block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 2].into_iter(),
        )
        .unwrap()
        .is_none());

    // The empty key is specifically tested due to SQLite having some weird behaviors mixing
    // null and empty bytes.
    assert!(db
        .block_storage_get(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [].into_iter(),
        )
        .unwrap()
        .is_none());
}

#[test]
fn storage_next_key_partial() {
    let DatabaseOpen::Empty(empty_db) = open(Config {
        block_number_bytes: 4,
        cache_size: 2 * 1024 * 1024,
        ty: ConfigTy::Memory,
    })
    .unwrap() else {
        panic!()
    };

    let db = empty_db
        .initialize(
            chain_information::ChainInformationRef {
                finalized_block_header: header::HeaderRef {
                    number: 0,
                    extrinsics_root: &[0; 32],
                    parent_hash: &[0; 32],
                    state_root: &[1; 32],
                    digest: header::DigestRef::empty(),
                },
                consensus: chain_information::ChainInformationConsensusRef::Unknown,
                finality: chain_information::ChainInformationFinalityRef::Outsourced,
            },
            iter::empty(),
            None,
        )
        .unwrap();

    // The empty key is specifically tested due to SQLite having some weird behaviors mixing
    // null and empty bytes.
    assert!(matches!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [].into_iter(),
            iter::empty(),
            true
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(matches!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1].into_iter(),
            iter::empty(),
            true
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    db.insert_trie_nodes(
        [InsertTrieNode {
            merkle_value: Cow::Borrowed(&[1; 32]),
            partial_key_nibbles: Cow::Borrowed(&[1, 1]),
            children_merkle_values: [
                None,
                Some(Cow::Borrowed(&[2; 32])),
                Some(Cow::Borrowed(&[3; 32])),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            storage_value: InsertTrieNodeStorageValue::NoValue,
        }]
        .into_iter(),
        0,
    )
    .unwrap();

    assert_eq!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 0].into_iter(),
            iter::empty(),
            true
        )
        .unwrap()
        .unwrap(),
        vec![1, 1]
    );

    assert_eq!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1].into_iter(),
            iter::empty(),
            true
        )
        .unwrap()
        .unwrap(),
        vec![1, 1]
    );

    assert!(matches!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1].into_iter(),
            iter::empty(),
            false
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(matches!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 0].into_iter(),
            iter::empty(),
            true
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(matches!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 2].into_iter(),
            iter::empty(),
            true
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    assert!(matches!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 3].into_iter(),
            iter::empty(),
            true
        ),
        Ok(None)
    ));

    db.insert_trie_nodes(
        [InsertTrieNode {
            merkle_value: Cow::Borrowed(&[3; 32]),
            partial_key_nibbles: Cow::Borrowed(&[2]),
            children_merkle_values: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            storage_value: InsertTrieNodeStorageValue::Value {
                value: Cow::Borrowed(b"hello"),
                references_merkle_value: false,
            },
        }]
        .into_iter(),
        0,
    )
    .unwrap();

    assert_eq!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 2].into_iter(),
            iter::empty(),
            true
        )
        .unwrap()
        .unwrap(),
        vec![1, 1, 2, 2]
    );

    assert!(matches!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 1, 1, 1, 1, 1].into_iter(),
            iter::empty(),
            true
        ),
        Err(StorageAccessError::IncompleteStorage)
    ));

    db.insert_trie_nodes(
        [InsertTrieNode {
            merkle_value: Cow::Borrowed(&[2; 32]),
            partial_key_nibbles: Cow::Borrowed(&[1, 1]),
            children_merkle_values: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            storage_value: InsertTrieNodeStorageValue::Value {
                value: Cow::Borrowed(b"hello"),
                references_merkle_value: false,
            },
        }]
        .into_iter(),
        0,
    )
    .unwrap();

    assert_eq!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [].into_iter(),
            iter::empty(),
            false
        )
        .unwrap()
        .unwrap(),
        vec![1, 1, 1, 1, 1]
    );

    assert_eq!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 1, 1, 1, 1, 1, 1].into_iter(),
            iter::empty(),
            true
        )
        .unwrap()
        .unwrap(),
        vec![1, 1, 2, 2]
    );

    assert_eq!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [1, 1, 3].into_iter(),
            iter::empty(),
            true
        )
        .unwrap(),
        None
    );

    assert_eq!(
        db.block_storage_next_key(
            &db.block_hash_by_number(0).unwrap().next().unwrap(),
            iter::empty::<iter::Empty<_>>(),
            [3].into_iter(),
            iter::empty(),
            true
        )
        .unwrap(),
        None
    );
}
