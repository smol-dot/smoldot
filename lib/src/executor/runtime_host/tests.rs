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

use core::{iter, ops};

use super::{run, Config, RuntimeHostVm};
use crate::{executor::host, header, trie};
use alloc::collections::BTreeMap;

#[test]
fn all_tests() {
    #[derive(serde::Deserialize)]
    struct Test {
        block: Block,
        storage: Storage,
    }

    #[derive(serde::Deserialize)]
    struct Block {
        header: Header,
        extrinsics: Vec<HexString>,
    }

    #[derive(serde::Deserialize)]
    struct Header {
        #[serde(rename = "parentHash")]
        parent_hash: HexString,
        number: HexString,
        #[serde(rename = "stateRoot")]
        state_root: HexString,
        #[serde(rename = "extrinsicsRoot")]
        extrinsics_root: HexString,
        digest: Digest,
    }

    #[derive(serde::Deserialize)]
    struct Digest {
        logs: Vec<HexString>,
    }

    #[derive(serde::Deserialize)]
    struct Storage {
        root: Vec<TrieEntry>,
        child_tries: hashbrown::HashMap<HexString, Vec<TrieEntry>>,
    }

    #[derive(serde::Deserialize)]
    struct TrieEntry {
        key: HexString,
        value: HexString,
    }

    #[derive(PartialEq, Eq, Hash)]
    struct HexString(Vec<u8>);
    impl<'a> serde::Deserialize<'a> for HexString {
        fn deserialize<D>(deserializer: D) -> Result<HexString, D::Error>
        where
            D: serde::Deserializer<'a>,
        {
            let string = String::deserialize(deserializer)?;

            if string.is_empty() {
                return Ok(HexString(Vec::new()));
            }

            if !string.starts_with("0x") {
                return Err(serde::de::Error::custom(
                    "hexadecimal string doesn't start with 0x",
                ));
            }

            let bytes = hex::decode(&string[2..]).map_err(serde::de::Error::custom)?;
            Ok(HexString(bytes))
        }
    }

    for (test_num, test_json) in [
        include_str!("./test1.json"),
        include_str!("./test2.json"),
        include_str!("./test3.json"),
        include_str!("./test4.json"),
    ]
    .into_iter()
    .enumerate()
    {
        let test_data = serde_json::from_str::<Test>(test_json).unwrap();

        let storage = {
            let mut storage = test_data
                .storage
                .root
                .into_iter()
                .map(|e| ((None, e.key.0), e.value.0))
                .collect::<BTreeMap<_, _>>();
            for (child_trie, child_trie_data) in &test_data.storage.child_tries {
                assert!(child_trie.0.starts_with(b":child_storage:default:"));
                let child_trie = child_trie.0[b":child_storage:default:".len()..].to_vec();
                for entry in child_trie_data {
                    storage.insert(
                        (Some(child_trie.clone()), entry.key.0.clone()),
                        entry.value.0.clone(),
                    );
                }
            }
            storage
        };

        let virtual_machine = {
            let code = storage
                .get(&(None, b":code".to_vec()))
                .expect("no runtime code found");
            let heap_pages = crate::executor::storage_heap_pages_to_value(
                storage.get(&(None, b":heappages".to_vec())).map(|v| &v[..]),
            )
            .unwrap();

            host::HostVmPrototype::new(host::Config {
                module: code,
                heap_pages,
                exec_hint: crate::executor::vm::ExecHint::Oneshot,
                allow_unresolved_imports: false,
            })
            .unwrap()
        };

        let state_version = virtual_machine
            .runtime_version()
            .decode()
            .state_version
            .unwrap_or(host::TrieEntryVersion::V0);

        let digest_items = test_data
            .block
            .header
            .digest
            .logs
            .iter()
            .map(|item| {
                header::DigestItem::from(
                    header::DigestItemRef::from_scale_encoded(&item.0, 4).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let mut execution = run(Config {
            virtual_machine,
            function_to_call: "Core_execute_block",
            max_log_level: 3,
            offchain_storage_changes: Default::default(),
            storage_main_trie_changes: Default::default(),
            parameter: {
                // Block header + number of extrinsics + extrinsics
                let encoded_body_len =
                    crate::util::encode_scale_compact_usize(test_data.block.extrinsics.len());
                crate::header::HeaderRef {
                    parent_hash: TryFrom::try_from(&test_data.block.header.parent_hash.0[..])
                        .unwrap(),
                    number: {
                        let mut num = 0u64;
                        for byte in &test_data.block.header.number.0 {
                            num <<= 8;
                            num |= u64::from(*byte);
                        }
                        num
                    },
                    state_root: TryFrom::try_from(&test_data.block.header.state_root.0[..])
                        .unwrap(),
                    extrinsics_root: TryFrom::try_from(
                        &test_data.block.header.extrinsics_root.0[..],
                    )
                    .unwrap(),
                    digest: header::DigestRef::from_slice(&digest_items).unwrap(),
                }
                .scale_encoding(4)
                .map(|b| either::Right(either::Left(b)))
                .chain(iter::once(either::Right(either::Right(encoded_body_len))))
                .chain(
                    test_data
                        .block
                        .extrinsics
                        .iter()
                        .map(|b| either::Left(&b.0)),
                )
            },
        })
        .unwrap();

        loop {
            match execution {
                RuntimeHostVm::Finished(Ok(_)) => break, // Test successful!
                RuntimeHostVm::Finished(Err(err)) => {
                    panic!("Error during test #{}: {:?}", test_num, err)
                }
                RuntimeHostVm::SignatureVerification(sig) => execution = sig.verify_and_resume(),
                RuntimeHostVm::ClosestDescendantMerkleValue(req) => {
                    execution = req.resume_unknown()
                }
                RuntimeHostVm::StorageGet(get) => {
                    let value = storage
                        .get(&(
                            get.child_trie().map(|c| c.as_ref().to_owned()),
                            get.key().as_ref().to_owned(),
                        ))
                        .map(|v| (iter::once(&v[..]), state_version));
                    execution = get.inject_value(value);
                }
                RuntimeHostVm::NextKey(req) => {
                    let mut search = trie::branch_search::BranchSearch::NextKey(
                        trie::branch_search::start_branch_search(trie::branch_search::Config {
                            key_before: req.key().collect::<Vec<_>>().into_iter(),
                            or_equal: req.or_equal(),
                            prefix: req.prefix().collect::<Vec<_>>().into_iter(),
                            no_branch_search: !req.branch_nodes(),
                        }),
                    );

                    let next_key = loop {
                        match search {
                            trie::branch_search::BranchSearch::Found {
                                branch_trie_node_key,
                            } => break branch_trie_node_key,
                            trie::branch_search::BranchSearch::NextKey(bs_req) => {
                                let result = storage
                                    .range((
                                        if bs_req.or_equal() {
                                            ops::Bound::Included((
                                                req.child_trie().map(|c| c.as_ref().to_owned()),
                                                bs_req.key_before().collect::<Vec<_>>(),
                                            ))
                                        } else {
                                            ops::Bound::Excluded((
                                                req.child_trie().map(|c| c.as_ref().to_owned()),
                                                bs_req.key_before().collect::<Vec<_>>(),
                                            ))
                                        },
                                        ops::Bound::Unbounded,
                                    ))
                                    .next()
                                    .filter(|((trie, key), _)| {
                                        *trie == req.child_trie().map(|c| c.as_ref().to_owned())
                                            && key.starts_with(&bs_req.prefix().collect::<Vec<_>>())
                                    })
                                    .map(|(k, _)| k);

                                search = bs_req.inject(result.map(|(_, k)| k.iter().copied()));
                            }
                        }
                    };

                    execution = req.inject_key(next_key.map(|nk| nk.into_iter()));
                }
            }
        }
    }
}
