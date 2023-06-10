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
use crate::{executor::host, trie};
use alloc::collections::BTreeMap;

#[test]
fn all_tests() {
    #[derive(serde::Deserialize)]
    struct Test {
        block: Block,
        storage: Vec<StorageEntry>,
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
    struct StorageEntry {
        key: HexString,
        value: HexString,
    }

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

    let test_data = serde_json::from_str::<Test>(include_str!("./test.json")).unwrap();
    let storage = test_data
        .storage
        .into_iter()
        .map(|e| (e.key.0, e.value.0))
        .collect::<BTreeMap<_, _>>();

    let virtual_machine = {
        let code = storage.get(&b":code"[..]).expect("no runtime code found");
        let heap_pages = crate::executor::storage_heap_pages_to_value(
            storage.get(&b":heappages"[..]).map(|v| &v[..]),
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
                parent_hash: TryFrom::try_from(&test_data.block.header.parent_hash.0[..]).unwrap(),
                number: {
                    let mut num = 0u64;
                    for byte in &test_data.block.header.number.0 {
                        num <<= 8;
                        num |= u64::from(*byte);
                    }
                    num
                },
                state_root: TryFrom::try_from(&test_data.block.header.state_root.0[..]).unwrap(),
                extrinsics_root: TryFrom::try_from(&test_data.block.header.extrinsics_root.0[..])
                    .unwrap(),
                digest: crate::header::DigestRef::empty(), // TODO: no, use test data
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
            RuntimeHostVm::Finished(Ok(_)) => return, // Test successful!
            RuntimeHostVm::Finished(Err(err)) => panic!("{:?}", err),
            RuntimeHostVm::SignatureVerification(sig) => execution = sig.verify_and_resume(),
            RuntimeHostVm::ClosestDescendantMerkleValue(req) => execution = req.resume_unknown(),
            RuntimeHostVm::StorageGet(get) => {
                let value = if get.child_trie().is_some() {
                    None
                } else {
                    storage
                        .get(get.key().as_ref())
                        .map(|v| (iter::once(&v[..]), state_version))
                };

                execution = get.inject_value(value);
            }
            RuntimeHostVm::NextKey(req) => {
                if req.child_trie().is_some() {
                    execution = req.inject_key(None::<iter::Empty<_>>);
                    continue;
                }

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
                        trie::branch_search::BranchSearch::NextKey(req) => {
                            let result = storage
                                .range((
                                    if req.or_equal() {
                                        ops::Bound::Included(req.key_before().collect::<Vec<_>>())
                                    } else {
                                        ops::Bound::Excluded(req.key_before().collect::<Vec<_>>())
                                    },
                                    ops::Bound::Unbounded,
                                ))
                                .next()
                                .filter(|(k, _)| k.starts_with(&req.prefix().collect::<Vec<_>>()))
                                .map(|(k, _)| k);

                            search = req.inject(result.map(|k| k.iter().copied()));
                        }
                    }
                };

                execution = req.inject_key(next_key.map(|nk| nk.into_iter()));
            }
        }
    }
}
