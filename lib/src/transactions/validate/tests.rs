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

use crate::{executor, header, trie::proof_decode};
use core::iter;

#[test]
fn validate_from_proof() {
    // Regression test for <https://github.com/smol-dot/smoldot/issues/873>.

    let test: Test = serde_json::from_str(include_str!("./test-fixture.json")).unwrap();

    let runtime = executor::host::HostVmPrototype::new(executor::host::Config {
        module: hex::decode(&test.runtime_code).unwrap(),
        heap_pages: executor::DEFAULT_HEAP_PAGES,
        allow_unresolved_imports: true,
        exec_hint: executor::vm::ExecHint::Oneshot,
    })
    .unwrap();

    let call_proof = proof_decode::decode_and_verify_proof(proof_decode::Config {
        proof: hex::decode(&test.call_proof).unwrap(),
    })
    .unwrap();

    let scale_encoded_header = hex::decode(test.block_header).unwrap();

    let main_trie_root = header::decode(&scale_encoded_header, 4).unwrap().state_root;

    let mut validation_in_progress = super::validate_transaction(super::Config {
        runtime,
        scale_encoded_header: &scale_encoded_header,
        block_number_bytes: 4,
        scale_encoded_transaction: iter::once(&hex::decode(test.transaction_bytes).unwrap()),
        source: super::TransactionSource::External,
        max_log_level: 0,
    });

    loop {
        match validation_in_progress {
            super::Query::Finished { result: Ok(_), .. } => return, // Success,
            super::Query::Finished { result: Err(_), .. } => panic!(),
            super::Query::StorageGet(get) => {
                let value = call_proof
                    .storage_value(main_trie_root, get.key().as_ref())
                    .unwrap();
                validation_in_progress =
                    get.inject_value(value.map(|(val, ver)| (iter::once(val), ver)));
            }
            super::Query::NextKey(nk) => {
                let next_key = call_proof
                    .next_key(
                        main_trie_root,
                        nk.key(),
                        nk.or_equal(),
                        nk.prefix(),
                        nk.branch_nodes(),
                    )
                    .unwrap();
                validation_in_progress = nk.inject_key(next_key);
            }
            super::Query::ClosestDescendantMerkleValue(mv) => {
                let value = call_proof
                    .closest_descendant_merkle_value(main_trie_root, mv.key())
                    .unwrap();
                validation_in_progress = mv.inject_merkle_value(value);
            }
        }
    }
}

// Serde structs used to decode the test fixtures.

#[derive(serde::Deserialize)]
struct Test {
    #[serde(rename = "transactionBytes")]
    transaction_bytes: String,
    #[serde(rename = "runtimeCode")]
    runtime_code: String,
    #[serde(rename = "callProof")]
    call_proof: String,
    #[serde(rename = "blockHeader")]
    block_header: String,
}
