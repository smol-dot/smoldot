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

use super::{Bootnode, ChainSpec, CheckpointToChainInformationError};

#[test]
fn can_decode_polkadot_genesis() {
    let spec = &include_bytes!("./tests/example.json")[..];
    let specs = ChainSpec::from_json_bytes(spec).unwrap();
    assert_eq!(specs.id(), "polkadot");

    // code_substitutes field
    assert_eq!(specs.client_spec.code_substitutes.get(&1), None);
    assert!(specs.client_spec.code_substitutes.get(&5203203).is_some());

    // bootnodes field
    assert_eq!(
        specs.boot_nodes().collect::<Vec<_>>(),
        vec![
            Bootnode::Parsed {
                multiaddr: "/dns4/p2p.cc1-0.polkadot.network/tcp/30100".into(),
                peer_id: vec![
                    0, 36, 8, 1, 18, 32, 71, 154, 61, 188, 212, 39, 215, 192, 217, 22, 168, 87,
                    162, 148, 234, 176, 0, 195, 4, 31, 109, 123, 175, 185, 26, 169, 218, 92, 192,
                    0, 126, 111
                ]
            },
            Bootnode::Parsed {
                multiaddr: "/dns4/cc1-1.parity.tech/tcp/30333".into(),
                peer_id: vec![
                    0, 36, 8, 1, 18, 32, 82, 103, 22, 131, 223, 29, 166, 147, 119, 199, 217, 185,
                    69, 70, 87, 73, 165, 110, 224, 141, 138, 44, 217, 75, 191, 55, 156, 212, 204,
                    41, 11, 59
                ]
            },
            Bootnode::UnrecognizedFormat("/some/wrong/multiaddress")
        ]
    );
}

#[test]
fn relay_chain_para_id_either_both_present_or_absent() {
    ChainSpec::from_json_bytes(
        r#"{
            "name": "Test",
            "id": "test",
            "bootNodes": [],
            "genesis": {
              "raw": {
                "top": {},
                "childrenDefault": {}
              }
            }
          }
          "#,
    )
    .unwrap();

    ChainSpec::from_json_bytes(
        r#"{
            "name": "Test",
            "id": "test",
            "bootNodes": [],
            "relay_chain": "foo",
            "para_id": 1,
            "genesis": {
              "raw": {
                "top": {},
                "childrenDefault": {}
              }
            }
          }
          "#,
    )
    .unwrap();

    ChainSpec::from_json_bytes(
        r#"{
            "name": "Test",
            "id": "test",
            "bootNodes": [],
            "relayChain": "foo",
            "paraId": 1,
            "genesis": {
              "raw": {
                "top": {},
                "childrenDefault": {}
              }
            }
          }
          "#,
    )
    .unwrap();

    assert!(
        ChainSpec::from_json_bytes(
            r#"{
            "name": "Test",
            "id": "test",
            "bootNodes": [],
            "relayChain": "foo",
            "genesis": {
              "raw": {
                "top": {},
                "childrenDefault": {}
              }
            }
          }
          "#,
        )
        .is_err()
    );

    assert!(
        ChainSpec::from_json_bytes(
            r#"{
            "name": "Test",
            "id": "test",
            "bootNodes": [],
            "paraId": 1,
            "genesis": {
              "raw": {
                "top": {},
                "childrenDefault": {}
              }
            }
          }
          "#,
        )
        .is_err()
    );
}

#[test]
fn issue_598() {
    // Regression test for a panic.
    let chain_spec = ChainSpec::from_json_bytes(include_bytes!("./tests/issue-598.json")).unwrap();
    assert!(matches!(
        chain_spec
            .light_sync_state()
            .unwrap()
            .to_chain_information(),
        Err(CheckpointToChainInformationError::GenesisBlockCheckpoint)
    ));
}
