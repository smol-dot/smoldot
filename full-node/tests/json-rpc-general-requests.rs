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

use smoldot::json_rpc;
use std::sync::Arc;

async fn start_client() -> smoldot_full_node::Client {
    smoldot_full_node::start(smoldot_full_node::Config {
        chain: smoldot_full_node::ChainConfig {
            chain_spec: (&include_bytes!("./substrate-node-template.json")[..]).into(),
            additional_bootnodes: Vec::new(),
            keystore_memory: vec![],
            sqlite_database_path: None,
            sqlite_cache_size: 256 * 1024 * 1024,
            keystore_path: None,
        },
        relay_chain: None,
        libp2p_key: Box::new([0; 32]),
        listen_addresses: Vec::new(),
        json_rpc_listen: None,
        tasks_executor: Arc::new(|task| smol::spawn(task).detach()),
        log_callback: Arc::new(move |_, _| {}),
        jaeger_agent: None,
    })
    .await
    .unwrap()
}

#[test]
fn chain_spec_v1_chain_name() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_chainName","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "Local Testnet"
        );
    });
}

#[test]
fn chain_spec_v1_genesis_hash() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_genesisHash","params":[]}"#
                .to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"
        );
    });
}

#[test]
fn chain_spec_v1_properties() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_properties","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(result_json, r#"{"tokenDecimals": 15}"#);
    });
}

#[test]
fn chain_get_block_hash() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"
        );

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[10000]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(result_json, "null");

        // TODO: test for a non-zero block?
    });
}

#[test]
fn state_get_metadata() {
    smol::block_on(async move {
        let client = start_client().await;

        // Query the metadata of the genesis.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getMetadata","params":["0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            include_str!("./substrate-node-template-metadata.hex").trim()
        );

        // TOOD: there are no tests for the corner cases of state_getMetadata because it's unclear how the function is supposed to behave at all
    });
}

#[test]
fn state_get_runtime_version() {
    smol::block_on(async move {
        let client = start_client().await;

        // Query the runtime of the genesis.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getRuntimeVersion","params":["0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded =
            serde_json::from_str::<json_rpc::methods::RuntimeVersion>(result_json).unwrap();
        assert_eq!(decoded.impl_name, "node-template");
        assert_eq!(decoded.spec_version, 100);
        assert_eq!(decoded.apis.len(), 10);

        // TOOD: there are no tests for the corner cases of state_getRuntimeVersion because it's unclear how the function is supposed to behave at all
    });
}

#[test]
fn system_chain() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_chain","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "Local Testnet"
        );
    });
}

#[test]
fn system_chain_type() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_chainType","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "Local"
        );
    });
}

#[test]
fn system_local_peer_id() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_localPeerId","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        );
    });
}

#[test]
fn system_name() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "smoldot-full-node"
        );
    });
}

#[test]
fn system_properties() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_properties","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(result_json, r#"{"tokenDecimals": 15}"#);
    });
}

#[test]
fn system_version() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_version","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        // Note: we don't check the actual result, as the version changes pretty often.
        json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
    });
}

// TODO: add tests for `chain_subscribeAllHeads`
// TODO: add tests for `chain_subscribeNewHeads`
