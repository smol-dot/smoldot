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
        json_rpc: Some(smoldot_full_node::JsonRpcConfig {
            address: "127.0.0.1:0".parse().unwrap(),
            max_json_rpc_clients: 0,
        }),
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

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_chainName","params":[]}"#
                    .to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("Local Testnet"));
    });
}

#[test]
fn chain_spec_v1_genesis_hash() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_genesisHash","params":[]}"#
                    .to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw
            .contains("0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"));
    });
}

#[test]
fn chain_spec_v1_properties() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_properties","params":[]}"#
                    .to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("\"result\""));
    });
}

#[test]
fn chain_get_block_hash() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}"#.to_owned(),
            )
            .unwrap();
        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw
            .contains("0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"));

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[10000]}"#
                    .to_owned(),
            )
            .unwrap();
        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("null"));

        // TODO: test for a non-zero block?
    });
}

#[test]
fn system_chain() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"system_chain","params":[]}"#.to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("Local Testnet"));
    });
}

#[test]
fn system_local_peer_id() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"system_localPeerId","params":[]}"#.to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"));
    });
}

#[test]
fn system_name() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}"#.to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("smoldot-full-node"));
    });
}

#[test]
fn system_properties() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"system_properties","params":[]}"#.to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("\"result\""));
    });
}

#[test]
fn system_version() {
    smol::block_on(async move {
        let client = start_client().await;

        client
            .send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"system_version","params":[]}"#.to_owned(),
            )
            .unwrap();

        let response_raw = client.next_json_rpc_response().await;
        // TODO: actually parse the response properly
        assert!(response_raw.contains("\"result\""));
    });
}
