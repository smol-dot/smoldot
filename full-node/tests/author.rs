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

#[test]
#[ignore] // TODO: restore after https://github.com/smol-dot/smoldot/issues/1109
fn basic_block_generated() {
    smol::block_on(async move {
        let client = smoldot_full_node::start(smoldot_full_node::Config {
            chain: smoldot_full_node::ChainConfig {
                chain_spec: (&include_bytes!("./substrate-node-template.json")[..]).into(),
                additional_bootnodes: Vec::new(),
                keystore_memory: vec![smoldot::identity::seed_phrase::decode_sr25519_private_key(
                    "//Alice",
                )
                .unwrap()],
                sqlite_database_path: None,
                sqlite_cache_size: 256 * 1024 * 1024,
                keystore_path: None,
                json_rpc_listen: None,
            },
            relay_chain: None,
            libp2p_key: Box::new([0; 32]),
            listen_addresses: Vec::new(),
            tasks_executor: Arc::new(|task| smol::spawn(task).detach()),
            log_callback: Arc::new(move |_, _| {}),
            jaeger_agent: None,
        })
        .await
        .unwrap();

        loop {
            client.send_json_rpc_request(
                r#"{"jsonrpc":"2.0","id":1,"method":"chainHead_v1_follow","params":[false]}"#
                    .to_owned(),
            );

            let _ = json_rpc::parse::parse_response(&client.next_json_rpc_response().await)
                .unwrap()
                .into_success()
                .unwrap();

            loop {
                match json_rpc::methods::parse_notification(&client.next_json_rpc_response().await)
                    .unwrap()
                {
                    json_rpc::methods::ServerToClient::chainHead_v1_followEvent {
                        result: json_rpc::methods::FollowEvent::NewBlock { .. },
                        ..
                    } => return, // Test success
                    json_rpc::methods::ServerToClient::chainHead_v1_followEvent {
                        result: json_rpc::methods::FollowEvent::Stop { .. },
                        ..
                    } => break,
                    _ => {}
                }
            }
        }
    });
}
