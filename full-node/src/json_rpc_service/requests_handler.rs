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

use smol::stream::StreamExt as _;
use smoldot::json_rpc::{methods, parse, service};
use std::{future::Future, pin::Pin, sync::Arc};

use crate::{database_thread, network_service, LogCallback, LogLevel};

pub struct Config {
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    pub receiver: async_channel::Receiver<Message>,

    /// Database to access blocks.
    pub database: Arc<database_thread::DatabaseThread>,

    /// Access to the peer-to-peer networking.
    pub network_service: Arc<network_service::NetworkService>,

    /// Name of the chain, as found in the chain specification.
    pub chain_name: String,

    /// JSON-encoded properties of the chain, as found in the chain specification.
    pub chain_properties_json: String,

    /// Hash of the genesis block.
    pub genesis_block_hash: [u8; 32],
}

pub enum Message {
    Request(service::RequestProcess),
    SubscriptionStart(service::SubscriptionStartProcess),
}

pub fn spawn_requests_handler(mut config: Config) {
    (config.tasks_executor)(Box::pin(async move {
        loop {
            match config.receiver.next().await {
                Some(Message::Request(request)) => match request.request() {
                    methods::MethodCall::rpc_methods {} => {
                        request.respond(methods::Response::rpc_methods(methods::RpcMethods {
                            methods: methods::MethodCall::method_names()
                                .map(|n| n.into())
                                .collect(),
                        }));
                    }

                    methods::MethodCall::chainSpec_v1_chainName {} => {
                        request.respond(methods::Response::chainSpec_v1_chainName(
                            (&config.chain_name).into(),
                        ));
                    }
                    methods::MethodCall::chainSpec_v1_genesisHash {} => {
                        request.respond(methods::Response::chainSpec_v1_genesisHash(
                            methods::HashHexString(config.genesis_block_hash),
                        ));
                    }
                    methods::MethodCall::chainSpec_v1_properties {} => {
                        request.respond(methods::Response::chainSpec_v1_properties(
                            serde_json::from_str(&config.chain_properties_json).unwrap(),
                        ));
                    }

                    methods::MethodCall::chain_getBlockHash { height: Some(0) } => {
                        // In the case where the database was populated through a warp sync, it
                        // might not store block 0 in it. However, the hash of block 0 is
                        // particularly important for JSON-RPC clients, and as such we make sure
                        // to always respond successfully to block 0 requests, even if it isn't
                        // in the database.
                        request.respond(methods::Response::chain_getBlockHash(
                            methods::HashHexString(config.genesis_block_hash),
                        ))
                    }
                    methods::MethodCall::chain_getBlockHash { height } => {
                        let outcome = config
                            .database
                            .with_database(move |database| match height {
                                Some(height) => database.best_block_hash_by_number(height),
                                None => database.best_block_hash().map(Some),
                            })
                            .await;
                        match outcome {
                            Ok(Some(hash)) => request.respond(
                                methods::Response::chain_getBlockHash(methods::HashHexString(hash)),
                            ),
                            Ok(None) => request.respond_null(),
                            Err(error) => {
                                config.log_callback.log(LogLevel::Warn, format!("json-rpc; request=chain_getBlockHash; height={:?}; database_error={}", height, error));
                                request.fail(parse::ErrorResponse::InternalError)
                            }
                        }
                    }
                    methods::MethodCall::system_chain {} => {
                        request
                            .respond(methods::Response::system_chain((&config.chain_name).into()));
                    }
                    methods::MethodCall::system_localPeerId {} => {
                        let peer_id = config.network_service.local_peer_id().to_base58();
                        request.respond(methods::Response::system_localPeerId(peer_id.into()));
                    }
                    methods::MethodCall::system_name {} => {
                        request.respond(methods::Response::system_version(
                            env!("CARGO_PKG_NAME").into(),
                        ));
                    }
                    methods::MethodCall::system_properties {} => {
                        request.respond(methods::Response::system_properties(
                            serde_json::from_str(&config.chain_properties_json).unwrap(),
                        ));
                    }
                    methods::MethodCall::system_version {} => {
                        request.respond(methods::Response::system_version(
                            env!("CARGO_PKG_VERSION").into(),
                        ));
                    }

                    _ => request.fail(service::ErrorResponse::ServerError(
                        -32000,
                        "Not implemented in smoldot yet",
                    )),
                },
                Some(Message::SubscriptionStart(request)) => request.fail(
                    service::ErrorResponse::ServerError(-32000, "Not implemented in smoldot yet"),
                ),
                None => return,
            }
        }
    }));
}
