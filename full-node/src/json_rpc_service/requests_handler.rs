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
use smoldot::{
    executor,
    json_rpc::{methods, parse, service},
};
use std::{future::Future, pin::Pin, sync::Arc};

use crate::{
    consensus_service, database_thread,
    json_rpc_service::{legacy_api_subscriptions, runtime_caches_service},
    network_service, LogCallback, LogLevel,
};

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
    // TODO: load from database maybe?
    pub genesis_block_hash: [u8; 32],

    /// Consensus service of the chain.
    pub consensus_service: Arc<consensus_service::ConsensusService>,

    /// Runtime caches service of the JSON-RPC service.
    pub runtime_caches_service: Arc<runtime_caches_service::RuntimeCachesService>,
}

pub enum Message {
    Request(service::RequestProcess),
    SubscriptionStart(service::SubscriptionStartProcess),
}

pub fn spawn_requests_handler(mut config: Config) {
    let tasks_executor = config.tasks_executor.clone();
    tasks_executor(Box::pin(async move {
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
                    methods::MethodCall::state_getRuntimeVersion { at } => {
                        let at = match at {
                            Some(h) => h.0,
                            None => match config
                                .database
                                .with_database(|db| db.best_block_hash())
                                .await
                            {
                                Ok(b) => b,
                                Err(_) => {
                                    request.fail(service::ErrorResponse::InternalError);
                                    continue;
                                }
                            },
                        };

                        match config.runtime_caches_service.get(at).await {
                            Ok(runtime) => {
                                request.respond(methods::Response::state_getRuntimeVersion(
                                    convert_runtime_version(runtime.runtime_version()),
                                ));
                            }
                            Err(runtime_caches_service::GetError::UnknownBlock)
                            | Err(runtime_caches_service::GetError::Pruned) => {
                                request.respond_null()
                            } // TODO: unclear if correct error
                            Err(runtime_caches_service::GetError::InvalidRuntime(_))
                            | Err(runtime_caches_service::GetError::NoCode)
                            | Err(runtime_caches_service::GetError::InvalidHeapPages)
                            | Err(runtime_caches_service::GetError::CorruptedDatabase) => {
                                request.fail(service::ErrorResponse::InternalError)
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
                Some(Message::SubscriptionStart(request)) => match request.request() {
                    methods::MethodCall::chain_subscribeAllHeads {} => {
                        let block_number_bytes = config.consensus_service.block_number_bytes();
                        let mut blocks_to_report = legacy_api_subscriptions::SubscribeAllHeads::new(
                            config.consensus_service.clone(),
                        );

                        (config.tasks_executor)(Box::pin(async move {
                            let mut subscription = request.accept();
                            let subscription_id = subscription.subscription_id().to_owned();

                            loop {
                                let scale_encoded_header =
                                    blocks_to_report.next_scale_encoded_header().await;

                                let json_rpc_header =
                                    match methods::Header::from_scale_encoded_header(
                                        &scale_encoded_header,
                                        block_number_bytes,
                                    ) {
                                        Ok(h) => h,
                                        Err(_) => {
                                            // TODO: consider reporting to logs
                                            continue;
                                        }
                                    };

                                subscription
                                    .send_notification(methods::ServerToClient::chain_allHead {
                                        subscription: (&subscription_id).into(),
                                        result: json_rpc_header.clone(),
                                    })
                                    .await
                            }
                        }));
                    }

                    _ => request.fail(service::ErrorResponse::ServerError(
                        -32000,
                        "Not implemented in smoldot yet",
                    )),
                },
                None => return,
            }
        }
    }));
}

fn convert_runtime_version(runtime_spec: &executor::CoreVersion) -> methods::RuntimeVersion {
    let runtime_spec = runtime_spec.decode();
    methods::RuntimeVersion {
        spec_name: runtime_spec.spec_name.into(),
        impl_name: runtime_spec.impl_name.into(),
        authoring_version: u64::from(runtime_spec.authoring_version),
        spec_version: u64::from(runtime_spec.spec_version),
        impl_version: u64::from(runtime_spec.impl_version),
        transaction_version: runtime_spec.transaction_version.map(u64::from),
        state_version: runtime_spec.state_version.map(u8::from).map(u64::from),
        apis: runtime_spec
            .apis
            .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
            .collect(),
    }
}
