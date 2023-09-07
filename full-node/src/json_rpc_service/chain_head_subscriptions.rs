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

use futures_channel::oneshot;
use smol::stream::StreamExt as _;
use smoldot::{
    executor,
    json_rpc::{methods, service},
};
use std::{future::Future, num::NonZeroUsize, pin::Pin, sync::Arc};

use crate::{consensus_service, database_thread, LogCallback};

pub struct Config {
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Receiver for actions that the JSON-RPC client wants to perform.
    pub receiver: async_channel::Receiver<Message>,

    /// `chainHead_unstable_follow` subscription start handle.
    pub chain_head_follow_subscription: service::SubscriptionStartProcess,

    /// Parameter that was passed by the user when requesting `chainHead_unstable_follow`.
    pub with_runtime: bool,

    /// Consensus service of the chain.
    pub consensus_service: Arc<consensus_service::ConsensusService>,

    /// Database to access blocks.
    pub database: Arc<database_thread::DatabaseThread>,
}

pub enum Message {
    Unpin {
        block_hashes: Vec<[u8; 32]>,
        outcome: oneshot::Sender<Result<(), ()>>,
    },
}

/// Spawns a new tasks dedicated to handling a `chainHead_unstable_follow` subscription.
///
/// Returns the identifier of the subscription.
pub async fn spawn_chain_head_subscription_task(mut config: Config) -> String {
    let mut json_rpc_subscription = config.chain_head_follow_subscription.accept();
    let json_rpc_subscription_id = json_rpc_subscription.subscription_id().to_owned();
    let return_value = json_rpc_subscription_id.clone();

    let tasks_executor = config.tasks_executor.clone();
    tasks_executor(Box::pin(async move {
        let mut consensus_service_subscription = config
            .consensus_service
            .subscribe_all(32, NonZeroUsize::new(32).unwrap())
            .await;

        json_rpc_subscription
            .send_notification(methods::ServerToClient::chainHead_unstable_followEvent {
                subscription: (&json_rpc_subscription_id).into(),
                result: methods::FollowEvent::Initialized {
                    finalized_block_hash: methods::HashHexString(
                        consensus_service_subscription.finalized_block_hash,
                    ),
                    finalized_block_runtime: if config.with_runtime {
                        Some(convert_runtime_spec(
                            consensus_service_subscription
                                .finalized_block_runtime
                                .runtime_version(),
                        ))
                    } else {
                        None
                    },
                },
            })
            .await;

        for block in consensus_service_subscription.non_finalized_blocks_ancestry_order {}

        loop {
            match consensus_service_subscription.new_blocks.next().await {
                Some(consensus_service::Notification::Block(block)) => {
                    json_rpc_subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&json_rpc_subscription_id).into(),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(block.block_hash),
                                    new_runtime: if let (Some(new_runtime), true) =
                                        (&block.runtime_update, config.with_runtime)
                                    {
                                        Some(convert_runtime_spec(new_runtime.runtime_version()))
                                    } else {
                                        None
                                    },
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                },
                            },
                        )
                        .await;

                    if block.is_new_best {
                        json_rpc_subscription
                            .send_notification(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&json_rpc_subscription_id).into(),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(block.block_hash),
                                    },
                                },
                            )
                            .await;
                    }
                }
                Some(consensus_service::Notification::Finalized {
                    hash,
                    best_block_hash,
                }) => {
                    json_rpc_subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&json_rpc_subscription_id).into(),
                                result: methods::FollowEvent::Finalized {
                                    finalized_blocks_hashes: todo!(),
                                    pruned_blocks_hashes: todo!(),
                                },
                            },
                        )
                        .await;
                }
                None => {
                    json_rpc_subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&json_rpc_subscription_id).into(),
                                result: methods::FollowEvent::Stop {},
                            },
                        )
                        .await;
                }
            }
        }
    }));

    return_value
}

fn convert_runtime_spec(runtime: &executor::CoreVersion) -> methods::MaybeRuntimeSpec {
    let runtime = runtime.decode();
    methods::MaybeRuntimeSpec::Valid {
        spec: methods::RuntimeSpec {
            impl_name: runtime.impl_name.into(),
            spec_name: runtime.spec_name.into(),
            impl_version: runtime.impl_version,
            spec_version: runtime.spec_version,
            transaction_version: runtime.transaction_version,
            apis: runtime
                .apis
                .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
                .collect(),
        },
    }
}
