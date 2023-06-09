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

//! All JSON-RPC method handlers that related to the `chainHead` API.

use super::{Background, SubscriptionMessage};

use crate::{platform::PlatformRef, runtime_service, sync_service};

use alloc::{
    borrow::ToOwned as _,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{
    cmp, iter,
    num::{NonZeroU32, NonZeroUsize},
    ops, pin,
    time::Duration,
};
use futures_channel::mpsc;
use futures_util::{future, FutureExt as _, StreamExt as _};
use hashbrown::HashMap;
use smoldot::{
    chain::fork_tree,
    executor::{self, runtime_host},
    header,
    json_rpc::{self, methods, requests_subscriptions},
    network::protocol,
};

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::chainHead_unstable_call`].
    pub(super) async fn chain_head_call(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        follow_subscription: &str,
        hash: methods::HashHexString,
        function_to_call: String,
        call_parameters: methods::HexString,
        network_config: Option<methods::NetworkConfig>,
    ) {
        let network_config = network_config.unwrap_or(methods::NetworkConfig {
            max_parallel: 1,
            timeout_ms: 8000,
            total_attempts: 3,
        });

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                follow_subscription,
                SubscriptionMessage::ChainHeadCall {
                    get_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                    hash,
                    call_parameters,
                    function_to_call,
                    network_config,
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_follow`].
    pub(super) async fn chain_head_follow(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        with_runtime: bool,
    ) {
        let (subscription_id, messages_rx, subscription_start) = match self
            .requests_subscriptions
            .start_subscription(request_id.1, 16)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let subscription = if with_runtime {
            let subscribe_all = self
                .runtime_service
                .subscribe_all("chainHead_follow", 32, NonZeroUsize::new(32).unwrap())
                .await;
            let id = subscribe_all.new_blocks.id();
            either::Left((subscribe_all, id))
        } else {
            either::Right(self.sync_service.subscribe_all(32, false).await)
        };

        let (
            subscription_id,
            initial_notifications,
            non_finalized_blocks,
            pinned_blocks_headers,
            subscription,
        ) = {
            let mut initial_notifications = Vec::with_capacity(match &subscription {
                either::Left((sa, _)) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
                either::Right(sa) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
            });

            let mut pinned_blocks_headers =
                HashMap::with_capacity_and_hasher(0, Default::default());
            let mut non_finalized_blocks = fork_tree::ForkTree::new();

            match &subscription {
                either::Left((subscribe_all, _)) => {
                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header[..],
                    );

                    pinned_blocks_headers.insert(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header.clone(),
                    );

                    initial_notifications.push({
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hash: methods::HashHexString(finalized_block_hash),
                                finalized_block_runtime: Some(convert_runtime_spec(
                                    &subscribe_all.finalized_block_runtime,
                                )),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    });

                    for block in &subscribe_all.non_finalized_blocks_ancestry_order {
                        let hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                        let _was_in =
                            pinned_blocks_headers.insert(hash, block.scale_encoded_header.clone());
                        debug_assert!(_was_in.is_none());

                        let parent_node_index = if block.parent_hash == finalized_block_hash {
                            None
                        } else {
                            // TODO: O(n)
                            Some(
                                non_finalized_blocks
                                    .find(|b| *b == block.parent_hash)
                                    .unwrap(),
                            )
                        };
                        non_finalized_blocks.insert(parent_node_index, hash);

                        initial_notifications.push(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    new_runtime: block
                                        .new_runtime
                                        .as_ref()
                                        .map(convert_runtime_spec),
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        );

                        if block.is_new_best {
                            initial_notifications.push(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            );
                        }
                    }
                }
                either::Right(subscribe_all) => {
                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header[..],
                    );

                    pinned_blocks_headers.insert(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header.clone(),
                    );

                    initial_notifications.push(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hash: methods::HashHexString(finalized_block_hash),
                                finalized_block_runtime: None,
                            },
                        }
                        .to_json_call_object_parameters(None),
                    );

                    for block in &subscribe_all.non_finalized_blocks_ancestry_order {
                        let hash =
                            header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                        let _was_in =
                            pinned_blocks_headers.insert(hash, block.scale_encoded_header.clone());
                        debug_assert!(_was_in.is_none());

                        let parent_node_index = if block.parent_hash == finalized_block_hash {
                            None
                        } else {
                            // TODO: O(n)
                            Some(
                                non_finalized_blocks
                                    .find(|b| *b == block.parent_hash)
                                    .unwrap(),
                            )
                        };
                        non_finalized_blocks.insert(parent_node_index, hash);

                        initial_notifications.push(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    new_runtime: None,
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        );

                        if block.is_new_best {
                            initial_notifications.push(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            );
                        }
                    }
                }
            }

            (
                subscription_id,
                initial_notifications,
                non_finalized_blocks,
                pinned_blocks_headers,
                subscription,
            )
        };

        subscription_start.start({
            let log_target = self.log_target.clone();
            let requests_subscriptions = self.requests_subscriptions.clone();
            let runtime_service = self.runtime_service.clone();
            let sync_service = self.sync_service.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());
            ChainHeadFollowTask {
                non_finalized_blocks,
                pinned_blocks_headers,
                subscription: match subscription {
                    either::Left((sub, id)) => Subscription::WithRuntime {
                        notifications: sub.new_blocks,
                        subscription_id: id,
                    },
                    either::Right(sub) => Subscription::WithoutRuntime(sub.new_blocks),
                },
                log_target,
                runtime_service,
                sync_service,
            }
            .run(
                requests_subscriptions,
                subscription_id,
                messages_rx,
                initial_notifications,
                request_id,
            )
        });
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storage`].
    pub(super) async fn chain_head_storage(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        follow_subscription: &str,
        hash: methods::HashHexString,
        key: methods::HexString,
        child_trie: Option<methods::HexString>,
        ty: methods::ChainHeadStorageType,
        network_config: Option<methods::NetworkConfig>,
    ) {
        let network_config = network_config.unwrap_or(methods::NetworkConfig {
            max_parallel: 1,
            timeout_ms: 8000,
            total_attempts: 3,
        });

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                follow_subscription,
                SubscriptionMessage::ChainHeadStorage {
                    get_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                    hash,
                    key,
                    child_trie,
                    ty,
                    network_config,
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storageContinue`].
    pub(super) async fn chain_head_storage_continue(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription_id: &str,
    ) {
        // Resuming the subscription is done by sending a message to it.
        let message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                subscription_id,
                SubscriptionMessage::ChainHeadStorageContinue {
                    continue_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                },
            )
            .await;

        // If the subscription is dead, then manually send back a response.
        // This could happen for example because there was a stop message earlier in its queue
        // or because it was the wrong type of subscription.
        if message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::chainHead_unstable_storageContinue(())
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_body`].
    pub(super) async fn chain_head_unstable_body(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        follow_subscription: &str,
        hash: methods::HashHexString,
        network_config: Option<methods::NetworkConfig>,
    ) {
        let network_config = network_config.unwrap_or(methods::NetworkConfig {
            max_parallel: 1,
            timeout_ms: 4000,
            total_attempts: 3,
        });

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                follow_subscription,
                SubscriptionMessage::ChainHeadBody {
                    get_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                    hash,
                    network_config,
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_header`].
    pub(super) async fn chain_head_unstable_header(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        follow_subscription: &str,
        hash: methods::HashHexString,
    ) {
        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                follow_subscription,
                SubscriptionMessage::ChainHeadHeader {
                    get_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                    hash,
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopBody`].
    pub(super) async fn chain_head_unstable_stop_body(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription_id: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                subscription_id,
                SubscriptionMessage::StopIfChainHeadBody {
                    stop_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if stop_message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::chainHead_unstable_stopBody(())
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopCall`].
    pub(super) async fn chain_head_unstable_stop_call(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription_id: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                subscription_id,
                SubscriptionMessage::StopIfChainHeadCall {
                    stop_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if stop_message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::chainHead_unstable_stopCall(())
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopStorage`].
    pub(super) async fn chain_head_unstable_stop_storage(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription_id: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                subscription_id,
                SubscriptionMessage::StopIfChainHeadStorage {
                    stop_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if stop_message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::chainHead_unstable_stopStorage(())
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_unfollow`].
    pub(super) async fn chain_head_unstable_unfollow(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        follow_subscription: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                follow_subscription,
                SubscriptionMessage::StopIfChainHeadFollow {
                    stop_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if stop_message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::chainHead_unstable_unfollow(())
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_unpin`].
    pub(super) async fn chain_head_unstable_unpin(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        follow_subscription: &str,
        hash: methods::HashHexString,
    ) {
        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                follow_subscription,
                SubscriptionMessage::ChainHeadFollowUnpin {
                    unpin_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                    hash,
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block to unpin isn't valid.
        if message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_finalizedDatabase`].
    pub(super) async fn chain_head_unstable_finalized_database(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        max_size_bytes: Option<u64>,
    ) {
        let response = crate::database::encode_database(
            &self.network_service.0,
            &self.sync_service,
            &self.genesis_block_hash,
            usize::try_from(max_size_bytes.unwrap_or(u64::max_value()))
                .unwrap_or(usize::max_value()),
        )
        .await;

        self.requests_subscriptions
            .respond(
                request_id.1,
                methods::Response::chainHead_unstable_finalizedDatabase(response.into())
                    .to_json_response(request_id.0),
            )
            .await;
    }
}

fn convert_runtime_spec(
    runtime: &Result<executor::CoreVersion, runtime_service::RuntimeError>,
) -> methods::MaybeRuntimeSpec {
    match &runtime {
        Ok(runtime) => {
            let runtime = runtime.decode();
            methods::MaybeRuntimeSpec::Valid {
                spec: methods::RuntimeSpec {
                    impl_name: runtime.impl_name.into(),
                    spec_name: runtime.spec_name.into(),
                    impl_version: runtime.impl_version,
                    spec_version: runtime.spec_version,
                    authoring_version: runtime.authoring_version,
                    transaction_version: runtime.transaction_version,
                    apis: runtime
                        .apis
                        .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
                        .collect(),
                },
            }
        }
        Err(error) => methods::MaybeRuntimeSpec::Invalid {
            error: error.to_string(),
        },
    }
}

struct ChainHeadFollowTask<TPlat: PlatformRef> {
    /// Tree of hashes of all the current non-finalized blocks. This includes unpinned blocks.
    non_finalized_blocks: fork_tree::ForkTree<[u8; 32]>,

    /// For each pinned block hash, the SCALE-encoded header of the block.
    pinned_blocks_headers: hashbrown::HashMap<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>,

    subscription: Subscription<TPlat>,

    log_target: String,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
}

enum Subscription<TPlat: PlatformRef> {
    WithRuntime {
        notifications: runtime_service::Subscription<TPlat>,
        subscription_id: runtime_service::SubscriptionId,
    },
    // TODO: better typing?
    WithoutRuntime(mpsc::Receiver<sync_service::Notification>),
}

impl<TPlat: PlatformRef> ChainHeadFollowTask<TPlat> {
    async fn run(
        mut self,
        requests_subscriptions: Arc<
            requests_subscriptions::RequestsSubscriptions<SubscriptionMessage>,
        >,
        subscription_id: String,
        mut messages_rx: requests_subscriptions::MessagesReceiver<SubscriptionMessage>,
        initial_notifications: Vec<String>,
        request_id: (String, requests_subscriptions::RequestId),
    ) {
        requests_subscriptions
            .respond(
                &request_id.1,
                methods::Response::chainHead_unstable_follow((&subscription_id).into())
                    .to_json_response(&request_id.0),
            )
            .await;

        // Send back to the user the initial notifications.
        for notif in initial_notifications {
            requests_subscriptions
                .push_notification(&request_id.1, &subscription_id, notif)
                .await;
        }

        let requests_subscriptions = {
            let weak = Arc::downgrade(&requests_subscriptions);
            drop(requests_subscriptions);
            weak
        };

        loop {
            let outcome = {
                let next_block = pin::pin!(match &mut self.subscription {
                    Subscription::WithRuntime { notifications, .. } => {
                        future::Either::Left(notifications.next().map(either::Left))
                    }
                    Subscription::WithoutRuntime(notifications) => {
                        future::Either::Right(notifications.next().map(either::Right))
                    }
                });
                let next_message = pin::pin!(messages_rx.next());

                match future::select(next_block, next_message).await {
                    future::Either::Left((v, _)) => either::Left(v),
                    future::Either::Right((v, _)) => either::Right(v),
                }
            };

            let requests_subscriptions = match requests_subscriptions.upgrade() {
                Some(rs) => rs,
                None => return,
            };

            // TODO: doesn't enforce any maximum number of pinned blocks
            match outcome {
                either::Left(either::Left(None) | either::Right(None)) => {
                    // TODO: clear queue of notifications?
                    break;
                }
                either::Left(
                    either::Left(Some(runtime_service::Notification::Finalized {
                        best_block_hash,
                        hash,
                        ..
                    }))
                    | either::Right(Some(sync_service::Notification::Finalized {
                        best_block_hash,
                        hash,
                    })),
                ) => {
                    let mut finalized_blocks_hashes = Vec::new();
                    let mut pruned_blocks_hashes = Vec::new();

                    let node_index = self.non_finalized_blocks.find(|b| *b == hash).unwrap();
                    for pruned in self.non_finalized_blocks.prune_ancestors(node_index) {
                        if pruned.is_prune_target_ancestor {
                            finalized_blocks_hashes.push(methods::HashHexString(pruned.user_data));
                        } else {
                            pruned_blocks_hashes.push(methods::HashHexString(pruned.user_data));
                        }
                    }

                    // TODO: don't always generate
                    if requests_subscriptions
                        .try_push_notification(
                            &request_id.1,
                            &subscription_id,
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::BestBlockChanged {
                                    best_block_hash: methods::HashHexString(best_block_hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }

                    if requests_subscriptions
                        .try_push_notification(
                            &request_id.1,
                            &subscription_id,
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::Finalized {
                                    finalized_blocks_hashes,
                                    pruned_blocks_hashes,
                                },
                            }
                            .to_json_call_object_parameters(None),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                either::Left(
                    either::Left(Some(runtime_service::Notification::BestBlockChanged { hash }))
                    | either::Right(Some(sync_service::Notification::BestBlockChanged { hash })),
                ) => {
                    let _ = requests_subscriptions
                        .try_push_notification(
                            &request_id.1,
                            &subscription_id,
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::BestBlockChanged {
                                    best_block_hash: methods::HashHexString(hash),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        )
                        .await;
                }
                either::Left(either::Left(Some(runtime_service::Notification::Block(block)))) => {
                    let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                    let _was_in = self
                        .pinned_blocks_headers
                        .insert(hash, block.scale_encoded_header);
                    debug_assert!(_was_in.is_none());

                    // TODO: check if it matches current finalized block
                    // TODO: O(n)
                    let parent_node_index =
                        self.non_finalized_blocks.find(|b| *b == block.parent_hash);
                    self.non_finalized_blocks.insert(parent_node_index, hash);

                    if requests_subscriptions
                        .try_push_notification(
                            &request_id.1,
                            &subscription_id,
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                    new_runtime: block
                                        .new_runtime
                                        .as_ref()
                                        .map(convert_runtime_spec),
                                },
                            }
                            .to_json_call_object_parameters(None),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }

                    if block.is_new_best
                        && requests_subscriptions
                            .try_push_notification(
                                &request_id.1,
                                &subscription_id,
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
                either::Left(either::Right(Some(sync_service::Notification::Block(block)))) => {
                    let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                    let _was_in = self
                        .pinned_blocks_headers
                        .insert(hash, block.scale_encoded_header);
                    debug_assert!(_was_in.is_none());

                    // TODO: check if it matches current finalized block
                    // TODO: O(n)
                    let parent_node_index =
                        self.non_finalized_blocks.find(|b| *b == block.parent_hash);
                    self.non_finalized_blocks.insert(parent_node_index, hash);

                    if requests_subscriptions
                        .try_push_notification(
                            &request_id.1,
                            &subscription_id,
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                    new_runtime: None, // TODO:
                                },
                            }
                            .to_json_call_object_parameters(None),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }

                    if block.is_new_best
                        && requests_subscriptions
                            .try_push_notification(
                                &request_id.1,
                                &subscription_id,
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
                either::Right((message, confirmation_sender)) => {
                    match self
                        .on_foreground_message(
                            &requests_subscriptions,
                            message,
                            confirmation_sender,
                        )
                        .await
                    {
                        // Intentionally `return` rather than `break` in order to not generate
                        // a `stop` event.
                        ops::ControlFlow::Break(()) => return,
                        ops::ControlFlow::Continue(()) => {}
                    }
                }
            }
        }

        if let Some(requests_subscriptions) = requests_subscriptions.upgrade() {
            requests_subscriptions
                .push_notification(
                    &request_id.1,
                    &subscription_id,
                    methods::ServerToClient::chainHead_unstable_followEvent {
                        subscription: (&subscription_id).into(),
                        result: methods::FollowEvent::Stop {},
                    }
                    .to_json_call_object_parameters(None),
                )
                .await;
        }
    }

    async fn on_foreground_message(
        &mut self,
        requests_subscriptions: &Arc<
            requests_subscriptions::RequestsSubscriptions<SubscriptionMessage>,
        >,
        message: SubscriptionMessage,
        confirmation_sender: requests_subscriptions::ConfirmationSend,
    ) -> ops::ControlFlow<(), ()> {
        match message {
            SubscriptionMessage::StopIfChainHeadFollow { stop_request_id } => {
                requests_subscriptions
                    .respond(
                        &stop_request_id.1,
                        methods::Response::chainHead_unstable_unfollow(())
                            .to_json_response(&stop_request_id.0),
                    )
                    .await;

                confirmation_sender.send();
                ops::ControlFlow::Break(())
            }
            SubscriptionMessage::ChainHeadBody {
                hash,
                get_request_id,
                network_config,
            } => {
                // Determine whether the requested block hash is valid, and if yes its number.
                let block_number = {
                    if let Some(header) = self.pinned_blocks_headers.get(&hash.0) {
                        let decoded =
                            header::decode(header, self.sync_service.block_number_bytes()).unwrap(); // TODO: unwrap?
                        Some(decoded.number)
                    } else {
                        // Ignore the message without sending a confirmation.
                        return ops::ControlFlow::Continue(());
                    }
                };

                self.start_chain_head_body(
                    requests_subscriptions,
                    (&get_request_id.0, &get_request_id.1),
                    hash,
                    network_config,
                    block_number,
                )
                .await;
                confirmation_sender.send();
                ops::ControlFlow::Continue(())
            }
            SubscriptionMessage::ChainHeadStorage {
                hash,
                get_request_id,
                network_config,
                key,
                child_trie,
                ty,
            } => {
                // Obtain the header of the requested block.
                // Contains `None` if the subscription is disjoint.
                let block_scale_encoded_header = {
                    if let Some(header) = self.pinned_blocks_headers.get(&hash.0) {
                        Some(header.clone())
                    } else {
                        // Ignore the message without sending a confirmation.
                        return ops::ControlFlow::Continue(());
                    }
                };

                self.start_chain_head_storage(
                    requests_subscriptions,
                    (&get_request_id.0, &get_request_id.1),
                    hash,
                    key,
                    child_trie,
                    ty,
                    network_config,
                    block_scale_encoded_header,
                )
                .await;
                confirmation_sender.send();
                ops::ControlFlow::Continue(())
            }
            SubscriptionMessage::ChainHeadCall {
                hash,
                get_request_id,
                network_config,
                function_to_call,
                call_parameters,
            } => {
                // Determine whether the requested block hash is valid and start the call.
                let pre_runtime_call = match self.subscription {
                    Subscription::WithRuntime {
                        subscription_id, ..
                    } => {
                        if !self.pinned_blocks_headers.contains_key(&hash.0) {
                            requests_subscriptions
                                .respond(
                                    &get_request_id.1,
                                    json_rpc::parse::build_error_response(
                                        &get_request_id.0,
                                        json_rpc::parse::ErrorResponse::InvalidParams,
                                        None,
                                    ),
                                )
                                .await;
                            // Ignore the message without sending a confirmation.
                            return ops::ControlFlow::Continue(());
                        }

                        self.runtime_service
                            .pinned_block_runtime_access(subscription_id, &hash.0)
                            .await
                            .ok()
                    }
                    Subscription::WithoutRuntime(_) => {
                        requests_subscriptions
                            .respond(
                                &get_request_id.1,
                                json_rpc::parse::build_error_response(
                                    &get_request_id.0,
                                    json_rpc::parse::ErrorResponse::InvalidParams,
                                    None,
                                ),
                            )
                            .await;
                        // Ignore the message without sending a confirmation.
                        return ops::ControlFlow::Continue(());
                    }
                };

                self.start_chain_head_call(
                    requests_subscriptions,
                    (&get_request_id.0, &get_request_id.1),
                    &function_to_call,
                    call_parameters,
                    pre_runtime_call,
                    network_config,
                )
                .await;
                confirmation_sender.send();
                ops::ControlFlow::Continue(())
            }
            SubscriptionMessage::ChainHeadHeader {
                hash,

                get_request_id,
            } => {
                let response = { self.pinned_blocks_headers.get(&hash.0).cloned() };

                requests_subscriptions
                    .respond(
                        &get_request_id.1,
                        methods::Response::chainHead_unstable_header(
                            response.map(methods::HexString),
                        )
                        .to_json_response(&get_request_id.0),
                    )
                    .await;
                confirmation_sender.send();
                ops::ControlFlow::Continue(())
            }
            SubscriptionMessage::ChainHeadFollowUnpin {
                hash,
                unpin_request_id,
            } => {
                let valid = {
                    if self.pinned_blocks_headers.remove(&hash.0).is_some() {
                        if let Subscription::WithRuntime {
                            subscription_id, ..
                        } = self.subscription
                        {
                            self.runtime_service
                                .unpin_block(subscription_id, &hash.0)
                                .await;
                        }
                        true
                    } else {
                        false
                    }
                };

                if valid {
                    requests_subscriptions
                        .respond(
                            &unpin_request_id.1,
                            methods::Response::chainHead_unstable_unpin(())
                                .to_json_response(&unpin_request_id.0),
                        )
                        .await;
                    confirmation_sender.send();
                }

                ops::ControlFlow::Continue(())
            }
            _ => {
                // Any other message.
                // Silently discard the confirmation sender.
                ops::ControlFlow::Continue(())
            }
        }
    }

    async fn start_chain_head_body(
        &mut self,
        requests_subscriptions: &Arc<
            requests_subscriptions::RequestsSubscriptions<SubscriptionMessage>,
        >,
        request_id: (&str, &requests_subscriptions::RequestId),
        hash: methods::HashHexString,
        network_config: methods::NetworkConfig,
        block_number: Option<u64>,
    ) {
        let (subscription_id, mut messages_rx, subscription_start) = match requests_subscriptions
            .start_subscription(request_id.1, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        subscription_start.start({
            let requests_subscriptions = requests_subscriptions.clone();
            let sync_service = self.sync_service.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());

            async move {
                requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::chainHead_unstable_body((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                if let Some(block_number) = block_number {
                    // TODO: right now we query the header because the underlying function returns an error if we don't
                    let mut future = pin::pin!(sync_service.clone().block_query(
                        block_number,
                        hash.0,
                        protocol::BlocksRequestFields {
                            header: true,
                            body: true,
                            justifications: false,
                        },
                        cmp::min(10, network_config.total_attempts),
                        Duration::from_millis(u64::from(cmp::min(
                            20000,
                            network_config.timeout_ms,
                        ))),
                        NonZeroU32::new(network_config.max_parallel.clamp(1, 5)).unwrap(),
                    ));

                    let requests_subscriptions = {
                        let weak = Arc::downgrade(&requests_subscriptions);
                        drop(requests_subscriptions);
                        weak
                    };

                    loop {
                        let outcome = {
                            let next_message = pin::pin!(messages_rx.next());
                            match future::select(&mut future, next_message).await {
                                future::Either::Left((v, _)) => either::Left(v),
                                future::Either::Right((v, _)) => either::Right(v),
                            }
                        };

                        let requests_subscriptions = match requests_subscriptions.upgrade() {
                            Some(rs) => rs,
                            None => return,
                        };

                        match outcome {
                            either::Left(Ok(block_data)) => {
                                requests_subscriptions
                                    .set_queued_notification(
                                        &request_id.1,
                                        &subscription_id,
                                        0,
                                        methods::ServerToClient::chainHead_unstable_bodyEvent {
                                            subscription: (&subscription_id).into(),
                                            result: methods::ChainHeadBodyEvent::Done {
                                                value: block_data
                                                    .body
                                                    .unwrap()
                                                    .into_iter()
                                                    .map(methods::HexString)
                                                    .collect(),
                                            },
                                        }
                                        .to_json_call_object_parameters(None),
                                    )
                                    .await;
                                break;
                            }
                            either::Left(Err(())) => {
                                requests_subscriptions
                                    .set_queued_notification(
                                        &request_id.1,
                                        &subscription_id,
                                        0,
                                        methods::ServerToClient::chainHead_unstable_bodyEvent {
                                            subscription: (&subscription_id).into(),
                                            result: methods::ChainHeadBodyEvent::Inaccessible {},
                                        }
                                        .to_json_call_object_parameters(None),
                                    )
                                    .await;
                                break;
                            }
                            either::Right((
                                SubscriptionMessage::StopIfChainHeadBody { stop_request_id },
                                confirmation_sender,
                            )) => {
                                requests_subscriptions
                                    .respond(
                                        &stop_request_id.1,
                                        methods::Response::chainHead_unstable_stopBody(())
                                            .to_json_response(&stop_request_id.0),
                                    )
                                    .await;

                                confirmation_sender.send();
                                return;
                            }
                            either::Right(_) => {
                                // Any other message.
                                // Silently discard the confirmation sender.
                            }
                        }
                    }
                } else {
                    requests_subscriptions
                        .set_queued_notification(
                            &request_id.1,
                            &subscription_id,
                            0,
                            methods::ServerToClient::chainHead_unstable_bodyEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::ChainHeadBodyEvent::Disjoint {},
                            }
                            .to_json_call_object_parameters(None),
                        )
                        .await;
                }
            }
        });
    }

    async fn start_chain_head_storage(
        &mut self,
        requests_subscriptions: &Arc<
            requests_subscriptions::RequestsSubscriptions<SubscriptionMessage>,
        >,
        request_id: (&str, &requests_subscriptions::RequestId),
        hash: methods::HashHexString,
        key: methods::HexString,
        child_trie: Option<methods::HexString>,
        ty: methods::ChainHeadStorageType,
        network_config: methods::NetworkConfig,
        block_scale_encoded_header: Option<Vec<u8>>,
    ) {
        if child_trie.is_some() {
            // TODO: implement this
            requests_subscriptions
                .respond(
                    request_id.1,
                    json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::ServerError(
                            -32000,
                            "Child key storage queries not supported yet",
                        ),
                        None,
                    ),
                )
                .await;
            log::warn!(
                target: &self.log_target,
                "chainHead_unstable_storage has been called with a non-null childTrie. \
                This isn't supported by smoldot yet."
            );
            return;
        }

        let is_hash = match ty {
            methods::ChainHeadStorageType::Value => false,
            methods::ChainHeadStorageType::Hash => true,
            methods::ChainHeadStorageType::DescendantsValues
            | methods::ChainHeadStorageType::DescendantsHashes
            | methods::ChainHeadStorageType::ClosestAncestorMerkleValue => {
                // TODO: implement this
                requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Child key storage queries not supported yet",
                            ),
                            None,
                        ),
                    )
                    .await;
                log::warn!(
                    target: &self.log_target,
                    "chainHead_unstable_storage has been called with a type other than value or hash. \
                    This isn't supported by smoldot yet."
                );
                return;
            }
        };

        let (subscription_id, mut messages_rx, subscription_start) = match requests_subscriptions
            .start_subscription(request_id.1, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        subscription_start.start({
            let requests_subscriptions = requests_subscriptions.clone();
            let sync_service = self.sync_service.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());

            async move {
                requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::chainHead_unstable_storage((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                match block_scale_encoded_header
                    .as_ref()
                    .map(|h| header::decode(h, sync_service.block_number_bytes()))
                {
                    Some(Ok(decoded_header)) => {
                        let mut future = pin::pin!(sync_service.clone().storage_query(
                            decoded_header.number,
                            &hash.0,
                            decoded_header.state_root,
                            iter::once(key.0.clone()), // TODO: clone :-/
                            cmp::min(10, network_config.total_attempts),
                            Duration::from_millis(u64::from(cmp::min(
                                20000,
                                network_config.timeout_ms,
                            ))),
                            NonZeroU32::new(network_config.max_parallel.clamp(1, 5)).unwrap(),
                        ));

                        let requests_subscriptions = {
                            let weak = Arc::downgrade(&requests_subscriptions);
                            drop(requests_subscriptions);
                            weak
                        };

                        loop {
                            let outcome = {
                                let next_message = pin::pin!(messages_rx.next());
                                match future::select(&mut future, next_message).await {
                                    future::Either::Left((v, _)) => either::Left(v),
                                    future::Either::Right((v, _)) => either::Right(v),
                                }
                            };

                            let requests_subscriptions = match requests_subscriptions.upgrade() {
                                Some(rs) => rs,
                                None => return,
                            };

                            match outcome {
                                either::Left(Ok(values)) => {
                                    // `storage_query` returns a list of values because it can perform
                                    // multiple queries at once. In our situation, we only start one query
                                    // and as such the outcome only ever contains one element.
                                    debug_assert_eq!(values.len(), 1);
                                    let value = values.into_iter().next().unwrap();
                                    if let Some(mut value) = value {
                                        if is_hash {
                                            value = blake2_rfc::blake2b::blake2b(8, &[], &value).as_bytes().to_vec();
                                        }

                                        requests_subscriptions.push_notification(
                                            &request_id.1,
                                            &subscription_id,
                                            methods::ServerToClient::chainHead_unstable_storageEvent {
                                                subscription: (&subscription_id).into(),
                                                result: methods::ChainHeadStorageEvent::Item {
                                                    key,
                                                    value: Some(methods::HexString(value)),
                                                    hash: None,
                                                    merkle_value: None,
                                                },
                                            }
                                            .to_json_call_object_parameters(None)
                                        ).await;
                                    }

                                    requests_subscriptions.push_notification(
                                        &request_id.1,
                                        &subscription_id,
                                        methods::ServerToClient::chainHead_unstable_storageEvent {
                                            subscription: (&subscription_id).into(),
                                            result: methods::ChainHeadStorageEvent::Done,
                                        }
                                        .to_json_call_object_parameters(None)
                                    ).await;
                                    break;
                                }
                                either::Left(Err(_)) => {
                                    requests_subscriptions.push_notification(
                                        &request_id.1,
                                        &subscription_id,
                                        methods::ServerToClient::chainHead_unstable_storageEvent {
                                            subscription: (&subscription_id).into(),
                                            result: methods::ChainHeadStorageEvent::Inaccessible {},
                                        }
                                        .to_json_call_object_parameters(None)
                                    ).await;
                                    break;
                                }
                                either::Right((
                                    SubscriptionMessage::ChainHeadStorageContinue { continue_request_id },
                                    confirmation_sender,
                                )) => {
                                    // Because we never emit a "waiting-for-continue" event, this
                                    // is always erroneous.
                                    requests_subscriptions
                                        .respond(
                                            &continue_request_id.1,
                                            json_rpc::parse::build_error_response(
                                                &continue_request_id.0,
                                                json_rpc::parse::ErrorResponse::InvalidParams,
                                                Some(&serde_json::to_string("storage subscription hasn't generated a waiting-for-continue").unwrap()),
                                            ),
                                        )
                                        .await;

                                    confirmation_sender.send();
                                    return;
                                }
                                either::Right((
                                    SubscriptionMessage::StopIfChainHeadStorage { stop_request_id },
                                    confirmation_sender,
                                )) => {
                                    requests_subscriptions
                                        .respond(
                                            &stop_request_id.1,
                                            methods::Response::chainHead_unstable_stopBody(())
                                                .to_json_response(&stop_request_id.0),
                                        )
                                        .await;

                                    confirmation_sender.send();
                                    return;
                                }
                                either::Right(_) => {
                                    // Any other message.
                                    // Silently discard the confirmation sender.
                                }
                            }
                        }
                    }
                    Some(Err(err)) => {
                        requests_subscriptions
                            .push_notification(
                                &request_id.1,
                                &subscription_id,
                                methods::ServerToClient::chainHead_unstable_storageEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadStorageEvent::Error {
                                        error: err.to_string().into(),
                                    },
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await;
                    }
                    None => {
                        requests_subscriptions
                            .push_notification(
                                &request_id.1,
                                &subscription_id,
                                methods::ServerToClient::chainHead_unstable_storageEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadStorageEvent::Disjoint {},
                                }
                                .to_json_call_object_parameters(None),
                            )
                            .await;
                    }
                };
            }
        });
    }

    async fn start_chain_head_call(
        &mut self,
        requests_subscriptions: &Arc<
            requests_subscriptions::RequestsSubscriptions<SubscriptionMessage>,
        >,
        request_id: (&str, &requests_subscriptions::RequestId),
        function_to_call: &str,
        call_parameters: methods::HexString,
        pre_runtime_call: Option<runtime_service::RuntimeAccess<TPlat>>,
        network_config: methods::NetworkConfig,
    ) {
        let (subscription_id, mut messages_rx, subscription_start) = match requests_subscriptions
            .start_subscription(request_id.1, 1)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        subscription_start.start({
            let requests_subscriptions = requests_subscriptions.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());
            let function_to_call = function_to_call.to_owned();

            async move {
                requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::chainHead_unstable_call((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                let (pre_runtime_call, requests_subscriptions) = if let Some(pre_runtime_call) = &pre_runtime_call {
                    let mut call_future = pin::pin!(pre_runtime_call.start(
                        &function_to_call,
                        iter::once(&call_parameters.0),
                        cmp::min(10, network_config.total_attempts),
                        Duration::from_millis(u64::from(cmp::min(
                            20000,
                            network_config.timeout_ms,
                        ))),
                        NonZeroU32::new(network_config.max_parallel.clamp(1, 5)).unwrap(),
                    ));

                    let requests_subscriptions = {
                        let weak = Arc::downgrade(&requests_subscriptions);
                        drop(requests_subscriptions);
                        weak
                    };

                    loop {
                        let outcome = {
                            let next_message = pin::pin!(messages_rx.next());
                            match future::select(&mut call_future, next_message).await {
                                future::Either::Left((v, _)) => either::Left(v),
                                future::Either::Right((v, _)) => either::Right(v),
                            }
                        };

                        let requests_subscriptions = match requests_subscriptions.upgrade() {
                            Some(rs) => rs,
                            None => return,
                        };

                        match outcome {
                            either::Left(outcome) => break (Some(outcome), requests_subscriptions),
                            either::Right((
                                SubscriptionMessage::StopIfChainHeadCall {
                                    stop_request_id,
                                },
                                confirmation_sender,
                            )) => {
                                requests_subscriptions
                                    .respond(
                                        &stop_request_id.1,
                                        methods::Response::chainHead_unstable_stopCall(())
                                            .to_json_response(&stop_request_id.0),
                                    )
                                    .await;

                                confirmation_sender.send();
                                return;
                            }
                            either::Right(_) => {
                                // Any other message.
                                // Silently discard the confirmation sender.
                            }
                        }
                    }
                } else {
                    (None, requests_subscriptions)
                };

                let final_notif = match pre_runtime_call {
                    Some(Ok((runtime_call_lock, virtual_machine))) => {
                        match runtime_host::run(runtime_host::Config {
                            virtual_machine,
                            function_to_call: &function_to_call,
                            parameter: iter::once(&call_parameters.0),
                            offchain_storage_changes: Default::default(),
                            storage_main_trie_changes: Default::default(),
                            max_log_level: 0,
                        }) {
                            Err((error, prototype)) => {
                                runtime_call_lock.unlock(prototype);
                                methods::ServerToClient::chainHead_unstable_callEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadCallEvent::Error {
                                        error: error.to_string().into(),
                                    },
                                }
                                .to_json_call_object_parameters(None)
                            }
                            Ok(mut runtime_call) => {
                                loop {
                                    match runtime_call {
                                        runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                                            let output =
                                                success.virtual_machine.value().as_ref().to_owned();
                                            runtime_call_lock
                                                .unlock(success.virtual_machine.into_prototype());
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: (&subscription_id).into(),
                                                    result: methods::ChainHeadCallEvent::Done {
                                                        output: methods::HexString(output),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                                            runtime_call_lock.unlock(error.prototype);
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: (&subscription_id).into(),
                                                    result: methods::ChainHeadCallEvent::Error {
                                                        error: error.detail.to_string().into(),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        runtime_host::RuntimeHostVm::StorageGet(get) => {
                                            // TODO: what if the remote lied to us?
                                            let storage_value = {
                                                let child_trie = get.child_trie();
                                                runtime_call_lock.storage_entry(child_trie.as_ref().map(|c| c.as_ref()), get.key().as_ref())
                                            };
                                            let storage_value = match storage_value {
                                                Ok(v) => v,
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::StorageGet(
                                                            get,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    break methods::ServerToClient::chainHead_unstable_callEvent {
                                                            subscription: (&subscription_id).into(),
                                                            result: methods::ChainHeadCallEvent::Inaccessible {
                                                                error: error.to_string().into(),
                                                            },
                                                        }
                                                        .to_json_call_object_parameters(None);
                                                }
                                            };
                                            runtime_call = get.inject_value(
                                                storage_value
                                                    .map(|(val, vers)| (iter::once(val), vers)),
                                            );
                                        }
                                        runtime_host::RuntimeHostVm::ClosestDescendantMerkleValue(mv) => {
                                            // TODO: what if the remote lied to us?
                                            let merkle_value = {
                                                let child_trie = mv.child_trie();
                                                runtime_call_lock
                                                    .closest_descendant_merkle_value(child_trie.as_ref().map(|c| c.as_ref()), &mv.key().collect::<Vec<_>>())
                                            };
                                            let merkle_value = match merkle_value {
                                                Ok(v) => v,
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::ClosestDescendantMerkleValue(
                                                            mv,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    break methods::ServerToClient::chainHead_unstable_callEvent {
                                                            subscription: (&subscription_id).into(),
                                                            result: methods::ChainHeadCallEvent::Inaccessible {
                                                                error: error.to_string().into(),
                                                            },
                                                        }
                                                        .to_json_call_object_parameters(None);
                                                }
                                            };
                                            runtime_call = mv.inject_merkle_value(merkle_value);
                                        }
                                        runtime_host::RuntimeHostVm::NextKey(nk) => {
                                            // TODO: what if the remote lied to us?
                                            let next_key = {
                                                let child_trie = nk.child_trie();
                                                runtime_call_lock.next_key(
                                                    child_trie.as_ref().map(|c| c.as_ref()),
                                                    &nk.key().collect::<Vec<_>>(),
                                                    nk.or_equal(),
                                                    &nk.prefix().collect::<Vec<_>>(),
                                                    nk.branch_nodes(),
                                                )
                                            };
                                            let next_key = match next_key {
                                                Ok(v) => v,
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::NextKey(
                                                            nk,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    break methods::ServerToClient::chainHead_unstable_callEvent {
                                                            subscription: (&subscription_id).into(),
                                                            result: methods::ChainHeadCallEvent::Inaccessible {
                                                                error: error.to_string().into(),
                                                            },
                                                        }
                                                        .to_json_call_object_parameters(None);
                                                }
                                            };
                                            runtime_call = nk.inject_key(next_key.map(|k| k.iter().copied()));
                                        }
                                        runtime_host::RuntimeHostVm::SignatureVerification(sig) => {
                                            runtime_call = sig.verify_and_resume();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(runtime_service::RuntimeCallError::InvalidRuntime(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageRetrieval(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::MissingProofEntry(_error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: "incomplete call proof".into(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::InvalidChildTrieRoot)) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: "invalid call proof".into(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::CallProof(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageQuery(error))) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: format!("failed to fetch call proof: {error}").into(),
                            },
                        }
                        .to_json_call_object_parameters(None)
                    }
                    None => methods::ServerToClient::chainHead_unstable_callEvent {
                        subscription: (&subscription_id).into(),
                        result: methods::ChainHeadCallEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None),
                };

                requests_subscriptions
                    .push_notification(&request_id.1,
                        &subscription_id, final_notif)
                    .await;
            }
        });
    }
}
