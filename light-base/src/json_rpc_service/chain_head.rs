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

use super::{Background, FollowSubscription, SubscriptionMessage};

use crate::{platform::Platform, runtime_service, sync_service};

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
    sync::atomic,
    time::Duration,
};
use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use hashbrown::HashMap;
use smoldot::{
    chain::fork_tree,
    executor::{self, runtime_host},
    header,
    json_rpc::{self, methods, requests_subscriptions},
    network::protocol,
};

impl<TPlat: Platform> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::chainHead_unstable_call`].
    pub(super) async fn chain_head_call(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
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
        let message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(follow_subscription)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::ChainHeadCall {
                            get_state_machine_request_id: state_machine_request_id.clone(),
                            get_request_id: request_id.to_owned(),
                            hash,
                            call_parameters,
                            function_to_call,
                            network_config,
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if !message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    async fn start_chain_head_call(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        function_to_call: &str,
        call_parameters: methods::HexString,
        pre_runtime_call: Option<runtime_service::RuntimeLock<TPlat>>,
        network_config: methods::NetworkConfig,
    ) {
        let (state_machine_subscription, messages_tx, mut messages_rx, subscription_start) =
            match self
                .requests_subscriptions
                .start_subscription(&state_machine_request_id, 1)
                .await
            {
                Ok(v) => v,
                Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                    self.requests_subscriptions
                        .respond(
                            &state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                &request_id,
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
            let me = self.clone();
            let request_id = request_id.to_owned();
            let function_to_call = function_to_call.to_owned();
            let state_machine_request_id = state_machine_request_id.clone();
            async move {
                let subscription_id = me
                    .next_subscription_id
                    .fetch_add(1, atomic::Ordering::Relaxed)
                    .to_string();

                me.subscriptions.lock().await.insert(
                    subscription_id.clone(),
                    (
                        Arc::new(Mutex::new(messages_tx)),
                        state_machine_subscription.clone(),
                    ),
                );

                me.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_call((&subscription_id).into())
                            .to_json_response(&request_id),
                    )
                    .await;

                let pre_runtime_call = if let Some(pre_runtime_call) = &pre_runtime_call {
                    let call_future = pre_runtime_call.start(
                        &function_to_call,
                        iter::once(&call_parameters.0),
                        cmp::min(10, network_config.total_attempts),
                        Duration::from_millis(u64::from(cmp::min(
                            20000,
                            network_config.timeout_ms,
                        ))),
                        NonZeroU32::new(network_config.max_parallel.clamp(1, 5)).unwrap(),
                    );
                    futures::pin_mut!(call_future);

                    loop {
                        let outcome = {
                            match future::select(&mut call_future, messages_rx.next()).await {
                                future::Either::Left((v, _)) => either::Left(v),
                                future::Either::Right((v, _)) => either::Right(v),
                            }
                        };

                        match outcome {
                            either::Left(outcome) => break Some(outcome),
                            either::Right(None) => {
                                unreachable!()
                            }
                            either::Right(Some((
                                SubscriptionMessage::StopIfChainHeadCall {
                                    stop_state_machine_request_id,
                                    stop_request_id,
                                },
                                confirmation_sender,
                            ))) => {
                                me.requests_subscriptions
                                    .stop_subscription(&state_machine_subscription)
                                    .await;

                                me.requests_subscriptions
                                    .respond(
                                        &stop_state_machine_request_id,
                                        methods::Response::chainHead_unstable_stopCall(())
                                            .to_json_response(&stop_request_id),
                                    )
                                    .await;

                                let _ = confirmation_sender.send(());
                                return;
                            }
                            either::Right(Some(_)) => {
                                // Any other message.
                                // Silently discard the confirmation sender.
                            }
                        }
                    }
                } else {
                    None
                };

                let final_notif = match pre_runtime_call {
                    Some(Ok((runtime_call_lock, virtual_machine))) => {
                        match runtime_host::run(runtime_host::Config {
                            virtual_machine,
                            function_to_call: &function_to_call,
                            parameter: iter::once(&call_parameters.0),
                            top_trie_root_calculation_cache: None,
                            offchain_storage_changes: Default::default(),
                            storage_top_trie_changes: Default::default(),
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
                                            let storage_value =
                                                runtime_call_lock.storage_entry(get.key().as_ref());
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
                                        runtime_host::RuntimeHostVm::NextKey(nk) => {
                                            // TODO: implement somehow
                                            runtime_call_lock.unlock(
                                                runtime_host::RuntimeHostVm::NextKey(nk)
                                                    .into_prototype(),
                                            );
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: (&subscription_id).into(),
                                                    result: methods::ChainHeadCallEvent::Inaccessible {
                                                        error: "getting next key not implemented".into(),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
                                        }
                                        runtime_host::RuntimeHostVm::PrefixKeys(nk) => {
                                            // TODO: implement somehow
                                            runtime_call_lock.unlock(
                                                runtime_host::RuntimeHostVm::PrefixKeys(nk)
                                                    .into_prototype(),
                                            );
                                            break methods::ServerToClient::chainHead_unstable_callEvent {
                                                    subscription: (&subscription_id).into(),
                                                    result: methods::ChainHeadCallEvent::Inaccessible {
                                                        error: "getting prefix keys not implemented".into(),
                                                    },
                                                }
                                                .to_json_call_object_parameters(None);
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
                    Some(Err(runtime_service::RuntimeCallError::MissingProofEntry)) => {
                        methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: "incomplete call proof".into(),
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

                me.requests_subscriptions
                    .push_notification(&state_machine_subscription, final_notif)
                    .await;
                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me.subscriptions.lock().await.remove(&subscription_id);
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_follow`].
    pub(super) async fn chain_head_follow(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        runtime_updates: bool,
    ) {
        let (state_machine_subscription, messages_tx, mut messages_rx, subscription_start) =
            match self
                .requests_subscriptions
                .start_subscription(state_machine_request_id, 16)
                .await
            {
                Ok(v) => v,
                Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                    self.requests_subscriptions
                        .respond(
                            state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
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

        let (mut subscribe_all, runtime_subscribe_all) = if runtime_updates {
            let subscribe_all = self
                .runtime_service
                .subscribe_all("chainHead_follow", 32, NonZeroUsize::new(32).unwrap())
                .await;
            let id = subscribe_all.new_blocks.id();
            (either::Left(subscribe_all), Some(id))
        } else {
            (
                either::Right(self.sync_service.subscribe_all(32, false).await),
                None,
            )
        };

        let (subscription_id, initial_notifications, mut subscription_state) = {
            let subscription_id = self
                .next_subscription_id
                .fetch_add(1, atomic::Ordering::Relaxed)
                .to_string();

            let mut initial_notifications = Vec::with_capacity(match &subscribe_all {
                either::Left(sa) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
                either::Right(sa) => 1 + sa.non_finalized_blocks_ancestry_order.len(),
            });

            let mut pinned_blocks_headers =
                HashMap::with_capacity_and_hasher(0, Default::default());
            let mut non_finalized_blocks = fork_tree::ForkTree::new();

            match &subscribe_all {
                either::Left(subscribe_all) => {
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
                                    new_runtime: if let Some(new_runtime) = &block.new_runtime {
                                        Some(convert_runtime_spec(new_runtime))
                                    } else {
                                        None
                                    },
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

            let mut lock = self.subscriptions.lock().await;

            lock.insert(
                subscription_id.clone(),
                (
                    Arc::new(Mutex::new(messages_tx)),
                    state_machine_subscription.clone(),
                ),
            );

            let subscription_state = FollowSubscription {
                non_finalized_blocks,
                pinned_blocks_headers,
                runtime_subscribe_all,
            };

            (subscription_id, initial_notifications, subscription_state)
        };

        subscription_start.start({
            let me = self.clone();
            let request_id = request_id.to_owned();
            let state_machine_request_id = state_machine_request_id.clone();

            async move {
                me.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_follow((&subscription_id).into())
                            .to_json_response(&request_id),
                    )
                    .await;

                // Send back to the user the initial notifications.
                for notif in initial_notifications {
                    me.requests_subscriptions
                        .push_notification(&state_machine_subscription, notif)
                        .await;
                }

                loop {
                    let next_block = match &mut subscribe_all {
                        either::Left(subscribe_all) => {
                            future::Either::Left(subscribe_all.new_blocks.next().map(either::Left))
                        }
                        either::Right(subscribe_all) => future::Either::Right(
                            subscribe_all.new_blocks.next().map(either::Right),
                        ),
                    };
                    futures::pin_mut!(next_block);

                    // TODO: doesn't enforce any maximum number of pinned blocks
                    match future::select(next_block, messages_rx.next()).await {
                        future::Either::Left((either::Left(None) | either::Right(None), _)) => {
                            // TODO: clear queue of notifications?
                            break;
                        }
                        future::Either::Left((
                            either::Left(Some(runtime_service::Notification::Finalized {
                                best_block_hash,
                                hash,
                                ..
                            }))
                            | either::Right(Some(sync_service::Notification::Finalized {
                                best_block_hash,
                                hash,
                            })),
                            _,
                        )) => {
                            let mut finalized_blocks_hashes = Vec::new();
                            let mut pruned_blocks_hashes = Vec::new();

                            let node_index = subscription_state
                                .non_finalized_blocks
                                .find(|b| *b == hash)
                                .unwrap();
                            for pruned in subscription_state
                                .non_finalized_blocks
                                .prune_ancestors(node_index)
                            {
                                if pruned.is_prune_target_ancestor {
                                    finalized_blocks_hashes
                                        .push(methods::HashHexString(pruned.user_data));
                                } else {
                                    pruned_blocks_hashes
                                        .push(methods::HashHexString(pruned.user_data));
                                }
                            }

                            // TODO: don't always generate
                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(
                                                best_block_hash,
                                            ),
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
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
                        future::Either::Left((
                            either::Left(Some(runtime_service::Notification::BestBlockChanged {
                                hash,
                            }))
                            | either::Right(Some(sync_service::Notification::BestBlockChanged {
                                hash,
                            })),
                            _,
                        )) => {
                            let _ = me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
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
                        future::Either::Left((
                            either::Left(Some(runtime_service::Notification::Block(block))),
                            _,
                        )) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            let _was_in = subscription_state
                                .pinned_blocks_headers
                                .insert(hash, block.scale_encoded_header);
                            debug_assert!(_was_in.is_none());

                            // TODO: check if it matches current finalized block
                            // TODO: O(n)
                            let parent_node_index = subscription_state
                                .non_finalized_blocks
                                .find(|b| *b == block.parent_hash);
                            subscription_state
                                .non_finalized_blocks
                                .insert(parent_node_index, hash);

                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::FollowEvent::NewBlock {
                                            block_hash: methods::HashHexString(hash),
                                            parent_block_hash: methods::HashHexString(
                                                block.parent_hash,
                                            ),
                                            new_runtime: if let Some(new_runtime) =
                                                &block.new_runtime
                                            {
                                                Some(convert_runtime_spec(new_runtime))
                                            } else {
                                                None
                                            },
                                        },
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await
                                .is_err()
                            {
                                break;
                            }

                            if block.is_new_best {
                                if me
                                    .requests_subscriptions
                                    .try_push_notification(
                                        &state_machine_subscription,
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
                        }
                        future::Either::Left((
                            either::Right(Some(sync_service::Notification::Block(block))),
                            _,
                        )) => {
                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);

                            let _was_in = subscription_state
                                .pinned_blocks_headers
                                .insert(hash, block.scale_encoded_header);
                            debug_assert!(_was_in.is_none());

                            // TODO: check if it matches current finalized block
                            // TODO: O(n)
                            let parent_node_index = subscription_state
                                .non_finalized_blocks
                                .find(|b| *b == block.parent_hash);
                            subscription_state
                                .non_finalized_blocks
                                .insert(parent_node_index, hash);

                            if me
                                .requests_subscriptions
                                .try_push_notification(
                                    &state_machine_subscription,
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::FollowEvent::NewBlock {
                                            block_hash: methods::HashHexString(hash),
                                            parent_block_hash: methods::HashHexString(
                                                block.parent_hash,
                                            ),
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

                            if block.is_new_best {
                                if me
                                    .requests_subscriptions
                                    .try_push_notification(
                                        &state_machine_subscription,
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
                        }
                        future::Either::Right((None, _)) => {
                            unreachable!()
                        }
                        future::Either::Right((
                            Some((
                                SubscriptionMessage::StopIfChainHeadFollow {
                                    stop_state_machine_request_id,
                                    stop_request_id,
                                },
                                confirmation_sender,
                            )),
                            _,
                        )) => {
                            me.requests_subscriptions
                                .stop_subscription(&state_machine_subscription)
                                .await;

                            me.requests_subscriptions
                                .respond(
                                    &stop_state_machine_request_id,
                                    methods::Response::chainHead_unstable_unfollow(())
                                        .to_json_response(&stop_request_id),
                                )
                                .await;

                            let _ = confirmation_sender.send(());
                            break;
                        }
                        future::Either::Right((
                            Some((
                                SubscriptionMessage::ChainHeadBody {
                                    hash,
                                    get_state_machine_request_id,
                                    get_request_id,
                                    network_config,
                                },
                                confirmation_sender,
                            )),
                            _,
                        )) => {
                            // Determine whether the requested block hash is valid, and if yes its number.
                            let block_number = {
                                if let Some(header) =
                                    subscription_state.pinned_blocks_headers.get(&hash.0)
                                {
                                    let decoded = header::decode(
                                        header,
                                        me.sync_service.block_number_bytes(),
                                    )
                                    .unwrap(); // TODO: unwrap?
                                    Some(decoded.number)
                                } else {
                                    continue;
                                }
                            };

                            me.start_chain_head_body(
                                &get_request_id,
                                &get_state_machine_request_id,
                                hash,
                                network_config,
                                block_number,
                            )
                            .await;
                            let _ = confirmation_sender.send(());
                        }
                        future::Either::Right((
                            Some((
                                SubscriptionMessage::ChainHeadStorage {
                                    hash,
                                    get_state_machine_request_id,
                                    get_request_id,
                                    network_config,
                                    key,
                                    child_key,
                                },
                                confirmation_sender,
                            )),
                            _,
                        )) => {
                            // Obtain the header of the requested block.
                            // Contains `None` if the subscription is disjoint.
                            let block_scale_encoded_header = {
                                if let Some(header) =
                                    subscription_state.pinned_blocks_headers.get(&hash.0)
                                {
                                    Some(header.clone())
                                } else {
                                    continue;
                                }
                            };

                            me.start_chain_head_storage(
                                &get_request_id,
                                &get_state_machine_request_id,
                                hash,
                                key,
                                child_key,
                                network_config,
                                block_scale_encoded_header,
                            )
                            .await;
                            let _ = confirmation_sender.send(());
                        }
                        future::Either::Right((
                            Some((
                                SubscriptionMessage::ChainHeadCall {
                                    hash,
                                    get_state_machine_request_id,
                                    get_request_id,
                                    network_config,
                                    function_to_call,
                                    call_parameters,
                                },
                                confirmation_sender,
                            )),
                            _,
                        )) => {
                            // Determine whether the requested block hash is valid and start the call.
                            let pre_runtime_call = {
                                let runtime_service_subscribe_all =
                                    match subscription_state.runtime_subscribe_all {
                                        Some(sa) => sa,
                                        None => {
                                            me.requests_subscriptions
                                            .respond(
                                                &get_state_machine_request_id,
                                                json_rpc::parse::build_error_response(
                                                    &get_request_id,
                                                    json_rpc::parse::ErrorResponse::InvalidParams,
                                                    None,
                                                ),
                                            )
                                            .await;
                                            return;
                                        }
                                    };

                                if !subscription_state
                                    .pinned_blocks_headers
                                    .contains_key(&hash.0)
                                {
                                    me.requests_subscriptions
                                        .respond(
                                            &get_state_machine_request_id,
                                            json_rpc::parse::build_error_response(
                                                &get_request_id,
                                                json_rpc::parse::ErrorResponse::InvalidParams,
                                                None,
                                            ),
                                        )
                                        .await;
                                    return;
                                }

                                me.runtime_service
                                    .pinned_block_runtime_lock(
                                        runtime_service_subscribe_all,
                                        &hash.0,
                                    )
                                    .await
                                    .ok()
                            };

                            me.start_chain_head_call(
                                &get_request_id,
                                &get_state_machine_request_id,
                                &function_to_call,
                                call_parameters,
                                pre_runtime_call,
                                network_config,
                            )
                            .await;
                            let _ = confirmation_sender.send(());
                        }
                        future::Either::Right((
                            Some((
                                SubscriptionMessage::ChainHeadHeader {
                                    hash,
                                    get_state_machine_request_id,
                                    get_request_id,
                                },
                                confirmation_sender,
                            )),
                            _,
                        )) => {
                            let response = {
                                subscription_state
                                    .pinned_blocks_headers
                                    .get(&hash.0)
                                    .cloned()
                            };

                            me.requests_subscriptions
                                .respond(
                                    &get_state_machine_request_id,
                                    methods::Response::chainHead_unstable_header(
                                        response.map(methods::HexString),
                                    )
                                    .to_json_response(&get_request_id),
                                )
                                .await;
                            let _ = confirmation_sender.send(());
                        }
                        future::Either::Right((
                            Some((
                                SubscriptionMessage::ChainHeadFollowUnpin {
                                    hash,
                                    unpin_state_machine_request_id,
                                    unpin_request_id,
                                },
                                confirmation_sender,
                            )),
                            _,
                        )) => {
                            let valid = {
                                if subscription_state
                                    .pinned_blocks_headers
                                    .remove(&hash.0)
                                    .is_some()
                                {
                                    if let Some(runtime_subscribe_all) =
                                        subscription_state.runtime_subscribe_all
                                    {
                                        me.runtime_service
                                            .unpin_block(runtime_subscribe_all, &hash.0)
                                            .await;
                                    }
                                    true
                                } else {
                                    false
                                }
                            };

                            if valid {
                                me.requests_subscriptions
                                    .respond(
                                        &unpin_state_machine_request_id,
                                        methods::Response::chainHead_unstable_unpin(())
                                            .to_json_response(&unpin_request_id),
                                    )
                                    .await;
                                let _ = confirmation_sender.send(());
                            }
                        }
                        future::Either::Right((Some(_), _)) => {
                            // Any other message.
                            // Silently discard the confirmation sender.
                        }
                    }
                }

                let _ = me.subscriptions.lock().await.remove(&subscription_id);
                me.requests_subscriptions
                    .push_notification(
                        &state_machine_subscription,
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::FollowEvent::Stop {},
                        }
                        .to_json_call_object_parameters(None),
                    )
                    .await;
                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storage`].
    pub(super) async fn chain_head_storage(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription: &str,
        hash: methods::HashHexString,
        key: methods::HexString,
        child_key: Option<methods::HexString>,
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
        let message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(follow_subscription)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::ChainHeadStorage {
                            get_state_machine_request_id: state_machine_request_id.clone(),
                            get_request_id: request_id.to_owned(),
                            hash,
                            key,
                            child_key,
                            network_config,
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if !message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    async fn start_chain_head_storage(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        hash: methods::HashHexString,
        key: methods::HexString,
        child_key: Option<methods::HexString>,
        network_config: methods::NetworkConfig,
        block_scale_encoded_header: Option<Vec<u8>>,
    ) {
        if child_key.is_some() {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
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
                "chainHead_unstable_storage with a non-null childKey has been called. \
                This isn't supported by smoldot yet."
            );
            return;
        }

        let (state_machine_subscription, messages_tx, mut messages_rx, subscription_start) =
            match self
                .requests_subscriptions
                .start_subscription(state_machine_request_id, 1)
                .await
            {
                Ok(v) => v,
                Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                    self.requests_subscriptions
                        .respond(
                            state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
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

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        self.subscriptions.lock().await.insert(
            subscription_id.clone(),
            (
                Arc::new(Mutex::new(messages_tx)),
                state_machine_subscription.clone(),
            ),
        );

        subscription_start.start({
            let me = self.clone();
            let request_id = request_id.to_owned();
            let state_machine_request_id = state_machine_request_id.clone();

            async move {
                me.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_storage((&subscription_id).into())
                            .to_json_response(&request_id),
                    )
                    .await;

                let response = match block_scale_encoded_header
                    .as_ref()
                    .map(|h| header::decode(&h, me.sync_service.block_number_bytes()))
                {
                    Some(Ok(decoded_header)) => {
                        let future = me.sync_service.clone().storage_query(
                            decoded_header.number,
                            &hash.0,
                            decoded_header.state_root,
                            iter::once(&key.0),
                            cmp::min(10, network_config.total_attempts),
                            Duration::from_millis(u64::from(cmp::min(
                                20000,
                                network_config.timeout_ms,
                            ))),
                            NonZeroU32::new(network_config.max_parallel.clamp(1, 5)).unwrap(),
                        );
                        futures::pin_mut!(future);

                        loop {
                            let outcome = {
                                match future::select(&mut future, messages_rx.next()).await {
                                    future::Either::Left((v, _)) => either::Left(v),
                                    future::Either::Right((v, _)) => either::Right(v),
                                }
                            };

                            match outcome {
                                either::Left(Ok(values)) => {
                                    // `storage_query` returns a list of values because it can perform
                                    // multiple queries at once. In our situation, we only start one query
                                    // and as such the outcome only ever contains one element.
                                    debug_assert_eq!(values.len(), 1);
                                    let value = values.into_iter().next().unwrap();
                                    let output = value.map(|v| methods::HexString(v).to_string());
                                    break methods::ServerToClient::chainHead_unstable_storageEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::ChainHeadStorageEvent::Done {
                                            value: output,
                                        },
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                either::Left(Err(_)) => {
                                    break methods::ServerToClient::chainHead_unstable_storageEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::ChainHeadStorageEvent::Inaccessible {},
                                    }
                                    .to_json_call_object_parameters(None)
                                }
                                either::Right(None) => {
                                    unreachable!()
                                }
                                either::Right(Some((
                                    SubscriptionMessage::StopIfChainHeadBody {
                                        stop_state_machine_request_id,
                                        stop_request_id,
                                    },
                                    confirmation_sender,
                                ))) => {
                                    me.requests_subscriptions
                                        .stop_subscription(&state_machine_subscription)
                                        .await;

                                    me.requests_subscriptions
                                        .respond(
                                            &stop_state_machine_request_id,
                                            methods::Response::chainHead_unstable_stopBody(())
                                                .to_json_response(&stop_request_id),
                                        )
                                        .await;

                                    let _ = confirmation_sender.send(());
                                    return;
                                }
                                either::Right(Some(_)) => {
                                    // Any other message.
                                    // Silently discard the confirmation sender.
                                }
                            }
                        }
                    }
                    Some(Err(err)) => methods::ServerToClient::chainHead_unstable_storageEvent {
                        subscription: (&subscription_id).into(),
                        result: methods::ChainHeadStorageEvent::Error {
                            error: err.to_string().into(),
                        },
                    }
                    .to_json_call_object_parameters(None),
                    None => methods::ServerToClient::chainHead_unstable_storageEvent {
                        subscription: (&subscription_id).into(),
                        result: methods::ChainHeadStorageEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None),
                };

                me.requests_subscriptions
                    .set_queued_notification(&state_machine_subscription, 0, response)
                    .await;
                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me.subscriptions.lock().await.remove(&subscription_id);
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_body`].
    pub(super) async fn chain_head_unstable_body(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
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
        let message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(follow_subscription)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::ChainHeadBody {
                            get_state_machine_request_id: state_machine_request_id.clone(),
                            get_request_id: request_id.to_owned(),
                            hash,
                            network_config,
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if !message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        None,
                    ),
                )
                .await;
        }
    }

    async fn start_chain_head_body(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        hash: methods::HashHexString,
        network_config: methods::NetworkConfig,
        block_number: Option<u64>,
    ) {
        let (state_machine_subscription, messages_tx, mut messages_rx, subscription_start) =
            match self
                .requests_subscriptions
                .start_subscription(&state_machine_request_id, 1)
                .await
            {
                Ok(v) => v,
                Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                    self.requests_subscriptions
                        .respond(
                            state_machine_request_id,
                            json_rpc::parse::build_error_response(
                                request_id,
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

        let subscription_id = self
            .next_subscription_id
            .fetch_add(1, atomic::Ordering::Relaxed)
            .to_string();

        self.subscriptions.lock().await.insert(
            subscription_id.clone(),
            (
                Arc::new(Mutex::new(messages_tx)),
                state_machine_subscription.clone(),
            ),
        );

        subscription_start.start({
            let me = self.clone();
            let request_id = request_id.to_owned();
            let state_machine_request_id = state_machine_request_id.clone();

            async move {
                me.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        methods::Response::chainHead_unstable_body((&subscription_id).into())
                            .to_json_response(&request_id),
                    )
                    .await;

                let response = if let Some(block_number) = block_number {
                    // TODO: right now we query the header because the underlying function returns an error if we don't
                    let future = me.sync_service.clone().block_query(
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
                    );
                    futures::pin_mut!(future);

                    loop {
                        let outcome = {
                            match future::select(&mut future, messages_rx.next()).await {
                                future::Either::Left((v, _)) => either::Left(v),
                                future::Either::Right((v, _)) => either::Right(v),
                            }
                        };

                        match outcome {
                            either::Left(Ok(block_data)) => {
                                break methods::ServerToClient::chainHead_unstable_bodyEvent {
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
                                .to_json_call_object_parameters(None)
                            }
                            either::Left(Err(())) => {
                                break methods::ServerToClient::chainHead_unstable_bodyEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadBodyEvent::Inaccessible {},
                                }
                                .to_json_call_object_parameters(None)
                            }
                            either::Right(None) => {
                                unreachable!()
                            }
                            either::Right(Some((
                                SubscriptionMessage::StopIfChainHeadStorage {
                                    stop_state_machine_request_id,
                                    stop_request_id,
                                },
                                confirmation_sender,
                            ))) => {
                                me.requests_subscriptions
                                    .stop_subscription(&state_machine_subscription)
                                    .await;

                                me.requests_subscriptions
                                    .respond(
                                        &stop_state_machine_request_id,
                                        methods::Response::chainHead_unstable_stopBody(())
                                            .to_json_response(&stop_request_id),
                                    )
                                    .await;

                                let _ = confirmation_sender.send(());
                                return;
                            }
                            either::Right(Some(_)) => {
                                // Any other message.
                                // Silently discard the confirmation sender.
                            }
                        }
                    }
                } else {
                    methods::ServerToClient::chainHead_unstable_bodyEvent {
                        subscription: (&subscription_id).into(),
                        result: methods::ChainHeadBodyEvent::Disjoint {},
                    }
                    .to_json_call_object_parameters(None)
                };

                me.requests_subscriptions
                    .set_queued_notification(&state_machine_subscription, 0, response)
                    .await;
                me.requests_subscriptions
                    .stop_subscription(&state_machine_subscription)
                    .await;
                let _ = me.subscriptions.lock().await.remove(&subscription_id);
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_header`].
    pub(super) async fn chain_head_unstable_header(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription: &str,
        hash: methods::HashHexString,
    ) {
        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(follow_subscription)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::ChainHeadHeader {
                            get_state_machine_request_id: state_machine_request_id.clone(),
                            get_request_id: request_id.to_owned(),
                            hash,
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block isn't pinned.
        if !message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
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
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription_id: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(subscription_id)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::StopIfChainHeadBody {
                            stop_state_machine_request_id: state_machine_request_id.clone(),
                            stop_request_id: request_id.to_owned(),
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if !stop_message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    methods::Response::chainHead_unstable_stopBody(()).to_json_response(request_id),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopCall`].
    pub(super) async fn chain_head_unstable_stop_call(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription_id: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(subscription_id)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::StopIfChainHeadCall {
                            stop_state_machine_request_id: state_machine_request_id.clone(),
                            stop_request_id: request_id.to_owned(),
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if !stop_message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    methods::Response::chainHead_unstable_stopCall(()).to_json_response(request_id),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopStorage`].
    pub(super) async fn chain_head_unstable_stop_storage(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        subscription_id: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(subscription_id)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::StopIfChainHeadStorage {
                            stop_state_machine_request_id: state_machine_request_id.clone(),
                            stop_request_id: request_id.to_owned(),
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if !stop_message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    methods::Response::chainHead_unstable_stopStorage(())
                        .to_json_response(request_id),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_unfollow`].
    pub(super) async fn chain_head_unstable_unfollow(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(follow_subscription)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::StopIfChainHeadFollow {
                            stop_state_machine_request_id: state_machine_request_id.clone(),
                            stop_request_id: request_id.to_owned(),
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if !stop_message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    methods::Response::chainHead_unstable_unfollow(()).to_json_response(request_id),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_unpin`].
    pub(super) async fn chain_head_unstable_unpin(
        self: &Arc<Self>,
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
        follow_subscription: &str,
        hash: methods::HashHexString,
    ) {
        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let message_received = {
            let sender = self
                .subscriptions
                .lock()
                .await
                .get(follow_subscription)
                .map(|(tx, _)| tx.clone());

            if let Some(sender) = sender {
                let (tx, rx) = oneshot::channel();
                let _ = sender
                    .lock()
                    .await
                    .send((
                        SubscriptionMessage::ChainHeadFollowUnpin {
                            unpin_state_machine_request_id: state_machine_request_id.clone(),
                            unpin_request_id: request_id.to_owned(),
                            hash,
                        },
                        tx,
                    ))
                    .await;
                rx.await.is_ok()
            } else {
                false
            }
        };

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which happens if the block to unpin isn't valid.
        if !message_received {
            self.requests_subscriptions
                .respond(
                    state_machine_request_id,
                    json_rpc::parse::build_error_response(
                        request_id,
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
        request_id: &str,
        state_machine_request_id: &requests_subscriptions::RequestId,
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
                state_machine_request_id,
                methods::Response::chainHead_unstable_finalizedDatabase(response.into())
                    .to_json_response(request_id),
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
