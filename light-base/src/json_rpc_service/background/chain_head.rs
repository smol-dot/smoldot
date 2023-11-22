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

use super::Background;

use crate::{platform::PlatformRef, runtime_service, sync_service};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{
    iter,
    num::{NonZeroU32, NonZeroUsize},
    pin,
    time::Duration,
};
use futures_lite::FutureExt as _;
use futures_util::{FutureExt as _, StreamExt as _};
use hashbrown::HashMap;
use smoldot::{
    chain::fork_tree,
    executor::{self, runtime_host},
    header,
    json_rpc::{self, methods, service},
    network::codec,
};

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::chainHead_unstable_call`].
    pub(super) async fn chain_head_call(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::chainHead_unstable_call {
            follow_subscription,
            ..
        } = request.request()
        else {
            unreachable!()
        };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            sender.deliver(request).await
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            request.respond(methods::Response::chainHead_unstable_call(
                methods::ChainHeadBodyCallReturn::LimitReached {},
            ));
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_follow`].
    pub(super) async fn chain_head_follow(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_follow { with_runtime } = request.request()
        else {
            unreachable!()
        };

        let (mut subscription, rx) = {
            let mut lock = self.chain_head_follow_tasks.lock().await;

            // As mentioned in the spec, the JSON-RPC server accepts 2 or more subscriptions per
            // JSON-RPC client. We choose to accept only exactly 2 in order to make sure that
            // JSON-RPC client implementations are made aware of this limit. This number of 2 might
            // be relaxed and/or configurable in the future.
            if lock.len() >= 2 {
                log::warn!(
                    target: &self.log_target,
                    "Rejected `chainHead_unstable_follow` subscription due to limit reached."
                );
                request.fail(json_rpc::parse::ErrorResponse::ApplicationDefined(
                    -32800,
                    "Maximum number of `chainHead_unstable_follow` subscriptions reached",
                ));
                return;
            }

            let (tx, rx) = service::deliver_channel();
            let subscription = request.accept();
            lock.insert(subscription.subscription_id().to_owned(), tx);
            (subscription, rx)
        };
        let subscription_id = subscription.subscription_id().to_owned();

        let events = if with_runtime {
            let subscribe_all = self
                .runtime_service
                .subscribe_all(32, NonZeroUsize::new(32).unwrap())
                .await;
            let id = subscribe_all.new_blocks.id();
            either::Left((subscribe_all, id))
        } else {
            either::Right(self.sync_service.subscribe_all(32, false).await)
        };

        let (non_finalized_blocks, pinned_blocks_headers, events) = {
            let mut pinned_blocks_headers =
                HashMap::with_capacity_and_hasher(0, Default::default());
            let mut non_finalized_blocks = fork_tree::ForkTree::new();

            match &events {
                either::Left((subscribe_all, _)) => {
                    let finalized_block_hash = header::hash_from_scale_encoded_header(
                        &subscribe_all.finalized_block_scale_encoded_header[..],
                    );

                    pinned_blocks_headers.insert(
                        finalized_block_hash,
                        subscribe_all.finalized_block_scale_encoded_header.clone(),
                    );

                    subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::Initialized {
                                    finalized_block_hash: methods::HashHexString(
                                        finalized_block_hash,
                                    ),
                                    finalized_block_runtime: Some(convert_runtime_spec(
                                        &subscribe_all.finalized_block_runtime,
                                    )),
                                },
                            },
                        )
                        .await;

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

                        subscription
                            .send_notification(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::NewBlock {
                                        block_hash: methods::HashHexString(hash),
                                        new_runtime: block
                                            .new_runtime
                                            .as_ref()
                                            .map(convert_runtime_spec),
                                        parent_block_hash: methods::HashHexString(
                                            block.parent_hash,
                                        ),
                                    },
                                },
                            )
                            .await;

                        if block.is_new_best {
                            subscription
                                .send_notification(
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(hash),
                                        },
                                    },
                                )
                                .await;
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

                    subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::Initialized {
                                    finalized_block_hash: methods::HashHexString(
                                        finalized_block_hash,
                                    ),
                                    finalized_block_runtime: None,
                                },
                            },
                        )
                        .await;

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

                        subscription
                            .send_notification(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::NewBlock {
                                        block_hash: methods::HashHexString(hash),
                                        new_runtime: None,
                                        parent_block_hash: methods::HashHexString(
                                            block.parent_hash,
                                        ),
                                    },
                                },
                            )
                            .await;

                        if block.is_new_best {
                            subscription
                                .send_notification(
                                    methods::ServerToClient::chainHead_unstable_followEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::FollowEvent::BestBlockChanged {
                                            best_block_hash: methods::HashHexString(hash),
                                        },
                                    },
                                )
                                .await;
                        }
                    }
                }
            }

            (non_finalized_blocks, pinned_blocks_headers, events)
        };

        self.platform
            .spawn_task(format!("{}-chain-head-follow", self.log_target).into(), {
                let log_target = self.log_target.clone();
                let runtime_service = self.runtime_service.clone();
                let sync_service = self.sync_service.clone();
                let platform = self.platform.clone();
                let (to_operation_handlers, from_operation_handlers) = async_channel::bounded(8);
                let from_operation_handlers = Box::pin(from_operation_handlers);

                ChainHeadFollowTask {
                    platform,
                    non_finalized_blocks,
                    pinned_blocks_headers,
                    subscription: match events {
                        either::Left((sub, id)) => Subscription::WithRuntime {
                            notifications: sub.new_blocks,
                            subscription_id: id,
                        },
                        either::Right(sub) => {
                            Subscription::WithoutRuntime(Box::pin(sub.new_blocks))
                        }
                    },
                    log_target,
                    runtime_service,
                    sync_service,
                    next_operation_id: 1,
                    to_main_task: to_operation_handlers,
                    from_operation_handlers,
                    available_operation_slots: 32, // TODO: make configurable? adjust dynamically?
                    operations_in_progress: hashbrown::HashMap::with_capacity_and_hasher(
                        32,
                        Default::default(),
                    ),
                }
                .run(subscription, subscription_id, rx)
            });
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storage`].
    pub(super) async fn chain_head_storage(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::chainHead_unstable_storage {
            follow_subscription,
            ..
        } = request.request()
        else {
            unreachable!()
        };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            sender.deliver(request).await
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            request.respond(methods::Response::chainHead_unstable_storage(
                methods::ChainHeadStorageReturn::LimitReached {},
            ));
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_stopOperation`].
    pub(super) async fn chain_head_stop_operation(
        self: &Arc<Self>,
        request: service::RequestProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_stopOperation {
            follow_subscription,
            ..
        } = request.request()
        else {
            unreachable!()
        };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        if let Some(sender) = lock.get_mut(&*follow_subscription) {
            let _ = sender.deliver(request).await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_continue`].
    pub(super) async fn chain_head_continue(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::chainHead_unstable_continue { .. } = request.request() else {
            unreachable!()
        };
        // TODO: not implemented properly
        request.respond(methods::Response::chainHead_unstable_continue(()));
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_body`].
    pub(super) async fn chain_head_unstable_body(
        self: &Arc<Self>,
        request: service::RequestProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_body {
            follow_subscription,
            ..
        } = request.request()
        else {
            unreachable!()
        };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            sender.deliver(request).await
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            request.respond(methods::Response::chainHead_unstable_body(
                methods::ChainHeadBodyCallReturn::LimitReached {},
            ));
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_header`].
    pub(super) async fn chain_head_unstable_header(
        self: &Arc<Self>,
        request: service::RequestProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_header {
            follow_subscription,
            ..
        } = request.request()
        else {
            unreachable!()
        };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            sender.deliver(request).await
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            request.respond(methods::Response::chainHead_unstable_header(None));
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_unpin`].
    pub(super) async fn chain_head_unstable_unpin(
        self: &Arc<Self>,
        request: service::RequestProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_unpin {
            follow_subscription,
            ..
        } = request.request()
        else {
            unreachable!()
        };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            sender.deliver(request).await
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            request.respond(methods::Response::chainHead_unstable_unpin(()));
        }
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

    platform: TPlat,

    subscription: Subscription<TPlat>,

    log_target: String,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    sync_service: Arc<sync_service::SyncService<TPlat>>,

    to_main_task: async_channel::Sender<OperationEvent>,

    from_operation_handlers: pin::Pin<Box<async_channel::Receiver<OperationEvent>>>,

    /// Identifier to assign to the next body/call/storage operation.
    next_operation_id: u128,

    /// List of body/call/storage operations currently in progress. Keys are operation IDs.
    operations_in_progress: hashbrown::HashMap<String, Operation, fnv::FnvBuildHasher>,

    available_operation_slots: u32,
}

struct OperationEvent {
    operation_id: String,
    notification: methods::FollowEvent<'static>,
    is_done: bool,
}

struct Operation {
    occupied_slots: u32,
    interrupt: event_listener::Event,
}

enum Subscription<TPlat: PlatformRef> {
    WithRuntime {
        notifications: runtime_service::Subscription<TPlat>,
        subscription_id: runtime_service::SubscriptionId,
    },
    // TODO: better typing?
    WithoutRuntime(pin::Pin<Box<async_channel::Receiver<sync_service::Notification>>>),
}

impl<TPlat: PlatformRef> ChainHeadFollowTask<TPlat> {
    async fn run(
        mut self,
        mut subscription: service::Subscription,
        subscription_id: String,
        mut messages_rx: service::DeliverReceiver<service::RequestProcess>,
    ) {
        loop {
            enum WakeUpReason {
                SubscriptionDead,
                NotificationWithRuntime(runtime_service::Notification),
                NotificationWithoutRuntime(sync_service::Notification),
                OperationEvent {
                    operation_id: String,
                    notification: methods::FollowEvent<'static>,
                    is_done: bool,
                },
                Unsubscribed,
                NewRequest(service::RequestProcess),
            }

            let outcome: WakeUpReason = {
                let next_block = async {
                    match &mut self.subscription {
                        Subscription::WithRuntime { notifications, .. } => {
                            match notifications.next().await {
                                Some(n) => WakeUpReason::NotificationWithRuntime(n),
                                None => WakeUpReason::SubscriptionDead,
                            }
                        }
                        Subscription::WithoutRuntime(notifications) => {
                            match notifications.next().await {
                                Some(n) => WakeUpReason::NotificationWithoutRuntime(n),
                                None => WakeUpReason::SubscriptionDead,
                            }
                        }
                    }
                };

                let operation_event = async {
                    let event = self.from_operation_handlers.next().await.unwrap();
                    WakeUpReason::OperationEvent {
                        operation_id: event.operation_id,
                        notification: event.notification,
                        is_done: event.is_done,
                    }
                };

                let message = async {
                    match messages_rx.next().await {
                        Some(rq) => WakeUpReason::NewRequest(rq),
                        None => WakeUpReason::Unsubscribed,
                    }
                };

                next_block
                    .or(message)
                    .or(operation_event)
                    .or(async {
                        subscription.wait_until_stale().await;
                        WakeUpReason::Unsubscribed
                    })
                    .await
            };

            // TODO: doesn't enforce any maximum number of pinned blocks
            match outcome {
                WakeUpReason::Unsubscribed => return,
                WakeUpReason::SubscriptionDead => {
                    subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::Stop {},
                            },
                        )
                        .await;
                    break;
                }

                WakeUpReason::OperationEvent {
                    operation_id,
                    notification,
                    is_done,
                } => {
                    let operation_is_valid = if is_done {
                        if let Some(operation) = self.operations_in_progress.remove(&operation_id) {
                            self.available_operation_slots += operation.occupied_slots;
                            true
                        } else {
                            false
                        }
                    } else {
                        self.operations_in_progress.contains_key(&operation_id)
                    };

                    if operation_is_valid {
                        subscription
                            .send_notification(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: notification,
                                },
                            )
                            .await;
                    }
                }

                WakeUpReason::NotificationWithRuntime(
                    runtime_service::Notification::Finalized {
                        best_block_hash,
                        hash,
                        ..
                    },
                )
                | WakeUpReason::NotificationWithoutRuntime(
                    sync_service::Notification::Finalized {
                        best_block_hash,
                        hash,
                    },
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
                    subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::BestBlockChanged {
                                    best_block_hash: methods::HashHexString(best_block_hash),
                                },
                            },
                        )
                        .await;

                    subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::Finalized {
                                    finalized_blocks_hashes,
                                    pruned_blocks_hashes,
                                },
                            },
                        )
                        .await;
                }
                WakeUpReason::NotificationWithoutRuntime(
                    sync_service::Notification::BestBlockChanged { hash },
                )
                | WakeUpReason::NotificationWithRuntime(
                    runtime_service::Notification::BestBlockChanged { hash },
                ) => {
                    subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::BestBlockChanged {
                                    best_block_hash: methods::HashHexString(hash),
                                },
                            },
                        )
                        .await;
                }
                WakeUpReason::NotificationWithRuntime(runtime_service::Notification::Block(
                    block,
                )) => {
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

                    subscription
                        .send_notification(
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
                            },
                        )
                        .await;

                    if block.is_new_best {
                        subscription
                            .send_notification(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                },
                            )
                            .await;
                    }
                }
                WakeUpReason::NotificationWithoutRuntime(sync_service::Notification::Block(
                    block,
                )) => {
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

                    subscription
                        .send_notification(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    parent_block_hash: methods::HashHexString(block.parent_hash),
                                    new_runtime: None, // TODO:
                                },
                            },
                        )
                        .await;

                    if block.is_new_best {
                        subscription
                            .send_notification(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                },
                            )
                            .await;
                    }
                }
                WakeUpReason::NewRequest(rq) => self.on_foreground_message(rq).await,
            }
        }
    }

    async fn on_foreground_message(&mut self, request: service::RequestProcess) {
        match request.request() {
            methods::MethodCall::chainHead_unstable_body { .. } => {
                self.start_chain_head_body(request).await;
            }
            methods::MethodCall::chainHead_unstable_storage { .. } => {
                self.start_chain_head_storage(request).await;
            }
            methods::MethodCall::chainHead_unstable_call { .. } => {
                self.start_chain_head_call(request).await;
            }
            methods::MethodCall::chainHead_unstable_stopOperation { operation_id, .. } => {
                if let Some(operation) = self.operations_in_progress.remove(&*operation_id) {
                    operation.interrupt.notify(usize::max_value());
                    self.available_operation_slots += operation.occupied_slots;
                }
            }
            methods::MethodCall::chainHead_unstable_header {
                follow_subscription: _,
                hash,
            } => {
                let response = self.pinned_blocks_headers.get(&hash.0).cloned();
                request.respond(methods::Response::chainHead_unstable_header(
                    response.map(methods::HexString),
                ));
            }
            methods::MethodCall::chainHead_unstable_unpin {
                follow_subscription: _,
                hash_or_hashes,
            } => {
                let all_hashes = match &hash_or_hashes {
                    methods::HashHexStringSingleOrArray::Single(hash) => {
                        either::Left(iter::once(&hash.0))
                    }
                    methods::HashHexStringSingleOrArray::Array(hashes) => {
                        either::Right(hashes.iter().map(|h| &h.0))
                    }
                };

                let is_valid = all_hashes
                    .clone()
                    .all(|hash| self.pinned_blocks_headers.contains_key(hash));

                if is_valid {
                    for hash in all_hashes {
                        self.pinned_blocks_headers.remove(hash);
                        if let Subscription::WithRuntime {
                            subscription_id, ..
                        } = self.subscription
                        {
                            self.runtime_service
                                .unpin_block(subscription_id, *hash)
                                .await;
                        }
                    }

                    request.respond(methods::Response::chainHead_unstable_unpin(()));
                } else {
                    request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                }
            }
            _ => unreachable!(),
        }
    }

    async fn start_chain_head_body(&mut self, request: service::RequestProcess) {
        let methods::MethodCall::chainHead_unstable_body { hash, .. } = request.request() else {
            unreachable!()
        };

        // Determine whether the requested block hash is valid, and if yes its number and
        // extrinsics trie root. The extrinsics trie root is used to verify whether the body we
        // download is correct.
        let (block_number, extrinsics_root) = {
            if let Some(header) = self.pinned_blocks_headers.get(&hash.0) {
                let decoded =
                    header::decode(header, self.sync_service.block_number_bytes()).unwrap(); // TODO: unwrap?
                (decoded.number, *decoded.extrinsics_root)
            } else {
                // Block isn't pinned. Request is invalid.
                request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                return;
            }
        };

        // Check whether there is an operation slot available.
        self.available_operation_slots = match self.available_operation_slots.checked_sub(1) {
            Some(s) => s,
            None => {
                request.respond(methods::Response::chainHead_unstable_call(
                    methods::ChainHeadBodyCallReturn::LimitReached {},
                ));
                return;
            }
        };

        let operation_id = self.next_operation_id.to_string();
        self.next_operation_id += 1;
        let to_main_task = self.to_main_task.clone();

        let interrupt = event_listener::Event::new();
        let on_interrupt = interrupt.listen();

        let _was_in = self.operations_in_progress.insert(
            operation_id.clone(),
            Operation {
                occupied_slots: 1,
                interrupt,
            },
        );
        debug_assert!(_was_in.is_none());

        request.respond(methods::Response::chainHead_unstable_body(
            methods::ChainHeadBodyCallReturn::Started {
                operation_id: (&operation_id).into(),
            },
        ));

        // Finish the request asynchronously.
        self.platform
            .spawn_task(format!("{}-chain-head-body", self.log_target).into(), {
                let sync_service = self.sync_service.clone();
                async move {
                    // TODO: right now we query the header because the underlying function returns an error if we don't
                    let future = sync_service.clone().block_query(
                        block_number,
                        hash.0,
                        codec::BlocksRequestFields {
                            header: true,
                            body: true,
                            justifications: false,
                        },
                        3,
                        Duration::from_secs(20),
                        NonZeroU32::new(2).unwrap(),
                    );

                    // Drive the future, but cancel execution if the JSON-RPC client
                    // unsubscribes.
                    let outcome = match future.map(Some).or(on_interrupt.map(|()| None)).await {
                        Some(v) => v,
                        None => return, // JSON-RPC client has unsubscribed in the meanwhile.
                    };

                    // We must check whether the body is present in the response and valid.
                    // TODO: should try the request again with a different peer instead of failing immediately
                    let body = match outcome {
                        Ok(outcome) => {
                            if let Some(body) = outcome.body {
                                if header::extrinsics_root(&body) == extrinsics_root {
                                    Ok(body)
                                } else {
                                    Err(())
                                }
                            } else {
                                Err(())
                            }
                        }
                        Err(err) => Err(err),
                    };

                    // Send back the response.
                    match body {
                        Ok(body) => {
                            let _ = to_main_task
                                .send(OperationEvent {
                                    operation_id: operation_id.clone(),
                                    is_done: true,
                                    notification: methods::FollowEvent::OperationBodyDone {
                                        operation_id: operation_id.clone().into(),
                                        value: body.into_iter().map(methods::HexString).collect(),
                                    },
                                })
                                .await;
                        }
                        Err(()) => {
                            let _ = to_main_task
                                .send(OperationEvent {
                                    operation_id: operation_id.clone(),
                                    is_done: true,
                                    notification: methods::FollowEvent::OperationInaccessible {
                                        operation_id: operation_id.clone().into(),
                                    },
                                })
                                .await;
                        }
                    }
                }
            });
    }

    async fn start_chain_head_storage(&mut self, request: service::RequestProcess) {
        let methods::MethodCall::chainHead_unstable_storage {
            hash,
            mut items,
            child_trie,
            ..
        } = request.request()
        else {
            unreachable!()
        };

        // Obtain the header of the requested block.
        let block_scale_encoded_header = {
            if let Some(header) = self.pinned_blocks_headers.get(&hash.0) {
                header.clone()
            } else {
                // Block isn't pinned. Request is invalid.
                request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                return;
            }
        };

        if child_trie.is_some() {
            // TODO: implement this
            request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                "Child key storage queries not supported yet",
            ));
            log::warn!(
                target: &self.log_target,
                "chainHead_unstable_storage has been called with a non-null childTrie. \
                This isn't supported by smoldot yet."
            );
            return;
        }

        // Scrap some of the items so that it fits in the number of operation slots.
        let (operation_id, occupied_operation_slots) = if self.available_operation_slots == 0 {
            request.respond(methods::Response::chainHead_unstable_storage(
                methods::ChainHeadStorageReturn::LimitReached {},
            ));
            return;
        } else if u32::try_from(items.len())
            .map_or(true, |num_items| num_items > self.available_operation_slots)
        {
            let operation_id = self.next_operation_id.to_string();
            self.next_operation_id += 1;

            request.respond(methods::Response::chainHead_unstable_storage(
                methods::ChainHeadStorageReturn::Started {
                    operation_id: (&operation_id).into(),
                    // This block is reached only if `items.len() > available_slots`. Since
                    // `items.len()` is a `usize`, we know that `available_slots` fits in a `usize`
                    // as well.
                    discarded_items: items.len()
                        - usize::try_from(self.available_operation_slots).unwrap(),
                },
            ));

            let occupied_slots = self.available_operation_slots;
            items.drain(..usize::try_from(self.available_operation_slots).unwrap());
            self.available_operation_slots = 0;

            (operation_id, occupied_slots)
        } else {
            let operation_id = self.next_operation_id.to_string();
            self.next_operation_id += 1;

            request.respond(methods::Response::chainHead_unstable_storage(
                methods::ChainHeadStorageReturn::Started {
                    operation_id: (&operation_id).into(),
                    discarded_items: 0,
                },
            ));

            // Since this block is reached only if `items.len() < available_slots` and that
            // `available_slots` is a `u32`, we know that `items.len()` fits in a `u32` as well.
            let num_items_u32 = u32::try_from(items.len()).unwrap();

            (operation_id, num_items_u32)
        };

        let interrupt = event_listener::Event::new();
        let on_interrupt = interrupt.listen();

        let _was_in = self.operations_in_progress.insert(
            operation_id.clone(),
            Operation {
                occupied_slots: occupied_operation_slots,
                interrupt,
            },
        );
        debug_assert!(_was_in.is_none());

        let to_main_task = self.to_main_task.clone();

        // Finish the call asynchronously.
        self.platform
            .spawn_task(format!("{}-chain-head-storage", self.log_target).into(), {
                let sync_service = self.sync_service.clone();
                async move {
                    let decoded_header = match header::decode(
                        &block_scale_encoded_header,
                        sync_service.block_number_bytes(),
                    ) {
                        Ok(h) => h,
                        Err(err) => {
                            // Header can't be decoded. Generate a single `error` event and
                            // return.
                            let _ = to_main_task.send(OperationEvent {
                                operation_id: operation_id.clone(),
                                is_done: true,
                                notification: methods::FollowEvent::OperationError {
                                    operation_id: operation_id.clone().into(),
                                    error: err.to_string().into(),
                                }
                            })
                            .await;
                            return;
                        }
                    };

                    // Perform some API conversions.
                    let queries = items
                        .into_iter()
                        .map(|item| sync_service::StorageRequestItem {
                            key: item.key.0,
                            ty: match item.ty {
                                methods::ChainHeadStorageType::Value => {
                                    sync_service::StorageRequestItemTy::Value
                                }
                                methods::ChainHeadStorageType::Hash => {
                                    sync_service::StorageRequestItemTy::Hash
                                }
                                methods::ChainHeadStorageType::ClosestDescendantMerkleValue => {
                                    sync_service::StorageRequestItemTy::ClosestDescendantMerkleValue
                                }
                                methods::ChainHeadStorageType::DescendantsValues => {
                                    sync_service::StorageRequestItemTy::DescendantsValues
                                }
                                methods::ChainHeadStorageType::DescendantsHashes => {
                                    sync_service::StorageRequestItemTy::DescendantsHashes
                                }
                            },
                        })
                        .collect::<Vec<_>>();

                    let future = sync_service.clone().storage_query(
                        decoded_header.number,
                        &hash.0,
                        decoded_header.state_root,
                        queries.into_iter(),
                        3,
                        Duration::from_secs(20),
                        NonZeroU32::new(2).unwrap(),
                    );

                    // Drive the future, but cancel execution if the JSON-RPC client
                    // unsubscribes.
                    let outcome = match future
                        .map(Some)
                        .or(on_interrupt.map(|()| None))
                        .await
                    {
                        Some(v) => v,
                        None => return, // JSON-RPC client has unsubscribed in the meanwhile.
                    };

                    match outcome {
                        Ok(entries) => {
                            // Perform some API conversions.
                            let items = entries
                                .into_iter()
                                .filter_map(|item| match item {
                                    sync_service::StorageResultItem::Value { key, value } => {
                                        Some(methods::ChainHeadStorageResponseItem {
                                            key: methods::HexString(key),
                                            value: Some(methods::HexString(value?)),
                                            hash: None,
                                            closest_descendant_merkle_value: None,
                                        })
                                    }
                                    sync_service::StorageResultItem::Hash { key, hash } => {
                                        Some(methods::ChainHeadStorageResponseItem {
                                            key: methods::HexString(key),
                                            value: None,
                                            hash: Some(methods::HexString(hash?.to_vec())),
                                            closest_descendant_merkle_value: None,
                                        })
                                    }
                                    sync_service::StorageResultItem::DescendantValue { key, value, .. } => {
                                        Some(methods::ChainHeadStorageResponseItem {
                                            key: methods::HexString(key),
                                            value: Some(methods::HexString(value)),
                                            hash: None,
                                            closest_descendant_merkle_value: None,
                                        })
                                    }
                                    sync_service::StorageResultItem::DescendantHash { key, hash, .. } => {
                                        Some(methods::ChainHeadStorageResponseItem {
                                            key: methods::HexString(key),
                                            value: None,
                                            hash: Some(methods::HexString(hash.to_vec())),
                                            closest_descendant_merkle_value: None,
                                        })
                                    }
                                    sync_service::StorageResultItem::ClosestDescendantMerkleValue { requested_key, closest_descendant_merkle_value: merkle_value, .. } => {
                                        Some(methods::ChainHeadStorageResponseItem {
                                            key: methods::HexString(requested_key),
                                            value: None,
                                            hash: None,
                                            closest_descendant_merkle_value: Some(methods::HexString(merkle_value?)),
                                        })
                                    }
                                })
                                .collect::<Vec<_>>();

                            if !items.is_empty() {
                                let _ = to_main_task.send(OperationEvent {
                                    operation_id: operation_id.clone(),
                                    is_done: false,
                                    notification: methods::FollowEvent::OperationStorageItems {
                                        operation_id: operation_id.clone().into(),
                                        items
                                    }
                                }).await;
                            }

                            let _ = to_main_task.send(OperationEvent {
                                operation_id: operation_id.clone(),
                                is_done: true,
                                notification: methods::FollowEvent::OperationStorageDone {
                                    operation_id: operation_id.clone().into(),
                                }
                            }).await;
                        }
                        Err(_) => {
                            let _ = to_main_task.send(OperationEvent {
                                operation_id: operation_id.clone(),
                                is_done: true,
                                notification: methods::FollowEvent::OperationInaccessible {
                                    operation_id: operation_id.clone().into(),
                                }
                            }).await;
                        }
                    }
                }
            });
    }

    async fn start_chain_head_call(&mut self, request: service::RequestProcess) {
        let (hash, function_to_call, call_parameters) = {
            let methods::MethodCall::chainHead_unstable_call {
                hash,
                function,
                call_parameters,
                ..
            } = request.request()
            else {
                unreachable!()
            };

            (hash, function.into_owned(), call_parameters.0)
        };

        // Check whether there is an operation slot available.
        self.available_operation_slots = match self.available_operation_slots.checked_sub(1) {
            Some(s) => s,
            None => {
                request.respond(methods::Response::chainHead_unstable_call(
                    methods::ChainHeadBodyCallReturn::LimitReached {},
                ));
                return;
            }
        };

        // Determine whether the requested block hash is valid and start the call.
        let pre_runtime_call = match self.subscription {
            Subscription::WithRuntime {
                subscription_id, ..
            } => {
                if !self.pinned_blocks_headers.contains_key(&hash.0) {
                    // Block isn't pinned. Request is invalid.
                    request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                    return;
                }

                match self
                    .runtime_service
                    .pinned_block_runtime_access(subscription_id, hash.0)
                    .await
                {
                    Ok(c) => c,
                    Err(runtime_service::PinnedBlockRuntimeAccessError::ObsoleteSubscription) => {
                        // The runtime service subscription is dead.
                        request.respond(methods::Response::chainHead_unstable_call(
                            methods::ChainHeadBodyCallReturn::LimitReached {},
                        ));
                        return;
                    }
                }
            }
            Subscription::WithoutRuntime(_) => {
                // It is invalid to call this function for a "without runtime" subscription.
                request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                return;
            }
        };

        let operation_id = self.next_operation_id.to_string();
        self.next_operation_id += 1;
        let to_main_task = self.to_main_task.clone();

        let interrupt = event_listener::Event::new();
        let on_interrupt = interrupt.listen();

        let _was_in = self.operations_in_progress.insert(
            operation_id.clone(),
            Operation {
                occupied_slots: 1,
                interrupt,
            },
        );
        debug_assert!(_was_in.is_none());

        request.respond(methods::Response::chainHead_unstable_call(
            methods::ChainHeadBodyCallReturn::Started {
                operation_id: (&operation_id).into(),
            },
        ));

        // Finish the call asynchronously.
        self.platform
            .spawn_task(format!("{}-chain-head-call", self.log_target).into(), {
            async move {
                let pre_runtime_call = {
                    let call_future = pre_runtime_call.start(
                        &function_to_call,
                        iter::once(&call_parameters),
                        3,
                        Duration::from_secs(20),
                        NonZeroU32::new(2).unwrap(),
                    );

                    // Drive the future, but cancel execution if the JSON-RPC client unsubscribes.
                    match call_future.map(Some).or(on_interrupt.map(|()| None)).await {
                        Some(v) => v,
                        None => return  // JSON-RPC client has unsubscribed in the meanwhile.
                    }
                };

                match pre_runtime_call {
                    Ok((runtime_call_lock, virtual_machine)) => {
                        match runtime_host::run(runtime_host::Config {
                            virtual_machine,
                            function_to_call: &function_to_call,
                            parameter: iter::once(&call_parameters),
                            storage_main_trie_changes: Default::default(),
                            max_log_level: 0,
                            calculate_trie_changes: false,
                        }) {
                            Err((error, prototype)) => {
                                runtime_call_lock.unlock(prototype);
                                let _ = to_main_task.send(OperationEvent {
                                    operation_id: operation_id.clone(),
                                    is_done: true,
                                    notification: methods::FollowEvent::OperationError {
                                    operation_id: operation_id.clone().into(),
                                    error: error.to_string().into(),
                                }}).await;
                            }
                            Ok(mut runtime_call) => {
                                loop {
                                    match runtime_call {
                                        runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                                            let output =
                                                success.virtual_machine.value().as_ref().to_owned();
                                            runtime_call_lock
                                                .unlock(success.virtual_machine.into_prototype());
                                            let _ = to_main_task.send(OperationEvent {
                                                operation_id: operation_id.clone(),
                                                is_done: true,
                                                notification: methods::FollowEvent::OperationCallDone {
                                                operation_id: operation_id.clone().into(),
                                                output: methods::HexString(output),
                                            }}).await;
                                            break;
                                        }
                                        runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                                            runtime_call_lock.unlock(error.prototype);
                                            let _ = to_main_task.send(OperationEvent {
                                                operation_id: operation_id.clone(),
                                                is_done: true,
                                                notification: methods::FollowEvent::OperationError {
                                                operation_id: operation_id.clone().into(),
                                                error: error.detail.to_string().into(),
                                            }}).await;
                                            break;
                                        }
                                        runtime_host::RuntimeHostVm::StorageGet(get) => {
                                            // TODO: what if the remote lied to us?
                                            let storage_value = {
                                                let child_trie = get.child_trie();
                                                runtime_call_lock.storage_entry(child_trie.as_ref().map(|c| c.as_ref()), get.key().as_ref())
                                            };
                                            let storage_value = match storage_value {
                                                Ok(v) => v,
                                                Err(_) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::StorageGet(
                                                            get,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    let _ = to_main_task.send(OperationEvent {
                                                        operation_id: operation_id.clone(),
                                                        is_done: true,
                                                        notification: methods::FollowEvent::OperationInaccessible {
                                                        operation_id: operation_id.clone().into(),
                                                    }}).await;
                                                    break;
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
                                                Err(_) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::ClosestDescendantMerkleValue(
                                                            mv,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    let _ = to_main_task.send(OperationEvent {
                                                        operation_id: operation_id.clone(),
                                                        is_done: true,
                                                        notification: methods::FollowEvent::OperationInaccessible {
                                                            operation_id: operation_id.clone().into(),
                                                        }
                                                    }).await;
                                                    break;
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
                                                Err(_) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::NextKey(
                                                            nk,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    let _ = to_main_task.send(OperationEvent {
                                                        operation_id: operation_id.clone(),
                                                        is_done: true,
                                                        notification: methods::FollowEvent::OperationInaccessible {
                                                            operation_id: operation_id.clone().into(),
                                                        }
                                                    }).await;
                                                    break;
                                                }
                                            };
                                            runtime_call = nk.inject_key(next_key.map(|k| k.iter().copied()));
                                        }
                                        runtime_host::RuntimeHostVm::OffchainStorageSet(req) => {
                                            runtime_call = req.resume();
                                        }
                                        runtime_host::RuntimeHostVm::SignatureVerification(sig) => {
                                            runtime_call = sig.verify_and_resume();
                                        }
                                        runtime_host::RuntimeHostVm::Offchain(ctx) => {
                                            runtime_call_lock.unlock(runtime_host::RuntimeHostVm::Offchain(ctx).into_prototype());
                                            let _ = to_main_task.send(OperationEvent {
                                                operation_id: operation_id.clone(),
                                                is_done: true,
                                                notification: methods::FollowEvent::OperationError {
                                                    operation_id: operation_id.clone().into(),
                                                    error: "Runtime has called an offchain host function".to_string().into(),
                                                }
                                            }).await;
                                            break;
                                        }
                                        runtime_host::RuntimeHostVm::LogEmit(log) => {
                                            // Logs are ignored. 
                                            runtime_call = log.resume();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(runtime_service::RuntimeCallError::InvalidRuntime(error)) => {
                        let _ = to_main_task.send(OperationEvent {
                            operation_id: operation_id.clone(),
                            is_done: true,
                            notification: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: error.to_string().into(),
                            }
                        }).await;
                    }
                    Err(runtime_service::RuntimeCallError::StorageRetrieval(error)) => {
                        let _ = to_main_task.send(OperationEvent {
                            operation_id: operation_id.clone(),
                            is_done: true,
                            notification: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: error.to_string().into(),
                            }
                        }).await;
                    }
                    Err(runtime_service::RuntimeCallError::MissingProofEntry(_error)) => {
                        let _ = to_main_task.send(OperationEvent {
                            operation_id: operation_id.clone(),
                            is_done: true,
                            notification: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: "incomplete call proof".into(),
                            }
                        }).await;
                    }
                    Err(runtime_service::RuntimeCallError::InvalidChildTrieRoot) => {
                        let _ = to_main_task.send(OperationEvent {
                            operation_id: operation_id.clone(),
                            is_done: true,
                            notification: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: "invalid call proof".into(),
                            }
                        }).await;
                    }
                    Err(runtime_service::RuntimeCallError::CallProof(error)) => {
                        let _ = to_main_task.send(OperationEvent {
                            operation_id: operation_id.clone(),
                            is_done: true,
                            notification: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: error.to_string().into(),
                            }
                        }).await;
                    }
                    Err(runtime_service::RuntimeCallError::StorageQuery(error)) => {
                        let _ = to_main_task.send(OperationEvent {
                            operation_id: operation_id.clone(),
                            is_done: true,
                            notification: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: format!("failed to fetch call proof: {error}").into(),
                            }
                        }).await;
                    }
                }
            }
        });
    }
}
