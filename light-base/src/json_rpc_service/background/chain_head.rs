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
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use core::{
    cmp, iter,
    num::{NonZeroU32, NonZeroUsize},
    pin,
    time::Duration,
};
use futures_channel::mpsc;
use futures_lite::FutureExt as _;
use futures_util::{future, FutureExt as _, StreamExt as _};
use hashbrown::HashMap;
use smoldot::{
    chain::fork_tree,
    executor::{self, runtime_host},
    header,
    json_rpc::{self, methods, service},
    network::protocol,
};

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::chainHead_unstable_call`].
    pub(super) async fn chain_head_call(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_call { follow_subscription, .. } = request.request()
            else { unreachable!() };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            match sender.deliver(either::Right(request)).await {
                Ok(()) => Ok(()),
                Err(either::Right(v)) => Err(v),
                Err(either::Left(_)) => unreachable!(),
            }
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            let mut subscription = request.accept();
            let subscription_id = subscription.subscription_id().to_owned();
            subscription
                .send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                    subscription: (&subscription_id).into(),
                    result: methods::ChainHeadCallEvent::Disjoint {},
                })
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_follow`].
    pub(super) async fn chain_head_follow(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_follow { with_runtime } = request.request()
            else { unreachable!() };

        let events = if with_runtime {
            let subscribe_all = self
                .runtime_service
                .subscribe_all("chainHead_follow", 32, NonZeroUsize::new(32).unwrap())
                .await;
            let id = subscribe_all.new_blocks.id();
            either::Left((subscribe_all, id))
        } else {
            either::Right(self.sync_service.subscribe_all(32, false).await)
        };

        let (mut subscription, rx) = {
            let (tx, rx) = service::deliver_channel();
            let mut lock = self.chain_head_follow_tasks.lock().await;
            let subscription = request.accept();
            lock.insert(subscription.subscription_id().to_owned(), tx);
            (subscription, rx)
        };
        let subscription_id = subscription.subscription_id().to_owned();

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

                ChainHeadFollowTask {
                    platform,
                    non_finalized_blocks,
                    pinned_blocks_headers,
                    subscription: match events {
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
                .run(subscription, subscription_id, rx)
            });
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storage`].
    pub(super) async fn chain_head_storage(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_storage { follow_subscription, .. } = request.request()
            else { unreachable!() };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            match sender.deliver(either::Right(request)).await {
                Ok(()) => Ok(()),
                Err(either::Right(v)) => Err(v),
                Err(either::Left(_)) => unreachable!(),
            }
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            let mut subscription = request.accept();
            let subscription_id = subscription.subscription_id().to_owned();
            subscription
                .send_notification(methods::ServerToClient::chainHead_unstable_storageEvent {
                    subscription: (&subscription_id).into(),
                    result: methods::ChainHeadStorageEvent::Disjoint {},
                })
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_storageContinue`].
    pub(super) async fn chain_head_storage_continue(
        self: &Arc<Self>,
        request: service::RequestProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_storageContinue { .. } = request.request()
            else { unreachable!() };
        // TODO: not implemented properly
        request.respond(methods::Response::chainHead_unstable_storageContinue(()));
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_body`].
    pub(super) async fn chain_head_unstable_body(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_body { follow_subscription, .. } = request.request()
            else { unreachable!() };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            match sender.deliver(either::Right(request)).await {
                Ok(()) => Ok(()),
                Err(either::Right(v)) => Err(v),
                Err(either::Left(_)) => unreachable!(),
            }
        } else {
            Err(request)
        };

        if let Err(request) = send_outcome {
            let mut subscription = request.accept();
            let subscription_id = subscription.subscription_id().to_owned();
            subscription
                .send_notification(methods::ServerToClient::chainHead_unstable_bodyEvent {
                    subscription: (&subscription_id).into(),
                    result: methods::ChainHeadBodyEvent::Disjoint {},
                })
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chainHead_unstable_header`].
    pub(super) async fn chain_head_unstable_header(
        self: &Arc<Self>,
        request: service::RequestProcess,
    ) {
        let methods::MethodCall::chainHead_unstable_header { follow_subscription, .. } = request.request()
            else { unreachable!() };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            match sender.deliver(either::Left(request)).await {
                Ok(()) => Ok(()),
                Err(either::Left(v)) => Err(v),
                Err(either::Right(_)) => unreachable!(),
            }
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
        let methods::MethodCall::chainHead_unstable_unpin { follow_subscription, .. } = request.request()
            else { unreachable!() };

        // This is implemented by sending a message to the notifications task.
        // The task dedicated to this subscription will receive the message and send a response to
        // the JSON-RPC client.
        let mut lock = self.chain_head_follow_tasks.lock().await;

        let send_outcome = if let Some(sender) = lock.get_mut(&*follow_subscription) {
            match sender.deliver(either::Left(request)).await {
                Ok(()) => Ok(()),
                Err(either::Left(v)) => Err(v),
                Err(either::Right(_)) => unreachable!(),
            }
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

    platform: TPlat,

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
        mut subscription: service::Subscription,
        subscription_id: String,
        mut messages_rx: service::DeliverReceiver<
            either::Either<service::RequestProcess, service::SubscriptionStartProcess>,
        >,
    ) {
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

                match future::select(
                    future::select(next_block, next_message),
                    pin::pin!(subscription.wait_until_stale()),
                )
                .await
                {
                    future::Either::Left((future::Either::Left((v, _)), _)) => either::Left(v),
                    future::Either::Left((future::Either::Right((v, _)), _)) => either::Right(v),
                    future::Either::Right(((), _)) => return,
                }
            };

            // TODO: doesn't enforce any maximum number of pinned blocks
            match outcome {
                either::Left(either::Left(None) | either::Right(None)) => {
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
                either::Left(
                    either::Left(Some(runtime_service::Notification::BestBlockChanged { hash }))
                    | either::Right(Some(sync_service::Notification::BestBlockChanged { hash })),
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
                either::Right(Some(message)) => self.on_foreground_message(message).await,
                either::Right(None) => unreachable!(), // TODO: really unreachable?
            }
        }
    }

    async fn on_foreground_message(
        &mut self,
        message: either::Either<service::RequestProcess, service::SubscriptionStartProcess>,
    ) {
        match message {
            either::Left(request) => match request.request() {
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
                    hash,
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
                        request.respond(methods::Response::chainHead_unstable_unpin(()));
                    } else {
                        request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                    }
                }
                _ => unreachable!(),
            },
            either::Right(request) => match request.request() {
                methods::MethodCall::chainHead_unstable_body { .. } => {
                    self.start_chain_head_body(request).await;
                }
                methods::MethodCall::chainHead_unstable_storage { .. } => {
                    self.start_chain_head_storage(request).await;
                }
                methods::MethodCall::chainHead_unstable_call { .. } => {
                    self.start_chain_head_call(request).await;
                }
                _ => unreachable!(),
            },
        }
    }

    async fn start_chain_head_body(&mut self, request: service::SubscriptionStartProcess) {
        let methods::MethodCall::chainHead_unstable_body { hash, network_config, .. } = request.request()
            else { unreachable!() };

        // Determine whether the requested block hash is valid, and if yes its number.
        let block_number = {
            if let Some(header) = self.pinned_blocks_headers.get(&hash.0) {
                let decoded =
                    header::decode(header, self.sync_service.block_number_bytes()).unwrap(); // TODO: unwrap?
                Some(decoded.number)
            } else {
                request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                return;
            }
        };

        let network_config = network_config.unwrap_or(methods::NetworkConfig {
            max_parallel: 1,
            timeout_ms: 4000,
            total_attempts: 3,
        });

        let mut subscription = request.accept();
        let subscription_id = subscription.subscription_id().to_owned();

        self.platform
            .spawn_task(format!("{}-chain-head-body", self.log_target).into(), {
                let sync_service = self.sync_service.clone();

                async move {
                    if let Some(block_number) = block_number {
                        // TODO: right now we query the header because the underlying function returns an error if we don't
                        let future = sync_service.clone().block_query(
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

                        let outcome = match future
                            .map(Some)
                            .race(subscription.wait_until_stale().map(|()| None))
                            .await
                        {
                            Some(v) => v,
                            None => return, // JSON-RPC client has unsubscribed in the meanwhile.
                        };

                        match outcome {
                            Ok(block_data) => {
                                subscription
                                    .send_notification(
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
                                        },
                                    )
                                    .await;
                            }
                            Err(()) => {
                                subscription
                                    .send_notification(
                                        methods::ServerToClient::chainHead_unstable_bodyEvent {
                                            subscription: (&subscription_id).into(),
                                            result: methods::ChainHeadBodyEvent::Inaccessible {},
                                        },
                                    )
                                    .await;
                            }
                        }
                    } else {
                        subscription
                            .send_notification(
                                methods::ServerToClient::chainHead_unstable_bodyEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadBodyEvent::Disjoint {},
                                },
                            )
                            .await;
                    }
                }
            });
    }

    async fn start_chain_head_storage(&mut self, request: service::SubscriptionStartProcess) {
        let methods::MethodCall::chainHead_unstable_storage {
            hash,
            key,
            child_trie,
            ty,
            network_config,
            ..
        } = request.request()
            else { unreachable!() };

        // Obtain the header of the requested block.
        // Contains `None` if the subscription is disjoint.
        let block_scale_encoded_header = {
            if let Some(header) = self.pinned_blocks_headers.get(&hash.0) {
                Some(header.clone())
            } else {
                request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                return;
            }
        };

        let network_config = network_config.unwrap_or(methods::NetworkConfig {
            max_parallel: 1,
            timeout_ms: 8000,
            total_attempts: 3,
        });

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

        let is_hash = match ty {
            methods::ChainHeadStorageType::Value => false,
            methods::ChainHeadStorageType::Hash => true,
            methods::ChainHeadStorageType::DescendantsValues
            | methods::ChainHeadStorageType::DescendantsHashes
            | methods::ChainHeadStorageType::ClosestAncestorMerkleValue => {
                // TODO: implement this
                request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    "Child key storage queries not supported yet",
                ));
                log::warn!(
                    target: &self.log_target,
                    "chainHead_unstable_storage has been called with a type other than value or hash. \
                    This isn't supported by smoldot yet."
                );
                return;
            }
        };

        let mut subscription = request.accept();
        let subscription_id = subscription.subscription_id().to_owned();

        self.platform
            .spawn_task(format!("{}-chain-head-storage", self.log_target).into(), {
            let sync_service = self.sync_service.clone();
            async move {
                match block_scale_encoded_header
                    .as_ref()
                    .map(|h| header::decode(h, sync_service.block_number_bytes()))
                {
                    Some(Ok(decoded_header)) => {
                        let future = sync_service.clone().storage_query(
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
                        );

                        let outcome = match future
                            .map(Some)
                            .race(subscription.wait_until_stale().map(|()| None))
                            .await
                        {
                            Some(v) => v,
                            None => return,  // JSON-RPC client has unsubscribed in the meanwhile.
                        };

                        match outcome {
                            Ok(values) => {
                                // `storage_query` returns a list of values because it can perform
                                // multiple queries at once. In our situation, we only start one query
                                // and as such the outcome only ever contains one element.
                                debug_assert_eq!(values.len(), 1);
                                let value = values.into_iter().next().unwrap();
                                if let Some(mut value) = value {
                                    if is_hash {
                                        value = blake2_rfc::blake2b::blake2b(8, &[], &value).as_bytes().to_vec();
                                    }

                                    subscription.send_notification(methods::ServerToClient::chainHead_unstable_storageEvent {
                                        subscription: (&subscription_id).into(),
                                        result: methods::ChainHeadStorageEvent::Item {
                                            key,
                                            value: Some(methods::HexString(value)),
                                            hash: None,
                                            merkle_value: None,
                                        },
                                    }).await;
                                }

                                subscription.send_notification(methods::ServerToClient::chainHead_unstable_storageEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadStorageEvent::Done,
                                }).await;
                            }
                            Err(_) => {
                                subscription.send_notification(methods::ServerToClient::chainHead_unstable_storageEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadStorageEvent::Inaccessible {},
                                }).await;
                            }
                        }
                    }
                    Some(Err(err)) => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_storageEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadStorageEvent::Error {
                                error: err.to_string().into(),
                            },
                        }).await;
                    }
                    None => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_storageEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadStorageEvent::Disjoint {},
                        }).await;
                    }
                };
            }
        });
    }

    async fn start_chain_head_call(&mut self, request: service::SubscriptionStartProcess) {
        let (hash, function_to_call, call_parameters, network_config) = {
            let methods::MethodCall::chainHead_unstable_call {
                hash,
                function,
                call_parameters,
                network_config,
                ..
            } = request.request()
                else { unreachable!() };

            let network_config = network_config.unwrap_or(methods::NetworkConfig {
                max_parallel: 1,
                timeout_ms: 8000,
                total_attempts: 3,
            });

            (
                hash,
                function.into_owned(),
                call_parameters.0,
                network_config,
            )
        };

        // Determine whether the requested block hash is valid and start the call.
        let pre_runtime_call = match self.subscription {
            Subscription::WithRuntime {
                subscription_id, ..
            } => {
                if !self.pinned_blocks_headers.contains_key(&hash.0) {
                    request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                    return;
                }

                self.runtime_service
                    .pinned_block_runtime_access(subscription_id, &hash.0)
                    .await
                    .ok()
            }
            Subscription::WithoutRuntime(_) => {
                request.fail(json_rpc::parse::ErrorResponse::InvalidParams);
                return;
            }
        };

        let mut subscription = request.accept();
        let subscription_id = subscription.subscription_id().to_owned();

        self.platform
            .spawn_task(format!("{}-chain-head-call", self.log_target).into(), {
            async move {
                let pre_runtime_call = if let Some(pre_runtime_call) = &pre_runtime_call {
                    let call_future = pre_runtime_call.start(
                        &function_to_call,
                        iter::once(&call_parameters),
                        cmp::min(10, network_config.total_attempts),
                        Duration::from_millis(u64::from(cmp::min(
                            20000,
                            network_config.timeout_ms,
                        ))),
                        NonZeroU32::new(network_config.max_parallel.clamp(1, 5)).unwrap(),
                    );

                    match call_future.map(Some).race(subscription.wait_until_stale().map(|()| None)).await {
                        Some(v) => Some(v),
                        None => return  // JSON-RPC client has unsubscribed in the meanwhile.
                    }
                } else {
                    None
                };

                match pre_runtime_call {
                    Some(Ok((runtime_call_lock, virtual_machine))) => {
                        match runtime_host::run(runtime_host::Config {
                            virtual_machine,
                            function_to_call: &function_to_call,
                            parameter: iter::once(&call_parameters),
                            offchain_storage_changes: Default::default(),
                            storage_main_trie_changes: Default::default(),
                            max_log_level: 0,
                        }) {
                            Err((error, prototype)) => {
                                runtime_call_lock.unlock(prototype);
                                subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::ChainHeadCallEvent::Error {
                                        error: error.to_string().into(),
                                    },
                                }).await;
                            }
                            Ok(mut runtime_call) => {
                                loop {
                                    match runtime_call {
                                        runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                                            let output =
                                                success.virtual_machine.value().as_ref().to_owned();
                                            runtime_call_lock
                                                .unlock(success.virtual_machine.into_prototype());
                                            subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                                                subscription: (&subscription_id).into(),
                                                result: methods::ChainHeadCallEvent::Done {
                                                    output: methods::HexString(output),
                                                },
                                            }).await;
                                            break;
                                        }
                                        runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                                            runtime_call_lock.unlock(error.prototype);
                                            subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                                                subscription: (&subscription_id).into(),
                                                result: methods::ChainHeadCallEvent::Error {
                                                    error: error.detail.to_string().into(),
                                                },
                                            }).await;
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
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::StorageGet(
                                                            get,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                                                        subscription: (&subscription_id).into(),
                                                        result: methods::ChainHeadCallEvent::Inaccessible {
                                                            error: error.to_string().into(),
                                                        },
                                                    }).await;
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
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::ClosestDescendantMerkleValue(
                                                            mv,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                                                        subscription: (&subscription_id).into(),
                                                        result: methods::ChainHeadCallEvent::Inaccessible {
                                                            error: error.to_string().into(),
                                                        },
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
                                                Err(error) => {
                                                    runtime_call_lock.unlock(
                                                        runtime_host::RuntimeHostVm::NextKey(
                                                            nk,
                                                        )
                                                        .into_prototype(),
                                                    );
                                                    subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                                                        subscription: (&subscription_id).into(),
                                                        result: methods::ChainHeadCallEvent::Inaccessible {
                                                            error: error.to_string().into(),
                                                        },
                                                    }).await;
                                                    break;
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
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: error.to_string().into(),
                            },
                        }).await;
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageRetrieval(error))) => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: error.to_string().into(),
                            },
                        }).await;
                    }
                    Some(Err(runtime_service::RuntimeCallError::MissingProofEntry(_error))) => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: "incomplete call proof".into(),
                            },
                        }).await;
                    }
                    Some(Err(runtime_service::RuntimeCallError::InvalidChildTrieRoot)) => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: "invalid call proof".into(),
                            },
                        }).await;
                    }
                    Some(Err(runtime_service::RuntimeCallError::CallProof(error))) => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: error.to_string().into(),
                            },
                        }).await
                    }
                    Some(Err(runtime_service::RuntimeCallError::StorageQuery(error))) => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Error {
                                error: format!("failed to fetch call proof: {error}").into(),
                            },
                        }).await;
                    }
                    None => {
                        subscription.send_notification(methods::ServerToClient::chainHead_unstable_callEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::ChainHeadCallEvent::Disjoint {},
                        }).await
                    },
                }
            }
        });
    }
}
