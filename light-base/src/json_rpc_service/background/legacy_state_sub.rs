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

use core::{
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    time::Duration,
};

use alloc::{borrow::ToOwned as _, boxed::Box, format, string::String, sync::Arc, vec::Vec};
use async_lock::Mutex;
use futures_channel::oneshot;
use futures_lite::{FutureExt as _, StreamExt as _};
use futures_util::{future, stream::AbortRegistration, FutureExt as _};
use smoldot::{
    header,
    informant::HashDisplay,
    json_rpc::{methods, service},
    network::protocol,
};

use crate::{platform::PlatformRef, runtime_service, sync_service};

use super::StateTrieRootHashError;

pub(super) enum Message<TPlat: PlatformRef> {
    SubscriptionStart(service::SubscriptionStartProcess),
    SubscriptionDestroyed {
        subscription_id: String,
    },
    RecentBlockRuntimeAccess {
        block_hash: [u8; 32],
        result_tx: oneshot::Sender<Option<runtime_service::RuntimeAccess<TPlat>>>,
    },
    BlockStateRootAndNumber {
        block_hash: [u8; 32],
        result_tx: oneshot::Sender<Result<([u8; 32], u64), StateTrieRootHashError>>,
    },
    BlockNumber {
        block_hash: [u8; 32],
        result_tx: oneshot::Sender<Option<u64>>,
    },
    BlockHeader {
        block_hash: [u8; 32],
        result_tx: oneshot::Sender<Option<Vec<u8>>>,
    },
}

// Spawn one task dedicated to filling the `Cache` with new blocks from the runtime service.
pub(super) fn start_task<TPlat: PlatformRef>(
    platform: TPlat,
    log_target: String,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    requests_rx: async_channel::Receiver<Message<TPlat>>,
) {
    platform.clone().spawn_task(
        format!("{}-cache", log_target).into(),
        Box::pin(run(Task {
            block_state_root_hashes_numbers: lru::LruCache::with_hasher(
                NonZeroUsize::new(32).unwrap(),
                Default::default(),
            ),
            log_target: log_target.clone(),
            platform: platform.clone(),
            sync_service,
            runtime_service,
            subscription: Subscription::NotCreated,
            requests_rx,
            // TODO: all the subscriptions are dropped if the task returns
            all_heads_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                8,
                Default::default(),
            ),
            new_heads_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                8,
                Default::default(),
            ),
        })),
    );
}

struct Task<TPlat: PlatformRef> {
    /// State trie root hashes and numbers of blocks that were not in
    /// [`Cache::recent_pinned_blocks`].
    ///
    /// The state trie root hash can also be an `Err` if the network request failed or if the
    /// header is of an invalid format.
    ///
    /// The state trie root hash and number are wrapped in a `Shared` future. When multiple
    /// requests need the state trie root hash and number of the same block, they are only queried
    /// once and the query is inserted in the cache while in progress. This way, the multiple
    /// requests can all wait on that single future.
    ///
    /// Most of the time, the JSON-RPC client will query blocks that are found in
    /// [`Cache::recent_pinned_blocks`], but occasionally it will query older blocks. When the
    /// storage of an older block is queried, it is common for the JSON-RPC client to make several
    /// storage requests to that same old block. In order to avoid having to retrieve the state
    /// trie root hash multiple, we store these hashes in this LRU cache.
    block_state_root_hashes_numbers: lru::LruCache<
        [u8; 32],
        future::MaybeDone<
            future::Shared<
                future::BoxFuture<'static, Result<([u8; 32], u64), StateTrieRootHashError>>,
            >,
        >,
        fnv::FnvBuildHasher,
    >,

    log_target: String,
    platform: TPlat,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    subscription: Subscription<TPlat>,
    requests_rx: async_channel::Receiver<Message<TPlat>>,
    // TODO: shrink_to_fit?
    all_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    new_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
}

enum Subscription<TPlat: PlatformRef> {
    Active {
        /// Object representing the subscription.
        subscription: runtime_service::Subscription<TPlat>,

        /// When the runtime service reports a new block, it is kept pinned and inserted in this
        /// LRU cache. When an entry in removed from the cache, it is unpinned.
        ///
        /// JSON-RPC clients are more likely to ask for information about recent blocks and
        /// perform calls on them, hence a cache of recent blocks.
        recent_pinned_blocks: lru::LruCache<[u8; 32], RecentBlock, fnv::FnvBuildHasher>,
    },
    Pending(Pin<Box<dyn Future<Output = runtime_service::SubscribeAll<TPlat>> + Send>>),
    NotCreated,
}

struct RecentBlock {
    scale_encoded_header: Vec<u8>,
}

async fn run<TPlat: PlatformRef>(mut task: Task<TPlat>) {
    loop {
        enum WhatHappened<'a, TPlat: PlatformRef> {
            SubscriptionNotification {
                notification: runtime_service::Notification,
                subscription: &'a mut runtime_service::Subscription<TPlat>,
                recent_pinned_blocks:
                    &'a mut lru::LruCache<[u8; 32], RecentBlock, fnv::FnvBuildHasher>,
            },
            SubscriptionDead,
            SubscriptionReady(runtime_service::SubscribeAll<TPlat>),
            Message(Message<TPlat>),
            ForegroundDead,
        }

        let event = {
            let subscription_event = async {
                match &mut task.subscription {
                    Subscription::NotCreated => WhatHappened::SubscriptionDead,
                    Subscription::Active {
                        subscription,
                        recent_pinned_blocks,
                    } => match subscription.next().await {
                        Some(notification) => WhatHappened::SubscriptionNotification {
                            notification,
                            subscription,
                            recent_pinned_blocks,
                        },
                        None => WhatHappened::SubscriptionDead,
                    },
                    Subscription::Pending(pending) => {
                        WhatHappened::SubscriptionReady(pending.await)
                    }
                }
            };

            let message = async {
                match task.requests_rx.next().await {
                    Some(msg) => WhatHappened::Message(msg),
                    None => WhatHappened::ForegroundDead,
                }
            };

            subscription_event.or(message).await
        };

        match event {
            WhatHappened::SubscriptionReady(subscribe_all) => {
                let mut recent_pinned_blocks =
                    lru::LruCache::with_hasher(NonZeroUsize::new(32).unwrap(), Default::default());

                let finalized_block_hash = header::hash_from_scale_encoded_header(
                    &subscribe_all.finalized_block_scale_encoded_header,
                );
                recent_pinned_blocks.put(
                    finalized_block_hash,
                    RecentBlock {
                        scale_encoded_header: subscribe_all.finalized_block_scale_encoded_header,
                    },
                );

                for block in subscribe_all.non_finalized_blocks_ancestry_order {
                    if recent_pinned_blocks.len() == recent_pinned_blocks.cap().get() {
                        let (hash, _) = recent_pinned_blocks.pop_lru().unwrap();
                        subscribe_all.new_blocks.unpin_block(&hash).await;
                    }

                    let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                    recent_pinned_blocks.put(
                        hash,
                        RecentBlock {
                            scale_encoded_header: block.scale_encoded_header,
                        },
                    );
                }

                task.subscription = Subscription::Active {
                    subscription: subscribe_all.new_blocks,
                    recent_pinned_blocks,
                };
            }

            WhatHappened::SubscriptionNotification {
                notification: runtime_service::Notification::Block(block),
                subscription,
                recent_pinned_blocks,
            } => {
                if recent_pinned_blocks.len() == recent_pinned_blocks.cap().get() {
                    let (hash, _) = recent_pinned_blocks.pop_lru().unwrap();
                    subscription.unpin_block(&hash).await;
                }

                let json_rpc_header = match methods::Header::from_scale_encoded_header(
                    &block.scale_encoded_header,
                    task.runtime_service.block_number_bytes(),
                ) {
                    Ok(h) => h,
                    Err(error) => {
                        log::warn!(
                            target: &task.log_target,
                            "`chain_subscribeAllHeads` or `chain_subscribeNewHeads` subscription \
                            has skipped block due to undecodable header. Hash: {}. Error: {}",
                            HashDisplay(&header::hash_from_scale_encoded_header(
                                &block.scale_encoded_header
                            )),
                            error,
                        );
                        continue;
                    }
                };

                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                recent_pinned_blocks.put(
                    hash,
                    RecentBlock {
                        scale_encoded_header: block.scale_encoded_header,
                    },
                );

                for (subscription_id, subscription) in &mut task.all_heads_subscriptions {
                    subscription
                        .send_notification(methods::ServerToClient::chain_allHead {
                            subscription: subscription_id.as_str().into(),
                            result: json_rpc_header.clone(),
                        })
                        .await;
                }

                if block.is_new_best {
                    for (subscription_id, subscription) in &mut task.new_heads_subscriptions {
                        subscription
                            .send_notification(methods::ServerToClient::chain_newHead {
                                subscription: subscription_id.as_str().into(),
                                result: json_rpc_header.clone(),
                            })
                            .await;
                    }
                }
            }
            WhatHappened::SubscriptionNotification {
                notification: runtime_service::Notification::Finalized { .. },
                ..
            } => {}
            WhatHappened::SubscriptionNotification {
                notification: runtime_service::Notification::BestBlockChanged { hash, .. },
                ..
            } => {
                // TODO: report a chain_newHead subscription
            }

            WhatHappened::Message(Message::SubscriptionStart(request)) => match request.request() {
                methods::MethodCall::chain_subscribeAllHeads {} => {
                    let subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    task.all_heads_subscriptions
                        .insert(subscription_id, subscription);
                }
                methods::MethodCall::chain_subscribeNewHeads {} => {
                    let subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    // TODO: must immediately send the current best block
                    task.new_heads_subscriptions
                        .insert(subscription_id, subscription);
                }
                _ => unreachable!(), // TODO: stronger typing to avoid this?
            },

            WhatHappened::Message(Message::SubscriptionDestroyed { subscription_id }) => {
                task.all_heads_subscriptions.remove(&subscription_id);
                task.new_heads_subscriptions.remove(&subscription_id);
                // TODO: shrink_to_fit?
            }

            WhatHappened::Message(Message::RecentBlockRuntimeAccess {
                block_hash,
                result_tx,
            }) => {
                let subscription_id_with_block = if let Subscription::Active {
                    recent_pinned_blocks,
                    subscription,
                    ..
                } = &task.subscription
                {
                    if recent_pinned_blocks.contains(&block_hash) {
                        // The runtime service has the block pinned, meaning that we can ask the runtime
                        // service to perform the call.
                        Some(subscription.id())
                    } else {
                        None
                    }
                } else {
                    None
                };

                let access = if let Some(subscription_id) = subscription_id_with_block {
                    task.runtime_service
                        .pinned_block_runtime_access(subscription_id, &block_hash)
                        .await
                        .ok()
                } else {
                    None
                };

                let _ = result_tx.send(access);
            }

            WhatHappened::Message(Message::BlockNumber {
                block_hash,
                result_tx,
            }) => {
                if let Some(future) = task.block_state_root_hashes_numbers.get_mut(&block_hash) {
                    let _ = future.now_or_never();
                }

                let block_number = if let Subscription::Active {
                    recent_pinned_blocks,
                    ..
                } = &mut task.subscription
                {
                    match (
                        recent_pinned_blocks.get(&block_hash).map(|b| {
                            header::decode(
                                &b.scale_encoded_header,
                                task.runtime_service.block_number_bytes(),
                            )
                        }),
                        task.block_state_root_hashes_numbers.get(&block_hash),
                    ) {
                        (Some(Ok(header)), _) => Some(header.number),
                        (_, Some(future::MaybeDone::Done(Ok((_, num))))) => Some(*num),
                        _ => None,
                    }
                } else {
                    None
                };

                let _ = result_tx.send(block_number);
            }

            WhatHappened::Message(Message::BlockHeader {
                block_hash,
                result_tx,
            }) => {
                let header = if let Subscription::Active {
                    recent_pinned_blocks,
                    ..
                } = &mut task.subscription
                {
                    if let Some(block) = recent_pinned_blocks.get(&block_hash) {
                        Some(block.scale_encoded_header.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };

                let _ = result_tx.send(header);
            }

            WhatHappened::Message(Message::BlockStateRootAndNumber {
                block_hash,
                result_tx,
            }) => {
                let fetch = {
                    // Try to find an existing entry in cache, and if not create one.

                    // Look in `recent_pinned_blocks`.
                    if let Subscription::Active {
                        recent_pinned_blocks,
                        ..
                    } = &mut task.subscription
                    {
                        match recent_pinned_blocks.get(&block_hash).map(|b| {
                            header::decode(
                                &b.scale_encoded_header,
                                task.runtime_service.block_number_bytes(),
                            )
                        }) {
                            Some(Ok(header)) => {
                                let _ = result_tx.send(Ok((*header.state_root, header.number)));
                                continue;
                            }
                            Some(Err(err)) => {
                                let _ = result_tx
                                    .send(Err(StateTrieRootHashError::HeaderDecodeError(err)));
                                continue;
                            } // TODO: can this actually happen? unclear
                            None => {}
                        }
                    }

                    // Look in `block_state_root_hashes`.
                    match task.block_state_root_hashes_numbers.get(&block_hash) {
                        Some(future::MaybeDone::Done(Ok(val))) => {
                            let _ = result_tx.send(Ok(*val));
                            continue;
                        }
                        Some(future::MaybeDone::Future(f)) => f.clone(),
                        Some(future::MaybeDone::Gone) => unreachable!(), // We never use `Gone`.
                        Some(future::MaybeDone::Done(Err(
                            err @ StateTrieRootHashError::HeaderDecodeError(_),
                        ))) => {
                            // In case of a fatal error, return immediately.
                            let _ = result_tx.send(Err(err.clone()));
                            continue;
                        }
                        Some(future::MaybeDone::Done(Err(
                            StateTrieRootHashError::NetworkQueryError,
                        )))
                        | None => {
                            // No existing cache entry. Create the future that will perform the fetch
                            // but do not actually start doing anything now.
                            let fetch = {
                                let sync_service = task.sync_service.clone();
                                async move {
                                    // The sync service knows which peers are potentially aware of
                                    // this block.
                                    let result = sync_service
                                        .clone()
                                        .block_query_unknown_number(
                                            block_hash,
                                            protocol::BlocksRequestFields {
                                                header: true,
                                                body: false,
                                                justifications: false,
                                            },
                                            4,
                                            Duration::from_secs(8),
                                            NonZeroU32::new(2).unwrap(),
                                        )
                                        .await;

                                    if let Ok(block) = result {
                                        // If successful, the `block_query` function guarantees that the
                                        // header is present and valid.
                                        let header = block.header.unwrap();
                                        debug_assert_eq!(
                                            header::hash_from_scale_encoded_header(&header),
                                            block_hash
                                        );
                                        let decoded = header::decode(
                                            &header,
                                            sync_service.block_number_bytes(),
                                        )
                                        .unwrap();
                                        Ok((*decoded.state_root, decoded.number))
                                    } else {
                                        // TODO: better error details?
                                        Err(StateTrieRootHashError::NetworkQueryError)
                                    }
                                }
                            };

                            // Insert the future in the cache, so that any other call will use the same
                            // future.
                            let wrapped = (Box::pin(fetch)
                                as Pin<Box<dyn Future<Output = _> + Send>>)
                                .shared();
                            task.block_state_root_hashes_numbers
                                .put(block_hash, future::maybe_done(wrapped.clone()));
                            wrapped
                        }
                    }
                };

                // We await separately to be certain that the lock isn't held anymore.
                // TODO: crappy design
                task.platform
                    .spawn_task("dummy-adapter".into(), async move {
                        let outcome = fetch.await;
                        let _ = result_tx.send(outcome);
                    });
            }

            WhatHappened::ForegroundDead => {
                break;
            }

            WhatHappened::SubscriptionDead => {
                // Subscribe to new runtime service blocks in order to push them in the
                // cache as soon as they are available.
                // The buffer size should be large enough so that, if the CPU is busy, it
                // doesn't become full before the execution of this task resumes.
                // The maximum number of pinned block is ignored, as this maximum is a way to
                // avoid malicious behaviors. This code is by definition not considered
                // malicious.
                let runtime_service = task.runtime_service.clone();
                task.subscription = Subscription::Pending(Box::pin(async move {
                    runtime_service
                        .subscribe_all(
                            "json-rpc-blocks-cache",
                            32,
                            NonZeroUsize::new(usize::max_value()).unwrap(),
                        )
                        .await
                }));
            }
        }
    }
}
