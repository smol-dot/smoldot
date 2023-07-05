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
    iter,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    time::Duration,
};

use alloc::{
    borrow::ToOwned as _, boxed::Box, collections::BTreeSet, format, string::String, sync::Arc,
    vec::Vec,
};
use futures_channel::oneshot;
use futures_lite::{FutureExt as _, StreamExt as _};
use futures_util::{future, FutureExt as _};
use smoldot::{
    executor, header,
    informant::HashDisplay,
    json_rpc::{self, methods, service},
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
    CurrentBestBlockHash {
        result_tx: oneshot::Sender<[u8; 32]>,
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
    StorageFetch {
        block_hash: [u8; 32],
        result: Result<Vec<sync_service::StorageResultItem>, sync_service::StorageQueryError>,
    },
}

// Spawn one task dedicated to filling the `Cache` with new blocks from the runtime service.
// TODO: weird to pass both the sender and receiver
pub(super) fn start_task<TPlat: PlatformRef>(
    platform: TPlat,
    log_target: String,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    requests_tx: async_channel::Sender<Message<TPlat>>,
    requests_rx: async_channel::Receiver<Message<TPlat>>,
) {
    let requests_tx = async_channel::Sender::downgrade(&requests_tx);

    platform.clone().spawn_task(
        format!("{}-cache", log_target).into(),
        Box::pin(run(Task {
            block_state_root_hashes_numbers: lru::LruCache::with_hasher(
                NonZeroUsize::new(32).unwrap(),
                Default::default(),
            ),
            log_target: log_target.clone(),
            platform: platform.clone(),
            best_block_report: Vec::with_capacity(4),
            sync_service,
            runtime_service,
            subscription: Subscription::NotCreated,
            requests_tx,
            requests_rx,
            all_heads_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                2,
                Default::default(),
            ),
            new_heads_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                2,
                Default::default(),
            ),
            finalized_heads_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                2,
                Default::default(),
            ),
            runtime_version_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                2,
                Default::default(),
            ),
            storage_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                16,
                Default::default(),
            ),
            storage_subscriptions_by_key: hashbrown::HashMap::with_capacity_and_hasher(
                16,
                crate::util::SipHasherBuild::new([0; 16]), // TODO: proper seed
            ),
            stale_storage_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
                16,
                Default::default(),
            ),
            storage_query_in_progress: false,
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
    best_block_report: Vec<oneshot::Sender<[u8; 32]>>,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    subscription: Subscription<TPlat>,
    /// Sending side of [`Task::requests_rx`].
    requests_tx: async_channel::WeakSender<Message<TPlat>>,
    requests_rx: async_channel::Receiver<Message<TPlat>>,
    // TODO: shrink_to_fit?
    all_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    new_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    finalized_heads_subscriptions:
        hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    runtime_version_subscriptions:
        hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    storage_subscriptions:
        hashbrown::HashMap<String, (service::Subscription, Vec<Vec<u8>>), fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    storage_subscriptions_by_key: hashbrown::HashMap<
        Vec<u8>,
        hashbrown::HashSet<String, fnv::FnvBuildHasher>,
        crate::util::SipHasherBuild,
    >,
    /// List of storage subscriptions whose latest sent notification isn't about the current
    /// best block.
    stale_storage_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,

    /// `true` if there exists a background task currently fetching storage items for storage
    /// subscriptions. This task will send a [`Message::StorageFetch`] once it's finished.
    storage_query_in_progress: bool,
}

enum Subscription<TPlat: PlatformRef> {
    Active {
        /// Object representing the subscription.
        subscription: runtime_service::Subscription<TPlat>,

        /// Hash of the current best block. Guaranteed to be in
        /// [`Subscription::Active::pinned_blocks`].
        current_best_block: [u8; 32],

        /// Hash of the current finalized block. Guaranteed to be in
        /// [`Subscription::Active::pinned_blocks`].
        current_finalized_block: [u8; 32],

        /// When the runtime service reports a new block, it is kept pinned and inserted in this
        /// list.
        ///
        /// Blocks are removed from this container and unpinned when they leave
        /// [`Subscription::Active::finalized_and_pruned_lru`].
        ///
        /// JSON-RPC clients are more likely to ask for information about recent blocks and
        /// perform calls on them, hence a cache of recent blocks.
        pinned_blocks: hashbrown::HashMap<[u8; 32], RecentBlock, fnv::FnvBuildHasher>,

        /// When a block is finalized or pruned, it is inserted into this LRU cache. The least
        /// recently used blocks are removed and unpinned.
        finalized_and_pruned_lru: lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>,
    },
    Pending(Pin<Box<dyn Future<Output = runtime_service::SubscribeAll<TPlat>> + Send>>),
    NotCreated,
}

struct RecentBlock {
    scale_encoded_header: Vec<u8>,
    // TODO: do we really need to keep the runtime version here, given that the block is still pinned in the runtime service?
    runtime_version: Arc<Result<executor::CoreVersion, runtime_service::RuntimeError>>,
}

async fn run<TPlat: PlatformRef>(mut task: Task<TPlat>) {
    loop {
        if let Subscription::Active {
            pinned_blocks,
            current_best_block,
            ..
        } = &task.subscription
        {
            while let Some(sender) = task.best_block_report.pop() {
                let _ = sender.send(*current_best_block);
            }
            task.best_block_report.shrink_to_fit();

            if !task.storage_query_in_progress && !task.stale_storage_subscriptions.is_empty() {
                let (block_number, state_trie_root) = match header::decode(
                    &pinned_blocks
                        .get(current_best_block)
                        .unwrap()
                        .scale_encoded_header,
                    task.runtime_service.block_number_bytes(),
                ) {
                    Ok(header) => (header.number, *header.state_root),
                    Err(_) => {
                        // Can't decode the header of the current best block.
                        // All the subscriptions are marked as non-stale, since they are up-to-date
                        // with the current best block.
                        // TODO: print warning?
                        task.stale_storage_subscriptions.clear();
                        continue;
                    }
                };

                task.storage_query_in_progress = true;

                let mut keys =
                    hashbrown::HashSet::with_hasher(crate::util::SipHasherBuild::new([0; 16])); // TODO: proper seed
                keys.extend(
                    task.stale_storage_subscriptions
                        .iter()
                        .map(|s_id| &task.storage_subscriptions.get(s_id).unwrap().1)
                        .flat_map(|keys_list| keys_list.iter().cloned()),
                );

                task.platform.spawn_task(
                    format!("{}-storage-subscriptions-fetch", task.log_target).into(),
                    Box::pin({
                        let block_hash = current_best_block.clone();
                        let sync_service = task.sync_service.clone();
                        // TODO: a bit overcomplicated because `WeakSender` doesn't implement `Clone`: https://github.com/smol-rs/async-channel/pull/62
                        let requests_tx = async_channel::Sender::downgrade(
                            &task.requests_tx.upgrade().unwrap().clone(),
                        );
                        async move {
                            let result = sync_service
                                .clone()
                                .storage_query(
                                    block_number,
                                    &block_hash,
                                    &state_trie_root,
                                    keys.into_iter()
                                        .map(|key| sync_service::StorageRequestItem {
                                            key,
                                            ty: sync_service::StorageRequestItemTy::Value,
                                        }),
                                    4,
                                    Duration::from_secs(12),
                                    NonZeroU32::new(2).unwrap(),
                                )
                                .await;
                            if let Some(requests_tx) = requests_tx.upgrade() {
                                let _ = requests_tx
                                    .send(Message::StorageFetch { block_hash, result })
                                    .await;
                            }
                        }
                    }),
                );
            }
        }

        enum WhatHappened<'a, TPlat: PlatformRef> {
            SubscriptionNotification {
                notification: runtime_service::Notification,
                subscription: &'a mut runtime_service::Subscription<TPlat>,
                pinned_blocks:
                    &'a mut hashbrown::HashMap<[u8; 32], RecentBlock, fnv::FnvBuildHasher>,
                finalized_and_pruned_lru: &'a mut lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>,
                current_best_block: &'a mut [u8; 32],
                current_finalized_block: &'a mut [u8; 32],
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
                        pinned_blocks,
                        finalized_and_pruned_lru,
                        current_best_block,
                        current_finalized_block,
                    } => match subscription.next().await {
                        Some(notification) => WhatHappened::SubscriptionNotification {
                            notification,
                            subscription,
                            pinned_blocks,
                            finalized_and_pruned_lru,
                            current_best_block,
                            current_finalized_block,
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
                let mut pinned_blocks =
                    hashbrown::HashMap::with_capacity_and_hasher(32, Default::default());
                let mut finalized_and_pruned_lru = lru::LruCache::with_hasher(
                    NonZeroUsize::new(32).unwrap(),
                    fnv::FnvBuildHasher::default(),
                );

                let finalized_block_hash = header::hash_from_scale_encoded_header(
                    &subscribe_all.finalized_block_scale_encoded_header,
                );
                pinned_blocks.insert(
                    finalized_block_hash,
                    RecentBlock {
                        scale_encoded_header: subscribe_all.finalized_block_scale_encoded_header,
                        runtime_version: Arc::new(subscribe_all.finalized_block_runtime),
                    },
                );
                finalized_and_pruned_lru.put(finalized_block_hash, ());

                let mut current_best_block = finalized_block_hash;

                for block in subscribe_all.non_finalized_blocks_ancestry_order {
                    let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                    pinned_blocks.insert(
                        hash,
                        RecentBlock {
                            scale_encoded_header: block.scale_encoded_header,
                            runtime_version: match block.new_runtime {
                                Some(r) => Arc::new(r),
                                None => pinned_blocks
                                    .get(&block.parent_hash)
                                    .unwrap()
                                    .runtime_version
                                    .clone(),
                            },
                        },
                    );

                    if block.is_new_best {
                        current_best_block = hash;
                    }
                }

                task.stale_storage_subscriptions
                    .extend(task.storage_subscriptions.keys().cloned());

                task.subscription = Subscription::Active {
                    subscription: subscribe_all.new_blocks,
                    pinned_blocks,
                    finalized_and_pruned_lru,
                    current_best_block,
                    current_finalized_block: finalized_block_hash,
                };
            }

            WhatHappened::SubscriptionNotification {
                notification: runtime_service::Notification::Block(block),
                pinned_blocks,
                current_best_block,
                ..
            } => {
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
                pinned_blocks.insert(
                    hash,
                    RecentBlock {
                        scale_encoded_header: block.scale_encoded_header,
                        runtime_version: match block.new_runtime {
                            Some(r) => Arc::new(r),
                            None => pinned_blocks
                                .get(&block.parent_hash)
                                .unwrap()
                                .runtime_version
                                .clone(),
                        },
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

                    let new_best_runtime = &pinned_blocks.get(&hash).unwrap().runtime_version;
                    if !Arc::ptr_eq(
                        new_best_runtime,
                        &pinned_blocks
                            .get(current_best_block)
                            .unwrap()
                            .runtime_version,
                    ) {
                        for (subscription_id, subscription) in
                            &mut task.runtime_version_subscriptions
                        {
                            subscription
                                .send_notification(methods::ServerToClient::state_runtimeVersion {
                                    subscription: subscription_id.as_str().into(),
                                    result: convert_runtime_version(new_best_runtime),
                                })
                                .await;
                        }
                    }

                    task.stale_storage_subscriptions
                        .extend(task.storage_subscriptions.keys().cloned());

                    *current_best_block = hash;
                }
            }

            WhatHappened::SubscriptionNotification {
                notification:
                    runtime_service::Notification::Finalized {
                        hash: finalized_hash,
                        pruned_blocks,
                        best_block_hash: new_best_block_hash,
                    },
                pinned_blocks,
                finalized_and_pruned_lru,
                subscription,
                current_best_block,
                current_finalized_block,
            } => {
                *current_finalized_block = finalized_hash;

                let finalized_block_header = &pinned_blocks
                    .get(&finalized_hash)
                    .unwrap()
                    .scale_encoded_header;
                let finalized_block_json_rpc_header =
                    match methods::Header::from_scale_encoded_header(
                        finalized_block_header,
                        task.runtime_service.block_number_bytes(),
                    ) {
                        Ok(h) => h,
                        Err(error) => {
                            log::warn!(
                                target: &task.log_target,
                                "`chain_subscribeFinalizedHeads` subscription has skipped block \
                                due to undecodable header. Hash: {}. Error: {}",
                                HashDisplay(&new_best_block_hash),
                                error,
                            );
                            continue;
                        }
                    };

                for (subscription_id, subscription) in &mut task.finalized_heads_subscriptions {
                    subscription
                        .send_notification(methods::ServerToClient::chain_finalizedHead {
                            subscription: subscription_id.as_str().into(),
                            result: finalized_block_json_rpc_header.clone(),
                        })
                        .await;
                }

                // An important detail here is that the newly-finalized block is added to the list
                // at the end, in order to guaranteed that it doesn't get removed. This is
                // necessary in order to guarantee that the current finalized (and current best,
                // if the best block is also the finalized block) remains pinned.
                for block_hash in pruned_blocks.into_iter().chain(iter::once(finalized_hash)) {
                    if finalized_and_pruned_lru.len() == finalized_and_pruned_lru.cap().get() {
                        let (hash_to_unpin, _) = finalized_and_pruned_lru.pop_lru().unwrap();
                        subscription.unpin_block(&hash_to_unpin).await;
                        pinned_blocks.remove(&hash_to_unpin).unwrap();
                    }
                    finalized_and_pruned_lru.put(block_hash, ());
                }

                if *current_best_block != new_best_block_hash {
                    let best_block_header = &pinned_blocks
                        .get(&new_best_block_hash)
                        .unwrap()
                        .scale_encoded_header;
                    let best_block_json_rpc_header =
                        match methods::Header::from_scale_encoded_header(
                            &best_block_header,
                            task.runtime_service.block_number_bytes(),
                        ) {
                            Ok(h) => h,
                            Err(error) => {
                                log::warn!(
                                    target: &task.log_target,
                                    "`chain_subscribeNewHeads` subscription has skipped block due to \
                                    undecodable header. Hash: {}. Error: {}",
                                    HashDisplay(&new_best_block_hash),
                                    error,
                                );
                                continue;
                            }
                        };

                    for (subscription_id, subscription) in &mut task.new_heads_subscriptions {
                        subscription
                            .send_notification(methods::ServerToClient::chain_newHead {
                                subscription: subscription_id.as_str().into(),
                                result: best_block_json_rpc_header.clone(),
                            })
                            .await;
                    }

                    let new_best_runtime = &pinned_blocks
                        .get(&new_best_block_hash)
                        .unwrap()
                        .runtime_version;
                    if !Arc::ptr_eq(
                        new_best_runtime,
                        &pinned_blocks
                            .get(current_best_block)
                            .unwrap()
                            .runtime_version,
                    ) {
                        for (subscription_id, subscription) in
                            &mut task.runtime_version_subscriptions
                        {
                            subscription
                                .send_notification(methods::ServerToClient::state_runtimeVersion {
                                    subscription: subscription_id.as_str().into(),
                                    result: convert_runtime_version(new_best_runtime),
                                })
                                .await;
                        }
                    }

                    task.stale_storage_subscriptions
                        .extend(task.storage_subscriptions.keys().cloned());

                    *current_best_block = new_best_block_hash;
                }
            }

            WhatHappened::SubscriptionNotification {
                notification:
                    runtime_service::Notification::BestBlockChanged {
                        hash: new_best_hash,
                        ..
                    },
                pinned_blocks,
                current_best_block,
                ..
            } => {
                let header = &pinned_blocks
                    .get(&new_best_hash)
                    .unwrap()
                    .scale_encoded_header;
                let json_rpc_header = match methods::Header::from_scale_encoded_header(
                    &header,
                    task.runtime_service.block_number_bytes(),
                ) {
                    Ok(h) => h,
                    Err(error) => {
                        log::warn!(
                            target: &task.log_target,
                            "`chain_subscribeNewHeads` subscription has skipped block due to \
                            undecodable header. Hash: {}. Error: {}",
                            HashDisplay(&new_best_hash),
                            error,
                        );
                        continue;
                    }
                };

                for (subscription_id, subscription) in &mut task.new_heads_subscriptions {
                    subscription
                        .send_notification(methods::ServerToClient::chain_newHead {
                            subscription: subscription_id.as_str().into(),
                            result: json_rpc_header.clone(),
                        })
                        .await;
                }

                let new_best_runtime = &pinned_blocks.get(&new_best_hash).unwrap().runtime_version;
                if !Arc::ptr_eq(
                    new_best_runtime,
                    &pinned_blocks
                        .get(current_best_block)
                        .unwrap()
                        .runtime_version,
                ) {
                    for (subscription_id, subscription) in &mut task.runtime_version_subscriptions {
                        subscription
                            .send_notification(methods::ServerToClient::state_runtimeVersion {
                                subscription: subscription_id.as_str().into(),
                                result: convert_runtime_version(new_best_runtime),
                            })
                            .await;
                    }
                }

                task.stale_storage_subscriptions
                    .extend(task.storage_subscriptions.keys().cloned());

                *current_best_block = new_best_hash;
            }

            WhatHappened::Message(Message::SubscriptionStart(request)) => match request.request() {
                methods::MethodCall::chain_subscribeAllHeads {} => {
                    let subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    task.all_heads_subscriptions
                        .insert(subscription_id, subscription);
                }
                methods::MethodCall::chain_subscribeNewHeads {} => {
                    let mut subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    let to_send = if let Subscription::Active {
                        current_best_block,
                        pinned_blocks,
                        ..
                    } = &task.subscription
                    {
                        Some(
                            match methods::Header::from_scale_encoded_header(
                                &pinned_blocks
                                    .get(current_best_block)
                                    .unwrap()
                                    .scale_encoded_header,
                                task.runtime_service.block_number_bytes(),
                            ) {
                                Ok(h) => h,
                                Err(error) => {
                                    log::warn!(
                                        target: &task.log_target,
                                        "`chain_subscribeNewHeads` subscription has skipped \
                                        block due to undecodable header. Hash: {}. Error: {}",
                                        HashDisplay(current_best_block),
                                        error,
                                    );
                                    continue;
                                }
                            },
                        )
                    } else {
                        None
                    };
                    if let Some(to_send) = to_send {
                        subscription
                            .send_notification(methods::ServerToClient::chain_newHead {
                                subscription: subscription_id.as_str().into(),
                                result: to_send,
                            })
                            .await;
                    }
                    task.new_heads_subscriptions
                        .insert(subscription_id, subscription);
                }
                methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                    let mut subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    let to_send = if let Subscription::Active {
                        current_finalized_block,
                        pinned_blocks,
                        ..
                    } = &task.subscription
                    {
                        Some(
                            match methods::Header::from_scale_encoded_header(
                                &pinned_blocks
                                    .get(current_finalized_block)
                                    .unwrap()
                                    .scale_encoded_header,
                                task.runtime_service.block_number_bytes(),
                            ) {
                                Ok(h) => h,
                                Err(error) => {
                                    log::warn!(
                                        target: &task.log_target,
                                        "`chain_subscribeFinalizedHeads` subscription has skipped \
                                        block due to undecodable header. Hash: {}. Error: {}",
                                        HashDisplay(current_finalized_block),
                                        error,
                                    );
                                    continue;
                                }
                            },
                        )
                    } else {
                        None
                    };
                    if let Some(to_send) = to_send {
                        subscription
                            .send_notification(methods::ServerToClient::chain_finalizedHead {
                                subscription: subscription_id.as_str().into(),
                                result: to_send,
                            })
                            .await;
                    }
                    task.finalized_heads_subscriptions
                        .insert(subscription_id, subscription);
                }
                methods::MethodCall::state_subscribeRuntimeVersion {} => {
                    let mut subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    let to_send = if let Subscription::Active {
                        current_best_block,
                        pinned_blocks,
                        ..
                    } = &task.subscription
                    {
                        Some(convert_runtime_version(
                            &pinned_blocks
                                .get(current_best_block)
                                .unwrap()
                                .runtime_version,
                        ))
                    } else {
                        None
                    };
                    if let Some(to_send) = to_send {
                        subscription
                            .send_notification(methods::ServerToClient::state_runtimeVersion {
                                subscription: (&subscription_id).into(),
                                result: to_send,
                            })
                            .await;
                    }
                    task.runtime_version_subscriptions
                        .insert(subscription_id, subscription);
                }
                methods::MethodCall::state_subscribeStorage { list } => {
                    // TODO: limit the size of `list` to avoid DoS attacks
                    if list.is_empty() {
                        // When the list of keys is empty, that means we want to subscribe to *all*
                        // storage changes. It is not possible to reasonably implement this in a
                        // light client.
                        request.fail(json_rpc::parse::ErrorResponse::ServerError(
                            -32000,
                            "Subscribing to all storage changes isn't supported",
                        ));
                        continue;
                    }

                    let subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    task.stale_storage_subscriptions
                        .insert(subscription_id.clone());
                    for key in &list {
                        task.storage_subscriptions_by_key
                            .entry(key.0.clone())
                            .or_default()
                            .insert(subscription_id.clone());
                    }
                    task.storage_subscriptions.insert(
                        subscription_id,
                        (subscription, list.into_iter().map(|l| l.0).collect()),
                    );
                }
                _ => unreachable!(), // TODO: stronger typing to avoid this?
            },

            WhatHappened::Message(Message::SubscriptionDestroyed { subscription_id }) => {
                task.all_heads_subscriptions.remove(&subscription_id);
                task.new_heads_subscriptions.remove(&subscription_id);
                task.finalized_heads_subscriptions.remove(&subscription_id);
                task.runtime_version_subscriptions.remove(&subscription_id);
                if let Some((_, keys)) = task.storage_subscriptions.remove(&subscription_id) {
                    for key in keys {
                        let hashbrown::hash_map::Entry::Occupied(mut entry) = task.storage_subscriptions_by_key.entry(key)
                            else { unreachable!() };
                        let _was_in = entry.get_mut().remove(&subscription_id);
                        debug_assert!(_was_in);
                        if entry.get().is_empty() {
                            entry.remove();
                        }
                    }
                }
                task.stale_storage_subscriptions.remove(&subscription_id);
                // TODO: shrink_to_fit?
            }

            WhatHappened::Message(Message::RecentBlockRuntimeAccess {
                block_hash,
                result_tx,
            }) => {
                let subscription_id_with_block = if let Subscription::Active {
                    pinned_blocks: recent_pinned_blocks,
                    subscription,
                    ..
                } = &task.subscription
                {
                    if recent_pinned_blocks.contains_key(&block_hash) {
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

            WhatHappened::Message(Message::CurrentBestBlockHash { result_tx }) => {
                match &task.subscription {
                    Subscription::Active {
                        current_best_block, ..
                    } => {
                        let _ = result_tx.send(*current_best_block);
                    }
                    Subscription::Pending(_) | Subscription::NotCreated => {
                        task.best_block_report.push(result_tx);
                    }
                }
            }

            WhatHappened::Message(Message::BlockNumber {
                block_hash,
                result_tx,
            }) => {
                if let Some(future) = task.block_state_root_hashes_numbers.get_mut(&block_hash) {
                    let _ = future.now_or_never();
                }

                let block_number = if let Subscription::Active {
                    pinned_blocks: recent_pinned_blocks,
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
                    pinned_blocks: recent_pinned_blocks,
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
                        pinned_blocks: recent_pinned_blocks,
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

            WhatHappened::Message(Message::StorageFetch {
                block_hash,
                result: Ok(result),
            }) => {
                debug_assert!(task.storage_query_in_progress);
                task.storage_query_in_progress = false;

                let is_up_to_date = match task.subscription {
                    Subscription::Active {
                        current_best_block, ..
                    } => current_best_block == block_hash,
                    Subscription::NotCreated | Subscription::Pending(_) => true,
                };

                let mut notifications_to_send = hashbrown::HashMap::<
                    String,
                    Vec<(methods::HexString, Option<methods::HexString>)>,
                    _,
                >::with_capacity_and_hasher(
                    task.storage_subscriptions.len(),
                    fnv::FnvBuildHasher::default(),
                );

                for item in result {
                    let sync_service::StorageResultItem::Value { key, value } = item
                        else { unreachable!() };
                    for subscription_id in task
                        .storage_subscriptions_by_key
                        .get(&key)
                        .into_iter()
                        .flat_map(|list| list.iter())
                    {
                        notifications_to_send
                            .entry_ref(subscription_id)
                            .or_insert_with(Vec::new)
                            .push((
                                methods::HexString(key.clone()),
                                value.clone().map(methods::HexString),
                            ));
                    }
                }

                for (subscription_id, changes) in notifications_to_send {
                    if is_up_to_date {
                        task.stale_storage_subscriptions.remove(&subscription_id);
                    }
                    task.storage_subscriptions
                        .get_mut(&subscription_id)
                        .unwrap()
                        .0
                        .send_notification(methods::ServerToClient::state_storage {
                            subscription: subscription_id.into(),
                            result: methods::StorageChangeSet {
                                block: methods::HashHexString(block_hash),
                                changes,
                            },
                        })
                        .await;
                }
            }

            WhatHappened::Message(Message::StorageFetch {
                block_hash,
                result: Err(_),
            }) => {
                debug_assert!(task.storage_query_in_progress);
                task.storage_query_in_progress = false;
                // TODO: add a delay or something?
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

fn convert_runtime_version(
    runtime: &Arc<Result<executor::CoreVersion, runtime_service::RuntimeError>>,
) -> Option<methods::RuntimeVersion> {
    if let Ok(runtime_spec) = &**runtime {
        let runtime_spec = runtime_spec.decode();
        Some(methods::RuntimeVersion {
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
        })
    } else {
        None
    }
}
