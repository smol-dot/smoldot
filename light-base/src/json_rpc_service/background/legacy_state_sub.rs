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

use alloc::{borrow::ToOwned as _, boxed::Box, format, string::String, sync::Arc, vec, vec::Vec};
use futures_channel::oneshot;
use futures_lite::{FutureExt as _, StreamExt as _};
use smoldot::{
    executor, header,
    informant::HashDisplay,
    json_rpc::{self, methods, service},
    network::codec,
};

use crate::{platform::PlatformRef, runtime_service, sync_service};

/// Message that can be passed to the task started with [`start_task`].
pub(super) enum Message<TPlat: PlatformRef> {
    /// JSON-RPC client has sent a subscription request.
    ///
    /// Only the legacy API subscription requests are supported. Any other will trigger a panic.
    SubscriptionStart(service::SubscriptionStartProcess),

    /// JSON-RPC client has unsubscribed from something.
    SubscriptionDestroyed {
        /// Identifier of the subscription. Does not necessarily match any of the subscriptions
        /// previously passed through [`Message::SubscriptionStart`].
        subscription_id: String,
    },

    /// The task must send back access to the runtime of the given block, or `None` if the block
    /// isn't available in the cache.
    RecentBlockRuntimeAccess {
        /// Hash of the block to query.
        block_hash: [u8; 32],
        /// How to send back the result.
        result_tx: oneshot::Sender<Option<runtime_service::RuntimeAccess<TPlat>>>,
    },

    /// The task must send back the current best block hash.
    ///
    /// Waits for the runtime service to be ready, which can potentially take a long time.
    CurrentBestBlockHash {
        /// How to send back the result.
        result_tx: oneshot::Sender<[u8; 32]>,
    },

    /// The task must send back the state root and number the given block. If the block isn't
    /// available in the cache, a network request is performed.
    // TODO: refactor this message and the ones below to be more consistent
    BlockStateRootAndNumber {
        /// Hash of the block to query.
        block_hash: [u8; 32],
        /// How to send back the result.
        result_tx: oneshot::Sender<Result<([u8; 32], u64), StateTrieRootHashError>>,
    },

    /// The task must send back the number of the given block, or `None` if the block isn't
    /// available in the cache.
    BlockNumber {
        /// Hash of the block to query.
        block_hash: [u8; 32],
        /// How to send back the result.
        result_tx: oneshot::Sender<Option<u64>>,
    },

    /// The task must send back the header of the given block, or `None` if the block isn't
    /// available in the cache.
    BlockHeader {
        /// Hash of the block to query.
        block_hash: [u8; 32],
        /// How to send back the result.
        result_tx: oneshot::Sender<Option<Vec<u8>>>,
    },

    /// Internal message. Do not use.
    StorageFetch {
        /// Hash of the block the storage fetch targets.
        block_hash: [u8; 32],
        /// Results provided by the [`sync_service`].
        result: Result<Vec<sync_service::StorageResultItem>, sync_service::StorageQueryError>,
    },
    /// Internal message. Do not use.
    BlockStateRootAndNumberFinished {
        /// Hash of the block that has been queried.
        block_hash: [u8; 32],
        /// Outcome of the fetch.
        result: Result<([u8; 32], u64), StateTrieRootHashError>,
    },
}

/// Configuration to pass to [`start_task`].
pub(super) struct Config<TPlat: PlatformRef> {
    /// Access to the platform bindings.
    pub platform: TPlat,
    /// Prefix used for all the logging in this module.
    pub log_target: String,
    /// Sync service used to start networking requests.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// Runtime service used to subscribe to notifications regarding blocks and report them to
    /// the JSON-RPC client.
    pub runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
}

/// Error potentially returned by [`Message::BlockStateRootAndNumber`].
#[derive(Debug, derive_more::Display, Clone)]
pub(super) enum StateTrieRootHashError {
    /// Failed to decode block header.
    HeaderDecodeError(header::Error),
    /// Error while fetching block header from network.
    NetworkQueryError,
}

/// Spawn a task dedicated to holding a cache and fulfilling the legacy API subscriptions that the
/// JSON-RPC client starts.
pub(super) fn start_task<TPlat: PlatformRef>(
    config: Config<TPlat>,
) -> async_channel::Sender<Message<TPlat>> {
    let (requests_tx, requests_rx) = async_channel::bounded(8);
    let requests_rx = Box::pin(requests_rx);

    config.platform.clone().spawn_task(
        format!("{}-legacy-state-subscriptions", config.log_target).into(),
        run(Task {
            log_target: config.log_target.clone(),
            platform: config.platform.clone(),
            best_block_report: Vec::with_capacity(4),
            sync_service: config.sync_service,
            runtime_service: config.runtime_service,
            subscription: Subscription::NotCreated,
            requests_tx: async_channel::Sender::downgrade(&requests_tx),
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
                crate::util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    config.platform.fill_random_bytes(&mut seed);
                    seed
                }),
            ),
            stale_storage_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
                16,
                Default::default(),
            ),
            storage_query_in_progress: false,
            block_state_root_hashes_numbers_cache: lru::LruCache::with_hasher(
                NonZeroUsize::new(32).unwrap(),
                Default::default(),
            ),
            block_state_root_hashes_numbers_pending: hashbrown::HashMap::with_capacity_and_hasher(
                32,
                Default::default(),
            ),
        }),
    );

    requests_tx
}

struct Task<TPlat: PlatformRef> {
    /// See [`Config::log_target`].
    log_target: String,
    /// See [`Config::platform`].
    platform: TPlat,
    /// See [`Config::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`Config::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// State of the subscription towards the runtime service.
    subscription: Subscription<TPlat>,
    /// Whenever the subscription becomes active and the best block becomes available, it must be
    /// sent on these channels as soon as possible.
    best_block_report: Vec<oneshot::Sender<[u8; 32]>>,

    /// Sending side of [`Task::requests_rx`].
    requests_tx: async_channel::WeakSender<Message<TPlat>>,
    /// How to receive messages from the API user.
    requests_rx: Pin<Box<async_channel::Receiver<Message<TPlat>>>>,

    /// List of all active `chain_subscribeAllHeads` subscriptions, indexed by the subscription ID.
    // TODO: shrink_to_fit?
    all_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    /// List of all active `chain_subscribeNewHeads` subscriptions, indexed by the subscription ID.
    // TODO: shrink_to_fit?
    new_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    /// List of all active `chain_subscribeFinalizedHeads` subscriptions, indexed by the
    /// subscription ID.
    finalized_heads_subscriptions:
        hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    /// List of all active `state_subscribeRuntimeVersion` subscriptions, indexed by the
    /// subscription ID.
    runtime_version_subscriptions:
        hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,

    /// List of all active `state_subscribeStorage` subscriptions, indexed by the subscription ID.
    /// The value is the subscription plus the list of keys requested by this subscription.
    // TODO: shrink_to_fit?
    storage_subscriptions:
        hashbrown::HashMap<String, (service::Subscription, Vec<Vec<u8>>), fnv::FnvBuildHasher>,
    /// Identical to [`Task::storage_subscriptions`] by indexed by requested key. The inner
    /// `HashSet`s are never empty.
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

    /// Cache of known state trie root hashes and numbers of blocks that were not in
    /// [`Subscription::Active::pinned_blocks`].
    ///
    /// The state trie root hash can also be an `Err` if the network request failed or if the
    /// header is of an invalid format.
    ///
    /// Most of the time, the JSON-RPC client will query blocks that are found in
    /// [`Subscription::Active::pinned_blocks`], but occasionally it will query older blocks. When
    /// the storage of an older block is queried, it is common for the JSON-RPC client to make
    /// several storage requests to that same old block. In order to avoid having to retrieve the
    /// state trie root hash multiple, we store these hashes in this LRU cache.
    block_state_root_hashes_numbers_cache: lru::LruCache<
        [u8; 32],
        Result<([u8; 32], u64), StateTrieRootHashError>,
        fnv::FnvBuildHasher,
    >,

    /// Requests for blocks state root hash and numbers that are still in progress.
    /// For each block hash, contains a list of senders that are interested in the response.
    /// Once the operation has been finished, the value is inserted in
    /// [`Task::block_state_root_hashes_numbers_cache`].
    block_state_root_hashes_numbers_pending: hashbrown::HashMap<
        [u8; 32],
        Vec<oneshot::Sender<Result<([u8; 32], u64), StateTrieRootHashError>>>,
        fnv::FnvBuildHasher,
    >,
}

/// State of the subscription towards the runtime service. See [`Task::subscription`].
enum Subscription<TPlat: PlatformRef> {
    /// Subscription is active.
    Active {
        /// Object representing the subscription.
        subscription: runtime_service::Subscription<TPlat>,

        /// Hash of the current best block. Guaranteed to be in
        /// [`Subscription::Active::pinned_blocks`].
        current_best_block: [u8; 32],

        /// If `Some`, the new heads and runtime version subscriptions haven't been updated about
        /// the new current best block yet. Contains the previous best block that the
        /// subscriptions are aware of. The previous best block is guaranteed to be in
        /// [`Subscription::Active::pinned_blocks`].
        new_heads_and_runtime_subscriptions_stale: Option<Option<[u8; 32]>>,

        /// Hash of the current finalized block. Guaranteed to be in
        /// [`Subscription::Active::pinned_blocks`].
        current_finalized_block: [u8; 32],

        /// If `true`, the finalized heads subscriptions haven't been updated about the new
        /// current finalized block yet.
        finalized_heads_subscriptions_stale: bool,

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

    /// Wiating for the runtime service to start the subscription. Can potentially take a long
    /// time.
    Pending(Pin<Box<dyn Future<Output = runtime_service::SubscribeAll<TPlat>> + Send>>),

    /// Subscription not requested yet. Should transition to [`Subscription::Pending`] as soon
    /// as possible.
    NotCreated,
}

struct RecentBlock {
    scale_encoded_header: Vec<u8>,
    // TODO: do we really need to keep the runtime version here, given that the block is still pinned in the runtime service?
    runtime_version: Arc<Result<executor::CoreVersion, runtime_service::RuntimeError>>,
}

/// Actually run the task.
async fn run<TPlat: PlatformRef>(mut task: Task<TPlat>) {
    loop {
        // Perform some internal state updates if necessary.

        // Process the content of `best_block_report`
        if let Subscription::Active {
            current_best_block, ..
        } = &task.subscription
        {
            while let Some(sender) = task.best_block_report.pop() {
                let _ = sender.send(*current_best_block);
            }
            task.best_block_report.shrink_to_fit();
        }

        // If the finalized heads subcriptions aren't up-to-date with the latest finalized block,
        // report it to them.
        if let Subscription::Active {
            pinned_blocks,
            current_finalized_block,
            finalized_heads_subscriptions_stale,
            ..
        } = &mut task.subscription
        {
            if *finalized_heads_subscriptions_stale {
                let finalized_block_header = &pinned_blocks
                    .get(current_finalized_block)
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
                                HashDisplay(current_finalized_block),
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

                *finalized_heads_subscriptions_stale = false;
            }
        }

        // If the new heads and runtime version subscriptions aren't up-to-date with the latest
        // best block, report it to them.
        if let Subscription::Active {
            pinned_blocks,
            current_best_block,
            new_heads_and_runtime_subscriptions_stale,
            ..
        } = &mut task.subscription
        {
            if let Some(previous_best_block) = new_heads_and_runtime_subscriptions_stale.take() {
                let best_block_header = &pinned_blocks
                    .get(current_best_block)
                    .unwrap()
                    .scale_encoded_header;
                let best_block_json_rpc_header = match methods::Header::from_scale_encoded_header(
                    best_block_header,
                    task.runtime_service.block_number_bytes(),
                ) {
                    Ok(h) => h,
                    Err(error) => {
                        log::warn!(
                            target: &task.log_target,
                            "`chain_subscribeNewHeads` subscription has skipped block due to \
                            undecodable header. Hash: {}. Error: {}",
                            HashDisplay(current_best_block),
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
                    .get(current_best_block)
                    .unwrap()
                    .runtime_version;
                if previous_best_block.map_or(true, |prev_best_block| {
                    !Arc::ptr_eq(
                        new_best_runtime,
                        &pinned_blocks.get(&prev_best_block).unwrap().runtime_version,
                    )
                }) {
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
            }
        }

        // Start a task that fetches the storage items of the stale storage subscriptions.
        if let Subscription::Active {
            pinned_blocks,
            current_best_block,
            ..
        } = &task.subscription
        {
            if !task.storage_query_in_progress && !task.stale_storage_subscriptions.is_empty() {
                // If the header of the current best block can't be decoded, we don't start
                // the task.
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

                // Build the list of keys that must be requested by aggregating the keys requested
                // by all stale storage subscriptions.
                let mut keys = hashbrown::HashSet::with_hasher(crate::util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    task.platform.fill_random_bytes(&mut seed);
                    seed
                }));
                keys.extend(
                    task.stale_storage_subscriptions
                        .iter()
                        .map(|s_id| &task.storage_subscriptions.get(s_id).unwrap().1)
                        .flat_map(|keys_list| keys_list.iter().cloned()),
                );

                // If the list of keys to query is empty, we mark all subscriptions as no longer
                // stale and loop again. This is necessary in order to prevent infinite loops if
                // the JSON-RPC client subscribes to an empty list of items.
                if keys.is_empty() {
                    task.stale_storage_subscriptions.clear();
                    continue;
                }

                // Start the task in the background.
                // The task will send a `Message::StorageFetch` once it is done.
                task.storage_query_in_progress = true;
                task.platform.spawn_task(
                    format!("{}-storage-subscriptions-fetch", task.log_target).into(),
                    {
                        let block_hash = *current_best_block;
                        let sync_service = task.sync_service.clone();
                        let requests_tx = task.requests_tx.clone();
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
                    },
                );
            }
        }

        enum WakeUpReason<'a, TPlat: PlatformRef> {
            SubscriptionNotification {
                notification: runtime_service::Notification,
                subscription: &'a mut runtime_service::Subscription<TPlat>,
                pinned_blocks:
                    &'a mut hashbrown::HashMap<[u8; 32], RecentBlock, fnv::FnvBuildHasher>,
                finalized_and_pruned_lru: &'a mut lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>,
                current_best_block: &'a mut [u8; 32],
                new_heads_and_runtime_subscriptions_stale: &'a mut Option<Option<[u8; 32]>>,
                current_finalized_block: &'a mut [u8; 32],
                finalized_heads_subscriptions_stale: &'a mut bool,
            },
            SubscriptionDead,
            SubscriptionReady(runtime_service::SubscribeAll<TPlat>),
            Message(Message<TPlat>),
            ForegroundDead,
        }

        // Asynchronously wait for something to happen. This can potentially take a long time.
        let event: WakeUpReason<'_, TPlat> = {
            let subscription_event = async {
                match &mut task.subscription {
                    Subscription::NotCreated => WakeUpReason::SubscriptionDead,
                    Subscription::Active {
                        subscription,
                        pinned_blocks,
                        finalized_and_pruned_lru,
                        current_best_block,
                        new_heads_and_runtime_subscriptions_stale,
                        current_finalized_block,
                        finalized_heads_subscriptions_stale,
                    } => match subscription.next().await {
                        Some(notification) => WakeUpReason::SubscriptionNotification {
                            notification,
                            subscription,
                            pinned_blocks,
                            finalized_and_pruned_lru,
                            current_best_block,
                            new_heads_and_runtime_subscriptions_stale,
                            current_finalized_block,
                            finalized_heads_subscriptions_stale,
                        },
                        None => WakeUpReason::SubscriptionDead,
                    },
                    Subscription::Pending(pending) => {
                        WakeUpReason::SubscriptionReady(pending.await)
                    }
                }
            };

            let message = async {
                match task.requests_rx.next().await {
                    Some(msg) => WakeUpReason::Message(msg),
                    None => WakeUpReason::ForegroundDead,
                }
            };

            subscription_event.or(message).await
        };

        // Perform internal state updates depending on what happened.
        match event {
            // Runtime service is now ready to give us blocks.
            WakeUpReason::SubscriptionReady(subscribe_all) => {
                // We must transition to `Subscription::Active`.
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

                task.subscription = Subscription::Active {
                    subscription: subscribe_all.new_blocks,
                    pinned_blocks,
                    finalized_and_pruned_lru,
                    current_best_block,
                    new_heads_and_runtime_subscriptions_stale: Some(None),
                    current_finalized_block: finalized_block_hash,
                    finalized_heads_subscriptions_stale: true,
                };
            }

            // A new non-finalized block has appeared!
            WakeUpReason::SubscriptionNotification {
                notification: runtime_service::Notification::Block(block),
                pinned_blocks,
                current_best_block,
                new_heads_and_runtime_subscriptions_stale,
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
                            "`chain_subscribeAllHeads` subscription has skipped block due to \
                            undecodable header. Hash: {}. Error: {}",
                            HashDisplay(&header::hash_from_scale_encoded_header(
                                &block.scale_encoded_header
                            )),
                            error,
                        );
                        continue;
                    }
                };

                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                let _was_in = pinned_blocks.insert(
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
                debug_assert!(_was_in.is_none());

                for (subscription_id, subscription) in &mut task.all_heads_subscriptions {
                    subscription
                        .send_notification(methods::ServerToClient::chain_allHead {
                            subscription: subscription_id.as_str().into(),
                            result: json_rpc_header.clone(),
                        })
                        .await;
                }

                if block.is_new_best {
                    *new_heads_and_runtime_subscriptions_stale = Some(Some(*current_best_block));
                    *current_best_block = hash;
                }
            }

            // A block has been finalized.
            WakeUpReason::SubscriptionNotification {
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
                new_heads_and_runtime_subscriptions_stale,
                current_finalized_block,
                finalized_heads_subscriptions_stale,
            } => {
                *current_finalized_block = finalized_hash;
                *finalized_heads_subscriptions_stale = true;

                debug_assert!(pruned_blocks
                    .iter()
                    .all(|hash| pinned_blocks.contains_key(hash)));

                // Add the pruned and finalized blocks to the LRU cache. The least-recently used
                // entries in the cache are unpinned and no longer tracked.
                //
                // An important detail here is that the newly-finalized block is added to the list
                // at the end, in order to guarantee that it doesn't get removed. This is
                // necessary in order to guarantee that the current finalized (and current best,
                // if the best block is also the finalized block) remains pinned until at least
                // a different block gets finalized.
                for block_hash in pruned_blocks.into_iter().chain(iter::once(finalized_hash)) {
                    if finalized_and_pruned_lru.len() == finalized_and_pruned_lru.cap().get() {
                        let (hash_to_unpin, _) = finalized_and_pruned_lru.pop_lru().unwrap();
                        subscription.unpin_block(hash_to_unpin).await;
                        pinned_blocks.remove(&hash_to_unpin).unwrap();
                    }
                    finalized_and_pruned_lru.put(block_hash, ());
                }

                if *current_best_block != new_best_block_hash {
                    *new_heads_and_runtime_subscriptions_stale = Some(Some(*current_best_block));
                    *current_best_block = new_best_block_hash;
                }
            }

            // The current best block has now changed.
            WakeUpReason::SubscriptionNotification {
                notification:
                    runtime_service::Notification::BestBlockChanged {
                        hash: new_best_hash,
                        ..
                    },
                current_best_block,
                new_heads_and_runtime_subscriptions_stale,
                ..
            } => {
                *new_heads_and_runtime_subscriptions_stale = Some(Some(*current_best_block));
                *current_best_block = new_best_hash;
            }

            // Request from the JSON-RPC client.
            WakeUpReason::Message(Message::SubscriptionStart(request)) => match request.request() {
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

                // Any other request.
                _ => unreachable!(), // TODO: stronger typing to avoid this?
            },

            // JSON-RPC client has unsubscribed.
            WakeUpReason::Message(Message::SubscriptionDestroyed { subscription_id }) => {
                // We don't know the type of the unsubscription, that's not a big deal. Just
                // remove the entry from everywhere.
                task.all_heads_subscriptions.remove(&subscription_id);
                task.new_heads_subscriptions.remove(&subscription_id);
                task.finalized_heads_subscriptions.remove(&subscription_id);
                task.runtime_version_subscriptions.remove(&subscription_id);
                if let Some((_, keys)) = task.storage_subscriptions.remove(&subscription_id) {
                    for key in keys {
                        let hashbrown::hash_map::Entry::Occupied(mut entry) =
                            task.storage_subscriptions_by_key.entry(key)
                        else {
                            unreachable!()
                        };
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

            WakeUpReason::Message(Message::RecentBlockRuntimeAccess {
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
                        .pinned_block_runtime_access(subscription_id, block_hash)
                        .await
                        .ok()
                } else {
                    None
                };

                let _ = result_tx.send(access);
            }

            WakeUpReason::Message(Message::CurrentBestBlockHash { result_tx }) => {
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

            WakeUpReason::Message(Message::BlockNumber {
                block_hash,
                result_tx,
            }) => {
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
                        task.block_state_root_hashes_numbers_cache.get(&block_hash),
                    ) {
                        (Some(Ok(header)), _) => Some(header.number),
                        (_, Some(Ok((_, num)))) => Some(*num),
                        _ => None,
                    }
                } else {
                    None
                };

                let _ = result_tx.send(block_number);
            }

            WakeUpReason::Message(Message::BlockHeader {
                block_hash,
                result_tx,
            }) => {
                let header = if let Subscription::Active {
                    pinned_blocks: recent_pinned_blocks,
                    ..
                } = &mut task.subscription
                {
                    recent_pinned_blocks
                        .get(&block_hash)
                        .map(|block| block.scale_encoded_header.clone())
                } else {
                    None
                };

                let _ = result_tx.send(header);
            }

            WakeUpReason::Message(Message::BlockStateRootAndNumber {
                block_hash,
                result_tx,
            }) => {
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
                            let _ =
                                result_tx.send(Err(StateTrieRootHashError::HeaderDecodeError(err)));
                            continue;
                        } // TODO: can this actually happen? unclear
                        None => {}
                    }
                }

                // Look in `block_state_root_hashes_numbers_cache`.
                if let Some(entry) = task.block_state_root_hashes_numbers_cache.get(&block_hash) {
                    let _ = result_tx.send(entry.clone());
                    continue;
                }

                // Look in `block_state_root_hashes_numbers_pending`.
                if let Some(entry) = task
                    .block_state_root_hashes_numbers_pending
                    .get_mut(&block_hash)
                {
                    entry.push(result_tx);
                    continue;
                }

                // Start a new task to retrieve the value.
                task.platform
                    .spawn_task("block-state-root-number-fetch∏".into(), {
                        let sync_service = task.sync_service.clone();
                        let requests_tx = task.requests_tx.clone();
                        async move {
                            // The sync service knows which peers are potentially aware of
                            // this block.
                            let result = sync_service
                                .clone()
                                .block_query_unknown_number(
                                    block_hash,
                                    codec::BlocksRequestFields {
                                        header: true,
                                        body: false,
                                        justifications: false,
                                    },
                                    4,
                                    Duration::from_secs(8),
                                    NonZeroU32::new(2).unwrap(),
                                )
                                .await;

                            let result = match result {
                                Ok(block) => {
                                    if let Some(header) = block.header {
                                        if header::hash_from_scale_encoded_header(&header)
                                            == block_hash
                                        {
                                            match header::decode(
                                                &header,
                                                sync_service.block_number_bytes(),
                                            ) {
                                                Ok(decoded) => {
                                                    Ok((*decoded.state_root, decoded.number))
                                                }
                                                Err(err) => Err(
                                                    StateTrieRootHashError::HeaderDecodeError(err),
                                                ),
                                            }
                                        } else {
                                            // TODO: try request again?
                                            Err(StateTrieRootHashError::NetworkQueryError)
                                        }
                                    } else {
                                        // TODO: try request again?
                                        Err(StateTrieRootHashError::NetworkQueryError)
                                    }
                                }
                                Err(_) => {
                                    // TODO: better error details?
                                    Err(StateTrieRootHashError::NetworkQueryError)
                                }
                            };

                            if let Some(requests_tx) = requests_tx.upgrade() {
                                let _ = requests_tx
                                    .send(Message::BlockStateRootAndNumberFinished {
                                        block_hash,
                                        result,
                                    })
                                    .await;
                            }
                        }
                    });

                // Insert `result_tx` so that it gets sent the result once the operation is
                // finished.
                task.block_state_root_hashes_numbers_pending
                    .insert(block_hash, vec![result_tx]);
            }

            // Background task dedicated to performing a fetch for a block trie root and number
            // has finished.
            WakeUpReason::Message(Message::BlockStateRootAndNumberFinished {
                block_hash,
                result,
            }) => {
                if let Some(senders) = task
                    .block_state_root_hashes_numbers_pending
                    .remove(&block_hash)
                {
                    for sender in senders {
                        let _ = sender.send(result.clone());
                    }
                }

                task.block_state_root_hashes_numbers_cache
                    .push(block_hash, result);
            }

            // Background task dedicated to performing a storage query for the storage
            // subscription has finished.
            WakeUpReason::Message(Message::StorageFetch {
                block_hash,
                result: Ok(result),
            }) => {
                debug_assert!(task.storage_query_in_progress);
                task.storage_query_in_progress = false;

                // Determine whether another storage query targeting a more up-to-date block
                // must be started afterwards.
                let is_up_to_date = match task.subscription {
                    Subscription::Active {
                        current_best_block, ..
                    } => current_best_block == block_hash,
                    Subscription::NotCreated | Subscription::Pending(_) => true,
                };

                // Because all the keys of all the subscriptions are merged into one network
                // request, we must now attribute each item in the result back to its subscription.
                // While this solution is a bit CPU-heavy, it is a more elegant solution than
                // keeping track of subscription in the background task.
                let mut notifications_to_send = hashbrown::HashMap::<
                    String,
                    Vec<(methods::HexString, Option<methods::HexString>)>,
                    _,
                >::with_capacity_and_hasher(
                    task.storage_subscriptions.len(),
                    fnv::FnvBuildHasher::default(),
                );
                for item in result {
                    let sync_service::StorageResultItem::Value { key, value } = item else {
                        unreachable!()
                    };
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

                // Send the notifications and mark the subscriptions as no longer stale if
                // relevant.
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

            // Background task dedicated to performing a storage query for the storage
            // subscription has finished but was unsuccessful.
            WakeUpReason::Message(Message::StorageFetch { result: Err(_), .. }) => {
                debug_assert!(task.storage_query_in_progress);
                task.storage_query_in_progress = false;
                // TODO: add a delay or something?
            }

            // JSON-RPC service has been destroyed. Stop the task altogether.
            WakeUpReason::ForegroundDead => {
                return;
            }

            // The subscription towards the runtime service needs to be renewed.
            WakeUpReason::SubscriptionDead => {
                // The buffer size should be large enough so that, if the CPU is busy, it
                // doesn't become full before the execution of this task resumes.
                // The maximum number of pinned block is ignored, as this maximum is a way to
                // avoid malicious behaviors. This code is by definition not considered
                // malicious.
                let runtime_service = task.runtime_service.clone();
                task.subscription = Subscription::Pending(Box::pin(async move {
                    runtime_service
                        .subscribe_all(32, NonZeroUsize::new(usize::max_value()).unwrap())
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
