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

use crate::{
    log, network_service,
    platform::PlatformRef,
    runtime_service, sync_service, transactions_service,
    util::{self, SipHasherBuild},
};

use super::StartConfig;

use alloc::{
    borrow::{Cow, ToOwned as _},
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    iter,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    time::Duration,
};
use futures_lite::{FutureExt as _, StreamExt as _};
use futures_util::{future, stream, FutureExt as _};
use rand_chacha::{
    rand_core::{RngCore as _, SeedableRng as _},
    ChaCha20Rng,
};
use smoldot::{
    chain::fork_tree,
    header,
    informant::HashDisplay,
    json_rpc::{self, methods, parse},
    libp2p::{multiaddr, PeerId},
    network::codec,
};

/// Fields used to process JSON-RPC requests in the background.
struct Background<TPlat: PlatformRef> {
    /// Target to use for all the logs.
    log_target: String,

    /// Access to the platform's capabilities.
    platform: TPlat,

    /// Name of the chain, as found in the chain specification.
    chain_name: String,
    /// Type of chain, as found in the chain specification.
    chain_ty: String,
    /// JSON-encoded properties of the chain, as found in the chain specification.
    chain_properties_json: String,
    /// Whether the chain is a live network. Found in the chain specification.
    chain_is_live: bool,
    /// Value to return when the `system_name` RPC is called.
    system_name: String,
    /// Value to return when the `system_version` RPC is called.
    system_version: String,

    /// Randomness used for various purposes, such as generating subscription IDs.
    randomness: ChaCha20Rng,

    /// See [`StartConfig::network_service`].
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// See [`StartConfig::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`StartConfig::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    /// See [`StartConfig::transactions_service`].
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Tasks that are spawned by the service and running in the background.
    background_tasks:
        stream::FuturesUnordered<Pin<Box<dyn future::Future<Output = Event<TPlat>> + Send>>>,

    /// Channel where requests are pulled from.
    requests_rx: Pin<Box<async_channel::Receiver<String>>>,

    /// Channel where to send responses and notifications to the foreground.
    responses_tx: async_channel::Sender<String>,

    /// Stream of notifications coming from the runtime service. Used for legacy JSON-RPC API
    /// subscriptions. `None` if not subscribed yet.
    runtime_service_subscription: RuntimeServiceSubscription<TPlat>,
    /// Best block used for legacy API functions that target the best block.
    legacy_api_best_block: [u8; 32],

    /// List of all active `chain_subscribeAllHeads` subscriptions, indexed by the subscription ID.
    // TODO: shrink_to_fit?
    all_heads_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    /// List of all active `chain_subscribeNewHeads` subscriptions, indexed by the subscription ID.
    // TODO: shrink_to_fit?
    new_heads_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    /// List of all active `chain_subscribeFinalizedHeads` subscriptions, indexed by the
    /// subscription ID.
    finalized_heads_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    /// List of all active `state_subscribeRuntimeVersion` subscriptions, indexed by the
    /// subscription ID.
    // TODO: shrink_to_fit?
    runtime_version_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    /// List of all active `author_submitAndWatchExtrinsic` and
    /// `transactionWatch_unstable_submitAndWatch` subscriptions, indexed by the subscription ID.
    // TODO: shrink_to_fit?
    transactions_subscriptions: hashbrown::HashMap<String, TransactionWatch, fnv::FnvBuildHasher>,
    /// State of each `chainHead_follow` subscription indexed by its ID.
    // TODO: shrink_to_fit?
    chain_head_follow_subscriptions:
        hashbrown::HashMap<String, ChainHeadFollow, fnv::FnvBuildHasher>,

    /// List of all active `state_subscribeStorage` subscriptions, indexed by the subscription ID.
    /// Values are the list of keys requested by this subscription.
    storage_subscriptions: BTreeSet<(Arc<str>, Vec<u8>)>,
    /// Identical to [`Task::storage_subscriptions`] by indexed by requested key.
    storage_subscriptions_by_key: BTreeSet<(Vec<u8>, Arc<str>)>,
    /// List of storage subscriptions whose latest sent notification isn't about the current
    /// best block.
    // TODO: shrink_to_fit?
    stale_storage_subscriptions: hashbrown::HashSet<Arc<str>, fnv::FnvBuildHasher>,
    /// `true` if there exists a background task in [`Background::background_tasks`] currently
    /// fetching storage items for storage subscriptions.
    storage_query_in_progress: bool,

    /// List of multi-stage requests (i.e. JSON-RPC requests that require multiple asynchronous
    /// operations) that are ready to make progress.
    multistage_requests_to_advance: VecDeque<(String, MultiStageRequest)>,

    /// Cache of known headers, state trie root hashes and numbers of blocks.
    ///
    /// Can also be an `Err` if the header is in an invalid format.
    block_headers_cache: lru::LruCache<
        [u8; 32],
        Result<(Vec<u8>, [u8; 32], u64), header::Error>,
        fnv::FnvBuildHasher,
    >,

    /// Requests for blocks headers, state root hash and numbers that are still in progress.
    /// For each block hash, contains a list of requests that are interested in the response.
    /// Once the operation has been finished, the value is inserted in
    /// [`Task::block_headers_cache`].
    block_headers_pending:
        hashbrown::HashMap<[u8; 32], Vec<(String, MultiStageRequest)>, fnv::FnvBuildHasher>,

    /// Cache of known runtimes of blocks.
    ///
    /// Note that runtimes that have failed to compile can be found here as well.
    block_runtimes_cache:
        lru::LruCache<[u8; 32], runtime_service::PinnedRuntime, fnv::FnvBuildHasher>,

    /// Requests for block runtimes that are still in progress.
    /// For each block hash, contains a list of requests that are interested in the response.
    /// Once the operation has been finished, the value is inserted in
    /// [`Task::block_runtimes_cache`].
    block_runtimes_pending:
        hashbrown::HashMap<[u8; 32], Vec<(String, MultiStageRequest)>, fnv::FnvBuildHasher>,

    /// When `state_getKeysPaged` is called and the response is truncated, the response is
    /// inserted in this cache. The API user is likely to call `state_getKeysPaged` again with
    /// the same parameters, in which case we hit the cache and avoid the networking requests.
    /// The values are list of keys.
    state_get_keys_paged_cache:
        lru::LruCache<GetKeysPagedCacheKey, Vec<Vec<u8>>, util::SipHasherBuild>,

    /// Hash of the genesis block.
    /// Keeping the genesis block is important, as the genesis block hash is included in
    /// transaction signatures, and must therefore be queried by upper-level UIs.
    genesis_block_hash: [u8; 32],

    /// If `true`, we have already printed a warning about usage of the legacy JSON-RPC API. This
    /// flag prevents printing this message multiple times.
    printed_legacy_json_rpc_warning: bool,
}

/// State of the subscription towards the runtime service. See [`Task::subscription`].
enum RuntimeServiceSubscription<TPlat: PlatformRef> {
    /// Subscription is active.
    Active {
        /// Object representing the subscription.
        subscription: runtime_service::Subscription<TPlat>,

        /// Hash of the current best block. Guaranteed to be in
        /// [`RuntimeServiceSubscription::Active::pinned_blocks`].
        current_best_block: [u8; 32],

        /// If `Some`, the new heads and runtime version subscriptions haven't been updated about
        /// the new current best block yet. Contains the previous best block that the
        /// subscriptions are aware of. The previous best block is guaranteed to be in
        /// [`RuntimeServiceSubscription::Active::pinned_blocks`].
        new_heads_and_runtime_subscriptions_stale: Option<Option<[u8; 32]>>,

        /// Hash of the current finalized block. Guaranteed to be in
        /// [`RuntimeServiceSubscription::Active::pinned_blocks`].
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
        // TODO: duplicate with other caches?
        finalized_and_pruned_lru: lru::LruCache<[u8; 32], (), fnv::FnvBuildHasher>,
    },

    /// Wiating for the runtime service to start the subscription. Can potentially take a long
    /// time.
    Pending(Pin<Box<dyn future::Future<Output = runtime_service::SubscribeAll<TPlat>> + Send>>),

    /// Subscription not requested yet. Should transition to [`Subscription::Pending`] as soon
    /// as possible.
    NotCreated,
}

struct RecentBlock {
    scale_encoded_header: Vec<u8>,
    // TODO: do we really need to keep the runtime version here, given that the block is still pinned in the runtime service?
    runtime_version: Arc<Result<smoldot::executor::CoreVersion, runtime_service::RuntimeError>>,
}

struct ChainHeadFollow {
    /// Tree of hashes of all the current non-finalized blocks. This includes unpinned blocks.
    // TODO: remove and instead determine the pruned blocks in the sync service
    non_finalized_blocks: fork_tree::ForkTree<[u8; 32]>,

    /// For each pinned block hash, the SCALE-encoded header of the block.
    pinned_blocks_headers: hashbrown::HashMap<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>,

    /// List of body/call/storage operations currently in progress. Keys are operation IDs.
    operations_in_progress: hashbrown::HashMap<String, Operation, fnv::FnvBuildHasher>,

    available_operation_slots: u32,

    /// If the subscription was created with `withRuntime: true`, contains the subscription ID
    /// according to the runtime service.
    ///
    /// Contains `None` if `withRuntime` was `false`, or if the subscription hasn't been
    /// initialized yet.
    runtime_service_subscription_id: Option<runtime_service::SubscriptionId>,
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

enum MultiStageRequest {
    ChainGetHeader {
        block_hash: [u8; 32],
    },
    StateCallStage1 {
        block_hash: [u8; 32],
        name: String,
        parameters: Vec<u8>,
    },
    StateCallStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
        name: String,
        parameters: Vec<u8>,
    },
    StateGetKeysStage1 {
        block_hash: [u8; 32],
        prefix: Vec<u8>,
    },
    StateGetKeysStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
        prefix: Vec<u8>,
    },
    StateGetKeysStage3 {
        in_progress_results: Vec<methods::HexString>,
    },
    StateGetKeysPagedStage1 {
        block_hash: [u8; 32],
        prefix: Vec<u8>,
        count: u32,
        start_key: Vec<u8>,
    },
    StateGetKeysPagedStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
        prefix: Vec<u8>,
        count: u32,
        start_key: Vec<u8>,
    },
    StateGetKeysPagedStage3 {
        in_progress_results: Vec<Vec<u8>>,
    },
    StateQueryStorageAtStage1 {
        block_hash: [u8; 32],
        keys: Vec<methods::HexString>,
    },
    StateQueryStorageAtStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
        keys: Vec<methods::HexString>,
    },
    StateQueryStorageAtStage3 {
        block_hash: [u8; 32],
        in_progress_results: Vec<(methods::HexString, Option<methods::HexString>)>,
    },
    StateGetMetadataStage1 {
        block_hash: [u8; 32],
    },
    StateGetMetadataStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
    },
    StateGetStorageStage1 {
        block_hash: [u8; 32],
        key: Vec<u8>,
    },
    StateGetStorageStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
        key: Vec<u8>,
    },
    StateGetStorageStage3 {},
    StateGetRuntimeVersionStage1 {
        block_hash: [u8; 32],
    },
    StateGetRuntimeVersionStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
    },
    PaymentQueryInfoStage1 {
        block_hash: [u8; 32],
        extrinsic: Vec<u8>,
    },
    PaymentQueryInfoStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
        extrinsic: Vec<u8>,
    },
    SystemAccountNextIndexStage1 {
        block_hash: [u8; 32],
        account_id: Vec<u8>,
    },
    SystemAccountNextIndexStage2 {
        block_hash: [u8; 32],
        block_state_trie_root_hash: [u8; 32],
        block_number: u64,
        account_id: Vec<u8>,
    },
}

enum Event<TPlat: PlatformRef> {
    TransactionEvent {
        subscription_id: String,
        event: transactions_service::TransactionStatus,
        watcher: Pin<Box<transactions_service::TransactionWatcher>>,
    },
    ChainGetBlockResult {
        request_id_json: String,
        result: Result<codec::BlockData, ()>,
        expected_block_hash: [u8; 32],
    },
    ChainHeadSubscriptionWithRuntimeReady {
        subscription_id: String,
        subscription: runtime_service::SubscribeAll<TPlat>,
    },
    ChainHeadSubscriptionWithRuntimeNotification {
        subscription_id: String,
        notification: runtime_service::Notification,
        stream: runtime_service::Subscription<TPlat>,
    },
    ChainHeadSubscriptionWithoutRuntimeReady {
        subscription_id: String,
        subscription: sync_service::SubscribeAll,
    },
    ChainHeadSubscriptionWithoutRuntimeNotification {
        subscription_id: String,
        notification: sync_service::Notification,
        stream: Pin<Box<async_channel::Receiver<sync_service::Notification>>>,
    },
    ChainHeadSubscriptionDeadSubcription {
        subscription_id: String,
    },
    ChainHeadStorageOperationProgress {
        subscription_id: String,
        operation_id: String,
        progress: sync_service::StorageQueryProgress<TPlat>,
    },
    ChainHeadCallOperationDone {
        subscription_id: String,
        operation_id: String,
        result: Result<runtime_service::RuntimeCallSuccess, runtime_service::RuntimeCallError>,
    },
    ChainHeadBodyOperationDone {
        subscription_id: String,
        operation_id: String,
        expected_extrinsics_root: [u8; 32],
        result: Result<codec::BlockData, ()>,
    },
    ChainHeadOperationCancelled,
    BlockInfoRetrieved {
        block_hash: [u8; 32],
        result: Result<Result<(Vec<u8>, [u8; 32], u64), header::Error>, ()>,
    },
    RuntimeDownloaded {
        block_hash: [u8; 32],
        result: Result<runtime_service::PinnedRuntime, ()>,
    },
    StorageRequestInProgress {
        request_id_json: String,
        request: MultiStageRequest,
        progress: sync_service::StorageQueryProgress<TPlat>,
    },
    StorageSubscriptionsUpdate {
        block_hash: [u8; 32],
        result: Result<Vec<sync_service::StorageResultItem>, sync_service::StorageQueryError>,
    },
}

struct TransactionWatch {
    included_block: Option<[u8; 32]>,
    num_broadcasted_peers: usize,
    ty: TransactionWatchTy,
}

enum TransactionWatchTy {
    /// `author_submitAndWatchExtrinsic`.
    Legacy,
    /// `transactionWatch_unstable_submitAndWatch`.
    NewApi,
}

/// See [`Background::state_get_keys_paged_cache`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GetKeysPagedCacheKey {
    /// Value of the `hash` parameter of the call to `state_getKeysPaged`.
    hash: [u8; 32],
    /// Value of the `prefix` parameter of the call to `state_getKeysPaged`.
    prefix: Vec<u8>,
}

pub(super) async fn run<TPlat: PlatformRef>(
    log_target: String,
    config: StartConfig<TPlat>,
    requests_rx: async_channel::Receiver<String>,
    responses_tx: async_channel::Sender<String>,
) {
    let mut me = Background {
        log_target,
        chain_name: config.chain_name,
        chain_ty: config.chain_ty,
        chain_is_live: config.chain_is_live,
        chain_properties_json: config.chain_properties_json,
        system_name: config.system_name.clone(),
        system_version: config.system_version.clone(),
        randomness: ChaCha20Rng::from_seed({
            let mut seed = [0; 32];
            config.platform.fill_random_bytes(&mut seed);
            seed
        }),
        network_service: config.network_service.clone(),
        sync_service: config.sync_service.clone(),
        runtime_service: config.runtime_service.clone(),
        transactions_service: config.transactions_service.clone(),
        background_tasks: stream::FuturesUnordered::new(),
        runtime_service_subscription: RuntimeServiceSubscription::NotCreated,
        legacy_api_best_block: config.genesis_block_hash, // TODO: better block
        all_heads_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        new_heads_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        finalized_heads_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        runtime_version_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        transactions_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
            2,
            Default::default(),
        ),
        chain_head_follow_subscriptions: hashbrown::HashMap::with_hasher(Default::default()),
        storage_subscriptions: BTreeSet::new(),
        storage_subscriptions_by_key: BTreeSet::new(),
        stale_storage_subscriptions: hashbrown::HashSet::with_capacity_and_hasher(
            0,
            Default::default(),
        ),
        storage_query_in_progress: false,
        requests_rx: Box::pin(requests_rx),
        responses_tx,
        multistage_requests_to_advance: VecDeque::new(),
        block_headers_cache: lru::LruCache::with_hasher(
            NonZeroUsize::new(32).unwrap_or_else(|| unreachable!()),
            Default::default(),
        ),
        block_headers_pending: hashbrown::HashMap::with_capacity_and_hasher(0, Default::default()),
        block_runtimes_cache: lru::LruCache::with_hasher(
            NonZeroUsize::new(32).unwrap_or_else(|| unreachable!()),
            Default::default(),
        ),
        block_runtimes_pending: hashbrown::HashMap::with_capacity_and_hasher(0, Default::default()),
        state_get_keys_paged_cache: lru::LruCache::with_hasher(
            NonZeroUsize::new(2).unwrap(),
            util::SipHasherBuild::new({
                let mut seed = [0; 16];
                config.platform.fill_random_bytes(&mut seed);
                seed
            }),
        ),
        genesis_block_hash: config.genesis_block_hash,
        printed_legacy_json_rpc_warning: false,
        platform: config.platform,
    };

    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        enum WakeUpReason<'a, TPlat: PlatformRef> {
            ForegroundDead,
            IncomingJsonRpcRequest(String),
            AdvanceMultiStageRequest {
                request_id_json: String,
                request: MultiStageRequest,
            },
            Event(Event<TPlat>),
            RuntimeServiceSubscriptionReady(runtime_service::SubscribeAll<TPlat>),
            RuntimeServiceSubscriptionNotification {
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
            RuntimeServiceSubscriptionDead,
            StartStorageSubscriptions,
            NotifyFinalizedHeads,
            NotifyNewHeadsRuntimeSubscriptions(Option<[u8; 32]>),
        }

        let wake_up_reason = {
            // TODO: do storage subscriptions
            async {
                match &mut me.runtime_service_subscription {
                    RuntimeServiceSubscription::NotCreated => {
                        WakeUpReason::RuntimeServiceSubscriptionDead
                    }
                    RuntimeServiceSubscription::Active {
                        subscription,
                        pinned_blocks,
                        finalized_and_pruned_lru,
                        current_best_block,
                        new_heads_and_runtime_subscriptions_stale,
                        current_finalized_block,
                        finalized_heads_subscriptions_stale,
                    } => {
                        if !me.storage_query_in_progress
                            && !me.stale_storage_subscriptions.is_empty()
                        {
                            return WakeUpReason::StartStorageSubscriptions;
                        }

                        if *finalized_heads_subscriptions_stale {
                            return WakeUpReason::NotifyFinalizedHeads;
                        }

                        if let Some(previous_best_block) =
                            new_heads_and_runtime_subscriptions_stale.take()
                        {
                            return WakeUpReason::NotifyNewHeadsRuntimeSubscriptions(
                                previous_best_block,
                            );
                        }

                        match subscription.next().await {
                            Some(notification) => {
                                WakeUpReason::RuntimeServiceSubscriptionNotification {
                                    notification,
                                    subscription,
                                    pinned_blocks,
                                    finalized_and_pruned_lru,
                                    current_best_block,
                                    new_heads_and_runtime_subscriptions_stale,
                                    current_finalized_block,
                                    finalized_heads_subscriptions_stale,
                                }
                            }
                            None => WakeUpReason::RuntimeServiceSubscriptionDead,
                        }
                    }
                    RuntimeServiceSubscription::Pending(pending) => {
                        WakeUpReason::RuntimeServiceSubscriptionReady(pending.await)
                    }
                }
            }
            .or(async {
                if let Some((request_id_json, request)) =
                    me.multistage_requests_to_advance.pop_front()
                {
                    WakeUpReason::AdvanceMultiStageRequest {
                        request_id_json,
                        request,
                    }
                } else {
                    future::pending().await
                }
            })
            .or(async {
                me.requests_rx.next().await.map_or(
                    WakeUpReason::ForegroundDead,
                    WakeUpReason::IncomingJsonRpcRequest,
                )
            })
            .or(async {
                if let Some(event) = me.background_tasks.next().await {
                    WakeUpReason::Event(event)
                } else {
                    future::pending().await
                }
            })
            .await // TODO: subscription notification missing
        };

        match wake_up_reason {
            WakeUpReason::ForegroundDead => {
                // Service foreground has been destroyed. Stop the background task.
                return;
            }

            WakeUpReason::IncomingJsonRpcRequest(request_json) => {
                let Ok((request_id_json, request_parsed)) =
                    methods::parse_jsonrpc_client_to_server(&request_json)
                else {
                    todo!()
                };

                match request_parsed {
                    methods::MethodCall::author_pendingExtrinsics {} => {
                        // Because multiple different chains ("chain" in the context of the
                        // public API of smoldot) might share the same transactions service, it
                        // could be possible for chain A to submit a transaction and then for
                        // chain B to read it by calling `author_pendingExtrinsics`. This would
                        // make it possible for the API user of chain A to be able to communicate
                        // with the API user of chain B. While the implications of permitting
                        // this are unclear, it is not a bad idea to prevent this communication
                        // from happening. Consequently, we always return an empty list of
                        // pending extrinsics.
                        // TODO: could store the list of pending transactions in the JSON-RPC service instead
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_pendingExtrinsics(Vec::new())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::author_submitExtrinsic { transaction } => {
                        // Note that this function is misnamed. It should really be called
                        // "author_submitTransaction".

                        // In Substrate, `author_submitExtrinsic` returns the hash of the
                        // transaction. It is unclear whether it has to actually be the hash of
                        // the transaction or if it could be any opaque value. Additionally, there
                        // isn't any other JSON-RPC method that accepts as parameter the value
                        // returned here. When in doubt, we return the hash as well.

                        let mut hash_context = blake2_rfc::blake2b::Blake2b::new(32);
                        hash_context.update(&transaction.0);
                        let mut transaction_hash: [u8; 32] = Default::default();
                        transaction_hash.copy_from_slice(hash_context.finalize().as_bytes());
                        me.transactions_service
                            .submit_transaction(transaction.0)
                            .await;
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_submitExtrinsic(methods::HashHexString(
                                    transaction_hash,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::author_submitAndWatchExtrinsic { transaction } => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let mut transaction_updates = Box::pin(
                            me.transactions_service
                                .submit_and_watch_transaction(transaction.0, 16)
                                .await,
                        );

                        let _prev_value = me.transactions_subscriptions.insert(
                            subscription_id.clone(),
                            TransactionWatch {
                                included_block: None,
                                num_broadcasted_peers: 0,
                                ty: TransactionWatchTy::Legacy,
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_submitAndWatchExtrinsic(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        me.background_tasks.push(Box::pin(async move {
                            let Some(status) = transaction_updates.as_mut().next().await else {
                                unreachable!()
                            };
                            Event::TransactionEvent {
                                subscription_id,
                                event: status,
                                watcher: transaction_updates,
                            }
                        }));
                    }

                    methods::MethodCall::author_unwatchExtrinsic { subscription } => {
                        let exists = me
                            .transactions_subscriptions
                            .get(&*subscription)
                            .map_or(false, |sub| matches!(sub.ty, TransactionWatchTy::Legacy));
                        if exists {
                            me.transactions_subscriptions.remove(&*subscription);
                        }
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_unwatchExtrinsic(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chain_getBlock { hash } => {
                        // `hash` equal to `None` means "the current best block".
                        let hash = hash.map_or(me.legacy_api_best_block, |b| b.0);

                        // Try to determine the block number by looking for the block in cache.
                        // The request can be fulfilled no matter whether the block number is
                        // known or not, but knowing it will lead to a better selection of peers,
                        // and thus increase the chances of the requests succeeding.
                        let block_number = me
                            .block_headers_cache
                            .get(&hash)
                            .and_then(|result| result.as_ref().ok().map(|(_, _, n)| *n));

                        // Block bodies and headers aren't stored locally. Ask the network.
                        me.background_tasks.push({
                            let sync_service = me.sync_service.clone();
                            let request_id_json = request_id_json.to_owned();
                            Box::pin(async move {
                                let result = if let Some(block_number) = block_number {
                                    sync_service
                                        .block_query(
                                            block_number,
                                            hash,
                                            codec::BlocksRequestFields {
                                                header: true,
                                                body: true,
                                                justifications: false,
                                            },
                                            3,
                                            Duration::from_secs(8),
                                            NonZeroU32::new(1).unwrap(),
                                        )
                                        .await
                                } else {
                                    sync_service
                                        .block_query_unknown_number(
                                            hash,
                                            codec::BlocksRequestFields {
                                                header: true,
                                                body: true,
                                                justifications: false,
                                            },
                                            3,
                                            Duration::from_secs(8),
                                            NonZeroU32::new(1).unwrap(),
                                        )
                                        .await
                                };
                                Event::ChainGetBlockResult {
                                    request_id_json,
                                    result,
                                    expected_block_hash: hash,
                                }
                            })
                        });
                    }

                    methods::MethodCall::chain_getBlockHash { height } => {
                        // TODO: maybe store values in cache?
                        match height {
                            Some(0) => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::chain_getBlockHash(
                                            methods::HashHexString(me.genesis_block_hash),
                                        )
                                        .to_json_response(request_id_json),
                                    )
                                    .await;
                            }
                            None => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::chain_getBlockHash(
                                            methods::HashHexString(me.legacy_api_best_block),
                                        )
                                        .to_json_response(request_id_json),
                                    )
                                    .await;
                            }
                            Some(_) => {
                                // TODO: look into some list of known blocks

                                // While could ask a full node for the block with a specific
                                // number, there is absolutely no way to verify the answer of
                                // the full node.
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_success_response(request_id_json, "null"))
                                    .await;
                            }
                        }
                    }

                    methods::MethodCall::chain_getFinalizedHead {} => {
                        // TODO: do differently
                        let finalized_hash = header::hash_from_scale_encoded_header(
                            me.runtime_service
                                .subscribe_all(16, NonZeroUsize::new(24).unwrap())
                                .await
                                .finalized_block_scale_encoded_header,
                        );

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_getFinalizedHead(methods::HashHexString(
                                    finalized_hash,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chain_getHeader { hash } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::ChainGetHeader {
                                block_hash: hash.map_or(me.legacy_api_best_block, |h| h.0),
                            },
                        ));
                    }

                    methods::MethodCall::chain_subscribeAllHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_subscribeAllHeads(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        let _was_inserted = me.all_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);
                    }

                    methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        // TODO: check max subscriptions

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_subscribeFinalizedHeads(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        if let RuntimeServiceSubscription::Active {
                            current_finalized_block,
                            pinned_blocks,
                            ..
                        } = &me.runtime_service_subscription
                        {
                            match methods::Header::from_scale_encoded_header(
                                &pinned_blocks
                                    .get(current_finalized_block)
                                    .unwrap()
                                    .scale_encoded_header,
                                me.runtime_service.block_number_bytes(),
                            ) {
                                Ok(h) => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::ServerToClient::chain_newHead {
                                                subscription: Cow::Borrowed(&subscription_id),
                                                result: h,
                                            }
                                            .to_json_request_object_parameters(None),
                                        )
                                        .await;
                                }
                                Err(error) => {
                                    log!(
                                        &me.platform,
                                        Warn,
                                        &me.log_target,
                                        format!(
                                            "`chain_subscribeFinalizedHeads` subscription has \
                                                skipped block due to undecodable header. Hash: {}. \
                                                Error: {}",
                                            HashDisplay(current_finalized_block),
                                            error
                                        )
                                    );
                                }
                            }
                        }

                        let _was_inserted =
                            me.finalized_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);
                    }

                    methods::MethodCall::chain_subscribeNewHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };
                        // TODO: check max subscriptions

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_subscribeNewHeads(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        if let RuntimeServiceSubscription::Active {
                            current_best_block,
                            pinned_blocks,
                            ..
                        } = &me.runtime_service_subscription
                        {
                            match methods::Header::from_scale_encoded_header(
                                &pinned_blocks
                                    .get(current_best_block)
                                    .unwrap()
                                    .scale_encoded_header,
                                me.runtime_service.block_number_bytes(),
                            ) {
                                Ok(h) => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::ServerToClient::chain_newHead {
                                                subscription: Cow::Borrowed(&subscription_id),
                                                result: h,
                                            }
                                            .to_json_request_object_parameters(None),
                                        )
                                        .await;
                                }
                                Err(error) => {
                                    log!(
                                        &me.platform,
                                        Warn,
                                        &me.log_target,
                                        format!(
                                            "`chain_subscribeNewHeads` subscription has \
                                                skipped block due to undecodable header. Hash: {}. \
                                                Error: {}",
                                            HashDisplay(current_best_block),
                                            error
                                        )
                                    );
                                }
                            }
                        }

                        let _was_inserted = me.new_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);
                    }

                    methods::MethodCall::chain_unsubscribeAllHeads { subscription } => {
                        let exists = me.all_heads_subscriptions.remove(&subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_unsubscribeAllHeads(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription } => {
                        let exists = me.finalized_heads_subscriptions.remove(&subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_unsubscribeFinalizedHeads(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                        let exists = me.new_heads_subscriptions.remove(&subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chain_unsubscribeNewHeads(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::payment_queryInfo { extrinsic, hash } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::PaymentQueryInfoStage1 {
                                block_hash: hash.map_or(me.legacy_api_best_block, |h| h.0),
                                extrinsic: extrinsic.0,
                            },
                        ));
                    }

                    methods::MethodCall::rpc_methods {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::rpc_methods(methods::RpcMethods {
                                    methods: methods::MethodCall::method_names()
                                        .map(|n| n.into())
                                        .collect(),
                                })
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::state_call {
                        name,
                        parameters,
                        hash,
                    } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::StateCallStage1 {
                                block_hash: hash.map_or(me.legacy_api_best_block, |h| h.0),
                                name: name.into_owned(),
                                parameters: parameters.0,
                            },
                        ));
                    }

                    methods::MethodCall::state_getKeys { prefix, hash } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::StateGetKeysStage1 {
                                block_hash: hash.map_or(me.legacy_api_best_block, |h| h.0),
                                prefix: prefix.0,
                            },
                        ));
                    }

                    methods::MethodCall::state_getKeysPaged {
                        prefix,
                        count,
                        start_key,
                        hash,
                    } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::StateGetKeysPagedStage1 {
                                block_hash: hash.map_or(me.legacy_api_best_block, |h| h.0),
                                prefix: prefix.map_or(Vec::new(), |p| p.0),
                                count,
                                start_key: start_key.map_or(Vec::new(), |p| p.0),
                            },
                        ));
                    }

                    methods::MethodCall::state_queryStorageAt { keys, at } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::StateQueryStorageAtStage1 {
                                block_hash: at.map_or(me.legacy_api_best_block, |h| h.0),
                                keys,
                            },
                        ));
                    }

                    methods::MethodCall::state_getMetadata { hash } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::StateGetMetadataStage1 {
                                block_hash: hash.map_or(me.legacy_api_best_block, |h| h.0),
                            },
                        ));
                    }

                    methods::MethodCall::state_getStorage { key, hash } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::StateGetStorageStage1 {
                                block_hash: hash.map_or(me.legacy_api_best_block, |h| h.0),
                                key: key.0,
                            },
                        ));
                    }

                    methods::MethodCall::state_getRuntimeVersion { at } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::StateGetRuntimeVersionStage1 {
                                block_hash: at.map_or(me.legacy_api_best_block, |h| h.0),
                            },
                        ));
                    }

                    methods::MethodCall::state_subscribeRuntimeVersion {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };
                        // TODO: check max subscriptions

                        let _was_inserted =
                            me.runtime_version_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);

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
                    }

                    methods::MethodCall::state_subscribeStorage { list } => {
                        // TODO: limit the size of `list` to avoid DoS attacks
                        if list.is_empty() {
                            // When the list of keys is empty, that means we want to subscribe to *all*
                            // storage changes. It is not possible to reasonably implement this in a
                            // light client.
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ServerError(
                                        -32000,
                                        "Subscribing to all storage changes isn't supported",
                                    ),
                                    None,
                                ))
                                .await;
                            continue;
                        }

                        let subscription_id = Arc::<str>::from({
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        });

                        let _was_inserted = me
                            .stale_storage_subscriptions
                            .insert(subscription_id.clone());
                        debug_assert!(_was_inserted);

                        for key in list {
                            let _was_inserted = me
                                .storage_subscriptions_by_key
                                .insert((key.0.clone(), subscription_id.clone()));
                            debug_assert!(_was_inserted);
                            let _was_inserted = me
                                .storage_subscriptions
                                .insert((subscription_id.clone(), key.0));
                            debug_assert!(_was_inserted);
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_subscribeStorage(Cow::Borrowed(
                                    &*subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::state_unsubscribeRuntimeVersion { subscription } => {
                        let exists = me.runtime_version_subscriptions.remove(&*subscription);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_unsubscribeRuntimeVersion(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::state_unsubscribeStorage { subscription } => {
                        let subscription = Arc::<str>::from(&*subscription);

                        let subscribed_keys = {
                            let mut after = me
                                .storage_subscriptions
                                .split_off(&(subscription.clone(), Vec::new()));
                            if let Some(first_entry_after) =
                                after.iter().find(|(s, _)| *s != subscription).cloned()
                            // TODO: O(n) ^
                            {
                                me.storage_subscriptions
                                    .append(&mut after.split_off(&first_entry_after));
                            }
                            after
                        };

                        let exists = !subscribed_keys.is_empty();

                        for (_, key) in subscribed_keys {
                            let _was_removed = me
                                .storage_subscriptions_by_key
                                .remove(&(key, subscription.clone()));
                            debug_assert!(_was_removed);
                        }

                        me.stale_storage_subscriptions.remove(&subscription);

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::state_unsubscribeStorage(exists)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_accountNextIndex { account } => {
                        me.multistage_requests_to_advance.push_back((
                            request_id_json.to_owned(),
                            MultiStageRequest::SystemAccountNextIndexStage1 {
                                block_hash: me.legacy_api_best_block,
                                account_id: account.0,
                            },
                        ));
                    }

                    methods::MethodCall::system_chain {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_chain((&me.chain_name).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_chainType {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_chainType((&me.chain_ty).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_health {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_health(methods::SystemHealth {
                                    // In smoldot, `is_syncing` equal to `false` means that GrandPa warp sync
                                    // is finished and that the block notifications report blocks that are
                                    // believed to be near the head of the chain.
                                    is_syncing: !me
                                        .runtime_service
                                        .is_near_head_of_chain_heuristic()
                                        .await,
                                    peers: u64::try_from(
                                        me.sync_service.syncing_peers().await.len(),
                                    )
                                    .unwrap_or(u64::max_value()),
                                    should_have_peers: me.chain_is_live,
                                })
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_localListenAddresses {} => {
                        // Light client never listens on any address.
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_localListenAddresses(Vec::new())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_name {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_name((&me.system_name).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_nodeRoles {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_nodeRoles(Cow::Borrowed(&[
                                    methods::NodeRole::Light,
                                ]))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_peers {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_peers(
                                    me.sync_service
                                        .syncing_peers()
                                        .await
                                        .map(|(peer_id, role, best_number, best_hash)| {
                                            methods::SystemPeer {
                                                peer_id: peer_id.to_string(),
                                                roles: match role {
                                                    sync_service::Role::Authority => {
                                                        methods::SystemPeerRole::Authority
                                                    }
                                                    sync_service::Role::Full => {
                                                        methods::SystemPeerRole::Full
                                                    }
                                                    sync_service::Role::Light => {
                                                        methods::SystemPeerRole::Light
                                                    }
                                                },
                                                best_hash: methods::HashHexString(best_hash),
                                                best_number,
                                            }
                                        })
                                        .collect(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_properties {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_properties(
                                    serde_json::from_str(&me.chain_properties_json).unwrap(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_version {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_version((&me.system_version).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_unstable_body {
                        follow_subscription,
                        hash,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_unstable_body(
                                        methods::ChainHeadBodyCallReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        // Determine whether the requested block hash is valid, and if yes its
                        // number and extrinsics trie root. The extrinsics trie root is used to
                        // verify whether the body we download is correct.
                        let (block_number, extrinsics_root) = {
                            if let Some(header) = subscription.pinned_blocks_headers.get(&hash.0) {
                                let decoded =
                                    header::decode(header, me.sync_service.block_number_bytes())
                                        .unwrap(); // TODO: unwrap?
                                (decoded.number, *decoded.extrinsics_root)
                            } else {
                                // Block isn't pinned. Request is invalid.
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::InvalidParams,
                                        None,
                                    ))
                                    .await;
                                continue;
                            }
                        };

                        // Check whether there is an operation slot available.
                        subscription.available_operation_slots =
                            match subscription.available_operation_slots.checked_sub(1) {
                                Some(s) => s,
                                None => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::Response::chainHead_unstable_body(
                                                methods::ChainHeadBodyCallReturn::LimitReached {},
                                            )
                                            .to_json_response(request_id_json),
                                        )
                                        .await;
                                    continue;
                                }
                            };

                        // Build the future that will grab the block body.
                        let body_download_future = me.sync_service.clone().block_query(
                            block_number,
                            hash.0,
                            codec::BlocksRequestFields {
                                header: false,
                                body: true,
                                justifications: false,
                            },
                            3,
                            Duration::from_secs(20),
                            NonZeroU32::new(2).unwrap(),
                        );

                        // Allocate an operation ID, update the local state, and notify the
                        // JSON-RPC client.
                        let operation_id = {
                            let mut operation_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut operation_id);
                            bs58::encode(operation_id).into_string()
                        };
                        let interrupt = event_listener::Event::new();
                        let on_interrupt = interrupt.listen();
                        let _was_in = subscription.operations_in_progress.insert(
                            operation_id.clone(),
                            Operation {
                                occupied_slots: 1,
                                interrupt,
                            },
                        );
                        debug_assert!(_was_in.is_none());
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_body(
                                    methods::ChainHeadBodyCallReturn::Started {
                                        operation_id: (&operation_id).into(),
                                    },
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // Finish the download asynchronously.
                        let subscription_id = follow_subscription.into_owned();
                        me.background_tasks.push(Box::pin(async move {
                            async move {
                                on_interrupt.await;
                                Event::ChainHeadOperationCancelled
                            }
                            .or(async move {
                                Event::ChainHeadBodyOperationDone {
                                    subscription_id,
                                    operation_id,
                                    expected_extrinsics_root: extrinsics_root,
                                    result: body_download_future.await,
                                }
                            })
                            .await
                        }));
                    }

                    methods::MethodCall::chainHead_unstable_call {
                        follow_subscription,
                        hash,
                        function,
                        call_parameters: methods::HexString(call_parameters),
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_unstable_call(
                                        methods::ChainHeadBodyCallReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        // Determine whether the requested block hash is valid.
                        if !subscription.pinned_blocks_headers.contains_key(&hash.0) {
                            // Block isn't pinned. Request is invalid.
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::InvalidParams,
                                    None,
                                ))
                                .await;
                            continue;
                        }

                        // Check whether there is an operation slot available.
                        subscription.available_operation_slots =
                            match subscription.available_operation_slots.checked_sub(1) {
                                Some(s) => s,
                                None => {
                                    let _ = me
                                        .responses_tx
                                        .send(
                                            methods::Response::chainHead_unstable_call(
                                                methods::ChainHeadBodyCallReturn::LimitReached {},
                                            )
                                            .to_json_response(request_id_json),
                                        )
                                        .await;
                                    continue;
                                }
                            };

                        // Make sure that the subscription is `withRuntime: true`.
                        let Some(runtime_service_subscription_id) =
                            subscription.runtime_service_subscription_id
                        else {
                            // Subscription is "without runtime".
                            // This path is in principle also reachable if the subscription isn't
                            // initialized yet, but in that case the block hash can't possibly be
                            // pinned.
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::InvalidParams,
                                    None,
                                ))
                                .await;
                            continue;
                        };

                        // Pin the pinned block's runtime and extract information about the block.
                        let (pinned_runtime, block_state_trie_root_hash, block_number) = match me
                            .runtime_service
                            .pin_pinned_block_runtime(runtime_service_subscription_id, hash.0)
                            .await
                        {
                            Ok(r) => r,
                            Err(runtime_service::PinPinnedBlockRuntimeError::BlockNotPinned) => {
                                // This has been verified above.
                                unreachable!()
                            }
                            Err(
                                runtime_service::PinPinnedBlockRuntimeError::ObsoleteSubscription,
                            ) => {
                                // The runtime service subscription is dead.
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::chainHead_unstable_call(
                                            methods::ChainHeadBodyCallReturn::LimitReached {},
                                        )
                                        .to_json_response(request_id_json),
                                    )
                                    .await;
                                continue;
                            }
                        };

                        // Create a future that will perform the runtime call.
                        let runtime_call_future = {
                            let runtime_service = me.runtime_service.clone();
                            let function = function.into_owned();
                            async move {
                                runtime_service
                                    .clone()
                                    .runtime_call(
                                        pinned_runtime,
                                        hash.0,
                                        block_number,
                                        block_state_trie_root_hash,
                                        function,
                                        None,
                                        call_parameters,
                                        3,
                                        Duration::from_secs(20),
                                        NonZeroU32::new(2).unwrap(),
                                    )
                                    .await
                            }
                        };

                        // Allocate a new operation ID, update the local state, and send the
                        // confirmation to the JSON-RPC client.
                        let operation_id = {
                            let mut operation_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut operation_id);
                            bs58::encode(operation_id).into_string()
                        };
                        let interrupt = event_listener::Event::new();
                        let on_interrupt = interrupt.listen();
                        let _was_in = subscription.operations_in_progress.insert(
                            operation_id.clone(),
                            Operation {
                                occupied_slots: 1,
                                interrupt,
                            },
                        );
                        debug_assert!(_was_in.is_none());
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_call(
                                    methods::ChainHeadBodyCallReturn::Started {
                                        operation_id: (&operation_id).into(),
                                    },
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;

                        // Finish the call asynchronously.
                        let subscription_id = follow_subscription.into_owned();
                        me.background_tasks.push(Box::pin(async move {
                            async move {
                                on_interrupt.await;
                                Event::ChainHeadOperationCancelled
                            }
                            .or(async move {
                                Event::ChainHeadCallOperationDone {
                                    subscription_id,
                                    operation_id,
                                    result: runtime_call_future.await,
                                }
                            })
                            .await
                        }));
                    }

                    methods::MethodCall::chainHead_unstable_continue { .. } => {
                        // TODO: not implemented properly
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_continue(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_unstable_storage {
                        follow_subscription,
                        hash,
                        items,
                        child_trie,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_unstable_storage(
                                        methods::ChainHeadStorageReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        // Determine whether the requested block hash is valid, and if yes its
                        // number and state trie root. The extrinsics trie root is used to
                        // verify whether the body we download is correct.
                        let (block_number, block_state_trie_root) = {
                            if let Some(header) = subscription.pinned_blocks_headers.get(&hash.0) {
                                let decoded =
                                    header::decode(header, me.sync_service.block_number_bytes())
                                        .unwrap(); // TODO: unwrap?
                                (decoded.number, *decoded.state_root)
                            } else {
                                // Block isn't pinned. Request is invalid.
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::InvalidParams,
                                        None,
                                    ))
                                    .await;
                                continue;
                            }
                        };

                        if child_trie.is_some() {
                            // TODO: implement this
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ServerError(
                                        -32000,
                                        "Child key storage queries not supported yet",
                                    ),
                                    None,
                                ))
                                .await;
                            log!(
                                &me.platform,
                                Warn,
                                &me.log_target,
                                "chainHead_unstable_storage has been called with a non-null childTrie. \
                                This isn't supported by smoldot yet."
                            );
                            continue;
                        }

                        let mut storage_operations = Vec::with_capacity(items.len());
                        let mut items = items.into_iter();

                        loop {
                            if subscription.available_operation_slots == 0 {
                                break;
                            }

                            let Some(item) = items.next() else { break };
                            storage_operations.push(sync_service::StorageRequestItem {
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
                                });

                            subscription.available_operation_slots -= 1;
                        }

                        if storage_operations.is_empty() {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_unstable_storage(
                                        methods::ChainHeadStorageReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        }

                        // Initialize the storage query operation.
                        let fetch_operation = me.sync_service.clone().storage_query(
                            block_number,
                            hash.0,
                            block_state_trie_root,
                            storage_operations.into_iter(),
                            3,
                            Duration::from_secs(20),
                            NonZeroU32::new(2).unwrap(),
                        );

                        let operation_id = {
                            let mut operation_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut operation_id);
                            bs58::encode(operation_id).into_string()
                        };

                        let interrupt = event_listener::Event::new();
                        let on_interrupt = interrupt.listen();

                        let _was_in = subscription.operations_in_progress.insert(
                            operation_id.clone(),
                            Operation {
                                occupied_slots: 1,
                                interrupt,
                            },
                        );
                        debug_assert!(_was_in.is_none());
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_storage(
                                    methods::ChainHeadStorageReturn::Started {
                                        operation_id: (&operation_id).into(),
                                        discarded_items: items.len(),
                                    },
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;

                        let subscription_id = follow_subscription.into_owned();
                        me.background_tasks.push(Box::pin(async move {
                            async {
                                on_interrupt.await;
                                Event::ChainHeadOperationCancelled
                            }
                            .or(async {
                                Event::ChainHeadStorageOperationProgress {
                                    subscription_id,
                                    operation_id,
                                    progress: fetch_operation.advance().await,
                                }
                            })
                            .await
                        }));
                    }

                    methods::MethodCall::chainHead_unstable_stopOperation {
                        follow_subscription,
                        operation_id,
                    } => {
                        if let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        {
                            if let Some(operation) =
                                subscription.operations_in_progress.remove(&*operation_id)
                            {
                                operation.interrupt.notify(usize::max_value());
                                subscription.available_operation_slots += operation.occupied_slots;
                            }
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_stopOperation(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_unstable_follow { with_runtime } => {
                        // Check that the number of existing subscriptions is below the limit.
                        // TODO: configurable limit
                        if me.chain_head_follow_subscriptions.len() >= 2 {
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ApplicationDefined(
                                        -32800,
                                        "too many active follow subscriptions",
                                    ),
                                    None,
                                ))
                                .await;
                            continue;
                        }

                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let _prev_value = me.chain_head_follow_subscriptions.insert(
                            subscription_id.clone(),
                            ChainHeadFollow {
                                non_finalized_blocks: fork_tree::ForkTree::new(), // TODO: capacity?
                                pinned_blocks_headers: hashbrown::HashMap::with_capacity_and_hasher(
                                    0,
                                    Default::default(),
                                ), // TODO: capacity?
                                operations_in_progress:
                                    hashbrown::HashMap::with_capacity_and_hasher(
                                        32,
                                        Default::default(),
                                    ),
                                available_operation_slots: 32, // TODO: make configurable? adjust dynamically?
                                runtime_service_subscription_id: None,
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_follow(Cow::Borrowed(
                                    &subscription_id,
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;

                        if with_runtime {
                            let runtime_service = me.runtime_service.clone();
                            me.background_tasks.push(Box::pin(async move {
                                Event::ChainHeadSubscriptionWithRuntimeReady {
                                    subscription_id,
                                    subscription: runtime_service
                                        .subscribe_all(
                                            32,
                                            NonZeroUsize::new(32).unwrap_or_else(|| unreachable!()),
                                        )
                                        .await,
                                }
                            }))
                        } else {
                            let sync_service = me.sync_service.clone();
                            me.background_tasks.push(Box::pin(async move {
                                Event::ChainHeadSubscriptionWithoutRuntimeReady {
                                    subscription_id,
                                    subscription: sync_service.subscribe_all(32, false).await,
                                }
                            }))
                        }
                    }

                    methods::MethodCall::chainHead_unstable_unfollow {
                        follow_subscription,
                    } => {
                        if let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .remove(&*follow_subscription)
                        {
                            for (_, operation) in subscription.operations_in_progress {
                                operation.interrupt.notify(usize::max_value());
                            }
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_unfollow(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_unstable_header {
                        follow_subscription,
                        hash,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_unstable_header(None)
                                        .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        let Some(block) = subscription.pinned_blocks_headers.get(&hash.0) else {
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ApplicationDefined(
                                        -32801,
                                        "unknown or unpinned block",
                                    ),
                                    None,
                                ))
                                .await;
                            continue;
                        };

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_header(Some(
                                    methods::HexString(block.clone()),
                                ))
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_unstable_unpin {
                        follow_subscription,
                        hash_or_hashes,
                    } => {
                        let Some(subscription) = me
                            .chain_head_follow_subscriptions
                            .get_mut(&*follow_subscription)
                        else {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::Response::chainHead_unstable_unpin(())
                                        .to_json_response(request_id_json),
                                )
                                .await;
                            continue;
                        };

                        let all_hashes = match &hash_or_hashes {
                            methods::HashHexStringSingleOrArray::Single(hash) => {
                                either::Left(iter::once(&hash.0))
                            }
                            methods::HashHexStringSingleOrArray::Array(hashes) => {
                                either::Right(hashes.iter().map(|h| &h.0))
                            }
                        };

                        // TODO: what if duplicate hashes
                        if !all_hashes
                            .clone()
                            .all(|hash| subscription.pinned_blocks_headers.contains_key(hash))
                        {
                            let _ = me
                                .responses_tx
                                .send(parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::InvalidParams,
                                    None,
                                ))
                                .await;
                            continue;
                        }

                        for hash in all_hashes {
                            subscription.pinned_blocks_headers.remove(hash);
                            if let Some(subscription_id) =
                                subscription.runtime_service_subscription_id
                            {
                                me.runtime_service.unpin_block(subscription_id, *hash).await;
                            }
                        }

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_unpin(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainHead_unstable_finalizedDatabase {
                        max_size_bytes,
                    } => {
                        let response = crate::database::encode_database(
                            &me.network_service,
                            &me.sync_service,
                            &me.runtime_service,
                            &me.genesis_block_hash,
                            usize::try_from(max_size_bytes.unwrap_or(u64::max_value()))
                                .unwrap_or(usize::max_value()),
                        )
                        .await;

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainHead_unstable_finalizedDatabase(
                                    response.into(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainSpec_v1_chainName {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainSpec_v1_chainName((&me.chain_name).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainSpec_v1_genesisHash {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainSpec_v1_genesisHash(
                                    methods::HashHexString(me.genesis_block_hash),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chainSpec_v1_properties {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::chainSpec_v1_properties(
                                    serde_json::from_str(&me.chain_properties_json).unwrap(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::sudo_unstable_p2pDiscover { multiaddr } => {
                        match multiaddr.parse::<multiaddr::Multiaddr>() {
                            Ok(mut addr)
                                if matches!(
                                    addr.iter().last(),
                                    Some(multiaddr::Protocol::P2p(_))
                                ) =>
                            {
                                let peer_id_bytes = match addr.iter().last() {
                                    Some(multiaddr::Protocol::P2p(peer_id)) => {
                                        peer_id.into_bytes().to_owned()
                                    }
                                    _ => unreachable!(),
                                };
                                addr.pop();

                                match PeerId::from_bytes(peer_id_bytes) {
                                    Ok(peer_id) => {
                                        me.network_service
                                            .discover(
                                                iter::once((peer_id, iter::once(addr))),
                                                false,
                                            )
                                            .await;
                                        let _ = me
                                            .responses_tx
                                            .send(
                                                methods::Response::sudo_unstable_p2pDiscover(())
                                                    .to_json_response(request_id_json),
                                            )
                                            .await;
                                    }
                                    Err(_) => {
                                        let _ = me
                                            .responses_tx
                                            .send(parse::build_error_response(
                                                request_id_json,
                                                parse::ErrorResponse::InvalidParams,
                                                Some(
                                                    &serde_json::to_string(
                                                        "multiaddr doesn't end with /p2p",
                                                    )
                                                    .unwrap_or_else(|_| unreachable!()),
                                                ),
                                            ))
                                            .await;
                                    }
                                }
                            }
                            Ok(_) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::InvalidParams,
                                        Some(
                                            &serde_json::to_string(
                                                "multiaddr doesn't end with /p2p",
                                            )
                                            .unwrap_or_else(|_| unreachable!()),
                                        ),
                                    ))
                                    .await;
                            }
                            Err(err) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::InvalidParams,
                                        Some(
                                            &serde_json::to_string(&err.to_string())
                                                .unwrap_or_else(|_| unreachable!()),
                                        ),
                                    ))
                                    .await;
                            }
                        }
                    }

                    methods::MethodCall::sudo_unstable_version {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::sudo_unstable_version(
                                    format!("{} {}", me.system_name, me.system_version).into(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::transactionWatch_unstable_submitAndWatch {
                        transaction: methods::HexString(transaction),
                    } => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        let mut transaction_updates = Box::pin(
                            me.transactions_service
                                .submit_and_watch_transaction(transaction, 16)
                                .await,
                        );

                        let _prev_value = me.transactions_subscriptions.insert(
                            subscription_id.clone(),
                            TransactionWatch {
                                included_block: None,
                                num_broadcasted_peers: 0,
                                ty: TransactionWatchTy::NewApi,
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::transactionWatch_unstable_submitAndWatch(
                                    Cow::Borrowed(&subscription_id),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;

                        me.background_tasks.push(Box::pin(async move {
                            let Some(status) = transaction_updates.as_mut().next().await else {
                                unreachable!()
                            };
                            Event::TransactionEvent {
                                subscription_id,
                                event: status,
                                watcher: transaction_updates,
                            }
                        }));
                    }

                    methods::MethodCall::transactionWatch_unstable_unwatch { subscription } => {
                        let exists = me
                            .transactions_subscriptions
                            .get(&*subscription)
                            .map_or(false, |sub| matches!(sub.ty, TransactionWatchTy::NewApi));
                        if exists {
                            me.transactions_subscriptions.remove(&*subscription);
                        }
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::transactionWatch_unstable_unwatch(())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    _method @ (methods::MethodCall::account_nextIndex { .. }
                    | methods::MethodCall::author_hasKey { .. }
                    | methods::MethodCall::author_hasSessionKeys { .. }
                    | methods::MethodCall::author_insertKey { .. }
                    | methods::MethodCall::author_removeExtrinsic { .. }
                    | methods::MethodCall::author_rotateKeys { .. }
                    | methods::MethodCall::babe_epochAuthorship { .. }
                    | methods::MethodCall::childstate_getKeys { .. }
                    | methods::MethodCall::childstate_getStorage { .. }
                    | methods::MethodCall::childstate_getStorageHash { .. }
                    | methods::MethodCall::childstate_getStorageSize { .. }
                    | methods::MethodCall::grandpa_roundState { .. }
                    | methods::MethodCall::offchain_localStorageGet { .. }
                    | methods::MethodCall::offchain_localStorageSet { .. }
                    | methods::MethodCall::state_getPairs { .. }
                    | methods::MethodCall::state_getReadProof { .. }
                    | methods::MethodCall::state_getStorageHash { .. }
                    | methods::MethodCall::state_getStorageSize { .. }
                    | methods::MethodCall::state_queryStorage { .. }
                    | methods::MethodCall::system_addReservedPeer { .. }
                    | methods::MethodCall::system_dryRun { .. }
                    | methods::MethodCall::system_localPeerId { .. }
                    | methods::MethodCall::system_networkState { .. }
                    | methods::MethodCall::system_removeReservedPeer { .. }
                    | methods::MethodCall::sudo_network_unstable_watch { .. }
                    | methods::MethodCall::sudo_network_unstable_unwatch { .. }) => {
                        // TODO: implement the ones that make sense to implement ^
                        log!(
                            &me.platform,
                            Warn,
                            &me.log_target,
                            format!("JSON-RPC call not supported yet: {:?}", _method)
                        );
                        let _ = me
                            .responses_tx
                            .send(parse::build_error_response(
                                request_id_json,
                                json_rpc::parse::ErrorResponse::ServerError(
                                    -32000,
                                    "Not implemented in smoldot yet",
                                ),
                                None,
                            ))
                            .await;
                    }

                    _ => todo!(),
                }
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json: request_id,
                request:
                    request @ (MultiStageRequest::ChainGetHeader { .. }
                    | MultiStageRequest::StateCallStage1 { .. }
                    | MultiStageRequest::StateGetKeysStage1 { .. }
                    | MultiStageRequest::StateGetKeysPagedStage1 { .. }
                    | MultiStageRequest::StateQueryStorageAtStage1 { .. }
                    | MultiStageRequest::StateGetMetadataStage1 { .. }
                    | MultiStageRequest::StateGetStorageStage1 { .. }
                    | MultiStageRequest::StateGetRuntimeVersionStage1 { .. }
                    | MultiStageRequest::PaymentQueryInfoStage1 { .. }
                    | MultiStageRequest::SystemAccountNextIndexStage1 { .. }),
            } => {
                let block_hash = match &request {
                    MultiStageRequest::ChainGetHeader { block_hash, .. }
                    | MultiStageRequest::StateCallStage1 { block_hash, .. }
                    | MultiStageRequest::StateGetKeysStage1 { block_hash, .. }
                    | MultiStageRequest::StateGetKeysPagedStage1 { block_hash, .. }
                    | MultiStageRequest::StateQueryStorageAtStage1 { block_hash, .. }
                    | MultiStageRequest::StateGetMetadataStage1 { block_hash }
                    | MultiStageRequest::StateGetStorageStage1 { block_hash, .. }
                    | MultiStageRequest::StateGetRuntimeVersionStage1 { block_hash }
                    | MultiStageRequest::PaymentQueryInfoStage1 { block_hash, .. }
                    | MultiStageRequest::SystemAccountNextIndexStage1 { block_hash, .. } => {
                        *block_hash
                    }
                    _ => unreachable!(),
                };

                // If the value is available in cache, switch the request to the next stage.
                if let Some(in_cache) = me.block_headers_cache.get(&block_hash) {
                    let Ok((_, state_trie_root_hash, block_number)) = in_cache else {
                        let _ = me
                            .responses_tx
                            .send(parse::build_error_response(
                                &request_id,
                                parse::ErrorResponse::ServerError(-32800, "invalid block header"),
                                None,
                            ))
                            .await;
                        continue;
                    };

                    // TODO: advance to stage 2
                    todo!();

                    continue;
                }

                // Value is not available in cache.
                match me.block_headers_pending.entry(block_hash) {
                    hashbrown::hash_map::Entry::Occupied(entry) => {
                        // We are already in the process of asking the networking service for
                        // the block information.
                        // Keep track of the request.
                        debug_assert!(!entry.get().is_empty());
                        entry.into_mut().push((request_id, request));
                    }
                    hashbrown::hash_map::Entry::Vacant(entry) => {
                        // No network request is in progress yet. Start one.
                        me.background_tasks.push({
                            let block_info_retrieve_future =
                                me.sync_service.clone().block_query_unknown_number(
                                    block_hash,
                                    codec::BlocksRequestFields {
                                        header: true,
                                        body: false,
                                        justifications: false,
                                    },
                                    3,
                                    Duration::from_secs(5),
                                    NonZeroU32::new(1).unwrap_or_else(|| unreachable!()),
                                );
                            // TODO: must check accuracy of hash
                            Box::pin(async move {
                                Event::BlockInfoRetrieved {
                                    block_hash,
                                    result: todo!(), // block_info_retrieve_future.await,
                                }
                            })
                        });

                        // Keep track of the request.
                        let mut list = Vec::with_capacity(4);
                        list.push((request_id, request));
                        entry.insert(list);
                    }
                }
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json: request_id,
                request:
                    request @ (MultiStageRequest::StateCallStage2 { .. }
                    | MultiStageRequest::StateGetMetadataStage2 { .. }
                    | MultiStageRequest::StateGetRuntimeVersionStage2 { .. }
                    | MultiStageRequest::PaymentQueryInfoStage2 { .. }
                    | MultiStageRequest::SystemAccountNextIndexStage2 { .. }),
            } => {
                let (block_hash, block_state_trie_root_hash, block_number) = match &request {
                    MultiStageRequest::StateGetMetadataStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                    }
                    | MultiStageRequest::StateGetRuntimeVersionStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                    }
                    | MultiStageRequest::PaymentQueryInfoStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        ..
                    }
                    | MultiStageRequest::SystemAccountNextIndexStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        ..
                    } => (*block_hash, *block_state_trie_root_hash, *block_number),
                    _ => unreachable!(),
                };

                // If the value is available in cache, do the runtime call.
                if let Some(in_cache) = me.block_runtimes_cache.get(&block_hash) {
                    if let MultiStageRequest::StateGetRuntimeVersionStage2 { .. } = &request {
                        match me
                            .runtime_service
                            .pinned_runtime_specification(in_cache.clone())
                            .await
                        {
                            Ok(spec) => {
                                let _ = me
                                    .responses_tx
                                    .send(
                                        methods::Response::state_getRuntimeVersion(
                                            convert_runtime_version_legacy(&spec),
                                        )
                                        .to_json_response(&request_id),
                                    )
                                    .await;
                            }
                            Err(error) => {
                                let _ = me
                                    .responses_tx
                                    .send(parse::build_error_response(
                                        &request_id,
                                        json_rpc::parse::ErrorResponse::ServerError(
                                            -32000,
                                            &error.to_string(),
                                        ),
                                        None,
                                    ))
                                    .await;
                            }
                        }

                        continue;
                    }

                    let (function_name, required_api_version, parameters_vectored) = match request {
                        MultiStageRequest::StateCallStage2 {
                            name, parameters, ..
                        } => (name, None, Vec::new()),
                        MultiStageRequest::StateGetMetadataStage2 { .. } => (
                            "Metadata_metadata".to_owned(),
                            Some(("Metadata".to_owned(), 1..=2)),
                            Vec::new(),
                        ),
                        MultiStageRequest::PaymentQueryInfoStage2 { extrinsic, .. } => (
                            json_rpc::payment_info::PAYMENT_FEES_FUNCTION_NAME.to_owned(),
                            Some(("TransactionPaymentApi".to_owned(), 1..=2)),
                            json_rpc::payment_info::payment_info_parameters(&extrinsic).fold(
                                Vec::new(),
                                |mut a, b| {
                                    a.extend_from_slice(b.as_ref());
                                    a
                                },
                            ),
                        ),
                        MultiStageRequest::SystemAccountNextIndexStage2 { account_id, .. } => (
                            "AccountNonceApi_account_nonce".to_owned(),
                            Some(("AccountNonceApi".to_owned(), 1..=1)),
                            account_id,
                        ),
                        _ => unreachable!(),
                    };

                    let runtime_call_future = me.runtime_service.runtime_call(
                        in_cache.clone(),
                        block_hash,
                        block_number,
                        block_state_trie_root_hash,
                        function_name,
                        required_api_version,
                        parameters_vectored,
                        3,
                        Duration::from_secs(5),
                        NonZeroU32::new(1).unwrap_or_else(|| unreachable!()),
                    );

                    me.background_tasks.push(Box::pin(async move { todo!() }));
                    continue;
                }

                // Runtime is not available in cache.
                match me.block_runtimes_pending.entry(block_hash) {
                    hashbrown::hash_map::Entry::Occupied(entry) => {
                        // We are already in the process of asking the networking service for
                        // the runtime.
                        // Keep track of the request.
                        debug_assert!(!entry.get().is_empty());
                        entry.into_mut().push((request_id, request));
                    }
                    hashbrown::hash_map::Entry::Vacant(entry) => {
                        // No network request is in progress yet. Start one.
                        me.background_tasks.push(Box::pin({
                            let sync_service = me.sync_service.clone();
                            let runtime_service = me.runtime_service.clone();
                            // TODO: move to separate function
                            async move {
                                let (
                                    storage_code,
                                    storage_heap_pages,
                                    code_merkle_value,
                                    code_closest_ancestor_excluding,
                                ) = {
                                    let mut storage_code = None;
                                    let mut storage_heap_pages = None;
                                    let mut code_merkle_value = None;
                                    let mut code_closest_ancestor_excluding = None;

                                    let mut query =
                                        sync_service
                                        .storage_query(
                                            block_number,
                                            block_hash,
                                            block_state_trie_root_hash,
                                            [
                                                sync_service::StorageRequestItem {
                                                    key: b":code".to_vec(),
                                                    ty: sync_service::StorageRequestItemTy::ClosestDescendantMerkleValue,
                                                },
                                                sync_service::StorageRequestItem {
                                                    key: b":code".to_vec(),
                                                    ty: sync_service::StorageRequestItemTy::Value,
                                                },
                                                sync_service::StorageRequestItem {
                                                    key: b":heappages".to_vec(),
                                                    ty: sync_service::StorageRequestItemTy::Value,
                                                },
                                            ]
                                            .into_iter(),
                                            3,
                                            Duration::from_secs(20),
                                            NonZeroU32::new(1).unwrap(),
                                        )
                                        .advance()
                                        .await;

                                    loop {
                                        match query {
                                            sync_service::StorageQueryProgress::Finished => {
                                                break (
                                                    storage_code,
                                                    storage_heap_pages,
                                                    code_merkle_value,
                                                    code_closest_ancestor_excluding,
                                                )
                                            }
                                            sync_service::StorageQueryProgress::Progress {
                                                request_index: 0,
                                                item:
                                                    sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                                                        closest_descendant_merkle_value,
                                                        found_closest_ancestor_excluding,
                                                        ..
                                                    },
                                                query: next,
                                            } => {
                                                code_merkle_value = closest_descendant_merkle_value;
                                                code_closest_ancestor_excluding = found_closest_ancestor_excluding;
                                                query = next.advance().await;
                                            }
                                            sync_service::StorageQueryProgress::Progress {
                                                request_index: 1,
                                                item: sync_service::StorageResultItem::Value { value, .. },
                                                query: next,
                                            } => {
                                                storage_code = value;
                                                query = next.advance().await;
                                            }
                                            sync_service::StorageQueryProgress::Progress {
                                                request_index: 2,
                                                item: sync_service::StorageResultItem::Value { value, .. },
                                                query: next,
                                            } => {
                                                storage_heap_pages = value;
                                                query = next.advance().await;
                                            }
                                            sync_service::StorageQueryProgress::Progress { .. } => unreachable!(),
                                            sync_service::StorageQueryProgress::Error(error) => {
                                                return Event::RuntimeDownloaded {
                                                    block_hash,
                                                    result: Err(()),
                                                }
                                            }
                                        }
                                    }
                                };

                                // Give the code and heap pages to the runtime service. The runtime service will
                                // try to find any similar runtime it might have, and if not will compile it.
                                let pinned_runtime = runtime_service
                                    .compile_and_pin_runtime(
                                        storage_code,
                                        storage_heap_pages,
                                        code_merkle_value,
                                        code_closest_ancestor_excluding,
                                    )
                                    .await;

                                Event::RuntimeDownloaded {
                                    block_hash,
                                    result: pinned_runtime.map_err(|_| ()),
                                }
                            }
                        }));

                        // Keep track of the request.
                        let mut list = Vec::with_capacity(4);
                        list.push((request_id, request));
                        entry.insert(list);
                    }
                }
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json,
                request:
                    request @ (MultiStageRequest::StateGetKeysStage2 { .. }
                    | MultiStageRequest::StateGetKeysPagedStage2 { .. }
                    | MultiStageRequest::StateQueryStorageAtStage2 { .. }
                    | MultiStageRequest::StateGetStorageStage2 { .. }),
            } => {
                let (
                    block_hash,
                    block_state_trie_root_hash,
                    block_number,
                    request,
                    storage_request,
                ) = match request {
                    MultiStageRequest::StateGetKeysStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        prefix,
                    } => (
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        MultiStageRequest::StateGetKeysStage3 {
                            in_progress_results: Vec::with_capacity(32),
                        },
                        either::Left(iter::once(sync_service::StorageRequestItem {
                            key: prefix.clone(),
                            ty: sync_service::StorageRequestItemTy::DescendantsHashes,
                        })),
                    ),
                    MultiStageRequest::StateGetKeysPagedStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        prefix,
                        count,
                        start_key,
                    } => (
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        MultiStageRequest::StateGetKeysPagedStage3 {
                            in_progress_results: Vec::with_capacity(32),
                        },
                        either::Left(iter::once(sync_service::StorageRequestItem {
                            key: prefix.clone(),
                            ty: sync_service::StorageRequestItemTy::DescendantsHashes,
                        })),
                    ),
                    MultiStageRequest::StateQueryStorageAtStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        keys,
                    } => (
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        MultiStageRequest::StateQueryStorageAtStage3 {
                            block_hash,
                            in_progress_results: Vec::with_capacity(keys.len()),
                        },
                        either::Right(keys.into_iter().map(|key| {
                            sync_service::StorageRequestItem {
                                key: key.0,
                                ty: sync_service::StorageRequestItemTy::Value,
                            }
                        })),
                    ),
                    MultiStageRequest::StateGetStorageStage2 {
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        key,
                    } => (
                        block_hash,
                        block_state_trie_root_hash,
                        block_number,
                        MultiStageRequest::StateGetStorageStage3 {},
                        either::Left(iter::once(sync_service::StorageRequestItem {
                            key,
                            ty: sync_service::StorageRequestItemTy::Value,
                        })),
                    ),
                    _ => unreachable!(),
                };

                let storage_query = me.sync_service.clone().storage_query(
                    block_number,
                    block_hash,
                    block_state_trie_root_hash,
                    storage_request,
                    3,
                    Duration::from_secs(10),
                    NonZeroU32::new(1).unwrap_or_else(|| unreachable!()),
                );

                me.background_tasks.push(Box::pin(async move {
                    Event::StorageRequestInProgress {
                        request_id_json,
                        request,
                        progress: storage_query.advance().await,
                    }
                }));
            }

            WakeUpReason::AdvanceMultiStageRequest {
                request_id_json: request_id,
                request:
                    request @ (MultiStageRequest::StateGetKeysStage3 { .. }
                    | MultiStageRequest::StateGetStorageStage3 { .. }
                    | MultiStageRequest::StateGetKeysPagedStage3 { .. }
                    | MultiStageRequest::StateQueryStorageAtStage3 { .. }),
            } => {
                unreachable!()
            }

            WakeUpReason::Event(Event::StorageRequestInProgress {
                request_id_json,
                request,
                progress,
            }) => match (progress, request) {
                (
                    sync_service::StorageQueryProgress::Progress {
                        item: sync_service::StorageResultItem::DescendantHash { key, .. },
                        query: next,
                        ..
                    },
                    MultiStageRequest::StateGetKeysStage3 {
                        mut in_progress_results,
                    },
                ) => {
                    in_progress_results.push(methods::HexString(key));
                    me.background_tasks.push(Box::pin(async move {
                        Event::StorageRequestInProgress {
                            request_id_json,
                            request: MultiStageRequest::StateGetKeysStage3 {
                                in_progress_results,
                            },
                            progress: next.advance().await,
                        }
                    }));
                }
                (
                    sync_service::StorageQueryProgress::Finished,
                    MultiStageRequest::StateGetKeysStage3 {
                        in_progress_results,
                    },
                ) => {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::Response::state_getKeys(in_progress_results)
                                .to_json_response(&request_id_json),
                        )
                        .await;
                }
                (
                    sync_service::StorageQueryProgress::Progress {
                        item: sync_service::StorageResultItem::DescendantHash { key, .. },
                        query: next,
                        ..
                    },
                    MultiStageRequest::StateGetKeysPagedStage3 {
                        mut in_progress_results,
                    },
                ) => {
                    in_progress_results.push(key);
                    me.background_tasks.push(Box::pin(async move {
                        Event::StorageRequestInProgress {
                            request_id_json,
                            request: MultiStageRequest::StateGetKeysPagedStage3 {
                                in_progress_results,
                            },
                            progress: next.advance().await,
                        }
                    }));
                }
                (
                    sync_service::StorageQueryProgress::Finished,
                    MultiStageRequest::StateGetKeysPagedStage3 {
                        in_progress_results,
                    },
                ) => {
                    // TODO: no; filter by count and start key and add to cache and all
                    let _ = me
                        .responses_tx
                        .send(
                            methods::Response::state_getKeysPaged(
                                in_progress_results
                                    .into_iter()
                                    .map(methods::HexString)
                                    .collect(),
                            )
                            .to_json_response(&request_id_json),
                        )
                        .await;
                }
                (
                    sync_service::StorageQueryProgress::Progress {
                        item: sync_service::StorageResultItem::Value { key, value },
                        query: next,
                        ..
                    },
                    MultiStageRequest::StateQueryStorageAtStage3 {
                        block_hash,
                        mut in_progress_results,
                    },
                ) => {
                    in_progress_results
                        .push((methods::HexString(key), value.map(methods::HexString)));
                    me.background_tasks.push(Box::pin(async move {
                        Event::StorageRequestInProgress {
                            request_id_json,
                            request: MultiStageRequest::StateQueryStorageAtStage3 {
                                block_hash,
                                in_progress_results,
                            },
                            progress: next.advance().await,
                        }
                    }));
                }
                (
                    sync_service::StorageQueryProgress::Finished,
                    MultiStageRequest::StateQueryStorageAtStage3 {
                        block_hash,
                        in_progress_results,
                    },
                ) => {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::Response::state_queryStorageAt(vec![
                                methods::StorageChangeSet {
                                    block: methods::HashHexString(block_hash),
                                    changes: in_progress_results,
                                },
                            ])
                            .to_json_response(&request_id_json),
                        )
                        .await;
                }
                (
                    sync_service::StorageQueryProgress::Progress {
                        item:
                            sync_service::StorageResultItem::Value {
                                value: Some(value), ..
                            },
                        query: next,
                        ..
                    },
                    MultiStageRequest::StateGetStorageStage3 {},
                ) => {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::Response::state_getStorage(methods::HexString(value))
                                .to_json_response(&request_id_json),
                        )
                        .await;
                }
                (
                    sync_service::StorageQueryProgress::Progress {
                        item: sync_service::StorageResultItem::Value { value: None, .. },
                        query: next,
                        ..
                    },
                    MultiStageRequest::StateGetStorageStage3 {},
                ) => {
                    let _ = me
                        .responses_tx
                        .send(parse::build_success_response(&request_id_json, "null"))
                        .await;
                }
                (sync_service::StorageQueryProgress::Error(error), _) => {
                    let _ = me
                        .responses_tx
                        .send(parse::build_error_response(
                            &request_id_json,
                            parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                            None,
                        ))
                        .await;
                }
                _ => unreachable!(),
            },

            WakeUpReason::Event(
                event @ (Event::ChainHeadSubscriptionWithRuntimeReady { .. }
                | Event::ChainHeadSubscriptionWithoutRuntimeReady { .. }),
            ) => {
                // Extract the event information.
                let (
                    subscription_id,
                    mut new_blocks,
                    finalized_block_scale_encoded_header,
                    finalized_block_runtime,
                    non_finalized_blocks_ancestry_order,
                ) = match event {
                    Event::ChainHeadSubscriptionWithRuntimeReady {
                        subscription_id,
                        subscription,
                    } => (
                        subscription_id,
                        either::Left(subscription.new_blocks),
                        subscription.finalized_block_scale_encoded_header,
                        Some(subscription.finalized_block_runtime),
                        either::Left(
                            subscription
                                .non_finalized_blocks_ancestry_order
                                .into_iter()
                                .map(either::Left),
                        ),
                    ),
                    Event::ChainHeadSubscriptionWithoutRuntimeReady {
                        subscription_id,
                        subscription,
                    } => (
                        subscription_id,
                        either::Right(Box::pin(subscription.new_blocks)),
                        subscription.finalized_block_scale_encoded_header,
                        None,
                        either::Right(
                            subscription
                                .non_finalized_blocks_ancestry_order
                                .into_iter()
                                .map(either::Right),
                        ),
                    ),
                    _ => unreachable!(),
                };

                // It might be that the JSON-RPC client has unsubscribed before the subscription
                // was initialized.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    continue;
                };

                // Store the subscription ID in the subscription.
                if let either::Left(new_blocks) = &new_blocks {
                    subscription_info.runtime_service_subscription_id = Some(new_blocks.id());
                }

                // Send the `initialized` event and pin the finalized block.
                let finalized_block_hash =
                    header::hash_from_scale_encoded_header(&finalized_block_scale_encoded_header); // TODO: indicate hash in subscription?
                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::Initialized {
                                finalized_block_hash: methods::HashHexString(finalized_block_hash),
                                finalized_block_runtime: finalized_block_runtime.as_ref().map(
                                    |runtime| match runtime {
                                        Ok(rt) => methods::MaybeRuntimeSpec::Valid {
                                            spec: convert_runtime_version(&rt),
                                        },
                                        Err(error) => methods::MaybeRuntimeSpec::Invalid {
                                            error: error.to_string(),
                                        },
                                    },
                                ),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
                subscription_info
                    .pinned_blocks_headers
                    .insert(finalized_block_hash, finalized_block_scale_encoded_header);

                // Send an event for each non-finalized block.
                for block in non_finalized_blocks_ancestry_order {
                    let parent_block_hash = header::hash_from_scale_encoded_header(match &block {
                        either::Left(b) => b.parent_hash,
                        either::Right(b) => b.parent_hash,
                    }); // TODO: indicate hash in subscription?
                    let hash = header::hash_from_scale_encoded_header(match &block {
                        either::Left(b) => &b.scale_encoded_header,
                        either::Right(b) => &b.scale_encoded_header,
                    }); // TODO: indicate hash in subscription?
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: Cow::Borrowed(&subscription_id),
                                result: methods::FollowEvent::NewBlock {
                                    block_hash: methods::HashHexString(hash),
                                    parent_block_hash: methods::HashHexString(parent_block_hash),
                                    new_runtime: if let either::Left(block) = &block {
                                        if let Some(rt) = &block.new_runtime {
                                            match rt {
                                                Ok(spec) => {
                                                    Some(methods::MaybeRuntimeSpec::Valid {
                                                        spec: convert_runtime_version(spec),
                                                    })
                                                }
                                                Err(error) => {
                                                    Some(methods::MaybeRuntimeSpec::Invalid {
                                                        error: error.to_string(),
                                                    })
                                                }
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    },
                                },
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                    if match &block {
                        either::Left(b) => b.is_new_best,
                        either::Right(b) => b.is_new_best,
                    } {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    subscription_info.pinned_blocks_headers.insert(
                        hash,
                        match block {
                            either::Left(b) => b.scale_encoded_header,
                            either::Right(b) => b.scale_encoded_header,
                        },
                    );

                    subscription_info.non_finalized_blocks.insert(
                        if parent_block_hash == finalized_block_hash {
                            None
                        } else {
                            Some(
                                subscription_info
                                    .non_finalized_blocks
                                    .iter_unordered()
                                    .find(|(_, b)| **b == parent_block_hash)
                                    .map(|(idx, _)| idx)
                                    .unwrap_or_else(|| unreachable!()),
                            )
                        },
                        hash,
                    );
                }

                me.background_tasks.push({
                    match new_blocks {
                        either::Left(mut new_blocks) => Box::pin(async move {
                            if let Some(notification) = new_blocks.next().await {
                                Event::ChainHeadSubscriptionWithRuntimeNotification {
                                    subscription_id,
                                    notification,
                                    stream: new_blocks,
                                }
                            } else {
                                Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                            }
                        }),
                        either::Right(mut new_blocks) => Box::pin(async move {
                            if let Some(notification) = new_blocks.next().await {
                                Event::ChainHeadSubscriptionWithoutRuntimeNotification {
                                    subscription_id,
                                    notification,
                                    stream: new_blocks,
                                }
                            } else {
                                Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                            }
                        }),
                    }
                });
            }

            WakeUpReason::Event(Event::ChainHeadSubscriptionWithRuntimeNotification {
                subscription_id,
                notification,
                mut stream,
            }) => {
                // It might be that the JSON-RPC client has unsubscribed.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    continue;
                };

                match notification {
                    runtime_service::Notification::Finalized {
                        hash,
                        best_block_hash,
                        pruned_blocks,
                    } => todo!(),
                    runtime_service::Notification::BestBlockChanged { hash } => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    runtime_service::Notification::Block(block) => todo!(),
                }

                me.background_tasks.push(Box::pin(async move {
                    if let Some(notification) = stream.next().await {
                        Event::ChainHeadSubscriptionWithRuntimeNotification {
                            subscription_id,
                            notification,
                            stream,
                        }
                    } else {
                        Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                    }
                }))
            }

            WakeUpReason::Event(Event::ChainHeadSubscriptionWithoutRuntimeNotification {
                subscription_id,
                notification,
                mut stream,
            }) => {
                // It might be that the JSON-RPC client has unsubscribed.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.get_mut(&subscription_id)
                else {
                    continue;
                };

                match notification {
                    sync_service::Notification::Finalized {
                        hash,
                        best_block_hash,
                    } => todo!(),
                    sync_service::Notification::BestBlockChanged { hash } => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::BestBlockChanged {
                                        best_block_hash: methods::HashHexString(hash),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    sync_service::Notification::Block(block) => todo!(),
                }

                me.background_tasks.push(Box::pin(async move {
                    if let Some(notification) = stream.next().await {
                        Event::ChainHeadSubscriptionWithoutRuntimeNotification {
                            subscription_id,
                            notification,
                            stream,
                        }
                    } else {
                        Event::ChainHeadSubscriptionDeadSubcription { subscription_id }
                    }
                }))
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result: Ok(success),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationCallDone {
                                operation_id: operation_id.clone().into(),
                                output: methods::HexString(success.output),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result: Err(runtime_service::RuntimeCallError::InvalidRuntime(error)),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                result: Err(runtime_service::RuntimeCallError::ApiVersionRequirementUnfulfilled),
                ..
            }) => {
                // We pass `None` for the API requirement, thus this error can never happen.
                unreachable!()
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result: Err(runtime_service::RuntimeCallError::Crash),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                // TODO: is this the appropriate error?
                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationInaccessible {
                                operation_id: operation_id.clone().into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result: Err(runtime_service::RuntimeCallError::Inaccessible(_)),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationInaccessible {
                                operation_id: operation_id.clone().into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result:
                    Err(runtime_service::RuntimeCallError::Execution(
                        runtime_service::RuntimeCallExecutionError::ForbiddenHostFunction,
                    )),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: "Runtime has called an offchain host function"
                                    .to_string()
                                    .into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result:
                    Err(runtime_service::RuntimeCallError::Execution(
                        runtime_service::RuntimeCallExecutionError::Start(error),
                    )),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadCallOperationDone {
                subscription_id,
                operation_id,
                result:
                    Err(runtime_service::RuntimeCallError::Execution(
                        runtime_service::RuntimeCallExecutionError::Execution(error),
                    )),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationError {
                                operation_id: operation_id.clone().into(),
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadBodyOperationDone {
                subscription_id,
                operation_id,
                expected_extrinsics_root,
                result,
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                // We must check whether the body is present in the response and valid.
                // TODO: should try the request again with a different peer instead of failing immediately
                let body = match result {
                    Ok(result) => {
                        if let Some(body) = result.body {
                            if header::extrinsics_root(&body) == expected_extrinsics_root {
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
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::OperationBodyDone {
                                        operation_id: operation_id.clone().into(),
                                        value: body.into_iter().map(methods::HexString).collect(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    Err(()) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::chainHead_unstable_followEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::FollowEvent::OperationInaccessible {
                                        operation_id: operation_id.clone().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                }
            }

            WakeUpReason::Event(Event::ChainHeadStorageOperationProgress {
                subscription_id,
                operation_id,
                progress:
                    sync_service::StorageQueryProgress::Progress {
                        request_index,
                        item,
                        mut query,
                    },
            }) => {
                let mut items_chunk = Vec::with_capacity(16);

                for (_, item) in
                    iter::once((request_index, item)).chain(iter::from_fn(|| query.try_advance()))
                {
                    // Perform some API conversion.
                    let item = match item {
                        sync_service::StorageResultItem::Value {
                            key,
                            value: Some(value),
                        } => Some(methods::ChainHeadStorageResponseItem {
                            key: methods::HexString(key),
                            value: Some(methods::HexString(value)),
                            hash: None,
                            closest_descendant_merkle_value: None,
                        }),
                        sync_service::StorageResultItem::Value { value: None, .. } => None,
                        sync_service::StorageResultItem::Hash {
                            key,
                            hash: Some(hash),
                        } => Some(methods::ChainHeadStorageResponseItem {
                            key: methods::HexString(key),
                            value: None,
                            hash: Some(methods::HexString(hash.to_vec())),
                            closest_descendant_merkle_value: None,
                        }),
                        sync_service::StorageResultItem::Hash { hash: None, .. } => None,
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
                        sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                            requested_key,
                            closest_descendant_merkle_value: Some(merkle_value),
                            ..
                        } => Some(methods::ChainHeadStorageResponseItem {
                            key: methods::HexString(requested_key),
                            value: None,
                            hash: None,
                            closest_descendant_merkle_value: Some(methods::HexString(merkle_value)),
                        }),
                        sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                            closest_descendant_merkle_value: None,
                            ..
                        } => None,
                    };

                    if let Some(item) = item {
                        items_chunk.push(item);
                    }
                }

                if !items_chunk.is_empty() {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: Cow::Borrowed(&subscription_id),
                                result: methods::FollowEvent::OperationStorageItems {
                                    operation_id: Cow::Borrowed(&operation_id),
                                    items: items_chunk,
                                },
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                }

                // TODO: generate a waitingForContinue here and wait for user to continue

                // Re-queue the operation for later.
                let on_interrupt = me
                    .chain_head_follow_subscriptions
                    .get(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .get(&operation_id)
                    .unwrap_or_else(|| unreachable!())
                    .interrupt
                    .listen();
                me.background_tasks.push(Box::pin(async move {
                    async {
                        on_interrupt.await;
                        Event::ChainHeadOperationCancelled
                    }
                    .or(async {
                        Event::ChainHeadStorageOperationProgress {
                            subscription_id,
                            operation_id,
                            progress: query.advance().await,
                        }
                    })
                    .await
                }));
            }

            WakeUpReason::Event(Event::ChainHeadStorageOperationProgress {
                subscription_id,
                operation_id,
                progress: sync_service::StorageQueryProgress::Finished,
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationStorageDone {
                                operation_id: Cow::Borrowed(&operation_id),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadStorageOperationProgress {
                subscription_id,
                operation_id,
                progress: sync_service::StorageQueryProgress::Error(_),
            }) => {
                let _prev_value = me
                    .chain_head_follow_subscriptions
                    .get_mut(&subscription_id)
                    .unwrap_or_else(|| unreachable!())
                    .operations_in_progress
                    .remove(&operation_id);
                debug_assert!(_prev_value.is_some());

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::OperationInaccessible {
                                operation_id: Cow::Borrowed(&operation_id),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadSubscriptionDeadSubcription {
                subscription_id,
            }) => {
                // It might be that the JSON-RPC client has already unsubscribed.
                let Some(subscription_info) =
                    me.chain_head_follow_subscriptions.remove(&subscription_id)
                else {
                    continue;
                };

                for (_, operation) in subscription_info.operations_in_progress {
                    operation.interrupt.notify(usize::max_value());
                }

                let _ = me
                    .responses_tx
                    .send(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: Cow::Borrowed(&subscription_id),
                            result: methods::FollowEvent::Stop {},
                        }
                        .to_json_request_object_parameters(None),
                    )
                    .await;
            }

            WakeUpReason::Event(Event::ChainHeadOperationCancelled) => {
                // Nothing to do.
            }

            WakeUpReason::RuntimeServiceSubscriptionReady(subscribe_all) => {
                // Runtime service is now ready to give us blocks.

                // We must transition to `RuntimeServiceSubscription::Active`.
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

                me.runtime_service_subscription = RuntimeServiceSubscription::Active {
                    subscription: subscribe_all.new_blocks,
                    pinned_blocks,
                    finalized_and_pruned_lru,
                    current_best_block,
                    new_heads_and_runtime_subscriptions_stale: Some(None),
                    current_finalized_block: finalized_block_hash,
                    finalized_heads_subscriptions_stale: true,
                };
            }

            WakeUpReason::RuntimeServiceSubscriptionDead => {
                // The subscription towards the runtime service needs to be renewed.

                // The buffer size should be large enough so that, if the CPU is busy, it
                // doesn't become full before the execution of this task resumes.
                // The maximum number of pinned block is ignored, as this maximum is a way to
                // avoid malicious behaviors. This code is by definition not considered
                // malicious.
                let runtime_service = me.runtime_service.clone();
                me.runtime_service_subscription =
                    RuntimeServiceSubscription::Pending(Box::pin(async move {
                        runtime_service
                            .subscribe_all(
                                32,
                                NonZeroUsize::new(usize::max_value())
                                    .unwrap_or_else(|| unreachable!()),
                            )
                            .await
                    }));
            }

            WakeUpReason::RuntimeServiceSubscriptionNotification {
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

            WakeUpReason::RuntimeServiceSubscriptionNotification {
                notification: runtime_service::Notification::Block(block),
                pinned_blocks,
                current_best_block,
                new_heads_and_runtime_subscriptions_stale,
                ..
            } => {
                let json_rpc_header = match methods::Header::from_scale_encoded_header(
                    &block.scale_encoded_header,
                    me.runtime_service.block_number_bytes(),
                ) {
                    Ok(h) => h,
                    Err(error) => {
                        log!(
                            &me.platform,
                            Warn,
                            &me.log_target,
                            format!(
                                "`chain_subscribeAllHeads` subscription has skipped block \
                                due to undecodable header. Hash: {}. Error: {}",
                                HashDisplay(&header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header
                                )),
                                error
                            )
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

                for subscription_id in &me.all_heads_subscriptions {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::ServerToClient::chain_allHead {
                                subscription: subscription_id.as_str().into(),
                                result: json_rpc_header.clone(),
                            }
                            .to_json_request_object_parameters(None),
                        )
                        .await;
                }

                if block.is_new_best {
                    *new_heads_and_runtime_subscriptions_stale = Some(Some(*current_best_block));
                    *current_best_block = hash;
                }
            }

            WakeUpReason::RuntimeServiceSubscriptionNotification {
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

            WakeUpReason::Event(Event::BlockInfoRetrieved {
                block_hash,
                result: Ok(result),
            }) => {
                me.block_headers_cache.put(block_hash, result);

                for (request_id, request) in me
                    .block_headers_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flat_map(|l| l)
                {
                    // Note that we push_front in order to guarantee that the information is
                    // not removed from cache before the request is processed.
                    me.multistage_requests_to_advance
                        .push_front((request_id, request));
                }
            }

            WakeUpReason::Event(Event::BlockInfoRetrieved {
                block_hash,
                result: Err(()),
            }) => {
                for (request_id, _) in me
                    .block_headers_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flat_map(|l| l)
                {
                    let _ = me
                        .responses_tx
                        .send(parse::build_error_response(
                            &request_id,
                            parse::ErrorResponse::ServerError(
                                -32800,
                                "failed to retrieve block information from the network",
                            ),
                            None,
                        ))
                        .await;
                }
            }

            WakeUpReason::Event(Event::RuntimeDownloaded {
                block_hash,
                result: Ok(result),
            }) => {
                me.block_runtimes_cache.put(block_hash, result);

                for (request_id, request) in me
                    .block_runtimes_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flat_map(|l| l)
                {
                    // Note that we push_front in order to guarantee that the information is
                    // not removed from cache before the request is processed.
                    me.multistage_requests_to_advance
                        .push_front((request_id, request));
                }
            }

            WakeUpReason::Event(Event::RuntimeDownloaded {
                block_hash,
                result: Err(()),
            }) => {
                for (request_id, _) in me
                    .block_runtimes_pending
                    .remove(&block_hash)
                    .into_iter()
                    .flat_map(|l| l)
                {
                    let _ = me
                        .responses_tx
                        .send(parse::build_error_response(
                            &request_id,
                            parse::ErrorResponse::ServerError(
                                -32800,
                                "failed to retrieve runtime from the network",
                            ),
                            None,
                        ))
                        .await;
                }
            }

            WakeUpReason::Event(Event::TransactionEvent {
                subscription_id,
                event: transactions_service::TransactionStatus::Dropped(drop_reason),
                ..
            }) => {
                let Some(transaction_watch) =
                    me.transactions_subscriptions.remove(&subscription_id)
                else {
                    // JSON-RPC client has unsubscribed from this transaction and is no longer
                    // interested in events.
                    continue;
                };

                match (drop_reason, transaction_watch.ty) {
                    (transactions_service::DropReason::GapInChain, TransactionWatchTy::Legacy)
                    | (
                        transactions_service::DropReason::MaxPendingTransactionsReached,
                        TransactionWatchTy::Legacy,
                    )
                    | (transactions_service::DropReason::Invalid(_), TransactionWatchTy::Legacy)
                    | (
                        transactions_service::DropReason::ValidateError(_),
                        TransactionWatchTy::Legacy,
                    )
                    | (transactions_service::DropReason::Crashed, TransactionWatchTy::Legacy) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::Dropped,
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (transactions_service::DropReason::GapInChain, TransactionWatchTy::NewApi) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Dropped {
                                        error: "gap in chain of blocks".into(),
                                        broadcasted: transaction_watch.num_broadcasted_peers != 0,
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::MaxPendingTransactionsReached,
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Dropped {
                                        error: "transactions pool full".into(),
                                        broadcasted: transaction_watch.num_broadcasted_peers != 0,
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::Invalid(error),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Invalid {
                                        error: error.to_string().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::ValidateError(error),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Error {
                                        error: error.to_string().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (transactions_service::DropReason::Crashed, TransactionWatchTy::NewApi) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Error {
                                        error: "transactions service has crashed".into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::DropReason::Finalized { block_hash, .. },
                        TransactionWatchTy::Legacy,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::Finalized(
                                        methods::HashHexString(block_hash),
                                    ),
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::DropReason::Finalized { block_hash, index },
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Finalized {
                                        block: methods::TransactionWatchEventBlock {
                                            hash: methods::HashHexString(block_hash),
                                            index,
                                        },
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                }
            }

            WakeUpReason::Event(Event::TransactionEvent {
                subscription_id,
                event,
                mut watcher,
            }) => {
                let Some(transaction_watch) =
                    me.transactions_subscriptions.get_mut(&subscription_id)
                else {
                    // JSON-RPC client has unsubscribed from this transaction and is no longer
                    // interested in events.
                    continue;
                };

                match (event, &transaction_watch.ty) {
                    (
                        transactions_service::TransactionStatus::Broadcast(peers),
                        TransactionWatchTy::Legacy,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::Broadcast(
                                        peers.into_iter().map(|peer| peer.to_base58()).collect(),
                                    ),
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::Broadcast(peers),
                        TransactionWatchTy::NewApi,
                    ) => {
                        transaction_watch.num_broadcasted_peers += peers.len();
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Broadcasted {
                                        num_peers: u32::try_from(
                                            transaction_watch.num_broadcasted_peers,
                                        )
                                        .unwrap_or(u32::max_value()),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::TransactionStatus::Validated,
                        TransactionWatchTy::Legacy,
                    ) => {
                        // Nothing to do.
                    }
                    (
                        transactions_service::TransactionStatus::Validated,
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionWatchEvent::Validated {},
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: Some((block_hash, _)),
                        },
                        TransactionWatchTy::Legacy,
                    ) => {
                        transaction_watch.included_block = Some(block_hash);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result: methods::TransactionStatus::InBlock(
                                        methods::HashHexString(block_hash),
                                    ),
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: None,
                        },
                        TransactionWatchTy::Legacy,
                    ) => {
                        if let Some(block_hash) = transaction_watch.included_block.take() {
                            let _ = me
                                .responses_tx
                                .send(
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: Cow::Borrowed(&subscription_id),
                                        result: methods::TransactionStatus::Retracted(
                                            methods::HashHexString(block_hash),
                                        ),
                                    }
                                    .to_json_request_object_parameters(None),
                                )
                                .await;
                        }
                    }
                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: Some((block_hash, index)),
                        },
                        TransactionWatchTy::NewApi,
                    ) => {
                        transaction_watch.included_block = Some(block_hash);
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result:
                                        methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: Some(methods::TransactionWatchEventBlock {
                                                hash: methods::HashHexString(block_hash),
                                                index,
                                            }),
                                        },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::IncludedBlockUpdate {
                            block_hash: None,
                        },
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: Cow::Borrowed(&subscription_id),
                                    result:
                                        methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: None,
                                        },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    // `Dropped` was handle above separately.
                    (transactions_service::TransactionStatus::Dropped(_), _) => unreachable!(),
                }

                // Add back an item to the events stream.
                me.background_tasks.push(Box::pin(async move {
                    let Some(status) = watcher.as_mut().next().await else {
                        unreachable!()
                    };
                    Event::TransactionEvent {
                        subscription_id,
                        event: status,
                        watcher,
                    }
                }));
            }

            WakeUpReason::Event(Event::ChainGetBlockResult {
                request_id_json,
                mut result,
                expected_block_hash,
            }) => {
                // Check whether the header and body are present and valid.
                // TODO: try the request again with a different peerin case the response is invalid, instead of returning null
                if let Ok(block) = &result {
                    if let (Some(header), Some(body)) = (&block.header, &block.body) {
                        if header::hash_from_scale_encoded_header(header) == expected_block_hash {
                            if let Ok(decoded) =
                                header::decode(header, me.sync_service.block_number_bytes())
                            {
                                if header::extrinsics_root(body) != *decoded.extrinsics_root {
                                    result = Err(());
                                }
                            } else {
                                // Note that if the header is undecodable it doesn't necessarily mean
                                // that the header and/or body is bad, but given that we have no way to
                                // check this we return an error.
                                result = Err(());
                            }
                        } else {
                            result = Err(());
                        }
                    } else {
                        result = Err(());
                    }
                }

                // Send the response.
                if let Ok(block) = result {
                    let _ = me
                        .responses_tx
                        .send(
                            methods::Response::chain_getBlock(methods::Block {
                                extrinsics: block
                                    .body
                                    .unwrap()
                                    .into_iter()
                                    .map(methods::HexString)
                                    .collect(),
                                header: methods::Header::from_scale_encoded_header(
                                    &block.header.unwrap(),
                                    me.sync_service.block_number_bytes(),
                                )
                                .unwrap(),
                                // There's no way to verify the correctness of the justifications, consequently
                                // we always return an empty list.
                                justifications: None,
                            })
                            .to_json_response(&request_id_json),
                        )
                        .await;
                } else {
                    let _ = me
                        .responses_tx
                        .send(parse::build_success_response(&request_id_json, "null"))
                        .await;
                }
            }

            WakeUpReason::StartStorageSubscriptions => {
                let RuntimeServiceSubscription::Active {
                    pinned_blocks,
                    current_best_block,
                    ..
                } = &mut me.runtime_service_subscription
                else {
                    unreachable!()
                };

                // If the header of the current best block can't be decoded, we don't start
                // the task.
                let (block_number, state_trie_root) = match header::decode(
                    &pinned_blocks
                        .get(current_best_block)
                        .unwrap()
                        .scale_encoded_header,
                    me.runtime_service.block_number_bytes(),
                ) {
                    Ok(header) => (header.number, *header.state_root),
                    Err(_) => {
                        // Can't decode the header of the current best block.
                        // All the subscriptions are marked as non-stale, since they are up-to-date
                        // with the current best block.
                        // TODO: print warning?
                        me.stale_storage_subscriptions.clear();
                        continue;
                    }
                };

                // Build the list of keys that must be requested by aggregating the keys requested
                // by all stale storage subscriptions.
                let mut keys = hashbrown::HashSet::with_hasher(SipHasherBuild::new({
                    let mut seed = [0; 16];
                    me.platform.fill_random_bytes(&mut seed);
                    seed
                }));
                keys.extend(
                    me.stale_storage_subscriptions
                        .iter()
                        .map(|s_id: &Arc<str>| &me.storage_subscriptions.get(s_id).unwrap().1)
                        .flat_map(|keys_list| keys_list.iter().cloned()),
                );

                // If the list of keys to query is empty, we mark all subscriptions as no longer
                // stale and loop again. This is necessary in order to prevent infinite loops if
                // the JSON-RPC client subscribes to an empty list of items.
                if keys.is_empty() {
                    me.stale_storage_subscriptions.clear();
                    continue;
                }

                // Start the task in the background.
                // The task will send a `Message::StorageFetch` once it is done.
                me.storage_query_in_progress = true;
                me.background_tasks.push(Box::pin({
                    let block_hash = *current_best_block;
                    let sync_service = me.sync_service.clone();
                    async move {
                        let mut out = Vec::with_capacity(keys.len());
                        let mut query = sync_service
                            .storage_query(
                                block_number,
                                block_hash,
                                state_trie_root,
                                keys.into_iter()
                                    .map(|key| sync_service::StorageRequestItem {
                                        key,
                                        ty: sync_service::StorageRequestItemTy::Value,
                                    }),
                                4,
                                Duration::from_secs(12),
                                NonZeroU32::new(2).unwrap(),
                            )
                            .advance()
                            .await;
                        loop {
                            match query {
                                sync_service::StorageQueryProgress::Progress {
                                    item,
                                    query: next,
                                    ..
                                } => {
                                    out.push(item);
                                    query = next.advance().await;
                                }
                                sync_service::StorageQueryProgress::Finished => {
                                    break Event::StorageSubscriptionsUpdate {
                                        block_hash,
                                        result: Ok(out),
                                    };
                                }
                                sync_service::StorageQueryProgress::Error(error) => {
                                    break Event::StorageSubscriptionsUpdate {
                                        block_hash,
                                        result: Err(error),
                                    };
                                }
                            }
                        }
                    }
                }));
            }

            // Background task dedicated to performing a storage query for the storage
            // subscription has finished.
            WakeUpReason::Event(Message::StorageSubscriptionsUpdate {
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
                        me.stale_storage_subscriptions.remove(&subscription_id);
                    }
                    me.storage_subscriptions
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
            WakeUpReason::Event(Event::StorageSubscriptionsUpdate { result: Err(_), .. }) => {
                debug_assert!(me.storage_query_in_progress);
                task.storage_query_in_progress = false;
                // TODO: add a delay or something?
            }

            WakeUpReason::NotifyFinalizedHeads => {
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
                            log!(
                                &task.platform,
                                Warn,
                                &task.log_target,
                                format!(
                                    "`chain_subscribeFinalizedHeads` subscription has skipped \
                                    block due to undecodable header. Hash: {}. Error: {}",
                                    HashDisplay(current_finalized_block),
                                    error,
                                )
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

            WakeUpReason::NotifyNewHeadsRuntimeSubscriptions(previous_best_block) => {
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
                        log!(
                            &task.platform,
                            Warn,
                            &task.log_target,
                            format!(
                                "`chain_subscribeNewHeads` subscription has skipped block due to \
                                undecodable header. Hash: {}. Error: {}",
                                HashDisplay(current_best_block),
                                error
                            )
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
    }
}

fn convert_runtime_version_legacy(
    runtime_spec: &smoldot::executor::CoreVersion,
) -> methods::RuntimeVersion {
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

fn convert_runtime_version(runtime_spec: &smoldot::executor::CoreVersion) -> methods::RuntimeSpec {
    let runtime_spec = runtime_spec.decode();
    methods::RuntimeSpec {
        spec_name: runtime_spec.spec_name.into(),
        impl_name: runtime_spec.impl_name.into(),
        spec_version: runtime_spec.spec_version,
        impl_version: runtime_spec.impl_version,
        transaction_version: runtime_spec.transaction_version,
        apis: runtime_spec
            .apis
            .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
            .collect(),
    }
}
