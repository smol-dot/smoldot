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
    network_service, platform::PlatformRef, runtime_service, sync_service, transactions_service,
};

use super::StartConfig;

use alloc::{
    borrow::ToOwned as _,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use async_lock::Mutex;
use core::{
    iter,
    num::{NonZeroU32, NonZeroUsize},
    ops,
    sync::atomic,
    time::Duration,
};
use futures_util::{future, FutureExt as _};
use smoldot::{
    executor::{host, runtime_host},
    header,
    json_rpc::{self, methods, requests_subscriptions},
    libp2p::{multiaddr, PeerId},
    network::protocol,
};

mod chain_head;
mod getters;
mod state_chain;
mod transactions;

/// Fields used to process JSON-RPC requests in the background.
struct Background<TPlat: PlatformRef> {
    /// Target to use for all the logs.
    log_target: String,

    /// Access to the platform's capabilities.
    platform: TPlat,

    /// State machine holding all the clients, requests, and subscriptions.
    ///
    /// Only requests that are valid JSON-RPC are insert into the state machine. However, requests
    /// can try to call an unknown method, or have invalid parameters.
    requests_subscriptions: Arc<requests_subscriptions::RequestsSubscriptions<SubscriptionMessage>>,

    /// Name of the chain, as found in the chain specification.
    chain_name: String,
    /// Type of chain, as found in the chain specification.
    chain_ty: String,
    /// JSON-encoded properties of the chain, as found in the chain specification.
    chain_properties_json: String,
    /// Whether the chain is a live network. Found in the chain specification.
    chain_is_live: bool,
    /// See [`StartConfig::peer_id`]. The only use for this field is to send the Base58 encoding of
    /// the [`PeerId`]. Consequently, we store the conversion to Base58 ahead of time.
    peer_id_base58: String,
    /// Value to return when the `system_name` RPC is called.
    system_name: String,
    /// Value to return when the `system_version` RPC is called.
    system_version: String,

    /// See [`StartConfig::network_service`].
    network_service: (Arc<network_service::NetworkService<TPlat>>, usize),
    /// See [`StartConfig::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`StartConfig::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    /// See [`StartConfig::transactions_service`].
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Various information caches about blocks, to potentially reduce the number of network
    /// requests to perform.
    cache: Mutex<Cache>,

    /// Hash of the genesis block.
    /// Keeping the genesis block is important, as the genesis block hash is included in
    /// transaction signatures, and must therefore be queried by upper-level UIs.
    genesis_block_hash: [u8; 32],

    /// If `true`, we have already printed a warning about usage of the legacy JSON-RPC API. This
    /// flag prevents printing this message multiple times.
    printed_legacy_json_rpc_warning: atomic::AtomicBool,
}

pub(super) enum SubscriptionMessage {
    StopIfAllHeads {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfNewHeads {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfFinalizedHeads {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfStorage {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfTransactionLegacy {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfTransaction {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfRuntimeSpec {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfChainHeadBody {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfChainHeadCall {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfChainHeadStorage {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    StopIfChainHeadFollow {
        stop_request_id: (String, requests_subscriptions::RequestId),
    },
    ChainHeadFollowUnpin {
        hash: methods::HashHexString,
        unpin_request_id: (String, requests_subscriptions::RequestId),
    },
    ChainHeadHeader {
        hash: methods::HashHexString,
        get_request_id: (String, requests_subscriptions::RequestId),
    },
    ChainHeadCall {
        hash: methods::HashHexString,
        get_request_id: (String, requests_subscriptions::RequestId),
        function_to_call: String,
        call_parameters: methods::HexString,
        network_config: methods::NetworkConfig,
    },
    ChainHeadStorage {
        hash: methods::HashHexString,
        get_request_id: (String, requests_subscriptions::RequestId),
        network_config: methods::NetworkConfig,
        key: methods::HexString,
        child_trie: Option<methods::HexString>,
        ty: methods::ChainHeadStorageType,
    },
    ChainHeadStorageContinue {
        continue_request_id: (String, requests_subscriptions::RequestId),
    },
    ChainHeadBody {
        hash: methods::HashHexString,
        get_request_id: (String, requests_subscriptions::RequestId),
        network_config: methods::NetworkConfig,
    },
}

struct Cache {
    /// When the runtime service reports a new block, it is kept pinned and inserted in this LRU
    /// cache. When an entry in removed from the cache, it is unpinned.
    ///
    /// JSON-RPC clients are more likely to ask for information about recent blocks and perform
    /// calls on them, hence a cache of recent blocks.
    recent_pinned_blocks: lru::LruCache<[u8; 32], Vec<u8>, fnv::FnvBuildHasher>,

    /// Subscription on the runtime service under which the blocks of
    /// [`Cache::recent_pinned_blocks`] are pinned.
    ///
    /// Contains `None` only at initialization, in which case [`Cache::recent_pinned_blocks`]
    /// is guaranteed to be empty. In other words, if a block is found in
    /// [`Cache::recent_pinned_blocks`] then this field is guaranteed to be `Some`.
    subscription_id: Option<runtime_service::SubscriptionId>,

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

    /// When `state_getKeysPaged` is called and the response is truncated, the response is
    /// inserted in this cache. The API user is likely to call `state_getKeysPaged` again with
    /// the same parameters, in which case we hit the cache and avoid the networking requests.
    /// The keys are `(block_hash, prefix)` and values are list of keys.
    state_get_keys_paged:
        lru::LruCache<([u8; 32], Option<methods::HexString>), Vec<Vec<u8>>, fnv::FnvBuildHasher>,
}

pub(super) fn start<TPlat: PlatformRef>(
    log_target: String,
    requests_subscriptions: Arc<requests_subscriptions::RequestsSubscriptions<SubscriptionMessage>>,
    config: StartConfig<'_, TPlat>,
    max_parallel_requests: NonZeroU32,
    max_parallel_subscription_updates: NonZeroU32,
    background_abort_registrations: Vec<future::AbortRegistration>,
) {
    let me = Arc::new(Background {
        log_target,
        platform: config.platform,
        requests_subscriptions,
        chain_name: config.chain_spec.name().to_owned(),
        chain_ty: config.chain_spec.chain_type().to_owned(),
        chain_is_live: config.chain_spec.has_live_network(),
        chain_properties_json: config.chain_spec.properties().to_owned(),
        peer_id_base58: config.peer_id.to_base58(),
        system_name: config.system_name.clone(),
        system_version: config.system_version.clone(),
        network_service: config.network_service.clone(),
        sync_service: config.sync_service.clone(),
        runtime_service: config.runtime_service.clone(),
        transactions_service: config.transactions_service.clone(),
        cache: Mutex::new(Cache {
            recent_pinned_blocks: lru::LruCache::with_hasher(
                NonZeroUsize::new(32).unwrap(),
                Default::default(),
            ),
            subscription_id: None,
            block_state_root_hashes_numbers: lru::LruCache::with_hasher(
                NonZeroUsize::new(32).unwrap(),
                Default::default(),
            ),
            state_get_keys_paged: lru::LruCache::with_hasher(
                NonZeroUsize::new(2).unwrap(),
                Default::default(),
            ),
        }),
        genesis_block_hash: config.genesis_block_hash,
        printed_legacy_json_rpc_warning: atomic::AtomicBool::new(false),
    });

    let mut background_abort_registrations = background_abort_registrations.into_iter();

    // A certain number of tasks (`max_parallel_requests`) are dedicated to pulling requests
    // from the inner state machine and processing them.
    // Each task can only process one request at a time, which is why we spawn one task per
    // desired level of parallelism.
    for n in 0..max_parallel_requests.get() {
        let me_task = me.clone();
        me.platform.spawn_task(
            format!("{}-requests-{}", me_task.log_target, n).into(),
            future::Abortable::new(
                async move {
                    loop {
                        me_task.handle_request().await;

                        // We yield once between each request in order to politely let other tasks
                        // do some work and not monopolize the CPU.
                        me_task.platform.yield_after_cpu_intensive().await;
                    }
                },
                background_abort_registrations.next().unwrap(),
            )
            .map(|_: Result<(), _>| ())
            .boxed(),
        );
    }

    // A certain number of tasks (`max_parallel_subscription_updates`) are dedicated to
    // processing subscriptions-related tasks after they wake up.
    for n in 0..max_parallel_subscription_updates.get() {
        let me_task = me.clone();
        me.platform.spawn_task(
            format!("{}-subscriptions-{}", me_task.log_target, n).into(),
            future::Abortable::new(
                async move {
                    loop {
                        me_task.requests_subscriptions.run_subscription_task().await;

                        // We yield once between each request in order to politely let other tasks
                        // do some work and not monopolize the CPU.
                        me_task.platform.yield_after_cpu_intensive().await;
                    }
                },
                background_abort_registrations.next().unwrap(),
            )
            .map(|_: Result<(), _>| ())
            .boxed(),
        );
    }

    // Spawn one task dedicated to filling the `Cache` with new blocks from the runtime
    // service.
    // TODO: this is actually racy, as a block subscription task could report a new block to a client, and then client can query it, before this block has been been added to the cache
    // TODO: extract to separate function
    me.platform
        .clone()
        .spawn_task(format!("{}-cache-populate", me.log_target).into(), {
            future::Abortable::new(
                async move {
                    loop {
                        let mut cache = me.cache.lock().await;

                        // Subscribe to new runtime service blocks in order to push them in the
                        // cache as soon as they are available.
                        // The buffer size should be large enough so that, if the CPU is busy, it
                        // doesn't become full before the execution of this task resumes.
                        // The maximum number of pinned block is ignored, as this maximum is a way to
                        // avoid malicious behaviors. This code is by definition not considered
                        // malicious.
                        let mut subscribe_all = me
                            .runtime_service
                            .subscribe_all(
                                "json-rpc-blocks-cache",
                                32,
                                NonZeroUsize::new(usize::max_value()).unwrap(),
                            )
                            .await;

                        cache.subscription_id = Some(subscribe_all.new_blocks.id());
                        cache.recent_pinned_blocks.clear();
                        debug_assert!(cache.recent_pinned_blocks.cap().get() >= 1);

                        let finalized_block_hash = header::hash_from_scale_encoded_header(
                            &subscribe_all.finalized_block_scale_encoded_header,
                        );
                        cache.recent_pinned_blocks.put(
                            finalized_block_hash,
                            subscribe_all.finalized_block_scale_encoded_header,
                        );

                        for block in subscribe_all.non_finalized_blocks_ancestry_order {
                            if cache.recent_pinned_blocks.len()
                                == cache.recent_pinned_blocks.cap().get()
                            {
                                let (hash, _) = cache.recent_pinned_blocks.pop_lru().unwrap();
                                subscribe_all.new_blocks.unpin_block(&hash).await;
                            }

                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            cache
                                .recent_pinned_blocks
                                .put(hash, block.scale_encoded_header);
                        }

                        drop(cache);

                        loop {
                            let notification = subscribe_all.new_blocks.next().await;
                            match notification {
                                Some(runtime_service::Notification::Block(block)) => {
                                    let mut cache = me.cache.lock().await;

                                    if cache.recent_pinned_blocks.len()
                                        == cache.recent_pinned_blocks.cap().get()
                                    {
                                        let (hash, _) =
                                            cache.recent_pinned_blocks.pop_lru().unwrap();
                                        subscribe_all.new_blocks.unpin_block(&hash).await;
                                    }

                                    let hash = header::hash_from_scale_encoded_header(
                                        &block.scale_encoded_header,
                                    );
                                    cache
                                        .recent_pinned_blocks
                                        .put(hash, block.scale_encoded_header);
                                }
                                Some(runtime_service::Notification::Finalized { .. })
                                | Some(runtime_service::Notification::BestBlockChanged {
                                    ..
                                }) => {}
                                None => break,
                            }
                        }
                    }
                },
                background_abort_registrations.next().unwrap(),
            )
            .map(|_: Result<(), _>| ())
            .boxed()
        });

    debug_assert!(background_abort_registrations.next().is_none());
}

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Pulls one request from the inner state machine, and processes it.
    async fn handle_request(self: &Arc<Self>) {
        let (json_rpc_request, state_machine_request_id) =
            self.requests_subscriptions.next_request().await;
        log::debug!(target: &self.log_target, "PendingRequestsQueue => {}",
            crate::util::truncated_str(
                json_rpc_request.chars().filter(|c| !c.is_control()),
                100,
            )
        );

        // Check whether the JSON-RPC request is correct, and bail out if it isn't.
        let (request_id, call) = match methods::parse_json_call(&json_rpc_request) {
            Ok((request_id, call)) => (request_id, call),
            Err(methods::ParseError::Method { request_id, error }) => {
                log::warn!(
                    target: &self.log_target,
                    "Error in JSON-RPC method call with id {:?}: {}", request_id, error
                );
                self.requests_subscriptions
                    .respond(&state_machine_request_id, error.to_json_error(request_id))
                    .await;
                return;
            }
            Err(_) => {
                // We make sure to not insert in the state machine requests that are not valid
                // JSON-RPC requests.
                unreachable!()
            }
        };

        // Print a warning for legacy JSON-RPC functions.
        match call {
            methods::MethodCall::account_nextIndex { .. }
            | methods::MethodCall::author_hasKey { .. }
            | methods::MethodCall::author_hasSessionKeys { .. }
            | methods::MethodCall::author_insertKey { .. }
            | methods::MethodCall::author_pendingExtrinsics { .. }
            | methods::MethodCall::author_removeExtrinsic { .. }
            | methods::MethodCall::author_rotateKeys { .. }
            | methods::MethodCall::author_submitAndWatchExtrinsic { .. }
            | methods::MethodCall::author_submitExtrinsic { .. }
            | methods::MethodCall::author_unwatchExtrinsic { .. }
            | methods::MethodCall::babe_epochAuthorship { .. }
            | methods::MethodCall::chain_getBlock { .. }
            | methods::MethodCall::chain_getBlockHash { .. }
            | methods::MethodCall::chain_getFinalizedHead { .. }
            | methods::MethodCall::chain_getHeader { .. }
            | methods::MethodCall::chain_subscribeAllHeads { .. }
            | methods::MethodCall::chain_subscribeFinalizedHeads { .. }
            | methods::MethodCall::chain_subscribeNewHeads { .. }
            | methods::MethodCall::chain_unsubscribeAllHeads { .. }
            | methods::MethodCall::chain_unsubscribeFinalizedHeads { .. }
            | methods::MethodCall::chain_unsubscribeNewHeads { .. }
            | methods::MethodCall::childstate_getKeys { .. }
            | methods::MethodCall::childstate_getStorage { .. }
            | methods::MethodCall::childstate_getStorageHash { .. }
            | methods::MethodCall::childstate_getStorageSize { .. }
            | methods::MethodCall::grandpa_roundState { .. }
            | methods::MethodCall::offchain_localStorageGet { .. }
            | methods::MethodCall::offchain_localStorageSet { .. }
            | methods::MethodCall::payment_queryInfo { .. }
            | methods::MethodCall::state_call { .. }
            | methods::MethodCall::state_getKeys { .. }
            | methods::MethodCall::state_getKeysPaged { .. }
            | methods::MethodCall::state_getMetadata { .. }
            | methods::MethodCall::state_getPairs { .. }
            | methods::MethodCall::state_getReadProof { .. }
            | methods::MethodCall::state_getRuntimeVersion { .. }
            | methods::MethodCall::state_getStorage { .. }
            | methods::MethodCall::state_getStorageHash { .. }
            | methods::MethodCall::state_getStorageSize { .. }
            | methods::MethodCall::state_queryStorage { .. }
            | methods::MethodCall::state_queryStorageAt { .. }
            | methods::MethodCall::state_subscribeRuntimeVersion { .. }
            | methods::MethodCall::state_subscribeStorage { .. }
            | methods::MethodCall::state_unsubscribeRuntimeVersion { .. }
            | methods::MethodCall::state_unsubscribeStorage { .. }
            | methods::MethodCall::system_accountNextIndex { .. }
            | methods::MethodCall::system_addReservedPeer { .. }
            | methods::MethodCall::system_chain { .. }
            | methods::MethodCall::system_chainType { .. }
            | methods::MethodCall::system_dryRun { .. }
            | methods::MethodCall::system_health { .. }
            | methods::MethodCall::system_localListenAddresses { .. }
            | methods::MethodCall::system_localPeerId { .. }
            | methods::MethodCall::system_name { .. }
            | methods::MethodCall::system_networkState { .. }
            | methods::MethodCall::system_nodeRoles { .. }
            | methods::MethodCall::system_peers { .. }
            | methods::MethodCall::system_properties { .. }
            | methods::MethodCall::system_removeReservedPeer { .. }
            | methods::MethodCall::system_version { .. } => {
                if !self
                    .printed_legacy_json_rpc_warning
                    .swap(true, atomic::Ordering::Relaxed)
                {
                    log::warn!(
                        target: &self.log_target,
                        "The JSON-RPC client has just called a JSON-RPC function from the legacy \
                        JSON-RPC API ({}). Legacy JSON-RPC functions have loose semantics and \
                        cannot be properly implemented on a light client. You are encouraged to \
                        use the new JSON-RPC API \
                        <https://github.com/paritytech/json-rpc-interface-spec/> instead. The \
                        legacy JSON-RPC API functions will be deprecated and removed in the \
                        distant future.",
                        call.name()
                    )
                }
            }
            methods::MethodCall::chainHead_unstable_body { .. }
            | methods::MethodCall::chainHead_unstable_call { .. }
            | methods::MethodCall::chainHead_unstable_follow { .. }
            | methods::MethodCall::chainHead_unstable_genesisHash { .. }
            | methods::MethodCall::chainHead_unstable_header { .. }
            | methods::MethodCall::chainHead_unstable_stopBody { .. }
            | methods::MethodCall::chainHead_unstable_stopCall { .. }
            | methods::MethodCall::chainHead_unstable_stopStorage { .. }
            | methods::MethodCall::chainHead_unstable_storage { .. }
            | methods::MethodCall::chainHead_unstable_storageContinue { .. }
            | methods::MethodCall::chainHead_unstable_unfollow { .. }
            | methods::MethodCall::chainHead_unstable_unpin { .. }
            | methods::MethodCall::chainSpec_unstable_chainName { .. }
            | methods::MethodCall::chainSpec_unstable_genesisHash { .. }
            | methods::MethodCall::chainSpec_unstable_properties { .. }
            | methods::MethodCall::rpc_methods { .. }
            | methods::MethodCall::sudo_unstable_p2pDiscover { .. }
            | methods::MethodCall::sudo_unstable_version { .. }
            | methods::MethodCall::transaction_unstable_submitAndWatch { .. }
            | methods::MethodCall::transaction_unstable_unwatch { .. }
            | methods::MethodCall::network_unstable_subscribeEvents { .. }
            | methods::MethodCall::network_unstable_unsubscribeEvents { .. }
            | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {}
        }

        // Each call is handled in a separate method.
        match call {
            methods::MethodCall::author_pendingExtrinsics {} => {
                self.author_pending_extrinsics((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::author_submitExtrinsic { transaction } => {
                self.author_submit_extrinsic((request_id, &state_machine_request_id), transaction)
                    .await;
            }
            methods::MethodCall::author_submitAndWatchExtrinsic { transaction } => {
                self.submit_and_watch_transaction(
                    (request_id, &state_machine_request_id),
                    transaction,
                    true,
                )
                .await
            }
            methods::MethodCall::author_unwatchExtrinsic { subscription } => {
                self.author_unwatch_extrinsic(
                    (request_id, &state_machine_request_id),
                    &subscription,
                )
                .await;
            }
            methods::MethodCall::chain_getBlock { hash } => {
                self.chain_get_block((request_id, &state_machine_request_id), hash)
                    .await;
            }
            methods::MethodCall::chain_getBlockHash { height } => {
                self.chain_get_block_hash((request_id, &state_machine_request_id), height)
                    .await;
            }
            methods::MethodCall::chain_getFinalizedHead {} => {
                self.chain_get_finalized_head((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::chain_getHeader { hash } => {
                self.chain_get_header((request_id, &state_machine_request_id), hash)
                    .await;
            }
            methods::MethodCall::chain_subscribeAllHeads {} => {
                self.chain_subscribe_all_heads((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                self.chain_subscribe_finalized_heads((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::chain_subscribeNewHeads {} => {
                self.chain_subscribe_new_heads((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::chain_unsubscribeAllHeads { subscription } => {
                self.chain_unsubscribe_all_heads(
                    (request_id, &state_machine_request_id),
                    subscription,
                )
                .await;
            }
            methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription } => {
                self.chain_unsubscribe_finalized_heads(
                    (request_id, &state_machine_request_id),
                    subscription,
                )
                .await;
            }
            methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                self.chain_unsubscribe_new_heads(
                    (request_id, &state_machine_request_id),
                    subscription,
                )
                .await;
            }
            methods::MethodCall::payment_queryInfo { extrinsic, hash } => {
                self.payment_query_info(
                    (request_id, &state_machine_request_id),
                    &extrinsic.0,
                    hash.as_ref().map(|h| &h.0),
                )
                .await;
            }
            methods::MethodCall::rpc_methods {} => {
                self.rpc_methods((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::state_call {
                name,
                parameters,
                hash,
            } => {
                self.state_call(
                    (request_id, &state_machine_request_id),
                    &name,
                    parameters,
                    hash,
                )
                .await;
            }
            methods::MethodCall::state_getKeys { prefix, hash } => {
                self.state_get_keys((request_id, &state_machine_request_id), prefix, hash)
                    .await;
            }
            methods::MethodCall::state_getKeysPaged {
                prefix,
                count,
                start_key,
                hash,
            } => {
                self.state_get_keys_paged(
                    (request_id, &state_machine_request_id),
                    prefix,
                    count,
                    start_key,
                    hash,
                )
                .await;
            }
            methods::MethodCall::state_queryStorageAt { keys, at } => {
                self.state_query_storage_at((request_id, &state_machine_request_id), keys, at)
                    .await;
            }
            methods::MethodCall::state_getMetadata { hash } => {
                self.state_get_metadata((request_id, &state_machine_request_id), hash)
                    .await;
            }
            methods::MethodCall::state_getStorage { key, hash } => {
                self.state_get_storage((request_id, &state_machine_request_id), key, hash)
                    .await;
            }
            methods::MethodCall::state_subscribeRuntimeVersion {} => {
                self.state_subscribe_runtime_version((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::state_unsubscribeRuntimeVersion { subscription } => {
                self.state_unsubscribe_runtime_version(
                    (request_id, &state_machine_request_id),
                    &subscription,
                )
                .await;
            }
            methods::MethodCall::state_subscribeStorage { list } => {
                self.state_subscribe_storage((request_id, &state_machine_request_id), list)
                    .await;
            }
            methods::MethodCall::state_unsubscribeStorage { subscription } => {
                self.state_unsubscribe_storage(
                    (request_id, &state_machine_request_id),
                    &subscription,
                )
                .await;
            }
            methods::MethodCall::state_getRuntimeVersion { at } => {
                self.state_get_runtime_version(
                    (request_id, &state_machine_request_id),
                    at.as_ref().map(|h| &h.0),
                )
                .await;
            }
            methods::MethodCall::system_accountNextIndex { account } => {
                self.account_next_index((request_id, &state_machine_request_id), account)
                    .await;
            }
            methods::MethodCall::system_chain {} => {
                self.system_chain((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_chainType {} => {
                self.system_chain_type((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_health {} => {
                self.system_health((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_localListenAddresses {} => {
                self.system_local_listen_addresses((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_localPeerId {} => {
                self.system_local_peer_id((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_name {} => {
                self.system_name((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_nodeRoles {} => {
                self.system_node_roles((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_peers {} => {
                self.system_peers((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_properties {} => {
                self.system_properties((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::system_version {} => {
                self.system_version((request_id, &state_machine_request_id))
                    .await;
            }

            methods::MethodCall::chainHead_unstable_stopBody { subscription } => {
                self.chain_head_unstable_stop_body(
                    (request_id, &state_machine_request_id),
                    &subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_body {
                follow_subscription,
                hash,
                network_config,
            } => {
                self.chain_head_unstable_body(
                    (request_id, &state_machine_request_id),
                    &follow_subscription,
                    hash,
                    network_config,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_call {
                follow_subscription,
                hash,
                function,
                call_parameters,
                network_config,
            } => {
                self.chain_head_call(
                    (request_id, &state_machine_request_id),
                    &follow_subscription,
                    hash,
                    function.into_owned(),
                    call_parameters,
                    network_config,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_stopCall { subscription } => {
                self.chain_head_unstable_stop_call(
                    (request_id, &state_machine_request_id),
                    &subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_stopStorage { subscription } => {
                self.chain_head_unstable_stop_storage(
                    (request_id, &state_machine_request_id),
                    &subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_storage {
                follow_subscription,
                hash,
                key,
                child_trie,
                ty,
                network_config,
            } => {
                self.chain_head_storage(
                    (request_id, &state_machine_request_id),
                    &follow_subscription,
                    hash,
                    key,
                    child_trie,
                    ty,
                    network_config,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_storageContinue { subscription } => {
                self.chain_head_storage_continue(
                    (request_id, &state_machine_request_id),
                    &subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_follow { with_runtime } => {
                self.chain_head_follow((request_id, &state_machine_request_id), with_runtime)
                    .await;
            }
            methods::MethodCall::chainHead_unstable_genesisHash {} => {
                self.chain_head_unstable_genesis_hash((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::chainHead_unstable_header {
                follow_subscription,
                hash,
            } => {
                self.chain_head_unstable_header(
                    (request_id, &state_machine_request_id),
                    &follow_subscription,
                    hash,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_unpin {
                follow_subscription,
                hash,
            } => {
                self.chain_head_unstable_unpin(
                    (request_id, &state_machine_request_id),
                    &follow_subscription,
                    hash,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_unfollow {
                follow_subscription,
            } => {
                self.chain_head_unstable_unfollow(
                    (request_id, &state_machine_request_id),
                    &follow_subscription,
                )
                .await;
            }
            methods::MethodCall::chainHead_unstable_finalizedDatabase { max_size_bytes } => {
                self.chain_head_unstable_finalized_database(
                    (request_id, &state_machine_request_id),
                    max_size_bytes,
                )
                .await;
            }
            methods::MethodCall::chainSpec_unstable_chainName {} => {
                self.chain_spec_unstable_chain_name((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::chainSpec_unstable_genesisHash {} => {
                self.chain_spec_unstable_genesis_hash((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::chainSpec_unstable_properties {} => {
                self.chain_spec_unstable_properties((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::sudo_unstable_p2pDiscover { multiaddr } => {
                self.sudo_unstable_p2p_discover(
                    (request_id, &state_machine_request_id),
                    &multiaddr,
                )
                .await;
            }
            methods::MethodCall::sudo_unstable_version {} => {
                self.sudo_unstable_version((request_id, &state_machine_request_id))
                    .await;
            }
            methods::MethodCall::transaction_unstable_submitAndWatch { transaction } => {
                self.submit_and_watch_transaction(
                    (request_id, &state_machine_request_id),
                    transaction,
                    false,
                )
                .await
            }
            methods::MethodCall::transaction_unstable_unwatch { subscription } => {
                self.transaction_unstable_unwatch(
                    (request_id, &state_machine_request_id),
                    &subscription,
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
            | methods::MethodCall::system_networkState { .. }
            | methods::MethodCall::system_removeReservedPeer { .. }
            | methods::MethodCall::network_unstable_subscribeEvents { .. }
            | methods::MethodCall::network_unstable_unsubscribeEvents { .. }) => {
                // TODO: implement the ones that make sense to implement ^
                log::error!(target: &self.log_target, "JSON-RPC call not supported yet: {:?}", _method);
                self.requests_subscriptions
                    .respond(
                        &state_machine_request_id,
                        json_rpc::parse::build_error_response(
                            request_id,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Not implemented in smoldot yet",
                            ),
                            None,
                        ),
                    )
                    .await;
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::sudo_unstable_p2pDiscover`].
    async fn sudo_unstable_p2p_discover(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        multiaddr: &str,
    ) {
        let response = match multiaddr.parse::<multiaddr::Multiaddr>() {
            Ok(mut addr) if matches!(addr.iter().last(), Some(multiaddr::ProtocolRef::P2p(_))) => {
                let peer_id_bytes = match addr.iter().last() {
                    Some(multiaddr::ProtocolRef::P2p(peer_id)) => peer_id.into_owned(),
                    _ => unreachable!(),
                };
                addr.pop();

                match PeerId::from_bytes(peer_id_bytes) {
                    Ok(peer_id) => {
                        self.network_service
                            .0
                            .discover(
                                &self.platform.now(),
                                self.network_service.1,
                                iter::once((peer_id, iter::once(addr))),
                                false,
                            )
                            .await;
                        methods::Response::sudo_unstable_p2pDiscover(())
                            .to_json_response(request_id.0)
                    }
                    Err(_) => json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        Some(&serde_json::to_string("multiaddr doesn't end with /p2p").unwrap()),
                    ),
                }
            }
            Ok(_) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::InvalidParams,
                Some(&serde_json::to_string("multiaddr doesn't end with /p2p").unwrap()),
            ),
            Err(err) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::InvalidParams,
                Some(&serde_json::to_string(&err.to_string()).unwrap()),
            ),
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Obtain the state trie root hash and number of the given block, and make sure to put it
    /// in cache.
    async fn state_trie_root_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<([u8; 32], u64), StateTrieRootHashError> {
        let fetch = {
            // Try to find an existing entry in cache, and if not create one.
            let mut cache_lock = self.cache.lock().await;

            // Look in `recent_pinned_blocks`.
            match cache_lock
                .recent_pinned_blocks
                .get(hash)
                .map(|h| header::decode(h, self.sync_service.block_number_bytes()))
            {
                Some(Ok(header)) => return Ok((*header.state_root, header.number)),
                Some(Err(err)) => return Err(StateTrieRootHashError::HeaderDecodeError(err)), // TODO: can this actually happen? unclear
                None => {}
            }

            // Look in `block_state_root_hashes`.
            match cache_lock.block_state_root_hashes_numbers.get(hash) {
                Some(future::MaybeDone::Done(Ok(val))) => return Ok(*val),
                Some(future::MaybeDone::Future(f)) => f.clone(),
                Some(future::MaybeDone::Gone) => unreachable!(), // We never use `Gone`.
                Some(future::MaybeDone::Done(Err(
                    err @ StateTrieRootHashError::HeaderDecodeError(_),
                ))) => {
                    // In case of a fatal error, return immediately.
                    return Err(err.clone());
                }
                Some(future::MaybeDone::Done(Err(StateTrieRootHashError::NetworkQueryError)))
                | None => {
                    // No existing cache entry. Create the future that will perform the fetch
                    // but do not actually start doing anything now.
                    let fetch = {
                        let sync_service = self.sync_service.clone();
                        let hash = *hash;
                        async move {
                            // The sync service knows which peers are potentially aware of
                            // this block.
                            let result = sync_service
                                .clone()
                                .block_query_unknown_number(
                                    hash,
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
                                    hash
                                );
                                let decoded =
                                    header::decode(&header, sync_service.block_number_bytes())
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
                    let wrapped = fetch.boxed().shared();
                    cache_lock
                        .block_state_root_hashes_numbers
                        .put(*hash, future::maybe_done(wrapped.clone()));
                    wrapped
                }
            }
        };

        // We await separately to be certain that the lock isn't held anymore.
        fetch.await
    }

    async fn storage_query(
        &self,
        keys: impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone,
        hash: &[u8; 32],
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<Vec<Option<Vec<u8>>>, StorageQueryError> {
        let (state_trie_root_hash, block_number) = self
            .state_trie_root_hash(hash)
            .await
            .map_err(StorageQueryError::FindStorageRootHashError)?;

        let result = self
            .sync_service
            .clone()
            .storage_query(
                block_number,
                hash,
                &state_trie_root_hash,
                keys,
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await
            .map_err(StorageQueryError::StorageRetrieval)?;

        Ok(result)
    }

    /// Obtain a lock to the runtime of the given block against the runtime service.
    // TODO: return better error?
    async fn runtime_access(
        self: &Arc<Self>,
        block_hash: &[u8; 32],
    ) -> Result<runtime_service::RuntimeAccess<TPlat>, RuntimeCallError> {
        let cache_lock = self.cache.lock().await;

        // Try to find the block in the cache of recent blocks. Most of the time, the call target
        // should be in there.
        let lock = if cache_lock.recent_pinned_blocks.contains(block_hash) {
            // The runtime service has the block pinned, meaning that we can ask the runtime
            // service to perform the call.
            self.runtime_service
                .pinned_block_runtime_access(cache_lock.subscription_id.unwrap(), block_hash)
                .await
                .ok()
        } else {
            None
        };

        Ok(if let Some(lock) = lock {
            lock
        } else {
            // Second situation: the block is not in the cache of recent blocks. This isn't great.
            drop::<async_lock::MutexGuard<_>>(cache_lock);

            // The only solution is to download the runtime of the block in question from the network.

            // TODO: considering caching the runtime code the same way as the state trie root hash

            // In order to grab the runtime code and perform the call network request, we need
            // to know the state trie root hash and the height of the block.
            let (state_trie_root_hash, block_number) = self
                .state_trie_root_hash(block_hash)
                .await
                .map_err(RuntimeCallError::FindStorageRootHashError)?;

            // Download the runtime of this block. This takes a long time as the runtime is rather
            // big (around 1MiB in general).
            let (storage_code, storage_heap_pages) = {
                let mut code_query_result = self
                    .sync_service
                    .clone()
                    .storage_query(
                        block_number,
                        block_hash,
                        &state_trie_root_hash,
                        iter::once(&b":code"[..]).chain(iter::once(&b":heappages"[..])),
                        3,
                        Duration::from_secs(20),
                        NonZeroU32::new(1).unwrap(),
                    )
                    .await
                    .map_err(runtime_service::RuntimeCallError::StorageQuery)
                    .map_err(RuntimeCallError::Call)?;
                let heap_pages = code_query_result.pop().unwrap();
                let code = code_query_result.pop().unwrap();
                (code, heap_pages)
            };

            // Give the code and heap pages to the runtime service. The runtime service will
            // try to find any similar runtime it might have, and if not will compile it.
            let pinned_runtime_id = self
                .runtime_service
                .compile_and_pin_runtime(storage_code, storage_heap_pages)
                .await;

            let precall = self
                .runtime_service
                .pinned_runtime_access(
                    pinned_runtime_id.clone(),
                    *block_hash,
                    block_number,
                    state_trie_root_hash,
                )
                .await;

            // TODO: consider keeping pinned runtimes in a cache instead
            self.runtime_service.unpin_runtime(pinned_runtime_id).await;

            precall
        })
    }

    /// Performs a runtime call to a random block.
    async fn runtime_call(
        self: &Arc<Self>,
        block_hash: &[u8; 32],
        runtime_api: &str,
        required_api_version_range: impl ops::RangeBounds<u32>,
        function_to_call: &str,
        call_parameters: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<RuntimeCallResult, RuntimeCallError> {
        let (return_value, api_version) = self
            .runtime_call_inner(
                block_hash,
                Some((runtime_api, required_api_version_range)),
                function_to_call,
                call_parameters,
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await?;
        Ok(RuntimeCallResult {
            return_value,
            api_version: api_version.unwrap(),
        })
    }

    /// Performs a runtime call to a random block.
    ///
    /// Similar to [`Background::runtime_call`], except that the API version isn't checked.
    async fn runtime_call_no_api_check(
        self: &Arc<Self>,
        block_hash: &[u8; 32],
        function_to_call: &str,
        call_parameters: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<Vec<u8>, RuntimeCallError> {
        let (return_value, _api_version) = self
            .runtime_call_inner(
                block_hash,
                None::<(&str, ops::RangeFull)>,
                function_to_call,
                call_parameters,
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await?;
        debug_assert!(_api_version.is_none());
        Ok(return_value)
    }

    /// Performs a runtime call to a random block.
    async fn runtime_call_inner(
        self: &Arc<Self>,
        block_hash: &[u8; 32],
        runtime_api_check: Option<(&str, impl ops::RangeBounds<u32>)>,
        function_to_call: &str,
        call_parameters: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<(Vec<u8>, Option<u32>), RuntimeCallError> {
        // This function contains two steps: obtaining the runtime of the block in question,
        // then performing the actual call. The first step is the longest and most difficult.
        let precall = self.runtime_access(block_hash).await?;

        let (runtime_call_lock, virtual_machine) = precall
            .start(
                function_to_call,
                call_parameters.clone(),
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await
            .unwrap(); // TODO: don't unwrap

        // Check that the runtime version is correct.
        let runtime_api_version = if let Some((api_name, version_range)) = runtime_api_check {
            let version = virtual_machine
                .runtime_version()
                .decode()
                .apis
                .find_version(api_name);
            match version {
                None => {
                    runtime_call_lock.unlock(virtual_machine);
                    return Err(RuntimeCallError::ApiNotFound);
                }
                Some(v) if version_range.contains(&v) => Some(v),
                Some(v) => {
                    runtime_call_lock.unlock(virtual_machine);
                    return Err(RuntimeCallError::ApiVersionUnknown { actual_version: v });
                }
            }
        } else {
            None
        };

        // Now that we have obtained the virtual machine, we can perform the call.
        // This is a CPU-only operation that executes the virtual machine.
        // The virtual machine might access the storage.
        // TODO: finish doc

        let mut runtime_call = match runtime_host::run(runtime_host::Config {
            virtual_machine,
            function_to_call,
            parameter: call_parameters,
            storage_main_trie_changes: Default::default(),
            offchain_storage_changes: Default::default(),
            max_log_level: 0,
        }) {
            Ok(vm) => vm,
            Err((err, prototype)) => {
                runtime_call_lock.unlock(prototype);
                return Err(RuntimeCallError::StartError(err));
            }
        };

        loop {
            match runtime_call {
                runtime_host::RuntimeHostVm::Finished(Ok(success)) => {
                    let output = success.virtual_machine.value().as_ref().to_vec();
                    runtime_call_lock.unlock(success.virtual_machine.into_prototype());
                    break Ok((output, runtime_api_version));
                }
                runtime_host::RuntimeHostVm::Finished(Err(error)) => {
                    runtime_call_lock.unlock(error.prototype);
                    break Err(RuntimeCallError::RuntimeError(error.detail));
                }
                runtime_host::RuntimeHostVm::StorageGet(get) => {
                    let storage_value = runtime_call_lock.storage_entry(get.key().as_ref());
                    let storage_value = match storage_value {
                        Ok(v) => v,
                        Err(err) => {
                            runtime_call_lock.unlock(
                                runtime_host::RuntimeHostVm::StorageGet(get).into_prototype(),
                            );
                            break Err(RuntimeCallError::Call(err));
                        }
                    };
                    runtime_call =
                        get.inject_value(storage_value.map(|(val, vers)| (iter::once(val), vers)));
                }
                runtime_host::RuntimeHostVm::ClosestDescendantMerkleValue(mv) => {
                    let merkle_value = runtime_call_lock
                        .closest_descendant_merkle_value(&mv.key().collect::<Vec<_>>());
                    let merkle_value = match merkle_value {
                        Ok(v) => v,
                        Err(err) => {
                            runtime_call_lock.unlock(
                                runtime_host::RuntimeHostVm::ClosestDescendantMerkleValue(mv)
                                    .into_prototype(),
                            );
                            break Err(RuntimeCallError::Call(err));
                        }
                    };
                    runtime_call = mv.inject_merkle_value(merkle_value);
                }
                runtime_host::RuntimeHostVm::NextKey(nk) => {
                    let next_key = runtime_call_lock.next_key(
                        &nk.key().collect::<Vec<_>>(),
                        nk.or_equal(),
                        &nk.prefix().collect::<Vec<_>>(),
                        nk.branch_nodes(),
                    );
                    let next_key = match next_key {
                        Ok(v) => v,
                        Err(err) => {
                            runtime_call_lock
                                .unlock(runtime_host::RuntimeHostVm::NextKey(nk).into_prototype());
                            break Err(RuntimeCallError::Call(err));
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

#[derive(Debug, derive_more::Display)]
enum StorageQueryError {
    /// Error while finding the storage root hash of the requested block.
    #[display(fmt = "Failed to obtain block state trie root: {_0}")]
    FindStorageRootHashError(StateTrieRootHashError),
    /// Error while retrieving the storage item from other nodes.
    #[display(fmt = "{_0}")]
    StorageRetrieval(sync_service::StorageQueryError),
}

// TODO: doc and properly derive Display
#[derive(Debug, derive_more::Display, Clone)]
enum RuntimeCallError {
    /// Error while finding the storage root hash of the requested block.
    #[display(fmt = "Failed to obtain block state trie root: {_0}")]
    FindStorageRootHashError(StateTrieRootHashError),
    #[display(fmt = "{_0}")]
    Call(runtime_service::RuntimeCallError),
    #[display(fmt = "{_0}")]
    StartError(host::StartErr),
    #[display(fmt = "{_0}")]
    RuntimeError(runtime_host::ErrorDetail),
    /// Required runtime API isn't supported by the runtime.
    #[display(fmt = "Required runtime API isn't supported by the runtime")]
    ApiNotFound,
    /// Version requirement of runtime API isn't supported.
    #[display(fmt = "Version {actual_version} of the runtime API not supported")]
    ApiVersionUnknown {
        /// Version that the runtime supports.
        actual_version: u32,
    },
}

/// Error potentially returned by [`Background::state_trie_root_hash`].
#[derive(Debug, derive_more::Display, Clone)]
enum StateTrieRootHashError {
    /// Failed to decode block header.
    HeaderDecodeError(header::Error),
    /// Error while fetching block header from network.
    NetworkQueryError,
}

#[derive(Debug)]
struct RuntimeCallResult {
    return_value: Vec<u8>,
    api_version: u32,
}
