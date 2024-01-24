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
    log, network_service, platform::PlatformRef, runtime_service, sync_service,
    transactions_service, util,
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
use futures_channel::oneshot;
use smoldot::{
    json_rpc::{self, methods, service},
    libp2p::{multiaddr, PeerId},
};

mod chain_head;
mod getters;
mod legacy_state_sub;
mod state_chain;
mod transactions;

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

    /// See [`StartConfig::network_service`].
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// See [`StartConfig::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`StartConfig::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    /// See [`StartConfig::transactions_service`].
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Channel where to send requests that concern the legacy JSON-RPC API that are handled by
    /// a dedicated task.
    to_legacy: Mutex<async_channel::Sender<legacy_state_sub::Message>>,

    /// When `state_getKeysPaged` is called and the response is truncated, the response is
    /// inserted in this cache. The API user is likely to call `state_getKeysPaged` again with
    /// the same parameters, in which case we hit the cache and avoid the networking requests.
    /// The values are list of keys.
    state_get_keys_paged_cache:
        Mutex<lru::LruCache<GetKeysPagedCacheKey, Vec<Vec<u8>>, util::SipHasherBuild>>,

    /// Hash of the genesis block.
    /// Keeping the genesis block is important, as the genesis block hash is included in
    /// transaction signatures, and must therefore be queried by upper-level UIs.
    genesis_block_hash: [u8; 32],

    /// If `true`, we have already printed a warning about usage of the legacy JSON-RPC API. This
    /// flag prevents printing this message multiple times.
    printed_legacy_json_rpc_warning: atomic::AtomicBool,

    /// For each `chainHead_follow` subscription ID, a channel to the task dedicated to processing
    /// this subscription.
    chain_head_follow_tasks: Mutex<
        hashbrown::HashMap<
            String,
            service::DeliverSender<service::RequestProcess>,
            fnv::FnvBuildHasher,
        >,
    >,
}

/// See [`Background::state_get_keys_paged_cache`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GetKeysPagedCacheKey {
    /// Value of the `hash` parameter of the call to `state_getKeysPaged`.
    hash: [u8; 32],
    /// Value of the `prefix` parameter of the call to `state_getKeysPaged`.
    prefix: Vec<u8>,
}

pub(super) fn start<TPlat: PlatformRef>(
    log_target: String,
    config: StartConfig<'_, TPlat>,
    mut requests_processing_task: service::ClientMainTask,
    max_parallel_requests: NonZeroU32,
) {
    let to_legacy_tx = legacy_state_sub::start_task(legacy_state_sub::Config {
        platform: config.platform.clone(),
        log_target: log_target.clone(),
        sync_service: config.sync_service.clone(),
        runtime_service: config.runtime_service.clone(),
    });

    let me = Arc::new(Background {
        log_target,
        chain_name: config.chain_spec.name().to_owned(),
        chain_ty: config.chain_spec.chain_type().to_owned(),
        chain_is_live: config.chain_spec.has_live_network(),
        chain_properties_json: config.chain_spec.properties().to_owned(),
        system_name: config.system_name.clone(),
        system_version: config.system_version.clone(),
        network_service: config.network_service.clone(),
        sync_service: config.sync_service.clone(),
        runtime_service: config.runtime_service.clone(),
        transactions_service: config.transactions_service.clone(),
        to_legacy: Mutex::new(to_legacy_tx),
        state_get_keys_paged_cache: Mutex::new(lru::LruCache::with_hasher(
            NonZeroUsize::new(2).unwrap(),
            util::SipHasherBuild::new({
                let mut seed = [0; 16];
                config.platform.fill_random_bytes(&mut seed);
                seed
            }),
        )),
        genesis_block_hash: config.genesis_block_hash,
        printed_legacy_json_rpc_warning: atomic::AtomicBool::new(false),
        chain_head_follow_tasks: Mutex::new(hashbrown::HashMap::with_hasher(Default::default())),
        platform: config.platform,
    });

    let (tx, rx) = async_channel::bounded(
        usize::try_from(max_parallel_requests.get()).unwrap_or(usize::max_value()),
    );

    // Spawn a task that is dedicated to receiving the raw JSON-RPC requests, decode them, and
    // send them to the request processing tasks.
    me.platform
        .clone()
        .spawn_task(format!("{}-main-task", me.log_target).into(), {
            let me = me.clone();
            async move {
                loop {
                    match requests_processing_task.run_until_event().await {
                        service::Event::HandleRequest {
                            task,
                            request_process,
                        } => {
                            requests_processing_task = task;
                            tx.send(either::Left(request_process)).await.unwrap();
                        }
                        service::Event::HandleSubscriptionStart {
                            task,
                            subscription_start,
                        } => {
                            requests_processing_task = task;
                            match subscription_start.request() {
                                methods::MethodCall::chain_subscribeAllHeads {}
                                | methods::MethodCall::chain_subscribeNewHeads {}
                                | methods::MethodCall::chain_subscribeFinalizedHeads {}
                                | methods::MethodCall::state_subscribeRuntimeVersion {}
                                | methods::MethodCall::state_subscribeStorage { .. } => {
                                    me.to_legacy
                                        .lock()
                                        .await
                                        .send(legacy_state_sub::Message::SubscriptionStart(
                                            subscription_start,
                                        ))
                                        .await
                                        .unwrap();
                                }
                                _ => tx.send(either::Right(subscription_start)).await.unwrap(),
                            }
                        }
                        service::Event::SubscriptionDestroyed {
                            task,
                            subscription_id,
                        } => {
                            requests_processing_task = task;
                            let _ = me
                                .chain_head_follow_tasks
                                .lock()
                                .await
                                .remove(&subscription_id);
                            me.to_legacy
                                .lock()
                                .await
                                .send(legacy_state_sub::Message::SubscriptionDestroyed {
                                    subscription_id,
                                })
                                .await
                                .unwrap();
                        }
                        service::Event::SerializedRequestsIoClosed => {
                            break;
                        }
                    }
                }
            }
        });

    // Spawn tasks dedicated to effectively process the JSON-RPC requests.
    for task_num in 0..max_parallel_requests.get() {
        me.platform.clone().spawn_task(
            format!("{}-requests-{}", me.log_target, task_num).into(),
            {
                let me = me.clone();
                let rx = rx.clone();
                async move {
                    loop {
                        match rx.recv().await {
                            Ok(either::Left(request_process)) => {
                                me.handle_request(request_process).await;
                            }
                            Ok(either::Right(subscription_start)) => {
                                me.handle_subscription_start(subscription_start).await;
                            }
                            Err(_) => break,
                        }
                    }
                }
            },
        );
    }
}

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Pulls one request from the inner state machine, and processes it.
    async fn handle_request(self: &Arc<Self>, request: service::RequestProcess) {
        // Print a warning for legacy JSON-RPC functions.
        match request.request() {
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
                    log!(
                        &self.platform,
                        Warn,
                        &self.log_target,
                        format!(
                            "The JSON-RPC client has just called a JSON-RPC function from \
                            the legacy JSON-RPC API ({}). Legacy JSON-RPC functions have \
                            loose semantics and cannot be properly implemented on a light \
                            client. You are encouraged to use the new JSON-RPC API \
                            <https://github.com/paritytech/json-rpc-interface-spec/> instead. The \
                            legacy JSON-RPC API functions will be deprecated and removed in the \
                            distant future.",
                            request.request().name()
                        )
                    )
                }
            }
            methods::MethodCall::chainHead_unstable_body { .. }
            | methods::MethodCall::chainHead_unstable_call { .. }
            | methods::MethodCall::chainHead_unstable_continue { .. }
            | methods::MethodCall::chainHead_unstable_follow { .. }
            | methods::MethodCall::chainHead_unstable_header { .. }
            | methods::MethodCall::chainHead_unstable_stopOperation { .. }
            | methods::MethodCall::chainHead_unstable_storage { .. }
            | methods::MethodCall::chainHead_unstable_unfollow { .. }
            | methods::MethodCall::chainHead_unstable_unpin { .. }
            | methods::MethodCall::chainSpec_v1_chainName { .. }
            | methods::MethodCall::chainSpec_v1_genesisHash { .. }
            | methods::MethodCall::chainSpec_v1_properties { .. }
            | methods::MethodCall::rpc_methods { .. }
            | methods::MethodCall::sudo_unstable_p2pDiscover { .. }
            | methods::MethodCall::sudo_unstable_version { .. }
            | methods::MethodCall::transactionWatch_unstable_submitAndWatch { .. }
            | methods::MethodCall::transactionWatch_unstable_unwatch { .. }
            | methods::MethodCall::sudo_network_unstable_watch { .. }
            | methods::MethodCall::sudo_network_unstable_unwatch { .. }
            | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {}
        }

        // Each call is handled in a separate method.
        match request.request() {
            methods::MethodCall::author_pendingExtrinsics {} => {
                self.author_pending_extrinsics(request).await;
            }
            methods::MethodCall::author_submitExtrinsic { .. } => {
                self.author_submit_extrinsic(request).await;
            }
            methods::MethodCall::chain_getBlock { .. } => {
                self.chain_get_block(request).await;
            }
            methods::MethodCall::chain_getBlockHash { .. } => {
                self.chain_get_block_hash(request).await;
            }
            methods::MethodCall::chain_getFinalizedHead {} => {
                self.chain_get_finalized_head(request).await;
            }
            methods::MethodCall::chain_getHeader { .. } => {
                self.chain_get_header(request).await;
            }
            methods::MethodCall::payment_queryInfo { .. } => {
                self.payment_query_info(request).await;
            }
            methods::MethodCall::rpc_methods {} => {
                self.rpc_methods(request).await;
            }
            methods::MethodCall::state_call { .. } => {
                self.state_call(request).await;
            }
            methods::MethodCall::state_getKeys { .. } => {
                self.state_get_keys(request).await;
            }
            methods::MethodCall::state_getKeysPaged { .. } => {
                self.state_get_keys_paged(request).await;
            }
            methods::MethodCall::state_queryStorageAt { .. } => {
                self.state_query_storage_at(request).await;
            }
            methods::MethodCall::state_getMetadata { .. } => {
                self.state_get_metadata(request).await;
            }
            methods::MethodCall::state_getStorage { .. } => {
                self.state_get_storage(request).await;
            }
            methods::MethodCall::state_getRuntimeVersion { .. } => {
                self.state_get_runtime_version(request).await;
            }
            methods::MethodCall::system_accountNextIndex { .. } => {
                self.account_next_index(request).await;
            }
            methods::MethodCall::system_chain {} => {
                self.system_chain(request).await;
            }
            methods::MethodCall::system_chainType {} => {
                self.system_chain_type(request).await;
            }
            methods::MethodCall::system_health {} => {
                self.system_health(request).await;
            }
            methods::MethodCall::system_localListenAddresses {} => {
                self.system_local_listen_addresses(request).await;
            }
            methods::MethodCall::system_name {} => {
                self.system_name(request).await;
            }
            methods::MethodCall::system_nodeRoles {} => {
                self.system_node_roles(request).await;
            }
            methods::MethodCall::system_peers {} => {
                self.system_peers(request).await;
            }
            methods::MethodCall::system_properties {} => {
                self.system_properties(request).await;
            }
            methods::MethodCall::system_version {} => {
                self.system_version(request).await;
            }

            methods::MethodCall::chainHead_unstable_body { .. } => {
                self.chain_head_unstable_body(request).await;
            }
            methods::MethodCall::chainHead_unstable_call { .. } => {
                self.chain_head_call(request).await;
            }
            methods::MethodCall::chainHead_unstable_continue { .. } => {
                self.chain_head_continue(request).await;
            }
            methods::MethodCall::chainHead_unstable_storage { .. } => {
                self.chain_head_storage(request).await;
            }
            methods::MethodCall::chainHead_unstable_stopOperation { .. } => {
                self.chain_head_stop_operation(request).await;
            }
            methods::MethodCall::chainHead_unstable_header { .. } => {
                self.chain_head_unstable_header(request).await;
            }
            methods::MethodCall::chainHead_unstable_unpin { .. } => {
                self.chain_head_unstable_unpin(request).await;
            }
            methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {
                self.chain_head_unstable_finalized_database(request).await;
            }
            methods::MethodCall::chainSpec_v1_chainName {} => {
                self.chain_spec_unstable_chain_name(request).await;
            }
            methods::MethodCall::chainSpec_v1_genesisHash {} => {
                self.chain_spec_unstable_genesis_hash(request).await;
            }
            methods::MethodCall::chainSpec_v1_properties {} => {
                self.chain_spec_unstable_properties(request).await;
            }
            methods::MethodCall::sudo_unstable_p2pDiscover { .. } => {
                self.sudo_unstable_p2p_discover(request).await;
            }
            methods::MethodCall::sudo_unstable_version {} => {
                self.sudo_unstable_version(request).await;
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
            | methods::MethodCall::system_removeReservedPeer { .. }) => {
                // TODO: implement the ones that make sense to implement ^
                log!(
                    &self.platform,
                    Warn,
                    &self.log_target,
                    format!("JSON-RPC call not supported yet: {:?}", _method)
                );
                request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    "Not implemented in smoldot yet",
                ));
            }

            _ => unreachable!(),
        }
    }

    /// Pulls one request from the inner state machine, and processes it.
    async fn handle_subscription_start(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        // TODO: restore some form of logging

        // Print a warning for legacy JSON-RPC functions.
        match request.request() {
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
                    log!(
                        &self.platform,
                        Warn,
                        &self.log_target,
                        format!(
                            "The JSON-RPC client has just called a JSON-RPC function from \
                            the legacy JSON-RPC API ({}). Legacy JSON-RPC functions have \
                            loose semantics and cannot be properly implemented on a light \
                            client. You are encouraged to use the new JSON-RPC API \
                            <https://github.com/paritytech/json-rpc-interface-spec/> instead. The \
                            legacy JSON-RPC API functions will be deprecated and removed in the \
                            distant future.",
                            request.request().name()
                        )
                    )
                }
            }
            methods::MethodCall::chainHead_unstable_body { .. }
            | methods::MethodCall::chainHead_unstable_call { .. }
            | methods::MethodCall::chainHead_unstable_continue { .. }
            | methods::MethodCall::chainHead_unstable_follow { .. }
            | methods::MethodCall::chainHead_unstable_header { .. }
            | methods::MethodCall::chainHead_unstable_stopOperation { .. }
            | methods::MethodCall::chainHead_unstable_storage { .. }
            | methods::MethodCall::chainHead_unstable_unfollow { .. }
            | methods::MethodCall::chainHead_unstable_unpin { .. }
            | methods::MethodCall::chainSpec_v1_chainName { .. }
            | methods::MethodCall::chainSpec_v1_genesisHash { .. }
            | methods::MethodCall::chainSpec_v1_properties { .. }
            | methods::MethodCall::rpc_methods { .. }
            | methods::MethodCall::sudo_unstable_p2pDiscover { .. }
            | methods::MethodCall::sudo_unstable_version { .. }
            | methods::MethodCall::transactionWatch_unstable_submitAndWatch { .. }
            | methods::MethodCall::transactionWatch_unstable_unwatch { .. }
            | methods::MethodCall::sudo_network_unstable_watch { .. }
            | methods::MethodCall::sudo_network_unstable_unwatch { .. }
            | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {}
        }

        // Each call is handled in a separate method.
        match request.request() {
            methods::MethodCall::author_submitAndWatchExtrinsic { .. } => {
                self.submit_and_watch_transaction(request).await
            }
            methods::MethodCall::chain_subscribeAllHeads {}
            | methods::MethodCall::chain_subscribeFinalizedHeads {}
            | methods::MethodCall::chain_subscribeNewHeads {}
            | methods::MethodCall::state_subscribeRuntimeVersion {}
            | methods::MethodCall::state_subscribeStorage { .. } => {
                unreachable!()
            }

            methods::MethodCall::chainHead_unstable_follow { .. } => {
                self.chain_head_follow(request).await;
            }
            methods::MethodCall::transactionWatch_unstable_submitAndWatch { .. } => {
                self.submit_and_watch_transaction(request).await
            }

            _method @ methods::MethodCall::sudo_network_unstable_watch { .. } => {
                // TODO: implement the ones that make sense to implement ^
                log!(
                    &self.platform,
                    Warn,
                    &self.log_target,
                    format!("JSON-RPC call not supported yet: {:?}", _method)
                );
                request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    "Not implemented in smoldot yet",
                ));
            }

            _ => unreachable!(),
        }
    }

    /// Handles a call to [`methods::MethodCall::sudo_unstable_p2pDiscover`].
    async fn sudo_unstable_p2p_discover(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::sudo_unstable_p2pDiscover { multiaddr } = request.request() else {
            unreachable!()
        };

        match multiaddr.parse::<multiaddr::Multiaddr>() {
            Ok(mut addr) if matches!(addr.iter().last(), Some(multiaddr::Protocol::P2p(_))) => {
                let peer_id_bytes = match addr.iter().last() {
                    Some(multiaddr::Protocol::P2p(peer_id)) => peer_id.into_bytes().to_owned(),
                    _ => unreachable!(),
                };
                addr.pop();

                match PeerId::from_bytes(peer_id_bytes) {
                    Ok(peer_id) => {
                        self.network_service
                            .discover(iter::once((peer_id, iter::once(addr))), false)
                            .await;
                        request.respond(methods::Response::sudo_unstable_p2pDiscover(()));
                    }
                    Err(_) => request.fail_with_attached_json(
                        json_rpc::parse::ErrorResponse::InvalidParams,
                        &serde_json::to_string("multiaddr doesn't end with /p2p").unwrap(),
                    ),
                }
            }
            Ok(_) => request.fail_with_attached_json(
                json_rpc::parse::ErrorResponse::InvalidParams,
                &serde_json::to_string("multiaddr doesn't end with /p2p").unwrap(),
            ),
            Err(err) => request.fail_with_attached_json(
                json_rpc::parse::ErrorResponse::InvalidParams,
                &serde_json::to_string(&err.to_string()).unwrap(),
            ),
        }
    }

    async fn storage_query(
        &self,
        keys: impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone,
        hash: &[u8; 32],
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<Vec<Option<Vec<u8>>>, StorageQueryError> {
        let (state_trie_root_hash, block_number) = {
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::BlockStateRootAndNumber {
                    block_hash: *hash,
                    result_tx: tx,
                })
                .await
                .unwrap();

            match rx.await.unwrap() {
                Ok(v) => v,
                Err(err) => {
                    return Err(StorageQueryError::FindStorageRootHashError(err));
                }
            }
        };

        let result = self
            .sync_service
            .clone()
            .storage_query(
                block_number,
                hash,
                &state_trie_root_hash,
                keys.clone().map(|key| sync_service::StorageRequestItem {
                    key: key.as_ref().to_vec(), // TODO: overhead
                    ty: sync_service::StorageRequestItemTy::Value,
                }),
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await
            .map_err(StorageQueryError::StorageRetrieval)?;

        let result = keys
            .map(|key| {
                result
                    .iter()
                    .find_map(|entry| match entry {
                        sync_service::StorageResultItem::Value { key: k, value }
                            if k == key.as_ref() =>
                        {
                            Some(value.clone()) // TODO: overhead
                        }
                        _ => None,
                    })
                    .unwrap()
            })
            .collect();

        Ok(result)
    }

    /// Obtain a pin of the runtime of the given block against the runtime service, plus the
    /// block hash and number.
    // TODO: return better error?
    async fn pinned_runtime_and_block_info(
        self: &Arc<Self>,
        block_hash: &[u8; 32],
    ) -> Result<(runtime_service::PinnedRuntime, [u8; 32], u64), RuntimeCallError> {
        // Try to find the block in the cache of recent blocks. Most of the time, the call target
        // should be in there.
        if let Some((pinned_runtime, state_trie_root_hash, block_number)) = {
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::RecentBlockPinnedRuntime {
                    block_hash: *block_hash,
                    result_tx: tx,
                })
                .await
                .unwrap();
            rx.await.unwrap()
        } {
            return Ok((pinned_runtime, state_trie_root_hash, block_number));
        };

        // Second situation: the block is not in the cache of recent blocks. This isn't great.
        // The only solution is to download the runtime of the block in question from the network.

        // TODO: considering caching the runtime code the same way as the state trie root hash

        // In order to grab the runtime code and perform the call network request, we need
        // to know the state trie root hash and the height of the block.
        let (state_trie_root_hash, block_number) = {
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::BlockStateRootAndNumber {
                    block_hash: *block_hash,
                    result_tx: tx,
                })
                .await
                .unwrap();

            match rx.await.unwrap() {
                Ok(v) => v,
                Err(err) => {
                    return Err(RuntimeCallError::FindStorageRootHashError(err));
                }
            }
        };

        // Download the runtime of this block. This takes a long time as the runtime is rather
        // big (around 1MiB in general).
        let (storage_code, storage_heap_pages, code_merkle_value, code_closest_ancestor_excluding) = {
            let entries = self
                .sync_service
                .clone()
                .storage_query(
                    block_number,
                    block_hash,
                    &state_trie_root_hash,
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
                .await
                .map_err(RuntimeCallError::StorageQuery)?;
            // TODO: not elegant
            let heap_pages = entries
                .iter()
                .find_map(|entry| match entry {
                    sync_service::StorageResultItem::Value { key, value }
                        if key == b":heappages" =>
                    {
                        Some(value.clone()) // TODO: overhead
                    }
                    _ => None,
                })
                .unwrap();
            let code = entries
                .iter()
                .find_map(|entry| match entry {
                    sync_service::StorageResultItem::Value { key, value } if key == b":code" => {
                        Some(value.clone()) // TODO: overhead
                    }
                    _ => None,
                })
                .unwrap();
            let (code_merkle_value, code_closest_ancestor_excluding) = if code.is_some() {
                entries
                    .iter()
                    .find_map(|entry| match entry {
                        sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                            requested_key,
                            closest_descendant_merkle_value,
                            found_closest_ancestor_excluding,
                        } if requested_key == b":code" => {
                            Some((
                                closest_descendant_merkle_value.clone(),
                                found_closest_ancestor_excluding.clone(),
                            )) // TODO overhead
                        }
                        _ => None,
                    })
                    .unwrap()
            } else {
                (None, None)
            };

            (
                code,
                heap_pages,
                code_merkle_value,
                code_closest_ancestor_excluding,
            )
        };

        // Give the code and heap pages to the runtime service. The runtime service will
        // try to find any similar runtime it might have, and if not will compile it.
        let pinned_runtime = self
            .runtime_service
            .compile_and_pin_runtime(
                storage_code,
                storage_heap_pages,
                code_merkle_value,
                code_closest_ancestor_excluding,
            )
            .await
            .map_err(|err| match err {
                runtime_service::CompileAndPinRuntimeError::Crash => {
                    RuntimeCallError::Call(runtime_service::RuntimeCallError::Crash)
                }
            })?;

        // TODO: consider keeping pinned runtimes in a cache instead
        Ok((pinned_runtime, state_trie_root_hash, block_number))
    }

    /// Performs a runtime call to a random block.
    async fn runtime_call(
        self: &Arc<Self>,
        block_hash: &[u8; 32],
        runtime_api: String,
        required_api_version: ops::RangeInclusive<u32>,
        function_to_call: String,
        call_parameters: Vec<u8>,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<RuntimeCallResult, RuntimeCallError> {
        let (return_value, api_version) = self
            .runtime_call_inner(
                block_hash,
                Some((runtime_api, required_api_version)),
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
        function_to_call: String,
        call_parameters: Vec<u8>,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<Vec<u8>, RuntimeCallError> {
        let (return_value, _api_version) = self
            .runtime_call_inner(
                block_hash,
                None,
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
        runtime_api_check: Option<(String, ops::RangeInclusive<u32>)>,
        function_to_call: String,
        parameters_vectored: Vec<u8>,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<(Vec<u8>, Option<u32>), RuntimeCallError> {
        // This function contains two steps: obtaining the runtime of the block in question,
        // then performing the actual call. The first step is the longest and most difficult.
        let (pinned_runtime, block_state_trie_root_hash, block_number) =
            self.pinned_runtime_and_block_info(block_hash).await?;

        match self
            .runtime_service
            .runtime_call(
                pinned_runtime,
                *block_hash,
                block_number,
                block_state_trie_root_hash,
                function_to_call,
                runtime_api_check,
                parameters_vectored,
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await
        {
            Ok(output) => Ok((output.output, output.api_version)),
            Err(error) => {
                return Err(RuntimeCallError::Call(error));
            }
        }
    }
}

#[derive(Debug, derive_more::Display)]
enum StorageQueryError {
    /// Error while finding the storage root hash of the requested block.
    #[display(fmt = "Failed to obtain block state trie root: {_0}")]
    FindStorageRootHashError(legacy_state_sub::StateTrieRootHashError),
    /// Error while retrieving the storage item from other nodes.
    #[display(fmt = "{_0}")]
    StorageRetrieval(sync_service::StorageQueryError),
}

// TODO: doc and properly derive Display
#[derive(Debug, derive_more::Display, Clone)]
enum RuntimeCallError {
    /// Error while finding the storage root hash of the requested block.
    #[display(fmt = "Failed to obtain block state trie root: {_0}")]
    FindStorageRootHashError(legacy_state_sub::StateTrieRootHashError),
    /// Error while downloading the runtime from the network.
    StorageQuery(sync_service::StorageQueryError),
    #[display(fmt = "{_0}")]
    Call(runtime_service::RuntimeCallError),
}

#[derive(Debug)]
struct RuntimeCallResult {
    return_value: Vec<u8>,
    api_version: u32,
}
