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
    vec,
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
use futures_util::{future, stream};
use rand_chacha::{
    rand_core::{RngCore as _, SeedableRng as _},
    ChaCha20Rng,
};
use smoldot::{
    json_rpc::{self, methods, parse, service},
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

    /// Randomness used for various purposes, such as generating subscription IDs.
    randomness: ChaCha20,

    /// See [`StartConfig::network_service`].
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// See [`StartConfig::sync_service`].
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    /// See [`StartConfig::runtime_service`].
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    /// See [`StartConfig::transactions_service`].
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    events: stream::FuturesUnordered<Pin<Box<dyn Future<Output = Event> + Send>>>,

    /// Channel where to send responses and notifications.
    responses_tx: async_channel::Sender<String>,

    /// Channel where to send requests that concern the legacy JSON-RPC API that are handled by
    /// a dedicated task.
    to_legacy: Mutex<async_channel::Sender<legacy_state_sub::Message>>,

    /// Stream of notifications coming from the runtime service. Used for legacy JSON-RPC API
    /// subscriptions. `None` if not subscribed yet.
    runtime_service_subscription: Option<(
        runtime_service::SubscriptionId,
        Pin<Box<dyn Stream<Item = runtime_service::Notification> + Send>>,
    )>,

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
    runtime_version_subscriptions: hashbrown::HashSet<String, fnv::FnvBuildHasher>,
    /// List of all active `author_submitAndWatchExtrinsic` and
    /// `transactionWatch_unstable_submitAndWatch` subscriptions, indexed by the subscription ID.
    transactions_subscriptions: hashbrown::HashMap<String, TransactionWatch, fnv::FnvBuildHasher>,

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

enum Event {
    TransactionEvent {
        suscription_id: String,
        event: transactions_service::TransactionStatus,
        watcher: Pin<Box<transactions_service::TransactionWatcher>>,
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

    // TODO: inline?
    let mut randomness = ChaCha20Rng::from_seed(todo!());

    let me = Background {
        log_target,
        chain_name: config.chain_spec.name().to_owned(),
        chain_ty: config.chain_spec.chain_type().to_owned(),
        chain_is_live: config.chain_spec.has_live_network(),
        chain_properties_json: config.chain_spec.properties().to_owned(),
        system_name: config.system_name.clone(),
        system_version: config.system_version.clone(),
        randomness,
        network_service: config.network_service.clone(),
        sync_service: config.sync_service.clone(),
        runtime_service: config.runtime_service.clone(),
        transactions_service: config.transactions_service.clone(),
        events: stream::FuturesUnordered::new(),
        to_legacy: Mutex::new(to_legacy_tx),
        runtime_service_subscription: None,
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
        responses_tx: async_channel::bounded(64).0, // TODO: /!\ do properly
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
    };

    loop {
        // Yield at every loop in order to provide better tasks granularity.
        futures_lite::future::yield_now().await;

        enum WakeUpReason {
            IncomingJsonRpcRequest(String),
            Event(Event),
        }

        let wake_up_reason: WakeUpReason = { todo!() };

        match wake_up_reason {
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

                        me.events.push(Box::pin(async move {
                            let status = transaction_updates.next().await;
                            Event::TransactionEvent {
                                suscription_id,
                                event: status,
                                watcher: transaction_updates,
                            }
                        }));

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::author_submitAndWatchExtrinsic(subscription_id)
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::chain_getBlock { .. } => {
                        self.chain_get_block(request).await;
                    }
                    methods::MethodCall::chain_getBlockHash { .. } => {
                        self.chain_get_block_hash(request).await;
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

                    methods::MethodCall::chain_getHeader { .. } => {
                        self.chain_get_header(request).await;
                    }

                    methods::MethodCall::chain_subscribeAllHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        // TODO: check max subscriptions

                        let _was_inserted = me.all_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);

                        todo!() // TODO: send current finalized block
                    }

                    methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        // TODO: check max subscriptions

                        let _was_inserted =
                            me.finalized_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);

                        todo!() // TODO: send current finalized block
                    }

                    methods::MethodCall::chain_subscribeNewHeads {} => {
                        let subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            me.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };
                        // TODO: check max subscriptions

                        let _was_inserted = me.new_heads_subscriptions.insert(subscription_id);
                        debug_assert!(_was_inserted);

                        todo!() // TODO: send current finalized block
                    }

                    methods::MethodCall::state_subscribeRuntimeVersion {}
                    | methods::MethodCall::state_subscribeStorage { .. } => todo!(),

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

                    methods::MethodCall::payment_queryInfo { .. } => {
                        self.payment_query_info(request).await;
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
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_chain((&self.chain_name).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_chainType {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_chainType((&self.chain_ty).into())
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
                                    is_syncing: !self
                                        .runtime_service
                                        .is_near_head_of_chain_heuristic()
                                        .await,
                                    peers: u64::try_from(
                                        self.sync_service.syncing_peers().await.len(),
                                    )
                                    .unwrap_or(u64::max_value()),
                                    should_have_peers: self.chain_is_live,
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
                                methods::Response::system_name((&self.system_name).into())
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
                                    self.sync_service
                                        .syncing_peers()
                                        .await
                                        .map(|(peer_id, role, best_number, best_hash)| {
                                            methods::SystemPeer {
                                                peer_id: peer_id.to_string(),
                                                roles: match role {
                                                    codec::Role::Authority => {
                                                        methods::SystemPeerRole::Authority
                                                    }
                                                    codec::Role::Full => {
                                                        methods::SystemPeerRole::Full
                                                    }
                                                    codec::Role::Light => {
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
                                    serde_json::from_str(&self.chain_properties_json).unwrap(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::system_version {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::system_version((&self.system_version).into())
                                    .to_json_response(request_id_json),
                            )
                            .await;
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
                    methods::MethodCall::chainHead_unstable_follow { .. } => {
                        self.chain_head_follow(request).await;
                    }
                    methods::MethodCall::chainHead_unstable_header { .. } => {
                        self.chain_head_unstable_header(request).await;
                    }
                    methods::MethodCall::chainHead_unstable_unpin { .. } => {
                        self.chain_head_unstable_unpin(request).await;
                    }

                    methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {
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
                                    methods::HashHexString(self.genesis_block_hash),
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
                                    serde_json::from_str(&self.chain_properties_json).unwrap(),
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
                                        self.network_service
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
                                    Err(_) => request.fail_with_attached_json(
                                        json_rpc::parse::ErrorResponse::InvalidParams,
                                        &serde_json::to_string("multiaddr doesn't end with /p2p")
                                            .unwrap(),
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

                    methods::MethodCall::sudo_unstable_version {} => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::sudo_unstable_version(
                                    format!("{} {}", self.system_name, self.system_version).into(),
                                )
                                .to_json_response(request_id_json),
                            )
                            .await;
                    }

                    methods::MethodCall::transactionWatch_unstable_submitAndWatch { .. } => {
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
                                ty: TransactionWatchTy::NewApi,
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        me.events.push(Box::pin(async move {
                            let status = transaction_updates.next().await;
                            Event::TransactionEvent {
                                suscription_id,
                                event: status,
                                watcher: transaction_updates,
                            }
                        }));

                        let _ = me
                            .responses_tx
                            .send(
                                methods::Response::transactionWatch_unstable_submitAndWatch(
                                    subscription_id,
                                )
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
                    | methods::MethodCall::system_removeReservedPeer { .. })
                    | methods::MethodCall::sudo_network_unstable_watch { .. }
                    | methods::MethodCall::sudo_network_unstable_unwatch { .. } => {
                        // TODO: implement the ones that make sense to implement ^
                        log!(
                            &self.platform,
                            Warn,
                            &self.log_target,
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

            WakeUpReason::Event(Event::TransactionEvent {
                suscription_id,
                event,
                watcher,
            }) => {
                let Some(transaction_watch) =
                    me.transactions_subscriptions.get_me(&subscription_id)
                else {
                    // JSON-RPC client has unsubscribed from this transaction and is no longer
                    // interested in events.
                    continue;
                };

                match (status_update, transaction_watch.ty) {
                    (
                        transactions_service::TransactionStatus::Broadcast(peers),
                        TransactionWatchTy::Legacy,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: (&subscription_id).into(),
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
                                    subscription: (&subscription_id).into(),
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
                                    subscription: (&subscription_id).into(),
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
                                    subscription: (&subscription_id).into(),
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
                            subscription
                                .send_notification(
                                    methods::ServerToClient::author_extrinsicUpdate {
                                        subscription: (&subscription_id).into(),
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
                                    subscription: (&subscription_id).into(),
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
                                    subscription: (&subscription_id).into(),
                                    result:
                                        methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: None,
                                        },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::GapInChain,
                        ),
                        TransactionWatchTy::Legacy,
                    )
                    | (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::MaxPendingTransactionsReached,
                        ),
                        TransactionWatchTy::Legacy,
                    )
                    | (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::Invalid(_),
                        ),
                        TransactionWatchTy::Legacy,
                    )
                    | (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::ValidateError(_),
                        ),
                        TransactionWatchTy::Legacy,
                    )
                    | (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::Crashed,
                        ),
                        TransactionWatchTy::Legacy,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionStatus::Dropped,
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::GapInChain,
                        ),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
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
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::MaxPendingTransactionsReached,
                        ),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
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
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::Invalid(error),
                        ),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionWatchEvent::Invalid {
                                        error: error.to_string().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::ValidateError(error),
                        ),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionWatchEvent::Error {
                                        error: error.to_string().into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::Crashed,
                        ),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionWatchEvent::Error {
                                        error: "transactions service has crashed".into(),
                                    },
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }

                    (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::Finalized { block_hash, .. },
                        ),
                        TransactionWatchTy::Legacy,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionStatus::Finalized(
                                        methods::HashHexString(block_hash),
                                    ),
                                }
                                .to_json_request_object_parameters(None),
                            )
                            .await;
                    }
                    (
                        transactions_service::TransactionStatus::Dropped(
                            transactions_service::DropReason::Finalized { block_hash, index },
                        ),
                        TransactionWatchTy::NewApi,
                    ) => {
                        let _ = me
                            .responses_tx
                            .send(
                                methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
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

                // Add back an item to the events stream.
                me.events.push(Box::pin(async move {
                    let status = watcher.next().await;
                    Event::TransactionEvent {
                        suscription_id,
                        event: status,
                        watcher,
                    }
                }));
            }
        }
    }
}

impl<TPlat: PlatformRef> Background<TPlat> {
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

        // TODO: weird that keys is an iterator; revisit
        let mut results = vec![None; keys.clone().count()];

        let mut query = self
            .sync_service
            .clone()
            .storage_query(
                block_number,
                *hash,
                state_trie_root_hash,
                keys.clone().map(|key| sync_service::StorageRequestItem {
                    key: key.as_ref().to_vec(), // TODO: overhead
                    ty: sync_service::StorageRequestItemTy::Value,
                }),
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .advance()
            .await;

        loop {
            match query {
                sync_service::StorageQueryProgress::Progress {
                    query: next,
                    request_index,
                    item: sync_service::StorageResultItem::Value { value, .. },
                    ..
                } => {
                    results[request_index] = value.clone();
                    query = next.advance().await;
                }
                sync_service::StorageQueryProgress::Progress { .. } => unreachable!(),
                sync_service::StorageQueryProgress::Error(error) => {
                    return Err(StorageQueryError::StorageRetrieval(error))
                }
                sync_service::StorageQueryProgress::Finished => return Ok(results),
            }
        }
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
            let mut storage_code = None;
            let mut storage_heap_pages = None;
            let mut code_merkle_value = None;
            let mut code_closest_ancestor_excluding = None;

            let mut query = self
                .sync_service
                .clone()
                .storage_query(
                    block_number,
                    *block_hash,
                    state_trie_root_hash,
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
                        return Err(RuntimeCallError::StorageQuery(error))
                    }
                }
            }
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
