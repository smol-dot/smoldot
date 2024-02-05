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

//!
//! # Usage
//!
//! TODO
//!
//! Call [`ReverseProxy::add_client`] whenever a client connects, and
//! [`ReverseProxy::remove_client`] whenever a client disconnects.
//!
//! # Behavior
//!
//! The behavior is as follows:
//!
//! For the legacy JSON-RPC API:
//!
//! - `system_name` and `system_version` are answered directly by the proxy, and not directed
//! towards any of the servers.
//! - TODO: functions that always error
//! - For all other legacy JSON-RPC API functions: the first time one of these functions is called,
//! it is directed towards a randomly-chosen server. Then, further calls to one of the functions
//! are always redirect to the same server. For example, if the JSON-RPC client calls
//! `chain_subscribeAllHeads` then `chain_getBlock`, these two function calls are guaranteed to be
//! redirected to the same server. If this server is removed, a different server is randomly
//! chosen. Note that there's no mechanism for a server to "steal" clients from another server, as
//! doing so would create inconsistencies from the point of view of the JSON-RPC client. This is
//! considered as a defect in the legacy JSON-RPC API.
//! - If a server is dropped, a `Dropped` update is generated for any active
//! `author_submitAndWatchExtrinsic` subscription. For all other subscriptions, the subscription
//! is silently re-opened on a different server.
//!
//! For the new JSON-RPC API:
//!
//! - `sudo_unstable_version` is answered directly by the proxy, and not directed towards any of
//! the servers.
//! - `sudo_unstable_p2pDiscover` is answered directly by the proxy and is a no-op. TODO: is that correct?
//! - `chainSpec_v1_chainName`, `chainSpec_v1_genesisHash`, and `chainSpec_v1_properties` are
//! redirected towards a randomly-chosen server.
//! - Each call to `chainHead_unstable_follow` is redirected to a randomly-chosen server (possibly
//! multiple different servers for each call). All the other `chainHead` JSON-RPC functions are
//! then redirected to the server corresponding to the provided `followSubscriptionId`. If the
//! server is removed, a `stop` event is generated.
//! - Each call to `transaction_unstable_submitAndWatch` is redirected to a randomly-chosen
//! server. If the server is removed, a `dropped` event is generated.
//!
//! If no server is available, the reverse proxy will delay answering JSON-RPC requests until one
//! server is added (except for the JSON-RPC functions that are answered immediately, as they are
//! always answered immediately).
//!
//! JSON-RPC requests that can't be parsed, use an unknown function, have invalid parameters, etc.
//! are answered immediately by the reverse proxy.
//!
//! If a server misbehaves or returns an internal error, it gets blacklisted and no further
//! requests are sent to it.
//!
//! When a request sent by a client is transferred to a server, the identifier for that request
//! is modified to a randomly-generated identifier. This is necessary because multiple different
//! clients might use the same identifiers for their requests.
//! Similarly, when a server sends a JSON-RPC response containing a subscription ID, the
//! identifier of that subscription is modified to become a randomly-generated value.

// TODO: what about rpc_methods

use alloc::{
    borrow::Cow,
    collections::{btree_map, BTreeMap, BTreeSet, VecDeque},
    format,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{cmp, mem, ops};
use rand::{seq::IteratorRandom as _, Rng as _};
use rand_chacha::{
    rand_core::{RngCore as _, SeedableRng as _},
    ChaCha20Rng,
};

use crate::json_rpc::methods;

use super::parse;

mod client_sanitizer;

/// Configuration for a new [`ReverseProxy`].
pub struct Config {
    /// Value to return when a call to the `system_name` JSON-RPC function is received.
    pub system_name: Cow<'static, str>,

    /// Value to return when a call to the `system_version` JSON-RPC function is received.
    pub system_version: Cow<'static, str>,

    /// Seed used for randomness. Used to avoid HashDoS attacks and to attribute clients and
    /// requests to servers.
    pub randomness_seed: [u8; 32],
}

/// Configuration for a new [`ReverseProxy`].
pub struct ClientConfig<TClient> {
    /// Maximum number of requests that haven't been answered yet that the client is allowed to
    /// make.
    pub max_unanswered_parallel_requests: usize,

    /// Maximum number of concurrent subscriptions for the legacy JSON-RPC API, except for
    /// `author_submitAndWatchExtrinsic` which is handled by
    /// [`ClientConfig::max_transactions_subscriptions`].
    pub max_legacy_api_subscriptions: usize,

    /// Maximum number of concurrent `chainHead_follow` subscriptions.
    ///
    /// The specification mentions that this value must be at least 2. If the value is inferior to
    /// 2, it is raised.
    pub max_chainhead_follow_subscriptions: usize,

    /// Maximum number of concurrent transactions-related subscriptions.
    pub max_transactions_subscriptions: usize,

    /// Opaque data stored for this client.
    /// Can later be accessed using the `ops::Index` trait implementation of [`ReverseProxy`].
    pub user_data: TClient,
}

/// Reverse proxy state machine. See [..](the module-level documentation).
pub struct ReverseProxy<TClient, TServer> {
    /// List of all clients. Indices serve as [`ClientId`].
    clients: slab::Slab<Client<TClient>>,

    /// List of all servers. Indices serve as [`ServerId`].
    servers: slab::Slab<Server<TServer>>,

    /// Queues of requests waiting to be sent to a server.
    /// Indexed by client and by server.
    ///
    /// The `VecDeque`s must never be empty. If a queue is emptied, the item must be removed from
    /// the `BTreeMap` altogether.
    // TODO: call shrink to fit from time to time?
    client_requests_queued: BTreeMap<(ClientId, ServerTarget), VecDeque<QueuedRequest>>,

    /// Same entries as [`ReverseProxy::client_requests_queued`], but indexed
    /// differently.
    /// [`ServerTarget::ServerAgnostic`] and [`ServerTarget::LegacyApiUnassigned`] both
    /// correspond to a key of `None`, while [`ServerTarget::Specific`] corresponds to a key of
    /// `Some`.
    clients_with_request_queued: BTreeSet<(Option<ServerId>, ClientId)>,

    /// Alternative representation for [`Client::legacy_api_assigned_server`].
    legacy_api_server_assignments: BTreeSet<(ServerId, ClientId)>,

    /// List of all requests that have been extracted with
    /// [`ReverseProxy::next_proxied_json_rpc_request`] and are being processed by the server.
    ///
    /// Entries are removed when a response is inserted with
    /// [`ReverseProxy::insert_proxied_json_rpc_response`] or the server blacklisted through
    /// [`ReverseProxy::blacklist_server`].
    ///
    /// Keys are server IDs and the request ID from the point of view of the server. Values are
    /// the client and request from the point of view of the client.
    requests_in_progress: BTreeMap<(ServerId, String), (ClientId, QueuedRequest)>,

    /// List of all subscriptions that are currently active according to servers.
    // TODO: clarify when entries are added/removed
    active_subscriptions_by_server: BTreeMap<(ServerId, String), (ClientId, String)>,

    /// List of all subscriptions that are currently active according to clients.
    ///
    /// Entries are inserted when we queue for the client a JSON-RPC response containing a
    /// subscription confirmation, and removed when we queue for the client a JSON-RPC response
    /// containing an unsubscription confirmation.
    ///
    /// Contains `Some` only if the subscription is active on a server.
    /// If it contains `None`, then there must be a subscription request either in queue or
    /// currently being processed by a server.
    active_subscriptions_by_client:
        BTreeMap<(ClientId, String), (SubscriptionTyWithParams, Option<(ServerId, String)>)>,

    /// Source of randomness used for various purposes.
    // TODO: is a crypto secure randomness overkill?
    randomness: ChaCha20Rng,

    /// See [`Config::system_name`]
    system_name: Cow<'static, str>,

    /// See [`Config::system_version`]
    system_version: Cow<'static, str>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ServerTarget {
    ServerAgnostic,
    LegacyApiUnassigned,
    Specific(ServerId),
}

// TODO: unnecessary?
impl ServerTarget {
    const MIN: ServerTarget = ServerTarget::ServerAgnostic;
    const MAX: ServerTarget = ServerTarget::Specific(ServerId(usize::MAX));
}

enum SubscriptionTyWithParams {
    AuthorSubmitAndWatchExtrinsic,
    ChainSubscribeAllHeads,
    ChainSubscribeFinalizedHeads,
    ChainSubscribeNewHeads,
    StateSubscribeRuntimeVersion,
    StateSubscribeStorage { keys: Vec<methods::HexString> },
    ChainHeadFollow,
    TransactionSubmitAndWatch,
}

enum SubscriptionTy {
    AuthorSubmitAndWatchExtrinsic,
    ChainSubscribeAllHeads,
    ChainSubscribeFinalizedHeads,
    ChainSubscribeNewHeads,
    StateSubscribeRuntimeVersion,
    StateSubscribeStorage,
    ChainHeadFollow,
    TransactionSubmitAndWatch,
}

struct Client<TClient> {
    /// Returns the number of requests inserted with
    /// [`ReverseProxy::insert_client_json_rpc_request`] whose response hasn't been pulled with
    /// [`ReverseProxy::next_client_json_rpc_response`] yet.
    num_unanswered_requests: usize,

    /// See [`ClientConfig::max_unanswered_parallel_requests`]
    max_unanswered_parallel_requests: usize,

    /// Number of legacy JSON-RPC API subscriptions that are active, from the moment when the
    /// request to subscribe is inserted in the queue to the moment when the response of the
    /// unsubscription is extracted with [`ReverseProxy::next_client_json_rpc_response`].
    num_legacy_api_subscriptions: usize,

    /// See [`ClientConfig::max_legacy_api_subscriptions`].
    max_legacy_api_subscriptions: usize,

    /// Number of `chainHead_follow` subscriptions that are active, from the moment when the
    /// request to subscribe is inserted in the queue to the moment when the response of the
    /// unsubscription or the `stop` event is extracted with
    /// [`ReverseProxy::next_client_json_rpc_response`].
    num_chainhead_follow_subscriptions: usize,

    /// See [`ClientConfig::max_chainhead_follow_subscriptions`].
    max_chainhead_follow_subscriptions: usize,

    /// Number of `author_submitAndWatchExtrinsic` and `transaction_unstable_submitAndWatch`
    /// subscriptions that are active, from the moment when the request to subscribe is inserted
    /// in the queue to the moment when the response of the unsubscription or the `dropped` event
    /// is extracted with [`ReverseProxy::next_client_json_rpc_response`].
    num_transactions_subscriptions: usize,

    /// See [`ClientConfig::max_transactions_subscriptions`].
    max_transactions_subscriptions: usize,

    /// Queue of responses waiting to be sent to the client.
    // TODO: call shrink to fit from time to time?
    json_rpc_responses_queue: VecDeque<QueuedResponse>,

    /// Server assigned to this client when it calls legacy JSON-RPC functions. Initially set
    /// to `None`. A server is chosen the first time the client calls a legacy JSON-RPC function.
    legacy_api_assigned_server: Option<ServerId>,

    /// Opaque data chosen by the API user.
    ///
    /// If `None`, then this client is considered non-existent for public-API-related purposes.
    /// This value is set to `None` when the API user wants to remove a client, but that this
    /// client still has active subscriptions that need to be cleaned up.
    user_data: Option<TClient>,
}

struct QueuedRequest {
    id_json: String,

    method: String,

    parameters_json: Option<String>,

    ty: QueuedRequestTy,
}

enum QueuedRequestTy {
    Regular {
        /// `true` if the JSON-RPC function belongs to the category of legacy JSON-RPC functions
        /// that are all redirected to the same server.
        is_legacy_api_server_specific: bool,
    },
    Subscription {
        ty: SubscriptionTyWithParams,
        /// `Some` if the JSON-RPC client thinks that the subscription is already active, in which
        /// case this field contains the client-side subscription ID.
        assigned_subscription_id: Option<String>,
    },
    Unsubscribe(SubscriptionTy),
}

struct QueuedResponse {
    /// The JSON-RPC response itself.
    response: String,

    /// If `true`, pulling this response decreases [`Client::num_unanswered_requests`].
    decreases_num_unanswered_requests: bool,
}

struct Server<TServer> {
    /// `true` if the given server has misbehaved and must not process new requests.
    is_blacklisted: bool,

    /// Opaque data chosen by the API user.
    user_data: TServer,
}

/// Identifier of a client within the [`ReverseProxy`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(usize);

/// Identifier of a server within the [`ReverseProxy`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerId(usize);

impl<TClient, TServer> ReverseProxy<TClient, TServer> {
    /// Initializes a new [`ReverseProxy`].
    pub fn new(config: Config) -> Self {
        ReverseProxy {
            clients: slab::Slab::new(), // TODO: capacity
            servers: slab::Slab::new(), // TODO: capacity
            requests_in_progress: BTreeMap::new(),
            randomness: ChaCha20Rng::from_seed(config.randomness_seed),
            ..todo!()
        }
    }

    /// Adds a client to the list of clients managed by this state machine.
    ///
    /// API users should be aware of the fact that clients are distributed evenly between servers.
    /// As more clients as added, the latency of the requests of each client is increased, unless
    /// additional servers are added as well.
    pub fn insert_client(&mut self, config: ClientConfig<TClient>) -> ClientId {
        ClientId(self.clients.insert(Client {
            num_unanswered_requests: 0,
            max_unanswered_parallel_requests: config.max_unanswered_parallel_requests,
            num_legacy_api_subscriptions: 0,
            max_legacy_api_subscriptions: config.max_legacy_api_subscriptions,
            num_chainhead_follow_subscriptions: 0,
            max_chainhead_follow_subscriptions: cmp::max(
                config.max_chainhead_follow_subscriptions,
                2,
            ),
            num_transactions_subscriptions: 0,
            max_transactions_subscriptions: config.max_transactions_subscriptions,
            json_rpc_responses_queue: VecDeque::with_capacity(16), // TODO: capacity?
            legacy_api_assigned_server: None,
            user_data: Some(config.user_data),
        }))
    }

    /// Removes a client previously-inserted with [`ReverseProxy::insert_client`].
    ///
    /// # Panic
    ///
    /// Panics if the given [`ClientId`] is invalid.
    ///
    // TODO: return list of servers that must wake up
    pub fn remove_client(&mut self, client_id: ClientId) -> TClient {
        let client = self
            .clients
            .get_mut(client_id.0)
            .unwrap_or_else(|| panic!("client doesn't exist"));
        let user_data = client
            .user_data
            .take()
            .unwrap_or_else(|| panic!("client doesn't exist"));

        // Clear the queue of pending requests of this client. While leaving the queue as-is
        // wouldn't be a problem in terms of logic, we clear it for optimization purposes, in
        // order to avoid processing requests that we know are pointless.
        // TODO: do it

        // For each subscription that was active on this client, push a request that unsubscribes.
        for ((_, client_subscription_id), (server_id, server_subscription_id)) in self
            .active_subscriptions_by_client
            .range((client_id, String::new())..(ClientId(client_id.0 + 1), String::new()))
        {
            // TODO:
        }

        // Try to remove the client entirely if possible.
        self.try_remove_client(client_id);

        // Client successfully removed for API-related purposes.
        user_data
    }

    ///
    ///
    /// An error is returned if the JSON-RPC client has queued too many requests that haven't been
    /// answered yet. Try again after a call to [`ReverseProxy::next_client_json_rpc_response`]
    /// has returned `Some`.
    ///
    /// # Panic
    ///
    /// Panics if the given [`ClientId`] is invalid.
    ///
    pub fn insert_client_json_rpc_request(
        &mut self,
        client_id: ClientId,
        request: &str,
    ) -> Result<InsertClientRequest, InsertClientRequestError> {
        // Check that the client ID is valid.
        assert!(self.clients[client_id.0].user_data.is_some());

        // Check the limit to the number of unanswered requests.
        if self.clients[client_id.0].num_unanswered_requests
            >= self.clients[client_id.0].max_unanswered_parallel_requests
        {
            return Err(InsertClientRequestError::TooManySimultaneousRequests);
        }
        self.clients[client_id.0].num_unanswered_requests += 1;

        // Determine the request information, or answer the request directly if possible.
        let queued_request = match methods::parse_jsonrpc_client_to_server(request) {
            Ok((request_id_json, method)) => {
                let ty = match method {
                    // Answer the request directly if possible.
                    methods::MethodCall::system_name {} => {
                        self.clients[client_id.0]
                            .json_rpc_responses_queue
                            .push_back(QueuedResponse {
                                response: methods::Response::system_name(Cow::Borrowed(
                                    &*self.system_name,
                                ))
                                .to_json_response(request_id_json),
                                decreases_num_unanswered_requests: true,
                            });
                        return Ok(InsertClientRequest::ImmediateAnswer);
                    }
                    methods::MethodCall::system_version {} => {
                        self.clients[client_id.0]
                            .json_rpc_responses_queue
                            .push_back(QueuedResponse {
                                response: methods::Response::system_version(Cow::Borrowed(
                                    &*self.system_version,
                                ))
                                .to_json_response(request_id_json),
                                decreases_num_unanswered_requests: true,
                            });
                        return Ok(InsertClientRequest::ImmediateAnswer);
                    }
                    methods::MethodCall::sudo_unstable_version {} => {
                        self.clients[client_id.0]
                            .json_rpc_responses_queue
                            .push_back(QueuedResponse {
                                response: methods::Response::sudo_unstable_version(Cow::Owned(
                                    format!("{} {}", self.system_name, self.system_version),
                                ))
                                .to_json_response(request_id_json),
                                decreases_num_unanswered_requests: true,
                            });
                        return Ok(InsertClientRequest::ImmediateAnswer);
                    }
                    methods::MethodCall::sudo_unstable_p2pDiscover { .. } => {
                        self.clients[client_id.0]
                            .json_rpc_responses_queue
                            .push_back(QueuedResponse {
                                response: methods::Response::sudo_unstable_p2pDiscover(())
                                    .to_json_response(request_id_json),
                                decreases_num_unanswered_requests: true,
                            });
                        return Ok(InsertClientRequest::ImmediateAnswer);
                    }

                    // Subscription functions.
                    methods::MethodCall::state_subscribeRuntimeVersion {}
                    | methods::MethodCall::state_subscribeStorage { .. }
                    | methods::MethodCall::chain_subscribeAllHeads {}
                    | methods::MethodCall::chain_subscribeFinalizedHeads {}
                    | methods::MethodCall::chain_subscribeNewHeads {} => {
                        if self.clients[client_id.0].num_legacy_api_subscriptions
                            >= self.clients[client_id.0].max_legacy_api_subscriptions
                        {
                            self.clients[client_id.0]
                                .json_rpc_responses_queue
                                .push_back(QueuedResponse {
                                    response: parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::ApplicationDefined(
                                            -32800,
                                            "Too many active subscriptions",
                                        ),
                                        None,
                                    ),
                                    decreases_num_unanswered_requests: true,
                                });
                            return Ok(InsertClientRequest::ImmediateAnswer);
                        }

                        self.clients[client_id.0].num_legacy_api_subscriptions += 1;
                        QueuedRequestTy::Subscription {
                            ty: match method {
                                methods::MethodCall::state_subscribeRuntimeVersion {} => {
                                    SubscriptionTyWithParams::StateSubscribeRuntimeVersion
                                }
                                methods::MethodCall::state_subscribeStorage { list } => {
                                    SubscriptionTyWithParams::StateSubscribeStorage { keys: list }
                                }
                                methods::MethodCall::chain_subscribeAllHeads {} => {
                                    SubscriptionTyWithParams::ChainSubscribeAllHeads
                                }
                                methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                                    SubscriptionTyWithParams::ChainSubscribeFinalizedHeads
                                }
                                methods::MethodCall::chain_subscribeNewHeads {} => {
                                    SubscriptionTyWithParams::ChainSubscribeNewHeads
                                }
                                _ => unreachable!(),
                            },
                            assigned_subscription_id: None,
                        }
                    }
                    methods::MethodCall::chainHead_unstable_follow { .. } => {
                        if self.clients[client_id.0].num_chainhead_follow_subscriptions
                            >= self.clients[client_id.0].max_chainhead_follow_subscriptions
                        {
                            self.clients[client_id.0]
                                .json_rpc_responses_queue
                                .push_back(QueuedResponse {
                                    response: parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::ApplicationDefined(
                                            -32800,
                                            "Too many active `chainHead_follow` subscriptions",
                                        ),
                                        None,
                                    ),
                                    decreases_num_unanswered_requests: true,
                                });
                            return Ok(InsertClientRequest::ImmediateAnswer);
                        }

                        self.clients[client_id.0].num_chainhead_follow_subscriptions += 1;
                        QueuedRequestTy::Subscription {
                            ty: SubscriptionTyWithParams::ChainHeadFollow,
                            assigned_subscription_id: None,
                        }
                    }
                    methods::MethodCall::author_submitAndWatchExtrinsic { .. }
                    | methods::MethodCall::transaction_unstable_submitAndWatch { .. } => {
                        if self.clients[client_id.0].num_transactions_subscriptions
                            >= self.clients[client_id.0].max_transactions_subscriptions
                        {
                            // TODO: send back error
                            todo!()
                        }

                        self.clients[client_id.0].num_transactions_subscriptions += 1;
                        QueuedRequestTy::Subscription {
                            ty: match method {
                                methods::MethodCall::author_submitAndWatchExtrinsic { .. } => {
                                    SubscriptionTyWithParams::ChainHeadFollow
                                }
                                methods::MethodCall::transaction_unstable_submitAndWatch {
                                    ..
                                } => SubscriptionTyWithParams::TransactionSubmitAndWatch,
                                _ => unreachable!(),
                            },
                            assigned_subscription_id: None,
                        }
                    }

                    // Unsubscription functions.
                    methods::MethodCall::chain_unsubscribeAllHeads { subscription }
                    | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription }
                    | methods::MethodCall::chain_unsubscribeNewHeads { subscription }
                    | methods::MethodCall::state_unsubscribeRuntimeVersion { subscription } => {
                        todo!()
                    }
                    methods::MethodCall::state_unsubscribeStorage { subscription } => todo!(),

                    // Legacy JSON-RPC API functions.
                    methods::MethodCall::account_nextIndex { .. }
                    | methods::MethodCall::author_hasKey { .. }
                    | methods::MethodCall::author_hasSessionKeys { .. }
                    | methods::MethodCall::author_insertKey { .. }
                    | methods::MethodCall::author_pendingExtrinsics { .. }
                    | methods::MethodCall::author_removeExtrinsic { .. }
                    | methods::MethodCall::author_rotateKeys { .. }
                    | methods::MethodCall::author_submitExtrinsic { .. }
                    | methods::MethodCall::author_unwatchExtrinsic { .. }
                    | methods::MethodCall::babe_epochAuthorship { .. }
                    | methods::MethodCall::chain_getBlock { .. }
                    | methods::MethodCall::chain_getBlockHash { .. }
                    | methods::MethodCall::chain_getFinalizedHead { .. }
                    | methods::MethodCall::chain_getHeader { .. }
                    | methods::MethodCall::childstate_getKeys { .. }
                    | methods::MethodCall::childstate_getStorage { .. }
                    | methods::MethodCall::childstate_getStorageHash { .. }
                    | methods::MethodCall::childstate_getStorageSize { .. }
                    | methods::MethodCall::grandpa_roundState { .. }
                    | methods::MethodCall::offchain_localStorageGet { .. }
                    | methods::MethodCall::offchain_localStorageSet { .. }
                    | methods::MethodCall::payment_queryInfo { .. }
                    | methods::MethodCall::rpc_methods { .. }
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
                    | methods::MethodCall::system_accountNextIndex { .. }
                    | methods::MethodCall::system_addReservedPeer { .. }
                    | methods::MethodCall::system_chain { .. }
                    | methods::MethodCall::system_chainType { .. }
                    | methods::MethodCall::system_dryRun { .. }
                    | methods::MethodCall::system_health { .. }
                    | methods::MethodCall::system_localListenAddresses { .. }
                    | methods::MethodCall::system_localPeerId { .. }
                    | methods::MethodCall::system_networkState { .. }
                    | methods::MethodCall::system_nodeRoles { .. }
                    | methods::MethodCall::system_peers { .. }
                    | methods::MethodCall::system_properties { .. }
                    | methods::MethodCall::system_removeReservedPeer { .. } => {
                        QueuedRequestTy::Regular {
                            is_legacy_api_server_specific: true,
                        }
                    }

                    // New JSON-RPC API.
                    methods::MethodCall::chainSpec_v1_chainName {}
                    | methods::MethodCall::chainSpec_v1_genesisHash {}
                    | methods::MethodCall::chainSpec_v1_properties {}
                    | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {
                        QueuedRequestTy::Regular {
                            is_legacy_api_server_specific: false,
                        }
                    }

                    // ChainHead functions.
                    methods::MethodCall::chainHead_unstable_body {
                        follow_subscription,
                        hash,
                    } => todo!(),
                    methods::MethodCall::chainHead_unstable_call {
                        follow_subscription,
                        hash,
                        function,
                        call_parameters,
                    } => todo!(),
                    methods::MethodCall::chainHead_unstable_header {
                        follow_subscription,
                        hash,
                    } => todo!(),
                    methods::MethodCall::chainHead_unstable_stopOperation {
                        follow_subscription,
                        operation_id,
                    } => todo!(),
                    methods::MethodCall::chainHead_unstable_storage {
                        follow_subscription,
                        hash,
                        items,
                        child_trie,
                    } => todo!(),
                    methods::MethodCall::chainHead_unstable_continue {
                        follow_subscription,
                        operation_id,
                    } => todo!(),
                    methods::MethodCall::chainHead_unstable_unfollow {
                        follow_subscription,
                    } => todo!(),
                    methods::MethodCall::chainHead_unstable_unpin {
                        follow_subscription,
                        hash_or_hashes,
                    } => todo!(),

                    methods::MethodCall::transaction_unstable_unwatch { subscription } => todo!(),
                    methods::MethodCall::network_unstable_subscribeEvents {} => todo!(),
                    methods::MethodCall::network_unstable_unsubscribeEvents { subscription } => {
                        todo!()
                    }
                };

                // TODO: to_owned?
                QueuedRequest {
                    id_json: request_id_json.to_owned(),
                    method: method.name().to_owned(),
                    parameters_json: Some(method.params_to_json_object()),
                    ty,
                }
            }

            Err(methods::ParseClientToServerError::JsonRpcParse(_error)) => {
                // Failed to parse the JSON-RPC request.
                self.clients[client_id.0]
                    .json_rpc_responses_queue
                    .push_back(parse::build_parse_error_response());
                return Ok(InsertClientRequest::ImmediateAnswer);
            }

            Err(methods::ParseClientToServerError::Method { request_id, error }) => {
                // JSON-RPC function not recognized.

                // Requests with an unknown method must not be blindly sent to a server, as it is
                // not possible for the reverse proxy to guarantee that the logic of the request
                // is respected.
                // For example, if the request is a subscription request, the reverse proxy
                // wouldn't be capable of understanding which client to redirect the notifications
                // to.
                self.clients[client_id.0]
                    .json_rpc_responses_queue
                    .push_back(parse::build_error_response(
                        request_id,
                        parse::ErrorResponse::MethodNotFound,
                        None,
                    ));
                return Ok(InsertClientRequest::ImmediateAnswer);
            }

            Err(methods::ParseClientToServerError::UnknownNotification(function)) => {
                // JSON-RPC function not recognized, and the call is a notification.
                // According to the JSON-RPC specification, the server must not send any response
                // to notifications, even in case of an error.
                return Ok(InsertClientRequest::Discarded);
            }
        };

        Ok(todo!())
    }

    /// Returns the next JSON-RPC response or notification to send to the given client.
    ///
    /// Returns `None` if none is available.
    ///
    /// The return type of [`ReverseProxy::insert_proxied_json_rpc_response`] indicates if a
    /// JSON-RPC response or notification has become available for a client.
    ///
    /// # Panic
    ///
    /// Panics if the given [`ClientId`] is invalid.
    ///
    pub fn next_client_json_rpc_response(&mut self, client_id: ClientId) -> Option<String> {
        assert!(self.clients[client_id.0].user_data.is_some());

        let response = self.clients[client_id.0]
            .json_rpc_responses_queue
            .pop_front()?;

        if response.decreases_num_unanswered_requests {
            self.clients[client_id.0].num_unanswered_requests -= 1;
        }

        Some(response.response)
    }

    /// Adds a new server to the list of servers.
    #[cold]
    pub fn insert_server(&mut self, user_data: TServer) -> ServerId {
        ServerId(self.servers.insert(Server {
            is_blacklisted: false,
            user_data,
        }))
    }

    /// Removes a server from the list of servers.
    ///
    /// All active subscriptions and requests are either stopped or redirected to a different
    /// server.
    ///
    /// After this function returns, [`ReverseProxy::next_proxied_json_rpc_request`] should be
    /// called with all idle servers, in order to pick up the requests that this server was
    /// processing.
    ///
    /// # Panic
    ///
    /// Panics if the given [`ServerId`] is invalid.
    ///
    // TODO: return list of clients that have a response available
    #[cold]
    pub fn remove_server(&mut self, server_id: ServerId) -> TServer {
        self.blacklist_server(server_id);
        self.servers.remove(server_id.0).user_data
    }

    // TODO: return list of clients that have a response available
    #[cold]
    fn blacklist_server(&mut self, server_id: ServerId) {
        // Set `is_blacklisted` to `true`, and return immediately if it was already `true`.
        if mem::replace(&mut self.servers[server_id.0].is_blacklisted, true) {
            return;
        }

        // Extract from `active_subscriptions` the subscriptions that were handled by that server.
        let subscriptions_to_cancel_or_reopen = {
            let mut server_and_after = self
                .active_subscriptions_by_server
                .split_off(&(server_id, String::new()));
            let mut after = server_and_after.split_off(&(ServerId(server_id.0 + 1), String::new()));
            self.active_subscriptions_by_server.append(&mut after);
            server_and_after
        };

        // Find in the subscriptions that were handled by that server the subscriptions that can
        // be cancelled by sending a notification to the client.
        // If the client happened to have a request in queue that concerns that subscription,
        // this guarantees that the notification about the cancellation is sent to the client
        // before the responses to this request.
        // For example, if the client has queued a `chainHead_unstable_header` request, it will
        // receive the `stop` event of the `chainHead_unstable_follow` subscription before
        // receiving the error response to the `chainHead_unstable_header` request.
        // While this ordering is in no way a requirement, it is more polite to do so.
        for ((_, server_subscription_id), (client_id, client_subscription_id, subscription_type)) in
            &subscriptions_to_cancel_or_reopen
        {
            match subscription_type {
                // Any active `chainHead_follow`, `transaction_submitAndWatch`, or
                // `author_submitAndWatchExtrinsic` subscription is killed.
                SubscriptionTyWithParams::AuthorSubmitAndWatchExtrinsic => {
                    self.clients[client_id.0]
                        .json_rpc_responses_queue
                        .push_back(
                            methods::ServerToClient::author_extrinsicUpdate {
                                subscription: client_subscription_id.into(),
                                result: methods::TransactionStatus::Dropped,
                            }
                            .to_json_request_object_parameters(None),
                        );
                    let _was_removed = self
                        .active_subscriptions_by_client
                        .remove(&(client_id, client_subscription_id.clone()));
                    debug_assert!(_was_removed.is_some());
                }
                SubscriptionTyWithParams::TransactionSubmitAndWatch => {
                    self.clients[client_id.0]
                        .json_rpc_responses_queue
                        .push_back(
                            methods::ServerToClient::transaction_unstable_watchEvent {
                                subscription: client_subscription_id.into(),
                                result: methods::TransactionWatchEvent::Dropped {
                                    // Unfortunately, there is no way of knowing whether the server has
                                    // broadcasted the transaction. Since `false` offers guarantees
                                    // but `true` doesn't, we opt to always send back `true`.
                                    // TODO: change the RPC spec to handle this more properly?
                                    broadcasted: true,
                                    error: "Proxied server gone".into(),
                                },
                            }
                            .to_json_request_object_parameters(None),
                        );
                    let _was_removed = self
                        .active_subscriptions_by_client
                        .remove(&(client_id, client_subscription_id.clone()));
                    debug_assert!(_was_removed.is_some());
                }
                SubscriptionTyWithParams::ChainHeadFollow => {
                    self.clients[client_id.0]
                        .json_rpc_responses_queue
                        .push_back(
                            methods::ServerToClient::chainHead_unstable_followEvent {
                                subscription: client_subscription_id.into(),
                                result: methods::FollowEvent::Stop {},
                            }
                            .to_json_request_object_parameters(None),
                        );
                    let _was_removed = self
                        .active_subscriptions_by_client
                        .remove(&(client_id, client_subscription_id.clone()));
                    debug_assert!(_was_removed.is_some());
                }

                // Other subscription types are handled below.
                SubscriptionTyWithParams::ChainSubscribeAllHeads
                | SubscriptionTyWithParams::ChainSubscribeFinalizedHeads
                | SubscriptionTyWithParams::ChainSubscribeNewHeads
                | SubscriptionTyWithParams::StateSubscribeRuntimeVersion
                | SubscriptionTyWithParams::StateSubscribeStorage { .. } => {}
            }
        }

        // The server-specific requests that were queued for this server and the requests that
        // were already sent to the server are processed the same way, as from the point of view
        // of the JSON-RPC client there's no possible way to differentiate the two.
        let requests_to_cancel = {
            // Extract from `client_with_requests_queued` the list of clients with pending
            // requests that can only target that server.
            let client_with_requests_queued = {
                let mut server_and_after = self
                    .clients_with_request_queued
                    .split_off(&(Some(server_id), ClientId(usize::MIN)));
                let mut after = server_and_after
                    .split_off(&(Some(ServerId(server_id.0 + 1)), ClientId(usize::MIN)));
                self.clients_with_request_queued.append(&mut after);
                server_and_after
            };

            // Extract from `requests_in_progress` the requests that were being processed by
            // that server.
            let requests_in_progress = {
                let mut server_and_after = self
                    .requests_in_progress
                    .split_off(&(server_id, String::new()));
                let mut after =
                    server_and_after.split_off(&(ServerId(server_id.0 + 1), String::new()));
                self.requests_in_progress.append(&mut after);
                server_and_after
            };

            let requests_queued =
                client_with_requests_queued
                    .into_iter()
                    .flat_map(|(_, client_id)| {
                        self.client_requests_queued
                            .remove(&(client_id, ServerTarget::Specific(server_id)))
                            .unwrap_or_else(|| unreachable!())
                            .into_iter()
                            .map(|rq| (client_id, rq))
                    });
            let requests_dispatched = requests_in_progress
                .into_iter()
                .map(|(_, (client_id, rq))| (client_id, rq));
            requests_dispatched.chain(requests_queued)
        };

        for (client_id, request_info) in requests_to_cancel {
            // For the sake of simplicity, we don't special-case the situation where the client
            // has been removed by the API user, as that would duplicate several code paths.
            // TODO: should try remove client nonetheless, otherwise leak

            // Unsubscription requests are immediately processed.
            if matches!(request_info.ty, QueuedRequestTy::Unsubscribe(unsub_ty)) {
                // TODO: are there fake unsubscription requests?
                self.clients[client_id.0]
                    .json_rpc_responses_queue
                    .push_back(QueuedResponse {
                        response: match unsub_ty {
                            _ => todo!(),
                        },
                        decreases_num_unanswered_requests: true,
                    });
                continue;
            }

            // Any pending request targetting a `chainHead_follow` subscription is answered
            // immediately, as a `stop` event has been generated above.
            // TODO:

            // Any other request is added back to the head of the queue of its JSON-RPC client.
            self.clients[client_id.0]
                .server_agnostic_requests_queue
                .push_front(request_info);
        }

        // Process a second time the subscriptions to cancel, this time reopening legacy JSON-RPC
        // API subscriptions by adding to the head of the JSON-RPC client requests queue a fake
        // subscription request.
        // This is done at the end, in order to avoid reopening subscriptions for which an
        // unsubscribe request was in queue.
        for ((_, server_subscription_id), (client_id, client_subscription_id, subscription_type)) in
            subscriptions_to_cancel_or_reopen
        {
            match subscription_type {
                SubscriptionTyWithParams::ChainSubscribeAllHeads
                | SubscriptionTyWithParams::ChainSubscribeFinalizedHeads
                | SubscriptionTyWithParams::ChainSubscribeNewHeads
                | SubscriptionTyWithParams::StateSubscribeRuntimeVersion
                | SubscriptionTyWithParams::StateSubscribeStorage { .. } => {
                    self.active_subscriptions_by_client
                        .get_mut(&(client_id, client_subscription_id.clone()))
                        .unwrap()
                        .1 = None;
                }

                // Already handled above.
                SubscriptionTyWithParams::AuthorSubmitAndWatchExtrinsic
                | SubscriptionTyWithParams::TransactionSubmitAndWatch
                | SubscriptionTyWithParams::ChainHeadFollow => {}
            }
        }

        // Unassign clients that were assigned to that server.
        let legacy_api_assigned_clients = {
            let mut server_and_after = self
                .legacy_api_server_assignments
                .split_off(&(server_id, ClientId(usize::MIN)));
            let mut after =
                server_and_after.split_off(&(ServerId(server_id.0 + 1), ClientId(usize::MIN)));
            self.legacy_api_server_assignments.append(&mut after);
            server_and_after
        };
        for (_, legacy_api_assigned_client) in legacy_api_assigned_clients {
            debug_assert_eq!(
                self.clients[legacy_api_assigned_client.0].legacy_api_assigned_server,
                Some(server_id)
            );
            self.clients[legacy_api_assigned_client.0].legacy_api_assigned_server = None;
        }
    }

    /// Pick a JSON-RPC request waiting to be processed.
    ///
    /// Returns `None` if no JSON-RPC request is waiting to be processed.
    ///
    /// If `None` is returned, you should try calling this function again after
    /// [`ReverseProxy::insert_client_json_rpc_request`] or [`ReverseProxy::remove_client`].
    ///
    /// If `Some(_, Some(_))` is returned, then the pulled request belongs to the given client,
    /// and [`ReverseProxy::insert_client_json_rpc_request`] can be called with that client
    /// with the guarantee that there is space for a request.
    ///
    /// If `Some(_, None)` is returned, the pulled request is related to the internal maintenance
    /// of the [`ReverseProxy`].
    ///
    /// Note that the [`ReverseProxy`] state machine doesn't enforce any limit to the number of
    /// JSON-RPC requests that a server processes simultaneously. A JSON-RPC server is expected to
    /// back-pressure its socket once it gets too busy, in which case
    /// [`ReverseProxy::next_proxied_json_rpc_request`] should no longer be called until the
    /// server is ready to accept more data.
    /// This ensures that for example a JSON-RPC server that is twice as powerful compared to
    /// another one should get approximately twice the number of requests.
    ///
    /// # Panic
    ///
    /// Panics if the given [`ServerId`] is invalid.
    ///
    pub fn next_proxied_json_rpc_request(
        &mut self,
        server_id: ServerId,
    ) -> Option<(String, Option<ClientId>)> {
        let server = &mut self.servers[server_id.0];
        if server.is_blacklisted {
            return None;
        }

        // In order to guarantee fairness between the clients, choosing which request to send to
        // the server is done in two steps: first, pick a client that has at least one request
        // waiting to be sent, then pick the first request from that client's queue. This
        // guarantees that a greedy client can't starve the other clients.
        // There are two types of requests: requests that aren't attributed to any server, and
        // requests that are attributed to a specific server. For this reason, the list of clients
        // to pick a request from depends on the server. This complicates fairness.
        // To solve this problem, we join two lists together: the list of clients with at least one
        // server-agnostic request waiting, and the list of clients with at least one
        // server-specific request waiting. The second list is weighted based on the total number
        // of clients and servers. The client to pick a request from is picked randomly from the
        // concatenation of these two lists.

        loop {
            // Choose the client to pick a request from.
            let (client_with_request, pick_from_server_specific) = {
                let mut clients_with_server_specific_request = self
                    .clients_with_request_queued
                    .range(
                        (Some(server_id), ClientId(usize::MIN))
                            ..=(Some(server_id), ClientId(usize::MAX)),
                    )
                    .map(|(_, client_id)| *client_id);
                let mut clients_with_server_agnostic_request = self
                    .clients_with_request_queued
                    .range((None, ClientId(usize::MIN))..=(None, ClientId(usize::MAX)))
                    .map(|(_, client_id)| *client_id);
                let clients_with_server_agnostic_request_len =
                    clients_with_server_agnostic_request.clone().count();
                let server_specific_weight: usize =
                    1 + (self.clients.len().saturating_sub(1) / self.servers.len());
                // While we could in theory use `rand::seq::IteratorRandom` with something
                // like `(0..server_specific_weight).flat_map(...)`, it's hard to guarantee
                // that doing so would be `O(1)`. Since we want this guarantee, we do it manually.
                let total_weight = clients_with_server_agnostic_request_len.saturating_add(
                    server_specific_weight
                        .saturating_mul(clients_with_server_specific_request.clone().count()),
                );
                let index = self.randomness.gen_range(0..total_weight);
                if index < clients_with_server_agnostic_request_len {
                    let client = *clients_with_server_agnostic_request.nth(index).unwrap();
                    (client, false)
                } else {
                    let client = clients_with_server_specific_request
                        .nth(
                            (index - clients_with_server_agnostic_request_len)
                                / server_specific_weight,
                        )
                        .unwrap();
                    (client, true)
                }
            };

            // Extract a request from that client.
            let queued_request = if pick_from_server_specific {
                // Pick a request from the server-agnostic queue of that client.
                let Some(requests_queue) = self
                    .client_requests_queued
                    .get_mut(&(client_with_request, ServerTarget::Specific(server_id)))
                else {
                    // A panic here indicates a bug in the code.
                    unreachable!()
                };

                let Some(request) = requests_queue.pop_front() else {
                    // A panic here indicates a bug in the code.
                    unreachable!()
                };

                // We need to update caches if this was the last request in queue.
                if requests_queue.is_empty() {
                    self.client_requests_queued
                        .remove(&(client_with_request, ServerTarget::Specific(server_id)));
                    self.clients_with_request_queued
                        .remove(&(Some(server_id), client_with_request));
                }

                request
            } else {
                /// Pick a request from the server-specific queue of that client.
                /// We currently always prefer the `LegacyApiUnassigned` requests queue over the
                /// `ServerAgnostic` requests queue, for no specific reason except avoiding
                /// making the implementation too complex.
                let (queue, is_legacy_api_unassigned) = if let Some(queue) = self
                    .client_requests_queued
                    .get_mut(&(client_with_request, ServerTarget::LegacyApiUnassigned))
                {
                    (queue, true)
                } else if let Some(queue) = self
                    .client_requests_queued
                    .get_mut(&(client_with_request, ServerTarget::ServerAgnostic))
                {
                    (queue, false)
                } else {
                    // A panic here indicates a bug in the code.
                    unreachable!()
                };

                // Extract the request.
                let Some(request) = queue.pop_front() else {
                    // As documented, queues must always be non-empty, otherwise they should have
                    // been removed altogether.
                    unreachable!()
                };

                // If the request is a legacy API server-specific request, assign the client to
                // the server.
                if is_legacy_api_unassigned {
                    debug_assert!(self.clients[client_with_request.0]
                        .legacy_api_assigned_server
                        .is_none());
                    self.clients[client_with_request.0].legacy_api_assigned_server =
                        Some(server_id);
                    let _was_inserted = self
                        .legacy_api_server_assignments
                        .insert((server_id, client_with_request));
                    debug_assert!(_was_inserted);
                }

                // Update the local state, either by removing the queue if it is empty, or, now
                // that the client is assigned a server, by merging it with the server-specific
                // queue.
                if queue.is_empty() {
                    self.client_requests_queued.remove(&(
                        client_with_request,
                        if is_legacy_api_unassigned {
                            ServerTarget::LegacyApiUnassigned
                        } else {
                            ServerTarget::ServerAgnostic
                        },
                    ));
                    if !self.client_requests_queued.contains_key(&(
                        client_with_request,
                        if is_legacy_api_unassigned {
                            ServerTarget::ServerAgnostic
                        } else {
                            ServerTarget::LegacyApiUnassigned
                        },
                    )) {
                        self.clients_with_request_queued
                            .remove(&(client_with_request, None));
                    }
                } else if is_legacy_api_unassigned {
                    // Queue is non-empty, and client was assigned to that server.
                    // We need to move around the queue of unassigned legacy API requests so that
                    // it targets the server.
                    let queue = mem::take(queue);
                    debug_assert!(!queue.is_empty());
                    self.client_requests_queued
                        .entry((client_with_request, ServerTarget::Specific(server_id)))
                        .or_insert_with(|| VecDeque::new())
                        .extend(queue);
                    self.clients_with_request_queued
                        .insert((Some(server_id), client_with_request));
                    self.client_requests_queued
                        .remove(&(client_with_request, ServerTarget::LegacyApiUnassigned));
                    if !self
                        .client_requests_queued
                        .contains_key(&(client_with_request, ServerTarget::ServerAgnostic))
                    {
                        let _was_removed = self
                            .clients_with_request_queued
                            .remove(&(None, client_with_request));
                        debug_assert!(_was_removed);
                    }
                }

                request
            };

            // At this point, we have extracted a request from the queue.

            // The next step is to generate a new request ID and rewrite the request in order to
            // change the request ID.
            let new_request_id = hex::encode({
                let mut bytes = [0; 48];
                self.randomness.fill_bytes(&mut bytes);
                bytes
            });
            let request_with_adjusted_id = parse::build_request(&parse::Request {
                id_json: Some(&new_request_id),
                method: &queued_request.method,
                params_json: queued_request.parameters_json.as_deref(),
            });

            // Update `self` to track that the server is processing this request.
            let _previous_value = self.requests_in_progress.insert(
                (server_id, new_request_id),
                (client_with_request, queued_request),
            );
            debug_assert!(_previous_value.is_none());

            // Success.
            break Some((
                request_with_adjusted_id,
                if self.clients[client_with_request.0].user_data.is_some() {
                    Some(client_with_request)
                } else {
                    None
                },
            ));
        }
    }

    /// Inserts a response or notification sent by a server.
    ///
    /// Note that there exists no back-pressure system here. Responses and notifications sent by
    /// servers are always accepted and buffered in order to be picked up later
    /// by [`ReverseProxy::next_client_json_rpc_response`].
    ///
    /// This cannot lead to an excessive memory usage, because the number of responses is bounded
    /// by the maximum number of in-flight JSON-RPC requests enforced on clients, and the
    /// number of notifications is bounded by the maximum number of active subscriptions enforced
    /// on clients. The state machine might merge multiple notifications from the same
    /// subscription into one in order to enforce this bound.
    ///
    /// # Panic
    ///
    /// Panics if the given [`ServerId`] is invalid.
    ///
    pub fn insert_proxied_json_rpc_response(
        &mut self,
        server_id: ServerId,
        response: &str,
    ) -> InsertProxiedJsonRpcResponse {
        match parse::parse_response(response) {
            Ok(parse::Response::ParseError { .. })
            | Ok(parse::Response::Error {
                error_code: -32603, // Internal server error.
                ..
            }) => {
                // JSON-RPC server has returned an "internal server error" or indicates that it
                // has failed to parse our JSON-RPC request as a valid request. This is never
                // supposed to happen and indicates that something is very wrong with the server.

                // The server is blacklisted. While the response might correspond to a request,
                // we do the blacklisting without removing that request from the state, as the
                // blacklisting will automatically remove all requests.
                self.blacklist_server(server_id);
                InsertProxiedJsonRpcResponse::Blacklisted("") // TODO:
            }

            Ok(parse::Response::Success {
                id_json,
                result_json,
            }) => {
                // Find in our local state the request being answered.
                // Because clients are removed only after all their in-progress requests have been
                // answered, it is guaranteed that the client is still in the list.
                // TODO: to_owned overhead
                let Some((client_id, request_info)) = self
                    .requests_in_progress
                    .remove(&(server_id, id_json.to_owned()))
                else {
                    // Server has answered a non-existing request. Blacklist it.
                    self.blacklist_server(server_id);
                    return InsertProxiedJsonRpcResponse::Blacklisted("");
                    // TODO: ^
                };

                match request_info.ty {
                    QueuedRequestTy::Subscription {
                        ty,
                        assigned_subscription_id,
                    } => {}
                    QueuedRequestTy::Unsubscribe(_) => {}
                    QueuedRequestTy::Regular {
                        is_legacy_api_server_specific,
                    } => {}
                }

                // TODO: add subscription if this was a subscribe request
                // TODO: remove subscription if this was an unsubscribe request

                // It is possible that this response concerns a client that has been
                // destroyed by the API user, in which case we simply discard the
                // response.
                if self.clients[client_id.0].user_data.is_none() {
                    // Remove the client for real if it was previously removed by the API user and
                    // that this was its last request.
                    self.try_remove_client(client_id);
                    return InsertProxiedJsonRpcResponse::Discarded;
                }

                // Rewrite the request ID found in the response in order to match what the
                // client expects.
                let response_with_translated_id =
                    parse::build_success_response(&request_info.id_json, result_json);
                self.clients[client_id.0]
                    .json_rpc_responses_queue
                    .push_back(response_with_translated_id);

                // Success.
                InsertProxiedJsonRpcResponse::Ok(client_id)
            }

            Ok(parse::Response::Error {
                id_json,
                error_code,
                error_message,
                error_data_json,
            }) => {
                // TODO: if this was a "fake subscription" request, re-queue it

                // JSON-RPC server has returned an error for this JSON-RPC call.
                // TODO: translate ID
                parse::build_error_response(
                    id_json,
                    parse::ErrorResponse::ApplicationDefined(error_code, error_message),
                    error_data_json,
                );
                // TODO: ?!
            }

            Err(response_parse_error) => {
                // If the message couldn't be parsed as a response, attempt to parse it as a
                // notification.
                match methods::parse_notification(response) {
                    Ok(mut notification) => {
                        // This is a subscription notification.
                        // Because clients are removed only after they have finished
                        // unsubscribing, it is guaranteed that the client is still in the
                        // list.
                        // TODO: overhead of into_owned
                        let Some((client_id, client_notification_id)) = self
                            .active_subscriptions_by_server
                            .get(&(server_id, notification.subscription().clone().into_owned()))
                        else {
                            // The subscription ID isn't recognized. This indicates something very
                            // wrong with the server. We handle this by blacklisting the server.
                            self.blacklist_server(server_id);
                            return InsertProxiedJsonRpcResponse::Blacklisted("");
                            // TODO: ^
                        };

                        // It is possible that this notification concerns a client that has been
                        // destroyed by the API user, in which case we simply discard the
                        // notification.
                        if self.clients[client_id.0].user_data.is_none() {
                            return InsertProxiedJsonRpcResponse::Discarded;
                        }

                        // Rewrite the subscription ID in the notification in order to match what
                        // the client expects.
                        notification.set_subscription(Cow::Borrowed(&client_notification_id));
                        let rewritten_notification =
                            notification.to_json_request_object_parameters(None);
                        // TODO: must handle situation where client doesn't pull its data
                        self.clients[client_id.0]
                            .json_rpc_responses_queue
                            .push_back(QueuedResponse {
                                response: rewritten_notification,
                                decreases_num_unanswered_requests: false,
                            });

                        // Success
                        InsertProxiedJsonRpcResponse::Ok(*client_id)
                    }

                    Err(notification_parse_error) => {
                        // Failed to parse the message from the JSON-RPC server.
                        self.blacklist_server(server_id);
                        InsertProxiedJsonRpcResponse::Blacklisted("")
                        // TODO: ^
                    }
                }
            }
        }
    }

    /// Checks if the given client has been removed using [`ReverseProxy::remove_client`] and that
    /// it has no request in progress and no active subscription, and if so removes it entirely
    /// from the state of `self`.
    fn try_remove_client(&mut self, client_id: ClientId) {
        if self.clients[client_id.0].user_data.is_some() {
            return;
        }

        if self.clients[client_id.0].num_unanswered_requests != 0 {
            return;
        }

        debug_assert!(!self
            .clients_with_server_agnostic_request_waiting
            .contains(&client_id));
        debug_assert!(self
            .client_requests_queued
            .range((client_id, ServerTarget::MIN)..(ClientId(client_id.0 + 1), ServerTarget::MIN))
            .next()
            .is_none());

        if self
            .active_subscriptions_by_client
            .range((client_id, String::new())..(ClientId(client_id.0 + 1), String::new()))
            .next()
            .is_some()
        {
            return;
        }

        let removed_client = self.clients.remove(client_id.0);

        if let Some(legacy_api_assigned_server) = removed_client.legacy_api_assigned_server {
            let _was_removed = self
                .legacy_api_server_assignments
                .remove(&(server_id, client_id));
            debug_assert!(_was_removed);
        }
    }
}

impl<TClient, TServer> ops::Index<ClientId> for ReverseProxy<TClient, TServer> {
    type Output = TClient;

    fn index(&self, id: ClientId) -> &TClient {
        self.clients[id.0].user_data.as_ref().unwrap()
    }
}

impl<TClient, TServer> ops::IndexMut<ClientId> for ReverseProxy<TClient, TServer> {
    fn index_mut(&mut self, id: ClientId) -> &mut TClient {
        self.clients[id.0].user_data.as_mut().unwrap()
    }
}

impl<TClient, TServer> ops::Index<ServerId> for ReverseProxy<TClient, TServer> {
    type Output = TServer;

    fn index(&self, id: ServerId) -> &TServer {
        &self.servers[id.0].user_data
    }
}

impl<TClient, TServer> ops::IndexMut<ServerId> for ReverseProxy<TClient, TServer> {
    fn index_mut(&mut self, id: ServerId) -> &mut TServer {
        &mut self.servers[id.0].user_data
    }
}

/// Outcome of a call to [`ReverseProxy::insert_client_json_rpc_request`].
#[derive(Debug)]
pub enum InsertClientRequest {
    /// The request has been silently discarded.
    ///
    /// This happens for example if the JSON-RPC client sends a notification.
    Discarded,

    /// The request has been immediately answered or discarded and doesn't need any
    /// further processing.
    /// [`ReverseProxy::next_client_json_rpc_response`] should be called in order to pull the
    /// response and send it to the client.
    ImmediateAnswer,

    /// The request can be processed by any server.
    /// [`ReverseProxy::next_proxied_json_rpc_request`] should be called with any [`ServerId`].
    AnyServerWakeUp,

    /// The request must be processed specifically by the indicated server.
    /// [`ReverseProxy::next_proxied_json_rpc_request`] should be called with the
    /// given [`ServerId`].
    ServerWakeUp(ServerId),
}

/// Error potentially returned by a call to [`ReverseProxy::insert_client_json_rpc_request`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum InsertClientRequestError {
    /// The number of requests that this client has queued is already equal to
    /// [`ClientConfig::max_unanswered_parallel_requests`].
    #[display(fmt = "Too many simultaneous requests")]
    TooManySimultaneousRequests,
}

pub enum InsertProxiedJsonRpcResponse {
    Ok(ClientId),
    Discarded,
    Blacklisted(&'static str),
}
