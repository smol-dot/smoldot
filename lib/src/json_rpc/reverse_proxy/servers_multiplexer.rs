// Smoldot
// Copyright (C) 2024  Pierre Krieger
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

//! Accept an incoming stream of JSON-RPC requests, and distributes them agmonst multiple
//! JSON-RPC servers.
//!
//! The [`ServersMultiplexer`] struct contains a list of servers, a queue of JSON-RPC requests,
//! and a queue of JSON-RPC responses.
//!
//! If a message sent by a JSON-RPC server is deemed to be incorrect, the server might be
//! blacklisted depending on the circumstance. No request will be sent to a blacklisted server,
//! and its messages will be ignored.
//!
//! Because multiple servers might accidentally assign the subscription ID, the subscription ID
//! of all subscriptions is rewritten by the [`ServersMultiplexer`]. In other words, the
//! subscription ID that the client observes are assigned by the [`ServersMultiplexer`].
//! Requests IDs are left untouched.
//!
//! If a server is removed or blacklisted, for each legacy JSON-RPC API subscription that this
//! server was handling, a dummy subscription request is sent to a different server and the
//! notifications sent by this other server are transparently redirected to the client as if they
//! were coming from the original server.
//! This might lead to some confusing situations, such as the latest finalized block going back
//! to an earlier block, but because the legacy JSON-RPC API doesn't provide any way to handle
//! this situation in a clean way, this is the last bad way to handle it.
// TODO: more doc

use alloc::collections::{btree_map, BTreeMap};

use crate::json_rpc::methods;

/// Configuration for a new [`ServersMultiplexer`].
pub struct Config {
    /// Value to return when a call to the `system_name` JSON-RPC function is received.
    pub system_name: Cow<'static, str>,

    /// Value to return when a call to the `system_version` JSON-RPC function is received.
    pub system_version: Cow<'static, str>,

    /// Seed used for randomness. Used to avoid HashDoS attacks and to attribute clients and
    /// requests to servers.
    pub randomness_seed: [u8; 32],
}

/// Identifier of a server within the [`ServersMultiplexer`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerId(usize);

/// See [the module-level documentation](..).
// TODO: Debug impl
pub struct ServersMultiplexer<T> {
    /// List of all servers. Indices serve as [`ServerId`].
    servers: slab::Slab<Server<TServer>>,

    /// List of all requests that have been extracted with
    /// [`ReverseProxy::next_proxied_json_rpc_request`] and are being processed by a server.
    ///
    /// Entries are removed when a response is inserted with
    /// [`ReverseProxy::insert_proxied_json_rpc_response`] or the server blacklisted through
    /// [`ReverseProxy::blacklist_server`].
    ///
    /// Keys are server IDs and the request ID from the point of view of the server.
    requests_in_progress: BTreeMap<(ServerId, String), QueuedRequest>,

    /// Queue of responses waiting to be sent to the client.
    // TODO: call shrink to fit from time to time?
    responses_queue: VecDeque<QueuedResponse>,

    /// List of all subscriptions that are currently active according to servers.
    ///
    /// Entries are inserted when a server successfully accepts a subscription request, and removed
    /// when a server sends back a confirmation of unsubscription, or a `stop` or `dropped` event
    /// or similar. In other words, entries are removed only once we don't expect any new
    /// notification coming from the server.
    active_subscriptions: BTreeMap<(ServerId, String), String>,

    /// See [`Config::system_name`]
    system_name: Cow<'static, str>,

    /// See [`Config::system_version`]
    system_version: Cow<'static, str>,
}

struct Server<TServer> {
    /// `true` if the given server has misbehaved and must not process new requests.
    is_blacklisted: bool,

    /// Opaque data chosen by the API user.
    user_data: TServer,
}

// TODO: is this struct useful?
struct QueuedResponse {
    /// The JSON-RPC response itself.
    response: String,
}

// TODO: what about rpc_methods? should we not query servers for the methods they support or something?

impl<T> ServersMultiplexer<T> {
    /// Creates a new multiplexer with an empty list of servers.
    pub fn new(config: Config) -> Self {
        ServersMultiplexer {
            servers: slab::Slab::new(), // TODO: capacity
            requests_in_progress: BTreeMap::new(),
            active_subscriptions: todo!(),
            system_name: config.system_name,
            system_version: config.system_version,
        }
    }

    /// Adds a new server to the collection.
    pub fn add_server(&mut self, user_data: T) -> ServerId {
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
    #[cold]
    pub fn remove_server(&mut self, server_id: ServerId) -> T {
        self.blacklist_server(server_id);
        self.servers.remove(server_id.0).user_data
    }

    #[cold]
    fn blacklist_server(&mut self, server_id: ServerId) {
        // Set `is_blacklisted` to `true`, and return immediately if it was already `true`.
        if mem::replace(&mut self.servers[server_id.0].is_blacklisted, true) {
            return;
        }

        // Extract from `active_subscriptions` the subscriptions that were handled by that server.
        let subscriptions_to_cancel_or_reopen = {
            let mut server_and_after = self
                .active_subscriptions
                .split_off(&(server_id, String::new()));
            let mut after = server_and_after.split_off(&(ServerId(server_id.0 + 1), String::new()));
            self.active_subscriptions.append(&mut after);
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
        for ((_, server_subscription_id), (client_subscription_id, subscription_type)) in
            &subscriptions_to_cancel_or_reopen
        {
            match subscription_type {
                // Any active `chainHead_follow`, `transaction_submitAndWatch`, or
                // `author_submitAndWatchExtrinsic` subscription is killed.
                SubscriptionTyWithParams::AuthorSubmitAndWatchExtrinsic => {
                    self.responses_queue.push_back(
                        methods::ServerToClient::author_extrinsicUpdate {
                            subscription: client_subscription_id.into(),
                            result: methods::TransactionStatus::Dropped,
                        }
                        .to_json_request_object_parameters(None),
                    );
                    let _was_removed = self
                        .active_subscriptions_by_client
                        .remove(client_subscription_id);
                    debug_assert!(_was_removed.is_some());
                }
                SubscriptionTyWithParams::TransactionSubmitAndWatch => {
                    self.responses_queue.push_back(
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
                        .remove(client_subscription_id);
                    debug_assert!(_was_removed.is_some());
                }
                SubscriptionTyWithParams::ChainHeadFollow => {
                    self.responses_queue.push_back(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: client_subscription_id.into(),
                            result: methods::FollowEvent::Stop {},
                        }
                        .to_json_request_object_parameters(None),
                    );
                    let _was_removed = self
                        .active_subscriptions_by_client
                        .remove(client_subscription_id);
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
            let requests_dispatched = requests_in_progress.into_iter().map(|(_, rq)| rq);
            requests_dispatched.chain(requests_queued)
        };

        for request_info in requests_to_cancel {
            // Unsubscription requests are immediately processed.
            if matches!(request_info.ty, QueuedRequestTy::Unsubscribe(unsub_ty)) {
                // TODO: are there fake unsubscription requests?
                self.responses_queue.push_back(QueuedResponse {
                    response: match unsub_ty {
                        _ => todo!(),
                    },
                });
                continue;
            }

            // Any pending request targetting a `chainHead_follow` subscription is answered
            // immediately, as a `stop` event has been generated above.
            // TODO:

            // Any other request is added back to the head of the queue.
            self.server_agnostic_requests_queue.push_front(request_info);
        }

        // Process a second time the subscriptions to cancel, this time reopening legacy JSON-RPC
        // API subscriptions by adding to the head of the JSON-RPC client requests queue a fake
        // subscription request.
        // This is done at the end, in order to avoid reopening subscriptions for which an
        // unsubscribe request was in queue.
        for ((_, server_subscription_id), (client_subscription_id, subscription_type)) in
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

    /// Adds a request to the queue of requests waiting to be picked up by a server.
    pub fn insert_json_rpc_request(&mut self, request: &str) -> InsertRequest {
        // Determine the request information, or answer the request directly if possible.
        let queued_request = match methods::parse_jsonrpc_client_to_server(request) {
            Ok((request_id_json, method)) => {
                let ty = match method {
                    // Answer the request directly if possible.
                    methods::MethodCall::system_name {} => {
                        self.responses_queue.push_back(QueuedResponse {
                            response: methods::Response::system_name(Cow::Borrowed(
                                &*self.system_name,
                            ))
                            .to_json_response(request_id_json),
                        });
                        return InsertRequest::ImmediateAnswer;
                    }
                    methods::MethodCall::system_version {} => {
                        self.responses_queue.push_back(QueuedResponse {
                            response: methods::Response::system_version(Cow::Borrowed(
                                &*self.system_version,
                            ))
                            .to_json_response(request_id_json),
                        });
                        return InsertRequest::ImmediateAnswer;
                    }
                    methods::MethodCall::sudo_unstable_version {} => {
                        self.responses_queue.push_back(QueuedResponse {
                            response: methods::Response::sudo_unstable_version(Cow::Owned(
                                format!("{} {}", self.system_name, self.system_version),
                            ))
                            .to_json_response(request_id_json),
                        });
                        return InsertRequest::ImmediateAnswer;
                    }
                    methods::MethodCall::sudo_unstable_p2pDiscover { .. } => {
                        self.responses_queue.push_back(QueuedResponse {
                            response: methods::Response::sudo_unstable_p2pDiscover(())
                                .to_json_response(request_id_json),
                        });
                        return InsertRequest::ImmediateAnswer;
                    }

                    // Subscription functions.
                    methods::MethodCall::state_subscribeRuntimeVersion {}
                    | methods::MethodCall::state_subscribeStorage { .. }
                    | methods::MethodCall::chain_subscribeAllHeads {}
                    | methods::MethodCall::chain_subscribeFinalizedHeads {}
                    | methods::MethodCall::chain_subscribeNewHeads {} => {
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
                        if self.num_chainhead_follow_subscriptions
                            >= self.max_chainhead_follow_subscriptions
                        {
                            self.responses_queue.push_back(QueuedResponse {
                                response: parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::ApplicationDefined(
                                        -32800,
                                        "Too many active `chainHead_follow` subscriptions",
                                    ),
                                    None,
                                ),
                            });
                            return InsertRequest::ImmediateAnswer;
                        }

                        self.num_chainhead_follow_subscriptions += 1;
                        QueuedRequestTy::Subscription {
                            ty: SubscriptionTyWithParams::ChainHeadFollow,
                            assigned_subscription_id: None,
                        }
                    }
                    methods::MethodCall::author_submitAndWatchExtrinsic { .. }
                    | methods::MethodCall::transaction_unstable_submitAndWatch { .. } => {
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
                self.responses_queue
                    .push_back(parse::build_parse_error_response());
                return InsertRequest::ImmediateAnswer;
            }

            Err(methods::ParseClientToServerError::Method { request_id, error }) => {
                // JSON-RPC function not recognized.

                // Requests with an unknown method must not be blindly sent to a server, as it is
                // not possible for the reverse proxy to guarantee that the logic of the request
                // is respected.
                // For example, if the request is a subscription request, the reverse proxy
                // wouldn't be capable of understanding which client to redirect the notifications
                // to.
                self.responses_queue.push_back(parse::build_error_response(
                    request_id,
                    parse::ErrorResponse::MethodNotFound,
                    None,
                ));
                return InsertRequest::ImmediateAnswer;
            }

            Err(methods::ParseClientToServerError::UnknownNotification(function)) => {
                // JSON-RPC function not recognized, and the call is a notification.
                // According to the JSON-RPC specification, the server must not send any response
                // to notifications, even in case of an error.
                return InsertRequest::Discarded;
            }
        };

        todo!()
    }

    /// Returns the next JSON-RPC response or notification to send to the client.
    ///
    /// Returns `None` if none is available.
    ///
    /// The return type of [`ReverseProxy::insert_proxied_json_rpc_response`] indicates if a
    /// JSON-RPC response or notification has become available.
    pub fn next_json_rpc_response(&mut self) -> Option<String> {
        let response = self.responses_queue.pop_front()?;
        Some(response.response)
    }

    /// Pick a JSON-RPC request waiting to be processed.
    ///
    /// Returns `None` if no JSON-RPC request is waiting to be processed, and you should try
    /// calling this function again after [`ReverseProxy::insert_json_rpc_request`].
    ///
    /// `None` is always returned if the server is blacklisted.
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
    pub fn next_proxied_json_rpc_request(&mut self, server_id: ServerId) -> Option<String> {
        let server = &mut self.servers[server_id.0];
        if server.is_blacklisted {
            return None;
        }

        // There are two types of requests: requests that aren't attributed to any server, and
        // requests that are attributed to a specific server.

        loop {
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
    /// by [`ReverseProxy::next_json_rpc_response`].
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
                // TODO: to_owned overhead
                let Some(request_info) = self
                    .requests_in_progress
                    .remove(&(server_id, id_json.to_owned()))
                else {
                    // Server has answered a non-existing request. Blacklist it.
                    self.blacklist_server(server_id);
                    return InsertProxiedJsonRpcResponse::Blacklisted("");
                    // TODO: ^
                };

                // TODO: in case of chainHead_follow or transaction_unstable_broadcast, try a different server if `null` is returned

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

                // Success.
                InsertProxiedJsonRpcResponse::Ok
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
                todo!()
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
                        let btree_map::Entry::Occupied(subscription_entry) = self
                            .active_subscriptions
                            .entry((server_id, notification.subscription().clone().into_owned()))
                        else {
                            // The subscription ID isn't recognized. This indicates something very
                            // wrong with the server. We handle this by blacklisting the server.
                            self.blacklist_server(server_id);
                            return InsertProxiedJsonRpcResponse::Blacklisted("");
                            // TODO: ^
                        };

                        // Rewrite the subscription ID in the notification in order to match what
                        // the client expects.
                        notification.set_subscription(Cow::Borrowed(&subscription_entry.get()));
                        let rewritten_notification =
                            notification.to_json_request_object_parameters(None);

                        // Remove the subscription if the notification indicates that the
                        // subscription is finished.
                        if matches!(
                            notification,
                            methods::ServerToClient::author_extrinsicUpdate {
                                result: methods::TransactionStatus::Dropped,
                                ..
                            } | methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                result: methods::TransactionWatchEvent::Error { .. }
                                    | methods::TransactionWatchEvent::Finalized { .. }
                                    | methods::TransactionWatchEvent::Invalid { .. }
                                    | methods::TransactionWatchEvent::Dropped { .. },
                                ..
                            } | methods::ServerToClient::chainHead_unstable_followEvent {
                                result: methods::FollowEvent::Stop {},
                                ..
                            }
                        ) {
                            subscription_entry.remove();
                        }

                        // Success.
                        self.responses_queue.push_back(QueuedResponse {
                            response: rewritten_notification,
                        });
                        InsertProxiedJsonRpcResponse::Ok
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
}

/// Outcome of a call to [`ReverseProxy::insert_json_rpc_request`].
#[derive(Debug)]
pub enum InsertRequest {
    /// The request has been silently discarded.
    ///
    /// This happens for example if the JSON-RPC client sends a notification.
    Discarded,

    /// The request has been immediately answered or discarded and doesn't need any
    /// further processing.
    /// [`ReverseProxy::next_json_rpc_response`] should be called in order to pull the response.
    ImmediateAnswer,

    /// The request can be processed by any server.
    /// [`ReverseProxy::next_proxied_json_rpc_request`] should be called with any [`ServerId`].
    AnyServerWakeUp,

    /// The request must be processed specifically by the indicated server.
    /// [`ReverseProxy::next_proxied_json_rpc_request`] should be called with the
    /// given [`ServerId`].
    ServerWakeUp(ServerId),
}

// TODO: clean up, document, etc.
pub enum InsertProxiedJsonRpcResponse {
    Ok,
    Discarded,
    Blacklisted(&'static str),
}
