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
//! When a server is removed or blacklisted, for each legacy JSON-RPC API subscription that this
//! server was handling (apart from `author_submitAndWatchExtrinsic`), a dummy subscription request
//! is sent to a different server and the notifications sent by this other server are
//! transparently redirected to the client as if they were coming from the original server.
//! This might lead to some confusing situations, such as the latest finalized block going back
//! to an earlier block, but because the legacy JSON-RPC API doesn't provide any way to handle
//! this situation in a clean way, this is the last bad way to handle it.
//!
//! When a server is removed or blacklisted, each active `chainHead_v1_follow` subscription
//! generates a `stop` event, and each active `author_submitAndWatchExtrinsic` and
//! `transactionWatch_v1_submitAndWatch` subscription generates a `dropped` event.
//!
//! JSON-RPC requests for `chainHead_v1_follow` and `transaction_unstable_broadcast` are
//! sent to a randomly-chosen server. If this server returns `null`, indicating that it has reached
//! its limits, the request is sent to a different randomly-chosen server instead. After 3 failed
//! attempts, `null` is returned to the client.
// TODO: document transaction_broadcast when server is removed
// TODO: more doc

// TODO: what about rpc_methods? should we not query servers for the methods they support or something?

use alloc::{
    borrow::Cow,
    collections::{btree_map, BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};
use core::{fmt, mem, ops};
use rand_chacha::{
    rand_core::{RngCore as _, SeedableRng as _},
    ChaCha20Rng,
};

use crate::{
    json_rpc::{methods, parse},
    util::SipHasherBuild,
};

/// Configuration for a new [`ServersMultiplexer`].
pub struct Config {
    /// Number of entries to pre-allocate for the list of servers.
    pub servers_capacity: usize,

    /// Number of entries to pre-allocate for the list of requests queued or in progress.
    pub requests_capacity: usize,

    /// Number of entries to pre-allocate for the list of active subscriptions.
    pub subscriptions_capacity: usize,

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
// TODO: can we replace String with Arc<str> in some of these fields?
pub struct ServersMultiplexer<T> {
    /// List of all servers. Indices serve as [`ServerId`].
    servers: slab::Slab<Server<T>>,

    /// Queues of requests waiting to be sent to a server.
    ///
    /// Entries are the request ID (in JSON), and the request information.
    ///
    /// Indexed by `None` if the request doesn't have to target any specific server, or by `Some`
    /// if the request must target a specific server.
    ///
    /// The `VecDeque`s must never be empty. If a queue is emptied, the item must be removed from
    /// the `BTreeMap` altogether.
    queued_requests: BTreeMap<Option<ServerId>, VecDeque<(String, Request)>>,

    /// List of all requests that have been extracted with
    /// [`ServersMultiplexer::next_proxied_json_rpc_request`] and are being processed by a server.
    ///
    /// Entries are removed when a response is inserted with
    /// [`ServersMultiplexer::insert_proxied_json_rpc_response`] or the server blacklisted through
    /// [`ServersMultiplexer::blacklist_server`].
    ///
    /// Keys are server IDs and the request ID (in JSON).
    requests_in_progress: BTreeMap<(ServerId, String), Request>,

    /// Queue of responses waiting to be sent to the client.
    responses_queue: VecDeque<String>,

    /// List of all subscriptions that are currently active.
    ///
    /// Keys are subscription IDs from the client's perspective, and values are the server that is
    /// handling this subscription and the subscription ID from the server's perspective.
    ///
    /// Entries are inserted when a server successfully accepts a subscription request, and removed
    /// when a server sends back a confirmation of unsubscription, or a `stop` or `dropped` event
    /// or similar. In other words, entries are removed only once we don't expect any new
    /// notification coming from the server.
    ///
    /// This collection does **not** include subscriptions that the client thinks are active but
    /// that aren't active on any server, which can happen after a server is removed.
    active_subscriptions:
        hashbrown::HashMap<Arc<str>, (ServerId, ActiveSubscription), SipHasherBuild>,

    /// Same entries as [`ServersMultiplexer::active_subscriptions`], but indexed by server.
    ///
    /// Keys are the server and subscription ID from the server's perspective, and values are
    /// the subscription ID from the client's perspective.
    active_subscriptions_by_server: BTreeMap<(ServerId, Arc<str>), Arc<str>>,

    /// List of subscriptions that the client thinks are alive but that aren't active on
    /// any server.
    ///
    /// Keys are the subscription ID from the point of view of the client.
    zombie_subscriptions: hashbrown::HashMap<Arc<str>, ZombieSubscription, SipHasherBuild>,

    /// Subset of the items of [`ServersMultiplexer::zombie_subscriptions`] for which a
    /// re-subscription is waiting to be sent to a server.
    ///
    /// Keys are the subscription ID from the point of view of the client.
    zombie_subscriptions_pending: BTreeSet<Arc<str>>,

    /// Subset of the items of [`ServersMultiplexer::zombie_subscriptions`] for which a
    /// re-subscription has been sent to a server.
    ///
    /// Keys are the request ID of the re-subscription request, and values are the subscription
    /// ID from the point of view of the client.
    zombie_subscriptions_by_resubscribe_id: BTreeMap<(ServerId, String), Arc<str>>,

    /// See [`Config::system_name`]
    system_name: Cow<'static, str>,

    /// See [`Config::system_version`]
    system_version: Cow<'static, str>,

    /// Source of randomness used for various purposes.
    randomness: ChaCha20Rng,
}

struct Request {
    /// Name of the method of the request.
    method_name: String,

    /// JSON-encoded parameters of the request. `None` if no parameters were provided.
    ///
    /// If the request targets a specific subscription (i.e. contains a subscription ID in its
    /// parameters), the parameters have been adjusted to target the subscription ID from the
    /// server's point of view.
    method_params_json: Option<String>,

    /// Number of times this request has previously been sent to a server, and the server has
    /// rejected it.
    previous_failed_attempts: u32,
}

struct Server<T> {
    /// `true` if the given server has misbehaved and must not process new requests.
    is_blacklisted: bool,

    /// Opaque data chosen by the API user.
    user_data: T,
}

struct ActiveSubscription {
    /// Subscription ID according to the server.
    server_subscription_id: Arc<str>,

    /// Name of the method that has performed the subscription.
    method_name: String,

    /// JSON-encoded parameters to the method that performed the subscription. `None` if no
    /// parameters were provided.
    method_params_json: Option<String>,
}

struct ZombieSubscription {
    /// Name of the method that has performed the subscription.
    method_name: String,

    /// JSON-encoded parameters to the method that performed the subscription. `None` if no
    /// parameters were provided.
    method_params_json: Option<String>,

    resubscribe_request_id: Option<String>,

    /// If `Some`, the client has sent an unsubscribe request for this subscription but that
    /// hasn't been answered yet. Immediately after the subscription has been re-subscribed,
    /// a unsubscribe request must be sent to the server.
    unsubscribe_request_id: Option<String>,
}

impl<T> ServersMultiplexer<T> {
    /// Creates a new multiplexer with an empty list of servers.
    pub fn new(config: Config) -> Self {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        ServersMultiplexer {
            servers: slab::Slab::with_capacity(config.servers_capacity),
            queued_requests: BTreeMap::new(),
            responses_queue: VecDeque::with_capacity(config.requests_capacity),
            requests_in_progress: BTreeMap::new(),
            active_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                config.subscriptions_capacity,
                SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            active_subscriptions_by_server: BTreeMap::new(),
            zombie_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                config.subscriptions_capacity,
                SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            zombie_subscriptions_pending: BTreeSet::new(),
            zombie_subscriptions_by_resubscribe_id: BTreeMap::new(),
            system_name: config.system_name,
            system_version: config.system_version,
            randomness,
        }
    }

    /// Shrinks the list of servers to the given capacity. Has no effect if the capacity is
    /// smaller than the requested one.
    pub fn shrink_servers_to(&mut self, _min_capacity: usize) {
        self.servers.shrink_to_fit() // TODO: implement Slab::shrink_to?
    }

    /// Shrinks the list of active requests to the given capacity. Has no effect if the capacity
    /// is smaller than the requested one.
    pub fn shrink_requests_to(&mut self, min_capacity: usize) {
        self.responses_queue.shrink_to(min_capacity);
    }

    /// Shrinks the list of active subscriptions to the given capacity. Has no effect if the
    /// capacity is smaller than the requested one.
    pub fn shrink_subscriptions_to(&mut self, min_capacity: usize) {
        self.active_subscriptions.shrink_to(min_capacity);
        self.zombie_subscriptions.shrink_to(min_capacity);
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
    /// After this function returns, [`ServersMultiplexer::next_proxied_json_rpc_request`] should be
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

        // Extract from `zombie_subscriptions_by_resubscribe_id` the re-subscription requests
        // that were handled by that server.
        let zombie_resubscriptions = {
            let mut server_and_after = self
                .zombie_subscriptions_by_resubscribe_id
                .split_off(&(server_id, String::new()));
            let mut after = server_and_after.split_off(&(ServerId(server_id.0 + 1), String::new()));
            self.zombie_subscriptions_by_resubscribe_id
                .append(&mut after);
            server_and_after
        };

        // Re-queue the zombie resubscriptions.
        for (_, zombie_subscription_id) in zombie_resubscriptions {
            let _was_inserted = self
                .zombie_subscriptions_pending
                .insert(zombie_subscription_id);
            debug_assert!(_was_inserted);
        }

        // Extract from `active_subscriptions_by_server` the subscriptions that were handled
        // by that server.
        let mut subscriptions_to_cancel_or_reopen = {
            let mut server_and_after = self
                .active_subscriptions_by_server
                .split_off(&(server_id, Arc::from("")));
            let mut after = server_and_after.split_off(&(ServerId(server_id.0 + 1), Arc::from("")));
            self.active_subscriptions_by_server.append(&mut after);
            server_and_after
        };

        // Find in the subscriptions that were handled by that server the subscriptions that can
        // be cancelled by sending a notification to the client.
        // If the client happened to have a request in queue that concerns that subscription,
        // this guarantees that the notification about the cancellation is sent to the client
        // before the responses to this request.
        // For example, if the client has queued a `chainHead_v1_header` request, it will
        // receive the `stop` event of the `chainHead_v1_follow` subscription before
        // receiving the error response to the `chainHead_v1_header` request.
        // While this ordering is in no way a requirement, it is more polite to do so.
        for (_, client_subscription_id) in &subscriptions_to_cancel_or_reopen {
            let hashbrown::hash_map::EntryRef::Occupied(active_subscriptions_entry) =
                self.active_subscriptions.entry_ref(client_subscription_id)
            else {
                unreachable!()
            };

            // TODO: not great to compare method names by string
            match &*active_subscriptions_entry.get().1.method_name {
                // Any active `chainHead_follow`, `transaction_submitAndWatch`, or
                // `author_submitAndWatchExtrinsic` subscription is killed.
                "author_submitAndWatchExtrinsic" => {
                    self.responses_queue.push_back(
                        methods::ServerToClient::author_extrinsicUpdate {
                            subscription: Cow::Borrowed(&*client_subscription_id),
                            result: methods::TransactionStatus::Dropped,
                        }
                        .to_json_request_object_parameters(None),
                    );
                    active_subscriptions_entry.remove();
                }
                "transactionWatch_v1_submitAndWatch" => {
                    self.responses_queue.push_back(
                        methods::ServerToClient::transactionWatch_v1_watchEvent {
                            subscription: Cow::Borrowed(&*client_subscription_id),
                            result: methods::TransactionWatchEvent::Dropped {
                                // Unfortunately, there is no way of knowing whether the server
                                // has broadcasted the transaction. Since `false` offers
                                // guarantees but `true` doesn't, we opt to always send
                                // back `true`.
                                // TODO: https://github.com/paritytech/json-rpc-interface-spec/issues/132
                                broadcasted: true,
                                error: "Proxied server gone".into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    );
                    active_subscriptions_entry.remove();
                }
                "chainHead_v1_follow" => {
                    self.responses_queue.push_back(
                        methods::ServerToClient::chainHead_v1_followEvent {
                            subscription: Cow::Borrowed(&*client_subscription_id),
                            result: methods::FollowEvent::Stop {},
                        }
                        .to_json_request_object_parameters(None),
                    );
                    active_subscriptions_entry.remove();
                }

                // Other subscription types are handled below.
                _ => {}
            }
        }

        // The server-specific requests that were queued for this server and the requests that
        // were already sent to the server are processed the same way, as from the point of view
        // of the JSON-RPC client there's no possible way to differentiate the two.
        let requests_to_cancel = {
            // Extract the list of requests that can only target that server.
            let requests_queued = {
                let mut server_and_after = self.queued_requests.split_off(&Some(server_id));
                let mut after = server_and_after.split_off(&Some(ServerId(server_id.0 + 1)));
                self.queued_requests.append(&mut after);
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

            let requests_queued = requests_queued
                .into_iter()
                .flat_map(|(_, requests)| requests.into_iter().map(|(id, rq)| (id, rq, false)));
            let requests_dispatched = requests_in_progress
                .into_iter()
                .map(|((_, rq_id), rq)| (rq_id, rq, true));
            requests_dispatched.chain(requests_queued)
        };

        for (request_id_json, request_info, already_dispatched) in requests_to_cancel {
            // Parse again the method. This is guaranteed to succeed, as otherwise the request
            // wouldn't have been inserted into the local state in the first place.
            let Ok(method) = methods::parse_jsonrpc_client_to_server_method_name_and_parameters(
                &request_info.method_name,
                request_info.method_params_json.as_deref(),
            ) else {
                unreachable!()
            };

            match &method {
                // Unsubscription requests are immediately processed, and any request targetting a
                // `chainHead_follow` subscription is answered immediately, as a `stop` event has
                // been generated above.
                methods::MethodCall::chain_unsubscribeAllHeads { subscription }
                | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription }
                | methods::MethodCall::chain_unsubscribeNewHeads { subscription }
                | methods::MethodCall::state_unsubscribeRuntimeVersion { subscription }
                | methods::MethodCall::state_unsubscribeStorage { subscription }
                | methods::MethodCall::transactionWatch_v1_unwatch { subscription }
                | methods::MethodCall::transaction_v1_stop {
                    operation_id: subscription,
                }
                | methods::MethodCall::chainHead_v1_body {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_v1_call {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_v1_header {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_v1_stopOperation {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_v1_storage {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_v1_continue {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_v1_unfollow {
                    follow_subscription: subscription,
                }
                | methods::MethodCall::chainHead_v1_unpin {
                    follow_subscription: subscription,
                    ..
                } => {
                    let subscription_exists = subscriptions_to_cancel_or_reopen
                        .remove(&(server_id, Arc::from(&**subscription)))
                        .is_some();
                    self.responses_queue.push_back(match method {
                        methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                            methods::Response::chain_unsubscribeAllHeads(subscription_exists)
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                            methods::Response::chain_unsubscribeFinalizedHeads(subscription_exists)
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                            methods::Response::chain_unsubscribeNewHeads(subscription_exists)
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                            methods::Response::state_unsubscribeRuntimeVersion(subscription_exists)
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::state_unsubscribeStorage { .. } => {
                            methods::Response::state_unsubscribeStorage(subscription_exists)
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::transactionWatch_v1_unwatch { .. } => {
                            parse::build_error_response(
                                &request_id_json,
                                parse::ErrorResponse::InvalidParams,
                                None,
                            )
                        }
                        methods::MethodCall::transaction_v1_stop { .. } => {
                            parse::build_error_response(
                                &request_id_json,
                                parse::ErrorResponse::InvalidParams,
                                None,
                            )
                        }
                        methods::MethodCall::chainHead_v1_body { .. } => {
                            methods::Response::chainHead_v1_body(
                                methods::ChainHeadBodyCallReturn::LimitReached {},
                            )
                            .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_call { .. } => {
                            methods::Response::chainHead_v1_call(
                                methods::ChainHeadBodyCallReturn::LimitReached {},
                            )
                            .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_header { .. } => {
                            methods::Response::chainHead_v1_header(None)
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_stopOperation { .. } => {
                            methods::Response::chainHead_v1_stopOperation(())
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_storage { .. } => {
                            methods::Response::chainHead_v1_storage(
                                methods::ChainHeadStorageReturn::LimitReached {},
                            )
                            .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_continue { .. } => {
                            methods::Response::chainHead_v1_continue(())
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_unfollow { .. } => {
                            methods::Response::chainHead_v1_unfollow(())
                                .to_json_response(&request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_unpin { .. } => {
                            methods::Response::chainHead_v1_unpin(())
                                .to_json_response(&request_id_json)
                        }
                        _ => unreachable!(),
                    });
                }

                // Any other request is added back to the head of the queue.
                _ => {
                    debug_assert!(already_dispatched);
                    self.queued_requests
                        .entry(None)
                        .or_insert_with(VecDeque::new)
                        .push_front((request_id_json, request_info));
                }
            }
        }

        // Process a second time the subscriptions to cancel. The list of subscriptions has been
        // adjusted by the unsubscribe requests processed above, which is why this is done
        // separately at the end.
        // This time, we reopen legacy JSON-RPC API subscriptions by inserting them into a
        // "zombie subscriptions" list.
        for (_, client_subscription_id) in subscriptions_to_cancel_or_reopen {
            let Some((_, active_subscription)) =
                self.active_subscriptions.remove(&client_subscription_id)
            else {
                // We might have already removed the subscription earlier.
                continue;
            };

            self.zombie_subscriptions.insert(
                client_subscription_id.clone(),
                ZombieSubscription {
                    method_name: active_subscription.method_name,
                    method_params_json: active_subscription.method_params_json,
                    resubscribe_request_id: None,
                    unsubscribe_request_id: None,
                },
            );

            self.zombie_subscriptions_pending
                .insert(client_subscription_id);
        }
    }

    /// Adds a request to the queue of requests waiting to be picked up by a server.
    pub fn insert_json_rpc_request(&mut self, request: String) -> InsertRequest {
        // Parse the request, making sure that it is valid JSON-RPC.
        let request = match parse::parse_request(&request) {
            Ok(rq) => rq,
            Err(_) => {
                // Failed to parse the JSON-RPC request.
                self.responses_queue
                    .push_back(parse::build_parse_error_response());
                return InsertRequest::ImmediateAnswer;
            }
        };

        // Extract the request ID.
        let Some(request_id_json) = request.id_json else {
            // The call is a notification. No notification is supported.
            // According to the JSON-RPC specification, the server must not send any response
            // to notifications, even in case of an error.
            return InsertRequest::Discarded;
        };

        // Now parse the method name and parameters.
        let Ok(method) = methods::parse_jsonrpc_client_to_server_method_name_and_parameters(
            request.method,
            request.params_json,
        ) else {
            // JSON-RPC function not recognized.

            // Requests with an unknown method must not be blindly sent to a server, as it is
            // not possible for the reverse proxy to guarantee that the logic of the request
            // is respected.
            // For example, if the request is a subscription request, the reverse proxy
            // wouldn't be capable of understanding which client to redirect the notifications
            // to.
            self.responses_queue.push_back(parse::build_error_response(
                request_id_json,
                parse::ErrorResponse::MethodNotFound,
                None,
            ));
            return InsertRequest::ImmediateAnswer;
        };

        // Try to answer the request directly. If not possible, determine which server the request
        // must target, and potentially adjust its parameters.
        let (rewritten_parameters, assigned_server) = match &method {
            // Answer the request directly if possible.
            methods::MethodCall::system_name {} => {
                self.responses_queue.push_back(
                    methods::Response::system_name(Cow::Borrowed(&*self.system_name))
                        .to_json_response(request_id_json),
                );
                return InsertRequest::ImmediateAnswer;
            }
            methods::MethodCall::system_version {} => {
                self.responses_queue.push_back(
                    methods::Response::system_version(Cow::Borrowed(&*self.system_version))
                        .to_json_response(request_id_json),
                );
                return InsertRequest::ImmediateAnswer;
            }
            methods::MethodCall::sudo_unstable_version {} => {
                self.responses_queue.push_back(
                    methods::Response::sudo_unstable_version(Cow::Owned(format!(
                        "{} {}",
                        self.system_name, self.system_version
                    )))
                    .to_json_response(request_id_json),
                );
                return InsertRequest::ImmediateAnswer;
            }
            methods::MethodCall::sudo_unstable_p2pDiscover { .. } => {
                self.responses_queue.push_back(
                    methods::Response::sudo_unstable_p2pDiscover(())
                        .to_json_response(request_id_json),
                );
                return InsertRequest::ImmediateAnswer;
            }

            // Some requests are forbidden.
            methods::MethodCall::sudo_network_unstable_watch {}
            | methods::MethodCall::sudo_network_unstable_unwatch { .. }
            | methods::MethodCall::author_removeExtrinsic { .. }
            | methods::MethodCall::author_rotateKeys { .. }
            | methods::MethodCall::system_addReservedPeer { .. }
            | methods::MethodCall::system_localListenAddresses { .. }
            | methods::MethodCall::system_localPeerId { .. }
            | methods::MethodCall::system_networkState { .. }
            | methods::MethodCall::system_nodeRoles { .. }
            | methods::MethodCall::system_peers { .. }
            | methods::MethodCall::system_removeReservedPeer { .. } => {
                self.responses_queue.push_back(parse::build_error_response(
                    request_id_json,
                    parse::ErrorResponse::MethodNotFound,
                    None,
                ));
                return InsertRequest::ImmediateAnswer;
            }

            // Unsubscription functions or functions that target a specific subscription.
            methods::MethodCall::chain_unsubscribeAllHeads { subscription }
            | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription }
            | methods::MethodCall::chain_unsubscribeNewHeads { subscription }
            | methods::MethodCall::state_unsubscribeRuntimeVersion { subscription }
            | methods::MethodCall::state_unsubscribeStorage { subscription }
            | methods::MethodCall::author_unwatchExtrinsic { subscription }
            | methods::MethodCall::transactionWatch_v1_unwatch { subscription }
            | methods::MethodCall::transaction_v1_stop {
                operation_id: subscription,
            }
            | methods::MethodCall::chainHead_v1_body {
                follow_subscription: subscription,
                ..
            }
            | methods::MethodCall::chainHead_v1_call {
                follow_subscription: subscription,
                ..
            }
            | methods::MethodCall::chainHead_v1_header {
                follow_subscription: subscription,
                ..
            }
            | methods::MethodCall::chainHead_v1_stopOperation {
                follow_subscription: subscription,
                ..
            }
            | methods::MethodCall::chainHead_v1_storage {
                follow_subscription: subscription,
                ..
            }
            | methods::MethodCall::chainHead_v1_continue {
                follow_subscription: subscription,
                ..
            }
            | methods::MethodCall::chainHead_v1_unfollow {
                follow_subscription: subscription,
            }
            | methods::MethodCall::chainHead_v1_unpin {
                follow_subscription: subscription,
                ..
            } => {
                // TODO: must check whether the subscription type matches the expected one
                if let Some(&(server_id, ref subscription_info)) =
                    self.active_subscriptions.get(&**subscription)
                {
                    // The subscription exists and is active.
                    // Pass the unsubscription request to the server.
                    // We have to adjust the parameters of the request so that the subscription
                    // ID becomes the one from the point of view of the server.
                    let parameters_rewrite = match method {
                        methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                            methods::MethodCall::chain_unsubscribeAllHeads {
                                subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                            methods::MethodCall::chain_unsubscribeFinalizedHeads {
                                subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                            methods::MethodCall::chain_unsubscribeNewHeads {
                                subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                            methods::MethodCall::state_unsubscribeRuntimeVersion {
                                subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::state_unsubscribeStorage { .. } => {
                            methods::MethodCall::state_unsubscribeStorage {
                                subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::author_unwatchExtrinsic { .. } => {
                            methods::MethodCall::author_unwatchExtrinsic {
                                subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::transactionWatch_v1_unwatch { .. } => {
                            methods::MethodCall::transactionWatch_v1_unwatch {
                                subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::transaction_v1_stop { .. } => {
                            methods::MethodCall::transaction_v1_stop {
                                operation_id: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::chainHead_v1_body { hash, .. } => {
                            methods::MethodCall::chainHead_v1_body {
                                follow_subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                                hash,
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::chainHead_v1_call {
                            hash,
                            function,
                            call_parameters,
                            ..
                        } => methods::MethodCall::chainHead_v1_call {
                            follow_subscription: Cow::Borrowed(
                                &subscription_info.server_subscription_id,
                            ),
                            hash,
                            function,
                            call_parameters,
                        }
                        .params_to_json_object(),
                        methods::MethodCall::chainHead_v1_header { hash, .. } => {
                            methods::MethodCall::chainHead_v1_header {
                                follow_subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                                hash,
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::chainHead_v1_stopOperation {
                            operation_id, ..
                        } => methods::MethodCall::chainHead_v1_stopOperation {
                            follow_subscription: Cow::Borrowed(
                                &subscription_info.server_subscription_id,
                            ),
                            operation_id,
                        }
                        .params_to_json_object(),
                        methods::MethodCall::chainHead_v1_storage {
                            hash,
                            items,
                            child_trie,
                            ..
                        } => methods::MethodCall::chainHead_v1_storage {
                            follow_subscription: Cow::Borrowed(
                                &subscription_info.server_subscription_id,
                            ),
                            hash,
                            items,
                            child_trie,
                        }
                        .params_to_json_object(),
                        methods::MethodCall::chainHead_v1_continue { operation_id, .. } => {
                            methods::MethodCall::chainHead_v1_continue {
                                follow_subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                                operation_id,
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::chainHead_v1_unfollow { .. } => {
                            methods::MethodCall::chainHead_v1_unfollow {
                                follow_subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                            }
                            .params_to_json_object()
                        }
                        methods::MethodCall::chainHead_v1_unpin { hash_or_hashes, .. } => {
                            methods::MethodCall::chainHead_v1_unpin {
                                follow_subscription: Cow::Borrowed(
                                    &subscription_info.server_subscription_id,
                                ),
                                hash_or_hashes,
                            }
                            .params_to_json_object()
                        }
                        _ => unreachable!(),
                    };

                    (Some(parameters_rewrite), Some(server_id))
                } else {
                    // The subscription isn't active on any server. It might exist in a special
                    // state.
                    let subscription_exists =
                        if let hashbrown::hash_map::EntryRef::Occupied(mut zombie_subscription) =
                            self.zombie_subscriptions.entry_ref(&**subscription)
                        {
                            // The subscription is a so-called "zombie subscription". It exists
                            // from the point of view of the client, but isn't active on any
                            // server.
                            if zombie_subscription.get().resubscribe_request_id.is_some() {
                                // We have sent a re-subscription request to one of the servers.
                                if zombie_subscription
                                    .get_mut()
                                    .unsubscribe_request_id
                                    .is_none()
                                {
                                    // Update the state of the zombie subscription so that we
                                    // immediately unsubscribe as soon as the re-subscription
                                    // happens.
                                    zombie_subscription.get_mut().unsubscribe_request_id =
                                        Some(request_id_json.to_owned());
                                    return InsertRequest::LocalStateUpdate;
                                } else {
                                    // The client has already unsubscribed from this subscription,
                                    // but we haven't sent an answer yet, and is now trying to
                                    // unsubscribe a second time. Consider that the subscription
                                    // doesn't exist for this second time.
                                    // TODO: the second unsubscribe response will come before the first unsubscribe, is that a problem?
                                    false
                                }
                            } else {
                                // We haven't sent any re-subscription request to any of the
                                // servers yet. The local state can be entirely cleaned up.
                                zombie_subscription.remove();
                                let _was_in =
                                    self.zombie_subscriptions_pending.remove(&**subscription);
                                debug_assert!(_was_in);
                                true
                            }
                        } else {
                            // Subscription isn't a "zombie subscription". It doesn't exist, or
                            // doesn't exist anymore.
                            false
                        };

                    // Immediately send back a response to the client.
                    self.responses_queue.push_back(match method {
                        methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                            methods::Response::chain_unsubscribeAllHeads(subscription_exists)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                            methods::Response::chain_unsubscribeFinalizedHeads(subscription_exists)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                            methods::Response::chain_unsubscribeNewHeads(subscription_exists)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                            methods::Response::state_unsubscribeRuntimeVersion(subscription_exists)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::state_unsubscribeStorage { .. } => {
                            methods::Response::state_unsubscribeStorage(subscription_exists)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::author_unwatchExtrinsic { .. } => {
                            parse::build_error_response(
                                request_id_json,
                                parse::ErrorResponse::InvalidParams,
                                None,
                            )
                        }
                        methods::MethodCall::transactionWatch_v1_unwatch { .. } => {
                            parse::build_error_response(
                                request_id_json,
                                parse::ErrorResponse::InvalidParams,
                                None,
                            )
                        }
                        methods::MethodCall::transaction_v1_stop { .. } => {
                            parse::build_error_response(
                                request_id_json,
                                parse::ErrorResponse::InvalidParams,
                                None,
                            )
                        }
                        methods::MethodCall::chainHead_v1_body { .. } => {
                            methods::Response::chainHead_v1_body(
                                methods::ChainHeadBodyCallReturn::LimitReached {},
                            )
                            .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_call { .. } => {
                            methods::Response::chainHead_v1_call(
                                methods::ChainHeadBodyCallReturn::LimitReached {},
                            )
                            .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_header { .. } => {
                            methods::Response::chainHead_v1_header(None)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_stopOperation { .. } => {
                            methods::Response::chainHead_v1_stopOperation(())
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_storage { .. } => {
                            methods::Response::chainHead_v1_storage(
                                methods::ChainHeadStorageReturn::LimitReached {},
                            )
                            .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_continue { .. } => {
                            methods::Response::chainHead_v1_continue(())
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_unfollow { .. } => {
                            methods::Response::chainHead_v1_unfollow(())
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_v1_unpin { .. } => {
                            methods::Response::chainHead_v1_unpin(())
                                .to_json_response(request_id_json)
                        }
                        _ => unreachable!(),
                    });
                    return InsertRequest::ImmediateAnswer;
                }
            }

            // Other JSON-RPC API functions.
            // Functions are listed individually so that if a function is added, this
            // code needs to be tweaked and added to the right category.
            methods::MethodCall::account_nextIndex { .. }
            | methods::MethodCall::author_hasKey { .. }
            | methods::MethodCall::author_hasSessionKeys { .. }
            | methods::MethodCall::author_insertKey { .. }
            | methods::MethodCall::author_pendingExtrinsics { .. }
            | methods::MethodCall::author_submitExtrinsic { .. }
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
            | methods::MethodCall::system_chain { .. }
            | methods::MethodCall::system_chainType { .. }
            | methods::MethodCall::system_dryRun { .. }
            | methods::MethodCall::system_health { .. }
            | methods::MethodCall::system_properties { .. }
            | methods::MethodCall::state_subscribeRuntimeVersion {}
            | methods::MethodCall::state_subscribeStorage { .. }
            | methods::MethodCall::chain_subscribeAllHeads {}
            | methods::MethodCall::chain_subscribeFinalizedHeads {}
            | methods::MethodCall::chain_subscribeNewHeads {}
            | methods::MethodCall::author_submitAndWatchExtrinsic { .. }
            | methods::MethodCall::chainHead_v1_follow { .. }
            | methods::MethodCall::transactionWatch_v1_submitAndWatch { .. }
            | methods::MethodCall::transaction_v1_broadcast { .. }
            | methods::MethodCall::chainSpec_v1_chainName {}
            | methods::MethodCall::chainSpec_v1_genesisHash {}
            | methods::MethodCall::chainSpec_v1_properties {}
            | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {
                (request.params_json.map(|p| p.to_owned()), None)
            }
        };

        // Everything went well. Insert the request in the queue.
        self.queued_requests
            .entry(assigned_server)
            .or_insert(VecDeque::new())
            .push_back((
                request_id_json.to_owned(),
                Request {
                    method_name: request.method.to_owned(),
                    method_params_json: rewritten_parameters,
                    previous_failed_attempts: 0,
                },
            ));
        if let Some(assigned_server) = assigned_server {
            InsertRequest::ServerWakeUp(assigned_server)
        } else {
            InsertRequest::AnyServerWakeUp
        }
    }

    /// Returns the next JSON-RPC response or notification to send to the client.
    ///
    /// Returns `None` if none is available.
    ///
    /// The return type of [`ServersMultiplexer::insert_proxied_json_rpc_response`] indicates
    /// if a JSON-RPC response or notification has become available.
    pub fn next_json_rpc_response(&mut self) -> Option<String> {
        self.responses_queue.pop_front()
    }

    /// Pick a JSON-RPC request waiting to be processed.
    ///
    /// Returns `None` if no JSON-RPC request is waiting to be processed, and you should try
    /// calling this function again after [`ServersMultiplexer::insert_json_rpc_request`].
    ///
    /// `None` is always returned if the server is blacklisted.
    ///
    /// Note that the [`ServersMultiplexer`] state machine doesn't enforce any limit to the number of
    /// JSON-RPC requests that a server processes simultaneously. A JSON-RPC server is expected to
    /// back-pressure its socket once it gets too busy, in which case
    /// [`ServersMultiplexer::next_proxied_json_rpc_request`] should no longer be called until the
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

        // It might be that the client had an active subscription against a server and that this
        // server got blacklisted or removed in the past.
        // If that happens, send a dummy subscription request in order to re-open that
        // subscription.
        if let Some(zombie_subscription_id) = self.zombie_subscriptions_pending.pop_first() {
            let Some(zombie_subscription) = self.zombie_subscriptions.get(&zombie_subscription_id)
            else {
                unreachable!()
            };

            let subscribe_request_id_json = serde_json::to_string(&{
                let mut subscription_id = [0u8; 32];
                self.randomness.fill_bytes(&mut subscription_id);
                bs58::encode(subscription_id).into_string()
            })
            .unwrap_or_else(|_| unreachable!());

            let resub_request_json = parse::build_request(&parse::Request {
                id_json: Some(&subscribe_request_id_json),
                method: &zombie_subscription.method_name,
                params_json: zombie_subscription.method_params_json.as_deref(),
            });

            let _prev_value = self.zombie_subscriptions_by_resubscribe_id.insert(
                (server_id, subscribe_request_id_json),
                zombie_subscription_id,
            );
            debug_assert!(_prev_value.is_none());

            return Some(resub_request_json);
        }

        // In any other case, grab a request from the queue.
        // There are two types of requests: requests that aren't attributed to any server, and
        // requests that are attributed to a specific server.
        // In order to guarantee some fairness, we pick from either list randomly.
        let (queued_request_id, queued_request) = {
            // Choose which queue to pick from.
            let pick_from_specific_queue = {
                let num_non_specific = self.queued_requests.get(&None).map_or(0, |l| l.len());
                let num_specific = (self
                .queued_requests
                .get(&Some(server_id))
                .map_or(0, |l| l.len())
                + (self.servers.len() - 1))  // `servers.len()` is necessarily non-zero, as a `ServerId` is provided as input.
                / self.servers.len();
                if num_non_specific == 0 && num_specific == 0 {
                    // No request available.
                    // The code below would panic if we continued.
                    return None;
                }

                let rand = rand::distributions::Distribution::sample(
                    &rand::distributions::Uniform::new(0, num_non_specific + num_specific),
                    &mut self.randomness,
                );

                rand >= num_non_specific
            };

            // Extract the request from the queue.
            let btree_map::Entry::Occupied(mut entry) =
                self.queued_requests.entry(if pick_from_specific_queue {
                    Some(server_id)
                } else {
                    None
                })
            else {
                unreachable!()
            };
            let request = entry
                .get_mut()
                .pop_front()
                .unwrap_or_else(|| unreachable!());
            if entry.get().is_empty() {
                entry.remove();
            }
            request
        };

        // Turn the request parameters into a proper request.
        let serialized_request = parse::build_request(&parse::Request {
            id_json: Some(&queued_request_id),
            method: &queued_request.method_name,
            params_json: queued_request.method_params_json.as_deref(),
        });

        // Update local state to track that the server is processing this request.
        let _previous_value = self
            .requests_in_progress
            .insert((server_id, queued_request_id), queued_request);
        debug_assert!(_previous_value.is_none());

        // Success.
        Some(serialized_request)
    }

    /// Inserts a response or notification sent by a server.
    ///
    /// Note that there exists no back-pressure system here. Responses and notifications sent by
    /// servers are always accepted and buffered in order to be picked up later
    /// by [`ServersMultiplexer::next_json_rpc_response`].
    ///
    /// # Panic
    ///
    /// Panics if the given [`ServerId`] is invalid.
    ///
    pub fn insert_proxied_json_rpc_response(
        &mut self,
        server_id: ServerId,
        mut response: String,
    ) -> InsertProxiedJsonRpcResponse {
        match parse::parse_response(&response) {
            Err(_) => {
                // If the message couldn't be parsed as a response, attempt to parse it as a
                // notification.
                let Ok(mut notification) = methods::parse_notification(&response) else {
                    // Failed to parse the message from the JSON-RPC server.
                    self.blacklist_server(server_id);
                    return InsertProxiedJsonRpcResponse::Blacklisted(
                        BlacklistReason::ParseFailure,
                    );
                };

                // This is a subscription notification.
                // TODO: overhead of into_owned
                let btree_map::Entry::Occupied(subscription_entry) = self
                    .active_subscriptions_by_server
                    .entry((server_id, Arc::from(&**notification.subscription())))
                else {
                    // The subscription ID isn't recognized. This indicates something very
                    // wrong with the server. We handle this by blacklisting the server.
                    self.blacklist_server(server_id);
                    return InsertProxiedJsonRpcResponse::Blacklisted(
                        BlacklistReason::InvalidSubscriptionId,
                    );
                };

                // Rewrite the subscription ID in the notification in order to match what
                // the client expects.
                notification.set_subscription(Cow::Borrowed(&subscription_entry.get()));
                let rewritten_notification = notification.to_json_request_object_parameters(None);

                // Remove the subscription if the notification indicates that the
                // subscription is finished.
                if matches!(
                    notification,
                    methods::ServerToClient::author_extrinsicUpdate {
                        result: methods::TransactionStatus::Dropped,
                        ..
                    } | methods::ServerToClient::transactionWatch_v1_watchEvent {
                        result: methods::TransactionWatchEvent::Error { .. }
                            | methods::TransactionWatchEvent::Finalized { .. }
                            | methods::TransactionWatchEvent::Invalid { .. }
                            | methods::TransactionWatchEvent::Dropped { .. },
                        ..
                    } | methods::ServerToClient::chainHead_v1_followEvent {
                        result: methods::FollowEvent::Stop {},
                        ..
                    }
                ) {
                    let _was_in = self.active_subscriptions.remove(subscription_entry.get());
                    debug_assert!(_was_in.is_some());
                    subscription_entry.remove();
                }

                // Success.
                self.responses_queue.push_back(rewritten_notification);
                InsertProxiedJsonRpcResponse::Queued
            }

            Ok(parse_result) => {
                // Grab the ID of the request that is being answered.
                let request_id_json = match parse_result {
                    parse::Response::Success { id_json, .. } => id_json,
                    parse::Response::Error { id_json, .. } => id_json,
                    parse::Response::ParseError { .. } => {
                        // JSON-RPC server indicates that it has failed to parse a JSON-RPC
                        // request as a valid request. This is never supposed to happen and
                        // indicates that something is very wrong with the server.
                        // The server is blacklisted.
                        self.blacklist_server(server_id);
                        return InsertProxiedJsonRpcResponse::Blacklisted(
                            BlacklistReason::ParseErrorResponse,
                        );
                    }
                };

                // TODO: detect internal server errors and blacklist the server

                // Find the answered request in the local state.
                // We don't immediately remove the request, as it might have to stay there.
                let mut requests_in_progress_entry = self
                    .requests_in_progress
                    .entry((server_id, request_id_json.to_owned())); // TODO: to_owned overhead
                let mut zombie_subscriptions_entry = self
                    .zombie_subscriptions_by_resubscribe_id
                    .entry((server_id, request_id_json.to_owned())); // TODO: to_owned overhead

                // Extract information about the request.
                let (
                    method_name,
                    method_params_json,
                    unsubscribe_request_id,
                    previous_failed_attempts,
                ) = match (
                    &mut requests_in_progress_entry,
                    &mut zombie_subscriptions_entry,
                ) {
                    (btree_map::Entry::Occupied(rq), _zombie) => {
                        debug_assert!(matches!(_zombie, btree_map::Entry::Vacant(_)));
                        let rq = rq.get_mut();
                        (
                            &rq.method_name,
                            &rq.method_params_json,
                            None,
                            Some(&mut rq.previous_failed_attempts),
                        )
                    }
                    (btree_map::Entry::Vacant(_), btree_map::Entry::Occupied(zombie)) => {
                        let Some(subscription) = self.zombie_subscriptions.get_mut(zombie.get())
                        else {
                            unreachable!()
                        };
                        (
                            &subscription.method_name,
                            &subscription.method_params_json,
                            Some(&mut subscription.unsubscribe_request_id),
                            None,
                        )
                    }
                    (btree_map::Entry::Vacant(_), btree_map::Entry::Vacant(_)) => {
                        // Server has answered a non-existing request. Blacklist it.
                        self.blacklist_server(server_id);
                        return InsertProxiedJsonRpcResponse::Blacklisted(
                            BlacklistReason::InvalidRequestId,
                        );
                    }
                };

                // Parse the request's method name and parameters again.
                // This is guaranteed to always succeed, as otherwise the request wouldn't have
                // been inserted into the local state.
                let Ok(request_method) =
                    methods::parse_jsonrpc_client_to_server_method_name_and_parameters(
                        &method_name,
                        method_params_json.as_deref(),
                    )
                else {
                    unreachable!()
                };

                match (
                    &request_method,
                    previous_failed_attempts.map_or(false, |n| *n >= 2),
                ) {
                    // Some functions return `null` if the server has reached its limit, in which
                    // case we silently discard the response and try a different server instead.
                    // TODO: not finished
                    (methods::MethodCall::chainHead_v1_follow { .. }, false) => {}

                    _ => {}
                }

                // TODO: what if error and zombie request
                match (&request_method, parse_result) {
                    // If the function is a subscription, we update our local state.
                    (
                        methods::MethodCall::chainHead_v1_follow { .. }
                        | methods::MethodCall::chain_subscribeAllHeads {}
                        | methods::MethodCall::chain_subscribeFinalizedHeads {}
                        | methods::MethodCall::chain_subscribeNewHeads {}
                        | methods::MethodCall::state_subscribeRuntimeVersion {}
                        | methods::MethodCall::state_subscribeStorage { .. }
                        | methods::MethodCall::author_submitAndWatchExtrinsic { .. }
                        | methods::MethodCall::transactionWatch_v1_submitAndWatch { .. }
                        | methods::MethodCall::transaction_v1_broadcast { .. },
                        parse::Response::Success { result_json, .. },
                    ) => {
                        let subscription_id = match methods::parse_jsonrpc_response(
                            request_method.name(),
                            result_json,
                        ) {
                            Ok(
                                methods::Response::chainHead_v1_follow(subscription_id)
                                | methods::Response::chain_subscribeAllHeads(subscription_id)
                                | methods::Response::chain_subscribeFinalizedHeads(subscription_id)
                                | methods::Response::chain_subscribeNewHeads(subscription_id)
                                | methods::Response::state_subscribeRuntimeVersion(subscription_id)
                                | methods::Response::state_subscribeStorage(subscription_id)
                                | methods::Response::author_submitAndWatchExtrinsic(subscription_id)
                                | methods::Response::transactionWatch_v1_submitAndWatch(
                                    subscription_id,
                                )
                                | methods::Response::transaction_v1_broadcast(subscription_id),
                            ) => subscription_id,
                            Ok(_) => unreachable!(),
                            Err(_) => {
                                // TODO: ?!
                                todo!()
                            }
                        };

                        // Turn the subscription into an `Arc<str>`.
                        let subscription_id: Arc<str> = Arc::from(subscription_id);

                        // Because multiple servers might assign the same subscription ID, we
                        // assign a new separate subscription ID to send back to the client.
                        let rellocated_subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            self.randomness.fill_bytes(&mut subscription_id);
                            Arc::<str>::from(bs58::encode(subscription_id).into_string())
                        };

                        // Update the list of active subscriptions stored in `self`.
                        match self
                            .active_subscriptions_by_server
                            .entry((server_id, subscription_id.clone()))
                        {
                            btree_map::Entry::Vacant(entry) => {
                                entry.insert(rellocated_subscription_id.clone());
                            }
                            btree_map::Entry::Occupied(_) => {
                                // The server has assigned a subscription ID that it has
                                // already assigned in the past. This indicates something
                                // very wrong with the server.
                                self.blacklist_server(server_id);
                                return InsertProxiedJsonRpcResponse::Blacklisted(
                                    BlacklistReason::DuplicateSubscriptionId,
                                );
                            }
                        }
                        let _prev_value = self.active_subscriptions.insert(
                            rellocated_subscription_id.clone(),
                            (
                                server_id,
                                ActiveSubscription {
                                    method_name: method_name.clone(),
                                    method_params_json: method_params_json.clone(),
                                    server_subscription_id: subscription_id.clone(),
                                },
                            ),
                        );
                        debug_assert!(_prev_value.is_none());

                        // If this subscription was a zombie subscription (i.e. a subscription
                        // that the client thinks is active but wasn't actually active on any
                        // server), it is possible that the client sent a request to unsubscribe
                        // while the server was still responding to the subscription request.
                        // When that happens, the client's unsubscription request is silently
                        // ignored, and we now re-queue it.
                        // TODO: notify through return type  that there's a request for the server to pick up?
                        if let Some(unsubscribe_request_id) =
                            unsubscribe_request_id.and_then(|rq_id| rq_id.take())
                        {
                            let unsub_request = match request_method {
                                methods::MethodCall::chainHead_v1_follow { .. } => {
                                    methods::MethodCall::chainHead_v1_unfollow {
                                        follow_subscription: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                methods::MethodCall::chain_subscribeAllHeads {} => {
                                    methods::MethodCall::chain_unsubscribeAllHeads {
                                        subscription: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                                    methods::MethodCall::chain_unsubscribeFinalizedHeads {
                                        subscription: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                methods::MethodCall::chain_subscribeNewHeads {} => {
                                    methods::MethodCall::chain_unsubscribeNewHeads {
                                        subscription: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                methods::MethodCall::state_subscribeRuntimeVersion {} => {
                                    methods::MethodCall::state_unsubscribeRuntimeVersion {
                                        subscription: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                methods::MethodCall::state_subscribeStorage { .. } => {
                                    methods::MethodCall::state_unsubscribeStorage {
                                        subscription: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                methods::MethodCall::author_submitAndWatchExtrinsic { .. } => {
                                    methods::MethodCall::author_unwatchExtrinsic {
                                        subscription: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                methods::MethodCall::transactionWatch_v1_submitAndWatch {
                                    ..
                                } => methods::MethodCall::transactionWatch_v1_unwatch {
                                    subscription: Cow::Borrowed(&*subscription_id),
                                },
                                methods::MethodCall::transaction_v1_broadcast { .. } => {
                                    methods::MethodCall::transaction_v1_stop {
                                        operation_id: Cow::Borrowed(&*subscription_id),
                                    }
                                }
                                _ => unreachable!(),
                            };

                            self.queued_requests
                                .entry(Some(server_id))
                                .or_insert(VecDeque::new())
                                .push_back((
                                    unsubscribe_request_id,
                                    Request {
                                        method_name: unsub_request.name().to_owned(),
                                        method_params_json: Some(
                                            unsub_request.params_to_json_object(),
                                        ),
                                        previous_failed_attempts: 0,
                                    },
                                ));
                        }

                        // The response to the client needs to be adjusted for the fact that
                        // we modify the subscription ID.
                        response = match request_method {
                            methods::MethodCall::chainHead_v1_follow { .. } => {
                                methods::Response::chainHead_v1_follow(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            methods::MethodCall::chain_subscribeAllHeads {} => {
                                methods::Response::chain_subscribeAllHeads(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            methods::MethodCall::chain_subscribeFinalizedHeads {} => {
                                methods::Response::chain_subscribeFinalizedHeads(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            methods::MethodCall::chain_subscribeNewHeads {} => {
                                methods::Response::chain_subscribeNewHeads(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            methods::MethodCall::state_subscribeRuntimeVersion {} => {
                                methods::Response::state_subscribeRuntimeVersion(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            methods::MethodCall::state_subscribeStorage { .. } => {
                                methods::Response::state_subscribeStorage(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            methods::MethodCall::author_submitAndWatchExtrinsic { .. } => {
                                methods::Response::author_submitAndWatchExtrinsic(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            methods::MethodCall::transactionWatch_v1_submitAndWatch { .. } => {
                                methods::Response::transactionWatch_v1_submitAndWatch(
                                    Cow::Borrowed(&rellocated_subscription_id),
                                )
                            }
                            methods::MethodCall::transaction_v1_broadcast { .. } => {
                                methods::Response::transaction_v1_broadcast(Cow::Borrowed(
                                    &rellocated_subscription_id,
                                ))
                            }
                            _ => unreachable!(),
                        }
                        .to_json_response(request_id_json);
                    }

                    // If the function is an unsubscription, we update our local state.
                    // It is possible that the server has sent back an error or indicating that
                    // the subscription was invalid. Because there is not much that can be done
                    // to handle that situation properly, we don't actually put much effort into
                    // detecting that case. In the best case scenario, the server has for some
                    // reason lost this subscription in the past and everything is fine. In the
                    // worst case scenario, the server will continue sending notifications which
                    // the multiplexer will ignore when they arrive.
                    (
                        methods::MethodCall::chain_unsubscribeAllHeads { subscription }
                        | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription }
                        | methods::MethodCall::chain_unsubscribeNewHeads { subscription }
                        | methods::MethodCall::state_unsubscribeRuntimeVersion { subscription }
                        | methods::MethodCall::state_unsubscribeStorage { subscription }
                        | methods::MethodCall::author_unwatchExtrinsic { subscription }
                        | methods::MethodCall::transactionWatch_v1_unwatch { subscription }
                        | methods::MethodCall::transaction_v1_stop {
                            operation_id: subscription,
                        }
                        | methods::MethodCall::chainHead_v1_unfollow {
                            follow_subscription: subscription,
                        },
                        _,
                    ) => {
                        // The request that has been extracted has had its parameters adjusted
                        // so that the subscription ID is the server-side ID.
                        if let Some(client_subscription_id) = self
                            .active_subscriptions_by_server
                            .remove(&(server_id, Arc::from(&**subscription)))
                        // TODO: overhead ^
                        {
                            let _was_in = self.active_subscriptions.remove(&client_subscription_id);
                            debug_assert!(_was_in.is_some());
                        }

                        // The response to the client is adjusted to always be a successful
                        // unsubscription.
                        response = match request_method {
                            methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                                methods::Response::chain_unsubscribeAllHeads(true)
                            }
                            methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                                methods::Response::chain_unsubscribeFinalizedHeads(true)
                            }
                            methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                                methods::Response::chain_unsubscribeNewHeads(true)
                            }
                            methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                                methods::Response::state_unsubscribeRuntimeVersion(true)
                            }
                            methods::MethodCall::state_unsubscribeStorage { .. } => {
                                methods::Response::state_unsubscribeStorage(true)
                            }
                            methods::MethodCall::author_unwatchExtrinsic { .. } => {
                                methods::Response::author_unwatchExtrinsic(true)
                            }
                            methods::MethodCall::transactionWatch_v1_unwatch { .. } => {
                                methods::Response::transactionWatch_v1_unwatch(())
                            }
                            methods::MethodCall::transaction_v1_stop { .. } => {
                                methods::Response::transaction_v1_stop(())
                            }
                            methods::MethodCall::chainHead_v1_unfollow { .. } => {
                                methods::Response::chainHead_v1_unfollow(())
                            }
                            _ => unreachable!(),
                        }
                        .to_json_response(request_id_json);
                    }

                    _ => {}
                }

                // Success.
                if let btree_map::Entry::Occupied(entry) = requests_in_progress_entry {
                    entry.remove();
                }
                if let btree_map::Entry::Occupied(entry) = zombie_subscriptions_entry {
                    entry.remove();
                }
                self.responses_queue.push_back(response);
                InsertProxiedJsonRpcResponse::Queued
            }
        }
    }
}

impl<T> fmt::Debug for ServersMultiplexer<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Servers<'a, T>(&'a ServersMultiplexer<T>);
        impl<'a, T: fmt::Debug> fmt::Debug for Servers<'a, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(
                        self.0
                            .servers
                            .iter()
                            .map(|(index, server)| (ServerId(index), &server.user_data)),
                    )
                    .finish()
            }
        }

        struct Requests<'a, T>(&'a ServersMultiplexer<T>);
        impl<'a, T: fmt::Debug> fmt::Debug for Requests<'a, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(
                        self.0
                            .requests_in_progress
                            .iter()
                            .map(|((_, rq_id), _)| rq_id)
                            .chain(
                                self.0
                                    .queued_requests
                                    .values()
                                    .flat_map(|list| list.iter())
                                    .map(|(rq_id, _)| rq_id),
                            ),
                    )
                    .finish()
            }
        }

        struct Subscriptions<'a, T>(&'a ServersMultiplexer<T>);
        impl<'a, T: fmt::Debug> fmt::Debug for Subscriptions<'a, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(
                        self.0
                            .active_subscriptions
                            .iter()
                            .map(|(sub_id, _)| sub_id)
                            .chain(self.0.zombie_subscriptions.keys()),
                    )
                    .finish()
            }
        }

        f.debug_struct("ServersMultiplexer")
            .field("servers", &Servers(self))
            .field("requests", &Requests(self))
            .field("subscriptions", &Subscriptions(self))
            .finish()
    }
}

impl<T> ops::Index<ServerId> for ServersMultiplexer<T> {
    type Output = T;

    fn index(&self, id: ServerId) -> &T {
        &self.servers[id.0].user_data
    }
}

impl<T> ops::IndexMut<ServerId> for ServersMultiplexer<T> {
    fn index_mut(&mut self, id: ServerId) -> &mut T {
        &mut self.servers[id.0].user_data
    }
}

/// Outcome of a call to [`ServersMultiplexer::insert_json_rpc_request`].
#[derive(Debug)]
pub enum InsertRequest {
    /// The request has been silently discarded.
    ///
    /// This happens for example if the JSON-RPC client sends a notification.
    Discarded,

    /// The request has been updated to take the request into account. No request needs to be
    /// sent to any server.
    LocalStateUpdate,

    /// The request has been immediately answered or discarded and doesn't need any
    /// further processing.
    /// [`ServersMultiplexer::next_json_rpc_response`] should be called in order to pull the response.
    ImmediateAnswer,

    /// The request can be processed by any server.
    /// [`ServersMultiplexer::next_proxied_json_rpc_request`] should be called with
    /// any [`ServerId`].
    AnyServerWakeUp,

    /// The request must be processed specifically by the indicated server.
    /// [`ServersMultiplexer::next_proxied_json_rpc_request`] should be called with the
    /// given [`ServerId`].
    ServerWakeUp(ServerId),
}

/// Outcome of a call to [`ServersMultiplexer::insert_proxied_json_rpc_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertProxiedJsonRpcResponse {
    /// The response or notification has been queued and can now be retrieved
    /// using [`ServersMultiplexer::next_json_rpc_response`].
    Queued,
    /// The server is misbehaving in some way.
    Blacklisted(BlacklistReason),
}

/// See [`InsertProxiedJsonRpcResponse::Blacklisted`].
#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
#[non_exhaustive]

pub enum BlacklistReason {
    /// Failed to parse the server's response or notification.
    ParseFailure,
    /// The response sent by the server doesn't correspond to any known request.
    InvalidRequestId,
    /// The notification sent by the server doesn't correspond to any known subscription.
    InvalidSubscriptionId,
    /// Server has sent a "parse error" response indicating that it has failed to parse our of
    /// our requests.
    ParseErrorResponse,
    /// Server has allocated a subscription ID that was already allocated against a different
    /// subscription.
    DuplicateSubscriptionId,
}
