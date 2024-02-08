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
//! When a server is removed or blacklisted, each active `chainHead_unstable_follow` subscription
//! generates a `stop` event, and each active `author_submitAndWatchExtrinsic` and
//! `transactionWatch_unstable_submitAndWatch` subscription generates a `dropped` event.
//!
//! JSON-RPC requests for `chainHead_unstable_follow` and `transaction_unstable_broadcast` are
//! sent to a randomly-chosen server. If this server returns `null`, indicating that it has reached
//! its limits, the request is sent to a different randomly-chosen server instead. After 3 failed
//! attempts, `null` is returned to the client.
// TODO: document transaction_broadcast when server is removed
// TODO: more doc

use alloc::{
    borrow::Cow,
    collections::{btree_map, BTreeMap, VecDeque},
};
use core::{mem, ops};
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
    // TODO: call shrink to fit from time to time?
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
    // TODO: call shrink to fit from time to time?
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
    // TODO: call shrink to fit from time to time?
    active_subscriptions:
        hashbrown::HashMap<String, (ServerId, ActiveSubscription), SipHasherBuild>,

    /// Same entries as [`ServersMultiplexer::active_subscriptions`], but indexed by server.
    ///
    /// Keys are the server and subscription ID from the server's perspective, and values are
    /// the subscription ID from the client's perspective.
    active_subscriptions_by_server: BTreeMap<(ServerId, String), String>,

    // TODO: call shrink to fit from time to time?
    zombie_subscriptions_queue: VecDeque<ZombieSubscription>,

    // TODO: call shrink to fit from time to time?
    zombie_subscriptions_resub_requests:
        hashbrown::HashMap<String, ZombieSubscription, fnv::FnvBuildHasher>,

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
    server_subscription_id: String,

    /// Name of the method that has performed the subscription.
    method_name: String,

    /// JSON-encoded parameters to the method that performed the subscription. `None` if no
    /// parameters were provided.
    method_params_json: Option<String>,
}

struct ZombieSubscription {
    /// Subscription ID according to the client.
    client_subscription_id: String,

    /// Name of the method that has performed the subscription.
    method_name: String,

    /// JSON-encoded parameters to the method that performed the subscription. `None` if no
    /// parameters were provided.
    method_params_json: Option<String>,

    /// If `Some`, the client has sent an unsubscribe request for this subscription but that
    /// hasn't been answered yet. Immediately after the subscription has been re-subscribed,
    /// a unsubscribe request must be sent to the server.
    unsubscribe_request_id: Option<String>,
}

// TODO: what about rpc_methods? should we not query servers for the methods they support or something?

impl<T> ServersMultiplexer<T> {
    /// Creates a new multiplexer with an empty list of servers.
    pub fn new(config: Config) -> Self {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        ServersMultiplexer {
            servers: slab::Slab::new(), // TODO: capacity
            queued_requests: BTreeMap::new(),
            responses_queue: VecDeque::new(), // TODO: capacity
            requests_in_progress: BTreeMap::new(),
            active_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                0, // TODO:
                SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            active_subscriptions_by_server: BTreeMap::new(),
            zombie_subscriptions_queue: VecDeque::new(),
            zombie_subscriptions_resub_requests: hashbrown::HashMap::with_capacity_and_hasher(
                0,
                Default::default(),
            ),
            system_name: config.system_name,
            system_version: config.system_version,
            randomness,
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

        // Extract from `active_subscriptions_by_server` the subscriptions that were handled by that server.
        let mut subscriptions_to_cancel_or_reopen = {
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
        for ((_, server_subscription_id), client_subscription_id) in
            &subscriptions_to_cancel_or_reopen
        {
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
                            subscription: client_subscription_id.into(),
                            result: methods::TransactionStatus::Dropped,
                        }
                        .to_json_request_object_parameters(None),
                    );
                    active_subscriptions_entry.remove();
                }
                "transactionWatch_unstable_submitAndWatch" => {
                    self.responses_queue.push_back(
                        methods::ServerToClient::transactionWatch_unstable_watchEvent {
                            subscription: client_subscription_id.into(),
                            result: methods::TransactionWatchEvent::Dropped {
                                // Unfortunately, there is no way of knowing whether the server
                                // has broadcasted the transaction. Since `false` offers
                                // guarantees but `true` doesn't, we opt to always send
                                // back `true`.
                                // TODO: change the RPC spec to handle this more properly?
                                broadcasted: true,
                                error: "Proxied server gone".into(),
                            },
                        }
                        .to_json_request_object_parameters(None),
                    );
                    active_subscriptions_entry.remove();
                }
                "chainHead_unstable_follow" => {
                    self.responses_queue.push_back(
                        methods::ServerToClient::chainHead_unstable_followEvent {
                            subscription: client_subscription_id.into(),
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
                .flat_map(|(_, requests)| requests.into_iter());
            let requests_dispatched = requests_in_progress.into_iter().map(|(_, rq)| rq);
            requests_dispatched.chain(requests_queued)
        };

        for request_info in requests_to_cancel {
            // Parse the request again. The request is guaranteed to parse succesfully, otherwise
            // it wouldn't have been queued.
            // TODO: could be optimized by storing the ID on the side during the first parsing?
            let Ok((request_id_json, method)) =
                methods::parse_jsonrpc_client_to_server(&request_info.request_json)
            else {
                unreachable!()
            };

            match method {
                // Unsubscription requests are immediately processed, and any request targetting a
                // `chainHead_follow` subscription is answered immediately, as a `stop` event has
                // been generated above.
                methods::MethodCall::chain_unsubscribeAllHeads { subscription }
                | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription }
                | methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                    let subscription_exists = subscriptions_to_cancel_or_reopen
                        .remove(&(server_id, subscription))
                        .is_some();
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
                        _ => unreachable!(),
                    });
                }
                methods::MethodCall::state_unsubscribeRuntimeVersion { subscription }
                | methods::MethodCall::state_unsubscribeStorage { subscription }
                | methods::MethodCall::transactionWatch_unstable_unwatch { subscription }
                | methods::MethodCall::sudo_network_unstable_unwatch { subscription }
                | methods::MethodCall::chainHead_unstable_body {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_unstable_call {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_unstable_header {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_unstable_stopOperation {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_unstable_storage {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_unstable_continue {
                    follow_subscription: subscription,
                    ..
                }
                | methods::MethodCall::chainHead_unstable_unfollow {
                    follow_subscription: subscription,
                }
                | methods::MethodCall::chainHead_unstable_unpin {
                    follow_subscription: subscription,
                    ..
                } => {
                    let subscription_exists = subscriptions_to_cancel_or_reopen
                        .remove(&(server_id, subscription.into_owned()))
                        .is_some();
                    self.responses_queue.push_back(match method {
                        methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                            methods::Response::state_unsubscribeRuntimeVersion(subscription_exists)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::state_unsubscribeStorage { .. } => {
                            methods::Response::state_unsubscribeStorage(subscription_exists)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::transactionWatch_unstable_unwatch { .. } => {
                            parse::build_error_response(
                                request_id_json,
                                parse::ErrorResponse::InvalidParams,
                                None,
                            )
                        }
                        methods::MethodCall::sudo_network_unstable_unwatch { .. } => {
                            parse::build_error_response(
                                request_id_json,
                                parse::ErrorResponse::InvalidParams,
                                None,
                            )
                        }
                        methods::MethodCall::chainHead_unstable_body { .. } => {
                            methods::Response::chainHead_unstable_body(
                                methods::ChainHeadBodyCallReturn::LimitReached {},
                            )
                            .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_unstable_call { .. } => {
                            methods::Response::chainHead_unstable_call(
                                methods::ChainHeadBodyCallReturn::LimitReached {},
                            )
                            .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_unstable_header { .. } => {
                            methods::Response::chainHead_unstable_header(None)
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_unstable_stopOperation { .. } => {
                            methods::Response::chainHead_unstable_stopOperation(())
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_unstable_storage { .. } => {
                            methods::Response::chainHead_unstable_storage(
                                methods::ChainHeadStorageReturn::LimitReached {},
                            )
                            .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_unstable_continue { .. } => {
                            methods::Response::chainHead_unstable_continue(())
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_unstable_unfollow { .. } => {
                            methods::Response::chainHead_unstable_unfollow(())
                                .to_json_response(request_id_json)
                        }
                        methods::MethodCall::chainHead_unstable_unpin { .. } => {
                            methods::Response::chainHead_unstable_unpin(())
                                .to_json_response(request_id_json)
                        }
                        _ => unreachable!(),
                    });
                }

                // Any other request is added back to the head of the queue.
                _ => {
                    self.queued_requests
                        .entry(None)
                        .or_insert_with(VecDeque::new)
                        .push_front(request_info);
                }
            }
        }

        // Process a second time the subscriptions to cancel, this time reopening legacy JSON-RPC
        // API subscriptions by adding to the head of the JSON-RPC client requests queue a fake
        // subscription request.
        // This is done at the end, in order to avoid reopening subscriptions for which an
        // unsubscribe request was in queue.
        for ((_, server_subscription_id), client_subscription_id) in
            subscriptions_to_cancel_or_reopen
        {
            let Some((_, active_subscription)) =
                self.active_subscriptions.remove(&client_subscription_id)
            else {
                // We might have already removed the subscription earlier.
                continue;
            };

            self.zombie_subscriptions_queue
                .push_back(ZombieSubscription {
                    client_subscription_id,
                    method_name: active_subscription.method_name,
                    method_params_json: active_subscription.method_params_json,
                    unsubscribe_request_id: None,
                });
        }
    }

    /// Adds a request to the queue of requests waiting to be picked up by a server.
    pub fn insert_json_rpc_request(&mut self, request: String) -> InsertRequest {
        // Determine the request information, or answer the request directly if possible.
        match methods::parse_jsonrpc_client_to_server(&request) {
            Ok((request_id_json, method)) => {
                let (rewritten_request, assigned_server) = match method {
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

                    // Unsubscription functions or functions that target a specific subscription.
                    methods::MethodCall::chain_unsubscribeAllHeads { subscription }
                    | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription }
                    | methods::MethodCall::chain_unsubscribeNewHeads { subscription } => {
                        // TODO: check against zombie subscriptions
                        if let Some(&server_id) = self.active_subscriptions.get(&*subscription) {
                            // TODO: must rewrite request
                            Some(server_id)
                        } else {
                            // Subscription doesn't exist, or doesn't exist anymore.
                            // Immediately return a response to the client.
                            self.responses_queue.push_back(match method {
                                methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                                    methods::Response::chain_unsubscribeAllHeads(false)
                                        .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                                    methods::Response::chain_unsubscribeFinalizedHeads(false)
                                        .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                                    methods::Response::chain_unsubscribeNewHeads(false)
                                        .to_json_response(request_id_json)
                                }
                                _ => unreachable!(),
                            });
                            return InsertRequest::ImmediateAnswer;
                        }
                    }
                    methods::MethodCall::state_unsubscribeRuntimeVersion { subscription }
                    | methods::MethodCall::state_unsubscribeStorage { subscription }
                    | methods::MethodCall::transactionWatch_unstable_unwatch { subscription }
                    | methods::MethodCall::sudo_network_unstable_unwatch { subscription }
                    | methods::MethodCall::chainHead_unstable_body {
                        follow_subscription: subscription,
                        ..
                    }
                    | methods::MethodCall::chainHead_unstable_call {
                        follow_subscription: subscription,
                        ..
                    }
                    | methods::MethodCall::chainHead_unstable_header {
                        follow_subscription: subscription,
                        ..
                    }
                    | methods::MethodCall::chainHead_unstable_stopOperation {
                        follow_subscription: subscription,
                        ..
                    }
                    | methods::MethodCall::chainHead_unstable_storage {
                        follow_subscription: subscription,
                        ..
                    }
                    | methods::MethodCall::chainHead_unstable_continue {
                        follow_subscription: subscription,
                        ..
                    }
                    | methods::MethodCall::chainHead_unstable_unfollow {
                        follow_subscription: subscription,
                    }
                    | methods::MethodCall::chainHead_unstable_unpin {
                        follow_subscription: subscription,
                        ..
                    } => {
                        // TODO: check against zombie subscriptions
                        if let Some(&server_id) = self.active_subscriptions.get(&*subscription) {
                            // TODO: must rewrite request
                            Some(server_id)
                        } else {
                            // Subscription doesn't exist, or doesn't exist anymore.
                            // Immediately return a response to the client.
                            self.responses_queue.push_back(match method {
                                methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                                    methods::Response::state_unsubscribeRuntimeVersion(false)
                                        .to_json_response(request_id_json)
                                }
                                methods::MethodCall::state_unsubscribeStorage { .. } => {
                                    methods::Response::state_unsubscribeStorage(false)
                                        .to_json_response(request_id_json)
                                }
                                methods::MethodCall::transactionWatch_unstable_unwatch {
                                    ..
                                } => parse::build_error_response(
                                    request_id_json,
                                    parse::ErrorResponse::InvalidParams,
                                    None,
                                ),
                                methods::MethodCall::sudo_network_unstable_unwatch { .. } => {
                                    parse::build_error_response(
                                        request_id_json,
                                        parse::ErrorResponse::InvalidParams,
                                        None,
                                    )
                                }
                                methods::MethodCall::chainHead_unstable_body { .. } => {
                                    methods::Response::chainHead_unstable_body(
                                        methods::ChainHeadBodyCallReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chainHead_unstable_call { .. } => {
                                    methods::Response::chainHead_unstable_call(
                                        methods::ChainHeadBodyCallReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chainHead_unstable_header { .. } => {
                                    methods::Response::chainHead_unstable_header(None)
                                        .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chainHead_unstable_stopOperation {
                                    ..
                                } => methods::Response::chainHead_unstable_stopOperation(())
                                    .to_json_response(request_id_json),
                                methods::MethodCall::chainHead_unstable_storage { .. } => {
                                    methods::Response::chainHead_unstable_storage(
                                        methods::ChainHeadStorageReturn::LimitReached {},
                                    )
                                    .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chainHead_unstable_continue { .. } => {
                                    methods::Response::chainHead_unstable_continue(())
                                        .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chainHead_unstable_unfollow { .. } => {
                                    methods::Response::chainHead_unstable_unfollow(())
                                        .to_json_response(request_id_json)
                                }
                                methods::MethodCall::chainHead_unstable_unpin { .. } => {
                                    methods::Response::chainHead_unstable_unpin(())
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
                    | methods::MethodCall::system_removeReservedPeer { .. }
                    | methods::MethodCall::state_subscribeRuntimeVersion {}
                    | methods::MethodCall::state_subscribeStorage { .. }
                    | methods::MethodCall::chain_subscribeAllHeads {}
                    | methods::MethodCall::chain_subscribeFinalizedHeads {}
                    | methods::MethodCall::chain_subscribeNewHeads {}
                    | methods::MethodCall::author_submitAndWatchExtrinsic { .. }
                    | methods::MethodCall::chainHead_unstable_follow { .. }
                    | methods::MethodCall::transactionWatch_unstable_submitAndWatch { .. }
                    | methods::MethodCall::sudo_network_unstable_watch {}
                    | methods::MethodCall::chainSpec_v1_chainName {}
                    | methods::MethodCall::chainSpec_v1_genesisHash {}
                    | methods::MethodCall::chainSpec_v1_properties {}
                    | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. } => {
                        (request, None)
                    }
                };

                // Insert the request in the queue.
                self.queued_requests
                    .entry(assigned_server)
                    .or_insert(VecDeque::new())
                    .push_back(request);
                if let Some(assigned_server) = assigned_server {
                    InsertRequest::ServerWakeUp(assigned_server)
                } else {
                    InsertRequest::AnyServerWakeUp
                }
            }

            Err(methods::ParseClientToServerError::JsonRpcParse(_error)) => {
                // Failed to parse the JSON-RPC request.
                self.responses_queue
                    .push_back(parse::build_parse_error_response());
                InsertRequest::ImmediateAnswer
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
                InsertRequest::ImmediateAnswer
            }

            Err(methods::ParseClientToServerError::UnknownNotification(function)) => {
                // JSON-RPC function not recognized, and the call is a notification.
                // According to the JSON-RPC specification, the server must not send any response
                // to notifications, even in case of an error.
                InsertRequest::Discarded
            }
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
        if let Some(zombie_subscription) = self.zombie_subscriptions_queue.pop_front() {
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

            let _prev_value = self
                .zombie_subscriptions_resub_requests
                .insert(subscribe_request_id_json, zombie_subscription);
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
        response: String,
    ) -> InsertProxiedJsonRpcResponse {
        match parse::parse_response(&response) {
            Err(_) => {
                // If the message couldn't be parsed as a response, attempt to parse it as a
                // notification.
                match methods::parse_notification(&response) {
                    Ok(mut notification) => {
                        // This is a subscription notification.
                        // TODO: overhead of into_owned
                        let btree_map::Entry::Occupied(subscription_entry) = self
                            .active_subscriptions_by_server
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
                            let _was_in =
                                self.active_subscriptions.remove(subscription_entry.get());
                            debug_assert!(_was_in.is_some());
                            subscription_entry.remove();
                        }

                        // Success.
                        self.responses_queue.push_back(rewritten_notification);
                        InsertProxiedJsonRpcResponse::Queued
                    }

                    Err(notification_parse_error) => {
                        // Failed to parse the message from the JSON-RPC server.
                        self.blacklist_server(server_id);
                        InsertProxiedJsonRpcResponse::Blacklisted("")
                        // TODO: ^
                    }
                }
            }

            Ok(parse_result) => {
                // Grab the ID of the request that is being answered.
                let request_id_json = match parse_result {
                    parse::Response::Success {
                        id_json,
                        result_json,
                    } => id_json,
                    parse::Response::Error { id_json, .. } => id_json,
                    parse::Response::ParseError { .. } => {
                        // JSON-RPC server indicates that it has failed to parse a JSON-RPC
                        // request as a valid request. This is never supposed to happen and
                        // indicates that something is very wrong with the server.
                        // The server is blacklisted.
                        self.blacklist_server(server_id);
                        return InsertProxiedJsonRpcResponse::Blacklisted(""); // TODO:
                    }
                };

                // TODO: detect internal server errors and blacklist the server

                // Extract the answered request from the local state.
                let (method_name, method_params_json, unsubscribe_request_id) = match (
                    self.requests_in_progress
                        .remove(&(server_id, request_id_json.to_owned())), // TODO: to_owned overhead
                    self.zombie_subscriptions_resub_requests
                        .remove(request_id_json),
                ) {
                    (Some(rq), _zombie) => {
                        debug_assert!(_zombie.is_none());
                        (rq.method_name, rq.method_params_json, None)
                    }
                    (None, Some(zombie)) => (
                        zombie.method_name,
                        zombie.method_params_json,
                        zombie.unsubscribe_request_id,
                    ),
                    (None, None) => {
                        // Server has answered a non-existing request. Blacklist it.
                        self.blacklist_server(server_id);
                        return InsertProxiedJsonRpcResponse::Blacklisted("");
                        // TODO: ^
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
                    request_method,
                    answered_request.previous_failed_attempts >= 2,
                ) {
                    // Some functions return `null` if the server has reached its limit, in which
                    // case we silently discard the response and try a different server instead.
                    // TODO: not finished
                    (methods::MethodCall::chainHead_unstable_follow { .. }, false) => {}

                    _ => {}
                }

                match (request_method, parse_result) {
                    // If the function is a subscription, we update our local state.
                    (
                        methods::MethodCall::chainHead_unstable_follow { .. }
                        | methods::MethodCall::chain_subscribeAllHeads {}
                        | methods::MethodCall::chain_subscribeFinalizedHeads {}
                        | methods::MethodCall::chain_subscribeNewHeads {}
                        | methods::MethodCall::state_subscribeRuntimeVersion {}
                        | methods::MethodCall::state_subscribeStorage { .. }
                        | methods::MethodCall::transactionWatch_unstable_submitAndWatch { .. }
                        | methods::MethodCall::sudo_network_unstable_watch {},
                        parse::Response::Success { result_json, .. },
                    ) => {
                        let subscription_id = match methods::parse_jsonrpc_response(
                            request_method.name(),
                            result_json,
                        ) {
                            Ok(
                                methods::Response::chainHead_unstable_follow(subscription_id)
                                | methods::Response::chain_subscribeAllHeads(subscription_id)
                                | methods::Response::chain_subscribeFinalizedHeads(subscription_id)
                                | methods::Response::chain_subscribeNewHeads(subscription_id)
                                | methods::Response::state_subscribeRuntimeVersion(subscription_id)
                                | methods::Response::state_subscribeStorage(subscription_id)
                                | methods::Response::transactionWatch_unstable_submitAndWatch(
                                    subscription_id,
                                )
                                | methods::Response::sudo_network_unstable_watch(subscription_id),
                            ) => subscription_id,
                            Ok(_) => unreachable!(),
                            Err(_) => {
                                // TODO: ?!
                                todo!()
                            }
                        };

                        let rellocated_subscription_id = {
                            let mut subscription_id = [0u8; 32];
                            self.randomness.fill_bytes(&mut subscription_id);
                            bs58::encode(subscription_id).into_string()
                        };

                        match self
                            .active_subscriptions_by_server
                            .entry((server_id, subscription_id.into_owned()))
                        {
                            btree_map::Entry::Vacant(entry) => {
                                entry.insert(rellocated_subscription_id);
                            }
                            btree_map::Entry::Occupied(_) => {
                                // The server has assigned a subscription ID that it has
                                // already assigned in the past. This indicates something
                                // very wrong with the server.
                                // TODO: must reinsert the subscription request or something, or avoid removing it before reaching this point
                                self.blacklist_server(server_id);
                                return InsertProxiedJsonRpcResponse::Blacklisted("");
                                // TODO:
                            }
                        }

                        let _prev_value = self.active_subscriptions.insert(
                            rellocated_subscription_id.clone(),
                            (
                                server_id,
                                ActiveSubscription {
                                    method_name,
                                    method_params_json,
                                    server_subscription_id: subscription_id.clone().into_owned(),
                                },
                            ),
                        );
                        debug_assert!(_prev_value.is_none());
                    }

                    // If the function is an unsubscription, we update our local state.
                    // TODO: what to do if server errors when unsubscribing?
                    (
                        methods::MethodCall::chain_unsubscribeAllHeads { subscription }
                        | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription }
                        | methods::MethodCall::chain_unsubscribeNewHeads { subscription },
                        _,
                    ) => {
                        let (_, server_subscription_id) =
                            self.active_subscriptions.remove(&subscription);
                    }
                    (
                        methods::MethodCall::state_unsubscribeRuntimeVersion { subscription }
                        | methods::MethodCall::state_unsubscribeStorage { subscription }
                        | methods::MethodCall::transactionWatch_unstable_unwatch { subscription }
                        | methods::MethodCall::sudo_network_unstable_unwatch { subscription }
                        | methods::MethodCall::chainHead_unstable_body {
                            follow_subscription: subscription,
                            ..
                        }
                        | methods::MethodCall::chainHead_unstable_call {
                            follow_subscription: subscription,
                            ..
                        }
                        | methods::MethodCall::chainHead_unstable_header {
                            follow_subscription: subscription,
                            ..
                        }
                        | methods::MethodCall::chainHead_unstable_stopOperation {
                            follow_subscription: subscription,
                            ..
                        }
                        | methods::MethodCall::chainHead_unstable_storage {
                            follow_subscription: subscription,
                            ..
                        }
                        | methods::MethodCall::chainHead_unstable_continue {
                            follow_subscription: subscription,
                            ..
                        }
                        | methods::MethodCall::chainHead_unstable_unfollow {
                            follow_subscription: subscription,
                        }
                        | methods::MethodCall::chainHead_unstable_unpin {
                            follow_subscription: subscription,
                            ..
                        },
                        _,
                    ) => {}

                    _ => {}
                }

                // Success.
                self.responses_queue.push_back(response);
                InsertProxiedJsonRpcResponse::Queued
            }
        }
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

    /// The request has been immediately answered or discarded and doesn't need any
    /// further processing.
    /// [`ServersMultiplexer::next_json_rpc_response`] should be called in order to pull the response.
    ImmediateAnswer,

    /// The request can be processed by any server.
    /// [`ServersMultiplexer::next_proxied_json_rpc_request`] should be called with any [`ServerId`].
    AnyServerWakeUp,

    /// The request must be processed specifically by the indicated server.
    /// [`ServersMultiplexer::next_proxied_json_rpc_request`] should be called with the
    /// given [`ServerId`].
    ServerWakeUp(ServerId),
}

/// Outcome of a call to [`ServersMultiplexer::insert_proxied_json_rpc_response`].
// TODO: clean up, document, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertProxiedJsonRpcResponse {
    /// The response or notification has been queued and can now be retrieved
    /// using [`ServersMultiplexer::next_json_rpc_response`].
    Queued,
    /// The response or notification has been silently discarded.
    Discarded,
    Blacklisted(&'static str),
}
