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

//! Accepts multiple clients and merges their requests into a single stream of requests, then
//! distributes back the responses to the relevant clients.
//!
//! Because multiple different clients might accidentally use the same IDs for their requests,
//! the [`ClientsMultiplexer`] modifies the ID of every request. This is also necessary in order
//! to match a server's response with its corresponding client.
//!
//! When a client is removed, dummy JSON-RPC requests are added to the stream of requests that
//! unsubscribe from the subscriptions that this client was maintaining.
//!
//! The [`ClientsMultiplexer`] might silently discard or merge notifications inserted through
//! [`ClientsMultiplexer::push_server_to_client`] in order to guarantee a bound to the maximum
//! number to the memory usage in situations where a client doesn't pull responses quickly enough.
//!
//! When a client sends a `chain_subscribeAllHeads`, `chain_subscribeFinalizedHeads`,
//! `chain_subscribeNewHeads`, or `state_subscribeRuntimeVersion` request, the
//! [`ClientsMultiplexer`] tries to re-use an existing server subscription. Notifications
//! concerning these subscriptions are multiplexed.
//!
//! When a client sends a `chainHead_unstable_follow` JSON-RPC request, the [`ClientsMultiplexer`]
//! will let it pass through, no matter how many other existing `chainHead_unstable_follow`
//! subscriptions exist. However, because there exists a limit to the maximum number of
//! `chainHead_unstable_follow` subscriptions, the server might return `null` to indicate that
//! this limit has been reached. When that happens, the [`ClientsMultiplexer`] will use the same
//! server-side `chainHead_unstable_follow` subscription to feed to multiple clients.

use core::cmp;

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};
use rand::seq::IteratorRandom as _;
use rand_chacha::{
    rand_core::{RngCore as _, SeedableRng as _},
    ChaCha20Rng,
};

use crate::{
    json_rpc::{methods, parse},
    util::SipHasherBuild,
};

/// Identifier of a client within the [`ClientsMultiplexer`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(usize);

/// Limits enforced to clients.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ClientLimits {
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
}

/// See [the module-level documentation](..).
pub struct ClientsMultiplexer<T> {
    /// List of all clients, including clients that have been removed by the API user.
    clients: slab::Slab<Client<T>>,

    /// Subset of [`ClientsMultiplexer::clients`] that has at least one request in
    /// [`Client::requests_queue`].
    clients_with_requests: hashbrown::HashSet<ClientId, fnv::FnvBuildHasher>,

    /// List of subscriptions indexed by id.
    ///
    /// The same subscription ID can be used for multiple clients at the same time.
    subscriptions_by_server_id: BTreeSet<(Arc<str>, ClientId)>,

    /// Source of randomness used for various purposes.
    randomness: ChaCha20Rng,
}

struct Client<T> {
    /// Queue of client-to-server JSON-RPC requests.
    requests_queue: VecDeque<String>,

    /// For each request ID (encoded as JSON), the in-progress requests with that ID.
    ///
    /// The vast majority of the time there will only be one entry, but there's in principle
    /// nothing illegal in having multiple requests with the same ID.
    requests_in_progress:
        hashbrown::HashMap<String, smallvec::SmallVec<[InProgressRequest; 1]>, SipHasherBuild>,

    /// All the entries of the queue. `None` if the slot is not allocated for an entry.
    ///
    /// The [`JsonRpcClientSanitizer`] is basically a double-ended queue: items are pushed to the
    /// end and popped from the front. Unfortunately, because we need to store indices of specific
    /// entries, we can't use a `VecDeque` and instead have to re-implement a double-ended queue
    /// manually.
    responses_container: Vec<Option<ResponseEntry>>,

    /// Index within [`JsonRpcClientSanitizer::responses_container`] where the first entry is
    /// located.
    responses_first_item: usize,

    /// Index within [`JsonRpcClientSanitizer::responses_container`] where the last entry is
    /// located. If it is equal to [`JsonRpcClientSanitizer::responses_first_item`], then the
    /// queue is empty.
    responses_last_item: usize,

    /// Limits enforced on the client.
    limits: ClientLimits,

    /// User data decided by the API user. If `None`, the client has been removed by the API user.
    user_data: Option<T>,
}

struct ResponseEntry {
    /// Stringified version of the response or notification.
    as_string: String,

    /// Entry within [`JsonRpcClientSanitizer::responses_container`] of the next item of
    /// the queue.
    next_item_index: Option<usize>,

    /// If this entry is a notification to a subscription, contains the identifier of this
    /// subscription.
    // TODO: is String maybe too expensive to clone?
    subscription_notification: Option<String>,
}

struct InProgressRequest {
    /// Subscription ID this request wants to unsubscribe from.
    unsubscribe: Option<String>,
}

// TODO: remove?
struct Subscription {
    ty: SubscriptionTy,
}

enum SubscriptionTy {
    RuntimeVersion {
        latest_update_queue_index: Option<usize>,
    },
}

impl<T> ClientsMultiplexer<T> {
    /// Initializes a new [`ClientsMultiplexer`].
    pub fn new() -> Self {
        let mut randomness = ChaCha20Rng::from_seed(todo!());
        ClientsMultiplexer {
            clients: slab::Slab::with_capacity(todo!()),
            clients_with_requests: hashbrown::HashSet::with_capacity_and_hasher(
                todo!(),
                Default::default(),
            ),
            subscriptions_by_server_id: BTreeSet::new(),
            randomness,
        }
    }

    /// Adds a new client to the collection.
    pub fn add_client(&mut self, mut limits: ClientLimits, user_data: T) -> ClientId {
        Self::sanitize_limits(&mut limits);

        ClientId(self.clients.insert(Client {
            requests_queue: VecDeque::with_capacity(cmp::min(
                32,
                limits.max_unanswered_parallel_requests,
            )),
            requests_in_progress: (),
            active_subscriptions: (),
            responses_container: {
                let mut container = Vec::with_capacity(limits.max_unanswered_parallel_requests);
                for _ in 0..limits.max_unanswered_parallel_requests {
                    container.push(None);
                }
                container
            },
            responses_first_item: 0,
            responses_last_item: 0,
            limits,
            user_data: Some(user_data),
        }))
    }

    /// Removes a client from the collection.
    ///
    /// Since the client might have requests in progress and active subscriptions, the removed
    /// client might still occupy a non-zero amount of memory after being destroyed, until
    /// enough requests and responses have been exchanged with the server.
    ///
    /// # Panics
    ///
    /// Panics if the [`ClientId`] is invalid.
    ///
    pub fn remove_client(&mut self, client_id: ClientId) -> T {
        let Some(client) = self.clients.get_mut(client_id.0) else {
            // Client was already destroyed.
            panic!()
        };

        // Extract user data ahead of time, in order to avoid going further if the client was
        // already destroyed.
        let Some(user_data) = client.user_data.take() else {
            // Client was already destroyed.
            panic!()
        };

        // Clear the queue of unprocessed requests, as we don't need them anymore.
        client.requests_queue.clear();

        // For each active subscription this client has, add to the queue of unprocessed
        // requests one dummy unsubscribe request.
        // TODO: do this ^

        user_data
    }

    /// Modifies the limits set for the given client.
    ///
    /// # Panic
    ///
    /// Panics if the [`ClientId`] is invalid.
    ///
    pub fn set_client_limits(&mut self, client: ClientId, mut limits: ClientLimits) {
        let Some(client) = self.clients.get_mut(client.0) else {
            panic!()
        };

        Self::sanitize_limits(&mut limits);
        client.limits = limits;
    }

    /// Equivalent to calling [`ClientsMultiplexer::set_client_limits`] for every client that
    /// exists.
    pub fn set_clients_limits(&mut self, mut limits: ClientLimits) {
        Self::sanitize_limits(&mut limits);
        for (_, client) in &mut self.clients {
            client.limits = limits;
        }
    }

    fn sanitize_limits(limits: &mut ClientLimits) {
        limits.max_chainhead_follow_subscriptions =
            cmp::max(limits.max_chainhead_follow_subscriptions, 2);
    }

    /// Returns the number of alive clients plus the number of clients that have been removed
    /// but that are still occuping memory.
    ///
    /// When enforcing a limit to the number of clients in the multiplexer, this is the number
    /// that should be compared against a certain limit.
    pub fn num_clients_footprints(&self) -> usize {
        self.clients.len()
    }

    /// Adds a new request to the back of the client-to-server queue.
    ///
    /// # Panic
    ///
    /// Panics if the [`ClientId`] is invalid.
    ///
    pub fn push_client_to_server(
        &mut self,
        client_id: ClientId,
        request: &str,
    ) -> Result<PushClientToServer, PushClientToServerError> {
        // Check whether the client exists.
        let Some(client) = self.clients.get_mut(client_id.0) else {
            // Client doesn't exist.
            panic!()
        };

        // Return an error if the client has already queued too many requests.
        // Note the usage of `>=`, as it can happen that the limit has been modified to be
        // lower than it was.
        if client
            .requests_queue
            .len()
            .checked_add(client.requests_in_progress.len())
            .map_or(true, |total| {
                total >= client.limits.max_unanswered_parallel_requests
            })
        {
            return Err(PushClientToServerError::TooManySimultaneousRequests);
        }

        // Try to parse the request.
        let Ok(request) = parse::parse_request(&request) else {
            todo!()
        };

        // Get the request ID.
        // The request might not have an ID if it is a notification. No notification is supported
        // in the JSON-RPC API. As mentioned in the JSON-RPC spec, nothing should ever be sent in
        // reply to notifications, not even errors. For this reason, we silently discard
        // notifications.
        let Some(request_id_json) = request.id_json else {
            return Ok(PushClientToServer::Discarded);
        };

        // Adjust the request ID to put the numerical value of the `ClientId` in front.
        // This not only ensures that clients can't have overlapping request IDs, but will also
        // be used in order to determine to which client a response to a request belongs to.
        let new_request_id = serde_json::to_string(&format!("{}-{request_id_json}", client_id.0))
            .unwrap_or_else(|_| unreachable!());

        // TODO: check limit to number of subscriptions

        debug_assert_ne!(
            self.clients_with_requests.contains(&client_id),
            client.requests_queue.is_empty()
        );

        if client.requests_queue.is_empty() {
            let _was_inserted = self.clients_with_requests.insert(client_id);
        }

        client
            .requests_queue
            .push_back(parse::build_request(&parse::Request {
                id_json: Some(&new_request_id),
                method: request.method,
                params_json: request.params_json,
            }));

        Ok(PushClientToServer::Queued)
    }

    /// Pops a request from the client-to-server queue of one of the clients.
    pub fn pop_client_to_server(&mut self) -> Option<String> {
        // In order to guarantee fairness, we first choose which client to grab the request from,
        // then only grab a request from its queue.
        let Some(&client_id) = self
            .clients_with_requests
            .iter()
            .choose(&mut self.randomness)
        else {
            debug_assert!(self.clients_with_requests.is_empty());
            return None;
        };

        let Some(client) = self.clients.get_mut(client_id.0) else {
            unreachable!()
        };

        let Some(request) = client.requests_queue.pop_front() else {
            unreachable!()
        };

        if client.requests_queue.is_empty() {
            let _was_removed = self.clients_with_requests.remove(&client_id);
            debug_assert!(_was_removed);
        }

        // TODO: client.requests_in_progress.insert();

        Some(request)
    }

    /// Adds a JSON-RPC response or notification coming from the server.
    ///
    /// Notifications that do not match any known active subscription are ignored.
    pub fn push_server_to_client(&mut self, response: &str) {}

    /// Adds a JSON-RPC notification to the back of the server-to-client queue.
    ///
    /// Notifications that do not match any known active subscription are ignored.
    pub fn push_server_to_client_notification(&mut self, notification: methods::ServerToClient) {
        // Find the subscription this notification corresponds to.
        let Some(subscription) = self.active_subscriptions.get_mut(match notification {
            methods::ServerToClient::author_extrinsicUpdate(subscription, _) => subscription,
            methods::ServerToClient::chain_finalizedHead(subscription, _) => subscription,
            methods::ServerToClient::chain_newHead(subscription, _) => subscription,
            methods::ServerToClient::chain_allHead(subscription, _) => subscription,
            methods::ServerToClient::state_runtimeVersion(subscription, _) => subscription,
            methods::ServerToClient::state_storage(subscription, _) => subscription,
            methods::ServerToClient::chainHead_unstable_followEvent(subscription, _) => {
                subscription
            }
            methods::ServerToClient::transactionWatch_unstable_watchEvent(subscription, _) => {
                subscription
            }
            methods::ServerToClient::sudo_networkState_event(subscription, _) => subscription,
        }) else {
            // Silently ignore notification that doesn't match any active subscription.
            return;
        };

        match (notification, &mut subscription.ty) {
            (methods::ServerToClient::author_extrinsicUpdate(_, event), _) => {}
            (methods::ServerToClient::chain_finalizedHead(_, event), _) => {}
            (methods::ServerToClient::chain_newHead(_, event), _) => {}
            (methods::ServerToClient::chain_allHead(_, event), _) => {}
            (
                methods::ServerToClient::state_runtimeVersion(_, event),
                SubscriptionTy::RuntimeVersion {
                    latest_update_queue_index: Some(latest_update_queue_index),
                },
            ) => {
                // Update the existing entry in queue.
                self.responses_container[latest_update_queue_index] = Some(notification);
                return;
            }
            (
                methods::ServerToClient::state_runtimeVersion(_, event),
                SubscriptionTy::RuntimeVersion {
                    latest_update_queue_index: latest_update_queue_index @ None,
                },
            ) => {}
            (methods::ServerToClient::state_storage(_, event), _) => {}
            (methods::ServerToClient::chainHead_unstable_followEvent(_, event), _) => {}
            (methods::ServerToClient::transactionWatch_unstable_watchEvent(_, event), _) => {}
            (methods::ServerToClient::sudo_networkState_event(_, event), _) => {}
            _ => {
                // Subscription type doesn't match notification. Silently ignore notification.
                return;
            }
        }
    }

    /// Adds a JSON-RPC response to the back of the server-to-client queue.
    ///
    /// The response is silently ignored if it can't be parsed or doesn't correspond to any
    /// request.
    pub fn push_server_to_client_response(&mut self, response: Response, request_id_json: &str) {
        // Remove the entry from `requests_in_progress`.
        let in_progress_request: InProgressRequest =
            match self.requests_in_progress.entry_ref(request_id_json) {
                hashbrown::hash_map::EntryRef::Occupied(entry) => {
                    let Some(in_progress_request) = entry.get_mut().pop() else {
                        unreachable!()
                    };
                    if entry.get().is_empty() {
                        entry.remove();
                    }
                    in_progress_request
                }
                hashbrown::hash_map::EntryRef::Vacant(_) => {
                    // Silently ignore the response.
                    return;
                }
            };

        match (response, in_progress_request.unsubscribe) {
            (Response::state_subscribeRuntimeVersion(subscription_id), None) => {
                let _ = self.active_subscriptions.insert(
                    subscription_id,
                    Subscription {
                        ty: SubscriptionTy::RuntimeVersion {
                            latest_update_queue_index: None,
                        },
                    },
                );
            }
            (Response::state_unsubscribeRuntimeVersion(true), Some(suscription_id)) => {
                self.active_subscriptions.remove(&subscription_id);
            }
            // TODO: others
            _ => {}
        };

        let response_string = response.to_json_response(request_id_json);
    }

    /// Pops an entry in the queue of server-to-client responses or notifications of the given
    /// client.
    ///
    /// Returns `None` if the queue is empty.
    ///
    /// # Panic
    ///
    /// Panics if the [`ClientId`] is invalid.
    ///
    pub fn pop_server_to_client(&mut self, client_id: ClientId) -> Option<String> {
        let Some(client) = self
            .clients
            .get_mut(client_id.0)
            .filter(|c| c.user_data.is_some())
        else {
            // Invalid `ClientId`.
            panic!()
        };

        if client.responses_first_item == client.responses_last_item {
            return None;
        }

        let Some(entry) = client.responses_container[client.responses_first_item].take() else {
            unreachable!()
        };

        client.responses_first_item =
            (client.responses_first_item + 1) % client.responses_container.len();

        // TODO: update subscriptions

        Some(entry.as_string)
    }
}

/// Outcome of a call to [`ClientsMultiplexer::push_client_to_server`].
#[derive(Debug)]
pub enum PushClientToServer {
    /// The request has been silently discarded.
    ///
    /// This happens for example if the JSON-RPC client sends a notification.
    Discarded,

    /// The request has been immediately answered or discarded and doesn't need any
    /// further processing.
    /// [`ClientsMultiplexer::pop_server_to_client`] should be called in order to pull the
    /// response and send it to the client.
    ImmediateAnswer,

    /// The request can be processed by the server.
    /// [`ClientsMultiplexer::pop_client_to_server`] will return `Some`.
    Queued,
}

/// Error potentially returned by a call to [`ClientsMultiplexer::push_client_to_server`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum PushClientToServerError {
    /// The number of requests that this client has queued is already equal to
    /// [`ClientLimits::max_unanswered_parallel_requests`].
    #[display(fmt = "Too many simultaneous requests")]
    TooManySimultaneousRequests,
}
