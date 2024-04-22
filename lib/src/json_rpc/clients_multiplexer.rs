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
//! When a client sends a `chainHead_v1_follow` JSON-RPC request, the [`ClientsMultiplexer`]
//! will let it pass through, no matter how many other existing `chainHead_v1_follow`
//! subscriptions exist. However, because there exists a limit to the maximum number of
//! `chainHead_v1_follow` subscriptions, the server might return `null` to indicate that
//! this limit has been reached. When that happens, the [`ClientsMultiplexer`] will use the same
//! server-side `chainHead_v1_follow` subscription to feed to multiple clients.

use core::cmp;

use alloc::{
    borrow::Cow,
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

mod responses_queue;

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
// TODO: Debug impl
pub struct ClientsMultiplexer<T> {
    /// List of all clients, including clients that have been removed by the API user.
    clients: slab::Slab<Client<T>>,

    /// Subset of [`ClientsMultiplexer::clients`] that has at least one request in
    /// [`Client::requests_queue`].
    clients_with_requests: hashbrown::HashSet<ClientId, fnv::FnvBuildHasher>,

    /// List of subscriptions indexed by id.
    ///
    /// The same subscription ID can be used for multiple clients at the same time.
    subscriptions_by_server_id: BTreeMap<(Arc<str>, ClientId), Subscription>,

    /// List of subscriptions indexed by client.
    subscriptions_by_client: BTreeSet<(ClientId, Arc<str>)>,

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

    /// Queue of server-to-client responses and notifications.
    // TODO: occasionally shrink to fit?
    responses_queue: responses_queue::ResponsesQueue<ResponseEntry>,

    /// Limits enforced on the client.
    limits: ClientLimits,

    /// User data decided by the API user. If `None`, the client has been removed by the API user.
    user_data: Option<T>,
}

struct ResponseEntry {
    /// Stringified version of the response or notification.
    as_string: String,

    /// If this entry is a notification to a subscription, contains the identifier of this
    /// subscription.
    // TODO: is String maybe too expensive to clone?
    subscription_notification: Option<Arc<str>>,
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
    AllHeads {
        latest_update_queue_index: Option<responses_queue::EntryIndex>,
    },
    FinalizedHeads {
        latest_update_queue_index: Option<responses_queue::EntryIndex>,
    },
    NewHeads {
        latest_update_queue_index: Option<responses_queue::EntryIndex>,
    },
    RuntimeVersion {
        latest_update_queue_index: Option<responses_queue::EntryIndex>,
    },
    Storage {
        latest_update_queue_index: Option<responses_queue::EntryIndex>,
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
            subscriptions_by_server_id: BTreeMap::new(),
            subscriptions_by_client: BTreeSet::new(),
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
            responses_queue: responses_queue::ResponsesQueue::with_capacity(cmp::min(
                32,
                limits.max_unanswered_parallel_requests,
            )),
            limits,
            user_data: Some(user_data),
            ..todo!()
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

        // Extract the list of subscriptions from `subscriptions_by_client`.
        let subscriptions = {
            let mut client_and_after = self
                .subscriptions_by_client
                .split_off(&(client_id, Arc::from("")));
            self.subscriptions_by_client.append(
                &mut client_and_after.split_off(&(ClientId(client_id.0 + 1), Arc::from(""))),
            );
            client_and_after
        };

        // For each active subscription this client has, add to the queue of unprocessed
        // requests one dummy unsubscribe request.
        // TODO: do this ^
        for (_, subscription_id) in subscriptions {
            let Some(subscription) = self
                .subscriptions_by_server_id
                .remove(&(subscription_id.clone(), client_id))
            else {
                unreachable!()
            };

            // TODO: only unsubscribe if sub isn't used by anything else
            client.requests_queue.push_back(match () {
                _ => unreachable!(),
            });
        }

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
            client.responses_queue.push_back(ResponseEntry {
                as_string: parse::build_parse_error_response(),
                subscription_notification: None,
            });
            return Ok(PushClientToServer::ImmediateAnswer);
        };

        // Get the request ID.
        // The request might not have an ID if it is a notification. No notification is supported
        // in the JSON-RPC API. As mentioned in the JSON-RPC spec, nothing should ever be sent in
        // reply to notifications, not even errors. For this reason, we silently discard
        // notifications.
        let Some(request_id_json) = request.id_json else {
            return Ok(PushClientToServer::Discarded);
        };

        // Try parse the request name and parameters.
        let Ok(method) = methods::parse_jsonrpc_client_to_server_method_name_and_parameters(
            request.method,
            request.params_json,
        ) else {
            client.responses_queue.push_back(ResponseEntry {
                as_string: parse::build_error_response(
                    request_id_json,
                    parse::ErrorResponse::MethodNotFound,
                    None,
                ),
                subscription_notification: None,
            });
            return Ok(PushClientToServer::ImmediateAnswer);
        };

        // TODO: for subscriptions, re-use existing subscription if any
        // TODO: check limit to number of subscriptions

        // Adjust the request ID to put the numerical value of the `ClientId` in front.
        // This not only ensures that clients can't have overlapping request IDs, but will also
        // be used in order to determine to which client a response to a request belongs to.
        let new_request_id = serde_json::to_string(&format!("{}-{request_id_json}", client_id.0))
            .unwrap_or_else(|_| unreachable!());

        // Now insert the request in queue.
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

        // Success.
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
    /// Responses that fail to parse or do not match any known request ID, and notifications that
    /// do not match any known active subscription are ignored.
    pub fn push_server_to_client(&mut self, response: &str) {
        // TODO: take by String? ^
        match parse::parse_response(response) {
            Ok(response) => {
                // The response is a response to a request.

                // Request ID as sent by the server.
                let server_request_id = match response {
                    parse::Response::Success { id_json, .. } => id_json,
                    parse::Response::Error { id_json, .. } => id_json,
                    parse::Response::ParseError { .. } => return,
                };

                // Extract the client ID and request ID from the client's perspective.
                // Return and silently discard the response if there is a parsing error.
                let (client_id, client_request_id) = {
                    let Ok(as_string) = serde_json::from_str::<Cow<str>>(server_request_id) else {
                        return;
                    };
                    let Some((id, rq_id)) = as_string.split_once('-') else {
                        return;
                    };
                    let Ok(id) = id.parse::<usize>() else { return };
                    if !self.clients.contains(id) {
                        return;
                    }
                    if serde_json::from_str::<serde_json::Value>(&rq_id).is_err() {
                        return;
                    }
                    (ClientId(id), rq_id.to_owned())
                };

                // TODO: must do things in case of subscription or unsubscription

                // Insert the response in queue, adjusting the request ID.
                self.clients[client_id.0]
                    .responses_queue
                    .push_back(ResponseEntry {
                        subscription_notification: None,
                        as_string: match response {
                            parse::Response::Success { result_json, .. } => {
                                parse::build_success_response(&client_request_id, result_json)
                            }
                            parse::Response::Error {
                                error_code,
                                error_message,
                                error_data_json,
                                ..
                            } => parse::build_error_response(
                                &client_request_id,
                                todo!(),
                                error_data_json,
                            ),
                            parse::Response::ParseError { .. } => unreachable!(),
                        },
                    });
            }

            Err(_) => {
                // Try to parse the response as a subscription notification.
                let Ok(notification) = methods::parse_notification(response) else {
                    return;
                };

                let subscription_id: Arc<str> = Arc::from(&**notification.subscription());

                for (&(_, client_id), subscription) in self.subscriptions_by_server_id.range_mut(
                    (subscription_id.clone(), ClientId(usize::MIN))
                        ..=(subscription_id.clone(), ClientId(usize::MAX)),
                ) {
                    let mut client = &mut self.clients[client_id.0];

                    match (&mut subscription.ty, &notification) {
                        // For some subscriptions, we overwrite any existing notification in the
                        // queue.
                        (
                            SubscriptionTy::FinalizedHeads {
                                latest_update_queue_index: Some(latest_update_queue_index),
                            },
                            methods::ServerToClient::chain_finalizedHead { .. },
                        )
                        | (
                            SubscriptionTy::NewHeads {
                                latest_update_queue_index: Some(latest_update_queue_index),
                            },
                            methods::ServerToClient::chain_newHead { .. },
                        )
                        | (
                            SubscriptionTy::RuntimeVersion {
                                latest_update_queue_index: Some(latest_update_queue_index),
                            },
                            methods::ServerToClient::state_runtimeVersion { .. },
                        ) => {
                            // Update the existing entry in queue.
                            let entry = &mut client.responses_queue[*latest_update_queue_index];
                            debug_assert_eq!(
                                entry.subscription_notification,
                                Some(subscription_id.clone())
                            );
                            entry.as_string = response.to_owned();
                            return;
                        }

                        // For some subscriptions, we push a notification if the queue is small
                        // enough. If the queue reaches a certain size, we overwrite the
                        // latest entry.
                        // The logic of the notifications makes it fundamentally wrong to
                        // overwrite notifications, however this is considered a defect in the
                        // logic of legacy JSON-RPC functions.
                        (
                            SubscriptionTy::AllHeads {
                                latest_update_queue_index: Some(latest_update_queue_index),
                            },
                            methods::ServerToClient::chain_allHead { .. },
                        )
                        | (
                            SubscriptionTy::Storage {
                                latest_update_queue_index: Some(latest_update_queue_index),
                            },
                            methods::ServerToClient::state_storage { .. },
                        ) => {
                            // TODO: do properly; what's the criteria for adding and for overwriting?
                            // Update the existing entry in queue.
                            let entry = &mut client.responses_queue[*latest_update_queue_index];
                            debug_assert_eq!(
                                entry.subscription_notification,
                                Some(subscription_id.clone())
                            );
                            entry.as_string = response.to_owned();
                            return;
                        }

                        // If there isn't any notification in the queue, insert one.
                        (
                            SubscriptionTy::AllHeads {
                                latest_update_queue_index: ref mut latest_update_queue_index @ None,
                            },
                            methods::ServerToClient::chain_allHead { .. },
                        )
                        | (
                            SubscriptionTy::FinalizedHeads {
                                latest_update_queue_index: ref mut latest_update_queue_index @ None,
                            },
                            methods::ServerToClient::chain_finalizedHead { .. },
                        )
                        | (
                            SubscriptionTy::NewHeads {
                                latest_update_queue_index: ref mut latest_update_queue_index @ None,
                            },
                            methods::ServerToClient::chain_newHead { .. },
                        )
                        | (
                            SubscriptionTy::RuntimeVersion {
                                latest_update_queue_index: ref mut latest_update_queue_index @ None,
                            },
                            methods::ServerToClient::state_runtimeVersion { .. },
                        )
                        | (
                            SubscriptionTy::Storage {
                                latest_update_queue_index: ref mut latest_update_queue_index @ None,
                            },
                            methods::ServerToClient::state_storage { .. },
                        ) => {
                            *latest_update_queue_index =
                                Some(client.responses_queue.push_back(ResponseEntry {
                                    as_string: response.to_owned(),
                                    subscription_notification: Some(subscription_id.clone()),
                                }));
                        }

                        _ => {} // TODO: no
                    }
                }
            }
        }
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

        let Some((entry_index, entry)) = client.responses_queue.pop_front() else {
            return None;
        };

        // Update the local state regarding the position of subscriptions notifications within the
        // queue.
        if let Some(subscription_id) = entry.subscription_notification {
            let Some(subscription_info) = self
                .subscriptions_by_server_id
                .get_mut(&(subscription_id, client_id))
            else {
                unreachable!()
            };

            match &mut subscription_info.ty {
                SubscriptionTy::AllHeads {
                    latest_update_queue_index,
                }
                | SubscriptionTy::NewHeads {
                    latest_update_queue_index,
                }
                | SubscriptionTy::FinalizedHeads {
                    latest_update_queue_index,
                }
                | SubscriptionTy::RuntimeVersion {
                    latest_update_queue_index,
                }
                | SubscriptionTy::Storage {
                    latest_update_queue_index,
                } => {
                    if *latest_update_queue_index == Some(entry_index) {
                        *latest_update_queue_index = None;
                    }
                }
            }
        }

        // Success.
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

    /// The request has been immediately answered and doesn't need any further processing.
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
