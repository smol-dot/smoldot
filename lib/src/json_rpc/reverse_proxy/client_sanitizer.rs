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

use crate::json_rpc::{methods, Response, ServerToClient};

use alloc::{collections::VecDeque, string::String, vec, vec::Vec};
use core::{cmp, num::NonZeroUsize};

/// Queue of requests coming from a JSON-RPC client, and queue of responses and notifications
/// destined to that JSON-RPC client.
///
/// These two queues are merged into a single data structure due to some tricky corner cases,
/// such as the queue of responses being full must lead to a dummy unsubscription request.
// TODO: Debug implementation
pub struct JsonRpcClientSanitizer<TRp> {
    /// `true` if [`JsonRpcClientSanitizer::close`] has been called.
    is_closed: bool,

    /// Queue of client-to-server JSON-RPC requests.
    requests_queue: VecDeque<String>,

    /// For each request ID (encoded as JSON), the in-progress requests with that ID.
    ///
    /// The vast majority of the time there will only be one entry, but there's in principle
    /// nothing illegal in having multiple requests with the same ID.
    requests_in_progress:
        hashbrown::HashMap<String, smallvec::SmallVec<InProgressRequest>, fnv::FnvBuildHasher>,

    active_subscriptions: hashbrown::HashMap<String, Subscription, fnv::FnvBuildHasher>,

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
}

struct ResponseEntry<TRp> {
    /// Stringified version of the response or notification.
    as_string: String,

    /// Entry within [`JsonRpcClientSanitizer::responses_container`] of the next item of
    /// the queue.
    next_item_index: Option<usize>,

    /// If this entry is a notification to a subscription, contains the identifier of this
    /// subscription.
    // TODO: is String maybe too expensive to clone?
    subscription_notification: Option<String>,

    /// User data associated with that entry.
    user_data: TRp,
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

impl<TRp> JsonRpcClientSanitizer<TRp> {
    /// Creates a new queue with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        JsonRpcClientSanitizer {
            is_closed: false,
            requests_queue: VecDeque::with_capacity(16), // TODO: capacity
            requests_in_progress: hashbrown::HashMap::with_capacity_and_hasher(16, todo!()), // TODO:
            active_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(16, todo!()), // TODO:
            responses_container: Vec::with_capacity(capacity),
            responses_first_item: 0,
            responses_last_item: 0,
        }
    }

    /// Closes the queues, notifying that [`JsonRpcClientSanitizer::push_client_to_server`] will
    /// no longer be called.
    ///
    /// After this function is called, calling [`JsonRpcClientSanitizer::pop_client_to_server`]
    /// will return one unsubscription request per active subscription, and calling
    /// [`JsonRpcClientSanitizer::pop_server_to_client`] will always return `None`.
    pub fn close(&mut self) {
        self.is_closed = true;

        /// Clear all existing requests.
        self.requests_queue.clear();

        /// Clear all existing responses.
        self.responses_container.clear();
        self.responses_first_item = 0;
        self.responses_last_item = 0;
    }

    /// Adds a new request to the back of the client-to-server queue.
    ///
    /// # Panic
    ///
    /// Panics if [`JsonRpcClientSanitizer::close`] has been called in the past.
    ///
    pub fn push_client_to_server(&mut self, request: String) {
        assert!(!self.is_closed);
        self.requests_queue.push_back(request);
    }

    /// Pops the oldest request from the client-to-server queue.
    pub fn pop_client_to_server(&mut self) -> Option<String> {
        loop {
            let Some(request_json) = self.requests_queue.pop_front() else {
                return None;
            };

            match methods::parse_jsonrpc_client_to_server(&request_json) {
                Ok((request_id_json, method)) => {
                    // Update `requests_in_progress`.
                    // TODO: immediately detect unsubscribing from invalid subscription
                    self.requests_in_progress
                        .entry(request_id_json.to_owned())
                        .or_insert_with(|| smallvec::SmallVec::new())
                        .push(InProgressRequest {
                            unsubscribe: match method {
                                methods::MethodCall::chainHead_unstable_unfollow(subscription) => {
                                    Some(subscription.to_owned())
                                }
                                methods::MethodCall::transactionWatch_unstable_unwatch(
                                    subscription,
                                ) => Some(subscription.to_owned()),
                                methods::MethodCall::sudo_network_unstable_unwatch(
                                    subscription,
                                ) => Some(subscription.to_owned()),
                                methods::MethodCall::author_unwatchExtrinsic(subscription) => {
                                    Some(subscription.to_owned())
                                }
                                methods::MethodCall::chain_unsubscribeAllHeads(subscription) => {
                                    Some(subscription.to_owned())
                                }
                                methods::MethodCall::chain_unsubscribeFinalizedHeads(
                                    subscription,
                                ) => Some(subscription.to_owned()),
                                methods::MethodCall::chain_unsubscribeNewHeads(subscription) => {
                                    Some(subscription.to_owned())
                                }
                                methods::MethodCall::state_unsubscribeRuntimeVersion(
                                    subscription,
                                ) => Some(subscription.to_owned()),
                                methods::MethodCall::state_unsubscribeStorage(subscription) => {
                                    Some(subscription.to_owned())
                                }
                                _ => None,
                            },
                        });

                    return Some(request_json);
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

                Err(methods::ParseClientToServerError::UnknownNotification(_)) => {
                    // JSON-RPC function not recognized, and the call is a notification.
                    // According to the JSON-RPC specification, the server must not send any
                    // response to notifications, even in case of an error.
                }
            }
        }
    }

    /// Adds a JSON-RPC notification to the back of the server-to-client queue.
    ///
    /// Notifications that do not match any known active subscription are ignored.
    pub fn push_server_to_client_notification(
        &mut self,
        notification: ServerToClient,
        user_data: TRp,
    ) {
        // Find the subscription this notification corresponds to.
        let Some(subscription) = self.active_subscriptions.get_mut(match notification {
            ServerToClient::author_extrinsicUpdate(subscription, _) => subscription,
            ServerToClient::chain_finalizedHead(subscription, _) => subscription,
            ServerToClient::chain_newHead(subscription, _) => subscription,
            ServerToClient::chain_allHead(subscription, _) => subscription,
            ServerToClient::state_runtimeVersion(subscription, _) => subscription,
            ServerToClient::state_storage(subscription, _) => subscription,
            ServerToClient::chainHead_unstable_followEvent(subscription, _) => subscription,
            ServerToClient::transactionWatch_unstable_watchEvent(subscription, _) => subscription,
            ServerToClient::sudo_networkState_event(subscription, _) => subscription,
        }) else {
            // Silently ignore notification that doesn't match any active subscription.
            return;
        };

        match (notification, &mut subscription.ty) {
            (ServerToClient::author_extrinsicUpdate(_, event), _) => {}
            (ServerToClient::chain_finalizedHead(_, event), _) => {}
            (ServerToClient::chain_newHead(_, event), _) => {}
            (ServerToClient::chain_allHead(_, event), _) => {}
            (
                ServerToClient::state_runtimeVersion(_, event),
                SubscriptionTy::RuntimeVersion {
                    latest_update_queue_index: Some(latest_update_queue_index),
                },
            ) => {
                // Update the existing entry in queue.
                self.responses_container[latest_update_queue_index] = Some(notification);
                return;
            }
            (
                ServerToClient::state_runtimeVersion(_, event),
                SubscriptionTy::RuntimeVersion {
                    latest_update_queue_index: latest_update_queue_index @ None,
                },
            ) => {}
            (ServerToClient::state_storage(_, event), _) => {}
            (ServerToClient::chainHead_unstable_followEvent(_, event), _) => {}
            (ServerToClient::transactionWatch_unstable_watchEvent(_, event), _) => {}
            (ServerToClient::sudo_networkState_event(_, event), _) => {}
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
    pub fn push_server_to_client_response(
        &mut self,
        response: Response,
        request_id_json: &str,
        user_data: TRp,
    ) {
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

    /// Pops the oldest entry in the queue of server-to-client queue.
    ///
    /// Returns `None` if the queue is empty or if [`JsonRpcClientSanitizer::close`] has been
    /// called in the past.
    ///
    /// The notification or response is serialized into a string.
    pub fn pop_server_to_client(&mut self) -> Option<(String, TRp)> {
        if self.responses_first_item == self.responses_last_item {
            return None;
        }

        let Some(entry) = self.responses_container[responses_first_item].take() else {
            unreachable!()
        };

        debug_assert!(!self.is_closed);

        self.responses_first_item =
            (self.responses_first_item + 1) % self.responses_container.len();

        // TODO: update subscriptions

        Some((entry.as_string, entry.user_data))
    }
}
