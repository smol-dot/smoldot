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

// TODO: doc

use crate::json_rpc::{methods, parse};
use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::VecDeque,
    string::{String, ToString as _},
    sync::Arc,
};
use async_lock::Mutex;
use core::{
    cmp, fmt, mem,
    num::{NonZeroU32, NonZeroUsize},
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
    task::Poll,
};
use futures_channel::mpsc;
use futures_util::{future, StreamExt as _};
use slab::Slab;

pub use crate::json_rpc::parse::{ErrorResponse, ParseError};

// TODO: this module contains unsafe code, consider extracting it to a separate module for easier reviewing

/// See [module-level-documentation](..).
pub struct ClientMainTask {
    /// Because we move the task around a lot, all the fields are actually within a `Box`.
    inner: Box<Inner>,
}

struct Inner {
    /// Unordered list of responses and notifications to send back to the client.
    ///
    /// Each entry contains the response/notification, and a boolean equal to `true` if this is
    /// a request response or `false` if this is a notification.
    pending_serialized_responses: Slab<(String, bool)>,
    /// Ordered list of responses and notifications to send back to the client, as indices within
    /// [`Inner::pending_serialized_responses`].
    pending_serialized_responses_queue: VecDeque<usize>,

    /// Identifier to allocate to the new subscription requested by the user.
    // TODO: better strategy than just integers?
    next_subscription_id: u64,

    /// Number of requests that have have been received from the client but whose answer hasn't
    /// been sent back to the client yet. Includes requests whose response is in
    /// [`Inner::pending_serialized_responses`].
    num_requests_in_fly: u32,
    /// Maximum value that [`Inner::num_requests_in_fly`] is allowed to reach. Beyond this, the
    /// [`Inner::serialized_rq_receiver`] is back-pressured in order to not receive any more
    /// request.
    max_requests_in_fly: NonZeroU32,

    /// List of all active subscriptions. Keys are subscription IDs.
    ///
    /// Given that the subscription IDs are allocated locally, there is no harm in using a
    /// non-HashDoS-resilient hash function.
    // TODO: shrink to fit from time to time?
    active_subscriptions:
        hashbrown::HashMap<String, Arc<SubscriptionKillChannel>, fnv::FnvBuildHasher>,
    /// Maximum value that [`Inner::num_active_subscriptions`] is allowed to reach. Beyond this,
    /// subscription start requests are automatically denied.
    max_active_subscriptions: u32,

    /// Channel connected to the [`SerializedRequestsIo`]. The requests received are guaranteed to
    /// be a valid request JSON, but not necessarily to use a known method.
    serialized_rq_receiver: async_channel::Receiver<String>,
    /// Channel connected to the [`SerializedRequestsIo`].
    serialized_rp_sender: mpsc::Sender<String>,

    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,
}

/// Queue where responses and subscriptions push responses/notifications.
struct ResponsesNotificationsQueue {
    /// The actual queue.
    queue: crossbeam_queue::SegQueue<ToMainTask>,
    /// Maximum size that [`ResponsesNotificationsQueue::queue`] should reach.
    /// This is however not a hard limit. Pushing a response to a request ignores this maximum
    /// (as doing so must always be lock-free), and pushing a notification checks against this
    /// limit in a racy way. For this reason, in the worst case scenario the queue can reach up to
    /// `max_requests_in_fly + max_active_subscriptions` elements. What matters, however, is that
    /// the queue is bounded in a way or the other more than the exact bound.
    max_len: usize,
    /// Event notified after an element from [`ResponsesNotificationsQueue::queue`] has been pushed.
    on_pushed: event_listener::Event,
    /// Event notified after an element from [`ResponsesNotificationsQueue::queue`] has been popped.
    on_popped: event_listener::Event,
}

// TODO: weird enum
enum ToMainTask {
    RequestResponse(String),
    Notification(String),
}

/// Configuration for [`client_main_task`].
pub struct Config {
    /// Maximum number of requests that have been sent by the [`SerializedRequestsIo`] but whose
    /// response hasn't been pulled through the [`SerializedRequestsIo`] yet.
    ///
    /// If this limit is reached, it is not possible to send further requests without pulling
    /// responses first.
    pub max_pending_requests: NonZeroU32,

    /// Maximum number of simultaneous subscriptions allowed. Trying to create a subscription will
    /// be automatically rejected if this limit is reached.
    pub max_active_subscriptions: u32,

    /// Number of elements in the channels between the [`ClientMainTask`] and
    /// [`SerializedRequestIo`]. If the value is too high, more memory will be used than necessary.
    /// If the value is too low, there might be more task switches than necessary.
    ///
    /// A typical reasonable value is 4.
    pub serialized_requests_io_channel_size_hint: NonZeroUsize,
}

/// Creates a new [`ClientMainTask`] and a [`SerializedRequestsIo`] connected to it.
pub fn client_main_task(config: Config) -> (ClientMainTask, SerializedRequestsIo) {
    let (serialized_rq_sender, serialized_rq_receiver) =
        async_channel::bounded(config.serialized_requests_io_channel_size_hint.get());
    let (serialized_rp_sender, serialized_rp_receiver) =
        mpsc::channel(config.serialized_requests_io_channel_size_hint.get());

    let buffers_capacity = usize::try_from(config.max_pending_requests.get())
        .unwrap_or(usize::max_value())
        .saturating_add(
            usize::try_from(config.max_active_subscriptions).unwrap_or(usize::max_value()),
        );

    let task = ClientMainTask {
        inner: Box::new(Inner {
            pending_serialized_responses_queue: VecDeque::with_capacity(cmp::min(
                64,
                buffers_capacity,
            )),
            pending_serialized_responses: Slab::with_capacity(cmp::min(64, buffers_capacity)),
            next_subscription_id: 1,
            num_requests_in_fly: 0,
            max_requests_in_fly: config.max_pending_requests,
            active_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                cmp::min(
                    usize::try_from(config.max_active_subscriptions).unwrap_or(usize::max_value()),
                    32,
                ),
                Default::default(),
            ),
            max_active_subscriptions: config.max_active_subscriptions,
            serialized_rq_receiver,
            serialized_rp_sender,
            responses_notifications_queue: Arc::new(ResponsesNotificationsQueue {
                queue: crossbeam_queue::SegQueue::new(),
                max_len: buffers_capacity,
                on_pushed: event_listener::Event::new(),
                on_popped: event_listener::Event::new(),
            }),
        }),
    };

    let serialized_requests_io = SerializedRequestsIo {
        requests_sender: serialized_rq_sender,
        responses_receiver: Mutex::new(serialized_rp_receiver),
    };

    (task, serialized_requests_io)
}

impl ClientMainTask {
    /// Processes the task's internals and waits until something noteworthy happens.
    pub async fn run_until_event(mut self) -> Event {
        loop {
            enum WhatHappened {
                CanSendToSocket,
                NewRequest(String),
                Message(ToMainTask),
            }

            let what_happened = {
                let when_ready_to_send = future::poll_fn(|cx| {
                    if !self.inner.pending_serialized_responses_queue.is_empty() {
                        self.inner.serialized_rp_sender.poll_ready(cx)
                    } else {
                        Poll::Pending
                    }
                });

                let next_serialized_request =
                    if self.inner.num_requests_in_fly < self.inner.max_requests_in_fly.get() {
                        either::Left(self.inner.serialized_rq_receiver.next())
                    } else {
                        either::Right(future::pending())
                    };

                let response_notif = async {
                    let mut wait = None;
                    loop {
                        if let Some(elem) = self.inner.responses_notifications_queue.queue.pop() {
                            break elem;
                        }
                        if let Some(wait) = wait.take() {
                            wait.await
                        } else {
                            wait =
                                Some(self.inner.responses_notifications_queue.on_pushed.listen());
                        }
                    }
                };

                match future::select(
                    future::select(when_ready_to_send, next_serialized_request),
                    core::pin::pin!(response_notif),
                )
                .await
                {
                    future::Either::Left((future::Either::Left((Ok(()), _)), _)) => {
                        WhatHappened::CanSendToSocket
                    }
                    future::Either::Left((future::Either::Left((Err(_), _)), _)) => {
                        return Event::SerializedRequestsIoClosed
                    }
                    future::Either::Left((future::Either::Right((Some(request), _)), _)) => {
                        WhatHappened::NewRequest(request)
                    }
                    future::Either::Left((future::Either::Right((None, _)), _)) => {
                        return Event::SerializedRequestsIoClosed
                    }
                    future::Either::Right((message, _)) => WhatHappened::Message(message),
                }
            };

            // Immediately handle every event apart from `NewRequest`.
            let new_request = match what_happened {
                WhatHappened::CanSendToSocket => {
                    // This block can only be reached if the sender is ready to send and if there
                    // is a response available to send.
                    let (response_or_notif, is_response) =
                        self.inner.pending_serialized_responses.remove(
                            self.inner
                                .pending_serialized_responses_queue
                                .pop_front()
                                .unwrap(),
                        );

                    // However, maybe the channel has disconnected since the code above.
                    // We simply ignore when that is the case, as it will be detected at the next
                    // iteration.
                    let _ = self
                        .inner
                        .serialized_rp_sender
                        .start_send(response_or_notif);

                    if is_response {
                        debug_assert!(self.inner.num_requests_in_fly >= 1);
                        self.inner.num_requests_in_fly -= 1;
                    }

                    // Shrink containers if necessary in order to reduce memory usage after a
                    // burst of requests.
                    if self.inner.pending_serialized_responses.capacity()
                        > self
                            .inner
                            .pending_serialized_responses
                            .len()
                            .saturating_mul(4)
                    {
                        self.inner.pending_serialized_responses.shrink_to_fit();
                    }
                    if self.inner.pending_serialized_responses_queue.capacity()
                        > self
                            .inner
                            .pending_serialized_responses_queue
                            .len()
                            .saturating_mul(4)
                    {
                        self.inner
                            .pending_serialized_responses_queue
                            .shrink_to_fit();
                    }

                    continue;
                }
                WhatHappened::NewRequest(request) => {
                    self.inner.num_requests_in_fly += 1;
                    debug_assert!(
                        self.inner.num_requests_in_fly <= self.inner.max_requests_in_fly.get()
                    );
                    request
                }
                WhatHappened::Message(ToMainTask::RequestResponse(response)) => {
                    let pos = self
                        .inner
                        .pending_serialized_responses
                        .insert((response, true));
                    self.inner.pending_serialized_responses_queue.push_back(pos);
                    continue;
                }
                WhatHappened::Message(ToMainTask::Notification(notification)) => {
                    // TODO: filter out redundant notifications, as it's the entire point of this module
                    let pos = self
                        .inner
                        .pending_serialized_responses
                        .insert((notification, false));
                    self.inner.pending_serialized_responses_queue.push_back(pos);
                    continue;
                }
            };

            let (request_id, parsed_request) = match methods::parse_json_call(&new_request) {
                Ok((request_id, method)) => (request_id, method),
                Err(methods::ParseCallError::Method { request_id, error }) => {
                    let response = error.to_json_error(request_id);
                    let pos = self
                        .inner
                        .pending_serialized_responses
                        .insert((response, true));
                    self.inner.pending_serialized_responses_queue.push_back(pos);
                    continue;
                }
                Err(methods::ParseCallError::UnknownNotification(_)) => continue,
                Err(methods::ParseCallError::JsonRpcParse(_)) => {
                    // The `SerializedRequestsIo` makes sure that requests are valid before
                    // sending them.
                    unreachable!()
                }
            };

            // There exists three types of requests:
            //
            // - Requests that follow a simple one-request-one-response schema.
            // - Requests that, if accepted, start a subscription.
            // - Requests that unsubscribe from a subscription.
            //
            match &parsed_request {
                methods::MethodCall::account_nextIndex { .. }
                | methods::MethodCall::author_hasKey { .. }
                | methods::MethodCall::author_hasSessionKeys { .. }
                | methods::MethodCall::author_insertKey { .. }
                | methods::MethodCall::author_pendingExtrinsics { .. }
                | methods::MethodCall::author_removeExtrinsic { .. }
                | methods::MethodCall::author_rotateKeys { .. }
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
                | methods::MethodCall::system_name { .. }
                | methods::MethodCall::system_networkState { .. }
                | methods::MethodCall::system_nodeRoles { .. }
                | methods::MethodCall::system_peers { .. }
                | methods::MethodCall::system_properties { .. }
                | methods::MethodCall::system_removeReservedPeer { .. }
                | methods::MethodCall::system_version { .. }
                | methods::MethodCall::chainHead_unstable_genesisHash { .. }
                | methods::MethodCall::chainSpec_unstable_chainName { .. }
                | methods::MethodCall::chainSpec_unstable_genesisHash { .. }
                | methods::MethodCall::chainSpec_unstable_properties { .. }
                | methods::MethodCall::rpc_methods { .. }
                | methods::MethodCall::sudo_unstable_p2pDiscover { .. }
                | methods::MethodCall::sudo_unstable_version { .. }
                | methods::MethodCall::chainHead_unstable_finalizedDatabase { .. }
                | methods::MethodCall::chainHead_unstable_header { .. }
                | methods::MethodCall::chainHead_unstable_storageContinue { .. }
                | methods::MethodCall::chainHead_unstable_unpin { .. } => {
                    // Simple one-request-one-response.
                    return Event::HandleRequest {
                        request_process: RequestProcess {
                            responses_notifications_queue: self
                                .inner
                                .responses_notifications_queue
                                .clone(),
                            request: new_request,
                            has_sent_response: false,
                        },
                        task: self,
                    };
                }

                methods::MethodCall::author_submitAndWatchExtrinsic { .. }
                | methods::MethodCall::chain_subscribeAllHeads { .. }
                | methods::MethodCall::chain_subscribeFinalizedHeads { .. }
                | methods::MethodCall::chain_subscribeNewHeads { .. }
                | methods::MethodCall::state_subscribeRuntimeVersion { .. }
                | methods::MethodCall::state_subscribeStorage { .. }
                | methods::MethodCall::transaction_unstable_submitAndWatch { .. }
                | methods::MethodCall::network_unstable_subscribeEvents { .. }
                | methods::MethodCall::chainHead_unstable_body { .. }
                | methods::MethodCall::chainHead_unstable_call { .. }
                | methods::MethodCall::chainHead_unstable_follow { .. }
                | methods::MethodCall::chainHead_unstable_storage { .. } => {
                    // Subscription starting requests.

                    // We must check the maximum number of subscriptions.
                    let max_subscriptions = usize::try_from(self.inner.max_active_subscriptions)
                        .unwrap_or(usize::max_value());
                    debug_assert!(self.inner.active_subscriptions.len() <= max_subscriptions);
                    if self.inner.active_subscriptions.len() >= max_subscriptions {
                        let response = parse::build_error_response(
                            request_id,
                            ErrorResponse::ServerError(-32000, "Too many active subscriptions"),
                            None,
                        );
                        let pos = self
                            .inner
                            .pending_serialized_responses
                            .insert((response, true));
                        self.inner.pending_serialized_responses_queue.push_back(pos);
                        continue;
                    }

                    // Allocate the new subscription ID.
                    let subscription_id = self.allocate_subscription_id();
                    debug_assert!(!self
                        .inner
                        .active_subscriptions
                        .contains_key(&subscription_id));

                    // Insert an "kill channel" in the local state. This kill channel is shared
                    // with the subscription object and is used to notify when a subscription
                    // should be killed.
                    let kill_channel = Arc::new(SubscriptionKillChannel {
                        state: AtomicPtr::new(ptr::null_mut()),
                        on_state_changed: event_listener::Event::new(),
                    });
                    self.inner
                        .active_subscriptions
                        .insert(subscription_id.clone(), kill_channel.clone());

                    return Event::HandleSubscriptionStart {
                        subscription_start: SubscriptionStartProcess {
                            responses_notifications_queue: self
                                .inner
                                .responses_notifications_queue
                                .clone(),
                            request: new_request,
                            kill_channel,
                            subscription_id,
                            has_sent_response: false,
                        },
                        task: self,
                    };
                }

                methods::MethodCall::author_unwatchExtrinsic { subscription, .. }
                | methods::MethodCall::state_unsubscribeRuntimeVersion { subscription, .. }
                | methods::MethodCall::state_unsubscribeStorage { subscription, .. }
                | methods::MethodCall::transaction_unstable_unwatch { subscription, .. }
                | methods::MethodCall::network_unstable_unsubscribeEvents {
                    subscription, ..
                }
                | methods::MethodCall::chainHead_unstable_stopBody { subscription, .. }
                | methods::MethodCall::chainHead_unstable_stopStorage { subscription, .. }
                | methods::MethodCall::chainHead_unstable_stopCall { subscription, .. }
                | methods::MethodCall::chainHead_unstable_unfollow {
                    follow_subscription: subscription,
                    ..
                } => {
                    // TODO: must check whether type of subscription matches
                    match self.inner.active_subscriptions.remove(&**subscription) {
                        Some(kill_channel) => {
                            let unsubscribe = match parsed_request {
                                methods::MethodCall::author_unwatchExtrinsic { .. } => {
                                    methods::Response::author_unwatchExtrinsic(true)
                                }
                                methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                                    methods::Response::state_unsubscribeRuntimeVersion(true)
                                }
                                methods::MethodCall::state_unsubscribeStorage { .. } => {
                                    methods::Response::state_unsubscribeStorage(true)
                                }
                                methods::MethodCall::transaction_unstable_unwatch { .. } => {
                                    methods::Response::transaction_unstable_unwatch(())
                                }
                                methods::MethodCall::network_unstable_unsubscribeEvents {
                                    ..
                                } => methods::Response::network_unstable_unsubscribeEvents(()),
                                methods::MethodCall::chainHead_unstable_stopBody { .. } => {
                                    methods::Response::chainHead_unstable_stopBody(())
                                }
                                methods::MethodCall::chainHead_unstable_stopStorage { .. } => {
                                    methods::Response::chainHead_unstable_stopStorage(())
                                }
                                methods::MethodCall::chainHead_unstable_stopCall { .. } => {
                                    methods::Response::chainHead_unstable_stopCall(())
                                }
                                methods::MethodCall::chainHead_unstable_unfollow { .. } => {
                                    methods::Response::chainHead_unstable_unfollow(())
                                }
                                _ => unreachable!(),
                            }
                            .to_json_response(request_id);

                            if kill_channel
                                .state
                                .swap(Box::into_raw(Box::new(unsubscribe)), Ordering::AcqRel)
                                .is_null()
                            {
                                // Subscription isn't currently sending a message. We can grab
                                // back the message and send it from here.
                                let ptr = kill_channel
                                    .state
                                    .swap(&DEAD_STATE as *const _ as *mut _, Ordering::AcqRel);
                                if ptr != &SENDING_STATE as *const _ as *mut _ {
                                    let unsubscribe = unsafe { Box::from_raw(ptr) };
                                    // Note that we push to the end of the concurrent queue, as
                                    // there could be pending notifications earlier in that queue.
                                    self.inner
                                        .responses_notifications_queue
                                        .queue
                                        .push(ToMainTask::RequestResponse(*unsubscribe));
                                    // Don't notify that an event is pushed, as there is no
                                    // listener except the currently function.
                                }
                            }

                            // Notify of the state change only at the end. There is no advantage
                            // in notifying during the intermediary state.
                            kill_channel.on_state_changed.notify(usize::max_value());
                        }
                        None => {
                            let response = match parsed_request {
                                methods::MethodCall::author_unwatchExtrinsic { .. } => {
                                    methods::Response::author_unwatchExtrinsic(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::state_unsubscribeRuntimeVersion { .. } => {
                                    methods::Response::state_unsubscribeRuntimeVersion(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::state_unsubscribeStorage { .. } => {
                                    methods::Response::state_unsubscribeStorage(false)
                                        .to_json_response(request_id)
                                }
                                _ => parse::build_error_response(
                                    request_id,
                                    ErrorResponse::InvalidParams,
                                    None,
                                ),
                            };

                            let pos = self
                                .inner
                                .pending_serialized_responses
                                .insert((response, true));
                            self.inner.pending_serialized_responses_queue.push_back(pos);
                        }
                    }
                }
                methods::MethodCall::chain_unsubscribeAllHeads { subscription, .. }
                | methods::MethodCall::chain_unsubscribeFinalizedHeads { subscription, .. }
                | methods::MethodCall::chain_unsubscribeNewHeads { subscription, .. } => {
                    // TODO: DRY with above
                    // TODO: must check whether type of subscription matches
                    match self.inner.active_subscriptions.remove(&**subscription) {
                        Some(kill_channel) => {
                            let unsubscribe = match parsed_request {
                                methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                                    methods::Response::chain_unsubscribeAllHeads(true)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                                    methods::Response::chain_unsubscribeFinalizedHeads(true)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                                    methods::Response::chain_unsubscribeNewHeads(true)
                                        .to_json_response(request_id)
                                }
                                _ => unreachable!(),
                            };

                            if kill_channel
                                .state
                                .swap(Box::into_raw(Box::new(unsubscribe)), Ordering::AcqRel)
                                .is_null()
                            {
                                // Subscription isn't currently sending a message. We can grab
                                // back the message and send it from here.
                                let ptr = kill_channel
                                    .state
                                    .swap(&DEAD_STATE as *const _ as *mut _, Ordering::AcqRel);
                                if ptr != &SENDING_STATE as *const _ as *mut _ {
                                    let unsubscribe = unsafe { Box::from_raw(ptr) };
                                    // Note that we push to the end of the concurrent queue, as
                                    // there could be pending notifications earlier in that queue.
                                    self.inner
                                        .responses_notifications_queue
                                        .queue
                                        .push(ToMainTask::RequestResponse(*unsubscribe));
                                    // Don't notify that an event is pushed, as there is no
                                    // listener except the currently function.
                                }
                            }

                            // Notify of the state change only at the end. There is no advantage
                            // in notifying during the intermediary state.
                            kill_channel.on_state_changed.notify(usize::max_value());
                        }
                        None => {
                            let response = match parsed_request {
                                methods::MethodCall::chain_unsubscribeAllHeads { .. } => {
                                    methods::Response::chain_unsubscribeAllHeads(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeFinalizedHeads { .. } => {
                                    methods::Response::chain_unsubscribeFinalizedHeads(false)
                                        .to_json_response(request_id)
                                }
                                methods::MethodCall::chain_unsubscribeNewHeads { .. } => {
                                    methods::Response::chain_unsubscribeNewHeads(false)
                                        .to_json_response(request_id)
                                }
                                _ => unreachable!(),
                            };

                            let pos = self
                                .inner
                                .pending_serialized_responses
                                .insert((response, true));
                            self.inner.pending_serialized_responses_queue.push_back(pos);
                        }
                    }
                }
            }
        }
    }

    fn allocate_subscription_id(&mut self) -> String {
        let subscription_id = self.inner.next_subscription_id.to_string();
        self.inner.next_subscription_id += 1;
        subscription_id
    }
}

impl fmt::Debug for ClientMainTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClientMainTask").finish()
    }
}

impl Drop for ClientMainTask {
    fn drop(&mut self) {
        // Mark all active subscriptions as dead.
        for (_, kill_channel) in self.inner.active_subscriptions.drain() {
            kill_channel
                .state
                .store(&DEAD_STATE as *const _ as *mut _, Ordering::Release);
            kill_channel.on_state_changed.notify(usize::max_value());
        }
    }
}

/// Outcome of the processing of [`ClientMainTask::run_until_event`].
#[derive(Debug)]
pub enum Event {
    /// JSON-RPC client has sent a plain request (i.e. that isn't related to subscriptions).
    HandleRequest {
        /// The task that generated the event.
        task: ClientMainTask,
        /// Object connected to the [`ClientMainTask`] and containing the information about the
        /// request to process.
        request_process: RequestProcess,
    },

    /// JSON-RPC client desires starting a new subscription.
    ///
    /// Note that the [`ClientMainTask`] automatically enforces a limit to the maximum number of
    /// subscriptions. If this event is generated, this check has already passed.
    HandleSubscriptionStart {
        /// The task that generated the event.
        task: ClientMainTask,
        /// Object connected to the [`ClientMainTask`] and containing the information about the
        /// request to process.
        subscription_start: SubscriptionStartProcess,
    },

    /// The [`SerializedRequestsIo`] has been dropped. The [`ClientMainTask`] has been destroyed.
    SerializedRequestsIoClosed,
}

/// Object connected to the [`ClientMainTask`] that allows sending requests to the task and
/// receiving responses.
pub struct SerializedRequestsIo {
    // TODO: instead of using channels we could do things manually, which would lead to less waker registrations
    requests_sender: async_channel::Sender<String>,
    responses_receiver: Mutex<mpsc::Receiver<String>>,
}

impl SerializedRequestsIo {
    /// Waits for a response or a notification to send to the JSON-RPC client to be available,
    /// and returns it.
    ///
    /// Returns `None` if the [`ClientMainTask`] has been destroyed.
    ///
    /// > **Note**: It is important to run [`ClientMainTask::run_until_event`] concurrently to
    /// >           this function, otherwise it might never return.
    pub async fn wait_next_response(&self) -> Result<String, WaitNextResponseError> {
        self.responses_receiver
            .lock()
            .await
            .next()
            .await
            .ok_or(WaitNextResponseError::ClientMainTaskDestroyed)
    }

    // TODO: add functions for when you want to block the sending

    /// Tries to add a JSON-RPC request to the queue of requests of the [`ClientMainTask`].
    ///
    /// This might cause a call to [`ClientMainTask::run_until_event`] to return
    /// [`Event::HandleRequest`] or [`Event::HandleSubscriptionStart`].
    pub fn try_send_request(&self, request: String) -> Result<(), TrySendRequestError> {
        // Try parse the request here. This guarantees that the [`ClientMainTask`] can't receive
        // requests that can't be parsed.
        if let Err(methods::ParseCallError::JsonRpcParse(err)) = methods::parse_json_call(&request)
        {
            return Err(TrySendRequestError {
                request,
                cause: TrySendRequestErrorCause::MalformedJson(err),
            });
        }

        match self.requests_sender.try_send(request) {
            Ok(()) => Ok(()),
            Err(async_channel::TrySendError::Full(request)) => Err(TrySendRequestError {
                request,
                cause: TrySendRequestErrorCause::QueueFull,
            }),
            Err(async_channel::TrySendError::Closed(request)) => Err(TrySendRequestError {
                request,
                cause: TrySendRequestErrorCause::ClientMainTaskDestroyed,
            }),
        }
    }
}

impl fmt::Debug for SerializedRequestsIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SerializedRequestsIo").finish()
    }
}

/// See [`SerializedRequestsio::wait_next_response`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum WaitNextResponseError {
    /// The attached [`ClientMainTask`] has been destroyed.
    ClientMainTaskDestroyed,
}

/// Error returned by [`SerializedRequestsIo::try_send_request`].
#[derive(Debug, derive_more::Display)]
#[display(fmt = "{cause}")]
pub struct TrySendRequestError {
    /// The JSON-RPC request that was passed as parameter.
    pub request: String,
    /// Reason for the error.
    pub cause: TrySendRequestErrorCause,
}

/// See [`TrySendRequestError::cause`].
#[derive(Debug, derive_more::Display)]
pub enum TrySendRequestErrorCause {
    /// Data is not JSON, or JSON is missing or has invalid fields.
    #[display(fmt = "{_0}")]
    MalformedJson(ParseError),
    /// Queue of JSON-RPC requests to the [`ClientMainTask`] is full.
    QueueFull,
    /// The attached [`ClientMainTask`] has been destroyed.
    ClientMainTaskDestroyed,
}

/// Object connected to the [`ClientMainTask`] and containing a request expecting an answer.
///
/// If this object is dropped before the request has been answered, an automatic "internal error"
/// error response is automatically sent back.
pub struct RequestProcess {
    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,
    /// Request in JSON form. Guaranteed to decode successfully.
    request: String,
    /// `true` if a response has already been sent.
    has_sent_response: bool,
}

impl RequestProcess {
    /// Returns the request which must be processed.
    ///
    /// The request is guaranteed to not be related to subscriptions in any way.
    // TODO: with stronger typing users wouldn't have to worry about the type of request
    pub fn request(&self) -> methods::MethodCall {
        methods::parse_json_call(&self.request).unwrap().1
    }

    /// Indicate the response to the request to the [`ClientMainTask`].
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn respond(mut self, response: methods::Response<'_>) {
        let request_id = methods::parse_json_call(&self.request).unwrap().0;
        let serialized = response.to_json_response(request_id);
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::max_value());
        self.has_sent_response = true;
    }

    /// Indicate to the [`ClientMainTask`] that the response to the request is `null`.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    // TODO: the necessity for this function is basically a hack
    pub fn respond_null(mut self) {
        let request_id = methods::parse_json_call(&self.request).unwrap().0;
        let serialized = parse::build_success_response(request_id, "null");
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::max_value());
        self.has_sent_response = true;
    }

    /// Indicate to the [`ClientMainTask`] that the request should return an error.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn fail(mut self, error: ErrorResponse) {
        let request_id = methods::parse_json_call(&self.request).unwrap().0;
        let serialized = parse::build_error_response(request_id, error, None);
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::max_value());
        self.has_sent_response = true;
    }

    /// Indicate to the [`ClientMainTask`] that the request should return an error.
    ///
    /// This function is similar to [`RequestProcess`], except that an additional JSON payload is
    /// attached to the error.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn fail_with_attached_json(mut self, error: ErrorResponse, json: &str) {
        let request_id = methods::parse_json_call(&self.request).unwrap().0;
        let serialized = parse::build_error_response(request_id, error, Some(json));
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::max_value());
        self.has_sent_response = true;
    }
}

impl fmt::Debug for RequestProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.request, f)
    }
}

impl Drop for RequestProcess {
    fn drop(&mut self) {
        if !self.has_sent_response {
            let request_id = methods::parse_json_call(&self.request).unwrap().0;
            let serialized =
                parse::build_error_response(request_id, ErrorResponse::InternalError, None);
            self.responses_notifications_queue
                .queue
                .push(ToMainTask::RequestResponse(serialized));
            self.responses_notifications_queue
                .on_pushed
                .notify(usize::max_value());
        }
    }
}

/// Object connected to the [`ClientMainTask`] and containing a request that leads to the creation
/// of a subscription.
///
/// If this object is dropped before the request has been answered, an automatic "internal error"
/// error response is automatically sent back.
pub struct SubscriptionStartProcess {
    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,
    /// `Arc` shared with the client main task and that is used to notify that the subscription
    /// should be killed.
    kill_channel: Arc<SubscriptionKillChannel>,
    /// Request in JSON form. Guaranteed to decode successfully.
    request: String,
    /// Identifier of the subscription. Assigned by the client task.
    subscription_id: String,
    /// `true` if a response has already been sent.
    has_sent_response: bool,
}

impl SubscriptionStartProcess {
    /// Returns the request which must be processed.
    ///
    /// The request is guaranteed to be a request that starts a subscription.
    // TODO: with stronger typing users wouldn't have to worry about the type of request
    pub fn request(&self) -> methods::MethodCall {
        methods::parse_json_call(&self.request).unwrap().1
    }

    /// Indicate to the [`ClientMainTask`] that the subscription is accepted.
    ///
    /// The [`ClientMainTask`] will send the confirmation to the JSON-RPC client.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn accept(mut self) -> Subscription {
        let (request_id, parsed_request) = methods::parse_json_call(&self.request).unwrap();

        let serialized_response = match parsed_request {
            methods::MethodCall::author_submitAndWatchExtrinsic { .. } => {
                methods::Response::author_submitAndWatchExtrinsic(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::chain_subscribeAllHeads { .. } => {
                methods::Response::chain_subscribeAllHeads(Cow::Borrowed(&self.subscription_id))
            }
            methods::MethodCall::chain_subscribeFinalizedHeads { .. } => {
                methods::Response::chain_subscribeFinalizedHeads(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::chain_subscribeNewHeads { .. } => {
                methods::Response::chain_subscribeNewHeads(Cow::Borrowed(&self.subscription_id))
            }
            methods::MethodCall::state_subscribeRuntimeVersion { .. } => {
                methods::Response::state_subscribeRuntimeVersion(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::state_subscribeStorage { .. } => {
                methods::Response::state_subscribeStorage(Cow::Borrowed(&self.subscription_id))
            }
            methods::MethodCall::transaction_unstable_submitAndWatch { .. } => {
                methods::Response::transaction_unstable_submitAndWatch(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            methods::MethodCall::network_unstable_subscribeEvents { .. } => {
                methods::Response::network_unstable_subscribeEvents(Cow::Borrowed(
                    &self.subscription_id,
                ))
            }
            _ => unreachable!(),
        }
        .to_json_response(request_id);

        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized_response));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::max_value());
        self.has_sent_response = true;

        Subscription {
            responses_notifications_queue: self.responses_notifications_queue.clone(),
            kill_channel: self.kill_channel.clone(),
            subscription_id: mem::take(&mut self.subscription_id),
        }
    }

    /// Indicate to the [`ClientMainTask`] that the subscription start request should return an
    /// error.
    ///
    /// Has no effect if the [`ClientMainTask`] has been destroyed.
    pub fn fail(mut self, error: ErrorResponse) {
        let request_id = methods::parse_json_call(&self.request).unwrap().0;
        let serialized = parse::build_error_response(request_id, error, None);
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::RequestResponse(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::max_value());
        self.has_sent_response = true;
    }
}

impl fmt::Debug for SubscriptionStartProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.request, f)
    }
}

impl Drop for SubscriptionStartProcess {
    fn drop(&mut self) {
        if !self.has_sent_response {
            let request_id = methods::parse_json_call(&self.request).unwrap().0;
            let serialized =
                parse::build_error_response(request_id, ErrorResponse::InternalError, None);
            self.responses_notifications_queue
                .queue
                .push(ToMainTask::RequestResponse(serialized));
            self.responses_notifications_queue
                .on_pushed
                .notify(usize::max_value());
        }
    }
}

/// Object connected to the [`ClientMainTask`] representing an active subscription.
///
/// Dropping this object doesn't have any particular effect and is the same as not sending any
/// notification anymore.
pub struct Subscription {
    /// Queue where responses and subscriptions push responses/notifications.
    responses_notifications_queue: Arc<ResponsesNotificationsQueue>,
    /// `Arc` shared with the client main task and that is used to notify that the subscription
    /// should be killed.
    kill_channel: Arc<SubscriptionKillChannel>,
    /// Identifier of the subscription. Assigned by the client task.
    subscription_id: String,
}

/// See [`SubscriptionKillChannel::state`].
static SENDING_STATE: String = String::new();
/// See [`SubscriptionKillChannel::state`].
static DEAD_STATE: String = String::new();

/// See [`Subscription::kill_channel`].
struct SubscriptionKillChannel {
    /// State of the subscription.
    ///
    /// This variable can be in the follow states:
    ///
    /// - `null`, which means "alive and idle".
    /// - [`SENDING_STATE`], which means that the subscription is alive and is currently pushing
    /// a message to the queue.
    /// - [`DEAD_STATE`], which means that the subscription is dead and shouldn't send any more
    /// notification.
    /// - Any other value is an unsubscribe confirmation message.
    ///
    /// The reason for this complicated design is that we want to avoid race conditions between
    /// the main task pushing an unsubscribe confirmation message to the queue, and the
    /// subscription sending a notification to the same queue. Unsubscribe confirmation messages
    /// should always be pushed after any notification.
    ///
    /// Before the subscription starts pushing a message to the queue for the main task, it
    /// switches this state to [`SENDING_STATE`]. Having having finished sending, it switches it
    /// back to `null`. If an unsubscribe confirmation message is grabbed while switching states,
    /// the subscription sends it to the queue.
    ///
    /// Destroying a subscription is done in two steps: first, store a unsubscribe confirmation
    /// message, then switch to [`DEAD_STATE`]. When switching to [`DEAD_STATE`], the unsubscribe
    /// confirmation message will likely be grabbed back and can be pushed to the queue  If
    /// [`SENDING_STATE`] is grabbed instead, then it is the job of the subscription to send the
    /// unsubscribe confirmation message.
    state: AtomicPtr<String>,

    /// Notified whenever [`SubscriptionKillChannel::state`] is modified.
    on_state_changed: event_listener::Event,
}

impl Subscription {
    /// Return the identifier of this subscription. Necessary in order to generate answers.
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    /// Send a notification the [`ClientMainTask`].
    ///
    /// Has no effect if [`Subscription::is_stale`] would return `true`.
    ///
    /// This notification might end up being discarded if the queue of responses to send back to
    /// the JSON-RPC client is full and/or if the notification is redundant with another
    /// notification sent earlier.
    ///
    /// While this function is asynchronous, it is expected to not take very long provided that
    /// [`ClientMainTask::run_until_event`] is called in parallel.
    ///
    /// > **Note**: It is important to run [`ClientMainTask::run_until_event`] concurrently to
    /// >           this function, otherwise it might never return.
    // TODO: with stronger typing we could automatically fill the subscription_id
    pub async fn send_notification(&mut self, notification: methods::ServerToClient<'_>) {
        let serialized = notification.to_json_call_object_parameters(None);

        // We first check and update the state in order to prevent race conditions with the
        // subscription being killed by the main task.
        match self
            .kill_channel
            .state
            .swap(&SENDING_STATE as *const _ as *mut _, Ordering::AcqRel)
        {
            ptr if ptr.is_null() => {
                // Normal case. Can send notification.
            }
            ptr if ptr == &DEAD_STATE as *const _ as *mut _ => {
                // Subscription is already dead. Don't send the notification.
                self.kill_channel
                    .state
                    .store(&DEAD_STATE as *const _ as *mut _, Ordering::Release);
                return;
            }
            ptr if ptr == &SENDING_STATE as *const _ as *mut _ => {
                // This is never supposed to happen. In theory, this could be a `debug_assert`,
                // but given that we use unsafe code below, it's not a bad idea to check this
                // even when debug assertions are disabled.
                unreachable!()
            }
            ptr => {
                // Grabbed an unsubscribe confirmation message.
                // The subscription is currently being killed by the main task. We finish its
                // job and skip the notification.
                let message = unsafe { Box::from_raw(ptr) };
                self.responses_notifications_queue
                    .queue
                    .push(ToMainTask::RequestResponse(*message));
                self.responses_notifications_queue
                    .on_pushed
                    .notify(usize::max_value());
                self.kill_channel
                    .state
                    .store(&DEAD_STATE as *const _ as *mut _, Ordering::Release);
                return;
            }
        }

        // Wait until there is space in the queue.
        // Note that this is intentionally racy.
        {
            let mut wait = None;
            loop {
                if self.responses_notifications_queue.queue.len()
                    < self.responses_notifications_queue.max_len
                {
                    break;
                }
                // TODO: also check for state update
                if let Some(wait) = wait.take() {
                    wait.await
                } else {
                    wait = Some(self.responses_notifications_queue.on_popped.listen());
                }
            }
        }

        // Actually push the element.
        self.responses_notifications_queue
            .queue
            .push(ToMainTask::Notification(serialized));
        self.responses_notifications_queue
            .on_pushed
            .notify(usize::max_value());

        // Now switch the state back.
        match self
            .kill_channel
            .state
            .swap(ptr::null_mut(), Ordering::AcqRel)
        {
            ptr if ptr == &SENDING_STATE as *const _ as *mut _ => {
                // We back found the state that we put there. Normal case.
            }
            ptr if ptr.is_null() => {
                // Shouldn't be happening.
                unreachable!()
            }
            ptr if ptr == &DEAD_STATE as *const _ as *mut _ => {
                // The subscription has been killed by the main task.
            }
            ptr => {
                // Grabbed an unsubscribe confirmation message.
                // The subscription has been killed by the main task. We finish its job.
                let message = unsafe { Box::from_raw(ptr) };
                self.responses_notifications_queue
                    .queue
                    .push(ToMainTask::RequestResponse(*message));
                self.kill_channel
                    .state
                    .store(&DEAD_STATE as *const _ as *mut _, Ordering::Release);
                self.responses_notifications_queue
                    .on_pushed
                    .notify(usize::max_value());
            }
        }
    }

    /// Returns `true` if the JSON-RPC client has unsubscribed, or the [`ClientMainTask`] has been
    /// destroyed, or the queue of responses to send to the JSON-RPC client is clogged and the
    /// logic of the subscription requires that it stops altogether in that situation.
    ///
    /// Due to the racy nature of this function, a value of `false` can at any moment switch to
    /// `true` and thus should be interpreted as "maybe". A value of `true`, however, actually
    /// means "yes", as it can't ever switch back to `false`.
    pub fn is_stale(&self) -> bool {
        self.kill_channel.state.load(Ordering::Relaxed) == &DEAD_STATE as *const _ as *mut _
    }

    /// Run indefinitely until [`Subscription::is_stale`] returns `true`.
    pub async fn wait_until_stale(&mut self) {
        // The control flow of this function is a bit magic, but simple enough that it should be
        // easy to understand.
        let mut wait = None;
        loop {
            if self.kill_channel.state.load(Ordering::Relaxed) == &DEAD_STATE as *const _ as *mut _
            {
                return;
            }

            if let Some(wait) = wait.take() {
                wait.await;
            } else {
                wait = Some(self.kill_channel.on_state_changed.listen());
            }
        }
    }
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Subscription")
            .field(&self.subscription_id)
            .finish()
    }
}
