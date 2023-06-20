// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! The [`RequestsSubscriptions`] state machine holds a list of clients, pending outgoing messages,
//! pending requests, and active subscriptions.
//!
//! The code in this module is the front line of the JSON-RPC server. It can be subject to DoS
//! attacks, and is therefore designed to properly distribute resources between JSON-RPC clients.
//! If you use this data structure as intended, your design is safe from DoS attacks.
//!
//! # Usage
//!
//! The [`RequestsSubscriptions`] is meant to be shared (through an `Arc` or similar) between many
//! different asynchronous tasks that call its methods.
//!
//! > **Note**: While off-topic for this module, you are strongly encouraged to put all these
//! >           asynchronous tasks within a single `FuturesUnordered`. This ensure that no two
//! >           tasks can be processed at the same time, and thus limits the total CPU usage of
//! >           all these tasks combined to `1.0` CPU cores. This leaves other CPU cores free for
//! >           the more urgent processing.
//!
//! There should be:
//!
//! - One lightweight task for each client currently connected to the server.
//! - A fixed number of lightweight tasks (e.g. 16) dedicated to answering requests.
//! - A fixed number of lightweight tasks (e.g. 8) dedicated to processing subscription tasks by
//! calling [`RequestsSubscriptions::run_subscription_task`] in a loop.
//!
//! ## Clients
//!
//! Whenever a new client connects to the server, spawn a new task dedicated to this client, that:
//!
//! - Calls [`RequestsSubscriptions::add_client`], denying the client if the function returns an
//!   error.
//! - Repeatedly polls the socket for a new request then calls
//!   [`RequestsSubscriptions::queue_client_request`].
//! - At the same time (for example in a `select!` block) calls
//!   [`RequestsSubscriptions::next_response`] then sends the response to the socket.
//! - When the client disconnects, calls [`RequestsSubscriptions::remove_client`].
//!
//! It is important that no new request is polled from the socket as long as
//! [`RequestsSubscriptions::queue_client_request`] hasn't been able to queue the previous
//! request. This makes it possible to back-pressure the JSON-RPC client in case when the queue
//! is slow to be processed.
//!
//! Similarly, do not call [`RequestsSubscriptions::next_response`] before the socket has been
//! able to send the previous response. Not calling [`RequestsSubscriptions::next_response`] often
//! enough will lead to back-pressure being applied onto
//! [`RequestsSubscriptions::queue_client_request`], which will in turn back-pressure the sending
//! side of the JSON-RPC client.
//!
//! Note that if a client is removed at the same time as a call to
//! [`RequestsSubscriptions::next_response`] is in progress, the call will never return  It is
//! your responsibility to interrupt this function call when the client is disconnected. If,
//! as advised above, everything is contained within a single task, this is normally not a problem
//! as you simply stop the task altogether after removing the client.
//!
//! ## Requests
//!
//! There should be a certain, fixed, number of lightweight tasks dedicated to pulling requests
//! from the state machine and answering them.
//!
//! Each of these lightweight tasks should:
//!
//! - Call [`RequestsSubscriptions::next_request`]. This function call sleeps until there is a
//! request available.
//! - Parse the request that was returned and generate its response. This step should be relatively
//! fast (e.g. not more than one second), but can liberally perform asynchronous requests, lock
//! mutexes, etc.
//! - Call [`RequestsSubscriptions::respond`].
//! - Jump back to step 1.
//!
//! If these tasks are too busy and don't call [`RequestsSubscriptions::next_request`] often
//! enough, back-pressure will be applied onto [`RequestsSubscriptions::queue_client_request`],
//! which in turn applies back-pressure onto the JSON-RPC clients.
//!
//! ## Subscriptions
//!
//! If a client-sent request requires starting a subscription, one of the
//! requests-pulling-dedicated tasks should call [`RequestsSubscriptions::start_subscription`].
//!
//! When a subscription is started, the higher-level code spawns a new task dedicated to
//! sending back notifications to the client using [`RequestsSubscriptions::push_notification`],
//! [`RequestsSubscriptions::try_push_notification`], or
//! [`RequestsSubscriptions::set_queued_notification`].
//!

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    string::{String, ToString as _},
    sync::{Arc, Weak},
    vec::Vec,
};
use async_lock::Mutex;
use core::{
    any::Any,
    cmp, fmt,
    future::Future,
    hash,
    num::NonZeroU32,
    ops,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use futures_channel::{mpsc, oneshot};
use futures_util::future;

mod tests;

#[derive(Clone)]
pub struct ClientId(u64, Weak<dyn Any + Send + Sync>);

#[derive(Clone)]
pub struct RequestId(u64, Weak<dyn Any + Send + Sync>);

#[derive(Debug, Clone, derive_more::From)]
pub enum ClientOrRequestIdRef<'a> {
    ClientId(&'a ClientId),
    RequestId(&'a RequestId),
}

impl<'a> ClientOrRequestIdRef<'a> {
    fn client_weak(self) -> &'a Weak<dyn Any + Send + Sync> {
        match self {
            ClientOrRequestIdRef::ClientId(c) => &c.1,
            ClientOrRequestIdRef::RequestId(r) => &r.1,
        }
    }
}

pub mod executor;

/// Configuration to pass to [`RequestsSubscriptions::new`].
pub struct Config {
    /// For each client, the maximum number of JSON-RPC requests that can be start at the same
    /// time before the first one has been responded to. Any additional request will need to wait.
    pub max_requests_per_client: NonZeroU32,

    /// Maximum number of active subscriptions that each client can start. Any additional
    /// subscription will be immediately rejected.
    pub max_subscriptions_per_client: u32,

    /// Maximum number of clients that can be added at the same time. Any additional client will
    /// be rejected.
    pub max_clients: u32,
}

pub struct RequestsSubscriptions<TSubMsg> {
    /// List of all clients of the state machine. Locked only when adding and removing clients.
    clients: Mutex<Clients<TSubMsg>>,

    /// List of requests sent by a client and not yet pulled by
    /// [`RequestsSubscriptions::next_request`].
    ///
    /// Can contain obsolete clients, in which case the entry should simply be ignored.
    ///
    /// We use an unbounded list because the maximum number of clients can be changed dynamically
    /// using [`RequestsSubscriptions::set_max_clients`], in which case it would be impossible
    /// to update the size of this list.
    // TODO: what about entries of obsolete clients clogging the queue? how do we deal with this?
    unpulled_requests: crossbeam_queue::SegQueue<(String, Weak<ClientInner<TSubMsg>>)>,

    /// Event notified whenever an element is pushed to [`RequestsSubscriptions::unpulled_requests`].
    new_unpulled_request: event_listener::Event,

    /// Queue of subscription-related tasks. Run manually using
    /// [`RequestsSubscriptions::run_subscription_task`].
    subscriptions_tasks: Arc<executor::TasksQueue>,

    /// Next identifier to assign to the next request.
    ///
    /// Matches the values found in [`ClientInnerGuarded::pending_requests`].
    next_request_id: atomic::Atomic<u64>,

    /// Next identifier to assign to the next subscription.
    ///
    /// Matches the values found in TODO.
    next_subscription_id: atomic::Atomic<u64>,

    /// Maximum number of clients simultaneously allowed.
    ///
    /// The value here can change at runtime.
    max_clients: AtomicUsize,

    /// Maximum number of requests each client can send before having to wait for some of its
    /// earlier requests to have been answered.
    max_requests_per_client: usize,

    /// Maximum number of subscriptions each client can have active before new subscriptions are
    /// rejected.
    max_subscriptions_per_client: usize,
}

impl<TSubMsg: Send + Sync + 'static> RequestsSubscriptions<TSubMsg> {
    /// Creates a new empty state machine.
    pub fn new(config: Config) -> Self {
        // The fields in the config are `u32`s rather than `usize`s so that they can be the same
        // on every machine. However, in practice they are queue lengths, and thus are converted
        // to `usize`s. Capping to `usize::max_value()` is fine considering that it's never
        // possible to actually have more than `usize` elements in a container.
        let max_clients = usize::try_from(config.max_clients).unwrap_or(usize::max_value());
        let max_subscriptions_per_client =
            usize::try_from(config.max_subscriptions_per_client).unwrap_or(usize::max_value());
        let max_requests_per_client =
            usize::try_from(config.max_requests_per_client.get()).unwrap_or(usize::max_value());

        Self {
            clients: Mutex::new(Clients {
                list: hashbrown::HashMap::with_capacity_and_hasher(8, Default::default()),
                next_id: 0,
            }),
            unpulled_requests: crossbeam_queue::SegQueue::new(),
            subscriptions_tasks: executor::TasksQueue::new(),
            new_unpulled_request: event_listener::Event::new(),
            next_request_id: atomic::Atomic::new(0),
            next_subscription_id: atomic::Atomic::new(0),
            max_clients: AtomicUsize::new(max_clients),
            max_requests_per_client,
            max_subscriptions_per_client,
        }
    }

    /// Changes the maximum number of allowed clients.
    ///
    /// Note that the ordering of this operation is `Relaxed`, meaning that this change will apply
    /// some time in the future and not necessarily immediately.
    ///
    /// Lowering the maximum number of allowed clients below the current number will *not*
    /// remove existing clients. If this is desired, this must be done manually by calling
    /// [`RequestsSubscriptions::remove_client`].
    ///
    /// > **Note**: This function can typically be used at runtime to adjust the maximum number
    /// >           of clients based on the resource consumption of the binary.
    pub fn set_max_clients(&self, max_clients: usize) {
        self.max_clients.store(max_clients, Ordering::Relaxed);
    }

    /// Adds a new client to the state machine. A new [`ClientId`] is attributed.
    ///
    /// Can return an error if the maximum simultaneous number of clients has been reached.
    ///
    /// A single instance of [`RequestsSubscriptions`] will never allocate multiple times the same
    /// [`ClientId`].
    pub async fn add_client(&self) -> Result<ClientId, AddClientError> {
        let mut clients = self.clients.lock().await;
        self.add_client_inner(&mut *clients)
    }

    /// Similar to [`RequestsSubscriptions::add_client`], but non-async and takes `self` as `&mut`.
    ///
    /// > **Note**: This function is notably useful for adding clients at initialization, when
    /// >           outside of an asynchronous context.
    pub fn add_client_mut(&mut self) -> Result<ClientId, AddClientError> {
        // Note that we don't use `clients.get_mut()`, as this would keep `self` mutably borrowed
        // and prevent use from calling `add_client_inner`.
        let mut clients = self.clients.try_lock().unwrap();
        self.add_client_inner(&mut *clients)
    }

    fn add_client_inner(&self, clients: &mut Clients<TSubMsg>) -> Result<ClientId, AddClientError> {
        // `clients.list.len()` can realistically be superior to `max_clients` since `max_clients`
        // can be updated at runtime by the API user.
        if clients.list.len() >= self.max_clients.load(Ordering::Relaxed) {
            return Err(AddClientError::LimitReached);
        }

        let arc = Arc::new(ClientInner {
            total_requests_in_fly_dec_or_dead: event_listener::Event::new(),
            dead: AtomicBool::new(false),
            total_requests_in_fly: AtomicUsize::new(0),
            guarded: Mutex::new(ClientInnerGuarded {
                pending_requests: hashbrown::HashSet::with_capacity_and_hasher(
                    cmp::min(self.max_requests_per_client, 64),
                    Default::default(),
                ),
                responses_send_back: VecDeque::with_capacity(cmp::min(
                    self.max_requests_per_client,
                    64,
                )),
                notification_messages: BTreeMap::new(),
                responses_send_back_pushed_or_dead: event_listener::Event::new(),
                notification_messages_popped_or_dead: event_listener::Event::new(),
                active_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                    cmp::min(self.max_subscriptions_per_client, 128),
                    Default::default(),
                ),
                num_inactive_alive_subscriptions: 0,
            }),
        });

        let new_client_id = clients.next_id;
        clients.next_id += 1;

        let ret = ClientId(new_client_id, Arc::downgrade(&(arc.clone() as Arc<_>)));
        clients.list.insert(new_client_id, arc);
        Ok(ret)
    }

    /// Removes from the state machine the client with the given id.
    ///
    /// Returns `None` if this [`ClientId`] is stale or invalid.
    ///
    /// This function invalidates all active requests and subscriptions that relate to this
    /// client. The concerned [`RequestId`]s and subscriptions are returned by this function.
    ///
    /// Note however that functions such as [`RequestsSubscriptions::respond`] and
    /// [`RequestsSubscriptions::push_notification`] intentionally have no effect if you pass an
    /// invalid [`ClientId`]. There is therefore no need to cancel any parallel task that might
    /// currently be responding to requests or pushing notification messages.
    pub async fn remove_client(&self, client: &ClientId) -> Option<(Vec<RequestId>, Vec<String>)> {
        // Try remove the client from the list. Returns if it doesn't exist.
        let removed = {
            let mut clients = self.clients.lock().await;

            let removed = clients.list.remove(&client.0)?;
            debug_assert!(Arc::ptr_eq(
                &removed,
                &Arc::downcast::<ClientInner<TSubMsg>>(client.1.upgrade().unwrap()).unwrap()
            ));

            // Shrink `clients.list` in order to potentially reclaim memory after a potential
            // spike in number of clients.
            if clients.list.capacity() >= 16 && clients.list.capacity() >= clients.list.len() * 2 {
                clients.list.shrink_to_fit();
            }

            removed
        };

        // TODO: how to abort subscription tasks?!

        // Note that `self.clients` is no longer locked here.

        removed.dead.store(true, Ordering::SeqCst);

        // TODO: future cancellation issue
        let guarded_lock = removed.guarded.lock().await;
        let requests_list = guarded_lock
            .pending_requests
            .iter()
            .map(|n| RequestId(*n, client.1.clone()))
            .collect();
        let subscriptions_list = guarded_lock
            .active_subscriptions
            .keys()
            .map(|n| n.to_string()) // TODO: a bit dangerous in case the mapping is modified? extract to own function?
            .collect();

        guarded_lock
            .responses_send_back_pushed_or_dead
            .notify_relaxed(usize::max_value());
        guarded_lock
            .notification_messages_popped_or_dead
            .notify_relaxed(usize::max_value());

        removed
            .total_requests_in_fly_dec_or_dead
            .notify_relaxed(usize::max_value());

        Some((requests_list, subscriptions_list))
    }

    /// Waits until a message is available in the queue of messages to send back to the given
    /// client, then extracts it.
    ///
    /// This asynchronous function can take a long time, as it blocks until a message is
    /// available.
    ///
    /// If the [`ClientId`] no longer exists because of a call to [`RequestsSubscriptions`], then
    /// this function never returns. It is the responsibility of the API user to not call this
    /// function or to interrupt a pending function call with a stale [`ClientId`].
    pub async fn next_response(&self, client: &ClientId) -> String {
        loop {
            let client = match client
                .1
                .upgrade()
                .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
            {
                Some(c) => c,
                None => {
                    // Freeze forever.
                    future::pending::<()>().await;
                    continue;
                }
            };

            let sleep_until = {
                let mut guarded_lock = client.guarded.lock().await;

                debug_assert!(
                    guarded_lock.responses_send_back.len()
                        <= self
                            .max_requests_per_client
                            .saturating_add(guarded_lock.notification_messages.len()),
                );

                match guarded_lock.responses_send_back.pop_front() {
                    Some(ResponseSendBack::Response(message)) => {
                        let _new_val = client.total_requests_in_fly.fetch_sub(1, Ordering::Release);
                        debug_assert_ne!(_new_val, usize::max_value()); // Check for underflows
                        client
                            .total_requests_in_fly_dec_or_dead
                            .notify_additional(1);
                        return message;
                    }
                    Some(ResponseSendBack::SubscriptionMessage(sub_id, index)) => {
                        let message = guarded_lock
                            .notification_messages
                            .remove(&(sub_id, index))
                            .unwrap();
                        guarded_lock
                            .notification_messages_popped_or_dead
                            .notify_additional(1);

                        // It might be that this subscription message concerns a subscription that
                        // is already dead. In this case, we try to decrease
                        // `num_inactive_alive_subscriptions`.
                        //
                        // Note that the check `num_inactive_alive_subscriptions > 0` is purely
                        // for optimization, to avoid doing a hashmap lookup every time.
                        if guarded_lock.num_inactive_alive_subscriptions > 0 {
                            if !guarded_lock.active_subscriptions.contains_key(&sub_id)
                                && guarded_lock
                                    .notification_messages
                                    .range(
                                        (sub_id, usize::min_value())..=(sub_id, usize::max_value()),
                                    )
                                    .next()
                                    .is_none()
                            {
                                guarded_lock.num_inactive_alive_subscriptions -= 1;
                            }
                        } else {
                            debug_assert!(guarded_lock.active_subscriptions.contains_key(&sub_id));
                        }

                        return message;
                    }
                    None => {}
                }

                guarded_lock.responses_send_back_pushed_or_dead.listen()
            };

            sleep_until.await;
        }
    }

    /// Waits until a slot in the queue of requests is available, then queues the given request
    /// passed as parameter.
    ///
    /// The request can later be retrieved by calling [`RequestsSubscriptions::next_request`].
    ///
    /// This asynchronous function can take a long time, as it blocks until a queue entry is
    /// available.
    ///
    /// Slots in the queue of requests are only reclaimed after
    /// [`RequestsSubscriptions::next_response`] has returned a response to a previous request.
    ///
    /// Has no effect if the [`ClientId`] is stale or invalid.
    pub async fn queue_client_request(&self, client: &ClientId, request: String) {
        let client = match client
            .1
            .upgrade()
            .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
        {
            Some(c) => c,
            None => return,
        };

        // Try increase `client.total_requests_in_fly`. If the limit is reached, wait until
        // `request_answered`.
        //
        // Because `request_answered` is notified *after* `total_requests_in_fly` is decremented,
        // we *must* check the value of `total_requests_in_fly` after calling
        // `request_answered.listen()` and before sleeping.
        // However, since `listen()` is rather heavy, we try to avoid calling it as much as
        // possible.
        //
        // This has been implemented as a loop, so that the behaviour is:
        //
        // - Try increase counter.
        // - If limit is reached, call `listen()`.
        // - Try increase counter again (mandatory to prevent race conditions).
        // - Actually wait for the notification, and jump back to step 1.
        let mut sleep_until = None;
        loop {
            // Make sure to not loop forever.
            if client.dead.load(Ordering::SeqCst) {
                return;
            }

            // Try increment `total_requests_in_fly`, capping at a maximum of
            // `max_requests_per_client`.
            let could_increase = client
                .total_requests_in_fly
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                    if old_value >= self.max_requests_per_client {
                        return None;
                    }

                    // Considering that `old_value < max`, and `max` fits in a `usize` by
                    // definition, then `old_value + 1` also always fits in a `usize`. QED.
                    // There's no risk of overflow.
                    Some(old_value + 1)
                })
                .is_ok();
            if could_increase {
                break;
            }

            if let Some(sleep_until) = sleep_until.take() {
                sleep_until.await;
            } else {
                sleep_until = Some(client.total_requests_in_fly_dec_or_dead.listen());
            }
        }

        // We can now insert the request.
        // Note that it is possible for `client.dead` to have become true in the meanwhile, but
        // this is not a problem as `unpulled_requests` is allowed to contain obsolete requests.
        self.unpulled_requests
            .push((request, Arc::downgrade(&client)));
        self.new_unpulled_request.notify_additional(1);
    }

    /// Similar to [`RequestsSubscriptions::queue_client_request`], but succeeds or fails
    /// instantly depending on whether there is enough room in the queue.
    ///
    /// Slots in the queue of requests are only reclaimed after
    /// [`RequestsSubscriptions::next_response`] has returned a response to a previous request.
    ///
    /// Returns `Ok` and silently discards the request if the [`ClientId`] is stale or invalid.
    pub fn try_queue_client_request(
        &self,
        client: &ClientId,
        request: String,
    ) -> Result<(), TryQueueClientRequestError> {
        let client = match client
            .1
            .upgrade()
            .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
        {
            Some(c) => c,
            None => return Ok(()),
        };

        if client.dead.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Try increment `total_requests_in_fly`, capping at a maximum of
        // `max_requests_per_client`.
        let failed_to_increase = client
            .total_requests_in_fly
            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                if old_value >= self.max_requests_per_client {
                    return None;
                }

                // Considering that `old_value < max`, and `max` fits in a `usize` by
                // definition, then `old_value + 1` also always fits in a `usize`. QED.
                // There's no risk of overflow.
                Some(old_value + 1)
            })
            .is_err();
        if failed_to_increase {
            return Err(TryQueueClientRequestError { request });
        }

        // We can now insert the request.
        // Note that it is possible for `client.dead` to have become true in the meanwhile, but
        // this is not a problem as `unpulled_requests` is allowed to contain obsolete requests.
        self.unpulled_requests
            .push((request, Arc::downgrade(&client)));
        self.new_unpulled_request.notify_additional(1);
        Ok(())
    }

    /// Waits until a request has been queued using
    /// [`RequestsSubscriptions::queue_client_request`] and returns it, alongside with an
    /// identifier to later pass back when answering the request.
    ///
    /// Note that the request's body, as a `String` has no guarantee to be valid. The `String` is
    /// simply the value that was passed to [`RequestsSubscriptions::queue_client_request`] and
    /// isn't parsed or validated by the state machine in any way.
    pub async fn next_request(&self) -> (String, RequestId) {
        // Try to pull a request from the queue. If there is none, wait for
        // `new_unpulled_request`.
        let (request_message, client) = loop {
            // Because `new_unpulled_request` is notified *after* new items are pushed to the queue,
            // we *must* check the queue after calling `new_unpulled_request.listen()` and before
            // sleeping.
            // However, since `listen()` is rather heavy, we try to avoid calling it as much as
            // possible.
            //
            // This has been implemented as a loop, so that the behaviour is:
            //
            // - Try pull from queue.
            // - If limit is reached, call `listen()`.
            // - Try pull from queue again (mandatory to prevent race conditions).
            // - Actually wait for the notification, and jump back to step 1.
            let mut sleep_until = None;
            let (request_message, client) = loop {
                if let Some(item) = self.unpulled_requests.pop() {
                    break item;
                }

                if let Some(sleep_until) = sleep_until.take() {
                    sleep_until.await;
                } else {
                    sleep_until = Some(self.new_unpulled_request.listen());
                }
            };

            // The queue might contain obsolete entries. Check that the client still exist, and
            // if not throw away the entry and pull another one.
            if let Some(client) = client.upgrade() {
                if !client.dead.load(Ordering::Relaxed) {
                    break (request_message, client);
                }
            }
        };

        // Allocate a new identifier for this request.
        let request_id_num = self.next_request_id.fetch_add(1, Ordering::Relaxed);

        // Insert the request in the client's state.
        {
            // TODO: future cancellation issue /!\
            let mut lock = client.guarded.lock().await;
            let _was_inserted = lock.pending_requests.insert(request_id_num);
            debug_assert!(_was_inserted);
        }

        // Success.
        let request_id = RequestId(request_id_num, Arc::downgrade(&(client as Arc<_>)));
        (request_message, request_id)
    }

    /// Sets the response to a request previously returned by
    /// [`RequestsSubscriptions::next_request`].
    ///
    /// Has no effect if the [`RequestId`] is invalid, for example if it has already been
    /// responded or if the client has been removed.
    pub async fn respond(&self, request: &RequestId, response: String) {
        let client = match request
            .1
            .upgrade()
            .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
        {
            Some(c) => c,
            None => return,
        };

        {
            let mut lock = client.guarded.lock().await;
            if !lock.pending_requests.remove(&request.0) {
                // The request ID is invalid.
                return;
            }

            lock.responses_send_back
                .push_back(ResponseSendBack::Response(response));
            lock.responses_send_back_pushed_or_dead.notify_additional(1);
        }
    }

    /// Waits until a subscription task is ready to be polled, and polls it.
    ///
    /// The subscription tasks do not run unless this function is called.
    ///
    /// This function is typically expected to be called multiple times in parallel and in a loop.
    pub async fn run_subscription_task(&self) {
        self.subscriptions_tasks.run_one().await
    }

    /// Adds a new subscription to the state machine, associated with the client that started
    /// the given request.
    ///
    /// Returns an error if the client has reached the maximum number of allowed subscriptions
    /// per client.
    ///
    /// If the given [`RequestId`] is stale or invalid, this function always succeeds and returns
    /// a stale subscription.
    ///
    /// The [`SubscriptionStart`] object returned by this function on success must be used in order
    /// to provide a background task associated with the given subscription. The subscription is
    /// automatically cleaned up when the task finishes.
    ///
    /// The provided [`MessagesReceiver`] can be used to receive the messages that were sent using
    /// [`RequestsSubscriptions::subscription_send`]. It is meant to be used only within the task
    /// that is provided to [`SubscriptionStart::start`]
    ///
    /// # About the notifications capacity
    ///
    /// The `notifications_capacity` parameter contains the number of notifications related to this
    /// notification that can be queued for send back simultaneously.
    ///
    /// This value is one of the parameters that bound the total memory usage of this state
    /// machine. In other words, if there was no maximum, a malicious JSON-RPC client could
    /// intentionally create a memory leak on the server.
    ///
    /// It is therefore important that this value isn't too large never gets decided by the
    /// JSON-RPC client.
    ///
    /// For some JSON-RPC functions, the value of this constant can easily be deduced from the
    /// logic of the function. For other functions, the value of this constant should be hard coded.
    // TODO: return a struct instead of a tuple
    pub async fn start_subscription<'a, 'b>(
        &'a self,
        client_or_request: impl Into<ClientOrRequestIdRef<'b>>,
        notifications_capacity: usize,
    ) -> Result<
        (
            String,
            MessagesReceiver<TSubMsg>,
            SubscriptionStart<'_, TSubMsg>,
        ),
        StartSubscriptionError,
    > {
        let (messages_tx, messages_rx) = mpsc::channel(0);

        let subscription_id_num = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
        let subscription_id_string = subscription_id_num.to_string();

        let client_arc = match client_or_request
            .into()
            .client_weak()
            .upgrade()
            .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
        {
            Some(c) => c,
            None => {
                return Ok((
                    subscription_id_string,
                    MessagesReceiver { rx: messages_rx },
                    SubscriptionStart {
                        requests_subscriptions: self,
                        client_subscription: None,
                    },
                ));
            }
        };

        let mut lock = client_arc.guarded.lock().await;

        // Note that the number of subscriptions compared against the limit also includes
        // subscriptions that have been stopped but still have some pending messages to send
        // back (`num_inactive_alive_subscriptions`). This ensures that the queue of responses
        // is properly bounded, and can't overflow because the client repeatedly starts and ends
        // subscriptions.
        if lock
            .active_subscriptions
            .len()
            .saturating_add(lock.num_inactive_alive_subscriptions)
            >= self.max_subscriptions_per_client
        {
            return Err(StartSubscriptionError::LimitReached);
        }

        let _prev_value = lock.active_subscriptions.insert(
            subscription_id_num,
            Subscription {
                notifications_capacity,
                messages_tx,
            },
        );
        debug_assert!(_prev_value.is_none());

        drop(lock);

        Ok((
            subscription_id_string,
            MessagesReceiver { rx: messages_rx },
            SubscriptionStart {
                requests_subscriptions: self,
                client_subscription: Some((client_arc, subscription_id_num)),
            },
        ))
    }

    /// Sends a message to the receiver that was provided when this subscription was created, and
    /// waits until the subscription has sent back a confirmation that it has processed the
    /// message.
    ///
    /// An error is returned if the [`ClientId`] or [`RequestId`] is stale or invalid, or if the
    /// subscription silently drops the confirmation sender. This can happen intentionally or if
    /// the subscription has shut down.
    ///
    /// This asynchronous function performs two steps: delivering a message, then waiting for a
    /// confirmation. Canceling the function in its confirmation waiting phase doesn't
    /// "un-deliver" the message. This function doesn't allow to deliver a message without
    /// waiting for a confirmation.
    pub async fn subscription_send<'a, 'b>(
        &'a self,
        client_or_request: impl Into<ClientOrRequestIdRef<'b>>,
        subscription: &str,
        message: TSubMsg,
    ) -> Result<(), ()> {
        let subscription_as_num: u64 = subscription.parse().map_err(|_| ())?;

        let confirmation_rx = {
            let client_arc = match client_or_request
                .into()
                .client_weak()
                .upgrade()
                .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
            {
                Some(c) => c,
                None => return Err(()),
            };

            let (confirmation_tx, confirmation_rx) = oneshot::channel();

            let mut lock = client_arc.guarded.lock().await;

            let subscription = lock
                .active_subscriptions
                .get_mut(&subscription_as_num)
                .ok_or(())?;

            // TODO: keeping the lock while sending the message doesn't seem great as it could potentially deadlock
            let _ = futures_util::SinkExt::send(
                &mut subscription.messages_tx,
                (message, confirmation_tx),
            )
            .await;

            confirmation_rx
        };

        // Note that no lock nor `Arc` is held at this point (except for `confirmation_rx`).
        if confirmation_rx.await.is_err() {
            return Err(());
        }

        Ok(())
    }

    /// Overwrites the notification whose index is `index` in the queue of notifications destined
    /// for the user.
    ///
    /// The queue of notifications can be sent as equivalent to a `Vec<Option<String>>` whose
    /// length is equal to the `messages_capacity` that was passed to
    /// [`RequestsSubscriptions::start_subscription`], and this function does
    /// `queue[index] = Some(message);`. It discards the message that was previously there, and
    /// works no matter the presence or not of other messages in the queue.
    ///
    /// Note that notifications are not provided to [`RequestsSubscriptions::next_response`]
    /// in the order of their index, but in the order in which they entered the queue. If there
    /// was no notification overwritten, then this notification is now at the end of the list
    /// of notifications to send back. If a notification is overwritten, then only its content
    /// is modified but not its position in the queue.
    ///
    /// This function isn't meant to interact well with
    /// [`RequestsSubscriptions::try_push_notification`]. For each subscription, you are expected
    /// to either push notifications one behind the other, or track which notification queue index
    /// corresponds to what, but not both at the same time.
    ///
    /// Has no effect if the [`ClientId`] or [`RequestId`] is stale or invalid.
    ///
    /// # Panic
    ///
    /// Panics if the `index` is superior or equal to the `messages_capacity` that was passed to
    /// [`RequestsSubscriptions::start_subscription`].
    ///
    pub async fn set_queued_notification<'a, 'b>(
        &'a self,
        client_or_request: impl Into<ClientOrRequestIdRef<'b>>,
        subscription: &str,
        index: usize,
        message: String,
    ) {
        let Ok(subscription_as_num): Result<u64, _> = subscription.parse() else { return };

        let client_arc = match client_or_request
            .into()
            .client_weak()
            .upgrade()
            .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
        {
            Some(c) => c,
            None => return,
        };

        let mut lock = client_arc.guarded.lock().await;

        // Two in one: check whether this subscription is indeed valid, and at the same time get
        // the messages capacity.
        let notifications_capacity = match lock.active_subscriptions.get(&subscription_as_num) {
            Some(l) => l.notifications_capacity,
            None => return,
        };

        // As documented.
        assert!(index < notifications_capacity);

        // Inserts or replaces the current value under the key `(subscription, index)`.
        let previous_message = lock
            .notification_messages
            .insert((subscription_as_num, index), message);

        // Add an entry in `responses_send_back`, or skip this step if not necessary.
        if previous_message.is_none() {
            lock.responses_send_back
                .push_back(ResponseSendBack::SubscriptionMessage(
                    subscription_as_num,
                    index,
                ));
            lock.responses_send_back_pushed_or_dead.notify_additional(1);
        }
    }

    /// Adds the given notification to the queue of notifications to send out for this
    /// subscription.
    ///
    /// This function will choose an index with no notification, and write the notification to it.
    /// If the queue is full, this function will wait for a slot to be available. Slots will only
    /// become available if [`RequestsSubscriptions::next_response`] is called in parallel.
    ///
    /// This function isn't meant to interact well with
    /// [`RequestsSubscriptions::set_queued_notification`]. For each subscription, you are expected
    /// to either push notifications one behind the other, or track which notification queue index
    /// corresponds to what, but not both at the same time.
    ///
    /// Has no effect and silently discards the message if the [`ClientId`] or [`RequestId`] is
    /// stale or invalid.
    pub async fn push_notification<'a>(
        &self,
        client: impl Into<ClientOrRequestIdRef<'a>>,
        subscription: &str,
        message: String,
    ) {
        let _result = self
            .try_push_notification_inner(client, subscription, message, false)
            .await;
        debug_assert!(_result.is_ok());
    }

    /// Adds the given notification to the queue of notifications to send out for this
    /// subscription.
    ///
    /// This function will choose an index with no notification, and write the notification to it.
    /// Returns an error if the queue is full.
    ///
    /// This function isn't meant to interact well with
    /// [`RequestsSubscriptions::set_queued_notification`]. For each subscription, you are expected
    /// to either push notifications one behind the other, or track which notification queue index
    /// corresponds to what, but not both at the same time.
    ///
    /// Note that notifications are not provided to [`RequestsSubscriptions::next_response`]
    /// in the order of their index, but in the order in which they entered the queue.
    ///
    /// Returns `Ok` and silently discards the message if the [`ClientId`] or [`RequestId`] is
    /// stale or invalid.
    pub async fn try_push_notification<'a>(
        &self,
        client: impl Into<ClientOrRequestIdRef<'a>>,
        subscription: &str,
        message: String,
    ) -> Result<(), ()> {
        self.try_push_notification_inner(client, subscription, message, true)
            .await
    }

    /// Internal implementation for pushing a message.
    ///
    /// If `try_only` is `false`, then this function waits for a slot to be available and always
    /// succeeds.
    async fn try_push_notification_inner<'a>(
        &self,
        client: impl Into<ClientOrRequestIdRef<'a>>,
        subscription: &str,
        message: String,
        try_only: bool,
    ) -> Result<(), ()> {
        let client_arc = match client
            .into()
            .client_weak()
            .upgrade()
            .and_then(|c| Arc::downcast::<ClientInner<TSubMsg>>(c).ok())
        {
            Some(c) => c,
            None => return Ok(()),
        };

        let subscription_as_num: u64 = subscription.parse().map_err(|_| ())?;

        // TODO: this is O(n)
        let (index, mut lock) = loop {
            if client_arc.dead.load(Ordering::SeqCst) {
                return Ok(());
            }

            let sleep_until = {
                let lock = client_arc.guarded.lock().await;

                // Two in one: check whether this subscription is indeed valid, and at the same
                // time get the messages capacity.
                // This is done at each iteration, to check whether the subscription is still
                // valid.
                let notifications_capacity =
                    match lock.active_subscriptions.get(&subscription_as_num) {
                        Some(l) => l.notifications_capacity,
                        None => return Ok(()),
                    };

                let control_flow = lock
                    .notification_messages
                    .range(
                        (subscription_as_num, usize::min_value())
                            ..=(subscription_as_num, usize::max_value()),
                    )
                    .map(|((_, idx), _)| *idx)
                    .try_fold(0, |maybe_free_index, index| {
                        if maybe_free_index == index {
                            ops::ControlFlow::Continue(index + 1)
                        } else {
                            ops::ControlFlow::Break(maybe_free_index)
                        }
                    });
                match control_flow {
                    ops::ControlFlow::Break(idx) => {
                        debug_assert!(idx < notifications_capacity);
                        break (idx, lock);
                    }
                    ops::ControlFlow::Continue(idx) if idx < notifications_capacity => {
                        break (idx, lock)
                    }
                    ops::ControlFlow::Continue(_) if try_only => return Err(()),
                    ops::ControlFlow::Continue(_) => {
                        lock.notification_messages_popped_or_dead.listen()
                    }
                }
            };

            sleep_until.await;
        };

        // Inserts or replaces the current value under the key `(subscription, index)`.
        let _previous_message = lock
            .notification_messages
            .insert((subscription_as_num, index), message);
        debug_assert!(_previous_message.is_none());

        // Add an entry in `responses_send_back`.
        lock.responses_send_back
            .push_back(ResponseSendBack::SubscriptionMessage(
                subscription_as_num,
                index,
            ));
        lock.responses_send_back_pushed_or_dead.notify_additional(1);

        Ok(())
    }
}

/// Returned by [`RequestsSubscriptions::start_subscription`] when a subscription is ready to be
/// started.
// TODO: cancel the subscription if the object is dropped before start() is called
#[must_use = "Subscriptions don't start until a task has been registered"]
pub struct SubscriptionStart<'a, TSubMsg> {
    requests_subscriptions: &'a RequestsSubscriptions<TSubMsg>,

    /// Allocated identifier of the client and subscription. `None` if this is a dummy and no
    /// subscription should actually be started because the client is no longer valid.
    client_subscription: Option<(Arc<ClientInner<TSubMsg>>, u64)>,
}

impl<'a, TSubMsg: Send + Sync + 'static> SubscriptionStart<'a, TSubMsg> {
    /// Starts the subscription.
    ///
    /// Note that the task doesn't run automatically. Instead,
    /// [`RequestsSubscriptions::run_subscription_task`] must be called.
    pub fn start(self, task: impl Future<Output = ()> + Send + 'static) {
        let Some((client_arc, subscription_id)) = self.client_subscription else { return };

        // Augment the task by adding at the end some code that cleans up this subscription from
        // the state machine.
        // Note that there is no future cancellation concerns here, as the task is always
        // guaranteed to be resumed at some point (unless the whole state machine is destroyed).
        let wrapped_task = {
            let max_subscriptions_per_client =
                self.requests_subscriptions.max_subscriptions_per_client;

            async move {
                task.await;

                // TODO: review this code now that subscription shut down gracefully instead of abruptly
                let mut lock = client_arc.guarded.lock().await;

                if lock.active_subscriptions.remove(&subscription_id).is_none() {
                    return;
                }

                if lock
                    .notification_messages
                    .range(
                        (subscription_id, usize::min_value())
                            ..=(subscription_id, usize::max_value()),
                    )
                    .next()
                    .is_some()
                {
                    lock.num_inactive_alive_subscriptions += 1;
                    debug_assert!(
                        lock.num_inactive_alive_subscriptions <= max_subscriptions_per_client
                    );
                }

                lock.notification_messages_popped_or_dead
                    .notify_relaxed(usize::max_value());

                debug_assert!(
                    lock.active_subscriptions.len() + lock.num_inactive_alive_subscriptions
                        <= max_subscriptions_per_client
                );
            }
        };

        self.requests_subscriptions
            .subscriptions_tasks
            .push(Box::pin(wrapped_task));
    }
}

impl<'a, TSubMsg> fmt::Debug for SubscriptionStart<'a, TSubMsg> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SubscriptionStart").finish()
    }
}

/// Provided when a subscription is started. Allows receiving the messages that were sent using
/// [`RequestsSubscriptions::subscription_send`].
pub struct MessagesReceiver<TSubMsg> {
    rx: mpsc::Receiver<(TSubMsg, oneshot::Sender<()>)>,
}

impl<TSubMsg> MessagesReceiver<TSubMsg> {
    /// Waits for the next message to be available.
    ///
    /// A [`ConfirmationSend`] is provided alongside with the message.
    /// If [`ConfirmationSend::send`] is called, then [`RequestsSubscriptions::subscription_send`]
    /// will return `Ok`. If, however, the object is dropped without [`ConfirmationSend::send`]
    /// being called, then it will return an `Err`.
    ///
    /// # Panic
    ///
    /// Panics if the task corresponding to the subscription has ended. This can never happen if
    /// you use the [`MessagesReceiver`] within the subscription's task, as is intended.
    ///
    pub async fn next(&mut self) -> (TSubMsg, ConfirmationSend) {
        // The channel can never be closed in normal situations, as the sender is kept in the list
        // of subscriptions and this list of subscriptions is only cleaned up.
        let (msg, tx) = futures_util::StreamExt::next(&mut self.rx).await.unwrap();
        (msg, ConfirmationSend { tx })
    }
}

impl<TSubMsg> fmt::Debug for MessagesReceiver<TSubMsg> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("MessagesReceiver").finish()
    }
}

/// Provided by the [`MessagesReceiver`] in the context of a subscription receiving a message.
///
/// If [`ConfirmationSend::send`] is called, then [`RequestsSubscriptions::subscription_send`]
/// will return `Ok`. If, however, the object is dropped without [`ConfirmationSend::send`] being
/// called, then it will return an `Err`.
#[must_use]
pub struct ConfirmationSend {
    tx: oneshot::Sender<()>,
}

impl ConfirmationSend {
    /// Sends the confirmation.
    pub fn send(self) {
        let _ = self.tx.send(());
    }
}

impl fmt::Debug for ConfirmationSend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ConfirmationSend").finish()
    }
}

/// Error returned by [`RequestsSubscriptions::try_queue_client_request`].
#[derive(Debug, derive_more::Display, Clone)]
#[display(fmt = "Queue of unpulled requests full")]
pub struct TryQueueClientRequestError {
    /// Original request, passed as parameter to the function.
    pub request: String,
}

/// Error returned by [`RequestsSubscriptions::add_client`] and
/// [`RequestsSubscriptions::add_client_mut`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum AddClientError {
    /// Reached maximum number of allowed clients.
    LimitReached,
}

/// Error returned by [`RequestsSubscriptions::start_subscription`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum StartSubscriptionError {
    /// Reached maximum number of subscriptions allowed per user.
    LimitReached,
}

struct Clients<TSubMsg> {
    /// Actual list of all the clients currently part of the state machine.
    list: hashbrown::HashMap<u64, Arc<ClientInner<TSubMsg>>, fnv::FnvBuildHasher>,

    /// Identifier to assign to the next client. Always increasing. Ids are never reused.
    next_id: u64,
}

struct ClientInner<TSubMsg> {
    /// Fields that are behind a `Mutex`.
    guarded: Mutex<ClientInnerGuarded<TSubMsg>>,

    /// Set to `true` whenever the client is removed.
    dead: AtomicBool,

    /// Total number of requests that are either unpulled, pending, or whose response is queued.
    ///
    /// In other words, this is the number of requests that have been injected in this state
    /// machine but not fully processed yet. They can be in one of
    /// [`RequestsSubscriptions::unpulled_requests`], [`ClientInnerGuarded::pending_requests`],
    /// or [`ClientInnerGuarded::responses_send_back`].
    ///
    /// Due to the racy nature of everything, a request might have increased the counter here but
    /// not be present yet in [`RequestsSubscriptions::unpulled_requests`].
    total_requests_in_fly: AtomicUsize,

    /// One listener is notified every time [`ClientInner::total_requests_in_fly`] is decremented.
    ///
    /// Note that the notification is done *after* the decrementation.
    ///
    /// All listeners are also notified when [`ClientInner::dead`] is set to `true`.
    total_requests_in_fly_dec_or_dead: event_listener::Event,
}

struct ClientInnerGuarded<TSubMsg> {
    /// List of requests that have been pulled by [`RequestsSubscriptions::next_request`] and
    /// waiting to be responded.
    ///
    /// A FNV hasher is used because the keys of this map are allocated locally.
    pending_requests: hashbrown::HashSet<u64, fnv::FnvBuildHasher>,

    /// Queue of responses to regular requests to send back to the client.
    ///
    /// It is critical that this list is bounded, in order to prevent malicious clients from
    /// DoS-attacking the machine by consuming all its available memory. This list is not
    /// explicitly bounded by its type, but it is bounded thanks to the logic within this module.
    ///
    /// In practice, the number of elements never exceeds
    /// `max_requests_per_client + sum(notification_capacity)`. This can't be verified by a debug
    /// assertion, because `notification_capacity` might refer to the capacity of subscriptions
    /// that have been stopped and whose capacity is no longer tracked.
    responses_send_back: VecDeque<ResponseSendBack>,

    /// Every time an entry is pushed on [`ClientInnerGuarded::responses_send_back`], one listener
    /// of this event is notified.
    ///
    /// All listeners are also notified when [`ClientInner::dead`] is set to `true`.
    responses_send_back_pushed_or_dead: event_listener::Event,

    /// List of notification messages to send back to the client.
    ///
    /// Each entry in this map also always has a corresponding entry in
    /// [`ClientInnerGuarded::responses_send_back`].
    notification_messages: BTreeMap<(u64, usize), String>,

    /// Every time an entry is removed from [`ClientInnerGuarded::notification_messages`], one
    /// listener of this event is notified.
    ///
    /// All listeners are also notified when [`ClientInner::dead`] is set to `true` and when
    /// a subscription is removed from [`ClientInnerGuarded::active_subscriptions`].
    notification_messages_popped_or_dead: event_listener::Event,

    /// List of active subscriptions. In other words, subscriptions that have been started but
    /// whose task haven't stopped yet.
    ///
    /// This doesn't include subscriptions that have been stopped but still have some entries in
    /// the list of messages.
    ///
    /// For each subscription, contains the maximum number of notifications that can be queued
    /// at the same time for this subscription.
    ///
    /// A FNV hasher is used because the keys of this map are allocated locally.
    active_subscriptions: hashbrown::HashMap<u64, Subscription<TSubMsg>, fnv::FnvBuildHasher>,

    /// Returns the number of subscriptions that have been stopped but still have at least one
    /// entry in [`ClientInnerGuarded::notification_messages`] (and thus also in
    /// [`ClientInnerGuarded::responses_send_back`]).
    num_inactive_alive_subscriptions: usize,
}

enum ResponseSendBack {
    /// Message to send back is a response to a request. Pulling out this message decrements
    /// [`ClientInner::total_requests_in_fly`].
    Response(String),

    /// Message to send back is a subscription notification. It can be found in
    /// [`ClientInnerGuarded::notification_messages`] at the given key.
    SubscriptionMessage(u64, usize),
}

struct Subscription<TSubMsg> {
    /// Maximum number of notifications towards the client queued at any given time.
    notifications_capacity: usize,

    /// Sender for messages towards the subscription task. Connected to the receiver that was
    /// provided to the API user when the subscription was created.
    messages_tx: mpsc::Sender<(TSubMsg, oneshot::Sender<()>)>,
}

// Common traits derivation on the id types.
macro_rules! traits_impl {
    ($ty:ty) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_tuple(stringify!($ty)).finish()
            }
        }

        impl cmp::PartialEq for $ty {
            fn eq(&self, other: &$ty) -> bool {
                self.0 == other.0
            }
        }

        impl cmp::Eq for $ty {}

        impl cmp::PartialOrd for $ty {
            fn partial_cmp(&self, other: &$ty) -> Option<cmp::Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }

        impl cmp::Ord for $ty {
            fn cmp(&self, other: &$ty) -> cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl hash::Hash for $ty {
            fn hash<H>(&self, state: &mut H)
            where
                H: hash::Hasher,
            {
                hash::Hash::hash(&self.0, state)
            }
        }
    };
}

traits_impl!(ClientId);
traits_impl!(RequestId);
