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
//! When a client is removed, dummy JSON-RPC requests are added to the stream of requests that
//! unsubscribe from the subscriptions that this client was maintaining.
//!
//! The [`ClientsMultiplexer`] will silently discard or merge notifications insert through
//! [`ClientsMultiplexer::TODO`] in order to guarantee a bound to the maximum number to the memory
//! usage in situations where a client doesn't pull responses quickly enough.
//!
//! When a client sends a `chainHead_unstable_follow` JSON-RPC request, the [`ClientsMultiplexer`]
//! will let it pass through, no matter how many other existing `chainHead_unstable_follow`
//! subscriptions exist. However, because there exists a limit to the maximum number of
//! `chainHead_unstable_follow` subscriptions, the server might return `null` to indicate that
//! this limit has been reached. When that happens, the [`ClientsMultiplexer`] will use the same
//! server-side `chainHead_unstable_follow` subscription to feed to multiple clients.

use alloc::collections::VecDeque;

use crate::util::SipHasherBuild;

/// Identifier of a client within the [`ClientsMultiplexer`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(usize);

pub struct ClientsMultiplexer<T> {
    clients: slab::Slab<Client<T>>,
}

struct Client<T> {
    /// `true` if [`JsonRpcClientSanitizer::close`] has been called.
    is_closed: bool,

    /// Queue of client-to-server JSON-RPC requests.
    requests_queue: VecDeque<String>,

    /// For each request ID (encoded as JSON), the in-progress requests with that ID.
    ///
    /// The vast majority of the time there will only be one entry, but there's in principle
    /// nothing illegal in having multiple requests with the same ID.
    requests_in_progress:
        hashbrown::HashMap<String, smallvec::SmallVec<[InProgressRequest; 1]>, SipHasherBuild>,

    active_subscriptions: hashbrown::HashMap<String, Subscription, SipHasherBuild>,

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

    /// User data decided by the API user.
    user_data: T,
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
    pub fn new() -> Self {
        todo!()
    }
}
