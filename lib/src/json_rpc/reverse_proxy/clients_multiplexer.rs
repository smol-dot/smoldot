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

/// Identifier of a client within the [`ClientsMultiplexer`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(usize);

pub struct ClientsMultiplexer<T> {

}

impl<T> ClientsMultiplexer<T> {
    pub fn new() -> Self {
        todo!()
    }
}
