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

//! Background JSON-RPC service.
//!
//! # Usage
//!
//! Create a new JSON-RPC service by calling [`service`] then [`ServicePrototype::start`].
//! Creating a JSON-RPC service spawns a background task (through [`StartConfig::tasks_executor`])
//! dedicated to processing JSON-RPC requests.
//!
//! In order to process a JSON-RPC request, call [`Frontend::queue_rpc_request`]. Later, the
//! JSON-RPC service can queue a response or, in the case of subscriptions, a notification. They
//! can be retrieved by calling [`Frontend::next_json_rpc_response`].
//!
//! In the situation where an attacker finds a JSON-RPC request that takes a long time to be
//! processed and continuously submits this same expensive request over and over again, the queue
//! of pending requests will start growing and use more and more memory. For this reason, if this
//! queue grows past [`Config::max_pending_requests`] items, [`Frontend::queue_rpc_request`]
//! will instead return an error.
//!

// TODO: doc
// TODO: re-review this once finished

mod background;

use crate::{
    network_service, platform::Platform, runtime_service, sync_service, transactions_service,
};

use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::num::NonZeroU32;
use futures::prelude::*;
use smoldot::{
    chain_spec,
    json_rpc::{self, requests_subscriptions},
    libp2p::PeerId,
};

/// Configuration for [`service`].
pub struct Config {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Maximum number of JSON-RPC requests that can be added to a queue if it is not ready to be
    /// processed immediately. Any additional request will be immediately rejected.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    pub max_pending_requests: NonZeroU32,

    /// Maximum number of active subscriptions. Any additional subscription will be immediately
    /// rejected.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    pub max_subscriptions: u32,

    /// Maximum number of JSON-RPC requests that can be processed simultaneously.
    ///
    /// This parameter is necessary in order to prevent users from using up too much memory within
    /// the client.
    pub max_parallel_requests: NonZeroU32,

    /// Maximum number of subscriptions that can be processed simultaneously.
    ///
    /// In combination with [`Config::max_parallel_requests`], this can increase or decrease
    /// the priority of updating subscriptions compared to answering requests.
    pub max_parallel_subscription_updates: NonZeroU32,
}

/// Creates a new JSON-RPC service with the given configuration.
///
/// Returns a handler that allows sending requests, and a [`ServicePrototype`] that must later
/// be initialized using [`ServicePrototype::start`].
///
/// Destroying the [`Frontend`] automatically shuts down the service.
pub fn service(config: Config) -> (Frontend, ServicePrototype) {
    let mut requests_subscriptions =
        requests_subscriptions::RequestsSubscriptions::new(requests_subscriptions::Config {
            max_clients: 1,
            max_requests_per_client: config.max_pending_requests,
            max_subscriptions_per_client: config.max_subscriptions,
        });

    let client_id = requests_subscriptions.add_client_mut().unwrap(); // Adding a client can fail only if the limit is reached.
    let requests_subscriptions = Arc::new(requests_subscriptions);

    let log_target = format!("json-rpc-{}", config.log_name);

    // We are later going to spawn a bunch of tasks. Each task is associated with an "abort
    // handle" that makes it possible to later abort it. We calculate here the number of handles
    // that are necessary.
    // This calculation must be in sync with the part of the code that spawns the tasks. Assertions
    // are there in order to make sure that this is the case.
    let num_handles =
        config.max_parallel_requests.get() + config.max_parallel_subscription_updates.get() + 1;

    let mut background_aborts = Vec::with_capacity(usize::try_from(num_handles).unwrap());
    let mut background_abort_registrations = Vec::with_capacity(background_aborts.capacity());
    for _ in 0..num_handles {
        let (abort, reg) = future::AbortHandle::new_pair();
        background_aborts.push(abort);
        background_abort_registrations.push(reg);
    }

    let frontend = Frontend {
        log_target: log_target.clone(),
        requests_subscriptions: requests_subscriptions.clone(),
        client_id,
        background_aborts: Arc::from(background_aborts),
    };

    let prototype = ServicePrototype {
        background_abort_registrations,
        log_target,
        requests_subscriptions,
        max_parallel_requests: config.max_parallel_requests,
        max_parallel_subscription_updates: config.max_parallel_subscription_updates,
    };

    (frontend, prototype)
}

/// Handle that allows sending JSON-RPC requests on the service.
///
/// The [`Frontend`] can be cloned, in which case the clone will refer to the same JSON-RPC
/// service.
///
/// Destroying all the [`Frontend`]s automatically shuts down the associated service.
#[derive(Clone)]
pub struct Frontend {
    /// State machine holding all the clients, requests, and subscriptions.
    ///
    /// Shared with the [`background`].
    requests_subscriptions:
        Arc<requests_subscriptions::RequestsSubscriptions<background::SubscriptionMessage>>,

    /// Identifier of the unique client within the [`Frontend::requests_subscriptions`].
    client_id: requests_subscriptions::ClientId,

    /// Target to use when emitting logs.
    log_target: String,

    /// Handles to abort the background tasks that hold and process the
    /// [`Frontend::requests_subscriptions`].
    background_aborts: Arc<[future::AbortHandle]>,
}

impl Frontend {
    /// Queues the given JSON-RPC request to be processed in the background.
    ///
    /// An error is returned if [`Config::max_pending_requests`] is exceeded, which can happen
    /// if the requests take a long time to process or if [`Frontend::next_json_rpc_response`]
    /// isn't called often enough. Use [`HandleRpcError::into_json_rpc_error`] to build the
    /// JSON-RPC response to immediately send back to the user.
    pub fn queue_rpc_request(&self, json_rpc_request: String) -> Result<(), HandleRpcError> {
        // If the request isn't even a valid JSON-RPC request, we can't even send back a response.
        // We have no choice but to immediately refuse the request.
        if let Err(error) = json_rpc::parse::parse_call(&json_rpc_request) {
            log::warn!(
                target: &self.log_target,
                "Refused malformed JSON-RPC request: {}", error
            );
            return Err(HandleRpcError::MalformedJsonRpc(error));
        }

        // Logging the request before it is queued.
        log::debug!(
            target: &self.log_target,
            "PendingRequestsQueue <= {}",
            crate::util::truncated_str(
                json_rpc_request.chars().filter(|c| !c.is_control()),
                100,
            )
        );

        match self
            .requests_subscriptions
            .try_queue_client_request(&self.client_id, json_rpc_request)
        {
            Ok(()) => Ok(()),
            Err(err) => {
                log::warn!(
                    target: &self.log_target,
                    "Request denied due to JSON-RPC service being overloaded. This will likely \
                    cause the JSON-RPC client to malfunction."
                );

                Err(HandleRpcError::Overloaded {
                    json_rpc_request: err.request,
                })
            }
        }
    }

    /// Waits until a JSON-RPC response has been generated, then returns it.
    ///
    /// If this function is called multiple times in parallel, the order in which the calls are
    /// responded to is unspecified.
    pub async fn next_json_rpc_response(&self) -> String {
        let message = self
            .requests_subscriptions
            .next_response(&self.client_id)
            .await;

        log::debug!(
            target: &self.log_target,
            "JSON-RPC <= {}",
            crate::util::truncated_str(
                message.chars().filter(|c| !c.is_control()),
                100,
            )
        );

        message
    }
}

impl Drop for Frontend {
    fn drop(&mut self) {
        // Call `abort()` if this was the last instance of the `Arc<AbortHandle>` (and thus the
        // last instance of `Frontend`).
        if let Some(background_aborts) = Arc::get_mut(&mut self.background_aborts) {
            for background_abort in background_aborts {
                background_abort.abort();
            }
        }
    }
}

/// Prototype for a JSON-RPC service. Must be initialized using [`ServicePrototype::start`].
pub struct ServicePrototype {
    /// State machine holding all the clients, requests, and subscriptions.
    ///
    /// Shared with the [`background`].
    requests_subscriptions:
        Arc<requests_subscriptions::RequestsSubscriptions<background::SubscriptionMessage>>,

    /// Target to use when emitting logs.
    log_target: String,

    /// Value obtained through [`Config::max_parallel_requests`].
    max_parallel_requests: NonZeroU32,

    /// Value obtained through [`Config::max_parallel_subscription_updates`].
    max_parallel_subscription_updates: NonZeroU32,

    /// List of abort handles. When tasks are spawned, each handle is associated with a task, so
    /// that they can all be aborted. See [`Frontend::background_aborts`].
    background_abort_registrations: Vec<future::AbortRegistration>,
}

/// Configuration for a JSON-RPC service.
pub struct StartConfig<'a, TPlat: Platform> {
    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, future::BoxFuture<'static, ()>) + Send>,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (Arc<network_service::NetworkService<TPlat>>, usize),

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Service responsible for emitting transactions and tracking their state.
    pub transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Service that provides a ready-to-be-called runtime for the current best block.
    pub runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Specification of the chain.
    pub chain_spec: &'a chain_spec::ChainSpec,

    /// Network identity of the node.
    pub peer_id: &'a PeerId,

    /// Value to return when the `system_name` RPC is called. Should be set to the name of the
    /// final executable.
    pub system_name: String,

    /// Value to return when the `system_version` RPC is called. Should be set to the version of
    /// the final executable.
    pub system_version: String,

    /// Hash of the genesis block of the chain.
    ///
    /// > **Note**: This can be derived from a [`chain_spec::ChainSpec`]. While the
    /// >           [`ServicePrototype::start`] function could in theory use the
    /// >           [`StartConfig::chain_spec`] parameter to derive this value, doing so is quite
    /// >           expensive. We prefer to require this value from the upper layer instead, as
    /// >           it is most likely needed anyway.
    pub genesis_block_hash: [u8; 32],

    /// Hash of the storage trie root of the genesis block of the chain.
    ///
    /// > **Note**: This can be derived from a [`chain_spec::ChainSpec`]. While the
    /// >           [`ServicePrototype::start`] function could in theory use the
    /// >           [`StartConfig::chain_spec`] parameter to derive this value, doing so is quite
    /// >           expensive. We prefer to require this value from the upper layer instead, as
    /// >           it is most likely needed anyway.
    pub genesis_block_state_root: [u8; 32],
}

impl ServicePrototype {
    /// Consumes this prototype and starts the service through [`StartConfig::tasks_executor`].
    pub fn start<TPlat: Platform>(self, config: StartConfig<'_, TPlat>) {
        background::start(
            self.log_target.clone(),
            self.requests_subscriptions.clone(),
            config,
            self.max_parallel_requests,
            self.max_parallel_subscription_updates,
            self.background_abort_registrations,
        )
    }
}

/// Error potentially returned when queuing a JSON-RPC request.
#[derive(Debug, derive_more::Display)]
pub enum HandleRpcError {
    /// The JSON-RPC service cannot process this request, as it is already too busy.
    #[display(
        fmt = "The JSON-RPC service cannot process this request, as it is already too busy."
    )]
    Overloaded {
        /// Request that was being queued.
        json_rpc_request: String,
    },
    /// The request isn't a valid JSON-RPC request.
    #[display(fmt = "The request isn't a valid JSON-RPC request: {_0}")]
    MalformedJsonRpc(json_rpc::parse::ParseError),
}

impl HandleRpcError {
    /// Builds the JSON-RPC error string corresponding to this error.
    ///
    /// Returns `None` if the JSON-RPC requests isn't valid JSON-RPC or if the call was a
    /// notification.
    pub fn into_json_rpc_error(self) -> Option<String> {
        let json_rpc_request = match self {
            HandleRpcError::Overloaded { json_rpc_request } => json_rpc_request,
            HandleRpcError::MalformedJsonRpc(_) => return None,
        };

        match json_rpc::parse::parse_call(&json_rpc_request) {
            Ok(json_rpc::parse::Call {
                id_json: Some(id), ..
            }) => Some(json_rpc::parse::build_error_response(
                id,
                json_rpc::parse::ErrorResponse::ServerError(-32000, "Too busy"),
                None,
            )),
            Ok(json_rpc::parse::Call { id_json: None, .. }) | Err(_) => None,
        }
    }
}
