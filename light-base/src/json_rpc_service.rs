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
//! Create a new JSON-RPC service by calling [`service()`] then [`ServicePrototype::start`].
//! Creating a JSON-RPC service spawns a background task (through [`PlatformRef::spawn_task`])
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
    network_service, platform::PlatformRef, runtime_service, sync_service, transactions_service,
};

use alloc::{
    format,
    string::{String, ToString as _},
    sync::Arc,
};
use core::num::NonZeroU32;
use smoldot::{chain_spec, json_rpc::service};

/// Configuration for [`service()`].
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
}

/// Creates a new JSON-RPC service with the given configuration.
///
/// Returns a handler that allows sending requests, and a [`ServicePrototype`] that must later
/// be initialized using [`ServicePrototype::start`].
///
/// Destroying the [`Frontend`] automatically shuts down the service.
pub fn service(config: Config) -> (Frontend, ServicePrototype) {
    let log_target = format!("json-rpc-{}", config.log_name);

    let (requests_processing_task, requests_responses_io) =
        service::client_main_task(service::Config {
            max_active_subscriptions: config.max_subscriptions,
            max_pending_requests: config.max_pending_requests,
        });

    let frontend = Frontend {
        log_target: log_target.clone(),
        requests_responses_io: Arc::new(requests_responses_io),
    };

    let prototype = ServicePrototype {
        log_target,
        requests_processing_task,
        max_parallel_requests: config.max_parallel_requests,
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
    /// Sending requests and receiving responses.
    ///
    /// Connected to the [`background`].
    requests_responses_io: Arc<service::SerializedRequestsIo>,

    /// Target to use when emitting logs.
    log_target: String,
}

impl Frontend {
    /// Queues the given JSON-RPC request to be processed in the background.
    ///
    /// An error is returned if [`Config::max_pending_requests`] is exceeded, which can happen
    /// if the requests take a long time to process or if [`Frontend::next_json_rpc_response`]
    /// isn't called often enough.
    pub fn queue_rpc_request(&self, json_rpc_request: String) -> Result<(), HandleRpcError> {
        let log_friendly_request =
            crate::util::truncated_str(json_rpc_request.chars().filter(|c| !c.is_control()), 250)
                .to_string();

        match self
            .requests_responses_io
            .try_send_request(json_rpc_request)
        {
            Ok(()) => {
                log::debug!(
                    target: &self.log_target,
                    "JSON-RPC => {}",
                    log_friendly_request
                );
                Ok(())
            }
            Err(service::TrySendRequestError {
                cause: service::TrySendRequestErrorCause::TooManyPendingRequests,
                request,
            }) => Err(HandleRpcError::TooManyPendingRequests {
                json_rpc_request: request,
            }),
            Err(service::TrySendRequestError {
                cause: service::TrySendRequestErrorCause::ClientMainTaskDestroyed,
                ..
            }) => unreachable!(),
        }
    }

    /// Waits until a JSON-RPC response has been generated, then returns it.
    ///
    /// If this function is called multiple times in parallel, the order in which the calls are
    /// responded to is unspecified.
    pub async fn next_json_rpc_response(&self) -> String {
        let message = match self.requests_responses_io.wait_next_response().await {
            Ok(m) => m,
            Err(service::WaitNextResponseError::ClientMainTaskDestroyed) => unreachable!(),
        };

        log::debug!(
            target: &self.log_target,
            "JSON-RPC <= {}",
            crate::util::truncated_str(
                message.chars().filter(|c| !c.is_control()),
                250,
            )
        );

        message
    }
}

/// Prototype for a JSON-RPC service. Must be initialized using [`ServicePrototype::start`].
pub struct ServicePrototype {
    /// Task processing the requests.
    ///
    /// Later sent to the [`background`].
    requests_processing_task: service::ClientMainTask,

    /// Target to use when emitting logs.
    log_target: String,

    /// Value obtained through [`Config::max_parallel_requests`].
    max_parallel_requests: NonZeroU32,
}

/// Configuration for a JSON-RPC service.
pub struct StartConfig<'a, TPlat: PlatformRef> {
    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Access to the network, and identifier of the chain from the point of view of the network
    /// service.
    pub network_service: Arc<network_service::NetworkServiceChain<TPlat>>,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Service responsible for emitting transactions and tracking their state.
    pub transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,

    /// Service that provides a ready-to-be-called runtime for the current best block.
    pub runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Specification of the chain.
    pub chain_spec: &'a chain_spec::ChainSpec,

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
    /// Consumes this prototype and starts the service through [`PlatformRef::spawn_task`].
    pub fn start<TPlat: PlatformRef>(self, config: StartConfig<'_, TPlat>) {
        background::start(
            self.log_target.clone(),
            config,
            self.requests_processing_task,
            self.max_parallel_requests,
        )
    }
}

/// Error potentially returned when queuing a JSON-RPC request.
#[derive(Debug, derive_more::Display)]
pub enum HandleRpcError {
    /// The JSON-RPC service cannot process this request, as too many requests are already being
    /// processed.
    #[display(
        fmt = "The JSON-RPC service cannot process this request, as too many requests are already being processed."
    )]
    TooManyPendingRequests {
        /// Request that was being queued.
        json_rpc_request: String,
    },
}
