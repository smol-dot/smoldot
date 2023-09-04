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

use smol::stream::StreamExt as _;
use smoldot::json_rpc::{methods, parse, service};
use std::{
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    sync::Arc,
};

use crate::{
    consensus_service, database_thread, json_rpc_service::legacy_api_subscriptions,
    network_service, LogCallback, LogLevel,
};

pub struct Config {
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// `chainHead_unstable_follow` subscription start handle.
    pub chain_head_follow_subscription: service::SubscriptionStartProcess,

    /// Parameter that was passed by the user when requesting `chainHead_unstable_follow`.
    pub with_runtime: bool,

    /// Consensus service of the chain.
    pub consensus_service: Arc<consensus_service::ConsensusService>,

    /// Database to access blocks.
    pub database: Arc<database_thread::DatabaseThread>,
}

/// Spawns a new tasks dedicated to handling a `chainHead_unstable_follow` subscription.
pub fn spawn_chain_head_subscription_task(mut config: Config) {
    let tasks_executor = config.tasks_executor.clone();
    tasks_executor(Box::pin(async move {
        let mut json_rpc_subscription = config.chain_head_follow_subscription.accept();
        let json_rpc_subscription_id = json_rpc_subscription.subscription_id().to_owned();

        let consensus_service_subscription = config
            .consensus_service
            .subscribe_all(32, NonZeroUsize::new(32).unwrap())
            .await;

        json_rpc_subscription
            .send_notification(methods::ServerToClient::chainHead_unstable_followEvent {
                subscription: (&json_rpc_subscription_id).into(),
                result: methods::FollowEvent::Initialized {
                    finalized_block_hash: methods::HashHexString(
                        consensus_service_subscription.finalized_block_hash,
                    ),
                    finalized_block_runtime: if config.with_runtime {
                        Some(todo!()) // TODO:
                    } else {
                        None
                    },
                },
            })
            .await;

        for block in consensus_service_subscription.non_finalized_blocks_ancestry_order {}

        loop {
            match consensus_service_subscription.new_blocks.next().await {}
        }
    }));
}
