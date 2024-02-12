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

//! All JSON-RPC method handlers that relate to transactions.

use super::{Background, PlatformRef};

use crate::transactions_service;

use alloc::{borrow::ToOwned as _, format, string::ToString as _, sync::Arc, vec::Vec};
use core::pin;
use futures_lite::future;
use smoldot::json_rpc::{methods, service};

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::author_submitAndWatchExtrinsic`] (if `is_legacy`
    /// is `true`) or to [`methods::MethodCall::transactionWatch_unstable_submitAndWatch`] (if
    /// `is_legacy` is `false`).
    pub(super) async fn submit_and_watch_transaction(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let (transaction, is_legacy) = match request.request() {
            methods::MethodCall::author_submitAndWatchExtrinsic { transaction } => {
                (transaction, true)
            }
            methods::MethodCall::transactionWatch_unstable_submitAndWatch { transaction } => {
                (transaction, false)
            }
            _ => unreachable!(),
        };

        self.platform
            .spawn_task(format!("{}-transaction-watch", self.log_target).into(), {
                let transaction_updates = self
                    .transactions_service
                    .submit_and_watch_transaction(transaction.0, 16)
                    .await;

                async move {
                    let mut transaction_updates = pin::pin!(transaction_updates);

                    let mut subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();

                    let mut included_block = None;
                    let mut num_broadcasted_peers = 0;

                    loop {
                        let status_update = match future::or(
                            async { Some(transaction_updates.as_mut().next().await) },
                            async { subscription.wait_until_stale().await; None }
                        ).await {
                            Some(Some(status)) => status,
                            Some(None) if !is_legacy => {
                                // Channel from the transactions service has been closed.
                                // Stop the task.
                                break;
                            }
                            Some(None) => {
                                // Channel from the transactions service has been closed.
                                // Stop the task.
                                // There is nothing more that can be done except hope that the
                                // client understands that no new notification is expected and
                                // unsubscribes.
                                subscription.wait_until_stale().await;
                                break;
                            }
                            None => break,
                        };

                        match (status_update, is_legacy) {
                            (transactions_service::TransactionStatus::Broadcast(peers), true) => {
                                subscription
                                    .send_notification(
                                        methods::ServerToClient::author_extrinsicUpdate {
                                            subscription: (&subscription_id).into(),
                                            result: methods::TransactionStatus::Broadcast(
                                                peers
                                                    .into_iter()
                                                    .map(|peer| peer.to_base58())
                                                    .collect(),
                                            ),
                                        },
                                    )
                                    .await;
                            }
                            (transactions_service::TransactionStatus::Broadcast(peers), false) => {
                                num_broadcasted_peers += peers.len();
                                subscription
                                    .send_notification(
                                        methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                            subscription: (&subscription_id).into(),
                                            result: methods::TransactionWatchEvent::Broadcasted {
                                                num_peers: u32::try_from(num_broadcasted_peers)
                                                    .unwrap_or(u32::max_value()),
                                            },
                                        },
                                    )
                                    .await;
                            }

                            (transactions_service::TransactionStatus::Validated, true) => {
                                continue;
                            }
                            (transactions_service::TransactionStatus::Validated, false) => {
                                subscription
                                    .send_notification(
                                        methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                            subscription: (&subscription_id).into(),
                                            result: methods::TransactionWatchEvent::Validated {},
                                        },
                                    )
                                    .await;
                            }

                            (
                                transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: Some((block_hash, _)),
                                },
                                true,
                            ) => {
                                included_block = Some(block_hash);
                                subscription
                                    .send_notification(
                                        methods::ServerToClient::author_extrinsicUpdate {
                                            subscription: (&subscription_id).into(),
                                            result: methods::TransactionStatus::InBlock(
                                                methods::HashHexString(block_hash),
                                            ),
                                        },
                                    )
                                    .await;
                            }
                            (
                                transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: None,
                                },
                                true,
                            ) => {
                                if let Some(block_hash) = included_block.take() {
                                    subscription
                                        .send_notification(
                                            methods::ServerToClient::author_extrinsicUpdate {
                                                subscription: (&subscription_id).into(),
                                                result: methods::TransactionStatus::Retracted(
                                                    methods::HashHexString(block_hash),
                                                ),
                                            },
                                        )
                                        .await;
                                }
                            }
                            (
                                transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: Some((block_hash, index)),
                                },
                                false,
                            ) => {
                                included_block = Some(block_hash);
                                subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
                                    result:
                                        methods::TransactionWatchEvent::BestChainBlockIncluded {
                                            block: Some(methods::TransactionWatchEventBlock {
                                                hash: methods::HashHexString(block_hash),
                                                index,
                                            }),
                                        },
                                }).await;
                            }
                            (
                                transactions_service::TransactionStatus::IncludedBlockUpdate {
                                    block_hash: None,
                                },
                                false,
                            ) => {
                                subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionWatchEvent::BestChainBlockIncluded {
                                        block: None,
                                    },
                                }).await
                            },

                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::GapInChain,
                                ),
                                true,
                            )
                            | (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::MaxPendingTransactionsReached,
                                ),
                                true,
                            )
                            | (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Invalid(_),
                                ),
                                true,
                            )
                            | (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::ValidateError(_),
                                ),
                                true,
                            )
                            | (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Crashed,
                                ),
                                true,
                            ) => {
                                subscription.send_notification(methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionStatus::Dropped,
                                }).await;
                            },
                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::GapInChain,
                                ),
                                false,
                            ) => subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::Dropped {
                                    error: "gap in chain of blocks".into(),
                                    broadcasted: num_broadcasted_peers != 0,
                                },
                            }).await,
                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::MaxPendingTransactionsReached,
                                ),
                                false,
                            ) => subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::Dropped {
                                    error: "transactions pool full".into(),
                                    broadcasted: num_broadcasted_peers != 0,
                                },
                            }).await,
                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Invalid(error),
                                ),
                                false,
                            ) => subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::Invalid {
                                    error: error.to_string().into(),
                                },
                            }).await,
                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::ValidateError(error),
                                ),
                                false,
                            ) => subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::Error {
                                    error: error.to_string().into(),
                                },
                            }).await,
                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Crashed,
                                ),
                                false,
                            ) => subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::Error {
                                    error: "transactions service has crashed".into(),
                                },
                            }).await,

                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Finalized {
                                        block_hash, ..
                                    },
                                ),
                                true,
                            ) => subscription.send_notification(methods::ServerToClient::author_extrinsicUpdate {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionStatus::Finalized(
                                    methods::HashHexString(block_hash),
                                ),
                            }).await,
                            (
                                transactions_service::TransactionStatus::Dropped(
                                    transactions_service::DropReason::Finalized {
                                        block_hash,
                                        index,
                                    },
                                ),
                                false,
                            ) => subscription.send_notification(methods::ServerToClient::transactionWatch_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::Finalized {
                                    block: methods::TransactionWatchEventBlock {
                                        hash: methods::HashHexString(block_hash),
                                        index,
                                    },
                                },
                            }).await,
                        }
                    }
                }
            });
    }
}
