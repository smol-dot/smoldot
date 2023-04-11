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

use super::{Background, Platform, SubscriptionMessage};

use crate::transactions_service;

use alloc::{borrow::ToOwned as _, str, string::ToString as _, sync::Arc, vec::Vec};
use futures::prelude::*;
use smoldot::json_rpc::{self, methods, requests_subscriptions};

impl<TPlat: Platform> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::author_pendingExtrinsics`].
    pub(super) async fn author_pending_extrinsics(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
    ) {
        // Because multiple different chains ("chain" in the context of the public API of smoldot)
        // might share the same transactions service, it could be possible for chain A to submit
        // a transaction and then for chain B to read it by calling `author_pendingExtrinsics`.
        // This would make it possible for the API user of chain A to be able to communicate with
        // the API user of chain B. While the implications of permitting this are unclear, it is
        // not a bad idea to prevent this communication from happening. Consequently, we always
        // return an empty list of pending extrinsics.
        self.requests_subscriptions
            .respond(
                request_id.1,
                methods::Response::author_pendingExtrinsics(Vec::new())
                    .to_json_response(request_id.0),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::author_submitExtrinsic`].
    pub(super) async fn author_submit_extrinsic(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        transaction: methods::HexString,
    ) {
        // Note that this function is misnamed. It should really be called
        // "author_submitTransaction".

        // In Substrate, `author_submitExtrinsic` returns the hash of the transaction. It
        // is unclear whether it has to actually be the hash of the transaction or if it
        // could be any opaque value. Additionally, there isn't any other JSON-RPC method
        // that accepts as parameter the value returned here. When in doubt, we return
        // the hash as well.

        let mut hash_context = blake2_rfc::blake2b::Blake2b::new(32);
        hash_context.update(&transaction.0);
        let mut transaction_hash: [u8; 32] = Default::default();
        transaction_hash.copy_from_slice(hash_context.finalize().as_bytes());
        self.transactions_service
            .submit_transaction(transaction.0)
            .await;
        self.requests_subscriptions
            .respond(
                request_id.1,
                methods::Response::author_submitExtrinsic(methods::HashHexString(transaction_hash))
                    .to_json_response(request_id.0),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::author_unwatchExtrinsic`].
    pub(super) async fn author_unwatch_extrinsic(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                subscription,
                SubscriptionMessage::StopIfTransactionLegacy {
                    stop_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if stop_message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::author_unwatchExtrinsic(false)
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::author_submitAndWatchExtrinsic`] (if `is_legacy`
    /// is `true`) or to [`methods::MethodCall::transaction_unstable_submitAndWatch`] (if
    /// `is_legacy` is `false`).
    pub(super) async fn submit_and_watch_transaction(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        transaction: methods::HexString,
        is_legacy: bool,
    ) {
        let (subscription_id, mut messages_rx, subscription_start) = match self
            .requests_subscriptions
            .start_subscription(request_id.1, 16)
            .await
        {
            Ok(v) => v,
            Err(requests_subscriptions::StartSubscriptionError::LimitReached) => {
                self.requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                "Too many active subscriptions",
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        subscription_start.start({
            let mut transaction_updates = self
                .transactions_service
                .submit_and_watch_transaction(transaction.0, 16)
                .await;
            let requests_subscriptions = self.requests_subscriptions.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());

            async move {
                requests_subscriptions
                    .respond(
                        &request_id.1,
                        if is_legacy {
                            methods::Response::author_submitAndWatchExtrinsic(
                                (&subscription_id).into(),
                            )
                            .to_json_response(&request_id.0)
                        } else {
                            methods::Response::transaction_unstable_submitAndWatch(
                                (&subscription_id).into(),
                            )
                            .to_json_response(&request_id.0)
                        },
                    )
                    .await;

                let mut included_block = None;
                let mut num_broadcasted_peers = 0;

                // TODO: doesn't reported `validated` events

                let requests_subscriptions = Arc::downgrade(&requests_subscriptions);

                loop {
                    let event = {
                        let next_message = messages_rx.next();
                        futures::pin_mut!(next_message);
                        match future::select(transaction_updates.next(), next_message).await {
                            future::Either::Left((v, _)) => either::Left(v),
                            future::Either::Right((v, _)) => either::Right(v),
                        }
                    };

                    let requests_subscriptions = match requests_subscriptions.upgrade() {
                        Some(rs) => rs,
                        None => return,
                    };

                    let status_update = match event {
                        either::Left(Some(status)) => status,
                        either::Left(None) if !is_legacy => {
                            // Channel from the transactions service has been closed.
                            // Stop the task.
                            break;
                        }
                        either::Left(None) => {
                            // Channel from the transactions service has been closed.
                            // Stop the task.
                            // There is nothing more that can be done except hope that the
                            // client understands that no new notification is expected and
                            // unsubscribes.
                            break loop {
                                let next_message = messages_rx.next();
                                futures::pin_mut!(next_message);
                                if let (
                                    SubscriptionMessage::StopIfTransactionLegacy {
                                        stop_request_id,
                                    },
                                    confirmation_sender,
                                ) = next_message.await
                                {
                                    requests_subscriptions
                                        .respond(
                                            &stop_request_id.1,
                                            methods::Response::author_unwatchExtrinsic(true)
                                                .to_json_response(&stop_request_id.0),
                                        )
                                        .await;

                                    confirmation_sender.send();
                                    break;
                                }
                            };
                        }
                        either::Right((
                            SubscriptionMessage::StopIfTransaction { stop_request_id },
                            confirmation_sender,
                        )) if !is_legacy => {
                            requests_subscriptions
                                .respond(
                                    &stop_request_id.1,
                                    methods::Response::transaction_unstable_unwatch(())
                                        .to_json_response(&stop_request_id.0),
                                )
                                .await;

                            confirmation_sender.send();
                            break;
                        }
                        either::Right((
                            SubscriptionMessage::StopIfTransactionLegacy { stop_request_id },
                            confirmation_sender,
                        )) if is_legacy => {
                            requests_subscriptions
                                .respond(
                                    &stop_request_id.1,
                                    methods::Response::author_unwatchExtrinsic(true)
                                        .to_json_response(&stop_request_id.0),
                                )
                                .await;

                            confirmation_sender.send();
                            break;
                        }
                        either::Right(_) => {
                            // Silently discard the message.
                            continue;
                        }
                    };

                    let update = match (status_update, is_legacy) {
                        (transactions_service::TransactionStatus::Broadcast(peers), false) => {
                            methods::ServerToClient::author_extrinsicUpdate {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionStatus::Broadcast(
                                    peers.into_iter().map(|peer| peer.to_base58()).collect(),
                                ),
                            }
                            .to_json_call_object_parameters(None)
                        }
                        (transactions_service::TransactionStatus::Broadcast(peers), true) => {
                            num_broadcasted_peers += peers.len();
                            methods::ServerToClient::transaction_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::Broadcasted {
                                    num_peers: u32::try_from(num_broadcasted_peers)
                                        .unwrap_or(u32::max_value()),
                                },
                            }
                            .to_json_call_object_parameters(None)
                        }

                        (
                            transactions_service::TransactionStatus::IncludedBlockUpdate {
                                block_hash: Some((block_hash, _)),
                            },
                            true,
                        ) => {
                            included_block = Some(block_hash);
                            methods::ServerToClient::author_extrinsicUpdate {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionStatus::InBlock(
                                    methods::HashHexString(block_hash),
                                ),
                            }
                            .to_json_call_object_parameters(None)
                        }
                        (
                            transactions_service::TransactionStatus::IncludedBlockUpdate {
                                block_hash: None,
                            },
                            true,
                        ) => {
                            if let Some(block_hash) = included_block.take() {
                                methods::ServerToClient::author_extrinsicUpdate {
                                    subscription: (&subscription_id).into(),
                                    result: methods::TransactionStatus::Retracted(
                                        methods::HashHexString(block_hash),
                                    ),
                                }
                                .to_json_call_object_parameters(None)
                            } else {
                                continue;
                            }
                        }
                        (
                            transactions_service::TransactionStatus::IncludedBlockUpdate {
                                block_hash: Some((block_hash, index)),
                            },
                            false,
                        ) => {
                            included_block = Some(block_hash);
                            methods::ServerToClient::transaction_unstable_watchEvent {
                                subscription: (&subscription_id).into(),
                                result: methods::TransactionWatchEvent::BestChainBlockIncluded {
                                    block: Some(methods::TransactionWatchEventBlock {
                                        hash: methods::HashHexString(block_hash),
                                        index: methods::NumberAsString(index),
                                    }),
                                },
                            }
                            .to_json_call_object_parameters(None)
                        }
                        (
                            transactions_service::TransactionStatus::IncludedBlockUpdate {
                                block_hash: None,
                            },
                            false,
                        ) => methods::ServerToClient::transaction_unstable_watchEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionWatchEvent::BestChainBlockIncluded {
                                block: None,
                            },
                        }
                        .to_json_call_object_parameters(None),

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
                        ) => methods::ServerToClient::author_extrinsicUpdate {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionStatus::Dropped,
                        }
                        .to_json_call_object_parameters(None),
                        (
                            transactions_service::TransactionStatus::Dropped(
                                transactions_service::DropReason::GapInChain,
                            ),
                            false,
                        ) => methods::ServerToClient::transaction_unstable_watchEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionWatchEvent::Dropped {
                                error: "gap in chain of blocks".into(),
                                broadcasted: num_broadcasted_peers != 0,
                            },
                        }
                        .to_json_call_object_parameters(None),
                        (
                            transactions_service::TransactionStatus::Dropped(
                                transactions_service::DropReason::MaxPendingTransactionsReached,
                            ),
                            false,
                        ) => methods::ServerToClient::transaction_unstable_watchEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionWatchEvent::Dropped {
                                error: "transactions pool full".into(),
                                broadcasted: num_broadcasted_peers != 0,
                            },
                        }
                        .to_json_call_object_parameters(None),
                        (
                            transactions_service::TransactionStatus::Dropped(
                                transactions_service::DropReason::Invalid(error),
                            ),
                            false,
                        ) => methods::ServerToClient::transaction_unstable_watchEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionWatchEvent::Invalid {
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_call_object_parameters(None),
                        (
                            transactions_service::TransactionStatus::Dropped(
                                transactions_service::DropReason::ValidateError(error),
                            ),
                            false,
                        ) => methods::ServerToClient::transaction_unstable_watchEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionWatchEvent::Error {
                                error: error.to_string().into(),
                            },
                        }
                        .to_json_call_object_parameters(None),

                        (
                            transactions_service::TransactionStatus::Dropped(
                                transactions_service::DropReason::Finalized { block_hash, .. },
                            ),
                            true,
                        ) => methods::ServerToClient::author_extrinsicUpdate {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionStatus::Finalized(methods::HashHexString(
                                block_hash,
                            )),
                        }
                        .to_json_call_object_parameters(None),
                        (
                            transactions_service::TransactionStatus::Dropped(
                                transactions_service::DropReason::Finalized { block_hash, index },
                            ),
                            false,
                        ) => methods::ServerToClient::transaction_unstable_watchEvent {
                            subscription: (&subscription_id).into(),
                            result: methods::TransactionWatchEvent::Finalized {
                                block: methods::TransactionWatchEventBlock {
                                    hash: methods::HashHexString(block_hash),
                                    index: methods::NumberAsString(index),
                                },
                            },
                        }
                        .to_json_call_object_parameters(None),
                    };

                    // TODO: handle situation where buffer is full
                    let _ = requests_subscriptions
                        .try_push_notification(&request_id.1, &subscription_id, update)
                        .await;
                }
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::transaction_unstable_unwatch`].
    pub(super) async fn transaction_unstable_unwatch(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription: &str,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                subscription,
                SubscriptionMessage::StopIfTransaction {
                    stop_request_id: (request_id.0.to_owned(), request_id.1.clone()),
                },
            )
            .await;

        // Send back a response manually if the task doesn't exist, or has discarded the message,
        // which could happen for example because there was already a stop message earlier in its
        // queue or because it was the wrong type of subscription.
        if stop_message_received.is_err() {
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::transaction_unstable_unwatch(())
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }
}
