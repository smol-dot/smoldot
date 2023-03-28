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

//! All legacy JSON-RPC method handlers that relate to the chain or the storage.

use super::{Background, Platform, SubscriptionMessage};

use crate::runtime_service;

use alloc::{
    borrow::ToOwned as _,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    iter,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use futures::{lock::MutexGuard, prelude::*};
use smoldot::{
    header,
    informant::HashDisplay,
    json_rpc::{self, methods, requests_subscriptions},
    network::protocol,
};

mod sub_utils;

impl<TPlat: Platform> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::system_accountNextIndex`].
    pub(super) async fn account_next_index(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        account: methods::AccountId,
    ) {
        let block_hash = header::hash_from_scale_encoded_header(
            sub_utils::subscribe_best(&self.runtime_service).await.0,
        );

        let result = self
            .runtime_call(
                &block_hash,
                "AccountNonceApi",
                1..=1,
                "AccountNonceApi_account_nonce",
                iter::once(&account.0),
                4,
                Duration::from_secs(4),
                NonZeroU32::new(2).unwrap(),
            )
            .await;

        let response = match result {
            Ok(result) => {
                // TODO: we get a u32 when expecting a u64; figure out problem
                // TODO: don't unwrap
                let index =
                    u32::from_le_bytes(<[u8; 4]>::try_from(&result.return_value[..]).unwrap());
                methods::Response::system_accountNextIndex(u64::from(index))
                    .to_json_response(request_id.0)
            }
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Returning error from `state_getMetadata`. \
                    API user might not function properly. Error: {}",
                    error
                );
                json_rpc::parse::build_error_response(
                    request_id.0,
                    json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                    None,
                )
            }
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chain_getBlock`].
    pub(super) async fn chain_get_block(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        hash: Option<methods::HashHexString>,
    ) {
        // `hash` equal to `None` means "the current best block".
        let hash = match hash {
            Some(h) => h.0,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        // Try to determine the block number by looking for the block in cache.
        // The request can be fulfilled no matter whether the block number is known or not, but
        // knowing it will lead to a better selection of peers, and thus increase the chances of
        // the requests succeeding.
        let block_number = {
            let mut cache_lock = self.cache.lock().await;
            let cache_lock = &mut *cache_lock;

            if let Some(future) = cache_lock.block_state_root_hashes_numbers.get_mut(&hash) {
                let _ = future.now_or_never();
            }

            match (
                cache_lock
                    .recent_pinned_blocks
                    .get(&hash)
                    .map(|h| header::decode(h, self.sync_service.block_number_bytes())),
                cache_lock.block_state_root_hashes_numbers.get(&hash),
            ) {
                (Some(Ok(header)), _) => Some(header.number),
                (_, Some(future::MaybeDone::Done(Ok((_, num))))) => Some(*num),
                _ => None,
            }
        };

        // Block bodies and justifications aren't stored locally. Ask the network.
        let result = if let Some(block_number) = block_number {
            self.sync_service
                .clone()
                .block_query(
                    block_number,
                    hash,
                    protocol::BlocksRequestFields {
                        header: true,
                        body: true,
                        justifications: true,
                    },
                    3,
                    Duration::from_secs(8),
                    NonZeroU32::new(1).unwrap(),
                )
                .await
        } else {
            self.sync_service
                .clone()
                .block_query_unknown_number(
                    hash,
                    protocol::BlocksRequestFields {
                        header: true,
                        body: true,
                        justifications: true,
                    },
                    3,
                    Duration::from_secs(8),
                    NonZeroU32::new(1).unwrap(),
                )
                .await
        };

        // The `block_query` function guarantees that the header and body are present and
        // are correct.

        let response = if let Ok(block) = result {
            methods::Response::chain_getBlock(methods::Block {
                extrinsics: block
                    .body
                    .unwrap()
                    .into_iter()
                    .map(methods::HexString)
                    .collect(),
                header: methods::Header::from_scale_encoded_header(
                    &block.header.unwrap(),
                    self.sync_service.block_number_bytes(),
                )
                .unwrap(),
                justifications: block.justifications,
            })
            .to_json_response(request_id.0)
        } else {
            json_rpc::parse::build_success_response(request_id.0, "null")
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chain_getBlockHash`].
    pub(super) async fn chain_get_block_hash(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        height: Option<u64>,
    ) {
        // TODO: maybe store values in cache?
        let response = {
            match height {
                Some(0) => methods::Response::chain_getBlockHash(methods::HashHexString(
                    self.genesis_block_hash,
                ))
                .to_json_response(request_id.0),
                None => {
                    let best_block = header::hash_from_scale_encoded_header(
                        sub_utils::subscribe_best(&self.runtime_service).await.0,
                    );
                    methods::Response::chain_getBlockHash(methods::HashHexString(best_block))
                        .to_json_response(request_id.0)
                }
                Some(_) => {
                    // While the block could be found in `known_blocks`, there is no guarantee
                    // that blocks in `known_blocks` are canonical, and we have no choice but to
                    // return null.
                    // TODO: ask a full node instead? or maybe keep a list of canonical blocks?
                    json_rpc::parse::build_success_response(request_id.0, "null")
                }
            }
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chain_getHeader`].
    pub(super) async fn chain_get_header(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        hash: Option<methods::HashHexString>,
    ) {
        // `hash` equal to `None` means "best block".
        let hash = match hash {
            Some(h) => h.0,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        // Try to look in the cache of recent blocks. If not found, ask the peer-to-peer network.
        // `header` is `Err` if and only if the network request failed.
        let scale_encoded_header = {
            let mut cache_lock = self.cache.lock().await;
            if let Some(header) = cache_lock.recent_pinned_blocks.get(&hash) {
                Ok(header.clone())
            } else {
                // Header isn't known locally. We need to ask the network.
                // First, try to determine the block number by looking into the cache.
                // The request can be fulfilled no matter whether it is found, but knowing it will
                // lead to a better selection of peers, and thus increase the chances of the
                // requests succeeding.
                let block_number = if let Some(future) =
                    cache_lock.block_state_root_hashes_numbers.get_mut(&hash)
                {
                    let _ = future.now_or_never();

                    match future {
                        future::MaybeDone::Done(Ok((_, num))) => Some(*num),
                        _ => None,
                    }
                } else {
                    None
                };

                // Release the lock as we're going to start a long asynchronous operation.
                drop::<MutexGuard<_>>(cache_lock);

                // Actual network query.
                let result = if let Some(block_number) = block_number {
                    self.sync_service
                        .clone()
                        .block_query(
                            block_number,
                            hash,
                            protocol::BlocksRequestFields {
                                header: true,
                                body: false,
                                justifications: false,
                            },
                            3,
                            Duration::from_secs(8),
                            NonZeroU32::new(1).unwrap(),
                        )
                        .await
                } else {
                    self.sync_service
                        .clone()
                        .block_query_unknown_number(
                            hash,
                            protocol::BlocksRequestFields {
                                header: true,
                                body: false,
                                justifications: false,
                            },
                            3,
                            Duration::from_secs(8),
                            NonZeroU32::new(1).unwrap(),
                        )
                        .await
                };

                // The `block_query` method guarantees that the header is present and valid.
                if let Ok(block) = result {
                    let header = block.header.unwrap();
                    debug_assert_eq!(header::hash_from_scale_encoded_header(&header), hash);
                    Ok(header)
                } else {
                    Err(())
                }
            }
        };

        // Build the JSON-RPC response.
        let response = match scale_encoded_header {
            Ok(header) => {
                // In the case of a parachain, it is possible for the header to be in
                // a format that smoldot isn't capable of parsing. In that situation,
                // we take of liberty of returning a JSON-RPC error.
                match methods::Header::from_scale_encoded_header(
                    &header,
                    self.sync_service.block_number_bytes(),
                ) {
                    Ok(decoded) => {
                        methods::Response::chain_getHeader(decoded).to_json_response(request_id.0)
                    }
                    Err(error) => json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::ServerError(
                            -32000,
                            &format!("Failed to decode header: {error}"),
                        ),
                        None,
                    ),
                }
            }
            Err(()) => {
                // Failed to retrieve the header.
                // TODO: error or null?
                json_rpc::parse::build_success_response(request_id.0, "null")
            }
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeAllHeads`].
    pub(super) async fn chain_subscribe_all_heads(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
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
                        &request_id.1,
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
            let me = self.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());

            async move {
                me.requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::chain_subscribeAllHeads((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                'main_sub_loop: loop {
                    let mut new_blocks = {
                        // The buffer size should be large enough so that, if the CPU is busy, it
                        // doesn't become full before the execution of the runtime service resumes.
                        // The maximum number of pinned block is ignored, as this maximum is a way
                        // to avoid malicious behaviors. This code is by definition not considered
                        // malicious.
                        let subscribe_all = me
                            .runtime_service
                            .subscribe_all(
                                "chain_subscribeAllHeads",
                                64,
                                NonZeroUsize::new(usize::max_value()).unwrap(),
                            )
                            .await;

                        // The existing finalized and already-known blocks aren't reported to the
                        // user, but we need to unpin them on to the runtime service.
                        subscribe_all
                            .new_blocks
                            .unpin_block(&header::hash_from_scale_encoded_header(
                                &subscribe_all.finalized_block_scale_encoded_header,
                            ))
                            .await;
                        for block in subscribe_all.non_finalized_blocks_ancestry_order {
                            subscribe_all
                                .new_blocks
                                .unpin_block(&header::hash_from_scale_encoded_header(
                                    &block.scale_encoded_header,
                                ))
                                .await;
                        }

                        subscribe_all.new_blocks
                    };

                    loop {
                        let message = {
                            let next_new_block = new_blocks.next();
                            let next_message = messages_rx.next();
                            futures::pin_mut!(next_message, next_new_block);
                            match future::select(next_new_block, next_message).await {
                                future::Either::Left((v, _)) => either::Left(v),
                                future::Either::Right((v, _)) => either::Right(v),
                            }
                        };

                        match message {
                            either::Left(None) => {
                                // Break from the inner loop in order to recreate the channel.
                                break;
                            }
                            either::Left(Some(runtime_service::Notification::Block(block))) => {
                                new_blocks
                                    .unpin_block(&header::hash_from_scale_encoded_header(
                                        &block.scale_encoded_header,
                                    ))
                                    .await;

                                let header = match methods::Header::from_scale_encoded_header(
                                    &block.scale_encoded_header,
                                    me.sync_service.block_number_bytes(),
                                ) {
                                    Ok(h) => h,
                                    Err(error) => {
                                        log::warn!(
                                            target: &me.log_target,
                                            "`chain_subscribeAllHeads` subscription has skipped \
                                            block due to undecodable header. Hash: {}. Error: {}",
                                            HashDisplay(&header::hash_from_scale_encoded_header(&block.scale_encoded_header)),
                                            error,
                                        );
                                        continue;
                                    }
                                };

                                // This function call will fail if the queue of notifications to
                                // the user has too many elements in it. This JSON-RPC function
                                // unfortunately doesn't provide any mechanism to deal with this
                                // situation, and we handle it by simply not sending the
                                // notification.
                                let _ = me
                                    .requests_subscriptions
                                    .try_push_notification(
                                        &request_id.1,
                                        &subscription_id,
                                        methods::ServerToClient::chain_allHead {
                                            subscription: (&subscription_id).into(),
                                            result: header,
                                        }
                                        .to_json_call_object_parameters(None),
                                    )
                                    .await;
                            }
                            either::Left(Some(
                                runtime_service::Notification::BestBlockChanged { .. },
                            ))
                            | either::Left(Some(runtime_service::Notification::Finalized {
                                ..
                            })) => {}
                            either::Right((
                                SubscriptionMessage::StopIfAllHeads {
                                    stop_request_id,
                                },
                                confirmation_sender,
                            )) => {
                                me.requests_subscriptions
                                    .respond(
                                        &stop_request_id.1,
                                        methods::Response::chain_unsubscribeAllHeads(true)
                                            .to_json_response(&stop_request_id.0),
                                    )
                                    .await;

                                confirmation_sender.send();
                                break 'main_sub_loop;
                            }
                            either::Right(_) => {
                                // Any other message.
                                // Silently discard the confirmation sender.
                            }
                        }
                    }
                }
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeFinalizedHeads`].
    pub(super) async fn chain_subscribe_finalized_heads(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
    ) {
        let (subscription_id, mut messages_rx, subscription_start) = match self
            .requests_subscriptions
            .start_subscription(request_id.1, 1)
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

        let mut blocks_list = {
            let (finalized_block_header, finalized_blocks_subscription) =
                sub_utils::subscribe_finalized(&self.runtime_service).await;
            stream::once(future::ready(finalized_block_header)).chain(finalized_blocks_subscription)
        };

        subscription_start.start({
            let me = self.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());

            async move {
                me.requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::chain_subscribeFinalizedHeads((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                loop {
                    let next_message = messages_rx.next();
                    futures::pin_mut!(next_message);
                    match future::select(blocks_list.next(), next_message).await {
                        future::Either::Left((None, _)) => {
                            // Stream returned by `subscribe_finalized` is always unlimited.
                            unreachable!()
                        }
                        future::Either::Left((Some(header), _)) => {
                            let header = match methods::Header::from_scale_encoded_header(
                                &header,
                                me.sync_service.block_number_bytes(),
                            ) {
                                Ok(h) => h,
                                Err(error) => {
                                    log::warn!(
                                        target: &me.log_target,
                                        "`chain_subscribeFinalizedHeads` subscription has skipped \
                                        block due to undecodable header. Hash: {}. Error: {}",
                                        HashDisplay(&header::hash_from_scale_encoded_header(&header)),
                                        error,
                                    );
                                    continue;
                                }
                            };

                            me.requests_subscriptions
                                .set_queued_notification(
                                    &request_id.1,
                                    &subscription_id,
                                    0,
                                    methods::ServerToClient::chain_finalizedHead {
                                        subscription: (&subscription_id).into(),
                                        result: header,
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await;
                        }
                        future::Either::Right((
                            (
                                SubscriptionMessage::StopIfFinalizedHeads {
                                    stop_request_id,
                                },
                                confirmation_sender,
                            ),
                            _,
                        )) => {
                            me.requests_subscriptions
                                .respond(
                                    &stop_request_id.1,
                                    methods::Response::chain_unsubscribeFinalizedHeads(true)
                                        .to_json_response(&stop_request_id.0),
                                )
                                .await;

                            confirmation_sender.send();
                            break;
                        }
                        future::Either::Right((_, _)) => {
                            // Any other message.
                            // Silently discard the confirmation sender.
                        }
                    }
                }
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeNewHeads`].
    pub(super) async fn chain_subscribe_new_heads(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
    ) {
        let (subscription_id, mut messages_rx, subscription_start) = match self
            .requests_subscriptions
            .start_subscription(request_id.1, 1)
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

        let mut blocks_list = {
            let (block_header, blocks_subscription) =
                sub_utils::subscribe_best(&self.runtime_service).await;
            stream::once(future::ready(block_header)).chain(blocks_subscription)
        };

        subscription_start.start({
            let me = self.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());

            async move {
                me.requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::chain_subscribeNewHeads((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                loop {
                    let next_message = messages_rx.next();
                    futures::pin_mut!(next_message);
                    match future::select(blocks_list.next(), next_message).await {
                        future::Either::Left((None, _)) => {
                            // Stream returned by `subscribe_best` is always unlimited.
                            unreachable!()
                        }
                        future::Either::Left((Some(header), _)) => {
                            let header = match methods::Header::from_scale_encoded_header(
                                &header,
                                me.sync_service.block_number_bytes(),
                            ) {
                                Ok(h) => h,
                                Err(error) => {
                                    log::warn!(
                                        target: &me.log_target,
                                        "`chain_subscribeNewHeads` subscription has skipped block \
                                        due to undecodable header. Hash: {}. Error: {}",
                                        HashDisplay(&header::hash_from_scale_encoded_header(&header)),
                                        error,
                                    );
                                    continue;
                                }
                            };

                            me.requests_subscriptions
                                .set_queued_notification(
                                    &request_id.1,
                                    &subscription_id,
                                    0,
                                    methods::ServerToClient::chain_newHead {
                                        subscription: (&subscription_id).into(),
                                        result: header,
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await;
                        }
                        future::Either::Right((
                            (
                                SubscriptionMessage::StopIfNewHeads {
                                    stop_request_id,
                                },
                                confirmation_sender,
                            ),
                            _,
                        )) => {
                            me.requests_subscriptions
                                .respond(
                                    &stop_request_id.1,
                                    methods::Response::chain_unsubscribeNewHeads(true)
                                        .to_json_response(&stop_request_id.0),
                                )
                                .await;

                            confirmation_sender.send();
                            break;
                        }
                        future::Either::Right((_, _)) => {
                            // Any other message.
                            // Silently discard the confirmation sender.
                        }
                    }
                }
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::chain_unsubscribeAllHeads`].
    pub(super) async fn chain_unsubscribe_all_heads(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription: String,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                &subscription,
                SubscriptionMessage::StopIfAllHeads {
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
                    methods::Response::chain_unsubscribeAllHeads(false)
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chain_unsubscribeFinalizedHeads`].
    pub(super) async fn chain_unsubscribe_finalized_heads(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription: String,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                &subscription,
                SubscriptionMessage::StopIfFinalizedHeads {
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
                    methods::Response::chain_unsubscribeFinalizedHeads(false)
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::chain_unsubscribeNewHeads`].
    pub(super) async fn chain_unsubscribe_new_heads(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        subscription: String,
    ) {
        // Stopping the subscription is done by sending a message to it.
        // The task dedicated to this subscription will receive the message, send a response to
        // the JSON-RPC client, then shut down.
        let stop_message_received = self
            .requests_subscriptions
            .subscription_send(
                request_id.1,
                &subscription,
                SubscriptionMessage::StopIfNewHeads {
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
                    methods::Response::chain_unsubscribeNewHeads(false)
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::payment_queryInfo`].
    pub(super) async fn payment_query_info(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        extrinsic: &[u8],
        block_hash: Option<&[u8; 32]>,
    ) {
        let block_hash = match block_hash {
            Some(h) => *h,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        let result = self
            .runtime_call(
                &block_hash,
                "TransactionPaymentApi",
                1..=2,
                json_rpc::payment_info::PAYMENT_FEES_FUNCTION_NAME,
                json_rpc::payment_info::payment_info_parameters(extrinsic),
                4,
                Duration::from_secs(4),
                NonZeroU32::new(2).unwrap(),
            )
            .await;

        let response = match result {
            Ok(result) => match json_rpc::payment_info::decode_payment_info(
                &result.return_value,
                result.api_version,
            ) {
                Ok(info) => {
                    methods::Response::payment_queryInfo(info).to_json_response(request_id.0)
                }
                Err(error) => json_rpc::parse::build_error_response(
                    request_id.0,
                    json_rpc::parse::ErrorResponse::ServerError(
                        -32000,
                        &format!("Failed to decode runtime output: {error}"),
                    ),
                    None,
                ),
            },
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Returning error from `state_getMetadata`. \
                    API user might not function properly. Error: {}",
                    error
                );
                json_rpc::parse::build_error_response(
                    request_id.0,
                    json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                    None,
                )
            }
        };

        self.requests_subscriptions
            .respond(&request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_call`].
    pub(super) async fn state_call(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        function_to_call: &str,
        call_parameters: methods::HexString,
        hash: Option<methods::HashHexString>,
    ) {
        let block_hash = if let Some(hash) = hash {
            hash.0
        } else {
            header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            )
        };

        let result = self
            .runtime_call_no_api_check(
                &block_hash,
                function_to_call,
                iter::once(call_parameters.0),
                3,
                Duration::from_secs(10),
                NonZeroU32::new(3).unwrap(),
            )
            .await;

        let response = match result {
            Ok(data) => methods::Response::state_call(methods::HexString(data.to_vec()))
                .to_json_response(request_id.0),
            Err(error) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                None,
            ),
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_getKeys`].
    pub(super) async fn state_get_keys(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        prefix: methods::HexString,
        hash: Option<methods::HashHexString>,
    ) {
        // `hash` equal to `None` means "best block".
        let hash = match hash {
            Some(h) => h.0,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        // Obtain the state trie root and height of the requested block.
        // This is necessary to perform network storage queries.
        let (state_root, block_number) = match self.state_trie_root_hash(&hash).await {
            Ok(v) => v,
            Err(err) => {
                self.requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                &format!("Failed to fetch block information: {err}"),
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let outcome = self
            .sync_service
            .clone()
            .storage_prefix_keys_query(
                block_number,
                &hash,
                &prefix.0,
                &state_root,
                3,
                Duration::from_secs(12),
                NonZeroU32::new(1).unwrap(),
            )
            .await;

        let response = match outcome {
            Ok(keys) => {
                let out = keys.into_iter().map(methods::HexString).collect::<Vec<_>>();
                methods::Response::state_getKeys(out).to_json_response(request_id.0)
            }
            Err(error) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                None,
            ),
        };

        self.requests_subscriptions
            .respond(&request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_getKeysPaged`].
    pub(super) async fn state_get_keys_paged(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        prefix: Option<methods::HexString>,
        count: u32,
        start_key: Option<methods::HexString>,
        hash: Option<methods::HashHexString>,
    ) {
        // `hash` equal to `None` means "best block".
        let hash = match hash {
            Some(h) => h.0,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        // Because the user is likely to call this function multiple times in a row with the exact
        // same parameters, we store the untruncated responses in a cache. Check if we hit the
        // cache.
        if let Some(keys) = self
            .cache
            .lock()
            .await
            .state_get_keys_paged
            .get(&(hash, prefix.clone()))
        {
            let out = keys
                .iter()
                .filter(|k| start_key.as_ref().map_or(true, |start| *k >= &start.0)) // TODO: not sure if start should be in the set or not?
                .cloned()
                .map(methods::HexString)
                .take(usize::try_from(count).unwrap_or(usize::max_value()))
                .collect::<Vec<_>>();

            self.requests_subscriptions
                .respond(
                    request_id.1,
                    methods::Response::state_getKeysPaged(out).to_json_response(request_id.0),
                )
                .await;
            return;
        }

        // Obtain the state trie root and height of the requested block.
        // This is necessary to perform network storage queries.
        let (state_root, block_number) = match self.state_trie_root_hash(&hash).await {
            Ok(v) => v,
            Err(err) => {
                self.requests_subscriptions
                    .respond(
                        request_id.1,
                        json_rpc::parse::build_error_response(
                            request_id.0,
                            json_rpc::parse::ErrorResponse::ServerError(
                                -32000,
                                &format!("Failed to fetch block information: {err}"),
                            ),
                            None,
                        ),
                    )
                    .await;
                return;
            }
        };

        let outcome = self
            .sync_service
            .clone()
            .storage_prefix_keys_query(
                block_number,
                &hash,
                &prefix.as_ref().unwrap().0, // TODO: don't unwrap! what is this Option?
                &state_root,
                3,
                Duration::from_secs(12),
                NonZeroU32::new(1).unwrap(),
            )
            .await;

        let response = match outcome {
            Ok(keys) => {
                // TODO: instead of requesting all keys with that prefix from the network, pass `start_key` to the network service
                let out = keys
                    .iter()
                    .filter(|k| start_key.as_ref().map_or(true, |start| *k >= &start.0)) // TODO: not sure if start should be in the set or not?
                    .cloned() // TODO: instead of cloning, make `Response::state_getKeysPaged` accept references
                    .map(methods::HexString)
                    .take(usize::try_from(count).unwrap_or(usize::max_value()))
                    .collect::<Vec<_>>();

                // If the returned response is somehow truncated, it is very likely that the
                // JSON-RPC client will call the function again with the exact same parameters.
                // Thus, store the results in a cache.
                if out.len() != keys.len() {
                    self.cache
                        .lock()
                        .await
                        .state_get_keys_paged
                        .push((hash, prefix), keys);
                }

                methods::Response::state_getKeysPaged(out).to_json_response(request_id.0)
            }
            Err(error) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                None,
            ),
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_getMetadata`].
    pub(super) async fn state_get_metadata(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        hash: Option<methods::HashHexString>,
    ) {
        let block_hash = if let Some(hash) = hash {
            hash.0
        } else {
            header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            )
        };

        let result = self
            .runtime_call(
                &block_hash,
                "Metadata",
                1..=1,
                "Metadata_metadata",
                iter::empty::<Vec<u8>>(),
                3,
                Duration::from_secs(8),
                NonZeroU32::new(1).unwrap(),
            )
            .await;
        let result = result
            .as_ref()
            .map(|output| methods::remove_metadata_length_prefix(&output.return_value));

        let response = match result {
            Ok(Ok(metadata)) => {
                methods::Response::state_getMetadata(methods::HexString(metadata.to_vec()))
                    .to_json_response(request_id.0)
            }
            Ok(Err(error)) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    &format!("Failed to decode metadata from runtime. Error: {}", error),
                ),
                None,
            ),
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Returning error from `state_getMetadata`. \
                            API user might not function properly. Error: {}",
                    error
                );
                json_rpc::parse::build_error_response(
                    request_id.0,
                    json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                    None,
                )
            }
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_getRuntimeVersion`].
    pub(super) async fn state_get_runtime_version(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        block_hash: Option<&[u8; 32]>,
    ) {
        let block_hash = match block_hash {
            Some(h) => *h,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        let response = match self
            .runtime_lock(&block_hash)
            .await
            .map(|l| l.specification())
        {
            Ok(Ok(spec)) => {
                let runtime_spec = spec.decode();
                methods::Response::state_getRuntimeVersion(methods::RuntimeVersion {
                    spec_name: runtime_spec.spec_name.into(),
                    impl_name: runtime_spec.impl_name.into(),
                    authoring_version: u64::from(runtime_spec.authoring_version),
                    spec_version: u64::from(runtime_spec.spec_version),
                    impl_version: u64::from(runtime_spec.impl_version),
                    transaction_version: runtime_spec.transaction_version.map(u64::from),
                    state_version: runtime_spec.state_version.map(u8::from).map(u64::from),
                    apis: runtime_spec
                        .apis
                        .map(|api| (methods::HexString(api.name_hash.to_vec()), api.version))
                        .collect(),
                })
                .to_json_response(request_id.0)
            }
            Ok(Err(error)) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                None,
            ),
            Err(error) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                None,
            ),
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_getStorage`].
    pub(super) async fn state_get_storage(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        key: methods::HexString,
        hash: Option<methods::HashHexString>,
    ) {
        let hash = hash
            .as_ref()
            .map(|h| h.0)
            .unwrap_or(header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ));

        let fut = self.storage_query(
            iter::once(&key.0),
            &hash,
            3,
            Duration::from_secs(12),
            NonZeroU32::new(1).unwrap(),
        );
        let response = fut.await;
        let response = match response.map(|mut r| r.pop().unwrap()) {
            Ok(Some(value)) => methods::Response::state_getStorage(methods::HexString(value))
                .to_json_response(request_id.0),
            Ok(None) => json_rpc::parse::build_success_response(request_id.0, "null"),
            Err(error) => json_rpc::parse::build_error_response(
                request_id.0,
                json_rpc::parse::ErrorResponse::ServerError(-32000, &error.to_string()),
                None,
            ),
        };

        self.requests_subscriptions
            .respond(request_id.1, response)
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_queryStorageAt`].
    pub(super) async fn state_query_storage_at(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        keys: Vec<methods::HexString>,
        at: Option<methods::HashHexString>,
    ) {
        let best_block = header::hash_from_scale_encoded_header(
            &sub_utils::subscribe_best(&self.runtime_service).await.0,
        );

        let cache = self.cache.lock().await;

        let at = at.as_ref().map(|h| h.0).unwrap_or(best_block);

        let mut out = methods::StorageChangeSet {
            block: methods::HashHexString(best_block),
            changes: Vec::new(),
        };

        drop(cache);

        let fut = self.storage_query(
            keys.iter(),
            &at,
            3,
            Duration::from_secs(12),
            NonZeroU32::new(1).unwrap(),
        );

        if let Ok(values) = fut.await {
            for (value, key) in values.into_iter().zip(keys) {
                out.changes.push((key, value.map(methods::HexString)));
            }
        }

        self.requests_subscriptions
            .respond(
                request_id.1,
                methods::Response::state_queryStorageAt(vec![out]).to_json_response(request_id.0),
            )
            .await;
    }

    /// Handles a call to [`methods::MethodCall::state_subscribeRuntimeVersion`].
    pub(super) async fn state_subscribe_runtime_version(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
    ) {
        let (subscription_id, mut messages_rx, subscription_start) = match self
            .requests_subscriptions
            .start_subscription(request_id.1, 1)
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
            let me = self.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());
            async move {
                me.requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::state_subscribeRuntimeVersion((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                let (current_spec, spec_changes) =
                    sub_utils::subscribe_runtime_version(&me.runtime_service).await;
                let spec_changes = stream::iter(iter::once(current_spec)).chain(spec_changes);
                futures::pin_mut!(spec_changes);

                loop {
                    let next_message = messages_rx.next();
                    futures::pin_mut!(next_message);
                    match future::select(spec_changes.next(), next_message).await {
                        future::Either::Left((None, _)) => {
                            // Stream returned by `subscribe_runtime_version` is always unlimited.
                            unreachable!()
                        }
                        future::Either::Left((Some(new_runtime), _)) => {
                            let notification_body = if let Ok(runtime_spec) = new_runtime {
                                let runtime_spec = runtime_spec.decode();
                                methods::ServerToClient::state_runtimeVersion {
                                    subscription: (&subscription_id).into(),
                                    result: Some(methods::RuntimeVersion {
                                        spec_name: runtime_spec.spec_name.into(),
                                        impl_name: runtime_spec.impl_name.into(),
                                        authoring_version: u64::from(
                                            runtime_spec.authoring_version,
                                        ),
                                        spec_version: u64::from(runtime_spec.spec_version),
                                        impl_version: u64::from(runtime_spec.impl_version),
                                        transaction_version: runtime_spec
                                            .transaction_version
                                            .map(u64::from),
                                        state_version: runtime_spec
                                            .state_version
                                            .map(u8::from)
                                            .map(u64::from),
                                        apis: runtime_spec
                                            .apis
                                            .map(|api| {
                                                (
                                                    methods::HexString(api.name_hash.to_vec()),
                                                    api.version,
                                                )
                                            })
                                            .collect(),
                                    }),
                                }
                                .to_json_call_object_parameters(None)
                            } else {
                                methods::ServerToClient::state_runtimeVersion {
                                    subscription: (&subscription_id).into(),
                                    result: None,
                                }
                                .to_json_call_object_parameters(None)
                            };

                            me.requests_subscriptions
                                .set_queued_notification(
                                    &request_id.1,
                                    &subscription_id,
                                    0,
                                    notification_body,
                                )
                                .await;
                        }
                        future::Either::Right((
                            (
                                SubscriptionMessage::StopIfRuntimeSpec { stop_request_id },
                                confirmation_sender,
                            ),
                            _,
                        )) => {
                            me.requests_subscriptions
                                .respond(
                                    &stop_request_id.1,
                                    methods::Response::state_unsubscribeRuntimeVersion(true)
                                        .to_json_response(&stop_request_id.0),
                                )
                                .await;

                            confirmation_sender.send();
                            break;
                        }
                        future::Either::Right((_, _)) => {
                            // Any other message.
                            // Silently discard the confirmation sender.
                        }
                    }
                }
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::state_subscribeStorage`].
    pub(super) async fn state_subscribe_storage(
        self: &Arc<Self>,
        request_id: (&str, &requests_subscriptions::RequestId),
        list: Vec<methods::HexString>,
    ) {
        if list.is_empty() {
            // When the list of keys is empty, that means we want to subscribe to *all*
            // storage changes. It is not possible to reasonably implement this in a
            // light client.
            self.requests_subscriptions
                .respond(
                    request_id.1,
                    json_rpc::parse::build_error_response(
                        request_id.0,
                        json_rpc::parse::ErrorResponse::ServerError(
                            -32000,
                            "Subscribing to all storage changes isn't supported",
                        ),
                        None,
                    ),
                )
                .await;
            return;
        }

        let (subscription_id, mut messages_rx, subscription_start) = match self
            .requests_subscriptions
            .start_subscription(request_id.1, 1)
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

        // Build a stream of `methods::StorageChangeSet` items to send back to the user.
        let storage_updates = {
            let known_values = (0..list.len()).map(|_| None).collect::<Vec<_>>();
            let runtime_service = self.runtime_service.clone();
            let sync_service = self.sync_service.clone();
            let log_target = self.log_target.clone();

            stream::unfold(
                (None, list, known_values),
                move |(mut blocks_stream, list, mut known_values)| {
                    let sync_service = sync_service.clone();
                    let runtime_service = runtime_service.clone();
                    let log_target = log_target.clone();
                    async move {
                        loop {
                            if blocks_stream.is_none() {
                                // TODO: why is this done against the runtime_service and not the sync_service? clarify
                                let (block_header, blocks_subscription) =
                                    sub_utils::subscribe_best(&runtime_service).await;
                                blocks_stream = Some(
                                    stream::once(future::ready(block_header))
                                        .chain(blocks_subscription),
                                );
                            }

                            let block = match blocks_stream.as_mut().unwrap().next().await {
                                Some(b) => b,
                                None => {
                                    blocks_stream = None;
                                    continue;
                                }
                            };

                            let block_hash = header::hash_from_scale_encoded_header(&block);
                            let (state_trie_root, block_number) = {
                                let decoded =
                                    header::decode(&block, sync_service.block_number_bytes())
                                        .unwrap();
                                (decoded.state_root, decoded.number)
                            };

                            let mut out = methods::StorageChangeSet {
                                block: methods::HashHexString(block_hash),
                                changes: Vec::new(),
                            };

                            for (key_index, key) in list.iter().enumerate() {
                                // TODO: parallelism?
                                match sync_service
                                    .clone()
                                    .storage_query(
                                        block_number,
                                        &block_hash,
                                        state_trie_root,
                                        iter::once(&key.0),
                                        4,
                                        Duration::from_secs(12),
                                        NonZeroU32::new(2).unwrap(),
                                    )
                                    .await
                                {
                                    Ok(mut values) => {
                                        let value = values.pop().unwrap();
                                        match &mut known_values[key_index] {
                                            Some(v) if *v == value => {}
                                            v => {
                                                *v = Some(value.clone());
                                                out.changes.push((
                                                    key.clone(),
                                                    value.map(methods::HexString),
                                                ));
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        log::log!(
                                            target: &log_target,
                                            if error.is_network_problem() {
                                                log::Level::Debug
                                            } else {
                                                log::Level::Warn
                                            },
                                            "state_subscribeStorage changes check failed: {}",
                                            error
                                        );
                                    }
                                }
                            }

                            if !out.changes.is_empty() {
                                return Some((out, (blocks_stream, list, known_values)));
                            }
                        }
                    }
                },
            )
        };

        subscription_start.start({
            let me = self.clone();
            let request_id = (request_id.0.to_owned(), request_id.1.clone());

            async move {
                me.requests_subscriptions
                    .respond(
                        &request_id.1,
                        methods::Response::state_subscribeStorage((&subscription_id).into())
                            .to_json_response(&request_id.0),
                    )
                    .await;

                futures::pin_mut!(storage_updates);

                loop {
                    let next_message = messages_rx.next();
                    futures::pin_mut!(next_message);
                    match future::select(storage_updates.next(), next_message).await {
                        future::Either::Left((None, _)) => {
                            // Stream created above is always unlimited.
                            unreachable!()
                        }
                        future::Either::Left((Some(changes), _)) => {
                            me.requests_subscriptions
                                .set_queued_notification(
                                    &request_id.1,
                                    &subscription_id,
                                    0,
                                    methods::ServerToClient::state_storage {
                                        subscription: (&subscription_id).into(),
                                        result: changes,
                                    }
                                    .to_json_call_object_parameters(None),
                                )
                                .await;
                        }
                        future::Either::Right((
                            (
                                SubscriptionMessage::StopIfStorage { stop_request_id },
                                confirmation_sender,
                            ),
                            _,
                        )) => {
                            me.requests_subscriptions
                                .respond(
                                    &stop_request_id.1,
                                    methods::Response::state_unsubscribeStorage(true)
                                        .to_json_response(&stop_request_id.0),
                                )
                                .await;

                            confirmation_sender.send();
                            break;
                        }
                        future::Either::Right((_, _)) => {
                            // Any other message.
                            // Silently discard the confirmation sender.
                        }
                    }
                }
            }
        });
    }

    /// Handles a call to [`methods::MethodCall::state_unsubscribeRuntimeVersion`].
    pub(super) async fn state_unsubscribe_runtime_version(
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
                SubscriptionMessage::StopIfRuntimeSpec {
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
                    methods::Response::state_unsubscribeRuntimeVersion(false)
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }

    /// Handles a call to [`methods::MethodCall::state_unsubscribeStorage`].
    pub(super) async fn state_unsubscribe_storage(
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
                SubscriptionMessage::StopIfStorage {
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
                    methods::Response::state_unsubscribeStorage(false)
                        .to_json_response(request_id.0),
                )
                .await;
        }
    }
}
