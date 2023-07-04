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

use super::{legacy_state_sub, Background, GetKeysPagedCacheKey, PlatformRef};

use crate::sync_service;

use alloc::{borrow::ToOwned as _, format, string::ToString as _, sync::Arc, vec, vec::Vec};
use async_lock::MutexGuard;
use core::{iter, num::NonZeroU32, pin, time::Duration};
use futures_channel::oneshot;
use futures_util::{future, stream, FutureExt as _, StreamExt as _};
use smoldot::{
    header,
    informant::HashDisplay,
    json_rpc::{self, methods, service},
    network::protocol,
};

mod sub_utils;

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::system_accountNextIndex`].
    pub(super) async fn account_next_index(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::system_accountNextIndex { account } = request.request() else {
            unreachable!()
        };

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

        match result {
            Ok(result) => {
                // TODO: we get a u32 when expecting a u64; figure out problem
                // TODO: don't unwrap
                let index =
                    u32::from_le_bytes(<[u8; 4]>::try_from(&result.return_value[..]).unwrap());
                request.respond(methods::Response::system_accountNextIndex(u64::from(index)));
            }
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Returning error from `system_accountNextIndex`. \
                    API user might not function properly. Error: {}",
                    error
                );
                request.fail(service::ErrorResponse::ServerError(
                    -32000,
                    &error.to_string(),
                ));
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::chain_getBlock`].
    pub(super) async fn chain_get_block(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::chain_getBlock { hash } = request.request() else {
            unreachable!()
        };

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
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::BlockNumber {
                    block_hash: hash,
                    result_tx: tx,
                })
                .await
                .unwrap();
            rx.await.unwrap()
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

        if let Ok(block) = result {
            request.respond(methods::Response::chain_getBlock(methods::Block {
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
                justifications: block.justifications.map(|list| {
                    list.into_iter()
                        .map(|j| (j.engine_id, j.justification))
                        .collect()
                }),
            }))
        } else {
            request.respond_null()
        }
    }

    /// Handles a call to [`methods::MethodCall::chain_getBlockHash`].
    pub(super) async fn chain_get_block_hash(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::chain_getBlockHash { height } = request.request() else {
            unreachable!()
        };

        // TODO: maybe store values in cache?
        match height {
            Some(0) => request.respond(methods::Response::chain_getBlockHash(
                methods::HashHexString(self.genesis_block_hash),
            )),
            None => {
                let best_block = header::hash_from_scale_encoded_header(
                    sub_utils::subscribe_best(&self.runtime_service).await.0,
                );
                request.respond(methods::Response::chain_getBlockHash(
                    methods::HashHexString(best_block),
                ));
            }
            Some(_) => {
                // While the block could be found in `known_blocks`, there is no guarantee
                // that blocks in `known_blocks` are canonical, and we have no choice but to
                // return null.
                // TODO: ask a full node instead? or maybe keep a list of canonical blocks?
                request.respond_null();
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::chain_getHeader`].
    pub(super) async fn chain_get_header(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::chain_getHeader { hash } = request.request() else {
            unreachable!()
        };

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

        // And finally respond.
        match scale_encoded_header {
            Ok(header) => {
                // In the case of a parachain, it is possible for the header to be in
                // a format that smoldot isn't capable of parsing. In that situation,
                // we take of liberty of returning a JSON-RPC error.
                match methods::Header::from_scale_encoded_header(
                    &header,
                    self.sync_service.block_number_bytes(),
                ) {
                    Ok(decoded) => request.respond(methods::Response::chain_getHeader(decoded)),
                    Err(error) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                        -32000,
                        &format!("Failed to decode header: {error}"),
                    )),
                }
            }
            Err(()) => {
                // Failed to retrieve the header.
                // TODO: error or null?
                request.respond_null();
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::chain_subscribeFinalizedHeads`].
    pub(super) async fn chain_subscribe_finalized_heads(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::chain_subscribeFinalizedHeads {} = request.request() else {
            unreachable!()
        };

        let mut blocks_list = {
            let (finalized_block_header, finalized_blocks_subscription) =
                sub_utils::subscribe_finalized(&self.runtime_service).await;
            stream::once(future::ready(finalized_block_header)).chain(finalized_blocks_subscription)
        };

        self.platform.spawn_task(
            format!("{}-subscribe-finalized-heads", self.log_target).into(),
            {
                let log_target = self.log_target.clone();
                let sync_service = self.sync_service.clone();

                async move {
                    let mut subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();

                    loop {
                        let event = {
                            let unsubscribed = pin::pin!(subscription.wait_until_stale());
                            match future::select(blocks_list.next(), unsubscribed).await {
                                future::Either::Left((ev, _)) => either::Left(ev),
                                future::Either::Right((ev, _)) => either::Right(ev),
                            }
                        };

                        match event {
                            either::Left(None) => {
                                // Stream returned by `subscribe_finalized` is always unlimited.
                                unreachable!()
                            }
                            either::Left(Some(header)) => {
                                let header = match methods::Header::from_scale_encoded_header(
                                    &header,
                                    sync_service.block_number_bytes(),
                                ) {
                                    Ok(h) => h,
                                    Err(error) => {
                                        log::warn!(
                                        target: &log_target,
                                        "`chain_subscribeFinalizedHeads` subscription has skipped \
                                        block due to undecodable header. Hash: {}. Error: {}",
                                        HashDisplay(&header::hash_from_scale_encoded_header(
                                            &header
                                        )),
                                        error,
                                    );
                                        continue;
                                    }
                                };

                                subscription
                                    .send_notification(
                                        methods::ServerToClient::chain_finalizedHead {
                                            subscription: (&subscription_id).into(),
                                            result: header,
                                        },
                                    )
                                    .await;
                            }
                            either::Right(()) => {
                                break;
                            }
                        }
                    }
                }
            },
        );
    }

    /// Handles a call to [`methods::MethodCall::payment_queryInfo`].
    pub(super) async fn payment_query_info(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::payment_queryInfo {
            extrinsic,
            hash: block_hash,
        } = request.request()
        else {
            unreachable!()
        };

        let block_hash = match block_hash {
            Some(h) => h.0,
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
                json_rpc::payment_info::payment_info_parameters(&extrinsic.0),
                4,
                Duration::from_secs(4),
                NonZeroU32::new(2).unwrap(),
            )
            .await;

        match result {
            Ok(result) => match json_rpc::payment_info::decode_payment_info(
                &result.return_value,
                result.api_version,
            ) {
                Ok(info) => request.respond(methods::Response::payment_queryInfo(info)),
                Err(error) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    &format!("Failed to decode runtime output: {error}"),
                )),
            },
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Returning error from `payment_queryInfo`. \
                    API user might not function properly. Error: {}",
                    error
                );
                request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    &error.to_string(),
                ));
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::state_call`].
    pub(super) async fn state_call(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::state_call {
            name: function_to_call,
            parameters: call_parameters,
            hash,
        } = request.request()
        else {
            unreachable!()
        };

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
                &function_to_call,
                iter::once(call_parameters.0),
                3,
                Duration::from_secs(10),
                NonZeroU32::new(3).unwrap(),
            )
            .await;

        match result {
            Ok(data) => request.respond(methods::Response::state_call(methods::HexString(
                data.to_vec(),
            ))),
            Err(error) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                &error.to_string(),
            )),
        }
    }

    /// Handles a call to [`methods::MethodCall::state_getKeys`].
    pub(super) async fn state_get_keys(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::state_getKeys { prefix, hash } = request.request() else {
            unreachable!()
        };

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
                request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    &format!("Failed to fetch block information: {err}"),
                ));
                return;
            }
        };

        let outcome = self
            .sync_service
            .clone()
            .storage_query(
                block_number,
                &hash,
                &state_root,
                iter::once(sync_service::StorageRequestItem {
                    key: prefix.0,
                    ty: sync_service::StorageRequestItemTy::DescendantsHashes,
                }),
                3,
                Duration::from_secs(12),
                NonZeroU32::new(1).unwrap(),
            )
            .await;

        match outcome {
            Ok(entries) => {
                let out = entries
                    .into_iter()
                    .map(|item| match item {
                        sync_service::StorageResultItem::DescendantHash { key, .. } => {
                            methods::HexString(key)
                        }
                        _ => unreachable!(),
                    })
                    .collect::<Vec<_>>();
                request.respond(methods::Response::state_getKeys(out))
            }
            Err(error) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                &error.to_string(),
            )),
        }
    }

    /// Handles a call to [`methods::MethodCall::state_getKeysPaged`].
    pub(super) async fn state_get_keys_paged(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::state_getKeysPaged {
            prefix,
            count,
            start_key,
            hash,
        } = request.request()
        else {
            unreachable!()
        };

        // `hash` equal to `None` means "best block".
        let hash = match hash {
            Some(h) => h.0,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        // A prefix of `None` means "empty".
        let prefix = prefix.unwrap_or(methods::HexString(Vec::new())).0;

        // Because the user is likely to call this function multiple times in a row with the exact
        // same parameters, we store the untruncated responses in a cache. Check if we hit the
        // cache.
        if let Some(keys) =
            self.cache
                .lock()
                .await
                .state_get_keys_paged
                .get(&GetKeysPagedCacheKey {
                    hash,
                    prefix: prefix.clone(),
                })
        {
            let out = keys
                .iter()
                .filter(|k| start_key.as_ref().map_or(true, |start| *k >= &start.0)) // TODO: not sure if start should be in the set or not?
                .cloned()
                .map(methods::HexString)
                .take(usize::try_from(count).unwrap_or(usize::max_value()))
                .collect::<Vec<_>>();

            request.respond(methods::Response::state_getKeysPaged(out));
            return;
        }

        // Obtain the state trie root and height of the requested block.
        // This is necessary to perform network storage queries.
        let (state_root, block_number) = match self.state_trie_root_hash(&hash).await {
            Ok(v) => v,
            Err(err) => {
                request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    &format!("Failed to fetch block information: {err}"),
                ));
                return;
            }
        };

        let outcome = self
            .sync_service
            .clone()
            .storage_query(
                block_number,
                &hash,
                &state_root,
                iter::once(sync_service::StorageRequestItem {
                    key: prefix.clone(),
                    ty: sync_service::StorageRequestItemTy::DescendantsHashes,
                }),
                3,
                Duration::from_secs(12),
                NonZeroU32::new(1).unwrap(),
            )
            .await;

        match outcome {
            Ok(entries) => {
                // TODO: instead of requesting all keys with that prefix from the network, pass `start_key` to the network service
                let keys = entries
                    .into_iter()
                    .map(|item| match item {
                        sync_service::StorageResultItem::DescendantHash { key, .. } => key,
                        _ => unreachable!(),
                    })
                    .collect::<Vec<_>>();

                let out = keys
                    .iter()
                    .cloned()
                    .filter(|k| start_key.as_ref().map_or(true, |start| *k >= start.0)) // TODO: not sure if start should be in the set or not?
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
                        .push(GetKeysPagedCacheKey { hash, prefix }, keys);
                }

                request.respond(methods::Response::state_getKeysPaged(out));
            }
            Err(error) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                &error.to_string(),
            )),
        }
    }

    /// Handles a call to [`methods::MethodCall::state_getMetadata`].
    pub(super) async fn state_get_metadata(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::state_getMetadata { hash } = request.request() else {
            unreachable!()
        };

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
                1..=2,
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

        match result {
            Ok(Ok(metadata)) => request.respond(methods::Response::state_getMetadata(
                methods::HexString(metadata.to_vec()),
            )),
            Ok(Err(error)) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                &format!("Failed to decode metadata from runtime. Error: {error}"),
            )),
            Err(error) => {
                log::warn!(
                    target: &self.log_target,
                    "Returning error from `state_getMetadata`. API user might not function \
                    properly. Error: {error}"
                );
                request.fail(json_rpc::parse::ErrorResponse::ServerError(
                    -32000,
                    &error.to_string(),
                ));
            }
        }
    }

    /// Handles a call to [`methods::MethodCall::state_getRuntimeVersion`].
    pub(super) async fn state_get_runtime_version(
        self: &Arc<Self>,
        request: service::RequestProcess,
    ) {
        let methods::MethodCall::state_getRuntimeVersion { at: block_hash } = request.request()
        else {
            unreachable!()
        };

        let block_hash = match block_hash {
            Some(h) => h.0,
            None => header::hash_from_scale_encoded_header(
                sub_utils::subscribe_best(&self.runtime_service).await.0,
            ),
        };

        match self
            .runtime_access(&block_hash)
            .await
            .map(|l| l.specification())
        {
            Ok(Ok(spec)) => {
                let runtime_spec = spec.decode();
                request.respond(methods::Response::state_getRuntimeVersion(
                    methods::RuntimeVersion {
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
                    },
                ))
            }
            Ok(Err(error)) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                &error.to_string(),
            )),
            Err(error) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                &error.to_string(),
            )),
        }
    }

    /// Handles a call to [`methods::MethodCall::state_getStorage`].
    pub(super) async fn state_get_storage(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::state_getStorage { key, hash } = request.request() else {
            unreachable!()
        };

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
        match response.map(|mut r| r.pop().unwrap()) {
            Ok(Some(value)) => request.respond(methods::Response::state_getStorage(
                methods::HexString(value),
            )),
            Ok(None) => request.respond_null(),
            Err(error) => request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                &error.to_string(),
            )),
        }
    }

    /// Handles a call to [`methods::MethodCall::state_queryStorageAt`].
    pub(super) async fn state_query_storage_at(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::state_queryStorageAt { keys, at } = request.request() else {
            unreachable!()
        };

        let best_block = header::hash_from_scale_encoded_header(
            &sub_utils::subscribe_best(&self.runtime_service).await.0,
        );

        let at = at.as_ref().map(|h| h.0).unwrap_or(best_block);

        let mut out = methods::StorageChangeSet {
            block: methods::HashHexString(best_block),
            changes: Vec::new(),
        };

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

        request.respond(methods::Response::state_queryStorageAt(vec![out]));
    }

    /// Handles a call to [`methods::MethodCall::state_subscribeRuntimeVersion`].
    pub(super) async fn state_subscribe_runtime_version(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::state_subscribeRuntimeVersion {} = request.request() else {
            unreachable!()
        };

        let runtime_service = self.runtime_service.clone();

        self.platform.spawn_task(
            format!("{}-subscribe-runtime-version", self.log_target).into(),
            async move {
                let mut subscription = request.accept();
                let subscription_id = subscription.subscription_id().to_owned();

                let (current_spec, spec_changes) =
                    sub_utils::subscribe_runtime_version(&runtime_service).await;
                let mut spec_changes =
                    pin::pin!(stream::iter(iter::once(current_spec)).chain(spec_changes));

                loop {
                    let event = {
                        let unsubscribed = pin::pin!(subscription.wait_until_stale());
                        match future::select(spec_changes.next(), unsubscribed).await {
                            future::Either::Left((ev, _)) => either::Left(ev),
                            future::Either::Right((ev, _)) => either::Right(ev),
                        }
                    };

                    match event {
                        either::Left(None) => {
                            // Stream returned by `subscribe_runtime_version` is always unlimited.
                            unreachable!()
                        }
                        either::Left(Some(new_runtime)) => {
                            if let Ok(runtime_spec) = new_runtime {
                                let runtime_spec = runtime_spec.decode();
                                subscription
                                    .send_notification(
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
                                                            methods::HexString(
                                                                api.name_hash.to_vec(),
                                                            ),
                                                            api.version,
                                                        )
                                                    })
                                                    .collect(),
                                            }),
                                        },
                                    )
                                    .await;
                            } else {
                                subscription
                                    .send_notification(
                                        methods::ServerToClient::state_runtimeVersion {
                                            subscription: (&subscription_id).into(),
                                            result: None,
                                        },
                                    )
                                    .await;
                            }
                        }
                        either::Right(()) => {
                            break;
                        }
                    }
                }
            },
        );
    }

    /// Handles a call to [`methods::MethodCall::state_subscribeStorage`].
    pub(super) async fn state_subscribe_storage(
        self: &Arc<Self>,
        request: service::SubscriptionStartProcess,
    ) {
        let methods::MethodCall::state_subscribeStorage { list } = request.request() else {
            unreachable!()
        };

        if list.is_empty() {
            // When the list of keys is empty, that means we want to subscribe to *all*
            // storage changes. It is not possible to reasonably implement this in a
            // light client.
            request.fail(json_rpc::parse::ErrorResponse::ServerError(
                -32000,
                "Subscribing to all storage changes isn't supported",
            ));
            return;
        }

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
                                        iter::once(sync_service::StorageRequestItem {
                                            key: key.0.clone(),
                                            ty: sync_service::StorageRequestItemTy::Value,
                                        }),
                                        4,
                                        Duration::from_secs(12),
                                        NonZeroU32::new(2).unwrap(),
                                    )
                                    .await
                                {
                                    Ok(mut values) => {
                                        let Some(sync_service::StorageResultItem::Value {
                                            value,
                                            ..
                                        }) = values.pop()
                                        else {
                                            unreachable!()
                                        };
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

        self.platform.spawn_task(
            format!("{}-subscribe-storage", self.log_target).into(),
            async move {
                let mut subscription = request.accept();
                let subscription_id = subscription.subscription_id().to_owned();

                let mut storage_updates = pin::pin!(storage_updates);

                loop {
                    let event = {
                        let unsubscribed = pin::pin!(subscription.wait_until_stale());
                        match future::select(storage_updates.next(), unsubscribed).await {
                            future::Either::Left((ev, _)) => either::Left(ev),
                            future::Either::Right((ev, _)) => either::Right(ev),
                        }
                    };

                    match event {
                        either::Left(None) => {
                            // Stream created above is always unlimited.
                            unreachable!()
                        }
                        either::Left(Some(changes)) => {
                            subscription
                                .send_notification(methods::ServerToClient::state_storage {
                                    subscription: (&subscription_id).into(),
                                    result: changes,
                                })
                                .await;
                        }
                        either::Right(()) => {
                            break;
                        }
                    }
                }
            },
        )
    }
}
