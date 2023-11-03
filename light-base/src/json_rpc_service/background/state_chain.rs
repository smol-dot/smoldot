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

use alloc::{format, string::ToString as _, sync::Arc, vec, vec::Vec};
use core::{iter, num::NonZeroU32, time::Duration};
use futures_channel::oneshot;
use smoldot::{
    header,
    json_rpc::{self, methods, service},
    network::codec,
};

impl<TPlat: PlatformRef> Background<TPlat> {
    /// Handles a call to [`methods::MethodCall::system_accountNextIndex`].
    pub(super) async fn account_next_index(self: &Arc<Self>, request: service::RequestProcess) {
        let methods::MethodCall::system_accountNextIndex { account } = request.request() else {
            unreachable!()
        };

        let block_hash = {
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                .await
                .unwrap();
            rx.await.unwrap()
        };

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
            None => {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                    .await
                    .unwrap();
                rx.await.unwrap()
            }
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

        // Block bodies and headers aren't stored locally. Ask the network.
        let mut result = if let Some(block_number) = block_number {
            self.sync_service
                .clone()
                .block_query(
                    block_number,
                    hash,
                    codec::BlocksRequestFields {
                        header: true,
                        body: true,
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
                    codec::BlocksRequestFields {
                        header: true,
                        body: true,
                        justifications: false,
                    },
                    3,
                    Duration::from_secs(8),
                    NonZeroU32::new(1).unwrap(),
                )
                .await
        };

        // Check whether the header and body are present and valid.
        // TODO: try the request again with a different peerin case the response is invalid, instead of returning null
        if let Ok(block) = &result {
            if let (Some(header), Some(body)) = (&block.header, &block.body) {
                if header::hash_from_scale_encoded_header(header) == hash {
                    if let Ok(decoded) =
                        header::decode(header, self.sync_service.block_number_bytes())
                    {
                        if header::extrinsics_root(body) != *decoded.extrinsics_root {
                            result = Err(());
                        }
                    } else {
                        // Note that if the header is undecodable it doesn't necessarily mean
                        // that the header and/or body is bad, but given that we have no way to
                        // check this we return an error.
                        result = Err(());
                    }
                } else {
                    result = Err(());
                }
            } else {
                result = Err(());
            }
        }

        // Return the response.
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
                // There's no way to verify the correctness of the justifications, consequently
                // we always return an empty list.
                justifications: None,
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
                let best_block = {
                    let (tx, rx) = oneshot::channel();
                    self.to_legacy
                        .lock()
                        .await
                        .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                        .await
                        .unwrap();
                    rx.await.unwrap()
                };

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
            None => {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                    .await
                    .unwrap();
                rx.await.unwrap()
            }
        };

        // Try to look in the cache of recent blocks. If not found, ask the peer-to-peer network.
        // `header` is `Err` if and only if the network request failed.
        let scale_encoded_header = {
            let from_cache = {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::BlockHeader {
                        block_hash: hash,
                        result_tx: tx,
                    })
                    .await
                    .unwrap();
                rx.await.unwrap()
            };

            if let Some(header) = from_cache {
                Ok(header)
            } else {
                // Header isn't known locally. We need to ask the network.
                // First, try to determine the block number by looking into the cache.
                // The request can be fulfilled no matter whether it is found, but knowing it will
                // lead to a better selection of peers, and thus increase the chances of the
                // requests succeeding.
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

                // Actual network query.
                let result = if let Some(block_number) = block_number {
                    self.sync_service
                        .clone()
                        .block_query(
                            block_number,
                            hash,
                            codec::BlocksRequestFields {
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
                            codec::BlocksRequestFields {
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
            None => {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                    .await
                    .unwrap();
                rx.await.unwrap()
            }
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
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                .await
                .unwrap();
            rx.await.unwrap()
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
            None => {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                    .await
                    .unwrap();
                rx.await.unwrap()
            }
        };

        // Obtain the state trie root and height of the requested block.
        // This is necessary to perform network storage queries.
        let (state_root, block_number) = {
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::BlockStateRootAndNumber {
                    block_hash: hash,
                    result_tx: tx,
                })
                .await
                .unwrap();

            match rx.await.unwrap() {
                Ok(v) => v,
                Err(err) => {
                    request.fail(json_rpc::parse::ErrorResponse::ServerError(
                        -32000,
                        &format!("Failed to fetch block information: {err}"),
                    ));
                    return;
                }
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
            None => {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                    .await
                    .unwrap();
                rx.await.unwrap()
            }
        };

        // A prefix of `None` means "empty".
        let prefix = prefix.unwrap_or(methods::HexString(Vec::new())).0;

        // Because the user is likely to call this function multiple times in a row with the exact
        // same parameters, we store the untruncated responses in a cache. Check if we hit the
        // cache.
        if let Some(keys) =
            self.state_get_keys_paged_cache
                .lock()
                .await
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
        let (state_root, block_number) = {
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::BlockStateRootAndNumber {
                    block_hash: hash,
                    result_tx: tx,
                })
                .await
                .unwrap();

            match rx.await.unwrap() {
                Ok(v) => v,
                Err(err) => {
                    request.fail(json_rpc::parse::ErrorResponse::ServerError(
                        -32000,
                        &format!("Failed to fetch block information: {err}"),
                    ));
                    return;
                }
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
                    self.state_get_keys_paged_cache
                        .lock()
                        .await
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
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                .await
                .unwrap();
            rx.await.unwrap()
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
            None => {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                    .await
                    .unwrap();
                rx.await.unwrap()
            }
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

        let hash = match hash {
            Some(h) => h.0,
            None => {
                let (tx, rx) = oneshot::channel();
                self.to_legacy
                    .lock()
                    .await
                    .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                    .await
                    .unwrap();
                rx.await.unwrap()
            }
        };

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

        let best_block = {
            let (tx, rx) = oneshot::channel();
            self.to_legacy
                .lock()
                .await
                .send(legacy_state_sub::Message::CurrentBestBlockHash { result_tx: tx })
                .await
                .unwrap();
            rx.await.unwrap()
        };

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
}
