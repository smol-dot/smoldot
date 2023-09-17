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

use super::{
    BlockNotification, ConfigRelayChainRuntimeCodeHint, FinalizedBlockRuntime, Notification,
    SubscribeAll, ToBackground,
};
use crate::{network_service, platform::PlatformRef, util};

use alloc::{borrow::ToOwned as _, boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{
    iter,
    num::{NonZeroU32, NonZeroU64},
    pin::Pin,
    time::Duration,
};
use futures_lite::FutureExt as _;
use futures_util::{future, stream, FutureExt as _, StreamExt as _};
use hashbrown::{HashMap, HashSet};
use smoldot::{
    chain, header,
    informant::HashDisplay,
    libp2p,
    network::{self, protocol},
    sync::all,
};

/// Starts a sync service background task to synchronize a standalone chain (relay chain or not).
pub(super) async fn start_standalone_chain<TPlat: PlatformRef>(
    log_target: String,
    platform: TPlat,
    chain_information: chain::chain_information::ValidChainInformation,
    block_number_bytes: usize,
    runtime_code_hint: Option<ConfigRelayChainRuntimeCodeHint>,
    mut from_foreground: async_channel::Receiver<ToBackground>,
    network_service: Arc<network_service::NetworkService<TPlat>>,
    network_chain_index: usize,
    mut from_network_service: stream::BoxStream<'static, network_service::Event>,
) {
    let mut task = Task {
        sync: all::AllSync::new(all::Config {
            chain_information,
            block_number_bytes,
            // Since this module doesn't verify block bodies, any block (even invalid) is accepted
            // as long as it comes from a legitimate validator. Consequently, validators could
            // perform attacks by sending completely invalid blocks. Passing `false` to this
            // option would tighten the definition of what a "legitimate" validator is, and thus
            // reduce the feasibility of attacks, but not in a significant way. Passing `true`,
            // on the other hand, allows supporting chains that use custom consensus engines,
            // which is considered worth the trade-off.
            allow_unknown_consensus_engines: true,
            sources_capacity: 32,
            blocks_capacity: {
                // This is the maximum number of blocks between two consecutive justifications.
                1024
            },
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZeroU32::new(3).unwrap(),
            download_ahead_blocks: {
                // Verifying a block mostly consists in:
                //
                // - Verifying a sr25519 signature for each block, plus a VRF output when the
                // block is claiming a primary BABE slot.
                // - Verifying one ed25519 signature per authority for every justification.
                //
                // At the time of writing, the speed of these operations hasn't been benchmarked.
                // It is likely that it varies quite a bit between the various environments (the
                // different browser engines, and NodeJS).
                //
                // Assuming a maximum verification speed of 5k blocks/sec and a 95% latency of one
                // second, the number of blocks to download ahead of time in order to not block
                // is 5k.
                NonZeroU32::new(5000).unwrap()
            },
            full_mode: false,
            code_trie_node_hint: runtime_code_hint.map(|hint| all::ConfigCodeTrieNodeHint {
                merkle_value: hint.merkle_value,
                storage_value: hint.storage_value,
                closest_ancestor_excluding: hint.closest_ancestor_excluding,
            }),
        }),
        network_up_to_date_best: true,
        network_up_to_date_finalized: true,
        known_finalized_runtime: None,
        pending_requests: stream::FuturesUnordered::new(),
        warp_sync_taking_long_time_warning: future::Either::Left(Box::pin(
            platform.sleep(Duration::from_secs(10)),
        ))
        .fuse(),
        all_notifications: Vec::<async_channel::Sender<Notification>>::new(),
        log_target,
        network_service,
        network_chain_index,
        peers_source_id_map: HashMap::with_capacity_and_hasher(
            0,
            util::SipHasherBuild::new({
                let mut seed = [0; 16];
                platform.fill_random_bytes(&mut seed);
                seed
            }),
        ),
        platform,
    };

    // Main loop of the syncing logic.
    //
    // This loop contains some CPU-heavy operations (e.g. verifying finality proofs and warp sync
    // proofs) but also responding to messages sent by the foreground sync service. In order to
    // avoid long delays in responding to foreground messages, the CPU-heavy operations are split
    // into small chunks, and each iteration of the loop processes at most one of these chunks and
    // processes one foreground message.
    loop {
        // Try to perform some CPU-heavy operations.
        // If any CPU-heavy verification was performed, then `queue_empty` will be `false`, in
        // which case we will loop again as soon as possible.
        let queue_empty = {
            let mut queue_empty = true;

            // Start a networking request (block requests, warp sync requests, etc.) that the
            // syncing state machine would like to start.
            if task.start_next_request() {
                queue_empty = false;
            }

            // TODO: handle obsolete requests

            // The sync state machine can be in a few various states. At the time of writing:
            // idle, verifying header, verifying block, verifying grandpa warp sync proof,
            // verifying storage proof.
            // If the state is one of the "verifying" states, perform the actual verification
            // and set ̀`queue_empty` to `false`.
            let (task_update, has_done_verif) = task.process_one_verification_queue().await;
            task = task_update;

            if has_done_verif {
                queue_empty = false;

                // Yield after a CPU-intensive operation. This helps provide a better granularity.
                futures_lite::future::yield_now().await;
            }

            queue_empty
        };

        // Processing the queue might have updated the best block of the syncing state machine.
        if !task.network_up_to_date_best {
            // The networking service needs to be kept up to date with what the local node
            // considers as the best block.
            // For some reason, first building the future then executing it solves a borrow
            // checker error.
            let fut = task.network_service.set_local_best_block(
                network_chain_index,
                task.sync.best_block_hash(),
                task.sync.best_block_number(),
            );
            fut.await;

            task.network_up_to_date_best = true;
        }

        // Processing the queue might have updated the finalized block of the syncing state
        // machine.
        if !task.network_up_to_date_finalized {
            // If the chain uses GrandPa, the networking has to be kept up-to-date with the
            // state of finalization for other peers to send back relevant gossip messages.
            // (code style) `grandpa_set_id` is extracted first in order to avoid borrowing
            // checker issues.
            let grandpa_set_id =
                if let chain::chain_information::ChainInformationFinalityRef::Grandpa {
                    after_finalized_block_authorities_set_id,
                    ..
                } = task.sync.as_chain_information().as_ref().finality
                {
                    Some(after_finalized_block_authorities_set_id)
                } else {
                    None
                };

            if let Some(set_id) = grandpa_set_id {
                let commit_finalized_height = task.sync.finalized_block_header().number;
                task.network_service
                    .set_local_grandpa_state(
                        network_chain_index,
                        network::service::GrandpaState {
                            set_id,
                            round_number: 1, // TODO:
                            commit_finalized_height,
                        },
                    )
                    .await;
            }

            task.network_up_to_date_finalized = true;
        }

        // Now waiting for some event to happen: a network event, a request from the frontend
        // of the sync service, or a request being finished.
        enum WhatHappened {
            NetworkEvent(network_service::Event),
            ForegroundMessage(ToBackground),
            ForegroundClosed,
            RequestFinished(all::RequestId, Result<RequestOutcome, future::Aborted>),
            WarpSyncTakingLongTimeWarning,
            MustLoopAgain,
        }

        let what_happened = {
            async {
                // We expect the networking channel to never close, so the event is unwrapped.
                WhatHappened::NetworkEvent(from_network_service.next().await.unwrap())
            }
            .or(async {
                from_foreground.next().await.map_or(
                    WhatHappened::ForegroundClosed,
                    WhatHappened::ForegroundMessage,
                )
            })
            .or(async {
                if task.pending_requests.is_empty() {
                    future::pending::<()>().await
                }
                let (request_id, result) = task.pending_requests.select_next_some().await;
                WhatHappened::RequestFinished(request_id, result)
            })
            .or(async {
                (&mut task.warp_sync_taking_long_time_warning).await;
                task.warp_sync_taking_long_time_warning =
                    future::Either::Left(Box::pin(task.platform.sleep(Duration::from_secs(10))))
                        .fuse();
                WhatHappened::WarpSyncTakingLongTimeWarning
            })
            .or(async {
                // If the list of CPU-heavy operations to perform is potentially non-empty,
                // then we wait for a future that is always instantly ready, in order to loop
                // again and perform the next CPU-heavy operation.
                // Note that if any of the other futures is ready, then that other ready
                // future will take precedence.
                if queue_empty {
                    future::pending::<()>().await;
                }
                WhatHappened::MustLoopAgain
            })
            .await
        };

        let response_outcome = match what_happened {
            WhatHappened::NetworkEvent(network_event) => {
                // Something happened on the networking.
                task.inject_network_event(network_event);
                continue;
            }

            WhatHappened::ForegroundMessage(message) => {
                // Received message from the front `SyncService`.
                task.process_foreground_message(message);
                continue;
            }

            WhatHappened::ForegroundClosed => {
                // The channel with the frontend sync service has been closed.
                // Closing the sync background task as a result.
                return;
            }

            WhatHappened::RequestFinished(request_id, result) => {
                // A request has been finished.
                // `result` is an error if the request got cancelled by the sync state machine.
                let Ok(result) = result else {
                    continue;
                };

                // Inject the result of the request into the sync state machine.
                match result {
                    RequestOutcome::Block(Ok(v)) => {
                        task.sync
                            .blocks_request_response(
                                request_id,
                                Ok(v.into_iter().filter_map(|block| {
                                    Some(all::BlockRequestSuccessBlock {
                                        scale_encoded_header: block.header?,
                                        scale_encoded_justifications: block
                                            .justifications
                                            .unwrap_or(Vec::new())
                                            .into_iter()
                                            .map(|j| all::Justification {
                                                engine_id: j.engine_id,
                                                justification: j.justification,
                                            })
                                            .collect(),
                                        scale_encoded_extrinsics: Vec::new(),
                                        user_data: (),
                                    })
                                })),
                            )
                            .1
                    }
                    RequestOutcome::Block(Err(_)) => {
                        task.sync
                            .blocks_request_response(request_id, Err::<iter::Empty<_>, _>(()))
                            .1
                    }
                    RequestOutcome::WarpSync(Ok(result)) => {
                        let decoded = result.decode();
                        let fragments = decoded
                            .fragments
                            .into_iter()
                            .map(|f| all::WarpSyncFragment {
                                scale_encoded_header: f.scale_encoded_header.to_vec(),
                                scale_encoded_justification: f.scale_encoded_justification.to_vec(),
                            })
                            .collect();
                        task.sync
                            .grandpa_warp_sync_response_ok(
                                request_id,
                                fragments,
                                decoded.is_finished,
                            )
                            .1
                    }
                    RequestOutcome::WarpSync(Err(_)) => {
                        task.sync.grandpa_warp_sync_response_err(request_id);
                        continue;
                    }
                    RequestOutcome::Storage(r) => task.sync.storage_get_response(request_id, r).1,
                    RequestOutcome::CallProof(Ok(r)) => {
                        task.sync
                            .call_proof_response(request_id, Ok(r.decode().to_owned()))
                            .1
                    } // TODO: need help from networking service to avoid this to_owned
                    RequestOutcome::CallProof(Err(err)) => {
                        task.sync.call_proof_response(request_id, Err(err)).1
                    }
                }
            }

            WhatHappened::WarpSyncTakingLongTimeWarning => {
                match task.sync.status() {
                    all::Status::Sync => {}
                    all::Status::WarpSyncFragments {
                        source: None,
                        finalized_block_hash,
                        finalized_block_number,
                    } => {
                        log::warn!(
                            target: &task.log_target,
                            "GrandPa warp sync idle at block #{} (0x{})",
                            finalized_block_number,
                            HashDisplay(&finalized_block_hash),
                        );
                    }
                    all::Status::WarpSyncFragments {
                        source: Some((_, (peer_id, _))),
                        finalized_block_hash,
                        finalized_block_number,
                    }
                    | all::Status::WarpSyncChainInformation {
                        source: (_, (peer_id, _)),
                        finalized_block_hash,
                        finalized_block_number,
                    } => {
                        log::warn!(
                            target: &task.log_target,
                            "GrandPa warp sync in progress. Block: #{} (0x{}). Peer attempt: {}.",
                            finalized_block_number,
                            HashDisplay(&finalized_block_hash),
                            peer_id
                        );
                    }
                };

                continue;
            }

            WhatHappened::MustLoopAgain => {
                continue;
            }
        };

        // `response_outcome` represents the way the state machine has changed as a
        // consequence of the response to a request.
        match response_outcome {
            all::ResponseOutcome::Outdated
            | all::ResponseOutcome::Queued
            | all::ResponseOutcome::NotFinalizedChain { .. }
            | all::ResponseOutcome::AllAlreadyInChain { .. } => {}
        }
    }
}

struct Task<TPlat: PlatformRef> {
    /// Log target to use for all logs that are emitted.
    log_target: String,

    /// Access to the platform's capabilities.
    platform: TPlat,

    /// Main syncing state machine. Contains a list of peers, requests, and blocks, and manages
    /// everything about the non-finalized chain.
    ///
    /// For each request, we store a [`future::AbortHandle`] that can be used to abort the
    /// request if desired.
    sync: all::AllSync<future::AbortHandle, (libp2p::PeerId, protocol::Role), ()>,

    /// If `Some`, contains the runtime of the current finalized block.
    known_finalized_runtime: Option<FinalizedBlockRuntime>,

    /// For each networking peer, the index of the corresponding peer within the [`Task::sync`].
    peers_source_id_map: HashMap<libp2p::PeerId, all::SourceId, util::SipHasherBuild>,

    /// `false` after the best block in the [`Task::sync`] has changed. Set back to `true`
    /// after the networking has been notified of this change.
    network_up_to_date_best: bool,
    /// `false` after the finalized block in the [`Task::sync`] has changed. Set back to `true`
    /// after the networking has been notified of this change.
    network_up_to_date_finalized: bool,

    /// All event subscribers that are interested in events about the chain.
    all_notifications: Vec<async_channel::Sender<Notification>>,

    /// Contains a `Delay` after which we print a warning about GrandPa warp sync taking a long
    /// time. Set to `Pending` after the warp sync has finished, so that future remains pending
    /// forever.
    warp_sync_taking_long_time_warning:
        future::Fuse<future::Either<Pin<Box<TPlat::Delay>>, future::Pending<()>>>,

    /// Network service. Used to send out requests to peers.
    network_service: Arc<network_service::NetworkService<TPlat>>,
    /// Index within the network service of the chain we are interested in. Must be indicated to
    /// the network service whenever a request is started.
    network_chain_index: usize,

    /// List of requests currently in progress.
    pending_requests: stream::FuturesUnordered<
        future::BoxFuture<'static, (all::RequestId, Result<RequestOutcome, future::Aborted>)>,
    >,
}

enum RequestOutcome {
    Block(Result<Vec<protocol::BlockData>, network_service::BlocksRequestError>),
    WarpSync(
        Result<
            network::service::EncodedGrandpaWarpSyncResponse,
            network_service::GrandpaWarpSyncRequestError,
        >,
    ),
    Storage(Result<Vec<u8>, ()>),
    CallProof(Result<network::service::EncodedMerkleProof, ()>),
}

impl<TPlat: PlatformRef> Task<TPlat> {
    /// Starts one network request if any is necessary.
    ///
    /// Returns `true` if a request has been started.
    fn start_next_request(&mut self) -> bool {
        // `desired_requests()` returns, in decreasing order of priority, the requests
        // that should be started in order for the syncing to proceed. The fact that multiple
        // requests are returned could be used to filter out undesired one. We use this
        // filtering to enforce a maximum of one ongoing request per source.
        let (source_id, _, mut request_detail) = match self
            .sync
            .desired_requests()
            .find(|(source_id, _, _)| self.sync.source_num_ongoing_requests(*source_id) == 0)
        {
            Some(v) => v,
            None => return false,
        };

        // Before inserting the request back to the syncing state machine, clamp the number
        // of blocks to the number of blocks we expect to receive.
        // This constant corresponds to the maximum number of blocks that nodes will answer
        // in one request. If this constant happens to be inaccurate, everything will still
        // work but less efficiently.
        request_detail.num_blocks_clamp(NonZeroU64::new(64).unwrap());

        match request_detail {
            all::DesiredRequest::BlocksRequest {
                first_block_hash,
                first_block_height,
                ascending,
                num_blocks,
                request_headers,
                request_bodies,
                request_justification,
            } => {
                let peer_id = self.sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let block_request = self.network_service.clone().blocks_request(
                    peer_id,
                    self.network_chain_index,
                    network::protocol::BlocksRequestConfig {
                        start: if let Some(first_block_hash) = first_block_hash {
                            network::protocol::BlocksRequestConfigStart::Hash(first_block_hash)
                        } else {
                            network::protocol::BlocksRequestConfigStart::Number(first_block_height)
                        },
                        desired_count: NonZeroU32::new(
                            u32::try_from(num_blocks.get()).unwrap_or(u32::max_value()),
                        )
                        .unwrap(),
                        direction: if ascending {
                            network::protocol::BlocksRequestDirection::Ascending
                        } else {
                            network::protocol::BlocksRequestDirection::Descending
                        },
                        fields: network::protocol::BlocksRequestFields {
                            header: request_headers,
                            body: request_bodies,
                            justifications: request_justification,
                        },
                    },
                    Duration::from_secs(10),
                );

                let (block_request, abort) = future::abortable(block_request);
                let request_id = self
                    .sync
                    .add_request(source_id, request_detail.into(), abort);

                self.pending_requests.push(Box::pin(async move {
                    (request_id, block_request.await.map(RequestOutcome::Block))
                }));
            }

            all::DesiredRequest::GrandpaWarpSync {
                sync_start_block_hash,
            } => {
                let peer_id = self.sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let grandpa_request = self.network_service.clone().grandpa_warp_sync_request(
                    peer_id,
                    self.network_chain_index,
                    sync_start_block_hash,
                    // The timeout needs to be long enough to potentially download the maximum
                    // response size of 16 MiB. Assuming a 128 kiB/sec connection, that's
                    // 128 seconds. Unfortunately, 128 seconds is way too large, and for
                    // pragmatic reasons we use a lower value.
                    Duration::from_secs(24),
                );

                let (grandpa_request, abort) = future::abortable(grandpa_request);
                let request_id = self
                    .sync
                    .add_request(source_id, request_detail.into(), abort);

                self.pending_requests.push(Box::pin(async move {
                    (
                        request_id,
                        grandpa_request.await.map(RequestOutcome::WarpSync),
                    )
                }));
            }

            all::DesiredRequest::StorageGetMerkleProof {
                block_hash,
                ref keys,
                ..
            } => {
                let peer_id = self.sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue

                let storage_request = self.network_service.clone().storage_proof_request(
                    self.network_chain_index,
                    peer_id,
                    network::protocol::StorageProofRequestConfig {
                        block_hash,
                        keys: keys.clone().into_iter(),
                    },
                    Duration::from_secs(16),
                );

                let storage_request = async move {
                    if let Ok(outcome) = storage_request.await {
                        // TODO: log what happens
                        Ok(outcome.decode().to_vec()) // TODO: no to_vec() here, needs some API change on the networking
                    } else {
                        Err(())
                    }
                };

                let (storage_request, abort) = future::abortable(storage_request);
                let request_id = self
                    .sync
                    .add_request(source_id, request_detail.into(), abort);

                self.pending_requests.push(Box::pin(async move {
                    (
                        request_id,
                        storage_request.await.map(RequestOutcome::Storage),
                    )
                }));
            }

            all::DesiredRequest::RuntimeCallMerkleProof {
                block_hash,
                ref function_name,
                ref parameter_vectored,
            } => {
                let peer_id = self.sync[source_id].0.clone(); // TODO: why does this require cloning? weird borrow chk issue
                let network_service = self.network_service.clone();
                let network_chain_index = self.network_chain_index;
                // TODO: all this copying is done because of lifetime requirements in NetworkService::call_proof_request; maybe check if it can be avoided
                let parameter_vectored = parameter_vectored.clone();
                let function_name = function_name.clone();

                let call_proof_request = async move {
                    let rq = network_service.call_proof_request(
                        network_chain_index,
                        peer_id,
                        network::protocol::CallProofRequestConfig {
                            block_hash,
                            method: function_name,
                            parameter_vectored: iter::once(parameter_vectored),
                        },
                        Duration::from_secs(16),
                    );

                    match rq.await {
                        Ok(p) => Ok(p),
                        Err(_) => Err(()),
                    }
                };

                let (call_proof_request, abort) = future::abortable(call_proof_request);
                let request_id = self
                    .sync
                    .add_request(source_id, request_detail.into(), abort);

                self.pending_requests.push(Box::pin(async move {
                    (
                        request_id,
                        call_proof_request.await.map(RequestOutcome::CallProof),
                    )
                }));
            }
        }

        true
    }

    /// Verifies one block, or finality proof, or warp sync fragment, etc. that is queued for
    /// verification.
    ///
    /// Returns `self` and a boolean indicating whether something has been processed.
    async fn process_one_verification_queue(mut self) -> (Self, bool) {
        // Note that `process_one` moves out of `sync` and provides the value back in its
        // return value.
        match self.sync.process_one() {
            all::ProcessOne::AllSync(sync) => {
                // Nothing to do. Queue is empty.
                self.sync = sync;
                return (self, false);
            }

            all::ProcessOne::WarpSyncBuildRuntime(req) => {
                // Warp syncing compiles the runtime. The compiled runtime will later be yielded
                // in the `WarpSyncFinished` variant, which is then provided as an event.
                let before_instant = self.platform.now();
                let (new_sync, error) = req.build(all::ExecHint::CompileAheadOfTime, true);
                let elapsed = self.platform.now() - before_instant;
                match error {
                    Ok(()) => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => WarpSyncRuntimeBuild(success=true, duration={:?})",
                            elapsed
                        );
                    }
                    Err(err) => {
                        log::debug!(target: &self.log_target, "Sync => WarpSyncRuntimeBuild(error={})", err);
                        log::warn!(target: &self.log_target, "Failed to compile runtime during warp syncing process: {}", err);
                    }
                };
                self.sync = new_sync;
            }

            all::ProcessOne::WarpSyncBuildChainInformation(req) => {
                let (new_sync, error) = req.build();
                match error {
                    Ok(()) => {
                        log::debug!(target: &self.log_target, "Sync => WarpSyncBuildChainInformation(success=true)")
                    }
                    Err(err) => {
                        log::debug!(target: &self.log_target, "Sync => WarpSyncBuildChainInformation(error={})", err);
                        log::warn!(target: &self.log_target, "Failed to build the chain information during warp syncing process: {}", err);
                    }
                };
                self.sync = new_sync;
            }

            all::ProcessOne::WarpSyncFinished {
                sync,
                finalized_block_runtime,
                finalized_storage_code,
                finalized_storage_code_closest_ancestor_excluding,
                finalized_storage_heap_pages,
                finalized_storage_code_merkle_value,
            } => {
                self.sync = sync;

                let finalized_header = self.sync.finalized_block_header();
                log::info!(
                    target: &self.log_target,
                    "GrandPa warp sync finished to #{} ({})",
                    finalized_header.number,
                    HashDisplay(&finalized_header.hash(self.sync.block_number_bytes()))
                );

                self.warp_sync_taking_long_time_warning =
                    future::Either::Right(future::pending()).fuse();

                debug_assert!(self.known_finalized_runtime.is_none());
                self.known_finalized_runtime = Some(FinalizedBlockRuntime {
                    virtual_machine: finalized_block_runtime,
                    storage_code: finalized_storage_code,
                    storage_heap_pages: finalized_storage_heap_pages,
                    code_merkle_value: finalized_storage_code_merkle_value,
                    closest_ancestor_excluding: finalized_storage_code_closest_ancestor_excluding,
                });

                self.network_up_to_date_finalized = false;
                self.network_up_to_date_best = false;
                // Since there is a gap in the blocks, all active notifications to all blocks
                // must be cleared.
                self.all_notifications.clear();
            }

            all::ProcessOne::VerifyWarpSyncFragment(verify) => {
                // Grandpa warp sync fragment to verify.
                let sender_peer_id = verify.proof_sender().1 .0.clone(); // TODO: unnecessary cloning most of the time

                let (sync, result) = verify.perform({
                    let mut seed = [0; 32];
                    self.platform.fill_random_bytes(&mut seed);
                    seed
                });
                self.sync = sync;

                if let Err(err) = result {
                    let maybe_forced_change = matches!(err, all::WarpSyncFragmentError::Verify(_));
                    log::warn!(
                        target: &self.log_target,
                        "Failed to verify warp sync fragment from {}: {}{}",
                        sender_peer_id,
                        err,
                        if maybe_forced_change {
                            ". This might be caused by a forced GrandPa authorities change having \
                            been enacted on the chain. If this is the case, please update the \
                            chain specification with a checkpoint past this forced change."
                        } else { "" }
                    );
                } else {
                    log::debug!(
                        target: &self.log_target,
                        "Sync => WarpSyncFragmentVerified(sender={})",
                        sender_peer_id,
                    );
                }
            }

            all::ProcessOne::VerifyBlock(verify) => {
                // Header to verify.
                let verified_hash = verify.hash();
                match verify.verify_header(self.platform.now_from_unix_epoch()) {
                    all::HeaderVerifyOutcome::Success {
                        success,
                        is_new_best,
                        ..
                    } => {
                        let verified_height = success.height();
                        self.sync = success.finish(());

                        log::debug!(
                            target: &self.log_target,
                            "Sync => HeaderVerified(hash={}, new_best={})",
                            HashDisplay(&verified_hash),
                            if is_new_best { "yes" } else { "no" }
                        );

                        if is_new_best {
                            self.network_up_to_date_best = false;
                        }

                        let (parent_hash, scale_encoded_header) = {
                            // TODO: the code below is `O(n)` complexity
                            let header = self
                                .sync
                                .non_finalized_blocks_unordered()
                                .find(|h| h.hash(self.sync.block_number_bytes()) == verified_hash)
                                .unwrap();
                            (
                                *header.parent_hash,
                                header.scale_encoding_vec(self.sync.block_number_bytes()),
                            )
                        };

                        // Announce the newly-verified block to all the light client sources that
                        // might not be aware of it. We can never be guaranteed that a certain
                        // source does *not* know about a block, however it is not a big problem
                        // to send a block announce to a source that already knows about that
                        // block. For this reason, the list of sources we send the block announce
                        // to is `all_sources - sources_that_know_it`.
                        //
                        // Note that not sending block announces to sources that already know that
                        // block means that these sources might also miss the fact that our local
                        // best block has been updated. This is in practice not a problem either.
                        //
                        // Block announces are intentionally sent only to light clients, and not
                        // to full nodes. Block announces coming from light clients are useless to
                        // full nodes, as they can't download the block body (which they need)
                        // from that light client.
                        //
                        // Announcing blocks to other light clients increases the likelihood that
                        // equivocations are detected by light clients. This is especially
                        // important for light clients, as they try to connect to as few full
                        // nodes as possible.
                        let sources_to_announce_to = {
                            let mut all_sources = self
                                .sync
                                .sources()
                                .filter(|s| matches!(self.sync[*s].1, protocol::Role::Light))
                                .collect::<HashSet<_, fnv::FnvBuildHasher>>();
                            for knows in self
                                .sync
                                .knows_non_finalized_block(verified_height, &verified_hash)
                            {
                                all_sources.remove(&knows);
                            }
                            all_sources
                        };

                        for source_id in sources_to_announce_to {
                            // The `PeerId` needs to be cloned, otherwise `self` would have to
                            // stay borrowed accross an `await`, which isn't possible because it
                            // doesn't implement `Sync`.
                            let (source_peer_id, _source_role) = &self.sync[source_id].clone();
                            debug_assert!(matches!(_source_role, protocol::Role::Light));

                            if self
                                .network_service
                                .clone()
                                .send_block_announce(
                                    source_peer_id,
                                    self.network_chain_index,
                                    &scale_encoded_header,
                                    is_new_best,
                                )
                                .await
                                .is_ok()
                            {
                                log::debug!(
                                    target: &self.log_target,
                                    "Network <= BlockAnnounce(peer_id={}, hash={})",
                                    source_peer_id,
                                    HashDisplay(&verified_hash)
                                );

                                // Update the sync state machine with the fact that the target of
                                // the block announce now knows this block.
                                //
                                // This code is never called for full nodes. When it comes to full
                                // nodes, we want track knowledge about block bodies and storage
                                // rather than just headers.
                                //
                                // Note that `try_add_known_block_to_source` might have
                                // no effect, which is not a problem considering that this
                                // block tracking is mostly about optimizations and
                                // politeness.
                                self.sync.try_add_known_block_to_source(
                                    source_id,
                                    verified_height,
                                    verified_hash,
                                );
                            }
                        }

                        // Notify of the new block.
                        self.dispatch_all_subscribers({
                            Notification::Block(BlockNotification {
                                is_new_best,
                                scale_encoded_header,
                                parent_hash,
                            })
                        });
                    }

                    all::HeaderVerifyOutcome::Error { sync, error, .. } => {
                        self.sync = sync;

                        // TODO: print which peer sent the header
                        log::debug!(
                            target: &self.log_target,
                            "Sync => HeaderVerifyError(hash={}, error={:?})",
                            HashDisplay(&verified_hash),
                            error
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Error while verifying header {}: {}",
                            HashDisplay(&verified_hash),
                            error
                        );
                    }
                }
            }

            all::ProcessOne::VerifyFinalityProof(verify) => {
                // Finality proof to verify.
                match verify.perform({
                    let mut seed = [0; 32];
                    self.platform.fill_random_bytes(&mut seed);
                    seed
                }) {
                    (
                        sync,
                        all::FinalityProofVerifyOutcome::NewFinalized {
                            updates_best_block,
                            finalized_blocks_newest_to_oldest,
                            ..
                        },
                    ) => {
                        self.sync = sync;

                        log::debug!(
                            target: &self.log_target,
                            "Sync => FinalityProofVerified(finalized_blocks={})",
                            finalized_blocks_newest_to_oldest.len(),
                        );

                        if updates_best_block {
                            self.network_up_to_date_best = false;
                        }
                        self.network_up_to_date_finalized = false;
                        // Invalidate the cache of the runtime of the finalized blocks if any
                        // of the finalized blocks indicates that a runtime update happened.
                        if finalized_blocks_newest_to_oldest
                            .iter()
                            .any(|b| b.header.digest.has_runtime_environment_updated())
                        {
                            self.known_finalized_runtime = None;
                        }
                        self.dispatch_all_subscribers(Notification::Finalized {
                            hash: self
                                .sync
                                .finalized_block_header()
                                .hash(self.sync.block_number_bytes()),
                            best_block_hash: self.sync.best_block_hash(),
                        });
                    }

                    (
                        sync,
                        all::FinalityProofVerifyOutcome::AlreadyFinalized
                        | all::FinalityProofVerifyOutcome::GrandpaCommitPending,
                    ) => {
                        self.sync = sync;
                    }

                    (sync, all::FinalityProofVerifyOutcome::JustificationError(error)) => {
                        self.sync = sync;

                        // TODO: print which peer sent the proof
                        log::debug!(
                            target: &self.log_target,
                            "Sync => JustificationVerificationError(error={:?})",
                            error,
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Error while verifying justification: {}",
                            error
                        );
                    }

                    (sync, all::FinalityProofVerifyOutcome::GrandpaCommitError(error)) => {
                        self.sync = sync;

                        // TODO: print which peer sent the proof
                        log::debug!(
                            target: &self.log_target,
                            "Sync => GrandpaCommitVerificationError(error={:?})",
                            error,
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Error while verifying GrandPa commit: {}",
                            error
                        );
                    }
                }
            }
        }

        (self, true)
    }

    /// Process a request coming from the foreground service.
    fn process_foreground_message(&mut self, message: ToBackground) {
        match message {
            ToBackground::IsNearHeadOfChainHeuristic { send_back } => {
                let _ = send_back.send(self.sync.is_near_head_of_chain_heuristic());
            }

            ToBackground::SubscribeAll {
                send_back,
                buffer_size,
                runtime_interest,
            } => {
                let (tx, new_blocks) = async_channel::bounded(buffer_size.saturating_sub(1));
                self.all_notifications.push(tx);

                let non_finalized_blocks_ancestry_order = {
                    let best_hash = self.sync.best_block_hash();
                    self.sync
                        .non_finalized_blocks_ancestry_order()
                        .map(|h| {
                            let scale_encoding =
                                h.scale_encoding_vec(self.sync.block_number_bytes());
                            BlockNotification {
                                is_new_best: header::hash_from_scale_encoded_header(
                                    &scale_encoding,
                                ) == best_hash,
                                scale_encoded_header: scale_encoding,
                                parent_hash: *h.parent_hash,
                            }
                        })
                        .collect()
                };

                let _ = send_back.send(SubscribeAll {
                    finalized_block_scale_encoded_header: self
                        .sync
                        .finalized_block_header()
                        .scale_encoding_vec(self.sync.block_number_bytes()),
                    finalized_block_runtime: if runtime_interest {
                        self.known_finalized_runtime.take()
                    } else {
                        None
                    },
                    non_finalized_blocks_ancestry_order,
                    new_blocks,
                });
            }

            ToBackground::PeersAssumedKnowBlock {
                send_back,
                block_number,
                block_hash,
            } => {
                let finalized_num = self.sync.finalized_block_header().number;
                let outcome = if block_number <= finalized_num {
                    self.sync
                        .sources()
                        .filter(|source_id| {
                            let source_best = self.sync.source_best_block(*source_id);
                            source_best.0 > block_number
                                || (source_best.0 == block_number && *source_best.1 == block_hash)
                        })
                        .map(|id| self.sync[id].0.clone())
                        .collect()
                } else {
                    // As documented, `knows_non_finalized_block` would panic if the
                    // block height was below the one of the known finalized block.
                    self.sync
                        .knows_non_finalized_block(block_number, &block_hash)
                        .map(|id| self.sync[id].0.clone())
                        .collect()
                };
                let _ = send_back.send(outcome);
            }

            ToBackground::SyncingPeers { send_back } => {
                let out = self
                    .sync
                    .sources()
                    .map(|src| {
                        let (peer_id, role) = self.sync[src].clone();
                        let (height, hash) = self.sync.source_best_block(src);
                        (peer_id, role, height, *hash)
                    })
                    .collect::<Vec<_>>();
                let _ = send_back.send(out);
            }

            ToBackground::SerializeChainInformation { send_back } => {
                let _ = send_back.send(Some(self.sync.as_chain_information().into()));
            }
        }
    }

    /// Updates the task with a new event coming from the network service.
    fn inject_network_event(&mut self, network_event: network_service::Event) {
        match network_event {
            network_service::Event::Connected {
                peer_id,
                role,
                chain_index,
                best_block_number,
                best_block_hash,
            } if chain_index == self.network_chain_index => {
                self.peers_source_id_map.insert(
                    peer_id.clone(),
                    self.sync
                        .add_source((peer_id, role), best_block_number, best_block_hash),
                );
            }

            network_service::Event::Disconnected {
                peer_id,
                chain_index,
            } if chain_index == self.network_chain_index => {
                let sync_source_id = self.peers_source_id_map.remove(&peer_id).unwrap();
                let (_, requests) = self.sync.remove_source(sync_source_id);

                // The `Disconnect` network event indicates that the main notifications substream
                // with that peer has been closed, not necessarily that the connection as a whole
                // has been closed. As such, the in-progress network requests might continue if
                // we don't abort them.
                for (_, abort) in requests {
                    abort.abort();
                }
            }

            network_service::Event::BlockAnnounce {
                chain_index,
                peer_id,
                announce,
            } if chain_index == self.network_chain_index => {
                let sync_source_id = *self.peers_source_id_map.get(&peer_id).unwrap();
                let decoded = announce.decode();

                match header::decode(decoded.scale_encoded_header, self.sync.block_number_bytes()) {
                    Ok(decoded_header) => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync <= BlockAnnounce(sender={}, hash={}, is_best={}, parent_hash={})",
                            peer_id,
                            HashDisplay(&header::hash_from_scale_encoded_header(decoded.scale_encoded_header)),
                            decoded.is_best,
                            HashDisplay(decoded_header.parent_hash)
                        );
                    }
                    Err(error) => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync <= BlockAnnounce(sender={}, hash={}, is_best={}, parent_hash=<unknown>)",
                            peer_id,
                            HashDisplay(&header::hash_from_scale_encoded_header(decoded.scale_encoded_header)),
                            decoded.is_best,
                        );

                        log::debug!(
                            target: &self.log_target,
                            "Sync => InvalidBlockHeader(error={})",
                            error
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Failed to decode header in block announce received from {}. Error: {}",
                            peer_id, error,
                        )
                    }
                }

                match self.sync.block_announce(
                    sync_source_id,
                    decoded.scale_encoded_header.to_owned(),
                    decoded.is_best,
                ) {
                    all::BlockAnnounceOutcome::HeaderVerify
                    | all::BlockAnnounceOutcome::AlreadyInChain => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => Ok"
                        );
                    }
                    all::BlockAnnounceOutcome::Discarded => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => Discarded"
                        );
                    }
                    all::BlockAnnounceOutcome::StoredForLater {} => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => StoredForLater"
                        );
                    }
                    all::BlockAnnounceOutcome::TooOld {
                        announce_block_height,
                        ..
                    } => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => TooOld"
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Block announce header height (#{}) from {} is below finalized block",
                            announce_block_height,
                            peer_id
                        );
                    }
                    all::BlockAnnounceOutcome::NotFinalizedChain => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync => NotFinalized"
                        );

                        log::warn!(
                            target: &self.log_target,
                            "Block announce from {} isn't part of finalized chain",
                            peer_id
                        );
                    }
                    all::BlockAnnounceOutcome::InvalidHeader(_) => {
                        // Log messages are already printed above.
                    }
                }
            }

            network_service::Event::GrandpaNeighborPacket {
                peer_id,
                chain_index,
                finalized_block_height,
            } if chain_index == self.network_chain_index => {
                let sync_source_id = *self.peers_source_id_map.get(&peer_id).unwrap();
                self.sync
                    .update_source_finality_state(sync_source_id, finalized_block_height);
            }

            network_service::Event::GrandpaCommitMessage {
                chain_index,
                peer_id,
                message,
            } if chain_index == self.network_chain_index => {
                let sync_source_id = *self.peers_source_id_map.get(&peer_id).unwrap();
                match self
                    .sync
                    .grandpa_commit_message(sync_source_id, message.into_encoded())
                {
                    all::GrandpaCommitMessageOutcome::Queued => {
                        // TODO: print more details?
                        log::debug!(
                            target: &self.log_target,
                            "Sync <= QueuedGrandpaCommit"
                        );
                    }
                    all::GrandpaCommitMessageOutcome::Discarded => {
                        log::debug!(
                            target: &self.log_target,
                            "Sync <= IgnoredGrandpaCommit"
                        );
                    }
                }
            }

            _ => {
                // Different chain index.
            }
        }
    }

    /// Sends a notification to all the notification receivers.
    fn dispatch_all_subscribers(&mut self, notification: Notification) {
        // Elements in `all_notifications` are removed one by one and inserted back if the
        // channel is still open.
        for index in (0..self.all_notifications.len()).rev() {
            let subscription = self.all_notifications.swap_remove(index);
            if subscription.try_send(notification.clone()).is_err() {
                continue;
            }

            self.all_notifications.push(subscription);
        }
    }
}
