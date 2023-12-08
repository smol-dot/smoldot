// Substrate-lite
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

//! All syncing strategies (optimistic, warp sync, all forks) grouped together.
//!
//! This state machine combines GrandPa warp syncing, optimistic syncing, and all forks syncing
//! into one state machine.
//!
//! # Overview
//!
//! This state machine acts as a container of sources, blocks (verified or not), and requests.
//! In order to initialize it, you need to pass, amongst other things, a
//! [`chain_information::ChainInformation`] struct indicating the known state of the finality of
//! the chain.
//!
//! A *request* represents a query for information from a source. Once the request has finished,
//! call one of the methods of the [`AllSync`] in order to notify the state machine of the outcome.

use crate::{
    chain::{blocks_tree, chain_information},
    executor::host,
    finality::decode,
    header,
    sync::{all_forks, optimistic, warp_sync},
    trie::Nibble,
    verify,
};

use alloc::{borrow::Cow, vec::Vec};
use core::{
    cmp, iter, marker, mem,
    num::{NonZeroU32, NonZeroU64},
    ops,
    time::Duration,
};

pub use crate::executor::vm::ExecHint;
pub use warp_sync::{
    BuildChainInformationError as WarpSyncBuildChainInformationError,
    BuildRuntimeError as WarpSyncBuildRuntimeError, ConfigCodeTrieNodeHint, VerifyFragmentError,
    WarpSyncFragment,
};

/// Configuration for the [`AllSync`].
// TODO: review these fields
#[derive(Debug)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// Number of bytes used when encoding/decoding the block number. Influences how various data
    /// structures should be parsed.
    pub block_number_bytes: usize,

    /// If `false`, blocks containing digest items with an unknown consensus engine will fail to
    /// verify.
    ///
    /// Note that blocks must always contain digest items that are relevant to the current
    /// consensus algorithm. This option controls what happens when blocks contain additional
    /// digest items that aren't recognized by the implementation.
    ///
    /// Passing `true` can lead to blocks being considered as valid when they shouldn't, as these
    /// additional digest items could have some logic attached to them that restricts which blocks
    /// are valid and which are not.
    ///
    /// However, since a recognized consensus engine must always be present, both `true` and
    /// `false` guarantee that the number of authorable blocks over the network is bounded.
    pub allow_unknown_consensus_engines: bool,

    /// Pre-allocated capacity for the number of block sources.
    pub sources_capacity: usize,

    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    ///
    /// Should be set to the maximum number of block between two consecutive justifications.
    pub blocks_capacity: usize,

    /// Maximum number of blocks of unknown ancestry to keep in memory.
    ///
    /// See [`all_forks::Config::max_disjoint_headers`] for more information.
    pub max_disjoint_headers: usize,

    /// Maximum number of simultaneous pending requests made towards the same block.
    ///
    /// See [`all_forks::Config::max_requests_per_block`] for more information.
    pub max_requests_per_block: NonZeroU32,

    /// Number of blocks to download ahead of the best verified block.
    ///
    /// Whenever the latest best block is updated, the state machine will start block
    /// requests for the block `best_block_height + download_ahead_blocks` and all its
    /// ancestors. Considering that requesting blocks has some latency, downloading blocks ahead
    /// of time ensures that verification isn't blocked waiting for a request to be finished.
    ///
    /// The ideal value here depends on the speed of blocks verification speed and latency of
    /// block requests.
    pub download_ahead_blocks: NonZeroU32,

    /// If `true`, the block bodies and storage are also synchronized and the block bodies are
    /// verified.
    // TODO: change this now that we don't verify block bodies here
    pub full_mode: bool,

    /// Known valid Merkle value and storage value combination for the `:code` key.
    ///
    /// If provided, the warp syncing algorithm will first fetch the Merkle value of `:code`, and
    /// if it matches the Merkle value provided in the hint, use the storage value in the hint
    /// instead of downloading it. If the hint doesn't match, an extra round-trip will be needed,
    /// but if the hint matches it saves a big download.
    // TODO: provide only in non-full mode?
    pub code_trie_node_hint: Option<ConfigCodeTrieNodeHint>,
}

/// Identifier for a source in the [`AllSync`].
//
// Implementation note: this is an index in `AllSync::sources`.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(usize);

/// Identifier for a request in the [`AllSync`].
//
// Implementation note: this is an index in `AllSync::requests`.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(usize);

/// Status of the synchronization.
#[derive(Debug)]
pub enum Status<'a, TSrc> {
    /// Regular syncing mode.
    Sync,
    /// Warp syncing algorithm is downloading Grandpa warp sync fragments containing a finality
    /// proof.
    WarpSyncFragments {
        /// Source from which the fragments are currently being downloaded, if any.
        source: Option<(SourceId, &'a TSrc)>,
        /// Hash of the highest block that is proven to be finalized.
        ///
        /// This isn't necessarily the same block as returned by
        /// [`AllSync::as_chain_information`], as this function first has to download extra
        /// information compared to just the finalized block.
        finalized_block_hash: [u8; 32],
        /// Height of the block indicated by [`Status::WarpSyncFragments::finalized_block_hash`].
        finalized_block_number: u64,
    },
    /// Warp syncing algorithm has reached the head of the finalized chain and is downloading and
    /// building the chain information.
    WarpSyncChainInformation {
        /// Hash of the highest block that is proven to be finalized.
        ///
        /// This isn't necessarily the same block as returned by
        /// [`AllSync::as_chain_information`], as this function first has to download extra
        /// information compared to just the finalized block.
        finalized_block_hash: [u8; 32],
        /// Height of the block indicated by
        /// [`Status::WarpSyncChainInformation::finalized_block_hash`].
        finalized_block_number: u64,
    },
}

pub struct AllSync<TRq, TSrc, TBl> {
    inner: AllSyncInner<TRq, TSrc, TBl>,
    shared: Shared<TRq>,
}

impl<TRq, TSrc, TBl> AllSync<TRq, TSrc, TBl> {
    /// Initializes a new state machine.
    pub fn new(config: Config) -> Self {
        AllSync {
            inner: if config.full_mode {
                AllSyncInner::Optimistic {
                    inner: optimistic::OptimisticSync::new(optimistic::Config {
                        chain_information: config.chain_information,
                        block_number_bytes: config.block_number_bytes,
                        sources_capacity: config.sources_capacity,
                        blocks_capacity: config.blocks_capacity,
                        download_ahead_blocks: config.download_ahead_blocks,
                        download_bodies: config.full_mode,
                    }),
                }
            } else {
                match warp_sync::start_warp_sync(warp_sync::Config {
                    start_chain_information: config.chain_information,
                    block_number_bytes: config.block_number_bytes,
                    sources_capacity: config.sources_capacity,
                    requests_capacity: config.sources_capacity, // TODO: ?! add as config?
                    code_trie_node_hint: config.code_trie_node_hint,
                    num_download_ahead_fragments: 128, // TODO: make configurable?
                    // TODO: make configurable?
                    // TODO: temporarily 0 before https://github.com/smol-dot/smoldot/issues/1109, as otherwise the warp syncing would take a long time if the starting point is too recent
                    warp_sync_minimum_gap: 0,
                }) {
                    Ok(inner) => AllSyncInner::WarpSync {
                        inner,
                        ready_to_transition: None,
                    },
                    Err((
                        chain_information,
                        warp_sync::WarpSyncInitError::NotGrandpa
                        | warp_sync::WarpSyncInitError::UnknownConsensus,
                    )) => {
                        // On error, `warp_sync` returns back the chain information that was
                        // provided in its configuration.
                        AllSyncInner::Optimistic {
                            inner: optimistic::OptimisticSync::new(optimistic::Config {
                                chain_information,
                                block_number_bytes: config.block_number_bytes,
                                sources_capacity: config.sources_capacity,
                                blocks_capacity: config.blocks_capacity,
                                download_ahead_blocks: config.download_ahead_blocks,
                                download_bodies: false,
                            }),
                        }
                    }
                }
            },
            shared: Shared {
                sources: slab::Slab::with_capacity(config.sources_capacity),
                requests: slab::Slab::with_capacity(config.sources_capacity),
                full_mode: config.full_mode,
                sources_capacity: config.sources_capacity,
                blocks_capacity: config.blocks_capacity,
                max_disjoint_headers: config.max_disjoint_headers,
                max_requests_per_block: config.max_requests_per_block,
                block_number_bytes: config.block_number_bytes,
                allow_unknown_consensus_engines: config.allow_unknown_consensus_engines,
            },
        }
    }

    /// Returns the value that was initially passed in [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.shared.block_number_bytes
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ValidChainInformationRef {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.as_chain_information(),
            AllSyncInner::WarpSync { inner, .. } => inner.as_chain_information(),
            AllSyncInner::Optimistic { inner } => inner.as_chain_information(),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the current status of the syncing.
    pub fn status(&self) -> Status<TSrc> {
        match &self.inner {
            AllSyncInner::AllForks(_) => Status::Sync,
            AllSyncInner::WarpSync { inner, .. } => match inner.status() {
                warp_sync::Status::Fragments {
                    source: None,
                    finalized_block_hash,
                    finalized_block_number,
                } => Status::WarpSyncFragments {
                    source: None,
                    finalized_block_hash,
                    finalized_block_number,
                },
                warp_sync::Status::Fragments {
                    source: Some((_, user_data)),
                    finalized_block_hash,
                    finalized_block_number,
                } => Status::WarpSyncFragments {
                    source: Some((user_data.outer_source_id, &user_data.user_data)),
                    finalized_block_hash,
                    finalized_block_number,
                },
                warp_sync::Status::ChainInformation {
                    finalized_block_hash,
                    finalized_block_number,
                } => Status::WarpSyncChainInformation {
                    finalized_block_hash,
                    finalized_block_number,
                },
            },
            AllSyncInner::Optimistic { .. } => Status::Sync, // TODO: right now we don't differentiate between AllForks and Optimistic, as they're kind of similar anyway
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.finalized_block_header(),
            AllSyncInner::Optimistic { inner } => inner.finalized_block_header(),
            AllSyncInner::WarpSync { inner, .. } => {
                inner.as_chain_information().as_ref().finalized_block_header
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.best_block_header(),
            AllSyncInner::Optimistic { inner } => inner.best_block_header(),
            AllSyncInner::WarpSync { .. } => self.finalized_block_header(),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.best_block_number(),
            AllSyncInner::Optimistic { inner } => inner.best_block_number(),
            AllSyncInner::WarpSync { .. } => self.best_block_header().number,
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        match &self.inner {
            AllSyncInner::AllForks(sync) => sync.best_block_hash(),
            AllSyncInner::Optimistic { inner } => inner.best_block_hash(),
            AllSyncInner::WarpSync { .. } => self
                .best_block_header()
                .hash(self.shared.block_number_bytes),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns consensus information about the current best block of the chain.
    pub fn best_block_consensus(&self) -> chain_information::ChainInformationConsensusRef {
        match &self.inner {
            AllSyncInner::AllForks(_) => todo!(), // TODO:
            AllSyncInner::Optimistic { inner } => inner.best_block_consensus(),
            AllSyncInner::WarpSync { .. } => todo!(), // TODO: ?!
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of all known non-finalized blocks in the chain without any specific
    /// order.
    pub fn non_finalized_blocks_unordered(&self) -> impl Iterator<Item = header::HeaderRef> {
        match &self.inner {
            AllSyncInner::AllForks(sync) => {
                let iter = sync.non_finalized_blocks_unordered();
                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner } => {
                let iter = inner.non_finalized_blocks_unordered();
                either::Right(either::Left(iter))
            }
            AllSyncInner::WarpSync { .. } => either::Right(either::Right(iter::empty())),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The returned items are guaranteed to be in an order in which the parents are found before
    /// their children.
    pub fn non_finalized_blocks_ancestry_order(&self) -> impl Iterator<Item = header::HeaderRef> {
        match &self.inner {
            AllSyncInner::AllForks(sync) => {
                let iter = sync.non_finalized_blocks_ancestry_order();
                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner } => {
                let iter = inner.non_finalized_blocks_ancestry_order();
                either::Right(either::Left(iter))
            }
            AllSyncInner::WarpSync { .. } => either::Right(either::Right(iter::empty())),
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub fn is_near_head_of_chain_heuristic(&self) -> bool {
        match &self.inner {
            AllSyncInner::AllForks(_) => true,
            AllSyncInner::Optimistic { .. } => false,
            AllSyncInner::WarpSync { .. } => false,
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Adds a new source to the sync state machine.
    ///
    /// Must be passed the best block number and hash of the source, as usually reported by the
    /// source itself.
    ///
    /// Returns an identifier for this new source, plus a list of requests to start or cancel.
    pub fn add_source(
        &mut self,
        user_data: TSrc,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> SourceId {
        // `inner` is temporarily replaced with `Poisoned`. A new value must be put back before
        // returning.
        match mem::replace(&mut self.inner, AllSyncInner::Poisoned) {
            AllSyncInner::WarpSync {
                mut inner,
                ready_to_transition,
            } => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let source_extra = WarpSyncSourceExtra {
                    outer_source_id,
                    user_data,
                    best_block_number,
                    best_block_hash,
                };

                let inner_source_id = inner.add_source(source_extra);
                outer_source_id_entry.insert(SourceMapping::WarpSync(inner_source_id));

                self.inner = AllSyncInner::WarpSync {
                    inner,
                    ready_to_transition,
                };
                outer_source_id
            }
            AllSyncInner::AllForks(mut all_forks) => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let source_user_data = AllForksSourceExtra {
                    user_data,
                    outer_source_id,
                };

                let source_id =
                    match all_forks.prepare_add_source(best_block_number, best_block_hash) {
                        all_forks::AddSource::BestBlockAlreadyVerified(b)
                        | all_forks::AddSource::BestBlockPendingVerification(b) => {
                            b.add_source(source_user_data)
                        }
                        all_forks::AddSource::OldBestBlock(b) => b.add_source(source_user_data),
                        all_forks::AddSource::UnknownBestBlock(b) => {
                            b.add_source_and_insert_block(source_user_data, None)
                        }
                    };

                outer_source_id_entry.insert(SourceMapping::AllForks(source_id));

                self.inner = AllSyncInner::AllForks(all_forks);
                outer_source_id
            }
            AllSyncInner::Optimistic { mut inner } => {
                let outer_source_id_entry = self.shared.sources.vacant_entry();
                let outer_source_id = SourceId(outer_source_id_entry.key());

                let source_id = inner.add_source(
                    OptimisticSourceExtra {
                        user_data,
                        outer_source_id,
                        best_block_hash,
                    },
                    best_block_number,
                );
                outer_source_id_entry.insert(SourceMapping::Optimistic(source_id));

                self.inner = AllSyncInner::Optimistic { inner };
                outer_source_id
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Removes a source from the state machine. Returns the user data of this source, and all
    /// the requests that this source were expected to perform.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] doesn't correspond to a valid source.
    ///
    pub fn remove_source(
        &mut self,
        source_id: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, TRq)>) {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&mut self.inner, self.shared.sources.remove(source_id.0)) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(source_id)) => {
                let (user_data, requests) = sync.remove_source(source_id);
                let requests = requests
                    .map(
                        |(_inner_request_id, _request_params, request_inner_user_data)| {
                            debug_assert!(self
                                .shared
                                .requests
                                .contains(request_inner_user_data.outer_request_id.0));
                            let _removed = self
                                .shared
                                .requests
                                .remove(request_inner_user_data.outer_request_id.0);
                            debug_assert!(matches!(
                                _removed,
                                RequestMapping::AllForks(_inner_request_id)
                            ));

                            (
                                request_inner_user_data.outer_request_id,
                                request_inner_user_data.user_data.unwrap(),
                            )
                        },
                    )
                    .collect::<Vec<_>>()
                    .into_iter();

                // TODO: also handle the "inline" requests

                (user_data.user_data, requests)
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(source_id)) => {
                let (user_data, requests) = inner.remove_source(source_id);
                // TODO: do properly
                let self_requests = &mut self.shared.requests;
                let requests = requests
                    .map(move |(_inner_request_id, request_inner_user_data)| {
                        debug_assert!(
                            self_requests.contains(request_inner_user_data.outer_request_id.0)
                        );
                        let _removed =
                            self_requests.remove(request_inner_user_data.outer_request_id.0);
                        debug_assert!(matches!(
                            _removed,
                            RequestMapping::Optimistic(_inner_request_id)
                        ));
                        (
                            request_inner_user_data.outer_request_id,
                            request_inner_user_data.user_data,
                        )
                    })
                    .collect::<Vec<_>>()
                    .into_iter();

                // TODO: also handle the "inline" requests

                (user_data.user_data, requests)
            }
            (AllSyncInner::WarpSync { inner, .. }, SourceMapping::WarpSync(source_id)) => {
                let (user_data, requests) = inner.remove_source(source_id);

                let requests = requests
                    .map(|(_inner_request_id, request_inner_user_data)| {
                        debug_assert!(self
                            .shared
                            .requests
                            .contains(request_inner_user_data.outer_request_id.0));
                        let _removed = self
                            .shared
                            .requests
                            .remove(request_inner_user_data.outer_request_id.0);
                        debug_assert!(matches!(
                            _removed,
                            RequestMapping::WarpSync(_inner_request_id)
                        ));

                        (
                            request_inner_user_data.outer_request_id,
                            request_inner_user_data.user_data,
                        )
                    })
                    .collect::<Vec<_>>()
                    .into_iter();

                // TODO: also handle the "inline" requests

                (user_data.user_data, requests)
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::WarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::WarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::WarpSync(_)) => unreachable!(),
        }
    }

    /// Returns the list of sources in this state machine.
    pub fn sources(&'_ self) -> impl Iterator<Item = SourceId> + '_ {
        match &self.inner {
            AllSyncInner::WarpSync { inner, .. } => {
                let iter = inner.sources().map(move |id| inner[id].outer_source_id);
                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner: sync } => {
                let iter = sync.sources().map(move |id| sync[id].outer_source_id);
                either::Right(either::Left(iter))
            }
            AllSyncInner::AllForks(sync) => {
                let iter = sync.sources().map(move |id| sync[id].outer_source_id);
                either::Right(either::Right(iter))
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Returns the number of ongoing requests that concern this source.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_num_ongoing_requests(&self, source_id: SourceId) -> usize {
        debug_assert!(self.shared.sources.contains(source_id.0));

        // TODO: O(n) :-/
        let num_inline = self
            .shared
            .requests
            .iter()
            .filter(|(_, rq)| matches!(rq, RequestMapping::Inline(id, _, _) if *id == source_id))
            .count();

        let num_inner = match (&self.inner, self.shared.sources.get(source_id.0).unwrap()) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                sync.source_num_ongoing_requests(*src)
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                inner.source_num_ongoing_requests(*src)
            }
            (AllSyncInner::WarpSync { .. }, SourceMapping::WarpSync(_)) => 0,

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::WarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::WarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::WarpSync(_)) => unreachable!(),
        };

        num_inline + num_inner
    }

    /// Returns the current best block of the given source.
    ///
    /// This corresponds either the latest call to [`AllSync::block_announce`] where `is_best` was
    /// `true`, or to the parameter passed to [`AllSync::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_best_block(&self, source_id: SourceId) -> (u64, &[u8; 32]) {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&self.inner, self.shared.sources.get(source_id.0).unwrap()) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                sync.source_best_block(*src)
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                let height = inner.source_best_block(*src);
                let hash = &inner[*src].best_block_hash;
                (height, hash)
            }
            (AllSyncInner::WarpSync { inner, .. }, SourceMapping::WarpSync(src)) => {
                let ud = &inner[*src];
                (ud.best_block_number, &ud.best_block_hash)
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::WarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::WarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::WarpSync(_)) => unreachable!(),
        }
    }

    /// Returns true if the source has earlier announced the block passed as parameter or one of
    /// its descendants.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    /// Panics if `height` is inferior or equal to the finalized block height. Finalized blocks
    /// are intentionally not tracked by this data structure, and panicking when asking for a
    /// potentially-finalized block prevents potentially confusing or erroneous situations.
    ///
    pub fn source_knows_non_finalized_block(
        &self,
        source_id: SourceId,
        height: u64,
        hash: &[u8; 32],
    ) -> bool {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&self.inner, self.shared.sources.get(source_id.0).unwrap()) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                sync.source_knows_non_finalized_block(*src, height, hash)
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                // TODO: is this correct?
                inner.source_best_block(*src) >= height
            }
            (AllSyncInner::WarpSync { inner, .. }, SourceMapping::WarpSync(src)) => {
                assert!(
                    height
                        > inner
                            .as_chain_information()
                            .as_ref()
                            .finalized_block_header
                            .number
                );

                let user_data = &inner[*src];
                user_data.best_block_hash == *hash && user_data.best_block_number == height
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::WarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::WarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::WarpSync(_)) => unreachable!(),
        }
    }

    /// Returns the list of sources for which [`AllSync::source_knows_non_finalized_block`] would
    /// return `true`.
    ///
    /// # Panic
    ///
    /// Panics if `height` is inferior or equal to the finalized block height. Finalized blocks
    /// are intentionally not tracked by this data structure, and panicking when asking for a
    /// potentially-finalized block prevents potentially confusing or erroneous situations.
    ///
    pub fn knows_non_finalized_block(
        &'_ self,
        height: u64,
        hash: &[u8; 32],
    ) -> impl Iterator<Item = SourceId> + '_ {
        match &self.inner {
            AllSyncInner::WarpSync { inner, .. } => {
                assert!(
                    height
                        > inner
                            .as_chain_information()
                            .as_ref()
                            .finalized_block_header
                            .number
                );

                let hash = *hash;
                let iter = inner
                    .sources()
                    .filter(move |source_id| {
                        let user_data = &inner[*source_id];
                        user_data.best_block_hash == hash && user_data.best_block_number == height
                    })
                    .map(move |id| inner[id].outer_source_id);

                either::Right(iter)
            }
            AllSyncInner::AllForks(sync) => {
                let iter = sync
                    .knows_non_finalized_block(height, hash)
                    .map(move |id| sync[id].outer_source_id);
                either::Left(either::Left(iter))
            }
            AllSyncInner::Optimistic { inner } => {
                // TODO: is this correct?
                let iter = inner
                    .sources()
                    .filter(move |source_id| inner.source_best_block(*source_id) >= height)
                    .map(move |source_id| inner[source_id].outer_source_id);
                either::Left(either::Right(iter))
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Try register a new block that the source is aware of.
    ///
    /// Some syncing strategies do not track blocks known to sources, in which case this function
    /// has no effect
    ///
    /// Has no effect if `height` is inferior or equal to the finalized block height, or if the
    /// source was already known to know this block.
    ///
    /// The block does not need to be known by the data structure.
    ///
    /// This is automatically done for the blocks added through block announces or block requests..
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn try_add_known_block_to_source(
        &mut self,
        source_id: SourceId,
        height: u64,
        hash: [u8; 32],
    ) {
        debug_assert!(self.shared.sources.contains(source_id.0));
        if let (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) = (
            &mut self.inner,
            self.shared.sources.get(source_id.0).unwrap(),
        ) {
            sync.add_known_block_to_source(*src, height, hash)
        }
    }

    /// Returns the details of a request to start towards a source.
    ///
    /// This method doesn't modify the state machine in any way. [`AllSync::add_request`] must be
    /// called in order for the request to actually be marked as started.
    pub fn desired_requests(
        &'_ self,
    ) -> impl Iterator<Item = (SourceId, &'_ TSrc, DesiredRequest)> + '_ {
        match &self.inner {
            AllSyncInner::AllForks(sync) => {
                let iter = sync.desired_requests().map(
                    move |(inner_source_id, src_user_data, rq_params)| {
                        (
                            sync[inner_source_id].outer_source_id,
                            &src_user_data.user_data,
                            all_forks_request_convert(rq_params, self.shared.full_mode),
                        )
                    },
                );

                either::Left(either::Right(iter))
            }
            AllSyncInner::Optimistic { inner } => {
                let iter = inner.desired_requests().map(move |rq_detail| {
                    (
                        inner[rq_detail.source_id].outer_source_id,
                        &inner[rq_detail.source_id].user_data,
                        optimistic_request_convert(rq_detail, self.shared.full_mode),
                    )
                });

                either::Right(iter)
            }
            AllSyncInner::WarpSync { inner, .. } => {
                let iter = inner
                    .desired_requests()
                    .map(move |(_, src_user_data, rq_detail)| {
                        let detail = match rq_detail {
                            warp_sync::DesiredRequest::WarpSyncRequest { block_hash } => {
                                DesiredRequest::WarpSync {
                                    sync_start_block_hash: block_hash,
                                }
                            }
                            warp_sync::DesiredRequest::StorageGetMerkleProof {
                                block_hash,
                                state_trie_root,
                                keys,
                            } => DesiredRequest::StorageGetMerkleProof {
                                block_hash,
                                state_trie_root,
                                keys,
                            },
                            warp_sync::DesiredRequest::RuntimeCallMerkleProof {
                                block_hash,
                                function_name,
                                parameter_vectored,
                            } => DesiredRequest::RuntimeCallMerkleProof {
                                block_hash,
                                function_name,
                                parameter_vectored,
                            },
                        };

                        (
                            src_user_data.outer_source_id,
                            &src_user_data.user_data,
                            detail,
                        )
                    });

                either::Left(either::Left(iter))
            }
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Inserts a new request in the data structure.
    ///
    /// > **Note**: The request doesn't necessarily have to match a request returned by
    /// >           [`AllSync::desired_requests`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is out of range.
    ///
    pub fn add_request(
        &mut self,
        source_id: SourceId,
        detail: RequestDetail,
        user_data: TRq,
    ) -> RequestId {
        match (&mut self.inner, &detail) {
            (
                AllSyncInner::AllForks(sync),
                RequestDetail::BlocksRequest {
                    ascending: false, // TODO: ?
                    first_block_hash: Some(first_block_hash),
                    first_block_height,
                    num_blocks,
                    ..
                },
            ) => {
                let inner_source_id = match self.shared.sources.get(source_id.0).unwrap() {
                    SourceMapping::AllForks(inner_source_id) => *inner_source_id,
                    _ => unreachable!(),
                };

                let request_mapping_entry = self.shared.requests.vacant_entry();
                let outer_request_id = RequestId(request_mapping_entry.key());

                let inner_request_id = sync.add_request(
                    inner_source_id,
                    all_forks::RequestParams {
                        first_block_hash: *first_block_hash,
                        first_block_height: *first_block_height,
                        num_blocks: *num_blocks,
                    },
                    AllForksRequestExtra {
                        outer_request_id,
                        user_data: Some(user_data),
                    },
                );

                request_mapping_entry.insert(RequestMapping::AllForks(inner_request_id));
                return outer_request_id;
            }
            (
                AllSyncInner::Optimistic { inner },
                RequestDetail::BlocksRequest {
                    ascending: true, // TODO: ?
                    first_block_height,
                    num_blocks,
                    ..
                },
            ) => {
                let inner_source_id = match self.shared.sources.get(source_id.0).unwrap() {
                    SourceMapping::Optimistic(inner_source_id) => *inner_source_id,
                    _ => unreachable!(),
                };

                let request_mapping_entry = self.shared.requests.vacant_entry();
                let outer_request_id = RequestId(request_mapping_entry.key());

                let inner_request_id = inner.insert_request(
                    optimistic::RequestDetail {
                        source_id: inner_source_id,
                        block_height: NonZeroU64::new(*first_block_height).unwrap(), // TODO: correct to unwrap?
                        num_blocks: NonZeroU32::new(u32::try_from(num_blocks.get()).unwrap())
                            .unwrap(), // TODO: don't unwrap
                    },
                    OptimisticRequestExtra {
                        outer_request_id,
                        user_data,
                    },
                );

                request_mapping_entry.insert(RequestMapping::Optimistic(inner_request_id));
                return outer_request_id;
            }
            (
                AllSyncInner::WarpSync { inner, .. },
                RequestDetail::WarpSync {
                    sync_start_block_hash,
                },
            ) => {
                let inner_source_id = match self.shared.sources.get(source_id.0).unwrap() {
                    SourceMapping::WarpSync(inner_source_id) => *inner_source_id,
                    _ => unreachable!(),
                };

                let request_mapping_entry = self.shared.requests.vacant_entry();
                let outer_request_id = RequestId(request_mapping_entry.key());

                let inner_request_id = inner.add_request(
                    inner_source_id,
                    WarpSyncRequestExtra {
                        outer_request_id,
                        user_data,
                    },
                    warp_sync::RequestDetail::WarpSyncRequest {
                        block_hash: *sync_start_block_hash,
                    },
                );

                request_mapping_entry.insert(RequestMapping::WarpSync(inner_request_id));
                return outer_request_id;
            }
            (
                AllSyncInner::WarpSync { inner, .. },
                RequestDetail::StorageGet { block_hash, keys },
            ) => {
                let inner_source_id = match self.shared.sources.get(source_id.0).unwrap() {
                    SourceMapping::WarpSync(inner_source_id) => *inner_source_id,
                    _ => unreachable!(),
                };

                let request_mapping_entry = self.shared.requests.vacant_entry();
                let outer_request_id = RequestId(request_mapping_entry.key());

                let inner_request_id = inner.add_request(
                    inner_source_id,
                    WarpSyncRequestExtra {
                        outer_request_id,
                        user_data,
                    },
                    warp_sync::RequestDetail::StorageGetMerkleProof {
                        block_hash: *block_hash,
                        keys: keys.clone(), // TODO: clone?
                    },
                );

                request_mapping_entry.insert(RequestMapping::WarpSync(inner_request_id));
                return outer_request_id;
            }
            (
                AllSyncInner::WarpSync { inner, .. },
                RequestDetail::RuntimeCallMerkleProof {
                    block_hash,
                    function_name,
                    parameter_vectored,
                },
            ) => {
                let inner_source_id = match self.shared.sources.get(source_id.0).unwrap() {
                    SourceMapping::WarpSync(inner_source_id) => *inner_source_id,
                    _ => unreachable!(),
                };

                let request_mapping_entry = self.shared.requests.vacant_entry();
                let outer_request_id = RequestId(request_mapping_entry.key());

                let inner_request_id = inner.add_request(
                    inner_source_id,
                    WarpSyncRequestExtra {
                        outer_request_id,
                        user_data,
                    },
                    warp_sync::RequestDetail::RuntimeCallMerkleProof {
                        block_hash: *block_hash,
                        function_name: function_name.clone(), // TODO: don't clone
                        parameter_vectored: parameter_vectored.clone(), // TODO: don't clone
                    },
                );

                request_mapping_entry.insert(RequestMapping::WarpSync(inner_request_id));
                return outer_request_id;
            }
            (AllSyncInner::AllForks { .. }, _) => {}
            (AllSyncInner::Optimistic { .. }, _) => {}
            (AllSyncInner::WarpSync { .. }, _) => {}
            (AllSyncInner::Poisoned, _) => unreachable!(),
        }

        RequestId(
            self.shared
                .requests
                .insert(RequestMapping::Inline(source_id, detail, user_data)),
        )
    }

    /// Returns a list of requests that are considered obsolete and can be removed using
    /// [`AllSync::blocks_request_response`] or similar.
    ///
    /// A request becomes obsolete if the state of the request blocks changes in such a way that
    /// they don't need to be requested anymore. The response to the request will be useless.
    ///
    /// > **Note**: It is in no way mandatory to actually call this function and cancel the
    /// >           requests that are returned.
    pub fn obsolete_requests(&'_ self) -> impl Iterator<Item = RequestId> + '_ {
        match &self.inner {
            AllSyncInner::AllForks(sync) => {
                let iter = sync
                    .obsolete_requests()
                    .map(move |(_, rq)| rq.outer_request_id)
                    .chain(
                        self.shared
                            .requests
                            .iter()
                            .filter(|(_, rq)| matches!(rq, RequestMapping::Inline(..)))
                            .map(|(id, _)| RequestId(id)),
                    );
                either::Left(iter)
            }
            AllSyncInner::Optimistic { inner } => {
                let iter = inner
                    .obsolete_requests()
                    .map(move |(_, rq)| rq.outer_request_id)
                    .chain(
                        self.shared
                            .requests
                            .iter()
                            .filter(|(_, rq)| matches!(rq, RequestMapping::Inline(..)))
                            .map(|(id, _)| RequestId(id)),
                    );
                either::Right(either::Left(iter))
            }
            AllSyncInner::WarpSync { .. } => either::Right(either::Right(iter::empty())), // TODO: not implemented properly
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`AllSync`] and starts a verification process. The
    /// [`AllSync`] is yielded back at the end of this process.
    pub fn process_one(mut self) -> ProcessOne<TRq, TSrc, TBl> {
        match self.inner {
            AllSyncInner::WarpSync {
                inner,
                ready_to_transition: None,
            } => match inner.process_one() {
                warp_sync::ProcessOne::Idle(inner) => {
                    self.inner = AllSyncInner::WarpSync {
                        inner,
                        ready_to_transition: None,
                    };
                    ProcessOne::AllSync(self)
                }
                warp_sync::ProcessOne::VerifyWarpSyncFragment(inner) => {
                    ProcessOne::VerifyWarpSyncFragment(WarpSyncFragmentVerify {
                        inner,
                        ready_to_transition: None,
                        shared: self.shared,
                        marker: marker::PhantomData,
                    })
                }
                warp_sync::ProcessOne::BuildRuntime(inner) => {
                    ProcessOne::WarpSyncBuildRuntime(WarpSyncBuildRuntime {
                        inner,
                        ready_to_transition: None,
                        shared: self.shared,
                        marker: marker::PhantomData,
                    })
                }
                warp_sync::ProcessOne::BuildChainInformation(inner) => {
                    ProcessOne::WarpSyncBuildChainInformation(WarpSyncBuildChainInformation {
                        inner,
                        shared: self.shared,
                        marker: marker::PhantomData,
                    })
                }
            },
            AllSyncInner::WarpSync {
                inner,
                ready_to_transition: Some(ready_to_transition),
            } => {
                let (
                    new_inner,
                    finalized_block_runtime,
                    finalized_storage_code,
                    finalized_storage_heap_pages,
                    finalized_storage_code_merkle_value,
                    finalized_storage_code_closest_ancestor_excluding,
                ) = self
                    .shared
                    .transition_warp_sync_all_forks(inner, ready_to_transition);
                self.inner = AllSyncInner::AllForks(new_inner);
                ProcessOne::WarpSyncFinished {
                    sync: self,
                    finalized_block_runtime,
                    finalized_storage_code,
                    finalized_storage_heap_pages,
                    finalized_storage_code_merkle_value,
                    finalized_storage_code_closest_ancestor_excluding,
                }
            }
            AllSyncInner::AllForks(sync) => match sync.process_one() {
                all_forks::ProcessOne::AllSync { sync } => {
                    self.inner = AllSyncInner::AllForks(sync);
                    ProcessOne::AllSync(self)
                }
                all_forks::ProcessOne::BlockVerify(verify) => {
                    ProcessOne::VerifyBlock(BlockVerify {
                        inner: BlockVerifyInner::AllForks(verify),
                        shared: self.shared,
                    })
                }
                all_forks::ProcessOne::FinalityProofVerify(verify) => {
                    ProcessOne::VerifyFinalityProof(FinalityProofVerify {
                        inner: FinalityProofVerifyInner::AllForks(verify),
                        shared: self.shared,
                    })
                }
            },
            AllSyncInner::Optimistic { inner } => match inner.process_one() {
                optimistic::ProcessOne::Idle { sync } => {
                    self.inner = AllSyncInner::Optimistic { inner: sync };
                    ProcessOne::AllSync(self)
                }
                optimistic::ProcessOne::VerifyBlock(inner) => {
                    ProcessOne::VerifyBlock(BlockVerify {
                        inner: BlockVerifyInner::Optimistic(inner),
                        shared: self.shared,
                    })
                }
                optimistic::ProcessOne::VerifyJustification(inner) => {
                    ProcessOne::VerifyFinalityProof(FinalityProofVerify {
                        inner: FinalityProofVerifyInner::Optimistic(inner),
                        shared: self.shared,
                    })
                }
            },
            AllSyncInner::Poisoned => unreachable!(),
        }
    }

    /// Injects a block announcement made by a source into the state machine.
    pub fn block_announce(
        &mut self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome {
        let source_id = self.shared.sources.get(source_id.0).unwrap();

        match (&mut self.inner, source_id) {
            (AllSyncInner::AllForks(sync), &SourceMapping::AllForks(source_id)) => {
                match sync.block_announce(source_id, announced_scale_encoded_header, is_best) {
                    all_forks::BlockAnnounceOutcome::TooOld {
                        announce_block_height,
                        finalized_block_height,
                    } => BlockAnnounceOutcome::TooOld {
                        announce_block_height,
                        finalized_block_height,
                    },
                    all_forks::BlockAnnounceOutcome::Unknown(source_update) => {
                        source_update.insert_and_update_source(None);
                        BlockAnnounceOutcome::StoredForLater // TODO: arbitrary
                    }
                    all_forks::BlockAnnounceOutcome::AlreadyInChain(source_update)
                    | all_forks::BlockAnnounceOutcome::Known(source_update) => {
                        source_update.update_source_and_block();
                        BlockAnnounceOutcome::StoredForLater // TODO: arbitrary
                    }
                    all_forks::BlockAnnounceOutcome::InvalidHeader(error) => {
                        BlockAnnounceOutcome::InvalidHeader(error)
                    }
                }
            }
            (AllSyncInner::Optimistic { inner }, &SourceMapping::Optimistic(source_id)) => {
                match header::decode(&announced_scale_encoded_header, inner.block_number_bytes()) {
                    Ok(header) => {
                        if is_best {
                            inner.raise_source_best_block(source_id, header.number);
                            inner[source_id].best_block_hash =
                                header::hash_from_scale_encoded_header(
                                    &announced_scale_encoded_header,
                                );
                        }
                        BlockAnnounceOutcome::Discarded
                    }
                    Err(err) => BlockAnnounceOutcome::InvalidHeader(err),
                }
            }
            (AllSyncInner::WarpSync { inner, .. }, &SourceMapping::WarpSync(source_id)) => {
                match header::decode(
                    &announced_scale_encoded_header,
                    self.shared.block_number_bytes,
                ) {
                    Err(err) => BlockAnnounceOutcome::InvalidHeader(err),
                    Ok(header) => {
                        // If GrandPa warp syncing is in progress, the best block of the source is stored
                        // in the user data. It will be useful later when transitioning to another
                        // syncing strategy.
                        if is_best {
                            let user_data = &mut inner[source_id];
                            user_data.best_block_number = header.number;
                            user_data.best_block_hash = header.hash(self.shared.block_number_bytes);
                        }

                        BlockAnnounceOutcome::Discarded
                    }
                }
            }
            (AllSyncInner::Poisoned, _) => unreachable!(),

            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::WarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::WarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::WarpSync(_)) => unreachable!(),
        }
    }

    /// Update the finalized block height of the given source.
    ///
    /// # Panic
    ///
    /// Panics if `source_id` is invalid.
    ///
    pub fn update_source_finality_state(
        &mut self,
        source_id: SourceId,
        finalized_block_height: u64,
    ) {
        let source_id = self.shared.sources.get(source_id.0).unwrap();

        match (&mut self.inner, source_id) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(source_id)) => {
                sync.update_source_finality_state(*source_id, finalized_block_height)
            }
            (AllSyncInner::Optimistic { .. }, _) => {} // TODO: the optimistic sync could get some help from the finalized block
            (AllSyncInner::WarpSync { inner, .. }, SourceMapping::WarpSync(source_id)) => {
                inner.set_source_finality_state(*source_id, finalized_block_height);
            }

            // Invalid internal states.
            (AllSyncInner::AllForks(_), _) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, _) => unreachable!(),
            (AllSyncInner::Poisoned, _) => unreachable!(),
        }
    }

    /// Update the state machine with a Grandpa commit message received from the network.
    ///
    /// This function only inserts the commit message into the state machine, and does not
    /// immediately verify it.
    pub fn grandpa_commit_message(
        &mut self,
        source_id: SourceId,
        scale_encoded_message: Vec<u8>,
    ) -> GrandpaCommitMessageOutcome {
        let source_id = self.shared.sources.get(source_id.0).unwrap();

        match (&mut self.inner, source_id) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(source_id)) => {
                match sync.grandpa_commit_message(*source_id, scale_encoded_message) {
                    all_forks::GrandpaCommitMessageOutcome::ParseError => {
                        GrandpaCommitMessageOutcome::Discarded
                    }
                    all_forks::GrandpaCommitMessageOutcome::Queued => {
                        GrandpaCommitMessageOutcome::Queued
                    }
                }
            }
            (AllSyncInner::WarpSync { inner, .. }, SourceMapping::WarpSync(source_id)) => {
                let block_number = match decode::decode_grandpa_commit(
                    &scale_encoded_message,
                    inner.block_number_bytes(),
                ) {
                    Ok(msg) => msg.target_number,
                    Err(_) => return GrandpaCommitMessageOutcome::Discarded,
                };

                inner.set_source_finality_state(*source_id, block_number);
                GrandpaCommitMessageOutcome::Discarded
            }
            (AllSyncInner::Optimistic { .. }, _) => GrandpaCommitMessageOutcome::Discarded,

            // Invalid internal states.
            (AllSyncInner::AllForks(_), _) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, _) => unreachable!(),
            (AllSyncInner::Poisoned, _) => unreachable!(),
        }
    }

    /// Inject a response to a previously-emitted blocks request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn blocks_request_response(
        &mut self,
        request_id: RequestId,
        blocks: Result<impl Iterator<Item = BlockRequestSuccessBlock<TBl>>, ()>,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        match (&mut self.inner, request) {
            (_, RequestMapping::Inline(_, _, user_data)) => (user_data, ResponseOutcome::Outdated),
            (AllSyncInner::WarpSync { .. }, _) => panic!(), // Grandpa warp sync never starts block requests.
            (
                sync_container @ AllSyncInner::AllForks(_),
                RequestMapping::AllForks(inner_request_id),
            ) => {
                // We need to extract the `AllForksSync` object in order to inject the
                // response.
                let sync = match mem::replace(sync_container, AllSyncInner::Poisoned) {
                    AllSyncInner::AllForks(sync) => sync,
                    _ => unreachable!(),
                };

                let (sync, request_user_data, outcome) = if let Ok(blocks) = blocks {
                    let (request_user_data, mut blocks_append) =
                        sync.finish_ancestry_search(inner_request_id);
                    let mut blocks_iter = blocks.into_iter().enumerate();

                    loop {
                        let (block_index, block) = match blocks_iter.next() {
                            Some(v) => v,
                            None => {
                                break (
                                    blocks_append.finish(),
                                    request_user_data,
                                    ResponseOutcome::Queued,
                                );
                            }
                        };

                        // TODO: many of the errors don't properly translate here, needs some refactoring
                        match blocks_append.add_block(
                            &block.scale_encoded_header,
                            block
                                .scale_encoded_justifications
                                .into_iter()
                                .map(|j| (j.engine_id, j.justification)),
                        ) {
                            Ok(all_forks::AddBlock::UnknownBlock(ba)) => {
                                blocks_append = ba.insert(Some(block.user_data))
                            }
                            Ok(all_forks::AddBlock::AlreadyPending(ba)) => {
                                // TODO: replacing the user data entirely is very opinionated, instead the API of the AllSync should be changed
                                blocks_append = ba.replace(Some(block.user_data)).0
                            }
                            Ok(all_forks::AddBlock::AlreadyInChain(ba)) if block_index == 0 => {
                                break (
                                    ba.cancel(),
                                    request_user_data,
                                    ResponseOutcome::AllAlreadyInChain,
                                )
                            }
                            Ok(all_forks::AddBlock::AlreadyInChain(ba)) => {
                                break (ba.cancel(), request_user_data, ResponseOutcome::Queued)
                            }
                            Err((
                                all_forks::AncestrySearchResponseError::NotFinalizedChain {
                                    discarded_unverified_block_headers,
                                },
                                sync,
                            )) => {
                                break (
                                    sync,
                                    request_user_data,
                                    ResponseOutcome::NotFinalizedChain {
                                        discarded_unverified_block_headers,
                                    },
                                )
                            }
                            Err((_, sync)) => {
                                break (sync, request_user_data, ResponseOutcome::Queued);
                            }
                        }
                    }
                } else {
                    let (ud, sync) = sync.ancestry_search_failed(inner_request_id);
                    // TODO: `Queued`?! doesn't seem right
                    (sync, ud, ResponseOutcome::Queued)
                };

                // Don't forget to re-insert the `AllForksSync`.
                *sync_container = AllSyncInner::AllForks(sync);

                debug_assert_eq!(request_user_data.outer_request_id, request_id);
                (request_user_data.user_data.unwrap(), outcome)
            }
            (AllSyncInner::Optimistic { inner }, RequestMapping::Optimistic(inner_request_id)) => {
                let (request_user_data, outcome) = if let Ok(blocks) = blocks {
                    let (request_user_data, outcome) = inner.finish_request_success(
                        inner_request_id,
                        blocks.map(|block| optimistic::RequestSuccessBlock {
                            scale_encoded_header: block.scale_encoded_header,
                            scale_encoded_justifications: block
                                .scale_encoded_justifications
                                .into_iter()
                                .map(|j| (j.engine_id, j.justification))
                                .collect(),
                            scale_encoded_extrinsics: block.scale_encoded_extrinsics,
                            user_data: block.user_data,
                        }),
                    );

                    match outcome {
                        optimistic::FinishRequestOutcome::Obsolete => {
                            (request_user_data, ResponseOutcome::Outdated)
                        }
                        optimistic::FinishRequestOutcome::Queued => {
                            (request_user_data, ResponseOutcome::Queued)
                        }
                    }
                } else {
                    // TODO: `ResponseOutcome::Queued` is a hack
                    (
                        inner.finish_request_failed(inner_request_id),
                        ResponseOutcome::Queued,
                    )
                };

                debug_assert_eq!(request_user_data.outer_request_id, request_id);
                (request_user_data.user_data, outcome)
            }
            _ => unreachable!(),
        }
    }

    /// Inject a successful response to a previously-emitted GrandPa warp sync request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn grandpa_warp_sync_response_ok(
        &mut self,
        request_id: RequestId,
        fragments: Vec<WarpSyncFragment>,
        is_finished: bool,
    ) -> (TRq, ResponseOutcome) {
        self.grandpa_warp_sync_response_inner(request_id, Some((fragments, is_finished)))
    }

    /// Inject a failure to a previously-emitted GrandPa warp sync request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn grandpa_warp_sync_response_err(
        &mut self,
        request_id: RequestId,
    ) -> (TRq, ResponseOutcome) {
        self.grandpa_warp_sync_response_inner(request_id, None)
    }

    fn grandpa_warp_sync_response_inner(
        &mut self,
        request_id: RequestId,
        response: Option<(Vec<WarpSyncFragment>, bool)>,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        match (&mut self.inner, request) {
            (AllSyncInner::WarpSync { inner, .. }, RequestMapping::WarpSync(request_id)) => {
                let user_data = if let Some((fragments, is_finished)) = response {
                    inner.warp_sync_request_success(request_id, fragments, is_finished)
                } else {
                    inner.fail_request(request_id)
                };

                (user_data.user_data, ResponseOutcome::Queued)
            }

            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            (_, RequestMapping::Inline(_, _, user_data)) => {
                (user_data, ResponseOutcome::Queued) // TODO: no, not queued
            }

            _ => todo!(), // TODO: handle other variants
        }
    }

    /// Inject a response to a previously-emitted storage proof request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    /// Panics if the number of items in the response doesn't match the number of keys that have
    /// been requested.
    ///
    pub fn storage_get_response(
        &mut self,
        request_id: RequestId,
        response: Result<Vec<u8>, ()>,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        match (
            mem::replace(&mut self.inner, AllSyncInner::Poisoned),
            response,
            request,
        ) {
            (
                AllSyncInner::WarpSync {
                    mut inner,
                    ready_to_transition,
                },
                Ok(response),
                RequestMapping::WarpSync(request_id),
            ) => {
                let user_data = inner.storage_get_success(request_id, response);
                self.inner = AllSyncInner::WarpSync {
                    inner,
                    ready_to_transition,
                };
                (user_data.user_data, ResponseOutcome::Queued)
            }
            (
                AllSyncInner::WarpSync {
                    mut inner,
                    ready_to_transition,
                },
                Err(_),
                RequestMapping::WarpSync(request_id),
            ) => {
                let user_data = inner.fail_request(request_id).user_data;
                self.inner = AllSyncInner::WarpSync {
                    inner,
                    ready_to_transition,
                };
                (user_data, ResponseOutcome::Queued)
            }
            // Only the GrandPa warp syncing ever starts GrandPa warp sync requests.
            (other, _, RequestMapping::Inline(_, _, user_data)) => {
                self.inner = other;
                (user_data, ResponseOutcome::Queued) // TODO: no
            }
            (_, _, _) => {
                // Type of request doesn't correspond to a storage get.
                panic!()
            }
        }
    }

    /// Inject a response to a previously-emitted call proof request.
    ///
    /// On success, must contain the encoded Merkle proof. See the
    /// [`trie`](crate::trie) module for a description of the format of Merkle proofs.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] doesn't correspond to any request, or corresponds to a request
    /// of a different type.
    ///
    pub fn call_proof_response(
        &mut self,
        request_id: RequestId,
        response: Result<Vec<u8>, ()>,
    ) -> (TRq, ResponseOutcome) {
        debug_assert!(self.shared.requests.contains(request_id.0));
        let request = self.shared.requests.remove(request_id.0);

        match (
            mem::replace(&mut self.inner, AllSyncInner::Poisoned),
            response,
            request,
        ) {
            (
                AllSyncInner::WarpSync {
                    mut inner,
                    ready_to_transition,
                },
                Ok(response),
                RequestMapping::WarpSync(request_id),
            ) => {
                let user_data = inner.runtime_call_merkle_proof_success(request_id, response);
                self.inner = AllSyncInner::WarpSync {
                    inner,
                    ready_to_transition,
                };
                (user_data.user_data, ResponseOutcome::Queued)
            }
            (
                AllSyncInner::WarpSync {
                    mut inner,
                    ready_to_transition,
                },
                Err(_),
                RequestMapping::WarpSync(request_id),
            ) => {
                let user_data = inner.fail_request(request_id);
                // TODO: notify user of the problem
                self.inner = AllSyncInner::WarpSync {
                    inner,
                    ready_to_transition,
                };
                (user_data.user_data, ResponseOutcome::Queued)
            }
            // Only the GrandPa warp syncing ever starts call proof requests.
            (other, _, RequestMapping::Inline(_, _, user_data)) => {
                self.inner = other;
                (user_data, ResponseOutcome::Queued) // TODO: no
            }
            (_, _, _) => {
                // Type of request doesn't correspond to a call proof request.
                panic!()
            }
        }
    }
}

impl<TRq, TSrc, TBl> ops::Index<SourceId> for AllSync<TRq, TSrc, TBl> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, source_id: SourceId) -> &TSrc {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (&self.inner, self.shared.sources.get(source_id.0).unwrap()) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => &sync[*src].user_data,
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                &inner[*src].user_data
            }
            (AllSyncInner::WarpSync { inner, .. }, SourceMapping::WarpSync(src)) => {
                &inner[*src].user_data
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::WarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::WarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::WarpSync(_)) => unreachable!(),
        }
    }
}

impl<TRq, TSrc, TBl> ops::IndexMut<SourceId> for AllSync<TRq, TSrc, TBl> {
    #[track_caller]
    fn index_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        debug_assert!(self.shared.sources.contains(source_id.0));
        match (
            &mut self.inner,
            self.shared.sources.get(source_id.0).unwrap(),
        ) {
            (AllSyncInner::AllForks(sync), SourceMapping::AllForks(src)) => {
                &mut sync[*src].user_data
            }
            (AllSyncInner::Optimistic { inner }, SourceMapping::Optimistic(src)) => {
                &mut inner[*src].user_data
            }
            (AllSyncInner::WarpSync { inner, .. }, SourceMapping::WarpSync(src)) => {
                &mut inner[*src].user_data
            }

            (AllSyncInner::Poisoned, _) => unreachable!(),
            // Invalid combinations of syncing state machine and source id.
            // This indicates a internal bug during the switch from one state machine to the
            // other.
            (AllSyncInner::WarpSync { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::WarpSync(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::AllForks(_)) => unreachable!(),
            (AllSyncInner::AllForks(_), SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::WarpSync { .. }, SourceMapping::Optimistic(_)) => unreachable!(),
            (AllSyncInner::Optimistic { .. }, SourceMapping::WarpSync(_)) => unreachable!(),
        }
    }
}

impl<'a, TRq, TSrc, TBl> ops::Index<(u64, &'a [u8; 32])> for AllSync<TRq, TSrc, TBl> {
    type Output = TBl;

    #[track_caller]
    fn index(&self, (block_height, block_hash): (u64, &'a [u8; 32])) -> &TBl {
        match &self.inner {
            AllSyncInner::AllForks(inner) => inner[(block_height, block_hash)].as_ref().unwrap(),
            AllSyncInner::Optimistic { inner, .. } => &inner[block_hash],
            AllSyncInner::WarpSync { .. } => panic!("unknown block"), // No block is ever stored during the warp syncing.
            AllSyncInner::Poisoned => unreachable!(),
        }
    }
}

impl<'a, TRq, TSrc, TBl> ops::IndexMut<(u64, &'a [u8; 32])> for AllSync<TRq, TSrc, TBl> {
    #[track_caller]
    fn index_mut(&mut self, (block_height, block_hash): (u64, &'a [u8; 32])) -> &mut TBl {
        match &mut self.inner {
            AllSyncInner::AllForks(inner) => inner[(block_height, block_hash)].as_mut().unwrap(),
            AllSyncInner::Optimistic { inner, .. } => &mut inner[block_hash],
            AllSyncInner::WarpSync { .. } => panic!("unknown block"), // No block is ever stored during the warp syncing.
            AllSyncInner::Poisoned => unreachable!(),
        }
    }
}

/// See [`AllSync::desired_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum DesiredRequest {
    /// Requesting blocks from the source is requested.
    BlocksRequest {
        /// Height of the first block to request.
        first_block_height: u64,
        /// Hash of the first block to request. `None` if not known.
        first_block_hash: Option<[u8; 32]>,
        /// `True` if the `first_block_hash` is the response should contain blocks in an
        /// increasing number, starting from `first_block_hash` with the lowest number. If `false`,
        /// the blocks should be in decreasing number, with `first_block_hash` as the highest
        /// number.
        ascending: bool,
        /// Number of blocks the request should return.
        ///
        /// Note that this is only an indication, and the source is free to give fewer blocks
        /// than requested.
        ///
        /// This might be equal to `u64::max_value()` in case no upper bound is required. The API
        /// user is responsible for clamping this value to a reasonable limit.
        num_blocks: NonZeroU64,
        /// `True` if headers should be included in the response.
        request_headers: bool,
        /// `True` if bodies should be included in the response.
        request_bodies: bool,
        /// `True` if the justification should be included in the response, if any.
        request_justification: bool,
    },

    /// Sending a Grandpa warp sync request is requested.
    WarpSync {
        /// Hash of the known finalized block. Starting point of the request.
        sync_start_block_hash: [u8; 32],
    },

    /// Sending a storage query is requested.
    StorageGetMerkleProof {
        /// Hash of the block whose storage is requested.
        block_hash: [u8; 32],
        /// Merkle value of the root of the storage trie of the block.
        state_trie_root: [u8; 32],
        /// Keys whose values is requested.
        keys: Vec<Vec<u8>>,
    },

    /// Sending a call proof query is requested.
    RuntimeCallMerkleProof {
        /// Hash of the block whose call is made against.
        block_hash: [u8; 32],
        /// Name of the function to be called.
        function_name: Cow<'static, str>,
        /// Concatenated SCALE-encoded parameters to provide to the call.
        parameter_vectored: Cow<'static, [u8]>,
    },
}

impl DesiredRequest {
    /// Caps the number of blocks to request to `max`.
    // TODO: consider removing due to the many types of requests
    pub fn num_blocks_clamp(&mut self, max: NonZeroU64) {
        if let DesiredRequest::BlocksRequest { num_blocks, .. } = self {
            *num_blocks = NonZeroU64::new(cmp::min(num_blocks.get(), max.get())).unwrap();
        }
    }

    /// Caps the number of blocks to request to `max`.
    // TODO: consider removing due to the many types of requests
    pub fn with_num_blocks_clamp(mut self, max: NonZeroU64) -> Self {
        self.num_blocks_clamp(max);
        self
    }
}

/// See [`AllSync::desired_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum RequestDetail {
    /// Requesting blocks from the source is requested.
    BlocksRequest {
        /// Height of the first block to request.
        first_block_height: u64,
        /// Hash of the first block to request. `None` if not known.
        first_block_hash: Option<[u8; 32]>,
        /// `True` if the `first_block_hash` is the response should contain blocks in an
        /// increasing number, starting from `first_block_hash` with the lowest number. If `false`,
        /// the blocks should be in decreasing number, with `first_block_hash` as the highest
        /// number.
        ascending: bool,
        /// Number of blocks the request should return.
        ///
        /// Note that this is only an indication, and the source is free to give fewer blocks
        /// than requested.
        ///
        /// This might be equal to `u64::max_value()` in case no upper bound is required. The API
        /// user is responsible for clamping this value to a reasonable limit.
        num_blocks: NonZeroU64,
        /// `True` if headers should be included in the response.
        request_headers: bool,
        /// `True` if bodies should be included in the response.
        request_bodies: bool,
        /// `True` if the justification should be included in the response, if any.
        request_justification: bool,
    },

    /// Sending a Grandpa warp sync request is requested.
    WarpSync {
        /// Hash of the known finalized block. Starting point of the request.
        sync_start_block_hash: [u8; 32],
    },

    /// Sending a storage query is requested.
    StorageGet {
        /// Hash of the block whose storage is requested.
        block_hash: [u8; 32],
        /// Keys whose values is requested.
        keys: Vec<Vec<u8>>,
    },

    /// Sending a call proof query is requested.
    RuntimeCallMerkleProof {
        /// Hash of the block whose call is made against.
        block_hash: [u8; 32],
        /// Name of the function to be called.
        function_name: Cow<'static, str>,
        /// Concatenated SCALE-encoded parameters to provide to the call.
        parameter_vectored: Cow<'static, [u8]>,
    },
}

impl RequestDetail {
    /// Caps the number of blocks to request to `max`.
    pub fn num_blocks_clamp(&mut self, max: NonZeroU64) {
        if let RequestDetail::BlocksRequest { num_blocks, .. } = self {
            *num_blocks = NonZeroU64::new(cmp::min(num_blocks.get(), max.get())).unwrap();
        }
    }

    /// Caps the number of blocks to request to `max`.
    pub fn with_num_blocks_clamp(mut self, max: NonZeroU64) -> Self {
        self.num_blocks_clamp(max);
        self
    }
}

impl From<DesiredRequest> for RequestDetail {
    fn from(rq: DesiredRequest) -> RequestDetail {
        match rq {
            DesiredRequest::BlocksRequest {
                first_block_height,
                first_block_hash,
                ascending,
                num_blocks,
                request_headers,
                request_bodies,
                request_justification,
            } => RequestDetail::BlocksRequest {
                first_block_height,
                first_block_hash,
                ascending,
                num_blocks,
                request_headers,
                request_bodies,
                request_justification,
            },
            DesiredRequest::WarpSync {
                sync_start_block_hash,
            } => RequestDetail::WarpSync {
                sync_start_block_hash,
            },
            DesiredRequest::StorageGetMerkleProof {
                block_hash, keys, ..
            } => RequestDetail::StorageGet { block_hash, keys },
            DesiredRequest::RuntimeCallMerkleProof {
                block_hash,
                function_name,
                parameter_vectored,
            } => RequestDetail::RuntimeCallMerkleProof {
                block_hash,
                function_name,
                parameter_vectored,
            },
        }
    }
}

pub struct BlockRequestSuccessBlock<TBl> {
    pub scale_encoded_header: Vec<u8>,
    pub scale_encoded_justifications: Vec<Justification>,
    pub scale_encoded_extrinsics: Vec<Vec<u8>>,
    pub user_data: TBl,
}

/// See [`BlockRequestSuccessBlock::scale_encoded_justifications`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Justification {
    /// Short identifier of the consensus engine associated with that justification.
    pub engine_id: [u8; 4],
    /// Body of the justification.
    pub justification: Vec<u8>,
}

/// Outcome of calling [`AllSync::block_announce`].
pub enum BlockAnnounceOutcome {
    /// Header is ready to be verified. Calling [`AllSync::process_one`] might yield that block.
    HeaderVerify,

    /// Announced block is too old to be part of the finalized chain.
    ///
    /// It is assumed that all sources will eventually agree on the same finalized chain. Blocks
    /// whose height is inferior to the height of the latest known finalized block should simply
    /// be ignored. Whether or not this old block is indeed part of the finalized block isn't
    /// verified, and it is assumed that the source is simply late.
    TooOld {
        /// Height of the announced block.
        announce_block_height: u64,
        /// Height of the currently finalized block.
        finalized_block_height: u64,
    },
    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyInChain,
    /// Announced block is known to not be a descendant of the finalized block.
    NotFinalizedChain,
    /// Header cannot be verified now because its parent hasn't been verified yet. The block has
    /// been stored for later. See [`Config::max_disjoint_headers`].
    StoredForLater,
    /// Failed to decode announce header.
    InvalidHeader(header::Error),

    /// Header cannot be verified now and has been silently discarded.
    Discarded,
}

/// Response to a GrandPa warp sync request.
#[derive(Debug)]
pub struct WarpSyncResponseFragment<'a> {
    /// Header of a block in the chain.
    pub scale_encoded_header: &'a [u8],

    /// Justification that proves the finality of
    /// [`WarpSyncResponseFragment::scale_encoded_header`].
    pub scale_encoded_justification: &'a [u8],
}

/// Outcome of calling [`AllSync::process_one`].
pub enum ProcessOne<TRq, TSrc, TBl> {
    /// No block ready to be processed.
    AllSync(AllSync<TRq, TSrc, TBl>),

    /// Building the runtime is necessary in order for the warp syncing to continue.
    WarpSyncBuildRuntime(WarpSyncBuildRuntime<TRq, TSrc, TBl>),

    /// Building the chain information is necessary in order for the warp syncing to continue.
    WarpSyncBuildChainInformation(WarpSyncBuildChainInformation<TRq, TSrc, TBl>),

    /// Response has made it possible to finish warp syncing.
    WarpSyncFinished {
        sync: AllSync<TRq, TSrc, TBl>,

        /// Runtime of the newly finalized block.
        ///
        /// > **Note**: Use methods such as [`AllSync::finalized_block_header`] to know which
        /// >           block this runtime corresponds to.
        finalized_block_runtime: host::HostVmPrototype,

        /// Storage value at the `:code` key of the finalized block.
        finalized_storage_code: Option<Vec<u8>>,

        /// Storage value at the `:heappages` key of the finalized block.
        finalized_storage_heap_pages: Option<Vec<u8>>,

        /// Merkle value of the `:code` trie node of the finalized block.
        finalized_storage_code_merkle_value: Option<Vec<u8>>,

        /// Closest ancestor of the `:code` trie node of the finalized block excluding `:code`
        /// itself.
        finalized_storage_code_closest_ancestor_excluding: Option<Vec<Nibble>>,
    },

    /// Ready to start verifying a block.
    VerifyBlock(BlockVerify<TRq, TSrc, TBl>),

    /// Ready to start verifying a proof of finality.
    VerifyFinalityProof(FinalityProofVerify<TRq, TSrc, TBl>),

    /// Ready to start verifying a warp sync fragment.
    VerifyWarpSyncFragment(WarpSyncFragmentVerify<TRq, TSrc, TBl>),
}

/// Outcome of injecting a response in the [`AllSync`].
pub enum ResponseOutcome {
    /// Request was no longer interesting for the state machine.
    Outdated,

    /// Content of the response has been queued and will be processed later.
    Queued,

    /// Source has given blocks that aren't part of the finalized chain.
    ///
    /// This doesn't necessarily mean that the source is malicious or uses a different chain. It
    /// is possible for this to legitimately happen, for example if the finalized chain has been
    /// updated while the ancestry search was in progress.
    NotFinalizedChain {
        /// List of block headers that were pending verification and that have now been discarded
        /// since it has been found out that they don't belong to the finalized chain.
        discarded_unverified_block_headers: Vec<Vec<u8>>,
    },

    /// All blocks in the ancestry search response were already in the list of verified blocks.
    ///
    /// This can happen if a block announce or different ancestry search response has been
    /// processed in between the request and response.
    AllAlreadyInChain,
}

/// See [`AllSync::grandpa_commit_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrandpaCommitMessageOutcome {
    /// Message has been silently discarded.
    Discarded,
    /// Message has been queued for later verification.
    Queued,
}

// TODO: doc
#[derive(Debug, Clone)]
pub struct Block<TBl> {
    /// Header of the block.
    pub header: header::Header,

    /// SCALE-encoded justifications of this block, if any.
    pub justifications: Vec<([u8; 4], Vec<u8>)>,

    /// User data associated to the block.
    pub user_data: TBl,

    /// Extra fields for full block verifications.
    pub full: Option<BlockFull>,
}

// TODO: doc
#[derive(Debug, Clone)]
pub struct BlockFull {
    /// List of SCALE-encoded extrinsics that form the block's body.
    pub body: Vec<Vec<u8>>,
}

pub struct BlockVerify<TRq, TSrc, TBl> {
    inner: BlockVerifyInner<TRq, TSrc, TBl>,
    shared: Shared<TRq>,
}

enum BlockVerifyInner<TRq, TSrc, TBl> {
    AllForks(
        all_forks::BlockVerify<Option<TBl>, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>,
    ),
    Optimistic(
        optimistic::BlockVerify<OptimisticRequestExtra<TRq>, OptimisticSourceExtra<TSrc>, TBl>,
    ),
}

impl<TRq, TSrc, TBl> BlockVerify<TRq, TSrc, TBl> {
    /// Returns the hash of the block to be verified.
    pub fn hash(&self) -> [u8; 32] {
        match &self.inner {
            BlockVerifyInner::AllForks(verify) => *verify.hash(),
            BlockVerifyInner::Optimistic(verify) => verify.hash(),
        }
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::full_mode`] is `true`
    pub fn scale_encoded_extrinsics(
        &'_ self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone + '_> + Clone + '_> {
        match &self.inner {
            BlockVerifyInner::AllForks(_verify) => todo!(), // TODO: /!\
            BlockVerifyInner::Optimistic(verify) => verify.scale_encoded_extrinsics(),
        }
    }

    /// Returns the SCALE-encoded header of the block about to be verified.
    pub fn scale_encoded_header(&self) -> Vec<u8> {
        match &self.inner {
            BlockVerifyInner::AllForks(verify) => verify.scale_encoded_header(),
            BlockVerifyInner::Optimistic(verify) => verify.scale_encoded_header().to_vec(),
        }
    }

    /// Verify the header of the block.
    pub fn verify_header(
        self,
        now_from_unix_epoch: Duration,
    ) -> HeaderVerifyOutcome<TRq, TSrc, TBl> {
        match self.inner {
            BlockVerifyInner::AllForks(verify) => {
                let verified_block_hash = *verify.hash();

                match verify.verify_header(now_from_unix_epoch) {
                    all_forks::HeaderVerifyOutcome::Success {
                        is_new_best,
                        success,
                    } => HeaderVerifyOutcome::Success {
                        is_new_best,
                        success: HeaderVerifySuccess {
                            inner: HeaderVerifySuccessInner::AllForks(success),
                            shared: self.shared,
                            verified_block_hash,
                        },
                    },
                    all_forks::HeaderVerifyOutcome::Error { sync, error } => {
                        HeaderVerifyOutcome::Error {
                            sync: AllSync {
                                inner: AllSyncInner::AllForks(sync),
                                shared: self.shared,
                            },
                            error: match error {
                                all_forks::HeaderVerifyError::VerificationFailed(error) => {
                                    HeaderVerifyError::VerificationFailed(error)
                                }
                                all_forks::HeaderVerifyError::UnknownConsensusEngine => {
                                    HeaderVerifyError::UnknownConsensusEngine
                                }
                                all_forks::HeaderVerifyError::ConsensusMismatch => {
                                    HeaderVerifyError::ConsensusMismatch
                                }
                            },
                        }
                    }
                }
            }
            BlockVerifyInner::Optimistic(verify) => {
                let verified_block_hash = verify.hash();

                match verify.verify_header(now_from_unix_epoch) {
                    optimistic::BlockVerification::NewBest { success, .. } => {
                        HeaderVerifyOutcome::Success {
                            is_new_best: true,
                            success: HeaderVerifySuccess {
                                inner: HeaderVerifySuccessInner::Optimistic(success),
                                shared: self.shared,
                                verified_block_hash,
                            },
                        }
                    }
                    optimistic::BlockVerification::Reset { sync, .. } => {
                        HeaderVerifyOutcome::Error {
                            sync: AllSync {
                                inner: AllSyncInner::Optimistic { inner: sync },
                                shared: self.shared,
                            },
                            error: HeaderVerifyError::ConsensusMismatch, // TODO: dummy error cause /!\
                        }
                    }
                }
            }
        }
    }
}

/// Outcome of calling [`BlockVerify::verify_header`].
pub enum HeaderVerifyOutcome<TRq, TSrc, TBl> {
    /// Header has been successfully verified.
    Success {
        /// True if the newly-verified block is considered the new best block.
        is_new_best: bool,
        success: HeaderVerifySuccess<TRq, TSrc, TBl>,
    },

    /// Header verification failed.
    Error {
        /// State machine yielded back. Use to continue the processing.
        sync: AllSync<TRq, TSrc, TBl>,
        /// Error that happened.
        error: HeaderVerifyError,
    },
}

/// Error that can happen when verifying a block header.
#[derive(Debug, derive_more::Display)]
pub enum HeaderVerifyError {
    /// Block can't be verified as it uses an unknown consensus engine.
    UnknownConsensusEngine,
    /// Block uses a different consensus than the rest of the chain.
    ConsensusMismatch,
    /// The block verification has failed. The block is invalid and should be thrown away.
    #[display(fmt = "{_0}")]
    VerificationFailed(verify::header_only::Error),
}

pub struct HeaderVerifySuccess<TRq, TSrc, TBl> {
    inner: HeaderVerifySuccessInner<TRq, TSrc, TBl>,
    shared: Shared<TRq>,
    verified_block_hash: [u8; 32],
}

enum HeaderVerifySuccessInner<TRq, TSrc, TBl> {
    AllForks(
        all_forks::HeaderVerifySuccess<
            Option<TBl>,
            AllForksRequestExtra<TRq>,
            AllForksSourceExtra<TSrc>,
        >,
    ),
    Optimistic(
        optimistic::BlockVerifySuccess<
            OptimisticRequestExtra<TRq>,
            OptimisticSourceExtra<TSrc>,
            TBl,
        >,
    ),
}

impl<TRq, TSrc, TBl> HeaderVerifySuccess<TRq, TSrc, TBl> {
    /// Returns the height of the block that was verified.
    pub fn height(&self) -> u64 {
        match &self.inner {
            HeaderVerifySuccessInner::AllForks(verify) => verify.height(),
            HeaderVerifySuccessInner::Optimistic(verify) => verify.height(),
        }
    }

    /// Returns the hash of the block that was verified.
    pub fn hash(&self) -> [u8; 32] {
        match &self.inner {
            HeaderVerifySuccessInner::AllForks(verify) => *verify.hash(),
            HeaderVerifySuccessInner::Optimistic(verify) => verify.hash(),
        }
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::full_mode`] is `true`
    pub fn scale_encoded_extrinsics(
        &'_ self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone + '_> + Clone + '_> {
        match &self.inner {
            HeaderVerifySuccessInner::AllForks(_verify) => todo!(), // TODO: /!\
            HeaderVerifySuccessInner::Optimistic(verify) => verify.scale_encoded_extrinsics(),
        }
    }

    /// Returns the hash of the parent of the block that was verified.
    pub fn parent_hash(&self) -> &[u8; 32] {
        match &self.inner {
            HeaderVerifySuccessInner::AllForks(verify) => verify.parent_hash(),
            HeaderVerifySuccessInner::Optimistic(verify) => verify.parent_hash(),
        }
    }

    /// Returns the user data of the parent of the block to be verified, or `None` if the parent
    /// is the finalized block.
    pub fn parent_user_data(&self) -> Option<&TBl> {
        match &self.inner {
            HeaderVerifySuccessInner::AllForks(_verify) => todo!(), // TODO: /!\
            HeaderVerifySuccessInner::Optimistic(verify) => verify.parent_user_data(),
        }
    }

    /// Returns the SCALE-encoded header of the block that was verified.
    pub fn scale_encoded_header(&self) -> &[u8] {
        match &self.inner {
            HeaderVerifySuccessInner::AllForks(verify) => verify.scale_encoded_header(),
            HeaderVerifySuccessInner::Optimistic(verify) => verify.scale_encoded_header(),
        }
    }

    /// Returns the SCALE-encoded header of the parent of the block.
    pub fn parent_scale_encoded_header(&self) -> Vec<u8> {
        match &self.inner {
            HeaderVerifySuccessInner::AllForks(_inner) => todo!(), // TODO: /!\
            HeaderVerifySuccessInner::Optimistic(inner) => inner.parent_scale_encoded_header(),
        }
    }

    /// Reject the block and mark it as bad.
    pub fn reject_bad_block(self) -> AllSync<TRq, TSrc, TBl> {
        match self.inner {
            HeaderVerifySuccessInner::AllForks(inner) => {
                let sync = inner.reject_bad_block();
                AllSync {
                    inner: AllSyncInner::AllForks(sync),
                    shared: self.shared,
                }
            }
            HeaderVerifySuccessInner::Optimistic(inner) => {
                let sync = inner.reject_bad_block();
                AllSync {
                    inner: AllSyncInner::Optimistic { inner: sync },
                    shared: self.shared,
                }
            }
        }
    }

    /// Finish inserting the block header.
    pub fn finish(self, user_data: TBl) -> AllSync<TRq, TSrc, TBl> {
        let height = self.height();
        match self.inner {
            HeaderVerifySuccessInner::AllForks(inner) => {
                let mut sync = inner.finish();
                *sync.block_user_data_mut(height, &self.verified_block_hash) = Some(user_data);
                AllSync {
                    inner: AllSyncInner::AllForks(sync),
                    shared: self.shared,
                }
            }
            HeaderVerifySuccessInner::Optimistic(inner) => {
                let sync = inner.finish(user_data);
                AllSync {
                    inner: AllSyncInner::Optimistic { inner: sync },
                    shared: self.shared,
                }
            }
        }
    }
}

// TODO: should be used by the optimistic syncing as well
pub struct FinalityProofVerify<TRq, TSrc, TBl> {
    inner: FinalityProofVerifyInner<TRq, TSrc, TBl>,
    shared: Shared<TRq>,
}

enum FinalityProofVerifyInner<TRq, TSrc, TBl> {
    AllForks(
        all_forks::FinalityProofVerify<
            Option<TBl>,
            AllForksRequestExtra<TRq>,
            AllForksSourceExtra<TSrc>,
        >,
    ),
    Optimistic(
        optimistic::JustificationVerify<
            OptimisticRequestExtra<TRq>,
            OptimisticSourceExtra<TSrc>,
            TBl,
        >,
    ),
}

impl<TRq, TSrc, TBl> FinalityProofVerify<TRq, TSrc, TBl> {
    /// Perform the verification.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    pub fn perform(
        self,
        randomness_seed: [u8; 32],
    ) -> (AllSync<TRq, TSrc, TBl>, FinalityProofVerifyOutcome<TBl>) {
        match self.inner {
            FinalityProofVerifyInner::AllForks(verify) => {
                let (sync, outcome) = match verify.perform(randomness_seed) {
                    (
                        sync,
                        all_forks::FinalityProofVerifyOutcome::NewFinalized {
                            finalized_blocks_newest_to_oldest,
                            pruned_blocks,
                            updates_best_block,
                        },
                    ) => (
                        sync,
                        FinalityProofVerifyOutcome::NewFinalized {
                            finalized_blocks_newest_to_oldest: finalized_blocks_newest_to_oldest
                                .into_iter()
                                .map(|b| Block {
                                    full: None, // TODO: wrong
                                    header: b.0,
                                    justifications: Vec::new(), // TODO: wrong
                                    user_data: b.1.unwrap(),
                                })
                                .collect(),
                            pruned_blocks: pruned_blocks
                                .into_iter()
                                .map(|b| b.0.hash(self.shared.block_number_bytes))
                                .collect(),
                            updates_best_block,
                        },
                    ),
                    (sync, all_forks::FinalityProofVerifyOutcome::AlreadyFinalized) => {
                        (sync, FinalityProofVerifyOutcome::AlreadyFinalized)
                    }
                    (sync, all_forks::FinalityProofVerifyOutcome::GrandpaCommitPending) => {
                        (sync, FinalityProofVerifyOutcome::GrandpaCommitPending)
                    }
                    (sync, all_forks::FinalityProofVerifyOutcome::JustificationError(error)) => {
                        (sync, FinalityProofVerifyOutcome::JustificationError(error))
                    }
                    (sync, all_forks::FinalityProofVerifyOutcome::GrandpaCommitError(error)) => {
                        (sync, FinalityProofVerifyOutcome::GrandpaCommitError(error))
                    }
                };

                (
                    AllSync {
                        inner: AllSyncInner::AllForks(sync),
                        shared: self.shared,
                    },
                    outcome,
                )
            }
            FinalityProofVerifyInner::Optimistic(verify) => match verify.perform(randomness_seed) {
                (
                    inner,
                    optimistic::JustificationVerification::Finalized {
                        finalized_blocks_newest_to_oldest: finalized_blocks,
                    },
                ) => (
                    // TODO: transition to all_forks
                    AllSync {
                        inner: AllSyncInner::Optimistic { inner },
                        shared: self.shared,
                    },
                    FinalityProofVerifyOutcome::NewFinalized {
                        finalized_blocks_newest_to_oldest: finalized_blocks
                            .into_iter()
                            .map(|b| Block {
                                header: b.header,
                                justifications: b.justifications,
                                user_data: b.user_data,
                                full: b.full.map(|b| BlockFull { body: b.body }),
                            })
                            .collect(),
                        pruned_blocks: Vec::new(),
                        updates_best_block: false,
                    },
                ),
                (inner, optimistic::JustificationVerification::Reset { error, .. }) => (
                    AllSync {
                        inner: AllSyncInner::Optimistic { inner },
                        shared: self.shared,
                    },
                    FinalityProofVerifyOutcome::JustificationError(error),
                ),
            },
        }
    }
}

/// Information about the outcome of verifying a finality proof.
#[derive(Debug)]
pub enum FinalityProofVerifyOutcome<TBl> {
    /// Proof verification successful. The block and all its ancestors is now finalized.
    NewFinalized {
        /// List of finalized blocks, in decreasing block number.
        finalized_blocks_newest_to_oldest: Vec<Block<TBl>>,
        /// List of hashes of blocks that are no longer descendant of the finalized block, in
        /// an unspecified order.
        pruned_blocks: Vec<[u8; 32]>,
        /// If `true`, this operation modifies the best block of the non-finalized chain.
        /// This can happen if the previous best block isn't a descendant of the now finalized
        /// block.
        updates_best_block: bool,
    },
    /// Finality proof concerns block that was already finalized.
    AlreadyFinalized,
    /// GrandPa commit cannot be verified yet and has been stored for later.
    GrandpaCommitPending,
    /// Problem while verifying justification.
    JustificationError(blocks_tree::JustificationVerifyError),
    /// Problem while verifying GrandPa commit.
    GrandpaCommitError(blocks_tree::CommitVerifyError),
}

pub struct WarpSyncFragmentVerify<TRq, TSrc, TBl> {
    inner: warp_sync::VerifyWarpSyncFragment<WarpSyncSourceExtra<TSrc>, WarpSyncRequestExtra<TRq>>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    shared: Shared<TRq>,
    marker: marker::PhantomData<Vec<TBl>>,
}

impl<TRq, TSrc, TBl> WarpSyncFragmentVerify<TRq, TSrc, TBl> {
    /// Returns the identifier and user data of the source that has sent the fragment to be
    /// verified.
    ///
    /// Returns `None` if the source has been removed since the fragments have been downloaded.
    pub fn proof_sender(&self) -> Option<(SourceId, &TSrc)> {
        let (_, ud) = self.inner.proof_sender()?;
        Some((ud.outer_source_id, &ud.user_data))
    }

    /// Perform the verification.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    ///
    /// On success, returns the block hash and height that have been verified as being part of
    /// the chain.
    pub fn perform(
        self,
        randomness_seed: [u8; 32],
    ) -> (
        AllSync<TRq, TSrc, TBl>,
        Result<([u8; 32], u64), VerifyFragmentError>,
    ) {
        let (next_grandpa_warp_sync, result) = self.inner.verify(randomness_seed);

        (
            AllSync {
                inner: AllSyncInner::WarpSync {
                    inner: next_grandpa_warp_sync,
                    ready_to_transition: self.ready_to_transition,
                },
                shared: self.shared,
            },
            result,
        )
    }
}

/// Compiling a new runtime is necessary for the warp sync process.
#[must_use]
pub struct WarpSyncBuildRuntime<TRq, TSrc, TBl> {
    inner: warp_sync::BuildRuntime<WarpSyncSourceExtra<TSrc>, WarpSyncRequestExtra<TRq>>,
    ready_to_transition: Option<warp_sync::RuntimeInformation>,
    shared: Shared<TRq>,
    marker: marker::PhantomData<Vec<TBl>>,
}

impl<TRq, TSrc, TBl> WarpSyncBuildRuntime<TRq, TSrc, TBl> {
    /// Builds the runtime.
    ///
    /// Assuming that the warp syncing goes to completion, the provided parameters are used to
    /// compile the runtime that will be yielded in
    /// [`ProcessOne::WarpSyncFinished::finalized_block_runtime`].
    pub fn build(
        self,
        exec_hint: ExecHint,
        allow_unresolved_imports: bool,
    ) -> (
        AllSync<TRq, TSrc, TBl>,
        Result<(), WarpSyncBuildRuntimeError>,
    ) {
        let (warp_sync_status, outcome) = self.inner.build(exec_hint, allow_unresolved_imports);

        (
            AllSync {
                inner: AllSyncInner::WarpSync {
                    inner: warp_sync_status,
                    ready_to_transition: self.ready_to_transition,
                },
                shared: self.shared,
            },
            outcome,
        )
    }
}

/// Building the chain information is necessary for the warp sync process.
#[must_use]
pub struct WarpSyncBuildChainInformation<TRq, TSrc, TBl> {
    inner: warp_sync::BuildChainInformation<WarpSyncSourceExtra<TSrc>, WarpSyncRequestExtra<TRq>>,
    shared: Shared<TRq>,
    marker: marker::PhantomData<Vec<TBl>>,
}

impl<TRq, TSrc, TBl> WarpSyncBuildChainInformation<TRq, TSrc, TBl> {
    /// Builds the chain information.
    pub fn build(
        self,
    ) -> (
        AllSync<TRq, TSrc, TBl>,
        Result<(), WarpSyncBuildChainInformationError>,
    ) {
        let (warp_sync_status, outcome) = self.inner.build();

        let (ready_to_transition, outcome) = match outcome {
            Ok(info) => (Some(info), Ok(())),
            Err(err) => (None, Err(err)),
        };

        (
            AllSync {
                inner: AllSyncInner::WarpSync {
                    inner: warp_sync_status,
                    ready_to_transition,
                },
                shared: self.shared,
            },
            outcome,
        )
    }
}

enum AllSyncInner<TRq, TSrc, TBl> {
    WarpSync {
        inner: warp_sync::WarpSync<WarpSyncSourceExtra<TSrc>, WarpSyncRequestExtra<TRq>>,
        ready_to_transition: Option<warp_sync::RuntimeInformation>,
    },
    Optimistic {
        inner: optimistic::OptimisticSync<
            OptimisticRequestExtra<TRq>,
            OptimisticSourceExtra<TSrc>,
            TBl,
        >,
    },
    // TODO: we store an `Option<TBl>` instead of `TBl` due to API issues; the all.rs doesn't let you insert user datas for pending blocks while the AllForksSync lets you; `None` is stored while a block is pending
    AllForks(
        all_forks::AllForksSync<Option<TBl>, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>,
    ),
    Poisoned,
}

struct AllForksSourceExtra<TSrc> {
    outer_source_id: SourceId,
    user_data: TSrc,
}

struct AllForksRequestExtra<TRq> {
    outer_request_id: RequestId,
    user_data: Option<TRq>, // TODO: why option?
}

struct OptimisticSourceExtra<TSrc> {
    user_data: TSrc,
    best_block_hash: [u8; 32],
    outer_source_id: SourceId,
}

struct OptimisticRequestExtra<TRq> {
    outer_request_id: RequestId,
    user_data: TRq,
}

struct WarpSyncSourceExtra<TSrc> {
    outer_source_id: SourceId,
    user_data: TSrc,
    best_block_number: u64,
    best_block_hash: [u8; 32],
}

struct WarpSyncRequestExtra<TRq> {
    outer_request_id: RequestId,
    user_data: TRq,
}

struct Shared<TRq> {
    sources: slab::Slab<SourceMapping>,
    requests: slab::Slab<RequestMapping<TRq>>,

    /// See [`Config::full_mode`].
    full_mode: bool,

    /// Value passed through [`Config::sources_capacity`].
    sources_capacity: usize,
    /// Value passed through [`Config::blocks_capacity`].
    blocks_capacity: usize,
    /// Value passed through [`Config::max_disjoint_headers`].
    max_disjoint_headers: usize,
    /// Value passed through [`Config::max_requests_per_block`].
    max_requests_per_block: NonZeroU32,
    /// Value passed through [`Config::block_number_bytes`].
    block_number_bytes: usize,
    /// Value passed through [`Config::allow_unknown_consensus_engines`].
    allow_unknown_consensus_engines: bool,
}

impl<TRq> Shared<TRq> {
    /// Transitions the sync state machine from the warp sync strategy to the "all-forks"
    /// strategy.
    fn transition_warp_sync_all_forks<TSrc, TBl>(
        &mut self,
        warp_sync: warp_sync::WarpSync<WarpSyncSourceExtra<TSrc>, WarpSyncRequestExtra<TRq>>,
        ready_to_transition: warp_sync::RuntimeInformation,
    ) -> (
        all_forks::AllForksSync<Option<TBl>, AllForksRequestExtra<TRq>, AllForksSourceExtra<TSrc>>,
        host::HostVmPrototype,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<Nibble>>,
    ) {
        let warp_sync = warp_sync.deconstruct();

        let mut all_forks = all_forks::AllForksSync::new(all_forks::Config {
            chain_information: warp_sync.chain_information,
            block_number_bytes: self.block_number_bytes,
            sources_capacity: self.sources_capacity,
            blocks_capacity: self.blocks_capacity,
            max_disjoint_headers: self.max_disjoint_headers,
            max_requests_per_block: self.max_requests_per_block,
            allow_unknown_consensus_engines: self.allow_unknown_consensus_engines,
            full: false,
        });

        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::WarpSync(_))));

        for (
            source_id,
            _,
            WarpSyncRequestExtra {
                outer_request_id,
                user_data,
            },
            detail,
        ) in warp_sync.in_progress_requests
        {
            // TODO: DRY
            let detail = match detail {
                warp_sync::RequestDetail::WarpSyncRequest { block_hash } => {
                    RequestDetail::WarpSync {
                        sync_start_block_hash: block_hash,
                    }
                }
                warp_sync::RequestDetail::StorageGetMerkleProof { block_hash, keys } => {
                    RequestDetail::StorageGet { block_hash, keys }
                }
                warp_sync::RequestDetail::RuntimeCallMerkleProof {
                    block_hash,
                    function_name,
                    parameter_vectored,
                } => RequestDetail::RuntimeCallMerkleProof {
                    block_hash,
                    function_name,
                    parameter_vectored,
                },
            };

            // TODO: O(n2)
            let (source_id, _) = self
                .sources
                .iter()
                .find(|(_, s)| {
                    matches!(s,
                        SourceMapping::WarpSync(s) if *s == source_id
                    )
                })
                .unwrap();

            self.requests[outer_request_id.0] =
                RequestMapping::Inline(SourceId(source_id), detail, user_data);
        }

        for (_, finalized_block_height, source) in warp_sync.sources_ordered {
            let source_user_data = AllForksSourceExtra {
                user_data: source.user_data,
                outer_source_id: source.outer_source_id,
            };

            let updated_source_id = match all_forks
                .prepare_add_source(source.best_block_number, source.best_block_hash)
            {
                all_forks::AddSource::BestBlockAlreadyVerified(b)
                | all_forks::AddSource::BestBlockPendingVerification(b) => {
                    b.add_source(source_user_data)
                }
                all_forks::AddSource::OldBestBlock(b) => b.add_source(source_user_data),
                all_forks::AddSource::UnknownBestBlock(b) => {
                    b.add_source_and_insert_block(source_user_data, None)
                }
            };

            if let Some(finalized_block_height) = finalized_block_height {
                all_forks.update_source_finality_state(updated_source_id, finalized_block_height);
            }

            self.sources[source.outer_source_id.0] = SourceMapping::AllForks(updated_source_id);
        }

        debug_assert!(self
            .sources
            .iter()
            .all(|(_, s)| matches!(s, SourceMapping::AllForks(_))));
        debug_assert!(self
            .requests
            .iter()
            .all(|(_, s)| matches!(s, RequestMapping::AllForks(..) | RequestMapping::Inline(..))));

        (
            all_forks,
            ready_to_transition.finalized_runtime,
            ready_to_transition.finalized_storage_code,
            ready_to_transition.finalized_storage_heap_pages,
            ready_to_transition.finalized_storage_code_merkle_value,
            ready_to_transition.finalized_storage_code_closest_ancestor_excluding,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestMapping<TRq> {
    Inline(SourceId, RequestDetail, TRq),
    AllForks(all_forks::RequestId),
    Optimistic(optimistic::RequestId),
    WarpSync(warp_sync::RequestId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceMapping {
    WarpSync(warp_sync::SourceId),
    AllForks(all_forks::SourceId),
    Optimistic(optimistic::SourceId),
}

fn all_forks_request_convert(
    rq_params: all_forks::RequestParams,
    full_node: bool,
) -> DesiredRequest {
    DesiredRequest::BlocksRequest {
        ascending: false, // Hardcoded based on the logic of the all-forks syncing.
        first_block_hash: Some(rq_params.first_block_hash),
        first_block_height: rq_params.first_block_height,
        num_blocks: rq_params.num_blocks,
        request_bodies: full_node,
        request_headers: true,
        request_justification: true,
    }
}

fn optimistic_request_convert(
    rq_params: optimistic::RequestDetail,
    full_node: bool,
) -> DesiredRequest {
    DesiredRequest::BlocksRequest {
        ascending: true, // Hardcoded based on the logic of the optimistic syncing.
        first_block_hash: None,
        first_block_height: rq_params.block_height.get(),
        num_blocks: rq_params.num_blocks.into(),
        request_bodies: full_node,
        request_headers: true,
        request_justification: true,
    }
}
