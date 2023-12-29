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

//! Optimistic header and body syncing.
//!
//! This state machine builds, from a set of sources, a fully verified chain of blocks headers
//! and bodies.
//!
//! # Overview
//!
//! The algorithm used by this state machine is called "optimistic syncing". It consists in
//! sending requests for blocks to a certain list of sources, aggregating the answers, and
//! verifying them.
//!
//! The [`OptimisticSync`] struct holds a list of sources, a list of pending block requests,
//! a chain, and a list of blocks received as answers and waiting to be verified.
//!
//! The requests are emitted ahead of time, so that they can be answered asynchronously while
//! blocks in the verification queue are being processed.
//!
//! The syncing is said to be *optimistic* because it is assumed that all sources will provide
//! correct blocks.
//! In the case where the verification of a block fails, the state machine jumps back to the
//! latest known finalized block and resumes syncing from there, possibly using different sources
//! this time.
//!
//! The *optimism* aspect comes from the fact that, while a bad source can't corrupt the state of
//! the local chain, and can't stall the syncing process (unless there isn't any other source
//! available), it can still slow it down.

// TODO: document better
// TODO: this entire module needs clean up

use crate::{
    chain::{blocks_tree, chain_information},
    header,
};

use alloc::{
    boxed::Box,
    collections::BTreeSet,
    vec::{self, Vec},
};
use core::{
    cmp, fmt, iter, mem,
    num::{NonZeroU32, NonZeroU64},
    ops,
    time::Duration,
};
use hashbrown::HashMap;

mod verification_queue;

/// Configuration for the [`OptimisticSync`].
#[derive(Debug)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// Number of bytes used when encoding/decoding the block number. Influences how various data
    /// structures should be parsed.
    pub block_number_bytes: usize,

    /// Pre-allocated capacity for the number of block sources.
    pub sources_capacity: usize,

    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    ///
    /// Should be set to the maximum number of block between two consecutive justifications.
    pub blocks_capacity: usize,

    /// Number of blocks to download ahead of the best block.
    ///
    /// Whenever the latest best block is updated, the state machine will start block
    /// requests for the block `best_block_height + download_ahead_blocks` and all its
    /// ancestors. Considering that requesting blocks has some latency, downloading blocks ahead
    /// of time ensures that verification isn't blocked waiting for a request to be finished.
    ///
    /// The ideal value here depends on the speed of blocks verification speed and latency of
    /// block requests.
    pub download_ahead_blocks: NonZeroU32,

    /// If `true`, the downloaded block bodies are stored in the state machine.
    pub download_bodies: bool,
}

/// Identifier for an ongoing request in the [`OptimisticSync`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// Returns a value that compares inferior or equal to any other [`RequestId`].
    pub fn min_value() -> Self {
        Self(u64::min_value())
    }

    /// Returns a value that compares superior or equal to any other [`RequestId`].
    pub fn max_value() -> Self {
        Self(u64::max_value())
    }
}

/// Identifier for a source in the [`OptimisticSync`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(u64);

/// Optimistic headers-only syncing.
pub struct OptimisticSync<TRq, TSrc, TBl> {
    /// Data structure containing the blocks.
    ///
    /// The user data, [`Block`], isn't used internally but stores information later reported
    /// to the user.
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,

    /// Extra fields. In a separate structure in order to be moved around.
    ///
    /// A `Box` is used in order to minimize the impact of moving the value around, and to reduce
    /// the size of the [`OptimisticSync`].
    inner: Box<OptimisticSyncInner<TRq, TSrc, TBl>>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct OptimisticSyncInner<TRq, TSrc, TBl> {
    /// Configuration for the actual finalized block of the chain.
    /// Used if the `chain` field needs to be recreated.
    finalized_chain_information: blocks_tree::Config,

    /// See [`Config::download_bodies`].
    download_bodies: bool,

    /// See [`Config::download_ahead_blocks`].
    download_ahead_blocks: NonZeroU32,

    /// List of sources of blocks.
    sources: HashMap<SourceId, Source<TSrc>, fnv::FnvBuildHasher>,

    /// Next [`SourceId`] to allocate.
    /// `SourceIds` are unique so that the source in the [`verification_queue::VerificationQueue`]
    /// doesn't accidentally collide with a new source.
    next_source_id: SourceId,

    /// Queue of block requests, either waiting to be started, in progress, or completed.
    verification_queue:
        verification_queue::VerificationQueue<(RequestId, TRq), RequestSuccessBlock<TBl>>,

    /// Justifications, if any, of the block that has just been verified.
    // TODO: clean up when a source is removed
    pending_encoded_justifications: vec::IntoIter<([u8; 4], Vec<u8>, SourceId)>,

    /// Identifier to assign to the next request.
    next_request_id: RequestId,

    /// Requests that have been started but whose answers are no longer desired.
    obsolete_requests: HashMap<RequestId, (SourceId, TRq), fnv::FnvBuildHasher>,

    /// Same as [`OptimisticSyncInner::obsolete_requests`], but ordered differently.
    obsolete_requests_by_source: BTreeSet<(SourceId, RequestId)>,
}

impl<TRq, TSrc, TBl> OptimisticSyncInner<TRq, TSrc, TBl> {
    fn make_requests_obsolete(&mut self, chain: &blocks_tree::NonFinalizedTree<Block<TBl>>) {
        let former_queue = mem::replace(
            &mut self.verification_queue,
            verification_queue::VerificationQueue::new(chain.best_block_header().number + 1),
        );

        for ((request_id, user_data), source) in former_queue.into_requests() {
            let _was_in = self
                .obsolete_requests
                .insert(request_id, (source, user_data));
            debug_assert!(_was_in.is_none());
            let _was_inserted = self
                .obsolete_requests_by_source
                .insert((source, request_id));
            debug_assert!(_was_inserted);
            debug_assert_eq!(
                self.obsolete_requests.len(),
                self.obsolete_requests_by_source.len()
            );
        }
    }

    fn with_requests_obsoleted(
        mut self: Box<Self>,
        chain: &blocks_tree::NonFinalizedTree<Block<TBl>>,
    ) -> Box<Self> {
        self.make_requests_obsolete(chain);
        self
    }
}

struct Source<TSrc> {
    /// Opaque value passed to [`OptimisticSync::add_source`].
    user_data: TSrc,

    /// Best block that the source has reported having.
    best_block_number: u64,

    /// Number of requests that use this source.
    num_ongoing_requests: u32,
}

// TODO: doc
pub struct Block<TBl> {
    /// Header of the block.
    pub header: header::Header,

    /// SCALE-encoded justification of this block, if any.
    pub justifications: Vec<([u8; 4], Vec<u8>)>,

    /// User data associated to the block.
    pub user_data: TBl,

    /// Extra fields for full block verifications.
    pub full: Option<BlockFull>,
}

// TODO: doc
pub struct BlockFull {
    /// List of SCALE-encoded extrinsics that form the block's body.
    pub body: Vec<Vec<u8>>,
}

impl<TRq, TSrc, TBl> OptimisticSync<TRq, TSrc, TBl> {
    /// Builds a new [`OptimisticSync`].
    pub fn new(config: Config) -> Self {
        let blocks_tree_config = blocks_tree::Config {
            chain_information: config.chain_information,
            block_number_bytes: config.block_number_bytes,
            blocks_capacity: config.blocks_capacity,
            // Considering that we rely on justifications to sync, there is no drawback in
            // accepting blocks with unrecognized consensus engines. While this could lead to
            // accepting blocks that wouldn't otherwise be accepted, it is already the case that
            // a malicious node could send non-finalized blocks. Accepting blocks with an
            // unrecognized consensus engine doesn't add any additional risk.
            allow_unknown_consensus_engines: true,
        };

        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree_config.clone());
        let best_block_header_num = chain.best_block_header().number;

        OptimisticSync {
            chain,
            inner: Box::new(OptimisticSyncInner {
                finalized_chain_information: blocks_tree_config,
                download_bodies: config.download_bodies,
                sources: HashMap::with_capacity_and_hasher(
                    config.sources_capacity,
                    Default::default(),
                ),
                next_source_id: SourceId(0),
                verification_queue: verification_queue::VerificationQueue::new(
                    best_block_header_num + 1,
                ),
                pending_encoded_justifications: Vec::new().into_iter(),
                download_ahead_blocks: config.download_ahead_blocks,
                next_request_id: RequestId(0),
                obsolete_requests: HashMap::with_capacity_and_hasher(0, Default::default()),
                obsolete_requests_by_source: BTreeSet::new(),
            }),
        }
    }

    /// Returns the value that was initially passed in [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.chain.block_number_bytes()
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ValidChainInformationRef {
        self.chain.as_chain_information()
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        self.inner
            .finalized_chain_information
            .chain_information
            .as_ref()
            .finalized_block_header
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        self.chain.best_block_header()
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        self.chain.best_block_header().number
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        self.chain.best_block_hash()
    }

    /// Returns consensus information about the current best block of the chain.
    pub fn best_block_consensus(&self) -> chain_information::ChainInformationConsensusRef {
        self.chain.best_block_consensus()
    }

    /// Returns the header of all known non-finalized blocks in the chain without any specific
    /// order.
    pub fn non_finalized_blocks_unordered(
        &'_ self,
    ) -> impl Iterator<Item = header::HeaderRef<'_>> + '_ {
        self.chain.iter_unordered()
    }

    /// Returns the header of all known non-finalized blocks in the chain.
    ///
    /// The returned items are guaranteed to be in an order in which the parents are found before
    /// their children.
    pub fn non_finalized_blocks_ancestry_order(
        &'_ self,
    ) -> impl Iterator<Item = header::HeaderRef<'_>> + '_ {
        self.chain.iter_ancestry_order()
    }

    /// Disassembles the state machine into its raw components.
    pub fn disassemble(self) -> Disassemble<TRq, TSrc> {
        Disassemble {
            chain_information: self.inner.finalized_chain_information.chain_information,
            sources: self
                .inner
                .sources
                .into_iter()
                .map(|(id, source)| DisassembleSource {
                    id,
                    user_data: source.user_data,
                    best_block_number: source.best_block_number,
                })
                .collect(),
            requests: self
                .inner
                .verification_queue
                .into_requests()
                .map(|((request_id, user_data), _)| (request_id, user_data))
                .collect(),
        }
    }

    /// Inform the [`OptimisticSync`] of a new potential source of blocks.
    pub fn add_source(&mut self, source: TSrc, best_block_number: u64) -> SourceId {
        let new_id = {
            let id = self.inner.next_source_id;
            self.inner.next_source_id.0 += 1;
            id
        };

        self.inner.sources.insert(
            new_id,
            Source {
                user_data: source,
                best_block_number,
                num_ongoing_requests: 0,
            },
        );

        new_id
    }

    /// Returns the current best block of the given source.
    ///
    /// This corresponds either the latest call to [`OptimisticSync::raise_source_best_block`],
    /// or to the parameter passed to [`OptimisticSync::add_source`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_best_block(&self, source_id: SourceId) -> u64 {
        self.inner
            .sources
            .get(&source_id)
            .unwrap()
            .best_block_number
    }

    /// Updates the best known block of the source.
    ///
    /// Has no effect if the previously-known best block is lower than the new one.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn raise_source_best_block(&mut self, id: SourceId, best_block_number: u64) {
        let current = &mut self.inner.sources.get_mut(&id).unwrap().best_block_number;
        if *current < best_block_number {
            *current = best_block_number;
        }
    }

    /// Inform the [`OptimisticSync`] that a source of blocks is no longer available.
    ///
    /// This automatically cancels all the requests that have been emitted for this source.
    /// This list of requests is returned as part of this function.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn remove_source(
        &'_ mut self,
        source_id: SourceId,
    ) -> (TSrc, impl Iterator<Item = (RequestId, TRq)> + '_) {
        let obsolete_requests_to_remove = self
            .inner
            .obsolete_requests_by_source
            .range((source_id, RequestId::min_value())..=(source_id, RequestId::max_value()))
            .map(|(_, id)| *id)
            .collect::<Vec<_>>();
        let mut obsolete_requests = Vec::with_capacity(obsolete_requests_to_remove.len());
        for rq_id in obsolete_requests_to_remove {
            let (_, user_data) = self.inner.obsolete_requests.remove(&rq_id).unwrap();
            obsolete_requests.push((rq_id, user_data));
            let _was_in = self
                .inner
                .obsolete_requests_by_source
                .remove(&(source_id, rq_id));
            debug_assert!(_was_in);
        }

        debug_assert_eq!(
            self.inner.obsolete_requests.len(),
            self.inner.obsolete_requests_by_source.len()
        );

        let src_user_data = self.inner.sources.remove(&source_id).unwrap().user_data;
        let drain = RequestsDrain {
            iter: self.inner.verification_queue.drain_source(source_id),
        };
        (src_user_data, drain.chain(obsolete_requests))
    }

    /// Returns the list of sources in this state machine.
    pub fn sources(&'_ self) -> impl ExactSizeIterator<Item = SourceId> + '_ {
        self.inner.sources.keys().copied()
    }

    /// Returns the number of ongoing requests that concern this source.
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn source_num_ongoing_requests(&self, source_id: SourceId) -> usize {
        let num_obsolete = self
            .inner
            .obsolete_requests_by_source
            .range((source_id, RequestId::min_value())..=(source_id, RequestId::max_value()))
            .count();
        let num_regular = self
            .inner
            .verification_queue
            .source_num_ongoing_requests(source_id);
        num_obsolete + num_regular
    }

    /// Returns an iterator that yields all the requests whose outcome is no longer desired.
    pub fn obsolete_requests(&'_ self) -> impl Iterator<Item = (RequestId, &'_ TRq)> + '_ {
        self.inner
            .obsolete_requests
            .iter()
            .map(|(id, (_, ud))| (*id, ud))
    }

    /// Returns an iterator that yields all requests that could be started.
    pub fn desired_requests(&'_ self) -> impl Iterator<Item = RequestDetail> + '_ {
        let sources = &self.inner.sources;
        self.inner
            .verification_queue
            .desired_requests(self.inner.download_ahead_blocks)
            .flat_map(move |e| sources.iter().map(move |s| (e, s)))
            .filter_map(|((block_height, num_blocks), (source_id, source))| {
                let source_avail_blocks = NonZeroU32::new(
                    u32::try_from(source.best_block_number.checked_sub(block_height.get())? + 1)
                        .unwrap(),
                )
                .unwrap();
                Some(RequestDetail {
                    block_height,
                    num_blocks: cmp::min(source_avail_blocks, num_blocks),
                    source_id: *source_id,
                })
            })
    }

    /// Updates the [`OptimisticSync`] with the fact that a request has been started.
    ///
    /// Returns the identifier for the request that must later be passed back to
    /// [`OptimisticSync::finish_request_success`] or [`OptimisticSync::finish_request_failed`].
    ///
    /// # Panic
    ///
    /// Panics if the [`SourceId`] is invalid.
    ///
    pub fn insert_request(&mut self, detail: RequestDetail, user_data: TRq) -> RequestId {
        self.inner
            .sources
            .get_mut(&detail.source_id)
            .unwrap()
            .num_ongoing_requests += 1;

        let request_id = self.inner.next_request_id;
        self.inner.next_request_id.0 += 1;

        match self.inner.verification_queue.insert_request(
            detail.block_height,
            detail.num_blocks,
            detail.source_id,
            (request_id, user_data),
        ) {
            Ok(()) => {}
            Err((_, user_data)) => {
                self.inner
                    .obsolete_requests
                    .insert(request_id, (detail.source_id, user_data));
                let _was_inserted = self
                    .inner
                    .obsolete_requests_by_source
                    .insert((detail.source_id, request_id));
                debug_assert!(_was_inserted);
                debug_assert_eq!(
                    self.inner.obsolete_requests.len(),
                    self.inner.obsolete_requests_by_source.len()
                );
            }
        }

        request_id
    }

    /// Update the [`OptimisticSync`] with the successful outcome of a request.
    ///
    /// Returns the user data that was associated to that request.
    ///
    /// If [`Config::download_bodies`] was `false`, then the values of
    /// [`RequestSuccessBlock::scale_encoded_extrinsics`] are silently ignored.
    ///
    /// > **Note**: If [`Config::download_bodies`] is `false`, you are encouraged to not request
    /// >           the block's body from the source altogether, and to fill the
    /// >           [`RequestSuccessBlock::scale_encoded_extrinsics`] fields with `Vec::new()`.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn finish_request_success(
        &mut self,
        request_id: RequestId,
        blocks: impl Iterator<Item = RequestSuccessBlock<TBl>>,
    ) -> (TRq, FinishRequestOutcome) {
        if let Some((source_id, user_data)) = self.inner.obsolete_requests.remove(&request_id) {
            self.inner.obsolete_requests.shrink_to_fit();
            let _was_in = self
                .inner
                .obsolete_requests_by_source
                .remove(&(source_id, request_id));
            debug_assert!(_was_in);
            debug_assert_eq!(
                self.inner.obsolete_requests.len(),
                self.inner.obsolete_requests_by_source.len()
            );
            self.inner
                .sources
                .get_mut(&source_id)
                .unwrap()
                .num_ongoing_requests -= 1;
            return (user_data, FinishRequestOutcome::Obsolete);
        }

        // TODO: important /!\ should check whether the block bodies match the extrinsics root in the headers, in order to differentiate invalid blocks from malicious peers

        let ((_, user_data), source_id) = self
            .inner
            .verification_queue
            .finish_request(|(rq, _)| *rq == request_id, Ok(blocks));

        self.inner
            .sources
            .get_mut(&source_id)
            .unwrap()
            .num_ongoing_requests -= 1;

        (user_data, FinishRequestOutcome::Queued)
    }

    /// Update the [`OptimisticSync`] with the information that the given request has failed.
    ///
    /// Returns the user data that was associated to that request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn finish_request_failed(&mut self, request_id: RequestId) -> TRq {
        if let Some((source_id, user_data)) = self.inner.obsolete_requests.remove(&request_id) {
            self.inner.obsolete_requests.shrink_to_fit();
            let _was_in = self
                .inner
                .obsolete_requests_by_source
                .remove(&(source_id, request_id));
            debug_assert!(_was_in);
            debug_assert_eq!(
                self.inner.obsolete_requests.len(),
                self.inner.obsolete_requests_by_source.len()
            );
            self.inner
                .sources
                .get_mut(&source_id)
                .unwrap()
                .num_ongoing_requests -= 1;
            return user_data;
        }

        let ((_, user_data), source_id) = self.inner.verification_queue.finish_request(
            |(rq, _)| *rq == request_id,
            Result::<iter::Empty<_>, _>::Err(()),
        );

        self.inner
            .sources
            .get_mut(&source_id)
            .unwrap()
            .num_ongoing_requests -= 1;

        user_data
    }

    /// Returns the [`SourceId`] that is expected to fulfill the given request.
    ///
    /// # Panic
    ///
    /// Panics if the [`RequestId`] is invalid.
    ///
    pub fn request_source_id(&self, request_id: RequestId) -> SourceId {
        if let Some((src, _)) = self.inner.obsolete_requests.get(&request_id) {
            *src
        } else {
            self.inner
                .verification_queue
                .requests()
                .find(|(rq, _)| rq.0 == request_id)
                .unwrap()
                .1
        }
    }

    /// Process the next block in the queue of verification.
    ///
    /// This method takes ownership of the [`OptimisticSync`]. The [`OptimisticSync`] is yielded
    /// back in the returned value.
    pub fn process_one(self) -> ProcessOne<TRq, TSrc, TBl> {
        if !self
            .inner
            .pending_encoded_justifications
            .as_slice()
            .is_empty()
        {
            return ProcessOne::VerifyJustification(JustificationVerify {
                chain: self.chain,
                inner: self.inner,
            });
        }

        // The block isn't immediately extracted. A `Verify` struct is built, whose existence
        // confirms that a block is ready. If the `Verify` is dropped without `start` being called,
        // the block stays in the list.
        if self.inner.verification_queue.blocks_ready() {
            ProcessOne::VerifyBlock(BlockVerify {
                inner: self.inner,
                chain: self.chain,
            })
        } else {
            ProcessOne::Idle { sync: self }
        }
    }
}

impl<TRq, TSrc, TBl> ops::Index<SourceId> for OptimisticSync<TRq, TSrc, TBl> {
    type Output = TSrc;

    #[track_caller]
    fn index(&self, source_id: SourceId) -> &TSrc {
        &self.inner.sources.get(&source_id).unwrap().user_data
    }
}

impl<TRq, TSrc, TBl> ops::IndexMut<SourceId> for OptimisticSync<TRq, TSrc, TBl> {
    #[track_caller]
    fn index_mut(&mut self, source_id: SourceId) -> &mut TSrc {
        &mut self.inner.sources.get_mut(&source_id).unwrap().user_data
    }
}

impl<'a, TRq, TSrc, TBl> ops::Index<&'a [u8; 32]> for OptimisticSync<TRq, TSrc, TBl> {
    type Output = TBl;

    #[track_caller]
    fn index(&self, block_hash: &'a [u8; 32]) -> &TBl {
        &self.chain[block_hash].user_data
    }
}

impl<'a, TRq, TSrc, TBl> ops::IndexMut<&'a [u8; 32]> for OptimisticSync<TRq, TSrc, TBl> {
    #[track_caller]
    fn index_mut(&mut self, block_hash: &'a [u8; 32]) -> &mut TBl {
        &mut self.chain[block_hash].user_data
    }
}

pub struct RequestSuccessBlock<TBl> {
    pub scale_encoded_header: Vec<u8>,
    pub scale_encoded_justifications: Vec<([u8; 4], Vec<u8>)>,
    pub scale_encoded_extrinsics: Vec<Vec<u8>>,
    pub user_data: TBl,
}

/// State of the processing of blocks.
pub enum ProcessOne<TRq, TSrc, TBl> {
    /// No processing is necessary.
    ///
    /// Calling [`OptimisticSync::process_one`] again is unnecessary.
    Idle {
        /// The state machine.
        /// The [`OptimisticSync::process_one`] method takes ownership of the
        /// [`OptimisticSync`]. This field yields it back.
        sync: OptimisticSync<TRq, TSrc, TBl>,
    },

    VerifyBlock(BlockVerify<TRq, TSrc, TBl>),

    VerifyJustification(JustificationVerify<TRq, TSrc, TBl>),
}

/// Start the processing of a block verification.
pub struct BlockVerify<TRq, TSrc, TBl> {
    inner: Box<OptimisticSyncInner<TRq, TSrc, TBl>>,
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,
}

impl<TRq, TSrc, TBl> BlockVerify<TRq, TSrc, TBl> {
    /// Returns the hash of the block about to be verified.
    pub fn hash(&self) -> [u8; 32] {
        header::hash_from_scale_encoded_header(self.scale_encoded_header())
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::download_bodies`] is `true`
    pub fn scale_encoded_extrinsics(
        &'_ self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone + '_> + Clone + '_> {
        if self.inner.download_bodies {
            let block = self.inner.verification_queue.first_block().unwrap();
            Some(block.scale_encoded_extrinsics.iter())
        } else {
            None
        }
    }

    /// Returns the SCALE-encoded header of the block about to be verified.
    pub fn scale_encoded_header(&self) -> &[u8] {
        &self
            .inner
            .verification_queue
            .first_block()
            .unwrap()
            .scale_encoded_header
    }

    /// Verify the header of the block.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    pub fn verify_header(
        mut self,
        now_from_unix_epoch: Duration,
    ) -> BlockVerification<TRq, TSrc, TBl> {
        // Extract the block to process. We are guaranteed that a block is available because a
        // `Verify` is built only when that is the case.
        // Be aware that `source_id` might refer to an obsolete source.
        let (block, source_id) = self.inner.verification_queue.pop_first_block().unwrap();

        debug_assert!(self
            .inner
            .pending_encoded_justifications
            .as_slice()
            .is_empty());
        self.inner.pending_encoded_justifications = block
            .scale_encoded_justifications
            .clone()
            .into_iter()
            .map(|(e, j)| (e, j, source_id))
            .collect::<Vec<_>>()
            .into_iter();

        let outcome = match self
            .chain
            .verify_header(block.scale_encoded_header, now_from_unix_epoch)
        {
            Ok(blocks_tree::HeaderVerifySuccess::Verified {
                verified_header,
                is_new_best: true,
                ..
            }) => Ok(verified_header),
            Ok(
                blocks_tree::HeaderVerifySuccess::Duplicate
                | blocks_tree::HeaderVerifySuccess::Verified {
                    is_new_best: false, ..
                },
            ) => Err(ResetCause::NonCanonical),
            Err(err) => Err(ResetCause::HeaderError(err)),
        };

        match outcome {
            Ok(verified_header) => {
                let new_best_hash = self.chain.best_block_hash();
                let new_best_number = self.chain.best_block_header().number;

                BlockVerification::NewBest {
                    success: BlockVerifySuccess {
                        parent: OptimisticSync {
                            inner: self.inner,
                            chain: self.chain,
                        },
                        scale_encoded_extrinsics: block.scale_encoded_extrinsics,
                        verified_header,
                        scale_encoded_justifications: block.scale_encoded_justifications,
                    },
                    new_best_hash,
                    new_best_number,
                }
            }
            Err(reason) => {
                self.inner.make_requests_obsolete(&self.chain);

                let previous_best_height = self.chain.best_block_header().number;
                BlockVerification::Reset {
                    sync: OptimisticSync {
                        inner: self.inner,
                        chain: self.chain,
                    },
                    previous_best_height,
                    reason,
                }
            }
        }
    }
}

/// State of the processing of blocks.
pub enum BlockVerification<TRq, TSrc, TBl> {
    /// An issue happened when verifying the block or its justification, resulting in resetting
    /// the chain to the latest finalized block.
    // TODO: unclear what happens to the block, are they kept? discarded?
    Reset {
        /// The state machine.
        /// The [`OptimisticSync::process_one`] method takes ownership of the
        /// [`OptimisticSync`]. This field yields it back.
        sync: OptimisticSync<TRq, TSrc, TBl>,

        /// Height of the best block before the reset.
        previous_best_height: u64,

        /// Problem that happened and caused the reset.
        reason: ResetCause,
    },

    /// Processing of the block is over.
    ///
    /// There might be more blocks remaining. Call [`OptimisticSync::process_one`] again.
    NewBest {
        /// The state machine.
        /// The [`OptimisticSync::process_one`] method takes ownership of the
        /// [`OptimisticSync`]. This field yields it back.
        success: BlockVerifySuccess<TRq, TSrc, TBl>,

        new_best_number: u64,
        new_best_hash: [u8; 32],
    },
}

/// Block verification successful.
///
/// Internally holds the [`OptimisticSync`].
pub struct BlockVerifySuccess<TRq, TSrc, TBl> {
    parent: OptimisticSync<TRq, TSrc, TBl>,
    verified_header: blocks_tree::VerifiedHeader,
    scale_encoded_extrinsics: Vec<Vec<u8>>,
    scale_encoded_justifications: Vec<([u8; 4], Vec<u8>)>,
}

impl<TRq, TSrc, TBl> BlockVerifySuccess<TRq, TSrc, TBl> {
    /// Returns the height of the block that was verified.
    pub fn height(&self) -> u64 {
        header::decode(
            self.scale_encoded_header(),
            self.parent.chain.block_number_bytes(),
        )
        .unwrap()
        .number
    }

    /// Returns the hash of the block that was verified.
    pub fn hash(&self) -> [u8; 32] {
        header::hash_from_scale_encoded_header(self.scale_encoded_header())
    }

    /// Returns the list of SCALE-encoded extrinsics of the block to verify.
    ///
    /// This is `Some` if and only if [`Config::download_bodies`] is `true`
    pub fn scale_encoded_extrinsics(
        &'_ self,
    ) -> Option<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone + '_> + Clone + '_> {
        if self.parent.inner.download_bodies {
            Some(self.scale_encoded_extrinsics.iter())
        } else {
            None
        }
    }

    /// Returns the hash of the parent of the block that was verified.
    pub fn parent_hash(&self) -> &[u8; 32] {
        header::decode(
            self.scale_encoded_header(),
            self.parent.chain.block_number_bytes(),
        )
        .unwrap()
        .parent_hash
    }

    /// Returns the user data of the parent of the block to be verified, or `None` if the parent
    /// is the finalized block.
    pub fn parent_user_data(&self) -> Option<&TBl> {
        let parent_hash = self.parent_hash();
        // TODO: optimize?
        if self.parent.chain.contains_non_finalized_block(parent_hash) {
            Some(&self.parent.chain[parent_hash].user_data)
        } else {
            None
        }
    }

    /// Returns the SCALE-encoded header of the block that was verified.
    pub fn scale_encoded_header(&self) -> &[u8] {
        self.verified_header.scale_encoded_header()
    }

    /// Returns the SCALE-encoded header of the parent of the block.
    pub fn parent_scale_encoded_header(&self) -> Vec<u8> {
        // TODO: return &[u8]
        self.parent
            .chain
            .best_block_header()
            .scale_encoding_vec(self.parent.chain.block_number_bytes())
    }

    /// Cancel the block verification.
    pub fn cancel(self) -> OptimisticSync<TRq, TSrc, TBl> {
        self.parent
    }

    /// Reject the block and mark it as bad.
    pub fn reject_bad_block(mut self) -> OptimisticSync<TRq, TSrc, TBl> {
        self.parent.inner.make_requests_obsolete(&self.parent.chain);
        self.parent
    }

    /// Finish inserting the block header.
    pub fn finish(mut self, user_data: TBl) -> OptimisticSync<TRq, TSrc, TBl> {
        // TODO: don't copy the header
        let header = header::decode(
            self.verified_header.scale_encoded_header(),
            self.parent.chain.block_number_bytes(),
        )
        .unwrap()
        .into();

        self.parent.chain.insert_verified_header(
            self.verified_header,
            Block {
                header,
                justifications: self.scale_encoded_justifications,
                user_data,
                full: None,
            },
        );

        self.parent
    }
}

/// Start the processing of a justification verification.
pub struct JustificationVerify<TRq, TSrc, TBl> {
    inner: Box<OptimisticSyncInner<TRq, TSrc, TBl>>,
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,
}

impl<TRq, TSrc, TBl> JustificationVerify<TRq, TSrc, TBl> {
    /// Returns the source the justification was obtained from.
    pub fn sender(&self) -> (SourceId, &TSrc) {
        let (_, _, source_id) = self
            .inner
            .pending_encoded_justifications
            .as_slice()
            .first()
            .unwrap();
        (*source_id, &self.inner.sources[source_id].user_data)
    }

    /// Verify the justification.
    ///
    /// A randomness seed must be provided and will be used during the verification. Note that the
    /// verification is nonetheless deterministic.
    pub fn perform(
        mut self,
        randomness_seed: [u8; 32],
    ) -> (
        OptimisticSync<TRq, TSrc, TBl>,
        JustificationVerification<TBl>,
    ) {
        let (consensus_engine_id, justification, _) =
            self.inner.pending_encoded_justifications.next().unwrap();

        let mut apply = match self.chain.verify_justification(
            consensus_engine_id,
            &justification,
            randomness_seed,
        ) {
            Ok(a) => a,
            Err(error) => {
                let chain = blocks_tree::NonFinalizedTree::new(
                    self.inner.finalized_chain_information.clone(),
                );

                let inner = self.inner.with_requests_obsoleted(&chain);
                let previous_best_height = chain.best_block_header().number;
                return (
                    OptimisticSync { chain, inner },
                    JustificationVerification::Reset {
                        previous_best_height,
                        error,
                    },
                );
            }
        };

        assert!(apply.is_current_best_block()); // TODO: can legitimately fail in case of malicious node

        // As part of the finalization, put the justification in the chain that's
        // going to be reported to the user.
        apply
            .block_user_data()
            .justifications
            .push((consensus_engine_id, justification));

        // Applying the finalization and iterating over the now-finalized block.
        let finalized_blocks_newest_to_oldest = apply
            .apply()
            .filter(|b| matches!(b.ty, blocks_tree::RemovedBlockType::Finalized))
            .map(|b| b.user_data)
            .collect();

        // Since the best block is now the finalized block, reset the storage
        // diff.
        debug_assert!(self.chain.is_empty());

        self.inner.finalized_chain_information.chain_information =
            self.chain.as_chain_information().into();

        (
            OptimisticSync {
                chain: self.chain,
                inner: self.inner,
            },
            JustificationVerification::Finalized {
                finalized_blocks_newest_to_oldest,
            },
        )
    }
}

/// Outcome of the verification of a justification.
pub enum JustificationVerification<TBl> {
    /// An issue happened when verifying the justification, resulting in resetting the chain to
    /// the latest finalized block.
    Reset {
        /// Height of the best block before the reset.
        previous_best_height: u64,

        /// Problem that happened and caused the reset.
        error: blocks_tree::JustificationVerifyError,
    },

    /// Processing of the justification is over. The best block has now been finalized.
    ///
    /// There might be more blocks remaining. Call [`OptimisticSync::process_one`] again.
    Finalized {
        /// Blocks that have been finalized, in decreasing block number.
        finalized_blocks_newest_to_oldest: Vec<Block<TBl>>,
    },
}

/// Request that should be emitted towards a certain source.
#[derive(Debug)]
pub struct RequestDetail {
    /// Source where to request blocks from.
    pub source_id: SourceId,
    /// Height of the block to request.
    pub block_height: NonZeroU64,
    /// Number of blocks to request. This might be equal to `u32::max_value()` in case no upper
    /// bound is required. The API user is responsible for clamping this value to a reasonable
    /// limit.
    pub num_blocks: NonZeroU32,
}

pub enum FinishRequestOutcome {
    Obsolete,
    Queued,
}

/// Iterator that drains requests after a source has been removed.
pub struct RequestsDrain<'a, TRq, TBl> {
    iter: verification_queue::SourceDrain<'a, (RequestId, TRq), TBl>,
}

impl<'a, TRq, TBl> Iterator for RequestsDrain<'a, TRq, TBl> {
    type Item = (RequestId, TRq);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, TRq, TBl> fmt::Debug for RequestsDrain<'a, TRq, TBl> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RequestsDrain").finish()
    }
}

impl<'a, TRq, TBl> Drop for RequestsDrain<'a, TRq, TBl> {
    fn drop(&mut self) {
        // Drain all remaining elements even if the iterator is dropped eagerly.
        // This is the reason why a custom iterator type is needed.
        for _ in self {}
    }
}

/// Problem that happened and caused the reset.
#[derive(Debug, derive_more::Display)]
pub enum ResetCause {
    /// Error while decoding a header.
    #[display(fmt = "Failed to decode header: {_0}")]
    InvalidHeader(header::Error),
    /// Error while verifying a header.
    #[display(fmt = "{_0}")]
    HeaderError(blocks_tree::HeaderVerifyError),
    /// Received block isn't a child of the current best block.
    NonCanonical,
}

/// Output of [`OptimisticSync::disassemble`].
#[derive(Debug)]
pub struct Disassemble<TRq, TSrc> {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ValidChainInformation,

    /// List of sources that were within the state machine.
    pub sources: Vec<DisassembleSource<TSrc>>,

    /// List of the requests that were active.
    pub requests: Vec<(RequestId, TRq)>,
    // TODO: add non-finalized blocks?
}

/// See [`Disassemble::sources`].
#[derive(Debug)]
pub struct DisassembleSource<TSrc> {
    /// Identifier that the source had.
    pub id: SourceId,

    /// Opaque value passed to [`OptimisticSync::add_source`].
    pub user_data: TSrc,

    /// Best block that the source has reported having.
    pub best_block_number: u64,
}
