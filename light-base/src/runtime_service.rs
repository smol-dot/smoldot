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

//! Background runtime download service.
//!
//! This service plugs on top of a [`sync_service`], listens for new best blocks and checks
//! whether the runtime has changed in any way. Its objective is to always provide an up-to-date
//! [`executor::host::HostVmPrototype`] ready to be called by other services.
//!
//! # Usage
//!
//! The runtime service lets user subscribe to block updates, similar to the [`sync_service`].
//! These subscriptions are implemented by subscribing to the underlying [`sync_service`] and,
//! for each notification, checking whether the runtime has changed (thanks to the presence or
//! absence of a header digest item), and downloading the runtime code if necessary. Therefore,
//! these notifications might come with a delay compared to directly using the [`sync_service`].
//!
//! If it isn't possible to download the runtime code of a block (for example because peers refuse
//! to answer or have already pruned the block) or if the runtime service already has too many
//! pending downloads, this block is simply not reported on the subscriptions. The download will
//! be repeatedly tried until it succeeds.
//!
//! Consequently, you are strongly encouraged to not use both the [`sync_service`] *and* the
//! [`RuntimeService`] of the same chain. They each provide a consistent view of the chain, but
//! this view isn't necessarily the same on both services.
//!
//! The main service offered by the runtime service is [`RuntimeService::subscribe_all`], that
//! notifies about new blocks once their runtime is known.
//!
//! # Blocks pinning
//!
//! Blocks that are reported through [`RuntimeService::subscribe_all`] are automatically *pinned*.
//! If multiple subscriptions exist, each block is pinned once per subscription.
//!
//! As long as a block is pinned, the [`RuntimeService`] is guaranteed to keep in its internal
//! state the runtime of this block and its properties.
//!
//! Blocks must be manually unpinned by calling [`Subscription::unpin_block`].
//! Failing to do so is effectively a memory leak. If the number of pinned blocks becomes too
//! large, the subscription is force-killed by the [`RuntimeService`].
//!

use crate::{platform::PlatformRef, sync_service};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString as _},
    sync::{Arc, Weak},
    vec::Vec,
};
use async_lock::{Mutex, MutexGuard};
use core::{
    iter, mem,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    time::Duration,
};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{future, stream, Stream, StreamExt as _};
use itertools::Itertools as _;
use smoldot::{
    chain::async_tree,
    executor, header,
    informant::{BytesDisplay, HashDisplay},
    network::codec,
    trie::{self, proof_decode, Nibble, TrieEntryVersion},
};

/// Configuration for a runtime service.
pub struct Config<TPlat: PlatformRef> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Service responsible for synchronizing the chain.
    pub sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Header of the genesis block of the chain, in SCALE encoding.
    pub genesis_block_scale_encoded_header: Vec<u8>,
}

/// Identifies a runtime currently pinned within a [`RuntimeService`].
#[derive(Clone)]
pub struct PinnedRuntimeId(Arc<Runtime>);

/// See [the module-level documentation](..).
pub struct RuntimeService<TPlat: PlatformRef> {
    /// Configuration of the background task. Used to restart the background task if necessary.
    background_task_config: BackgroundTaskConfig<TPlat>,

    /// Sender to send messages to the background task.
    to_background: Mutex<async_channel::Sender<ToBackground<TPlat>>>,
}

impl<TPlat: PlatformRef> RuntimeService<TPlat> {
    /// Initializes a new runtime service.
    pub fn new(config: Config<TPlat>) -> Self {
        // Target to use for all the logs of this service.
        let log_target = format!("runtime-{}", config.log_name);

        let background_task_config = BackgroundTaskConfig {
            log_target: log_target.clone(),
            platform: config.platform.clone(),
            sync_service: config.sync_service,
            genesis_block_scale_encoded_header: config.genesis_block_scale_encoded_header,
        };

        // Spawns a task that runs in the background and updates the content of the mutex.
        let to_background;
        config.platform.spawn_task(log_target.clone().into(), {
            let (tx, rx) = async_channel::bounded(16);
            let tx_weak = tx.downgrade();
            to_background = tx;
            let background_task_config = background_task_config.clone();
            async move {
                run_background(background_task_config, rx, tx_weak).await;
                log::debug!(target: &log_target, "Shutdown");
            }
        });

        RuntimeService {
            background_task_config,
            to_background: Mutex::new(to_background),
        }
    }

    /// Calls [`sync_service::SyncService::block_number_bytes`] on the sync service associated to
    /// this runtime service.
    pub fn block_number_bytes(&self) -> usize {
        self.background_task_config
            .sync_service
            .block_number_bytes()
    }

    /// Subscribes to the state of the chain: the current state and the new blocks.
    ///
    /// This function only returns once the runtime of the current finalized block is known. This
    /// might take a long time.
    ///
    /// Only up to `buffer_size` block notifications are buffered in the channel. If the channel
    /// is full when a new notification is attempted to be pushed, the channel gets closed.
    ///
    /// A maximum number of finalized or non-canonical (i.e. not part of the finalized chain)
    /// pinned blocks must be passed, indicating the maximum number of blocks that are finalized
    /// or non-canonical that the runtime service will pin at the same time for this subscription.
    /// If this maximum is reached, the channel will get closed. In situations where the subscriber
    /// is guaranteed to always properly unpin blocks, a value of `usize::max_value()` can be
    /// passed in order to ignore this maximum.
    ///
    /// The channel also gets closed if a gap in the finality happens, such as after a Grandpa
    /// warp syncing.
    ///
    /// See [`SubscribeAll`] for information about the return value.
    pub async fn subscribe_all(
        &self,
        buffer_size: usize,
        max_pinned_blocks: NonZeroUsize,
    ) -> SubscribeAll<TPlat> {
        loop {
            let (result_tx, result_rx) = oneshot::channel();
            let _ = self
                .send_message_or_restart_service(ToBackground::SubscribeAll(
                    ToBackgroundSubscribeAll {
                        result_tx,
                        buffer_size,
                        max_pinned_blocks,
                    },
                ))
                .await;

            if let Ok(subscribe_all) = result_rx.await {
                break subscribe_all;
            }
        }
    }

    /// Unpins a block after it has been reported by a subscription.
    ///
    /// Has no effect if the [`SubscriptionId`] is not or no longer valid (as the runtime service
    /// can kill any subscription at any moment).
    ///
    /// # Panic
    ///
    /// Panics if the block hash has not been reported or has already been unpinned.
    ///
    // TODO: add #[track_caller] once possible, see https://github.com/rust-lang/rust/issues/87417
    pub async fn unpin_block(&self, subscription_id: SubscriptionId, block_hash: [u8; 32]) {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::UnpinBlock {
                result_tx,
                subscription_id,
                block_hash,
            })
            .await;
        match result_rx.await {
            Ok(Ok(())) => {
                // Background task has indicated success.
            }
            Err(_) => {
                // Background task has crashed. Subscription is stale. Function has no effect.
            }
            Ok(Err(_)) => {
                // Background task has indicated that the block has already been unpinned.
                panic!()
            }
        }
    }

    /// Returns the storage value and Merkle value of the `:code` key of the finalized block.
    ///
    /// Returns `None` if the runtime of the current finalized block is not known yet.
    // TODO: this function has a bad API but is hopefully temporary
    pub async fn finalized_runtime_storage_merkle_values(
        &self,
    ) -> Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<Nibble>>)> {
        let (result_tx, result_rx) = oneshot::channel();

        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::FinalizedRuntimeStorageMerkleValues { result_tx })
            .await;

        result_rx.await.unwrap_or(None)
    }

    /// Lock the runtime service and prepare a call to a runtime entry point.
    ///
    /// The hash of the block passed as parameter corresponds to the block whose runtime to use
    /// to make the call. The block must be currently pinned in the context of the provided
    /// [`SubscriptionId`].
    ///
    /// Returns an error if the subscription is stale, meaning that it has been reset by the
    /// runtime service.
    ///
    /// # Panic
    ///
    /// Panics if the given block isn't currently pinned by the given subscription.
    ///
    pub async fn pinned_block_runtime_access(
        &self,
        subscription_id: SubscriptionId,
        block_hash: [u8; 32],
    ) -> Result<RuntimeAccess<TPlat>, PinnedBlockRuntimeAccessError> {
        let (result_tx, result_rx) = oneshot::channel();

        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::PinnedBlockRuntimeAccess {
                result_tx,
                subscription_id,
                block_hash,
            })
            .await;

        match result_rx.await {
            Ok(Err(())) => {
                // Background service indicates that the block isn't pinned.
                panic!()
            }
            Ok(Ok(outcome)) => outcome,
            Err(_) => {
                // Background service has crashed. This means that the subscription is obsolete.
                Err(PinnedBlockRuntimeAccessError::ObsoleteSubscription)
            }
        }
    }

    /// Lock the runtime service and prepare a call to a runtime entry point.
    ///
    /// The hash of the block passed as parameter corresponds to the block whose runtime to use
    /// to make the call. The block must be currently pinned in the context of the provided
    /// [`SubscriptionId`].
    ///
    /// # Panic
    ///
    /// Panics if the provided [`PinnedRuntimeId`] is stale or invalid.
    ///
    pub async fn pinned_runtime_access(
        &self,
        pinned_runtime_id: PinnedRuntimeId,
        block_hash: [u8; 32],
        block_number: u64,
        block_state_trie_root_hash: [u8; 32],
    ) -> RuntimeAccess<TPlat> {
        RuntimeAccess {
            sync_service: self.background_task_config.sync_service.clone(),
            hash: block_hash,
            runtime: pinned_runtime_id.0,
            block_number,
            block_state_root_hash: block_state_trie_root_hash,
        }
    }

    /// Tries to find a runtime within the [`RuntimeService`] that has the given storage code and
    /// heap pages. If none is found, compiles the runtime and stores it within the
    /// [`RuntimeService`]. In both cases, it is kept pinned until it is unpinned with
    /// [`RuntimeService::unpin_runtime`].
    pub async fn compile_and_pin_runtime(
        &self,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
        code_merkle_value: Option<Vec<u8>>,
        closest_ancestor_excluding: Option<Vec<Nibble>>,
    ) -> Result<PinnedRuntimeId, CompileAndPinRuntimeError> {
        let (result_tx, result_rx) = oneshot::channel();

        let _ = self
            .send_message_or_restart_service(ToBackground::CompileAndPinRuntime {
                result_tx,
                storage_code,
                storage_heap_pages,
                code_merkle_value,
                closest_ancestor_excluding,
            })
            .await;

        Ok(PinnedRuntimeId(
            result_rx
                .await
                .map_err(|_| CompileAndPinRuntimeError::Crash)?,
        ))
    }

    /// Un-pins a previously-pinned runtime.
    ///
    /// # Panic
    ///
    /// Panics if the provided [`PinnedRuntimeId`] is stale or invalid.
    ///
    pub async fn unpin_runtime(&self, id: PinnedRuntimeId) {
        // Nothing to do.
        // TODO: doesn't check whether id is stale
        drop(id);
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub async fn is_near_head_of_chain_heuristic(&self) -> bool {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background
            .lock()
            .await
            .send(ToBackground::IsNearHeadOfChainHeuristic { result_tx })
            .await;
        result_rx.await.unwrap_or(false)
    }

    /// Sends a message to the background task. Restarts the background task if it has crashed.
    async fn send_message_or_restart_service(&self, message: ToBackground<TPlat>) {
        let mut lock = self.to_background.lock().await;

        if lock.is_closed() {
            let (tx, rx) = async_channel::bounded(16);
            let tx_weak = tx.downgrade();
            *lock = tx;

            self.background_task_config.platform.spawn_task(
                self.background_task_config.log_target.clone().into(),
                {
                    let background_task_config = self.background_task_config.clone();
                    async move {
                        // Sleep for a bit in order to avoid infinite loops of repeated crashes.
                        background_task_config
                            .platform
                            .sleep(Duration::from_secs(2))
                            .await;
                        let log_target = background_task_config.log_target.clone();
                        log::debug!(target: &log_target, "Restart");
                        run_background(background_task_config, rx, tx_weak).await;
                        log::debug!(target: &log_target, "Shutdown");
                    }
                },
            );
        }

        // Note that the background task might have crashed again at this point already, and thus
        // errors are not impossible.
        let _ = lock.send(message).await;
    }
}

/// Return value of [`RuntimeService::subscribe_all`].
pub struct SubscribeAll<TPlat: PlatformRef> {
    /// SCALE-encoded header of the finalized block at the time of the subscription.
    pub finalized_block_scale_encoded_header: Vec<u8>,

    /// If the runtime of the finalized block is known, contains the information about it.
    pub finalized_block_runtime: Result<executor::CoreVersion, RuntimeError>,

    /// List of all known non-finalized blocks at the time of subscription.
    ///
    /// Only one element in this list has [`BlockNotification::is_new_best`] equal to true.
    ///
    /// The blocks are guaranteed to be ordered so that parents are always found before their
    /// children.
    pub non_finalized_blocks_ancestry_order: Vec<BlockNotification>,

    /// Channel onto which new blocks are sent. The channel gets closed if it is full when a new
    /// block needs to be reported.
    pub new_blocks: Subscription<TPlat>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(u64);

pub struct Subscription<TPlat: PlatformRef> {
    subscription_id: u64,
    channel: Pin<Box<async_channel::Receiver<Notification>>>,
    to_background: async_channel::Sender<ToBackground<TPlat>>,
}

impl<TPlat: PlatformRef> Subscription<TPlat> {
    pub async fn next(&mut self) -> Option<Notification> {
        self.channel.next().await
    }

    /// Returns an opaque identifier that can be used to call [`RuntimeService::unpin_block`].
    pub fn id(&self) -> SubscriptionId {
        SubscriptionId(self.subscription_id)
    }

    /// Unpins a block after it has been reported.
    ///
    /// # Panic
    ///
    /// Panics if the block hash has not been reported or has already been unpinned.
    ///
    pub async fn unpin_block(&self, block_hash: [u8; 32]) {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background
            .send(ToBackground::UnpinBlock {
                result_tx,
                subscription_id: SubscriptionId(self.subscription_id),
                block_hash,
            })
            .await;
        result_rx.await.unwrap().unwrap()
    }
}

/// Notification about a new block or a new finalized block.
///
/// See [`RuntimeService::subscribe_all`].
#[derive(Debug, Clone)]
pub enum Notification {
    /// A non-finalized block has been finalized.
    Finalized {
        /// BLAKE2 hash of the header of the block that has been finalized.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        ///
        /// It is also guaranteed that this block is a child of the previously-finalized block. In
        /// other words, if multiple blocks are finalized at the same time, only one
        /// [`Notification::Finalized`] is generated and contains the highest finalized block.
        ///
        /// If it is not possible for the [`RuntimeService`] to avoid a gap in the list of
        /// finalized blocks, then the [`SubscribeAll::new_blocks`] channel is force-closed.
        hash: [u8; 32],

        /// Hash of the header of the best block after the finalization.
        ///
        /// If the newly-finalized block is an ancestor of the current best block, then this field
        /// contains the hash of this current best block. Otherwise, the best block is now
        /// the non-finalized block with the given hash.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        best_block_hash: [u8; 32],

        /// List of BLAKE2 hashes of the headers of the blocks that have been discarded because
        /// they're not descendants of the newly-finalized block.
        ///
        /// This list contains all the siblings of the newly-finalized block and all their
        /// descendants.
        pruned_blocks: Vec<[u8; 32]>,
    },

    /// A new block has been added to the list of unfinalized blocks.
    Block(BlockNotification),

    /// The best block has changed to a different one.
    BestBlockChanged {
        /// Hash of the new best block.
        ///
        /// This can be either the hash of the latest finalized block or the hash of a
        /// non-finalized block.
        hash: [u8; 32],
    },
}

/// Notification about a new block.
///
/// See [`RuntimeService::subscribe_all`].
#[derive(Debug, Clone)]
pub struct BlockNotification {
    /// True if this block is considered as the best block of the chain.
    pub is_new_best: bool,

    /// SCALE-encoded header of the block.
    pub scale_encoded_header: Vec<u8>,

    /// BLAKE2 hash of the header of the parent of this block.
    ///
    ///
    /// A block with this hash is guaranteed to have earlier been reported in a
    /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`] or
    /// in a [`Notification::Block`].
    ///
    /// > **Note**: The header of a block contains the hash of its parent. When it comes to
    /// >           consensus algorithms such as Babe or Aura, the syncing code verifies that this
    /// >           hash, stored in the header, actually corresponds to a valid block. However,
    /// >           when it comes to parachain consensus, no such verification is performed.
    /// >           Contrary to the hash stored in the header, the value of this field is
    /// >           guaranteed to refer to a block that is known by the syncing service. This
    /// >           allows a subscriber of the state of the chain to precisely track the hierarchy
    /// >           of blocks, without risking to run into a problem in case of a block with an
    /// >           invalid header.
    pub parent_hash: [u8; 32],

    /// If the runtime of the block is different from its parent, contains the information about
    /// the new runtime.
    pub new_runtime: Option<Result<executor::CoreVersion, RuntimeError>>,
}

/// See [`RuntimeService::pinned_block_runtime_access`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum PinnedBlockRuntimeAccessError {
    /// Subscription is dead.
    ObsoleteSubscription,
}

/// See [`RuntimeService::pinned_block_runtime_access`].
#[must_use]
pub struct RuntimeAccess<TPlat: PlatformRef> {
    sync_service: Arc<sync_service::SyncService<TPlat>>,

    block_number: u64,
    block_state_root_hash: [u8; 32],
    hash: [u8; 32],
    runtime: Arc<Runtime>,
}

impl<TPlat: PlatformRef> RuntimeAccess<TPlat> {
    /// Returns the hash of the block the call is being made against.
    pub fn block_hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Returns the specification of the given runtime.
    pub fn specification(&self) -> Result<executor::CoreVersion, RuntimeError> {
        match self.runtime.runtime.as_ref() {
            Ok(r) => Ok(r.runtime_spec.clone()),
            Err(err) => Err(err.clone()),
        }
    }

    pub async fn start<'b>(
        &'b self,
        method: &'b str,
        parameter_vectored: impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZeroU32,
    ) -> Result<(RuntimeCall<'b>, executor::host::HostVmPrototype), RuntimeCallError> {
        // TODO: DRY :-/ this whole thing is messy

        // Perform the call proof request.
        // Note that `Background` is not locked.
        // TODO: there's no way to verify that the call proof is actually correct; we have to ban the peer and restart the whole call process if it turns out that it's not
        // TODO: also, an empty proof will be reported as an error right now, which is weird
        let call_proof = self
            .sync_service
            .clone()
            .call_proof_query(
                self.block_number,
                codec::CallProofRequestConfig {
                    block_hash: self.hash,
                    method: method.into(),
                    parameter_vectored: parameter_vectored.clone(),
                },
                total_attempts,
                timeout_per_request,
                max_parallel,
            )
            .await
            .map_err(RuntimeCallError::CallProof);

        let call_proof = call_proof.and_then(|call_proof| {
            proof_decode::decode_and_verify_proof(proof_decode::Config {
                proof: call_proof.decode().to_owned(), // TODO: to_owned() inefficiency, need some help from the networking to obtain the owned data
            })
            .map_err(RuntimeCallError::StorageRetrieval)
        });

        let (guarded, virtual_machine) = match self.runtime.runtime.as_ref() {
            Ok(r) => {
                let mut lock = r.virtual_machine.lock().await;
                let vm = lock.take().unwrap();
                (lock, vm)
            }
            Err(err) => {
                return Err(RuntimeCallError::InvalidRuntime(err.clone()));
            }
        };

        let lock = RuntimeCall {
            guarded,
            block_state_root_hash: self.block_state_root_hash,
            call_proof,
        };

        Ok((lock, virtual_machine))
    }
}

/// See [`RuntimeService::pinned_block_runtime_access`].
#[must_use]
pub struct RuntimeCall<'a> {
    guarded: MutexGuard<'a, Option<executor::host::HostVmPrototype>>,
    block_state_root_hash: [u8; 32],
    call_proof: Result<trie::proof_decode::DecodedTrieProof<Vec<u8>>, RuntimeCallError>,
}

impl<'a> RuntimeCall<'a> {
    /// Finds the given key in the call proof and returns the associated storage value.
    ///
    /// If `child_trie` is `Some`, look for the key in the given child trie. If it is `None`, look
    /// for the key in the main trie.
    ///
    /// Returns an error if the key couldn't be found in the proof, meaning that the proof is
    /// invalid.
    // TODO: if proof is invalid, we should give the option to fetch another call proof
    pub fn storage_entry(
        &self,
        child_trie: Option<&[u8]>,
        requested_key: &[u8],
    ) -> Result<Option<(&[u8], TrieEntryVersion)>, RuntimeCallError> {
        let call_proof = match &self.call_proof {
            Ok(p) => p,
            Err(err) => return Err(err.clone()),
        };

        let trie_root = match child_trie {
            Some(child_trie) => {
                match Self::child_trie_root(call_proof, &self.block_state_root_hash, child_trie)? {
                    Some(h) => h,
                    None => return Ok(None),
                }
            }
            None => self.block_state_root_hash,
        };

        match call_proof.storage_value(&trie_root, requested_key) {
            Ok(v) => Ok(v),
            Err(err) => Err(RuntimeCallError::MissingProofEntry(err)),
        }
    }

    /// Find in the proof the trie node that follows `key_before` in lexicographic order.
    ///
    /// If `child_trie` is `Some`, look for the key in the given child trie. If it is `None`, look
    /// for the key in the main trie.
    ///
    /// If `or_equal` is `true`, then `key_before` is returned if it is equal to a node in the
    /// trie. If `false`, then only keys that are strictly superior are returned.
    ///
    /// The returned value must always start with `prefix`. Note that the value of `prefix` is
    /// important as it can be the difference between `None` and `Some(None)`.
    ///
    /// If `branch_nodes` is `false`, then trie nodes that don't have a storage value are skipped.
    ///
    /// Returns an error if the proof doesn't contain enough information, meaning that the proof is
    /// invalid.
    pub fn next_key(
        &'_ self,
        child_trie: Option<&[u8]>,
        key_before: &[trie::Nibble],
        or_equal: bool,
        prefix: &[trie::Nibble],
        branch_nodes: bool,
    ) -> Result<Option<&'_ [trie::Nibble]>, RuntimeCallError> {
        let call_proof = match &self.call_proof {
            Ok(p) => p,
            Err(err) => return Err(err.clone()),
        };

        let trie_root = match child_trie {
            Some(child_trie) => {
                match Self::child_trie_root(call_proof, &self.block_state_root_hash, child_trie)? {
                    Some(h) => h,
                    None => return Ok(None),
                }
            }
            None => self.block_state_root_hash,
        };

        match call_proof.next_key(&trie_root, key_before, or_equal, prefix, branch_nodes) {
            Ok(v) => Ok(v),
            Err(err) => Err(RuntimeCallError::MissingProofEntry(err)),
        }
    }

    /// Find in the proof the closest trie node that descends from `key` and returns its Merkle
    /// value.
    ///
    /// If `child_trie` is `Some`, look for the key in the given child trie. If it is `None`, look
    /// for the key in the main trie.
    ///
    /// Returns an error if the proof doesn't contain enough information, meaning that the proof is
    /// invalid.
    ///
    /// Returns `Ok(None)` if the child trie is known to not exist or if it is known that there is
    /// no descendant.
    pub fn closest_descendant_merkle_value(
        &'_ self,
        child_trie: Option<&[u8]>,
        key: &[trie::Nibble],
    ) -> Result<Option<&'_ [u8]>, RuntimeCallError> {
        let call_proof = match &self.call_proof {
            Ok(p) => p,
            Err(err) => return Err(err.clone()),
        };

        let trie_root = match child_trie {
            Some(child_trie) => {
                match Self::child_trie_root(call_proof, &self.block_state_root_hash, child_trie)? {
                    Some(h) => h,
                    None => return Ok(None),
                }
            }
            None => self.block_state_root_hash,
        };

        call_proof
            .closest_descendant_merkle_value(&trie_root, key)
            .map_err(RuntimeCallError::MissingProofEntry)
    }

    /// End the runtime call.
    ///
    /// This method **must** be called.
    pub fn unlock(mut self, vm: executor::host::HostVmPrototype) {
        debug_assert!(self.guarded.is_none());
        *self.guarded = Some(vm);
    }

    fn child_trie_root(
        proof: &proof_decode::DecodedTrieProof<Vec<u8>>,
        main_trie_root: &[u8; 32],
        child_trie: &[u8],
    ) -> Result<Option<[u8; 32]>, RuntimeCallError> {
        // TODO: allocation here, but probably not problematic
        const PREFIX: &[u8] = b":child_storage:default:";
        let mut key = Vec::with_capacity(PREFIX.len() + child_trie.as_ref().len());
        key.extend_from_slice(PREFIX);
        key.extend_from_slice(child_trie.as_ref());

        match proof.storage_value(main_trie_root, &key) {
            Err(err) => Err(RuntimeCallError::MissingProofEntry(err)),
            Ok(None) => Ok(None),
            Ok(Some((value, _))) => match <[u8; 32]>::try_from(value) {
                Ok(hash) => Ok(Some(hash)),
                Err(_) => Err(RuntimeCallError::InvalidChildTrieRoot),
            },
        }
    }
}

impl<'a> Drop for RuntimeCall<'a> {
    fn drop(&mut self) {
        if self.guarded.is_none() {
            // The [`RuntimeCall`] has been destroyed without being properly unlocked.
            panic!()
        }
    }
}

/// Error that can happen when calling a runtime function.
// TODO: clean up these errors
#[derive(Debug, Clone, derive_more::Display)]
pub enum RuntimeCallError {
    /// Runtime of the block isn't valid.
    #[display(fmt = "Runtime of the block isn't valid: {_0}")]
    InvalidRuntime(RuntimeError),
    /// Error while retrieving the storage item from other nodes.
    // TODO: change error type?
    #[display(fmt = "Error in call proof: {_0}")]
    StorageRetrieval(proof_decode::Error),
    /// One or more entries are missing from the call proof.
    #[display(fmt = "One or more entries are missing from the call proof")]
    MissingProofEntry(proof_decode::IncompleteProofError),
    /// Call proof contains a reference to a child trie whose hash isn't 32 bytes.
    InvalidChildTrieRoot,
    /// Error while retrieving the call proof from the network.
    #[display(fmt = "Error when retrieving the call proof: {_0}")]
    CallProof(sync_service::CallProofQueryError),
    /// Error while querying the storage of the block.
    #[display(fmt = "Error while querying block storage: {_0}")]
    StorageQuery(sync_service::StorageQueryError),
}

impl RuntimeCallError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            RuntimeCallError::InvalidRuntime(_) => false,
            RuntimeCallError::StorageRetrieval(_) => false,
            RuntimeCallError::MissingProofEntry(_) => false,
            RuntimeCallError::InvalidChildTrieRoot => false,
            RuntimeCallError::CallProof(err) => err.is_network_problem(),
            RuntimeCallError::StorageQuery(err) => err.is_network_problem(),
        }
    }
}

/// Error when analyzing the runtime.
#[derive(Debug, derive_more::Display, Clone)]
pub enum RuntimeError {
    /// The `:code` key of the storage is empty.
    CodeNotFound,
    /// Error while parsing the `:heappages` storage value.
    #[display(fmt = "Failed to parse `:heappages` storage value: {_0}")]
    InvalidHeapPages(executor::InvalidHeapPagesError),
    /// Error while compiling the runtime.
    #[display(fmt = "{_0}")]
    Build(executor::host::NewErr),
}

/// Error potentially returned by [`RuntimeService::compile_and_pin_runtime`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum CompileAndPinRuntimeError {
    /// Background service has crashed while compiling this runtime. The crash might however not
    /// necessarily be caused by the runtime compilation.
    Crash,
}

/// Message towards the background task.
enum ToBackground<TPlat: PlatformRef> {
    SubscribeAll(ToBackgroundSubscribeAll<TPlat>),
    CompileAndPinRuntime {
        result_tx: oneshot::Sender<Arc<Runtime>>,
        storage_code: Option<Vec<u8>>,
        storage_heap_pages: Option<Vec<u8>>,
        code_merkle_value: Option<Vec<u8>>,
        closest_ancestor_excluding: Option<Vec<Nibble>>,
    },
    FinalizedRuntimeStorageMerkleValues {
        // TODO: overcomplicated
        result_tx: oneshot::Sender<Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<Nibble>>)>>,
    },
    IsNearHeadOfChainHeuristic {
        result_tx: oneshot::Sender<bool>,
    },
    UnpinBlock {
        result_tx: oneshot::Sender<Result<(), ()>>,
        subscription_id: SubscriptionId,
        block_hash: [u8; 32],
    },
    PinnedBlockRuntimeAccess {
        result_tx: oneshot::Sender<
            Result<Result<RuntimeAccess<TPlat>, PinnedBlockRuntimeAccessError>, ()>,
        >,
        subscription_id: SubscriptionId,
        block_hash: [u8; 32],
    },
}

struct ToBackgroundSubscribeAll<TPlat: PlatformRef> {
    result_tx: oneshot::Sender<SubscribeAll<TPlat>>,
    buffer_size: usize,
    max_pinned_blocks: NonZeroUsize,
}

#[derive(Clone)]
struct PinnedBlock {
    /// Reference-counted runtime of the pinned block.
    runtime: Arc<Runtime>,

    /// Hash of the trie root of the pinned block.
    state_trie_root_hash: [u8; 32],

    /// Height of the pinned block.
    block_number: u64,

    /// `true` if the block is non-finalized and part of the canonical chain.
    /// If `true`, then the block doesn't count towards the maximum number of pinned blocks of
    /// the subscription.
    block_ignores_limit: bool,
}

#[derive(Clone)]
struct Block {
    /// Hash of the block in question. Redundant with `header`, but the hash is so often needed
    /// that it makes sense to cache it.
    hash: [u8; 32],

    /// Header of the block in question.
    /// Guaranteed to always be valid for the output best and finalized blocks. Otherwise,
    /// not guaranteed to be valid.
    scale_encoded_header: Vec<u8>,
}

#[derive(Clone)]
struct BackgroundTaskConfig<TPlat: PlatformRef> {
    log_target: String,
    platform: TPlat,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    genesis_block_scale_encoded_header: Vec<u8>,
}

async fn run_background<TPlat: PlatformRef>(
    config: BackgroundTaskConfig<TPlat>,
    to_background: async_channel::Receiver<ToBackground<TPlat>>,
    to_background_tx: async_channel::WeakSender<ToBackground<TPlat>>,
) {
    // State machine containing all the state that will be manipulated below.
    let mut background = {
        let tree = {
            let mut tree = async_tree::AsyncTree::new(async_tree::Config {
                finalized_async_user_data: None,
                retry_after_failed: Duration::from_secs(10),
                blocks_capacity: 32,
            });
            let node_index = tree.input_insert_block(
                Block {
                    hash: header::hash_from_scale_encoded_header(
                        &config.genesis_block_scale_encoded_header,
                    ),
                    scale_encoded_header: config.genesis_block_scale_encoded_header,
                },
                None,
                false,
                true,
            );
            tree.input_finalize(node_index, node_index);

            Tree::FinalizedBlockRuntimeUnknown { tree }
        };

        Background {
            log_target: config.log_target.clone(),
            platform: config.platform.clone(),
            sync_service: config.sync_service.clone(),
            to_background: Box::pin(to_background.clone()),
            to_background_tx: to_background_tx.clone(),
            next_subscription_id: 0,
            best_near_head_of_chain: config.sync_service.is_near_head_of_chain_heuristic().await,
            tree,
            must_update_tree_and_notify_subscribers: true,
            runtimes: slab::Slab::with_capacity(2),
            pending_subscriptions: Vec::with_capacity(8),
            blocks_stream: None,
            // Initialized to `ready` so that the downloads immediately start.
            wake_up_new_necessary_download: Box::pin(future::ready(())),
            runtime_downloads: stream::FuturesUnordered::new(),
        }
    };

    // Inner loop. Process incoming events.
    loop {
        enum WakeUpReason<TPlat: PlatformRef> {
            MustSubscribe,
            NewNecessaryDownload,
            MustAdvanceTree,
            StartPendingSubscribeAll,
            Notification(Option<sync_service::Notification>),
            ToBackground(ToBackground<TPlat>),
            ForegroundClosed,
            RuntimeDownloadFinished(
                async_tree::AsyncOpId,
                Result<
                    (
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<Nibble>>,
                    ),
                    RuntimeDownloadError,
                >,
            ),
        }

        // Wait for something to happen or for some processing to be necessary.
        let wake_up_reason: WakeUpReason<_> = {
            async {
                if !background.pending_subscriptions.is_empty()
                    && matches!(background.tree, Tree::FinalizedBlockRuntimeKnown { .. })
                {
                    WakeUpReason::StartPendingSubscribeAll
                } else {
                    future::pending().await
                }
            }
            .or(async {
                if let Some(blocks_stream) = background.blocks_stream.as_mut() {
                    WakeUpReason::Notification(blocks_stream.next().await)
                } else {
                    WakeUpReason::MustSubscribe
                }
            })
            .or(async {
                background
                    .to_background
                    .next()
                    .await
                    .map_or(WakeUpReason::ForegroundClosed, WakeUpReason::ToBackground)
            })
            .or(async {
                if !background.runtime_downloads.is_empty() {
                    let (async_op_id, download_result) =
                        background.runtime_downloads.select_next_some().await;
                    WakeUpReason::RuntimeDownloadFinished(async_op_id, download_result)
                } else {
                    future::pending().await
                }
            })
            .or(async {
                (&mut background.wake_up_new_necessary_download).await;
                background.wake_up_new_necessary_download = Box::pin(future::pending());
                WakeUpReason::NewNecessaryDownload
            })
            .or(async {
                if background.must_update_tree_and_notify_subscribers {
                    background.must_update_tree_and_notify_subscribers = false;
                    WakeUpReason::MustAdvanceTree
                } else {
                    future::pending().await
                }
            })
            .await
        };

        match wake_up_reason {
            WakeUpReason::NewNecessaryDownload => {
                // There might be a new runtime download to start.

                // Don't download more than 2 runtimes at a time.
                if background.runtime_downloads.len() >= 2 {
                    continue;
                }

                // Grab what to download. If there's nothing more to download, continue looping.
                let download_params = {
                    let async_op = match &mut background.tree {
                        Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                            tree.next_necessary_async_op(&background.platform.now())
                        }
                        Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                            tree.next_necessary_async_op(&background.platform.now())
                        }
                    };

                    match async_op {
                        async_tree::NextNecessaryAsyncOp::Ready(dl) => dl,
                        async_tree::NextNecessaryAsyncOp::NotReady { when } => {
                            if let Some(when) = when {
                                background.wake_up_new_necessary_download =
                                    Box::pin(background.platform.sleep_until(when)) as Pin<Box<_>>;
                            }
                            continue;
                        }
                    }
                };

                log::debug!(
                    target: &background.log_target,
                    "Worker => NewDownload(block={})",
                    HashDisplay(&download_params.block_user_data.hash)
                );

                // Dispatches a runtime download task to `runtime_downloads`.
                background.runtime_downloads.push({
                    let download_id = download_params.id;

                    // In order to perform the download, we need to known the state root hash of the
                    // block in question, which requires decoding the block. If the decoding fails,
                    // we report that the asynchronous operation has failed with the hope that this
                    // block gets pruned in the future.
                    match header::decode(
                        &download_params.block_user_data.scale_encoded_header,
                        background.sync_service.block_number_bytes(),
                    ) {
                        Ok(decoded_header) => {
                            let sync_service = background.sync_service.clone();
                            let block_hash = download_params.block_user_data.hash;
                            let state_root = *decoded_header.state_root;
                            let block_number = decoded_header.number;

                            Box::pin(async move {
                                let result = sync_service
                                    .storage_query(
                                        block_number,
                                        &block_hash,
                                        &state_root,
                                        [
                                            sync_service::StorageRequestItem {
                                                key: b":code".to_vec(),
                                                ty: sync_service::StorageRequestItemTy::ClosestDescendantMerkleValue,
                                            },
                                            sync_service::StorageRequestItem {
                                                key: b":code".to_vec(),
                                                ty: sync_service::StorageRequestItemTy::Value,
                                            },
                                            sync_service::StorageRequestItem {
                                                key: b":heappages".to_vec(),
                                                ty: sync_service::StorageRequestItemTy::Value,
                                            },
                                        ]
                                        .into_iter(),
                                        3,
                                        Duration::from_secs(20),
                                        NonZeroU32::new(3).unwrap(),
                                    )
                                    .await;

                                let result = match result {
                                    Ok(entries) => {
                                        let heap_pages = entries
                                            .iter()
                                            .find_map(|entry| match entry {
                                                sync_service::StorageResultItem::Value {
                                                    key,
                                                    value,
                                                } if key == b":heappages" => {
                                                    Some(value.clone()) // TODO: overhead
                                                }
                                                _ => None,
                                            })
                                            .unwrap();
                                        let code = entries
                                            .iter()
                                            .find_map(|entry| match entry {
                                                sync_service::StorageResultItem::Value {
                                                    key,
                                                    value,
                                                } if key == b":code" => {
                                                    Some(value.clone()) // TODO: overhead
                                                }
                                                _ => None,
                                            })
                                            .unwrap();
                                        let (code_merkle_value, code_closest_ancestor) = if code.is_some() {
                                            entries
                                                .iter()
                                                .find_map(|entry| match entry {
                                                    sync_service::StorageResultItem::ClosestDescendantMerkleValue {
                                                        requested_key,
                                                        found_closest_ancestor_excluding,
                                                        closest_descendant_merkle_value,
                                                    } if requested_key == b":code" => {
                                                        Some((closest_descendant_merkle_value.clone(), found_closest_ancestor_excluding.clone())) // TODO overhead
                                                    }
                                                    _ => None
                                                })
                                                .unwrap()
                                        } else {
                                            (None, None)
                                        };
                                        Ok((code, heap_pages, code_merkle_value, code_closest_ancestor))
                                    }
                                    Err(error) => Err(RuntimeDownloadError::StorageQuery(error)),
                                };

                                (download_id, result)
                            })
                        }
                        Err(error) => {
                            log::warn!(
                                target: &background.log_target,
                                "Failed to decode header from sync service: {}", error
                            );

                            Box::pin(async move {
                                (download_id, Err(RuntimeDownloadError::InvalidHeader(error)))
                            })
                        }
                    }
                });

                // There might be other downloads to start.
                background.wake_up_new_necessary_download = Box::pin(future::ready(()));
            }

            WakeUpReason::MustAdvanceTree => {
                // The tree of blocks might need to be advanced.
                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown {
                        tree,
                        finalized_block,
                        all_blocks_subscriptions,
                        pinned_blocks,
                    } => match tree.try_advance_output() {
                        None => continue,
                        Some(async_tree::OutputUpdate::Finalized {
                            user_data: new_finalized,
                            best_block_index,
                            pruned_blocks,
                            former_finalized_async_op_user_data: former_finalized_runtime,
                            ..
                        }) => {
                            *finalized_block = new_finalized;
                            let best_block_hash = best_block_index
                                .map_or(finalized_block.hash, |idx| tree.block_user_data(idx).hash);

                            log::debug!(
                                target: &background.log_target,
                                "Worker => OutputFinalized(hash={}, best={})",
                                HashDisplay(&finalized_block.hash), HashDisplay(&best_block_hash)
                            );

                            // The finalization might cause some runtimes in the list of runtimes
                            // to have become unused. Clean them up.
                            drop(former_finalized_runtime);
                            background
                                .runtimes
                                .retain(|_, runtime| runtime.strong_count() > 0);

                            let all_blocks_notif = Notification::Finalized {
                                best_block_hash,
                                hash: finalized_block.hash,
                                pruned_blocks: pruned_blocks
                                    .iter()
                                    .map(|(_, b, _)| b.hash)
                                    .collect(),
                            };

                            let mut to_remove = Vec::new();
                            for (subscription_id, (sender, finalized_pinned_remaining)) in
                                all_blocks_subscriptions.iter_mut()
                            {
                                let count_limit = pruned_blocks.len() + 1;

                                if *finalized_pinned_remaining < count_limit {
                                    to_remove.push(*subscription_id);
                                    continue;
                                }

                                if sender.try_send(all_blocks_notif.clone()).is_err() {
                                    to_remove.push(*subscription_id);
                                    continue;
                                }

                                *finalized_pinned_remaining -= count_limit;

                                // Mark the finalized and pruned blocks as finalized or non-canonical.
                                for block in iter::once(&finalized_block.hash)
                                    .chain(pruned_blocks.iter().map(|(_, b, _)| &b.hash))
                                {
                                    if let Some(pin) =
                                        pinned_blocks.get_mut(&(*subscription_id, *block))
                                    {
                                        debug_assert!(pin.block_ignores_limit);
                                        pin.block_ignores_limit = false;
                                    }
                                }
                            }
                            for to_remove in to_remove {
                                all_blocks_subscriptions.remove(&to_remove);
                                let pinned_blocks_to_remove = pinned_blocks
                                    .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                                    .map(|((_, h), _)| *h)
                                    .collect::<Vec<_>>();
                                for block in pinned_blocks_to_remove {
                                    pinned_blocks.remove(&(to_remove, block));
                                }
                            }

                            // There might be other updates.
                            background.must_update_tree_and_notify_subscribers = true;
                        }
                        Some(async_tree::OutputUpdate::Block(block)) => {
                            let block_index = block.index;
                            let block_runtime = block.async_op_user_data.clone();
                            let block_hash = block.user_data.hash;
                            let scale_encoded_header = block.user_data.scale_encoded_header.clone();
                            let is_new_best = block.is_new_best;

                            let (block_number, state_trie_root_hash) = {
                                let decoded = header::decode(
                                    &scale_encoded_header,
                                    background.sync_service.block_number_bytes(),
                                )
                                .unwrap();
                                (decoded.number, *decoded.state_root)
                            };

                            let parent_runtime = tree
                                .parent(block_index)
                                .map_or(tree.output_finalized_async_user_data().clone(), |idx| {
                                    tree.block_async_user_data(idx).unwrap().clone()
                                });

                            log::debug!(
                                target: &background.log_target,
                                "Worker => OutputNewBlock(hash={}, is_new_best={})",
                                HashDisplay(&tree.block_user_data(block_index).hash),
                                is_new_best
                            );

                            let notif = Notification::Block(BlockNotification {
                                parent_hash: tree
                                    .parent(block_index)
                                    .map_or(finalized_block.hash, |idx| {
                                        tree.block_user_data(idx).hash
                                    }),
                                is_new_best,
                                scale_encoded_header,
                                new_runtime: if !Arc::ptr_eq(&parent_runtime, &block_runtime) {
                                    Some(
                                        block_runtime
                                            .runtime
                                            .as_ref()
                                            .map(|rt| rt.runtime_spec.clone())
                                            .map_err(|err| err.clone()),
                                    )
                                } else {
                                    None
                                },
                            });

                            let mut to_remove = Vec::new();
                            for (subscription_id, (sender, _)) in
                                all_blocks_subscriptions.iter_mut()
                            {
                                if sender.try_send(notif.clone()).is_ok() {
                                    let _prev_value = pinned_blocks.insert(
                                        (*subscription_id, block_hash),
                                        PinnedBlock {
                                            runtime: block_runtime.clone(),
                                            state_trie_root_hash,
                                            block_number,
                                            block_ignores_limit: true,
                                        },
                                    );
                                    debug_assert!(_prev_value.is_none());
                                } else {
                                    to_remove.push(*subscription_id);
                                }
                            }
                            for to_remove in to_remove {
                                all_blocks_subscriptions.remove(&to_remove);
                                let pinned_blocks_to_remove = pinned_blocks
                                    .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                                    .map(|((_, h), _)| *h)
                                    .collect::<Vec<_>>();
                                for block in pinned_blocks_to_remove {
                                    pinned_blocks.remove(&(to_remove, block));
                                }
                            }

                            // There might be other updates.
                            background.must_update_tree_and_notify_subscribers = true;
                        }
                        Some(async_tree::OutputUpdate::BestBlockChanged { best_block_index }) => {
                            let hash = best_block_index
                                .map_or(&*finalized_block, |idx| tree.block_user_data(idx))
                                .hash;

                            log::debug!(
                                target: &background.log_target,
                                "Worker => OutputBestBlockChanged(hash={})",
                                HashDisplay(&hash),
                            );

                            let notif = Notification::BestBlockChanged { hash };

                            let mut to_remove = Vec::new();
                            for (subscription_id, (sender, _)) in
                                all_blocks_subscriptions.iter_mut()
                            {
                                if sender.try_send(notif.clone()).is_err() {
                                    to_remove.push(*subscription_id);
                                }
                            }
                            for to_remove in to_remove {
                                all_blocks_subscriptions.remove(&to_remove);
                                let pinned_blocks_to_remove = pinned_blocks
                                    .range((to_remove, [0; 32])..=(to_remove, [0xff; 32]))
                                    .map(|((_, h), _)| *h)
                                    .collect::<Vec<_>>();
                                for block in pinned_blocks_to_remove {
                                    pinned_blocks.remove(&(to_remove, block));
                                }
                            }

                            // There might be other updates.
                            background.must_update_tree_and_notify_subscribers = true;
                        }
                    },
                    Tree::FinalizedBlockRuntimeUnknown { tree } => {
                        match tree.try_advance_output() {
                            None => continue,
                            Some(async_tree::OutputUpdate::Block(_))
                            | Some(async_tree::OutputUpdate::BestBlockChanged { .. }) => {
                                // There might be other updates.
                                background.must_update_tree_and_notify_subscribers = true;
                                continue;
                            }
                            Some(async_tree::OutputUpdate::Finalized {
                                user_data: new_finalized,
                                former_finalized_async_op_user_data,
                                best_block_index,
                                ..
                            }) => {
                                // Make sure that this is the first finalized block whose runtime is
                                // known, otherwise there's a pretty big bug somewhere.
                                debug_assert!(former_finalized_async_op_user_data.is_none());

                                let best_block_hash = best_block_index
                                    .map_or(new_finalized.hash, |idx| {
                                        tree.block_user_data(idx).hash
                                    });
                                log::debug!(
                                    target: &background.log_target,
                                    "Worker => RuntimeKnown(finalized_hash={}, best={})",
                                    HashDisplay(&new_finalized.hash), HashDisplay(&best_block_hash)
                                );

                                // Substitute `tree` with a dummy empty tree just in order to extract
                                // the value. The `tree` only contains "async op user datas" equal
                                // to `Some` (they're inserted manually when a download finishes)
                                // except for the finalized block which has now just been extracted.
                                // We can safely unwrap() all these user datas.
                                let new_tree = mem::replace(
                                    tree,
                                    async_tree::AsyncTree::new(async_tree::Config {
                                        finalized_async_user_data: None,
                                        retry_after_failed: Duration::new(0, 0),
                                        blocks_capacity: 0,
                                    }),
                                )
                                .map_async_op_user_data(|runtime_index| runtime_index.unwrap());

                                // Change the state of `Background` to the "finalized runtime known" state.
                                background.tree = Tree::FinalizedBlockRuntimeKnown {
                                    all_blocks_subscriptions:
                                        hashbrown::HashMap::with_capacity_and_hasher(
                                            32,
                                            Default::default(),
                                        ), // TODO: capacity?
                                    pinned_blocks: BTreeMap::new(),
                                    tree: new_tree,
                                    finalized_block: new_finalized,
                                };

                                // There might be other updates.
                                background.must_update_tree_and_notify_subscribers = true;
                            }
                        }
                    }
                }
            }

            WakeUpReason::MustSubscribe => {
                // Subscription to the sync service must be recreated.

                // The buffer size should be large enough so that, if the CPU is busy, it
                // doesn't become full before the execution of the runtime service resumes.
                // Note that this `await` freezes the entire runtime service background task,
                // but the sync service guarantees that `subscribe_all` returns very quickly.
                let subscription = background.sync_service.subscribe_all(32, true).await;

                log::debug!(
                    target: &background.log_target,
                    "Worker <= Reset(finalized_block: {})",
                    HashDisplay(&header::hash_from_scale_encoded_header(
                        &subscription.finalized_block_scale_encoded_header
                    ))
                );

                // Update the state of `Background` with what we just grabbed.
                //
                // Note that the content of `Background` is reset unconditionally.
                // It might seem like a good idea to only reset the content of `Background` if the new
                // subscription has a different finalized block than currently. However, there is
                // absolutely no guarantee for the non-finalized blocks currently in the tree to be a
                // subset or superset of the non-finalized blocks in the new subscription.
                // Using the new subscription but keeping the existing tree could therefore result in
                // state inconsistencies.
                //
                // Additionally, the situation where a subscription is killed but the finalized block
                // didn't change should be extremely rare anyway.
                {
                    // TODO: restore
                    /*guarded.best_near_head_of_chain =
                    is_near_head_of_chain_heuristic(&sync_service, &guarded).await;*/

                    background.runtimes = slab::Slab::with_capacity(2); // TODO: hardcoded capacity

                    // TODO: DRY below
                    if let Some(finalized_block_runtime) = subscription.finalized_block_runtime {
                        let finalized_block_hash = header::hash_from_scale_encoded_header(
                            &subscription.finalized_block_scale_encoded_header,
                        );

                        let storage_code_len = u64::try_from(
                            finalized_block_runtime
                                .storage_code
                                .as_ref()
                                .map_or(0, |v| v.len()),
                        )
                        .unwrap();

                        let runtime = Arc::new(Runtime {
                            runtime_code: finalized_block_runtime.storage_code,
                            heap_pages: finalized_block_runtime.storage_heap_pages,
                            code_merkle_value: finalized_block_runtime.code_merkle_value,
                            closest_ancestor_excluding: finalized_block_runtime
                                .closest_ancestor_excluding,
                            runtime: Ok(SuccessfulRuntime {
                                runtime_spec: finalized_block_runtime
                                    .virtual_machine
                                    .runtime_version()
                                    .clone(),
                                virtual_machine: Mutex::new(Some(
                                    finalized_block_runtime.virtual_machine,
                                )),
                            }),
                        });

                        match &runtime.runtime {
                            Ok(runtime) => {
                                log::info!(
                                    target: &background.log_target,
                                    "Finalized block runtime ready. Spec version: {}. Size of `:code`: {}.",
                                    runtime.runtime_spec.decode().spec_version,
                                    BytesDisplay(storage_code_len)
                                );
                            }
                            Err(error) => {
                                log::warn!(
                                    target: &background.log_target,
                                    "Erroenous finalized block runtime. Size of `:code`: {}.\nError: {}\n\
                                    This indicates an incompatibility between smoldot and the chain.",
                                    BytesDisplay(storage_code_len),
                                    error
                                );
                            }
                        }

                        log::debug!(
                            target: &background.log_target,
                            "Worker => RuntimeKnown(finalized_hash={})",
                            HashDisplay(&finalized_block_hash)
                        );

                        background.tree = Tree::FinalizedBlockRuntimeKnown {
                            all_blocks_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                                32,
                                Default::default(),
                            ), // TODO: capacity?
                            pinned_blocks: BTreeMap::new(),
                            finalized_block: Block {
                                hash: finalized_block_hash,
                                scale_encoded_header: subscription
                                    .finalized_block_scale_encoded_header,
                            },
                            tree: {
                                let mut tree =
                                    async_tree::AsyncTree::<_, Block, _>::new(async_tree::Config {
                                        finalized_async_user_data: runtime,
                                        retry_after_failed: Duration::from_secs(10), // TODO: hardcoded
                                        blocks_capacity: 32,
                                    });

                                for block in subscription.non_finalized_blocks_ancestry_order {
                                    let parent_index = if block.parent_hash == finalized_block_hash
                                    {
                                        None
                                    } else {
                                        Some(
                                            tree.input_output_iter_unordered()
                                                .find(|b| b.user_data.hash == block.parent_hash)
                                                .unwrap()
                                                .id,
                                        )
                                    };

                                    let same_runtime_as_parent = same_runtime_as_parent(
                                        &block.scale_encoded_header,
                                        background.sync_service.block_number_bytes(),
                                    );
                                    let _ = tree.input_insert_block(
                                        Block {
                                            hash: header::hash_from_scale_encoded_header(
                                                &block.scale_encoded_header,
                                            ),
                                            scale_encoded_header: block.scale_encoded_header,
                                        },
                                        parent_index,
                                        same_runtime_as_parent,
                                        block.is_new_best,
                                    );
                                }

                                tree
                            },
                        };
                    } else {
                        background.tree = Tree::FinalizedBlockRuntimeUnknown {
                            tree: {
                                let mut tree = async_tree::AsyncTree::new(async_tree::Config {
                                    finalized_async_user_data: None,
                                    retry_after_failed: Duration::from_secs(10), // TODO: hardcoded
                                    blocks_capacity: 32,
                                });
                                let node_index = tree.input_insert_block(
                                    Block {
                                        hash: header::hash_from_scale_encoded_header(
                                            &subscription.finalized_block_scale_encoded_header,
                                        ),
                                        scale_encoded_header: subscription
                                            .finalized_block_scale_encoded_header,
                                    },
                                    None,
                                    false,
                                    true,
                                );
                                tree.input_finalize(node_index, node_index);

                                for block in subscription.non_finalized_blocks_ancestry_order {
                                    let parent_index = tree
                                        .input_output_iter_unordered()
                                        .find(|b| b.user_data.hash == block.parent_hash)
                                        .unwrap()
                                        .id;

                                    let same_runtime_as_parent = same_runtime_as_parent(
                                        &block.scale_encoded_header,
                                        background.sync_service.block_number_bytes(),
                                    );
                                    let _ = tree.input_insert_block(
                                        Block {
                                            hash: header::hash_from_scale_encoded_header(
                                                &block.scale_encoded_header,
                                            ),
                                            scale_encoded_header: block.scale_encoded_header,
                                        },
                                        Some(parent_index),
                                        same_runtime_as_parent,
                                        block.is_new_best,
                                    );
                                }

                                tree
                            },
                        };
                    }
                }

                background.blocks_stream = Some(Box::pin(subscription.new_blocks));
                background.wake_up_new_necessary_download = Box::pin(future::ready(()));
                background.runtime_downloads = stream::FuturesUnordered::new();
            }

            WakeUpReason::StartPendingSubscribeAll => {
                // A subscription is waiting to be started.

                // Extract the components of the `FinalizedBlockRuntimeKnown`.
                let (tree, finalized_block, pinned_blocks, all_blocks_subscriptions) =
                    match &mut background.tree {
                        Tree::FinalizedBlockRuntimeKnown {
                            tree,
                            finalized_block,
                            pinned_blocks,
                            all_blocks_subscriptions,
                        } => (
                            tree,
                            finalized_block,
                            pinned_blocks,
                            all_blocks_subscriptions,
                        ),
                        _ => continue,
                    };

                for pending_subscription in background.pending_subscriptions.drain(..) {
                    let (tx, new_blocks_channel) =
                        async_channel::bounded(pending_subscription.buffer_size);
                    let subscription_id = background.next_subscription_id;
                    debug_assert_eq!(
                        pinned_blocks
                            .range((subscription_id, [0; 32])..=(subscription_id, [0xff; 32]))
                            .count(),
                        0
                    );
                    background.next_subscription_id += 1;

                    let decoded_finalized_block = header::decode(
                        &finalized_block.scale_encoded_header,
                        background.sync_service.block_number_bytes(),
                    )
                    .unwrap();

                    let _prev_value = pinned_blocks.insert(
                        (subscription_id, finalized_block.hash),
                        PinnedBlock {
                            runtime: tree.output_finalized_async_user_data().clone(),
                            state_trie_root_hash: *decoded_finalized_block.state_root,
                            block_number: decoded_finalized_block.number,
                            block_ignores_limit: false,
                        },
                    );
                    debug_assert!(_prev_value.is_none());

                    let mut non_finalized_blocks_ancestry_order =
                        Vec::with_capacity(tree.num_input_non_finalized_blocks());
                    for block in tree.input_output_iter_ancestry_order() {
                        let runtime = match block.async_op_user_data {
                            Some(rt) => rt.clone(),
                            None => continue, // Runtime of that block not known yet, so it shouldn't be reported.
                        };

                        let block_hash = block.user_data.hash;
                        let parent_runtime = tree.parent(block.id).map_or(
                            tree.output_finalized_async_user_data().clone(),
                            |parent_idx| tree.block_async_user_data(parent_idx).unwrap().clone(),
                        );

                        let parent_hash = *header::decode(
                            &block.user_data.scale_encoded_header,
                            background.sync_service.block_number_bytes(),
                        )
                        .unwrap()
                        .parent_hash; // TODO: correct? if yes, document
                        debug_assert!(
                            parent_hash == finalized_block.hash
                                || tree
                                    .input_output_iter_ancestry_order()
                                    .any(|b| parent_hash == b.user_data.hash
                                        && b.async_op_user_data.is_some())
                        );

                        let decoded_header = header::decode(
                            &block.user_data.scale_encoded_header,
                            background.sync_service.block_number_bytes(),
                        )
                        .unwrap();

                        let _prev_value = pinned_blocks.insert(
                            (subscription_id, block_hash),
                            PinnedBlock {
                                runtime: runtime.clone(),
                                state_trie_root_hash: *decoded_header.state_root,
                                block_number: decoded_header.number,
                                block_ignores_limit: true,
                            },
                        );
                        debug_assert!(_prev_value.is_none());

                        non_finalized_blocks_ancestry_order.push(BlockNotification {
                            is_new_best: block.is_output_best,
                            parent_hash,
                            scale_encoded_header: block.user_data.scale_encoded_header.clone(),
                            new_runtime: if !Arc::ptr_eq(&runtime, &parent_runtime) {
                                Some(
                                    runtime
                                        .runtime
                                        .as_ref()
                                        .map(|rt| rt.runtime_spec.clone())
                                        .map_err(|err| err.clone()),
                                )
                            } else {
                                None
                            },
                        });
                    }

                    debug_assert!(matches!(
                        non_finalized_blocks_ancestry_order
                            .iter()
                            .filter(|b| b.is_new_best)
                            .count(),
                        0 | 1
                    ));

                    all_blocks_subscriptions.insert(
                        subscription_id,
                        (tx, pending_subscription.max_pinned_blocks.get() - 1),
                    );

                    let _ = pending_subscription.result_tx.send(SubscribeAll {
                        finalized_block_scale_encoded_header: finalized_block
                            .scale_encoded_header
                            .clone(),
                        finalized_block_runtime: tree
                            .output_finalized_async_user_data()
                            .runtime
                            .as_ref()
                            .map(|rt| rt.runtime_spec.clone())
                            .map_err(|err| err.clone()),
                        non_finalized_blocks_ancestry_order,
                        new_blocks: Subscription {
                            subscription_id,
                            channel: Box::pin(new_blocks_channel),
                            to_background: background.to_background_tx.upgrade().unwrap(),
                        },
                    });
                }
            }

            WakeUpReason::Notification(None) => {
                // The sync service has reset the subscription.
                background.blocks_stream = None;
            }

            WakeUpReason::ForegroundClosed => {
                // Frontend and all subscriptions have shut down.
                return;
            }

            WakeUpReason::ToBackground(ToBackground::SubscribeAll(msg)) => {
                // Foreground wants to subscribe.

                // In order to avoid potentially growing `pending_subscriptions` forever, we
                // remove senders that are closed. This is `O(n)`, but we expect this list to
                // be rather small.
                background
                    .pending_subscriptions
                    .retain(|s| !s.result_tx.is_canceled());
                background.pending_subscriptions.push(msg);
            }

            WakeUpReason::ToBackground(ToBackground::CompileAndPinRuntime {
                result_tx,
                storage_code,
                storage_heap_pages,
                code_merkle_value,
                closest_ancestor_excluding,
            }) => {
                // Foreground wants to compile the given runtime.

                // Try to find an existing identical runtime.
                let existing_runtime = background
                    .runtimes
                    .iter()
                    .filter_map(|(_, rt)| rt.upgrade())
                    .find(|rt| {
                        rt.runtime_code == storage_code && rt.heap_pages == storage_heap_pages
                    });

                let runtime = if let Some(existing_runtime) = existing_runtime {
                    existing_runtime
                } else {
                    // No identical runtime was found. Try compiling the new runtime.
                    let runtime =
                        SuccessfulRuntime::from_storage(&storage_code, &storage_heap_pages).await;
                    let runtime = Arc::new(Runtime {
                        heap_pages: storage_heap_pages,
                        runtime_code: storage_code,
                        code_merkle_value,
                        closest_ancestor_excluding,
                        runtime,
                    });
                    background.runtimes.insert(Arc::downgrade(&runtime));
                    runtime
                };

                let _ = result_tx.send(runtime);
            }

            WakeUpReason::ToBackground(ToBackground::FinalizedRuntimeStorageMerkleValues {
                result_tx,
            }) => {
                // Foreground wants the finalized runtime storage Merkle values.
                let _ = result_tx.send(
                    if let Tree::FinalizedBlockRuntimeKnown { tree, .. } = &background.tree {
                        let runtime = &tree.output_finalized_async_user_data();
                        Some((
                            runtime.runtime_code.clone(),
                            runtime.code_merkle_value.clone(),
                            runtime.closest_ancestor_excluding.clone(),
                        ))
                    } else {
                        None
                    },
                );
            }

            WakeUpReason::ToBackground(ToBackground::IsNearHeadOfChainHeuristic { result_tx }) => {
                // Foreground wants to query whether we are at the head of the chain.

                // The runtime service adds a delay between the moment a best block is reported by
                // the sync service and the moment it is reported by the runtime service.
                // Because of this, any "far from head of chain" to "near head of chain" transition
                // must take that delay into account. The other way around ("near" to "far") is
                // unaffected.

                // If the sync service is far from the head, the runtime service is also far.
                if !background
                    .sync_service
                    .is_near_head_of_chain_heuristic()
                    .await
                {
                    let _ = result_tx.send(false);
                    continue;
                }

                // If the sync service is near, report the result of
                // `is_near_head_of_chain_heuristic()` when called at the latest best block that
                // the runtime service reported through its API, to make sure that we don't report
                // "near" while having reported only blocks that were far.
                let _ = result_tx.send(background.best_near_head_of_chain);
            }

            WakeUpReason::ToBackground(ToBackground::UnpinBlock {
                result_tx,
                subscription_id,
                block_hash,
            }) => {
                // Foreground wants a block unpinned.

                if let Tree::FinalizedBlockRuntimeKnown {
                    all_blocks_subscriptions,
                    pinned_blocks,
                    ..
                } = &mut background.tree
                {
                    let block_ignores_limit = match pinned_blocks
                        .remove(&(subscription_id.0, block_hash))
                    {
                        Some(b) => b.block_ignores_limit,
                        None => {
                            // Cold path.Ò
                            if let Some((_, _)) = all_blocks_subscriptions.get(&subscription_id.0) {
                                let _ = result_tx.send(Err(()));
                            } else {
                                let _ = result_tx.send(Ok(()));
                            }
                            continue;
                        }
                    };

                    background.runtimes.retain(|_, rt| rt.strong_count() > 0);

                    if !block_ignores_limit {
                        let (_, finalized_pinned_remaining) = all_blocks_subscriptions
                            .get_mut(&subscription_id.0)
                            .unwrap();
                        *finalized_pinned_remaining += 1;
                    }
                }

                let _ = result_tx.send(Ok(()));
            }

            WakeUpReason::ToBackground(ToBackground::PinnedBlockRuntimeAccess {
                result_tx,
                subscription_id,
                block_hash,
            }) => {
                // Foreground wants to access the runtime of a pinned block.

                let pinned_block = {
                    if let Tree::FinalizedBlockRuntimeKnown {
                        all_blocks_subscriptions,
                        pinned_blocks,
                        ..
                    } = &mut background.tree
                    {
                        match pinned_blocks.get(&(subscription_id.0, block_hash)) {
                            Some(v) => v.clone(),
                            None => {
                                // Cold path.
                                if let Some((_, _)) =
                                    all_blocks_subscriptions.get(&subscription_id.0)
                                {
                                    let _ = result_tx.send(Err(()));
                                } else {
                                    let _ = result_tx.send(Ok(Err(
                                        PinnedBlockRuntimeAccessError::ObsoleteSubscription,
                                    )));
                                }
                                continue;
                            }
                        }
                    } else {
                        let _ = result_tx
                            .send(Ok(Err(PinnedBlockRuntimeAccessError::ObsoleteSubscription)));
                        continue;
                    }
                };

                let _ = result_tx.send(Ok(Ok(RuntimeAccess {
                    sync_service: background.sync_service.clone(),
                    hash: block_hash,
                    runtime: pinned_block.runtime,
                    block_number: pinned_block.block_number,
                    block_state_root_hash: pinned_block.state_trie_root_hash,
                })));
            }

            WakeUpReason::Notification(Some(sync_service::Notification::Block(new_block))) => {
                // Sync service has reported a new block.

                log::debug!(
                    target: &background.log_target,
                    "Worker <= InputNewBlock(hash={}, parent={}, is_new_best={})",
                    HashDisplay(&header::hash_from_scale_encoded_header(&new_block.scale_encoded_header)),
                    HashDisplay(&new_block.parent_hash),
                    new_block.is_new_best
                );

                let near_head_of_chain = background
                    .sync_service
                    .is_near_head_of_chain_heuristic()
                    .await;

                // TODO: note that this code is never reached for parachains
                if new_block.is_new_best {
                    background.best_near_head_of_chain = near_head_of_chain;
                }

                let same_runtime_as_parent = same_runtime_as_parent(
                    &new_block.scale_encoded_header,
                    background.sync_service.block_number_bytes(),
                );

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown {
                        tree,
                        finalized_block,
                        ..
                    } => {
                        let parent_index = if new_block.parent_hash == finalized_block.hash {
                            None
                        } else {
                            Some(
                                tree.input_output_iter_unordered()
                                    .find(|block| block.user_data.hash == new_block.parent_hash)
                                    .unwrap()
                                    .id,
                            )
                        };

                        tree.input_insert_block(
                            Block {
                                hash: header::hash_from_scale_encoded_header(
                                    &new_block.scale_encoded_header,
                                ),
                                scale_encoded_header: new_block.scale_encoded_header,
                            },
                            parent_index,
                            same_runtime_as_parent,
                            new_block.is_new_best,
                        );
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        let parent_index = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == new_block.parent_hash)
                            .unwrap()
                            .id;
                        tree.input_insert_block(
                            Block {
                                hash: header::hash_from_scale_encoded_header(
                                    &new_block.scale_encoded_header,
                                ),
                                scale_encoded_header: new_block.scale_encoded_header,
                            },
                            Some(parent_index),
                            same_runtime_as_parent,
                            new_block.is_new_best,
                        );
                    }
                }

                background.must_update_tree_and_notify_subscribers = true;
                background.wake_up_new_necessary_download = Box::pin(future::ready(()));
            }

            WakeUpReason::Notification(Some(sync_service::Notification::Finalized {
                hash,
                best_block_hash,
            })) => {
                // Sync service has reported a finalized block.

                log::debug!(
                    target: &background.log_target,
                    "Worker <= InputFinalized(hash={}, best={})",
                    HashDisplay(&hash), HashDisplay(&best_block_hash)
                );

                background.wake_up_new_necessary_download = Box::pin(future::ready(()));

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown {
                        tree,
                        finalized_block,
                        ..
                    } => {
                        debug_assert_ne!(finalized_block.hash, hash);
                        let node_to_finalize = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == hash)
                            .unwrap()
                            .id;
                        let new_best_block = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == best_block_hash)
                            .unwrap()
                            .id;
                        tree.input_finalize(node_to_finalize, new_best_block);
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        let node_to_finalize = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == hash)
                            .unwrap()
                            .id;
                        let new_best_block = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == best_block_hash)
                            .unwrap()
                            .id;
                        tree.input_finalize(node_to_finalize, new_best_block);
                    }
                }

                background.must_update_tree_and_notify_subscribers = true;
            }

            WakeUpReason::Notification(Some(sync_service::Notification::BestBlockChanged {
                hash,
            })) => {
                // Sync service has reported a change in the best block.

                log::debug!(
                    target: &background.log_target,
                    "Worker <= BestBlockChanged(hash={})",
                    HashDisplay(&hash)
                );

                let near_head_of_chain = background
                    .sync_service
                    .is_near_head_of_chain_heuristic()
                    .await;

                background.best_near_head_of_chain = near_head_of_chain;

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown {
                        finalized_block,
                        tree,
                        ..
                    } => {
                        let idx = if hash == finalized_block.hash {
                            None
                        } else {
                            Some(
                                tree.input_output_iter_unordered()
                                    .find(|block| block.user_data.hash == hash)
                                    .unwrap()
                                    .id,
                            )
                        };
                        tree.input_set_best_block(idx);
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        let idx = tree
                            .input_output_iter_unordered()
                            .find(|block| block.user_data.hash == hash)
                            .unwrap()
                            .id;
                        tree.input_set_best_block(Some(idx));
                    }
                }
                background.must_update_tree_and_notify_subscribers = true;

                background.wake_up_new_necessary_download = Box::pin(future::ready(()));
            }

            WakeUpReason::RuntimeDownloadFinished(
                async_op_id,
                Ok((
                    storage_code,
                    storage_heap_pages,
                    code_merkle_value,
                    closest_ancestor_excluding,
                )),
            ) => {
                // A runtime has successfully finished downloading.

                // TODO: the line below is a complete hack; the code that updates this value is never reached for parachains, and as such the line below is here to update this field
                background.best_near_head_of_chain = true;

                // Try to find an existing runtime identical to the one that has just been
                // downloaded. This loop is `O(n)`, but given that we expect this list to very
                // small (at most 1 or 2 elements), this is not a problem.
                let existing_runtime = background
                    .runtimes
                    .iter()
                    .filter_map(|(_, rt)| rt.upgrade())
                    .find(|rt| {
                        rt.runtime_code == storage_code && rt.heap_pages == storage_heap_pages
                    });

                // If no identical runtime was found, try compiling the runtime.
                let runtime = if let Some(existing_runtime) = existing_runtime {
                    existing_runtime
                } else {
                    let runtime =
                        SuccessfulRuntime::from_storage(&storage_code, &storage_heap_pages).await;
                    match &runtime {
                        Ok(runtime) => {
                            log::info!(
                                target: &background.log_target,
                                "Successfully compiled runtime. Spec version: {}. Size of `:code`: {}.",
                                runtime.runtime_spec.decode().spec_version,
                                BytesDisplay(u64::try_from(storage_code.as_ref().map_or(0, |v| v.len())).unwrap())
                            );
                        }
                        Err(error) => {
                            log::warn!(
                                target: &background.log_target,
                                "Failed to compile runtime. Size of `:code`: {}.\nError: {}\n\
                                This indicates an incompatibility between smoldot and the chain.",
                                BytesDisplay(u64::try_from(storage_code.as_ref().map_or(0, |v| v.len())).unwrap()),
                                error
                            );
                        }
                    }

                    let runtime = Arc::new(Runtime {
                        heap_pages: storage_heap_pages,
                        runtime_code: storage_code,
                        runtime,
                        code_merkle_value,
                        closest_ancestor_excluding,
                    });

                    background.runtimes.insert(Arc::downgrade(&runtime));
                    runtime
                };

                // Insert the runtime into the tree.
                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                        tree.async_op_finished(async_op_id, runtime);
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        tree.async_op_finished(async_op_id, Some(runtime));
                    }
                }
                background.must_update_tree_and_notify_subscribers = true;

                // Because runtime downloads are clamped to a maximum, when a download is finished
                // we should try to start new downloads.
                background.wake_up_new_necessary_download = Box::pin(future::ready(()));
            }

            WakeUpReason::RuntimeDownloadFinished(async_op_id, Err(error)) => {
                // A runtime download has failed.

                let concerned_blocks = match &background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                        either::Left(tree.async_op_blocks(async_op_id))
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        either::Right(tree.async_op_blocks(async_op_id))
                    }
                }
                .format_with(", ", |block, fmt| fmt(&HashDisplay(&block.hash)))
                .to_string();

                log::debug!(
                    target: &background.log_target,
                    "Worker <= FailedDownload(blocks=[{}], error={:?})",
                    concerned_blocks,
                    error
                );
                if !error.is_network_problem() {
                    log::warn!(
                        target: &background.log_target,
                        "Failed to download :code and :heappages of blocks {}: {}",
                        concerned_blocks,
                        error
                    );
                }

                match &mut background.tree {
                    Tree::FinalizedBlockRuntimeKnown { tree, .. } => {
                        tree.async_op_failure(async_op_id, &background.platform.now());
                    }
                    Tree::FinalizedBlockRuntimeUnknown { tree, .. } => {
                        tree.async_op_failure(async_op_id, &background.platform.now());
                    }
                }

                // Because runtime downloads are clamped to a maximum, when a download is finished
                // we should try to start new downloads.
                background.wake_up_new_necessary_download = Box::pin(future::ready(()));
            }
        }
    }
}

#[derive(Debug, Clone, derive_more::Display)]
enum RuntimeDownloadError {
    #[display(fmt = "{_0}")]
    StorageQuery(sync_service::StorageQueryError),
    #[display(fmt = "Couldn't decode header: {_0}")]
    InvalidHeader(header::Error),
}

impl RuntimeDownloadError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    fn is_network_problem(&self) -> bool {
        match self {
            RuntimeDownloadError::StorageQuery(err) => err.is_network_problem(),
            RuntimeDownloadError::InvalidHeader(_) => false,
        }
    }
}

struct Background<TPlat: PlatformRef> {
    log_target: String,

    /// See [`Config::platform`].
    platform: TPlat,

    sync_service: Arc<sync_service::SyncService<TPlat>>,

    /// Receiver for messages to the background task.
    to_background: Pin<Box<async_channel::Receiver<ToBackground<TPlat>>>>,

    /// Sending side of [`Background::to_background`].
    to_background_tx: async_channel::WeakSender<ToBackground<TPlat>>,

    /// Identifier of the next subscription for
    /// [`Tree::FinalizedBlockRuntimeKnown::all_blocks_subscriptions`].
    ///
    /// To avoid race conditions, subscription IDs are never used, even if we switch back to
    /// [`Tree::FinalizedBlockRuntimeUnknown`].
    next_subscription_id: u64,

    /// Return value of calling [`sync_service::SyncService::is_near_head_of_chain_heuristic`]
    /// after the latest best block update.
    best_near_head_of_chain: bool,

    /// List of runtimes referenced by the tree in [`Tree`] and by
    /// [`Tree::FinalizedBlockRuntimeKnown::pinned_blocks`].
    ///
    /// Might contains obsolete values (i.e. stale `Weak`s) and thus must be cleaned from time to
    /// time.
    ///
    /// Because this list shouldn't contain many entries, it is acceptable to iterate over all
    /// the elements.
    runtimes: slab::Slab<Weak<Runtime>>,

    /// Tree of blocks received from the sync service. Keeps track of which block has been
    /// reported to the outer API.
    tree: Tree<TPlat>,

    /// If `true`, the `AsyncTree`s potentially need being advanced.
    must_update_tree_and_notify_subscribers: bool,

    /// List of subscription attempts started with
    /// [`Tree::FinalizedBlockRuntimeKnown::all_blocks_subscriptions`].
    ///
    /// When in the [`Tree::FinalizedBlockRuntimeKnown`] state, a [`SubscribeAll`] is constructed
    /// and sent back for each of these senders.
    /// When in the [`Tree::FinalizedBlockRuntimeUnknown`] state, the senders patiently wait here.
    pending_subscriptions: Vec<ToBackgroundSubscribeAll<TPlat>>,

    /// Stream of notifications coming from the sync service. `None` if not subscribed yet.
    blocks_stream: Option<Pin<Box<dyn Stream<Item = sync_service::Notification> + Send>>>,

    /// List of runtimes currently being downloaded from the network.
    /// For each item, the download id, storage value of `:code`, storage value of `:heappages`,
    /// and Merkle value and closest ancestor of `:code`.
    runtime_downloads: stream::FuturesUnordered<
        future::BoxFuture<
            'static,
            (
                async_tree::AsyncOpId,
                Result<
                    (
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<Vec<Nibble>>,
                    ),
                    RuntimeDownloadError,
                >,
            ),
        >,
    >,

    /// Future that wakes up when a new download to start is potentially ready.
    wake_up_new_necessary_download: future::BoxFuture<'static, ()>,
}

enum Tree<TPlat: PlatformRef> {
    FinalizedBlockRuntimeKnown {
        /// Tree of blocks. Holds the state of the download of everything. Always `Some` when the
        /// `Mutex` is being locked. Temporarily switched to `None` during some operations.
        ///
        /// The asynchronous operation user data is a `usize` corresponding to the index within
        /// [`Background::runtimes`].
        tree: async_tree::AsyncTree<TPlat::Instant, Block, Arc<Runtime>>,

        /// Finalized block. Outside of the tree.
        finalized_block: Block,

        /// List of senders that get notified when new blocks arrive.
        /// See [`RuntimeService::subscribe_all`]. Alongside with each sender, the number of pinned
        /// finalized or non-canonical blocks remaining for this subscription.
        ///
        /// Keys are assigned from [`Background::next_subscription_id`].
        all_blocks_subscriptions: hashbrown::HashMap<
            u64,
            (async_channel::Sender<Notification>, usize),
            fnv::FnvBuildHasher,
        >,

        /// List of pinned blocks.
        ///
        /// Every time a block is reported to the API user, it is inserted in this map. The block
        /// is inserted after it has been pushed in the channel, but before it is pulled.
        /// Therefore, if the channel is closed it is the background that needs to purge all
        /// blocks from this container that are no longer relevant.
        ///
        /// Keys are `(subscription_id, block_hash)`. Values are indices within
        /// [`Background::runtimes`], state trie root hashes, block numbers, and whether the block
        /// is non-finalized and part of the canonical chain.
        pinned_blocks: BTreeMap<(u64, [u8; 32]), PinnedBlock>,
    },
    FinalizedBlockRuntimeUnknown {
        /// Tree of blocks. Holds the state of the download of everything. Always `Some` when the
        /// `Mutex` is being locked. Temporarily switched to `None` during some operations.
        ///
        /// The finalized block according to the [`async_tree::AsyncTree`] is actually a dummy.
        /// The "real" finalized block is a non-finalized block within this tree.
        ///
        /// The asynchronous operation user data is a `usize` corresponding to the index within
        /// [`Background::runtimes`]. The asynchronous operation user data is `None` for the dummy
        /// finalized block.
        // TODO: explain better
        tree: async_tree::AsyncTree<TPlat::Instant, Block, Option<Arc<Runtime>>>,
    },
}

struct Runtime {
    /// Successfully-compiled runtime and all its information. Can contain an error if an error
    /// happened, including a problem when obtaining the runtime specs.
    runtime: Result<SuccessfulRuntime, RuntimeError>,

    /// Merkle value of the `:code` trie node.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    code_merkle_value: Option<Vec<u8>>,

    /// Closest ancestor of the `:code` key except for `:code` itself.
    closest_ancestor_excluding: Option<Vec<Nibble>>,

    /// Undecoded storage value of `:code` corresponding to the [`Runtime::runtime`]
    /// field.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    // TODO: consider storing hash instead
    runtime_code: Option<Vec<u8>>,

    /// Undecoded storage value of `:heappages` corresponding to the
    /// [`Runtime::runtime`] field.
    ///
    /// Can be `None` if the storage is empty, in which case the runtime will have failed to
    /// build.
    // TODO: consider storing hash instead
    heap_pages: Option<Vec<u8>>,
}

struct SuccessfulRuntime {
    /// Runtime specs extracted from the runtime.
    runtime_spec: executor::CoreVersion,

    /// Virtual machine itself, to perform additional calls.
    ///
    /// Always `Some`, except for temporary extractions necessary to execute the VM.
    virtual_machine: Mutex<Option<executor::host::HostVmPrototype>>,
}

impl SuccessfulRuntime {
    async fn from_storage(
        code: &Option<Vec<u8>>,
        heap_pages: &Option<Vec<u8>>,
    ) -> Result<Self, RuntimeError> {
        // Since compiling the runtime is a CPU-intensive operation, we yield once before.
        futures_lite::future::yield_now().await;

        // Parameters for `HostVmPrototype::new`.
        let module = code.as_ref().ok_or(RuntimeError::CodeNotFound)?;
        let heap_pages = executor::storage_heap_pages_to_value(heap_pages.as_deref())
            .map_err(RuntimeError::InvalidHeapPages)?;
        let exec_hint = executor::vm::ExecHint::CompileAheadOfTime;

        // We try once with `allow_unresolved_imports: false`. If this fails due to unresolved
        // import, we try again but with `allowed_unresolved_imports: true`.
        // Having unresolved imports might cause errors later on, for example when validating
        // transactions or getting the parachain heads, but for now we continue the execution
        // and print a warning.
        match executor::host::HostVmPrototype::new(executor::host::Config {
            module,
            heap_pages,
            exec_hint,
            allow_unresolved_imports: false,
        }) {
            Ok(vm) => {
                return Ok(SuccessfulRuntime {
                    runtime_spec: vm.runtime_version().clone(),
                    virtual_machine: Mutex::new(Some(vm)),
                })
            }
            Err(executor::host::NewErr::VirtualMachine(
                executor::vm::NewErr::UnresolvedFunctionImport {
                    function,
                    module_name,
                },
            )) => {
                match executor::host::HostVmPrototype::new(executor::host::Config {
                    module,
                    heap_pages,
                    exec_hint,
                    allow_unresolved_imports: true,
                }) {
                    Ok(vm) => {
                        log::warn!(
                            "Unresolved host function in runtime: `{}`:`{}`. Smoldot might \
                            encounter errors later on. Please report this issue in \
                            https://github.com/smol-dot/smoldot",
                            module_name,
                            function
                        );

                        Ok(SuccessfulRuntime {
                            runtime_spec: vm.runtime_version().clone(),
                            virtual_machine: Mutex::new(Some(vm)),
                        })
                    }
                    Err(executor::host::NewErr::VirtualMachine(
                        executor::vm::NewErr::UnresolvedFunctionImport { .. },
                    )) => unreachable!(),
                    Err(error) => {
                        // It's still possible that errors other than an unresolved host
                        // function happen.
                        Err(RuntimeError::Build(error))
                    }
                }
            }
            Err(error) => Err(RuntimeError::Build(error)),
        }
    }
}

/// Returns `true` if the block can be assumed to have the same runtime as its parent.
fn same_runtime_as_parent(header: &[u8], block_number_bytes: usize) -> bool {
    match header::decode(header, block_number_bytes) {
        Ok(h) => !h.digest.has_runtime_environment_updated(),
        Err(_) => false,
    }
}
