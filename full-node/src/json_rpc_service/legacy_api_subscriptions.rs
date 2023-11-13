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

use hashbrown::HashMap;
use smol::stream::StreamExt as _;
use smoldot::{
    chain::fork_tree,
    executor::{host::HostVmPrototype, CoreVersion},
    trie,
};
use std::{collections::BTreeSet, iter, mem, num::NonZeroUsize, ops, pin::Pin, sync::Arc};

use crate::{consensus_service, database_thread};

/// Helper that provides the blocks of a `chain_subscribeAllHeads` subscription.
pub struct SubscribeAllHeads {
    consensus_service: Arc<consensus_service::ConsensusService>,

    /// Active subscription to the consensus service blocks. `None` if not subscribed yet or if
    /// the subscription has stopped.
    subscription: Option<SubscribeAllHeadsSubscription>,
}

struct SubscribeAllHeadsSubscription {
    subscription_id: consensus_service::SubscriptionId,
    new_blocks: Pin<Box<async_channel::Receiver<consensus_service::Notification>>>,
    blocks_to_unpin: Vec<[u8; 32]>,
}

impl SubscribeAllHeads {
    /// Builds a new [`SubscribeAllHeads`].
    pub fn new(consensus_service: Arc<consensus_service::ConsensusService>) -> Self {
        SubscribeAllHeads {
            consensus_service,
            subscription: None,
        }
    }

    /// Returns the SCALE-encoded header of the next block to provide as part of the subscription.
    pub async fn next_scale_encoded_header(&mut self) -> Vec<u8> {
        loop {
            let subscription = match &mut self.subscription {
                Some(s) => s,
                None => {
                    let subscribe_all = self
                        .consensus_service
                        .subscribe_all(32, NonZeroUsize::new(usize::max_value()).unwrap())
                        .await;

                    let blocks_to_unpin = iter::once(subscribe_all.finalized_block_hash)
                        .chain(
                            subscribe_all
                                .non_finalized_blocks_ancestry_order
                                .into_iter()
                                .map(|b| b.block_hash),
                        )
                        .collect();

                    self.subscription.insert(SubscribeAllHeadsSubscription {
                        subscription_id: subscribe_all.id,
                        new_blocks: Box::pin(subscribe_all.new_blocks),
                        blocks_to_unpin,
                    })
                }
            };

            while let Some(block_to_unpin) = subscription.blocks_to_unpin.last() {
                self.consensus_service
                    .unpin_block(subscription.subscription_id, *block_to_unpin)
                    .await;
                let _ = subscription.blocks_to_unpin.pop();
            }

            loop {
                match subscription.new_blocks.next().await {
                    None => {
                        self.subscription = None;
                        break;
                    }
                    Some(consensus_service::Notification::Block { block, .. }) => {
                        subscription.blocks_to_unpin.push(block.block_hash);
                        return block.scale_encoded_header;
                    }
                    Some(consensus_service::Notification::Finalized { .. }) => {
                        // Ignore event.
                    }
                }
            }
        }
    }
}

/// Helper that provides the blocks of a `chain_subscribeFinalizedHeads` subscription.
pub struct SubscribeFinalizedHeads {
    consensus_service: Arc<consensus_service::ConsensusService>,

    /// Active subscription to the consensus service blocks. `None` if not subscribed yet or if
    /// the subscription has stopped.
    subscription: Option<SubscribeFinalizedHeadsSubscription>,
}

struct SubscribeFinalizedHeadsSubscription {
    subscription_id: consensus_service::SubscriptionId,
    new_blocks: Pin<Box<async_channel::Receiver<consensus_service::Notification>>>,
    pinned_blocks: HashMap<[u8; 32], Vec<u8>>,
    blocks_to_unpin: Vec<[u8; 32]>,
}

impl SubscribeFinalizedHeads {
    /// Builds a new [`SubscribeFinalizedHeads`].
    pub fn new(consensus_service: Arc<consensus_service::ConsensusService>) -> Self {
        SubscribeFinalizedHeads {
            consensus_service,
            subscription: None,
        }
    }

    /// Returns the SCALE-encoded header of the next block to provide as part of the subscription.
    pub async fn next_scale_encoded_header(&mut self) -> Vec<u8> {
        loop {
            let subscription = match &mut self.subscription {
                Some(s) => s,
                None => {
                    let subscribe_all = self
                        .consensus_service
                        .subscribe_all(32, NonZeroUsize::new(usize::max_value()).unwrap())
                        .await;

                    let mut pinned_blocks = HashMap::with_capacity(
                        subscribe_all.non_finalized_blocks_ancestry_order.len() + 1 + 8,
                    );
                    for block in subscribe_all.non_finalized_blocks_ancestry_order {
                        pinned_blocks.insert(block.block_hash, block.scale_encoded_header);
                    }

                    let mut blocks_to_unpin = Vec::with_capacity(8);
                    blocks_to_unpin.push(subscribe_all.finalized_block_hash);

                    self.subscription = Some(SubscribeFinalizedHeadsSubscription {
                        subscription_id: subscribe_all.id,
                        new_blocks: Box::pin(subscribe_all.new_blocks),
                        pinned_blocks,
                        blocks_to_unpin,
                    });

                    return subscribe_all.finalized_block_scale_encoded_header;
                }
            };

            while let Some(block_to_unpin) = subscription.blocks_to_unpin.last() {
                self.consensus_service
                    .unpin_block(subscription.subscription_id, *block_to_unpin)
                    .await;
                let _ = subscription.blocks_to_unpin.pop();
            }

            loop {
                match subscription.new_blocks.next().await {
                    None => {
                        self.subscription = None;
                        break;
                    }
                    Some(consensus_service::Notification::Block { block, .. }) => {
                        subscription
                            .pinned_blocks
                            .insert(block.block_hash, block.scale_encoded_header);
                    }
                    Some(consensus_service::Notification::Finalized {
                        finalized_blocks_newest_to_oldest,
                        pruned_blocks_hashes,
                        ..
                    }) => {
                        debug_assert!(!finalized_blocks_newest_to_oldest.is_empty());
                        let finalized_block_hash =
                            *finalized_blocks_newest_to_oldest.first().unwrap();
                        subscription.blocks_to_unpin.push(finalized_block_hash);
                        let finalized_block_header = subscription
                            .pinned_blocks
                            .remove(&finalized_block_hash)
                            .unwrap();

                        for block in pruned_blocks_hashes {
                            subscription.blocks_to_unpin.push(block);
                            let _was_in = subscription.pinned_blocks.remove(&block);
                            debug_assert!(_was_in.is_some());
                        }

                        for block in finalized_blocks_newest_to_oldest.into_iter().skip(1) {
                            subscription.blocks_to_unpin.push(block);
                            let _was_in = subscription.pinned_blocks.remove(&block);
                            debug_assert!(_was_in.is_some());
                        }

                        return finalized_block_header;
                    }
                }
            }
        }
    }
}

/// Helper that provides the blocks of a `chain_subscribeNewHeads` subscription.
pub struct SubscribeNewHeads {
    consensus_service: Arc<consensus_service::ConsensusService>,

    /// Active subscription to the consensus service blocks. `None` if not subscribed yet or if
    /// the subscription has stopped.
    subscription: Option<SubscribeNewHeadsSubscription>,
}

struct SubscribeNewHeadsSubscription {
    subscription_id: consensus_service::SubscriptionId,
    new_blocks: Pin<Box<async_channel::Receiver<consensus_service::Notification>>>,
    pinned_blocks: HashMap<[u8; 32], Vec<u8>>,
    blocks_to_unpin: Vec<[u8; 32]>,
    current_best_block_hash: [u8; 32],
}

impl SubscribeNewHeads {
    /// Builds a new [`SubscribeNewHeads`].
    pub fn new(consensus_service: Arc<consensus_service::ConsensusService>) -> Self {
        SubscribeNewHeads {
            consensus_service,
            subscription: None,
        }
    }

    /// Returns the SCALE-encoded header of the next block to provide as part of the subscription.
    pub async fn next_scale_encoded_header(&mut self) -> &Vec<u8> {
        // Note: this function is convoluted with many unwraps due to a difficult fight with the
        // Rust borrow checker.

        loop {
            if self.subscription.is_none() {
                let subscribe_all = self
                    .consensus_service
                    .subscribe_all(32, NonZeroUsize::new(usize::max_value()).unwrap())
                    .await;

                let mut pinned_blocks = HashMap::with_capacity(
                    subscribe_all.non_finalized_blocks_ancestry_order.len() + 1 + 8,
                );

                let mut current_best_block_hash = subscribe_all.finalized_block_hash;

                pinned_blocks.insert(
                    subscribe_all.finalized_block_hash,
                    subscribe_all.finalized_block_scale_encoded_header,
                );

                for block in subscribe_all.non_finalized_blocks_ancestry_order {
                    pinned_blocks.insert(block.block_hash, block.scale_encoded_header);
                    if block.is_new_best {
                        current_best_block_hash = block.block_hash;
                    }
                }

                let subscription = self.subscription.insert(SubscribeNewHeadsSubscription {
                    subscription_id: subscribe_all.id,
                    new_blocks: Box::pin(subscribe_all.new_blocks),
                    pinned_blocks,
                    blocks_to_unpin: Vec::with_capacity(8),
                    current_best_block_hash,
                });

                return subscription
                    .pinned_blocks
                    .get(&subscription.current_best_block_hash)
                    .unwrap();
            }

            {
                let subscription = self.subscription.as_mut().unwrap();
                while let Some(block_to_unpin) = subscription.blocks_to_unpin.last() {
                    self.consensus_service
                        .unpin_block(subscription.subscription_id, *block_to_unpin)
                        .await;
                    let _ = subscription.blocks_to_unpin.pop();
                }
            }

            loop {
                let notification = self.subscription.as_mut().unwrap().new_blocks.next().await;
                let Some(notification) = notification else {
                    self.subscription = None;
                    break;
                };

                match notification {
                    consensus_service::Notification::Block { block, .. } => {
                        let _previous_value = self
                            .subscription
                            .as_mut()
                            .unwrap()
                            .pinned_blocks
                            .insert(block.block_hash, block.scale_encoded_header);
                        debug_assert!(_previous_value.is_none());

                        if block.is_new_best {
                            self.subscription.as_mut().unwrap().current_best_block_hash =
                                block.block_hash;
                            return self
                                .subscription
                                .as_mut()
                                .unwrap()
                                .pinned_blocks
                                .get(&block.block_hash)
                                .unwrap();
                        }
                    }
                    consensus_service::Notification::Finalized {
                        pruned_blocks_hashes,
                        finalized_blocks_newest_to_oldest,
                        best_block_hash,
                    } => {
                        for hash in pruned_blocks_hashes {
                            self.subscription
                                .as_mut()
                                .unwrap()
                                .blocks_to_unpin
                                .push(hash);
                            let _was_in = self
                                .subscription
                                .as_mut()
                                .unwrap()
                                .pinned_blocks
                                .remove(&hash);
                            debug_assert!(_was_in.is_some());
                        }

                        for hash in finalized_blocks_newest_to_oldest.iter().skip(1) {
                            self.subscription
                                .as_mut()
                                .unwrap()
                                .blocks_to_unpin
                                .push(*hash);
                            let _was_in = self
                                .subscription
                                .as_mut()
                                .unwrap()
                                .pinned_blocks
                                .remove(hash);
                            debug_assert!(_was_in.is_some());
                        }

                        if best_block_hash
                            != self.subscription.as_mut().unwrap().current_best_block_hash
                        {
                            self.subscription.as_mut().unwrap().current_best_block_hash =
                                best_block_hash;
                            return self
                                .subscription
                                .as_mut()
                                .unwrap()
                                .pinned_blocks
                                .get(&best_block_hash)
                                .unwrap();
                        }
                    }
                }
            }
        }
    }
}

/// Helper that provides the blocks of a `state_subscribeRuntimeVersion` subscription.
pub struct SubscribeRuntimeVersion {
    consensus_service: Arc<consensus_service::ConsensusService>,

    /// Active subscription to the consensus service blocks. `None` if not subscribed yet or if
    /// the subscription has stopped.
    subscription: Option<SubscribeRuntimeVersionSubscription>,
}

struct SubscribeRuntimeVersionSubscription {
    subscription_id: consensus_service::SubscriptionId,
    new_blocks: Pin<Box<async_channel::Receiver<consensus_service::Notification>>>,
    pinned_blocks: HashMap<[u8; 32], Arc<HostVmPrototype>>,
    blocks_to_unpin: Vec<[u8; 32]>,
    current_best_block_hash: [u8; 32],
    current_best_block_runtime: Arc<HostVmPrototype>,
}

impl SubscribeRuntimeVersion {
    /// Builds a new [`SubscribeRuntimeVersion`].
    pub fn new(consensus_service: Arc<consensus_service::ConsensusService>) -> Self {
        SubscribeRuntimeVersion {
            consensus_service,
            subscription: None,
        }
    }

    /// Returns the next runtime version to provide as part of the subscription.
    pub async fn next_runtime_version(&mut self) -> &CoreVersion {
        // Note: this function is convoluted with many unwraps due to a difficult fight with the
        // Rust borrow checker.

        loop {
            if self.subscription.is_none() {
                let subscribe_all = self
                    .consensus_service
                    .subscribe_all(32, NonZeroUsize::new(usize::max_value()).unwrap())
                    .await;

                let mut pinned_blocks = HashMap::with_capacity(
                    subscribe_all.non_finalized_blocks_ancestry_order.len() + 1 + 8,
                );

                let mut current_best_block_hash = subscribe_all.finalized_block_hash;
                let mut current_best_block_runtime = subscribe_all.finalized_block_runtime.clone();

                pinned_blocks.insert(
                    subscribe_all.finalized_block_hash,
                    subscribe_all.finalized_block_runtime,
                );

                for block in subscribe_all.non_finalized_blocks_ancestry_order {
                    let runtime = block
                        .runtime_update
                        .unwrap_or_else(|| pinned_blocks.get(&block.parent_hash).unwrap().clone());
                    if block.is_new_best {
                        current_best_block_hash = block.block_hash;
                        current_best_block_runtime = runtime.clone();
                    }
                    pinned_blocks.insert(block.block_hash, runtime);
                }

                let subscription = self
                    .subscription
                    .insert(SubscribeRuntimeVersionSubscription {
                        subscription_id: subscribe_all.id,
                        new_blocks: Box::pin(subscribe_all.new_blocks),
                        pinned_blocks,
                        blocks_to_unpin: Vec::with_capacity(8),
                        current_best_block_hash,
                        current_best_block_runtime: current_best_block_runtime.clone(),
                    });

                return subscription.current_best_block_runtime.runtime_version();
            }

            {
                let subscription = self.subscription.as_mut().unwrap();
                while let Some(block_to_unpin) = subscription.blocks_to_unpin.last() {
                    self.consensus_service
                        .unpin_block(subscription.subscription_id, *block_to_unpin)
                        .await;
                    let _ = subscription.blocks_to_unpin.pop();
                }
            }

            loop {
                let notification = self.subscription.as_mut().unwrap().new_blocks.next().await;
                let Some(notification) = notification else {
                    self.subscription = None;
                    break;
                };

                match notification {
                    consensus_service::Notification::Block { block, .. } => {
                        let runtime = block.runtime_update.unwrap_or_else(|| {
                            self.subscription
                                .as_ref()
                                .unwrap()
                                .pinned_blocks
                                .get(&block.parent_hash)
                                .unwrap()
                                .clone()
                        });

                        let _previous_value = self
                            .subscription
                            .as_mut()
                            .unwrap()
                            .pinned_blocks
                            .insert(block.block_hash, runtime.clone());
                        debug_assert!(_previous_value.is_none());

                        if block.is_new_best {
                            self.subscription.as_mut().unwrap().current_best_block_hash =
                                block.block_hash;
                            if !Arc::ptr_eq(
                                &self
                                    .subscription
                                    .as_mut()
                                    .unwrap()
                                    .current_best_block_runtime,
                                &runtime,
                            ) {
                                self.subscription
                                    .as_mut()
                                    .unwrap()
                                    .current_best_block_runtime = runtime;
                                return self
                                    .subscription
                                    .as_mut()
                                    .unwrap()
                                    .current_best_block_runtime
                                    .runtime_version();
                            }
                        }
                    }
                    consensus_service::Notification::Finalized {
                        pruned_blocks_hashes,
                        finalized_blocks_newest_to_oldest,
                        best_block_hash,
                    } => {
                        for hash in pruned_blocks_hashes {
                            self.subscription
                                .as_mut()
                                .unwrap()
                                .blocks_to_unpin
                                .push(hash);
                            let _was_in = self
                                .subscription
                                .as_mut()
                                .unwrap()
                                .pinned_blocks
                                .remove(&hash);
                            debug_assert!(_was_in.is_some());
                        }

                        for hash in finalized_blocks_newest_to_oldest.iter().skip(1) {
                            self.subscription
                                .as_mut()
                                .unwrap()
                                .blocks_to_unpin
                                .push(*hash);
                            let _was_in = self
                                .subscription
                                .as_mut()
                                .unwrap()
                                .pinned_blocks
                                .remove(hash);
                            debug_assert!(_was_in.is_some());
                        }

                        if best_block_hash
                            != self.subscription.as_mut().unwrap().current_best_block_hash
                        {
                            self.subscription.as_mut().unwrap().current_best_block_hash =
                                best_block_hash;
                            let new_best_runtime = self
                                .subscription
                                .as_ref()
                                .unwrap()
                                .pinned_blocks
                                .get(&best_block_hash)
                                .unwrap()
                                .clone();
                            if !Arc::ptr_eq(
                                &self
                                    .subscription
                                    .as_mut()
                                    .unwrap()
                                    .current_best_block_runtime,
                                &new_best_runtime,
                            ) {
                                self.subscription
                                    .as_mut()
                                    .unwrap()
                                    .current_best_block_runtime = new_best_runtime;
                                return self
                                    .subscription
                                    .as_mut()
                                    .unwrap()
                                    .current_best_block_runtime
                                    .runtime_version();
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Helper that provides the blocks of a `state_subscribeStorage` subscription.
///
/// Note that various corner cases are weirdly handled, due to `state_subscribeStorage` not being
/// properly defined anyway.
pub struct SubscribeStorage {
    /// Consensus service that was passed to [`SubscribeStorage::new`].
    consensus_service: Arc<consensus_service::ConsensusService>,
    /// Database that was passed to [`SubscribeStorage::new`].
    database: Arc<database_thread::DatabaseThread>,
    /// List of keys that was passed to [`SubscribeStorage::new`].
    keys: Vec<Vec<u8>>,

    /// Active subscription to the consensus service blocks. `None` if not subscribed yet or if
    /// the subscription has stopped.
    subscription: Option<SubscribeStorageSubscription>,
}

struct SubscribeStorageSubscription {
    /// Next changes report currently being prepared.
    new_report_preparation: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// List of keys that remain to be included
    /// in [`SubscribeStorageSubscription::new_report_preparation`].
    new_report_remaining_keys: hashbrown::HashSet<Vec<u8>, fnv::FnvBuildHasher>,

    /// Identifier of the subscription towards the consensus service.
    subscription_id: consensus_service::SubscriptionId,
    /// Channel connected to the consensus service where notifications are received.
    new_blocks: Pin<Box<async_channel::Receiver<consensus_service::Notification>>>,
    /// List of block hashes that are still pinned but are not necessary anymore and should be
    /// unpinned.
    blocks_to_unpin: Vec<[u8; 32]>,

    /// Tree of all pinned blocks. Doesn't include the current finalized block.
    pinned_blocks: fork_tree::ForkTree<[u8; 32]>,
    /// Content of [`SubscribeStorageSubscription::pinned_blocks`], indexed by block hashes.
    pinned_blocks_by_hash: hashbrown::HashMap<[u8; 32], fork_tree::NodeIndex>,
    /// Contains all the storage changes related to the keys found by [`SubscribeStorage::keys`]
    /// (or all keys if subscribing to all keys) made in the pinned blocks found
    /// in [`SubscribeStorageSubscription::pinned_blocks`].
    ///
    /// Because the storage changes of blocks that were already present at the time when the
    /// subscription starts are unknown, they are also not in this list. This leads to corner
    /// cases where some changes aren't provided, but we don't really care
    /// as `state_subscribeStorage` is not properly defined anyway.
    pinned_blocks_storage_changes: BTreeSet<(fork_tree::NodeIndex, Vec<u8>)>,
    /// Hash of the current finalized block. Not found
    /// in [`SubscribeStorageSubscription::pinned_blocks`].
    current_finalized_block_hash: [u8; 32],
    /// Index of the current  best block within [`SubscribeStorageSubscription::pinned_blocks`],
    /// or `None` if the best block is equal to the finalized block.
    current_best_block_index: Option<fork_tree::NodeIndex>,
}

impl SubscribeStorage {
    /// Builds a new [`SubscribeStorage`].
    ///
    /// If the list of keys is empty, then all storage changes are reported, in accordance to the
    /// behavior of `state_subscribeStorage`.
    pub fn new(
        consensus_service: Arc<consensus_service::ConsensusService>,
        database: Arc<database_thread::DatabaseThread>,
        subscribed_keys: Vec<Vec<u8>>,
    ) -> Self {
        SubscribeStorage {
            consensus_service,
            database,
            keys: subscribed_keys,
            subscription: None,
        }
    }

    /// Returns the next storage change notification.
    pub async fn next_storage_update(
        &'_ mut self,
    ) -> (
        [u8; 32],
        impl Iterator<Item = (Vec<u8>, Option<Vec<u8>>)> + '_,
    ) {
        'main_subscription: loop {
            // Get the active consensus service subscription, or subscribe if necessary.
            let subscription = match &mut self.subscription {
                Some(s) => s,
                subscription @ None => {
                    let subscribe_all = self
                        .consensus_service
                        .subscribe_all(32, NonZeroUsize::new(usize::max_value()).unwrap())
                        .await;

                    let mut pinned_blocks_by_hash = HashMap::with_capacity(
                        subscribe_all.non_finalized_blocks_ancestry_order.len() + 1 + 8,
                    );
                    let mut pinned_blocks =
                        fork_tree::ForkTree::with_capacity(pinned_blocks_by_hash.capacity());

                    let mut current_best_block_index = None;

                    for block in subscribe_all.non_finalized_blocks_ancestry_order {
                        let node_index = pinned_blocks.insert(
                            if block.parent_hash != subscribe_all.finalized_block_hash {
                                Some(*pinned_blocks_by_hash.get(&block.parent_hash).unwrap())
                            } else {
                                None
                            },
                            block.block_hash,
                        );
                        pinned_blocks_by_hash.insert(block.block_hash, node_index);
                        if block.is_new_best {
                            current_best_block_index = Some(node_index);
                        }
                    }

                    subscription.insert(SubscribeStorageSubscription {
                        new_report_preparation: Vec::with_capacity(self.keys.len()),
                        // We put all the keys in `new_report_remaining_keys`, as we must indicate
                        // the initial values of all the keys.
                        // If the list of keys is empty (meaning that the API user wants to
                        // subscribe to all keys), this will intentionally not lead to any report,
                        // as said report would be huge.
                        // It is unclear how `state_subscribeStorage` is supposed to behave in
                        // that situation.
                        //
                        // Also note that this initial report will happen after a re-subscription,
                        // in order to not miss a storage change.
                        new_report_remaining_keys: self.keys.iter().cloned().collect(),
                        subscription_id: subscribe_all.id,
                        new_blocks: Box::pin(subscribe_all.new_blocks),
                        pinned_blocks,
                        pinned_blocks_by_hash,
                        pinned_blocks_storage_changes: BTreeSet::new(),
                        blocks_to_unpin: Vec::with_capacity(8),
                        current_finalized_block_hash: subscribe_all.finalized_block_hash,
                        current_best_block_index,
                    })
                }
            };

            // Unpin the blocks that must be unpinned.
            while let Some(block_to_unpin) = subscription.blocks_to_unpin.last() {
                self.consensus_service
                    .unpin_block(subscription.subscription_id, *block_to_unpin)
                    .await;
                let _ = subscription.blocks_to_unpin.pop();
            }

            // Continue to fill the next storage changes report.
            while let Some(key) = subscription.new_report_remaining_keys.iter().next() {
                let best_block_hash = subscription
                    .current_best_block_index
                    .map_or(subscription.current_finalized_block_hash, |idx| {
                        *subscription.pinned_blocks.get(idx).unwrap()
                    });

                let key = key.clone();

                let (key, result) = self
                    .database
                    .with_database(move |database| {
                        let result = database.block_storage_get(
                            &best_block_hash,
                            iter::empty::<iter::Empty<_>>(),
                            trie::bytes_to_nibbles(key.iter().copied()).map(u8::from),
                        );
                        (key, result)
                    })
                    .await;

                subscription.new_report_remaining_keys.remove(&key);

                match result {
                    Ok(value) => subscription
                        .new_report_preparation
                        .push((key, value.map(|(v, _)| v))),
                    Err(database_thread::StorageAccessError::UnknownBlock)
                    | Err(database_thread::StorageAccessError::StoragePruned) => {
                        self.subscription = None;
                        continue 'main_subscription;
                    }
                    Err(database_thread::StorageAccessError::Corrupted(_)) => {
                        // Database corruption errors are ignored.
                        continue;
                    }
                }
            }

            // Send the storage changes report if it is complete.
            debug_assert!(subscription.new_report_remaining_keys.is_empty());
            if !subscription.new_report_preparation.is_empty() {
                let best_block_hash = subscription
                    .current_best_block_index
                    .map_or(subscription.current_finalized_block_hash, |idx| {
                        *subscription.pinned_blocks.get(idx).unwrap()
                    });
                return (
                    best_block_hash,
                    mem::replace(
                        &mut subscription.new_report_preparation,
                        Vec::with_capacity(self.keys.len()),
                    )
                    .into_iter(),
                );
            }

            // Process the next incoming consensus service notification.
            let notification = subscription.new_blocks.next().await;
            let Some(mut notification) = notification else {
                self.subscription = None;
                continue;
            };

            // If the notification is about a new block, insert said new block in the state
            // machine.
            if let consensus_service::Notification::Block {
                block,
                storage_changes,
            } = &mut notification
            {
                let node_index = subscription.pinned_blocks.insert(
                    if block.parent_hash != subscription.current_finalized_block_hash {
                        Some(
                            *subscription
                                .pinned_blocks_by_hash
                                .get(&block.parent_hash)
                                .unwrap(),
                        )
                    } else {
                        None
                    },
                    block.block_hash,
                );

                subscription
                    .pinned_blocks_by_hash
                    .insert(block.block_hash, node_index);

                if !self.keys.is_empty() {
                    for key in &self.keys {
                        if storage_changes.main_trie_diff_get(key).is_some() {
                            subscription
                                .pinned_blocks_storage_changes
                                .insert((node_index, key.clone()));
                        }
                    }
                } else {
                    for (changed_key, _) in
                        storage_changes.main_trie_storage_changes_iter_unordered()
                    {
                        subscription
                            .pinned_blocks_storage_changes
                            .insert((node_index, changed_key.to_owned()));
                    }
                }
            }

            // If the notification changes the best block, find the keys that have changed and
            // put them in `new_report_remaining_keys`.
            if let consensus_service::Notification::Block {
                block:
                    consensus_service::BlockNotification {
                        block_hash: best_block_hash,
                        is_new_best: true,
                        ..
                    },
                ..
            }
            | consensus_service::Notification::Finalized {
                best_block_hash, ..
            } = &notification
            {
                let new_best_block_node_index = *subscription
                    .pinned_blocks_by_hash
                    .get(best_block_hash)
                    .unwrap();

                let ascend_descend_iter = match subscription.current_best_block_index {
                    Some(prev_best_idx) => {
                        let (a, d) = subscription
                            .pinned_blocks
                            .ascend_and_descend(prev_best_idx, new_best_block_node_index);
                        either::Left(a.chain(d))
                    }
                    None => either::Right(
                        subscription
                            .pinned_blocks
                            .root_to_node_path(new_best_block_node_index),
                    ),
                };

                for block in ascend_descend_iter {
                    let storage_changes = subscription.pinned_blocks_storage_changes.range((
                        ops::Bound::Included((block, Vec::new())),
                        if let Some(block_plus_one) = block.inc() {
                            ops::Bound::Excluded((block_plus_one, Vec::new()))
                        } else {
                            ops::Bound::Unbounded
                        },
                    ));

                    for (_, key) in storage_changes {
                        subscription.new_report_remaining_keys.insert(key.clone());
                    }
                }

                subscription.current_best_block_index = Some(new_best_block_node_index);
            }

            // Remove from the state machine the blocks that have been finalized.
            if let consensus_service::Notification::Finalized {
                finalized_blocks_newest_to_oldest,
                ..
            } = notification
            {
                subscription.current_finalized_block_hash =
                    *finalized_blocks_newest_to_oldest.first().unwrap();

                for pruned_block in subscription.pinned_blocks.prune_ancestors(
                    *subscription
                        .pinned_blocks_by_hash
                        .get(&subscription.current_finalized_block_hash)
                        .unwrap(),
                ) {
                    let _was_in = subscription
                        .pinned_blocks_by_hash
                        .remove(&pruned_block.user_data);
                    debug_assert_eq!(_was_in, Some(pruned_block.index));

                    let mut after_split_off_point = subscription
                        .pinned_blocks_storage_changes
                        .split_off(&(pruned_block.index, Vec::new()));
                    if let Some(index_plus_one) = pruned_block.index.inc() {
                        let mut after_changes =
                            after_split_off_point.split_off(&(index_plus_one, Vec::new()));
                        subscription
                            .pinned_blocks_storage_changes
                            .append(&mut after_changes);
                    }

                    subscription.blocks_to_unpin.push(pruned_block.user_data);
                }
            }
        }
    }
}
