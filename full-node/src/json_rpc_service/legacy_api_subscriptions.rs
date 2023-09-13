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
use std::{iter, num::NonZeroUsize, sync::Arc};

use crate::consensus_service;

/// Helper that provides the blocks of a `chain_subscribeAllHeads` subscription.
pub struct SubscribeAllHeads {
    consensus_service: Arc<consensus_service::ConsensusService>,

    /// Active subscription to the consensus service blocks. `None` if not subscribed yet or if
    /// the subscription has stopped.
    subscription: Option<SubscribeAllHeadsSubscription>,
}

struct SubscribeAllHeadsSubscription {
    subscription_id: consensus_service::SubscriptionId,
    new_blocks: async_channel::Receiver<consensus_service::Notification>,
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
                        .subscribe_all(32, NonZeroUsize::new(32).unwrap())
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
                        new_blocks: subscribe_all.new_blocks,
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
                    Some(consensus_service::Notification::Block(block)) => {
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
    new_blocks: async_channel::Receiver<consensus_service::Notification>,
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
                        .subscribe_all(32, NonZeroUsize::new(32).unwrap())
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
                        new_blocks: subscribe_all.new_blocks,
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
                    Some(consensus_service::Notification::Block(block)) => {
                        subscription
                            .pinned_blocks
                            .insert(block.block_hash, block.scale_encoded_header);
                    }
                    Some(consensus_service::Notification::Finalized {
                        mut finalized_blocks_hashes,
                        pruned_blocks_hashes,
                        ..
                    }) => {
                        debug_assert!(!finalized_blocks_hashes.is_empty());
                        let finalized_block_hash = finalized_blocks_hashes.pop().unwrap();
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

                        for block in finalized_blocks_hashes {
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
    new_blocks: async_channel::Receiver<consensus_service::Notification>,
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
                    .subscribe_all(32, NonZeroUsize::new(32).unwrap())
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
                    new_blocks: subscribe_all.new_blocks,
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
                    consensus_service::Notification::Block(block) => {
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
                        finalized_blocks_hashes,
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

                        for hash in finalized_blocks_hashes
                            .iter()
                            .take(finalized_blocks_hashes.len() - 1)
                        {
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
