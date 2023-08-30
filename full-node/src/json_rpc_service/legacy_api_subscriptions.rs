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

use smol::stream::StreamExt as _;
use std::{iter, num::NonZeroUsize, sync::Arc};

use crate::consensus_service;

pub struct SubscribeAllHeads {
    consensus_service: Arc<consensus_service::ConsensusService>,
    subscription: Option<SubscribeAllHeadsSubscription>,
}

struct SubscribeAllHeadsSubscription {
    subscription_id: consensus_service::SubscriptionId,
    new_blocks: async_channel::Receiver<consensus_service::Notification>,
    blocks_to_unpin: Vec<[u8; 32]>,
}

impl SubscribeAllHeads {
    pub fn new(consensus_service: Arc<consensus_service::ConsensusService>) -> Self {
        SubscribeAllHeads {
            consensus_service,
            subscription: None,
        }
    }

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
                    None => break,
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
