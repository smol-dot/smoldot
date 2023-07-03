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

//! Extension module containing the API and implementation of everything related to verifying
//! blocks.

// TODO: clean up this module

use crate::{
    chain::{chain_information, fork_tree},
    header, verify,
};

use super::{
    best_block, fmt, Arc, Block, BlockConsensus, BlockFinality, Duration, Finality,
    FinalizedConsensus, NonFinalizedTree, NonFinalizedTreeInner, Vec,
};

use alloc::boxed::Box;
use core::cmp::Ordering;

impl<T> NonFinalizedTree<T> {
    /// Verifies the given block.
    ///
    /// The verification is performed in the context of the chain. In particular, the
    /// verification will fail if the parent block isn't already in the chain.
    ///
    /// If the verification succeeds, an [`HeaderInsert`] object might be returned which can be
    /// used to then insert the block in the chain.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    pub fn verify_header(
        &mut self,
        scale_encoded_header: Vec<u8>,
        now_from_unix_epoch: Duration,
    ) -> Result<HeaderVerifySuccess, HeaderVerifyError> {
        let self_inner = self.inner.take().unwrap();
        match self_inner.verify(scale_encoded_header, now_from_unix_epoch) {
            VerifyOut::HeaderErr(self_inner, err) => {
                self.inner = Some(self_inner);
                Err(err)
            }
            VerifyOut::HeaderOk(self_inner, verified_header) => {
                self.inner = Some(self_inner);
                let is_new_best = verified_header.is_new_best;
                Ok(HeaderVerifySuccess::Verified {
                    is_new_best,
                    verified_header,
                })
            }
            VerifyOut::HeaderDuplicate(self_inner) => {
                self.inner = Some(self_inner);
                Ok(HeaderVerifySuccess::Duplicate)
            }
        }
    }

    /// Insert a header that has already been verified to be valid.
    ///
    /// # Panic
    ///
    /// Panics if the parent of the block isn't in the tree. The presence of the parent is verified
    /// when the block is verified, so this can only happen if you remove the parent after having
    /// verified the block but before calling this function.
    ///
    pub fn insert_verified_header(&mut self, verified_header: VerifiedHeader, user_data: T) {
        let inner = self.inner.as_mut().unwrap();

        // Try to find the parent block in the tree of known blocks.
        // `Some` with an index of the parent within the tree of unfinalized blocks.
        // `None` means that the parent is the finalized block.
        let parent_tree_index = {
            let decoded_header = header::decode(
                &verified_header.scale_encoded_header,
                inner.block_number_bytes,
            )
            .unwrap();

            if *decoded_header.parent_hash == inner.finalized_block_hash {
                None
            } else {
                Some(
                    *inner
                        .blocks_by_hash
                        .get(decoded_header.parent_hash)
                        .unwrap(),
                )
            }
        };

        let new_node_index = inner.blocks.insert(
            parent_tree_index,
            Block {
                header: verified_header.scale_encoded_header,
                hash: verified_header.hash,
                consensus: verified_header.consensus,
                finality: verified_header.finality,
                user_data,
            },
        );

        let _prev_value = inner
            .blocks_by_hash
            .insert(verified_header.hash, new_node_index);
        // A bug here would be serious enough that it is worth being an `assert!`
        assert!(_prev_value.is_none());

        // TODO: what if it's no longer the new best because the API user has inserted another block in between? the best block system should be refactored
        if verified_header.is_new_best {
            inner.current_best = Some(new_node_index);
        }
    }
}

/// Successfully-verified block header that can be inserted into the chain.
pub struct VerifiedHeader {
    scale_encoded_header: Vec<u8>,
    is_new_best: bool,
    consensus: BlockConsensus,
    finality: BlockFinality,
    hash: [u8; 32],
}

impl VerifiedHeader {
    /// Returns the block header.
    pub fn scale_encoded_header(&self) -> &[u8] {
        &self.scale_encoded_header
    }

    /// Returns the block header.
    pub fn into_scale_encoded_header(self) -> Vec<u8> {
        self.scale_encoded_header
    }
}

impl fmt::Debug for VerifiedHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifiedHeader")
            .field(&hex::encode(&self.scale_encoded_header))
            .finish()
    }
}

impl<T> NonFinalizedTreeInner<T> {
    /// Common implementation for both [`NonFinalizedTree::verify_header`] and
    /// [`NonFinalizedTree::verify_body`].
    fn verify(
        self: Box<Self>,
        scale_encoded_header: Vec<u8>,
        now_from_unix_epoch: Duration,
    ) -> VerifyOut<T> {
        let decoded_header = match header::decode(&scale_encoded_header, self.block_number_bytes) {
            Ok(h) => h,
            Err(err) => return VerifyOut::HeaderErr(self, HeaderVerifyError::InvalidHeader(err)),
        };

        let hash = header::hash_from_scale_encoded_header(&scale_encoded_header);

        // Check for duplicates.
        if self.blocks_by_hash.contains_key(&hash) {
            return VerifyOut::HeaderDuplicate(self);
        }

        // Try to find the parent block in the tree of known blocks.
        // `Some` with an index of the parent within the tree of unfinalized blocks.
        // `None` means that the parent is the finalized block.
        let parent_tree_index = {
            if *decoded_header.parent_hash == self.finalized_block_hash {
                None
            } else {
                match self.blocks_by_hash.get(decoded_header.parent_hash) {
                    Some(parent) => Some(*parent),
                    None => {
                        let parent_hash = *decoded_header.parent_hash;
                        return VerifyOut::HeaderErr(
                            self,
                            HeaderVerifyError::BadParent { parent_hash },
                        );
                    }
                }
            }
        };

        // Some consensus-specific information must be fetched from the tree of ancestry. The
        // information is found either in the parent block, or in the finalized block.
        let (parent_consensus, parent_finality) = if let Some(parent_tree_index) = parent_tree_index
        {
            let parent = self.blocks.get(parent_tree_index).unwrap();
            (Some(parent.consensus.clone()), parent.finality.clone())
        } else {
            let consensus = match &self.finalized_consensus {
                FinalizedConsensus::Unknown => None,
                FinalizedConsensus::Aura {
                    authorities_list, ..
                } => Some(BlockConsensus::Aura {
                    authorities_list: authorities_list.clone(),
                }),
                FinalizedConsensus::Babe {
                    block_epoch_information,
                    next_epoch_transition,
                    ..
                } => Some(BlockConsensus::Babe {
                    current_epoch: block_epoch_information.clone(),
                    next_epoch: next_epoch_transition.clone(),
                }),
            };

            let finality = match self.finality {
                Finality::Outsourced => BlockFinality::Outsourced,
                Finality::Grandpa {
                    after_finalized_block_authorities_set_id,
                    ref finalized_scheduled_change,
                    ref finalized_triggered_authorities,
                } => {
                    debug_assert!(finalized_scheduled_change
                        .as_ref()
                        .map(|(n, _)| *n >= decoded_header.number)
                        .unwrap_or(true));
                    BlockFinality::Grandpa {
                        prev_auth_change_trigger_number: None,
                        triggers_change: false,
                        scheduled_change: finalized_scheduled_change.clone(),
                        after_block_authorities_set_id: after_finalized_block_authorities_set_id,
                        triggered_authorities: finalized_triggered_authorities.clone(),
                    }
                }
            };

            (consensus, finality)
        };

        let context = Box::new(VerifyContext {
            chain: self,
            header: scale_encoded_header,
            parent_tree_index,
            consensus: parent_consensus,
            finality: parent_finality,
        });

        let parent_block_header = if let Some(parent_tree_index) = parent_tree_index {
            &context.chain.blocks.get(parent_tree_index).unwrap().header
        } else {
            &context.chain.finalized_block_header
        };

        let header_verify_result = verify::header_only::verify(verify::header_only::Config {
            consensus: match (&context.chain.finalized_consensus, &context.consensus) {
                (
                    FinalizedConsensus::Aura { slot_duration, .. },
                    Some(BlockConsensus::Aura { authorities_list }),
                ) => verify::header_only::ConfigConsensus::Aura {
                    current_authorities: header::AuraAuthoritiesIter::from_slice(authorities_list),
                    now_from_unix_epoch,
                    slot_duration: *slot_duration,
                },
                (
                    FinalizedConsensus::Babe {
                        slots_per_epoch, ..
                    },
                    Some(BlockConsensus::Babe {
                        current_epoch,
                        next_epoch,
                    }),
                ) => verify::header_only::ConfigConsensus::Babe {
                    parent_block_epoch: current_epoch.as_ref().map(|v| (&**v).into()),
                    parent_block_next_epoch: (&**next_epoch).into(),
                    slots_per_epoch: *slots_per_epoch,
                    now_from_unix_epoch,
                },
                (FinalizedConsensus::Unknown, None) => {
                    return VerifyOut::HeaderErr(
                        context.chain,
                        HeaderVerifyError::UnknownConsensusEngine,
                    )
                }
                _ => {
                    return VerifyOut::HeaderErr(
                        context.chain,
                        HeaderVerifyError::ConsensusMismatch,
                    )
                }
            },
            finality: match &context.finality {
                BlockFinality::Outsourced => verify::header_only::ConfigFinality::Outsourced,
                BlockFinality::Grandpa { .. } => verify::header_only::ConfigFinality::Grandpa,
            },
            allow_unknown_consensus_engines: context.chain.allow_unknown_consensus_engines,
            block_header: header::decode(&context.header, context.chain.block_number_bytes)
                .unwrap(), // TODO: inefficiency ; in case of header only verify we do an extra allocation to build the context above
            block_number_bytes: context.chain.block_number_bytes,
            parent_block_header: header::decode(
                parent_block_header,
                context.chain.block_number_bytes,
            )
            .unwrap(),
        })
        .map_err(HeaderVerifyError::VerificationFailed);

        let header_verify_result = match header_verify_result {
            Ok(success) => success,
            Err(err) => return VerifyOut::HeaderErr(context.chain, err),
        };

        let decoded_header =
            header::decode(&context.header, context.chain.block_number_bytes).unwrap();

        let is_new_best = if let Some(current_best) = context.chain.current_best {
            best_block::is_better_block(
                &context.chain.blocks,
                context.chain.block_number_bytes,
                current_best,
                context.parent_tree_index,
                decoded_header.clone(),
            ) == Ordering::Greater
        } else {
            true
        };

        let consensus = match (
            header_verify_result,
            &context.consensus,
            context.chain.finalized_consensus.clone(),
            context
                .parent_tree_index
                .map(|idx| context.chain.blocks.get(idx).unwrap().consensus.clone()),
        ) {
            (
                verify::header_only::Success::Aura { authorities_change },
                Some(BlockConsensus::Aura {
                    authorities_list: parent_authorities,
                }),
                FinalizedConsensus::Aura { .. },
                _,
            ) => {
                if authorities_change {
                    todo!() // TODO: fetch from header
                            /*BlockConsensus::Aura {
                                authorities_list:
                            }*/
                } else {
                    BlockConsensus::Aura {
                        authorities_list: parent_authorities.clone(),
                    }
                }
            }

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: Some(epoch_transition_target),
                    ..
                },
                Some(BlockConsensus::Babe { .. }),
                FinalizedConsensus::Babe { .. },
                Some(BlockConsensus::Babe { next_epoch, .. }),
            ) if next_epoch.start_slot_number.is_some() => BlockConsensus::Babe {
                current_epoch: Some(next_epoch),
                next_epoch: Arc::new(epoch_transition_target),
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: Some(epoch_transition_target),
                    slot_number,
                    ..
                },
                Some(BlockConsensus::Babe { .. }),
                FinalizedConsensus::Babe { .. },
                Some(BlockConsensus::Babe { next_epoch, .. }),
            ) => BlockConsensus::Babe {
                current_epoch: Some(Arc::new(chain_information::BabeEpochInformation {
                    start_slot_number: Some(slot_number),
                    allowed_slots: next_epoch.allowed_slots,
                    epoch_index: next_epoch.epoch_index,
                    authorities: next_epoch.authorities.clone(),
                    c: next_epoch.c,
                    randomness: next_epoch.randomness,
                })),
                next_epoch: Arc::new(epoch_transition_target),
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: None,
                    ..
                },
                Some(BlockConsensus::Babe { .. }),
                FinalizedConsensus::Babe { .. },
                Some(BlockConsensus::Babe {
                    current_epoch,
                    next_epoch,
                }),
            ) => BlockConsensus::Babe {
                current_epoch,
                next_epoch,
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: Some(epoch_transition_target),
                    ..
                },
                Some(BlockConsensus::Babe { .. }),
                FinalizedConsensus::Babe {
                    next_epoch_transition,
                    ..
                },
                None,
            ) if next_epoch_transition.start_slot_number.is_some() => BlockConsensus::Babe {
                current_epoch: Some(next_epoch_transition),
                next_epoch: Arc::new(epoch_transition_target),
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: Some(epoch_transition_target),
                    slot_number,
                    ..
                },
                Some(BlockConsensus::Babe { .. }),
                FinalizedConsensus::Babe {
                    next_epoch_transition,
                    ..
                },
                None,
            ) => BlockConsensus::Babe {
                current_epoch: Some(Arc::new(chain_information::BabeEpochInformation {
                    start_slot_number: Some(slot_number),
                    allowed_slots: next_epoch_transition.allowed_slots,
                    authorities: next_epoch_transition.authorities.clone(),
                    c: next_epoch_transition.c,
                    epoch_index: next_epoch_transition.epoch_index,
                    randomness: next_epoch_transition.randomness,
                })),
                next_epoch: Arc::new(epoch_transition_target),
            },

            (
                verify::header_only::Success::Babe {
                    epoch_transition_target: None,
                    ..
                },
                Some(BlockConsensus::Babe { .. }),
                FinalizedConsensus::Babe {
                    block_epoch_information,
                    next_epoch_transition,
                    ..
                },
                None,
            ) => BlockConsensus::Babe {
                current_epoch: block_epoch_information,
                next_epoch: next_epoch_transition,
            },

            // Any mismatch between consensus algorithms should have been detected by the
            // block verification.
            _ => unreachable!(),
        };

        let finality = match &context.finality {
            BlockFinality::Outsourced => BlockFinality::Outsourced,
            BlockFinality::Grandpa {
                prev_auth_change_trigger_number: parent_prev_auth_change_trigger_number,
                after_block_authorities_set_id: parent_after_block_authorities_set_id,
                scheduled_change: parent_scheduled_change,
                triggered_authorities: parent_triggered_authorities,
                triggers_change: parent_triggers_change,
                ..
            } => {
                let mut triggered_authorities = parent_triggered_authorities.clone();
                let mut triggers_change = false;
                let mut scheduled_change = parent_scheduled_change.clone();

                // Check whether the verified block schedules a change of authorities.
                for grandpa_digest_item in decoded_header.digest.logs().filter_map(|d| match d {
                    header::DigestItemRef::GrandpaConsensus(gp) => Some(gp),
                    _ => None,
                }) {
                    // TODO: implement items other than ScheduledChange
                    // TODO: when it comes to forced change, they take precedence over scheduled changes but only sheduled changes within the same block
                    if let header::GrandpaConsensusLogRef::ScheduledChange(change) =
                        grandpa_digest_item
                    {
                        let trigger_block_height =
                            decoded_header.number.checked_add(change.delay).unwrap();

                        // It is forbidden to schedule a change while a change is already
                        // scheduled, otherwise the block is invalid. This is verified during
                        // the block verification.
                        match scheduled_change {
                            Some(_) => {
                                // Ignore any new change if a change is already in progress.
                                // Matches the behaviour here: <https://github.com/paritytech/substrate/blob/a357c29ebabb075235977edd5e3901c66575f995/client/finality-grandpa/src/authorities.rs#L479>
                            }
                            None => {
                                scheduled_change = Some((
                                    trigger_block_height,
                                    change.next_authorities.map(|a| a.into()).collect(),
                                ));
                            }
                        }
                    }
                }

                // If the newly-verified block is one where Grandpa scheduled change are
                // triggered, we need update the field values.
                // Note that this is checked after we have potentially fetched `scheduled_change`
                // from the block.
                if let Some((trigger_height, new_list)) = &scheduled_change {
                    if *trigger_height == decoded_header.number {
                        triggers_change = true;
                        triggered_authorities = new_list.clone();
                        scheduled_change = None;
                    }
                }

                // Some sanity checks.
                debug_assert!(scheduled_change
                    .as_ref()
                    .map(|(n, _)| *n > decoded_header.number)
                    .unwrap_or(true));
                debug_assert!(parent_prev_auth_change_trigger_number
                    .as_ref()
                    .map(|n| *n < decoded_header.number)
                    .unwrap_or(true));

                BlockFinality::Grandpa {
                    prev_auth_change_trigger_number: if *parent_triggers_change {
                        Some(decoded_header.number - 1)
                    } else {
                        *parent_prev_auth_change_trigger_number
                    },
                    triggered_authorities,
                    scheduled_change,
                    triggers_change,
                    after_block_authorities_set_id: if triggers_change {
                        *parent_after_block_authorities_set_id + 1
                    } else {
                        *parent_after_block_authorities_set_id
                    },
                }
            }
        };

        VerifyOut::HeaderOk(
            context.chain,
            VerifiedHeader {
                scale_encoded_header: context.header,
                is_new_best,
                consensus,
                finality,
                hash,
            },
        )
    }
}

enum VerifyOut<T> {
    HeaderOk(Box<NonFinalizedTreeInner<T>>, VerifiedHeader),
    HeaderErr(Box<NonFinalizedTreeInner<T>>, HeaderVerifyError),
    HeaderDuplicate(Box<NonFinalizedTreeInner<T>>),
}

struct VerifyContext<T> {
    chain: Box<NonFinalizedTreeInner<T>>,
    parent_tree_index: Option<fork_tree::NodeIndex>,
    header: Vec<u8>,
    consensus: Option<BlockConsensus>,
    finality: BlockFinality,
}

///
#[derive(Debug)]
pub enum HeaderVerifySuccess {
    /// Block is already known.
    Duplicate,
    /// Block wasn't known and has been successfully verified.
    Verified {
        /// Header that has been verified. Can be passed to
        /// [`NonFinalizedTree::insert_verified_header`].
        verified_header: VerifiedHeader,
        /// True if the verified block will become the new "best" block after being inserted.
        is_new_best: bool,
    },
}

/// Error that can happen when verifying a block header.
#[derive(Debug, derive_more::Display)]
pub enum HeaderVerifyError {
    /// Error while decoding the header.
    #[display(fmt = "Error while decoding the header: {_0}")]
    InvalidHeader(header::Error),
    /// Block can't be verified as it uses an unknown consensus engine.
    UnknownConsensusEngine,
    /// Block uses a different consensus than the rest of the chain.
    ConsensusMismatch,
    /// The parent of the block isn't known.
    #[display(fmt = "The parent of the block isn't known.")]
    BadParent {
        /// Hash of the parent block in question.
        parent_hash: [u8; 32],
    },
    /// The block verification has failed. The block is invalid and should be thrown away.
    #[display(fmt = "{_0}")]
    VerificationFailed(verify::header_only::Error),
}
