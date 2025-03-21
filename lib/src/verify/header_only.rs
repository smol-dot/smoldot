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

use crate::{
    chain::chain_information,
    header,
    verify::{aura, babe},
};

use alloc::vec::Vec;
use core::{num::NonZero, time::Duration};

/// Configuration for a block verification.
pub struct Config<'a> {
    /// Header of the parent of the block to verify.
    ///
    /// The hash of this header must be the one referenced in [`Config::block_header`].
    pub parent_block_header: header::HeaderRef<'a>,

    /// Header of the block to verify.
    ///
    /// The `parent_hash` field is the hash of the parent whose storage can be accessed through
    /// the other fields.
    pub block_header: header::HeaderRef<'a>,

    /// Number of bytes used to encode the block number in the header.
    pub block_number_bytes: usize,

    /// Configuration items related to the consensus engine.
    pub consensus: ConfigConsensus<'a>,

    /// Configuration items related to the finality engine.
    pub finality: ConfigFinality,

    /// If `false`, digest items with an unknown consensus engine lead to an error.
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
}

/// Extra items of [`Config`] that are dependant on the consensus engine of the chain.
pub enum ConfigConsensus<'a> {
    /// Chain is using the Aura consensus engine.
    Aura {
        /// Aura authorities that must validate the block.
        ///
        /// This list is either equal to the parent's list, or, if the parent changes the list of
        /// authorities, equal to that new modified list.
        current_authorities: header::AuraAuthoritiesIter<'a>,

        /// Duration of a slot in milliseconds.
        /// Can be found by calling the `AuraApi_slot_duration` runtime function.
        slot_duration: NonZero<u64>,

        /// Time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time) (i.e.
        /// 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
        now_from_unix_epoch: Duration,
    },

    /// Chain is using the Babe consensus engine.
    Babe {
        /// Number of slots per epoch in the Babe configuration.
        slots_per_epoch: NonZero<u64>,

        /// Epoch the parent block belongs to. Must be `None` if and only if the parent block's
        /// number is 0, as block #0 doesn't belong to any epoch.
        parent_block_epoch: Option<chain_information::BabeEpochInformationRef<'a>>,

        /// Epoch that follows the epoch the parent block belongs to.
        parent_block_next_epoch: chain_information::BabeEpochInformationRef<'a>,

        /// Time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time) (i.e.
        /// 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
        now_from_unix_epoch: Duration,
    },
}

/// Extra items of [`Config`] that are dependant on the finality engine of the chain.
pub enum ConfigFinality {
    /// Blocks themselves don't contain any information concerning finality. Finality is provided
    /// by a mechanism that is entirely external to the chain.
    ///
    /// > **Note**: This is the mechanism used for parachains. Finality is provided entirely by
    /// >           the relay chain.
    Outsourced,

    /// Chain uses the Grandpa finality algorithm.
    Grandpa,
}

/// Block successfully verified.
pub enum Success {
    /// Chain is using the Aura consensus engine.
    Aura {
        /// `Some` if the list of authorities is modified by this block. Contains the new list of
        /// authorities.
        authorities_change: Option<Vec<header::AuraAuthority>>,
    },

    /// Chain is using the Babe consensus engine.
    Babe {
        /// Slot number the block belongs to.
        ///
        /// > **Note**: This is a simple reminder. The value can also be found in the header of the
        /// >           block.
        slot_number: u64,

        /// `true` if the claimed slot is a primary slot. `false` if it is a secondary slot.
        is_primary_slot: bool,

        /// If `Some`, the verified block contains an epoch transition describing the new
        /// "next epoch". When verifying blocks that are children of this one, the value in this
        /// field must be provided as [`ConfigConsensus::Babe::parent_block_next_epoch`], and the
        /// value previously in [`ConfigConsensus::Babe::parent_block_next_epoch`] must instead be
        /// passed as [`ConfigConsensus::Babe::parent_block_epoch`].
        epoch_transition_target: Option<chain_information::BabeEpochInformation>,
    },
}

/// Error that can happen during the verification.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Number of the block to verify isn't equal to the parent block's number plus one.
    NonSequentialBlockNumber,
    /// Hash of the parent block doesn't match the hash in the header to verify.
    BadParentHash,
    /// Block header contains an unrecognized consensus engine.
    #[display("Block header contains an unrecognized consensus engine: {engine:?}")]
    UnknownConsensusEngine { engine: [u8; 4] },
    /// Block header contains items relevant to multiple consensus engines at the same time.
    MultipleConsensusEngines,
    /// Block header contains items that don't match the finality engine of the chain.
    FinalityEngineMismatch,
    /// Failed to verify the authenticity of the block with the AURA algorithm.
    #[display("{_0}")]
    AuraVerification(aura::VerifyError),
    /// Failed to verify the authenticity of the block with the BABE algorithm.
    #[display("{_0}")]
    BabeVerification(babe::VerifyError),
    /// Block schedules a Grandpa authorities change while another change is still in progress.
    GrandpaChangesOverlap,
}

impl Error {
    /// Returns `true` if the error isn't actually about the block being verified but about a
    /// bad configuration of the chain.
    pub fn is_invalid_chain_configuration(&self) -> bool {
        matches!(
            self,
            Error::BabeVerification(babe::VerifyError::InvalidChainConfiguration(_))
        )
    }
}

/// Verifies whether a block is valid.
pub fn verify(config: Config) -> Result<Success, Error> {
    // Check that there is no mismatch in the parent header hash.
    // Note that the user is expected to pass a parent block that matches the parent indicated by
    // the header to verify, and not blindly pass an "expected parent". As such, this check is
    // unnecessary and introduces an overhead.
    // However this check is performed anyway, as the consequences of a failure here could be
    // potentially quite high.
    if config.parent_block_header.hash(config.block_number_bytes)
        != *config.block_header.parent_hash
    {
        return Err(Error::BadParentHash);
    }

    // Some basic verification of the block number. This is normally verified by the runtime, but
    // no runtime call can be performed with only the header.
    if config
        .parent_block_header
        .number
        .checked_add(1)
        .map_or(true, |v| v != config.block_header.number)
    {
        return Err(Error::NonSequentialBlockNumber);
    }

    // Fail verification if there is any digest log item with an unrecognized consensus engine.
    if !config.allow_unknown_consensus_engines {
        if let Some(engine) = config
            .block_header
            .digest
            .logs()
            .find_map(|item| match item {
                header::DigestItemRef::UnknownConsensus { engine, .. }
                | header::DigestItemRef::UnknownSeal { engine, .. }
                | header::DigestItemRef::UnknownPreRuntime { engine, .. } => Some(engine),
                _ => None,
            })
        {
            return Err(Error::UnknownConsensusEngine { engine });
        }
    }

    // Check whether the log items respect the finality engine.
    match config.finality {
        ConfigFinality::Grandpa => {}
        ConfigFinality::Outsourced => {
            if config.block_header.digest.has_any_grandpa() {
                return Err(Error::FinalityEngineMismatch);
            }
        }
    }

    match config.consensus {
        ConfigConsensus::Aura {
            current_authorities,
            slot_duration,
            now_from_unix_epoch,
        } => {
            if config.block_header.digest.has_any_babe() {
                return Err(Error::MultipleConsensusEngines);
            }

            let result = aura::verify_header(aura::VerifyConfig {
                header: config.block_header.clone(),
                block_number_bytes: config.block_number_bytes,
                parent_block_header: config.parent_block_header,
                now_from_unix_epoch,
                current_authorities,
                slot_duration,
            });

            match result {
                Ok(s) => Ok(Success::Aura {
                    authorities_change: s.authorities_change,
                }),
                Err(err) => Err(Error::AuraVerification(err)),
            }
        }
        ConfigConsensus::Babe {
            parent_block_epoch,
            parent_block_next_epoch,
            slots_per_epoch,
            now_from_unix_epoch,
        } => {
            if config.block_header.digest.has_any_aura() {
                return Err(Error::MultipleConsensusEngines);
            }

            let result = babe::verify_header(babe::VerifyConfig {
                header: config.block_header.clone(),
                block_number_bytes: config.block_number_bytes,
                parent_block_header: config.parent_block_header,
                parent_block_epoch,
                parent_block_next_epoch,
                slots_per_epoch,
                now_from_unix_epoch,
            });

            match result {
                Ok(s) => Ok(Success::Babe {
                    epoch_transition_target: s.epoch_transition_target,
                    is_primary_slot: s.is_primary_slot,
                    slot_number: s.slot_number,
                }),
                Err(err) => Err(Error::BabeVerification(err)),
            }
        }
    }
}
