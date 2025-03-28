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

// TODO: docs

use crate::{
    author::{aura, runtime},
    executor::host,
    header,
    verify::inherents,
};

use alloc::vec::Vec;
use core::{num::NonZero, time::Duration};

pub use runtime::{Nibble, StorageChanges, TrieEntryVersion};

/// Configuration for a block generation.
pub struct Config<'a, TLocAuth> {
    /// Consensus-specific configuration.
    pub consensus: ConfigConsensus<'a, TLocAuth>,
}

/// Extension to [`Config`].
pub enum ConfigConsensus<'a, TLocAuth> {
    /// Chain is using the Aura consensus algorithm.
    Aura {
        /// Time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time) (i.e.
        /// 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
        now_from_unix_epoch: Duration,

        /// Duration, in milliseconds, of an Aura slot.
        slot_duration: NonZero<u64>,

        /// List of the Aura authorities allowed to produce a block. This is either the same as
        /// the ones of the current best block, or a new list if the current best block contains
        /// an authorities list change digest item.
        current_authorities: header::AuraAuthoritiesIter<'a>,

        /// Iterator to the list of Sr25519 public keys available locally.
        ///
        /// Must implement `Iterator<Item = &[u8; 32]>`.
        local_authorities: TLocAuth,
    },
    // TODO: Babe isn't supported yet
}

/// Current state of the block building process.
#[must_use]
pub enum Builder {
    /// None of the authorities available locally are allowed to produce a block.
    Idle,

    /// Block production is idle, waiting for a slot.
    WaitSlot(WaitSlot),

    /// Block production is ready to start.
    Ready(AuthoringStart),
}

impl Builder {
    /// Initializes a new builder.
    ///
    /// Returns `None` if none of the local authorities are allowed to produce blocks.
    ///
    /// Keep in mind that the builder should be reconstructed every time the best block changes.
    pub fn new<'a>(config: Config<'a, impl Iterator<Item = &'a [u8; 32]>>) -> Self {
        let (slot, ready): (WaitSlotConsensus, bool) = match config.consensus {
            ConfigConsensus::Aura {
                current_authorities,
                local_authorities,
                now_from_unix_epoch,
                slot_duration,
            } => {
                let consensus = match aura::next_slot_claim(aura::Config {
                    now_from_unix_epoch,
                    slot_duration,
                    current_authorities,
                    local_authorities,
                }) {
                    Some(c) => c,
                    None => return Builder::Idle,
                };

                debug_assert!(now_from_unix_epoch < consensus.slot_end_from_unix_epoch);
                let ready = now_from_unix_epoch >= consensus.slot_start_from_unix_epoch;

                (WaitSlotConsensus::Aura(consensus), ready)
            }
        };

        if ready {
            Builder::Ready(AuthoringStart { consensus: slot })
        } else {
            Builder::WaitSlot(WaitSlot { consensus: slot })
        }
    }
}

/// Current state of the block building process.
#[must_use]
pub enum BuilderAuthoring {
    /// Error happened during the generation.
    Error {
        /// Runtime of the parent block, as provided at initialization.
        parent_runtime: host::HostVmPrototype,
        /// The error in question.
        error: Error,
    },

    /// Block building is ready to accept extrinsics.
    ///
    /// If [`ApplyExtrinsic::add_extrinsic`] is used, then a
    /// [`BuilderAuthoring::ApplyExtrinsicResult`] stage will be emitted later.
    ///
    /// > **Note**: These extrinsics are generally coming from a transactions pool, but this is
    /// >           out of scope of this module.
    ApplyExtrinsic(ApplyExtrinsic),

    /// Result of the previous call to [`ApplyExtrinsic::add_extrinsic`].
    ///
    /// An [`ApplyExtrinsic`] object is provided in order to continue the operation.
    ApplyExtrinsicResult {
        /// Result of the previous call to [`ApplyExtrinsic::add_extrinsic`].
        result: Result<Result<(), runtime::DispatchError>, runtime::TransactionValidityError>,
        /// Object to use to continue trying to push other transactions or finish the block.
        resume: ApplyExtrinsic,
    },

    /// Loading a storage value from the parent storage is required in order to continue.
    StorageGet(StorageGet),

    /// Obtaining the Merkle value of the closest descendant of a trie node is required in order
    /// to continue.
    ClosestDescendantMerkleValue(ClosestDescendantMerkleValue),

    /// Fetching the key that follows a given one in the parent storage is required in order to
    /// continue.
    NextKey(NextKey),

    /// Setting the value of an offchain storage value is required.
    OffchainStorageSet(OffchainStorageSet),

    /// Block has been produced by the runtime and must now be sealed.
    Seal(Seal),
}

/// Block production is idle, waiting for a slot.
#[must_use]
#[derive(Debug)]
pub struct WaitSlot {
    consensus: WaitSlotConsensus,
}

#[derive(Debug)]
enum WaitSlotConsensus {
    Aura(aura::SlotClaim),
}

impl WaitSlot {
    /// Returns when block production can begin, as a UNIX timestamp (i.e. number of seconds since
    /// the UNIX epoch, ignoring leap seconds).
    pub fn when(&self) -> Duration {
        // TODO: we can actually start building the block before our slot in some situations?
        match self.consensus {
            WaitSlotConsensus::Aura(claim) => claim.slot_start_from_unix_epoch,
        }
    }

    /// Start the block production.
    ///
    /// Shouldn't be called before the timestamp returned by [`WaitSlot::when`]. Blocks that are
    /// authored and sent to other nodes before the proper timestamp will be considered as
    /// invalid.
    pub fn start(self) -> AuthoringStart {
        AuthoringStart {
            consensus: self.consensus,
        }
    }
}

/// Ready to start producing blocks.
pub struct AuthoringStart {
    consensus: WaitSlotConsensus,
}

impl AuthoringStart {
    /// Returns when the authoring slot start, as a UNIX timestamp (i.e. number of seconds since
    /// the UNIX epoch, ignoring leap seconds).
    pub fn slot_start_from_unix_epoch(&self) -> Duration {
        match self.consensus {
            WaitSlotConsensus::Aura(claim) => claim.slot_start_from_unix_epoch,
        }
    }

    /// Returns when the authoring slot ends, as a UNIX timestamp (i.e. number of seconds since
    /// the UNIX epoch, ignoring leap seconds).
    ///
    /// The block should finish being authored before the slot ends.
    /// However, in order for the network to perform smoothly, the block should have been
    /// authored **and** propagated throughout the entire peer-to-peer network before the slot
    /// ends.
    pub fn slot_end_from_unix_epoch(&self) -> Duration {
        match self.consensus {
            WaitSlotConsensus::Aura(claim) => claim.slot_end_from_unix_epoch,
        }
    }

    /// Start producing the block.
    pub fn start(self, config: AuthoringStartConfig) -> BuilderAuthoring {
        let inner_block_build = runtime::build_block(runtime::Config {
            block_number_bytes: config.block_number_bytes,
            parent_hash: config.parent_hash,
            parent_number: config.parent_number,
            parent_runtime: config.parent_runtime,
            block_body_capacity: config.block_body_capacity,
            consensus_digest_log_item: match self.consensus {
                WaitSlotConsensus::Aura(slot) => {
                    runtime::ConfigPreRuntime::Aura(header::AuraPreDigest {
                        slot_number: slot.slot_number,
                    })
                }
            },
            max_log_level: config.max_log_level,
            calculate_trie_changes: config.calculate_trie_changes,
        });

        let inherent_data = inherents::InherentData {
            timestamp: u64::try_from(config.now_from_unix_epoch.as_millis()).unwrap_or(u64::MAX),
        };

        (Shared {
            inherent_data: Some(inherent_data),
            slot_claim: self.consensus,
            block_number_bytes: config.block_number_bytes,
        })
        .with_runtime_inner(inner_block_build)
    }
}

/// Configuration to pass when the actual block authoring is started.
pub struct AuthoringStartConfig<'a> {
    /// Number of bytes used to encode block numbers in the header.
    pub block_number_bytes: usize,

    /// Hash of the parent of the block to generate.
    ///
    /// Used to populate the header of the new block.
    pub parent_hash: &'a [u8; 32],

    /// Height of the parent of the block to generate.
    ///
    /// Used to populate the header of the new block.
    pub parent_number: u64,

    /// Time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time) (i.e.
    /// 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    pub now_from_unix_epoch: Duration,

    /// Runtime used to check the new block. Must be built using the Wasm code found at the
    /// `:code` key of the parent block storage.
    pub parent_runtime: host::HostVmPrototype,

    /// Capacity to reserve for the number of extrinsics. Should be higher than the approximate
    /// number of extrinsics that are going to be applied.
    pub block_body_capacity: usize,

    /// Maximum log level of the runtime.
    ///
    /// > **Note**: This value is opaque from the point of the view of the client, and the runtime
    /// >           is free to interpret it the way it wants. However, usually values are: `0` for
    /// >           "off", `1` for "error", `2` for "warn", `3` for "info", `4` for "debug",
    /// >           and `5` for "trace".
    pub max_log_level: u32,

    /// If `true`, then [`StorageChanges::trie_changes_iter_ordered`] will return `Some`.
    /// Passing `None` requires fewer calculation and fewer storage accesses.
    pub calculate_trie_changes: bool,
}

/// More transactions can be added.
#[must_use]
pub struct ApplyExtrinsic {
    inner: runtime::ApplyExtrinsic,
    shared: Shared,
}

impl ApplyExtrinsic {
    /// Adds a SCALE-encoded extrinsic and resumes execution.
    ///
    /// See the module-level documentation for more information.
    pub fn add_extrinsic(self, extrinsic: Vec<u8>) -> BuilderAuthoring {
        self.shared
            .with_runtime_inner(self.inner.add_extrinsic(extrinsic))
    }

    /// Indicate that no more extrinsics will be added, and resume execution.
    pub fn finish(self) -> BuilderAuthoring {
        self.shared.with_runtime_inner(self.inner.finish())
    }
}

/// Loading a storage value from the parent storage is required in order to continue.
#[must_use]
pub struct StorageGet(runtime::StorageGet, Shared);

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.0.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        self.0.child_trie()
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(
        self,
        value: Option<(impl Iterator<Item = impl AsRef<[u8]>>, TrieEntryVersion)>,
    ) -> BuilderAuthoring {
        self.1.with_runtime_inner(self.0.inject_value(value))
    }
}

/// Obtaining the Merkle value of the closest descendant of a trie node is required in order
/// to continue.
#[must_use]
pub struct ClosestDescendantMerkleValue(runtime::ClosestDescendantMerkleValue, Shared);

impl ClosestDescendantMerkleValue {
    /// Returns the key whose closest descendant Merkle value must be passed to
    /// [`ClosestDescendantMerkleValue::inject_merkle_value`].
    pub fn key(&self) -> impl Iterator<Item = Nibble> {
        self.0.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        self.0.child_trie()
    }

    /// Indicate that the value is unknown and resume the calculation.
    ///
    /// This function be used if you are unaware of the Merkle value. The algorithm will perform
    /// the calculation of this Merkle value manually, which takes more time.
    pub fn resume_unknown(self) -> BuilderAuthoring {
        self.1.with_runtime_inner(self.0.resume_unknown())
    }

    /// Injects the corresponding Merkle value.
    ///
    /// `None` can be passed if there is no descendant or, in the case of a child trie read, in
    /// order to indicate that the child trie does not exist.
    pub fn inject_merkle_value(self, merkle_value: Option<&[u8]>) -> BuilderAuthoring {
        self.1
            .with_runtime_inner(self.0.inject_merkle_value(merkle_value))
    }
}

/// Fetching the key that follows a given one in the parent storage is required in order to
/// continue.
#[must_use]
pub struct NextKey(runtime::NextKey, Shared);

impl NextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&self) -> impl Iterator<Item = Nibble> {
        self.0.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&self) -> Option<impl AsRef<[u8]>> {
        self.0.child_trie()
    }

    /// If `true`, then the provided value must the one superior or equal to the requested key.
    /// If `false`, then the provided value must be strictly superior to the requested key.
    pub fn or_equal(&self) -> bool {
        self.0.or_equal()
    }

    /// If `true`, then the search must include both branch nodes and storage nodes. If `false`,
    /// the search only covers storage nodes.
    pub fn branch_nodes(&self) -> bool {
        self.0.branch_nodes()
    }

    /// Returns the prefix the next key must start with. If the next key doesn't start with the
    /// given prefix, then `None` should be provided.
    pub fn prefix(&self) -> impl Iterator<Item = Nibble> {
        self.0.prefix()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl Iterator<Item = Nibble>>) -> BuilderAuthoring {
        self.1.with_runtime_inner(self.0.inject_key(key))
    }
}

/// Setting the value of an offchain storage value is required.
#[must_use]
pub struct OffchainStorageSet(runtime::OffchainStorageSet, Shared);

impl OffchainStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&self) -> impl AsRef<[u8]> {
        self.0.key()
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&self) -> Option<impl AsRef<[u8]>> {
        self.0.value()
    }

    /// Resumes execution after having set the value.
    pub fn resume(self) -> BuilderAuthoring {
        self.1.with_runtime_inner(self.0.resume())
    }
}

/// Block has been produced and must now be sealed.
#[must_use]
pub struct Seal {
    shared: Shared,
    block: runtime::Success,
}

impl Seal {
    /// Returns the SCALE-encoded header whose hash must be signed.
    pub fn scale_encoded_header(&self) -> &[u8] {
        &self.block.scale_encoded_header
    }

    /// Returns the data to sign. This is the hash of the SCALE-encoded header of the block.
    pub fn to_sign(&self) -> [u8; 32] {
        header::hash_from_scale_encoded_header(&self.block.scale_encoded_header)
    }

    /// Returns the index within the list of authorities of the authority that must sign the
    /// block.
    ///
    /// See [`ConfigConsensus::Aura::local_authorities`].
    pub fn authority_index(&self) -> usize {
        match self.shared.slot_claim {
            WaitSlotConsensus::Aura(slot) => slot.local_authorities_index,
        }
    }

    /// Injects the Sr25519 signature of the hash of the SCALE-encoded header from the given
    /// authority.
    ///
    /// The method then returns the finished block.
    pub fn inject_sr25519_signature(mut self, signature: [u8; 64]) -> runtime::Success {
        let header = header::decode(
            &self.block.scale_encoded_header,
            self.shared.block_number_bytes,
        )
        .unwrap();

        self.block.scale_encoded_header = header
            .scale_encoding_with_extra_digest_item(
                self.shared.block_number_bytes,
                header::DigestItemRef::AuraSeal(&signature),
            )
            .fold(Vec::with_capacity(8192), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        self.block
    }
}

/// Error that can happen during the block production.
#[derive(Debug, derive_more::Display, derive_more::Error, derive_more::From)]
pub enum Error {
    /// Error while producing the block in the runtime.
    #[display("{_0}")]
    Runtime(runtime::Error),
    /// Runtime has generated an invalid block header.
    #[from(ignore)]
    InvalidHeaderGenerated,
}

/// Extra information maintained in all variants of the [`Builder`].
#[derive(Debug)]
struct Shared {
    /// Inherent data waiting to be injected. Will be extracted from its `Option` when the inner
    /// block builder requests it.
    inherent_data: Option<inherents::InherentData>,

    /// Number of bytes used to encode the block number in the header.
    block_number_bytes: usize,

    /// Slot that has been claimed.
    slot_claim: WaitSlotConsensus,
}

impl Shared {
    fn with_runtime_inner(mut self, mut inner: runtime::BlockBuild) -> BuilderAuthoring {
        loop {
            match inner {
                runtime::BlockBuild::Finished(Ok(block)) => {
                    // After the runtime has produced a block, the last step is to seal it.

                    // Verify the correctness of the header. If not, the runtime is misbehaving.
                    let decoded_header = match header::decode(
                        &block.scale_encoded_header,
                        self.block_number_bytes,
                    ) {
                        Ok(h) => h,
                        Err(_) => {
                            break BuilderAuthoring::Error {
                                parent_runtime: block.parent_runtime,
                                error: Error::InvalidHeaderGenerated,
                            };
                        }
                    };

                    // The `Seal` object created below assumes that there is no existing seal.
                    if decoded_header.digest.aura_seal().is_some()
                        || decoded_header.digest.babe_seal().is_some()
                    {
                        break BuilderAuthoring::Error {
                            parent_runtime: block.parent_runtime,
                            error: Error::InvalidHeaderGenerated,
                        };
                    }

                    break BuilderAuthoring::Seal(Seal {
                        shared: self,
                        block,
                    });
                }
                runtime::BlockBuild::Finished(Err((error, parent_runtime))) => {
                    break BuilderAuthoring::Error {
                        parent_runtime,
                        error: Error::Runtime(error),
                    };
                }
                runtime::BlockBuild::InherentExtrinsics(a) => {
                    // Injecting the inherent is guaranteed to be done only once per block.
                    inner = a.inject_inherents(self.inherent_data.take().unwrap());
                }
                runtime::BlockBuild::ApplyExtrinsic(a) => {
                    inner = a.finish();
                }
                runtime::BlockBuild::ApplyExtrinsicResult { result, resume } => {
                    break BuilderAuthoring::ApplyExtrinsicResult {
                        result,
                        resume: ApplyExtrinsic {
                            inner: resume,
                            shared: self,
                        },
                    };
                }
                runtime::BlockBuild::StorageGet(inner) => {
                    break BuilderAuthoring::StorageGet(StorageGet(inner, self));
                }
                runtime::BlockBuild::ClosestDescendantMerkleValue(inner) => {
                    break BuilderAuthoring::ClosestDescendantMerkleValue(
                        ClosestDescendantMerkleValue(inner, self),
                    );
                }
                runtime::BlockBuild::NextKey(inner) => {
                    break BuilderAuthoring::NextKey(NextKey(inner, self));
                }
                runtime::BlockBuild::OffchainStorageSet(inner) => {
                    break BuilderAuthoring::OffchainStorageSet(OffchainStorageSet(inner, self));
                }
            }
        }
    }
}
