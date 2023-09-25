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
    executor::{self, host, runtime_host, vm},
    header, util,
    verify::{aura, babe, inherents},
};

use alloc::{string::String, vec::Vec};
use core::{iter, num::NonZeroU64, time::Duration};

pub use runtime_host::{
    Nibble, StorageChanges, TrieChange, TrieChangeStorageValue, TrieEntryVersion,
};

/// Configuration for a block verification.
pub struct Config<'a, TBody> {
    /// Runtime used to check the new block. Must be built using the `:code` of the parent
    /// block.
    pub parent_runtime: host::HostVmPrototype,

    /// Header of the parent of the block to verify.
    ///
    /// The hash of this header must be the one referenced in [`Config::block_header`].
    pub parent_block_header: header::HeaderRef<'a>,

    /// Time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time) (i.e.
    /// 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    pub now_from_unix_epoch: Duration,

    /// Header of the block to verify.
    ///
    /// The `parent_hash` field is the hash of the parent whose storage can be accessed through
    /// the other fields.
    pub block_header: header::HeaderRef<'a>,

    /// Number of bytes used to encode the block number in the header.
    pub block_number_bytes: usize,

    /// Body of the block to verify.
    pub block_body: TBody,

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
        slot_duration: NonZeroU64,
    },

    /// Chain is using the Babe consensus engine.
    Babe {
        /// Number of slots per epoch in the Babe configuration.
        slots_per_epoch: NonZeroU64,

        /// Epoch the parent block belongs to. Must be `None` if and only if the parent block's
        /// number is 0, as block #0 doesn't belong to any epoch.
        parent_block_epoch: Option<chain_information::BabeEpochInformationRef<'a>>,

        /// Epoch that follows the epoch the parent block belongs to.
        parent_block_next_epoch: chain_information::BabeEpochInformationRef<'a>,
    },
}

/// Block successfully verified.
pub struct Success {
    /// Runtime that was passed by [`Config`].
    pub parent_runtime: host::HostVmPrototype,

    /// Contains `Some` if and only if [`Success::storage_changes`] contains a change in
    /// the `:code` or `:heappages` keys, indicating that the runtime has been modified. Contains
    /// the new runtime.
    pub new_runtime: Option<host::HostVmPrototype>,

    /// List of changes to the storage main trie that the block performs.
    pub storage_changes: StorageChanges,

    /// State trie version indicated by the runtime. All the storage changes indicated by
    /// [`Success::storage_changes`] should store this version alongside with them.
    pub state_trie_version: TrieEntryVersion,

    /// Concatenation of all the log messages printed by the runtime.
    pub logs: String,
}

/// Extra items in [`Success`] relevant to the consensus engine.
pub enum SuccessConsensus {
    /// Chain is using the Aura consensus engine.
    Aura {
        /// True if the list of authorities is modified by this block.
        authorities_change: bool,
    },

    /// Chain is using the Babe consensus engine.
    Babe {
        /// Slot number the block belongs to.
        ///
        /// > **Note**: This is a simple reminder. The value can also be found in the header of the
        /// >           block.
        slot_number: u64,

        /// If `Some`, the verified block contains an epoch transition describing the new
        /// "next epoch". When verifying blocks that are children of this one, the value in this
        /// field must be provided as [`ConfigConsensus::Babe::parent_block_next_epoch`], and the
        /// value previously in [`ConfigConsensus::Babe::parent_block_next_epoch`] must instead be
        /// passed as [`ConfigConsensus::Babe::parent_block_epoch`].
        epoch_transition_target: Option<chain_information::BabeEpochInformation>,
    },
}

/// Error that can happen during the verification.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Error while starting the Wasm virtual machine to execute the block.
    #[display(fmt = "{_0}")]
    WasmStart(host::StartErr),
    /// Error while running the Wasm virtual machine to execute the block.
    #[display(fmt = "{_0}")]
    WasmVm(runtime_host::ErrorDetail),
    /// Runtime has returned some errors when verifying inherents.
    #[display(fmt = "Runtime has returned some errors when verifying inherents: {errors:?}")]
    CheckInherentsError {
        /// List of errors produced by the runtime.
        ///
        /// The first element of each tuple is an identifier of the module that produced the
        /// error, while the second element is a SCALE-encoded piece of data.
        ///
        /// Due to the fact that errors are not supposed to happen, and that the format of errors
        /// has changed depending on runtime versions, no utility is provided to decode them.
        errors: Vec<([u8; 8], Vec<u8>)>,
    },
    /// Failed to parse the output of `BlockBuilder_check_inherents`.
    CheckInherentsOutputParseFailure,
    /// Output of `Core_execute_block` wasn't empty.
    NonEmptyOutput,
    /// Block header contains items relevant to multiple consensus engines at the same time.
    MultipleConsensusEngines,
    /// Block header contains an unrecognized consensus engine.
    #[display(fmt = "Block header contains an unrecognized consensus engine: {engine:?}")]
    UnknownConsensusEngine { engine: [u8; 4] },
    /// Failed to verify the authenticity of the block with the AURA algorithm.
    #[display(fmt = "{_0}")]
    AuraVerification(aura::VerifyError),
    /// Failed to verify the authenticity of the block with the BABE algorithm.
    #[display(fmt = "{_0}")]
    BabeVerification(babe::VerifyError),
    /// Error while compiling new runtime.
    NewRuntimeCompilationError(host::NewErr),
    /// Block being verified has erased the `:code` key from the storage.
    CodeKeyErased,
    /// Parent storage has an empty `:code` key.
    ///
    /// > **Note**: This indicates that the parent block is invalid. This error is likely caused
    /// >           by some kind of internal error or failed assumption somewhere in the API user's
    /// >           code.
    #[display(fmt = "Parent storage has an empty `:code` key")]
    ParentCodeEmpty,
    /// Block has modified the `:heappages` key in a way that fails to parse.
    #[display(fmt = "Block has modified `:heappages` key in invalid way: {_0}")]
    HeapPagesParseError(executor::InvalidHeapPagesError),
    /// Runtime called a forbidden host function.
    ForbiddenHostCall,
}

/// Verifies whether a block body is valid.
pub fn verify(
    config: Config<impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone>,
) -> Verify {
    // We need to call two runtime functions:
    //
    // - `BlockBuilder_check_inherents`, which does some basic verification of the inherents
    //   contained in the block.
    // - `Core_execute_block`, which goes through transactions and makes sure that everything is
    //   valid.
    //
    // The first parameter of these two runtime functions is the same: a SCALE-encoded
    // `(header, body)` where `body` is a `Vec<Extrinsic>`. We perform the encoding ahead of time
    // in order to re-use it later for the second call.
    let execute_block_parameters = {
        // Consensus engines add a seal at the end of the digest logs. This seal is guaranteed to
        // be the last item. We need to remove it before we can verify the unsealed header.
        let mut unsealed_header = config.block_header.clone();
        let _seal_log = unsealed_header.digest.pop_seal();

        let encoded_body_len = util::encode_scale_compact_usize(config.block_body.len());
        unsealed_header
            .scale_encoding(config.block_number_bytes)
            .map(|b| either::Right(either::Left(b)))
            .chain(iter::once(either::Right(either::Right(encoded_body_len))))
            .chain(config.block_body.map(either::Left))
            .fold(Vec::with_capacity(8192), |mut a, b| {
                // TODO: better capacity ^ ?
                a.extend_from_slice(AsRef::<[u8]>::as_ref(&b));
                a
            })
    };

    // Start the virtual machine with `BlockBuilder_check_inherents`.
    let check_inherents_process = {
        // The second parameter of `BlockBuilder_check_inherents` contains information such as
        // the current timestamp.
        let inherent_data = inherents::InherentData {
            timestamp: u64::try_from(config.now_from_unix_epoch.as_millis())
                .unwrap_or(u64::max_value()),
        };

        let vm = runtime_host::run(runtime_host::Config {
            virtual_machine: config.parent_runtime,
            function_to_call: "BlockBuilder_check_inherents",
            parameter: {
                // The `BlockBuilder_check_inherents` function expects a SCALE-encoded list of
                // tuples containing an "inherent identifier" (`[u8; 8]`) and a value (`Vec<u8>`).
                let list = inherent_data.as_raw_list();
                let len = util::encode_scale_compact_usize(list.len());
                let encoded_list = list.flat_map(|(id, value)| {
                    let value_len = util::encode_scale_compact_usize(value.as_ref().len());
                    let value_and_len = iter::once(value_len)
                        .map(either::Left)
                        .chain(iter::once(value).map(either::Right));
                    iter::once(id)
                        .map(either::Left)
                        .chain(value_and_len.map(either::Right))
                });

                [either::Left(&execute_block_parameters), either::Right(len)]
                    .into_iter()
                    .map(either::Left)
                    .chain(encoded_list.map(either::Right))
            },
            storage_main_trie_changes: Default::default(),
            max_log_level: config.max_log_level,
            // Calculating the trie changes is done at the next step.
            calculate_trie_changes: false,
        });

        match vm {
            Ok(vm) => vm,
            Err((error, prototype)) => {
                return Verify::Finished(Err((Error::WasmStart(error), prototype)))
            }
        }
    };

    VerifyInner {
        inner: check_inherents_process,
        phase: VerifyInnerPhase::CheckInherents {
            execute_block_parameters,
        },
        calculate_trie_changes: config.calculate_trie_changes,
    }
    .run()
}

/// Current state of the verification.
#[must_use]
pub enum Verify {
    /// Verification is over.
    ///
    /// In case of error, also contains the value that was passed through
    /// [`Config::parent_runtime`].
    Finished(Result<Success, (Error, host::HostVmPrototype)>),
    /// A new runtime must be compiled.
    ///
    /// This variant doesn't require any specific input from the user, but is provided in order to
    /// make it possible to benchmark the time it takes to compile runtimes.
    RuntimeCompilation(RuntimeCompilation),
    /// Loading a storage value is required in order to continue.
    StorageGet(StorageGet),
    /// Obtaining the Merkle value of the closest descendant of a trie node is required in order
    /// to continue.
    StorageClosestDescendantMerkleValue(StorageClosestDescendantMerkleValue),
    /// Fetching the key that follows a given one is required in order to continue.
    StorageNextKey(StorageNextKey),
    /// Setting the value of an offchain storage value is required.
    OffchainStorageSet(OffchainStorageSet),
}

struct VerifyInner {
    inner: runtime_host::RuntimeHostVm,
    phase: VerifyInnerPhase,
    calculate_trie_changes: bool,
}

enum VerifyInnerPhase {
    CheckInherents {
        /// Parameter to later pass when invoking `Core_execute_block`.
        execute_block_parameters: Vec<u8>,
    },
    ExecuteBlock {
        /// If the block modifies the `:heappages` but not the `:code`, we will need to fetch the
        /// parent's `:code` in order to compile the new runtime. If that is the case, it will
        /// be stored here.
        parent_code: Option<Option<Vec<u8>>>,
    },
}

impl VerifyInner {
    fn run(mut self) -> Verify {
        loop {
            match (self.inner, self.phase) {
                (runtime_host::RuntimeHostVm::Finished(Err(err)), _) => {
                    break Verify::Finished(Err((Error::WasmVm(err.detail), err.prototype)))
                }
                (
                    runtime_host::RuntimeHostVm::Finished(Ok(success)),
                    VerifyInnerPhase::CheckInherents {
                        execute_block_parameters,
                    },
                ) => {
                    // Check the output of the `BlockBuilder_check_inherents` runtime call.
                    let check_inherents_result =
                        check_check_inherents_output(success.virtual_machine.value().as_ref());
                    if let Err(err) = check_inherents_result {
                        return Verify::Finished(Err((
                            err,
                            success.virtual_machine.into_prototype(),
                        )));
                    }

                    // Switch to phase 2: calling `Core_execute_block`.
                    let import_process = {
                        let vm = runtime_host::run(runtime_host::Config {
                            virtual_machine: success.virtual_machine.into_prototype(),
                            function_to_call: "Core_execute_block",
                            parameter: iter::once(&execute_block_parameters),
                            storage_main_trie_changes: success
                                .storage_changes
                                .into_main_trie_diff(),
                            max_log_level: 0,
                            calculate_trie_changes: self.calculate_trie_changes,
                        });

                        match vm {
                            Ok(vm) => vm,
                            Err((error, prototype)) => {
                                return Verify::Finished(Err((Error::WasmStart(error), prototype)))
                            }
                        }
                    };

                    self = VerifyInner {
                        phase: VerifyInnerPhase::ExecuteBlock { parent_code: None },
                        inner: import_process,
                        calculate_trie_changes: self.calculate_trie_changes,
                    };
                }

                (
                    runtime_host::RuntimeHostVm::Finished(Ok(success)),
                    VerifyInnerPhase::ExecuteBlock { parent_code },
                ) => {
                    if !success.virtual_machine.value().as_ref().is_empty() {
                        return Verify::Finished(Err((
                            Error::NonEmptyOutput,
                            success.virtual_machine.into_prototype(),
                        )));
                    }

                    match (
                        success.storage_changes.main_trie_diff_get(&b":code"[..]),
                        parent_code,
                        success
                            .storage_changes
                            .main_trie_diff_get(&b":heappages"[..]),
                    ) {
                        (None, _, None) => {}
                        (Some(None), _, _) => {
                            return Verify::Finished(Err((
                                Error::CodeKeyErased,
                                success.virtual_machine.into_prototype(),
                            )))
                        }
                        (None, None, Some(_)) => {
                            break Verify::StorageGet(StorageGet {
                                inner: StorageGetInner::ParentCode {
                                    success,
                                    calculate_trie_changes: self.calculate_trie_changes,
                                },
                            })
                        }
                        (None, Some(None), _) => {
                            return Verify::Finished(Err((
                                Error::ParentCodeEmpty,
                                success.virtual_machine.into_prototype(),
                            )))
                        }
                        (Some(Some(_)), parent_code, heap_pages)
                        | (_, parent_code @ Some(Some(_)), heap_pages) => {
                            let parent_runtime = success.virtual_machine.into_prototype();

                            let heap_pages = match heap_pages {
                                Some(heap_pages) => {
                                    match executor::storage_heap_pages_to_value(heap_pages) {
                                        Ok(hp) => hp,
                                        Err(err) => {
                                            return Verify::Finished(Err((
                                                Error::HeapPagesParseError(err),
                                                parent_runtime,
                                            )))
                                        }
                                    }
                                }
                                None => parent_runtime.heap_pages(),
                            };

                            return Verify::RuntimeCompilation(RuntimeCompilation {
                                parent_runtime,
                                heap_pages,
                                parent_code,
                                logs: success.logs,
                                storage_changes: success.storage_changes,
                                state_trie_version: success.state_trie_version,
                            });
                        }
                    }

                    break Verify::Finished(Ok(Success {
                        parent_runtime: success.virtual_machine.into_prototype(),
                        new_runtime: None,
                        storage_changes: success.storage_changes,
                        state_trie_version: success.state_trie_version,
                        logs: success.logs,
                    }));
                }

                (runtime_host::RuntimeHostVm::StorageGet(inner), phase) => {
                    break Verify::StorageGet(StorageGet {
                        inner: StorageGetInner::Execution {
                            inner,
                            phase,
                            calculate_trie_changes: self.calculate_trie_changes,
                        },
                    })
                }
                (runtime_host::RuntimeHostVm::ClosestDescendantMerkleValue(inner), phase) => {
                    break Verify::StorageClosestDescendantMerkleValue(
                        StorageClosestDescendantMerkleValue {
                            inner,
                            phase,
                            calculate_trie_changes: self.calculate_trie_changes,
                        },
                    )
                }
                (runtime_host::RuntimeHostVm::NextKey(inner), phase) => {
                    break Verify::StorageNextKey(StorageNextKey {
                        inner,
                        phase,
                        calculate_trie_changes: self.calculate_trie_changes,
                    })
                }
                (runtime_host::RuntimeHostVm::OffchainStorageSet(inner), phase) => {
                    break Verify::OffchainStorageSet(OffchainStorageSet {
                        inner,
                        phase,
                        calculate_trie_changes: self.calculate_trie_changes,
                    })
                }
                (runtime_host::RuntimeHostVm::SignatureVerification(sig), phase) => {
                    self.inner = sig.verify_and_resume();
                    self.phase = phase;
                }
                (runtime_host::RuntimeHostVm::Offchain(ctx), _phase) => {
                    return Verify::Finished(Err((Error::ForbiddenHostCall, ctx.into_prototype())))
                }
            }
        }
    }
}

/// Loading a storage value is required in order to continue.
#[must_use]
pub struct StorageGet {
    inner: StorageGetInner,
}

enum StorageGetInner {
    Execution {
        inner: runtime_host::StorageGet,
        /// See [`VerifyInner::phase`].
        phase: VerifyInnerPhase,
        calculate_trie_changes: bool,
    },
    ParentCode {
        success: runtime_host::Success,
        calculate_trie_changes: bool,
    },
}

impl StorageGet {
    /// Returns the key whose value must be passed to [`StorageGet::inject_value`].
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        match &self.inner {
            StorageGetInner::Execution { inner, .. } => either::Left(inner.key()),
            StorageGetInner::ParentCode { .. } => either::Right(b":code"),
        }
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&'_ self) -> Option<impl AsRef<[u8]> + '_> {
        match &self.inner {
            StorageGetInner::Execution { inner, .. } => inner.child_trie(),
            StorageGetInner::ParentCode { .. } => None,
        }
    }

    /// Injects the corresponding storage value.
    pub fn inject_value(
        self,
        value: Option<(impl Iterator<Item = impl AsRef<[u8]>>, TrieEntryVersion)>,
    ) -> Verify {
        match self.inner {
            StorageGetInner::Execution {
                inner,
                phase,
                calculate_trie_changes,
            } => VerifyInner {
                inner: inner.inject_value(value),
                phase,
                calculate_trie_changes,
            }
            .run(),
            StorageGetInner::ParentCode {
                success,
                calculate_trie_changes,
            } => VerifyInner {
                inner: runtime_host::RuntimeHostVm::Finished(Ok(success)),
                phase: VerifyInnerPhase::ExecuteBlock {
                    parent_code: Some(value.map(|(val_iter, _)| {
                        val_iter.fold(Vec::new(), |mut a, b| {
                            a.extend_from_slice(b.as_ref());
                            a
                        })
                    })),
                },
                calculate_trie_changes,
            }
            .run(),
        }
    }
}

/// Obtaining the Merkle value of the closest descendant of a trie node is required in order
/// to continue.
#[must_use]
pub struct StorageClosestDescendantMerkleValue {
    inner: runtime_host::ClosestDescendantMerkleValue,
    /// See [`VerifyInner::phase`].
    phase: VerifyInnerPhase,
    calculate_trie_changes: bool,
}

impl StorageClosestDescendantMerkleValue {
    /// Returns the key whose closest descendant Merkle value must be passed back.
    pub fn key(&'_ self) -> impl Iterator<Item = Nibble> + '_ {
        self.inner.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&'_ self) -> Option<impl AsRef<[u8]> + '_> {
        self.inner.child_trie()
    }

    /// Indicate that the value is unknown and resume the calculation.
    ///
    /// This function be used if you are unaware of the Merkle value. The algorithm will perform
    /// the calculation of this Merkle value manually, which takes more time.
    pub fn resume_unknown(self) -> Verify {
        VerifyInner {
            inner: self.inner.resume_unknown(),
            phase: self.phase,
            calculate_trie_changes: self.calculate_trie_changes,
        }
        .run()
    }

    /// Injects the corresponding Merkle value.
    ///
    /// `None` can be passed if there is no descendant or, in the case of a child trie read, in
    /// order to indicate that the child trie does not exist.
    pub fn inject_merkle_value(self, merkle_value: Option<&[u8]>) -> Verify {
        VerifyInner {
            inner: self.inner.inject_merkle_value(merkle_value),
            phase: self.phase,
            calculate_trie_changes: self.calculate_trie_changes,
        }
        .run()
    }
}

/// Fetching the key that follows a given one is required in order to continue.
#[must_use]
pub struct StorageNextKey {
    inner: runtime_host::NextKey,
    /// See [`VerifyInner::phase`].
    phase: VerifyInnerPhase,
    calculate_trie_changes: bool,
}

impl StorageNextKey {
    /// Returns the key whose next key must be passed back.
    pub fn key(&'_ self) -> impl Iterator<Item = Nibble> + '_ {
        self.inner.key()
    }

    /// If `Some`, read from the given child trie. If `None`, read from the main trie.
    pub fn child_trie(&'_ self) -> Option<impl AsRef<[u8]> + '_> {
        self.inner.child_trie()
    }

    /// If `true`, then the provided value must the one superior or equal to the requested key.
    /// If `false`, then the provided value must be strictly superior to the requested key.
    pub fn or_equal(&self) -> bool {
        self.inner.or_equal()
    }

    /// If `true`, then the search must include both branch nodes and storage nodes. If `false`,
    /// the search only covers storage nodes.
    pub fn branch_nodes(&self) -> bool {
        self.inner.branch_nodes()
    }

    /// Returns the prefix the next key must start with. If the next key doesn't start with the
    /// given prefix, then `None` should be provided.
    pub fn prefix(&'_ self) -> impl Iterator<Item = Nibble> + '_ {
        self.inner.prefix()
    }

    /// Injects the key.
    ///
    /// # Panic
    ///
    /// Panics if the key passed as parameter isn't strictly superior to the requested key.
    ///
    pub fn inject_key(self, key: Option<impl Iterator<Item = Nibble>>) -> Verify {
        VerifyInner {
            inner: self.inner.inject_key(key),
            phase: self.phase,
            calculate_trie_changes: self.calculate_trie_changes,
        }
        .run()
    }
}

/// Setting the value of an offchain storage value is required.
#[must_use]
pub struct OffchainStorageSet {
    inner: runtime_host::OffchainStorageSet,
    /// See [`VerifyInner::phase`].
    phase: VerifyInnerPhase,
    calculate_trie_changes: bool,
}

impl OffchainStorageSet {
    /// Returns the key whose value must be set.
    pub fn key(&'_ self) -> impl AsRef<[u8]> + '_ {
        self.inner.key()
    }

    /// Returns the value to set.
    ///
    /// If `None` is returned, the key should be removed from the storage entirely.
    pub fn value(&'_ self) -> Option<impl AsRef<[u8]> + '_> {
        self.inner.value()
    }

    /// Resumes execution after having set the value.
    pub fn resume(self) -> Verify {
        VerifyInner {
            inner: self.inner.resume(),
            phase: self.phase,
            calculate_trie_changes: self.calculate_trie_changes,
        }
        .run()
    }
}

/// A new runtime must be compiled.
///
/// This variant doesn't require any specific input from the user, but is provided in order to
/// make it possible to benchmark the time it takes to compile runtimes.
#[must_use]
pub struct RuntimeCompilation {
    parent_runtime: host::HostVmPrototype,
    storage_changes: StorageChanges,
    state_trie_version: TrieEntryVersion,
    logs: String,
    heap_pages: vm::HeapPages,
    parent_code: Option<Option<Vec<u8>>>,
}

impl RuntimeCompilation {
    /// Performs the runtime compilation.
    pub fn build(self) -> Verify {
        // A `RuntimeCompilation` object is built only if `:code` is available.
        let code = self
            .storage_changes
            .main_trie_diff_get(&b":code"[..])
            .or(self.parent_code.as_ref().map(|v| v.as_deref()))
            .unwrap()
            .unwrap();

        let new_runtime = match host::HostVmPrototype::new(host::Config {
            module: code,
            heap_pages: self.heap_pages,
            exec_hint: vm::ExecHint::CompileAheadOfTime,
            allow_unresolved_imports: false,
        }) {
            Ok(vm) => vm,
            Err(err) => {
                return Verify::Finished(Err((
                    Error::NewRuntimeCompilationError(err),
                    self.parent_runtime,
                )))
            }
        };

        Verify::Finished(Ok(Success {
            parent_runtime: self.parent_runtime,
            new_runtime: Some(new_runtime),
            storage_changes: self.storage_changes,
            state_trie_version: self.state_trie_version,
            logs: self.logs,
        }))
    }
}

/// Checks the output of the `BlockBuilder_check_inherents` runtime call.
fn check_check_inherents_output(output: &[u8]) -> Result<(), Error> {
    // The format of the output of `check_inherents` consists of two booleans and a list of
    // errors.
    // We don't care about the value of the two booleans, and they are ignored during the parsing.
    // Because we don't pass as parameter the `auraslot` or `babeslot`, errors will be generated
    // on older runtimes that expect these values. For this reason, errors concerning `auraslot`
    // and `babeslot` are ignored.
    let parser = nom::sequence::preceded(
        nom::sequence::tuple((crate::util::nom_bool_decode, crate::util::nom_bool_decode)),
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
            nom::multi::fold_many_m_n(
                num_elems,
                num_elems,
                nom::sequence::tuple((
                    nom::combinator::map(nom::bytes::streaming::take(8u8), |b| {
                        <[u8; 8]>::try_from(b).unwrap()
                    }),
                    crate::util::nom_bytes_decode,
                )),
                Vec::new,
                |mut errors, (module, error)| {
                    if module != *b"auraslot" && module != *b"babeslot" {
                        errors.push((module, error.to_vec()));
                    }
                    errors
                },
            )
        }),
    );

    match nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(parser)(output) {
        Err(_err) => Err(Error::CheckInherentsOutputParseFailure),
        Ok((_, errors)) => {
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Error::CheckInherentsError { errors })
            }
        }
    }
}
