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

//! Substrate chain configuration.
//!
//! A **chain spec** (short for *chain specification*) is the description of everything that is
//! required for the client to successfully interact with a certain blockchain.
//! For example, the Polkadot chain spec contains all the constants that are needed in order to
//! successfully interact with Polkadot.
//!
//! Chain specs contain, notably:
//!
//! - The state of the genesis block. In other words, the initial content of the database. This
//! includes the Wasm runtime code of the genesis block.
//! - The list of bootstrap nodes. These are the IP addresses of the machines we need to connect
//! to.
//! - The default telemetry endpoints, to which we should send telemetry information to.
//! - The name of the network protocol, in order to avoid accidentally connecting to a different
//! network.
//! - Multiple other miscellaneous information.
//!

use crate::{
    chain::chain_information::{
        BabeEpochInformation, ChainInformation, ChainInformationConsensus,
        ChainInformationFinality, ValidChainInformation, ValidityError, build,
    },
    executor, libp2p, trie,
};

use alloc::{
    boxed::Box,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{iter, num::NonZero, ops::Bound};

mod light_sync_state;
mod structs;
mod tests;

/// A configuration of a chain. Can be used to build a genesis block.
#[derive(Clone)]
pub struct ChainSpec {
    client_spec: structs::ClientSpec,
}

impl ChainSpec {
    /// Parse JSON content into a [`ChainSpec`].
    pub fn from_json_bytes(json: impl AsRef<[u8]>) -> Result<Self, ParseError> {
        let client_spec: structs::ClientSpec = serde_json::from_slice(json.as_ref())
            .map_err(ParseErrorInner::Serde)
            .map_err(ParseError)?;

        // TODO: we don't support child tries in the genesis block
        assert!(match &client_spec.genesis {
            structs::Genesis::Raw(genesis) => genesis.children_default.is_empty(),
            structs::Genesis::StateRootHash(_) => true,
        });

        if client_spec.relay_chain.is_some() != client_spec.para_id.is_some() {
            return Err(ParseError(ParseErrorInner::Other));
        }

        // Make sure that the light sync state can be successfully decoded.
        if let Some(light_sync_state) = &client_spec.light_sync_state {
            // TODO: this "4" constant is repeated
            light_sync_state.decode(client_spec.block_number_bytes.unwrap_or(4).into())?;
        }

        Ok(ChainSpec { client_spec })
    }

    /// Turns this chain specification into a JSON document representing it.
    pub fn serialize(&self) -> String {
        // Can only panic in case of a bug in this module.
        serde_json::to_string_pretty(&self.client_spec).unwrap()
    }

    /// Builds the [`ChainInformation`] corresponding to the genesis block contained in this chain
    /// spec.
    ///
    /// In addition to the information, also returns the virtual machine of the runtime of the
    /// genesis block.
    pub fn to_chain_information(
        &self,
    ) -> Result<(ValidChainInformation, executor::host::HostVmPrototype), FromGenesisStorageError>
    {
        let genesis_storage = match self.genesis_storage() {
            GenesisStorage::Items(items) => items,
            GenesisStorage::TrieRootHash(_) => {
                return Err(FromGenesisStorageError::UnknownStorageItems);
            }
        };

        let wasm_code = genesis_storage
            .value(b":code")
            .ok_or(FromGenesisStorageError::RuntimeNotFound)?;
        let heap_pages =
            executor::storage_heap_pages_to_value(genesis_storage.value(b":heappages"))
                .map_err(FromGenesisStorageError::HeapPagesDecode)?;
        let vm_prototype = executor::host::HostVmPrototype::new(executor::host::Config {
            module: &wasm_code,
            heap_pages,
            exec_hint: executor::vm::ExecHint::ValidateAndExecuteOnce,
            allow_unresolved_imports: true,
        })
        .map_err(FromGenesisStorageError::VmInitialization)?;

        let state_version = vm_prototype
            .runtime_version()
            .decode()
            .state_version
            .unwrap_or(trie::TrieEntryVersion::V0);

        let mut chain_information_build = build::ChainInformationBuild::new(build::Config {
            finalized_block_header: build::ConfigFinalizedBlockHeader::Genesis {
                state_trie_root_hash: {
                    match self.genesis_storage() {
                        GenesisStorage::TrieRootHash(hash) => *hash,
                        GenesisStorage::Items(genesis_storage) => {
                            let mut calculation =
                                trie::calculate_root::root_merkle_value(trie::HashFunction::Blake2);

                            loop {
                                match calculation {
                                    trie::calculate_root::RootMerkleValueCalculation::Finished {
                                        hash,
                                        ..
                                    } => break hash,
                                    trie::calculate_root::RootMerkleValueCalculation::NextKey(next_key) => {
                                        // TODO: borrowchecker erroneously thinks that `outcome` borrows `next_key`
                                        let outcome = genesis_storage.next_key(next_key.key_before(), next_key.or_equal(), next_key.prefix()).map(|k| k.collect::<Vec<_>>().into_iter());
                                        calculation = next_key.inject_key(outcome);
                                    }
                                    trie::calculate_root::RootMerkleValueCalculation::StorageValue(
                                        val,
                                    ) => {
                                        let key: alloc::vec::Vec<u8> = val.key().collect();
                                        let value = genesis_storage.value(&key[..]);
                                        calculation = val.inject(value.map(move |v| (v, state_version)));
                                    }
                                }
                            }
                        }
                    }
                },
            },
            block_number_bytes: usize::from(self.block_number_bytes()),
            runtime: vm_prototype,
        });

        let (chain_info, vm_prototype) = loop {
            match chain_information_build {
                build::ChainInformationBuild::InProgress(build::InProgress::StorageGet(get)) => {
                    // TODO: child tries not supported
                    let value = genesis_storage.value(get.key().as_ref());
                    chain_information_build =
                        get.inject_value(value.map(|v| (iter::once(v), state_version)));
                }
                build::ChainInformationBuild::InProgress(build::InProgress::NextKey(_nk)) => {
                    todo!() // TODO:
                }
                build::ChainInformationBuild::InProgress(
                    build::InProgress::ClosestDescendantMerkleValue(_mv),
                ) => {
                    todo!() // TODO:
                }
                build::ChainInformationBuild::Finished {
                    result: Err(err), ..
                } => {
                    return Err(FromGenesisStorageError::BuildChainInformation(err));
                }
                build::ChainInformationBuild::Finished {
                    result: Ok(chain_info),
                    virtual_machine,
                } => {
                    break (chain_info, virtual_machine);
                }
            }
        };

        Ok((chain_info, vm_prototype))
    }

    /// Returns the name of the chain. Meant to be displayed to the user.
    pub fn name(&self) -> &str {
        &self.client_spec.name
    }

    /// Returns the identifier of the chain. Similar to the name, but a bit more "system-looking".
    /// For example, if the name is "Flaming Fir 7", then the id could be `flamingfir7`. To be
    /// used for example in file system paths.
    pub fn id(&self) -> &str {
        &self.client_spec.id
    }

    /// Returns a string indicating the type of chain.
    ///
    /// This value doesn't have any meaning in the absolute and is only meant to be shown to
    /// the user.
    pub fn chain_type(&self) -> &str {
        match &self.client_spec.chain_type {
            structs::ChainType::Development => "Development",
            structs::ChainType::Local => "Local",
            structs::ChainType::Live => "Live",
            structs::ChainType::Custom(ty) => ty,
        }
    }

    /// Returns the number of bytes that the "block number" field of various data structures uses.
    pub fn block_number_bytes(&self) -> u8 {
        self.client_spec.block_number_bytes.unwrap_or(4)
    }

    /// Returns true if the chain is of a type for which a live network is expected.
    pub fn has_live_network(&self) -> bool {
        match &self.client_spec.chain_type {
            structs::ChainType::Development | structs::ChainType::Custom(_) => false,
            structs::ChainType::Local | structs::ChainType::Live => true,
        }
    }

    /// Returns a list of hashes of block headers that should always be considered as invalid.
    pub fn bad_blocks_hashes(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.client_spec
            .bad_blocks
            .as_ref()
            .into_iter()
            .flat_map(|l| l.iter())
            .map(|h| &h.0)
    }

    /// Returns the list of bootnode addresses found in the chain spec.
    ///
    /// Bootnode addresses that have failed to be parsed are returned as well in the form of
    /// a [`Bootnode::UnrecognizedFormat`].
    pub fn boot_nodes(&self) -> impl ExactSizeIterator<Item = Bootnode> {
        // Note that we intentionally don't expose types found in the `libp2p` module in order to
        // not tie the code that parses chain specifications to the libp2p code.
        self.client_spec.boot_nodes.iter().map(|unparsed| {
            if let Ok(mut addr) = unparsed.parse::<libp2p::Multiaddr>() {
                if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
                    if let Ok(peer_id) =
                        libp2p::peer_id::PeerId::from_bytes(peer_id.into_bytes().to_vec())
                    {
                        addr.pop();
                        return Bootnode::Parsed {
                            multiaddr: addr.to_string(),
                            peer_id: peer_id.into_bytes(),
                        };
                    }
                }
            }

            Bootnode::UnrecognizedFormat(unparsed)
        })
    }

    /// Returns the list of libp2p multiaddresses of the default telemetry servers of the chain.
    // TODO: more strongly typed?
    pub fn telemetry_endpoints(&self) -> impl Iterator<Item = impl AsRef<str>> {
        self.client_spec
            .telemetry_endpoints
            .as_ref()
            .into_iter()
            .flat_map(|ep| ep.iter().map(|e| &e.0))
    }

    /// Returns the network protocol id that uniquely identifies a chain. Used to prevent nodes
    /// from different blockchain networks from accidentally connecting to each other.
    ///
    /// It is possible for the JSON chain specs to not specify any protocol id, in which case a
    /// default value is returned.
    ///
    /// > **Note**: This mechanism is legacy and no longer used.
    pub fn protocol_id(&self) -> Option<&str> {
        self.client_spec.protocol_id.as_deref()
    }

    /// Returns the "fork id" of the chain. This is arbitrary string that can be used in order to
    /// segregate nodes in case when multiple chains have the same genesis hash. Nodes should only
    /// synchronize with nodes that have the same "fork id".
    pub fn fork_id(&self) -> Option<&str> {
        self.client_spec.fork_id.as_deref()
    }

    // TODO: this API is probably unstable, as the meaning of the string is unclear
    pub fn relay_chain(&self) -> Option<(&str, u32)> {
        match (
            self.client_spec.relay_chain.as_ref(),
            self.client_spec.para_id.as_ref(),
        ) {
            (Some(r), Some(p)) => Some((r.as_str(), *p)),
            _ => None,
        }
    }

    /// Gives access to what is known about the storage of the genesis block of the chain.
    pub fn genesis_storage(&self) -> GenesisStorage {
        match &self.client_spec.genesis {
            structs::Genesis::Raw(raw) => GenesisStorage::Items(GenesisStorageItems { raw }),
            structs::Genesis::StateRootHash(hash) => GenesisStorage::TrieRootHash(&hash.0),
        }
    }

    /// Returns a list of arbitrary properties contained in the chain specs, such as the name of
    /// the token or the number of decimals.
    ///
    /// The value of these properties is never interpreted by the local node, but can be served
    /// to a UI.
    ///
    /// The returned value is a JSON-formatted map, for example `{"foo":"bar"}`.
    pub fn properties(&self) -> &str {
        self.client_spec
            .properties
            .as_ref()
            .map_or("{}", |p| p.get())
    }

    pub fn light_sync_state(&self) -> Option<LightSyncState> {
        self.client_spec
            .light_sync_state
            .as_ref()
            .map(|state| LightSyncState {
                // We made sure at initialization that the decoding succeeds.
                inner: state.decode(self.block_number_bytes().into()).unwrap(),
            })
    }
}

/// See [`ChainSpec::boot_nodes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bootnode<'a> {
    /// The address of the bootnode is valid.
    Parsed {
        /// String representation of the multiaddress that can be used to reach the bootnode.
        ///
        /// Does *not* contain the trailing `/p2p/...`.
        multiaddr: String,

        /// Bytes representation of the libp2p peer id of the bootnode.
        ///
        /// The format can be found in the libp2p specification:
        /// <https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md>
        peer_id: Vec<u8>,
    },

    /// The address of the bootnode couldn't be parsed.
    ///
    /// This could be due to the format being invalid, or to smoldot not supporting one of the
    /// multiaddress components that is being used.
    UnrecognizedFormat(&'a str),
}

/// See [`ChainSpec::genesis_storage`].
pub enum GenesisStorage<'a> {
    /// The items of the genesis storage are known.
    Items(GenesisStorageItems<'a>),
    /// The items of the genesis storage are unknown, but we know the hash of the root node
    /// of the trie.
    TrieRootHash(&'a [u8; 32]),
}

impl<'a> GenesisStorage<'a> {
    /// Returns `Some` for [`GenesisStorage::Items`], and `None` otherwise.
    pub fn into_genesis_items(self) -> Option<GenesisStorageItems<'a>> {
        match self {
            GenesisStorage::Items(items) => Some(items),
            GenesisStorage::TrieRootHash(_) => None,
        }
    }

    /// Returns `Some` for [`GenesisStorage::TrieRootHash`], and `None` otherwise.
    pub fn into_trie_root_hash(self) -> Option<&'a [u8; 32]> {
        match self {
            GenesisStorage::Items(_) => None,
            GenesisStorage::TrieRootHash(hash) => Some(hash),
        }
    }
}

/// See [`GenesisStorage`].
pub struct GenesisStorageItems<'a> {
    raw: &'a structs::RawGenesis,
}

impl<'a> GenesisStorageItems<'a> {
    /// Returns the list of storage keys and values of the genesis block.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + Clone {
        self.raw.top.iter().map(|(k, v)| (&k.0[..], &v.0[..]))
    }

    /// Find the storage key that immediately follows `key_before` in the list of storage items.
    ///
    /// If `or_equal` is `true`, then `key_before` is returned if it corresponds to a key in the
    /// storage.
    ///
    /// Returns `None` if no next key could be found, or if the next key doesn't start with the
    /// given prefix.
    pub fn next_key(
        &self,
        key_before: impl Iterator<Item = u8>,
        or_equal: bool,
        prefix: impl Iterator<Item = u8>,
    ) -> Option<impl Iterator<Item = u8>> {
        let lower_bound = if or_equal {
            Bound::Included(structs::HexString(key_before.collect::<Vec<_>>()))
        } else {
            Bound::Excluded(structs::HexString(key_before.collect::<Vec<_>>()))
        };

        self.raw
            .top
            .range((lower_bound, Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.0.iter().copied().zip(prefix).all(|(a, b)| a == b))
            .map(|(k, _)| k.0.iter().copied())
    }

    /// Returns the genesis storage value for a specific key.
    ///
    /// Returns `None` if there is no value corresponding to that key.
    pub fn value(&self, key: &[u8]) -> Option<&[u8]> {
        self.raw.top.get(key).map(|value| &value.0[..])
    }
}

pub struct LightSyncState {
    inner: light_sync_state::DecodedLightSyncState,
}

fn convert_epoch(epoch: &light_sync_state::BabeEpoch) -> Box<BabeEpochInformation> {
    let epoch_authorities: Vec<_> = epoch
        .authorities
        .iter()
        .map(|authority| crate::header::BabeAuthority {
            public_key: authority.public_key,
            weight: authority.weight,
        })
        .collect();

    Box::new(BabeEpochInformation {
        epoch_index: epoch.epoch_index,
        start_slot_number: Some(epoch.slot_number),
        authorities: epoch_authorities,
        randomness: epoch.randomness,
        c: epoch.config.c,
        allowed_slots: epoch.config.allowed_slots,
    })
}

impl LightSyncState {
    pub fn to_chain_information(
        &self,
    ) -> Result<ValidChainInformation, CheckpointToChainInformationError> {
        // TODO: this code is a bit of a shitshow when it comes to corner cases and should be cleaned up after https://github.com/paritytech/substrate/issues/11184

        if self.inner.finalized_block_header.number == 0 {
            return Err(CheckpointToChainInformationError::GenesisBlockCheckpoint);
        }

        // Create a sorted list of all regular epochs that haven't been pruned from the sync state.
        let mut epochs: Vec<_> = self
            .inner
            .babe_epoch_changes
            .epochs
            .iter()
            .filter(|((_, block_num), _)| {
                u64::from(*block_num) <= self.inner.finalized_block_header.number
            })
            .filter_map(|((_, block_num), epoch)| match epoch {
                light_sync_state::PersistedEpoch::Regular(epoch) => Some((block_num, epoch)),
                _ => None,
            })
            .collect();

        epochs.sort_unstable_by_key(|(block_num, _)| **block_num);

        // TODO: it seems that multiple identical epochs can be found in the list ; figure out why Substrate does that and fix it
        epochs.dedup_by_key(|(_, epoch)| epoch.epoch_index);

        // Get the latest two epochs.
        if epochs.len() < 2 {
            return Err(CheckpointToChainInformationError::GenesisBlockCheckpoint);
        }
        let current_epoch = epochs[epochs.len() - 2].1;
        let next_epoch = epochs[epochs.len() - 1].1;

        ChainInformation {
            finalized_block_header: Box::new(self.inner.finalized_block_header.clone()),
            consensus: ChainInformationConsensus::Babe {
                slots_per_epoch: NonZero::<u64>::new(next_epoch.duration)
                    .ok_or(CheckpointToChainInformationError::InvalidBabeSlotsPerEpoch)?,
                finalized_block_epoch_information: Some(convert_epoch(current_epoch)),
                finalized_next_epoch_transition: convert_epoch(next_epoch),
            },
            finality: ChainInformationFinality::Grandpa {
                after_finalized_block_authorities_set_id: self.inner.grandpa_authority_set.set_id,
                finalized_triggered_authorities: {
                    self.inner
                        .grandpa_authority_set
                        .current_authorities
                        .iter()
                        .map(|authority| {
                            Ok(crate::header::GrandpaAuthority {
                                public_key: authority.public_key,
                                weight: NonZero::<u64>::new(authority.weight)
                                    .ok_or(CheckpointToChainInformationError::InvalidGrandpaAuthorityWeight)?,
                            })
                        })
                        .collect::<Result<_, _>>()?
                },
                finalized_scheduled_change: None, // TODO: unimplemented
            },
        }
        .try_into()
        .map_err(CheckpointToChainInformationError::InvalidData)
    }
}

/// Error that can happen when parsing a chain spec JSON.
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("Failed to parse chain spec")]
pub struct ParseError(ParseErrorInner);

#[derive(Debug, derive_more::Display, derive_more::Error)]
enum ParseErrorInner {
    Serde(serde_json::Error),
    Other,
}

/// Error when building the chain information from the genesis storage.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum FromGenesisStorageError {
    /// Runtime couldn't be found in the storage.
    RuntimeNotFound,
    /// Error while building the chain information.
    #[display("{_0}")]
    BuildChainInformation(build::Error),
    /// Failed to decode heap pages from the storage.
    #[display("Failed to decode heap pages from the storage: {_0}")]
    HeapPagesDecode(executor::InvalidHeapPagesError),
    /// Error when initializing the virtual machine.
    #[display("Error when initializing the virtual machine: {_0}")]
    VmInitialization(executor::host::NewErr),
    /// Chain specification doesn't contain the list of storage items.
    UnknownStorageItems,
}

/// Error when building the chain information corresponding to a checkpoint.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum CheckpointToChainInformationError {
    /// The checkpoint corresponds to the genesis block.
    GenesisBlockCheckpoint,
    /// Found a value of 0 for the number of Babe slots per epoch.
    InvalidBabeSlotsPerEpoch,
    /// Found a Grandpa authority with a weight of 0.
    InvalidGrandpaAuthorityWeight,
    /// Information found in the checkpoint is invalid.
    #[display("{_0}")]
    InvalidData(ValidityError),
}
