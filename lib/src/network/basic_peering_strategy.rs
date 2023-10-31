// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

//! Basic address book and slots assignments algorithm.
//!
//! The [`BasicPeeringStrategy`] contains a collection of network identities, identified by
//! a [`PeerId`]. Each network identity is associated to one or more chains, identified by a
//! `TChainId`.
//!
//! Each network-identity-chain association can be in one of these three states:
//!
//! - Normal.
//! - Banned until a certain instant represented by `TInstant`.
//! - Has a slot.
//!
//! "Normal" and "banned" network-identity-chain associations represent the potential peers to
//! connect to, while "slot" represent pending or established gossip slots.
//!
//! Use [`BasicPeeringStrategy::pick_assignable_peer`] in order to assign a slot to a
//! randomly-chosen network-identity that doesn't currently have one.
//!
//! If a gossip slot fails to be established with a certain peer, or if the peer misbehaves,
//! use [`BasicPeeringStrategy::unassign_slot_and_ban`] to ban the peer, preventing it from
//! obtaining a slot for a certain amount of time.
//!
//! Each network identity that is associated with at least one chain is associated with zero or
//! more addresses. It is not possible to insert addresses to peers that aren't associated to at
//! least one chain. Each address is either "connected" or "disconnected".
//!
//! There exists a limit to the number of peers per chain and the number of addresses per peer,
//! guaranteeing that the data structure only uses a bounded amount of memory. If these limits
//! are reached, peers and addresses are removed randomly. Peers that have a slot and addresses
//! in the "connected" state are never removed.
//!

use crate::util;
use alloc::{
    borrow::ToOwned as _,
    collections::{btree_map, BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{hash::Hash, iter, ops};
use rand::seq::IteratorRandom as _;
use rand_chacha::{
    rand_core::{RngCore as _, SeedableRng as _},
    ChaCha20Rng,
};

pub use crate::libp2p::PeerId;

#[derive(Debug)]
pub struct BasicPeeringStrategy<TChainId, TInstant> {
    /// Contains all the `PeerId`s used throughout the collection.
    peer_ids: slab::Slab<PeerId>,

    /// Contains all the keys of [`BasicPeeringStrategy::peer_ids`] indexed differently.
    peer_ids_indices: hashbrown::HashMap<PeerId, usize, util::SipHasherBuild>,

    /// List of all known addresses, indexed by `peer_id_index`. The addresses are not intended
    /// to be in a particular order.
    addresses: BTreeMap<(usize, Vec<u8>), AddressState>,

    /// List of all chains throughout the collection.
    ///
    /// > **Note**: In principle this field is completely unnecessary. In practice, however, we
    /// >           can't use `BTreeMap::range` with `TChainId`s because we don't know the minimum
    /// >           and maximum values of a `TChainId`. In order to bypass this problem,
    /// >           `TChainId`s are instead refered to as a `usize`.
    chains: slab::Slab<TChainId>,

    /// Contains all the keys of [`BasicPeeringStrategy::chains`] indexed differently.
    /// While a dumber hasher is in principle enough, we use a `SipHasherBuild` "just in case"
    /// as we don't know the properties of `TChainId`.
    chains_indices: hashbrown::HashMap<TChainId, usize, util::SipHasherBuild>,

    /// Collection of
    /// Keys are `(peer_id_index, chain_id_index)`.
    peers_chains: BTreeMap<(usize, usize), PeerChainState<TInstant>>,

    /// Entries are `(chain_id_index, state, peer_id_index)`.
    peers_chains_by_state: BTreeSet<(usize, PeerChainState<TInstant>, usize)>,

    /// Random number generator used to select peers to assign slots to and remove addresses/peers.
    randomness: ChaCha20Rng,
}

#[derive(Debug)]
enum AddressState {
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
enum PeerChainState<TInstant> {
    Assignable,
    Banned { expires: TInstant },
    Slot,
}

/// Configuration passed to [`BasicPeeringStrategy::new`].
pub struct Config {
    /// Seed used for the randomness for choosing peers and addresses to connect to or remove.
    pub randomness_seed: [u8; 32],

    /// Number of peers, all chains together, to initially reserve memory for.
    pub peers_capacity: usize,

    /// Number of chains to initially reserve memory for.
    pub chains_capacity: usize,
}

impl<TChainId, TInstant> BasicPeeringStrategy<TChainId, TInstant>
where
    TChainId: PartialOrd + Ord + Eq + Hash + Clone,
    TInstant: PartialOrd + Ord + Eq + Clone,
{
    /// Creates a new empty [`BasicPeeringStrategy`].
    ///
    /// Must be passed a seed for randomness used
    /// in [`BasicPeeringStrategy::pick_assignable_peer`].
    pub fn new(config: Config) -> Self {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        BasicPeeringStrategy {
            peer_ids: slab::Slab::with_capacity(config.peers_capacity),
            peer_ids_indices: hashbrown::HashMap::with_capacity_and_hasher(
                config.peers_capacity,
                util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            addresses: BTreeMap::new(),
            chains: slab::Slab::with_capacity(config.chains_capacity),
            chains_indices: hashbrown::HashMap::with_capacity_and_hasher(
                config.chains_capacity,
                util::SipHasherBuild::new({
                    let mut seed = [0; 16];
                    randomness.fill_bytes(&mut seed);
                    seed
                }),
            ),
            peers_chains: BTreeMap::new(),
            peers_chains_by_state: BTreeSet::new(),
            randomness,
        }
    }

    /// Inserts a chain-peer combination to the collection, indicating that the given peer belongs
    /// to the given chain.
    ///
    /// Has no effect if the peer is already assigned to the given chain, in which case
    /// [`InsertChainPeerResult::Duplicate`] is returned.
    ///
    /// A maximum number of peers per chain must be provided. If the peer is inserted and the
    /// limit is exceeded, a peer (other than the one that has just been inserted) that belongs
    /// to the given chain is randomly chosen and removed. Peers that have slots assigned to them
    /// are never removed.
    pub fn insert_chain_peer(
        &mut self,
        chain: TChainId,
        peer_id: PeerId,
        max_peers_per_chain: usize,
    ) -> InsertChainPeerResult {
        let peer_id_index = self.get_or_insert_peer_index(&peer_id);
        let chain_index = self.get_or_insert_chain_index(&chain);

        if let btree_map::Entry::Vacant(entry) =
            self.peers_chains.entry((peer_id_index, chain_index))
        {
            let peer_to_remove = if self
                .peers_chains_by_state
                .range(
                    (chain_index, PeerChainState::Assignable, usize::min_value())
                        ..=(chain_index, PeerChainState::Slot, usize::max_value()),
                )
                .count()
                >= max_peers_per_chain
            {
                self.peers_chains_by_state
                    .range(
                        (chain_index, PeerChainState::Assignable, usize::min_value())
                            ..(chain_index, PeerChainState::Slot, usize::min_value()),
                    )
                    .choose(&mut self.randomness)
                    .map(|(_, _, peer_index)| *peer_index)
            } else {
                None
            };

            let _was_inserted = self.peers_chains_by_state.insert((
                chain_index,
                PeerChainState::Assignable,
                peer_id_index,
            ));
            debug_assert!(_was_inserted);

            entry.insert(PeerChainState::Assignable);

            let peer_removed = if let Some(peer_to_remove) = peer_to_remove {
                let peer_id_to_remove = self.peer_ids[peer_to_remove].clone();
                let state = self
                    .peers_chains
                    .remove(&(peer_to_remove, chain_index))
                    .unwrap_or_else(|| unreachable!());
                debug_assert!(!matches!(state, PeerChainState::Slot));
                let _was_removed =
                    self.peers_chains_by_state
                        .remove(&(chain_index, state, peer_to_remove));
                debug_assert!(_was_removed);
                self.try_clean_up_peer_id(peer_to_remove);
                Some(peer_id_to_remove)
            } else {
                None
            };

            InsertChainPeerResult::Inserted { peer_removed }
        } else {
            InsertChainPeerResult::Duplicate
        }
    }

    /// Removes a peer-chain associated previously inserted with
    /// [`BasicPeeringStrategy::insert_chain_peer`].
    ///
    /// Has no effect if the peer-chain association didn't exist.
    ///
    /// If the peer isn't assigned to any chain anymore, all of its addresses are also removed
    /// from the collection.
    pub fn unassign_slot_and_remove_chain_peer(&mut self, chain: &TChainId, peer_id: &PeerId) {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it wasn't assigned in the first place.
            return;
        };

        let Some(&chain_index) = self.chains_indices.get(chain) else {
            // If the `TChainId` is unknown, it means the peer wasn't assigned in the first place.
            return;
        };

        if let Some(state) = self.peers_chains.remove(&(peer_id_index, chain_index)) {
            let _was_removed =
                self.peers_chains_by_state
                    .remove(&(chain_index, state, peer_id_index));
            debug_assert!(_was_removed);

            self.try_clean_up_peer_id(peer_id_index);
            self.try_clean_up_chain(chain_index);
        }
    }

    /// Returns the list of all peers that are known to belong to the given chain, in other
    /// words peers added through [`BasicPeeringStrategy::insert_chain_peer`].
    ///
    /// The order of the yielded elements is unspecified.
    pub fn chain_peers_unordered(
        &'_ self,
        chain: &TChainId,
    ) -> impl Iterator<Item = &'_ PeerId> + '_ {
        let Some(&chain_index) = self.chains_indices.get(chain) else {
            // If the `TChainId` is unknown, it means that it doesn't have any peer.
            return either::Right(iter::empty());
        };

        either::Left(
            self.peers_chains_by_state
                .range(
                    (chain_index, PeerChainState::Assignable, usize::min_value())
                        ..=(chain_index, PeerChainState::Slot, usize::max_value()),
                )
                .map(|(_, _, p)| &self.peer_ids[*p]),
        )
    }

    /// Inserts a new address for the given peer.
    ///
    /// If the peer doesn't belong to any chain (see [`BasicPeeringStrategy::insert_chain_peer`]),
    /// then this function has no effect. This is to avoid accidentally collecting addresses for
    /// peers that will never be removed and create a memory leak. For this reason, you most likely
    /// want to call [`BasicPeeringStrategy::insert_chain_peer`] before calling this function.
    ///
    /// A maximum number of addresses that are maintained for this peer must be passed as
    /// parameter. If this number is exceeded, an address in the "not connected" state (other than
    /// the one passed as parameter) is randomly removed.
    ///
    /// If an address is inserted, it is in the "not connected" state.
    pub fn insert_address(
        &mut self,
        peer_id: &PeerId,
        address: Vec<u8>,
        max_addresses: usize,
    ) -> InsertAddressResult {
        self.insert_address_inner(
            peer_id,
            address,
            max_addresses,
            AddressState::Disconnected,
            false,
        )
    }

    /// Similar to [`BasicPeeringStrategy::insert_address`], except that the address, if it is
    /// inserted, is directly in the "connected" state. If the address is already known, switches
    /// it to the "connected" state.
    ///
    /// > **Note**: Use this function if you establish a connection and accidentally reach a
    /// >           certain [`PeerId`].
    pub fn insert_or_set_connected_address(
        &mut self,
        peer_id: &PeerId,
        address: Vec<u8>,
        max_addresses: usize,
    ) -> InsertAddressResult {
        self.insert_address_inner(
            peer_id,
            address,
            max_addresses,
            AddressState::Connected,
            true,
        )
    }

    fn insert_address_inner(
        &mut self,
        peer_id: &PeerId,
        address: Vec<u8>,
        max_addresses: usize,
        initial_state: AddressState,
        update_if_present: bool,
    ) -> InsertAddressResult {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            return InsertAddressResult::UnknownPeer;
        };

        match self.addresses.entry((peer_id_index, address.clone())) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(initial_state);

                let address_removed = {
                    let num_addresses = self
                        .addresses
                        .range((peer_id_index, Vec::new())..=(peer_id_index + 1, Vec::new()))
                        .count();

                    if num_addresses >= max_addresses {
                        // TODO: is it a good idea to choose the address randomly to remove? maybe there should be a sorting system with best addresses first?
                        self.addresses
                            .range((peer_id_index, Vec::new())..=(peer_id_index + 1, Vec::new()))
                            .filter(|((_, a), s)| {
                                matches!(s, AddressState::Disconnected) && *a != address
                            })
                            .choose(&mut self.randomness)
                            .map(|((_, a), _)| a.clone())
                    } else {
                        None
                    }
                };

                if let Some(address_removed) = address_removed.as_ref() {
                    self.addresses
                        .remove(&(peer_id_index, address_removed.clone()));
                }

                InsertAddressResult::Inserted { address_removed }
            }
            btree_map::Entry::Occupied(entry) => {
                if update_if_present {
                    *entry.into_mut() = initial_state;
                }

                InsertAddressResult::Duplicate
            }
        }
    }

    /// Removes an address.
    ///
    /// Works on both "not connected" and "connected" addresses.
    ///
    /// Returns `true` if an address was removed, or `false` if the address wasn't known.
    pub fn remove_address(&mut self, peer_id: &PeerId, address: &[u8]) -> bool {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it doesn't have an address anyway.
            return false;
        };

        if self
            .addresses
            .remove(&(peer_id_index, address.to_owned()))
            .is_some()
        {
            self.try_clean_up_peer_id(peer_id_index);
            true
        } else {
            false
        }
    }

    /// Returns the list of all addresses that have been inserted for the given peer.
    pub fn peer_addresses(&'_ self, peer_id: &PeerId) -> impl Iterator<Item = &'_ [u8]> + '_ {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it doesn't have any address.
            return either::Right(iter::empty());
        };

        either::Left(
            self.addresses
                .range((peer_id_index, Vec::new())..(peer_id_index + 1, Vec::new()))
                .map(|((_, a), _)| &a[..]),
        )
    }

    /// Chooses a [`PeerId`] that is known to belong to the given chain, that is not banned, and
    /// that doesn't have a slot assigned to it.
    ///
    /// A `TInstant` must be provided in order to determine whether past bans have expired.
    ///
    /// If multiple peers can be assigned a slot, the one returned is chosen randomly. Calling
    /// this function multiple times might return different peers.
    /// For this reason, this function requires `&mut self`.
    ///
    /// Note that this function might return a peer for which no address is present. While this is
    /// often not desirable, it is preferable to keep the API simple and straight-forward rather
    /// than try to be smart about function behaviours.
    pub fn pick_assignable_peer(
        &'_ mut self,
        chain: &TChainId,
        now: &TInstant,
    ) -> AssignablePeer<'_, TInstant> {
        let Some(&chain_index) = self.chains_indices.get(chain) else {
            return AssignablePeer::NoPeer;
        };

        if let Some((_, _, peer_id_index)) = self
            .peers_chains_by_state
            .range(
                (chain_index, PeerChainState::Assignable, usize::min_value())
                    ..=(
                        chain_index,
                        PeerChainState::Banned {
                            expires: now.clone(),
                        },
                        usize::max_value(),
                    ),
            )
            .choose(&mut self.randomness)
        {
            return AssignablePeer::Assignable(&self.peer_ids[*peer_id_index]);
        }

        if let Some((_, state, _)) = self
            .peers_chains_by_state
            .range((
                ops::Bound::Excluded((
                    chain_index,
                    PeerChainState::Banned {
                        expires: now.clone(),
                    },
                    usize::max_value(),
                )),
                ops::Bound::Excluded((chain_index, PeerChainState::Slot, usize::min_value())),
            ))
            .next()
        {
            let PeerChainState::Banned { expires } = state else {
                unreachable!()
            };
            return AssignablePeer::AllPeersBanned {
                next_unban: expires,
            };
        } else {
            return AssignablePeer::NoPeer;
        }
    }

    /// Assigns a slot to the given peer on the given chain.
    ///
    /// Acts as an implicit call to [`BasicPeeringStrategy::insert_chain_peer`].
    ///
    /// A slot is assigned even if the peer is banned. API users that call this function are
    /// expected to be aware of that.
    pub fn assign_slot(&'_ mut self, chain: &TChainId, peer_id: &PeerId) {
        let peer_id_index = self.get_or_insert_peer_index(peer_id);
        let chain_index = self.get_or_insert_chain_index(chain);

        match self.peers_chains.entry((peer_id_index, chain_index)) {
            btree_map::Entry::Occupied(e) => {
                let _was_removed = self.peers_chains_by_state.remove(&(
                    chain_index,
                    e.get().clone(),
                    peer_id_index,
                ));
                debug_assert!(_was_removed);
                *e.into_mut() = PeerChainState::Slot;
            }
            btree_map::Entry::Vacant(e) => {
                e.insert(PeerChainState::Slot);
            }
        }

        let _was_inserted =
            self.peers_chains_by_state
                .insert((chain_index, PeerChainState::Slot, peer_id_index));
        debug_assert!(_was_inserted);
    }

    /// Unassign the slot that has been assigned to the given peer and bans the peer, preventing
    /// it from being assigned a slot on this chain for a certain amount of time.
    ///
    /// Has no effect if the peer isn't assigned to the given chain.
    ///
    /// If the peer was already banned, the new ban expiration is `max(existing_ban, when_unban)`.
    pub fn unassign_slot_and_ban(
        &mut self,
        chain: &TChainId,
        peer_id: &PeerId,
        when_unban: TInstant,
    ) {
        let (Some(&peer_id_index), Some(&chain_index)) = (
            self.peer_ids_indices.get(peer_id),
            self.chains_indices.get(chain),
        ) else {
            return;
        };

        if let Some(state) = self.peers_chains.get_mut(&(peer_id_index, chain_index)) {
            if matches!(state, PeerChainState::Banned { expires } if *expires >= when_unban) {
                // Ban is already long enough. Nothing to do.
                return;
            }

            let _was_in =
                self.peers_chains_by_state
                    .remove(&(chain_index, state.clone(), peer_id_index));
            debug_assert!(_was_in);

            *state = PeerChainState::Banned {
                expires: when_unban,
            };

            let _was_inserted =
                self.peers_chains_by_state
                    .insert((chain_index, state.clone(), peer_id_index));
            debug_assert!(_was_inserted);
        }
    }

    /// Unassigns all the slots that have been assigned to the given peer and bans the peer,
    /// preventing it from being assigned a slot for all of the chains it had a slot on for a
    /// certain amount of time.
    ///
    /// Has no effect on chains the peer isn't assigned to.
    ///
    /// If the peer was already banned, the new ban expiration is `max(existing_ban, when_unban)`.
    ///
    /// > **Note**: This function is a shortcut for calling
    /// >           [`BasicPeeringStrategy::unassign_slot_and_ban`] for all existing chains.
    pub fn unassign_slots_and_ban(&mut self, peer_id: &PeerId, when_unban: TInstant) {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            return;
        };

        for ((_, chain_index), state) in self
            .peers_chains
            .range_mut((peer_id_index, usize::min_value())..=(peer_id_index, usize::max_value()))
        {
            if matches!(state, PeerChainState::Banned { expires } if *expires >= when_unban) {
                // Ban is already long enough. Nothing to do.
                continue;
            }

            let _was_in =
                self.peers_chains_by_state
                    .remove(&(*chain_index, state.clone(), peer_id_index));
            debug_assert!(_was_in);

            *state = PeerChainState::Banned {
                expires: when_unban.clone(),
            };

            let _was_inserted =
                self.peers_chains_by_state
                    .insert((*chain_index, state.clone(), peer_id_index));
            debug_assert!(_was_inserted);
        }
    }

    /// Picks an address from the list whose state is "not connected", and switches it to
    /// "connected". Returns `None` if no such address is available.
    pub fn addr_to_connected(&mut self, peer_id: &PeerId) -> Option<&[u8]> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it doesn't have any address.
            return None;
        };

        // TODO: could be optimized further by removing filter() and adjusting the set
        if let Some(((_, address), state)) = self
            .addresses
            .range_mut((peer_id_index, Vec::new())..(peer_id_index + 1, Vec::new()))
            .filter(|(_, state)| matches!(state, AddressState::Disconnected))
            .choose(&mut self.randomness)
        {
            *state = AddressState::Connected;
            return Some(address);
        }

        None
    }

    /// Marks the given address as "disconnected".
    ///
    /// Has no effect if the address isn't known to the data structure, or if it was not in the
    /// "connected" state.
    pub fn disconnect_addr(
        &mut self,
        peer_id: &PeerId,
        address: &[u8],
    ) -> Result<(), DisconnectAddrError> {
        let Some(&peer_id_index) = self.peer_ids_indices.get(peer_id) else {
            // If the `PeerId` is unknown, it means it doesn't have any address.
            return Err(DisconnectAddrError::UnknownAddress);
        };

        let Some(addr) = self.addresses.get_mut(&(peer_id_index, address.to_owned())) else {
            return Err(DisconnectAddrError::UnknownAddress);
        };

        match addr {
            s @ AddressState::Connected => *s = AddressState::Disconnected,
            AddressState::Disconnected => return Err(DisconnectAddrError::NotConnected),
        }

        Ok(())
    }

    /// Finds the index of the given `TChainId` in [`BasicPeeringStrategy::chains`], or inserts
    /// one if there is none.
    fn get_or_insert_chain_index(&mut self, chain: &TChainId) -> usize {
        debug_assert_eq!(self.chains.len(), self.chains_indices.len());

        match self.chains_indices.raw_entry_mut().from_key(chain) {
            hashbrown::hash_map::RawEntryMut::Occupied(occupied_entry) => *occupied_entry.get(),
            hashbrown::hash_map::RawEntryMut::Vacant(vacant_entry) => {
                let idx = self.chains.insert(chain.clone());
                vacant_entry.insert(chain.clone(), idx);
                idx
            }
        }
    }

    /// Check if the given `TChainId` is still used within the collection. If no, removes it from
    /// [`BasicPeeringStrategy::chains`].
    fn try_clean_up_chain(&mut self, chain_index: usize) {
        if self
            .peers_chains_by_state
            .range(
                (chain_index, PeerChainState::Assignable, usize::min_value())
                    ..=(chain_index, PeerChainState::Slot, usize::max_value()),
            )
            .next()
            .is_some()
        {
            return;
        }

        // Chain is unused. We can remove it.
        let chain_id = self.chains.remove(chain_index);
        let _was_in = self.chains_indices.remove(&chain_id);
        debug_assert_eq!(_was_in, Some(chain_index));
    }

    /// Finds the index of the given [`PeerId`] in [`BasicPeeringStrategy::peer_ids`], or inserts
    /// one if there is none.
    fn get_or_insert_peer_index(&mut self, peer_id: &PeerId) -> usize {
        debug_assert_eq!(self.peer_ids.len(), self.peer_ids_indices.len());

        match self.peer_ids_indices.raw_entry_mut().from_key(peer_id) {
            hashbrown::hash_map::RawEntryMut::Occupied(occupied_entry) => *occupied_entry.get(),
            hashbrown::hash_map::RawEntryMut::Vacant(vacant_entry) => {
                let idx = self.peer_ids.insert(peer_id.clone());
                vacant_entry.insert(peer_id.clone(), idx);
                idx
            }
        }
    }

    /// Check if the given [`PeerId`] is still used within the collection. If no, removes it from
    /// [`BasicPeeringStrategy::peer_ids`].
    fn try_clean_up_peer_id(&mut self, peer_id_index: usize) {
        if self
            .peers_chains
            .range((peer_id_index, usize::min_value())..=(peer_id_index, usize::max_value()))
            .next()
            .is_some()
        {
            return;
        }

        // PeerId is unused. We can remove it.
        let peer_id = self.peer_ids.remove(peer_id_index);
        let _was_in = self.peer_ids_indices.remove(&peer_id);
        debug_assert_eq!(_was_in, Some(peer_id_index));
        for address in self
            .addresses
            .range((peer_id_index, Vec::new())..(peer_id_index + 1, Vec::new()))
            .map(|((_, a), _)| a.clone())
            .collect::<Vec<_>>()
        {
            let _was_removed = self.addresses.remove(&(peer_id_index, address));
            debug_assert!(_was_removed.is_some());
        }
    }
}

/// See [`BasicPeeringStrategy::disconnect_addr`].
#[derive(Debug, derive_more::Display)]
pub enum DisconnectAddrError {
    /// Address isn't known to the collection.
    UnknownAddress,
    /// The address was not in the "connected" state.
    NotConnected,
}

/// See [`BasicPeeringStrategy::pick_assignable_peer`].
pub enum AssignablePeer<'a, TInstant> {
    /// An assignal peer was found. Note that the peer wasn't assigned yet.
    Assignable(&'a PeerId),
    /// No peer was found as all known un-assigned peers are currently in the "banned" state.
    AllPeersBanned {
        /// Instant when the first peer will be unbanned.
        next_unban: &'a TInstant,
    },
    /// No un-assigned peer was found.
    NoPeer,
}

/// See [`BasicPeeringStrategy::insert_chain_peer`].
pub enum InsertChainPeerResult {
    /// Peer-chain association has been successfully inserted.
    Inserted {
        /// If the maximum number of peers is reached, an old peer might have been removed. If so,
        /// this contains the peer.
        peer_removed: Option<PeerId>,
    },
    /// Peer-chain association was already inserted.
    Duplicate,
}

/// See [`BasicPeeringStrategy::insert_address`] and
/// [`BasicPeeringStrategy::insert_or_set_connected_address`].
pub enum InsertAddressResult {
    /// Address has been successfully inserted.
    Inserted {
        /// If the maximum number of addresses is reached, an old address might have been
        /// removed. If so, this contains the address.
        address_removed: Option<Vec<u8>>,
    },
    /// Address was already inserted.
    Duplicate,
    /// The peer isn't associated to any chain, and as such the address was not inserted.
    UnknownPeer,
}

#[cfg(test)]
mod tests {
    #[test]
    fn peer_state_ordering() {
        // The implementation above relies on the properties tested here.
        use super::PeerChainState;
        assert!(PeerChainState::Assignable < PeerChainState::Banned { expires: 0 });
        assert!(PeerChainState::Banned { expires: 5 } < PeerChainState::Banned { expires: 7 });
        assert!(
            PeerChainState::Banned {
                expires: u32::max_value()
            } < PeerChainState::Slot
        );
    }
}
