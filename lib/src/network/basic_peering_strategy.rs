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
//! a [`PeerId`].
//!
//! Each network identity is associated with zero or more addresses. Each address is either
//! "connected" or "disconnected".

use alloc::{
    borrow::ToOwned as _,
    collections::{btree_map, BTreeMap, BTreeSet},
    vec::Vec,
};

use core::hash::Hash;

pub use crate::libp2p::PeerId;

#[derive(Debug)]
pub struct BasicPeeringStrategy<TChainId, TInstant> {
    addresses: BTreeMap<(PeerId, Vec<u8>), AddressState>,

    peers_chains: BTreeMap<(PeerId, TChainId), PeerChainState<TInstant>>,

    peers_chains_by_state: BTreeSet<(TChainId, PeerChainState<TInstant>, PeerId)>,
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

impl<TChainId, TInstant> BasicPeeringStrategy<TChainId, TInstant>
where
    TChainId: PartialOrd + Ord + Eq + Hash + Clone,
    TInstant: PartialOrd + Ord + Eq + Clone, // TODO: remove Clone?
{
    /// Creates a new empty [`BasicPeeringStrategy`].
    pub fn new() -> Self {
        BasicPeeringStrategy {
            addresses: BTreeMap::new(),
            peers_chains: BTreeMap::new(),
            peers_chains_by_state: BTreeSet::new(),
        }
    }

    pub fn insert_chain_peer(&mut self, chain: TChainId, peer_id: PeerId) {
        if let btree_map::Entry::Vacant(entry) = self.peers_chains.entry((peer_id, chain)) {
            let _was_inserted = self.peers_chains_by_state.insert((
                entry.key().1.clone(),
                PeerChainState::Assignable,
                entry.key().0.clone(),
            ));
            debug_assert!(_was_inserted);

            entry.insert(PeerChainState::Assignable);
        }
    }

    pub fn unassign_slot_and_remove_chain_peer(&mut self, chain: &TChainId, peer_id: &PeerId) {
        if let Some(state) = self.peers_chains.remove(&(peer_id.clone(), chain.clone())) {
            let _was_removed =
                self.peers_chains_by_state
                    .remove(&(chain.clone(), state, peer_id.clone()));
            debug_assert!(_was_removed);
        }
    }

    /// Returns the list of all peers that are known to belong to the given chain.
    ///
    /// The order of the yielded elements is unspecified.
    pub fn chain_peers_unordered(
        &'_ self,
        chain: &TChainId,
    ) -> impl Iterator<Item = &'_ PeerId> + '_ {
        // TODO: optimize
        let chain = chain.clone();
        self.peers_chains
            .iter()
            .filter(move |((_, c), _)| *c == chain)
            .map(|((p, _), _)| p)
    }

    /// Inserts a new address for the given peer.
    ///
    /// Returns `true` if an address was inserted, or `false` if the address was already known.
    ///
    /// If an address is inserted, it is in the "not connected" state.
    pub fn insert_address(&mut self, peer_id: &PeerId, address: Vec<u8>) -> bool {
        if let btree_map::Entry::Vacant(entry) =
            self.addresses.entry((peer_id.clone(), address.to_owned()))
        {
            entry.insert(AddressState::Disconnected);
            true
        } else {
            false
        }
    }

    // TODO: doc
    pub fn insert_connected_address(&mut self, peer_id: &PeerId, address: Vec<u8>) {
        *self
            .addresses
            .entry((peer_id.clone(), address.to_owned()))
            .or_insert(AddressState::Connected) = AddressState::Connected;
    }

    /// Removes an address.
    ///
    /// Works on both "not connected" and "connected" addresses.
    ///
    /// Returns `true` if an address was removed, or `false` if the address wasn't known.
    pub fn remove_address(&mut self, peer_id: &PeerId, address: &[u8]) -> bool {
        self.addresses
            .remove(&(peer_id.clone(), address.to_owned()))
            .is_some()
    }

    /// Returns the list of all addresses that have been inserted for the given peer.
    pub fn peer_addresses(&'_ self, peer_id: &PeerId) -> impl Iterator<Item = &'_ [u8]> + '_ {
        // TODO: optimize
        let peer_id = peer_id.clone();
        self.addresses
            .iter()
            .filter(move |((p, _), _)| *p == peer_id)
            .map(|((_, a), _)| &a[..])
    }

    /// Choose a [`PeerId`] known to belong to the given chain, that is not banned and doesn't
    /// have a slot assigned to it, and assigns a slot to it. Returns the [`PeerId`] that was
    /// chosen, or `None` if no [`PeerId`] matches this criteria.
    ///
    /// A `TInstant` must be provided in order to determine whether past bans have expired.
    ///
    /// Note that this function might assign a slot to a peer for which no address is present.
    /// While this is often not desirable, it is preferable to keep the API simple and
    /// straight-forward rather than try to be smart about function behaviours.
    pub fn assign_slot(
        &'_ mut self,
        chain: &TChainId,
        now: &TInstant,
    ) -> AssignSlotOutcome<'_, TInstant> {
        // TODO: choose randomly which peer to assign
        // TODO: optimize
        if let Some(((peer_id, _), state)) = self.peers_chains.iter_mut().find(|((_, c), s)| {
            *c == *chain
                && (matches!(*s, PeerChainState::Assignable)
                    || matches!(&*s, PeerChainState::Banned { expires } if *expires <= *now))
        }) {
            let _was_in =
                self.peers_chains_by_state
                    .remove(&(chain.clone(), state.clone(), peer_id.clone()));
            debug_assert!(_was_in);

            *state = PeerChainState::Slot;

            let _was_inserted =
                self.peers_chains_by_state
                    .insert((chain.clone(), state.clone(), peer_id.clone()));
            debug_assert!(_was_inserted);

            AssignSlotOutcome::Assigned(peer_id)
        } else {
            // TODO: never returns `AllBanned`
            AssignSlotOutcome::NoPeer
        }
    }

    /// Unassign the slot that has been assigned to the given peer and bans the peer, preventing
    /// it from being assigned a slot on this chain for a certain amount of time.
    pub fn unassign_slot_and_ban(
        &mut self,
        chain: &TChainId,
        peer_id: &PeerId,
        when_unban: TInstant,
    ) {
        // TODO: optimize
        for (_, state) in self
            .peers_chains
            .iter_mut()
            .filter(|((p, c), s)| c == chain && p == peer_id && matches!(*s, PeerChainState::Slot))
        {
            let _was_in =
                self.peers_chains_by_state
                    .remove(&(chain.clone(), state.clone(), peer_id.clone()));
            debug_assert!(_was_in);

            *state = PeerChainState::Banned {
                expires: when_unban.clone(),
            };

            let _was_inserted =
                self.peers_chains_by_state
                    .insert((chain.clone(), state.clone(), peer_id.clone()));
            debug_assert!(_was_inserted);
        }
    }

    /// Unassigns all the slots that have been assigned to the given peer and bans the peer,
    /// preventing it from being assigned a slot for all of the chains it had a slot on for a
    /// certain amount of time.
    ///
    /// > **Note**: This function is a shortcut for calling
    /// >           [`BasicPeeringStrategy::unassign_slot_and_ban`] for all existing chains.
    pub fn unassign_slots_and_ban(&mut self, peer_id: &PeerId, when_unban: TInstant) {
        // TODO: optimize
        for ((_, chain), state) in self
            .peers_chains
            .iter_mut()
            .filter(|((p, _), s)| p == peer_id && matches!(*s, PeerChainState::Slot))
        {
            let _was_in =
                self.peers_chains_by_state
                    .remove(&(chain.clone(), state.clone(), peer_id.clone()));
            debug_assert!(_was_in);

            *state = PeerChainState::Banned {
                expires: when_unban.clone(),
            };

            let _was_inserted =
                self.peers_chains_by_state
                    .insert((chain.clone(), state.clone(), peer_id.clone()));
            debug_assert!(_was_inserted);
        }
    }

    /// Picks an address from the list whose state is "not connected", and switches it to
    /// "connected". Returns `None` if no such address is available.
    pub fn addr_to_connected(&mut self, peer_id: &PeerId) -> Option<&[u8]> {
        // TODO: optimize
        if let Some(((_, address), state)) =
            self.addresses.iter_mut().find(|((p, _), _)| p == peer_id)
        {
            *state = AddressState::Connected;
            Some(&address)
        } else {
            None
        }
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
        let Some(addr) = self
            .addresses
            .get_mut(&(peer_id.clone(), address.to_owned()))
        else {
            return Err(DisconnectAddrError::UnknownAddress);
        };

        match addr {
            s @ AddressState::Connected => *s = AddressState::Disconnected,
            AddressState::Disconnected => return Err(DisconnectAddrError::NotConnected),
        }

        Ok(())
    }
}

#[derive(Debug, derive_more::Display)]
pub enum DisconnectAddrError {
    UnknownAddress,
    NotConnected,
}

pub enum AssignSlotOutcome<'a, TInstant> {
    Assigned(&'a PeerId),
    AllPeersBanned { next_unban: &'a TInstant },
    NoPeer,
}
