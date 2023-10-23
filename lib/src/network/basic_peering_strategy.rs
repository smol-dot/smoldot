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
    collections::{btree_map, btree_set, BTreeMap},
    vec::Vec,
};

use core::hash::Hash;

pub use crate::libp2p::PeerId;

#[derive(Debug)]
pub struct BasicPeeringStrategy<TChainId> {
    addresses: BTreeMap<(PeerId, Vec<u8>), AddressState>,

    peers_chains: BTreeMap<(TChainId, PeerId), PeerChainState>,
}

#[derive(Debug)]
enum AddressState {
    Connected,
    Disconnected,
}

#[derive(Debug)]
enum PeerChainState {
    Belongs,
    InSlot,
    OutSlot,
}

/// Identifier of a connection.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(usize);

impl ConnectionId {
    /// Returns the value that compares inferior or equal to any possible [`ConnectionId`̀].
    pub fn min_value() -> Self {
        ConnectionId(usize::min_value())
    }

    /// Returns the value that compares superior or equal to any possible [`ConnectionId`̀].
    pub fn max_value() -> Self {
        ConnectionId(usize::max_value())
    }
}

impl<TChainId> BasicPeeringStrategy<TChainId>
where
    TChainId: PartialOrd + Ord + Eq + Hash,
{
    pub fn new() -> Self {
        BasicPeeringStrategy {
            addresses: BTreeMap::new(),
            peers_chains: BTreeMap::new(),
        }
    }

    pub fn insert_chain_peer(&mut self, peer_id: PeerId, chain: TChainId) {
        if let btree_map::Entry::Vacant(entry) = self.peers_chains.entry((chain, peer_id)) {
            entry.insert(PeerChainState::Belongs);
        }
    }

    pub fn remove_chain_peer(&mut self, peer_id: &PeerId, chain: TChainId) {
        // TODO: cloning
        self.peers_chains.remove(&(chain, peer_id.clone()));
    }

    /// Inserts a new address for the given peer.
    ///
    /// Returns `true` if an address was inserted, or `false` if the address was already known.
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

    /// Choose a [`PeerId`] known to belong to the given chain, that is not banned, and assigns
    /// an "out slot" to it. Returns the [`PeerId`] that was chosen, or `None` if no [`PeerId`]
    /// matches these criteria.
    ///
    /// Note that this function might assign a slot to a peer for which no address is present.
    /// While this is often not desirable, it is preferable to keep the API simple and
    /// straight-forward rather than try to be smart about function behaviours.
    pub fn assign_out_slot(&mut self, chain: &TChainId) -> Option<&PeerId> {
        // TODO: choose randomly which peer to assign
        // TODO: optimize
        if let Some(((_, peer_id), state)) = self
            .peers_chains
            .iter_mut()
            .find(|((c, _), s)| *c == *chain && !matches!(*s, PeerChainState::OutSlot))
        {
            *state = PeerChainState::OutSlot;
            Some(peer_id)
        } else {
            None
        }
    }

    /// Unassign the out slot that has been assigned to the given peer and bans the peer,
    /// preventing it from being assigned an out slot on this chain for a certain amount of time.
    pub fn unassign_out_slot_and_ban(&mut self, chain: &TChainId, peer_id: &PeerId) {
        // TODO: optimize
        for (_, state) in self.peers_chains.iter_mut().filter(|((c, p), s)| {
            c == chain && p == peer_id && matches!(*s, PeerChainState::OutSlot)
        }) {
            // TODO:  what about in slots?
            *state = PeerChainState::Belongs;
        }

        // TODO: implement the ban
    }

    /// Unassigns all the out slots that have been assigned to the given peer and bans the peer,
    /// preventing it from being assigned an out slot for all of the chains it had a slot on for
    /// a certain amount of time.
    ///
    /// > **Note**: This function is a shortcut for calling
    /// >           [`BasicPeeringStrategy::unassign_out_slot_and_ban`] for all existing chains.
    pub fn unassign_out_slots_and_ban(&mut self, peer_id: &PeerId) {
        // TODO: optimize
        for (_, state) in self
            .peers_chains
            .iter_mut()
            .filter(|((_, p), s)| p == peer_id && matches!(*s, PeerChainState::OutSlot))
        {
            // TODO:  what about in slots?
            *state = PeerChainState::Belongs;
        }

        // TODO: implement the ban
    }

    // TODO: unused at the moment
    pub fn assign_in_slot(&mut self, chain: TChainId, peer_id: &PeerId) -> Result<(), ()> {
        // TODO: check against maximum
        match self.peers_chains.entry((chain, peer_id.clone())) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(PeerChainState::InSlot);
                Ok(())
            }
            btree_map::Entry::Occupied(mut entry) => {
                match entry.get() {
                    PeerChainState::Belongs => {}
                    PeerChainState::InSlot => {}
                    PeerChainState::OutSlot => return Err(()),
                };

                entry.insert(PeerChainState::InSlot);
                Ok(())
            }
        }
    }

    /// Picks an address from the list whose state is "not connected", and switches it to
    /// "connect". Returns `None` if no such address is available.
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
