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

use alloc::{
    borrow::ToOwned as _,
    collections::{btree_map, BTreeMap},
    vec::Vec,
};

use core::hash::Hash;

pub use crate::libp2p::PeerId;

#[derive(Debug)]
pub struct AddressBook<TChainId> {
    addresses: BTreeMap<(PeerId, Vec<u8>), AddressState>,

    peers_chains: BTreeMap<(TChainId, PeerId), ()>, // TODO: value
}

#[derive(Debug)]
enum AddressState {
    Connected,
    Pending,
    Disconnected,
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

impl<TChainId> AddressBook<TChainId>
where
    TChainId: PartialOrd + Ord + Eq + Hash,
{
    pub fn new() -> Self {
        AddressBook {
            addresses: BTreeMap::new(),
            peers_chains: BTreeMap::new(),
        }
    }

    /*pub fn insert_connection(
        &mut self,
        expected_peer_id: Option<PeerId>,
        address: Vec<u8>,
    ) -> ConnectionId {
    }*/

    pub fn remove_connection(&mut self, id: ConnectionId) {}

    pub fn insert_chain_peer(&mut self, peer_id: PeerId, chain: TChainId) {
        self.peers_chains.insert((chain, peer_id), ());
    }

    pub fn remove_chain_peer(&mut self, peer_id: &PeerId, chain: TChainId) {
        // TODO: cloning
        self.peers_chains.remove(&(chain, peer_id.clone()));
    }

    pub fn insert_address(&mut self, peer_id: &PeerId, multiaddr: &[u8]) {
        if let btree_map::Entry::Vacant(entry) = self
            .addresses
            .entry((peer_id.clone(), multiaddr.to_owned()))
        {
            entry.insert(AddressState::Disconnected);
        }
    }

    pub fn random_peer(&mut self, chain_id: &TChainId) -> Option<&PeerId> {
        // TODO: should switch peer state
        self.peers_chains
            .iter()
            .filter(|((c, _), _)| c == chain_id)
            .map(|((_, p), _)| p)
            .next()
    }

    /// Picks an address from the list whose state is "not connected", and switches it to
    /// "pending". Returns `None` if no such address is available.
    pub fn addr_to_pending(&mut self, peer_id: &PeerId) -> Option<&[u8]> {
        if let Some(((_, address), state)) =
            self.addresses.iter_mut().find(|((p, _), _)| p == peer_id)
        {
            *state = AddressState::Pending;
            Some(&address)
        } else {
            None
        }
    }
}
