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
};

pub use crate::libp2p::PeerId;

pub struct AddressBook<TChainId> {
    addresses: BTreeMap<(PeerId, Vec<u8>), AddressState>,

    foo: core::marker::PhantomData<TChainId>,
}

enum AddressState {
    Connected,
    Pending,
    Disconnected,
}

impl<TChainId> AddressBook<TChainId> {
    pub fn new() -> Self {
        AddressBook {
            addresses: BTreeMap::new(),
            foo: core::marker::PhantomData,
        }
    }

    pub fn insert_chain_peer(&mut self, peer_id: PeerId, chain: TChainId) {
        
    }

    pub fn insert_address(&mut self, peer_id: &PeerId, multiaddr: &[u8]) {
        if let btree_map::Entry::Vacant(entry) = self
            .addresses
            .entry((peer_id.clone(), multiaddr.to_owned()))
        {
            entry.insert(AddressState::Disconnected);
        }
    }

    /// Picks an address from the list whose state is "not connected", and switches it to
    /// "pending". Returns `None` if no such address is available.
    pub fn addr_to_pending(&mut self, peer_id: &PeerId) -> Option<Vec<u8>> {
        todo!()
    }
}
