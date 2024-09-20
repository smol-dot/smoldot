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

#![cfg(test)]

use core::num::NonZero;

use super::{Config, Pool, ValidTransaction};

#[test]
fn basic_includable() {
    let mut pool = Pool::new(Config {
        capacity: 16,
        finalized_block_height: 0,
        randomness_seed: [0; 16],
    });

    let tx_id = pool.add_unvalidated(vec![], ());

    pool.append_empty_block();
    assert!(pool.best_block_includable_transactions().next().is_none());

    pool.set_validation_result(
        tx_id,
        1,
        ValidTransaction {
            longevity: NonZero::<u64>::new(16).unwrap(),
            priority: 0,
            propagate: true,
            provides: Vec::new(),
            requires: Vec::new(),
        },
    );

    pool.append_empty_block();
    assert_eq!(
        pool.best_block_includable_transactions().next(),
        Some((tx_id, &()))
    );

    pool.best_block_add_transaction_by_id(tx_id);
    assert!(pool.best_block_includable_transactions().next().is_none());
}

// TODO: more tests
