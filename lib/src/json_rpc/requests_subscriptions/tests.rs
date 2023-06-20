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

use super::{Config, RequestsSubscriptions};
use core::num::NonZeroU32;

#[test]
fn clients_limit_adjustement() {
    futures_executor::block_on(async move {
        let req_sub = RequestsSubscriptions::<()>::new(Config {
            max_clients: 2,
            max_requests_per_client: NonZeroU32::new(5).unwrap(),
            max_subscriptions_per_client: 5,
        });

        let _ = req_sub.add_client().await.unwrap();
        let _ = req_sub.add_client().await.unwrap();
        assert!(req_sub.add_client().await.is_err());
        assert!(req_sub.add_client().await.is_err());

        req_sub.set_max_clients(4);
        let _ = req_sub.add_client().await.unwrap();

        req_sub.set_max_clients(1);
        assert!(req_sub.add_client().await.is_err());
    });
}
