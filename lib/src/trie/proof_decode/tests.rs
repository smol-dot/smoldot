// Smoldot
// Copyright (C) 2024  Pierre Krieger
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

use super::*;

#[test]
fn issue_2035() {
    // Repro for <https://github.com/smol-dot/smoldot/issues/2035>.
    let proof = include_bytes!("./issue_2035_proof");
    let state_root_hash: [u8; 32] = [
        247, 47, 169, 142, 251, 242, 60, 33, 209, 98, 166, 105, 10, 36, 18, 208, 178, 227, 210,
        231, 105, 202, 180, 106, 126, 182, 0, 65, 56, 235, 237, 167,
    ];
    let key: [u8; 32] = [
        0x63, 0xf7, 0x8c, 0x98, 0x72, 0x3d, 0xdc, 0x90, 0x73, 0x52, 0x3e, 0xf3, 0xbe, 0xef, 0xda,
        0x0c, 0xa9, 0x5d, 0xac, 0x46, 0xc0, 0x7a, 0x40, 0xd9, 0x15, 0x06, 0xe7, 0x63, 0x7e, 0xc4,
        0xba, 0x57,
    ];

    let decoded = decode_and_verify_proof(Config { proof }).unwrap();

    let next_key = decoded.next_key(
        &state_root_hash,
        crate::trie::bytes_to_nibbles(key.iter().copied()),
        false,
        iter::empty(),
        false,
    );

    assert_eq!(
        next_key.unwrap().unwrap().collect::<Vec<_>>(),
        crate::trie::bytes_to_nibbles(
            [
                0x63, 0xf7, 0x8c, 0x98, 0x72, 0x3d, 0xdc, 0x90, 0x73, 0x52, 0x3e, 0xf3, 0xbe, 0xef,
                0xda, 0x0c, 0xa9, 0x5d, 0xac, 0x46, 0xc0, 0x7a, 0x40, 0xd9, 0x15, 0x06, 0xe7, 0x63,
                0x7e, 0xc4, 0xba, 0x57, 0x07, 0x1c, 0xef, 0xf5, 0xb0, 0xf6, 0x4d, 0x36, 0x2e, 0x08,
                0x00, 0x00
            ]
            .iter()
            .copied()
        )
        .collect::<Vec<_>>()
    );
}
