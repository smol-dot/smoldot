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

#![cfg(test)]

use super::{super::super::read_write::ReadWrite, Handshake, NoiseKey};

#[test]
fn handshake_basic_works() {
    fn test_with_buffer_sizes(size1: usize, size2: usize) {
        let key1 = NoiseKey::new(&rand::random(), &rand::random());
        let key2 = NoiseKey::new(&rand::random(), &rand::random());

        let mut handshake1 = Handshake::noise_yamux(&key1, &rand::random(), true);
        let mut handshake2 = Handshake::noise_yamux(&key2, &rand::random(), false);

        let mut buf_1_to_2 = Vec::new();
        let mut buf_2_to_1 = Vec::new();

        while !matches!(
            (&handshake1, &handshake2),
            (Handshake::Success { .. }, Handshake::Success { .. })
        ) {
            match handshake1 {
                Handshake::Success { .. } => {}
                Handshake::Healthy(nego) => {
                    let mut read_write = ReadWrite {
                        now: 0,
                        incoming_buffer: buf_2_to_1,
                        expected_incoming_bytes: Some(0),
                        read_bytes: 0,
                        write_buffers: Vec::new(),
                        write_bytes_queued: 0,
                        write_bytes_queueable: Some(size1 - buf_1_to_2.len()),
                        wake_up_after: None,
                    };
                    handshake1 = nego.read_write(&mut read_write).unwrap();
                    buf_2_to_1 = read_write.incoming_buffer;
                    buf_1_to_2.extend(
                        read_write
                            .write_buffers
                            .drain(..)
                            .flat_map(|b| b.into_iter()),
                    );
                    for _ in 0..read_write.read_bytes {
                        buf_2_to_1.remove(0);
                    }
                }
            }

            match handshake2 {
                Handshake::Success { .. } => {}
                Handshake::Healthy(nego) => {
                    let mut read_write = ReadWrite {
                        now: 0,
                        incoming_buffer: buf_1_to_2,
                        expected_incoming_bytes: Some(0),
                        read_bytes: 0,
                        write_buffers: Vec::new(),
                        write_bytes_queued: 0,
                        write_bytes_queueable: Some(size2 - buf_2_to_1.len()),
                        wake_up_after: None,
                    };
                    handshake2 = nego.read_write(&mut read_write).unwrap();
                    buf_1_to_2 = read_write.incoming_buffer;
                    buf_2_to_1.extend(
                        read_write
                            .write_buffers
                            .drain(..)
                            .flat_map(|b| b.into_iter()),
                    );
                    for _ in 0..read_write.read_bytes {
                        buf_1_to_2.remove(0);
                    }
                }
            }
        }
    }

    test_with_buffer_sizes(256, 256);
    // TODO: not passing because Noise wants at least 19 bytes of buffer
    //test_with_buffer_sizes(1, 1);
    //test_with_buffer_sizes(1, 2048);
    //test_with_buffer_sizes(2048, 1);
}
