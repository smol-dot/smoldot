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

use super::{Config, Error, IncomingDataDetail, Yamux};

#[test]
fn not_immediate_data_send_when_opening_substream() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let _ = yamux.open_substream(());
    assert!(yamux.extract_next(usize::max_value()).is_none())
}

#[test]
fn syn_sent() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let substream_id = yamux.open_substream(());
    yamux.write(substream_id, b"foo".to_vec());

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 1]));
    assert!(output.ends_with(&[0, 0, 0, 3, 102, 111, 111]));
}

#[test]
fn ack_sent() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let mut opened_substream = None;

    {
        let data = [0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0];
        let mut cursor = 0;
        while cursor < data.len() {
            let outcome = yamux.incoming_data(&data[cursor..]).unwrap();
            yamux = outcome.yamux;
            cursor += outcome.bytes_read;
            match outcome.detail {
                Some(IncomingDataDetail::IncomingSubstream) => {
                    assert!(opened_substream.is_none());
                    opened_substream = Some(yamux.accept_pending_substream(()))
                }
                _ => {}
            }
        }
    }

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    assert_eq!(
        output,
        &[0, 0, 0, 2, 0, 0, 0, 84, 0, 0, 0, 3, 102, 111, 111]
    );
}

#[test]
fn invalid_inbound_substream_id() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let data = [0, 0, 0, 1, 0, 0, 0, 83, 0, 0, 0, 0];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::InvalidInboundStreamId(v)) if v.get() == 83 => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn substream_opened_twice() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let data = [
        0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0,
    ];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    yamux.accept_pending_substream(());
                }
            }
            Err(Error::UnexpectedSyn(v)) if v.get() == 84 => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn substream_opened_back_after_rst() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let data = [
        0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 84, 0, 0, 0, 0,
    ];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    yamux.accept_pending_substream(());
                }
            }
            Err(_) => panic!(),
        }
    }

    // Test success.
}
