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
fn bad_header_data() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    {
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut cursor = 0;
        while cursor < data.len() {
            match yamux.incoming_data(&data[cursor..]) {
                Ok(outcome) => {
                    yamux = outcome.yamux;
                    cursor += outcome.bytes_read;
                }
                Err(Error::HeaderDecode(_)) => return,
                Err(_) => panic!(),
            }
        }
    }

    // Test failed.
    panic!()
}

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
fn extract_bytes_one_by_one() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let substream_id = yamux.open_substream(());
    yamux.write(substream_id, b"foo".to_vec());

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(1) {
        assert_eq!(out.as_ref().len(), 1);
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 1]));
    assert!(output.ends_with(&[0, 0, 0, 3, 102, 111, 111]));
}

#[test]
fn inject_bytes_one_by_one() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let data = [0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 5, 255, 255, 255];
    let mut cursor = 0;

    while cursor < data.len() {
        let outcome = yamux.incoming_data(&data[cursor..][..1]).unwrap();
        yamux = outcome.yamux;
        assert_eq!(outcome.bytes_read, 1);

        match outcome.detail {
            Some(IncomingDataDetail::IncomingSubstream) => {
                assert_eq!(cursor, 11); // We've read 12 bytes but `cursor` is still 11
                yamux.accept_pending_substream(());
            }
            Some(IncomingDataDetail::DataFrame { start_offset, .. }) => {
                assert_eq!(start_offset, 0);
                assert!(cursor >= 12);
                assert_eq!(data[cursor], 255);
            }
            _ => {}
        }

        cursor += 1;
    }

    assert_eq!(cursor, data.len());
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

    yamux.write(opened_substream.unwrap(), b"foo".to_vec());

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
fn rst_sent_when_rejecting() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    {
        let data = [0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0];
        let mut cursor = 0;
        while cursor < data.len() {
            let outcome = yamux.incoming_data(&data[cursor..]).unwrap();
            yamux = outcome.yamux;
            cursor += outcome.bytes_read;
            match outcome.detail {
                Some(IncomingDataDetail::IncomingSubstream) => yamux.reject_pending_substream(),
                _ => {}
            }
        }
    }

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.ends_with(&[0, 8, 0, 0, 0, 84, 0, 0, 0, 0]));
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

    // One SYN frame, one RST frame, one SYN frame again. All using the same substream ID.
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

                let dead_substream = yamux.dead_substreams().next().map(|(s, ..)| s);
                if let Some(substream_id) = dead_substream {
                    yamux.remove_dead_substream(substream_id);
                }
            }
            Err(_) => panic!(),
        }
    }

    // Test success.
    assert_eq!(cursor, data.len());
}

#[test]
fn multiple_writes_combined_into_one() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let substream_id = yamux.open_substream(());

    // Write multiple times. All these writes should be combined into a single data frame.
    yamux.write(substream_id, b"aaaa".to_vec());
    yamux.write(substream_id, b"cc".to_vec());
    yamux.write(substream_id, b"bbbbbb".to_vec());

    let mut output = Vec::new();
    // We read 7 bytes at a time, in order to land in-between the buffers.
    while let Some(out) = yamux.extract_next(7) {
        assert!(out.as_ref().len() <= 7);
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 1]));
    assert!(output.ends_with(&[0, 0, 0, 12, 97, 97, 97, 97, 99, 99, 98, 98, 98, 98, 98, 98]));
}

#[test]
fn close_before_syn_sent() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let substream_id = yamux.open_substream(());
    yamux.write(substream_id, b"foo".to_vec());
    yamux.close(substream_id);

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 1 | 4]));
    assert!(output.ends_with(&[0, 0, 0, 3, 102, 111, 111]));
}

#[test]
#[should_panic = "write after close"]
fn write_after_close_illegal() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let substream_id = yamux.open_substream(());
    yamux.write(substream_id, b"foo".to_vec());
    assert!(yamux.can_send(substream_id));
    yamux.close(substream_id);
    assert!(!yamux.can_send(substream_id));

    yamux.write(substream_id, b"test".to_vec());
}

#[test]
fn credits_exceeded_checked_before_data_is_received() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    // Data frame with a SYN flag, then data frame with a ton of data.
    // Note that the data isn't actually there. We only *announce* that we're going to send a ton
    // of data. The error should happen anyway, if the data isn't here, as we don't want to buffer
    // data that exceeds the credits limit.
    let data = [
        0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 5, 0, 0, 0, 0xff, 0xff, 0xff,
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
            Err(Error::CreditsExceeded) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn credits_exceeded_checked_at_the_syn() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    // Data frame with a SYN flag and a ton of data.
    // Note that the data isn't actually there. We only *announce* that we're going to send a ton
    // of data. The error should happen anyway, if the data isn't here, as we don't want to buffer
    // data that exceeds the credits limit.
    let data = [0, 0, 0, 1, 0, 0, 0, 84, 5, 0, 0, 0, 0xff, 0xff, 0xff];

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
            Err(Error::CreditsExceeded) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn data_coming_with_the_syn_taken_into_account() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    // Data frame with a SYN flag and 200kiB of data, followed with data frame with 100kiB of
    // data. The limit is 256kiB, so the combination of both exceeds the limit.
    let mut data = [0, 0, 0, 1, 0, 0, 0, 84].to_vec();
    data.extend_from_slice(&(200 * 1024u32).to_be_bytes()[..]);
    data.extend((0..200 * 1024).map(|_| 0u8));
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 84]);
    data.extend_from_slice(&(100 * 1024u32).to_be_bytes()[..]);
    data.extend((0..100 * 1024).map(|_| 0u8));

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
            Err(Error::CreditsExceeded) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn add_remote_window_works() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    // Data frame with a SYN flag and 200kiB of data, followed with data frame with 100kiB of
    // data. The limit is 256kiB, so the combination of both exceeds the limit.
    let mut data = [0, 0, 0, 1, 0, 0, 0, 84].to_vec();
    data.extend_from_slice(&(200 * 1024u32).to_be_bytes()[..]);
    data.extend((0..200 * 1024).map(|_| 0u8));
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 84]);
    data.extend_from_slice(&(100 * 1024u32).to_be_bytes()[..]);
    data.extend((0..100 * 1024).map(|_| 0u8));

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    let substream_id = yamux.accept_pending_substream(());

                    // `add_remote_window` doesn't immediately raise the limit, so we flush the
                    // output buffer in order to obtain a window frame.
                    yamux.add_remote_window(substream_id, 100 * 1024);

                    let mut output = Vec::new();
                    while let Some(out) = yamux.extract_next(usize::max_value()) {
                        output.extend_from_slice(out.as_ref());
                    }
                    // `[0, 1, 144, 0]` is 102400
                    assert_eq!(output, &[0, 1, 0, 2, 0, 0, 0, 84, 0, 1, 144, 0]);
                }
            }
            Err(_) => panic!(),
        }
    }

    // Test succeeded.
    assert_eq!(cursor, data.len());
}

#[test]
fn add_remote_window_doesnt_immediately_raise_limit() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    // Data frame with a SYN flag and 200kiB of data, followed with data frame with 100kiB of
    // data. The limit is 256kiB, so the combination of both exceeds the limit.
    let mut data = [0, 0, 0, 1, 0, 0, 0, 84].to_vec();
    data.extend_from_slice(&(200 * 1024u32).to_be_bytes()[..]);
    data.extend((0..200 * 1024).map(|_| 0u8));
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 84]);
    data.extend_from_slice(&(100 * 1024u32).to_be_bytes()[..]);
    data.extend((0..100 * 1024).map(|_| 0u8));

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    let substream_id = yamux.accept_pending_substream(());

                    // `add_remote_window` shouldn't immediately raise the limit.
                    yamux.add_remote_window(substream_id, 100 * 1024);
                }
            }
            Err(Error::CreditsExceeded) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn remote_default_window_respected() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    let substream_id = yamux.open_substream(());
    yamux.write(substream_id, vec![255; 300 * 1024]); // Exceeds default limit.

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        if output.len() >= 50 {
            panic!("{:?}", out.as_ref().len())
        }
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 1]));
    assert_eq!(&output[8..12], &[0, 4, 0, 0]); // 256 * 1024
    assert_eq!(output.len(), 12 + 256 * 1024);
}

#[test]
fn remote_window_frames_respected() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
    });

    // Window frame with a SYN flag and 5 bytes of window.
    let data = [0, 1, 0, 1, 0, 0, 0, 84, 0, 0, 0, 5];

    let mut accepted_substream = None;

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    assert!(accepted_substream.is_none());
                    accepted_substream = Some(yamux.accept_pending_substream(()));
                }
            }
            Err(_) => panic!(),
        }
    }

    let substream_id = accepted_substream.unwrap();

    yamux.write(substream_id, vec![255; 300 * 1024]); // Exceeds default limit.

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        if output.len() >= 50 {
            panic!("{:?}", out.as_ref().len())
        }
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 2]));
    assert_eq!(&output[8..12], &[0, 4, 0, 5]); // 256 * 1024 + 5
    assert_eq!(output.len(), 12 + 256 * 1024 + 5);
}
