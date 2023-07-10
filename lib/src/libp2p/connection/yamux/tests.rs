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

use super::{
    CloseError, Config, Error, GoAwayErrorCode, IncomingDataDetail, OpenSubstreamError, WriteError,
    Yamux,
};

use core::{
    cmp,
    num::{NonZeroU32, NonZeroUsize},
};

#[test]
fn bad_header_data() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let _ = yamux.open_substream(()).unwrap();
    assert!(yamux.extract_next(usize::max_value()).is_none())
}

#[test]
fn syn_sent() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"foo".to_vec()).unwrap();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 1]));
    assert!(output.ends_with(&[0, 0, 0, 3, 102, 111, 111]));
}

#[test]
fn max_out_data_frame_size_works() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(2).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"foo".to_vec()).unwrap();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    assert_eq!(&output[0..4], &[0, 0, 0, 1]);
    assert_eq!(&output[8..14], &[0, 0, 0, 2, 102, 111]);
    assert_eq!(&output[14..18], &[0, 0, 0, 0]);
    assert_eq!(&output[22..27], &[0, 0, 0, 1, 111]);
    assert_eq!(output.len(), 27);
}

#[test]
fn extract_bytes_one_by_one() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"foo".to_vec()).unwrap();

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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                yamux.accept_pending_substream(()).unwrap();
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let mut opened_substream = None;

    {
        let data = [0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0];
        let mut cursor = 0;
        while cursor < data.len() {
            let outcome = yamux.incoming_data(&data[cursor..]).unwrap();
            yamux = outcome.yamux;
            cursor += outcome.bytes_read;
            if let Some(IncomingDataDetail::IncomingSubstream) = outcome.detail {
                assert!(opened_substream.is_none());
                opened_substream = Some(yamux.accept_pending_substream(()).unwrap())
            }
        }
    }

    yamux
        .write(opened_substream.unwrap(), b"foo".to_vec())
        .unwrap();

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
fn syn_and_ack_together() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let data = [0, 0, 0, 1 | 2, 0, 0, 0, 84, 0, 0, 0, 0];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::UnexpectedAck) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn syn_and_rst_together() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // SYN and RST together. The new substream is simply ignored.
    let data = [0, 0, 0, 1 | 8, 0, 0, 0, 84, 0, 0, 0, 0];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                assert!(!matches!(
                    outcome.detail,
                    Some(IncomingDataDetail::IncomingSubstream)
                ));
            }
            Err(_) => panic!(),
        }
    }

    // Test succeeded.
}

#[test]
fn data_with_rst() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let data = [
        0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 84, 0, 0, 0, 2, 255, 255,
    ];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if let Some(IncomingDataDetail::IncomingSubstream) = outcome.detail {
                    yamux.accept_pending_substream(()).unwrap();
                }
            }
            Err(Error::DataWithRst) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn empty_data_frame_with_rst() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Normal SYN frame then normal RST frame.
    let data = [
        0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 84, 0, 0, 0, 0,
    ];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if let Some(IncomingDataDetail::IncomingSubstream) = outcome.detail {
                    yamux.accept_pending_substream(()).unwrap();
                }
            }
            Err(_) => panic!(),
        }
    }

    // Test succeeded.
}

#[test]
fn rst_sent_when_rejecting() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    {
        let data = [0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0];
        let mut cursor = 0;
        while cursor < data.len() {
            let outcome = yamux.incoming_data(&data[cursor..]).unwrap();
            yamux = outcome.yamux;
            cursor += outcome.bytes_read;
            if let Some(IncomingDataDetail::IncomingSubstream) = outcome.detail {
                yamux.reject_pending_substream().unwrap()
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
fn max_simultaneous_rst_substreams() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(16).unwrap(),
    });

    let mut data = Vec::new();

    // Queue many new substreams.
    for n in 1..32 {
        data.extend_from_slice(&[0, 0, 0, 1]);
        data.extend_from_slice(&u32::to_be_bytes(n * 2)[..]);
        data.extend_from_slice(&[0, 0, 0, 0]);
    }

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
                if let Some(IncomingDataDetail::IncomingSubstream) = outcome.detail {
                    yamux.reject_pending_substream().unwrap()
                }
            }
            Err(Error::MaxSimultaneousRstSubstreamsExceeded) => return,
            Err(_) => panic!(),
        }
    }
}

#[test]
fn invalid_inbound_substream_id() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    yamux.accept_pending_substream(()).unwrap();
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    yamux.accept_pending_substream(()).unwrap();
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
fn substream_opened_back_after_graceful_closing() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // One SYN|FIN frame.
    let data = [0, 0, 0, 1 | 4, 0, 0, 0, 84, 0, 0, 0, 1, 255];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    let substream_id = yamux.accept_pending_substream(()).unwrap();

                    // Close the substream gracefully.
                    yamux.close(substream_id).unwrap();
                }
            }
            Err(_) => panic!(),
        }
    }

    // Flush the queue in order to send out the FIN.
    while yamux.extract_next(usize::max_value()).is_some() {}

    // One SYN frame again, using the same substream ID as earlier.
    let data = [0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 1, 255];

    let mut cursor = 0;
    let mut killed_substream = false;

    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;

                // Because we can't have two substreams with the same ID at the same time, the
                // reading of the new SYN frame will be blocked until we've removed the dead
                // substream.
                if outcome.bytes_read == 0 {
                    let substream_id = yamux.dead_substreams().next().unwrap().0;
                    yamux.remove_dead_substream(substream_id);
                    killed_substream = true;
                    continue;
                }

                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    // Make sure we've removed the dead substream.
                    assert!(killed_substream);
                    return;
                }
            }
            Err(_) => panic!(),
        }
    }

    // Test failure.
    panic!()
}

#[test]
fn missing_ack() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"hello world".to_vec()).unwrap();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    // Data frame without an ACK.
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 0]);
    data.extend_from_slice(&output[4..8]);
    data.extend_from_slice(&[0, 0, 0, 1, 0xff]);

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::ExpectedAck) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn multiple_acks() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"hello world".to_vec()).unwrap();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    // Two data frames with an ACK.
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 2]);
    data.extend_from_slice(&output[4..8]);
    data.extend_from_slice(&[0, 0, 0, 1, 0xff]);
    data.extend_from_slice(&[0, 0, 0, 2]);
    data.extend_from_slice(&output[4..8]);
    data.extend_from_slice(&[0, 0, 0, 1, 0xff]);

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::UnexpectedAck) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn multiple_writes_combined_into_one() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();

    // Write multiple times. All these writes should be combined into a single data frame.
    yamux.write(substream_id, b"aaaa".to_vec()).unwrap();
    yamux.write(substream_id, b"cc".to_vec()).unwrap();
    yamux.write(substream_id, b"bbbbbb".to_vec()).unwrap();

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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"foo".to_vec()).unwrap();
    yamux.close(substream_id).unwrap();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    assert!(output.starts_with(&[0, 0, 0, 1 | 4]));
    assert!(output.ends_with(&[0, 0, 0, 3, 102, 111, 111]));
}

#[test]
fn close_twice() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.close(substream_id).unwrap();
    assert!(matches!(
        yamux.close(substream_id),
        Err(CloseError::AlreadyClosed)
    ));
}

#[test]
fn close_after_reset() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.reset(substream_id).unwrap();
    assert!(matches!(yamux.close(substream_id), Err(CloseError::Reset)));
}

#[test]
fn write_after_close_illegal() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"foo".to_vec()).unwrap();
    assert!(yamux.can_send(substream_id));
    yamux.close(substream_id).unwrap();
    assert!(!yamux.can_send(substream_id));

    assert!(matches!(
        yamux.write(substream_id, b"test".to_vec()),
        Err(WriteError::Closed)
    ));
}

#[test]
fn credits_exceeded_checked_before_data_is_received() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    yamux.accept_pending_substream(()).unwrap();
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    yamux.accept_pending_substream(()).unwrap();
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    yamux.accept_pending_substream(()).unwrap();
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    let substream_id = yamux.accept_pending_substream(()).unwrap();

                    // `add_remote_window` doesn't immediately raise the limit, so we flush the
                    // output buffer in order to obtain a window frame.
                    yamux.add_remote_window_saturating(substream_id, 100 * 1024);

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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    let substream_id = yamux.accept_pending_substream(()).unwrap();

                    // `add_remote_window` shouldn't immediately raise the limit.
                    yamux.add_remote_window_saturating(substream_id, 100 * 1024);
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
fn add_remote_window_saturates() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();

    // Check that `add_remote_window_saturating` doesn't panic.
    yamux.add_remote_window_saturating(substream_id, u64::max_value());
}

#[test]
fn remote_default_window_respected() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, vec![255; 300 * 1024]).unwrap(); // Exceeds default limit.

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
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
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
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
                    accepted_substream = Some(yamux.accept_pending_substream(()).unwrap());
                }
            }
            Err(_) => panic!(),
        }
    }

    let substream_id = accepted_substream.unwrap();

    yamux.write(substream_id, vec![255; 300 * 1024]).unwrap(); // Exceeds default limit.

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

#[test]
fn write_after_fin() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Data frame with SYN|FIN flags, then data frame again.
    let data = [
        0, 0, 0, 5, 0, 0, 0, 84, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 0, 0, 0, 2, 0, 0,
    ];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    yamux.accept_pending_substream(()).unwrap();
                }
            }
            Err(Error::WriteAfterFin) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn write_after_fin_even_with_empty_frame() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Data frame with SYN|FIN flags, then empty data frame.
    let data = [
        0, 0, 0, 5, 0, 0, 0, 84, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 0, 0, 0, 0,
    ];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    yamux.accept_pending_substream(()).unwrap();
                }
            }
            Err(Error::WriteAfterFin) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn window_frame_with_fin_after_fin() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Data frame with SYN|FIN flags, then window frame with FIN flag.
    // The spec is really ambiguous about whether post-FIN window frames must have a FIN flag as
    // well, so when in doubt we accept it.
    let data = [
        0, 0, 0, 5, 0, 0, 0, 84, 0, 0, 0, 2, 0, 0, 0, 1, 0, 4, 0, 0, 0, 84, 0, 0, 0, 5,
    ];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    yamux.accept_pending_substream(()).unwrap();
                }
            }
            Err(_) => panic!(),
        }
    }

    assert_eq!(cursor, data.len());
}

#[test]
fn window_frame_without_fin_after_fin() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Data frame with SYN|FIN flags, then window frame without FIN flag.
    // The spec is really ambiguous about whether post-FIN window frames must have a FIN flag as
    // well, so when in doubt we accept it.
    let data = [
        0, 0, 0, 5, 0, 0, 0, 84, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 84, 0, 0, 0, 5,
    ];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::IncomingSubstream)) {
                    yamux.accept_pending_substream(()).unwrap();
                }
            }
            Err(_) => panic!(),
        }
    }

    assert_eq!(cursor, data.len());
}

#[test]
fn send_ping() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    yamux.queue_ping();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }
    assert_eq!(&output[0..8], &[0, 2, 0, 1, 0, 0, 0, 0]);

    // Ping response frame.
    let mut data = vec![0, 2, 0, 2, 0, 0, 0, 0];
    data.extend_from_slice(&output[8..12]);

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                if matches!(outcome.detail, Some(IncomingDataDetail::PingResponse)) {
                    return;
                }
            }
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn remote_pong_wrong_opaque_value() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    yamux.queue_ping();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }
    assert_eq!(&output[0..8], &[0, 2, 0, 1, 0, 0, 0, 0]);

    // Ping response frame.
    let mut data = vec![0, 2, 0, 2, 0, 0, 0, 0];
    data.extend_from_slice(&output[8..12]);

    // Intentionally modify the opaque value to not match.
    data[10] = data[10].overflowing_add(1).0;

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::PingResponseNotMatching) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn pings_answered_in_wrong_order() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    yamux.queue_ping();
    yamux.queue_ping();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }
    assert_eq!(&output[0..8], &[0, 2, 0, 1, 0, 0, 0, 0]);
    assert_eq!(&output[12..20], &[0, 2, 0, 1, 0, 0, 0, 0]);

    // Ping response frame of the second ping.
    let mut data = vec![0, 2, 0, 2, 0, 0, 0, 0];
    data.extend_from_slice(&output[20..24]);

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::PingResponseNotMatching) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn remote_pong_out_of_nowhere() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Ping response frame.
    let data = &[0, 2, 0, 2, 0, 0, 0, 0, 1, 2, 3, 4];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::PingResponseNotMatching) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn answer_remote_ping() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Ping request frame.
    let data = &[0, 2, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4];

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(_) => panic!(),
        }
    }

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }
    assert_eq!(output, &[0, 2, 0, 2, 0, 0, 0, 0, 1, 2, 3, 4]);
}

#[test]
fn max_simultaneous_queued_pongs() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let mut data = Vec::new();

    // Queue many new pings.
    for _ in 1..16 {
        data.extend_from_slice(&[0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::MaxSimultaneousPingsExceeded) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn simultaneous_pongs_flushed() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let mut data = Vec::new();

    // Queue many new pings.
    for _ in 1..16 {
        data.extend_from_slice(&[0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..][..cmp::min(12, data.len() - cursor)]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;

                // Flush out in order to send the pong.
                while yamux.extract_next(usize::max_value()).is_some() {}
            }
            Err(_) => panic!(),
        }
    }

    // Test succeded.
}

#[test]
fn dont_send_syn_after_goaway() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"foo".to_vec()).unwrap();
    assert!(yamux.can_send(substream_id));

    // GoAway frame.
    let data = &[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(_) => panic!(),
        }
    }

    assert!(!yamux.can_send(substream_id));
    assert!(yamux.extract_next(usize::max_value()).is_none());
    assert_eq!(yamux.dead_substreams().next().unwrap().0, substream_id);
}

#[test]
fn substream_reset_on_goaway_if_not_acked() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"foo".to_vec()).unwrap();
    while yamux.extract_next(usize::max_value()).is_some() {}

    // GoAway frame.
    let data = &[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(_) => panic!(),
        }
    }

    assert!(!yamux.can_send(substream_id));
    assert_eq!(yamux.dead_substreams().next().unwrap().0, substream_id);
}

#[test]
fn can_still_send_after_goaway_if_acked() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    let substream_id = yamux.open_substream(()).unwrap();
    yamux.write(substream_id, b"hello world".to_vec()).unwrap();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }

    // ACK frame followed with GoAway frame.
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 0, 2]);
    data.extend_from_slice(&output[4..8]);
    data.extend_from_slice(&[0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(_) => panic!(),
        }
    }

    assert!(yamux.can_send(substream_id));

    yamux.write(substream_id, b"foo".to_vec()).unwrap();

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }
    assert!(output.ends_with(&[3, 102, 111, 111]));
}

#[test]
fn receive_multiple_goaways() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // Two GoAway frames.
    let data = &[
        0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(Error::MultipleGoAways) => return,
            Err(_) => panic!(),
        }
    }

    // Test failed.
    panic!()
}

#[test]
fn ignore_incoming_substreams_after_goaway() {
    let mut yamux = Yamux::<()>::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    yamux
        .send_goaway(GoAwayErrorCode::NormalTermination)
        .unwrap();

    // New substream.
    let data = [0, 0, 0, 1, 0, 0, 0, 84, 0, 0, 0, 0];
    let mut cursor = 0;
    while cursor < data.len() {
        let outcome = yamux.incoming_data(&data[cursor..]).unwrap();
        yamux = outcome.yamux;
        cursor += outcome.bytes_read;
        assert!(!matches!(
            outcome.detail,
            Some(IncomingDataDetail::IncomingSubstream)
        ));
    }

    let mut output = Vec::new();
    while let Some(out) = yamux.extract_next(usize::max_value()) {
        output.extend_from_slice(out.as_ref());
    }
    assert_eq!(output, &[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn opening_forbidden_after_goaway() {
    let mut yamux = Yamux::new(Config {
        capacity: 0,
        is_initiator: true,
        randomness_seed: [0; 32],
        max_out_data_frame_size: NonZeroU32::new(u32::max_value()).unwrap(),
        max_simultaneous_queued_pongs: NonZeroUsize::new(4).unwrap(),
        max_simultaneous_rst_substreams: NonZeroUsize::new(1024).unwrap(),
    });

    // GoAway frame.
    let data = &[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut cursor = 0;
    while cursor < data.len() {
        match yamux.incoming_data(&data[cursor..]) {
            Ok(outcome) => {
                yamux = outcome.yamux;
                cursor += outcome.bytes_read;
            }
            Err(_) => panic!(),
        }
    }

    assert!(matches!(
        yamux.open_substream(()),
        Err(OpenSubstreamError::GoAwayReceived)
    ));
}
