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

#![no_main]

use smoldot::libp2p::{
    connection::{
        established::{Config, Event, InboundTy},
        noise, single_stream_handshake,
    },
    read_write::ReadWrite,
};

use core::{iter, time::Duration};

// This fuzzing target simulates an incoming or outgoing connection whose handshake has succeeded.
// The remote endpoint of that connection sends the fuzzing data to smoldot after it has been
// encrypted. Encrypting the fuzzing data means that the fuzzing test will not trigger payload
// decode failures. The data that smoldot sends back on that connection is silently discarded and
// doesn't influence the behaviour of this fuzzing test.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut data = data;

    // We use the first element of ̀`data` to determine whether we have opened the connection
    // or whether the remote has opened it.
    let local_is_initiator = {
        if data.is_empty() {
            return;
        }
        let is_initiator = (data[0] % 2) == 0;
        data = &data[1..];
        is_initiator
    };

    // Note that the noise keys and randomness are constant rather than being derived from the
    // fuzzing data. This is because we're not here to fuzz the cryptographic code (which we
    // assume is working well) but everything around it (decoding frames, allocating buffers,
    // etc.).
    let local_key = noise::NoiseKey::new(&[0; 32], &[0; 32]);
    let remote_key = noise::NoiseKey::new(&[1; 32], &[0; 32]);

    let mut local =
        single_stream_handshake::Handshake::noise_yamux(&local_key, &[0; 32], local_is_initiator);
    let mut remote =
        single_stream_handshake::Handshake::noise_yamux(&remote_key, &[0; 32], !local_is_initiator);

    // Store the data that the local has emitted but the remote hasn't received yet, and vice
    // versa.
    let mut local_to_remote_buffer = Vec::new();
    let mut remote_to_local_buffer = Vec::new();

    // Perform handshake.
    while !matches!(
        (&local, &remote),
        (
            single_stream_handshake::Handshake::Success { .. },
            single_stream_handshake::Handshake::Success { .. }
        )
    ) {
        match local {
            single_stream_handshake::Handshake::Success { .. } => {}
            single_stream_handshake::Handshake::Healthy(nego) => {
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: remote_to_local_buffer,
                    expected_incoming_bytes: Some(0),
                    read_bytes: 0,
                    write_buffers: Vec::new(),
                    write_bytes_queued: 0,
                    write_bytes_queueable: Some(8162 - local_to_remote_buffer.len()),
                    wake_up_after: None,
                };

                local = nego.read_write(&mut read_write).unwrap();
                remote_to_local_buffer = read_write.incoming_buffer;
                local_to_remote_buffer.extend(
                    read_write
                        .write_buffers
                        .drain(..)
                        .flat_map(|b| b.into_iter()),
                );
            }
        }

        match remote {
            single_stream_handshake::Handshake::Success { .. } => {}
            single_stream_handshake::Handshake::Healthy(nego) => {
                let mut read_write = ReadWrite {
                    now: Duration::new(0, 0),
                    incoming_buffer: local_to_remote_buffer,
                    expected_incoming_bytes: Some(0),
                    read_bytes: 0,
                    write_buffers: Vec::new(),
                    write_bytes_queued: 0,
                    write_bytes_queueable: Some(8162 - remote_to_local_buffer.len()),
                    wake_up_after: None,
                };

                remote = nego.read_write(&mut read_write).unwrap();
                local_to_remote_buffer = read_write.incoming_buffer;
                remote_to_local_buffer.extend(
                    read_write
                        .write_buffers
                        .drain(..)
                        .flat_map(|b| b.into_iter()),
                );
            }
        }
    }

    // Handshake successful.
    // Turn `local` and `remote` into state machines corresponding to the established connection.
    let mut local = match local {
        single_stream_handshake::Handshake::Success { connection, .. } => connection
            .into_connection::<_, ()>(Config {
                first_out_ping: Duration::new(60, 0),
                max_protocol_name_len: 12,
                max_inbound_substreams: 10,
                substreams_capacity: 16,
                ping_interval: Duration::from_secs(20),
                ping_protocol: "ping".to_owned(),
                ping_timeout: Duration::from_secs(20),
                randomness_seed: [0; 32],
            }),
        _ => unreachable!(),
    };
    let mut remote = match remote {
        single_stream_handshake::Handshake::Success { connection, .. } => {
            connection.into_noise_state_machine()
        }
        _ => unreachable!(),
    };

    // From this point on we will just discard the data sent by `local`.

    // We now encrypt the fuzzing data and add it to the buffer to send to the remote. This is
    // done all in one go.
    for buffer in remote.encrypt(iter::once(data.to_vec())) {
        remote_to_local_buffer.extend_from_slice(&buffer);
    }

    // Now send the data to the connection.
    loop {
        let mut local_read_write = ReadWrite {
            now: Duration::new(0, 0),
            incoming_buffer: remote_to_local_buffer,
            expected_incoming_bytes: Some(0),
            read_bytes: 0,
            write_buffers: Vec::new(),
            write_bytes_queued: 0,
            write_bytes_queueable: Some(8192),
            wake_up_after: None,
        };

        let local_event = match local.read_write(&mut local_read_write) {
            Ok((new_local, local_event)) => {
                local = new_local;
                remote_to_local_buffer = local_read_write.incoming_buffer;
                local_event
            }
            Err(_) => return, // Invalid data. Counts as fuzzing success.
        };

        let (local_read_bytes, local_written_bytes) = (
            local_read_write.read_bytes,
            local_read_write.write_bytes_queued,
        );

        // Process some of the events in order to drive the fuzz test as far as possible.
        match local_event {
            None => {}
            Some(Event::InboundNegotiated { id, protocol_name }) => {
                if protocol_name == "rq" {
                    local.accept_inbound(
                        id,
                        InboundTy::Request {
                            request_max_size: Some(128),
                        },
                        (),
                    )
                } else if protocol_name == "notif" {
                    local.accept_inbound(
                        id,
                        InboundTy::Notifications {
                            max_handshake_size: 128,
                        },
                        (),
                    );
                } else if protocol_name == "ping" {
                    local.accept_inbound(id, InboundTy::Ping, ());
                } else {
                    local.reject_inbound(id);
                }
                continue;
            }
            Some(Event::RequestIn { id, .. }) => {
                let _ = local.respond_in_request(id, Ok(b"dummy response".to_vec()));
                continue;
            }
            Some(Event::NotificationsInOpen { id, .. }) => {
                local.accept_in_notifications_substream(id, b"dummy handshake".to_vec(), 16);
                continue;
            }

            Some(_) => continue,
        }

        if local_read_bytes != 0 || local_written_bytes != 0 {
            continue;
        }

        // Nothing more will happen. Test successful.
        break;
    }
});
