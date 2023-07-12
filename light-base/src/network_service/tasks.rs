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

use super::{Shared, ToBackground};
use crate::platform::{
    address_parse, ConnectError, MultiStreamWebRtcConnection, PlatformRef, ReadBuffer,
    SubstreamDirection,
};

use alloc::{sync::Arc, vec, vec::Vec};
use core::{cmp, iter, pin};
use futures_lite::FutureExt as _;
use futures_util::{future, FutureExt as _, StreamExt as _};
use smoldot::{
    libp2p::{collection::SubstreamFate, read_write::ReadWrite},
    network::service,
};

/// Asynchronous task managing a specific connection, including the connection process and the
/// processing of the connection after it's been open.
pub(super) async fn connection_task<TPlat: PlatformRef>(
    start_connect: service::StartConnect<TPlat::Instant>,
    shared: Arc<Shared<TPlat>>,
    connection_to_coordinator_tx: async_channel::Sender<ToBackground<TPlat>>,
    is_important: bool,
) {
    log::debug!(
        target: "connections",
        "Pending({:?}, {}) started: {}",
        start_connect.id, start_connect.expected_peer_id,
        start_connect.multiaddr
    );

    // Convert the `multiaddr` (typically of the form `/ip4/a.b.c.d/tcp/d/ws`) into a future.
    // The future returns an error if the multiaddr isn't supported.
    let socket = {
        let address = address_parse::multiaddr_to_address(&start_connect.multiaddr)
            .ok()
            .filter(|addr| {
                shared.platform.supports_connection_type(match &addr {
                    address_parse::AddressOrMultiStreamAddress::Address(addr) => From::from(addr),
                    address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(addr) => {
                        From::from(addr)
                    }
                })
            });
        let socket = address.map(|addr| match addr {
            address_parse::AddressOrMultiStreamAddress::Address(addr) => either::Left(
                shared
                    .platform
                    .connect_stream(addr)
                    .map(|res| res.map(either::Left)),
            ),
            address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(addr) => either::Right(
                shared
                    .platform
                    .connect_multistream(addr)
                    .map(|res| res.map(either::Right)),
            ),
        });
        async move {
            if let Some(socket) = socket {
                socket.await.map_err(|err| (err, false))
            } else {
                Err((
                    ConnectError {
                        message: "Invalid multiaddr".into(),
                    },
                    true,
                ))
            }
        }
    };

    let socket = {
        let timeout = async {
            shared.platform.sleep_until(start_connect.timeout).await;
            Err((
                ConnectError {
                    message: "Timeout reached".into(),
                },
                false,
            ))
        };

        let result = socket.or(timeout).await;

        match (&result, is_important) {
            (Ok(_), _) => {}
            (Err((err, false)), true) => {
                log::warn!(
                    target: "connections",
                    "Failed to reach bootnode {} through {}: {}. Because bootnodes constitue the \
                    access point of a chain, they are expected to be online at all time.",
                    start_connect.expected_peer_id, start_connect.multiaddr,
                    err.message
                );
            }
            (Err((err, is_bad_addr)), _) => {
                log::debug!(
                    target: "connections",
                    "Pending({:?}, {}) => ReachFailed(addr={}, known-unreachable={:?}, error={:?})",
                    start_connect.id, start_connect.expected_peer_id,
                    start_connect.multiaddr, is_bad_addr, err.message
                );
            }
        }

        match result {
            Ok(connection) => connection,
            Err((_, is_bad_addr)) => {
                connection_to_coordinator_tx
                    .send(ToBackground::ConnectionAttemptErr {
                        pending_id: start_connect.id,
                        expected_peer_id: start_connect.expected_peer_id,
                        is_bad_addr,
                    })
                    .await
                    .unwrap();

                // We wake up the background task so that the slot can potentially be
                // assigned to a different peer.
                shared.wake_up_main_background_task.notify(1);

                // Stop the task.
                return;
            }
        }
    };

    // Connection process is successful. Notify the background task.
    // There exists two different kind of connections: "single stream" (for example TCP) that is
    // then divided into substreams internally, or "multi stream" where the substreams management
    // is done by the user of the smoldot crate rather than by the smoldot crate itself.
    match socket {
        either::Left(connection) => {
            connection_to_coordinator_tx
                .send(ToBackground::ConnectionAttemptOkSingleStream {
                    pending_id: start_connect.id,
                    connection,
                    expected_peer_id: start_connect.expected_peer_id,
                    multiaddr: start_connect.multiaddr,
                    handshake_kind: service::SingleStreamHandshakeKind::MultistreamSelectNoiseYamux,
                })
                .await
                .unwrap();
        }
        either::Right(MultiStreamWebRtcConnection {
            connection,
            local_tls_certificate_sha256,
            remote_tls_certificate_sha256,
        }) => {
            // Convert the SHA256 hashes into multihashes.
            let local_tls_certificate_multihash = [12u8, 32]
                .into_iter()
                .chain(local_tls_certificate_sha256.into_iter())
                .collect();
            let remote_tls_certificate_multihash = [12u8, 32]
                .into_iter()
                .chain(remote_tls_certificate_sha256.into_iter())
                .collect();
            connection_to_coordinator_tx
                .send(ToBackground::ConnectionAttemptOkMultiStream {
                    pending_id: start_connect.id,
                    connection,
                    expected_peer_id: start_connect.expected_peer_id,
                    multiaddr: start_connect.multiaddr,
                    handshake_kind: service::MultiStreamHandshakeKind::WebRtc {
                        local_tls_certificate_multihash,
                        remote_tls_certificate_multihash,
                    },
                })
                .await
                .unwrap();
        }
    }
}

/// Asynchronous task managing a specific single-stream connection after it's been open.
// TODO: a lot of logging disappeared
pub(super) async fn single_stream_connection_task<TPlat: PlatformRef>(
    mut connection: TPlat::Stream,
    shared: Arc<Shared<TPlat>>,
    connection_id: service::ConnectionId,
    mut connection_task: service::SingleStreamConnectionTask<TPlat::Instant>,
    coordinator_to_connection: async_channel::Receiver<
        service::CoordinatorToConnection<TPlat::Instant>,
    >,
    connection_to_coordinator: async_channel::Sender<ToBackground<TPlat>>,
) {
    // We need to use `peek()` on this future later down this function.
    let mut coordinator_to_connection = coordinator_to_connection.peekable();

    // In order to write data on a stream, we simply pass a slice, and the platform will copy
    // from this slice the data to send. Consequently, the write buffer is held locally. This is
    // suboptimal compared to writing to a write buffer provided by the platform, but it is easier
    // to implement it this way.
    // Switched to `None` after the connection closes its writing side.
    let mut write_buffer = Some(vec![0; 4096]);

    // The main loop is as follows:
    // - Update the state machine.
    // - Wait until there's something to do.
    // - Repeat.
    loop {
        // Inject in the connection task the messages coming from the coordinator, if any.
        loop {
            let message = match coordinator_to_connection.next().now_or_never() {
                Some(Some(msg)) => msg,
                _ => break,
            };
            connection_task.inject_coordinator_message(message);
        }

        let now = shared.platform.now();

        let (read_bytes, written_bytes, wake_up_after) = if !connection_task.is_reset_called() {
            let write_side_was_open = write_buffer.is_some();
            let writable_bytes = cmp::min(
                shared.platform.writable_bytes(&mut connection),
                write_buffer.as_ref().map_or(0, |b| b.len()),
            );

            let incoming_buffer = match shared.platform.read_buffer(&mut connection) {
                ReadBuffer::Reset => {
                    connection_task.reset();
                    continue;
                }
                ReadBuffer::Open(b) => Some(b),
                ReadBuffer::Closed => None,
            };

            // Perform a read-write. This updates the internal state of the connection task.
            let mut read_write = ReadWrite {
                now: now.clone(),
                incoming_buffer,
                outgoing_buffer: write_buffer
                    .as_mut()
                    .map(|b| (&mut b[..writable_bytes], &mut [][..])),
                read_bytes: 0,
                written_bytes: 0,
                wake_up_after: None,
            };
            connection_task.read_write(&mut read_write);

            // Because the `read_write` object borrows the connection, we need to drop it before we
            // can modify the connection. Before dropping the `read_write`, clone some important
            // information from it.
            let read_bytes = read_write.read_bytes;
            debug_assert!(read_bytes <= incoming_buffer.as_ref().map_or(0, |b| b.len()));
            let write_size_closed = write_side_was_open && read_write.outgoing_buffer.is_none();
            let written_bytes = read_write.written_bytes;
            debug_assert!(written_bytes <= writable_bytes);
            let wake_up_after = read_write.wake_up_after.clone();
            drop(read_write);

            // Now update the connection.
            if written_bytes != 0 {
                // `written_bytes`non-zero when the writing side has been closed before
                // doesn't make sense and would indicate a bug in the networking code
                shared.platform.send(
                    &mut connection,
                    &write_buffer.as_mut().unwrap()[..written_bytes],
                );
            }
            if write_size_closed {
                shared.platform.close_send(&mut connection);
                debug_assert!(write_buffer.is_some());
                write_buffer = None;
            }
            shared
                .platform
                .advance_read_cursor(&mut connection, read_bytes);

            (read_bytes, written_bytes, wake_up_after)
        } else {
            (0, 0, None)
        };

        // Try pull message to send to the coordinator.

        // Calling this method takes ownership of the task and returns that task if it has
        // more work to do. If `None` is returned, then the entire task is gone and the
        // connection must be abruptly closed, which is what happens when we return from
        // this function.
        let (mut task_update, message) = connection_task.pull_message_to_coordinator();

        let has_message = message.is_some();
        if let Some(message) = message {
            // Sending this message might take a long time (in case the coordinator is busy),
            // but this is intentional and serves as a back-pressure mechanism.
            // However, it is important to continue processing the messages coming from the
            // coordinator, otherwise this could result in a deadlock.
            let process_in = async {
                loop {
                    if let Some(message) = coordinator_to_connection.next().await {
                        if let Some(task_update) = &mut task_update {
                            task_update.inject_coordinator_message(message);
                        }
                    } else {
                        break Err(());
                    }
                }
            };

            let send_out = async {
                connection_to_coordinator
                    .send(ToBackground::ConnectionMessage {
                        connection_id,
                        message,
                    })
                    .await
                    .map_err(|_| ())
            };

            if send_out.or(process_in).await.is_err() {
                return;
            }

            shared.wake_up_main_background_task.notify(1);
        }

        if let Some(task_update) = task_update {
            connection_task = task_update;
        } else {
            // As documented in `update_stream`, we call this function one last time in order to
            // give the possibility to the implementation to process closing the writing side
            // before the connection is dropped.
            shared.platform.update_stream(&mut connection).await;
            return;
        }

        // We must call `read_write` and `pull_message_to_coordinator` repeatedly until nothing
        // happens anymore.
        if has_message || read_bytes != 0 || written_bytes != 0 {
            continue;
        }

        // Starting from here, we block the current task until more processing needs to happen.

        // Future ready when the timeout indicated by the connection state machine is reached.
        let poll_after = if wake_up_after
            .as_ref()
            .map_or(false, |wake_up_after| *wake_up_after <= now)
        {
            // "Wake up" immediately.
            continue;
        } else {
            async {
                if let Some(wake_up_after) = wake_up_after {
                    shared.platform.sleep_until(wake_up_after).await
                } else {
                    future::pending().await
                }
            }
        };
        // Future that is woken up when new data is ready on the socket or more data is writable.
        let stream_update = shared.platform.update_stream(&mut connection);
        // Future that is woken up when a new message is coming from the coordinator.
        let message_from_coordinator = async {
            pin::Pin::new(&mut coordinator_to_connection).peek().await;
        };

        // Combines the three futures above into one.
        stream_update
            .or(message_from_coordinator)
            .or(poll_after)
            .await;
    }
}

/// Asynchronous task managing a specific multi-stream connection after it's been open.
///
/// > **Note**: This function is specific to WebRTC in the sense that it checks whether the reading
/// >           and writing sides of substreams never close, and adjusts the size of the write
/// >           buffer to not go over the frame size limit of WebRTC. It can easily be made more
/// >           general-purpose.
// TODO: a lot of logging disappeared
pub(super) async fn webrtc_multi_stream_connection_task<TPlat: PlatformRef>(
    mut connection: TPlat::MultiStream,
    shared: Arc<Shared<TPlat>>,
    connection_id: service::ConnectionId,
    mut connection_task: service::MultiStreamConnectionTask<TPlat::Instant, usize>,
    coordinator_to_connection: async_channel::Receiver<
        service::CoordinatorToConnection<TPlat::Instant>,
    >,
    connection_to_coordinator: async_channel::Sender<ToBackground<TPlat>>,
) {
    // We need to use `peek()` on this future later down this function.
    let mut coordinator_to_connection = coordinator_to_connection.peekable();

    // Number of substreams that are currently being opened by the `PlatformRef` implementation
    // and that the `connection_task` state machine isn't aware of yet.
    let mut pending_opening_out_substreams = 0;
    // Newly-open substream that has just been yielded by the connection.
    let mut newly_open_substream = None;
    // `true` if the remote has force-closed our connection.
    let mut remote_has_reset = false;
    // List of all currently open substreams. The index (as a `usize`) corresponds to the id
    // of this substream within the `connection_task` state machine.
    // For each stream, a boolean indicates whether the local writing side is closed.
    let mut open_substreams = slab::Slab::<(TPlat::Stream, bool)>::with_capacity(16);

    // In order to write data on a stream, we simply pass a slice, and the platform will copy
    // from this slice the data to send. Consequently, the write buffer is held locally. This is
    // suboptimal compared to writing to a write buffer provided by the platform, but it is easier
    // to implement it this way.
    // The write buffer is limited to 16kiB, as this is the maximum amount of data a single
    // WebRTC frame can have.
    let mut write_buffer = vec![0; 16384];

    loop {
        // Start opening new outbound substreams, if needed.
        for _ in 0..connection_task
            .desired_outbound_substreams()
            .saturating_sub(pending_opening_out_substreams)
        {
            shared.platform.open_out_substream(&mut connection);
            pending_opening_out_substreams += 1;
        }

        // The previous wait might have ended when the connection has finished opening a new
        // substream. Notify the `connection_task` state machine.
        if let Some((stream, direction)) = newly_open_substream.take() {
            let outbound = match direction {
                SubstreamDirection::Outbound => true,
                SubstreamDirection::Inbound => false,
            };
            let id = open_substreams.insert((stream, true));
            connection_task.add_substream(id, outbound);
            if outbound {
                pending_opening_out_substreams -= 1;
            }
        }

        // Inject in the connection task the messages coming from the coordinator, if any.
        loop {
            let message = match coordinator_to_connection.next().now_or_never() {
                Some(Some(msg)) => msg,
                _ => break,
            };
            connection_task.inject_coordinator_message(message);
        }

        let now = shared.platform.now();

        // When reading/writing substreams, the substream can ask to be woken up after a certain
        // time. This variable stores the earliest time when we should be waking up.
        let mut wake_up_after = None;

        // Perform a read-write on all substreams.
        // TODO: trying to read/write every single substream every single time is suboptimal, but making this not suboptimal is very complicated
        for substream_id in open_substreams.iter().map(|(id, _)| id).collect::<Vec<_>>() {
            loop {
                let (substream, write_side_was_open) = &mut open_substreams[substream_id];

                let writable_bytes = cmp::min(
                    shared.platform.writable_bytes(substream),
                    write_buffer.len(),
                );

                let incoming_buffer = match shared.platform.read_buffer(substream) {
                    ReadBuffer::Open(buf) => buf,
                    ReadBuffer::Closed => panic!(), // Forbidden for WebRTC.
                    ReadBuffer::Reset => {
                        // Inform the connection task. The substream is now considered dead.
                        connection_task.reset_substream(&substream_id);
                        open_substreams.remove(substream_id);
                        break;
                    }
                };

                let mut read_write = ReadWrite {
                    now: now.clone(),
                    incoming_buffer: Some(incoming_buffer),
                    outgoing_buffer: if *write_side_was_open {
                        Some((&mut write_buffer[..writable_bytes], &mut []))
                    } else {
                        None
                    },
                    read_bytes: 0,
                    written_bytes: 0,
                    wake_up_after,
                };

                debug_assert!(read_write.outgoing_buffer.is_some());

                let substream_fate =
                    connection_task.substream_read_write(&substream_id, &mut read_write);

                // Because the `read_write` object borrows the stream, we need to drop it before we
                // can modify the connection. Before dropping the `read_write`, clone some important
                // information from it.
                let read_bytes = read_write.read_bytes;
                debug_assert!(read_bytes <= incoming_buffer.len());
                let written_bytes = read_write.written_bytes;
                let must_close_writing_side =
                    *write_side_was_open && read_write.outgoing_buffer.is_none();
                wake_up_after = read_write.wake_up_after.take();
                drop(read_write);

                // Now update the connection.
                if written_bytes != 0 {
                    shared
                        .platform
                        .send(substream, &write_buffer[..written_bytes]);
                }
                if must_close_writing_side {
                    shared.platform.close_send(substream);
                    *write_side_was_open = false;
                }
                shared.platform.advance_read_cursor(substream, read_bytes);

                // If the `connection_task` requires this substream to be killed, we drop the
                // `Stream` object.
                if matches!(substream_fate, SubstreamFate::Reset) {
                    open_substreams.remove(substream_id);
                    break;
                }

                if read_bytes == 0 && written_bytes == 0 {
                    break;
                }
            }
        }

        // Try pull message to send to the coordinator.
        {
            // Calling this method takes ownership of the task and returns that task if it has
            // more work to do. If `None` is returned, then the entire task is gone and the
            // connection must be abruptly closed, which is what happens when we return from
            // this function.
            let (mut task_update, message) = connection_task.pull_message_to_coordinator();

            let has_message = message.is_some();
            if let Some(message) = message {
                // Sending this message might take a long time (in case the coordinator is busy),
                // but this is intentional and serves as a back-pressure mechanism.
                // However, it is important to continue processing the messages coming from the
                // coordinator, otherwise this could result in a deadlock.
                let process_in = async {
                    loop {
                        if let Some(message) = coordinator_to_connection.next().await {
                            if let Some(task_update) = &mut task_update {
                                task_update.inject_coordinator_message(message);
                            }
                        } else {
                            break Err(());
                        }
                    }
                };

                let send_out = async {
                    connection_to_coordinator
                        .send(ToBackground::ConnectionMessage {
                            connection_id,
                            message,
                        })
                        .await
                        .map_err(|_| ())
                };

                if send_out.or(process_in).await.is_err() {
                    return;
                }

                shared.wake_up_main_background_task.notify(1);
            }

            if let Some(task_update) = task_update {
                connection_task = task_update;
            } else {
                return;
            }

            if has_message {
                continue;
            }
        }

        // Starting from here, we block the current task until more processing needs to happen.

        // Future ready when the timeout indicated by the connection state machine is reached.
        let poll_after = if wake_up_after
            .as_ref()
            .map_or(false, |wake_up_after| *wake_up_after <= now)
        {
            // "Wake up" immediately.
            continue;
        } else {
            async {
                if let Some(wake_up_after) = wake_up_after {
                    shared.platform.sleep_until(wake_up_after).await
                } else {
                    future::pending().await
                }
                None
            }
        };

        // Future that is woken up when new data is ready on any of the streams.
        let streams_updated = {
            let list = iter::once(future::Either::Right(future::pending()))
                .chain(open_substreams.iter_mut().map(|(_, (stream, _))| {
                    future::Either::Left(shared.platform.update_stream(stream))
                }))
                .collect::<future::SelectAll<_>>();
            async move {
                list.await;
                None
            }
        };

        // Future that is woken up when a new message is coming from the coordinator.
        let message_from_coordinator = async {
            pin::Pin::new(&mut coordinator_to_connection).peek().await;
            None
        };

        // Future that is woken up when a new substream is available.
        let next_substream = async {
            if remote_has_reset {
                future::pending().await
            } else {
                Some(shared.platform.next_substream(&mut connection).await)
            }
        };

        // Do the actual waiting.
        debug_assert!(newly_open_substream.is_none());
        match poll_after
            .or(message_from_coordinator)
            .or(streams_updated)
            .or(next_substream)
            .await
        {
            None => {}
            Some(Some(s)) => newly_open_substream = Some(s),
            Some(None) => {
                // `None` is returned if the remote has force-closed the connection.
                connection_task.reset();
                remote_has_reset = true;
            }
        }
    }
}
