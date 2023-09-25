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

use super::ToBackground;
use crate::platform::{
    address_parse, ConnectError, MultiStreamWebRtcConnection, PlatformRef, SubstreamDirection,
};

use alloc::{boxed::Box, string::String};
use core::{pin, time::Duration};
use futures_lite::FutureExt as _;
use futures_util::{future, stream::FuturesUnordered, FutureExt as _, StreamExt as _};
use smoldot::{libp2p::collection::SubstreamFate, network::service};

/// Asynchronous task managing a specific connection, including the connection process and the
/// processing of the connection after it's been open.
pub(super) async fn connection_task<TPlat: PlatformRef>(
    start_connect: service::StartConnect<TPlat::Instant>,
    platform: TPlat,
    messages_tx: async_channel::Sender<ToBackground<TPlat>>,
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
                platform.supports_connection_type(match &addr {
                    address_parse::AddressOrMultiStreamAddress::Address(addr) => From::from(addr),
                    address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(addr) => {
                        From::from(addr)
                    }
                })
            });
        let socket = address.map(|addr| match addr {
            address_parse::AddressOrMultiStreamAddress::Address(addr) => either::Left(
                platform
                    .connect_stream(addr)
                    .map(|res| res.map(either::Left)),
            ),
            address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(addr) => either::Right(
                platform
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
            platform.sleep_until(start_connect.timeout).await;
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
                let _ = messages_tx
                    .send(ToBackground::ConnectionAttemptErr {
                        pending_id: start_connect.id,
                        expected_peer_id: start_connect.expected_peer_id,
                        is_bad_addr,
                    })
                    .await;

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
            let _ = messages_tx
                .send(ToBackground::ConnectionAttemptOkSingleStream {
                    pending_id: start_connect.id,
                    connection,
                    expected_peer_id: start_connect.expected_peer_id,
                    multiaddr: start_connect.multiaddr,
                    handshake_kind: service::SingleStreamHandshakeKind::MultistreamSelectNoiseYamux,
                })
                .await;
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
            let _ = messages_tx
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
                .await;
        }
    }
}

/// Asynchronous task managing a specific single-stream connection after it's been open.
pub(super) async fn single_stream_connection_task<TPlat: PlatformRef>(
    mut socket: TPlat::Stream,
    address: String,
    platform: TPlat,
    connection_id: service::ConnectionId,
    mut connection_task: service::SingleStreamConnectionTask<TPlat::Instant>,
    mut coordinator_to_connection: async_channel::Receiver<
        service::CoordinatorToConnection<TPlat::Instant>,
    >,
    connection_to_coordinator: async_channel::Sender<ToBackground<TPlat>>,
) {
    let mut socket = pin::pin!(socket);

    // Future that sends a message to the coordinator. Only one message is sent to the coordinator
    // at a time. `None` if no message is being sent.
    let mut message_sending = None;

    loop {
        // Because only one message should be sent to the coordinator at a time, and that
        // processing the socket might generate a message, we only process the socket if no
        // message is currently being sent.
        if message_sending.is_none() {
            if let Ok(mut socket_read_write) = platform.read_write_access(socket.as_mut()) {
                let read_bytes_before = socket_read_write.read_bytes;
                let written_bytes_before = socket_read_write.write_bytes_queued;
                let write_closed = socket_read_write.write_bytes_queueable.is_none();

                connection_task.read_write(&mut *socket_read_write);

                if socket_read_write.read_bytes != read_bytes_before
                    || socket_read_write.write_bytes_queued != written_bytes_before
                    || (!write_closed && socket_read_write.write_bytes_queueable.is_none())
                {
                    log::trace!(target: "connections",
                        "Connection({address}) <=> read={}; written={}; wake_up_after={:?}; write_close={:?}",
                        socket_read_write.read_bytes - read_bytes_before,
                        socket_read_write.write_bytes_queued - written_bytes_before,
                        socket_read_write.wake_up_after.as_ref().map(|w| {
                            if *w > socket_read_write.now {
                                w.clone() - socket_read_write.now.clone()
                            } else {
                                Duration::new(0, 0)
                            }
                        }),
                        socket_read_write.write_bytes_queueable.is_none(),
                    );
                }
            } else {
                // Error on the socket.
                if !connection_task.is_reset_called() {
                    log::trace!(target: "connections", "Connection({address}) => Reset");
                    connection_task.reset();
                }
            }

            // Try pull message to send to the coordinator.

            // Calling this method takes ownership of the task and returns that task if it has
            // more work to do. If `None` is returned, then the entire task is gone and the
            // connection must be abruptly closed, which is what happens when we return from
            // this function.
            let (task_update, message) = connection_task.pull_message_to_coordinator();
            if let Some(task_update) = task_update {
                connection_task = task_update;
                debug_assert!(message_sending.is_none());
                if let Some(message) = message {
                    message_sending = Some(connection_to_coordinator.send(
                        super::ToBackground::ConnectionMessage {
                            connection_id,
                            message,
                        },
                    ));
                }
            } else {
                return;
            }
        }

        // Now wait for something interesting to happen before looping again.

        enum WhatHappened<TPlat: PlatformRef> {
            CoordinatorMessage(service::CoordinatorToConnection<TPlat::Instant>),
            CoordinatorDead,
            SocketEvent,
            MessageSent,
        }

        let what_happened: WhatHappened<TPlat> = {
            let coordinator_message = async {
                match coordinator_to_connection.next().await {
                    Some(msg) => WhatHappened::CoordinatorMessage(msg),
                    None => WhatHappened::CoordinatorDead,
                }
            };

            let socket_event = {
                // The future returned by `wait_read_write_again` yields when `read_write_access`
                // must be called. Because we only call `read_write_access` when `message_sending`
                // is `None`, we also call `wait_read_write_again` only when `message_sending` is
                // `None`.
                let fut = if message_sending.is_none() {
                    Some(platform.wait_read_write_again(socket.as_mut()))
                } else {
                    None
                };
                async {
                    if let Some(fut) = fut {
                        fut.await;
                        WhatHappened::SocketEvent
                    } else {
                        future::pending().await
                    }
                }
            };

            let message_sent = async {
                let result = if let Some(message_sending) = message_sending.as_mut() {
                    message_sending.await
                } else {
                    future::pending().await
                };
                message_sending = None;
                if result.is_ok() {
                    WhatHappened::MessageSent
                } else {
                    WhatHappened::CoordinatorDead
                }
            };

            coordinator_message.or(socket_event).or(message_sent).await
        };

        match what_happened {
            WhatHappened::CoordinatorMessage(message) => {
                connection_task.inject_coordinator_message(message);
            }
            WhatHappened::CoordinatorDead => return,
            WhatHappened::SocketEvent => {}
            WhatHappened::MessageSent => {}
        }
    }
}

/// Asynchronous task managing a specific multi-stream connection after it's been open.
///
/// > **Note**: This function is specific to WebRTC in the sense that it checks whether the reading
/// >           and writing sides of substreams never close, and adjusts the size of the write
/// >           buffer to not go over the frame size limit of WebRTC. It can easily be made more
/// >           general-purpose.
pub(super) async fn webrtc_multi_stream_connection_task<TPlat: PlatformRef>(
    mut connection: TPlat::MultiStream,
    address: String,
    platform: TPlat,
    connection_id: service::ConnectionId,
    mut connection_task: service::MultiStreamConnectionTask<TPlat::Instant, usize>,
    mut coordinator_to_connection: async_channel::Receiver<
        service::CoordinatorToConnection<TPlat::Instant>,
    >,
    connection_to_coordinator: async_channel::Sender<ToBackground<TPlat>>,
) {
    // Future that sends a message to the coordinator. Only one message is sent to the coordinator
    // at a time. `None` if no message is being sent.
    let mut message_sending = None;
    // Number of substreams that are currently being opened by the `PlatformRef` implementation
    // and that the `connection_task` state machine isn't aware of yet.
    let mut pending_opening_out_substreams = 0;
    // Stream that yields an item whenever a substream is ready to be read-written.
    // TODO: we box the future because of the type checker being annoying
    let mut when_substreams_rw_ready = FuturesUnordered::<
        pin::Pin<Box<dyn future::Future<Output = (pin::Pin<Box<TPlat::Stream>>, usize)> + Send>>,
    >::new();
    // Identifier to assign to the next substream.
    let mut next_substream_id = 0; // TODO: weird API

    loop {
        // Start opening new outbound substreams, if needed.
        for _ in 0..connection_task
            .desired_outbound_substreams()
            .saturating_sub(pending_opening_out_substreams)
        {
            platform.open_out_substream(&mut connection);
            pending_opening_out_substreams += 1;
        }

        // Now wait for something interesting to happen before looping again.

        enum WhatHappened<TPlat: PlatformRef> {
            CoordinatorMessage(service::CoordinatorToConnection<TPlat::Instant>),
            CoordinatorDead,
            SocketEvent(pin::Pin<Box<TPlat::Stream>>, usize),
            MessageSent,
            NewSubstream(TPlat::Stream, SubstreamDirection),
            ConnectionReset,
        }

        let what_happened: WhatHappened<TPlat> = {
            let coordinator_message = async {
                match coordinator_to_connection.next().await {
                    Some(msg) => WhatHappened::CoordinatorMessage(msg),
                    None => WhatHappened::CoordinatorDead,
                }
            };

            let socket_event = {
                // The future returned by `wait_read_write_again` yields when `read_write_access`
                // must be called. Because we only call `read_write_access` when `message_sending`
                // is `None`, we also call `wait_read_write_again` only when `message_sending` is
                // `None`.
                let fut = if message_sending.is_none() {
                    Some(when_substreams_rw_ready.select_next_some())
                } else {
                    None
                };
                async move {
                    if let Some(fut) = fut {
                        let (stream, substream_id) = fut.await;
                        WhatHappened::SocketEvent(stream, substream_id)
                    } else {
                        future::pending().await
                    }
                }
            };

            let message_sent = async {
                let result: Result<(), _> = if let Some(message_sending) = message_sending.as_mut()
                {
                    message_sending.await
                } else {
                    future::pending().await
                };
                message_sending = None;
                if result.is_ok() {
                    WhatHappened::MessageSent
                } else {
                    WhatHappened::CoordinatorDead
                }
            };

            // Future that is woken up when a new substream is available.
            let next_substream = async {
                if connection_task.is_reset_called() {
                    future::pending().await
                } else {
                    match platform.next_substream(&mut connection).await {
                        Some((stream, direction)) => WhatHappened::NewSubstream(stream, direction),
                        None => WhatHappened::ConnectionReset,
                    }
                }
            };

            coordinator_message
                .or(socket_event)
                .or(message_sent)
                .or(next_substream)
                .await
        };

        match what_happened {
            WhatHappened::CoordinatorMessage(message) => {
                connection_task.inject_coordinator_message(message);
            }
            WhatHappened::CoordinatorDead => return,
            WhatHappened::SocketEvent(mut socket, substream_id) => {
                debug_assert!(message_sending.is_none());

                let substream_fate = if let Ok(mut socket_read_write) =
                    platform.read_write_access(socket.as_mut())
                {
                    let read_bytes_before = socket_read_write.read_bytes;
                    let written_bytes_before = socket_read_write.write_bytes_queued;
                    let write_closed = socket_read_write.write_bytes_queueable.is_none();

                    let substream_fate = connection_task
                        .substream_read_write(&substream_id, &mut *socket_read_write);

                    if socket_read_write.read_bytes != read_bytes_before
                        || socket_read_write.write_bytes_queued != written_bytes_before
                        || (!write_closed && socket_read_write.write_bytes_queueable.is_none())
                    {
                        log::trace!(target: "connections",
                            "Connection({address}) <=> substream_id={substream_id}; read={}; written={}; wake_up_after={:?}; write_close={:?}; fate={substream_fate:?}",
                            socket_read_write.read_bytes - read_bytes_before,
                            socket_read_write.write_bytes_queued - written_bytes_before,
                            socket_read_write.wake_up_after.as_ref().map(|w| {
                                if *w > socket_read_write.now {
                                    w.clone() - socket_read_write.now.clone()
                                } else {
                                    Duration::new(0, 0)
                                }
                            }),
                            socket_read_write.write_bytes_queueable.is_none(),
                        );
                    }

                    substream_fate
                } else {
                    // Error on the socket.
                    if !connection_task.is_reset_called() {
                        log::trace!(target: "connections", "Connection({address}) => SubstreamReset(substream_id={substream_id})");
                        connection_task.reset();
                    }
                    SubstreamFate::Reset
                };

                // Try pull message to send to the coordinator.

                // Calling this method takes ownership of the task and returns that task if it has
                // more work to do. If `None` is returned, then the entire task is gone and the
                // connection must be abruptly closed, which is what happens when we return from
                // this function.
                let (task_update, message) = connection_task.pull_message_to_coordinator();
                if let Some(task_update) = task_update {
                    connection_task = task_update;
                    debug_assert!(message_sending.is_none());
                    if let Some(message) = message {
                        message_sending = Some(connection_to_coordinator.send(
                            super::ToBackground::ConnectionMessage {
                                connection_id,
                                message,
                            },
                        ));
                    }
                } else {
                    return;
                }

                // Put back the stream in `when_substreams_rw_ready`.
                if let SubstreamFate::Continue = substream_fate {
                    when_substreams_rw_ready.push({
                        let platform = platform.clone();
                        Box::pin(async move {
                            platform.wait_read_write_again(socket.as_mut());
                            (socket, substream_id)
                        })
                    });
                }
            }
            WhatHappened::MessageSent => {}
            WhatHappened::ConnectionReset => {
                debug_assert!(!connection_task.is_reset_called());
                log::trace!(target: "connections", "Connection({address}) => Reset");
                connection_task.reset();
            }
            WhatHappened::NewSubstream(substream, direction) => {
                log::trace!(target: "connections", "Connection({address}) => NewSubstream({direction:?})");
                let outbound = match direction {
                    SubstreamDirection::Outbound => true,
                    SubstreamDirection::Inbound => false,
                };
                let substream_id = next_substream_id;
                next_substream_id += 1;
                connection_task.add_substream(substream_id, outbound);
                if outbound {
                    pending_opening_out_substreams -= 1;
                }

                when_substreams_rw_ready
                    .push(Box::pin(async move { (Box::pin(substream), substream_id) }));
            }
        }
    }
}
