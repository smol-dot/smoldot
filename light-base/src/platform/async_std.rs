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

#![cfg(feature = "std")]
#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

use super::{ConnectError, Platform, PlatformConnection, PlatformSubstreamDirection, ReadBuffer};

use alloc::collections::VecDeque;
use core::{pin::Pin, str, task::Poll, time::Duration};
use futures::prelude::*;
use smoldot::libp2p::{
    multiaddr::{Multiaddr, ProtocolRef},
    websocket,
};
use std::{
    io::{IoSlice, IoSliceMut},
    net::{IpAddr, SocketAddr},
};

/// Implementation of the [`Platform`] trait that uses the `async-std` library and provides TCP
/// and WebSocket connections.
pub struct AsyncStdTcpWebSocket;

// TODO: this trait implementation was written before GATs were stable in Rust; now that the associated types have lifetimes, it should be possible to considerably simplify this code
impl Platform for AsyncStdTcpWebSocket {
    type Delay = future::BoxFuture<'static, ()>;
    type Yield = future::Ready<()>;
    type Instant = std::time::Instant;
    type Connection = std::convert::Infallible;
    type Stream = Stream;
    type ConnectFuture = future::BoxFuture<
        'static,
        Result<PlatformConnection<Self::Stream, Self::Connection>, ConnectError>,
    >;
    type StreamUpdateFuture<'a> = future::BoxFuture<'a, ()>;
    type NextSubstreamFuture<'a> =
        future::Pending<Option<(Self::Stream, PlatformSubstreamDirection)>>;

    fn now_from_unix_epoch() -> Duration {
        // Intentionally panic if the time is configured earlier than the UNIX EPOCH.
        std::time::UNIX_EPOCH.elapsed().unwrap()
    }

    fn now() -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(duration: Duration) -> Self::Delay {
        async_std::task::sleep(duration).boxed()
    }

    fn sleep_until(when: Self::Instant) -> Self::Delay {
        let duration = when.saturating_duration_since(std::time::Instant::now());
        Self::sleep(duration)
    }

    fn yield_after_cpu_intensive() -> Self::Yield {
        // No-op.
        future::ready(())
    }

    fn connect(multiaddr: &str) -> Self::ConnectFuture {
        // We simply copy the address to own it. We could be more zero-cost here, but doing so
        // would considerably complicate the implementation.
        let multiaddr = multiaddr.to_owned();

        Box::pin(async move {
            let addr = multiaddr.parse::<Multiaddr>().map_err(|_| ConnectError {
                is_bad_addr: true,
                message: "Failed to parse address".to_string(),
            })?;

            let mut iter = addr.iter().fuse();
            let proto1 = iter.next().ok_or(ConnectError {
                is_bad_addr: true,
                message: "Unknown protocols combination".to_string(),
            })?;
            let proto2 = iter.next().ok_or(ConnectError {
                is_bad_addr: true,
                message: "Unknown protocols combination".to_string(),
            })?;
            let proto3 = iter.next();

            if iter.next().is_some() {
                return Err(ConnectError {
                    is_bad_addr: true,
                    message: "Unknown protocols combination".to_string(),
                });
            }

            // TODO: doesn't support WebSocket secure connections

            // Ensure ahead of time that the multiaddress is supported.
            let (addr, host_if_websocket) = match (&proto1, &proto2, &proto3) {
                (ProtocolRef::Ip4(ip), ProtocolRef::Tcp(port), None) => (
                    either::Left(SocketAddr::new(IpAddr::V4((*ip).into()), *port)),
                    None,
                ),
                (ProtocolRef::Ip6(ip), ProtocolRef::Tcp(port), None) => (
                    either::Left(SocketAddr::new(IpAddr::V6((*ip).into()), *port)),
                    None,
                ),
                (ProtocolRef::Ip4(ip), ProtocolRef::Tcp(port), Some(ProtocolRef::Ws)) => {
                    let addr = SocketAddr::new(IpAddr::V4((*ip).into()), *port);
                    (either::Left(addr), Some(addr.to_string()))
                }
                (ProtocolRef::Ip6(ip), ProtocolRef::Tcp(port), Some(ProtocolRef::Ws)) => {
                    let addr = SocketAddr::new(IpAddr::V6((*ip).into()), *port);
                    (either::Left(addr), Some(addr.to_string()))
                }

                // TODO: we don't care about the differences between Dns, Dns4, and Dns6
                (
                    ProtocolRef::Dns(addr) | ProtocolRef::Dns4(addr) | ProtocolRef::Dns6(addr),
                    ProtocolRef::Tcp(port),
                    None,
                ) => (either::Right((addr.to_string(), *port)), None),
                (
                    ProtocolRef::Dns(addr) | ProtocolRef::Dns4(addr) | ProtocolRef::Dns6(addr),
                    ProtocolRef::Tcp(port),
                    Some(ProtocolRef::Ws),
                ) => (
                    either::Right((addr.to_string(), *port)),
                    Some(format!("{}:{}", addr, *port)),
                ),

                _ => {
                    return Err(ConnectError {
                        is_bad_addr: true,
                        message: "Unknown protocols combination".to_string(),
                    })
                }
            };

            let tcp_socket = match addr {
                either::Left(socket_addr) => async_std::net::TcpStream::connect(socket_addr).await,
                either::Right((dns, port)) => {
                    async_std::net::TcpStream::connect((&dns[..], port)).await
                }
            };

            if let Ok(tcp_socket) = &tcp_socket {
                let _ = tcp_socket.set_nodelay(true);
            }

            let socket: TcpOrWs = match (tcp_socket, host_if_websocket) {
                (Ok(tcp_socket), Some(host)) => future::Either::Right(
                    websocket::websocket_client_handshake(websocket::Config {
                        tcp_socket,
                        host: &host,
                        url: "/",
                    })
                    .await
                    .map_err(|err| ConnectError {
                        message: format!("Failed to negotiate WebSocket: {err}"),
                        is_bad_addr: false,
                    })?,
                ),
                (Ok(tcp_socket), None) => future::Either::Left(tcp_socket),
                (Err(err), _) => {
                    return Err(ConnectError {
                        is_bad_addr: false,
                        message: format!("Failed to reach peer: {err}"),
                    })
                }
            };

            Ok(PlatformConnection::SingleStreamMultistreamSelectNoiseYamux(
                Stream {
                    socket,
                    buffers: Some((
                        StreamReadBuffer::Open {
                            buffer: VecDeque::with_capacity(16384),
                            is_api_available: true,
                        },
                        StreamWriteBuffer::Open {
                            buffer: VecDeque::with_capacity(16384),
                            must_flush: false,
                        },
                    )),
                },
            ))
        })
    }

    fn open_out_substream(c: &mut Self::Connection) {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn next_substream(c: &'_ mut Self::Connection) -> Self::NextSubstreamFuture<'_> {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn update_stream(stream: &'_ mut Self::Stream) -> Self::StreamUpdateFuture<'_> {
        Box::pin(future::poll_fn(|cx| {
            let Some((read_buffer, write_buffer)) = stream.buffers.as_mut() else { return Poll::Pending };

            // Whether the future returned by `update_stream` should return `Ready` or `Pending`.
            let mut update_stream_future_ready = false;

            if let StreamReadBuffer::Open {
                buffer: ref mut buf,
                is_api_available,
            } = read_buffer
            {
                // If `is_api_available` is `false`, we set it to `true` and pretend that more data
                // has arrived.
                if !*is_api_available {
                    *is_api_available = true;
                    if !buf.is_empty() {
                        update_stream_future_ready = true;
                    }
                }

                let data_in_buf_before_read = buf.len();

                // Only try to read if there is space available in the buffer.
                if data_in_buf_before_read < buf.capacity() {
                    buf.resize(buf.capacity(), 0);

                    let buf_as_slices = {
                        let slices = buf.as_mut_slices();
                        if slices.0.len() > data_in_buf_before_read {
                            (&mut slices.0[data_in_buf_before_read..], slices.1)
                        } else {
                            (
                                &mut slices.1[data_in_buf_before_read - slices.0.len()..],
                                &mut [][..],
                            )
                        }
                    };

                    debug_assert!(!buf_as_slices.0.is_empty());

                    if let Poll::Ready(result) = Pin::new(&mut stream.socket).poll_read_vectored(
                        cx,
                        &mut [
                            IoSliceMut::new(buf_as_slices.0),
                            IoSliceMut::new(buf_as_slices.1),
                        ],
                    ) {
                        update_stream_future_ready = true;
                        match result {
                            Err(_) => {
                                // End the stream.
                                stream.buffers = None;
                                return Poll::Ready(());
                            }
                            Ok(0) => {
                                // EOF.
                                *read_buffer = StreamReadBuffer::Closed;
                            }
                            Ok(bytes) => {
                                buf.truncate(data_in_buf_before_read + bytes);
                            }
                        }
                    } else {
                        buf.truncate(data_in_buf_before_read);
                    }
                }
            }

            if let StreamWriteBuffer::Open {
                buffer: ref mut buf,
                must_flush,
            } = write_buffer
            {
                if !buf.is_empty() {
                    let write_queue_slices = buf.as_slices();
                    if let Poll::Ready(result) = Pin::new(&mut stream.socket).poll_write_vectored(
                        cx,
                        &[
                            IoSlice::new(write_queue_slices.0),
                            IoSlice::new(write_queue_slices.1),
                        ],
                    ) {
                        update_stream_future_ready = true;
                        match result {
                            Err(_) => {
                                // End the stream.
                                stream.buffers = None;
                                return Poll::Ready(());
                            }
                            Ok(bytes) => {
                                *must_flush = true;
                                for _ in 0..bytes {
                                    buf.pop_front();
                                }
                            }
                        }
                    }
                }

                if *must_flush {
                    if let Poll::Ready(result) = Pin::new(&mut stream.socket).poll_flush(cx) {
                        update_stream_future_ready = true;
                        match result {
                            Err(_) => {
                                // End the stream.
                                stream.buffers = None;
                                return Poll::Ready(());
                            }
                            Ok(()) => {
                                *must_flush = false;
                            }
                        }
                    }
                }
            } else if let StreamWriteBuffer::MustClose = write_buffer {
                if let Poll::Ready(result) = Pin::new(&mut stream.socket).poll_close(cx) {
                    update_stream_future_ready = true;
                    match result {
                        Err(_) => {
                            // End the stream.
                            stream.buffers = None;
                            return Poll::Ready(());
                        }
                        Ok(()) => {
                            *write_buffer = StreamWriteBuffer::Closed;
                        }
                    }
                }
            }

            if update_stream_future_ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }))
    }

    fn read_buffer(stream: &mut Self::Stream) -> ReadBuffer {
        match stream.buffers.as_ref().map(|(r, _)| r) {
            None => ReadBuffer::Reset,
            Some(StreamReadBuffer::Closed) => ReadBuffer::Closed,
            Some(StreamReadBuffer::Open {
                buffer,
                is_api_available: true,
            }) => ReadBuffer::Open(buffer.as_slices().0),
            Some(StreamReadBuffer::Open {
                is_api_available: false,
                ..
            }) => ReadBuffer::Open(&[][..]),
        }
    }

    fn advance_read_cursor(stream: &mut Self::Stream, bytes: usize) {
        let Some(StreamReadBuffer::Open { ref mut buffer, is_api_available }) =
            stream.buffers.as_mut().map(|(r, _)| r)
        else {
            assert_eq!(bytes, 0);
            return
        };

        // Since `read_buffer` only returns `buffer.as_slices().0`, we want to prevent the user
        // from accessing `buffer.as_slices().1`. As such, if the user advances the read cursor
        // at the end of `buffer.as_slices().0` we set `is_api_available` to `false` which
        // pretends that the read buffer is now empty.

        assert!(bytes <= buffer.as_slices().0.len());
        if bytes == buffer.as_slices().0.len() {
            *is_api_available = false;
        }

        for _ in 0..bytes {
            buffer.pop_front().unwrap();
        }
    }

    fn writable_bytes(stream: &mut Self::Stream) -> usize {
        let Some(StreamWriteBuffer::Open { ref mut buffer, ..}) =
            stream.buffers.as_mut().map(|(_, w)| w) else { return 0 };
        buffer.capacity() - buffer.len()
    }

    fn send(stream: &mut Self::Stream, data: &[u8]) {
        debug_assert!(!data.is_empty());

        // Because `writable_bytes` returns 0 if the writing side is closed, and because `data`
        // must always have a size inferior or equal to `writable_bytes`, we know for sure that
        // the writing side isn't closed.
        let Some(StreamWriteBuffer::Open { ref mut buffer, .. } )=
            stream.buffers.as_mut().map(|(_, w)| w) else { panic!() };
        buffer.reserve(data.len());
        buffer.extend(data.iter().copied());
    }

    fn close_send(stream: &mut Self::Stream) {
        // It is not illegal to call this on an already-reset stream.
        let Some((_, write_buffer)) = stream.buffers.as_mut() else { return };
        // However, it is illegal to call this on a stream that was already close-attempted.
        assert!(matches!(write_buffer, StreamWriteBuffer::Open { .. }));
        *write_buffer = StreamWriteBuffer::MustClose;
    }
}

/// Implementation detail of [`AsyncStdTcpWebSocket`].
pub struct Stream {
    socket: TcpOrWs,
    /// Read and write buffers of the connection, or `None` if the socket has been reset.
    buffers: Option<(StreamReadBuffer, StreamWriteBuffer)>,
}

enum StreamReadBuffer {
    Open {
        buffer: VecDeque<u8>,
        /// The API of the platform trait only allow providing one slice of read buffer to the
        /// user. Unfortunately, the actual read buffer consists of two slices.
        /// In order to solve that problem, we pretend in the API that the read buffer only
        /// consists either in `buffer.as_slices().0` (if `is_api_available` is `true`) or
        /// is empty (if `is_api_available` is `false`).
        /// The `update_stream` function sets `is_api_available` to `true` if necessary.
        is_api_available: bool,
    },
    Closed,
}

enum StreamWriteBuffer {
    Open {
        buffer: VecDeque<u8>,
        must_flush: bool,
    },
    MustClose,
    Closed,
}

type TcpOrWs =
    future::Either<async_std::net::TcpStream, websocket::Connection<async_std::net::TcpStream>>;
