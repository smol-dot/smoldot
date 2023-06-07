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

use super::{
    ConnectError, PlatformConnection, PlatformRef, PlatformSubstreamDirection, ReadBuffer,
};

use alloc::{borrow::Cow, collections::VecDeque, sync::Arc};
use core::{ops, pin::Pin, str, task::Poll, time::Duration};
use futures_util::{future, AsyncRead, AsyncWrite, FutureExt as _};
use smoldot::libp2p::{
    multiaddr::{Multiaddr, ProtocolRef},
    websocket,
};
use std::{
    io::IoSlice,
    net::{IpAddr, SocketAddr},
};

/// Implementation of the [`PlatformRef`] trait that leverages the operating system.
pub struct DefaultPlatform {
    client_name: String,
    client_version: String,
}

impl DefaultPlatform {
    pub fn new(client_name: String, client_version: String) -> Arc<Self> {
        Arc::new(DefaultPlatform {
            client_name,
            client_version,
        })
    }
}

impl PlatformRef for Arc<DefaultPlatform> {
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

    fn now_from_unix_epoch(&self) -> Duration {
        // Intentionally panic if the time is configured earlier than the UNIX EPOCH.
        std::time::UNIX_EPOCH.elapsed().unwrap()
    }

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: Duration) -> Self::Delay {
        async_std::task::sleep(duration).boxed()
    }

    fn sleep_until(&self, when: Self::Instant) -> Self::Delay {
        let duration = when.saturating_duration_since(std::time::Instant::now());
        self.sleep(duration)
    }

    fn spawn_task(&self, _task_name: Cow<str>, task: future::BoxFuture<'static, ()>) {
        async_std::task::spawn(task);
    }

    fn client_name(&self) -> Cow<str> {
        Cow::Borrowed(&self.client_name)
    }

    fn client_version(&self) -> Cow<str> {
        Cow::Borrowed(&self.client_version)
    }

    fn yield_after_cpu_intensive(&self) -> Self::Yield {
        // No-op.
        future::ready(())
    }

    fn connect(&self, multiaddr: &str) -> Self::ConnectFuture {
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
                            buffer: vec![0; 16384],
                            cursor: 0..0,
                        },
                        StreamWriteBuffer::Open {
                            buffer: VecDeque::with_capacity(16384),
                            must_close: false,
                            must_flush: false,
                        },
                    )),
                },
            ))
        })
    }

    fn open_out_substream(&self, c: &mut Self::Connection) {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn next_substream(&self, c: &'_ mut Self::Connection) -> Self::NextSubstreamFuture<'_> {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn update_stream<'a>(&self, stream: &'a mut Self::Stream) -> Self::StreamUpdateFuture<'a> {
        Box::pin(future::poll_fn(|cx| {
            let Some((read_buffer, write_buffer)) = stream.buffers.as_mut() else { return Poll::Pending };

            // Whether the future returned by `update_stream` should return `Ready` or `Pending`.
            let mut update_stream_future_ready = false;

            if let StreamReadBuffer::Open {
                buffer: ref mut buf,
                ref mut cursor,
            } = read_buffer
            {
                // When reading data from the socket, `poll_read` might return "EOF". In that
                // situation, we transition to the `Closed` state, which would discard the data
                // currently in the buffer. For this reason, we only try to read if there is no
                // data left in the buffer.
                if cursor.start == cursor.end {
                    if let Poll::Ready(result) = Pin::new(&mut stream.socket).poll_read(cx, buf) {
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
                                *cursor = 0..bytes;
                            }
                        }
                    }
                }
            }

            if let StreamWriteBuffer::Open {
                buffer: ref mut buf,
                must_flush,
                must_close,
            } = write_buffer
            {
                while !buf.is_empty() {
                    let write_queue_slices = buf.as_slices();
                    if let Poll::Ready(result) = Pin::new(&mut stream.socket).poll_write_vectored(
                        cx,
                        &[
                            IoSlice::new(write_queue_slices.0),
                            IoSlice::new(write_queue_slices.1),
                        ],
                    ) {
                        if !*must_close {
                            // In the situation where the API user wants to close the writing
                            // side, simply sending the buffered data isn't enough to justify
                            // making the future ready.
                            update_stream_future_ready = true;
                        }

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
                    } else {
                        break;
                    }
                }

                if buf.is_empty() && *must_close {
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
                } else if *must_flush {
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
            }

            if update_stream_future_ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }))
    }

    fn read_buffer<'a>(&self, stream: &'a mut Self::Stream) -> ReadBuffer<'a> {
        match stream.buffers.as_ref().map(|(r, _)| r) {
            None => ReadBuffer::Reset,
            Some(StreamReadBuffer::Closed) => ReadBuffer::Closed,
            Some(StreamReadBuffer::Open { buffer, cursor }) => {
                ReadBuffer::Open(&buffer[cursor.clone()])
            }
        }
    }

    fn advance_read_cursor(&self, stream: &mut Self::Stream, extra_bytes: usize) {
        let Some(StreamReadBuffer::Open { ref mut cursor, .. }) =
            stream.buffers.as_mut().map(|(r, _)| r)
        else {
            assert_eq!(extra_bytes, 0);
            return
        };

        assert!(cursor.start + extra_bytes <= cursor.end);
        cursor.start += extra_bytes;
    }

    fn writable_bytes(&self, stream: &mut Self::Stream) -> usize {
        let Some(StreamWriteBuffer::Open { ref mut buffer, must_close: false, ..}) =
            stream.buffers.as_mut().map(|(_, w)| w) else { return 0 };
        buffer.capacity() - buffer.len()
    }

    fn send(&self, stream: &mut Self::Stream, data: &[u8]) {
        debug_assert!(!data.is_empty());

        // Because `writable_bytes` returns 0 if the writing side is closed, and because `data`
        // must always have a size inferior or equal to `writable_bytes`, we know for sure that
        // the writing side isn't closed.
        let Some(StreamWriteBuffer::Open { ref mut buffer, .. } )=
            stream.buffers.as_mut().map(|(_, w)| w) else { panic!() };
        buffer.reserve(data.len());
        buffer.extend(data.iter().copied());
    }

    fn close_send(&self, stream: &mut Self::Stream) {
        // It is not illegal to call this on an already-reset stream.
        let Some((_, write_buffer)) = stream.buffers.as_mut() else { return };

        match write_buffer {
            StreamWriteBuffer::Open {
                must_close: must_close @ false,
                ..
            } => *must_close = true,
            _ => {
                // However, it is illegal to call this on a stream that was already close
                // attempted.
                panic!()
            }
        }
    }
}

/// Implementation detail of [`DefaultPlatform`].
pub struct Stream {
    socket: TcpOrWs,
    /// Read and write buffers of the connection, or `None` if the socket has been reset.
    buffers: Option<(StreamReadBuffer, StreamWriteBuffer)>,
}

enum StreamReadBuffer {
    Open {
        buffer: Vec<u8>,
        cursor: ops::Range<usize>,
    },
    Closed,
}

enum StreamWriteBuffer {
    Open {
        buffer: VecDeque<u8>,
        must_flush: bool,
        must_close: bool,
    },
    Closed,
}

type TcpOrWs =
    future::Either<async_std::net::TcpStream, websocket::Connection<async_std::net::TcpStream>>;
