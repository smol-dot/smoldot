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
    Address, ConnectError, ConnectionType, IpAddr, PlatformConnection, PlatformRef,
    PlatformSubstreamDirection, ReadBuffer,
};

use alloc::{borrow::Cow, collections::VecDeque, sync::Arc};
use core::{ops, pin::Pin, str, task::Poll, time::Duration};
use futures_util::{future, AsyncRead, AsyncWrite, FutureExt as _};
use smoldot::libp2p::websocket;
use std::{io::IoSlice, net::SocketAddr};

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
    type Instant = std::time::Instant;
    type MultiStream = std::convert::Infallible;
    type Stream = Stream;
    type ConnectFuture = future::BoxFuture<
        'static,
        Result<PlatformConnection<Self::Stream, Self::MultiStream>, ConnectError>,
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
        smol::Timer::after(duration).map(|_| ()).boxed()
    }

    fn sleep_until(&self, when: Self::Instant) -> Self::Delay {
        let duration = when.saturating_duration_since(std::time::Instant::now());
        self.sleep(duration)
    }

    fn spawn_task(
        &self,
        _task_name: Cow<str>,
        task: impl future::Future<Output = ()> + Send + 'static,
    ) {
        smol::spawn(task).detach();
    }

    fn client_name(&self) -> Cow<str> {
        Cow::Borrowed(&self.client_name)
    }

    fn client_version(&self) -> Cow<str> {
        Cow::Borrowed(&self.client_version)
    }

    fn supports_connection_type(&self, connection_type: ConnectionType) -> bool {
        // TODO: support WebSocket secure
        matches!(
            connection_type,
            ConnectionType::Tcp | ConnectionType::WebSocket { secure: false, .. }
        )
    }

    fn connect(&self, multiaddr: Address) -> Self::ConnectFuture {
        let (tcp_socket_addr, host_if_websocket): (
            either::Either<SocketAddr, (String, u16)>,
            Option<String>,
        ) = match multiaddr {
            Address::TcpDns { hostname, port } => {
                (either::Right((hostname.to_string(), port)), None)
            }
            Address::TcpIp {
                ip: IpAddr::V4(ip),
                port,
            } => (either::Left(SocketAddr::from((ip, port))), None),
            Address::TcpIp {
                ip: IpAddr::V6(ip),
                port,
            } => (either::Left(SocketAddr::from((ip, port))), None),
            Address::WebSocketDns {
                hostname,
                port,
                secure: false,
            } => (
                either::Right((hostname.to_string(), port)),
                Some(format!("{}:{}", hostname, port)),
            ),
            Address::WebSocketIp {
                ip: IpAddr::V4(ip),
                port,
            } => {
                let addr = SocketAddr::from((ip, port));
                (either::Left(addr), Some(addr.to_string()))
            }
            Address::WebSocketIp {
                ip: IpAddr::V6(ip),
                port,
            } => {
                let addr = SocketAddr::from((ip, port));
                (either::Left(addr), Some(addr.to_string()))
            }

            // The API user of the `PlatformRef` trait is never supposed to open connections of
            // a type that isn't supported.
            _ => unreachable!(),
        };

        Box::pin(async move {
            let tcp_socket = match tcp_socket_addr {
                either::Left(socket_addr) => smol::net::TcpStream::connect(socket_addr).await,
                either::Right((dns, port)) => smol::net::TcpStream::connect((&dns[..], port)).await,
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
                    })?,
                ),
                (Ok(tcp_socket), None) => future::Either::Left(tcp_socket),
                (Err(err), _) => {
                    return Err(ConnectError {
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

    fn open_out_substream(&self, c: &mut Self::MultiStream) {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn next_substream(&self, c: &'_ mut Self::MultiStream) -> Self::NextSubstreamFuture<'_> {
        // This function can only be called with so-called "multi-stream" connections. We never
        // open such connection.
        match *c {}
    }

    fn update_stream<'a>(&self, stream: &'a mut Self::Stream) -> Self::StreamUpdateFuture<'a> {
        Box::pin(future::poll_fn(|cx| {
            let Some((read_buffer, write_buffer)) = stream.buffers.as_mut() else {
                return Poll::Pending;
            };

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
            return;
        };

        assert!(cursor.start + extra_bytes <= cursor.end);
        cursor.start += extra_bytes;
    }

    fn writable_bytes(&self, stream: &mut Self::Stream) -> usize {
        let Some(StreamWriteBuffer::Open {
            ref mut buffer,
            must_close: false,
            ..
        }) = stream.buffers.as_mut().map(|(_, w)| w)
        else {
            return 0;
        };
        buffer.capacity() - buffer.len()
    }

    fn send(&self, stream: &mut Self::Stream, data: &[u8]) {
        debug_assert!(!data.is_empty());

        // Because `writable_bytes` returns 0 if the writing side is closed, and because `data`
        // must always have a size inferior or equal to `writable_bytes`, we know for sure that
        // the writing side isn't closed.
        let Some(StreamWriteBuffer::Open { ref mut buffer, .. }) =
            stream.buffers.as_mut().map(|(_, w)| w)
        else {
            panic!()
        };
        buffer.reserve(data.len());
        buffer.extend(data.iter().copied());
    }

    fn close_send(&self, stream: &mut Self::Stream) {
        // It is not illegal to call this on an already-reset stream.
        let Some((_, write_buffer)) = stream.buffers.as_mut() else {
            return;
        };

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

type TcpOrWs = future::Either<smol::net::TcpStream, websocket::Connection<smol::net::TcpStream>>;
