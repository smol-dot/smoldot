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
    with_buffers, Address, ConnectError, ConnectionType, IpAddr, MultiStreamAddress,
    MultiStreamWebRtcConnection, PlatformRef, SubstreamDirection,
};

use alloc::{borrow::Cow, sync::Arc};
use core::{pin::Pin, str, time::Duration};
use futures_util::{future, FutureExt as _};
use smoldot::libp2p::websocket;
use std::{
    io,
    net::SocketAddr,
    thread,
    time::{Instant, UNIX_EPOCH},
};

/// Implementation of the [`PlatformRef`] trait that leverages the operating system.
pub struct DefaultPlatform {
    client_name: String,
    client_version: String,
    tasks_executor: smol::Executor<'static>,
}

impl DefaultPlatform {
    /// Creates a new [`DefaultPlatform`]. Spawns threads to executor background tasks.
    ///
    /// # Panic
    ///
    /// Panics if it wasn't possible to spawn background threads to execute background tasks.
    ///
    pub fn new(client_name: String, client_version: String) -> Arc<Self> {
        let platform = Arc::new(DefaultPlatform {
            client_name,
            client_version,
            tasks_executor: smol::Executor::new(),
        });

        for n in 0..thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
        {
            let platform = platform.clone();

            let spawn_result = thread::Builder::new()
                .name(format!("tasks-pool-{}", n))
                .spawn(move || {
                    smol::block_on(platform.tasks_executor.run(future::pending::<()>()))
                });

            if let Err(err) = spawn_result {
                panic!("Failed to spawn execution thread: {err}");
            }
        }

        platform
    }
}

impl PlatformRef for Arc<DefaultPlatform> {
    type Delay = futures_util::future::Map<smol::Timer, fn(Instant) -> ()>;
    type Instant = Instant;
    type MultiStream = std::convert::Infallible; // TODO: replace with `!` once stable: https://github.com/rust-lang/rust/issues/35121
    type Stream = Stream;
    type StreamConnectFuture = future::BoxFuture<'static, Result<Self::Stream, ConnectError>>;
    type MultiStreamConnectFuture = future::BoxFuture<
        'static,
        Result<MultiStreamWebRtcConnection<Self::MultiStream>, ConnectError>,
    >;
    type ReadWriteAccess<'a> = with_buffers::ReadWriteAccess<'a>;
    type StreamUpdateFuture<'a> = future::BoxFuture<'a, ()>;
    type StreamErrorRef<'a> = &'a io::Error;
    type NextSubstreamFuture<'a> = future::Pending<Option<(Self::Stream, SubstreamDirection)>>;

    fn now_from_unix_epoch(&self) -> Duration {
        // Intentionally panic if the time is configured earlier than the UNIX EPOCH.
        UNIX_EPOCH.elapsed().unwrap()
    }

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn fill_random_bytes(&self, buffer: &mut [u8]) {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), buffer);
    }

    fn sleep(&self, duration: Duration) -> Self::Delay {
        smol::Timer::after(duration).map(|_| ())
    }

    fn sleep_until(&self, when: Self::Instant) -> Self::Delay {
        smol::Timer::at(when).map(|_| ())
    }

    fn spawn_task(
        &self,
        _task_name: Cow<str>,
        task: impl future::Future<Output = ()> + Send + 'static,
    ) {
        self.tasks_executor.spawn(task).detach();
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
            ConnectionType::TcpIpv4
                | ConnectionType::TcpIpv6
                | ConnectionType::TcpDns
                | ConnectionType::WebSocketIpv4 { .. }
                | ConnectionType::WebSocketIpv6 { .. }
                | ConnectionType::WebSocketDns { secure: false, .. }
        )
    }

    fn connect_stream(&self, multiaddr: Address) -> Self::StreamConnectFuture {
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

            Ok(Stream(with_buffers::WithBuffers::new(socket)))
        })
    }

    fn connect_multistream(&self, _address: MultiStreamAddress) -> Self::MultiStreamConnectFuture {
        panic!()
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

    fn read_write_access<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Result<Self::ReadWriteAccess<'a>, &'a io::Error> {
        let stream = stream.project();
        stream.0.read_write_access(Instant::now())
    }

    fn wait_read_write_again<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Self::StreamUpdateFuture<'a> {
        let stream = stream.project();
        Box::pin(stream.0.wait_read_write_again(|when| async move {
            smol::Timer::at(when).await;
        }))
    }
}

/// Implementation detail of [`DefaultPlatform`].
#[pin_project::pin_project]
pub struct Stream(#[pin] with_buffers::WithBuffers<TcpOrWs>);

type TcpOrWs = future::Either<smol::net::TcpStream, websocket::Connection<smol::net::TcpStream>>;
