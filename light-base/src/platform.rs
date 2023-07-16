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

use alloc::{borrow::Cow, string::String};
use core::{future::Future, ops, str, time::Duration};
use futures_util::future;

pub mod address_parse;
pub mod default;

/// Access to a platform's capabilities.
///
/// Implementations of this trait are expected to be cheaply-clonable "handles". All clones of the
/// same platform share the same objects. For instance, it is legal to create clone a platform,
/// then create a connection on one clone, then access this connection on the other clone.
// TODO: remove `Unpin` trait bounds
pub trait PlatformRef: Clone + Send + Sync + 'static {
    type Delay: Future<Output = ()> + Unpin + Send + 'static;
    type Instant: Clone
        + ops::Add<Duration, Output = Self::Instant>
        + ops::Sub<Self::Instant, Output = Duration>
        + PartialOrd
        + Ord
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static;

    /// A multi-stream connection.
    ///
    /// This object is merely a handle. The underlying connection should be dropped only after
    /// the `MultiStream` and all its associated substream objects ([`PlatformRef::Stream`]) have
    /// been dropped.
    type MultiStream: Send + Sync + 'static;
    /// Opaque object representing either a single-stream connection or a substream in a
    /// multi-stream connection.
    ///
    /// If this object is abruptly dropped, the underlying single stream connection or substream
    /// should be abruptly dropped (i.e. RST) as well, unless its reading and writing sides
    /// have been gracefully closed in the past.
    type Stream: Send + 'static;
    type StreamConnectFuture: Future<Output = Result<Self::Stream, ConnectError>>
        + Unpin
        + Send
        + 'static;
    type MultiStreamConnectFuture: Future<Output = Result<MultiStreamWebRtcConnection<Self::MultiStream>, ConnectError>>
        + Unpin
        + Send
        + 'static;
    type StreamUpdateFuture<'a>: Future<Output = ()> + Unpin + Send + 'a;
    type NextSubstreamFuture<'a>: Future<Output = Option<(Self::Stream, SubstreamDirection)>>
        + Unpin
        + Send
        + 'a;

    /// Returns the time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time)
    /// (i.e. 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    ///
    /// # Panic
    ///
    /// Panics if the system time is configured to be below the UNIX epoch. This situation is a
    /// very very niche edge case that isn't worth handling.
    ///
    fn now_from_unix_epoch(&self) -> Duration;

    /// Returns an object that represents "now".
    fn now(&self) -> Self::Instant;

    /// The given buffer must be completely filled with pseudo-random bytes.
    ///
    /// # Panic
    ///
    /// Must panic if for some reason it is not possible to fill the buffer.
    ///
    fn fill_random_bytes(&self, buffer: &mut [u8]);

    /// Creates a future that becomes ready after at least the given duration has elapsed.
    fn sleep(&self, duration: Duration) -> Self::Delay;

    /// Creates a future that becomes ready after the given instant has been reached.
    fn sleep_until(&self, when: Self::Instant) -> Self::Delay;

    /// Spawns a task that runs indefinitely in the background.
    ///
    /// The first parameter is the name of the task, which can be useful for debugging purposes.
    ///
    /// The `Future` must be run until it yields a value.
    fn spawn_task(
        &self,
        task_name: Cow<str>,
        task: impl future::Future<Output = ()> + Send + 'static,
    );

    /// Value returned when a JSON-RPC client requests the name of the client, or when a peer
    /// performs an identification request. Reasonable value is `env!("CARGO_PKG_NAME")`.
    fn client_name(&self) -> Cow<str>;

    /// Value returned when a JSON-RPC client requests the version of the client, or when a peer
    /// performs an identification request. Reasonable value is `env!("CARGO_PKG_VERSION")`.
    fn client_version(&self) -> Cow<str>;

    /// Returns `true` if [`PlatformRef::connect_stream`] or [`PlatformRef::connect_multistream`]
    /// accepts a connection of the corresponding type.
    ///
    /// > **Note**: This function is meant to be pure. Implementations are expected to always
    /// >           return the same value for the same [`ConnectionType`] input. Enabling or
    /// >           disabling certain connection types after start-up is not supported.
    fn supports_connection_type(&self, connection_type: ConnectionType) -> bool;

    /// Starts a connection attempt to the given multiaddress.
    ///
    /// # Panic
    ///
    /// The function implementation panics if [`Address`] is of a type for which
    /// [`PlatformRef::supports_connection_type`] returns `false`.
    ///
    fn connect_stream(&self, address: Address) -> Self::StreamConnectFuture;

    /// Starts a connection attempt to the given multiaddress.
    ///
    /// # Panic
    ///
    /// The function implementation panics if [`MultiStreamAddress`] is of a type for which
    /// [`PlatformRef::supports_connection_type`] returns `false`.
    ///
    fn connect_multistream(&self, address: MultiStreamAddress) -> Self::MultiStreamConnectFuture;

    /// Queues the opening of an additional outbound substream.
    ///
    /// The substream, once opened, must be yielded by [`PlatformRef::next_substream`].
    ///
    /// Calls to this function should be ignored if the connection has already been killed by the
    /// remote.
    ///
    /// > **Note**: No mechanism exists in this API to handle the situation where a substream fails
    /// >           to open, as this is not supposed to happen. If you need to handle such a
    /// >           situation, either try again opening a substream again or reset the entire
    /// >           connection.
    fn open_out_substream(&self, connection: &mut Self::MultiStream);

    /// Waits until a new incoming substream arrives on the connection.
    ///
    /// This returns both inbound and outbound substreams. Outbound substreams should only be
    /// yielded once for every call to [`PlatformRef::open_out_substream`].
    ///
    /// The future can also return `None` if the connection has been killed by the remote. If
    /// the future returns `None`, the user of the `PlatformRef` should drop the `MultiStream` and
    /// all its associated `Stream`s as soon as possible.
    fn next_substream<'a>(
        &self,
        connection: &'a mut Self::MultiStream,
    ) -> Self::NextSubstreamFuture<'a>;

    /// Synchronizes the stream with the "actual" stream.
    ///
    /// Returns a future that becomes ready when "something" in the state has changed. In other
    /// words, when data has been added to the read buffer of the given stream , or the remote
    /// closes their sending side, or the number of writable bytes (see
    /// [`PlatformRef::writable_bytes`]) increases.
    ///
    /// This function might not add data to the read buffer nor process the remote closing its
    /// writing side, unless the read buffer has been emptied beforehand using
    /// [`PlatformRef::advance_read_cursor`].
    ///
    /// In the specific situation where the reading side is closed and the writing side has been
    /// closed using [`PlatformRef::close_send`], the API user must call this function before
    /// dropping the `Stream` object. This makes it possible for the implementation to finish
    /// cleaning up everything gracefully before the object is dropped.
    ///
    /// This function should also flush any outgoing data if necessary.
    ///
    /// In order to avoid race conditions, the state of the read buffer and the writable bytes
    /// shouldn't be updated unless this function is called.
    /// In other words, calling this function switches the stream from a state to another, and
    /// this state transition should only happen when this function is called and not otherwise.
    fn update_stream<'a>(&self, stream: &'a mut Self::Stream) -> Self::StreamUpdateFuture<'a>;

    /// Gives access to the content of the read buffer of the given stream.
    fn read_buffer<'a>(&self, stream: &'a mut Self::Stream) -> ReadBuffer<'a>;

    /// Discards the first `bytes` bytes of the read buffer of this stream.
    ///
    /// This makes it possible for more data to be received when [`PlatformRef::update_stream`] is
    /// called.
    ///
    /// # Panic
    ///
    /// Panics if there aren't enough bytes to discard in the buffer.
    ///
    fn advance_read_cursor(&self, stream: &mut Self::Stream, bytes: usize);

    /// Returns the maximum size of the buffer that can be passed to [`PlatformRef::send`].
    ///
    /// Must return 0 if [`PlatformRef::close_send`] has previously been called, or if the stream
    /// has been reset by the remote.
    ///
    /// If [`PlatformRef::send`] is called, the number of writable bytes must decrease by exactly
    /// the size of the buffer that was provided.
    /// The number of writable bytes should never change unless [`PlatformRef::update_stream`] is
    /// called.
    fn writable_bytes(&self, stream: &mut Self::Stream) -> usize;

    /// Queues the given bytes to be sent out on the given stream.
    ///
    /// > **Note**: In the case of [`MultiStreamAddress::WebRtc`], be aware that there
    /// >           exists a limit to the amount of data to send in a single packet. The `data`
    /// >           parameter is guaranteed to fit within that limit. Due to the existence of this
    /// >           limit, the implementation of this function shouldn't attempt to save function
    /// >           calls by performing internal buffering and batching multiple calls into one.
    ///
    /// # Panic
    ///
    /// Panics if `data.is_empty()`.
    /// Panics if `data.len()` is superior to the value returned by [`PlatformRef::writable_bytes`].
    /// Panics if [`PlatformRef::close_send`] has been called before on this stream.
    ///
    fn send(&self, stream: &mut Self::Stream, data: &[u8]);

    /// Closes the sending side of the given stream.
    ///
    /// > **Note**: In situations where this isn't possible, such as with the WebSocket protocol,
    /// >           this is a no-op.
    ///
    /// # Panic
    ///
    /// Panics if [`PlatformRef::close_send`] has already been called on this stream.
    ///
    // TODO: consider not calling this function at all for WebSocket
    fn close_send(&self, stream: &mut Self::Stream);
}

/// Established multistream connection information. See [`PlatformRef::connect_multistream`].
#[derive(Debug)]
pub struct MultiStreamWebRtcConnection<TConnection> {
    /// Object representing the WebRTC connection.
    pub connection: TConnection,
    /// SHA256 hash of the TLS certificate used by the local node at the DTLS layer.
    pub local_tls_certificate_sha256: [u8; 32],
    /// SHA256 hash of the TLS certificate used by the remote node at the DTLS layer.
    // TODO: consider caching the information that was passed in the address instead of passing it back
    pub remote_tls_certificate_sha256: [u8; 32],
}

/// Direction in which a substream has been opened. See [`PlatformRef::next_substream`].
#[derive(Debug)]
pub enum SubstreamDirection {
    /// Substream has been opened by the remote.
    Inbound,
    /// Substream has been opened locally in response to [`PlatformRef::open_out_substream`].
    Outbound,
}

/// Connection type passed to [`PlatformRef::supports_connection_type`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    /// TCP/IP connection.
    TcpIpv4,
    /// TCP/IP connection.
    TcpIpv6,
    /// TCP/IP connection.
    TcpDns,
    /// Non-secure WebSocket connection.
    WebSocketIpv4 {
        /// `true` if the target of the connection is `localhost`.
        ///
        /// > **Note**: Some platforms (namely browsers) sometimes only accept non-secure WebSocket
        /// >           connections only towards `localhost`.
        remote_is_localhost: bool,
    },
    /// Non-secure WebSocket connection.
    WebSocketIpv6 {
        /// `true` if the target of the connection is `localhost`.
        ///
        /// > **Note**: Some platforms (namely browsers) sometimes only accept non-secure WebSocket
        /// >           connections only towards `localhost`.
        remote_is_localhost: bool,
    },
    /// WebSocket connection.
    WebSocketDns {
        /// `true` for WebSocket secure connections.
        secure: bool,
        /// `true` if the target of the connection is `localhost`.
        ///
        /// > **Note**: Some platforms (namely browsers) sometimes only accept non-secure WebSocket
        /// >           connections only towards `localhost`.
        remote_is_localhost: bool,
    },
    /// Libp2p-specific WebRTC flavour.
    WebRtcIpv4,
    /// Libp2p-specific WebRTC flavour.
    WebRtcIpv6,
}

impl<'a> From<&'a Address<'a>> for ConnectionType {
    fn from(address: &'a Address<'a>) -> ConnectionType {
        match address {
            Address::TcpIp {
                ip: IpAddr::V4(_), ..
            } => ConnectionType::TcpIpv4,
            Address::TcpIp {
                ip: IpAddr::V6(_), ..
            } => ConnectionType::TcpIpv6,
            Address::TcpDns { .. } => ConnectionType::TcpDns,
            Address::WebSocketIp {
                ip: IpAddr::V4(ip), ..
            } => ConnectionType::WebSocketIpv4 {
                remote_is_localhost: no_std_net::Ipv4Addr::from(*ip).is_loopback(),
            },
            Address::WebSocketIp {
                ip: IpAddr::V6(ip), ..
            } => ConnectionType::WebSocketIpv6 {
                remote_is_localhost: no_std_net::Ipv6Addr::from(*ip).is_loopback(),
            },
            Address::WebSocketDns {
                hostname, secure, ..
            } => ConnectionType::WebSocketDns {
                secure: *secure,
                remote_is_localhost: hostname.eq_ignore_ascii_case("localhost"),
            },
        }
    }
}

impl<'a> From<&'a MultiStreamAddress> for ConnectionType {
    fn from(address: &'a MultiStreamAddress) -> ConnectionType {
        match address {
            MultiStreamAddress::WebRtc {
                ip: IpAddr::V4(_), ..
            } => ConnectionType::WebRtcIpv4,
            MultiStreamAddress::WebRtc {
                ip: IpAddr::V6(_), ..
            } => ConnectionType::WebRtcIpv6,
        }
    }
}

/// Address passed to [`PlatformRef::connect_stream`].
// TODO: we don't differentiate between Dns4 and Dns6
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Address<'a> {
    /// TCP/IP connection with a domain name.
    TcpDns {
        /// DNS hostname to connect to.
        ///
        /// > **Note**: According to RFC2181 section 11, a domain name is not necessarily an UTF-8
        /// >           string. Any binary data can be used as a domain name, provided it follows
        /// >           a few restrictions (notably its length). However, in the context of the
        /// >           [`PlatformRef`] trait, we automatically consider as non-supported a
        /// >           multiaddress that contains a non-UTF-8 domain name, for the sake of
        /// >           simplicity.
        hostname: &'a str,
        /// TCP port to connect to.
        port: u16,
    },

    /// TCP/IP connection with an IP address.
    TcpIp {
        /// IP address to connect to.
        ip: IpAddr,
        /// TCP port to connect to.
        port: u16,
    },

    /// WebSocket connection with an IP address.
    WebSocketIp {
        /// IP address to connect to.
        ip: IpAddr,
        /// TCP port to connect to.
        port: u16,
    },

    /// WebSocket connection with a domain name.
    WebSocketDns {
        /// DNS hostname to connect to.
        ///
        /// > **Note**: According to RFC2181 section 11, a domain name is not necessarily an UTF-8
        /// >           string. Any binary data can be used as a domain name, provided it follows
        /// >           a few restrictions (notably its length). However, in the context of the
        /// >           [`PlatformRef`] trait, we automatically consider as non-supported a
        /// >           multiaddress that contains a non-UTF-8 domain name, for the sake of
        /// >           simplicity.
        hostname: &'a str,
        /// TCP port to connect to.
        port: u16,
        /// `true` for WebSocket secure connections.
        secure: bool,
    },
}

/// Address passed to [`PlatformRef::connect_multistream`].
// TODO: we don't differentiate between Dns4 and Dns6
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MultiStreamAddress {
    /// Libp2p-specific WebRTC flavour.
    ///
    /// The implementation the [`PlatformRef`] trait is responsible for opening the SCTP
    /// connection. The API user of the [`PlatformRef`] trait is responsible for opening the first
    /// data channel and performing the Noise handshake.
    // TODO: maybe explain more what the implementation is supposed to do?
    WebRtc {
        /// IP address to connect to.
        ip: IpAddr,
        /// UDP port to connect to.
        port: u16,
        /// SHA-256 hash of the target's WebRTC certificate.
        // TODO: consider providing a reference here; right now there's some issues with multiaddr preventing that
        remote_certificate_sha256: [u8; 32],
    },
}

/// Either an IPv4 or IPv6 address.
// TODO: replace this with `core::net::IpAddr` once it's stable: https://github.com/rust-lang/rust/issues/108443
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// Error potentially returned by [`PlatformRef::connect_stream`] or
/// [`PlatformRef::connect_multistream`].
pub struct ConnectError {
    /// Human-readable error message.
    pub message: String,
}

/// State of the read buffer, as returned by [`PlatformRef::read_buffer`].
#[derive(Debug)]
pub enum ReadBuffer<'a> {
    /// Reading side of the stream is fully open. Contains the data waiting to be processed.
    Open(&'a [u8]),

    /// The reading side of the stream has been closed by the remote.
    ///
    /// Note that this is forbidden for connections of
    /// type [`MultiStreamAddress::WebRtc`].
    Closed,

    /// The stream has been abruptly closed by the remote.
    Reset,
}
