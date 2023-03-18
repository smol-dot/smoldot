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

use alloc::{string::String, vec::Vec};
use core::{ops, str, time::Duration};
use futures::prelude::*;

pub mod async_std;

/// Access to a platform's capabilities.
pub trait Platform: Send + 'static {
    type Delay: Future<Output = ()> + Unpin + Send + 'static;
    type Yield: Future<Output = ()> + Unpin + Send + 'static;
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
    /// the `Connection` and all its associated substream objects ([`Platform::Stream`]) have
    /// been dropped.
    type Connection: Send + Sync + 'static;
    /// Opaque object representing either a single-stream connection or a substream in a
    /// multi-stream connection.
    ///
    /// If this object is abruptly dropped, the underlying single stream connection or substream
    /// should be abruptly dropped (i.e. RST) as well, unless its reading and writing sides
    /// have been gracefully closed in the past.
    type Stream: Send + 'static;
    type ConnectFuture: Future<Output = Result<PlatformConnection<Self::Stream, Self::Connection>, ConnectError>>
        + Unpin
        + Send
        + 'static;
    type StreamUpdateFuture<'a>: Future<Output = ()> + Unpin + Send + 'a;
    type NextSubstreamFuture<'a>: Future<Output = Option<(Self::Stream, PlatformSubstreamDirection)>>
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
    fn now_from_unix_epoch() -> Duration;

    /// Returns an object that represents "now".
    fn now() -> Self::Instant;

    /// Creates a future that becomes ready after at least the given duration has elapsed.
    fn sleep(duration: Duration) -> Self::Delay;

    /// Creates a future that becomes ready after the given instant has been reached.
    fn sleep_until(when: Self::Instant) -> Self::Delay;

    /// Should be called after a CPU-intensive operation in order to yield back control.
    ///
    /// This function can be implemented as no-op on platforms where this is irrelevant.
    fn yield_after_cpu_intensive() -> Self::Yield;

    /// Starts a connection attempt to the given multiaddress.
    ///
    /// The multiaddress is passed as a string. If the string can't be parsed, an error should be
    /// returned where [`ConnectError::is_bad_addr`] is `true`.
    fn connect(url: &str) -> Self::ConnectFuture;

    /// Queues the opening of an additional outbound substream.
    ///
    /// The substream, once opened, must be yielded by [`Platform::next_substream`].
    ///
    /// Calls to this function should be ignored if the connection has already been killed by the
    /// remote.
    ///
    /// > **Note**: No mechanism exists in this API to handle the situation where a substream fails
    /// >           to open, as this is not supposed to happen. If you need to handle such a
    /// >           situation, either try again opening a substream again or reset the entire
    /// >           connection.
    fn open_out_substream(connection: &mut Self::Connection);

    /// Waits until a new incoming substream arrives on the connection.
    ///
    /// This returns both inbound and outbound substreams. Outbound substreams should only be
    /// yielded once for every call to [`Platform::open_out_substream`].
    ///
    /// The future can also return `None` if the connection has been killed by the remote. If
    /// the future returns `None`, the user of the `Platform` should drop the `Connection` and
    /// all its associated `Stream`s as soon as possible.
    fn next_substream(connection: &'_ mut Self::Connection) -> Self::NextSubstreamFuture<'_>;

    /// Synchronizes the stream with the "actual" stream.
    ///
    /// Returns a future that becomes ready when data has been added to the read buffer of the
    /// given stream , or the remote closes their sending side, or the number of writable bytes
    /// (see [`Platform::writable_bytes`]) increases.
    ///
    /// This function should also flush any outgoing data if necessary.
    ///
    /// In order to avoid race conditions, the state of the read buffer and the writable bytes
    /// shouldn't be updated unless this function is called.
    /// In other words, calling this function switches the stream from a state to another, and
    /// this state transition should only happen when this function is called and not otherwise.
    fn update_stream(stream: &'_ mut Self::Stream) -> Self::StreamUpdateFuture<'_>;

    /// Gives access to the content of the read buffer of the given stream.
    fn read_buffer(stream: &mut Self::Stream) -> ReadBuffer;

    /// Discards the first `bytes` bytes of the read buffer of this stream.
    ///
    /// This makes it possible for more data to be received when [`Platform::update_stream`] is
    /// called.
    ///
    /// # Panic
    ///
    /// Panics if there aren't enough bytes to discard in the buffer.
    ///
    fn advance_read_cursor(stream: &mut Self::Stream, bytes: usize);

    /// Returns the maximum size of the buffer that can be passed to [`Platform::send`].
    ///
    /// Must return 0 if [`Platform::close_send`] has previously been called, or if the stream
    /// has been reset by the remote.
    ///
    /// If [`Platform::send`] is called, the number of writable bytes must decrease by exactly
    /// the size of the buffer that was provided.
    /// The number of writable bytes should never change unless [`Platform::update_stream`] is
    /// called.
    fn writable_bytes(stream: &mut Self::Stream) -> usize;

    /// Queues the given bytes to be sent out on the given stream.
    ///
    /// > **Note**: In the case of [`PlatformConnection::MultiStreamWebRtc`], be aware that there
    /// >           exists a limit to the amount of data to send in a single packet. The `data`
    /// >           parameter is guaranteed to fit within that limit. Due to the existence of this
    /// >           limit, the implementation of this function shouldn't attempt to save function
    /// >           calls by performing internal buffering and batching multiple calls into one.
    ///
    /// # Panic
    ///
    /// Panics if `data.len()` is superior to the value returned by [`Platform::writable_bytes`].
    /// Panics if [`Platform::close_send`] has been called before on this stream.
    ///
    fn send(stream: &mut Self::Stream, data: &[u8]);

    /// Closes the sending side of the given stream.
    ///
    /// > **Note**: In situations where this isn't possible, such as with the WebSocket protocol,
    /// >           this is a no-op.
    ///
    /// # Panic
    ///
    /// Panics if [`Platform::close_send`] has already been called on this stream.
    ///
    fn close_send(stream: &mut Self::Stream);
}

/// Type of opened connection. See [`Platform::connect`].
#[derive(Debug)]
pub enum PlatformConnection<TStream, TConnection> {
    /// The connection is a single stream on top of which Noise encryption and Yamux multiplexing
    /// should be negotiated. The division in multiple substreams is handled internally.
    SingleStreamMultistreamSelectNoiseYamux(TStream),
    /// The connection is made of multiple substreams. The encryption and multiplexing are handled
    /// externally. The reading and writing sides of substreams must never close, and substreams
    /// can only be abruptly closed by either side.
    MultiStreamWebRtc {
        /// Object representing the WebRTC connection.
        connection: TConnection,
        /// Multihash encoding of the TLS certificate used by the local node at the DTLS layer.
        local_tls_certificate_multihash: Vec<u8>,
        /// Multihash encoding of the TLS certificate used by the remote node at the DTLS layer.
        remote_tls_certificate_multihash: Vec<u8>,
    },
}

/// Direction in which a substream has been opened. See [`Platform::next_substream`].
#[derive(Debug)]
pub enum PlatformSubstreamDirection {
    /// Substream has been opened by the remote.
    Inbound,
    /// Substream has been opened locally in response to [`Platform::open_out_substream`].
    Outbound,
}

/// Error potentially returned by [`Platform::connect`].
pub struct ConnectError {
    /// Human-readable error message.
    pub message: String,

    /// `true` if the error is caused by the address to connect to being forbidden or unsupported.
    pub is_bad_addr: bool,
}

/// State of the read buffer, as returned by [`Platform::read_buffer`].
#[derive(Debug)]
pub enum ReadBuffer<'a> {
    /// Reading side of the stream is fully open. Contains the data waiting to be processed.
    Open(&'a [u8]),

    /// The reading side of the stream has been closed by the remote.
    ///
    /// Note that this is forbidden for connections of
    /// type [`PlatformConnection::MultiStreamWebRtc`].
    Closed,

    /// The stream has been abruptly closed by the remote.
    Reset,
}
