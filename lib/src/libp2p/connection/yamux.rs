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

//! Yamux multiplexing protocol.
//!
//! The Yamux protocol is a multiplexing protocol. As such, it allows dividing a single stream of
//! data, typically a TCP socket, into multiple individual parallel substreams. The data sent and
//! received over that single stream is divided into frames which, with the exception of `ping`
//! and `goaway` frames, belong to a specific substream. In other words, the data transmitted
//! over the substreams is interleaved.
//!
//! Specification available at <https://github.com/hashicorp/yamux/blob/master/spec.md>
//!
//! # Usage
//!
//! The [`Yamux`] object holds the state of all yamux-specific information, and the list of
//! all currently-open substreams.
//!
//! Call [`Yamux::incoming_data`] when data is available on the socket. This function parses
//! the received data, updates the internal state machine, and possibly returns an
//! [`IncomingDataDetail`].
//! Call [`Yamux::extract_next`] when the remote is ready to accept more data.
//!
//! The generic parameter of [`Yamux`] is an opaque "user data" associated to each substream.
//!
//! When [`Yamux::write`] is called, the buffer of data to send out is stored within the
//! [`Yamux`] object. This data will then be progressively returned by [`Yamux::extract_next`].
//!
//! It is the responsibility of the user to enforce a bound to the amount of enqueued data, as
//! the [`Yamux`] itself doesn't enforce any limit. Enforcing such a bound must be done based
//! on the logic of the higher-level protocols. Failing to do so might lead to potential DoS
//! attack vectors.

use crate::util::SipHasherBuild;

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{
    cmp, fmt, mem,
    num::{NonZeroU32, NonZeroUsize},
};
use rand::{seq::IteratorRandom as _, Rng as _};
use rand_chacha::{rand_core::SeedableRng as _, ChaCha20Rng};

pub use header::GoAwayErrorCode;

mod header;
mod tests;
mod write_queue;

/// Name of the protocol, typically used when negotiated it using *multistream-select*.
pub const PROTOCOL_NAME: &str = "/yamux/1.0.0";

/// Configuration for a new [`Yamux`].
#[derive(Debug)]
pub struct Config {
    /// `true` if the local machine has initiated the connection. Otherwise, `false`.
    pub is_initiator: bool,

    /// Expected number of substreams simultaneously open, both inbound and outbound substreams
    /// combined.
    pub capacity: usize,

    /// Seed used for the randomness. Used to avoid HashDoS attack and determines the order in
    /// which the data on substreams is sent out.
    pub randomness_seed: [u8; 32],

    /// Maximum size of data frames to send out.
    ///
    /// A higher value increases the variance of the latency of the data sent on the substreams,
    /// which is undesirable. A lower value increases the overhead of the Yamux protocol. This
    /// overhead is equal to `1200 / (max_out_data_frame_size + 12)` per cent, for example setting
    /// `max_out_data_frame_size` to 24 incurs a `33%` overhead.
    ///
    /// The "best" value depends on the bandwidth speed of the underlying connection, and is thus
    /// impossible to tell.
    ///
    /// A typical value is `8192`.
    pub max_out_data_frame_size: NonZeroU32,

    /// When the remote sends a ping, we need to send out a pong. However, the remote could refuse
    /// to read any additional data from the socket and continue sending pings, thus increasing
    /// the local buffer size indefinitely. In order to protect against this attack, there exists
    /// a maximum number of queued pongs, after which the connection will be shut down abruptly.
    pub max_simultaneous_queued_pongs: NonZeroUsize,

    /// When the remote sends a substream, and this substream gets rejected by the API user, some
    /// data needs to be sent out. However, the remote could refuse reading any additional data
    /// and continue sending new substream requests, thus increasing the local buffer size
    /// indefinitely. In order to protect against this attack, there exists a maximum number of
    /// queued substream rejections after which the connection will be shut down abruptly.
    pub max_simultaneous_rst_substreams: NonZeroUsize,
}

/// Yamux state machine. See [the module-level documentation](..) for more information.
pub struct Yamux<T> {
    /// The actual fields are wrapped in a `Box` because the `Yamux` object is moved around pretty
    /// often.
    inner: Box<YamuxInner<T>>,
}

struct YamuxInner<T> {
    /// List of substreams currently open in the Yamux state machine.
    ///
    /// A `SipHasher` is used in order to avoid hash collision attacks on substream IDs.
    substreams: hashbrown::HashMap<NonZeroU32, Substream<T>, SipHasherBuild>,

    /// Subset of the content of [`YamuxInner::substreams`] that is considered "dead", meaning
    /// that it is returned by [`Yamux::dead_substreams`].
    dead_substreams: hashbrown::HashSet<NonZeroU32, SipHasherBuild>,

    /// Subset of the content of [`YamuxInner::substreams`] that requires some outgoing data to
    /// be sent out, either because they have data to send out or because they have a window
    /// update to send out.
    outgoing_req_substreams: hashbrown::HashSet<NonZeroU32, SipHasherBuild>,

    /// Number of substreams within [`YamuxInner::substreams`] whose [`Substream::inbound`] is
    /// `true`.
    num_inbound: usize,

    /// `Some` if a `GoAway` frame has been received in the past.
    received_goaway: Option<GoAwayErrorCode>,

    /// What kind of data is expected on the socket next.
    incoming: Incoming,

    /// What to write to the socket next.
    outgoing: Outgoing,

    /// Whether to send out a `GoAway` frame.
    outgoing_goaway: OutgoingGoAway,

    /// See [`Config::max_out_data_frame_size`].
    max_out_data_frame_size: NonZeroU32,

    /// Id of the next outgoing substream to open.
    /// This implementation allocates identifiers linearly. Every time a substream is open, its
    /// value is incremented by two.
    next_outbound_substream: NonZeroU32,

    /// Number of pings to send out that haven't been queued yet.
    pings_to_send: usize,

    /// List of pings that have been sent out but haven't been replied yet.
    pings_waiting_reply: VecDeque<u32>,

    /// List of opaque values corresponding to ping requests sent by the remote. For each entry,
    /// a PONG header should be sent to the remote.
    pongs_to_send: VecDeque<u32>,

    /// See [`Config::max_simultaneous_queued_pongs`].
    max_simultaneous_queued_pongs: NonZeroUsize,

    /// List of substream IDs that have been reset locally. For each entry, a RST header should
    /// be sent to the remote.
    rsts_to_send: VecDeque<NonZeroU32>,

    /// See [`Config::max_simultaneous_rst_substreams`].
    max_simultaneous_rst_substreams: NonZeroUsize,

    /// Source of randomness used for various purposes.
    randomness: ChaCha20Rng,
}

struct Substream<T> {
    /// State of the substream.
    state: SubstreamState,
    /// `true` if the substream has been opened by the remote.
    inbound: bool,
    /// Data chosen by the user.
    user_data: T,
}

enum SubstreamState {
    Healthy {
        /// True if a message on this substream has already been sent since it has been opened. The
        /// first message on a substream must contain either a SYN or `ACK` flag.
        first_message_queued: bool,
        /// True if the remote has sent a message on this substream and has thus acknowledged that
        /// this substream exists.
        remote_syn_acked: bool,
        /// Amount of data the remote is allowed to transmit to the local node.
        remote_allowed_window: u64,
        /// If non-zero, a window update frame must be sent to the remote to grant this number of
        /// bytes.
        remote_window_pending_increase: u64,
        /// Amount of data the local node is allowed to transmit to the remote.
        allowed_window: u64,
        /// State of the local writing side of this substream.
        local_write_close: SubstreamStateLocalWrite,
        /// True if the writing side of the remote node is closed for this substream.
        remote_write_closed: bool,
        /// Buffer of buffers to be written out to the socket.
        write_queue: write_queue::WriteQueue,
    },

    /// The substream has been reset, either locally or by the remote. Its entire purpose is to
    /// be removed by the API user.
    Reset,
}

enum SubstreamStateLocalWrite {
    Open,
    FinDesired,
    FinQueued,
}

enum Incoming {
    /// Expect a header. The field might contain some already-read bytes.
    Header(arrayvec::ArrayVec<u8, 12>),
    /// Expect the data of a previously-received data frame header.
    DataFrame {
        /// Identifier of the substream the data belongs to.
        substream_id: SubstreamId,
        /// Number of bytes of data remaining before the frame ends.
        remaining_bytes: u32,
        /// True if the remote writing side of the substream should be closed after receiving the
        /// data frame.
        fin: bool,
    },

    /// A header referring to a new substream has been received. The reception of any further data
    /// is blocked waiting for the API user to accept or reject this substream.
    ///
    /// Note that [`YamuxInner::outgoing`] must always be [`Outgoing::Idle`], in order to give the
    /// possibility to send back a RST frame for the new substream.
    PendingIncomingSubstream {
        /// Identifier of the pending substream.
        substream_id: SubstreamId,
        /// Extra local window size to give to this substream.
        extra_window: u32,
        /// If non-zero, must transition to a [`Incoming::DataFrame`].
        data_frame_size: u32,
        /// True if the remote writing side of the substream should be closed after receiving the
        /// `data_frame_size` bytes.
        fin: bool,
    },
}

enum Outgoing {
    /// Nothing to write out.
    Idle,

    /// Writing out a header.
    Header {
        /// Header to write out.
        ///
        /// The length of this buffer might not be equal to 12 in case some parts of the header have
        /// already been written out but not all.
        ///
        /// Never empty (as otherwise the state must have been transitioned to something else).
        header: header::DecodedYamuxHeader,

        /// Number of bytes from `header` that have already been sent out. Always strictly
        /// inferior to 12.
        header_already_sent: u8,

        /// If `Some`, then the header is data frame header and we must then transition the
        /// state to [`Outgoing::SubstreamData`].
        substream_data_frame: Option<(OutgoingSubstreamData, NonZeroUsize)>,
    },

    /// Writing out data from a substream.
    ///
    /// We have sent a data header in the past, and we must now send the associated data.
    SubstreamData {
        /// Source of the data to write out.
        data: OutgoingSubstreamData,

        /// Number of bytes remaining to write.
        ///
        /// Always superior or equal to the total length of the data in `write_buffers`.
        remaining_bytes: NonZeroUsize,
    },
}

enum OutgoingGoAway {
    /// No `GoAway` frame has been sent or requested. Normal mode of operations.
    NotRequired,

    /// API user has asked to send a `GoAway` frame. This frame hasn't been queued into
    /// [`YamuxInner::outgoing`] yet.
    Required(GoAwayErrorCode),

    /// A `GoAway` frame has been queued into [`YamuxInner::outgoing`] in the past.
    Queued,

    /// A `GoAway` frame has been extracted through [`Yamux::extract_next`].
    Sent,
}

#[derive(Debug, Clone)]
enum OutgoingSubstreamData {
    /// Data is coming from the given substream.
    ///
    /// The substream must **not** be in a "reset" state.
    Healthy(SubstreamId),

    /// Data is coming from a substream in a reset state.
    Obsolete {
        /// Buffer of buffers to be written out to the socket.
        write_queue: write_queue::WriteQueue,
    },
}

/// Maximum number of simultaneous outgoing pings allowed.
pub const MAX_PINGS: usize = 100000;

impl<T> Yamux<T> {
    /// Initializes a new Yamux state machine.
    pub fn new(config: Config) -> Yamux<T> {
        let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

        Yamux {
            inner: Box::new(YamuxInner {
                substreams: hashbrown::HashMap::with_capacity_and_hasher(
                    config.capacity,
                    SipHasherBuild::new(randomness.gen()),
                ),
                dead_substreams: hashbrown::HashSet::with_capacity_and_hasher(
                    config.capacity,
                    SipHasherBuild::new(randomness.gen()),
                ),
                outgoing_req_substreams: hashbrown::HashSet::with_capacity_and_hasher(
                    config.capacity,
                    SipHasherBuild::new(randomness.gen()),
                ),
                num_inbound: 0,
                received_goaway: None,
                incoming: Incoming::Header(arrayvec::ArrayVec::new()),
                outgoing: Outgoing::Idle,
                outgoing_goaway: OutgoingGoAway::NotRequired,
                max_out_data_frame_size: config.max_out_data_frame_size,
                next_outbound_substream: if config.is_initiator {
                    NonZeroU32::new(1).unwrap()
                } else {
                    NonZeroU32::new(2).unwrap()
                },
                pings_to_send: 0,
                // We leave the initial capacity at 0, as it is likely that no ping is sent at all.
                pings_waiting_reply: VecDeque::with_capacity(0),
                pongs_to_send: VecDeque::with_capacity(4),
                max_simultaneous_queued_pongs: config.max_simultaneous_queued_pongs,
                rsts_to_send: VecDeque::with_capacity(4),
                max_simultaneous_rst_substreams: config.max_simultaneous_rst_substreams,
                randomness,
            }),
        }
    }

    /// Returns `true` if there is no substream in the state machine.
    ///
    /// > **Note**: After a substream has been closed or reset, it must be removed using
    /// >           [`Yamux::remove_dead_substream`] before this function can return `true`.
    pub fn is_empty(&self) -> bool {
        self.inner.substreams.is_empty()
    }

    /// Returns the number of substreams in the Yamux state machine. Includes substreams that are
    /// dead but haven't been removed yet.
    pub fn len(&self) -> usize {
        self.inner.substreams.len()
    }

    /// Returns the number of inbound substreams in the Yamux state machine. Includes substreams
    /// that are dead but haven't been removed yet.
    pub fn num_inbound(&self) -> usize {
        debug_assert_eq!(
            self.inner.num_inbound,
            self.inner.substreams.values().filter(|s| s.inbound).count()
        );

        self.inner.num_inbound
    }

    /// Opens a new substream.
    ///
    /// This method only modifies the state of `self` and reserves an identifier. No message needs
    /// to be sent to the remote before data is actually being sent on the substream.
    ///
    /// > **Note**: Importantly, the remote will not be notified of the substream being open
    /// >           before the local side sends data on this substream. As such, protocols where
    /// >           the remote is expected to send data in response to a substream being open,
    /// >           without the local side first sending some data on that substream, will not
    /// >           work. In practice, while this is technically out of concern of the Yamux
    /// >           protocol, all substreams in the context of libp2p start with a
    /// >           multistream-select negotiation, and this scenario can therefore never happen.
    ///
    /// Returns an error if a [`IncomingDataDetail::GoAway`] event has been generated. This can
    /// also be checked by calling [`Yamux::received_goaway`].
    ///
    /// Returns an error if all possible substream IDs are already taken. This happen if there
    /// exists more than approximately `2^31` substreams, which is very unlikely to happen unless
    /// there exists a bug in the code.
    ///
    pub fn open_substream(&mut self, user_data: T) -> Result<SubstreamId, OpenSubstreamError> {
        if self.inner.received_goaway.is_some() {
            return Err(OpenSubstreamError::GoAwayReceived);
        }

        let substream_id = self.inner.next_outbound_substream;

        self.inner.next_outbound_substream = match self.inner.next_outbound_substream.checked_add(2)
        {
            Some(new_id) => new_id,
            None => return Err(OpenSubstreamError::NoFreeSubstreamId),
        };

        let _prev_value = self.inner.substreams.insert(
            substream_id,
            Substream {
                state: SubstreamState::Healthy {
                    first_message_queued: false,
                    remote_syn_acked: false,
                    remote_allowed_window: NEW_SUBSTREAMS_FRAME_SIZE,
                    remote_window_pending_increase: 0,
                    allowed_window: NEW_SUBSTREAMS_FRAME_SIZE,
                    local_write_close: SubstreamStateLocalWrite::Open,
                    remote_write_closed: false,
                    write_queue: write_queue::WriteQueue::new(),
                },
                inbound: false,
                user_data,
            },
        );
        debug_assert!(_prev_value.is_none());

        Ok(SubstreamId(substream_id))
    }

    /// Returns `Some` if a [`IncomingDataDetail::GoAway`] event has been generated in the past,
    /// in which case the code is returned.
    ///
    /// If `Some` is returned, it is forbidden to open new outbound substreams.
    pub fn received_goaway(&self) -> Option<GoAwayErrorCode> {
        self.inner.received_goaway
    }

    /// Returns an iterator to the list of all substream user datas.
    pub fn user_datas(&self) -> impl ExactSizeIterator<Item = (SubstreamId, &T)> {
        self.inner
            .substreams
            .iter()
            .map(|(id, s)| (SubstreamId(*id), &s.user_data))
    }

    /// Returns an iterator to the list of all substream user datas.
    pub fn user_datas_mut(&mut self) -> impl ExactSizeIterator<Item = (SubstreamId, &mut T)> {
        self.inner
            .substreams
            .iter_mut()
            .map(|(id, s)| (SubstreamId(*id), &mut s.user_data))
    }

    /// Returns `true` if the given [`SubstreamId`] exists.
    ///
    /// Also returns `true` if the substream is in a dead state.
    pub fn has_substream(&self, substream_id: SubstreamId) -> bool {
        self.inner.substreams.contains_key(&substream_id.0)
    }

    /// Returns the user data associated to a substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn user_data(&self, substream_id: SubstreamId) -> &T {
        &self
            .inner
            .substreams
            .get(&substream_id.0)
            .unwrap()
            .user_data
    }

    /// Returns the user data associated to a substream.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn user_data_mut(&mut self, substream_id: SubstreamId) -> &mut T {
        &mut self
            .inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!())
            .user_data
    }

    /// Appends data to the buffer of data to send out on this substream.
    ///
    /// Returns an error if [`Yamux::close`] or [`Yamux::reset`] has been called on this substream,
    /// or if the substream has been reset by the remote.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn write(&mut self, substream_id: SubstreamId, data: Vec<u8>) -> Result<(), WriteError> {
        let substream = self
            .inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!());

        match &mut substream.state {
            SubstreamState::Healthy {
                local_write_close: SubstreamStateLocalWrite::Open,
                write_queue,
                allowed_window,
                ..
            } => {
                // Don't push empty data onto the queue.
                if data.is_empty() {
                    return Ok(());
                }

                // If the write queue switches from empty to non-empty, queue the substream for
                // writing.
                if *allowed_window != 0 && write_queue.is_empty() {
                    // Note that the substream might already be queued if it has a window update
                    // to write.
                    self.inner.outgoing_req_substreams.insert(substream_id.0);
                }

                write_queue.push_back(data);
                Ok(())
            }
            SubstreamState::Reset => Err(WriteError::Reset),
            SubstreamState::Healthy {
                local_write_close:
                    SubstreamStateLocalWrite::FinDesired | SubstreamStateLocalWrite::FinQueued,
                ..
            } => Err(WriteError::Closed),
        }
    }

    /// Adds `bytes` to the number of bytes the remote is allowed to send at once in the next
    /// packet.
    ///
    /// The counter saturates if its maximum is reached. This could cause stalls if the
    /// remote sends a ton of data. However, given that the number of bytes is stored in a `u64`,
    /// the remote would have to send at least  `2^64` bytes in order to reach this situation,
    /// making it basically impossible.
    ///
    /// It is, furthermore, a bad idea to increase this counter by an immense number ahead of
    /// time, as the remote can shut down the connection if its own counter overflows. The way
    /// this counter is supposed to be used is in a "streaming" way.
    ///
    /// > **Note**: When a substream has just been opened or accepted, it starts with an initial
    /// >           window of [`NEW_SUBSTREAMS_FRAME_SIZE`].
    ///
    /// > **Note**: It is only possible to add more bytes to the window and not set or reduce this
    /// >           number of bytes, and it is also not possible to obtain the number of bytes the
    /// >           remote is allowed. That's because it would be ambiguous whether bytes possibly
    /// >           in the send or receive queue should be counted or not.
    ///
    /// Has no effect if the remote has already closed their writing side.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn add_remote_window_saturating(&mut self, substream_id: SubstreamId, bytes: u64) {
        if let SubstreamState::Healthy {
            remote_window_pending_increase,
            remote_write_closed: false,
            ..
        } = &mut self
            .inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!())
            .state
        {
            if *remote_window_pending_increase == 0 && bytes != 0 {
                // Note that the substream might already be queued if it has data to write.
                self.inner.outgoing_req_substreams.insert(substream_id.0);
            }

            *remote_window_pending_increase = remote_window_pending_increase.saturating_add(bytes);
        }
    }

    /// Returns the number of bytes queued for writing on this substream.
    ///
    /// Returns 0 if the substream is in a reset state.
    ///
    /// > **Note**: Might return non-zero even if [`Yamux::close`] has been called, as this counts
    /// >           the number of bytes still waiting to be written out.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn queued_bytes(&self, substream_id: SubstreamId) -> usize {
        match &self
            .inner
            .substreams
            .get(&substream_id.0)
            .unwrap_or_else(|| panic!())
            .state
        {
            SubstreamState::Healthy { write_queue, .. } => write_queue.queued_bytes(),
            SubstreamState::Reset => 0,
        }
    }

    /// Returns `false` if the remote has closed their writing side of this substream, or if
    /// [`Yamux::reset`] has been called on this substream, or if the substream has been
    /// reset by the remote.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn can_receive(&self, substream_id: SubstreamId) -> bool {
        matches!(self.inner.substreams.get(&substream_id.0).unwrap_or_else(|| panic!()).state,
            SubstreamState::Healthy {
                remote_write_closed,
                ..
            } if !remote_write_closed)
    }

    /// Returns `false` if [`Yamux::close`] or [`Yamux::reset`] has been called on this substream,
    /// or if the remote has .
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn can_send(&self, substream_id: SubstreamId) -> bool {
        matches!(
            self.inner
                .substreams
                .get(&substream_id.0)
                .unwrap_or_else(|| panic!())
                .state,
            SubstreamState::Healthy {
                local_write_close: SubstreamStateLocalWrite::Open,
                ..
            }
        )
    }

    /// Marks the substream as closed. It is no longer possible to write data on it.
    ///
    /// Returns an error if the local writing side is already closed, which can happen if
    /// [`Yamux::close`] has already been called on this substream.
    /// Returns an error if [`Yamux::reset`] has been called on this substream, or if the remote
    /// has reset the substream in the past.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn close(&mut self, substream_id: SubstreamId) -> Result<(), CloseError> {
        let substream = self
            .inner
            .substreams
            .get_mut(&substream_id.0)
            .unwrap_or_else(|| panic!());

        match substream.state {
            SubstreamState::Healthy {
                local_write_close: ref mut local_write @ SubstreamStateLocalWrite::Open,
                ..
            } => {
                *local_write = SubstreamStateLocalWrite::FinDesired;
                self.inner.outgoing_req_substreams.insert(substream_id.0);
                Ok(())
            }
            SubstreamState::Healthy {
                local_write_close:
                    SubstreamStateLocalWrite::FinDesired | SubstreamStateLocalWrite::FinQueued,
                ..
            } => Err(CloseError::AlreadyClosed),
            SubstreamState::Reset => Err(CloseError::Reset),
        }
    }

    /// Abruptly shuts down the substream. Sends a frame with the `RST` flag to the remote.
    ///
    /// Use this method when a protocol error happens on a substream.
    ///
    /// Returns an error if [`Yamux::reset`] has already been called on this substream or if the
    /// remote has reset the substream in the past.
    ///
    /// # Panic
    ///
    /// Panics if the [`SubstreamId`] is invalid.
    ///
    pub fn reset(&mut self, substream_id: SubstreamId) -> Result<(), ResetError> {
        // Add an entry to the list of RST headers to send to the remote.
        if let SubstreamState::Healthy { .. } = self
            .inner
            .substreams
            .get(&substream_id.0)
            .unwrap_or_else(|| panic!())
            .state
        {
            // Note that we intentionally don't check the size against
            // `max_simultaneous_rst_substreams`, as locally-emitted RST frames aren't the
            // remote's fault.
            self.inner.rsts_to_send.push_back(substream_id.0);
        } else {
            return Err(ResetError::AlreadyReset);
        }

        let _was_inserted = self.inner.dead_substreams.insert(substream_id.0);
        debug_assert!(_was_inserted);

        self.inner.outgoing_req_substreams.remove(&substream_id.0);

        // We might be currently writing a frame of data of the substream being reset.
        // If that happens, we need to update some internal state regarding this frame of data.
        match (
            &mut self.inner.outgoing,
            mem::replace(
                &mut self
                    .inner
                    .substreams
                    .get_mut(&substream_id.0)
                    .unwrap_or_else(|| panic!())
                    .state,
                SubstreamState::Reset,
            ),
        ) {
            (
                Outgoing::Header {
                    substream_data_frame: Some((data @ OutgoingSubstreamData::Healthy(_), _)),
                    ..
                }
                | Outgoing::SubstreamData {
                    data: data @ OutgoingSubstreamData::Healthy(_),
                    ..
                },
                SubstreamState::Healthy { write_queue, .. },
            ) if matches!(*data, OutgoingSubstreamData::Healthy(i) if i == substream_id) => {
                *data = OutgoingSubstreamData::Obsolete { write_queue };
            }
            _ => {}
        }

        Ok(())
    }

    /// Queues sending out a ping to the remote.
    ///
    /// # Panic
    ///
    /// Panics if there are already [`MAX_PINGS`] pings that have been queued and that the remote
    /// hasn't answered yet. [`MAX_PINGS`] is pretty large, and unless there is a bug in the API
    /// user's code causing pings to be allocated in a loop, this limit is not likely to ever be
    /// reached.
    ///
    pub fn queue_ping(&mut self) {
        // A maximum number of simultaneous pings (`MAX_PINGS`) is necessary because we don't
        // support sending multiple identical ping opaque values. Since the ping opaque values
        // are 32 bits, the actual maximum number of simultaneous pings is 2^32. But because we
        // allocate ping values by looping until we find a not-yet-allocated value, the arbitrary
        // self-enforced maximum needs to be way lower.
        assert!(self.inner.pings_to_send + self.inner.pings_waiting_reply.len() < MAX_PINGS);
        self.inner.pings_to_send += 1;
    }

    /// Returns `true` if [`Yamux::send_goaway`] has been called in the past.
    ///
    /// In other words, returns `true` if a `GoAway` frame has been either queued for sending
    /// (and is available through [`Yamux::extract_next`]) or has already been sent out.
    pub fn goaway_queued_or_sent(&self) -> bool {
        !matches!(self.inner.outgoing_goaway, OutgoingGoAway::NotRequired)
    }

    /// Returns `true` if [`Yamux::send_goaway`] has been called in the past and that this
    /// `GoAway` frame has been extracted through [`Yamux::extract_next`].
    pub fn goaway_sent(&self) -> bool {
        matches!(self.inner.outgoing_goaway, OutgoingGoAway::Sent)
    }

    /// Queues a `GoAway` frame, requesting the remote to no longer open any substream.
    ///
    /// If the state of [`Yamux`] is currently waiting for a confirmation to accept/reject a
    /// substream, then this function automatically implies calling
    /// [`Yamux::reject_pending_substream`].
    ///
    /// All follow-up requests for new substreams from the remote are automatically rejected.
    /// [`IncomingDataDetail::IncomingSubstream`] events can no longer happen.
    ///
    pub fn send_goaway(&mut self, code: GoAwayErrorCode) -> Result<(), SendGoAwayError> {
        match self.inner.outgoing_goaway {
            OutgoingGoAway::NotRequired => {
                self.inner.outgoing_goaway = OutgoingGoAway::Required(code)
            }
            _ => return Err(SendGoAwayError::AlreadySent),
        }

        // If the remote is currently opening a substream, ignore it. The remote understands when
        // receiving the GoAway that the substream has been rejected.
        if let Incoming::PendingIncomingSubstream {
            substream_id,
            data_frame_size,
            fin,
            ..
        } = self.inner.incoming
        {
            self.inner.incoming = if data_frame_size == 0 {
                Incoming::Header(arrayvec::ArrayVec::new())
            } else {
                Incoming::DataFrame {
                    substream_id,
                    remaining_bytes: data_frame_size,
                    fin,
                }
            };
        }

        Ok(())
    }

    /// Returns the list of all substreams that have been closed or reset.
    ///
    /// This function does not remove dead substreams from the state machine. In other words, if
    /// this function is called multiple times in a row, it will always return the same
    /// substreams. Use [`Yamux::remove_dead_substream`] to remove substreams.
    pub fn dead_substreams(
        &'_ self,
    ) -> impl Iterator<Item = (SubstreamId, DeadSubstreamTy, &'_ T)> + '_ {
        self.inner
            .dead_substreams
            .iter()
            .map(|id| {
                let substream = self.inner.substreams.get(id).unwrap();
                match &substream.state {
                    SubstreamState::Reset => (
                        SubstreamId(*id),
                        DeadSubstreamTy::Reset,
                        &substream.user_data,
                    ),
                    SubstreamState::Healthy {
                        local_write_close,
                        remote_write_closed,
                        write_queue,
                        ..
                    } => {
                        debug_assert!(
                            matches!(local_write_close, SubstreamStateLocalWrite::FinQueued)
                                && *remote_write_closed
                                && write_queue.is_empty()
                        );

                        (
                            SubstreamId(*id),
                            DeadSubstreamTy::ClosedGracefully,
                            &substream.user_data,
                        )
                    }
                }
            })
            .inspect(|(dead_id, _, _)| {
                debug_assert!(!matches!(self.inner.outgoing,
                    Outgoing::Header {
                        substream_data_frame: Some((OutgoingSubstreamData::Healthy(id), _)),
                        ..
                    }
                    | Outgoing::SubstreamData {
                        data: OutgoingSubstreamData::Healthy(id),
                        ..
                    } if id == *dead_id));
            })
    }

    /// Removes a dead substream from the state machine.
    ///
    /// # Panic
    ///
    /// Panics if the substream with that id doesn't exist or isn't dead.
    ///
    pub fn remove_dead_substream(&mut self, id: SubstreamId) -> T {
        let was_in = self.inner.dead_substreams.remove(&id.0);
        if !was_in {
            panic!()
        }

        debug_assert!(!self.inner.outgoing_req_substreams.contains(&id.0));

        let substream = self.inner.substreams.remove(&id.0).unwrap();

        if substream.inbound {
            self.inner.num_inbound -= 1;
        }

        substream.user_data
    }

    /// Process some incoming data.
    ///
    /// This function takes ownership of `self` and yields it back if everything goes well. If,
    /// on the other hand, a malformed packet is received, an error is yielded and `self` is
    /// destroyed.
    ///
    /// This function might not process all the data available for one of the following reasons:
    ///
    /// - Not all outgoing data has been extracted. In order to process incoming messages, the
    /// Yamux might have to queue data to be written out. For example, incoming pings must be
    /// replied to. In order to avoid queue an infinite amount of data, processing incoming
    /// messages might be blocked if there is data to be sent out.
    /// - It is currently waiting for either [`Yamux::accept_pending_substream`] or
    /// [`Yamux::reject_pending_substream`] to be called.
    /// - If the remote opens a substream whose ID is equal to a previous substream that is now
    /// dead. Use [`Yamux::dead_substreams`] and [`Yamux::remove_dead_substream`] to remove dead
    /// substreams before continuing.
    ///
    /// If the return value contains [`IncomingDataDetail::IncomingSubstream`], then either
    /// [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be called
    /// in order to accept or reject the pending substream. API users are encouraged to enforce a
    /// limit to the total number of substreams in order to clamp the memory usage of this state
    /// machine.
    pub fn incoming_data(mut self, mut data: &[u8]) -> Result<IncomingDataOutcome<T>, Error> {
        let mut total_read: usize = 0;

        loop {
            match self.inner.incoming {
                Incoming::PendingIncomingSubstream { .. } => break,

                Incoming::DataFrame {
                    substream_id,
                    remaining_bytes: 0,
                    fin: true,
                } => {
                    // End of the data frame. Proceed to receive new header at the next iteration.
                    self.inner.incoming = Incoming::Header(arrayvec::ArrayVec::new());

                    // Note that it is possible that we are receiving data corresponding to a
                    // substream for which a RST has been sent out by the local node. Since the
                    // local state machine doesn't keep track of RST'ted substreams, any
                    // frame concerning a substream that has been RST or doesn't exist is
                    // discarded and doesn't result in an error, under the presumption that we
                    // are in this situation.
                    let Some(Substream {
                        state:
                            SubstreamState::Healthy {
                                remote_write_closed: remote_write_closed @ false,
                                local_write_close,
                                write_queue,
                                remote_window_pending_increase,
                                ..
                            },
                        ..
                    }) = self.inner.substreams.get_mut(&substream_id.0) else { continue; };

                    *remote_write_closed = true;

                    if matches!(*local_write_close, SubstreamStateLocalWrite::FinQueued)
                        && write_queue.is_empty()
                    {
                        let _was_in = self.inner.outgoing_req_substreams.remove(&substream_id.0);
                        debug_assert_eq!(*remote_window_pending_increase != 0, _was_in);

                        let _was_inserted = self.inner.dead_substreams.insert(substream_id.0);
                        debug_assert!(_was_inserted);
                    }

                    return Ok(IncomingDataOutcome {
                        yamux: self,
                        bytes_read: total_read,
                        detail: Some(IncomingDataDetail::StreamClosed { substream_id }),
                    });
                }

                Incoming::DataFrame {
                    remaining_bytes: 0,
                    fin: false,
                    ..
                } => {
                    // End of the data frame. Proceed to receive new header at the next iteration.
                    self.inner.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                }

                Incoming::DataFrame {
                    substream_id,
                    ref mut remaining_bytes,
                    ..
                } if !data.is_empty() => {
                    // We only enter this block if `data` isn't empty, as we don't want to
                    // generate a `DataFrame` event if there's no data.

                    debug_assert_ne!(*remaining_bytes, 0);

                    // Extract the data and update the local states.
                    let pulled_data = cmp::min(
                        *remaining_bytes,
                        u32::try_from(data.len()).unwrap_or(u32::max_value()),
                    );
                    let pulled_data_usize = usize::try_from(pulled_data).unwrap();
                    *remaining_bytes -= pulled_data;
                    let start_offset = total_read;
                    total_read += pulled_data_usize;
                    data = &data[pulled_data_usize..];

                    // If the substream still exists, report the event to the API user.
                    // If the substream doesn't exist anymore, just continue iterating.
                    //
                    // It is possible that we are receiving data corresponding to a substream for
                    // which a RST has been sent out by the local node. Since the
                    // local state machine doesn't keep track of RST'ted substreams, any
                    // frame concerning a substream that has been RST or doesn't exist is
                    // discarded and doesn't result in an error, under the presumption that we
                    // are in this situation.
                    if let Some(Substream {
                        state:
                            SubstreamState::Healthy {
                                remote_write_closed,
                                ..
                            },
                        ..
                    }) = self.inner.substreams.get_mut(&substream_id.0)
                    {
                        debug_assert!(!*remote_write_closed);
                        return Ok(IncomingDataOutcome {
                            yamux: self,
                            bytes_read: total_read,
                            detail: Some(IncomingDataDetail::DataFrame {
                                substream_id,
                                start_offset,
                            }),
                        });
                    }

                    // We don't switch back `self.inner.incoming` to `Header` even if there's no
                    // bytes remaining in the data frame. Instead, the next iteration will pick up
                    // `DataFrame` again and transition again. This is necessary to handle the
                    // `fin` flag elegantly.
                }

                Incoming::DataFrame {
                    ref mut remaining_bytes,
                    ..
                } => {
                    debug_assert_ne!(*remaining_bytes, 0);
                    debug_assert!(data.is_empty());
                    break;
                }

                Incoming::Header(ref mut incoming_header) => {
                    // Try to copy as much as possible from `data` to `incoming_header`.
                    while !data.is_empty() && incoming_header.len() < 12 {
                        incoming_header.push(data[0]);
                        total_read += 1;
                        data = &data[1..];
                    }

                    // Decode the header in `incoming_header`.
                    let decoded_header = {
                        let Ok(full_header) = <&[u8; 12]>::try_from(&incoming_header[..])
                        else {
                            // Not enough data to finish receiving header. Nothing more can be
                            // done.
                            debug_assert!(data.is_empty());
                            break;
                        };

                        match header::decode_yamux_header(full_header) {
                            Ok(h) => h,
                            Err(err) => return Err(Error::HeaderDecode(err)),
                        }
                    };

                    match decoded_header {
                        header::DecodedYamuxHeader::PingRequest { opaque_value } => {
                            if self.inner.pongs_to_send.len()
                                >= self.inner.max_simultaneous_queued_pongs.get()
                            {
                                return Err(Error::MaxSimultaneousPingsExceeded);
                            }

                            self.inner.pongs_to_send.push_back(opaque_value);
                            self.inner.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                        }
                        header::DecodedYamuxHeader::PingResponse { opaque_value } => {
                            if self.inner.pings_waiting_reply.pop_front() != Some(opaque_value) {
                                return Err(Error::PingResponseNotMatching);
                            }

                            self.inner.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                            return Ok(IncomingDataOutcome {
                                yamux: self,
                                bytes_read: total_read,
                                detail: Some(IncomingDataDetail::PingResponse),
                            });
                        }
                        header::DecodedYamuxHeader::GoAway { error_code } => {
                            if self.inner.received_goaway.is_some() {
                                return Err(Error::MultipleGoAways);
                            }

                            self.inner.incoming = Incoming::Header(arrayvec::ArrayVec::new());
                            self.inner.received_goaway = Some(error_code);

                            let mut reset_substreams =
                                Vec::with_capacity(self.inner.substreams.len());
                            for (substream_id, substream) in self.inner.substreams.iter_mut() {
                                if !matches!(
                                    substream.state,
                                    SubstreamState::Healthy {
                                        remote_syn_acked: false,
                                        ..
                                    }
                                ) {
                                    continue;
                                }

                                reset_substreams.push(SubstreamId(*substream_id));

                                let _was_inserted =
                                    self.inner.dead_substreams.insert(*substream_id);
                                debug_assert!(_was_inserted);

                                self.inner.outgoing_req_substreams.remove(substream_id);

                                // We might be currently writing a frame of data of the substream
                                // being reset. If that happens, we need to update some internal
                                // state regarding this frame of data.
                                match (
                                    &mut self.inner.outgoing,
                                    mem::replace(&mut substream.state, SubstreamState::Reset),
                                ) {
                                    (
                                        Outgoing::Header {
                                            substream_data_frame:
                                                Some((data @ OutgoingSubstreamData::Healthy(_), _)),
                                            ..
                                        }
                                        | Outgoing::SubstreamData {
                                            data: data @ OutgoingSubstreamData::Healthy(_),
                                            ..
                                        },
                                        SubstreamState::Healthy { write_queue, .. },
                                    ) if matches!(*data, OutgoingSubstreamData::Healthy(SubstreamId(i)) if i == *substream_id) =>
                                    {
                                        *data = OutgoingSubstreamData::Obsolete { write_queue };
                                    }
                                    _ => {}
                                }
                            }

                            return Ok(IncomingDataOutcome {
                                yamux: self,
                                bytes_read: total_read,
                                detail: Some(IncomingDataDetail::GoAway {
                                    code: error_code,
                                    reset_substreams,
                                }),
                            });
                        }
                        header::DecodedYamuxHeader::Data {
                            rst: true,
                            ack,
                            stream_id,
                            length,
                            ..
                        }
                        | header::DecodedYamuxHeader::Window {
                            rst: true,
                            ack,
                            stream_id,
                            length,
                            ..
                        } => {
                            // Frame with the `RST` flag set. Destroy the substream.

                            // Sending a `RST` flag and data together is a weird corner case and
                            // is difficult to handle. It is unclear whether it is allowed at all.
                            // We thus consider it as invalid.
                            if matches!(decoded_header, header::DecodedYamuxHeader::Data { .. })
                                && length != 0
                            {
                                return Err(Error::DataWithRst);
                            }

                            self.inner.incoming = Incoming::Header(arrayvec::ArrayVec::new());

                            // The remote might have sent a RST frame concerning a substream for
                            // which we have sent a RST frame earlier. Considering that we don't
                            // always keep traces of old substreams, we have no way to know whether
                            // this is the case or not.
                            let Some(s) = self.inner.substreams.get_mut(&stream_id) else { continue };
                            if !matches!(s.state, SubstreamState::Healthy { .. }) {
                                continue;
                            }

                            let _was_inserted = self.inner.dead_substreams.insert(stream_id);
                            debug_assert!(_was_inserted);

                            self.inner.outgoing_req_substreams.remove(&stream_id);

                            // Check whether the remote has ACKed multiple times.
                            if matches!(
                                s.state,
                                SubstreamState::Healthy {
                                    remote_syn_acked: true,
                                    ..
                                }
                            ) && ack
                            {
                                return Err(Error::UnexpectedAck);
                            }

                            // We might be currently writing a frame of data of the substream
                            // being reset. If that happens, we need to update some internal
                            // state regarding this frame of data.
                            match (
                                &mut self.inner.outgoing,
                                mem::replace(&mut s.state, SubstreamState::Reset),
                            ) {
                                (
                                    Outgoing::Header {
                                        substream_data_frame:
                                            Some((data @ OutgoingSubstreamData::Healthy(_), _)),
                                        ..
                                    }
                                    | Outgoing::SubstreamData {
                                        data: data @ OutgoingSubstreamData::Healthy(_),
                                        ..
                                    },
                                    SubstreamState::Healthy { write_queue, .. },
                                ) if matches!(*data,
                                    OutgoingSubstreamData::Healthy(SubstreamId(i)) if i == stream_id) =>
                                {
                                    *data = OutgoingSubstreamData::Obsolete { write_queue };
                                }
                                _ => {}
                            }

                            return Ok(IncomingDataOutcome {
                                yamux: self,
                                bytes_read: total_read,
                                detail: Some(IncomingDataDetail::StreamReset {
                                    substream_id: SubstreamId(stream_id),
                                }),
                            });
                        }

                        header::DecodedYamuxHeader::Data {
                            syn: true,
                            ack: true,
                            ..
                        }
                        | header::DecodedYamuxHeader::Window {
                            syn: true,
                            ack: true,
                            ..
                        } => {
                            // You're never supposed to send a SYN and ACK at the same time.
                            return Err(Error::UnexpectedAck);
                        }

                        header::DecodedYamuxHeader::Data {
                            syn: true,
                            fin,
                            rst: false,
                            stream_id,
                            length,
                            ..
                        }
                        | header::DecodedYamuxHeader::Window {
                            syn: true,
                            fin,
                            rst: false,
                            stream_id,
                            length,
                            ..
                        } => {
                            // The initiator should only allocate uneven substream IDs, and the
                            // other side only even IDs. We don't know anymore whether we're
                            // initiator at this point, but we can compare with the even-ness of
                            // the IDs that we allocate locally.
                            if (self.inner.next_outbound_substream.get() % 2)
                                == (stream_id.get() % 2)
                            {
                                return Err(Error::InvalidInboundStreamId(stream_id));
                            }

                            // Remote has sent a SYN flag. A new substream is to be opened.
                            match self.inner.substreams.get(&stream_id) {
                                None => {}
                                Some(Substream {
                                    state:
                                        SubstreamState::Healthy {
                                            local_write_close: SubstreamStateLocalWrite::FinQueued,
                                            remote_write_closed: true,
                                            ..
                                        },
                                    ..
                                })
                                | Some(Substream {
                                    state: SubstreamState::Reset,
                                    ..
                                }) => {
                                    // Because we don't immediately destroy substreams, the remote
                                    // might decide to re-use a substream ID that is still
                                    // allocated locally. If that happens, we block the reading.
                                    // It will be unblocked when the API user destroys the old
                                    // substream.
                                    break;
                                }
                                Some(Substream {
                                    state: SubstreamState::Healthy { .. },
                                    ..
                                }) => {
                                    return Err(Error::UnexpectedSyn(stream_id));
                                }
                            }

                            // When receiving a new substream, we might have to potentially queue
                            // a substream rejection message later.
                            // In order to ensure that there is enough space in `rsts_to_send`,
                            // we check it against the limit now.
                            if self.inner.rsts_to_send.len()
                                >= self.inner.max_simultaneous_rst_substreams.get()
                            {
                                return Err(Error::MaxSimultaneousRstSubstreamsExceeded);
                            }

                            let is_data =
                                matches!(decoded_header, header::DecodedYamuxHeader::Data { .. });

                            // If we have queued or sent a GoAway frame, then the substream is
                            // ignored. The remote understands when receiving the GoAway that the
                            // substream has been rejected.
                            if !matches!(self.inner.outgoing_goaway, OutgoingGoAway::NotRequired) {
                                self.inner.incoming = if !is_data {
                                    Incoming::Header(arrayvec::ArrayVec::new())
                                } else {
                                    Incoming::DataFrame {
                                        substream_id: SubstreamId(stream_id),
                                        remaining_bytes: length,
                                        fin,
                                    }
                                };

                                continue;
                            }

                            if is_data && u64::from(length) > NEW_SUBSTREAMS_FRAME_SIZE {
                                return Err(Error::CreditsExceeded);
                            }

                            self.inner.incoming = Incoming::PendingIncomingSubstream {
                                substream_id: SubstreamId(stream_id),
                                extra_window: if !is_data { length } else { 0 },
                                data_frame_size: if is_data { length } else { 0 },
                                fin,
                            };

                            return Ok(IncomingDataOutcome {
                                yamux: self,
                                bytes_read: total_read,
                                detail: Some(IncomingDataDetail::IncomingSubstream),
                            });
                        }

                        header::DecodedYamuxHeader::Data {
                            syn: false,
                            rst: false,
                            stream_id,
                            length,
                            ack,
                            fin,
                            ..
                        } => {
                            // Note that it is possible that the remote is referring to a substream
                            // for which a RST has been sent out by the local node. Since the
                            // local state machine doesn't keep track of RST'ted substreams, any
                            // frame concerning a substream that has been RST or with an unknown
                            // id is discarded and doesn't result in an error, under the
                            // presumption that we are in this situation.
                            if let Some(Substream {
                                state:
                                    SubstreamState::Healthy {
                                        remote_write_closed,
                                        remote_allowed_window,
                                        remote_syn_acked,
                                        ..
                                    },
                                ..
                            }) = self.inner.substreams.get_mut(&stream_id)
                            {
                                match (ack, remote_syn_acked) {
                                    (false, true) => {}
                                    (true, acked @ false) => *acked = true,
                                    (true, true) => return Err(Error::UnexpectedAck),
                                    (false, false) => return Err(Error::ExpectedAck),
                                }

                                if *remote_write_closed {
                                    return Err(Error::WriteAfterFin);
                                }

                                // Check whether the remote has the right to send that much data.
                                // Note that the credits aren't checked in the case of an unknown
                                // substream.
                                *remote_allowed_window = remote_allowed_window
                                    .checked_sub(u64::from(length))
                                    .ok_or(Error::CreditsExceeded)?;
                            }

                            // Switch to the `DataFrame` state in order to process the frame, even
                            // if the substream no longer exists.
                            self.inner.incoming = Incoming::DataFrame {
                                substream_id: SubstreamId(stream_id),
                                remaining_bytes: length,
                                fin,
                            };
                        }

                        header::DecodedYamuxHeader::Window {
                            syn: false,
                            rst: false,
                            stream_id,
                            length,
                            ack,
                            fin,
                            ..
                        } => {
                            // Note that it is possible that the remote is referring to a substream
                            // for which a RST has been sent out by the local node. Since the
                            // local state machine doesn't keep track of RST'ted substreams, any
                            // frame concerning a substream that has been RST or with an unknown
                            // id is discarded and doesn't result in an error, under the
                            // presumption that we are in this situation.
                            if let Some(Substream {
                                state:
                                    SubstreamState::Healthy {
                                        remote_syn_acked,
                                        allowed_window,
                                        write_queue,
                                        ..
                                    },
                                ..
                            }) = self.inner.substreams.get_mut(&stream_id)
                            {
                                match (ack, remote_syn_acked) {
                                    (false, true) => {}
                                    (true, acked @ false) => *acked = true,
                                    (true, true) => return Err(Error::UnexpectedAck),
                                    (false, false) => return Err(Error::ExpectedAck),
                                }

                                if *allowed_window == 0 && length != 0 && !write_queue.is_empty() {
                                    self.inner.outgoing_req_substreams.insert(stream_id);
                                }

                                *allowed_window = allowed_window
                                    .checked_add(u64::from(length))
                                    .ok_or(Error::LocalCreditsOverflow)?;
                            }

                            // Note that the specs are unclear about whether the remote can or
                            // should continue sending FIN flags on window size frames after
                            // their side of the substream has already been closed before.

                            // We transition to `DataFrame` to make the handling a bit more
                            // elegant.
                            self.inner.incoming = Incoming::DataFrame {
                                substream_id: SubstreamId(stream_id),
                                remaining_bytes: 0,
                                fin,
                            };
                        }
                    }
                }
            }
        }

        Ok(IncomingDataOutcome {
            yamux: self,
            bytes_read: total_read,
            detail: None,
        })
    }

    /// Builds the next buffer to send out on the socket and returns it.
    ///
    /// The buffer will never be larger than `size_bytes` bytes. The user is expected to pass an
    /// exact amount of bytes that the next layer is ready to accept.
    ///
    /// > **Note**: Most other objects in the networking code have a "`read_write`" method that
    /// >           writes the outgoing data to a buffer. This is an idiomatic way to do things in
    /// >           situations where the data is generated on the fly. In the context of Yamux,
    /// >           however, this would be rather sub-optimal considering that buffers to send out
    /// >           are already stored in their final form in the state machine.
    pub fn extract_next(&'_ mut self, size_bytes: usize) -> Option<impl AsRef<[u8]> + '_> {
        if size_bytes == 0 {
            return None;
        }

        loop {
            match self.inner.outgoing {
                Outgoing::Header {
                    ref mut header,
                    ref mut header_already_sent,
                    ref mut substream_data_frame,
                } => {
                    // Finish writing the header.
                    debug_assert!(*header_already_sent < 12);
                    let encoded_header = header::encode(header);
                    let encoded_header_remains_to_write =
                        &encoded_header[usize::from(*header_already_sent)..];

                    if size_bytes >= encoded_header_remains_to_write.len() {
                        let out =
                            arrayvec::ArrayVec::<u8, 12>::try_from(encoded_header_remains_to_write)
                                .unwrap();
                        if matches!(header, header::DecodedYamuxHeader::GoAway { .. }) {
                            debug_assert!(matches!(
                                self.inner.outgoing_goaway,
                                OutgoingGoAway::Queued
                            ));
                            self.inner.outgoing_goaway = OutgoingGoAway::Sent;
                        }
                        self.inner.outgoing =
                            if let Some((data, remaining_bytes)) = substream_data_frame.take() {
                                Outgoing::SubstreamData {
                                    data,
                                    remaining_bytes,
                                }
                            } else {
                                Outgoing::Idle
                            };
                        return Some(either::Left(out));
                    } else {
                        let to_add = encoded_header_remains_to_write[..size_bytes].to_vec();
                        *header_already_sent += u8::try_from(size_bytes).unwrap();
                        debug_assert!(*header_already_sent < 12);
                        return Some(either::Right(write_queue::VecWithOffset(to_add, 0)));
                    }
                }

                Outgoing::SubstreamData {
                    remaining_bytes: ref mut remain,
                    ref mut data,
                } => {
                    let (write_queue, substream_id) = match data {
                        OutgoingSubstreamData::Healthy(id) => {
                            if let SubstreamState::Healthy {
                                ref mut write_queue,
                                ..
                            } = &mut self.inner.substreams.get_mut(&id.0).unwrap().state
                            {
                                (write_queue, Some(*id))
                            } else {
                                unreachable!()
                            }
                        }
                        OutgoingSubstreamData::Obsolete {
                            ref mut write_queue,
                        } => (write_queue, None),
                    };

                    // We only reach here if `size_bytes` and `remain` are non-zero.
                    // Also, `write_queue` must always have a size >= `remain`.
                    // Consequently, `out` can also never be empty.
                    debug_assert!(write_queue.queued_bytes() >= remain.get());
                    let out = write_queue.extract_some(cmp::min(remain.get(), size_bytes));
                    debug_assert!(!out.as_ref().is_empty());

                    // Since we are sure that `write_queue` wasn't empty beforehand, if it is
                    // now empty it means that we have sent out all the queued data. If a `FIN`
                    // was received and queued in the past, the substream is now dead.
                    if write_queue.is_empty() {
                        if let Some(id) = substream_id {
                            if let SubstreamState::Healthy {
                                local_write_close: SubstreamStateLocalWrite::FinQueued,
                                remote_write_closed: true,
                                ..
                            } = self.inner.substreams.get(&id.0).unwrap().state
                            {
                                debug_assert!(!self.inner.outgoing_req_substreams.contains(&id.0));
                                let _was_inserted = self.inner.dead_substreams.insert(id.0);
                                debug_assert!(_was_inserted);
                            }
                        }
                    }

                    if let Some(still_some_remain) =
                        NonZeroUsize::new(remain.get() - out.as_ref().len())
                    {
                        *remain = still_some_remain;
                    } else {
                        self.inner.outgoing = Outgoing::Idle;
                    }

                    return Some(either::Right(out));
                }

                Outgoing::Idle => {
                    // Send a `GoAway` frame if demanded.
                    if let OutgoingGoAway::Required(error_code) = self.inner.outgoing_goaway {
                        self.inner.outgoing = Outgoing::Header {
                            header: header::DecodedYamuxHeader::GoAway { error_code },
                            header_already_sent: 0,
                            substream_data_frame: None,
                        };
                        self.inner.outgoing_goaway = OutgoingGoAway::Queued;
                        continue;
                    }

                    // Send RST frames.
                    if let Some(substream_id) = self.inner.rsts_to_send.pop_front() {
                        self.inner.outgoing = Outgoing::Header {
                            header: header::DecodedYamuxHeader::Window {
                                syn: false,
                                ack: false,
                                fin: false,
                                rst: true,
                                stream_id: substream_id,
                                length: 0,
                            },
                            header_already_sent: 0,
                            substream_data_frame: None,
                        };
                        continue;
                    }

                    // Send outgoing pings.
                    if self.inner.pings_to_send > 0 {
                        self.inner.pings_to_send -= 1;
                        let opaque_value: u32 = self.inner.randomness.gen();
                        self.inner.pings_waiting_reply.push_back(opaque_value);
                        self.inner.outgoing = Outgoing::Header {
                            header: header::DecodedYamuxHeader::PingRequest { opaque_value },
                            header_already_sent: 0,
                            substream_data_frame: None,
                        };
                        debug_assert!(self.inner.pings_waiting_reply.len() <= MAX_PINGS);
                        continue;
                    }

                    // Send outgoing pongs.
                    if let Some(opaque_value) = self.inner.pongs_to_send.pop_front() {
                        self.inner.outgoing = Outgoing::Header {
                            header: header::DecodedYamuxHeader::PingResponse { opaque_value },
                            header_already_sent: 0,
                            substream_data_frame: None,
                        };
                        continue;
                    }

                    // Send either window update frames or data frames.
                    if let Some(substream_id) = self
                        .inner
                        .outgoing_req_substreams
                        .iter()
                        .choose(&mut self.inner.randomness)
                        .cloned()
                    {
                        debug_assert!(!self.inner.dead_substreams.contains(&substream_id));

                        let sub = self.inner.substreams.get_mut(&substream_id).unwrap();

                        let SubstreamState::Healthy {
                            first_message_queued,
                            remote_window_pending_increase,
                            remote_allowed_window,
                            write_queue,
                            local_write_close: local_write,
                            allowed_window,
                            ..
                        } = &mut sub.state else { unreachable!() };

                        let has_data_to_write = (*allowed_window != 0 && !write_queue.is_empty())
                            || matches!(local_write, SubstreamStateLocalWrite::FinDesired);
                        let has_window_size_update_to_write = *remote_window_pending_increase != 0;

                        if has_window_size_update_to_write {
                            let syn_ack_flag = !*first_message_queued;
                            *first_message_queued = true;

                            let update = u32::try_from(*remote_window_pending_increase)
                                .unwrap_or(u32::max_value());
                            *remote_window_pending_increase -= u64::from(update);
                            *remote_allowed_window += u64::from(update);

                            if *remote_window_pending_increase == 0 && !has_data_to_write {
                                self.inner.outgoing_req_substreams.remove(&substream_id);
                            }

                            self.inner.outgoing = Outgoing::Header {
                                header: header::DecodedYamuxHeader::Window {
                                    syn: syn_ack_flag && !sub.inbound,
                                    ack: syn_ack_flag && sub.inbound,
                                    fin: false,
                                    rst: false,
                                    stream_id: substream_id,
                                    length: update,
                                },
                                header_already_sent: 0,
                                substream_data_frame: None,
                            };
                            continue;
                        } else if has_data_to_write {
                            let pending_len = write_queue.queued_bytes();
                            let max_possible = cmp::min(
                                u32::try_from(pending_len).unwrap_or(u32::max_value()),
                                u32::try_from(*allowed_window).unwrap_or(u32::max_value()),
                            );
                            let len_out =
                                cmp::min(self.inner.max_out_data_frame_size.get(), max_possible);
                            let len_out_usize = usize::try_from(len_out).unwrap();
                            *allowed_window -= u64::from(len_out);
                            let syn_ack_flag = !*first_message_queued;
                            *first_message_queued = true;
                            let fin_flag = !matches!(local_write, SubstreamStateLocalWrite::Open)
                                && len_out_usize == pending_len;
                            if fin_flag {
                                *local_write = SubstreamStateLocalWrite::FinQueued;
                            }
                            debug_assert!(len_out != 0 || fin_flag);

                            if max_possible == len_out && !has_window_size_update_to_write {
                                self.inner.outgoing_req_substreams.remove(&substream_id);
                            }

                            self.inner.outgoing = Outgoing::Header {
                                header: header::DecodedYamuxHeader::Data {
                                    syn: syn_ack_flag && !sub.inbound,
                                    ack: syn_ack_flag && sub.inbound,
                                    fin: fin_flag,
                                    rst: false,
                                    stream_id: substream_id,
                                    length: len_out,
                                },
                                header_already_sent: 0,
                                substream_data_frame: NonZeroUsize::new(
                                    usize::try_from(len_out).unwrap(),
                                )
                                .map(|length| {
                                    (
                                        OutgoingSubstreamData::Healthy(SubstreamId(substream_id)),
                                        length,
                                    )
                                }),
                            };

                            continue;
                        } else {
                            // Substream was queued but there's nothing to do. Should never
                            // happen. We use a `debug_assert!` as to not panic in that situation,
                            // as the queue is just a cache and not a critical state.
                            debug_assert!(false);
                            self.inner.outgoing_req_substreams.remove(&substream_id);
                        }
                    }

                    // Nothing to send out.
                    break;
                }
            }
        }

        None
    }

    /// Accepts an incoming substream.
    ///
    /// Either [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be
    /// called after [`IncomingDataDetail::IncomingSubstream`] is returned.
    ///
    /// Note that there is no expiration window after [`IncomingDataDetail::IncomingSubstream`]
    /// is returned until the substream is no longer valid. However, reading will be blocked until
    /// the substream is either accepted or rejected. This function should thus be called as
    /// soon as possible.
    ///
    /// Returns an error if no incoming substream is currently pending.
    ///
    pub fn accept_pending_substream(
        &mut self,
        user_data: T,
    ) -> Result<SubstreamId, PendingSubstreamError> {
        match self.inner.incoming {
            Incoming::PendingIncomingSubstream {
                substream_id,
                extra_window,
                data_frame_size,
                fin,
            } => {
                debug_assert!(u64::from(data_frame_size) <= NEW_SUBSTREAMS_FRAME_SIZE);

                let _was_before = self.inner.substreams.insert(
                    substream_id.0,
                    Substream {
                        state: SubstreamState::Healthy {
                            first_message_queued: false,
                            remote_syn_acked: true,
                            remote_allowed_window: NEW_SUBSTREAMS_FRAME_SIZE
                                - u64::from(data_frame_size),
                            remote_window_pending_increase: 0,
                            allowed_window: NEW_SUBSTREAMS_FRAME_SIZE + u64::from(extra_window),
                            local_write_close: SubstreamStateLocalWrite::Open,
                            remote_write_closed: data_frame_size == 0 && fin,
                            write_queue: write_queue::WriteQueue::new(),
                        },
                        inbound: true,
                        user_data,
                    },
                );
                debug_assert!(_was_before.is_none());

                self.inner.num_inbound += 1;

                self.inner.incoming = if data_frame_size == 0 {
                    Incoming::Header(arrayvec::ArrayVec::new())
                } else {
                    Incoming::DataFrame {
                        substream_id,
                        remaining_bytes: data_frame_size,
                        fin,
                    }
                };

                Ok(substream_id)
            }
            _ => Err(PendingSubstreamError::NoPendingSubstream),
        }
    }

    /// Rejects an incoming substream.
    ///
    /// Either [`Yamux::accept_pending_substream`] or [`Yamux::reject_pending_substream`] must be
    /// called after [`IncomingDataDetail::IncomingSubstream`] is returned.
    ///
    /// Note that there is no expiration window after [`IncomingDataDetail::IncomingSubstream`]
    /// is returned until the substream is no longer valid. However, reading will be blocked until
    /// the substream is either accepted or rejected. This function should thus be called as
    /// soon as possible.
    ///
    /// Returns an error if no incoming substream is currently pending.
    ///
    pub fn reject_pending_substream(&mut self) -> Result<(), PendingSubstreamError> {
        match self.inner.incoming {
            Incoming::PendingIncomingSubstream {
                substream_id,
                data_frame_size,
                fin,
                ..
            } => {
                self.inner.incoming = Incoming::DataFrame {
                    substream_id,
                    remaining_bytes: data_frame_size,
                    fin,
                };

                self.inner.rsts_to_send.push_back(substream_id.0);
                Ok(())
            }
            _ => Err(PendingSubstreamError::NoPendingSubstream),
        }
    }
}

impl<T> fmt::Debug for Yamux<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct List<'a, T>(&'a Yamux<T>);
        impl<'a, T> fmt::Debug for List<'a, T>
        where
            T: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.inner.substreams.values().map(|v| &v.user_data))
                    .finish()
            }
        }

        f.debug_struct("Yamux")
            .field("substreams", &List(self))
            .finish()
    }
}

/// Identifier of a substream in the context of a connection.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, derive_more::From)]
pub struct SubstreamId(NonZeroU32);

impl SubstreamId {
    /// Returns the value that compares inferior or equal to all possible values.
    pub fn min_value() -> Self {
        Self(NonZeroU32::new(1).unwrap())
    }

    /// Returns the value that compares superior or equal to all possible values.
    pub fn max_value() -> Self {
        Self(NonZeroU32::new(u32::max_value()).unwrap())
    }
}

#[must_use]
#[derive(Debug)]
pub struct IncomingDataOutcome<T> {
    /// Yamux object on which [`Yamux::incoming_data`] has been called.
    pub yamux: Yamux<T>,
    /// Number of bytes read from the incoming buffer. These bytes should no longer be present the
    /// next time [`Yamux::incoming_data`] is called.
    pub bytes_read: usize,
    /// Detail about the incoming data. `None` if nothing of interest has happened.
    pub detail: Option<IncomingDataDetail>,
}

/// Details about the incoming data.
#[must_use]
#[derive(Debug)]
pub enum IncomingDataDetail {
    /// Remote has requested to open a new substream.
    ///
    /// After this has been received, either [`Yamux::accept_pending_substream`] or
    /// [`Yamux::reject_pending_substream`] needs to be called in order to accept or reject
    /// this substream. Calling [`Yamux::incoming_data`] before this is done will lead to a
    /// panic.
    ///
    /// Note that this can never happen after [`Yamux::send_goaway`] has been called, as all
    /// substreams are then automatically rejected.
    IncomingSubstream,

    /// Received data corresponding to a substream.
    DataFrame {
        /// Offset in the buffer passed to [`Yamux::incoming_data`] where the data frame
        /// starts. The data frame ends at the offset of [`IncomingDataOutcome::bytes_read`].
        start_offset: usize,
        /// Substream the data belongs to. Guaranteed to be valid.
        substream_id: SubstreamId,
    },

    /// Remote has closed its writing side of the substream.
    StreamClosed {
        /// Substream that got closed.
        substream_id: SubstreamId,
    },

    /// Remote has asked to reset a substream.
    StreamReset {
        /// Substream that has been reset.
        substream_id: SubstreamId,
    },

    /// Received a "go away" request. This means that it is now forbidden to open new outbound
    /// substreams. It is still allowed to send and receive data on existing substreams, and the
    /// remote is still allowed to open substreams.
    GoAway {
        /// Error code sent by the remote.
        code: GoAwayErrorCode,
        /// List of all outgoing substreams that haven't been acknowledged by the remote yet.
        /// These substreams are considered as reset, similar to
        /// [`IncomingDataDetail::StreamReset`].
        reset_substreams: Vec<SubstreamId>,
    },

    /// Received a response to a ping that has been sent out earlier.
    ///
    /// If multiple pings have been sent out simultaneously, they are always answered in the same
    /// order as they have been sent out.
    PingResponse,
}

/// Error potentially returned by [`Yamux::open_substream`].
#[derive(Debug, derive_more::Display)]
pub enum OpenSubstreamError {
    /// A `GoAway` frame has been received in the past.
    GoAwayReceived,
    /// Impossible to allocate a new substream.
    NoFreeSubstreamId,
}

/// Error potentially returned by [`Yamux::write`].
#[derive(Debug, derive_more::Display)]
pub enum WriteError {
    /// Substream was already closed.
    Closed,
    /// Substream was reset.
    Reset,
}

/// Error potentially returned by [`Yamux::close`].
#[derive(Debug, derive_more::Display)]
pub enum CloseError {
    /// Substream was already closed.
    AlreadyClosed,
    /// Substream was reset.
    Reset,
}

/// Error potentially returned by [`Yamux::reset`].
#[derive(Debug, derive_more::Display)]
pub enum ResetError {
    /// Substream was already reset.
    AlreadyReset,
}

/// Error potentially returned by [`Yamux::send_goaway`].
#[derive(Debug, derive_more::Display)]
pub enum SendGoAwayError {
    /// A `GoAway` has already been sent.
    AlreadySent,
}

/// Error potentially returned by [`Yamux::accept_pending_substream`] or
/// [`Yamux::reject_pending_substream`].
#[derive(Debug, derive_more::Display)]
pub enum PendingSubstreamError {
    /// No substream is pending.
    NoPendingSubstream,
}

/// Error while decoding the Yamux stream.
#[derive(Debug, derive_more::Display)]
pub enum Error {
    /// Failed to decode an incoming Yamux header.
    HeaderDecode(header::YamuxHeaderDecodeError),
    /// Received a SYN flag with a substream ID that is of the same side as the local side.
    InvalidInboundStreamId(NonZeroU32),
    /// Received a SYN flag with a known substream ID.
    #[display(fmt = "Received a SYN flag with a known substream ID")]
    UnexpectedSyn(NonZeroU32),
    /// Remote tried to send more data than it was allowed to.
    CreditsExceeded,
    /// Number of credits allocated to the local node has overflowed.
    LocalCreditsOverflow,
    /// Remote sent additional data on a substream after having sent the FIN flag.
    WriteAfterFin,
    /// Remote has sent a data frame containing data at the same time as a `RST` flag.
    DataWithRst,
    /// Remote has sent a ping response, but its opaque data didn't match any of the ping that
    /// have been sent out in the past.
    PingResponseNotMatching,
    /// Maximum number of simultaneous RST frames to send out has been exceeded.
    MaxSimultaneousRstSubstreamsExceeded,
    /// Maximum number of simultaneous PONG frames to send out has been exceeded.
    MaxSimultaneousPingsExceeded,
    /// The remote should have sent an ACK flag but didn't.
    ExpectedAck,
    /// The remote sent an ACK flag but shouldn't have.
    UnexpectedAck,
    /// Received multiple `GoAway` frames.
    MultipleGoAways,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeadSubstreamTy {
    ClosedGracefully,
    Reset,
}

/// By default, all new substreams have this implicit window size.
pub const NEW_SUBSTREAMS_FRAME_SIZE: u64 = 256 * 1024;
