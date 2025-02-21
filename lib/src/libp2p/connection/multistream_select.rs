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

//! Multistream-select is a protocol whose purpose is to negotiate protocols.
//!
//! # Context
//!
//! The multistream-select protocol makes it possible for two parties to negotiate a protocol.
//!
//! When using TCP connections, it is used immediately after a connection opens in order to
//! negotiate which encryption protocol to use, then after the encryption protocol handshake to
//! negotiate which multiplexing protocol to use.
//!
//! It is also used every time a substream opens in order to negotiate which protocol to use for
//! this substream in particular.
//!
//! Once a protocol has been negotiated, the connection or substream immediately starts speaking
//! this protocol.
//!
//! The multistream-select protocol is asymmetric: one side needs to be the dialer and the other
//! side the listener. In the context of a TCP connection, the dialer and listener correspond to
//! the dialer and listener of the connection. In the context of a substream, the dialer is the
//! side that initiated the opening of the substream.
//!
//! # About protocol names
//!
//! Due to flaws in the wire protocol design, a protocol named `na` causes an ambiguity in
//! the exchange. Because protocol names are normally decided ahead of time, this situation is
//! expected to never arise, except in the presence of a malicious remote. The decision has been
//! taken that such protocol will always fail to negotiate, but will also not produce any error
//! or panic.
//!
//! Please don't intentionally name a protocol `na`.
//!
//! # Usage
//!
//! To be written.
//!
//! # See also
//!
//! - [Official repository](https://github.com/multiformats/multistream-select)
//!

// TODO: write usage

use super::super::read_write::ReadWrite;
use crate::{libp2p::read_write, util::leb128};

use alloc::{collections::VecDeque, string::String};
use core::{cmp, fmt, str};

/// Configuration of a multistream-select protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Config<P> {
    /// Local node is the dialing side and requests the specific protocol.
    Dialer {
        /// Name of the protocol to try negotiate. The multistream-select negotiation will
        /// ultimately succeed if and only if the remote supports this protocol.
        requested_protocol: P,
    },
    /// Local node is the listening side.
    Listener {
        /// Maximum allowed length of a protocol. Set this to a value superior or equal to the
        /// length of the longest protocol that is supported locally.
        ///
        /// This limit is necessary in order to prevent the remote from sending an infinite stream
        /// of data for the protocol name.
        max_protocol_name_len: usize,
    },
}

/// Current state of a multistream-select negotiation.
#[derive(Debug)]
pub enum Negotiation<P> {
    /// Negotiation is still in progress. Use the provided [`InProgress`] object to inject and
    /// extract more data from/to the remote.
    InProgress(InProgress<P>),
    /// Negotiation is still in progress and is waiting for accepting or refusing the protocol
    /// requested by the remote.
    ///
    /// Can never happen if configured as the dialing side.
    ListenerAcceptOrDeny(ListenerAcceptOrDeny<P>),
    /// Negotiation has ended successfully. A protocol has been negotiated.
    Success,
    /// Negotiation has ended, but there isn't any protocol in common between the two parties.
    ///
    /// Can only ever happen as the dialing side.
    NotAvailable,
}

impl<P> Negotiation<P>
where
    P: AsRef<str>,
{
    /// Shortcut method for [`InProgress::new`] and wrapping the [`InProgress`] in a
    /// [`Negotiation`].
    pub fn new(config: Config<P>) -> Self {
        Negotiation::InProgress(InProgress::new(config))
    }
}

/// Negotiation is still in progress and is waiting for accepting or refusing the protocol
/// requested by the remote.
#[derive(Debug)]
pub struct ListenerAcceptOrDeny<P> {
    inner: InProgress<P>,
    protocol: String,
}

impl<P> ListenerAcceptOrDeny<P> {
    /// Name of the protocol requested by the remote.
    pub fn requested_protocol(&self) -> &str {
        &self.protocol
    }

    /// Accept the requested protocol and resume the handshake.
    pub fn accept(mut self) -> InProgress<P> {
        debug_assert!(matches!(self.inner.state, InProgressState::CommandExpected));
        write_message(
            Message::ProtocolOk(self.protocol.into_bytes()),
            &mut self.inner.data_send_out,
        );
        self.inner.state = InProgressState::Finishing;
        self.inner
    }

    /// Reject the requested protocol and resume the handshake.
    pub fn reject(mut self) -> InProgress<P> {
        debug_assert!(matches!(self.inner.state, InProgressState::CommandExpected));
        write_message(
            Message::<&'static [u8]>::ProtocolNa,
            &mut self.inner.data_send_out,
        );
        self.inner
    }
}

/// Negotiation in progress.
pub struct InProgress<P> {
    /// Configuration of the negotiation.
    config: Config<P>,
    /// Data currently being sent out.
    data_send_out: VecDeque<u8>,
    /// Current state of the negotiation.
    state: InProgressState,
    /// Maximum allowed size of an incoming frame.
    max_in_frame_len: usize,
    /// Size of the next frame to receive, or `None` if not known yet. If `Some`, we have already
    /// extracted the length from the incoming buffer.
    next_in_frame_len: Option<usize>,
}

/// Current state of the negotiation.
#[derive(Debug, Copy, Clone)]
enum InProgressState {
    Finishing,
    HandshakeExpected,
    CommandExpected,
    ProtocolRequestAnswerExpected,
}

impl<P> InProgress<P>
where
    P: AsRef<str>,
{
    /// Initializes a new handshake state machine.
    pub fn new(config: Config<P>) -> Self {
        // Length, in bytes, of the longest protocol name.
        let max_proto_name_len = match &config {
            Config::Dialer { requested_protocol } => requested_protocol.as_ref().len(),
            Config::Listener {
                max_protocol_name_len,
            } => *max_protocol_name_len,
        };

        // Any incoming frame larger than `max_frame_len` will trigger a protocol error.
        // This means that a protocol error might be reported in situations where the dialer
        // legitimately requests a protocol that the listener doesn't support. In order to prevent
        // confusion, a minimum length is applied to the protocol name length. Any protocol name
        // smaller than this will never trigger a protocol error, even if it isn't supported.
        const MIN_PROTO_LEN_NO_ERR: usize = 512;
        let max_frame_len = cmp::max(
            cmp::max(max_proto_name_len, MIN_PROTO_LEN_NO_ERR),
            HANDSHAKE.len(),
        ) + 1;

        InProgress {
            // Note that the listener theoretically doesn't necessarily have to immediately send
            // a handshake, and could instead wait for a command from the dialer. In practice,
            // however, the specification doesn't mention anything about this, and some libraries
            // such as js-libp2p wait for the listener to send a handshake before emitting a
            // command.
            data_send_out: {
                let mut data = VecDeque::new();
                write_message(Message::<&'static [u8]>::Handshake, &mut data);
                if let Config::Dialer { requested_protocol } = &config {
                    write_message(
                        Message::ProtocolRequest(requested_protocol.as_ref()),
                        &mut data,
                    );
                }
                data
            },
            config,
            state: InProgressState::HandshakeExpected,
            max_in_frame_len: max_frame_len,
            next_in_frame_len: None,
        }
    }

    /// If this function returns true, then the multistream-select handshake has finished writing
    /// all its data, and the API user can now start writing the protocol-specific data if it
    /// desires, even though the multistream-handshake isn't finished.
    ///
    /// If the remote supports the requested protocol, then doing so will save one networking
    /// round-trip. If however the remote doesn't support the requested protocol, then doing so
    /// will lead to confusing errors on the remote, as it will interpret the protocol-specific
    /// data as being from the multistream-select protocol, and the substream will be rendered
    /// unusable. Overall, saving a round-trip is usually seen as preferable over confusing
    /// errors.
    pub fn can_write_protocol_data(&self) -> bool {
        matches!(self.state, InProgressState::ProtocolRequestAnswerExpected)
    }

    /// Feeds data coming from a socket, updates the internal state machine, and writes data
    /// destined to the socket.
    ///
    /// On success, returns the new state of the negotiation.
    ///
    /// An error is returned if the reading or writing are closed, or if the protocol is being
    /// violated by the remote. When that happens, the connection should be closed altogether.
    pub fn read_write<TNow>(
        mut self,
        read_write: &mut ReadWrite<TNow>,
    ) -> Result<Negotiation<P>, Error> {
        loop {
            // First, try to send out data currently being queued for sending.
            read_write.write_from_vec_deque(&mut self.data_send_out);

            // The `Finishing` state is special because it doesn't expect any incoming message
            // anymore, and just finishes the negotiation after all the data has been written out.
            // As such, we do not proceed further unless we have finished sending out everything.
            if let InProgressState::Finishing = self.state {
                debug_assert!(matches!(self.config, Config::Listener { .. }));
                if self.data_send_out.is_empty() {
                    return Ok(Negotiation::Success);
                } else {
                    break;
                }
            }

            // Try to extract a message from the incoming buffer.
            let mut frame = if let Some(next_frame_len) = self.next_in_frame_len {
                match read_write.incoming_bytes_take(next_frame_len) {
                    Ok(None) => return Ok(Negotiation::InProgress(self)),
                    Ok(Some(frame)) => {
                        self.next_in_frame_len = None;
                        frame
                    }
                    Err(err) => return Err(Error::Frame(err)),
                }
            } else {
                match read_write.incoming_bytes_take_leb128(self.max_in_frame_len) {
                    Ok(None) => return Ok(Negotiation::InProgress(self)),
                    Ok(Some(size)) => {
                        self.next_in_frame_len = Some(size);
                        continue;
                    }
                    Err(err) => return Err(Error::FrameLength(err)),
                }
            };

            match (self.state, &self.config) {
                (InProgressState::HandshakeExpected, Config::Dialer { .. }) => {
                    if &*frame != HANDSHAKE {
                        return Err(Error::BadHandshake);
                    }

                    // The dialer immediately sends the request after its handshake and before
                    // waiting for the handshake from the listener. As such, after receiving the
                    // handshake, the next step is to wait for the request answer.
                    self.state = InProgressState::ProtocolRequestAnswerExpected;
                }

                (InProgressState::HandshakeExpected, Config::Listener { .. }) => {
                    if &*frame != HANDSHAKE {
                        return Err(Error::BadHandshake);
                    }

                    // The listener immediately sends the handshake at initialization. When this
                    // code is reached, it has therefore already been sent.
                    self.state = InProgressState::CommandExpected;
                }

                (InProgressState::CommandExpected, Config::Listener { .. }) => {
                    if frame.pop() != Some(b'\n') {
                        return Err(Error::InvalidCommand);
                    }

                    let protocol = String::from_utf8(frame).map_err(|_| Error::InvalidCommand)?;

                    return Ok(Negotiation::ListenerAcceptOrDeny(ListenerAcceptOrDeny {
                        inner: self,
                        protocol,
                    }));
                }

                (
                    InProgressState::ProtocolRequestAnswerExpected,
                    Config::Dialer { requested_protocol },
                ) => {
                    if frame.pop() != Some(b'\n') {
                        return Err(Error::UnexpectedProtocolRequestAnswer);
                    }
                    if &*frame == b"na" {
                        // Because of the order of checks, a protocol named `na` will never be
                        // successfully negotiated. Debugging is expected to be less confusing if
                        // the negotiation always fails.
                        return Ok(Negotiation::NotAvailable);
                    }
                    if frame != requested_protocol.as_ref().as_bytes() {
                        return Err(Error::UnexpectedProtocolRequestAnswer);
                    }
                    return Ok(Negotiation::Success);
                }

                // Invalid states.
                (InProgressState::CommandExpected, Config::Dialer { .. })
                | (InProgressState::ProtocolRequestAnswerExpected, Config::Listener { .. })
                | (InProgressState::Finishing, _) => {
                    unreachable!();
                }
            };
        }

        // This point should be reached only if data is lacking in order to proceed.
        Ok(Negotiation::InProgress(self))
    }
}

impl<P> fmt::Debug for InProgress<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("InProgress").finish()
    }
}

/// Error that can happen during the negotiation.
#[derive(Debug, Clone, derive_more::Display, derive_more::Error)]
pub enum Error {
    /// Reading side of the connection is closed. The handshake can't proceed further.
    ReadClosed,
    /// Writing side of the connection is closed. The handshake can't proceed further.
    WriteClosed,
    /// Error while decoding a frame length, or frame size limit reached.
    #[display("LEB128 frame error: {_0}")]
    FrameLength(read_write::IncomingBytesTakeLeb128Error),
    /// Error while decoding a frame.
    #[display("LEB128 frame error: {_0}")]
    Frame(read_write::IncomingBytesTakeError),
    /// Unknown handshake or unknown multistream-select protocol version.
    BadHandshake,
    /// Received empty command.
    InvalidCommand,
    /// Received answer to protocol request that doesn't match the requested protocol.
    UnexpectedProtocolRequestAnswer,
}

/// Handshake message sent by both parties at the beginning of each multistream-select negotiation.
const HANDSHAKE: &[u8] = b"/multistream/1.0.0\n";

/// Message on the multistream-select protocol.
#[derive(Debug, Copy, Clone)]
enum Message<P> {
    Handshake,
    ProtocolRequest(P),
    ProtocolOk(P),
    ProtocolNa,
}

fn write_message(message: Message<impl AsRef<[u8]>>, out: &mut VecDeque<u8>) {
    match message {
        Message::Handshake => {
            out.reserve(HANDSHAKE.len() + 4);
            out.extend(leb128::encode_usize(HANDSHAKE.len()));
            out.extend(HANDSHAKE);
        }
        Message::ProtocolRequest(p) | Message::ProtocolOk(p) => {
            let p = p.as_ref();
            out.reserve(p.len() + 5);
            out.extend(leb128::encode_usize(p.len() + 1));
            out.extend(p);
            out.push_back(b'\n');
        }
        Message::ProtocolNa => {
            out.reserve(8);
            out.extend(leb128::encode_usize(3));
            out.extend(b"na\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use core::{cmp, mem};

    use super::{super::super::read_write::ReadWrite, Config, Message, Negotiation, write_message};

    #[test]
    fn encode() {
        let mut message = VecDeque::new();

        write_message(Message::<&'static [u8]>::Handshake, &mut message);
        assert_eq!(
            message.drain(..).collect::<Vec<_>>(),
            b"\x13/multistream/1.0.0\n".to_vec()
        );

        write_message(Message::ProtocolRequest("/hello"), &mut message);
        assert_eq!(
            message.drain(..).collect::<Vec<_>>(),
            b"\x07/hello\n".to_vec()
        );

        write_message(Message::<&'static [u8]>::ProtocolNa, &mut message);
        assert_eq!(message.drain(..).collect::<Vec<_>>(), b"\x03na\n".to_vec());
    }

    #[test]
    fn negotiation_basic_works() {
        fn test_with_buffer_sizes(mut size1: usize, mut size2: usize) {
            let mut negotiation1 = Negotiation::new(Config::Dialer {
                requested_protocol: "/foo",
            });
            let mut negotiation2 = Negotiation::new(Config::<String>::Listener {
                max_protocol_name_len: 4,
            });

            let mut buf_1_to_2 = Vec::new();
            let mut buf_2_to_1 = Vec::new();

            let mut num_iterations = 0;

            while !matches!(
                (&negotiation1, &negotiation2),
                (Negotiation::Success, Negotiation::Success)
            ) {
                num_iterations += 1;
                assert!(num_iterations <= 5000);

                match negotiation1 {
                    Negotiation::InProgress(nego) => {
                        let mut read_write = ReadWrite {
                            now: 0,
                            incoming_buffer: buf_2_to_1,
                            expected_incoming_bytes: Some(0),
                            read_bytes: 0,
                            write_bytes_queued: buf_1_to_2.len(),
                            write_bytes_queueable: Some(size1 - buf_1_to_2.len()),
                            write_buffers: vec![mem::take(&mut buf_1_to_2)],
                            wake_up_after: None,
                        };
                        negotiation1 = nego.read_write(&mut read_write).unwrap();
                        buf_2_to_1 = read_write.incoming_buffer;
                        buf_1_to_2.extend(
                            read_write
                                .write_buffers
                                .drain(..)
                                .flat_map(|b| b.into_iter()),
                        );
                        size2 = cmp::max(size2, read_write.expected_incoming_bytes.unwrap_or(0));
                    }
                    Negotiation::Success => {}
                    Negotiation::ListenerAcceptOrDeny(_) => unreachable!(),
                    Negotiation::NotAvailable => panic!(),
                }

                match negotiation2 {
                    Negotiation::InProgress(nego) => {
                        let mut read_write = ReadWrite {
                            now: 0,
                            incoming_buffer: buf_1_to_2,
                            expected_incoming_bytes: Some(0),
                            read_bytes: 0,
                            write_bytes_queued: buf_2_to_1.len(),
                            write_bytes_queueable: Some(size2 - buf_2_to_1.len()),
                            write_buffers: vec![mem::take(&mut buf_2_to_1)],
                            wake_up_after: None,
                        };
                        negotiation2 = nego.read_write(&mut read_write).unwrap();
                        buf_1_to_2 = read_write.incoming_buffer;
                        buf_2_to_1.extend(
                            read_write
                                .write_buffers
                                .drain(..)
                                .flat_map(|b| b.into_iter()),
                        );
                        size1 = cmp::max(size1, read_write.expected_incoming_bytes.unwrap_or(0));
                    }
                    Negotiation::ListenerAcceptOrDeny(accept_reject)
                        if accept_reject.requested_protocol() == "/foo" =>
                    {
                        negotiation2 = Negotiation::InProgress(accept_reject.accept());
                    }
                    Negotiation::ListenerAcceptOrDeny(accept_reject) => {
                        negotiation2 = Negotiation::InProgress(accept_reject.reject());
                    }
                    Negotiation::Success => {}
                    Negotiation::NotAvailable => panic!(),
                }
            }
        }

        test_with_buffer_sizes(256, 256);
        test_with_buffer_sizes(1, 1);
        test_with_buffer_sizes(1, 2048);
        test_with_buffer_sizes(2048, 1);
    }
}
