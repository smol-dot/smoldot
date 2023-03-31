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
use crate::util::leb128;

use alloc::{string::String, vec::Vec};
use core::{cmp, fmt, iter, mem, str};

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
        self.inner.state = InProgressState::SendProtocolOk {
            num_bytes_written: 0,
            protocol: self.protocol.into_bytes(),
        };
        self.inner
    }

    /// Reject the requested protocol and resume the handshake.
    pub fn reject(mut self) -> InProgress<P> {
        debug_assert!(matches!(self.inner.state, InProgressState::CommandExpected));
        self.inner.state = InProgressState::SendProtocolNa {
            num_bytes_written: 0,
        };
        self.inner
    }
}

/// Negotiation in progress.
pub struct InProgress<P> {
    /// Configuration of the negotiation. Always `Some` except right before destruction.
    config: Option<Config<P>>,
    /// Current state of the negotiation.
    state: InProgressState,
    /// Maximum allowed size of a frame for `recv_buffer`.
    max_frame_len: usize,
    /// Incoming data is buffered in this `recv_buffer` before being decoded.
    recv_buffer: leb128::Framed,
}

/// Current state of the negotiation.
enum InProgressState {
    SendHandshake {
        /// Number of bytes of the handshake already written out.
        num_bytes_written: usize,
    },
    SendProtocolRequest {
        /// Number of bytes of the request already written out.
        num_bytes_written: usize,
    },
    SendProtocolOk {
        /// Number of bytes of the response already written out.
        num_bytes_written: usize,
        /// Which protocol to acknowledge.
        protocol: Vec<u8>,
    },
    SendProtocolNa {
        /// Number of bytes of the response already written out.
        num_bytes_written: usize,
    },
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
            config: Some(config),
            // Note that the listener theoretically doesn't necessarily have to immediately send
            // a handshake, and could instead wait for a command from the dialer. In practice,
            // however, the specification doesn't mention anything about this, and some libraries
            // such as js-libp2p wait for the listener to send a handshake before emitting a
            // command.
            state: InProgressState::SendHandshake {
                num_bytes_written: 0,
            },
            max_frame_len,
            recv_buffer: leb128::Framed::InProgress(leb128::FramedInProgress::new(max_frame_len)),
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
            // `self.recv_buffer` serves as a helper to delimit `data` into frames. The first step
            // is to inject the received data into `recv_buffer`.
            if let leb128::Framed::InProgress(recv_buffer) = self.recv_buffer {
                let (num_read, framed_result) = recv_buffer
                    .update(read_write.incoming_buffer.as_ref().unwrap_or(&&[][..]))
                    .map_err(Error::Frame)?;
                self.recv_buffer = framed_result;
                read_write.advance_read(num_read);
            }

            match (self.state, &mut self.config) {
                (
                    InProgressState::SendHandshake {
                        mut num_bytes_written,
                    },
                    Some(config),
                ) => {
                    if read_write.outgoing_buffer.is_none() {
                        return Err(Error::WriteClosed);
                    }

                    let message = MessageOut::Handshake::<&'static str>;

                    let written_before = read_write.written_bytes;
                    let done = message.write_out(num_bytes_written, read_write);
                    num_bytes_written += read_write.written_bytes - written_before;

                    match (done, config) {
                        (false, _) => {
                            self.state = InProgressState::SendHandshake { num_bytes_written };
                            break;
                        }
                        (true, Config::Dialer { .. }) => {
                            self.state = InProgressState::SendProtocolRequest {
                                num_bytes_written: 0,
                            }
                        }
                        (true, Config::Listener { .. }) => {
                            self.state = InProgressState::HandshakeExpected;
                        }
                    };
                }

                (
                    InProgressState::SendProtocolRequest {
                        mut num_bytes_written,
                    },
                    Some(Config::Dialer { requested_protocol }),
                ) => {
                    if read_write.outgoing_buffer.is_none() {
                        return Err(Error::WriteClosed);
                    }

                    let message = MessageOut::ProtocolRequest(requested_protocol.as_ref());

                    let written_before = read_write.written_bytes;
                    let done = message.write_out(num_bytes_written, read_write);
                    num_bytes_written += read_write.written_bytes - written_before;

                    if done {
                        self.state = InProgressState::HandshakeExpected;
                    } else {
                        self.state = InProgressState::SendProtocolRequest { num_bytes_written };
                        break;
                    }
                }

                (
                    InProgressState::SendProtocolNa {
                        mut num_bytes_written,
                    },
                    _,
                ) => {
                    if read_write.outgoing_buffer.is_none() {
                        return Err(Error::WriteClosed);
                    }

                    let message = MessageOut::ProtocolNa::<&'static str>;

                    let written_before = read_write.written_bytes;
                    let done = message.write_out(num_bytes_written, read_write);
                    num_bytes_written += read_write.written_bytes - written_before;

                    if done {
                        self.state = InProgressState::CommandExpected;
                    } else {
                        self.state = InProgressState::SendProtocolNa { num_bytes_written };
                        break;
                    }
                }

                (
                    InProgressState::SendProtocolOk {
                        mut num_bytes_written,
                        protocol,
                    },
                    _,
                ) => {
                    if read_write.outgoing_buffer.is_none() {
                        return Err(Error::WriteClosed);
                    }

                    let message = MessageOut::ProtocolOk(&protocol);

                    let written_before = read_write.written_bytes;
                    let done = message.write_out(num_bytes_written, read_write);
                    num_bytes_written += read_write.written_bytes - written_before;

                    if done {
                        return Ok(Negotiation::Success);
                    }
                    self.state = InProgressState::SendProtocolOk {
                        num_bytes_written,
                        protocol,
                    };
                    break;
                }

                (InProgressState::HandshakeExpected, Some(Config::Dialer { .. })) => {
                    if read_write.incoming_buffer.is_none() {
                        return Err(Error::ReadClosed);
                    }

                    let frame = match self.recv_buffer {
                        leb128::Framed::Finished(frame) => {
                            self.recv_buffer = leb128::Framed::InProgress(
                                leb128::FramedInProgress::new(self.max_frame_len),
                            );
                            frame
                        }
                        leb128::Framed::InProgress(f) => {
                            // No frame is available.
                            debug_assert_eq!(read_write.incoming_buffer_available(), 0);
                            self.recv_buffer = leb128::Framed::InProgress(f);
                            self.state = InProgressState::HandshakeExpected;
                            break;
                        }
                    };

                    if &*frame != HANDSHAKE {
                        return Err(Error::BadHandshake);
                    }

                    // The dialer immediately sends the request after its handshake and before
                    // waiting for the handshake from the listener. As such, after receiving the
                    // handshake, the next step is to wait for the request answer.
                    self.state = InProgressState::ProtocolRequestAnswerExpected;
                }

                (InProgressState::HandshakeExpected, Some(Config::Listener { .. })) => {
                    if read_write.incoming_buffer.is_none() {
                        return Err(Error::ReadClosed);
                    }

                    let frame = match self.recv_buffer {
                        leb128::Framed::Finished(frame) => {
                            self.recv_buffer = leb128::Framed::InProgress(
                                leb128::FramedInProgress::new(self.max_frame_len),
                            );
                            frame
                        }
                        leb128::Framed::InProgress(f) => {
                            // No frame is available.
                            debug_assert_eq!(read_write.incoming_buffer_available(), 0);
                            self.recv_buffer = leb128::Framed::InProgress(f);
                            self.state = InProgressState::HandshakeExpected;
                            break;
                        }
                    };

                    if &*frame != HANDSHAKE {
                        return Err(Error::BadHandshake);
                    }

                    // The listener immediately sends the handshake at initialization. When this
                    // code is reached, it has therefore already been sent.
                    self.state = InProgressState::CommandExpected;
                }

                (InProgressState::CommandExpected, Some(Config::Listener { .. })) => {
                    if read_write.incoming_buffer.is_none() {
                        return Err(Error::ReadClosed);
                    }

                    let mut frame = match self.recv_buffer {
                        leb128::Framed::Finished(frame) => {
                            self.recv_buffer = leb128::Framed::InProgress(
                                leb128::FramedInProgress::new(self.max_frame_len),
                            );
                            frame
                        }
                        leb128::Framed::InProgress(f) => {
                            // No frame is available.
                            debug_assert_eq!(read_write.incoming_buffer_available(), 0);
                            self.recv_buffer = leb128::Framed::InProgress(f);
                            self.state = InProgressState::CommandExpected;
                            break;
                        }
                    };

                    if frame.last().map_or(true, |b| *b != b'\n') {
                        return Err(Error::InvalidCommand);
                    }

                    frame.pop().unwrap();

                    let protocol = String::from_utf8(frame).map_err(|_| Error::InvalidCommand)?;

                    self.state = InProgressState::CommandExpected;
                    return Ok(Negotiation::ListenerAcceptOrDeny(ListenerAcceptOrDeny {
                        inner: self,
                        protocol,
                    }));
                }

                (
                    InProgressState::ProtocolRequestAnswerExpected,
                    cfg @ Some(Config::Dialer { .. }),
                ) => {
                    if read_write.incoming_buffer.is_none() {
                        return Err(Error::ReadClosed);
                    }

                    let frame = match self.recv_buffer {
                        leb128::Framed::Finished(f) => f,
                        leb128::Framed::InProgress(f) => {
                            // No frame is available.
                            debug_assert_eq!(read_write.incoming_buffer_available(), 0);
                            self.recv_buffer = leb128::Framed::InProgress(f);
                            self.state = InProgressState::ProtocolRequestAnswerExpected;
                            break;
                        }
                    };

                    // Extract `config` to get the protocol name. All the paths below return,
                    // thereby `config` doesn't need to be put back in `self`.
                    let requested_protocol = match cfg.take() {
                        Some(Config::Dialer { requested_protocol }) => requested_protocol,
                        _ => unreachable!(),
                    };

                    if frame.last().map_or(true, |c| *c != b'\n') {
                        return Err(Error::UnexpectedProtocolRequestAnswer);
                    }
                    if &*frame == b"na\n" {
                        // Because of the order of checks, a protocol named `na` will never be
                        // successfully negotiated. Debugging is expected to be less confusing if
                        // the negotiation always fails.
                        return Ok(Negotiation::NotAvailable);
                    }
                    if &frame[..frame.len() - 1] != requested_protocol.as_ref().as_bytes() {
                        return Err(Error::UnexpectedProtocolRequestAnswer);
                    }
                    return Ok(Negotiation::Success);
                }

                // Invalid states.
                (InProgressState::SendProtocolRequest { .. }, Some(Config::Listener { .. })) => {
                    unreachable!();
                }
                (InProgressState::CommandExpected, Some(Config::Dialer { .. })) => unreachable!(),
                (InProgressState::ProtocolRequestAnswerExpected, Some(Config::Listener { .. })) => {
                    unreachable!();
                }
                (_, None) => unreachable!(),
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
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Reading side of the connection is closed. The handshake can't proceed further.
    ReadClosed,
    /// Writing side of the connection is closed. The handshake can't proceed further.
    WriteClosed,
    /// Error while decoding a frame length, or frame size limit reached.
    #[display(fmt = "LEB128 frame error: {_0}")]
    Frame(leb128::FramedError),
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
pub enum MessageOut<P> {
    Handshake,
    ProtocolRequest(P),
    ProtocolOk(P),
    LnAfterProtocol,
    ProtocolNa,
}

impl<P> MessageOut<P>
where
    P: AsRef<[u8]>,
{
    /// Returns the bytes representation of this message, as a list of buffers. The message
    /// consists in the concatenation of all buffers.
    pub fn into_bytes(mut self) -> impl Iterator<Item = impl AsRef<[u8]>> {
        let len = match &self {
            MessageOut::Handshake => HANDSHAKE.len(),
            MessageOut::ProtocolRequest(p) => p.as_ref().len() + 1,
            MessageOut::ProtocolOk(p) => p.as_ref().len() + 1,
            MessageOut::LnAfterProtocol => 1,
            MessageOut::ProtocolNa => 3,
        };

        let length_prefix = leb128::encode_usize(len).map(|n| [n]);

        let mut n = 0;
        let body = iter::from_fn(move || {
            let ret = match (&mut self, n) {
                (MessageOut::Handshake, 0) => Some(either::Left(HANDSHAKE)),
                (MessageOut::Handshake, _) => None,
                (MessageOut::ProtocolOk(_) | MessageOut::ProtocolRequest(_), 0) => {
                    let proto = match mem::replace(&mut self, MessageOut::LnAfterProtocol) {
                        MessageOut::ProtocolOk(p) | MessageOut::ProtocolRequest(p) => p,
                        _ => unreachable!(),
                    };

                    Some(either::Right(proto))
                }
                (MessageOut::ProtocolOk(_) | MessageOut::ProtocolRequest(_), _) => {
                    unreachable!()
                }
                (MessageOut::LnAfterProtocol, 0 | 1) => {
                    n = 1;
                    Some(either::Left(&b"\n"[..]))
                }
                (MessageOut::LnAfterProtocol, _) => None,
                (MessageOut::ProtocolNa, 0) => Some(either::Left(&b"na\n"[..])),
                (MessageOut::ProtocolNa, _) => None,
            };

            if ret.is_some() {
                n += 1;
            }

            ret
        });

        length_prefix
            .map(either::Left)
            .chain(body.map(either::Right))
    }

    /// Write to the given [`ReadWrite`] as many bytes of the message as possible, starting at
    /// `message_offset`.
    ///
    /// Returns a boolean indicating whether the message has been fully written in the buffer.
    ///
    /// # Panic
    ///
    /// Panics if `message_offset` is larger than the size of the message.
    ///
    pub fn write_out<TNow>(
        self,
        mut message_offset: usize,
        read_write: &mut ReadWrite<TNow>,
    ) -> bool {
        for buf in self.into_bytes() {
            let buf = buf.as_ref();
            if message_offset >= buf.len() {
                message_offset -= buf.len();
                continue;
            }

            let buf = &buf[message_offset..];
            debug_assert!(!buf.is_empty());

            let to_write = cmp::min(buf.len(), read_write.outgoing_buffer_available());

            read_write.write_out(&buf[..to_write]);
            message_offset = 0;

            if to_write < buf.len() {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::{super::super::read_write::ReadWrite, Config, MessageOut, Negotiation};

    #[test]
    fn encode() {
        assert_eq!(
            MessageOut::<&'static [u8]>::Handshake.into_bytes().fold(
                Vec::new(),
                move |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                }
            ),
            b"\x13/multistream/1.0.0\n".to_vec()
        );

        assert_eq!(
            MessageOut::ProtocolRequest("/hello")
                .into_bytes()
                .fold(Vec::new(), move |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                }),
            b"\x07/hello\n".to_vec()
        );

        assert_eq!(
            MessageOut::<&'static [u8]>::ProtocolNa.into_bytes().fold(
                Vec::new(),
                move |mut a, b| {
                    a.extend_from_slice(b.as_ref());
                    a
                }
            ),
            b"\x03na\n".to_vec()
        );

        // TODO: all encoding testing
    }

    #[test]
    fn negotiation_basic_works() {
        fn test_with_buffer_sizes(size1: usize, size2: usize) {
            let mut negotiation1 = Negotiation::new(Config::Dialer {
                requested_protocol: "/foo",
            });
            let mut negotiation2 = Negotiation::new(Config::<String>::Listener {
                max_protocol_name_len: 4,
            });

            let mut buf_1_to_2 = Vec::new();
            let mut buf_2_to_1 = Vec::new();

            while !matches!(
                (&negotiation1, &negotiation2),
                (Negotiation::Success, Negotiation::Success)
            ) {
                match negotiation1 {
                    Negotiation::InProgress(nego) => {
                        if buf_1_to_2.is_empty() {
                            buf_1_to_2.resize(size1, 0);
                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_2_to_1),
                                outgoing_buffer: Some((&mut buf_1_to_2, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            negotiation1 = nego.read_write(&mut read_write).unwrap();
                            let (read_bytes, written_bytes) =
                                (read_write.read_bytes, read_write.written_bytes);
                            for _ in 0..read_bytes {
                                buf_2_to_1.remove(0);
                            }
                            buf_1_to_2.truncate(written_bytes);
                        } else {
                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_2_to_1),
                                outgoing_buffer: Some((&mut [], &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            negotiation1 = nego.read_write(&mut read_write).unwrap();
                            for _ in 0..read_write.read_bytes {
                                buf_2_to_1.remove(0);
                            }
                        }
                    }
                    Negotiation::Success => {}
                    Negotiation::ListenerAcceptOrDeny(_) => unreachable!(),
                    Negotiation::NotAvailable => panic!(),
                }

                match negotiation2 {
                    Negotiation::InProgress(nego) => {
                        if buf_2_to_1.is_empty() {
                            buf_2_to_1.resize(size2, 0);
                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_1_to_2),
                                outgoing_buffer: Some((&mut buf_2_to_1, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            negotiation2 = nego.read_write(&mut read_write).unwrap();
                            let (read_bytes, written_bytes) =
                                (read_write.read_bytes, read_write.written_bytes);
                            for _ in 0..read_bytes {
                                buf_1_to_2.remove(0);
                            }
                            buf_2_to_1.truncate(written_bytes);
                        } else {
                            let mut read_write = ReadWrite {
                                now: 0,
                                incoming_buffer: Some(&buf_1_to_2),
                                outgoing_buffer: Some((&mut [], &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            negotiation2 = nego.read_write(&mut read_write).unwrap();
                            for _ in 0..read_write.read_bytes {
                                buf_1_to_2.remove(0);
                            }
                        }
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
