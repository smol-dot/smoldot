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

//! State machine handling the handshake with a TCP or WebSocket libp2p connection.
//!
//! A connection handshake consists of three steps:
//!
//! - A multistream-select negotiation to negotiate the encryption protocol. Only the noise
//! protocol is supported at the moment.
//! - A noise protocol handshake, where public keys are exchanged and symmetric encryption is
//! initialized.
//! - A multistream-select negotiation to negotiate the Yamux protocol. Only the Yamux protocol is
//! supported at the moment. This negotiation is performed on top of the noise cipher.
//!
//! This entire handshake requires in total either three or five TCP packets (not including the
//! TCP handshake), depending on the strategy used for the multistream-select protocol.

// TODO: finish commenting on the number of round trips
// TODO: some round-trips can be removed: the multistream-select ones, and maybe also a Noise one, but it's complicated

use super::{
    super::peer_id::PeerId,
    super::read_write::ReadWrite,
    established::ConnectionPrototype,
    multistream_select,
    noise::{self, NoiseKey},
    yamux,
};

use alloc::boxed::Box;
use core::fmt;

mod tests;

/// Current state of a connection handshake.
#[derive(Debug, derive_more::From)]
pub enum Handshake {
    /// Connection handshake in progress.
    Healthy(HealthyHandshake),
    /// Handshake has succeeded. Connection is now open.
    Success {
        /// Network identity of the remote.
        remote_peer_id: PeerId,
        /// Prototype for the connection.
        connection: ConnectionPrototype,
    },
}

impl Handshake {
    /// Shortcut for [`HealthyHandshake::noise_yamux`] wrapped in a [`Handshake`].
    pub fn noise_yamux(
        noise_key: &NoiseKey,
        noise_ephemeral_secret_key: &[u8; 32],
        is_initiator: bool,
    ) -> Self {
        HealthyHandshake::noise_yamux(noise_key, noise_ephemeral_secret_key, is_initiator).into()
    }
}

/// Connection handshake in progress.
pub struct HealthyHandshake {
    state: NegotiationState,
}

enum NegotiationState {
    EncryptionProtocol {
        negotiation: multistream_select::InProgress<&'static str>,
        /// Handshake that will be driven after the protocol negotiation is successful. Created
        /// ahead of time but not actually used.
        handshake: noise::HandshakeInProgress,
    },
    Encryption {
        handshake: noise::HandshakeInProgress,
    },
    Multiplexing {
        peer_id: PeerId,
        encryption: Box<noise::Noise>,
        negotiation: multistream_select::InProgress<&'static str>,
    },
}

impl HealthyHandshake {
    /// Initializes a new state machine for a Noise + Yamux handshake.
    ///
    /// Must pass `true` for `is_initiator` if the connection has been opened by the local machine,
    /// or `false` if it has been opened by the remote.
    ///
    /// The Noise ephemeral secret key must never be re-used.
    pub fn noise_yamux(
        noise_key: &NoiseKey,
        noise_ephemeral_secret_key: &[u8; 32],
        is_initiator: bool,
    ) -> Self {
        let negotiation = multistream_select::InProgress::new(if is_initiator {
            multistream_select::Config::Dialer {
                requested_protocol: noise::PROTOCOL_NAME,
            }
        } else {
            multistream_select::Config::Listener {
                max_protocol_name_len: noise::PROTOCOL_NAME.len(),
            }
        });

        HealthyHandshake {
            state: NegotiationState::EncryptionProtocol {
                negotiation,
                handshake: noise::HandshakeInProgress::new(noise::Config {
                    key: noise_key,
                    is_initiator,
                    prologue: &[],
                    ephemeral_secret_key: noise_ephemeral_secret_key,
                }),
            },
        }
    }

    /// Feeds data coming from a socket and writes back data to send up.
    ///
    /// On success, returns the new state of the negotiation.
    ///
    /// An error is returned if the protocol is being violated by the remote. When that happens,
    /// the connection should be closed altogether.
    pub fn read_write<TNow: Clone>(
        mut self,
        read_write: &mut ReadWrite<TNow>,
    ) -> Result<Handshake, HandshakeError> {
        loop {
            match self.state {
                NegotiationState::EncryptionProtocol {
                    negotiation,
                    handshake,
                } => {
                    // Earliest point of the handshake. The encryption is being negotiated.
                    // Delegating read/write to the negotiation.
                    let updated = negotiation
                        .read_write(read_write)
                        .map_err(HandshakeError::EncryptionMultistreamSelect)?;

                    return match updated {
                        multistream_select::Negotiation::InProgress(updated) => {
                            Ok(Handshake::Healthy(HealthyHandshake {
                                state: NegotiationState::EncryptionProtocol {
                                    negotiation: updated,
                                    handshake,
                                },
                            }))
                        }
                        multistream_select::Negotiation::Success => {
                            self.state = NegotiationState::Encryption { handshake };
                            continue;
                        }
                        multistream_select::Negotiation::ListenerAcceptOrDeny(accept_reject) => {
                            let negotiation =
                                if accept_reject.requested_protocol() == noise::PROTOCOL_NAME {
                                    accept_reject.accept()
                                } else {
                                    accept_reject.reject()
                                };
                            self.state = NegotiationState::EncryptionProtocol {
                                negotiation,
                                handshake,
                            };
                            continue;
                        }
                        multistream_select::Negotiation::NotAvailable => {
                            Err(HandshakeError::NoEncryptionProtocol)
                        }
                    };
                }

                NegotiationState::Encryption { handshake } => {
                    // Delegating read/write to the Noise handshake state machine.
                    let updated = handshake.read_write(read_write).map_err(|err| {
                        debug_assert!(!matches!(err, noise::HandshakeError::WriteClosed));
                        HandshakeError::NoiseHandshake(err)
                    })?;

                    match updated {
                        noise::NoiseHandshake::Success {
                            cipher,
                            remote_peer_id,
                        } => {
                            // Encryption layer has been successfully negotiated. Start the
                            // handshake for the multiplexing protocol negotiation.
                            let negotiation =
                                multistream_select::InProgress::new(if cipher.is_initiator() {
                                    multistream_select::Config::Dialer {
                                        requested_protocol: yamux::PROTOCOL_NAME,
                                    }
                                } else {
                                    multistream_select::Config::Listener {
                                        max_protocol_name_len: yamux::PROTOCOL_NAME.len(),
                                    }
                                });

                            self.state = NegotiationState::Multiplexing {
                                peer_id: remote_peer_id,
                                encryption: Box::new(cipher),
                                negotiation,
                            };

                            continue;
                        }
                        noise::NoiseHandshake::InProgress(updated) => {
                            return Ok(Handshake::Healthy(HealthyHandshake {
                                state: NegotiationState::Encryption { handshake: updated },
                            }));
                        }
                    };
                }

                NegotiationState::Multiplexing {
                    negotiation,
                    mut encryption,
                    peer_id,
                } => {
                    // During the multiplexing protocol negotiation, all exchanges have to go
                    // through the Noise cipher.

                    if read_write.expected_incoming_bytes.is_none() {
                        return Err(HandshakeError::MultiplexingMultistreamSelect(
                            multistream_select::Error::ReadClosed,
                        ));
                    }
                    if read_write.write_bytes_queueable.is_none() {
                        return Err(HandshakeError::MultiplexingMultistreamSelect(
                            multistream_select::Error::WriteClosed,
                        ));
                    }

                    let negotiation_update = {
                        let mut decrypted_stream = encryption
                            .read_write(read_write)
                            .map_err(HandshakeError::Noise)?;
                        negotiation
                            .read_write(&mut *decrypted_stream)
                            .map_err(HandshakeError::MultiplexingMultistreamSelect)?
                    };

                    return match negotiation_update {
                        multistream_select::Negotiation::InProgress(updated) => {
                            Ok(Handshake::Healthy(HealthyHandshake {
                                state: NegotiationState::Multiplexing {
                                    negotiation: updated,
                                    encryption,
                                    peer_id,
                                },
                            }))
                        }
                        multistream_select::Negotiation::ListenerAcceptOrDeny(accept_reject) => {
                            let negotiation =
                                if accept_reject.requested_protocol() == yamux::PROTOCOL_NAME {
                                    accept_reject.accept()
                                } else {
                                    accept_reject.reject()
                                };
                            self.state = NegotiationState::Multiplexing {
                                peer_id,
                                encryption,
                                negotiation,
                            };
                            continue;
                        }
                        multistream_select::Negotiation::Success => Ok(Handshake::Success {
                            connection: ConnectionPrototype::from_noise_yamux(*encryption),
                            remote_peer_id: peer_id,
                        }),
                        multistream_select::Negotiation::NotAvailable => {
                            Err(HandshakeError::NoMultiplexingProtocol)
                        }
                    };
                }
            }
        }
    }
}

impl fmt::Debug for HealthyHandshake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HealthyHandshake").finish()
    }
}

/// Error during a connection handshake. The connection should be shut down.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum HandshakeError {
    /// Protocol error during the multistream-select negotiation of the encryption protocol.
    #[display("Encryption protocol selection error: {_0}")]
    EncryptionMultistreamSelect(multistream_select::Error),
    /// Protocol error during the multistream-select negotiation of the multiplexing protocol.
    #[display("Multiplexing protocol selection error: {_0}")]
    MultiplexingMultistreamSelect(multistream_select::Error),
    /// Protocol error during the noise handshake.
    #[display("Noise handshake error: {_0}")]
    NoiseHandshake(noise::HandshakeError),
    /// No encryption protocol in common with the remote.
    ///
    /// The remote is behaving correctly but isn't compatible with the local node.
    NoEncryptionProtocol,
    /// No multiplexing protocol in common with the remote.
    ///
    /// The remote is behaving correctly but isn't compatible with the local node.
    NoMultiplexingProtocol,
    /// Error in the noise cipher. Data has most likely been corrupted.
    #[display("Noise cipher error: {_0}")]
    Noise(noise::CipherError),
}
