// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

//! Noise protocol libp2p layer.
//!
//! The [noise protocol](https://noiseprotocol.org/) is a standard framework for building
//! cryptographic protocols. Libp2p uses the noise protocol to provide an encryption layer on
//! top of which data is exchanged.
//!
//! # Protocol details
//!
//! Libp2p uses [the XX pattern](https://noiseexplorer.com/patterns/XX/). The handshake consists
//! of three packets:
//!
//! - The initiator generates an ephemeral key pair and sends the public key to the responder.
//! - The responder generates its own ephemeral key pair and sends the public key to the
//! initiator. Afterwards, the responder derives a shared secret and uses it to encrypt all
//! further communications. Now encrypted, the responder also sends back its static noise public
//! key (represented with the [`NoiseKey`] type of this module), its libp2p public key, and a
//! signature of the static noise public key made using its libp2p private key.
//! - The initiator, after having received the ephemeral key from the remote, derives the same
//! shared secret. It sends its own static noise public key, libp2p public key, and signature.
//!
//! After these three packets, the initiator and responder derive another shared secret using
//! both the static and ephemeral keys, which is then used to encrypt communications. Note that
//! the libp2p key isn't used in the key derivation.
//!
//! # Usage
//!
//! While this is out of scope of this module, the noise protocol must typically first be
//! negotiated using the *multistream-select* protocol. The name of the protocol is given by
//! the [`PROTOCOL_NAME`] constant.
//!
//! In order to use noise on top of a connection which has agreed to use noise, create a
//! [`HandshakeInProgress`], passing a [`NoiseKey`]. This [`NoiseKey`] is typically generated at
//! startup and doesn't need to be persisted after a restart.
//!
//! Use [`HandshakeInProgress::read_write`] when data is received from the wire or when the remote
//! is ready to receive more data. At every call, a [`NoiseHandshake`] is returned, potentially
//! indicating the end of the handshake.
//!
//! If the handshake is finished, a [`NoiseHandshake::Success`] is returned, containing the
//! [`PeerId`] of the remote, which is known to be legitimate, and a [`Noise`] object through
//! which all further communications should go through.
//!
//! Use [`Noise::encrypt`] in order to send out data to the remote, and
//! [`Noise::decrypt_to_vecdeque`] when data is received.

// # Q&A
//
// ## Why not use a library such as `snow`?
//
// Snow suffers from a variety of problems:
//
// - It doesn't support `no_std`.
// - It uses outdated versions of dependencies.
// - It doesn't allow writing a single Noise message onto two consecutive buffers.
// - It doesn't support encoding a Noise message already present in the output buffer.
// - It isn't really maintained.
// - It doesn't give control over its random number generator.
//

use crate::{
    libp2p::{
        peer_id::{PeerId, PublicKey, SignatureVerifyFailed},
        read_write::ReadWrite,
    },
    util::protobuf,
};

use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use core::{cmp, fmt, iter, mem};

/// Name of the protocol, typically used when negotiated it using *multistream-select*.
pub const PROTOCOL_NAME: &str = "/noise";

/// The noise key is the key exchanged during the noise handshake. It is **not** the same as the
/// libp2p key. The libp2p key is used only to sign the noise public key, while the ECDH is
/// performed with the noise key.
///
/// From the point of view of the noise protocol specification, this [`NoiseKey`] corresponds to
/// the static key. The noise key is typically generated at startup and doesn't have to be
/// persisted on disk, contrary to the libp2p key which is typically persisted after a restart.
///
/// In order to generate a [`NoiseKey`], two things are needed:
///
/// - A public/private key, also represented as [`UnsignedNoiseKey`].
/// - A signature of this public key made using the libp2p private key.
///
/// The signature requires access to the libp2p private key. As such, there are two possible
/// ways to create a [`NoiseKey`]:
///
/// - The easier way, by passing the libp2p private key to [`NoiseKey::new`].
/// - The slightly more complex way, by first creating an [`UnsignedNoiseKey`], then passing a
/// a signature. This second method doesn't require direct access to the private key but only
/// to a method of signing a message, which makes it for example possible to use a hardware
/// device.
///
pub struct NoiseKey {
    private_key: zeroize::Zeroizing<x25519_dalek::StaticSecret>,
    public_key: x25519_dalek::PublicKey,
    /// Handshake to encrypt then send on the wire.
    handshake_message: Vec<u8>,
    /// Ed25519 public key used for the signature in the handshake message.
    libp2p_public_ed25519_key: [u8; 32],
}

impl NoiseKey {
    /// Turns a libp2p private key and a Noise static private key into a [`NoiseKey`].
    pub fn new(libp2p_ed25519_private_key: &[u8; 32], noise_static_private_key: &[u8; 32]) -> Self {
        let unsigned = UnsignedNoiseKey::from_private_key(noise_static_private_key);

        let (libp2p_public_key, signature) = {
            // Creating a `SecretKey` can fail only if the length isn't 32 bytes.
            let secret = ed25519_zebra::SigningKey::from(*libp2p_ed25519_private_key);
            let public = ed25519_zebra::VerificationKey::from(&secret);
            // TODO: use sign_prehashed or sign_vectored (https://github.com/dalek-cryptography/ed25519-dalek/pull/143) to not allocate Vec
            let signature = secret.sign(&unsigned.payload_to_sign_as_vec());
            (public, signature)
        };

        unsigned.sign(libp2p_public_key.into(), signature.into())
    }

    /// Returns the libp2p public key associated to the signature contained in this noise key.
    pub fn libp2p_public_ed25519_key(&self) -> &[u8; 32] {
        &self.libp2p_public_ed25519_key
    }
}

/// Prototype for a [`NoiseKey`].
///
/// This type is provided for situations where the user has access to some signing mechanism,
/// such as a hardware device, but not directly to the private key.
///
/// For simple cases, prefer using [`NoiseKey::new`].
pub struct UnsignedNoiseKey {
    private_key: Option<zeroize::Zeroizing<x25519_dalek::StaticSecret>>,
    public_key: x25519_dalek::PublicKey,
}

impl UnsignedNoiseKey {
    /// Turns a private key into an [`UnsignedNoiseKey`].
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let private_key = zeroize::Zeroizing::new(x25519_dalek::StaticSecret::from(*private_key));
        let public_key = x25519_dalek::PublicKey::from(&*private_key);
        UnsignedNoiseKey {
            private_key: Some(private_key),
            public_key,
        }
    }

    /// Returns the data that has to be signed.
    pub fn payload_to_sign(&'_ self) -> impl Iterator<Item = impl AsRef<[u8]> + '_> + '_ {
        [
            &b"noise-libp2p-static-key:"[..],
            &self.public_key.as_bytes()[..],
        ]
        .into_iter()
    }

    /// Returns the data that has to be signed.
    ///
    /// This method is a more convenient equivalent to
    /// [`UnsignedNoiseKey::payload_to_sign_as_vec`].
    pub fn payload_to_sign_as_vec(&self) -> Vec<u8> {
        self.payload_to_sign().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b.as_ref());
            a
        })
    }

    /// Turns this [`UnsignedNoiseKey`] into a [`NoiseKey`] after signing it using the libp2p
    /// private key.
    pub fn sign(mut self, libp2p_public_ed25519_key: [u8; 32], signature: [u8; 64]) -> NoiseKey {
        let libp2p_pubkey_protobuf =
            PublicKey::Ed25519(libp2p_public_ed25519_key).to_protobuf_encoding();

        let handshake_message = {
            // Protobuf message format can be found here:
            // https://github.com/libp2p/specs/tree/master/noise#the-libp2p-handshake-payload

            // The capacity is arbitrary but large enough to avoid Vec reallocations.
            let mut msg = Vec::with_capacity(32 + libp2p_pubkey_protobuf.len() + signature.len());

            for slice in protobuf::bytes_tag_encode(1, &libp2p_pubkey_protobuf) {
                msg.extend_from_slice(slice.as_ref());
            }

            for slice in protobuf::bytes_tag_encode(2, &signature) {
                msg.extend_from_slice(slice.as_ref());
            }

            msg
        };

        NoiseKey {
            public_key: self.public_key,
            private_key: self.private_key.take().unwrap(),
            libp2p_public_ed25519_key,
            handshake_message,
        }
    }
}

/// Configuration for a Noise handshake.
pub struct Config<'a> {
    /// Key to use during the handshake.
    pub key: &'a NoiseKey,

    /// Secret key to use for that specific handshake. Must be randomly generated. Must never be
    /// re-used between multiple handshakes.
    pub ephemeral_secret_key: &'a [u8; 32],

    /// `true` if this side of the handshake has initiated the connection or substream onto which
    /// the handshake is performed.
    pub is_initiator: bool,

    /// Prologue data. The prologue data must be identical on both sides of the handshake,
    /// otherwise it will fail.
    ///
    /// See <https://noiseprotocol.org/noise.html#prologue>.
    ///
    /// > **Note**: If a certain protocol specification doesn't mention any prologue, it probably
    /// >           means that this prologue is empty.
    pub prologue: &'a [u8],
}

/// State of the noise encryption/decryption cipher.
pub struct Noise {
    /// See [`Config::is_initiator`].
    is_initiator: bool,

    /// Cipher used to encrypt outgoing data.
    out_cipher_state: CipherState,

    /// Cipher used to decrypt incoming data.
    in_cipher_state: CipherState,

    /// Buffer of data containing data received on the wire (still encrypted) but that isn't
    /// enough to form a full message. Includes the two bytes of libp2p length prefix.
    rx_buffer_encrypted: Vec<u8>,
}

impl Noise {
    /// Feeds encrypted data received from the wire and writes the decrypted data into `out`.
    ///
    /// Returns the number of bytes from `encrypted_data` that it has processed. These bytes must
    /// be discarded and not passed again.
    ///
    /// The [`Noise`] state machine might copy some of the encrypted data internally for later.
    /// Consequently, be aware that it is not possible to (easily) predict how much `out` is going
    /// to grow based on the size of `encrypted_data`.
    ///
    /// This function always writes as much data to `out` as possible. In other words, calling
    /// this function with an empty `encrypted_data` always has no effect.
    ///
    /// An error is returned if part of the payload fails to decode, which can happen if a
    /// malicious actor has added or modified data to the stream of encrypted data. You are
    /// encouraged to shut down the connection altogether if that happens.
    // TODO: this API is very specific, maybe provide a way to decode into slices?
    pub fn decrypt_to_vecdeque(
        &mut self,
        mut encrypted_data: &[u8],
        out: &mut VecDeque<u8>,
    ) -> Result<usize, CipherError> {
        let mut total_read = 0;

        loop {
            // Try to construct the length prefix in `rx_buffer_encrypted` by moving bytes from
            // `payload`.
            while self.rx_buffer_encrypted.len() < 2 {
                if encrypted_data.is_empty() {
                    return Ok(total_read);
                }

                self.rx_buffer_encrypted.push(encrypted_data[0]);
                encrypted_data = &encrypted_data[1..];
                total_read += 1;
            }

            // Length of the message currently being received.
            let expected_len = usize::from(u16::from_be_bytes(
                <[u8; 2]>::try_from(&self.rx_buffer_encrypted[..2]).unwrap(),
            ));

            // If there isn't enough data available for the full message, copy the partial message
            // to `rx_buffer_encrypted` and return early.
            if self.rx_buffer_encrypted.len() + encrypted_data.len() < expected_len + 2 {
                self.rx_buffer_encrypted.extend_from_slice(encrypted_data);
                total_read += encrypted_data.len();
                return Ok(total_read);
            }

            // Construct the encrypted slice of data to decode.
            let to_decode_slice = if self.rx_buffer_encrypted.len() == 2 {
                // If the entirety of the message is in `payload`, decode it from there without
                // moving data. This is the most common situation.
                debug_assert!(encrypted_data.len() >= expected_len);
                let decode = &encrypted_data[..expected_len];
                encrypted_data = &encrypted_data[expected_len..];
                total_read += expected_len;
                decode
            } else {
                // Otherwise, copy the rest of the message to `rx_buffer_encrypted`.
                let remains = expected_len - (self.rx_buffer_encrypted.len() - 2);
                self.rx_buffer_encrypted
                    .extend_from_slice(&encrypted_data[..remains]);
                encrypted_data = &encrypted_data[remains..];
                total_read += remains;
                &self.rx_buffer_encrypted[2..]
            };

            // Read and decrypt the message.
            // Note that `out` isn't modified if an error is returned.
            let result =
                self.in_cipher_state
                    .read_chachapoly_message_to_vecdeque(&[], to_decode_slice, out);

            // Clear the now-decoded message. This is done even on failure, in order to potentially
            // continue receiving messages if it is desired.
            self.rx_buffer_encrypted.clear();

            result?;
        }
    }

    /// Returns true if the local side has opened the connection.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Start the encryption process.
    ///
    /// Must provide two destination buffers where the encrypted data will be written. The
    /// implementation will try fill the first buffer until it is full, then switch to the second
    /// buffer.
    ///
    /// Call [`Encrypt::unencrypted_write_buffers`] in order to obtain an iterator of sub-slices.
    /// These sub-slices always point within `destination`. Write the unencrypted data to the
    /// buffers returned by this iterator. Once done, call [`Encrypt::encrypt`], providing the
    /// amount of unencrypted data that was written.
    ///
    /// Returns an error if the nonce has overflowed and that no more message can be written.
    // TODO: write to temporary buffer if destination is too small
    pub fn encrypt<'a>(
        &'a mut self,
        destination: (&'a mut [u8], &'a mut [u8]),
    ) -> Result<Encrypt<'a>, EncryptError> {
        Ok(Encrypt {
            out_cipher_state: &mut self.out_cipher_state,
            destination,
        })
    }
}

impl fmt::Debug for Noise {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Noise").finish()
    }
}

#[must_use]
pub struct Encrypt<'a> {
    out_cipher_state: &'a mut CipherState,
    destination: (&'a mut [u8], &'a mut [u8]),
}

impl<'a> Encrypt<'a> {
    /// Returns an iterator to a list of buffers where the unencrypted data must be written.
    ///
    /// All the buffers are subslices of the `destination` parameter that was provided.
    pub fn unencrypted_write_buffers(&'_ mut self) -> impl Iterator<Item = &'_ mut [u8]> + '_ {
        let full_message_len = usize::from(u16::max_value()) + 2;

        let max_messages_before_nonce_overflow =
            usize::try_from(u64::max_value() - self.out_cipher_state.nonce)
                .unwrap_or(usize::max_value())
                .saturating_add(1);

        let dest0_len = self.destination.0.len();
        let dest1_len = self.destination.1.len();

        let dest0 = self
            .destination
            .0
            .chunks_mut(full_message_len)
            .filter_map(move |buffer| {
                let len = buffer.len();
                let len_avail = cmp::min(len.saturating_add(dest1_len), full_message_len);
                // The minium message size is 18, but that would give an empty message.
                if len_avail < 19 {
                    return None;
                }
                Some(&mut buffer[2..cmp::min(len, len_avail - 16)])
            });

        let (dest1_first, dest1_rest) = self.destination.1.split_at_mut(cmp::min(
            dest1_len,
            full_message_len - (dest0_len % full_message_len),
        ));

        let dest1_first = iter::once(dest1_first).filter_map(move |buf| {
            let len = buf.len();
            let start_discard = 2usize.saturating_sub(dest0_len % full_message_len);
            if len < 17 {
                return None;
            }
            Some(&mut buf[start_discard..len - 16])
        });

        let dest1_rest = dest1_rest
            .chunks_mut(full_message_len)
            .filter_map(move |buffer| {
                let len = buffer.len();
                // The minium message size is 18, but that would give an empty message.
                if len < 19 {
                    return None;
                }
                Some(&mut buffer[2..len - 16])
            });

        dest0
            .chain(dest1_first)
            .chain(dest1_rest)
            .take(max_messages_before_nonce_overflow)
    }

    /// Performs the actual encryption. Must be passed the number of bytes that were written to the
    /// buffers returned by [`Encrypt::unencrypted_write_buffers`]. Returns the total number of
    /// bytes written to `destination`.
    ///
    /// # Panic
    ///
    /// Panics if `num_written` is larger than the sum of the buffers that were returned by
    /// [`Encrypt::unencrypted_write_buffers`].
    ///
    pub fn encrypt(mut self, mut num_written: usize) -> usize {
        let mut num_written_encrypted = 0;

        loop {
            if num_written == 0 {
                break;
            }

            // This debug_assert! can trigger if `num_written` is out of bounds. However, passing
            // a correct `num_written` is rather easy, and so it might most likely detect a bug
            // in the Noise code.
            debug_assert!(self.destination.0.len() + self.destination.1.len() >= 19);

            // Number of unencrypted bytes to include in the next message out.
            let next_message_payload_size =
                cmp::min(num_written, usize::from(u16::max_value() - 16));
            num_written -= next_message_payload_size;
            let next_message_size = next_message_payload_size + 16;

            // Write the libp2p length prefix and advance `self.destination`.
            {
                let message_length_prefix = u16::try_from(next_message_size).unwrap().to_be_bytes();
                if !self.destination.0.is_empty() {
                    self.destination.0[0] = message_length_prefix[0];
                    self.destination.0 = &mut self.destination.0[1..];
                } else {
                    self.destination.1[0] = message_length_prefix[0];
                    self.destination.1 = &mut self.destination.1[1..];
                }
                if !self.destination.0.is_empty() {
                    self.destination.0[0] = message_length_prefix[1];
                    self.destination.0 = &mut self.destination.0[1..];
                } else {
                    self.destination.1[0] = message_length_prefix[1];
                    self.destination.1 = &mut self.destination.1[1..];
                }
                num_written_encrypted += 2;
            }

            // `self.destination` now points to slices that contain `next_message_payload_size`
            // bytes of unencrypted data plus 16 bytes reserved for the HMAC, which we can write
            // in place.
            let destination0_message_end = cmp::min(next_message_size, self.destination.0.len());
            let destination1_message_end = next_message_size - destination0_message_end;
            // `write_chachapoly_message_in_place` can only fail if the nonce overflowed, which
            // can happen only if the user has passed a `num_written` too large.
            self.out_cipher_state
                .write_chachapoly_message_in_place(&[], {
                    let message_dest0 = &mut self.destination.0[..destination0_message_end];
                    let message_dest1 = &mut self.destination.1[..destination1_message_end];
                    (message_dest0, message_dest1)
                })
                .unwrap();

            // Update `destination` to be after these bytes.
            self.destination = (
                &mut self.destination.0[destination0_message_end..],
                &mut self.destination.1[destination1_message_end..],
            );
            num_written_encrypted += next_message_size;
        }

        num_written_encrypted
    }
}

/// State of a Noise handshake.
#[derive(Debug)]
pub enum NoiseHandshake {
    /// Handshake still in progress. More data needs to be sent or received.
    InProgress(HandshakeInProgress),
    /// Noise handshake has successfully completed.
    Success {
        /// Object to use to encrypt and decrypt all further communications.
        cipher: Noise,
        /// [`PeerId`] of the remote.
        remote_peer_id: PeerId,
    },
}

/// Handshake still in progress. More data needs to be sent or received.
pub struct HandshakeInProgress(Box<HandshakeInProgressInner>);

/// The actual fields are wrapped within a `Box` because we move the `HandshakeInProgress`
/// frequently.
struct HandshakeInProgressInner {
    /// See [`Config::is_initiator`].
    is_initiator: bool,

    /// Queued data that should be sent out as soon as possible.
    pending_out_data: VecDeque<u8>,

    /// Buffer of data containing data received on the wire. This buffer is only used in rare
    /// situations where Noise handshake messages are split and received in multiple calls
    /// to `read_write`.
    receive_buffer: Vec<u8>,

    /// Progression of the handshake.
    ///
    /// Every time a message is sent out or buffered in
    /// [`HandshakeInProgressInner::pending_out_data`], this is increased by 1.
    num_buffered_or_transmitted_messages: u8,

    /// A single cipher is used during the handshake, as each side takes turn to send data rather
    /// than both at the same time.
    cipher_state: CipherState,

    /// Product of the diffie-hellmans between the various keys that are exchanged. Used to
    /// initialize the ciphers once the handshake is over.
    ///
    /// Corresponds to the `ck` field of the `SymmetricState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-symmetricstate-object>.
    chaining_key: zeroize::Zeroizing<[u8; 32]>,

    /// Hash that maintains the state of the data that we've sent out or received. Used as the
    /// associated data whenever we produce or verify a frame during the handshake.
    ///
    /// Corresponds to the `h` field of the `SymmetricState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-symmetricstate-object>.
    hash: zeroize::Zeroizing<[u8; 32]>,

    /// Local ephemeral key. Generate for this handshake specifically.
    ///
    /// Corresponds to the `e` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    local_ephemeral_private_key: zeroize::Zeroizing<x25519_dalek::StaticSecret>,

    /// Local static key. Corresponds to a [`NoiseKey`].
    ///
    /// Corresponds to the `s` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    local_static_private_key: zeroize::Zeroizing<x25519_dalek::StaticSecret>,

    /// Public key corresponding to [`HandshakeInProgressInner::local_static_private_key`].
    local_static_public_key: x25519_dalek::PublicKey,

    /// Ephemeral public key of the remote. Initially set to `0`s, then set to the correct value
    /// once it's been received.
    ///
    /// Corresponds to the `re` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    remote_ephemeral_public_key: x25519_dalek::PublicKey,

    /// Static public key of the remote. Initially set to `0`s, then set to the correct value
    /// once it's been received.
    ///
    /// Corresponds to the `rs` field of the `HandshakeState` in the Noise specification.
    /// See <https://noiseprotocol.org/noise.html#the-handshakestate-object>.
    remote_static_public_key: x25519_dalek::PublicKey,

    /// Libp2p public key of the remote. Initially `None`, then set to the correct value once
    /// we've received it.
    remote_public_key: Option<PublicKey>,

    /// Libp2p-specific additional handshake message to encrypt then send to the remote.
    libp2p_handshake_message: Vec<u8>,
}

impl NoiseHandshake {
    /// Shortcut function that calls [`HandshakeInProgress::new`] and wraps it into a
    /// [`NoiseHandshake`].
    pub fn new(config: Config) -> Self {
        NoiseHandshake::InProgress(HandshakeInProgress::new(config))
    }
}

impl HandshakeInProgress {
    /// Initializes a new noise handshake state machine.
    pub fn new(config: Config) -> Self {
        // Generate a new ephemeral key for this handshake.
        // TODO: is it zeroize-safe to call `from([u8; 32])`?
        let local_ephemeral_private_key = zeroize::Zeroizing::new(
            x25519_dalek::StaticSecret::from(*config.ephemeral_secret_key),
        );

        // Initialize the hash.
        let mut hash = zeroize::Zeroizing::new([0u8; 32]);

        // InitializeSymmetric(protocol_name).
        {
            const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";
            if PROTOCOL_NAME.len() <= hash.len() {
                hash[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
                hash[PROTOCOL_NAME.len()..].fill(0);
            } else {
                let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
                sha2::Digest::update(&mut hasher, PROTOCOL_NAME);
                sha2::Digest::finalize_into(
                    hasher,
                    sha2::digest::generic_array::GenericArray::from_mut_slice(&mut *hash),
                );
            }
        }
        let chaining_key = hash.clone();

        // Perform MixHash(prologue).
        mix_hash(&mut hash, config.prologue);

        HandshakeInProgress(Box::new(HandshakeInProgressInner {
            cipher_state: CipherState {
                key: zeroize::Zeroizing::new([0; 32]),
                nonce: 0,
                nonce_has_overflowed: false,
            },
            chaining_key,
            hash,
            local_ephemeral_private_key,
            local_static_private_key: config.key.private_key.clone(),
            local_static_public_key: config.key.public_key,
            remote_ephemeral_public_key: x25519_dalek::PublicKey::from([0; 32]),
            remote_static_public_key: x25519_dalek::PublicKey::from([0; 32]),
            remote_public_key: None,
            is_initiator: config.is_initiator,
            pending_out_data: VecDeque::with_capacity(usize::from(u16::max_value()) + 2),
            receive_buffer: Vec::with_capacity(usize::from(u16::max_value()) + 2),
            num_buffered_or_transmitted_messages: 0,
            libp2p_handshake_message: config.key.handshake_message.clone(),
        }))
    }

    /// Feeds data coming from a socket and outputs data to write to the socket.
    ///
    /// On success, returns the new state of the negotiation.
    ///
    /// An error is returned if the protocol is being violated by the remote. When that happens,
    /// the connection should be closed altogether.
    pub fn read_write<TNow>(
        mut self,
        read_write: &mut ReadWrite<'_, TNow>,
    ) -> Result<NoiseHandshake, HandshakeError> {
        loop {
            // Write out the data currently buffered waiting to be written out.
            // If we didn't finish writing our payload, don't do anything more and return now.
            // Don't even read the data from the remote.
            read_write.write_from_vec_deque(&mut self.0.pending_out_data);
            if !self.0.pending_out_data.is_empty() {
                if read_write.outgoing_buffer.is_none() {
                    return Err(HandshakeError::WriteClosed);
                }
                return Ok(NoiseHandshake::InProgress(self));
            }

            // If the handshake has finished, we return successfully here.
            if self.0.num_buffered_or_transmitted_messages == 3 {
                debug_assert!(self.0.pending_out_data.is_empty());
                debug_assert!(self.0.receive_buffer.is_empty());

                // Perform the `Split()`.
                let HkdfOutput {
                    output1: init_to_resp,
                    output2: resp_to_init,
                } = hkdf(&self.0.chaining_key, &[]);
                let (out_key, in_key) = match self.0.is_initiator {
                    true => (init_to_resp, resp_to_init),
                    false => (resp_to_init, init_to_resp),
                };
                return Ok(NoiseHandshake::Success {
                    cipher: Noise {
                        is_initiator: self.0.is_initiator,
                        out_cipher_state: CipherState {
                            key: out_key,
                            nonce: 0,
                            nonce_has_overflowed: false,
                        },
                        in_cipher_state: CipherState {
                            key: in_key,
                            nonce: 0,
                            nonce_has_overflowed: false,
                        },
                        // We reuse `self.receive_buffer` as it already has the correct capacity.
                        rx_buffer_encrypted: mem::take(&mut self.0.receive_buffer),
                    },
                    remote_peer_id: {
                        // The logic of this module guarantees that `remote_peer_id` has
                        // been set during the handshake.
                        self.0
                            .remote_public_key
                            .take()
                            .unwrap_or_else(|| unreachable!())
                            .into_peer_id()
                    },
                });
            }

            // If the handshake is in a phase where we need to send out more data, queue said
            // data to `pending_out_data` and continue.
            match (
                self.0.num_buffered_or_transmitted_messages,
                self.0.is_initiator,
            ) {
                (0, true) => {
                    // Send `e`, the ephemeral local public key.

                    // Process `e`.
                    let local_ephemeral_public_key =
                        x25519_dalek::PublicKey::from(&*self.0.local_ephemeral_private_key);
                    self.0
                        .pending_out_data
                        .extend(local_ephemeral_public_key.as_bytes());
                    mix_hash(&mut self.0.hash, local_ephemeral_public_key.as_bytes());

                    // Call MixHash(&[]) to process the empty payload.
                    mix_hash(&mut self.0.hash, &[]);

                    // Add the libp2p message length.
                    let len = u16::try_from(self.0.pending_out_data.len())
                        .unwrap()
                        .to_be_bytes();
                    self.0.pending_out_data.push_front(len[1]);
                    self.0.pending_out_data.push_front(len[0]);

                    // Message is now fully queued.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (1, false) => {
                    // Send `e, ee, s, es` and the libp2p-specific handshake.

                    // Process `e`.
                    let local_ephemeral_public_key =
                        x25519_dalek::PublicKey::from(&*self.0.local_ephemeral_private_key);
                    self.0
                        .pending_out_data
                        .extend(local_ephemeral_public_key.as_bytes());
                    mix_hash(&mut self.0.hash, local_ephemeral_public_key.as_bytes());

                    // Process `ee`. Call MixKey(DH(e, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process `s`. Append EncryptAndHash(s.public_key) to the buffer.
                    let encrypted_static_public_key = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            self.0.local_static_public_key.as_bytes(),
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_static_public_key.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_static_public_key);

                    // Process `es`. Call MixKey(DH(s, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_static_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Add the libp2p handshake message.
                    let encrypted_libp2p_handshake = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            &self.0.libp2p_handshake_message,
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_libp2p_handshake.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_libp2p_handshake);

                    // Add the libp2p message length.
                    let len = u16::try_from(self.0.pending_out_data.len())
                        .unwrap()
                        .to_be_bytes();
                    self.0.pending_out_data.push_front(len[1]);
                    self.0.pending_out_data.push_front(len[0]);

                    // Message is now fully queued.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (2, true) => {
                    // Send `s, se` and the libp2p-specific handshake.

                    // Process `s`. Append EncryptAndHash(s.public_key) to the buffer.
                    let encrypted_static_public_key = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            self.0.local_static_public_key.as_bytes(),
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_static_public_key.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_static_public_key);

                    // Process `se`. Call MixKey(DH(s, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_static_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Add the libp2p handshake message.
                    let encrypted_libp2p_handshake = self
                        .0
                        .cipher_state
                        .write_chachapoly_message_to_vec(
                            &*self.0.hash,
                            &self.0.libp2p_handshake_message,
                        )
                        .unwrap();
                    self.0
                        .pending_out_data
                        .extend(encrypted_libp2p_handshake.iter().copied());
                    mix_hash(&mut self.0.hash, &encrypted_libp2p_handshake);

                    // Add the libp2p message length.
                    let len = u16::try_from(self.0.pending_out_data.len())
                        .unwrap()
                        .to_be_bytes();
                    self.0.pending_out_data.push_front(len[1]);
                    self.0.pending_out_data.push_front(len[0]);

                    // Message is now fully queued.
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                _ => {}
            }

            // Since we have no more data to write out, and that the handshake isn't finished yet,
            // the next step is necessarily receiving a message sent by the remote.
            // Most of the time, `incoming_buffer` will contain an entire Noise handshake message.
            // However, it is also possible that the Noise message is split into multiple chunks
            // received over time. When that is the case, we have to fall back to `receive_buffer`.
            let available_message: &[u8] = {
                // The remaining of the body requires reading from `read_write`. As such, error if
                // the reading side is closed.
                let Some(incoming_buffer) = read_write.incoming_buffer else {
                    return Err(HandshakeError::ReadClosed);
                };

                // If `self.receive_buffer` is empty and `incoming_data` contains at least a
                // whole message, we can directly extract said message.
                if self.0.receive_buffer.is_empty()
                    && incoming_buffer.len() >= 2
                    && incoming_buffer.len()
                        >= usize::from(u16::from_be_bytes(
                            <[u8; 2]>::try_from(&incoming_buffer[..2]).unwrap(),
                        )) + 2
                {
                    let message_length = usize::from(u16::from_be_bytes(
                        <[u8; 2]>::try_from(&incoming_buffer[..2]).unwrap(),
                    )) + 2;
                    read_write.read_bytes += message_length;
                    read_write.incoming_buffer = Some(&incoming_buffer[message_length..]);
                    &incoming_buffer[2..message_length]
                } else {
                    // The incoming buffer only contains a partial message, or we have started
                    // reading a partial message in a previous iteration.
                    // This is the more uncommon and complicated situation. We need to copy the
                    // data from the incoming buffer to the receive buffer.
                    let mut incoming_buffer_iter = incoming_buffer.iter();
                    while self.0.receive_buffer.len() < 2 {
                        let Some(byte) = incoming_buffer_iter.next() else {
                            read_write.incoming_buffer = Some(incoming_buffer_iter.as_slice());
                            return Ok(NoiseHandshake::InProgress(self));
                        };
                        read_write.read_bytes += 1;
                        self.0.receive_buffer.push(*byte);
                    }

                    let message_length = usize::from(u16::from_be_bytes(
                        <[u8; 2]>::try_from(&self.0.receive_buffer[..2]).unwrap(),
                    )) + 2;
                    while self.0.receive_buffer.len() < message_length {
                        let Some(byte) = incoming_buffer_iter.next() else {
                            read_write.incoming_buffer = Some(incoming_buffer_iter.as_slice());
                            return Ok(NoiseHandshake::InProgress(self));
                        };
                        read_write.read_bytes += 1;
                        self.0.receive_buffer.push(*byte);
                    }

                    // A full message is available in `receive_buffer`.
                    read_write.incoming_buffer = Some(incoming_buffer_iter.as_slice());
                    &self.0.receive_buffer[2..]
                }
            };

            // The rest of the function depends on the current handshake phase.
            match (
                self.0.num_buffered_or_transmitted_messages,
                self.0.is_initiator,
            ) {
                (0, false) => {
                    // Receive `e` message from the remote.
                    self.0.remote_ephemeral_public_key = x25519_dalek::PublicKey::from(*{
                        // Because the remote hasn't authenticated us at this point, sending more
                        // data than what the protocol specifies is forbidden.
                        let mut parser = nom::combinator::all_consuming::<
                            _,
                            _,
                            (&[u8], nom::error::ErrorKind),
                            _,
                        >(nom::combinator::map(
                            nom::bytes::complete::take(32u32),
                            |k| <&[u8; 32]>::try_from(k).unwrap(),
                        ));
                        match parser(available_message) {
                            Ok((_, out)) => out,
                            Err(_) => {
                                return Err(HandshakeError::PayloadDecode(PayloadDecodeError))
                            }
                        }
                    });
                    mix_hash(
                        &mut self.0.hash,
                        self.0.remote_ephemeral_public_key.as_bytes(),
                    );

                    // Call MixHash(&[]) to process the empty payload.
                    mix_hash(&mut self.0.hash, &[]);

                    // Message has been fully processed.
                    self.0.receive_buffer.clear();
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (1, true) => {
                    // Receive `e, ee, s, es` and the libp2p-specific handshake from the remote.
                    let (
                        remote_ephemeral_public_key,
                        remote_static_public_key_encrypted,
                        libp2p_handshake_encrypted,
                    ) = {
                        // Because the remote hasn't fully authenticated us at this point, sending
                        // more data than what the protocol specifies is forbidden.
                        let mut parser = nom::combinator::all_consuming::<
                            _,
                            _,
                            (&[u8], nom::error::ErrorKind),
                            _,
                        >(nom::sequence::tuple((
                            nom::combinator::map(nom::bytes::complete::take(32u32), |k| {
                                <&[u8; 32]>::try_from(k).unwrap()
                            }),
                            nom::combinator::map(nom::bytes::complete::take(48u32), |k| {
                                <&[u8; 48]>::try_from(k).unwrap()
                            }),
                            nom::combinator::rest,
                        )));
                        match parser(available_message) {
                            Ok((_, out)) => out,
                            Err(_) => {
                                return Err(HandshakeError::PayloadDecode(PayloadDecodeError))
                            }
                        }
                    };

                    // Process `e`.
                    self.0.remote_ephemeral_public_key =
                        x25519_dalek::PublicKey::from(*remote_ephemeral_public_key);
                    mix_hash(
                        &mut self.0.hash,
                        self.0.remote_ephemeral_public_key.as_bytes(),
                    );

                    // Process `ee`. Call MixKey(DH(e, re)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .diffie_hellman(&self.0.remote_ephemeral_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process `s`.
                    self.0.remote_static_public_key = x25519_dalek::PublicKey::from(
                        self.0
                            .cipher_state
                            .read_chachapoly_message_to_array(
                                &*self.0.hash,
                                remote_static_public_key_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?,
                    );
                    mix_hash(&mut self.0.hash, remote_static_public_key_encrypted);

                    // Process `es`. Call MixKey(DH(e, rs)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .diffie_hellman(&self.0.remote_static_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process the libp2p-specific handshake.
                    self.0.remote_public_key = Some({
                        let libp2p_handshake_decrypted = self
                            .0
                            .cipher_state
                            .read_chachapoly_message_to_vec(
                                &*self.0.hash,
                                libp2p_handshake_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?;
                        let (libp2p_key, libp2p_signature) = {
                            let mut parser =
                                nom::combinator::all_consuming::<
                                    _,
                                    _,
                                    (&[u8], nom::error::ErrorKind),
                                    _,
                                >(protobuf::message_decode! {
                                    #[required] key = 1 => protobuf::bytes_tag_decode,
                                    #[required] sig = 2 => protobuf::bytes_tag_decode,
                                });
                            match parser(&libp2p_handshake_decrypted) {
                                Ok((_, out)) => (out.key, out.sig),
                                Err(_) => {
                                    return Err(HandshakeError::PayloadDecode(PayloadDecodeError))
                                }
                            }
                        };
                        let remote_public_key = PublicKey::from_protobuf_encoding(libp2p_key)
                            .map_err(|_| HandshakeError::InvalidKey)?;
                        remote_public_key
                            .verify(
                                &[
                                    &b"noise-libp2p-static-key:"[..],
                                    &self.0.remote_static_public_key.as_bytes()[..],
                                ]
                                .concat(),
                                libp2p_signature,
                            )
                            .map_err(HandshakeError::SignatureVerificationFailed)?;
                        remote_public_key
                    });
                    mix_hash(&mut self.0.hash, libp2p_handshake_encrypted);

                    // Message has been fully processed.
                    self.0.receive_buffer.clear();
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                (2, false) => {
                    // Receive `s, se` and the libp2p-specific handshake from the remote.
                    let (remote_static_public_key_encrypted, libp2p_handshake_encrypted) = {
                        // The noise and libp2p-noise specifications clearly define a noise
                        // handshake message and a noise transport message as two different things.
                        // While the remote could in theory send post-handshake
                        // application-specific data in this message, in practice it is forbidden.
                        let mut parser = nom::combinator::all_consuming::<
                            _,
                            _,
                            (&[u8], nom::error::ErrorKind),
                            _,
                        >(nom::sequence::tuple((
                            nom::combinator::map(nom::bytes::complete::take(48u32), |k| {
                                <&[u8; 48]>::try_from(k).unwrap()
                            }),
                            nom::combinator::rest,
                        )));
                        match parser(available_message) {
                            Ok((_, out)) => out,
                            Err(_) => {
                                return Err(HandshakeError::PayloadDecode(PayloadDecodeError))
                            }
                        }
                    };

                    // Process `s`.
                    self.0.remote_static_public_key = x25519_dalek::PublicKey::from(
                        self.0
                            .cipher_state
                            .read_chachapoly_message_to_array(
                                &*self.0.hash,
                                remote_static_public_key_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?,
                    );
                    mix_hash(&mut self.0.hash, remote_static_public_key_encrypted);

                    // Process `se`. Call MixKey(DH(e, rs)).
                    let HkdfOutput {
                        output1: chaining_key_update,
                        output2: key_update,
                    } = hkdf(
                        &self.0.chaining_key,
                        self.0
                            .local_ephemeral_private_key
                            .clone()
                            .diffie_hellman(&self.0.remote_static_public_key)
                            .as_bytes(),
                    );
                    self.0.chaining_key = chaining_key_update;
                    self.0.cipher_state.key = key_update;
                    self.0.cipher_state.nonce = 0;

                    // Process the libp2p-specific handshake.
                    self.0.remote_public_key = Some({
                        let libp2p_handshake_decrypted = self
                            .0
                            .cipher_state
                            .read_chachapoly_message_to_vec(
                                &*self.0.hash,
                                libp2p_handshake_encrypted,
                            )
                            .map_err(HandshakeError::Cipher)?;
                        let (libp2p_key, libp2p_signature) = {
                            let mut parser =
                                nom::combinator::all_consuming::<
                                    _,
                                    _,
                                    (&[u8], nom::error::ErrorKind),
                                    _,
                                >(protobuf::message_decode! {
                                    #[required] key = 1 => protobuf::bytes_tag_decode,
                                    #[required] sig = 2 => protobuf::bytes_tag_decode,
                                });
                            match parser(&libp2p_handshake_decrypted) {
                                Ok((_, out)) => (out.key, out.sig),
                                Err(_) => {
                                    return Err(HandshakeError::PayloadDecode(PayloadDecodeError))
                                }
                            }
                        };
                        let remote_public_key = PublicKey::from_protobuf_encoding(libp2p_key)
                            .map_err(|_| HandshakeError::InvalidKey)?;
                        remote_public_key
                            .verify(
                                &[
                                    &b"noise-libp2p-static-key:"[..],
                                    &self.0.remote_static_public_key.as_bytes()[..],
                                ]
                                .concat(),
                                libp2p_signature,
                            )
                            .map_err(HandshakeError::SignatureVerificationFailed)?;
                        remote_public_key
                    });
                    mix_hash(&mut self.0.hash, libp2p_handshake_encrypted);

                    // Message has been fully processed.
                    self.0.receive_buffer.clear();
                    self.0.num_buffered_or_transmitted_messages += 1;
                    continue;
                }
                _ => {
                    // Any other state was handled earlier in the function.
                    unreachable!()
                }
            }
        }
    }
}

impl fmt::Debug for HandshakeInProgress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HandshakeInProgress").finish()
    }
}

/// Potential error during the noise handshake.
#[derive(Debug, derive_more::Display)]
pub enum HandshakeError {
    /// Reading side of the connection is closed. The handshake can't proceed further.
    ReadClosed,
    /// Writing side of the connection is closed. The handshake can't proceed further.
    WriteClosed,
    /// Error in the decryption state machine.
    #[display(fmt = "Cipher error: {_0}")]
    Cipher(CipherError),
    /// Failed to decode the payload as the libp2p-extension-to-noise payload.
    #[display(fmt = "Failed to decode payload as the libp2p-extension-to-noise payload: {_0}")]
    PayloadDecode(PayloadDecodeError),
    /// Key passed as part of the payload failed to decode into a libp2p public key.
    InvalidKey,
    /// Signature of the noise public key by the libp2p key failed.
    #[display(fmt = "Signature of the noise public key by the libp2p key failed.")]
    SignatureVerificationFailed(SignatureVerifyFailed),
}

/// Error while encrypting data.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "Error while encrypting the Noise payload")]
pub enum EncryptError {
    /// The nonce has overflowed because too many messages have been exchanged. This error is a
    /// normal situation and will happen given sufficient time.
    NonceOverflow,
}

/// Error while decoding data.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "Error while decrypting the Noise payload")]
pub enum CipherError {
    /// Message is too small. This is likely caused by a bug either in this code or in the remote's
    /// code.
    MissingHmac,
    /// Authentication data doesn't match what is expected.
    HmacInvalid,
    /// The nonce has overflowed because too many messages have been exchanged. This error is a
    /// normal situation and will happen given sufficient time.
    NonceOverflow,
}

/// Error while decoding the handshake.
#[derive(Debug, derive_more::Display)]
pub struct PayloadDecodeError;

struct CipherState {
    key: zeroize::Zeroizing<[u8; 32]>,
    nonce: u64,
    nonce_has_overflowed: bool,
}

impl CipherState {
    /// Accepts two `destination` buffers that contain unencrypted data plus 16 unused bytes where
    /// the HMAC will be written. Encrypts the data in place and writes the HMAC.
    ///
    /// Does *not* include the libp2p-specific message length prefix.
    ///
    /// # Panic
    ///
    /// Panics if `destination.0.len() + destination.1.len() < 16`.
    /// Panics if `destination.0.len() + destination.1.len() > 1 << 16`.
    ///
    fn write_chachapoly_message_in_place(
        &'_ mut self,
        associated_data: &[u8],
        destination: (&'_ mut [u8], &'_ mut [u8]),
    ) -> Result<(), EncryptError> {
        debug_assert!(destination.0.len() + destination.1.len() <= usize::from(u16::max_value()));

        if self.nonce_has_overflowed {
            return Err(EncryptError::NonceOverflow);
        }

        let (mut cipher, mut mac) = self.prepare(associated_data);

        // The difficulty in this function implementation is that the cipher and MAC operate on
        // 64 bytes blocks (in other words, the data passed to them must have a size multiple of
        // 64), and unfortunately `destination` might be weirdly aligned.
        // To overcome this, if there's an alignment issue, we copy the data to an intermediary
        // buffer, encrypt it, then copy it back.

        // The function below does a maximum of three passes: one on `destination.0`, one on a
        // copy of the block that overlaps between `destination.0` and `destination.1`, and one
        // on `destination.1`.
        // Most of the time, only one or two passes are necessary as the API user is expected to
        // provide buffers that are aligned over 64 bytes.

        // To start find where the payload ends in `destination.0` and `destination.1` by removing
        // 16 bytes from them.
        let payload0_length = destination.0.len() - 16usize.saturating_sub(destination.1.len());
        let payload1_length = destination.1.len().saturating_sub(16);

        // If `destination.1` is empty, we only need a single pass which processes all the bytes
        // of `destination.0` at once. Otherwise, the first pass ends at a multiple of 64 bytes.
        let first_chunk_end_offset = if destination.1.is_empty() {
            payload0_length
        } else {
            64 * (payload0_length / 64)
        };
        let first_chunk = &mut destination.0[..first_chunk_end_offset];
        chacha20::cipher::StreamCipher::apply_keystream(&mut cipher, first_chunk);
        poly1305::universal_hash::UniversalHash::update_padded(&mut mac, first_chunk);

        // Process bytes of frames that are in the block that overlaps `destination.0`
        // and `destination.1`.
        if first_chunk_end_offset != payload0_length {
            let intermediary_buffer_len = (payload0_length + payload1_length) % 64;
            let mut intermediary_buffer = vec![0; intermediary_buffer_len];
            intermediary_buffer[..payload0_length - first_chunk_end_offset]
                .copy_from_slice(&destination.0[first_chunk_end_offset..payload0_length]);
            intermediary_buffer[payload0_length - first_chunk_end_offset..].copy_from_slice(
                &destination.1
                    [..intermediary_buffer_len - (payload0_length - first_chunk_end_offset)],
            );
            chacha20::cipher::StreamCipher::apply_keystream(&mut cipher, &mut intermediary_buffer);
            poly1305::universal_hash::UniversalHash::update_padded(&mut mac, &intermediary_buffer);
            destination.0[first_chunk_end_offset..payload0_length]
                .copy_from_slice(&intermediary_buffer[..payload0_length - first_chunk_end_offset]);
            destination.1[..intermediary_buffer_len - (payload0_length - first_chunk_end_offset)]
                .copy_from_slice(&intermediary_buffer[payload0_length - first_chunk_end_offset..]);
        }

        // Process bytes aligned on a 64 bytes boundary in `destination.1`.
        let second_chunk_start_offset = cmp::min(
            payload1_length,
            64 - (payload0_length - first_chunk_end_offset),
        );
        let second_chunk = &mut destination.1[second_chunk_start_offset..payload1_length];
        chacha20::cipher::StreamCipher::apply_keystream(&mut cipher, second_chunk);
        poly1305::universal_hash::UniversalHash::update_padded(&mut mac, second_chunk);

        // Update the MAC with the length of the associated data and input data.
        let mut block = poly1305::universal_hash::generic_array::GenericArray::default();
        block[..8].copy_from_slice(&u64::try_from(associated_data.len()).unwrap().to_le_bytes());
        block[8..].copy_from_slice(
            &u64::try_from(payload0_length + payload1_length)
                .unwrap()
                .to_le_bytes(),
        );
        poly1305::universal_hash::UniversalHash::update(&mut mac, &[block]);

        // Write the HMAC.
        let mac_bytes: [u8; 16] = poly1305::universal_hash::UniversalHash::finalize(mac).into();
        let destination1_length = destination.1.len();
        destination.0[payload0_length..]
            .copy_from_slice(&mac_bytes[..16usize.saturating_sub(destination1_length)]);
        destination.1[payload1_length..]
            .copy_from_slice(&mac_bytes[16usize.saturating_sub(destination1_length)..]);

        // Increment the nonce by 1.
        (self.nonce, self.nonce_has_overflowed) = self.nonce.overflowing_add(1);

        Ok(())
    }

    /// Creates a ChaChaPoly1305 frame as a `Vec`.
    ///
    /// Does *not* include the libp2p-specific message length prefix.
    fn write_chachapoly_message_to_vec(
        &'_ mut self,
        associated_data: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, EncryptError> {
        let mut out = vec![0; data.len() + 16];
        out[..data.len()].copy_from_slice(data);
        self.write_chachapoly_message_in_place(associated_data, (&mut out, &mut []))?;
        Ok(out)
    }

    /// Highly-specific function when the message to decode is 32 bytes.
    fn read_chachapoly_message_to_array(
        &'_ mut self,
        associated_data: &[u8],
        message_data: &[u8; 48],
    ) -> Result<[u8; 32], CipherError> {
        let mut out = [0; 32];
        self.read_chachapoly_message_to_slice(associated_data, message_data, &mut out)?;
        Ok(out)
    }

    fn read_chachapoly_message_to_vecdeque(
        &'_ mut self,
        associated_data: &[u8],
        message_data: &[u8],
        destination: &mut VecDeque<u8>,
    ) -> Result<(), CipherError> {
        let original_dest_len = destination.len();
        destination.resize(original_dest_len + message_data.len().saturating_sub(16), 0);

        if destination.as_mut_slices().1.is_empty() {
            match self.read_chachapoly_message_to_slice(
                associated_data,
                message_data,
                &mut destination.as_mut_slices().0[original_dest_len..],
            ) {
                Ok(()) => Ok(()),
                Err(err) => {
                    destination.truncate(original_dest_len);
                    Err(err)
                }
            }
        } else {
            destination.truncate(original_dest_len);
            let intermediary =
                self.read_chachapoly_message_to_vec(associated_data, message_data)?;
            destination.extend(intermediary.into_iter());
            Ok(())
        }
    }

    fn read_chachapoly_message_to_vec(
        &'_ mut self,
        associated_data: &[u8],
        message_data: &[u8],
    ) -> Result<Vec<u8>, CipherError> {
        let mut destination = vec![0; message_data.len().saturating_sub(16)];
        self.read_chachapoly_message_to_slice(associated_data, message_data, &mut destination)?;
        Ok(destination)
    }

    fn read_chachapoly_message_to_slice(
        &'_ mut self,
        associated_data: &[u8],
        message_data: &[u8],
        destination: &mut [u8],
    ) -> Result<(), CipherError> {
        debug_assert_eq!(destination.len(), message_data.len() - 16);

        if self.nonce_has_overflowed {
            return Err(CipherError::NonceOverflow);
        }

        // Messages that are missing a HMAC are invalid.
        if message_data.len() < 16 {
            return Err(CipherError::MissingHmac);
        }

        let (mut cipher, mut mac) = self.prepare(associated_data);

        poly1305::universal_hash::UniversalHash::update_padded(
            &mut mac,
            &message_data[..message_data.len() - 16],
        );

        // Update the MAC with the length of the associated data and input data.
        let mut block = poly1305::universal_hash::generic_array::GenericArray::default();
        block[..8].copy_from_slice(&u64::try_from(associated_data.len()).unwrap().to_le_bytes());
        block[8..].copy_from_slice(
            &u64::try_from(message_data.len() - 16)
                .unwrap()
                .to_le_bytes(),
        );
        poly1305::universal_hash::UniversalHash::update(&mut mac, &[block]);

        // Compare the calculated MAC with the one in the payload.
        // This is done in constant time.
        let obtained_mac_bytes = &message_data[message_data.len() - 16..];
        if poly1305::universal_hash::UniversalHash::verify(
            mac,
            poly1305::universal_hash::generic_array::GenericArray::from_slice(obtained_mac_bytes),
        )
        .is_err()
        {
            return Err(CipherError::HmacInvalid);
        }

        // Only after the MAC has been verified, we copy the data and decrypt it.
        // This function returns an error if the cipher stream is exhausted. Because we recreate
        // a cipher stream every time we encode a message, and a message is maximum 2^16 bytes,
        // this can't happen.
        chacha20::cipher::StreamCipher::apply_keystream_b2b(
            &mut cipher,
            &message_data[..message_data.len() - 16],
            destination,
        )
        .unwrap_or_else(|_| unreachable!());

        // Increment the nonce by 1.
        (self.nonce, self.nonce_has_overflowed) = self.nonce.overflowing_add(1);

        Ok(())
    }

    fn prepare(&self, associated_data: &[u8]) -> (chacha20::ChaCha20, poly1305::Poly1305) {
        let mut cipher = {
            let nonce = {
                let mut out = [0; 12];
                out[4..].copy_from_slice(&self.nonce.to_le_bytes());
                out
            };

            <chacha20::ChaCha20 as chacha20::cipher::KeyIvInit>::new(
                chacha20::cipher::generic_array::GenericArray::from_slice(&self.key[..]),
                chacha20::cipher::generic_array::GenericArray::from_slice(&nonce[..]),
            )
        };

        let mut mac = {
            let mut mac_key = zeroize::Zeroizing::new([0u8; 32]);
            chacha20::cipher::StreamCipher::apply_keystream(&mut cipher, &mut *mac_key);
            chacha20::cipher::StreamCipherSeek::seek(&mut cipher, 64);
            <poly1305::Poly1305 as poly1305::universal_hash::KeyInit>::new(
                poly1305::universal_hash::generic_array::GenericArray::from_slice(&*mac_key),
            )
        };

        poly1305::universal_hash::UniversalHash::update_padded(&mut mac, associated_data);

        (cipher, mac)
    }
}

// Implementation of `MixHash`. See <https://noiseprotocol.org/noise.html#the-symmetricstate-object>.
fn mix_hash(hash: &mut [u8; 32], data: &[u8]) {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, *hash);
    sha2::Digest::update(&mut hasher, data);
    sha2::Digest::finalize_into(
        hasher,
        sha2::digest::generic_array::GenericArray::from_mut_slice(hash),
    );
}

// Implementation of `HKDF`. See <https://noiseprotocol.org/noise.html#hash-functions>.
//
// Contrary to the version in the Noise specification, this always returns 2 outputs. The third
// output version is never used in this module.
fn hkdf(chaining_key: &[u8; 32], input_key_material: &[u8]) -> HkdfOutput {
    fn hmac_hash<'a>(
        key: &[u8; 32],
        data: impl IntoIterator<Item = &'a [u8]>,
    ) -> zeroize::Zeroizing<[u8; 32]> {
        // Formula is: `H(K XOR opad, H(K XOR ipad, text))`
        // See <https://www.ietf.org/rfc/rfc2104.txt>.
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];

        // Algorithm says that we have to zero-extend `key` to 64 bits, then XOR `ipad` and `opad`
        // with that zero-extended `key`. Given that XOR'ing with 0 is a no-op, we don't care with
        // that and just XOR the key without zero-extending it.
        for n in 0..key.len() {
            ipad[n] ^= key[n];
            opad[n] ^= key[n];
        }

        let intermediary_result = {
            let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut hasher, ipad);
            for data in data {
                sha2::Digest::update(&mut hasher, data);
            }
            sha2::Digest::finalize(hasher)
        };

        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, opad);
        sha2::Digest::update(&mut hasher, intermediary_result);

        let mut output = zeroize::Zeroizing::new([0; 32]);
        sha2::Digest::finalize_into(
            hasher,
            sha2::digest::generic_array::GenericArray::from_mut_slice(&mut *output),
        );
        output
    }

    let temp_key = hmac_hash(chaining_key, [input_key_material]);
    let output1 = hmac_hash(&temp_key, [&[0x01][..]]);
    let output2 = hmac_hash(&temp_key, [&*output1, &[0x02][..]]);
    HkdfOutput { output1, output2 }
}

/// Output of the [`hkdf`] function.
struct HkdfOutput {
    output1: zeroize::Zeroizing<[u8; 32]>,
    output2: zeroize::Zeroizing<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::{Config, NoiseHandshake, NoiseKey, ReadWrite};

    #[test]
    fn handshake_basic_works() {
        fn test_with_buffer_sizes(size1: usize, size2: usize) {
            let key1 = NoiseKey::new(&rand::random(), &rand::random());
            let key2 = NoiseKey::new(&rand::random(), &rand::random());

            let mut handshake1 = NoiseHandshake::new(Config {
                key: &key1,
                is_initiator: true,
                prologue: &[],
                ephemeral_secret_key: &rand::random(),
            });
            let mut handshake2 = NoiseHandshake::new(Config {
                key: &key2,
                is_initiator: false,
                prologue: &[],
                ephemeral_secret_key: &rand::random(),
            });

            let mut buf_1_to_2 = Vec::new();
            let mut buf_2_to_1 = Vec::new();

            while !matches!(
                (&handshake1, &handshake2),
                (
                    NoiseHandshake::Success { .. },
                    NoiseHandshake::Success { .. }
                )
            ) {
                match handshake1 {
                    NoiseHandshake::Success { .. } => {}
                    NoiseHandshake::InProgress(nego) => {
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

                            handshake1 = nego.read_write(&mut read_write).unwrap();
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
                                outgoing_buffer: Some((&mut buf_1_to_2, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            handshake1 = nego.read_write(&mut read_write).unwrap();
                            for _ in 0..read_write.read_bytes {
                                buf_2_to_1.remove(0);
                            }
                        }
                    }
                }

                match handshake2 {
                    NoiseHandshake::Success { .. } => {}
                    NoiseHandshake::InProgress(nego) => {
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

                            handshake2 = nego.read_write(&mut read_write).unwrap();
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
                                outgoing_buffer: Some((&mut buf_2_to_1, &mut [])),
                                read_bytes: 0,
                                written_bytes: 0,
                                wake_up_after: None,
                            };
                            handshake2 = nego.read_write(&mut read_write).unwrap();
                            for _ in 0..read_write.read_bytes {
                                buf_1_to_2.remove(0);
                            }
                        }
                    }
                }
            }
        }

        test_with_buffer_sizes(256, 256);
        test_with_buffer_sizes(1, 1);
        test_with_buffer_sizes(1, 2048);
        test_with_buffer_sizes(2048, 1);
    }
}
