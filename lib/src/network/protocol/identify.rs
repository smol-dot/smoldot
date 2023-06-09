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

//! The identify protocol is a request-response protocol.
//!
//! The request's body is empty. Contrary to other request-response protocols, it doesn't even
//! contain a message length. As soon as the protocol has been negotiated, the other side should
//! send back the response.
//!
//! The response's body consists in various useful general-purpose information about the node.
//! See [`IdentifyResponse`] for details.
//!
//! The two most important fields are [`IdentifyResponse::listen_addrs`] and
//! [`IdentifyResponse::observed_addr`]. They are necessary in order for nodes to discover their
//! public address, and in order to insert peers in the Kademlia k-buckets.
//!
//! See also [the official specification](https://github.com/libp2p/specs/tree/69e57d59dc5d59d3979d79842b577ec2c483f7fa/identify).

use crate::{
    libp2p::peer_id::{FromProtobufEncodingError, PublicKey},
    util::protobuf,
};

use alloc::vec::{self, Vec};

/// Description of a response to an identify request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyResponse<'a, TLaIter, TProtoIter> {
    /// Name of the set of protocols supposed by the node.
    pub protocol_version: &'a str,

    /// Name and version of the software that responds. Similar to `User-Agent` in the HTTP
    /// protocol. Used for debugging purposes.
    pub agent_version: &'a str,

    /// Ed25519 public key of the local node.
    pub ed25519_public_key: [u8; 32],

    /// List of multiaddresses the local node is listening on. This should include first and
    /// foremost addresses that are publicly-reachable.
    ///
    /// > **Note**: Each item should be decoded into a multiaddr, but keep in mind that it might
    /// >           not be valid.
    pub listen_addrs: TLaIter,

    /// Multiaddress of the sender of the identify request, as seen from the receiver.
    ///
    /// > **Note**: This should be decoded into a multiaddr, but keep in mind that it might not
    /// >           be valid.
    pub observed_addr: &'a [u8],

    /// Names of the protocols supported by the local node.
    pub protocols: TProtoIter,
}

// See https://github.com/libp2p/specs/tree/master/identify#the-identify-message for the protobuf
// message format.

/// Builds the bytes corresponding to a block request.
pub fn build_identify_response<'a>(
    config: IdentifyResponse<
        'a,
        impl Iterator<Item = &'a [u8]> + 'a,
        impl Iterator<Item = &'a str> + 'a,
    >,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
    protobuf::string_tag_encode(5, config.protocol_version)
        .map(either::Left)
        .map(either::Left)
        .map(either::Left)
        .chain(
            protobuf::string_tag_encode(6, config.agent_version)
                .map(either::Right)
                .map(either::Left)
                .map(either::Left),
        )
        .chain(
            protobuf::bytes_tag_encode(
                1,
                PublicKey::Ed25519(config.ed25519_public_key).to_protobuf_encoding(),
            )
            .map(either::Left)
            .map(either::Right)
            .map(either::Left),
        )
        .chain(
            config
                .listen_addrs
                .flat_map(|addr| protobuf::bytes_tag_encode(2, addr))
                .map(either::Right)
                .map(either::Right)
                .map(either::Left),
        )
        .chain(
            protobuf::bytes_tag_encode(4, config.observed_addr)
                .map(either::Left)
                .map(either::Right),
        )
        .chain(
            config
                .protocols
                .flat_map(|p| protobuf::string_tag_encode(3, p))
                .map(either::Right)
                .map(either::Right),
        )
}

/// Decodes a response to an identify request.
pub fn decode_identify_response(
    response_bytes: &'_ [u8],
) -> Result<
    IdentifyResponse<'_, vec::IntoIter<&'_ [u8]>, vec::IntoIter<&'_ str>>,
    DecodeIdentifyResponseError,
> {
    let mut parser = nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(
        nom::combinator::complete(protobuf::message_decode! {
            #[optional] protocol_version = 5 => protobuf::string_tag_decode,
            #[optional] agent_version = 6 => protobuf::string_tag_decode,
            #[optional] ed25519_public_key = 1 => protobuf::bytes_tag_decode,
            #[repeated(max = 1024)] listen_addrs = 2 => protobuf::bytes_tag_decode,
            #[optional] observed_addr = 4 => protobuf::bytes_tag_decode,
            #[repeated(max = 1024)] protocols = 3 => protobuf::string_tag_decode,
        }),
    );

    let decoded = match nom::Finish::finish(parser(response_bytes)) {
        Ok((_, out)) => out,
        Err(_) => return Err(DecodeIdentifyResponseError::ProtobufDecode),
    };

    Ok(IdentifyResponse {
        agent_version: decoded.agent_version.unwrap_or_default(),
        protocol_version: decoded.protocol_version.unwrap_or_default(),
        ed25519_public_key: match PublicKey::from_protobuf_encoding(
            decoded.ed25519_public_key.unwrap_or_default(),
        )
        .map_err(DecodeIdentifyResponseError::InvalidPublicKey)?
        {
            PublicKey::Ed25519(key) => key,
        },
        listen_addrs: decoded.listen_addrs.into_iter(),
        observed_addr: decoded.observed_addr.unwrap_or_default(),
        protocols: decoded.protocols.into_iter(),
    })
}

/// Error potentially returned by [`decode_identify_response`].
#[derive(Debug, derive_more::Display)]
pub enum DecodeIdentifyResponseError {
    /// Error while decoding the Protobuf encoding.
    ProtobufDecode,
    /// Couldn't decode the public key of the remote.
    #[display(fmt = "Failed to decode remote public key: {_0}")]
    InvalidPublicKey(FromProtobufEncodingError),
}
