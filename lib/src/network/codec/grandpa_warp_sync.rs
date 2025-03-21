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

//! The GrandPa warp sync protocol is a request-response protocol.
//!
//! The request's body consists in a block hash.
//!
//! The response's body consists in a sequence of so-called *fragments*. Each fragment consists in
//! a block header and a GrandPa justification corresponding to this header. The justification
//! must be verified.
//!
//! The fragments only contain blocks higher than the hash of the block passed in the request.
//!
//! By doing a GrandPa warp sync request, a node is capable of quickly obtaining a proof that a
//! certain recent block has been finalized by authorities.
//!
//! A proof has to be minimum. All the headers in all fragments, except for the last, have to
//! contain a change in the set of GrandPa authorities.
//!
//! The responding node has the possibility to cut proofs that are above a certain threshold. When
//! it does so, [`GrandpaWarpSyncResponse::is_finished`] should be set to `false`, so that the
//! requester can start additional warp sync requests afterwards.

use crate::{finality, header};

use alloc::vec::Vec;

// TODO: all the constraints explained here should be checked when decoding the message

/// Response to a GrandPa warp sync request.
#[derive(Debug)]
pub struct GrandpaWarpSyncResponse<'a> {
    /// List of fragments that consist in the proof.
    ///
    /// The fragments must be ordered by ascending block height.
    pub fragments: Vec<GrandpaWarpSyncResponseFragment<'a>>,

    /// If `true`, the last fragment corresponds to the highest finalized block known to the
    /// responder. If `false`, the requested is encouraged to start a follow-up GrandPa warp sync
    /// request starting at the last block in the fragments.
    pub is_finished: bool,
}

/// Response to a GrandPa warp sync request.
#[derive(Debug)]
pub struct GrandpaWarpSyncResponseFragment<'a> {
    /// Header of a block in the chain.
    ///
    /// Must always contain a change in the list of authorities, except for the last fragment
    /// if [`GrandpaWarpSyncResponse::is_finished`] is `true`.
    pub scale_encoded_header: &'a [u8],

    /// Justification that proves the finality of
    /// [`GrandpaWarpSyncResponseFragment::scale_encoded_header`].
    pub scale_encoded_justification: &'a [u8],
}

/// Error potentially returned by [`decode_grandpa_warp_sync_response`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("Failed to decode response")]
pub struct DecodeGrandpaWarpSyncResponseError;

/// Decodes a SCALE-encoded GrandPa warp sync response.
pub fn decode_grandpa_warp_sync_response(
    encoded: &[u8],
    block_number_bytes: usize,
) -> Result<GrandpaWarpSyncResponse, DecodeGrandpaWarpSyncResponseError> {
    nom::Parser::parse(
        &mut nom::combinator::all_consuming::<_, (&[u8], nom::error::ErrorKind), _>(
            nom::combinator::map(
                (
                    decode_fragments(block_number_bytes),
                    nom::number::streaming::le_u8,
                ),
                |(fragments, is_finished)| GrandpaWarpSyncResponse {
                    fragments,
                    is_finished: is_finished != 0,
                },
            ),
        ),
        encoded,
    )
    .map(|(_, parse_result)| parse_result)
    .map_err(|_| DecodeGrandpaWarpSyncResponseError)
}

fn decode_fragments<'a, E: nom::error::ParseError<&'a [u8]>>(
    block_number_bytes: usize,
) -> impl nom::Parser<&'a [u8], Output = Vec<GrandpaWarpSyncResponseFragment<'a>>, Error = E> {
    nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
        nom::multi::many_m_n(num_elems, num_elems, decode_fragment(block_number_bytes))
    })
}

fn decode_fragment<'a, E: nom::error::ParseError<&'a [u8]>>(
    block_number_bytes: usize,
) -> impl nom::Parser<&'a [u8], Output = GrandpaWarpSyncResponseFragment<'a>, Error = E> {
    nom::combinator::map(
        (
            nom::combinator::recognize(move |s| {
                header::decode_partial(s, block_number_bytes)
                    .map(|(a, b)| (b, a))
                    .map_err(|_| {
                        nom::Err::Failure(nom::error::make_error(s, nom::error::ErrorKind::Verify))
                    })
            }),
            nom::combinator::recognize(move |s| {
                finality::decode::decode_partial_grandpa_justification(s, block_number_bytes)
                    .map(|(a, b)| (b, a))
                    .map_err(|_| {
                        nom::Err::Failure(nom::error::make_error(s, nom::error::ErrorKind::Verify))
                    })
            }),
        ),
        move |(scale_encoded_header, scale_encoded_justification)| {
            GrandpaWarpSyncResponseFragment {
                scale_encoded_header,
                scale_encoded_justification,
            }
        },
    )
}
