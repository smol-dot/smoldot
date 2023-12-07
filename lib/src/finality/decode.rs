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

use crate::header;

use alloc::vec::Vec;
use core::fmt;

/// Attempt to decode the given SCALE-encoded justification.
pub fn decode_grandpa_justification(
    scale_encoded: &[u8],
    block_number_bytes: usize,
) -> Result<GrandpaJustificationRef, JustificationDecodeError> {
    match nom::combinator::complete(nom::combinator::all_consuming(grandpa_justification(
        block_number_bytes,
    )))(scale_encoded)
    {
        Ok((_, justification)) => Ok(justification),
        Err(nom::Err::Error(err) | nom::Err::Failure(err)) => {
            Err(JustificationDecodeError(err.code))
        }
        Err(_) => unreachable!(),
    }
}

/// Attempt to decode the given SCALE-encoded justification.
///
/// Contrary to [`decode_grandpa_justification`], doesn't return an error if the slice is too long
/// but returns the remainder.
pub fn decode_partial_grandpa_justification(
    scale_encoded: &[u8],
    block_number_bytes: usize,
) -> Result<(GrandpaJustificationRef, &[u8]), JustificationDecodeError> {
    match nom::combinator::complete(grandpa_justification(block_number_bytes))(scale_encoded) {
        Ok((remainder, justification)) => Ok((justification, remainder)),
        Err(nom::Err::Error(err) | nom::Err::Failure(err)) => {
            Err(JustificationDecodeError(err.code))
        }
        Err(_) => unreachable!(),
    }
}

/// Decoded justification.
// TODO: document and explain
#[derive(Debug)]
pub struct GrandpaJustificationRef<'a> {
    pub round: u64,
    pub target_hash: &'a [u8; 32],
    pub target_number: u64,
    pub precommits: PrecommitsRef<'a>,
    pub votes_ancestries: VotesAncestriesIter<'a>,
}

/// Decoded justification.
// TODO: document and explain
#[derive(Debug)]
pub struct GrandpaJustification {
    pub round: u64,
    pub target_hash: [u8; 32],
    pub target_number: u64,
    pub precommits: Vec<Precommit>,
    // TODO: pub votes_ancestries: Vec<Header>,
}

/// Attempt to decode the given SCALE-encoded Grandpa commit.
pub fn decode_grandpa_commit(
    scale_encoded: &[u8],
    block_number_bytes: usize,
) -> Result<CommitMessageRef, CommitDecodeError> {
    match nom::combinator::all_consuming(commit_message(block_number_bytes))(scale_encoded) {
        Ok((_, commit)) => Ok(commit),
        Err(err) => Err(CommitDecodeError(err)),
    }
}

/// Attempt to decode the given SCALE-encoded commit.
///
/// Contrary to [`decode_grandpa_commit`], doesn't return an error if the slice is too long, but
/// returns the remainder.
pub fn decode_partial_grandpa_commit(
    scale_encoded: &[u8],
    block_number_bytes: usize,
) -> Result<(CommitMessageRef, &[u8]), CommitDecodeError> {
    match commit_message(block_number_bytes)(scale_encoded) {
        Ok((remainder, commit)) => Ok((commit, remainder)),
        Err(err) => Err(CommitDecodeError(err)),
    }
}

/// Error potentially returned by [`decode_grandpa_commit`].
#[derive(Debug, derive_more::Display)]
pub struct CommitDecodeError<'a>(nom::Err<nom::error::Error<&'a [u8]>>);

// TODO: document and explain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMessageRef<'a> {
    pub round_number: u64,
    pub set_id: u64,
    pub target_hash: &'a [u8; 32],
    pub target_number: u64,
    // TODO: don't use Vec
    pub precommits: Vec<UnsignedPrecommitRef<'a>>,

    /// List of Ed25519 signatures and public keys.
    // TODO: refactor
    // TODO: don't use Vec
    pub auth_data: Vec<(&'a [u8; 64], &'a [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedPrecommitRef<'a> {
    pub target_hash: &'a [u8; 32],
    pub target_number: u64,
}

const PRECOMMIT_ENCODED_LEN: usize = 32 + 4 + 64 + 32;

impl<'a> From<&'a GrandpaJustification> for GrandpaJustificationRef<'a> {
    fn from(j: &'a GrandpaJustification) -> GrandpaJustificationRef<'a> {
        GrandpaJustificationRef {
            round: j.round,
            target_hash: &j.target_hash,
            target_number: j.target_number,
            precommits: PrecommitsRef {
                inner: PrecommitsRefInner::Decoded(&j.precommits),
            },
            // TODO:
            votes_ancestries: VotesAncestriesIter {
                slice: &[],
                num: 0,
                block_number_bytes: 4,
            },
        }
    }
}

impl<'a> From<GrandpaJustificationRef<'a>> for GrandpaJustification {
    fn from(j: GrandpaJustificationRef<'a>) -> GrandpaJustification {
        GrandpaJustification {
            round: j.round,
            target_hash: *j.target_hash,
            target_number: j.target_number,
            precommits: j.precommits.iter().map(Into::into).collect(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct PrecommitsRef<'a> {
    inner: PrecommitsRefInner<'a>,
}

impl<'a> fmt::Debug for PrecommitsRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[derive(Copy, Clone)]
enum PrecommitsRefInner<'a> {
    Undecoded {
        data: &'a [u8],
        block_number_bytes: usize,
    },
    Decoded(&'a [Precommit]),
}

impl<'a> PrecommitsRef<'a> {
    pub fn iter(&self) -> impl ExactSizeIterator<Item = PrecommitRef<'a>> + 'a {
        match self.inner {
            PrecommitsRefInner::Undecoded {
                data,
                block_number_bytes,
            } => {
                debug_assert_eq!(data.len() % PRECOMMIT_ENCODED_LEN, 0);
                PrecommitsRefIter {
                    inner: PrecommitsRefIterInner::Undecoded {
                        block_number_bytes,
                        remaining_len: data.len() / PRECOMMIT_ENCODED_LEN,
                        pointer: data,
                    },
                }
            }
            PrecommitsRefInner::Decoded(slice) => PrecommitsRefIter {
                inner: PrecommitsRefIterInner::Decoded(slice.iter()),
            },
        }
    }
}

pub struct PrecommitsRefIter<'a> {
    inner: PrecommitsRefIterInner<'a>,
}

enum PrecommitsRefIterInner<'a> {
    Decoded(core::slice::Iter<'a, Precommit>),
    Undecoded {
        block_number_bytes: usize,
        remaining_len: usize,
        pointer: &'a [u8],
    },
}

impl<'a> Iterator for PrecommitsRefIter<'a> {
    type Item = PrecommitRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            PrecommitsRefIterInner::Decoded(iter) => iter.next().map(Into::into),
            PrecommitsRefIterInner::Undecoded {
                block_number_bytes,
                pointer,
                remaining_len,
            } => {
                if *remaining_len == 0 {
                    return None;
                }

                let (new_pointer, precommit) = precommit(*block_number_bytes)(pointer).unwrap();
                *pointer = new_pointer;
                *remaining_len -= 1;

                Some(precommit)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            PrecommitsRefIterInner::Decoded(iter) => iter.size_hint(),
            PrecommitsRefIterInner::Undecoded { remaining_len, .. } => {
                (*remaining_len, Some(*remaining_len))
            }
        }
    }
}

impl<'a> ExactSizeIterator for PrecommitsRefIter<'a> {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecommitRef<'a> {
    /// Hash of the block concerned by the pre-commit.
    pub target_hash: &'a [u8; 32],
    /// Height of the block concerned by the pre-commit.
    pub target_number: u64,

    /// Ed25519 signature made with [`PrecommitRef::authority_public_key`].
    // TODO: document what is being signed
    pub signature: &'a [u8; 64],

    /// Authority that signed the precommit. Must be part of the authority set for the
    /// justification to be valid.
    pub authority_public_key: &'a [u8; 32],
}

impl<'a> PrecommitRef<'a> {
    /// Decodes a SCALE-encoded precommit.
    ///
    /// Returns the rest of the data alongside with the decoded struct.
    pub fn decode_partial(
        scale_encoded: &[u8],
        block_number_bytes: usize,
    ) -> Result<(PrecommitRef, &[u8]), JustificationDecodeError> {
        match precommit(block_number_bytes)(scale_encoded) {
            Ok((remainder, precommit)) => Ok((precommit, remainder)),
            Err(nom::Err::Error(err) | nom::Err::Failure(err)) => {
                Err(JustificationDecodeError(err.code))
            }
            Err(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Precommit {
    /// Hash of the block concerned by the pre-commit.
    pub target_hash: [u8; 32],
    /// Height of the block concerned by the pre-commit.
    pub target_number: u64,

    /// Ed25519 signature made with [`PrecommitRef::authority_public_key`].
    // TODO: document what is being signed
    pub signature: [u8; 64],

    /// Authority that signed the precommit. Must be part of the authority set for the
    /// justification to be valid.
    pub authority_public_key: [u8; 32],
}

impl<'a> From<&'a Precommit> for PrecommitRef<'a> {
    fn from(pc: &'a Precommit) -> PrecommitRef<'a> {
        PrecommitRef {
            target_hash: &pc.target_hash,
            target_number: pc.target_number,
            signature: &pc.signature,
            authority_public_key: &pc.authority_public_key,
        }
    }
}

impl<'a> From<PrecommitRef<'a>> for Precommit {
    fn from(pc: PrecommitRef<'a>) -> Precommit {
        Precommit {
            target_hash: *pc.target_hash,
            target_number: pc.target_number,
            signature: *pc.signature,
            authority_public_key: *pc.authority_public_key,
        }
    }
}

/// Iterator towards the headers of the vote ancestries.
#[derive(Debug, Clone)]
pub struct VotesAncestriesIter<'a> {
    /// Encoded headers.
    slice: &'a [u8],
    /// Number of headers items remaining.
    num: usize,
    /// Number of bytes when encoding the block number.
    block_number_bytes: usize,
}

impl<'a> Iterator for VotesAncestriesIter<'a> {
    type Item = header::HeaderRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.num == 0 {
            return None;
        }

        // Validity is guaranteed when the `VotesAncestriesIter` is constructed.
        let (item, new_slice) =
            header::decode_partial(self.slice, self.block_number_bytes).unwrap();
        self.slice = new_slice;
        self.num -= 1;

        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.num, Some(self.num))
    }
}

impl<'a> ExactSizeIterator for VotesAncestriesIter<'a> {}

/// Potential error when decoding a Grandpa justification.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "Justification parsing error: {_0:?}")]
pub struct JustificationDecodeError(nom::error::ErrorKind);

/// `Nom` combinator that parses a justification.
fn grandpa_justification<'a>(
    block_number_bytes: usize,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&[u8], GrandpaJustificationRef> {
    nom::error::context(
        "grandpa_justification",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::streaming::le_u64,
                nom::bytes::streaming::take(32u32),
                crate::util::nom_varsize_number_decode_u64(block_number_bytes),
                precommits(block_number_bytes),
                votes_ancestries(block_number_bytes),
            )),
            |(round, target_hash, target_number, precommits, votes_ancestries)| {
                GrandpaJustificationRef {
                    round,
                    target_hash: TryFrom::try_from(target_hash).unwrap(),
                    target_number,
                    precommits,
                    votes_ancestries,
                }
            },
        ),
    )
}

/// `Nom` combinator that parses a list of precommits.
fn precommits<'a>(
    block_number_bytes: usize,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&[u8], PrecommitsRef> {
    nom::combinator::map(
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
            nom::combinator::recognize(nom::multi::fold_many_m_n(
                num_elems,
                num_elems,
                precommit(block_number_bytes),
                || {},
                |(), _| (),
            ))
        }),
        move |data| PrecommitsRef {
            inner: PrecommitsRefInner::Undecoded {
                data,
                block_number_bytes,
            },
        },
    )
}

/// `Nom` combinator that parses a single precommit.
fn precommit<'a>(
    block_number_bytes: usize,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&[u8], PrecommitRef> {
    nom::error::context(
        "precommit",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::bytes::streaming::take(32u32),
                crate::util::nom_varsize_number_decode_u64(block_number_bytes),
                nom::bytes::streaming::take(64u32),
                nom::bytes::streaming::take(32u32),
            )),
            |(target_hash, target_number, signature, authority_public_key)| PrecommitRef {
                target_hash: TryFrom::try_from(target_hash).unwrap(),
                target_number,
                signature: TryFrom::try_from(signature).unwrap(),
                authority_public_key: TryFrom::try_from(authority_public_key).unwrap(),
            },
        ),
    )
}

/// `Nom` combinator that parses a list of headers.
fn votes_ancestries<'a>(
    block_number_bytes: usize,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&[u8], VotesAncestriesIter> {
    nom::error::context(
        "votes ancestries",
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
            nom::combinator::map(
                nom::combinator::recognize(nom::multi::fold_many_m_n(
                    num_elems,
                    num_elems,
                    move |s| {
                        header::decode_partial(s, block_number_bytes)
                            .map(|(a, b)| (b, a))
                            .map_err(|_| {
                                nom::Err::Failure(nom::error::make_error(
                                    s,
                                    nom::error::ErrorKind::Verify,
                                ))
                            })
                    },
                    || {},
                    |(), _| (),
                )),
                move |slice| VotesAncestriesIter {
                    slice,
                    num: num_elems,
                    block_number_bytes,
                },
            )
        }),
    )
}

fn commit_message<'a>(
    block_number_bytes: usize,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&[u8], CommitMessageRef> {
    nom::error::context(
        "commit_message",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::streaming::le_u64,
                nom::number::streaming::le_u64,
                nom::bytes::streaming::take(32u32),
                crate::util::nom_varsize_number_decode_u64(block_number_bytes),
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
                    nom::multi::many_m_n(
                        num_elems,
                        num_elems,
                        unsigned_precommit(block_number_bytes),
                    )
                }),
                nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                    nom::multi::many_m_n(
                        num_elems,
                        num_elems,
                        nom::combinator::map(
                            nom::sequence::tuple((
                                nom::bytes::streaming::take(64u32),
                                nom::bytes::streaming::take(32u32),
                            )),
                            |(sig, pubkey)| {
                                (
                                    <&[u8; 64]>::try_from(sig).unwrap(),
                                    <&[u8; 32]>::try_from(pubkey).unwrap(),
                                )
                            },
                        ),
                    )
                }),
            )),
            |(round_number, set_id, target_hash, target_number, precommits, auth_data)| {
                CommitMessageRef {
                    round_number,
                    set_id,
                    target_hash: <&[u8; 32]>::try_from(target_hash).unwrap(),
                    target_number,
                    precommits,
                    auth_data,
                }
            },
        ),
    )
}

fn unsigned_precommit<'a>(
    block_number_bytes: usize,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&[u8], UnsignedPrecommitRef> {
    nom::error::context(
        "unsigned_precommit",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::bytes::streaming::take(32u32),
                crate::util::nom_varsize_number_decode_u64(block_number_bytes),
            )),
            |(target_hash, target_number)| UnsignedPrecommitRef {
                target_hash: <&[u8; 32]>::try_from(target_hash).unwrap(),
                target_number,
            },
        ),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn basic_decode_justification() {
        super::decode_grandpa_justification(
            &[
                7, 181, 6, 0, 0, 0, 0, 0, 41, 241, 171, 236, 144, 172, 25, 157, 240, 109, 238, 59,
                160, 115, 76, 8, 195, 253, 109, 240, 108, 170, 63, 120, 149, 47, 143, 149, 22, 64,
                88, 210, 0, 158, 4, 0, 20, 41, 241, 171, 236, 144, 172, 25, 157, 240, 109, 238, 59,
                160, 115, 76, 8, 195, 253, 109, 240, 108, 170, 63, 120, 149, 47, 143, 149, 22, 64,
                88, 210, 0, 158, 4, 0, 13, 247, 129, 120, 204, 170, 120, 173, 41, 241, 213, 234,
                121, 111, 20, 38, 193, 94, 99, 139, 57, 30, 71, 209, 236, 222, 165, 123, 70, 139,
                71, 65, 36, 142, 39, 13, 94, 240, 44, 174, 150, 85, 149, 223, 166, 82, 210, 103,
                40, 129, 102, 26, 212, 116, 231, 209, 163, 107, 49, 82, 229, 197, 82, 8, 28, 21,
                28, 17, 203, 114, 51, 77, 38, 215, 7, 105, 227, 175, 123, 191, 243, 128, 26, 78,
                45, 202, 43, 9, 183, 204, 224, 175, 141, 216, 19, 7, 41, 241, 171, 236, 144, 172,
                25, 157, 240, 109, 238, 59, 160, 115, 76, 8, 195, 253, 109, 240, 108, 170, 63, 120,
                149, 47, 143, 149, 22, 64, 88, 210, 0, 158, 4, 0, 62, 37, 145, 44, 21, 192, 120,
                229, 236, 113, 122, 56, 193, 247, 45, 210, 184, 12, 62, 220, 253, 147, 70, 133, 85,
                18, 90, 167, 201, 118, 23, 107, 184, 187, 3, 104, 170, 132, 17, 18, 89, 77, 156,
                145, 242, 8, 185, 88, 74, 87, 21, 52, 247, 101, 57, 154, 163, 5, 130, 20, 15, 230,
                8, 3, 104, 13, 39, 130, 19, 249, 8, 101, 138, 73, 161, 2, 90, 127, 70, 108, 25,
                126, 143, 182, 250, 187, 94, 98, 34, 10, 123, 215, 95, 134, 12, 171, 41, 241, 171,
                236, 144, 172, 25, 157, 240, 109, 238, 59, 160, 115, 76, 8, 195, 253, 109, 240,
                108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210, 0, 158, 4, 0, 125, 172, 79,
                71, 1, 38, 137, 128, 232, 95, 70, 104, 217, 95, 7, 58, 28, 114, 182, 216, 171, 56,
                231, 218, 199, 244, 220, 122, 6, 225, 5, 175, 172, 47, 198, 61, 84, 42, 75, 66, 62,
                90, 243, 18, 58, 36, 108, 235, 132, 103, 136, 38, 164, 164, 237, 164, 41, 225, 152,
                157, 146, 237, 24, 11, 142, 89, 54, 135, 0, 234, 137, 226, 191, 137, 34, 204, 158,
                75, 134, 214, 101, 29, 28, 104, 154, 13, 87, 129, 63, 151, 104, 219, 170, 222, 207,
                113, 41, 241, 171, 236, 144, 172, 25, 157, 240, 109, 238, 59, 160, 115, 76, 8, 195,
                253, 109, 240, 108, 170, 63, 120, 149, 47, 143, 149, 22, 64, 88, 210, 0, 158, 4, 0,
                68, 192, 211, 142, 239, 33, 55, 222, 165, 127, 203, 155, 217, 170, 61, 95, 206, 74,
                74, 19, 123, 60, 67, 142, 80, 18, 175, 40, 136, 156, 151, 224, 191, 157, 91, 187,
                39, 185, 249, 212, 158, 73, 197, 90, 54, 222, 13, 76, 181, 134, 69, 3, 165, 248,
                94, 196, 68, 186, 80, 218, 87, 162, 17, 11, 222, 166, 244, 167, 39, 211, 178, 57,
                146, 117, 214, 238, 136, 23, 136, 31, 16, 89, 116, 113, 220, 29, 39, 241, 68, 41,
                90, 214, 251, 147, 60, 122, 41, 241, 171, 236, 144, 172, 25, 157, 240, 109, 238,
                59, 160, 115, 76, 8, 195, 253, 109, 240, 108, 170, 63, 120, 149, 47, 143, 149, 22,
                64, 88, 210, 0, 158, 4, 0, 58, 187, 123, 135, 2, 157, 81, 197, 40, 200, 218, 52,
                253, 193, 119, 104, 190, 246, 221, 225, 175, 195, 177, 218, 209, 175, 83, 119, 98,
                175, 196, 48, 67, 76, 59, 223, 13, 202, 48, 1, 10, 99, 200, 201, 123, 29, 89, 131,
                120, 70, 162, 235, 11, 191, 96, 57, 83, 51, 217, 199, 35, 50, 174, 2, 247, 45, 175,
                46, 86, 14, 79, 15, 34, 251, 92, 187, 4, 173, 29, 127, 238, 133, 10, 171, 35, 143,
                208, 20, 193, 120, 118, 158, 126, 58, 155, 132, 0,
            ],
            4,
        )
        .unwrap();
    }

    #[test]
    fn basic_decode_commit() {
        let actual = super::decode_grandpa_commit(
            &[
                85, 14, 0, 0, 0, 0, 0, 0, 162, 13, 0, 0, 0, 0, 0, 0, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 28, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 182, 68, 115, 35, 15, 201,
                152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253, 4, 180, 158, 70, 161, 84,
                76, 118, 151, 68, 101, 104, 187, 82, 49, 231, 77, 0, 28, 189, 185, 216, 33, 163,
                12, 201, 104, 162, 255, 11, 241, 156, 90, 244, 205, 251, 44, 45, 139, 129, 117,
                178, 85, 129, 78, 58, 255, 76, 232, 199, 85, 236, 30, 227, 87, 50, 34, 22, 27, 241,
                6, 33, 137, 55, 5, 190, 36, 122, 61, 112, 51, 99, 34, 119, 46, 185, 156, 188, 133,
                140, 103, 33, 10, 45, 154, 173, 12, 30, 12, 25, 95, 195, 198, 235, 98, 29, 248, 44,
                121, 73, 203, 132, 51, 196, 138, 65, 42, 3, 49, 169, 182, 129, 146, 242, 193, 228,
                217, 26, 9, 233, 239, 30, 213, 103, 10, 33, 27, 44, 13, 178, 236, 216, 167, 190, 9,
                123, 151, 143, 1, 199, 58, 77, 121, 122, 215, 22, 19, 238, 190, 216, 8, 62, 6, 216,
                37, 197, 124, 141, 51, 196, 205, 205, 193, 24, 86, 246, 60, 16, 139, 66, 51, 93,
                168, 159, 147, 77, 90, 91, 8, 64, 14, 252, 119, 77, 211, 141, 23, 18, 115, 222, 3,
                2, 22, 42, 105, 85, 176, 71, 232, 230, 141, 12, 9, 124, 205, 194, 191, 90, 47, 202,
                233, 218, 161, 80, 55, 8, 134, 223, 202, 4, 137, 45, 10, 71, 90, 162, 252, 99, 19,
                252, 17, 175, 5, 75, 208, 81, 0, 96, 218, 5, 89, 250, 183, 161, 188, 227, 62, 107,
                34, 63, 155, 28, 176, 141, 174, 113, 162, 229, 148, 55, 39, 65, 36, 97, 159, 198,
                238, 222, 34, 76, 187, 40, 19, 109, 1, 67, 146, 40, 75, 194, 208, 80, 208, 221,
                175, 151, 239, 239, 127, 65, 39, 237, 145, 130, 36, 154, 135, 68, 105, 52, 102, 49,
                62, 137, 34, 187, 159, 55, 157, 88, 195, 49, 116, 72, 11, 37, 132, 176, 74, 69, 60,
                157, 67, 36, 156, 165, 71, 164, 86, 220, 240, 241, 13, 40, 125, 79, 147, 27, 56,
                254, 198, 231, 108, 187, 214, 187, 98, 229, 123, 116, 160, 126, 192, 98, 132, 247,
                206, 70, 228, 175, 152, 217, 252, 4, 109, 98, 24, 90, 117, 184, 11, 107, 32, 186,
                217, 155, 44, 253, 198, 120, 175, 170, 229, 66, 122, 141, 158, 75, 68, 108, 104,
                182, 223, 91, 126, 210, 38, 84, 143, 10, 142, 225, 77, 169, 12, 215, 222, 158, 85,
                4, 111, 196, 47, 56, 147, 93, 1, 202, 247, 137, 115, 30, 127, 94, 191, 31, 223,
                162, 16, 73, 219, 118, 52, 40, 255, 191, 183, 70, 132, 115, 91, 214, 191, 156, 189,
                203, 208, 152, 165, 115, 64, 123, 209, 153, 80, 44, 134, 143, 188, 140, 168, 162,
                134, 178, 192, 122, 10, 137, 41, 133, 127, 72, 223, 16, 65, 170, 114, 53, 173, 180,
                59, 208, 190, 54, 96, 123, 199, 137, 214, 115, 240, 73, 87, 253, 137, 81, 36, 66,
                175, 76, 40, 52, 216, 110, 234, 219, 158, 208, 142, 85, 168, 43, 164, 19, 154, 21,
                125, 174, 153, 165, 45, 54, 100, 36, 196, 46, 95, 64, 192, 178, 156, 16, 112, 5,
                237, 207, 113, 132, 125, 148, 34, 132, 105, 148, 216, 148, 182, 33, 74, 215, 161,
                252, 44, 24, 67, 77, 87, 6, 94, 109, 38, 64, 10, 195, 28, 194, 169, 175, 7, 98,
                210, 151, 4, 221, 136, 161, 204, 171, 251, 101, 63, 21, 245, 84, 189, 77, 59, 75,
                136, 44, 17, 217, 119, 206, 191, 191, 137, 127, 81, 55, 208, 225, 33, 209, 59, 83,
                121, 234, 160, 191, 38, 82, 1, 102, 178, 140, 58, 20, 131, 206, 37, 148, 106, 135,
                149, 74, 57, 27, 84, 215, 0, 47, 68, 1, 8, 139, 183, 125, 169, 4, 165, 168, 86,
                218, 178, 95, 157, 185, 64, 45, 211, 221, 151, 205, 240, 69, 133, 200, 15, 213,
                170, 162, 127, 93, 224, 36, 86, 116, 44, 42, 22, 255, 144, 193, 35, 175, 145, 62,
                184, 67, 143, 199, 253, 37, 115, 23, 154, 213, 141, 122, 105,
            ],
            4,
        )
        .unwrap();

        let expected = super::CommitMessageRef {
            round_number: 3669,
            set_id: 3490,
            target_hash: &[
                182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248, 98, 253,
                4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
            ],
            target_number: 5_105_457,
            precommits: vec![
                super::UnsignedPrecommitRef {
                    target_hash: &[
                        182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248,
                        98, 253, 4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
                    ],
                    target_number: 5_105_457,
                },
                super::UnsignedPrecommitRef {
                    target_hash: &[
                        182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248,
                        98, 253, 4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
                    ],
                    target_number: 5_105_457,
                },
                super::UnsignedPrecommitRef {
                    target_hash: &[
                        182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248,
                        98, 253, 4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
                    ],
                    target_number: 5_105_457,
                },
                super::UnsignedPrecommitRef {
                    target_hash: &[
                        182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248,
                        98, 253, 4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
                    ],
                    target_number: 5_105_457,
                },
                super::UnsignedPrecommitRef {
                    target_hash: &[
                        182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248,
                        98, 253, 4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
                    ],
                    target_number: 5_105_457,
                },
                super::UnsignedPrecommitRef {
                    target_hash: &[
                        182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248,
                        98, 253, 4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
                    ],
                    target_number: 5_105_457,
                },
                super::UnsignedPrecommitRef {
                    target_hash: &[
                        182, 68, 115, 35, 15, 201, 152, 195, 12, 181, 59, 244, 231, 124, 34, 248,
                        98, 253, 4, 180, 158, 70, 161, 84, 76, 118, 151, 68, 101, 104, 187, 82,
                    ],
                    target_number: 5_105_457,
                },
            ],
            auth_data: vec![
                (
                    &[
                        189, 185, 216, 33, 163, 12, 201, 104, 162, 255, 11, 241, 156, 90, 244, 205,
                        251, 44, 45, 139, 129, 117, 178, 85, 129, 78, 58, 255, 76, 232, 199, 85,
                        236, 30, 227, 87, 50, 34, 22, 27, 241, 6, 33, 137, 55, 5, 190, 36, 122, 61,
                        112, 51, 99, 34, 119, 46, 185, 156, 188, 133, 140, 103, 33, 10,
                    ],
                    &[
                        45, 154, 173, 12, 30, 12, 25, 95, 195, 198, 235, 98, 29, 248, 44, 121, 73,
                        203, 132, 51, 196, 138, 65, 42, 3, 49, 169, 182, 129, 146, 242, 193,
                    ],
                ),
                (
                    &[
                        228, 217, 26, 9, 233, 239, 30, 213, 103, 10, 33, 27, 44, 13, 178, 236, 216,
                        167, 190, 9, 123, 151, 143, 1, 199, 58, 77, 121, 122, 215, 22, 19, 238,
                        190, 216, 8, 62, 6, 216, 37, 197, 124, 141, 51, 196, 205, 205, 193, 24, 86,
                        246, 60, 16, 139, 66, 51, 93, 168, 159, 147, 77, 90, 91, 8,
                    ],
                    &[
                        64, 14, 252, 119, 77, 211, 141, 23, 18, 115, 222, 3, 2, 22, 42, 105, 85,
                        176, 71, 232, 230, 141, 12, 9, 124, 205, 194, 191, 90, 47, 202, 233,
                    ],
                ),
                (
                    &[
                        218, 161, 80, 55, 8, 134, 223, 202, 4, 137, 45, 10, 71, 90, 162, 252, 99,
                        19, 252, 17, 175, 5, 75, 208, 81, 0, 96, 218, 5, 89, 250, 183, 161, 188,
                        227, 62, 107, 34, 63, 155, 28, 176, 141, 174, 113, 162, 229, 148, 55, 39,
                        65, 36, 97, 159, 198, 238, 222, 34, 76, 187, 40, 19, 109, 1,
                    ],
                    &[
                        67, 146, 40, 75, 194, 208, 80, 208, 221, 175, 151, 239, 239, 127, 65, 39,
                        237, 145, 130, 36, 154, 135, 68, 105, 52, 102, 49, 62, 137, 34, 187, 159,
                    ],
                ),
                (
                    &[
                        55, 157, 88, 195, 49, 116, 72, 11, 37, 132, 176, 74, 69, 60, 157, 67, 36,
                        156, 165, 71, 164, 86, 220, 240, 241, 13, 40, 125, 79, 147, 27, 56, 254,
                        198, 231, 108, 187, 214, 187, 98, 229, 123, 116, 160, 126, 192, 98, 132,
                        247, 206, 70, 228, 175, 152, 217, 252, 4, 109, 98, 24, 90, 117, 184, 11,
                    ],
                    &[
                        107, 32, 186, 217, 155, 44, 253, 198, 120, 175, 170, 229, 66, 122, 141,
                        158, 75, 68, 108, 104, 182, 223, 91, 126, 210, 38, 84, 143, 10, 142, 225,
                        77,
                    ],
                ),
                (
                    &[
                        169, 12, 215, 222, 158, 85, 4, 111, 196, 47, 56, 147, 93, 1, 202, 247, 137,
                        115, 30, 127, 94, 191, 31, 223, 162, 16, 73, 219, 118, 52, 40, 255, 191,
                        183, 70, 132, 115, 91, 214, 191, 156, 189, 203, 208, 152, 165, 115, 64,
                        123, 209, 153, 80, 44, 134, 143, 188, 140, 168, 162, 134, 178, 192, 122,
                        10,
                    ],
                    &[
                        137, 41, 133, 127, 72, 223, 16, 65, 170, 114, 53, 173, 180, 59, 208, 190,
                        54, 96, 123, 199, 137, 214, 115, 240, 73, 87, 253, 137, 81, 36, 66, 175,
                    ],
                ),
                (
                    &[
                        76, 40, 52, 216, 110, 234, 219, 158, 208, 142, 85, 168, 43, 164, 19, 154,
                        21, 125, 174, 153, 165, 45, 54, 100, 36, 196, 46, 95, 64, 192, 178, 156,
                        16, 112, 5, 237, 207, 113, 132, 125, 148, 34, 132, 105, 148, 216, 148, 182,
                        33, 74, 215, 161, 252, 44, 24, 67, 77, 87, 6, 94, 109, 38, 64, 10,
                    ],
                    &[
                        195, 28, 194, 169, 175, 7, 98, 210, 151, 4, 221, 136, 161, 204, 171, 251,
                        101, 63, 21, 245, 84, 189, 77, 59, 75, 136, 44, 17, 217, 119, 206, 191,
                    ],
                ),
                (
                    &[
                        191, 137, 127, 81, 55, 208, 225, 33, 209, 59, 83, 121, 234, 160, 191, 38,
                        82, 1, 102, 178, 140, 58, 20, 131, 206, 37, 148, 106, 135, 149, 74, 57, 27,
                        84, 215, 0, 47, 68, 1, 8, 139, 183, 125, 169, 4, 165, 168, 86, 218, 178,
                        95, 157, 185, 64, 45, 211, 221, 151, 205, 240, 69, 133, 200, 15,
                    ],
                    &[
                        213, 170, 162, 127, 93, 224, 36, 86, 116, 44, 42, 22, 255, 144, 193, 35,
                        175, 145, 62, 184, 67, 143, 199, 253, 37, 115, 23, 154, 213, 141, 122, 105,
                    ],
                ),
            ],
        };

        assert_eq!(actual, expected);
    }
}
