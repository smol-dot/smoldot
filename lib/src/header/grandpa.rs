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

use super::Error;
use crate::util;

use alloc::vec::Vec;
use core::{cmp, fmt, iter, num::NonZero, slice};

/// A consensus log item for GrandPa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrandpaConsensusLogRef<'a> {
    /// Schedule an authority set change.
    ///
    /// The earliest digest of this type in a single block will be respected,
    /// provided that there is no `ForcedChange` digest. If there is, then the
    /// `ForcedChange` will take precedence.
    ///
    /// No change should be scheduled if one is already and the delay has not
    /// passed completely.
    ///
    /// This should be a pure function: i.e. as long as the runtime can interpret
    /// the digest type it should return the same result regardless of the current
    /// state.
    ScheduledChange(GrandpaScheduledChangeRef<'a>),

    /// Force an authority set change.
    ///
    /// Forced changes are applied after a delay of _imported_ blocks,
    /// while pending changes are applied after a delay of _finalized_ blocks.
    ///
    /// The earliest digest of this type in a single block will be respected,
    /// with others ignored.
    ///
    /// No change should be scheduled if one is already and the delay has not
    /// passed completely.
    ///
    /// This should be a pure function: i.e. as long as the runtime can interpret
    /// the digest type it should return the same result regardless of the current
    /// state.
    ForcedChange {
        reset_block_height: u64,
        change: GrandpaScheduledChangeRef<'a>,
    },

    /// Note that the authority with given index is disabled until the next change.
    OnDisabled(u64),

    /// A signal to pause the current authority set after the given delay.
    /// After finalizing the block at _delay_ the authorities should stop voting.
    Pause(u64),

    /// A signal to resume the current authority set after the given delay.
    /// After authoring the block at _delay_ the authorities should resume voting.
    Resume(u64),
}

impl<'a> GrandpaConsensusLogRef<'a> {
    /// Decodes a [`GrandpaConsensusLogRef`] from a slice of bytes.
    pub fn from_slice(slice: &'a [u8], block_number_bytes: usize) -> Result<Self, Error> {
        Ok(nom::Parser::parse(
            &mut nom::combinator::all_consuming(grandpa_consensus_log_ref(block_number_bytes)),
            slice,
        )
        .map_err(|_: nom::Err<(&[u8], nom::error::ErrorKind)>| {
            Error::GrandpaConsensusLogDecodeError
        })?
        .1)
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
        block_number_bytes: usize,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + use<'a>> + Clone + use<'a> {
        let index = iter::once(match self {
            GrandpaConsensusLogRef::ScheduledChange(_) => [1],
            GrandpaConsensusLogRef::ForcedChange { .. } => [2],
            GrandpaConsensusLogRef::OnDisabled(_) => [3],
            GrandpaConsensusLogRef::Pause(_) => [4],
            GrandpaConsensusLogRef::Resume(_) => [5],
        });

        let body = match self {
            GrandpaConsensusLogRef::ScheduledChange(change) => either::Left(either::Left(
                change
                    .scale_encoding(block_number_bytes)
                    .map(either::Left)
                    .map(either::Left),
            )),
            GrandpaConsensusLogRef::ForcedChange {
                reset_block_height,
                change,
            } => {
                let mut data = Vec::with_capacity(block_number_bytes);
                data.extend_from_slice(&reset_block_height.to_le_bytes());
                // TODO: unclear what to do if the block number doesn't fit within `expected_block_number_bytes`
                data.resize(block_number_bytes, 0);
                either::Left(either::Right(
                    iter::once(either::Right(either::Right(data))).chain(
                        change
                            .scale_encoding(block_number_bytes)
                            .map(either::Right)
                            .map(either::Left),
                    ),
                ))
            }
            GrandpaConsensusLogRef::OnDisabled(n) => {
                either::Right(iter::once(either::Right(either::Left(n.to_le_bytes()))))
            }
            GrandpaConsensusLogRef::Pause(n) => {
                let mut data = Vec::with_capacity(block_number_bytes);
                data.extend_from_slice(&n.to_le_bytes());
                // TODO: unclear what to do if the block number doesn't fit within `expected_block_number_bytes`
                data.resize(block_number_bytes, 0);
                either::Right(iter::once(either::Right(either::Right(data))))
            }
            GrandpaConsensusLogRef::Resume(n) => {
                let mut data = Vec::with_capacity(block_number_bytes);
                data.extend_from_slice(&n.to_le_bytes());
                // TODO: unclear what to do if the block number doesn't fit within `expected_block_number_bytes`
                data.resize(block_number_bytes, 0);
                either::Right(iter::once(either::Right(either::Right(data))))
            }
        };

        index.map(either::Left).chain(body.map(either::Right))
    }
}

impl<'a> From<&'a GrandpaConsensusLog> for GrandpaConsensusLogRef<'a> {
    fn from(a: &'a GrandpaConsensusLog) -> Self {
        match a {
            GrandpaConsensusLog::ScheduledChange(v) => {
                GrandpaConsensusLogRef::ScheduledChange(v.into())
            }
            GrandpaConsensusLog::ForcedChange {
                reset_block_height,
                change,
            } => GrandpaConsensusLogRef::ForcedChange {
                reset_block_height: *reset_block_height,
                change: change.into(),
            },
            GrandpaConsensusLog::OnDisabled(v) => GrandpaConsensusLogRef::OnDisabled(*v),
            GrandpaConsensusLog::Pause(v) => GrandpaConsensusLogRef::Pause(*v),
            GrandpaConsensusLog::Resume(v) => GrandpaConsensusLogRef::Resume(*v),
        }
    }
}

/// A consensus log item for GrandPa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrandpaConsensusLog {
    /// Schedule an authority set change.
    ///
    /// The earliest digest of this type in a single block will be respected,
    /// provided that there is no `ForcedChange` digest. If there is, then the
    /// `ForcedChange` will take precedence.
    ///
    /// No change should be scheduled if one is already and the delay has not
    /// passed completely.
    ///
    /// This should be a pure function: i.e. as long as the runtime can interpret
    /// the digest type it should return the same result regardless of the current
    /// state.
    ScheduledChange(GrandpaScheduledChange),

    /// Force an authority set change.
    ///
    /// Forced changes are applied after a delay of _imported_ blocks,
    /// while pending changes are applied after a delay of _finalized_ blocks.
    ///
    /// The earliest digest of this type in a single block will be respected,
    /// with others ignored.
    ///
    /// No change should be scheduled if one is already and the delay has not
    /// passed completely.
    ///
    /// This should be a pure function: i.e. as long as the runtime can interpret
    /// the digest type it should return the same result regardless of the current
    /// state.
    ForcedChange {
        reset_block_height: u64,
        change: GrandpaScheduledChange,
    },

    /// Note that the authority with given index is disabled until the next change.
    OnDisabled(u64),

    /// A signal to pause the current authority set after the given delay.
    /// After finalizing the block at _delay_ the authorities should stop voting.
    Pause(u64),

    /// A signal to resume the current authority set after the given delay.
    /// After authoring the block at _delay_ the authorities should resume voting.
    Resume(u64),
}

impl<'a> From<GrandpaConsensusLogRef<'a>> for GrandpaConsensusLog {
    fn from(a: GrandpaConsensusLogRef<'a>) -> Self {
        match a {
            GrandpaConsensusLogRef::ScheduledChange(v) => {
                GrandpaConsensusLog::ScheduledChange(v.into())
            }
            GrandpaConsensusLogRef::ForcedChange {
                reset_block_height,
                change,
            } => GrandpaConsensusLog::ForcedChange {
                reset_block_height,
                change: change.into(),
            },
            GrandpaConsensusLogRef::OnDisabled(v) => GrandpaConsensusLog::OnDisabled(v),
            GrandpaConsensusLogRef::Pause(v) => GrandpaConsensusLog::Pause(v),
            GrandpaConsensusLogRef::Resume(v) => GrandpaConsensusLog::Resume(v),
        }
    }
}

/// A scheduled change of authority set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrandpaScheduledChangeRef<'a> {
    /// The new authorities after the change, along with their respective weights.
    pub next_authorities: GrandpaAuthoritiesIter<'a>,
    /// The number of blocks to delay.
    pub delay: u64,
}

impl<'a> GrandpaScheduledChangeRef<'a> {
    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
        block_number_bytes: usize,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + use<'a>> + Clone + use<'a> {
        let header = util::encode_scale_compact_usize(self.next_authorities.len());

        let mut delay = Vec::with_capacity(block_number_bytes);
        delay.extend_from_slice(&self.delay.to_le_bytes());
        // TODO: unclear what to do if the block number doesn't fit within `expected_block_number_bytes`
        delay.resize(block_number_bytes, 0);

        iter::once(either::Left(either::Left(header)))
            .chain(
                self.next_authorities
                    .clone()
                    .flat_map(|a| a.scale_encoding())
                    .map(either::Right),
            )
            .chain(iter::once(either::Left(either::Right(delay))))
    }
}

impl<'a> From<&'a GrandpaScheduledChange> for GrandpaScheduledChangeRef<'a> {
    fn from(gp: &'a GrandpaScheduledChange) -> Self {
        GrandpaScheduledChangeRef {
            next_authorities: GrandpaAuthoritiesIter(GrandpaAuthoritiesIterInner::Decoded(
                gp.next_authorities.iter(),
            )),
            delay: gp.delay,
        }
    }
}

/// A scheduled change of authority set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrandpaScheduledChange {
    /// The new authorities after the change, along with their respective weights.
    pub next_authorities: Vec<GrandpaAuthority>,
    /// The number of blocks to delay.
    pub delay: u64,
}

impl<'a> From<GrandpaScheduledChangeRef<'a>> for GrandpaScheduledChange {
    fn from(gp: GrandpaScheduledChangeRef<'a>) -> Self {
        GrandpaScheduledChange {
            next_authorities: gp.next_authorities.map(Into::into).collect(),
            delay: gp.delay,
        }
    }
}

/// List of authorities in a GrandPa context.
#[derive(Clone)]
pub struct GrandpaAuthoritiesIter<'a>(GrandpaAuthoritiesIterInner<'a>);

#[derive(Clone)]
enum GrandpaAuthoritiesIterInner<'a> {
    Encoded(slice::Chunks<'a, u8>),
    Decoded(slice::Iter<'a, GrandpaAuthority>),
}

impl<'a> GrandpaAuthoritiesIter<'a> {
    /// Returns an iterator corresponding to the given slice.
    pub fn new(slice: &'a [GrandpaAuthority]) -> Self {
        GrandpaAuthoritiesIter(GrandpaAuthoritiesIterInner::Decoded(slice.iter()))
    }
}

impl<'a> Iterator for GrandpaAuthoritiesIter<'a> {
    type Item = GrandpaAuthorityRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            GrandpaAuthoritiesIterInner::Decoded(inner) => inner.next().map(Into::into),
            GrandpaAuthoritiesIterInner::Encoded(inner) => {
                let item = inner.next()?;
                Some(
                    nom::Parser::parse(
                        &mut nom::combinator::all_consuming::<_, (&[u8], nom::error::ErrorKind), _>(
                            grandpa_authority_ref,
                        ),
                        item,
                    )
                    .unwrap()
                    .1,
                )
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            GrandpaAuthoritiesIterInner::Encoded(inner) => inner.size_hint(),
            GrandpaAuthoritiesIterInner::Decoded(inner) => inner.size_hint(),
        }
    }
}

impl<'a> ExactSizeIterator for GrandpaAuthoritiesIter<'a> {}

impl<'a> cmp::PartialEq<GrandpaAuthoritiesIter<'a>> for GrandpaAuthoritiesIter<'a> {
    fn eq(&self, other: &GrandpaAuthoritiesIter<'a>) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        loop {
            match (a.next(), b.next()) {
                (Some(a), Some(b)) if a == b => {}
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl<'a> cmp::Eq for GrandpaAuthoritiesIter<'a> {}

impl<'a> fmt::Debug for GrandpaAuthoritiesIter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GrandpaAuthorityRef<'a> {
    /// Ed25519 public key.
    pub public_key: &'a [u8; 32],

    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    pub weight: NonZero<u64>,
}

impl<'a> GrandpaAuthorityRef<'a> {
    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + use<'a>> + Clone + use<'a> {
        iter::once(either::Right(self.public_key))
            .chain(iter::once(either::Left(self.weight.get().to_le_bytes())))
    }
}

impl<'a> From<&'a GrandpaAuthority> for GrandpaAuthorityRef<'a> {
    fn from(gp: &'a GrandpaAuthority) -> Self {
        GrandpaAuthorityRef {
            public_key: &gp.public_key,
            weight: gp.weight,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GrandpaAuthority {
    /// Ed25519 public key.
    pub public_key: [u8; 32],

    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    pub weight: NonZero<u64>,
}

impl GrandpaAuthority {
    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(&self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        GrandpaAuthorityRef::from(self).scale_encoding()
    }
}

impl<'a> From<GrandpaAuthorityRef<'a>> for GrandpaAuthority {
    fn from(gp: GrandpaAuthorityRef<'a>) -> Self {
        GrandpaAuthority {
            public_key: *gp.public_key,
            weight: gp.weight,
        }
    }
}

fn grandpa_consensus_log_ref<
    'a,
    E: nom::error::ParseError<&'a [u8]> + nom::error::ContextError<&'a [u8]>,
>(
    block_number_bytes: usize,
) -> impl nom::Parser<&'a [u8], Output = GrandpaConsensusLogRef<'a>, Error = E> {
    nom::error::context(
        "grandpa_consensus_log_ref",
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[1][..]),
                    grandpa_scheduled_change_ref(block_number_bytes),
                ),
                GrandpaConsensusLogRef::ScheduledChange,
            ),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[2][..]),
                    (
                        crate::util::nom_varsize_number_decode_u64(block_number_bytes),
                        grandpa_scheduled_change_ref(block_number_bytes),
                    ),
                ),
                |(reset_block_height, change)| GrandpaConsensusLogRef::ForcedChange {
                    reset_block_height,
                    change,
                },
            ),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[3][..]),
                    nom::number::streaming::le_u64,
                ),
                GrandpaConsensusLogRef::OnDisabled,
            ),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[4][..]),
                    crate::util::nom_varsize_number_decode_u64(block_number_bytes),
                ),
                GrandpaConsensusLogRef::Pause,
            ),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[5][..]),
                    crate::util::nom_varsize_number_decode_u64(block_number_bytes),
                ),
                GrandpaConsensusLogRef::Resume,
            ),
        )),
    )
}

fn grandpa_scheduled_change_ref<
    'a,
    E: nom::error::ParseError<&'a [u8]> + nom::error::ContextError<&'a [u8]>,
>(
    block_number_bytes: usize,
) -> impl nom::Parser<&'a [u8], Output = GrandpaScheduledChangeRef<'a>, Error = E> {
    nom::error::context(
        "grandpa_scheduled_change_ref",
        nom::combinator::map(
            (
                nom::combinator::flat_map(util::nom_scale_compact_usize, |num_authorities| {
                    nom::combinator::map(
                        nom::combinator::recognize(nom::multi::fold_many_m_n(
                            num_authorities,
                            num_authorities,
                            grandpa_authority_ref,
                            || {},
                            |(), _| (),
                        )),
                        |bytes| {
                            GrandpaAuthoritiesIter(GrandpaAuthoritiesIterInner::Encoded(
                                bytes.chunks(40),
                            ))
                        },
                    )
                }),
                crate::util::nom_varsize_number_decode_u64(block_number_bytes),
            ),
            |(next_authorities, delay)| GrandpaScheduledChangeRef {
                next_authorities,
                delay,
            },
        ),
    )
}

fn grandpa_authority_ref<
    'a,
    E: nom::error::ParseError<&'a [u8]> + nom::error::ContextError<&'a [u8]>,
>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], GrandpaAuthorityRef<'a>, E> {
    nom::Parser::parse(
        &mut nom::error::context(
            "grandpa_authority_ref",
            nom::combinator::map(
                (
                    nom::bytes::streaming::take(32u32),
                    nom::combinator::map_opt(nom::number::streaming::le_u64, NonZero::<u64>::new),
                ),
                |(public_key, weight)| GrandpaAuthorityRef {
                    public_key: TryFrom::try_from(public_key).unwrap(),
                    weight,
                },
            ),
        ),
        bytes,
    )
}
