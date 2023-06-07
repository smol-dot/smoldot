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

use super::{ParseError, ParseErrorInner};
use crate::header::BabeNextConfig;

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub(super) struct LightSyncState {
    babe_epoch_changes: HexString,
    babe_finalized_block_weight: u32,
    finalized_block_header: HexString,
    grandpa_authority_set: HexString,
}

impl LightSyncState {
    pub(super) fn decode(
        &self,
        block_number_bytes: usize,
    ) -> Result<DecodedLightSyncState, ParseError> {
        // We don't use `all_consuming` in order to remain compatible in case new fields are added
        // in Substrate to these data structures.
        // This really should be solved by having a proper format for checkpoints, but
        // there isn't.
        let grandpa_authority_set = match nom::Finish::finish(nom::combinator::complete(
            authority_set::<nom::error::Error<&[u8]>>,
        )(
            &self.grandpa_authority_set.0[..]
        )) {
            Ok((_, v)) => v,
            Err(_err) => return Err(ParseError(ParseErrorInner::Other)),
        };
        let babe_epoch_changes = match nom::Finish::finish(nom::combinator::complete(
            epoch_changes::<nom::error::Error<&[u8]>>,
        )(&self.babe_epoch_changes.0[..]))
        {
            Ok((_, v)) => v,
            Err(_err) => return Err(ParseError(ParseErrorInner::Other)),
        };

        Ok(DecodedLightSyncState {
            finalized_block_header: crate::header::decode(
                &self.finalized_block_header.0[..],
                block_number_bytes,
            )
            .map_err(|_| ParseError(ParseErrorInner::Other))?
            .into(),
            grandpa_authority_set,
            babe_epoch_changes,
        })
    }
}

#[derive(Debug)]
pub(super) struct DecodedLightSyncState {
    pub(super) babe_epoch_changes: EpochChanges,
    pub(super) finalized_block_header: crate::header::Header,
    pub(super) grandpa_authority_set: AuthoritySet,
}

#[derive(Debug)]
pub(super) struct EpochChanges {
    _inner: ForkTree<PersistedEpochHeader>,
    pub(super) epochs: BTreeMap<([u8; 32], u32), PersistedEpoch>,
    // TODO: Substrate has added the field below to the checkpoints format ; it is commented out
    //       right now in order to maintain compatibility with checkpoints that were generated
    //       a long time ago
    // gap: Option<GapEpochs>,
}

fn epoch_changes<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], EpochChanges, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            fork_tree(persisted_epoch_header),
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::sequence::tuple((
                        nom::bytes::complete::take(32u32),
                        nom::number::complete::le_u32,
                        persisted_epoch,
                    )),
                )
            }),
        )),
        move |(inner, epochs)| EpochChanges {
            _inner: inner,
            epochs: epochs
                .into_iter()
                .map(|(h, n, e)| ((*<&[u8; 32]>::try_from(h).unwrap(), n), e))
                .collect(),
        },
    )(bytes)
}

#[allow(unused)]
#[derive(Debug)]
pub(super) struct GapEpochs {
    current: ([u8; 32], u32, PersistedEpoch),
    next: Option<([u8; 32], u32, BabeEpoch)>,
}

#[allow(unused)]
fn gap_epochs<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], GapEpochs, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::sequence::tuple((
                nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
                    *<&[u8; 32]>::try_from(b).unwrap()
                }),
                nom::number::complete::le_u32,
                persisted_epoch,
            )),
            crate::util::nom_option_decode(nom::sequence::tuple((
                nom::combinator::map(nom::bytes::complete::take(32u32), |b| {
                    *<&[u8; 32]>::try_from(b).unwrap()
                }),
                nom::number::complete::le_u32,
                babe_epoch,
            ))),
        )),
        move |(current, next)| GapEpochs { current, next },
    )(bytes)
}

#[derive(Debug)]
pub(super) enum PersistedEpochHeader {
    Genesis(EpochHeader, EpochHeader),
    Regular(EpochHeader),
}

fn persisted_epoch_header<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], PersistedEpochHeader, E> {
    nom::branch::alt((
        nom::combinator::map(
            nom::sequence::preceded(
                nom::bytes::complete::tag(&[0]),
                nom::sequence::tuple((epoch_header, epoch_header)),
            ),
            |(a, b)| PersistedEpochHeader::Genesis(a, b),
        ),
        nom::combinator::map(
            nom::sequence::preceded(nom::bytes::complete::tag(&[1]), epoch_header),
            PersistedEpochHeader::Regular,
        ),
    ))(bytes)
}

#[derive(Debug)]
pub(super) struct EpochHeader {
    _start_slot: u64,
    _end_slot: u64,
}

fn epoch_header<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], EpochHeader, E> {
    nom::combinator::map(
        nom::sequence::tuple((nom::number::complete::le_u64, nom::number::complete::le_u64)),
        move |(start_slot, end_slot)| EpochHeader {
            _start_slot: start_slot,
            _end_slot: end_slot,
        },
    )(bytes)
}

#[derive(Debug)]
pub(super) enum PersistedEpoch {
    Genesis(BabeEpoch, BabeEpoch),
    Regular(BabeEpoch),
}

fn persisted_epoch<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], PersistedEpoch, E> {
    nom::branch::alt((
        nom::combinator::map(
            nom::sequence::preceded(
                nom::bytes::complete::tag(&[0]),
                nom::sequence::tuple((babe_epoch, babe_epoch)),
            ),
            |(a, b)| PersistedEpoch::Genesis(a, b),
        ),
        nom::combinator::map(
            nom::sequence::preceded(nom::bytes::complete::tag(&[1]), babe_epoch),
            PersistedEpoch::Regular,
        ),
    ))(bytes)
}

#[derive(Debug)]
pub(super) struct BabeEpoch {
    pub(super) epoch_index: u64,
    pub(super) slot_number: u64,
    pub(super) duration: u64,
    pub(super) authorities: Vec<BabeAuthority>,
    pub(super) randomness: [u8; 32],
    pub(super) config: BabeNextConfig,
}

fn babe_epoch<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], BabeEpoch, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
                nom::multi::many_m_n(num_elems, num_elems, babe_authority)
            }),
            nom::bytes::complete::take(32u32),
            |b| {
                BabeNextConfig::from_slice(b)
                    .map(|c| (&b[17..], c)) // TODO: hacky to use a constant
                    .map_err(|_| {
                        nom::Err::Error(nom::error::make_error(b, nom::error::ErrorKind::MapOpt))
                    })
            },
        )),
        move |(epoch_index, slot_number, duration, authorities, randomness, config)| BabeEpoch {
            epoch_index,
            slot_number,
            duration,
            authorities,
            randomness: *<&[u8; 32]>::try_from(randomness).unwrap(),
            config,
        },
    )(bytes)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabeAuthority {
    /// Sr25519 public key.
    pub public_key: [u8; 32],
    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    // TODO: should be NonZeroU64; requires deep changes in decoding code though
    pub weight: u64,
}

fn babe_authority<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], BabeAuthority, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::bytes::complete::take(32u32),
            nom::number::complete::le_u64,
        )),
        move |(public_key, weight)| BabeAuthority {
            public_key: *<&[u8; 32]>::try_from(public_key).unwrap(),
            weight,
        },
    )(bytes)
}

#[derive(Debug)]
pub(super) struct AuthoritySet {
    pub(super) current_authorities: Vec<GrandpaAuthority>,
    pub(super) set_id: u64,
    _pending_standard_changes: ForkTree<PendingChange>,
    _pending_forced_changes: Vec<PendingChange>,
    /// Note: this field didn't exist in Substrate before 2021-01-20. Light sync states that are
    /// older than that are missing it.
    _authority_set_changes: Vec<(u64, u32)>,
}

fn authority_set<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], AuthoritySet, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
                nom::multi::many_m_n(num_elems, num_elems, grandpa_authority)
            }),
            nom::number::complete::le_u64,
            fork_tree(pending_change),
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
                nom::multi::many_m_n(num_elems, num_elems, pending_change)
            }),
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::sequence::tuple((
                        nom::number::complete::le_u64,
                        nom::number::complete::le_u32,
                    )),
                )
            }),
        )),
        move |(
            current_authorities,
            set_id,
            pending_standard_changes,
            pending_forced_changes,
            authority_set_changes,
        )| AuthoritySet {
            current_authorities,
            set_id,
            _pending_standard_changes: pending_standard_changes,
            _pending_forced_changes: pending_forced_changes,
            _authority_set_changes: authority_set_changes,
        },
    )(bytes)
}

#[derive(Debug)]
pub(super) struct PendingChange {
    _next_authorities: Vec<GrandpaAuthority>,
    _delay: u32,
    _canon_height: u32,
    _canon_hash: [u8; 32],
    _delay_kind: DelayKind,
}

fn pending_change<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], PendingChange, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, move |num_elems| {
                nom::multi::many_m_n(num_elems, num_elems, grandpa_authority)
            }),
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::bytes::complete::take(32u32),
            delay_kind,
        )),
        move |(next_authorities, delay, canon_height, canon_hash, delay_kind)| PendingChange {
            _next_authorities: next_authorities,
            _delay: delay,
            _canon_height: canon_height,
            _canon_hash: *<&[u8; 32]>::try_from(canon_hash).unwrap(),
            _delay_kind: delay_kind,
        },
    )(bytes)
}

#[derive(Debug)]
pub(super) enum DelayKind {
    Finalized,
    Best { _median_last_finalized: u32 },
}

fn delay_kind<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], DelayKind, E> {
    nom::branch::alt((
        nom::combinator::map(nom::bytes::complete::tag(&[0]), |_| DelayKind::Finalized),
        nom::combinator::map(
            nom::sequence::preceded(
                nom::bytes::complete::tag(&[1]),
                nom::number::complete::le_u32,
            ),
            |median_last_finalized| DelayKind::Best {
                _median_last_finalized: median_last_finalized,
            },
        ),
    ))(bytes)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GrandpaAuthority {
    /// Ed25519 public key.
    pub public_key: [u8; 32],

    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    // TODO: should be NonZeroU64; requires deep changes in decoding code though
    pub weight: u64,
}

fn grandpa_authority<'a, E: nom::error::ParseError<&'a [u8]>>(
    bytes: &'a [u8],
) -> nom::IResult<&'a [u8], GrandpaAuthority, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::bytes::complete::take(32u32),
            nom::number::complete::le_u64,
        )),
        move |(public_key, weight)| GrandpaAuthority {
            public_key: *<&[u8; 32]>::try_from(public_key).unwrap(),
            weight,
        },
    )(bytes)
}

#[derive(Debug)]
pub(super) struct ForkTree<T> {
    _roots: Vec<ForkTreeNode<T>>,
    _best_finalized_number: Option<u32>,
}

fn fork_tree<'a, T, E: nom::error::ParseError<&'a [u8]>>(
    mut inner: impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], T, E>,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], ForkTree<T>, E> {
    nom::combinator::map(
        nom::sequence::tuple((
            // We do parsing manually due to borrow checking troubles regarding `inner`.
            move |mut bytes| {
                let (bytes_rest, num_roots) = match crate::util::nom_scale_compact_usize(bytes) {
                    Ok(d) => d,
                    Err(err) => return Err(err),
                };
                bytes = bytes_rest;

                let mut roots = Vec::with_capacity(num_roots);
                for _ in 0..num_roots {
                    let (bytes_rest, child) = match fork_tree_node(&mut inner)(bytes) {
                        Ok(d) => d,
                        Err(err) => return Err(err),
                    };
                    bytes = bytes_rest;
                    roots.push(child);
                }

                Ok((bytes, roots))
            },
            crate::util::nom_option_decode(nom::number::complete::le_u32),
        )),
        |(roots, best_finalized_number)| ForkTree {
            _roots: roots,
            _best_finalized_number: best_finalized_number,
        },
    )
}

#[derive(Debug)]
pub(super) struct ForkTreeNode<T> {
    _hash: [u8; 32],
    _number: u32,
    _data: T,
    _children: Vec<Self>,
}

fn fork_tree_node<'a, 'p, T, E: nom::error::ParseError<&'a [u8]>>(
    inner: &'p mut dyn FnMut(&'a [u8]) -> nom::IResult<&'a [u8], T, E>,
) -> impl FnMut(&'a [u8]) -> nom::IResult<&'a [u8], ForkTreeNode<T>, E> + 'p {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::bytes::complete::take(32u32),
            nom::number::complete::le_u32,
            // We do parsing manually due to borrow checking troubles regarding `inner`.
            move |mut bytes| {
                let (bytes_rest, data) = match inner(bytes) {
                    Ok(d) => d,
                    Err(err) => return Err(err),
                };
                bytes = bytes_rest;

                let (bytes_rest, num_children) = match crate::util::nom_scale_compact_usize(bytes) {
                    Ok(d) => d,
                    Err(err) => return Err(err),
                };
                bytes = bytes_rest;

                let mut children = Vec::with_capacity(num_children);
                for _ in 0..num_children {
                    let (bytes_rest, child) = match fork_tree_node(&mut *inner)(bytes) {
                        Ok(d) => d,
                        Err(err) => return Err(err),
                    };
                    bytes = bytes_rest;
                    children.push(child);
                }

                Ok((bytes, (data, children)))
            },
        )),
        |(hash, number, (data, children))| ForkTreeNode {
            _hash: *<&[u8; 32]>::try_from(hash).unwrap(),
            _number: number,
            _data: data,
            _children: children,
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct HexString(pub(super) Vec<u8>);

impl serde::Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        format!("0x{}", hex::encode(&self.0[..])).serialize(serializer)
    }
}

impl<'a> serde::Deserialize<'a> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<HexString, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = String::deserialize(deserializer)?;

        if !string.starts_with("0x") {
            return Err(serde::de::Error::custom(
                "hexadecimal string doesn't start with 0x",
            ));
        }

        let bytes = hex::decode(&string[2..]).map_err(serde::de::Error::custom)?;
        Ok(HexString(bytes))
    }
}
