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

//! Verifying a block body. This operation is also called executing a block.
//!
//! In order to execute a block, one must perform two runtime calls, to
//! [`CHECK_INHERENTS_FUNCTION_NAME`] and to [`EXECUTE_BLOCK_FUNCTION_NAME`] (in that order).
//!
//! The parameter to pass for these runtime calls can be determined using
//! [`check_inherents_parameter`] and [`execute_block_parameter`]. When execution succeeds,
//! the output of the runtime call must be checked using [`check_check_inherents_output`]
//! and [`check_execute_block_output`].
//! The storage changes must be preserved between the two calls.
//!
//! Any error during the execution or the output verification means that the block is invalid.

use crate::{header, util, verify::inherents};

use alloc::vec::Vec;
use core::{iter, time::Duration};

pub const EXECUTE_BLOCK_FUNCTION_NAME: &str = "Core_execute_block";

/// Returns a list of buffers that, when concatenated together, forms the parameter to pass to
/// the `Core_execute_block` function in order to verify the inherents of a block.
pub fn execute_block_parameter<'a>(
    block_header: &'a [u8],
    block_number_bytes: usize,
    block_body: impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a,
) -> Result<
    impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a,
    ExecuteBlockParameterError,
> {
    // Consensus engines add a seal at the end of the digest logs. This seal is guaranteed to
    // be the last item. We need to remove it before we can verify the unsealed header.
    let mut unsealed_header = match header::decode(block_header, block_number_bytes) {
        Ok(h) => h,
        Err(err) => return Err(ExecuteBlockParameterError::InvalidHeader(err)),
    };
    let _seal_log = unsealed_header.digest.pop_seal();

    let encoded_body_len = util::encode_scale_compact_usize(block_body.len());
    Ok(unsealed_header
        .scale_encoding(block_number_bytes)
        .map(|b| either::Right(either::Left(b)))
        .chain(iter::once(either::Right(either::Right(encoded_body_len))))
        .chain(block_body.map(either::Left)))
}

/// Error potentially returned by [`execute_block_parameter`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ExecuteBlockParameterError {
    /// Header provided as parameter is invalid.
    InvalidHeader(header::Error),
}

/// Checks the output of the `Core_execute_block` runtime call.
pub fn check_execute_block_output(output: &[u8]) -> Result<(), ExecuteBlockOutputError> {
    if !output.is_empty() {
        return Err(ExecuteBlockOutputError::NotEmpty);
    }

    Ok(())
}

/// Error potentially returned by [`check_execute_block_output`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ExecuteBlockOutputError {
    /// The output is not empty.
    NotEmpty,
}

pub const CHECK_INHERENTS_FUNCTION_NAME: &str = "BlockBuilder_check_inherents";

/// Returns a list of buffers that, when concatenated together, forms the parameter to pass to
/// the `BlockBuilder_check_inherents` function in order to verify the inherents of a block.
pub fn check_inherents_parameter<'a>(
    block_header: &'a [u8],
    block_number_bytes: usize,
    block_body: impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a,
    now_from_unix_epoch: Duration,
) -> Result<
    impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a,
    ExecuteBlockParameterError,
> {
    // The first parameter of `BlockBuilder_check_inherents` is identical to the one of
    // `Core_execute_block`.
    let execute_block_parameter =
        execute_block_parameter(block_header, block_number_bytes, block_body)?;

    // The second parameter of `BlockBuilder_check_inherents` is a SCALE-encoded list of
    // tuples containing an "inherent identifier" (`[u8; 8]`) and a value (`Vec<u8>`).
    let inherent_data = inherents::InherentData {
        timestamp: u64::try_from(now_from_unix_epoch.as_millis()).unwrap_or(u64::MAX),
    };
    let list = inherent_data.into_raw_list();
    let len = util::encode_scale_compact_usize(list.len());
    let encoded_list = list.flat_map(|(id, value)| {
        let value_len = util::encode_scale_compact_usize(value.as_ref().len());
        let value_and_len = iter::once(value_len)
            .map(either::Left)
            .chain(iter::once(value).map(either::Right));
        iter::once(id)
            .map(either::Left)
            .chain(value_and_len.map(either::Right))
    });

    Ok([
        either::Left(execute_block_parameter.map(either::Left)),
        either::Right(either::Left(iter::once(either::Right(either::Left(len))))),
        either::Right(either::Right(
            encoded_list.map(either::Right).map(either::Right),
        )),
    ]
    .into_iter()
    .flatten())
}

/// Checks the output of the `BlockBuilder_check_inherents` runtime call.
pub fn check_check_inherents_output(output: &[u8]) -> Result<(), InherentsOutputError> {
    // The format of the output of `check_inherents` consists of two booleans and a list of
    // errors.
    // We don't care about the value of the two booleans, and they are ignored during the parsing.
    // Because we don't pass as parameter the `auraslot` or `babeslot`, errors will be generated
    // on older runtimes that expect these values. For this reason, errors concerning `auraslot`
    // and `babeslot` are ignored.
    let parser = nom::sequence::preceded(
        nom::sequence::tuple((crate::util::nom_bool_decode, crate::util::nom_bool_decode)),
        nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
            nom::multi::fold_many_m_n(
                num_elems,
                num_elems,
                nom::sequence::tuple((
                    nom::combinator::map(nom::bytes::streaming::take(8u8), |b| {
                        <[u8; 8]>::try_from(b).unwrap()
                    }),
                    crate::util::nom_bytes_decode,
                )),
                Vec::new,
                |mut errors, (module, error)| {
                    if module != *b"auraslot" && module != *b"babeslot" {
                        errors.push((module, error.to_vec()));
                    }
                    errors
                },
            )
        }),
    );

    match nom::combinator::all_consuming::<_, _, nom::error::Error<&[u8]>, _>(parser)(output) {
        Err(_err) => Err(InherentsOutputError::ParseFailure),
        Ok((_, errors)) => {
            if errors.is_empty() {
                Ok(())
            } else {
                Err(InherentsOutputError::Error { errors })
            }
        }
    }
}

/// Error potentially returned by [`check_check_inherents_output`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum InherentsOutputError {
    /// Runtime has returned some errors.
    #[display("Runtime has returned some errors when verifying inherents: {errors:?}")]
    Error {
        /// List of errors produced by the runtime.
        ///
        /// The first element of each tuple is an identifier of the module that produced the
        /// error, while the second element is a SCALE-encoded piece of data.
        ///
        /// Due to the fact that errors are not supposed to happen, and that the format of errors
        /// has changed depending on runtime versions, no utility is provided to decode them.
        errors: Vec<([u8; 8], Vec<u8>)>,
    },
    /// Failed to parse the output.
    ParseFailure,
}
