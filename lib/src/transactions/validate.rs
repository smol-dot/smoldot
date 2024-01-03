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

//! Runtime call to obtain the transactions validity status.

use crate::util;

use alloc::{borrow::ToOwned as _, vec::Vec};
use core::{iter, num::NonZeroU64};

mod tests;

/// Source of the transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransactionSource {
    /// Transaction is already included in a block.
    ///
    /// It isn't possible to tell where the transaction is coming from, since it's already in a
    /// received block.
    InBlock,

    /// Transaction is coming from a local source.
    ///
    /// The transaction was produced internally by the node (for instance an off-chain worker).
    /// This transaction therefore has a higher level of trust compared to the other variants.
    Local,

    /// Transaction has been received externally.
    ///
    /// The transaction has been received from an "untrusted" source, such as the network or the
    /// JSON-RPC server.
    External,
}

/// Information concerning a valid transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidTransaction {
    /// Priority of the transaction.
    ///
    /// Priority determines the ordering of two transactions that have all
    /// [their required tags](ValidTransaction::requires) satisfied. Transactions with a higher
    /// priority should be included first.
    pub priority: u64,

    /// Transaction dependencies.
    ///
    /// Contains a list of so-called *tags*. The actual bytes of the tags can be compared in order
    /// to determine whether two tags are equal, but aren't meaningful from the client
    /// perspective.
    ///
    /// A non-empty list signifies that this transaction can't be included before some other
    /// transactions which [provide](ValidTransaction::provides) the given tags. *All* the tags
    /// must be fulfilled before the transaction can be included.
    // TODO: better type than `Vec<Vec<u8>>`? I feel like this could be a single `Vec<u8>` that is decoded on the fly?
    pub requires: Vec<Vec<u8>>,

    /// Tags provided by the transaction.
    ///
    /// The bytes of the tags aren't meaningful from the client's perspective, but are used to
    /// enforce an ordering between transactions. See [`ValidTransaction::requires`].
    ///
    /// Two transactions that have a provided tag in common are mutually exclusive, and cannot be
    /// both included in the same chain of blocks.
    ///
    /// Guaranteed to never be empty.
    // TODO: better type than `Vec<Vec<u8>>`? I feel like this could be a single `Vec<u8>` that is decoded on the fly?
    pub provides: Vec<Vec<u8>>,

    /// Transaction longevity.
    ///
    /// This value provides a hint of the number of blocks during which the client can assume the
    /// transaction to be valid. This is provided for optimization purposes, to save the client
    /// from re-validating every pending transaction at each new block. It is only a hint, and the
    /// transaction might become invalid sooner.
    ///
    /// After this period, transaction should be removed from the pool or revalidated.
    ///
    /// > **Note**: Many transactions are "mortal", meaning that they automatically become invalid
    /// >           after a certain number of blocks. In that case, the longevity returned by the
    /// >           validation function will be at most this number of blocks. The concept of
    /// >           mortal transactions, however, is not relevant from the client's perspective.
    pub longevity: NonZeroU64,

    /// A flag indicating whether the transaction should be propagated to other peers.
    ///
    /// If `false`, the transaction will still be considered for inclusion in blocks that are
    /// authored locally, but will not be sent to the rest of the network.
    ///
    /// > **Note**: A value of `false` is typically returned for transactions that are very heavy.
    pub propagate: bool,
}

/// An invalid transaction validity.
#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
pub enum InvalidTransaction {
    /// The call of the transaction is not expected.
    Call,
    /// General error to do with the inability to pay some fees (e.g. account balance too low).
    Payment,
    /// General error to do with the transaction not yet being valid (e.g. nonce too high).
    Future,
    /// General error to do with the transaction being outdated (e.g. nonce too low).
    Stale,
    /// General error to do with the transaction's proofs (e.g. signature).
    ///
    /// # Possible causes
    ///
    /// When using a signed extension that provides additional data for signing, it is required
    /// that the signing and the verifying side use the same additional data. Additional
    /// data will only be used to generate the signature, but will not be part of the transaction
    /// itself. As the verifying side does not know which additional data was used while signing
    /// it will only be able to assume a bad signature and cannot express a more meaningful error.
    BadProof,
    /// The transaction birth block is ancient.
    AncientBirthBlock,
    /// The transaction would exhaust the resources of current block.
    ///
    /// The transaction might be valid, but there are not enough resources
    /// left in the current block.
    ExhaustsResources,
    /// Any other custom invalid validity that is not covered by this enum.
    #[display(fmt = "Other reason (code: {_0})")]
    Custom(u8),
    /// An extrinsic with a Mandatory dispatch resulted in Error. This is indicative of either a
    /// malicious validator or a buggy `provide_inherent`. In any case, it can result in dangerously
    /// overweight blocks and therefore if found, invalidates the block.
    BadMandatory,
    /// A transaction with a mandatory dispatch. This is invalid; only inherent extrinsics are
    /// allowed to have mandatory dispatches.
    MandatoryDispatch,
}

/// An unknown transaction validity.
#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
pub enum UnknownTransaction {
    /// Could not lookup some information that is required to validate the transaction.
    CannotLookup,
    /// No validator found for the given unsigned transaction.
    NoUnsignedValidator,
    /// Any other custom unknown validity that is not covered by this enum.
    #[display(fmt = "Other reason (code: {_0})")]
    Custom(u8),
}

/// Error that can happen during the decoding.
#[derive(Debug, derive_more::Display, Clone)]
pub struct DecodeError();

/// Errors that can occur while checking the validity of a transaction.
#[derive(Debug, derive_more::Display, Clone, PartialEq, Eq)]
pub enum TransactionValidityError {
    /// The transaction is invalid.
    #[display(fmt = "Invalid transaction: {_0}")]
    Invalid(InvalidTransaction),
    /// Transaction validity can't be determined.
    #[display(fmt = "Transaction validity couldn't be determined: {_0}")]
    Unknown(UnknownTransaction),
}

/// Produces the input to pass to the `TaggedTransactionQueue_validate_transaction` runtime call.
pub fn validate_transaction_runtime_parameters_v2<'a>(
    scale_encoded_transaction: impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a,
    source: TransactionSource,
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a {
    validate_transaction_runtime_parameters_inner(scale_encoded_transaction, source, &[])
}

/// Produces the input to pass to the `TaggedTransactionQueue_validate_transaction` runtime call.
pub fn validate_transaction_runtime_parameters_v3<'a>(
    scale_encoded_transaction: impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a,
    source: TransactionSource,
    block_hash: &'a [u8; 32],
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a {
    validate_transaction_runtime_parameters_inner(scale_encoded_transaction, source, block_hash)
}

fn validate_transaction_runtime_parameters_inner<'a>(
    scale_encoded_transaction: impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a,
    source: TransactionSource,
    block_hash: &'a [u8],
) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + Clone + 'a {
    // The `TaggedTransactionQueue_validate_transaction` function expects a SCALE-encoded
    // `(source, tx, block_hash)`. The encoding is performed manually in order to avoid
    // performing redundant data copies.
    let source = match source {
        TransactionSource::InBlock => &[0],
        TransactionSource::Local => &[1],
        TransactionSource::External => &[2],
    };

    iter::once(source)
        .map(either::Left)
        .chain(
            scale_encoded_transaction
                .map(either::Right)
                .map(either::Right),
        )
        .chain(iter::once(block_hash).map(either::Left).map(either::Right))
}

/// Name of the runtime function to call in order to validate a transaction.
pub const VALIDATION_FUNCTION_NAME: &str = "TaggedTransactionQueue_validate_transaction";

/// Attempt to decode the return value of the  `TaggedTransactionQueue_validate_transaction`
/// runtime call.
pub fn decode_validate_transaction_return_value(
    scale_encoded: &[u8],
) -> Result<Result<ValidTransaction, TransactionValidityError>, DecodeError> {
    match nom::combinator::all_consuming(transaction_validity)(scale_encoded) {
        Ok((_, data)) => Ok(data),
        Err(_) => Err(DecodeError()),
    }
}

// `nom` parser functions can be found below.

fn transaction_validity(
    bytes: &[u8],
) -> nom::IResult<&[u8], Result<ValidTransaction, TransactionValidityError>> {
    nom::error::context(
        "transaction validity",
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::streaming::tag(&[0]), valid_transaction),
                Ok,
            ),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[1]),
                    transaction_validity_error,
                ),
                Err,
            ),
        )),
    )(bytes)
}

fn valid_transaction(bytes: &[u8]) -> nom::IResult<&[u8], ValidTransaction> {
    nom::error::context(
        "valid transaction",
        nom::combinator::map(
            nom::sequence::tuple((
                nom::number::streaming::le_u64,
                tags,
                // TODO: maybe show by strong typing the fact that the provide tags are never empty
                nom::combinator::verify(tags, |provides: &Vec<Vec<u8>>| !provides.is_empty()),
                nom::combinator::map_opt(nom::number::streaming::le_u64, NonZeroU64::new),
                util::nom_bool_decode,
            )),
            |(priority, requires, provides, longevity, propagate)| ValidTransaction {
                priority,
                requires,
                provides,
                longevity,
                propagate,
            },
        ),
    )(bytes)
}

fn transaction_validity_error(bytes: &[u8]) -> nom::IResult<&[u8], TransactionValidityError> {
    nom::error::context(
        "transaction validity error",
        nom::branch::alt((
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::streaming::tag(&[0]), invalid_transaction),
                TransactionValidityError::Invalid,
            ),
            nom::combinator::map(
                nom::sequence::preceded(nom::bytes::streaming::tag(&[1]), unknown_transaction),
                TransactionValidityError::Unknown,
            ),
        )),
    )(bytes)
}

fn invalid_transaction(bytes: &[u8]) -> nom::IResult<&[u8], InvalidTransaction> {
    nom::error::context(
        "invalid transaction",
        nom::branch::alt((
            nom::combinator::map(nom::bytes::streaming::tag(&[0]), |_| {
                InvalidTransaction::Call
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[1]), |_| {
                InvalidTransaction::Payment
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[2]), |_| {
                InvalidTransaction::Future
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[3]), |_| {
                InvalidTransaction::Stale
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[4]), |_| {
                InvalidTransaction::BadProof
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[5]), |_| {
                InvalidTransaction::AncientBirthBlock
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[6]), |_| {
                InvalidTransaction::ExhaustsResources
            }),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[7]),
                    nom::bytes::streaming::take(1u32),
                ),
                |n: &[u8]| InvalidTransaction::Custom(n[0]),
            ),
            nom::combinator::map(nom::bytes::streaming::tag(&[8]), |_| {
                InvalidTransaction::BadMandatory
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[9]), |_| {
                InvalidTransaction::MandatoryDispatch
            }),
        )),
    )(bytes)
}

fn unknown_transaction(bytes: &[u8]) -> nom::IResult<&[u8], UnknownTransaction> {
    nom::error::context(
        "unknown transaction",
        nom::branch::alt((
            nom::combinator::map(nom::bytes::streaming::tag(&[0]), |_| {
                UnknownTransaction::CannotLookup
            }),
            nom::combinator::map(nom::bytes::streaming::tag(&[1]), |_| {
                UnknownTransaction::NoUnsignedValidator
            }),
            nom::combinator::map(
                nom::sequence::preceded(
                    nom::bytes::streaming::tag(&[2]),
                    nom::bytes::streaming::take(1u32),
                ),
                |n: &[u8]| UnknownTransaction::Custom(n[0]),
            ),
        )),
    )(bytes)
}

fn tags(bytes: &[u8]) -> nom::IResult<&[u8], Vec<Vec<u8>>> {
    nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
        nom::multi::many_m_n(
            num_elems,
            num_elems,
            nom::combinator::map(
                nom::multi::length_data(crate::util::nom_scale_compact_usize),
                |tag| tag.to_owned(),
            ),
        )
    })(bytes)
}
