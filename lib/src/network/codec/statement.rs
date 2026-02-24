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

//! Encoding and decoding of statements for the Statement Store protocol.
//!
//! Statements are encoded as `Vec<Field>` where each field has a discriminant byte
//! followed by field-specific data. Fields must appear in ascending order by discriminant.

use alloc::vec::Vec;

use nom::Finish as _;

/// Maximum size of a statement notification in bytes (1MB).
pub const MAX_STATEMENT_NOTIFICATION_SIZE: usize = 1024 * 1024;

/// Maximum number of topics per statement.
pub const MAX_TOPICS: usize = 4;

/// Statement topic (32 bytes).
pub type Topic = [u8; 32];

/// Decryption key identifier (32 bytes).
pub type DecryptionKey = [u8; 32];

/// Channel identifier (32 bytes).
pub type Channel = [u8; 32];

/// Account identifier (32 bytes).
pub type AccountId = [u8; 32];

/// Block hash (32 bytes).
pub type BlockHash = [u8; 32];

/// A decoded statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementRef<'a> {
    /// Authentication proof for the statement.
    pub proof: Option<ProofRef<'a>>,
    /// Identifier for the key that the data field may be decrypted with.
    pub decryption_key: Option<&'a DecryptionKey>,
    /// Account channel. Only one message per (account, channel) pair is allowed.
    pub channel: Option<&'a Channel>,
    /// Priority when competing with other messages from the same sender.
    pub priority: Option<u32>,
    /// Statement topics (0 to 4).
    pub topics: Vec<&'a Topic>,
    /// Additional data.
    pub data: Option<&'a [u8]>,
}

/// Statement proof variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofRef<'a> {
    /// Sr25519 signature proof.
    Sr25519 {
        /// The signature (64 bytes).
        signature: &'a [u8; 64],
        /// The signer's public key (32 bytes).
        signer: &'a [u8; 32],
    },
    /// Ed25519 signature proof.
    Ed25519 {
        /// The signature (64 bytes).
        signature: &'a [u8; 64],
        /// The signer's public key (32 bytes).
        signer: &'a [u8; 32],
    },
    /// Secp256k1 ECDSA signature proof.
    Secp256k1Ecdsa {
        /// The signature (65 bytes).
        signature: &'a [u8; 65],
        /// The signer's public key (33 bytes).
        signer: &'a [u8; 33],
    },
    /// On-chain event proof.
    OnChain {
        /// Account identifier associated with the event.
        who: &'a AccountId,
        /// Hash of block that contains the event.
        block_hash: &'a BlockHash,
        /// Index of the event in the event list.
        event_index: u64,
    },
}

/// Decodes a statement notification (a list of statements).
pub fn decode_statement_notification(
    scale_encoded: &[u8],
) -> Result<Vec<StatementRef<'_>>, DecodeStatementNotificationError> {
    match nom::Parser::parse(
        &mut nom::combinator::all_consuming::<_, nom::error::Error<&[u8]>, _>(
            nom::combinator::complete(statement_notification_parser),
        ),
        scale_encoded,
    )
    .finish()
    {
        Ok((_, statements)) => Ok(statements),
        Err(err) => Err(DecodeStatementNotificationError(err.code)),
    }
}

/// Error when decoding a statement notification.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
#[display("Failed to decode statement notification")]
pub struct DecodeStatementNotificationError(#[error(not(source))] nom::error::ErrorKind);

/// Decodes a single statement.
pub fn decode_statement(scale_encoded: &[u8]) -> Result<StatementRef<'_>, DecodeStatementError> {
    match nom::Parser::parse(
        &mut nom::combinator::all_consuming::<_, nom::error::Error<&[u8]>, _>(
            nom::combinator::complete(statement_parser),
        ),
        scale_encoded,
    )
    .finish()
    {
        Ok((_, statement)) => Ok(statement),
        Err(err) => Err(DecodeStatementError(err.code)),
    }
}

/// Error when decoding a statement.
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
#[display("Failed to decode statement")]
pub struct DecodeStatementError(#[error(not(source))] nom::error::ErrorKind);

/// Encodes a statement notification (a list of statements).
pub fn encode_statement_notification(statements: &[StatementRef<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(crate::util::encode_scale_compact_usize(statements.len()).as_ref());
    for statement in statements {
        encode_statement_into(statement, &mut out);
    }
    out
}

/// Encodes a single statement.
pub fn encode_statement(statement: &StatementRef<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_statement_into(statement, &mut out);
    out
}

fn encode_statement_into(statement: &StatementRef<'_>, out: &mut Vec<u8>) {
    // Count the number of fields
    let num_fields = statement.proof.is_some() as usize
        + statement.decryption_key.is_some() as usize
        + statement.priority.is_some() as usize
        + statement.channel.is_some() as usize
        + statement.topics.len()
        + statement.data.is_some() as usize;

    out.extend_from_slice(crate::util::encode_scale_compact_usize(num_fields).as_ref());

    // Field 0: Proof
    if let Some(proof) = &statement.proof {
        out.push(0);
        encode_proof_into(proof, out);
    }

    // Field 1: DecryptionKey
    if let Some(key) = statement.decryption_key {
        out.push(1);
        out.extend_from_slice(key);
    }

    // Field 2: Priority
    if let Some(priority) = statement.priority {
        out.push(2);
        out.extend_from_slice(&priority.to_le_bytes());
    }

    // Field 3: Channel
    if let Some(channel) = statement.channel {
        out.push(3);
        out.extend_from_slice(channel);
    }

    // Fields 4-7: Topics
    for (i, topic) in statement.topics.iter().enumerate() {
        out.push(4 + i as u8);
        out.extend_from_slice(*topic);
    }

    // Field 8: Data
    if let Some(data) = statement.data {
        out.push(8);
        out.extend_from_slice(crate::util::encode_scale_compact_usize(data.len()).as_ref());
        out.extend_from_slice(data);
    }
}

fn encode_proof_into(proof: &ProofRef<'_>, out: &mut Vec<u8>) {
    match proof {
        ProofRef::Sr25519 { signature, signer } => {
            out.push(0);
            out.extend_from_slice(*signature);
            out.extend_from_slice(*signer);
        }
        ProofRef::Ed25519 { signature, signer } => {
            out.push(1);
            out.extend_from_slice(*signature);
            out.extend_from_slice(*signer);
        }
        ProofRef::Secp256k1Ecdsa { signature, signer } => {
            out.push(2);
            out.extend_from_slice(*signature);
            out.extend_from_slice(*signer);
        }
        ProofRef::OnChain {
            who,
            block_hash,
            event_index,
        } => {
            out.push(3);
            out.extend_from_slice(*who);
            out.extend_from_slice(*block_hash);
            out.extend_from_slice(&event_index.to_le_bytes());
        }
    }
}

// Nom parsers

fn statement_notification_parser(input: &[u8]) -> nom::IResult<&[u8], Vec<StatementRef<'_>>> {
    let (input, num_statements) = crate::util::nom_scale_compact_usize(input)?;
    nom::Parser::parse(
        &mut nom::multi::many_m_n(num_statements, num_statements, statement_parser),
        input,
    )
}

fn statement_parser(input: &[u8]) -> nom::IResult<&[u8], StatementRef<'_>> {
    let (input, num_fields) = crate::util::nom_scale_compact_usize(input)?;
    fields_parser(num_fields)(input)
}

fn fields_parser(num_fields: usize) -> impl FnMut(&[u8]) -> nom::IResult<&[u8], StatementRef<'_>> {
    move |mut input: &[u8]| {
        let mut statement = StatementRef {
            proof: None,
            decryption_key: None,
            channel: None,
            priority: None,
            topics: Vec::new(),
            data: None,
        };

        let mut last_tag: Option<u8> = None;

        for _ in 0..num_fields {
            let (rest, tag) = nom::number::streaming::u8(input)?;

            // Ensure fields are in ascending order
            if let Some(lt) = last_tag {
                if tag <= lt {
                    return Err(nom::Err::Failure(nom::error::make_error(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
            }
            last_tag = Some(tag);

            let rest = match tag {
                0 => {
                    let (rest, proof) = proof_parser(rest)?;
                    statement.proof = Some(proof);
                    rest
                }
                1 => {
                    let (rest, key) = nom::bytes::streaming::take(32u32)(rest)?;
                    statement.decryption_key = Some(<&[u8; 32]>::try_from(key).unwrap());
                    rest
                }
                2 => {
                    let (rest, priority) = nom::number::streaming::le_u32(rest)?;
                    statement.priority = Some(priority);
                    rest
                }
                3 => {
                    let (rest, channel) = nom::bytes::streaming::take(32u32)(rest)?;
                    statement.channel = Some(<&[u8; 32]>::try_from(channel).unwrap());
                    rest
                }
                4..=7 => {
                    let topic_index = (tag - 4) as usize;
                    if topic_index != statement.topics.len() {
                        return Err(nom::Err::Failure(nom::error::make_error(
                            input,
                            nom::error::ErrorKind::Verify,
                        )));
                    }
                    let (rest, topic) = nom::bytes::streaming::take(32u32)(rest)?;
                    statement.topics.push(<&[u8; 32]>::try_from(topic).unwrap());
                    rest
                }
                8 => {
                    let (rest, len) = crate::util::nom_scale_compact_usize(rest)?;
                    let (rest, data) = nom::bytes::streaming::take(len)(rest)?;
                    statement.data = Some(data);
                    rest
                }
                _ => {
                    return Err(nom::Err::Failure(nom::error::make_error(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
            };

            input = rest;
        }

        Ok((input, statement))
    }
}

fn proof_parser(input: &[u8]) -> nom::IResult<&[u8], ProofRef<'_>> {
    let (input, variant) = nom::number::streaming::u8(input)?;
    match variant {
        0 => {
            // Sr25519
            let (input, signature) = nom::bytes::streaming::take(64u32)(input)?;
            let (input, signer) = nom::bytes::streaming::take(32u32)(input)?;
            Ok((
                input,
                ProofRef::Sr25519 {
                    signature: <&[u8; 64]>::try_from(signature).unwrap(),
                    signer: <&[u8; 32]>::try_from(signer).unwrap(),
                },
            ))
        }
        1 => {
            // Ed25519
            let (input, signature) = nom::bytes::streaming::take(64u32)(input)?;
            let (input, signer) = nom::bytes::streaming::take(32u32)(input)?;
            Ok((
                input,
                ProofRef::Ed25519 {
                    signature: <&[u8; 64]>::try_from(signature).unwrap(),
                    signer: <&[u8; 32]>::try_from(signer).unwrap(),
                },
            ))
        }
        2 => {
            // Secp256k1Ecdsa
            let (input, signature) = nom::bytes::streaming::take(65u32)(input)?;
            let (input, signer) = nom::bytes::streaming::take(33u32)(input)?;
            Ok((
                input,
                ProofRef::Secp256k1Ecdsa {
                    signature: <&[u8; 65]>::try_from(signature).unwrap(),
                    signer: <&[u8; 33]>::try_from(signer).unwrap(),
                },
            ))
        }
        3 => {
            // OnChain
            let (input, who) = nom::bytes::streaming::take(32u32)(input)?;
            let (input, block_hash) = nom::bytes::streaming::take(32u32)(input)?;
            let (input, event_index) = nom::number::streaming::le_u64(input)?;
            Ok((
                input,
                ProofRef::OnChain {
                    who: <&[u8; 32]>::try_from(who).unwrap(),
                    block_hash: <&[u8; 32]>::try_from(block_hash).unwrap(),
                    event_index,
                },
            ))
        }
        _ => Err(nom::Err::Failure(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty_statement() {
        // Compact(0) - no fields
        let encoded = [0u8];
        let statement = decode_statement(&encoded).unwrap();
        assert!(statement.proof.is_none());
        assert!(statement.decryption_key.is_none());
        assert!(statement.channel.is_none());
        assert!(statement.priority.is_none());
        assert!(statement.topics.is_empty());
        assert!(statement.data.is_none());
    }

    #[test]
    fn decode_statement_with_priority() {
        // Compact(1), Field::Priority(2), value 42
        let mut encoded = vec![4u8]; // Compact(1)
        encoded.push(2); // Field discriminant for Priority
        encoded.extend_from_slice(&42u32.to_le_bytes());

        let statement = decode_statement(&encoded).unwrap();
        assert_eq!(statement.priority, Some(42));
    }

    #[test]
    fn decode_statement_with_topics() {
        let topic1 = [1u8; 32];
        let topic2 = [2u8; 32];

        // Compact(2), Topic1, Topic2
        let mut encoded = vec![8u8]; // Compact(2)
        encoded.push(4); // Field discriminant for Topic1
        encoded.extend_from_slice(&topic1);
        encoded.push(5); // Field discriminant for Topic2
        encoded.extend_from_slice(&topic2);

        let statement = decode_statement(&encoded).unwrap();
        assert_eq!(statement.topics.len(), 2);
        assert_eq!(statement.topics[0], &topic1);
        assert_eq!(statement.topics[1], &topic2);
    }

    #[test]
    fn decode_statement_with_data() {
        let data = b"hello world";

        // Compact(1), Field::Data(8), Compact(len), data
        let mut encoded = vec![4u8]; // Compact(1)
        encoded.push(8); // Field discriminant for Data
        encoded.push(data.len() as u8 * 4); // Compact length
        encoded.extend_from_slice(data);

        let statement = decode_statement(&encoded).unwrap();
        assert_eq!(statement.data, Some(data.as_slice()));
    }

    #[test]
    fn decode_statement_with_sr25519_proof() {
        let signature = [0xAAu8; 64];
        let signer = [0xBBu8; 32];

        // Compact(1), Field::AuthenticityProof(0), Proof::Sr25519(0), signature, signer
        let mut encoded = vec![4u8]; // Compact(1)
        encoded.push(0); // Field discriminant for AuthenticityProof
        encoded.push(0); // Proof variant: Sr25519
        encoded.extend_from_slice(&signature);
        encoded.extend_from_slice(&signer);

        let statement = decode_statement(&encoded).unwrap();
        assert!(matches!(
            statement.proof,
            Some(ProofRef::Sr25519 { signature: s, signer: p })
            if s == &signature && p == &signer
        ));
    }

    #[test]
    fn decode_statement_with_onchain_proof() {
        let who = [0xAAu8; 32];
        let block_hash = [0xBBu8; 32];
        let event_index = 42u64;

        // Compact(1), Field::AuthenticityProof(0), Proof::OnChain(3), who, block_hash, event_index
        let mut encoded = vec![4u8]; // Compact(1)
        encoded.push(0); // Field discriminant for AuthenticityProof
        encoded.push(3); // Proof variant: OnChain
        encoded.extend_from_slice(&who);
        encoded.extend_from_slice(&block_hash);
        encoded.extend_from_slice(&event_index.to_le_bytes());

        let statement = decode_statement(&encoded).unwrap();
        assert!(matches!(
            statement.proof,
            Some(ProofRef::OnChain { who: w, block_hash: bh, event_index: ei })
            if w == &who && bh == &block_hash && ei == 42
        ));
    }

    #[test]
    fn decode_statement_notification_empty() {
        // Compact(0) - no statements
        let encoded = [0u8];
        let statements = decode_statement_notification(&encoded).unwrap();
        assert!(statements.is_empty());
    }

    #[test]
    fn decode_statement_notification_single() {
        // Compact(1), then one empty statement (Compact(0))
        let encoded = [4u8, 0u8]; // Compact(1), Compact(0)
        let statements = decode_statement_notification(&encoded).unwrap();
        assert_eq!(statements.len(), 1);
    }

    #[test]
    fn encode_decode_roundtrip_empty() {
        let statement = StatementRef {
            proof: None,
            decryption_key: None,
            channel: None,
            priority: None,
            topics: Vec::new(),
            data: None,
        };

        let encoded = encode_statement(&statement);
        let decoded = decode_statement(&encoded).unwrap();
        assert_eq!(decoded, statement);
    }

    #[test]
    fn encode_decode_roundtrip_full() {
        let signature = [0xAAu8; 64];
        let signer = [0xBBu8; 32];
        let decryption_key = [0xCCu8; 32];
        let channel = [0xDDu8; 32];
        let topic1 = [0x11u8; 32];
        let topic2 = [0x22u8; 32];
        let data = b"test data";

        let statement = StatementRef {
            proof: Some(ProofRef::Sr25519 {
                signature: &signature,
                signer: &signer,
            }),
            decryption_key: Some(&decryption_key),
            channel: Some(&channel),
            priority: Some(100),
            topics: vec![&topic1, &topic2],
            data: Some(data.as_slice()),
        };

        let encoded = encode_statement(&statement);
        let decoded = decode_statement(&encoded).unwrap();
        assert_eq!(decoded.priority, statement.priority);
        assert_eq!(decoded.topics.len(), statement.topics.len());
        assert_eq!(decoded.data, statement.data);
        assert!(decoded.proof.is_some());
        assert!(decoded.decryption_key.is_some());
        assert!(decoded.channel.is_some());
    }

    #[test]
    fn reject_out_of_order_fields() {
        // Compact(2), Priority(2), then DecryptionKey(1) - wrong order
        let mut encoded = vec![8u8]; // Compact(2)
        encoded.push(2); // Field discriminant for Priority
        encoded.extend_from_slice(&42u32.to_le_bytes());
        encoded.push(1); // Field discriminant for DecryptionKey (should come before Priority)
        encoded.extend_from_slice(&[0u8; 32]);

        assert!(decode_statement(&encoded).is_err());
    }

    #[test]
    fn reject_duplicate_fields() {
        // Compact(2), Priority(2), Priority(2) - duplicate
        let mut encoded = vec![8u8]; // Compact(2)
        encoded.push(2); // Field discriminant for Priority
        encoded.extend_from_slice(&42u32.to_le_bytes());
        encoded.push(2); // Field discriminant for Priority again
        encoded.extend_from_slice(&43u32.to_le_bytes());

        assert!(decode_statement(&encoded).is_err());
    }
}
