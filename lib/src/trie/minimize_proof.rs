// Smoldot
// Copyright (C) 2025  Pierre Krieger
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

use hashbrown::HashSet;
use itertools::Itertools as _;

use crate::trie::{
    bytes_to_nibbles,
    proof_decode::{DecodedTrieProof, StorageValue},
    proof_encode::ProofBuilder,
};
use alloc::vec::Vec;

/// Error potentially returned by [`minimize_proof`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum MinimizeProofError {
    /// Desired key can't be found in the proof.
    KeyNotFound,
    /// Proof doesn't contain enough information and isn't valid.
    IncompleteProof,
}

/// Minimizes a single-key proof, removing all entries that are not related to
/// the proof for that key.
///
/// Returns the resulting proof encoded
pub fn minimize_proof<T: AsRef<[u8]>>(
    decoded_proof: &DecodedTrieProof<T>,
    trie_root_merkle_value: &[u8; 32],
    key: &[u8],
) -> Result<Vec<u8>, MinimizeProofError> {
    let mut builder = ProofBuilder::new();

    let nibbles = decoded_proof
        .closest_ancestor_in_proof(
            trie_root_merkle_value,
            bytes_to_nibbles(key.iter().copied()),
        )
        .map_err(|_| MinimizeProofError::IncompleteProof)?
        .ok_or(MinimizeProofError::KeyNotFound)?
        .collect_vec();

    // Set the node value of the leaf
    let node = decoded_proof
        .trie_node_info(trie_root_merkle_value, nibbles.iter().cloned())
        .map_err(|_| MinimizeProofError::IncompleteProof)?;
    let storage_value = match node.storage_value {
        StorageValue::Known { value, .. } => Some(value),
        _ => None,
    };
    builder.set_node_value(&nibbles, node.node_value, storage_value);

    // Query a missing node and provide its value. Stop when the proof is complete.
    loop {
        let Some(missing) = builder.missing_node_values().next().map(|v| Vec::from(v)) else {
            break;
        };
        let value = decoded_proof
            .trie_node_info(trie_root_merkle_value, missing.iter().copied())
            .map_err(|_| MinimizeProofError::IncompleteProof)?
            .node_value;
        builder.set_node_value(&missing, value, None);
    }

    Ok(builder.build_to_vec())
}

/// Failed to parse one of the input proofs.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub struct ParseError();

/// Merges multiple proofs into a single one, removing common entries
pub fn merge_proofs<'a>(proofs: &Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, ParseError> {
    proofs
        .into_iter()
        .try_fold(HashSet::new(), |mut acc, proof| {
            let (_, proof_entries) = nom::Parser::parse(
                &mut nom::combinator::all_consuming(nom::combinator::flat_map(
                    crate::util::nom_scale_compact_usize,
                    |num_elems| {
                        nom::multi::many_m_n(num_elems, num_elems, crate::util::nom_bytes_decode)
                    },
                )),
                proof,
            )
            .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ParseError())?;

            acc.extend(proof_entries);
            Ok(acc)
        })
        .map(|merged_entries| merged_entries.into_iter().map(|v| Vec::from(v)).collect())
}
