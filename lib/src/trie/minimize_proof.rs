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

use crate::trie::{
    bytes_to_nibbles,
    proof_decode::{self, DecodedTrieProof, StorageValue},
    proof_encode::ProofBuilder,
};
use alloc::vec::Vec;
use hashbrown::HashSet;

pub use proof_decode::ParseError;

/// Error potentially returned by [`minimize_proof`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum MinimizeProofError {
    /// Desired key can't be found in the proof.
    KeyNotFound,
    /// Proof doesn't contain enough information and isn't valid.
    IncompleteProof,
}

/// Minimizes a single-key proof, removing all entries that are not related to the proof for
/// that key.
///
/// Returns the resulting proof, encoded.
pub fn minimize_proof<T: AsRef<[u8]>>(
    decoded_proof: &DecodedTrieProof<T>,
    trie_root_merkle_value: &[u8; 32],
    key: &[u8],
) -> Result<Vec<u8>, MinimizeProofError> {
    let mut builder = ProofBuilder::new();

    let mut key_nibbles_if_first_iter =
        Some(bytes_to_nibbles(key.iter().copied()).collect::<Vec<_>>());

    // Query a missing node and provide its value. Stop when the proof is complete.
    loop {
        let Some(missing) = builder
            .missing_node_values()
            .next()
            .map(|v| Vec::from(v))
            .or_else(|| key_nibbles_if_first_iter.take())
        else {
            break;
        };

        if let Some(ancestor_key) = decoded_proof
            .closest_ancestor_in_proof(trie_root_merkle_value, missing.iter().copied())
            .map_err(|_| MinimizeProofError::KeyNotFound)?
        {
            let ancestor = decoded_proof
                .proof_entry(trie_root_merkle_value, ancestor_key)
                .unwrap();
            builder.set_node_value(
                &missing,
                ancestor.node_value,
                match ancestor.trie_node_info.storage_value {
                    StorageValue::Known { value, .. } => Some(value),
                    _ => None,
                },
            );
        } else {
            // Add the root node in the output.
            // This should only ever happen if the input key is completely outside of the trie.
            debug_assert!(itertools::equal(
                missing.iter().copied(),
                bytes_to_nibbles(key.iter().copied())
            ));
            let root = decoded_proof
                .trie_root_proof_entry(trie_root_merkle_value)
                .ok_or(MinimizeProofError::KeyNotFound)?;
            builder.set_node_value(&missing, root.node_value, None);
        };
    }

    Ok(builder.build_to_vec())
}

/// Merges multiple proofs into a single one, removing common entries.
pub fn merge_proofs<'a>(mut proofs: impl Iterator<Item = &'a [u8]>) -> Result<Vec<u8>, ParseError> {
    // Decode each element of `proofs` and collect the entries in a `HashSet`.
    let entries = proofs.try_fold(
        HashSet::with_hasher(fnv::FnvBuildHasher::default()),
        |mut acc, proof| {
            let proof_entries = proof_decode::decode_proof(&proof)?;
            acc.extend(proof_entries);
            Ok(acc)
        },
    )?;

    // Encode the output proof.
    let mut ret = Vec::with_capacity(8 + entries.iter().map(|e| e.len() + 8).sum::<usize>());
    ret.extend_from_slice(crate::util::encode_scale_compact_usize(entries.len()).as_ref());
    for entry in entries {
        ret.extend_from_slice(crate::util::encode_scale_compact_usize(entry.len()).as_ref());
        ret.extend_from_slice(entry);
    }
    Ok(ret)
}
