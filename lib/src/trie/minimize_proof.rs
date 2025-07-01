use hashbrown::HashSet;
use itertools::Itertools;

use crate::trie::{
    bytes_to_nibbles,
    proof_decode::{DecodedTrieProof, StorageValue},
    proof_encode::ProofBuilder,
};
use alloc::vec::Vec;

pub enum MinimizeProofError {
    KeyDoesNotMatch,
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
        .ok_or(MinimizeProofError::KeyDoesNotMatch)?
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
    let mut maybe_missing = builder.missing_node_values().next().map(|v| Vec::from(v));
    while let Some(ref missing) = maybe_missing {
        let value = decoded_proof
            .trie_node_info(trie_root_merkle_value, missing.iter().copied())
            .map_err(|_| MinimizeProofError::IncompleteProof)?
            .node_value;
        builder.set_node_value(&missing, value, None);
        maybe_missing = builder.missing_node_values().next().map(|v| Vec::from(v));
    }

    Ok(builder.build_to_vec())
}

pub struct ParseError {}

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
            .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ParseError {})?;

            acc.extend(proof_entries);
            Ok(acc)
        })
        .map(|merged_entries| merged_entries.into_iter().map(|v| Vec::from(v)).collect())
}
