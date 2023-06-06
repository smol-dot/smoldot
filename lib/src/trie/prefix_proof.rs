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

//! Scanning, through trie proofs, the list of all keys that share a certain prefix.
//!
//! This module is a helper whose objective is to find out the list of all keys that start with
//! a certain prefix by performing storage proofs.
//!
//! The total number of storage proofs required is equal to the maximum depth of the tree below
//! the requested prefix, plus one. For example, if a tree has the nodes `[1, 5]`, `[1, 5, 8, 9]`,
//! and `[1, 5, 8, 9, 2]`, then four queries are necessary to find all the keys whose prefix
//! is `[1]`.

// TODO: usage example

use super::{nibble, proof_decode};

use alloc::{borrow::ToOwned as _, vec, vec::Vec};
use core::{fmt, iter, mem};

mod tests;

/// Configuration to pass to [`prefix_scan`].
pub struct Config<'a> {
    /// Prefix that all the keys must share.
    pub prefix: &'a [u8],

    /// Merkle value (or node value) of the root node of the trie.
    ///
    /// > **Note**: The Merkle value and node value are always the same for the root node.
    pub trie_root_hash: [u8; 32],
}

/// Start a new scanning process.
pub fn prefix_scan(config: Config<'_>) -> PrefixScan {
    PrefixScan {
        trie_root_hash: config.trie_root_hash,
        next_queries: vec![(
            nibble::bytes_to_nibbles(config.prefix.iter().copied()).collect(),
            QueryTy::Exact,
        )],
        final_result: Vec::with_capacity(32),
    }
}

/// Scan of a prefix in progress.
pub struct PrefixScan {
    trie_root_hash: [u8; 32],
    // TODO: we have lots of Vecs here; maybe find a way to optimize
    next_queries: Vec<(Vec<nibble::Nibble>, QueryTy)>,
    // TODO: we have lots of Vecs here; maybe find a way to optimize
    final_result: Vec<Vec<u8>>,
}

#[derive(Copy, Clone, Debug)]
enum QueryTy {
    /// Expect to find a trie node with this exact key.
    Exact,
    /// The last nibble of the key is a dummy to force the remote to prove to us either that this
    /// node exists or that this node doesn't exist, and if it doesn't exist prove it by including
    /// the "actual" child that we're looking for in the proof.
    /// It is guaranteed that the trie contains a node whose key is the requested key without its
    /// last nibble.
    Direction,
}

impl PrefixScan {
    /// Returns the list of keys whose storage proof must be queried.
    pub fn requested_keys(
        &'_ self,
    ) -> impl Iterator<Item = impl Iterator<Item = nibble::Nibble> + '_> + '_ {
        self.next_queries.iter().map(|(l, _)| l.iter().copied())
    }

    /// Injects the proof presumably containing the keys returned by [`PrefixScan::requested_keys`].
    ///
    /// Returns an error if the proof is invalid. In that case, `self` isn't modified.
    pub fn resume(mut self, proof: &[u8]) -> Result<ResumeOutcome, (Self, Error)> {
        let decoded_proof = match proof_decode::decode_and_verify_proof(proof_decode::Config {
            proof,
            trie_root_hash: &self.trie_root_hash,
        }) {
            Ok(d) => d,
            Err(err) => return Err((self, Error::InvalidProof(err))),
        };

        let mut non_terminal_queries = mem::take(&mut self.next_queries);

        // The entire body is executed as long as verifying at least one proof succeeds.
        for is_first_iteration in iter::once(true).chain(iter::repeat(false)) {
            // Filled with the queries to perform at the next iteration.
            // Capacity assumes a maximum of 2 children per node on average. This value was chosen
            // completely arbitrarily.
            let mut next = Vec::with_capacity(non_terminal_queries.len() * 2);

            debug_assert!(!non_terminal_queries.is_empty());
            while let Some((query_key, query_ty)) = non_terminal_queries.pop() {
                // Get the information from the proof about this key.
                // If the query type is "direction", then instead we look up the parent (that we
                // know for sure exists in the trie) then find the child.
                let info = {
                    let info_of_node = match query_ty {
                        QueryTy::Exact => &query_key[..],
                        QueryTy::Direction => &query_key[..query_key.len() - 1],
                    };

                    match (
                        decoded_proof.trie_node_info(&self.trie_root_hash, info_of_node),
                        query_ty,
                    ) {
                        (Some(info), QueryTy::Exact) => info,
                        (Some(info), QueryTy::Direction) => {
                            match info.children.child(query_key[query_key.len() - 1]) {
                                proof_decode::Child::InProof { child_key, .. } => {
                                    // Rather than complicate this code, we just add the child to
                                    // `next` (this time an `Exact` query) and process it during
                                    // the next iteration.
                                    next.push((child_key.to_owned(), QueryTy::Exact));
                                    continue;
                                }
                                proof_decode::Child::AbsentFromProof { .. }
                                    if !is_first_iteration =>
                                {
                                    // Node not in the proof. There's no point in adding this node
                                    // to `next` as we will fail again if we try to verify the
                                    // proof again.
                                    // If `is_first_iteration`, it means that the proof is
                                    // incorrect.
                                    self.next_queries.push((query_key, QueryTy::Direction));
                                    continue;
                                }
                                proof_decode::Child::AbsentFromProof { .. } => {
                                    // Push all the non-processed queries back to `next_queries`
                                    // before returning the error, so that we can try again.
                                    self.next_queries.push((query_key, QueryTy::Direction));
                                    self.next_queries.extend(non_terminal_queries);
                                    return Err((self, Error::MissingProofEntry));
                                }
                                proof_decode::Child::NoChild => {
                                    // We know for sure that there is a child in this direction,
                                    // otherwise the query wouldn't have been added to this
                                    // state machine.
                                    unreachable!()
                                }
                            }
                        }
                        (None, _) if !is_first_iteration => {
                            // Node not in the proof. There's no point in adding this node to `next`
                            // as we will fail again if we try to verify the proof again.
                            // If `is_first_iteration`, it means that the proof is incorrect.
                            self.next_queries.push((query_key, query_ty));
                            continue;
                        }
                        (None, _) => {
                            // Push all the non-processed queries back to `next_queries` before
                            // returning the error, so that we can try again.
                            self.next_queries.push((query_key, query_ty));
                            self.next_queries.extend(non_terminal_queries);
                            return Err((self, Error::MissingProofEntry));
                        }
                    }
                };

                if matches!(
                    info.storage_value,
                    proof_decode::StorageValue::Known { .. }
                        | proof_decode::StorageValue::HashKnownValueMissing(_)
                ) {
                    // Trie nodes with a value are always aligned to "bytes-keys". In other words,
                    // the number of nibbles is always even.
                    debug_assert_eq!(query_key.len() % 2, 0);
                    let key = query_key
                        .chunks(2)
                        .map(|n| (u8::from(n[0]) << 4) | u8::from(n[1]))
                        .collect::<Vec<_>>();

                    // Insert in final results, making sure we check for duplicates.
                    debug_assert!(!self.final_result.iter().any(|n| *n == key));
                    self.final_result.push(key);
                }

                // For each child of the node, put into `next` the key that goes towards this
                // child.
                for (nibble, child) in info.children.children().enumerate() {
                    match child {
                        proof_decode::Child::NoChild => continue,
                        proof_decode::Child::AbsentFromProof { .. } => {
                            let mut direction = query_key.clone();
                            direction.push(
                                nibble::Nibble::try_from(u8::try_from(nibble).unwrap()).unwrap(),
                            );
                            next.push((direction, QueryTy::Direction));
                        }
                        proof_decode::Child::InProof { child_key, .. } => {
                            next.push((child_key.to_owned(), QueryTy::Exact))
                        }
                    }
                }
            }

            // Finished when nothing more to request.
            if next.is_empty() && self.next_queries.is_empty() {
                return Ok(ResumeOutcome::Success {
                    keys: self.final_result,
                });
            }

            // If we have failed to make any progress during this iteration, return `InProgress`.
            if next.is_empty() {
                debug_assert!(!self.next_queries.is_empty());
                // Errors are immediately returned if `is_first_iteration`.
                debug_assert!(!is_first_iteration);
                break;
            }

            // Update `non_terminal_queries` for the next iteration.
            non_terminal_queries = next;
        }

        Ok(ResumeOutcome::InProgress(self))
    }
}

impl fmt::Debug for PrefixScan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PrefixScan").finish()
    }
}

/// Outcome of calling [`PrefixScan::resume`].
#[derive(Debug)]
pub enum ResumeOutcome {
    /// Scan must continue with the next storage proof query.
    InProgress(PrefixScan),
    /// Scan has succeeded.
    Success {
        /// List of keys with the requested prefix.
        keys: Vec<Vec<u8>>,
    },
}

/// Possible error returned by [`PrefixScan::resume`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// The proof has an invalid format.
    #[display(fmt = "{_0}")]
    InvalidProof(proof_decode::Error),
    /// One or more entries in the proof are missing.
    MissingProofEntry,
}
