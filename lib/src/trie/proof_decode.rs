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

//! Decodes and verifies a trie proof.
//!
//! A trie proof is a proof that a certain key in the trie has a certain storage value (or lacks
//! a storage value). The proof can be verified by knowing only the Merkle value of the root node.
//!
//! # Details
//!
//! > **Note**: For reminder, the Merkle value of a node is the hash of its node value, or the
//! >           node value directly if its length is smaller than 32 bytes.
//!
//! A trie proof consists in a list of node values of nodes in the trie. For the proof to be valid,
//! the hash of one of these node values must match the expected trie root node value. Since a
//! node value contains the Merkle values of the children of the node, it is possible to iterate
//! down the hierarchy of nodes until the one closest to the desired key is found.
//!
//! # Usage
//!
//! This modules provides the [`decode_and_verify_proof`] function that decodes a proof and
//! verifies whether it is correct.
//!
//! Once decoded, one can examine the content of the proof, in other words the list of storage
//! items and values.

use super::{nibble, trie_node, TrieEntryVersion};

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{fmt, iter, mem, ops};

/// Configuration to pass to [`decode_and_verify_proof`].
pub struct Config<I> {
    /// List of node values of nodes found in the trie. At least one entry corresponding to the
    /// root node of the trie must be present in order for the verification to succeed.
    pub proof: I,
}

/// Verifies whether a proof is correct and returns an object that allows examining its content.
///
/// The proof is then stored within the [`DecodedTrieProof`].
///
/// Due to the generic nature of this function, the proof can be either a `Vec<u8>` or a `&[u8]`.
///
/// Returns an error if the proof is invalid, or if the proof contains entries that are
/// disconnected from the root node of the trie.
pub fn decode_and_verify_proof<T>(config: Config<T>) -> Result<DecodedTrieProof<T>, Error>
where
    T: AsRef<[u8]>,
{
    // Call `as_ref()` once at the beginning in order to guarantee stability of the memory
    // location.
    let proof_as_ref = config.proof.as_ref();

    // A Merkle proof is a SCALE-encoded `Vec<Vec<u8>>`.
    //
    // This `Vec` contains two types of items: trie node values, and standalone storage items. In
    // both cases, we will later need a hashed version of them. Create a list of hashes, one per
    // entry in `proof`.
    //
    // This hashmap uses a FNV hasher, theoretically vulnerable to HashDos attacks. While it is
    // possible for an attacker to craft a proof that leads to all entries being in the same
    // bucket, this proof is going to be invalid (unless the blake2 hash function is broken, which
    // we assume it isn't). So while an attacker can slightly increase the time that this function
    // takes, it is always cause this function to return an error and is actually likely to make
    // the function actually take less time than if it was a legitimate proof.
    let merkle_values = {
        // TODO: don't use a Vec?
        let (_, decoded_proof) = nom::combinator::all_consuming(nom::combinator::flat_map(
            crate::util::nom_scale_compact_usize,
            |num_elems| nom::multi::many_m_n(num_elems, num_elems, crate::util::nom_bytes_decode),
        ))(config.proof.as_ref())
        .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::InvalidFormat)?;

        let merkle_values = decoded_proof
            .iter()
            .copied()
            .enumerate()
            .map(
                |(proof_entry_num, proof_entry)| -> ([u8; 32], (usize, ops::Range<usize>)) {
                    // The merkle value of a trie node is normally either its hash or the node
                    // itself if its length is < 32. In the context of a proof, however, nodes
                    // whose length is < 32 aren't supposed to be their own entry. For this reason,
                    // we only hash each entry.
                    let hash = *<&[u8; 32]>::try_from(
                        blake2_rfc::blake2b::blake2b(32, &[], proof_entry).as_bytes(),
                    )
                    .unwrap();

                    let proof_entry_offset = if proof_entry.is_empty() {
                        0
                    } else {
                        proof_entry.as_ptr() as usize - proof_as_ref.as_ptr() as usize
                    };

                    (
                        hash,
                        (
                            proof_entry_num,
                            proof_entry_offset..(proof_entry_offset + proof_entry.len()),
                        ),
                    )
                },
            )
            .collect::<hashbrown::HashMap<_, _, fnv::FnvBuildHasher>>();

        // Using a hashmap has the consequence that if multiple proof entries were identical, only
        // one would be tracked. For this reason, we make sure that the proof doesn't contain
        // multiple identical entries.
        if merkle_values.len() != decoded_proof.len() {
            return Err(Error::DuplicateProofEntry);
        }

        merkle_values
    };

    // Dummy empty proofs are always valid.
    if merkle_values.is_empty() {
        return Ok(DecodedTrieProof {
            proof: config.proof,
            entries: BTreeMap::new(),
        });
    }

    // Start by iterating over each element of the proof, and keep track of elements that are
    // decodable but aren't mentioned in any other element. This gives us the tries roots.
    let trie_roots = {
        let mut maybe_trie_roots = merkle_values
            .keys()
            .collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();
        for (hash, (_, proof_entry_range)) in merkle_values.iter() {
            let node_value = &config.proof.as_ref()[proof_entry_range.clone()];
            let Ok(decoded) = trie_node::decode(node_value) else {
                maybe_trie_roots.remove(hash);
                continue;
            };
            for child in decoded.children.into_iter().flatten() {
                if let Ok(child) = &<[u8; 32]>::try_from(child) {
                    maybe_trie_roots.remove(child);
                }
            }
        }
        maybe_trie_roots
    };

    // The implementation below iterates down the tree of nodes represented by this proof, keeping
    // note of the traversed elements.

    // Keep track of all the entries found in the proof.
    let mut entries = BTreeMap::new();

    // Keep track of the proof entries that haven't been visited when traversing.
    let mut unvisited_proof_entries =
        (0..merkle_values.len()).collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();

    // We repeat this operation for every trie root.
    for trie_root_hash in trie_roots {
        // Find the expected trie root in the proof. This is the starting point of the verification.
        let mut remain_iterate = {
            let (root_position, root_range) =
                merkle_values.get(&trie_root_hash[..]).unwrap().clone();
            let _ = unvisited_proof_entries.remove(&root_position);
            vec![(root_range, Vec::new())]
        };

        while !remain_iterate.is_empty() {
            // Iterate through each entry in `remain_iterate`.
            // This clears `remain_iterate` so that we can add new entries to it during the iteration.
            for (proof_entry_range, storage_key_before_partial) in
                mem::replace(&mut remain_iterate, Vec::with_capacity(merkle_values.len()))
            {
                // Decodes the proof entry.
                let proof_entry = &proof_as_ref[proof_entry_range.clone()];
                let decoded_node_value =
                    trie_node::decode(proof_entry).map_err(Error::InvalidNodeValue)?;
                let decoded_node_value_children_bitmap = decoded_node_value.children_bitmap();

                // Build the storage key of the node.
                let storage_key = {
                    let mut storage_key_after_partial = Vec::with_capacity(
                        storage_key_before_partial.len() + decoded_node_value.partial_key.len(),
                    );
                    storage_key_after_partial.extend_from_slice(&storage_key_before_partial);
                    storage_key_after_partial.extend(decoded_node_value.partial_key);
                    storage_key_after_partial
                };

                // Add the children to `remain_iterate`.
                for (child_num, child_node_value) in
                    decoded_node_value.children.into_iter().enumerate()
                {
                    // Ignore missing children slots.
                    let child_node_value = match child_node_value {
                        None => continue,
                        Some(v) => v,
                    };

                    debug_assert!(child_num < 16);
                    let child_nibble =
                        nibble::Nibble::try_from(u8::try_from(child_num).unwrap()).unwrap();

                    // Key of the child node before its partial key.
                    let mut child_storage_key_before_partial =
                        Vec::with_capacity(storage_key.len() + 1);
                    child_storage_key_before_partial.extend_from_slice(&storage_key);
                    child_storage_key_before_partial.push(child_nibble);

                    // The value of the child node is either directly inlined (if less than 32 bytes)
                    // or is a hash.
                    if child_node_value.len() < 32 {
                        let offset = proof_entry_range.start
                            + if !child_node_value.is_empty() {
                                child_node_value.as_ptr() as usize - proof_entry.as_ptr() as usize
                            } else {
                                0
                            };
                        debug_assert!(offset == 0 || offset >= proof_entry_range.start);
                        debug_assert!(offset <= (proof_entry_range.start + proof_entry.len()));
                        remain_iterate.push((
                            offset..(offset + child_node_value.len()),
                            child_storage_key_before_partial,
                        ));
                    } else {
                        // The decoding API guarantees that the child value is never larger than
                        // 32 bytes.
                        debug_assert_eq!(child_node_value.len(), 32);
                        if let Some((child_position, child_entry_range)) =
                            merkle_values.get(child_node_value)
                        {
                            // If the node value of the child is less than 32 bytes long, it should
                            // have been inlined instead of given separately.
                            if child_entry_range.end - child_entry_range.start < 32 {
                                return Err(Error::UnexpectedHashedNode);
                            }

                            // Remove the entry from `unvisited_proof_entries`.
                            // Note that it is questionable what to do if the same entry is visited
                            // multiple times. In case where multiple storage branches are identical,
                            // the sender of the proof should de-duplicate the identical nodes. For
                            // this reason, it could be legitimate for the same proof entry to be
                            // visited multiple times.
                            let _ = unvisited_proof_entries.remove(child_position);
                            remain_iterate.push((
                                child_entry_range.clone(),
                                child_storage_key_before_partial,
                            ));
                        }
                    }
                }

                // Insert the node into `entries`.
                // This is done at the end so that `storage_key` doesn't need to be cloned.
                let _prev_value = entries.insert((*trie_root_hash, storage_key), {
                    let storage_value = match decoded_node_value.storage_value {
                        trie_node::StorageValue::None => StorageValueInner::None,
                        trie_node::StorageValue::Hashed(value_hash) => {
                            if let Some((value_position, value_entry_range)) =
                                merkle_values.get(&value_hash[..])
                            {
                                let _ = unvisited_proof_entries.remove(value_position);
                                StorageValueInner::Known {
                                    is_inline: false,
                                    offset: value_entry_range.start,
                                    len: value_entry_range.end - value_entry_range.start,
                                }
                            } else {
                                let offset =
                                    value_hash.as_ptr() as usize - proof_as_ref.as_ptr() as usize;
                                debug_assert!(offset >= proof_entry_range.start);
                                debug_assert!(
                                    offset <= (proof_entry_range.start + proof_entry.len())
                                );
                                StorageValueInner::HashKnownValueMissing { offset }
                            }
                        }
                        trie_node::StorageValue::Unhashed(v) => {
                            let offset = if !v.is_empty() {
                                v.as_ptr() as usize - proof_as_ref.as_ptr() as usize
                            } else {
                                0
                            };
                            debug_assert!(offset == 0 || offset >= proof_entry_range.start);
                            debug_assert!(offset <= (proof_entry_range.start + proof_entry.len()));
                            StorageValueInner::Known {
                                is_inline: true,
                                offset,
                                len: v.len(),
                            }
                        }
                    };

                    (
                        storage_value,
                        proof_entry_range.clone(),
                        decoded_node_value_children_bitmap,
                    )
                });
                debug_assert!(_prev_value.is_none());
            }
        }
    }

    // The entire reason why we track the unvisited proof entries is to return this error if
    // necessary.
    if !unvisited_proof_entries.is_empty() {
        return Err(Error::UnusedProofEntry);
    }

    Ok(DecodedTrieProof {
        proof: config.proof,
        entries,
    })
}

/// Equivalent to [`StorageValue`] but contains offsets indexing [`DecodedTrieProof::proof`].
#[derive(Debug, Copy, Clone)]
enum StorageValueInner {
    /// Equivalent to [`StorageValue::Known`].
    Known {
        is_inline: bool,
        offset: usize,
        len: usize,
    },
    /// Equivalent to [`StorageValue::HashKnownValueMissing`].
    HashKnownValueMissing { offset: usize },
    /// Equivalent to [`StorageValue::None`].
    None,
}

/// Decoded Merkle proof. The proof is guaranteed valid.
pub struct DecodedTrieProof<T> {
    /// The proof itself.
    proof: T,

    /// For each trie-root-hash + storage-key tuple, contains the entry found in the proof, the
    /// range at which to find its node value, and the children bitmap.
    // TODO: a BTreeMap is actually kind of stupid since `proof` is itself in a tree format
    entries: BTreeMap<([u8; 32], Vec<nibble::Nibble>), (StorageValueInner, ops::Range<usize>, u16)>,
}

impl<T: AsRef<[u8]>> fmt::Debug for DecodedTrieProof<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.iter_ordered().map(
                |(
                    EntryKey {
                        trie_root_hash,
                        key,
                    },
                    entry,
                )| {
                    struct DummyHash<'a>(&'a [u8]);
                    impl<'a> fmt::Debug for DummyHash<'a> {
                        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                            if self.0.is_empty() {
                                write!(f, "∅")?
                            }
                            for byte in self.0 {
                                write!(f, "{:02x}", *byte)?
                            }
                            Ok(())
                        }
                    }

                    struct DummyNibbles<'a>(&'a [nibble::Nibble]);
                    impl<'a> fmt::Debug for DummyNibbles<'a> {
                        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                            if self.0.is_empty() {
                                write!(f, "∅")?
                            }
                            for nibble in self.0 {
                                write!(f, "{:x}", *nibble)?
                            }
                            Ok(())
                        }
                    }

                    (
                        (DummyHash(trie_root_hash), DummyNibbles(key)),
                        (
                            entry.trie_node_info.children,
                            entry.trie_node_info.storage_value,
                        ),
                    )
                },
            ))
            .finish()
    }
}

/// Identifier for an entry within a decoded proof.
pub struct EntryKey<'a, K> {
    /// Hash of the root of the trie the key is in.
    pub trie_root_hash: &'a [u8; 32],
    /// The trie node key.
    pub key: K,
}

impl<T: AsRef<[u8]>> DecodedTrieProof<T> {
    /// Returns a list of all elements of the proof, ordered by key in lexicographic order.
    ///
    /// This function is a convenient wrapper around [`DecodedTrieProof::iter_ordered`] that
    /// converts the keys into arrays of bytes. If a key can't be represented as an array of
    /// bytes, then it is filtered out. Assuming that the trie has only ever been used in the
    /// context of the runtime, then this cannot happen. See the section below for an
    /// explanation.
    ///
    /// The iterator might include branch nodes. It is not possible for this function to
    /// differentiate between value-less nodes that are present in the proof only because they are
    /// branch nodes, and value-less nodes that are present in the proof because the fact that they
    /// have no value is important for the proof.
    ///
    /// # Detailed explanation
    ///
    /// The trie consists of nodes, each with a key and a value. The keys consist of an array of
    /// "nibbles", which are 4 bits each.
    ///
    /// When the runtime writes a value in the trie, it passes a key as an array a bytes. In order
    /// to know where to write this value, this array of bytes is converted into an array of
    /// nibbles by turning each byte into two nibbles.
    ///
    /// Due to the fact that the host-runtime interface only ever uses arrays of bytes, it is not
    /// possible for the runtime to store a value or read a value in the trie at a key that
    /// consists in an uneven number of nibbles, as an uneven number of nibbles cannot be
    /// converted to an array of bytes.
    ///
    /// In other words, if a trie has only ever been used in the context of a runtime, then it is
    /// guaranteed to not contain any storage value at key that consists in an uneven number of
    /// nibbles.
    ///
    /// The trie format itself, however, technically doesn't forbid storing reading and writing
    /// values at keys that consist in an uneven number of nibbles. For this reason, a proof
    /// containing a value at a key that consists in an uneven number of nibbles is considered as
    /// valid according to [`decode_and_verify_proof`].
    ///
    /// However, given that [`decode_and_verify_proof`] verifies the trie proof against the state
    /// trie root hash, we are also guaranteed that this proof reflects the actual trie. If the
    /// actual trie can't contain any storage value at a key that consists in an uneven number of
    /// nibbles, then the proof is also guaranteed to not contain any storage value at a key that
    /// consists in an uneven number of nibbles. Importantly, this is only true if we are sure that
    /// the block is valid, in other words that it has indeed been created using a runtime. Blocks
    /// that are invalid might have been created through a fake trie.
    ///
    /// As a conclusion, if this proof is made against a trie that has only ever been used in the
    /// context of a runtime, and that the block using this trie is guaranteed to be valid, then
    /// this function will work as intended and return the entire content of the proof.
    ///
    pub fn iter_runtime_context_ordered(
        &'_ self,
    ) -> impl Iterator<Item = (EntryKey<'_, Vec<u8>>, StorageValue<'_>)> + '_ {
        self.iter_ordered().filter_map(
            |(
                EntryKey {
                    trie_root_hash,
                    key,
                },
                entry,
            )| {
                let value = entry.trie_node_info.storage_value;

                if key.len() % 2 != 0 {
                    return None;
                }

                let key = nibble::nibbles_to_bytes_suffix_extend(key.iter().copied()).collect();
                Some((
                    EntryKey {
                        trie_root_hash,
                        key,
                    },
                    value,
                ))
            },
        )
    }

    /// Returns a list of all elements of the proof, ordered by key in lexicographic order.
    ///
    /// The iterator includes branch nodes.
    pub fn iter_ordered(
        &'_ self,
    ) -> impl Iterator<Item = (EntryKey<'_, &'_ [nibble::Nibble]>, ProofEntry<'_>)> + '_ {
        self.entries.iter().map(
            |((trie_root_hash, key), (storage_value_inner, node_value_range, children_bitmap))| {
                let storage_value = match storage_value_inner {
                    StorageValueInner::Known {
                        offset,
                        len,
                        is_inline,
                        ..
                    } => StorageValue::Known {
                        value: &self.proof.as_ref()[*offset..][..*len],
                        inline: *is_inline,
                    },
                    StorageValueInner::None => StorageValue::None,
                    StorageValueInner::HashKnownValueMissing { offset } => {
                        StorageValue::HashKnownValueMissing(
                            <&[u8; 32]>::try_from(&self.proof.as_ref()[*offset..][..32]).unwrap(),
                        )
                    }
                };

                (
                    EntryKey {
                        trie_root_hash,
                        key: &key[..],
                    },
                    ProofEntry {
                        node_value: &self.proof.as_ref()[node_value_range.clone()],
                        unhashed_storage_value: match storage_value_inner {
                            StorageValueInner::Known {
                                is_inline: false,
                                offset,
                                len,
                            } => Some(&self.proof.as_ref()[*offset..][..*len]),
                            _ => None,
                        },
                        trie_node_info: TrieNodeInfo {
                            children: self.children_from_key(
                                trie_root_hash,
                                key,
                                &self.proof.as_ref()[node_value_range.clone()],
                                *children_bitmap,
                            ),
                            storage_value,
                        },
                    },
                )
            },
        )
    }

    fn children_from_key<'a>(
        &'a self,
        trie_root_merkle_value: &[u8; 32],
        key: &[nibble::Nibble],
        parent_node_value: &'a [u8],
        children_bitmap: u16,
    ) -> Children<'a> {
        debug_assert_eq!(
            self.entries
                .get(&(*trie_root_merkle_value, key.to_vec()))
                .unwrap()
                .2,
            children_bitmap
        );

        let mut children = [Child::NoChild; 16];
        let mut child_search = key.to_vec();

        let parent_node_value = trie_node::decode(parent_node_value).unwrap();

        for nibble in nibble::all_nibbles().filter(|n| (children_bitmap & (1 << u8::from(*n))) != 0)
        {
            child_search.push(nibble);

            let merkle_value = &parent_node_value.children[usize::from(u8::from(nibble))].unwrap();

            children[usize::from(u8::from(nibble))] = if let Some(((_, child), _)) = self
                .entries
                .range((
                    ops::Bound::Included((*trie_root_merkle_value, child_search.clone())), // TODO: stupid allocation
                    ops::Bound::Unbounded,
                ))
                .next()
                .filter(|((trie_root, maybe_child), _)| {
                    trie_root == trie_root_merkle_value && maybe_child.starts_with(&child_search)
                }) {
                Child::InProof {
                    child_key: child,
                    merkle_value,
                }
            } else {
                Child::AbsentFromProof { merkle_value }
            };

            child_search.pop();
        }

        Children { children }
    }

    /// Returns the closest ancestor to the given key that can be found in the proof. If `key` is
    /// in the proof, returns `key`.
    fn closest_ancestor<'a>(
        &'a self,
        trie_root_merkle_value: &[u8; 32],
        key: &[nibble::Nibble],
    ) -> Result<
        Option<(
            &'a [nibble::Nibble],
            &'a (StorageValueInner, ops::Range<usize>, u16),
        )>,
        IncompleteProofError,
    > {
        // If the proof doesn't contain any entry for the requested trie, then we have no
        // information about the node whatsoever.
        // This check is necessary because we assume below that a lack of ancestor means that the
        // key is outside of the trie.
        if self
            .entries
            .range((
                ops::Bound::Included((*trie_root_merkle_value, Vec::new())),
                ops::Bound::Unbounded,
            ))
            .next()
            .map_or(true, |((h, _), _)| h != trie_root_merkle_value)
        {
            return Err(IncompleteProofError());
        }

        // Search for the key in the proof that is an ancestor or equal to the requested key.
        // As explained in the comments below, there are at most `key.len()` iterations, making
        // this `O(log n)`.
        let mut to_search = key;
        loop {
            debug_assert!(key.starts_with(to_search));

            match self
                .entries
                .range((
                    ops::Bound::Included(&(*trie_root_merkle_value, Vec::new())),
                    ops::Bound::Included(&(*trie_root_merkle_value, to_search.to_vec())), // TODO: stupid allocation
                ))
                .next_back()
            {
                None => {
                    debug_assert!(!self.entries.is_empty());
                    // The requested key doesn't have any ancestor in the trie. This means that
                    // it doesn't share any prefix with any other entry in the trie. This means
                    // that it doesn't exist.
                    return Ok(None);
                }
                Some(((_, found_key), value)) if key.starts_with(found_key) => {
                    // Requested key is a descendant of an entry found in the proof. Returning.
                    return Ok(Some((found_key, value)));
                }
                Some(((_, found_key), _)) => {
                    // ̀`found_key` is somewhere between the ancestor of the requested key and the
                    // requested key. Continue searching, this time starting at the common ancestor
                    // between `found_key` and the requested key.
                    // This means that we have at most `key.len()` loop iterations.
                    let common_nibbles = found_key
                        .iter()
                        .zip(key.iter())
                        .take_while(|(a, b)| a == b)
                        .count();
                    debug_assert!(common_nibbles < to_search.len()); // Make sure we progress.
                    debug_assert_eq!(&found_key[..common_nibbles], &key[..common_nibbles]);
                    to_search = &key[..common_nibbles];
                }
            }
        }
    }

    /// Returns the key of the closest ancestor to the given key that can be found in the proof.
    /// If `key` is in the proof, returns `key`.
    pub fn closest_ancestor_in_proof<'a>(
        &'a self,
        trie_root_merkle_value: &[u8; 32],
        key: &[nibble::Nibble],
    ) -> Result<Option<&'a [nibble::Nibble]>, IncompleteProofError> {
        Ok(self
            .closest_ancestor(trie_root_merkle_value, key)?
            .map(|(key, _)| key))
    }

    /// Returns information about a trie node.
    ///
    /// Returns an error if the proof doesn't contain enough information about this trie node.
    ///
    /// This function will return `Ok` even if there is no node in the trie for `key`, in which
    /// case the returned [`TrieNodeInfo`] will indicate no storage value and no children.
    pub fn trie_node_info(
        &'_ self,
        trie_root_merkle_value: &[u8; 32],
        key: &[nibble::Nibble],
    ) -> Result<TrieNodeInfo<'_>, IncompleteProofError> {
        match self.closest_ancestor(trie_root_merkle_value, key)? {
            None => {
                // Node is known to not exist.
                Ok(TrieNodeInfo {
                    storage_value: StorageValue::None,
                    children: Children {
                        children: [Child::NoChild; 16],
                    },
                })
            }
            Some((ancestor_key, (storage_value, node_value_range, children_bitmap)))
                if ancestor_key == key =>
            {
                // Found exact match.
                return Ok(TrieNodeInfo {
                    storage_value: match storage_value {
                        StorageValueInner::Known {
                            offset,
                            len,
                            is_inline,
                            ..
                        } => StorageValue::Known {
                            value: &self.proof.as_ref()[*offset..][..*len],
                            inline: *is_inline,
                        },
                        StorageValueInner::None => StorageValue::None,
                        StorageValueInner::HashKnownValueMissing { offset } => {
                            StorageValue::HashKnownValueMissing(
                                <&[u8; 32]>::try_from(&self.proof.as_ref()[*offset..][..32])
                                    .unwrap(),
                            )
                        }
                    },
                    children: self.children_from_key(
                        trie_root_merkle_value,
                        ancestor_key,
                        &self.proof.as_ref()[node_value_range.clone()],
                        *children_bitmap,
                    ),
                });
            }
            Some((ancestor_key, (_, _, children_bitmap))) => {
                // Requested key is a descendant of an entry found in the proof.
                // Check whether the entry can have a descendant in the direction towards the
                // requested key.
                if children_bitmap & (1 << u8::from(key[ancestor_key.len()])) == 0 {
                    // Child absent.
                    // It has been proven that the requested key doesn't exist in the trie.
                    return Ok(TrieNodeInfo {
                        storage_value: StorageValue::None,
                        children: Children {
                            children: [Child::NoChild; 16],
                        },
                    });
                }

                if self
                    .entries
                    .range((
                        ops::Bound::Included((
                            *trie_root_merkle_value,
                            key[..ancestor_key.len() + 1].to_vec(), // TODO: stupid allocation
                        )),
                        ops::Bound::Unbounded,
                    ))
                    .next()
                    .map_or(false, |((r, k), _)| {
                        r == trie_root_merkle_value && k.starts_with(&key[..ancestor_key.len() + 1])
                    })
                {
                    // There exists at least one node in the proof that starts with
                    // `key[..ancestor.len() + 1]` but that isn't `key` and doesn't start
                    // with key, and there isn't any branch node at the common ancestor between
                    // this node and `key`, as otherwise would have found it when iterating
                    // earlier. This branch node can't be missing from the proof as otherwise
                    // the proof would be invalid.
                    // Thus, the requested key doesn't exist in the trie.
                    return Ok(TrieNodeInfo {
                        storage_value: StorageValue::None,
                        children: Children {
                            children: [Child::NoChild; 16],
                        },
                    });
                }

                // Child present.
                // The request key can possibly be in the trie, but we have no way of
                // knowing because the proof doesn't have enough information.
                Err(IncompleteProofError())
            }
        }
    }

    /// Queries from the proof the storage value at the given key.
    ///
    /// Returns an error if the storage value couldn't be determined from the proof. Returns
    /// `Ok(None)` if the storage value is known to have no value.
    ///
    /// > **Note**: This function is a convenient wrapper around
    /// >           [`DecodedTrieProof::trie_node_info`].
    // TODO: accept param as iterator rather than slice?
    pub fn storage_value(
        &'_ self,
        trie_root_merkle_value: &[u8; 32],
        key: &[u8],
    ) -> Result<Option<(&'_ [u8], TrieEntryVersion)>, IncompleteProofError> {
        // Annoyingly we have to create a `Vec` for the key, but the API of BTreeMap gives us
        // no other choice.
        let key = nibble::bytes_to_nibbles(key.iter().copied()).collect::<Vec<_>>();
        match self
            .trie_node_info(trie_root_merkle_value, &key)?
            .storage_value
        {
            StorageValue::Known { value, inline } => Ok(Some((
                value,
                if inline {
                    TrieEntryVersion::V0
                } else {
                    TrieEntryVersion::V1
                },
            ))),
            StorageValue::HashKnownValueMissing(_) => Err(IncompleteProofError()),
            StorageValue::None => Ok(None),
        }
    }

    /// Find in the proof the trie node that follows `key_before` in lexicographic order.
    ///
    /// If `or_equal` is `true`, then `key_before` is returned if it is equal to a node in the
    /// trie. If `false`, then only keys that are strictly superior are returned.
    ///
    /// The returned value must always start with `prefix`. Note that the value of `prefix` is
    /// important as it can be the difference between `Err(IncompleteProofError)` and `Ok(None)`.
    ///
    /// If `branch_nodes` is `false`, then trie nodes that don't have a storage value are skipped.
    ///
    /// Returns an error if the proof doesn't contain enough information to determine the next key.
    /// Returns `Ok(None)` if the proof indicates that there is no next key (within the given
    /// prefix).
    // TODO: accept params as iterators rather than slices?
    pub fn next_key(
        &'_ self,
        trie_root_merkle_value: &[u8; 32],
        key_before: &[nibble::Nibble],
        or_equal: bool,
        prefix: &[nibble::Nibble],
        branch_nodes: bool,
    ) -> Result<Option<&'_ [nibble::Nibble]>, IncompleteProofError> {
        let mut key_before = {
            let mut k = Vec::with_capacity(key_before.len() + 4);
            k.extend_from_slice(key_before);
            k
        };

        // First, we get rid of the question of `or_equal` by pushing an additional nibble if it
        // is `false`. In the algorithm below, we assume that `or_equal` is `true`.
        if !or_equal {
            key_before.push(nibble::Nibble::zero());
        }

        loop {
            match self.closest_ancestor(trie_root_merkle_value, &key_before)? {
                None => {
                    // `key_before` has no ancestor, meaning that it is either the root of the
                    // trie or out of range of the trie completely. In both cases, the only
                    // possible candidate if the root of the trie.
                    match self
                        .entries
                        .range((
                            ops::Bound::Included((*trie_root_merkle_value, Vec::new())),
                            ops::Bound::Unbounded,
                        ))
                        .next()
                        .filter(|((h, _), _)| h == trie_root_merkle_value)
                    {
                        Some(((_, k), _)) if *k >= key_before => {
                            // We still need to handle the prefix and branch nodes. To make our
                            // life easier, we just update `key_before` and loop again.
                            key_before = k.clone()
                        }
                        Some(_) => return Ok(None), // `key_before` is after every trie node.
                        None => return Ok(None),    // Empty trie.
                    };
                }
                Some((ancestor_key, (storage_value, _, _))) if ancestor_key == key_before => {
                    // It's a match!

                    // Check for `branch_nodes`.
                    if !branch_nodes && matches!(storage_value, StorageValueInner::None) {
                        // Skip to next node.
                        key_before.push(nibble::Nibble::zero());
                        continue;
                    }

                    if !key_before.starts_with(prefix) {
                        return Ok(None);
                    } else {
                        return Ok(Some(ancestor_key));
                    }
                }
                Some((ancestor_key, (_, _, children_bitmap))) => {
                    debug_assert!(key_before.starts_with(ancestor_key));

                    // Find which descendant of `ancestor_key` and that is after `key_before`
                    // actually exists.
                    let nibble_towards_key_before = key_before[ancestor_key.len()];
                    let nibble_that_exists =
                        iter::successors(Some(nibble_towards_key_before), |n| n.checked_add(1))
                            .find(|n| children_bitmap & (1 << u8::from(*n)) != 0);

                    if let Some(nibble_that_exists) = nibble_that_exists {
                        // The next key of `key_before` is the descendant of `ancestor_key` in
                        // the direction of `nibble_that_exists`.
                        key_before.push(nibble_that_exists);
                        if let Some(((_, descendant_key), _)) = self
                            .entries
                            .range((
                                ops::Bound::Included((
                                    *trie_root_merkle_value,
                                    key_before.to_vec(), // TODO: stupid allocation
                                )),
                                ops::Bound::Unbounded,
                            ))
                            .next()
                            .filter(|((h, k), _)| {
                                h == trie_root_merkle_value && k.starts_with(&key_before)
                            })
                        {
                            key_before = descendant_key.clone();
                        } else {
                            // We know that there is a descendant but it is not in the proof.
                            return Err(IncompleteProofError());
                        }
                    } else {
                        // `ancestor_key` has no children that can possibly be superior
                        // to `key_before`. Advance to finding the first sibling after
                        // `ancestor_key`.
                        key_before.truncate(ancestor_key.len());
                        loop {
                            let Some(nibble) = key_before.pop() else {
                                // `key_before` is equal to `0xffff...` and thus can't
                                // have any next sibling.
                                return Ok(None);
                            };
                            if let Some(new_nibble) = nibble.checked_add(1) {
                                key_before.push(new_nibble);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Find in the proof the closest trie node that descends from `key` and returns its Merkle
    /// value.
    ///
    /// Returns an error if the proof doesn't contain enough information to determine the Merkle
    /// value.
    /// Returns `Ok(None)` if the proof indicates that there is no descendant.
    // TODO: accept params as iterators rather than slices?
    pub fn closest_descendant_merkle_value(
        &'_ self,
        trie_root_merkle_value: &[u8; 32],
        key: &[nibble::Nibble],
    ) -> Result<Option<&'_ [u8]>, IncompleteProofError> {
        if key.is_empty() {
            // The closest descendant of an empty key is always the root of the trie itself,
            // assuming that the proof contains this trie.
            return self
                .entries
                .range((
                    ops::Bound::Included((*trie_root_merkle_value, Vec::new())),
                    ops::Bound::Unbounded,
                ))
                .next()
                .and_then(|((h, _), _)| {
                    if h == trie_root_merkle_value {
                        Some(&h[..])
                    } else {
                        None
                    }
                })
                .ok_or(IncompleteProofError())
                .map(Some);
        }

        // Call `closest_ancestor(parent(key))`.
        match self.closest_ancestor(trie_root_merkle_value, &key[..key.len() - 1])? {
            None => Ok(None),
            Some((parent_key, (_, parent_node_value_range, _)))
                if parent_key.len() == key.len() - 1 =>
            {
                // Exact match, meaning that `parent_key` is precisely one less nibble than `key`.
                // This means that there's no node between `parent_key` and `key`. Consequently,
                // the closest-descendant-or-equal of `key` is also the strict-closest-descendant
                // of `parent_key`, and its Merkle value can be found in `parent_key`'s node
                // value.
                let nibble = key[key.len() - 1];
                let parent_node_value =
                    trie_node::decode(&self.proof.as_ref()[parent_node_value_range.clone()])
                        .unwrap();
                Ok(parent_node_value.children[usize::from(u8::from(nibble))])
            }
            Some((parent_key, (_, parent_node_value_range, _))) => {
                // The closest parent is more than one nibble away.
                // If the proof contains a node in this direction, then we know that there's no
                // node in the trie between `parent_key` and `key`. If the proof doesn't contain
                // any node in this direction, then we can't be sure of that.
                if self
                    .entries
                    .range((
                        ops::Bound::Included((*trie_root_merkle_value, key.to_vec())), // TODO: stupid allocation
                        ops::Bound::Unbounded,
                    ))
                    .next()
                    .map_or(true, |((h, k), _)| {
                        h != trie_root_merkle_value || !k.starts_with(key)
                    })
                {
                    return Ok(None);
                }

                let nibble = key[parent_key.len()];
                let parent_node_value =
                    trie_node::decode(&self.proof.as_ref()[parent_node_value_range.clone()])
                        .unwrap();
                Ok(parent_node_value.children[usize::from(u8::from(nibble))])
            }
        }
    }
}

/// Proof doesn't contain enough information to answer the request.
#[derive(Debug, Clone, derive_more::Display)]
pub struct IncompleteProofError();

/// Storage value of the node.
#[derive(Copy, Clone)]
pub enum StorageValue<'a> {
    /// The storage value was found in the proof.
    Known {
        /// The storage value.
        value: &'a [u8],
        /// `true` if the storage value was inline in the node. This indicates "version 0" of the
        /// state version, while `false` indicates "version 1".
        inline: bool,
    },
    /// The hash of the storage value was found, but the un-hashed value wasn't in the proof. This
    /// indicates an incomplete proof.
    HashKnownValueMissing(&'a [u8; 32]),
    /// The node doesn't have a storage value.
    None,
}

impl<'a> fmt::Debug for StorageValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageValue::Known { value, inline } if value.len() <= 48 => {
                write!(
                    f,
                    "0x{}{}",
                    hex::encode(value),
                    if *inline { " (inline)" } else { "" }
                )
            }
            StorageValue::Known { value, inline } => {
                write!(
                    f,
                    "0x{}…{} ({} bytes{})",
                    hex::encode(&value[0..4]),
                    hex::encode(&value[value.len() - 4..]),
                    value.len(),
                    if *inline { ", inline" } else { "" }
                )
            }
            StorageValue::HashKnownValueMissing(hash) => {
                write!(f, "hash(0x{})", hex::encode(hash))
            }
            StorageValue::None => write!(f, "<none>"),
        }
    }
}

/// Possible error returned by [`decode_and_verify_proof`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Proof is in an invalid format.
    InvalidFormat,
    /// One of the node values in the proof has an invalid format.
    #[display(fmt = "A node of the proof has an invalid format: {_0}")]
    InvalidNodeValue(trie_node::Error),
    /// One of the entries of the proof is disconnected from the root node.
    UnusedProofEntry,
    /// The same entry has been found multiple times in the proof.
    DuplicateProofEntry,
    /// A node has been passed separately and referred to by its hash, while its length is inferior
    /// to 32 bytes.
    UnexpectedHashedNode,
}

/// Information about an entry in the proof.
#[derive(Debug, Copy, Clone)]
pub struct ProofEntry<'a> {
    /// Information about the node of the trie associated to this entry.
    pub trie_node_info: TrieNodeInfo<'a>,

    /// Node value of that proof entry.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub node_value: &'a [u8],

    /// If [`ProofEntry::node_value`] indicates that the storage value is hashed, then this field
    /// contains the unhashed storage value that is found in the proof, if any.
    ///
    /// If this field contains `Some`, then [`TrieNodeInfo::storage_value`] is guaranteed to
    /// contain [`StorageValue::Known`]. However the opposite is not necessarily true.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub unhashed_storage_value: Option<&'a [u8]>,
}

/// Information about a node of the trie.
///
/// > **Note**: This structure might represent a node that doesn't actually exist in the trie.
#[derive(Debug, Copy, Clone)]
pub struct TrieNodeInfo<'a> {
    /// Storage value of the node, if any.
    pub storage_value: StorageValue<'a>,
    /// Which children the node has.
    pub children: Children<'a>,
}

/// See [`TrieNodeInfo::children`].
#[derive(Copy, Clone)]
pub struct Children<'a> {
    children: [Child<'a>; 16],
}

/// Information about a specific child in the list of children.
#[derive(Copy, Clone)]
pub enum Child<'a> {
    /// Child exists and can be found in the proof.
    InProof {
        /// Key of the child. Always starts with the key of its parent.
        child_key: &'a [nibble::Nibble],
        /// Merkle value of the child.
        merkle_value: &'a [u8],
    },
    /// Child exists but isn't present in the proof.
    AbsentFromProof {
        /// Merkle value of the child.
        merkle_value: &'a [u8],
    },
    /// Child doesn't exist.
    NoChild,
}

impl<'a> Child<'a> {
    /// Returns the Merkle value of this child. `None` if the child doesn't exist.
    pub fn merkle_value(&self) -> Option<&'a [u8]> {
        match self {
            Child::InProof { merkle_value, .. } => Some(merkle_value),
            Child::AbsentFromProof { merkle_value } => Some(merkle_value),
            Child::NoChild => None,
        }
    }
}

impl<'a> Children<'a> {
    /// Returns `true` if a child in the direction of the given nibble is present.
    pub fn has_child(&self, nibble: nibble::Nibble) -> bool {
        match self.children[usize::from(u8::from(nibble))] {
            Child::InProof { .. } | Child::AbsentFromProof { .. } => true,
            Child::NoChild => false,
        }
    }

    /// Returns the information about the child in the given direction.
    pub fn child(&self, direction: nibble::Nibble) -> Child<'a> {
        self.children[usize::from(u8::from(direction))]
    }

    /// Returns an iterator of 16 items, one for each child.
    pub fn children(
        &'_ self,
    ) -> impl DoubleEndedIterator + ExactSizeIterator<Item = Child<'a>> + '_ {
        self.children.iter().copied()
    }
}

impl<'a> fmt::Debug for Children<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Binary::fmt(&self, f)
    }
}

impl<'a> fmt::Binary for Children<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for child in &self.children {
            let chr = match child {
                Child::InProof { .. } | Child::AbsentFromProof { .. } => '1',
                Child::NoChild => '0',
            };

            fmt::Write::write_char(f, chr)?
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty_is_valid() {
        let _ = super::decode_and_verify_proof(super::Config { proof: &[0] }).unwrap();
    }

    #[test]
    fn basic_works() {
        // Key/value taken from the Polkadot genesis block.

        let proof = vec![
            24, 212, 125, 1, 84, 37, 150, 173, 176, 93, 97, 64, 193, 112, 172, 71, 158, 223, 124,
            253, 90, 163, 83, 87, 89, 10, 207, 229, 209, 26, 128, 77, 148, 78, 80, 13, 20, 86, 253,
            218, 123, 142, 199, 249, 229, 199, 148, 205, 131, 25, 79, 5, 147, 228, 234, 53, 5, 128,
            63, 147, 128, 78, 76, 108, 66, 34, 183, 71, 229, 7, 0, 142, 241, 222, 240, 99, 187, 13,
            45, 238, 173, 241, 126, 244, 177, 14, 113, 98, 77, 58, 12, 248, 28, 128, 36, 31, 44, 6,
            242, 46, 197, 137, 104, 251, 104, 212, 50, 49, 158, 37, 230, 200, 250, 163, 173, 44,
            92, 169, 238, 72, 242, 232, 237, 21, 142, 36, 128, 173, 138, 104, 35, 73, 50, 38, 152,
            70, 188, 64, 36, 10, 71, 207, 216, 216, 133, 123, 29, 129, 225, 103, 191, 178, 76, 148,
            122, 76, 218, 217, 230, 128, 200, 69, 144, 227, 159, 139, 121, 162, 105, 74, 210, 191,
            126, 114, 88, 175, 104, 107, 71, 47, 56, 176, 100, 187, 206, 125, 8, 64, 73, 49, 164,
            48, 128, 92, 114, 242, 91, 27, 99, 4, 209, 102, 103, 226, 118, 111, 161, 169, 6, 203,
            8, 23, 136, 235, 69, 2, 120, 125, 247, 195, 89, 116, 18, 177, 123, 128, 110, 33, 197,
            241, 162, 74, 25, 102, 21, 180, 229, 179, 109, 33, 40, 12, 220, 200, 0, 152, 193, 226,
            188, 232, 238, 175, 48, 30, 153, 81, 118, 116, 128, 66, 79, 26, 205, 128, 186, 7, 74,
            44, 232, 209, 128, 191, 52, 136, 165, 202, 145, 203, 129, 251, 169, 108, 140, 60, 29,
            51, 234, 203, 177, 129, 96, 128, 94, 132, 157, 92, 20, 140, 163, 97, 165, 90, 44, 155,
            56, 78, 23, 206, 145, 158, 147, 108, 203, 128, 17, 164, 247, 37, 4, 233, 249, 61, 184,
            205, 128, 237, 208, 5, 161, 73, 92, 112, 37, 13, 119, 248, 28, 36, 193, 90, 153, 25,
            240, 52, 247, 152, 61, 248, 229, 5, 229, 58, 90, 247, 180, 2, 19, 128, 18, 160, 221,
            144, 73, 123, 101, 49, 43, 218, 103, 234, 21, 153, 101, 120, 238, 179, 137, 27, 202,
            134, 102, 149, 26, 50, 102, 18, 65, 142, 49, 67, 177, 4, 128, 85, 93, 128, 67, 251, 73,
            124, 27, 42, 123, 158, 79, 235, 89, 244, 16, 193, 162, 158, 40, 178, 166, 40, 255, 156,
            96, 3, 224, 128, 246, 185, 250, 221, 149, 249, 128, 110, 141, 145, 27, 104, 24, 3, 142,
            183, 200, 83, 74, 248, 231, 142, 153, 32, 161, 171, 141, 147, 156, 54, 211, 230, 155,
            10, 30, 89, 40, 17, 11, 128, 186, 77, 63, 84, 57, 87, 244, 34, 180, 12, 142, 116, 175,
            157, 224, 10, 203, 235, 168, 21, 74, 252, 165, 122, 127, 128, 251, 188, 254, 187, 30,
            74, 128, 61, 27, 143, 92, 241, 120, 139, 41, 69, 55, 184, 253, 45, 52, 172, 236, 70,
            70, 167, 98, 124, 108, 211, 210, 3, 154, 246, 79, 245, 209, 151, 109, 128, 231, 98, 15,
            33, 207, 19, 150, 79, 41, 211, 75, 167, 8, 195, 180, 78, 164, 94, 161, 28, 88, 251,
            190, 221, 162, 157, 19, 71, 11, 200, 12, 160, 128, 249, 138, 174, 79, 131, 216, 27,
            241, 93, 136, 1, 158, 92, 48, 61, 124, 25, 208, 82, 78, 132, 199, 20, 224, 95, 97, 81,
            124, 222, 11, 19, 130, 128, 213, 24, 250, 245, 102, 253, 196, 208, 69, 9, 74, 190, 55,
            43, 179, 187, 236, 212, 117, 63, 118, 219, 140, 65, 186, 159, 192, 21, 85, 139, 242,
            58, 128, 144, 143, 153, 17, 38, 209, 44, 231, 172, 213, 85, 8, 255, 30, 125, 255, 165,
            111, 116, 36, 1, 225, 129, 79, 193, 70, 150, 88, 167, 140, 122, 127, 128, 1, 176, 160,
            141, 160, 200, 50, 83, 213, 192, 203, 135, 114, 134, 192, 98, 218, 47, 83, 10, 228, 36,
            254, 37, 69, 55, 121, 65, 253, 1, 105, 19, 53, 5, 128, 179, 167, 128, 162, 159, 172,
            127, 125, 250, 226, 29, 5, 217, 80, 110, 125, 166, 81, 91, 127, 161, 173, 151, 15, 248,
            118, 222, 53, 241, 190, 194, 89, 158, 192, 2, 128, 91, 103, 114, 220, 106, 78, 118, 4,
            200, 208, 101, 36, 121, 249, 91, 52, 54, 7, 194, 217, 19, 140, 89, 238, 183, 153, 216,
            91, 244, 59, 107, 191, 128, 61, 18, 190, 203, 106, 75, 153, 25, 221, 199, 197, 151, 61,
            4, 238, 215, 105, 108, 131, 79, 144, 199, 121, 252, 31, 207, 115, 80, 204, 194, 141,
            107, 128, 95, 51, 235, 207, 25, 31, 221, 207, 59, 63, 52, 110, 195, 54, 193, 5, 199,
            75, 64, 164, 211, 93, 253, 160, 197, 146, 242, 190, 160, 0, 132, 233, 128, 247, 100,
            199, 51, 214, 227, 87, 113, 169, 178, 106, 31, 168, 107, 155, 236, 89, 116, 43, 4, 111,
            105, 139, 230, 193, 64, 175, 16, 115, 137, 125, 61, 128, 205, 59, 200, 195, 206, 60,
            248, 53, 159, 115, 113, 161, 51, 22, 240, 47, 210, 43, 2, 163, 211, 39, 104, 74, 43,
            97, 244, 164, 126, 0, 34, 184, 128, 218, 117, 42, 250, 235, 146, 93, 83, 0, 228, 91,
            133, 16, 82, 197, 248, 169, 197, 170, 232, 132, 241, 93, 100, 118, 78, 223, 150, 27,
            139, 34, 200, 128, 191, 31, 169, 199, 228, 201, 67, 64, 219, 175, 215, 92, 190, 1, 108,
            152, 13, 14, 93, 91, 78, 118, 130, 63, 161, 30, 97, 98, 144, 20, 195, 75, 128, 79, 84,
            161, 94, 93, 81, 208, 43, 132, 232, 202, 233, 76, 152, 51, 174, 129, 229, 107, 143, 11,
            104, 77, 37, 127, 111, 114, 46, 230, 108, 173, 249, 128, 148, 131, 63, 178, 220, 232,
            199, 141, 68, 60, 214, 120, 110, 12, 1, 216, 151, 74, 75, 119, 156, 23, 142, 245, 230,
            107, 73, 224, 33, 221, 127, 26, 225, 2, 159, 12, 93, 121, 93, 2, 151, 190, 86, 2, 122,
            75, 36, 100, 227, 51, 151, 96, 146, 128, 243, 50, 255, 85, 106, 191, 93, 175, 13, 52,
            82, 61, 247, 200, 205, 19, 105, 188, 182, 173, 187, 35, 164, 128, 147, 191, 7, 10, 151,
            17, 191, 52, 128, 56, 41, 52, 19, 74, 169, 25, 181, 156, 22, 255, 141, 232, 217, 122,
            127, 220, 194, 68, 142, 163, 39, 178, 111, 68, 0, 93, 117, 109, 23, 133, 135, 128, 129,
            214, 52, 20, 11, 54, 206, 3, 28, 75, 108, 98, 102, 226, 167, 193, 157, 154, 136, 227,
            143, 221, 138, 210, 58, 189, 61, 178, 14, 113, 79, 105, 128, 253, 225, 112, 65, 242,
            47, 9, 96, 157, 121, 219, 227, 141, 204, 206, 252, 170, 193, 57, 199, 161, 15, 178, 59,
            210, 132, 193, 196, 146, 176, 4, 253, 128, 210, 135, 173, 29, 10, 222, 101, 230, 77,
            57, 105, 244, 171, 133, 163, 112, 118, 129, 96, 49, 67, 140, 234, 11, 248, 195, 59,
            123, 43, 198, 195, 48, 141, 8, 159, 3, 230, 211, 193, 251, 21, 128, 94, 223, 208, 36,
            23, 46, 164, 129, 125, 255, 255, 128, 21, 40, 51, 227, 74, 133, 46, 151, 81, 207, 192,
            249, 84, 174, 184, 53, 225, 248, 67, 147, 107, 169, 151, 152, 83, 164, 14, 67, 153, 55,
            37, 95, 128, 106, 54, 224, 173, 35, 251, 50, 36, 255, 246, 230, 219, 98, 4, 132, 99,
            167, 242, 124, 203, 146, 246, 91, 78, 52, 138, 205, 90, 122, 163, 160, 104, 128, 39,
            182, 224, 153, 193, 21, 129, 251, 46, 138, 207, 59, 107, 148, 234, 237, 68, 34, 119,
            185, 167, 76, 231, 249, 34, 246, 227, 191, 41, 89, 134, 123, 128, 253, 12, 194, 200,
            70, 219, 106, 158, 209, 154, 113, 93, 108, 60, 212, 106, 72, 183, 244, 9, 136, 60, 112,
            178, 212, 201, 120, 179, 6, 222, 55, 158, 128, 171, 0, 138, 120, 195, 64, 245, 204,
            117, 217, 156, 219, 144, 89, 81, 147, 102, 134, 68, 92, 131, 71, 25, 190, 33, 247, 98,
            11, 149, 13, 205, 92, 128, 109, 134, 175, 84, 213, 223, 177, 192, 111, 63, 239, 221,
            90, 67, 8, 97, 192, 209, 158, 37, 250, 212, 186, 208, 124, 110, 112, 212, 166, 121,
            240, 184, 128, 243, 94, 220, 84, 0, 182, 102, 31, 177, 230, 251, 167, 197, 153, 200,
            186, 137, 20, 88, 209, 68, 0, 3, 15, 165, 6, 153, 154, 25, 114, 54, 159, 128, 116, 108,
            218, 160, 183, 218, 46, 156, 56, 100, 151, 31, 80, 241, 45, 155, 66, 129, 248, 4, 213,
            162, 219, 166, 235, 224, 105, 89, 178, 169, 251, 71, 128, 46, 207, 222, 17, 69, 100,
            35, 200, 127, 237, 128, 104, 244, 20, 165, 186, 68, 235, 227, 174, 145, 176, 109, 20,
            204, 35, 26, 120, 212, 171, 166, 142, 128, 246, 85, 41, 24, 51, 164, 156, 242, 61, 5,
            123, 177, 92, 66, 211, 119, 197, 93, 80, 245, 136, 83, 41, 6, 11, 10, 170, 178, 34,
            131, 203, 177, 128, 140, 149, 251, 43, 98, 186, 243, 7, 24, 184, 51, 14, 246, 138, 82,
            124, 151, 193, 188, 153, 96, 48, 67, 83, 34, 77, 138, 138, 232, 138, 121, 213, 128, 69,
            193, 182, 217, 144, 74, 225, 113, 213, 115, 189, 206, 186, 160, 81, 66, 216, 22, 72,
            189, 190, 177, 108, 238, 221, 197, 74, 14, 209, 93, 62, 43, 128, 168, 234, 25, 50, 130,
            254, 133, 182, 72, 23, 7, 9, 28, 119, 201, 33, 142, 161, 157, 233, 20, 231, 89, 80,
            146, 95, 232, 100, 0, 251, 12, 176, 128, 194, 34, 206, 171, 83, 85, 234, 164, 29, 168,
            7, 20, 111, 46, 45, 247, 255, 100, 140, 62, 139, 187, 109, 142, 226, 50, 116, 186, 114,
            69, 81, 177, 128, 8, 241, 66, 220, 60, 89, 191, 17, 81, 200, 41, 236, 239, 234, 53,
            145, 158, 128, 69, 61, 181, 233, 102, 159, 90, 115, 137, 154, 170, 81, 102, 238, 128,
            79, 29, 33, 251, 220, 1, 128, 196, 222, 136, 107, 244, 15, 145, 223, 194, 32, 43, 62,
            182, 212, 37, 72, 212, 118, 144, 128, 65, 221, 97, 123, 184,
        ];

        let trie_root = {
            let bytes =
                hex::decode("29d0d972cd27cbc511e9589fcb7a4506d5eb6a9e8df205f00472e5ab354a4e17")
                    .unwrap();
            <[u8; 32]>::try_from(&bytes[..]).unwrap()
        };

        let decoded = super::decode_and_verify_proof(super::Config { proof }).unwrap();

        let requested_key = hex::decode("9c5d795d0297be56027a4b2464e3339763e6d3c1fb15805edfd024172ea4817d7081542596adb05d6140c170ac479edf7cfd5aa35357590acfe5d11a804d944e").unwrap();
        let obtained = decoded.storage_value(&trie_root, &requested_key).unwrap();

        assert_eq!(
            obtained.unwrap().0,
            &hex::decode("0d1456fdda7b8ec7f9e5c794cd83194f0593e4ea").unwrap()[..]
        );
    }

    #[test]
    fn node_values_smaller_than_32bytes() {
        let proof = vec![
            12, 17, 1, 158, 195, 101, 195, 207, 89, 214, 113, 235, 114, 218, 14, 122, 65, 19, 196,
            0, 3, 88, 95, 7, 141, 67, 77, 97, 37, 180, 4, 67, 254, 17, 253, 41, 45, 19, 164, 16, 2,
            0, 0, 0, 104, 95, 15, 31, 5, 21, 244, 98, 205, 207, 132, 224, 241, 214, 4, 93, 252,
            187, 32, 80, 82, 127, 41, 119, 1, 0, 0, 185, 5, 128, 175, 188, 128, 15, 126, 137, 9,
            189, 204, 29, 117, 244, 124, 194, 9, 181, 214, 119, 106, 91, 55, 85, 146, 101, 112, 37,
            46, 31, 42, 133, 72, 101, 38, 60, 66, 128, 28, 186, 118, 76, 106, 111, 232, 204, 106,
            88, 52, 218, 113, 2, 76, 119, 132, 172, 202, 215, 130, 198, 184, 230, 206, 134, 44,
            171, 25, 86, 243, 121, 128, 233, 10, 145, 50, 95, 100, 17, 213, 147, 28, 9, 142, 56,
            95, 33, 40, 56, 9, 39, 3, 193, 79, 169, 207, 115, 80, 61, 217, 4, 106, 172, 152, 128,
            12, 255, 241, 157, 249, 219, 101, 33, 139, 178, 174, 121, 165, 33, 175, 0, 232, 230,
            129, 23, 89, 219, 21, 35, 23, 48, 18, 153, 124, 96, 81, 66, 128, 30, 174, 194, 227,
            100, 149, 97, 237, 23, 238, 114, 178, 106, 158, 238, 48, 166, 82, 19, 210, 129, 122,
            70, 165, 94, 186, 31, 28, 80, 29, 73, 252, 128, 16, 56, 19, 158, 188, 178, 192, 234,
            12, 251, 221, 107, 119, 243, 74, 155, 111, 53, 36, 107, 183, 204, 174, 253, 183, 67,
            77, 199, 47, 121, 185, 162, 128, 17, 217, 226, 195, 240, 113, 144, 201, 129, 184, 240,
            237, 204, 79, 68, 191, 165, 29, 219, 170, 152, 134, 160, 153, 245, 38, 181, 131, 83,
            209, 245, 194, 128, 137, 217, 3, 84, 1, 224, 52, 199, 112, 213, 150, 42, 51, 214, 103,
            194, 225, 224, 210, 84, 84, 53, 31, 159, 82, 201, 3, 104, 118, 212, 110, 7, 128, 240,
            251, 81, 190, 126, 80, 60, 139, 88, 152, 39, 153, 231, 178, 31, 184, 56, 44, 133, 31,
            47, 98, 234, 107, 15, 248, 64, 78, 36, 89, 9, 149, 128, 233, 75, 238, 120, 212, 149,
            223, 135, 48, 174, 211, 219, 223, 217, 20, 172, 212, 172, 3, 234, 54, 130, 55, 225, 63,
            17, 255, 217, 150, 252, 93, 15, 128, 89, 54, 254, 99, 202, 80, 50, 27, 92, 48, 57, 174,
            8, 211, 44, 58, 108, 207, 129, 245, 129, 80, 170, 57, 130, 80, 166, 250, 214, 40, 156,
            181, 21, 1, 128, 65, 0, 128, 182, 204, 71, 61, 83, 76, 85, 166, 19, 22, 212, 242, 236,
            229, 51, 88, 16, 191, 227, 125, 217, 54, 7, 31, 36, 176, 211, 111, 72, 220, 181, 241,
            128, 149, 2, 12, 26, 95, 9, 193, 115, 207, 253, 90, 218, 0, 41, 140, 119, 189, 166,
            101, 244, 74, 171, 53, 248, 82, 113, 79, 110, 25, 72, 62, 65,
        ];

        let trie_root = [
            43, 100, 198, 174, 1, 66, 26, 95, 93, 119, 43, 242, 5, 176, 153, 134, 193, 74, 159,
            215, 134, 15, 252, 135, 67, 129, 21, 16, 20, 211, 97, 217,
        ];

        let decoded = super::decode_and_verify_proof(super::Config { proof }).unwrap();

        let requested_key =
            hex::decode("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
                .unwrap();
        let obtained = decoded.storage_value(&trie_root, &requested_key).unwrap();

        assert_eq!(obtained.unwrap().0, &[80, 82, 127, 41, 119, 1, 0, 0][..]);
    }

    #[test]
    fn very_small_root_node_decodes() {
        // Checks that a proof with one root node whose length is < 32 bytes properly verifies.
        let proof = vec![
            4, 64, 66, 3, 52, 120, 31, 215, 222, 245, 16, 76, 51, 181, 0, 245, 192, 194,
        ];

        let proof = super::decode_and_verify_proof(super::Config { proof }).unwrap();

        assert!(proof
            .closest_descendant_merkle_value(
                &[
                    83, 2, 191, 235, 8, 252, 233, 114, 129, 199, 229, 115, 221, 238, 15, 205, 193,
                    110, 145, 107, 12, 3, 10, 145, 117, 211, 203, 151, 182, 147, 221, 178,
                ],
                &[]
            )
            .is_ok());
    }

    #[test]
    fn identical_inline_nodes() {
        // One root node with two identical inlined children.
        let proof = super::decode_and_verify_proof(super::Config {
            proof: &[
                4, 60, 128, 3, 0, 20, 65, 0, 8, 104, 105, 20, 65, 0, 8, 104, 105,
            ],
        })
        .unwrap();

        assert!(proof
            .closest_descendant_merkle_value(
                &[
                    15, 224, 134, 90, 11, 145, 174, 197, 185, 253, 233, 197, 95, 101, 197, 10, 78,
                    28, 137, 217, 102, 198, 242, 100, 90, 96, 9, 204, 213, 69, 174, 4,
                ],
                &[]
            )
            .is_ok());
    }

    #[test]
    fn identical_non_inline_nodes() {
        // One root node with two identical children and the proof contains the two children
        // separately. In other words, the proof is invalid.
        assert!(matches!(
            super::decode_and_verify_proof(super::Config {
                proof: &[
                    12, 21, 1, 128, 3, 0, 128, 205, 154, 249, 23, 88, 152, 61, 75, 170, 87, 182, 7,
                    127, 171, 174, 60, 2, 124, 79, 166, 31, 155, 155, 185, 182, 155, 250, 63, 139,
                    166, 222, 184, 128, 205, 154, 249, 23, 88, 152, 61, 75, 170, 87, 182, 7, 127,
                    171, 174, 60, 2, 124, 79, 166, 31, 155, 155, 185, 182, 155, 250, 63, 139, 166,
                    222, 184, 97, 1, 65, 0, 81, 1, 108, 111, 110, 103, 32, 115, 116, 111, 114, 97,
                    103, 101, 32, 118, 97, 108, 117, 101, 32, 105, 110, 32, 111, 114, 100, 101,
                    114, 32, 116, 111, 32, 101, 110, 115, 117, 114, 101, 32, 116, 104, 97, 116, 32,
                    116, 104, 101, 32, 110, 111, 100, 101, 32, 118, 97, 108, 117, 101, 32, 105,
                    115, 32, 109, 111, 114, 101, 32, 116, 104, 97, 110, 32, 51, 50, 32, 98, 121,
                    116, 101, 115, 32, 108, 111, 110, 103, 97, 1, 65, 0, 81, 1, 108, 111, 110, 103,
                    32, 115, 116, 111, 114, 97, 103, 101, 32, 118, 97, 108, 117, 101, 32, 105, 110,
                    32, 111, 114, 100, 101, 114, 32, 116, 111, 32, 101, 110, 115, 117, 114, 101,
                    32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 110, 111, 100, 101, 32, 118, 97,
                    108, 117, 101, 32, 105, 115, 32, 109, 111, 114, 101, 32, 116, 104, 97, 110, 32,
                    51, 50, 32, 98, 121, 116, 101, 115, 32, 108, 111, 110, 103
                ],
            }),
            Err(super::Error::DuplicateProofEntry)
        ));

        // One root node with two identical children that aren't inlined.
        // The proof is the same as above, just without two identical proof entries.
        super::decode_and_verify_proof(super::Config {
            proof: &[
                8, 21, 1, 128, 3, 0, 128, 205, 154, 249, 23, 88, 152, 61, 75, 170, 87, 182, 7, 127,
                171, 174, 60, 2, 124, 79, 166, 31, 155, 155, 185, 182, 155, 250, 63, 139, 166, 222,
                184, 128, 205, 154, 249, 23, 88, 152, 61, 75, 170, 87, 182, 7, 127, 171, 174, 60,
                2, 124, 79, 166, 31, 155, 155, 185, 182, 155, 250, 63, 139, 166, 222, 184, 97, 1,
                65, 0, 81, 1, 108, 111, 110, 103, 32, 115, 116, 111, 114, 97, 103, 101, 32, 118,
                97, 108, 117, 101, 32, 105, 110, 32, 111, 114, 100, 101, 114, 32, 116, 111, 32,
                101, 110, 115, 117, 114, 101, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 110,
                111, 100, 101, 32, 118, 97, 108, 117, 101, 32, 105, 115, 32, 109, 111, 114, 101,
                32, 116, 104, 97, 110, 32, 51, 50, 32, 98, 121, 116, 101, 115, 32, 108, 111, 110,
                103,
            ],
        })
        .unwrap();
    }

    #[test]
    fn statemine_decode_proof_fails() {
        use hex_literal::hex;
        // kusama asset hub (statemine) block#5,800,000 fails `Err` value: InvalidNodeValue(Empty)
        // parachainSystem::relayStateProof()
        let fail_nodes = vec![
			hex!("0000300000500000aaaa0a0000004000fbff0000800000000a000000100e00005802000000000000000000000000500000c800001e000000005039278c0400000000000000000000005039278c0400000000000000000000e8030000009001001e000000009001000401002000008070000000000000000000001027000080b2e60e80c3c90180969800000000000000000000000000050000000a0000000a000000010000000103000000012c01000006000000580200000300000059000000000000001e00000006000000020000001400000002000000").to_vec(),
			hex!("011a76c141d78d31d566a475819a2b8f6e56c78cf56e33ed792a2f2fb128cbca24").to_vec(),
			hex!("36ff6f7d467b87a9e8030000378d122109e460d614fa0889aa45e8ac7cebfe8d7ee4b5da1d135c69768de027").to_vec(),
			hex!("36ff6f7d467b87a9e803000081879858c3fec3f733fe2e3f02ae2938ebd014cf31f1fdcdb7449664ec481944").to_vec(),
			hex!("3d0027092eef0545e8030000d7070000201b0f7fcd79beb93ecc0180322e65c952c678a8ba5f11b31101791aad683911").to_vec(),
			hex!("3d00288c141c721de80300004d0800003d96d2fee6debbe11f3ce3225dcc4f0b62edb6a1791aaafcb661faad053db695").to_vec(),
			hex!("3d00ab91cf0114d8e8030000000800005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d0417395fc0bddfea030000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d063802d0f8d472e8030000e7070000d392198be5fb230eca11cfac934c60eedd325f8a7b733f9ffdd0515daf2f88b1").to_vec(),
			hex!("3d0a18d8d01946cb2c080000e80300006cbfd35aa95360c4dc316f9b825e6100a589970cbc11e9717c0682bd245ebf2b").to_vec(),
			hex!("3d0abb2f2bb1c94f3e080000e803000054b1195c556e32986f7e3ca9cec749f5babf0e81d265a3b9676e0e3580097187").to_vec(),
			hex!("3d0b7902b430328be8030000490800005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d0b80079d8b99f3e8030000240800006e90d9a52eccddc21946b9184827a5aa7c8f28d52f55a93ccf379929f21f2cc5").to_vec(),
			hex!("3d0ba169a93195b3e8030000d107000087007a2162e4be5ba54321522d5201cab8094bb4aa5dcc03a86e8ccdd016a0db").to_vec(),
			hex!("3d0c0201e32ae86bd1070000e803000097ee556ac8b40971acaf4d844546ad5370a6ccfeb569d5fde57f69926520f889").to_vec(),
			hex!("3d0c808d54a8937be80300004b0800005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d0f1131b7f54b0800080000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3e0053f38ebdfd42e7070000e8030000152316e9d599ef34f36fea1a953f6b0621d34a20391b06cfcf2b429756287657").to_vec(),
			hex!("3e04d2a15ab51127e8030000d007000004f3c3863574ab5c9847b420356fe00624ec7240decab100b63da55bdb6de79e").to_vec(),
			hex!("3e0f2c689744e55be80300003e0800009755b9fa9b544ce565a17f1587fd34bb6f219da748e1250e32d8eef8f878cd98").to_vec(),
			hex!("3e1c643c9d90ab7427080000e80300003de4c6d279bcff5b353645dcf04d0c4198e5fefa9ab4abae0b06c50e18e1f621").to_vec(),
			hex!("3e1fc502e2b07e96e803000027080000c6441d6967e9b776f0370af73bb06aa9515ad27a10b53ff7393da61f8162be1f").to_vec(),
			hex!("3e29b296823383d7e80300004c080000f434e45a5b74f98880767169214528b5c4439942cd1c4309d09d6eb548e8c926").to_vec(),
			hex!("3e3ba901905f80c024080000e8030000e6fd550482fb6209127dacc57e4b326cb79d76596dbfc51a0dd2f5485a72b9a9").to_vec(),
			hex!("3e43d73bfd0011312a080000e8030000e59767f571a57835b5442079a76d739333583d410756f84ec9a283acea4af4fb").to_vec(),
			hex!("3e4f36708366b722d0070000e8030000675a6f8e1283323a92a3c0c0a36144e16ca9a2e00aaaf8d1973f968442cb2dcf").to_vec(),
			hex!("3e5351db2428a52c4d080000e803000095ce736a7c6a72c08b0b8d49e8b0d7ea21a69d0f3938f15ee116f3be0323670a").to_vec(),
			hex!("3e55ca0b91260bbdd7070000e8030000387fddf5b0642679e076aaf48fba2b2f2e866497cdadc8beee94ef3b70011e42").to_vec(),
			hex!("3e6fe8fcbc5314b84c080000e8030000e6b7d897b76212e737f36aad983d29046111061997c570fee79f6f6882de3e7e").to_vec(),
			hex!("3e77dfdb8adb10f78f10a5df8742c5453766a403669af6ee94ae714196ade69f2fb7a519a89d7b681ec35045879c2ea3").to_vec(),
			hex!("3e7913c5068de7ece80300002a080000803b074eb81222acf331eac85163e4a655227574a6b2d7a44cc65b4d4635ce2b").to_vec(),
			hex!("3e7b9ae336e44cf849080000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3e7d99738139957de8030000ea0300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3e99246104cf41564b080000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3ea0c4f025fc646725080000e8030000dfb95976e2858ea609a39f40231abc8c356c3031e5e8013cc80876ff4809601e").to_vec(),
			hex!("3ece433339688292e80300002508000042fe77280c654067e249952a64233b4042c884578390fe2185083237c492f196").to_vec(),
			hex!("3ee82ccb5cb954bae80300002c0800003ebbbe445eb1fd748570604ea1bb5725d400b4c6b635c215589877cfedc35a09").to_vec(),
			hex!("3f0004b49d95320d9021994c850f25b8e385a259772211246037413843b474d01d815daa0c5f682d658885e9ae6e14fe57a5").to_vec(),
			hex!("40ea030000d0070000d1070000d7070000e7070000000800002408000025080000270800002a0800002c0800003e080000490800004b0800004c0800004d080000").to_vec(),
			hex!("56ff6f7d467b87a9e803000080db0a83e6387a81d3507b9b35d8273ac212111ee711d20bce4fb16fe267d8b70f").to_vec(),
			hex!("5e414cb008e0e61e46722aa60abdd6728021f1b7591467ba620877010be1d99a1d98c60f4f294e2f343c165ca29eff2a3d").to_vec(),
			hex!("5ee678799d3eff024253b90e84927cc6801db6d08e4dfa6c12435b4beb8b646fe44971d5f0ad4f51c5dbda835da5b06927").to_vec(),
			hex!("8000148027900e5b829d5b12954da214af4b0f0267a2ca0533e870316a30c64c1865fa0c80a415ede1ce9bf6d7ba0b5f1c86adf933e5e0a4bd31f97c0cdf0192f05cddef71").to_vec(),
			hex!("80006080693eb65dd48d9815414fbfd0a9d999c20eb2364386c286eccc867e458a14f4644c5e7b9012096b41c4eb3aaf947f6ea429080000").to_vec(),
			hex!("80008480ba1cc0504df9c9a34ce53baaeb58fd9e4cb72c4f2af518abbfc225f74a833e27802665115226983291438599ceb37967c42a9476dc562598f9ea1bdef2d8334747").to_vec(),
			hex!("80011080093a3ed5610dd2050a01a5fc05cc3c75d8f388b8df0786f185927510055fb700806524adc73860a1a35fdc649d9db6255e1ba13419405652748fe0272ae7c3be4f").to_vec(),
			hex!("80011080b966c569f1bd701be74277fe71694e38e5201c68380aedd6eaad0b1e83bc2b2d800ebe650369ce0e3ce85b22816181f598cc6ecf7a3b22314357ab4181b9ccb867").to_vec(),
			hex!("8002a4806231212da6baa80044a1d72059b7d9ea47a832d554708b48f95f3b1ae818400480e556fd774eb73493c623b929d2241b3f6c11a6f734794a2f108334cafe8ddddc8016ba46aabe2bd8ab1031a4c0b15265f71355d969545276c7906676ad88517d8b8046c9d3a08c34d30fd5051a67c9f315335c464491c319e603b7f3011338c9c9b7").to_vec(),
			hex!("800401801e226c962da28b0639e3affe37b1b0f9e26a5cb3d5e1aaebfad5a8e89429c05180073d2ffc2d5c08423ebe357fe876182f2ff80855a20e7e8f2376bfe1abddf6b3").to_vec(),
			hex!("800404808e80f60fdfa6e4d86bfedd92a383d33e605fe658ee83d6d6a9323c3a0c6bdbac80e1af12e9054e5b39d83866c1ee03b7f3c2041a679e6f27463f69263c09ec78cf").to_vec(),
			hex!("80040480ef8369476cf4dfacbaa24ccd3bd094453b876f624359482a1995239ca70cc4f6800fe6b03639ff2739e42b263a64b97458bbb7b04a7f13a7dd10b77ba5c3d3940e").to_vec(),
			hex!("80046c8015b7c3a49d22d0203020517f757d2ad3132fc51ee0a4e4b1b3ae8555e07dece980058e64fa3f33663abf4985564d9d80fe81c2d6d16a802e80de32b087e4e584a2808f83f0d8e6399e9f9d10c3c89b614e318848dfb7ecead89b137ab1fe2fa968f980e291a13e1d2d6fc6d7ec2d3119393b79261a061b16e5ad52a13609ca9edef7e2802a75438aeaee4f2eed515ed3206be080dc356b04e21002f0018fdf379870d195").to_vec(),
			hex!("800802801d79c3436485a9c1173a679f70877d551c8a84cefe54edf4e0867ee117f94fed80d4fa184dad7a3c7c443d478ce0aa58afc3ec264d3aae00943cad72c34a32b4a7").to_vec(),
			hex!("80082080c8e113af416c0f5bf56039bae79afce2c4059b72341fe754799b174af8d65274485ead6eef5c4b1c68eaa71ea17a02d9de0400").to_vec(),
			hex!("80106f80fca96f7cd27fef556cd361bee696532434d4820934a57c329c4d927b874e9b9f8076365ef7e5bd0d0f42f498cd62a36ad27739c3c741143a5b71039a65a90d8fa280d6976eb32786962cf50707a3471004eed1741ce866c9e0eafd983d60c5dddc14808c42f9339b40ccc5b3e0b95ebae7473e8eaeeb6e1d5428487b990818ef90a24e80494c2303e068f5aa16655942664f2606f785c3655e238e8500e6d89756ad6343807636f650ed4d404d7aad09f5f9d1be1e637c5e916d0561185b10de76d3dab6d98006e07fa51fc6202adb173426d9f1848a6f716ed5a6c89850cf986b3dadede199").to_vec(),
			hex!("80108080a2e7794026527ddebe6e3b75c377539cfa0a774f645ec57c0ef1197adc4cfc1880339f920b1e559d1ceda19ee1d5335e713a97a79a4474f2fd5884be18fb7449dc").to_vec(),
			hex!("801117806083fccc5ad9489e8fffd469466a4206a743d8dbbc8fb301059daa1d198c86288077b7b1af409a8997625ea767d881ff79dd3c4d1b472e1f0a1fa3c4c4f96324cf80e08b7eda419fa4012af01994e92703d3fe04eba694eeeb17e5ebe7ecd397c2c880391967182f74c6b3b362824b2c3a40a7949cc092a06bcbbf417a9c873cc15ea48047d306502909a31f46f0fa655debc2ea6dbe1edf3666abb2a0aea3f5913a78d980f2a1fadf1f46b65d5d7b255936e570167f2d59beeca55dd12cd950b3d6721a07").to_vec(),
			hex!("801eff80e0efd97247bd26cde84d2ff36a775d7c4862401aa0ed17f78a96f245eda23d4980550e5b2fc17d5f529f33dc284b6a35522b63a2631eaafd07de2b8dbb75e73c2180223c559f33130f05df3a1450661c61cc1ee029b63b979589c2dae867f6a5b4e68073502844b357f01e79e2f03819232731584b2f041390b720508d35bd7e9e7dd4804406aa8129659d0c3231c1fcbfd2b2ab54588b21ea4f7dc214eca3c49f7414be8004e85658be70231f424ac9a280a0838d95a1fb68facd6dd27b288c018e409c49800ee9de7b167a434c414d2b3a82647456eca3b14557eebefae80e1ad0e20048ee809336fab2f375faed160b6a36f84d09c84e250ce9a63dadd0350999ad0c306188809094050c874af0ef992f49cbcf8534656ccda5391a59234d33742f6709cb618680a722c11ffb9f70a150c25dfd58d66d6c770641138e5c924d6528d3dbd9b0213580ac6aa9a8fed7844d63c1cffc128c36c170fd975b3d84ab946357f4f6e64daf6a805d3371bea33e9fa3d763a18db4be8d40016c3647090768b76776b61a0d9141ce").to_vec(),
			hex!("8020808082456e54dee67b858ea53059bb160edd6e5433cdc0b689406a6e0b8eb2758e198028321f6f6443ccad255f46f30debb49462c3ec50e79853e134852b96329b86f9").to_vec(),
			hex!("802800808553cc052d210285f729cfb3fb728c5021ebb5a16e0f5f081df4e50c7c561f9380c87659315890f101449c0846b8bc7d0fac51d1707812c454e453ae3000731fc4").to_vec(),
			hex!("802f3780edcf379572daadb00f28d23265a5f9a5c345acf399b7efe1a9214e3acca68fa680d26f9c2151e0617794c68d6faddf9ac2c697903a191992c4f4e772a747d517e4807df108c4639032f934d262a436ee237f2603a899e948153234f853ff346c831580bcefe00d529f2fc348a9237751595123f720f875b835f0863af355ba69f3674a8030011bc1da5291d9e00cac484b33115ec2d90e97cf4fb8edc2a6f0e94fb1874980f1ddb1fc87229e54d58accf1e81682bf99380533ed88761c94a09b58632f47288070b1c4c86280018fb8ca4927765e98275960e4a743547d557cd82ef7aa5c1a538087b6e1ffb09333e27845e171c52cd89dede1a783813388a71d25be01551d782b805851df58df2a6edf5a3d327b5f0afecfe01fed5d36cfc6c72b7e4e9721f3f8248010f79b987ac137d23660a0baefaaa97b3d00dafa80c96283c3f2360ebee77ac7").to_vec(),
			hex!("803e9d80807ac633ddba304f0d64ecba016dca9662f149975f97631a54f4ce1491099dde802f0fdec192cfff7933f10f018597a1ae4ad787344dc45690084501c45102374780d2e506f695e2cc1ab43354d0a6246993a7f209d4e23832d14c44df1e65bd3c0680d57143f068172a116f9816e516e5a172d673923a3728279c64e3255e49180f5e80c5d70ba380fcb9c9fc7afd581c192b52e6d22d62eb57b6a9608a79c3c3030e598032e18c9ffdf8655d32dae489fb849eeb58b2630d3fd095ab8efee115a56d7e23803c291cb0d7170f7a801499c66aa95b2aef8fa7431eace9843569957b91cad7f58027857da13cb393a02549f9544ad98c08bf67c08d94ca9345744f86997f54a0478023139cb9e9a48914faca60c6262f49b493626ff71dbaa8bb585addafe589c7218085715d2eba5615ec744050979c4abfcff500060665384ba9dff3f8edc8690fa4").to_vec(),
			hex!("80400180001f62a30ff19499eab277e5beb96cdaaa6e9078e48339b0e1fad96ca81f7df280f92e94452e422a68c8d8555789ed3fd13cc431c0bf26e9bf76528ed81a9cc140").to_vec(),
			hex!("804040808661c412e1aa17d1444477e1706cc21411d5e4b649d465d61c475b4bcfa2fc33804113745ff20a53cd45c65432e99f461e7139078fa4f09ee7f4fb78a2eb16bcc2").to_vec(),
			hex!("8044015456b032492225337bea0300002000000000000000005456ff6f7d467b87a9e803000020000000000000000054566e75077b23ad2427080000200600000089010000").to_vec(),
			hex!("80490080e9bcbdb2ea42be3c991ebd04e9687ad42b4dfb7e968ebf3dc1df6e49b5ee0e5d80b90d9eba534fa5a51f48abd2267f321272f9e69b6c3bfdc2ce2506d87d1bb82980b89708d626efc69cf2a063986d3abf78f247d6a5c4d181c4711f520d62867572").to_vec(),
			hex!("804c834856b032492225337bea0300001404e80300005856aa5e225c309a382f0800002408d0070000d70700008063677d9e4bf66b9091c650ef3fc0749de98274aee4e97c317bff0bff0bfdedb180932624aa03db3929aa9a46659461380a4ee4491f50360f3fc7a1d048d2f43d5448566d13b2c21d52eb360800001404d0070000807a66a29e1da45c3e901d6144514963d2ffc40b999a4b770baf406109d3ba6598").to_vec(),
			hex!("804e83806e737e80f34720c65f30ae9be538353ab7b3e38bd80c51eacf2cee66c5d101d080d0a82f452e4ad384d6b053f6ac50e99385f01d229b3853d1cfa4c7f5dce2d6de800b9d138f32f794e00ff3499902c4401a043653f0185e6c3778658642fb8c4b4a80f4d277c8c740628352faa3c0a873019d20dfb1b34665aff10c70b78d2dd7b1ed80c1beade3dce295a02aed64b385b0dafe34ca2895277067ca06827d94c9ac88698037fa7bf9c2668fc7e3e0c6b7891a01209b6f5e2b123ce836a1bdf33752fd3db280230b2e27d27d36ef81faf1fadb6a7f2be997ebca450b75e19a1e3ad738e1a308").to_vec(),
			hex!("804ff7806e48de3939a64c007b14d9d36378bb334caa9414802c6b6085834b278de2f7e48087a38ffaf90be6c0d8a0de547991b808d814f0400343fca84573b086bbf25332802361f257a4c05ab0f9c35a457758625161df045bd50d39de215053532f3f04da804d7f70590e8d38f0879d8cda463d82a76f6b7701bf2b7a40eda38fa946e8a690804f1b62bba2b97df141d415b2e73b8bf4a49aee26191012c95b67f006c01fb77f803476d83e68bf203dd4719ac3b86ac3289438e32c3c04eebc5331377a3f29f349809fd8bcf8719a55d4321b4061756fa14e88ee93d492b00ca5c6076aae4dc0e9c480bf25efc42d65e7c29695df1b82a71d357ffbb27f49277950993d48c54147ea6180ee28cd1d2ccb533ffc0519f83a1b2fea05e908b6870818c29bcb41ec614edf7180c789e466878df90704e927b5d048051ac3bf0b76e71e7b96badf041f83f59ea78063663e1e8348c4b27ce97720268c770fc19caee96091343852137b064dc4828580c0478d5ab87094af08fe9181ef29f0369a4640bcfa13676cc9baeaac869b70fa").to_vec(),
			hex!("805c8380587dbeb711feb47f76323fc62b9cf685fa9965ee17cc407b071b3ddf8701a2fa8091c5f4ce6c19b0ef4227812539f892b302fcab1091aae529693ee88905cf7e0580e4017499976842429b8298449869a0a110f236cebd2d53518b4051752262bb0980bec569aa5bcdbaab2cb92c7a879aa92e53241724895d819e670a9222e8b0bc03804a0e57cc136954383f1017304e99e2ec217373dbe8b69deb7f1bb7bba8a015d980d50a9daa66e6e3fafbf2b6545c4f8f7a0e067dd8f2df3099b5740953e51ba22f80f6ff29e199d2d578bc1628db1ff34c7b723ad8a7c1764003cea88fb670a1013e").to_vec(),
			hex!("806100803f40f320a7d44fd0578dcbbfa69179c8995ed881dabc4a1ee21494f98b12eecc80dec8af6e436add8d3f4c08e8618852d28d1eb9b3f6fe888462b6f51b1f970581800c71da2ab7c4489af77d366af1d0dfa7e3934193ef91dd1935ae3e03ccb0f7fb").to_vec(),
			hex!("8075888054655eb684d417b2cf9db260bb601cbd4a5e7b2b9c9f12b9bd99f118d951991580da15405fb963859f9cb6c9dd6d6b95e51f95dbaa95985b000752131405907a5f80c266c8fb7cb08ae1222a4e278a965a106100771a58fd33622dbf29a11d48e207804cb1678f035dfadba663fca5ed94d97f1ec695249d04ef8efd69eb01024085bf8039ceeeb409398cad685c6434afccdb160cb9684388fcf1756d27a2add046ab4680108756cd035e04d6fbed805f0bc56a828e163e6385bbd79178829afa180ad29c80113bcb1f6e72a674e1b8204b1c9d13c6f0028108d081242a9c8ea14a025b1a5b").to_vec(),
			hex!("807f0380cfb50936b8f4d2dc6264faba17568fb0d46480a61f1c75b35d4c84ed6367d411805658850c76c8e0d4c78b4d7b522cc6ff7a783ce68db72cf49af4cb2fb3118ebc807a927184e7eb4a92fd3161f5bd73614721b3314dbad2f554338934cc1e78dc5680cb104ca21aadb06ea617a60966ebf40c43129a3d066b1ea6e17c5a7b69c6e91680d624190bd8b55df001829389d399c0716bbbefa3bdc97e9578862394afdbada180bef717beb192238d648066c5a06138955ba76d7d95a20f1e02827cef319e839880da680453e8ffcc8af3546df953f8ff5408b48d07112fae2e5e04173c840f167d8012a32bcac04aee219d16f8a229e91ceb8b6fca49cbee1298969ba780b67f1350800af2b646dbc33ef98ffb244e747a08307078b46aae4fa9ca1a076ddab87a8b89").to_vec(),
			hex!("807fdd801bcacfc6e6480226ad9aef6fd056c800199adf83d95a35af1d0bdcbdf03a45b38059c838a1382686562a1d9075071da852573739fa9fd710e7a824b1efd220e38e807af50c02adeb268770c95e5a80ed695efe9485a12af6b6fff9e83634647d20b58059f4009b1b42c19253442876c9804ad174a2f1ed7ad5650077044af9a5353d61801a5bec8436c876222d99b4a21ab8a554fda92be495a9fa852d8c64c35183b6e580f500e0cc9c04a33aaf3275152fb08e8b1f746ff42601cbe63f602e564dab1c1680f804131abf7a208b78aaeacc4cd4016bdb52990f10c4858f231e254991590cc18050d8fe3f74fad81df76ec8851ba9c50d4f39b263b7b9e704162a416f3d907fe5806c3f9af579d7477067c1cef624612d29057cef3a152f4c67e0d110405404fbf7804e885c22a02598bf62ed20d526d41927c05160c905d3e7ca49a94ed0e57db88e80028abb399094a7bf31dc820a9cfbb38e4f95e556f29c3e481a286710593eeaaf803a020ce3fe5dd0b0d75e6271ce9c2a51cdb22e37da1733ddb252e8f02096bf34808e26e458bbf49c551ae3389140afdf17b6c775c3bd3e7bca16dd1738d2047080").to_vec(),
			hex!("808008807230a92286e1baeb9e410cd0f031f13bfaec3821e375fff2e2268f170b8d775e801977ec0fa48ec459bd0f5b9a929de1d4cfadb9344bb318d9eabd0e6d42cd5249").to_vec(),
			hex!("808017344607000020aaaa0a000000400078810088003044000020aaaa0a00000040003044000020aaaa0a0000004000344603000020aaaa0a0000004000344603000020aaaa0a0000004000344608000020aaaa0a0000004000").to_vec(),
			hex!("80881480ea15181f64bb5fe747fb139afd6e647c5283b2684204c4f88db1df4c00e45312801b5433326d99da1761205b4cee5c6ce94b99d849ca93395bbb15d6c211fae3e68020d619e2ee9995192baeacb26a96cb7dcefb5b63d2f1552a42ed063dc1bd97ba802ecfff1113d6fbe55a765237dc87effb29317696b62fed39c763086b627ba14a").to_vec(),
			hex!("80910880859145393581d070f54d3214c17b7264ccb48928d4059a0e5024e20b2c6502db80c1ad4997417ad21ccd355c8b446d8f22b6b1dcaf5fed4fe3cd41bc01ca49dbda80599c4b7df21ca43186f4a20a7f6dab8eef01cf4d965a88f7e367d81a072c3ce4808630604d318d99c4de824d3b2a12d1fd54a6677ffa6d766227e2f296fb28a40b").to_vec(),
			hex!("80a6f380157e2ba07e7dcd5869e4c52019584b0b6593f47a13b575c0ef6b0bc2ee28a49e80bd3fc768fcef6cd8866d1ff49b8d17643bea0226757cdc0554ef3829724cdc6580634598730c864ce8525b53d710952607911a5ae1022faed5ae0e9141a5ca50b5800fd77edc4f6a21912f95a3277075edf33f810c18003641a01608e3b88b60f576806b20abd77f8fbb8d737c4fb4bf690e40d42c160be787618d735d7cd17312d04980749a6397e75f8ee4953b805cb579e4ed8b3092ca12f741dda1f488b11fd7f4d080a4918b93dd88fe29f6d2601bb856af3e8422206989e2068f1ff94df0966dae8380b6f8e4185cf7e04c542ba01f4ab46edff54a980078c31b3f4af25f793f6c205280f682de46a187d5f697983a2c644e96889db91fd003337f1bf0a633e4faa9904980c8bbfbea8417d0d054d97b215c697284b27c32410bd607b1f1334c9606663e86").to_vec(),
			hex!("80c0008083995e0167de77ac8578af9796111636c7e5811f36de4a01945e2612c9d6167180155e565ae7f3ea93207b3fccbb33854963a4bbe616b2fc134b034257e2c55129").to_vec(),
			hex!("80c08980e8aa6bd49a2bf6a0f62ae9610d4e4d48b2c9e0e9f9c7202ab450384137c70cd380e057538715f4271224a948d273d36a2aa0aec1765a747c2ebf590d3657796d9d80e4520b50e7f463a2986c882fc8c28c5e034bdd86b10bd068897c69113a4b4a8480c6279d0cab3d47e47119915812024de5323dbc8772c8d31554820f5032d6d516809a95ef6086c878674ca1620484ef517652f6b1b1dfb77e8f45a056870b2ddf0a").to_vec(),
			hex!("80c39c805bce01dd905b92ef3e9007c2569e54bd457b30ec5eff34334e1fa3895c351ae88043a6a3eb51a0c05f4157612ebb9200b1f8bfd6276c7115f6c9dcd892fc7977aa80229d58a677d8445805c43cd1bf3f71a6e9d1bd270dbb45fef7e6f461fc02422b80787fdd75ffc48b03b19ec3b923f600b3c9010ec8be3bd363794baca878d0dde3805bbc7ed9bf94dcfa398acd40b78e3e34025b489a9ef7b25b196025cccfed8c9e80096233891b1941f94a448ac77ab4b30c879092fc0a62c800ac3edda18ab2cb2280c54aeb5267f45e5d1682d685eb8b2e80c6c7494541330d0b7d53daf32868a34c806ac7ab463c1505a5ec3f5bb91254b292467dd593ce222e151afb7e5d0013654c").to_vec(),
			hex!("80dc0080943782ac497a1fda6104b1edb43febcea56af70e26298b428e825acb6bb5d09780bccf533e0e80a957bb29f2965ddc4865e61f2d6a9095e17ef334fe658d721a4a80b604f0d9c4143fd23f6b9f7c2f82b8fcc199d75fcff286b426f467b9c83a701d806672e3babe19a72c4830e866ab9962867f9e567d23ec77c3c2c5d52b5cd229228004d4c3c69fd0de3901fe4062ef94b2e7e99e89ad603c86e4531824009947272b").to_vec(),
			hex!("80e6778065c35cfe27a746e21930af413ca62167331b05ecd4dc9ad61683b932e6d52ab380a266a7519dd0a4f76beffc1048904c9989deb94a90d8f20c1127fbab6dc4d1f98097679df04789eac59989b2424bb4e2af650c5c809d0098ddb2da844cc33bf87680a9e9dd724dd503df5f2c29e01e074697d4a0ed8b66b013ba135e561a398a9e348067365525ae7a69a26b7cbc7ad726524d3546faedc74ecc8bd6d40b831ff6c863808d5e166ad2fbaebb8fa5dab49385ea4ac863e5fc95a5c3c7eaa106715138e32d801db281200abacbb8bc06b72079e921704e707f3094c19679b363d79c978b8d9180725eb7af94abf259a7d7dadfeffcfdda9d7ec6d83fa105e26bc6d54d69ed3ce7809224731b37ed912cb70421c963edd1eb336a20d53c0939b6a3f5daead66b48f280a2eb40cab1042f698f1d26780e43b07df40ad8760b5d86e07d8ef0e96cc9e0cf803fc6c013ce47d3ab1d4ac45f1fbb85b72fb7b054a9032adf9513e9805328fc95").to_vec(),
			hex!("80eae4801ec01457df7975f40ce32b660ffa6b1d0ba422c26416fbe6bd1cc2e8efd06db380f5317243fe29fbc20c872f8114ead6dfb53d318b5231fae7d596439dc4bb887680c228f4cbf4cd8ae9c6d55f48d19fee7e3a38d29324636934138fceb12ee3ab7d807d348c5e2c9669c686432e10716949d8fb15540390fd9b318c2f36735ad21263808e4f04d8061a7dd06e1e39778e540799d58f84ec50f89b34462f1464af6e7ab6800e13b2d869bebfaf452db48fa91a34d7810bd1fe808f6060228842313d5e256a80fd0c4140ad90e1ee2cb49dcb47f28ec64958559dbddfd943913388d10e8315b78001e445330f8b21c306967c45a39fa3d9415e4963351a2a74abd92f53c64b08d2809a14e4f273040a9a0e92787f5900a1755dfbd4d7c85493d704bd23746934e21f").to_vec(),
			hex!("80f9dd80b4554afcd19d1bb4ee031e4c7b24fcd0ce53b8c3510d2e8efb2e184fa4d87af2800b6cee639b5703da9ebcad7f651d104c52f838626ef70a401fab45a649f76937809381bf6ba184222cced7d5df3a410bce6c1906d8324540f6a1a187d688f94f7c8016ca96b9875522c3396ab3484a0ec2d4ad928f723f82d260ccc660aa0c6216ee801c342643397645f0e7f332bd56a95c2e9bfbca82b0036b2007deb4d176e57417804edaa8724a9e892ea9ad7024634774a129bdbc2ad65073124e30e6a9088bf53a80bd087457dbb73f36194d60ed5ea1772e4021817dd401e87f564c3c29629fd5ea80947ea4a5027a0dd7f20837ea1481f31e2954b022332cbe221090bab8a6afda2b80d956263ff5026bada73fc43f6a12e039d201506263d1e111c2ba21e352d726e38017a7051c5faf599ee4e237854b8e6269f69a616b4b6df475820dc05985522156804db0a5589ac4f893e633a2a219150afd601bc7ec800bfe2482af3047af2c63fe8015e9d3816afa8d370e4d2c359acce94f02f9e5e37e43ad40652c41dfcff4a2a8").to_vec(),
			hex!("80ffff80ff76aae5531640edac6423388bee8f3dcdd7ef1b4360d703a51fe8d898e1402b80a788f173028011ec00fd0329951f3d882cb15be7a7efb3cd3546ff0af9ff27e2803a16acf1821b4091190682cfa5b385cd98de560c7536ca0a062cee846e0e799580287cd520d2e603a4738955916e0714ff4d25f57e877a87c03eb1d927bcc7ba438019572171f282091b5af15a1cdb5cb1b9392b44a0027d440634ac1956f7b478ed80de4ef0461317b112ddd092d9ffcfdc0a2c875ba4525878d094ccfff9edaeb90080637819694e7442d09ff191cf519e06e31224a46bb60f124c6f3e1faccf073dfa8054e06aab76e24d66bf5fb407d4ffd552dea6e4b683f24f206ba53285c780ce83809ed6ff13141140013f26f8395ac70d31a32bc2151259858c0a3df4b02db0f03c8030d50be4d04fab51301c6f168063bf49c66e3539fcef269c5fa7f59bb6d6c74a80906990fba71b14bef9fa4bc6347dbbd78c0abdce5c3aab72a16e0071eba724a6806e5346110f0a735f94d00471ac6b412b647b72c9cc6cbac6f8cabdae0a51ae9580e7bc7b2c6ba10aa68a47a3b318c96a0bfb54a65ffc0af3adf6dd63f89ba6079280b5ea5d6d0d474eb51b1bdb7526d49c0f8407e051a89617da47b87c17d17331d5807a5077ae8924247bf4b4eb471806fd2d57e3337db5226460930481fa0ca5bf1880cec10bdd2d656bc14660c4a8ae40e76b2ad2c9ed643147046fd8de6b87e0a951").to_vec(),
			hex!("9103a28a56962c8b5fa71ee435a4a8e0721315bfdd66a467f1c873eeef3aae1d5989fe0062013bd70c0def19b3d2da2d179a75407ead813b1839826ff71b4660d0a2659826338e221aea32905d38cfe23891a6fc4bd78437cab2935ae39d16f37932d6b3b8a70c0661757261205dc57108000000000452505352904bfa8c018ce4e828d7598872eb5a93f12fd7c6d25cc4c00064dee5b3a12b70380aaae70405617572610101c22ef1df251a0d9d77f056d70d86ac66f6881d85284e39d0962b08766b09b32f4a92abe1e9981b6eac5c88ab477abf3a9d315f7c105c2284a708eeb56296c082").to_vec(),
			hex!("9d007f03cfdce586301014700e2c2593d1c08063828bd4fdc2dfbebc2d7a771be214522df151c03801e2f9c0f2f3a8e8547851505f0e7b9012096b41c4eb3aaf947f6ea429080100685f0d9ef3b78afddab7f5c7142131132ad420cf00000000000000585f02275f64c354954352b71eea39cfaca210cf0000004c5f0ec2d17a76153ff51817f12d9cfc3c7f040080d2705ed6fb4282e60c9bfb3cefb5f1c1dd6743438b0988ac5e304cbdc7d26782").to_vec(),
			hex!("9d0da05ca59913bc38a8630590f2627c17dd80ebda459533e621d37a535024ce510d262de1773e8e55d92da5401b6cd4d7637680d7a01b4ccb277fb3b91cefaa0a9a2a043d38b98eeb6d19012fd4a3702ef39ba080dfeb24124eb02e900d4c59ec8de843786b7732e8229ef9b4d356f9ec6c55da31505f0e7b9012096b41c4eb3aaf947f6ea42908000080af1b5b29387bd9eb8c289a9a83430e8bc5d6b8311d5a7ea5c07e19e87cc2fad680cace1b4bc0cc4d171084fd79c024a8dcfeb076a13798e482ba028ee3bebb246980c0b3aa86afe77463adc28c6c34c71a200e3888c72531449845cb1bce6f3d8be480b544aa34b22c8ce065d7e280d46d0af733fe8907a6c96eb8d272156be37ef0b8806daa3588f32a96573c74e0d73444c4647c6bd2b2719b0b7716b11d5c8e644dd780af28e0cde6aed89ffee12c107290bc7ebda4b4c7f52e4f9cbbae651317d77ade").to_vec(),
			hex!("9e710b30bd2eab0352ddcc26417aa1945fc380360c98cd291f697953f9d412ff4d0af185ed19732597d8e7bab79827975a75b080e460a1851d37f8b730efdcdd28210765c9d3cc5501395bf229f3e03bb67019e180cc507e3c24e7265c2756d5ea5b0eb28bd73e53e46db292aab9a7d457f68a2d6b8049a8eed89fab9754e3d5155d25d6f403a200648bcbe5bbb03be3030d99dcdfbe505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f03c716fb8fff3de61a883bb76adb34a20400804fb29dffddfbe7b7c3a801e4f22b904e70cfb681f3742706ee0045a52b0cb1ba4c5f0f4993f016e2d2f8e5f43be7bb25948604008046365ad8a785967033a772169eb996427745e113a5b8fd29c2d564b696f401ed809a812064857f01877f367b044d298567f4492c9ce05dbb36b6e39cb75a45d38c").to_vec(),
			hex!("9e7fefc408aac59dbfe80a72ac8e3ce5fbff801c902cbe419e7cea75b1d971cbbf91d733d711f134307162e1359cf85d02971680f62ce159296d30b0975fa703c88335deeafabe3c047f59f37deea5d4b74d0bd1806c6aeffc7bb2d635aca1e667d42dceed9b337307caf841f643efb173cdb6a05c8099313cfd08f7454a4e254d07467c724b8e1f8a20fcaab8e795ebe20ac2efc98b80a38e2ce5933ec05307fc6e11f82592d62e8236da22a7746995618599c0de1496802cd4e4e88c171a099b7decb4b5870710feb9373923bb705b3c47f3d64c455f3180249ac884f757608079745ec844acd182411e5bbc83bdf670fa6e52171a169eff80ff3730246e45762e9b43f5d5d1523d7a5763e832869ecf8d0db6371ff5728a0080540f8666993d4bc0293b76860e97b27ffdfaa4ec10bac34823f42e4f3c4fb5fa807db12a17b28c0d0bffe7c9c522ca642a91ed499edcaf31eb9838ef82a35f76a8809d9997fdf4e1b8051027bf7c6c4fdd86d801beb1cc60c53c11869048ce2f1b4d8078bcab20d17237fe3c95c85048643b8eeac6a9b3974caa0713e208e415d5bacf802e03d2c5f1d5cb5743f237dd38123bda5354eab3b56b1f6a4579fdd2906a24ba804a07eecd8261b82a2f42e04a8181a8b0802abd207f011ad733c120a7c08e8f0c80d8463698b1dc2c93bb8ed8d71e08b5df853bd8636f7253ab70340230c7b1420d").to_vec(),
			hex!("9eb6f36e027abb2091cfb5110ab5087ff96e685f06155b3cd9a8c9e5e9a23fd5dc13a5ed20bc8ae31000000000685f08316cbf8fa0da822a20ac1c55bf1be320c487000000000000505f0e7b9012096b41c4eb3aaf947f6ea42908000080eab2b87c39924e24d8df1881d71313be2edb36c0def5608fc4c080cb7fee6250809d3fd79275a68cdcae96054d764f718cd8cdcfcaffba58588647a7356d9a4978803f9b05ff5e7e50cd715adbd2733504980ee170154f810983b5d896122441150b800d49fef039517cc312c00412803ca1df50ac6d90c50541f649a9c85b83c0fdd88002e416fcea98d7b1e8df493877b93072eccaa860e42a081a80d7831e71a7464980fcfbec2850511c0b9896ff447368a4db19c159b11ed23b63c59a8e3754c68a5d8069f958e064df4bc2939ae2fff2d03fe3b696ffb897573519f2b833b69ea55316685f090e2fbf2d792cb324bffa9427fe1f0e20bfe6390117e93901").to_vec(),
			hex!("9ede3d8a54d27e44a9d5ce189618f22d3008505f0e7b9012096b41c4eb3aaf947f6ea4290809004c5f03b4123b2e186e07fb7bad5dda5f55c00400807273d96691e5d9c9c7bfe351d367c9b0aba25ed1ffb23da3a59d4b549792a212").to_vec(),
			hex!("9ef78c98723ddc9073523ef3beefda0c104480bd65e89352678313da760a786868794d2ce8ddcbb94112f6f645c7dca3e9b4ef80e283a5f10c6f8a8b6cc5b4f97351a7a14d384967e8b37dc17290e7cb813b5d4b809a8025095f0fb1cf12f83b2799110508a9d2bb3060ec9c805ed39d483d18cbcb").to_vec(),
			hex!("9f012b746dcf32e843354583c9702cc020f9ff5c5702a6fc915ccc55a0300800002408d0070000d707000080bfadc9bbb2c3ca2b38cd11b725b0f41a4d082a542db8367be0c14911e8bc668e80c0caa3a1941089d9694945f064fff6cd5482f9e49ecd94eb0bc4985cdcb9f43b800d93a67b11fa746acf6c5c7fa9b58f529112824c157144bf2bb2217ccf12485a805a3b37efc61813edd3841e2d309299c89b92a311184e065ff44b48ad8da1f5ff6c57073de59802de4637e8070000340cd0070000d7070000250800006c570c58f3b5989bb72cdf070000340cd0070000d1070000e707000080770f754c658cc038f95b520d1b1e4d00c10877e482be592b8685fa8ba7cb57f880e98895c9c0ffbf97c65956ba272c22887aa35468434c9f85e1e1381d31e1e38180cafce73d6ce28a72801c89e30eb0fbf937fc0178266c70f95e6165ce78d3adb180239c34f9ca90136889810a2033709e5bcf7d0f0f6bd6aa989a06d0deb76321de804fa3dc756442cb94a5a1157ee2ddde94d5aa5848f4cee0ea4ff7aeceaedbd0f18000a78ab1fcfa723fc6f48e95bcfa3f49bd8df60228f60a97babbb80f9245741c5c570c7327a2a48bf2b1490800002408e80300003e080000").to_vec(),
			hex!("9f06604cff828a6e3f579ca6c59ace013dffff805822b1b8d57ff464e3142bffee55bb842310b8fe09ac4b5dc6e534de1b9f4e8a802368ac8e3f37dcdb00892f09699313eb0961806e5dfbe70a8da32d2662da3509801494938b3fc8a9ae08c4465ff71ef379c7a8cdbb4677c85af9f2c052cbb1b80e8064ef08748d9c2e1dabe90fe06b871946e261920ce3ad30dd588dc20fba6933c48059341632c3f20251959d36a5c5fb724977cbabae68ac2acab5d3b6c15157a45080ea77b66dcfbdb6fda7d686af86f79e9e32ec2d8d699ee05cbf00aa4bcdddcefa8035c8c0ba90859be0d2174bf51c7c7b72dc54e5362a5f6498572369f7332bf8d080ace22ad75a329be8268be380fa986206c707fe8cc408f9c1a24c105728c48e168027ba6c700ecc3c1cb1e4e7450987c2dc5583134222ede6c988e227934427eaa1801ed184999bd1b2af34a43287cc720cf05f6969714575eef9630f5ee706d41085801202cbab53d52b9f17e3529020facb3747f4a2e8f496faea526a1b12eaaf5c94807cd1f537e17348a27e05dc775f997b0f2b76bbdf66c027a5b3d734c55505c17e8033c620bdd1cf4b0dce14fad89a920caf966e4e279efa335ad520781e72945ace80cc4fc572b0ab027567561bb41d7b315f7682d8f441b7cdd34c3fa077f4ebcbc7801df0b7b316a1485c2ede799d49ef2cd2198b8dcc47773226dbbdaed89bf8f6b28052420524019840e50797f0aa5c9d050723888a935656674b534bd360d5cc525e").to_vec(),
			hex!("9f0ad157e461d71fd4c1f936839a5f1f3ef8df8008ef8ee2ab5466cfcbe2251cd0aa4c9e43b4a15a6a2919ebe78c3cef323bc37a8045add92157c7b68d3fbfe254d814c30861b567ca1a261eef264dd0a21fe5a0cc58570c88433df862dbcb2408000020000000000000000080f1f90ebe2449756caa238a37a4f622baa474567d5d3178bc84cf4d94f4e4a9c45857073de59802de4637e807000020000000000000000058570c58f3b5989bb72cdf07000020000000000000000080a43a9cadb8df327bd035615f93d1cc99719da39113502a1dd4ce6f099d47e5c3808f6f5121aee45b4e788e40c5cf493fd9e0be05187cce23b1c861f7bcb3b1feaf80813e3bb93186f01cab4b632ba8f5873a1289855d3a258dd74a38c272ce61761980588cf3f41206413f7c6dfe3ff1d85befce030efe50a3b8e8a4453b87d3aea0ef5857073ba61bc4d713354b08000020000000000000000058570c7327a2a48bf2b149080000200000000000000000").to_vec(),
			hex!("9f0b3c252fcb29d88eff4f3de5de4476c3ffff80ba024dfb1b77ebcc9a1e9dcd0e46ddce1af8be35a9f8d7667f1699aa963c8e5380580670bdf4d75905b6e4d8e2215733f20bc5e01d9b847e643e3befeb8970274e807f7cb87e93b3f3dc005d3b0abe70153e95f1a9791315f08c5e748c8aec0fadc9804ce17556f23a81af65cf79f8ecd96e7786d81dc03c41235958fc77bc689e39f5804ea9a9ff2c86cdf5489a01a6206ac844b6f97c284254e0938e7db650781a271f809291c1bed852629e118ca4877256c2671f6d12e6e8e1af2835f4c860d13e48a78000b4698cb5e42b2b24cd8f837ccdc305669a91ba0843c01a0fc73b65300035f580a1c6da23cbfd2295b14cc86eb10407c4e99b094b6d1f22da4e53f1c0fe6eff0580030085a5d66b7b28122b4a9634a0295dab7e0e946f3153092e027baf1c6ed1068092355bf9be9bdf16cb66fd9badf8afa206fcbf90996badb0c87d33050f6e2f2c8077e6c818bfc2ab5f7a63aa788d1f7a591752643d1bd5f260d82009e44d90f4de8065594ed4c0839ff17bfed08487885b0dd08863c695bf41d23c2a294bfee292e3806b03ea8aa59a84d30b2b127bb65cc008dbd840e311bf1a8f8b68fd0ab01a5efa803b63ee4199abe7fd2674014f30ff8718e3adc61d33cc09496b48d13db8f758a980ddfcbf631afe9105d66549406ac86f2c64f17f5fdb25da69c67a44332ba728aa808c912d638eed0af3b1c135280af00625e0189fe263c1c8c40507aa1fcedd007c").to_vec(),
			hex!("9f0d3719f5b0b12c7105c073c507445948f9ff5c5702a6fc915ccc55a0300800002408d0070000d407000080b7c6e2167110e8b651eb693a5bbfb83b6f968091478222e136a68389f2cd385c80e6086b406a930613d6f03e4d1bbaa36c00c53c176b59f4d9fa63a837fb0cade87c570c88433df862dbcb240800004410e8030000d0070000d4070000e7070000805a3b37efc61813edd3841e2d309299c89b92a311184e065ff44b48ad8da1f5ff5c57073de59802de4637e80700002408d0070000250800006c570c58f3b5989bb72cdf070000340cd0070000d1070000e707000080dbd75e09babf2a19db3fedf382d7e7a16978cd02c781b1ccae2849c29a605f15806f95921fe3f4084c32869ee6a76db36d2c982664a628869469cb658c847ebe7380cafce73d6ce28a72801c89e30eb0fbf937fc0178266c70f95e6165ce78d3adb18097fe80188ec468eb8ee172ddc2f8a6606482f09058b3fc0034596be62867ab09804fa3dc756442cb94a5a1157ee2ddde94d5aa5848f4cee0ea4ff7aeceaedbd0f18000a78ab1fcfa723fc6f48e95bcfa3f49bd8df60228f60a97babbb80f9245741c5c570c7327a2a48bf2b1490800002408e80300003e080000").to_vec(),
			hex!("bf0e02656c61795f64697370617463685f71756575655f72656d61696e696e675f63617061636974791c60808f6e2b238160338d09b9777042423f2c080d2554575b8b4c8282606e91f0b2b480e229e6382cb05058145a936a2c33a28e998a98fbb4a9123e2d5108a5613bcbc780462c6fd312f1d8c48aae32e5bd6866bb8395478ba334c30720f035938f5eeea9802413ada492771a8e2130c6128d13c09432ef58f80106c0e17c07fa97bb23ec1d80b0018a90e5093fb5d579d76c73bf1b65fe79d9d1e09b4a3654a6d9475aca50a0").to_vec(),
			hex!("e80300000090010000900100000000000000000000005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000010305fad7a0ae358701d8c8dd382d43f172b19589419d3844cd707bcbdd463df9005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000107bba9585f1432e0d4e4b62dd034776d239f7c8798c65f7ef9bb639d3b0f6988005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001093fa1ffcf9abf23881294f10ec5622e19e69968f312f0b535a808671c8db37e005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000012b94fa94e4ac4384ab258701255822180e06e8dd482cb6516ec11cc9245da55d005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000013f935c894b48dc883581e0362b9d8801329eb2ecf8539ce35ced900e7c8b888e005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000140a18fabd271f1a5e4fcb0e1d96ff01ae686dae46fb0e7a8892cec97f8ba5574005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000153cadca5a7be8eba1363c9aba5781cecf6b3bc59f3182e55e6fec355e9509116005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000016278c3f2e3e9c118a9005fe5a544cc278b6052472e4b1cc32b0a7e7643359a68005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000163677a48bf325234e5d67d153253bf2f0e8c9995e8e042ea42decc21893d4ae9005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000016a1bfca2dddf6aaaf52c5eba07427a96e989f94910a8ec6796a0a39f1202c7c1005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000016bc1f5445e8ad2c251b5f771a5ce653c0a214dbc600b9918e11e0f20a25c5b09005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000173fc47b2858261eb40e7e73b9124e04b19d72aec4da087c23700285c16c7ca7d005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000017cea21f428b2b3b60f39aaaa38df8ea22a75d9f63f046bd874071021fbc583ec005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000017f70f81377f6fc1aa09570a4179b81b594e7b8ebfabd0718d3a0a7491d3036c6005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000018d1f26e6793d2b4827c57aa4bb6e943d784555d10b725984a52e3878ca3ce9ce005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000019abfc99687d3363b2cdd538c081f2c762a7cfe58832907811bd8d6baba868602005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000019d94b07e995cec5740fe6328dc1d53a5fdb296844544bdfc665f49778fc70f6f005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001a25b0f899a14f6fb6c592e2ac6894779d9be71bf7615560e1522d2012ea528f6005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001b05bb7ec2cc7615f5d28f566185505040426f8471d5f6f8becfb01c16d92f630005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001d198d83e299dc6445b36551102a4b2eaa47abacd3b0657b5b1e498475cd9dd2b005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001ef71f5fb1eeccabce794c2d1b04235da282d2e66c507eb5bf5ec4a8f8f140c5a005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001f6a0f0bf50ff677934c2d37d99926ffe5d007e24ff32f8d665acfd3662377a4e005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001f793fe84288e0d06ba8c2028c5955f6629e7af1d16aadb87fe9b5676c85e4bf2005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001ffe8c75e69e49cfedf1f7d863beda022272916e8a1bb7d450ae30168fc5f0e81005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
		];

        // kusama asset hub (statemine) block#5,823,280 works
        // parachainSystem::relayStateProof()
        let ok_nodes = vec![
			hex!("0000300000500000aaaa0a0000004000fbff0000800000000a000000100e00005802000000000000000000000000500000c800001e000000005039278c0400000000000000000000005039278c0400000000000000000000e8030000009001001e000000009001000401002000008070000000000000000000001027000080b2e60e80c3c90180969800000000000000000000000000050000000a0000000a000000010000000103000000012c01000006000000580200000300000059000000000000001e00000006000000020000001400000002000000").to_vec(),
			hex!("01dbcae190c70b867ecd0fbe980af4651db774b3a8576424e548c8f79935dba36b").to_vec(),
			hex!("36ff6f7d467b87a9e803000081879858c3fec3f733fe2e3f02ae2938ebd014cf31f1fdcdb7449664ec481944").to_vec(),
			hex!("36ff6f7d467b87a9e80300008338d715bc037e99b43985990f53caebfa8d5ed41f8f9a2f3d20048e691d7fa2").to_vec(),
			hex!("3d0027092eef0545e8030000d70700000f4891eed327ec619956fd7a4a69eb71aadc28a7f8ea475e857645df783856f9").to_vec(),
			hex!("3d00288c141c721de80300004d0800003d96d2fee6debbe11f3ce3225dcc4f0b62edb6a1791aaafcb661faad053db695").to_vec(),
			hex!("3d00ab91cf0114d8e8030000000800005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d0417395fc0bddfea030000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d063802d0f8d472e8030000e707000088e03f152dc913082561cebf1201d4bb3da8eea8e395e7e8a38afd7a43891932").to_vec(),
			hex!("3d0a18d8d01946cb2c080000e80300006cbfd35aa95360c4dc316f9b825e6100a589970cbc11e9717c0682bd245ebf2b").to_vec(),
			hex!("3d0abb2f2bb1c94f3e080000e80300007c3acf45e8f82888c31994e1fdfa96117b809b75052466ad7a0f5b21bc07c159").to_vec(),
			hex!("3d0b7902b430328be8030000490800005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d0b80079d8b99f3e8030000240800006e90d9a52eccddc21946b9184827a5aa7c8f28d52f55a93ccf379929f21f2cc5").to_vec(),
			hex!("3d0ba169a93195b3e8030000d1070000a2c652e2c6c495ec464a7b46becf8f8cc94c14f5acb0a101dc619b451857c1f6").to_vec(),
			hex!("3d0c0201e32ae86bd1070000e803000040264e6d205df9469889487febe5b59555f54e4ccdd5bba893ae27d622bc11e6").to_vec(),
			hex!("3d0c808d54a8937be80300004b0800005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3d0f1131b7f54b0800080000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3e0053f38ebdfd42e7070000e8030000c49cf7b1fc233b4fced68be1f3a64a41975804200fde40a671019a18667dc7c6").to_vec(),
			hex!("3e04d2a15ab51127e8030000d00700000a430aad3a657052c4ad316e5d6f218d0e23f32eaff72c96da734dd4819d3563").to_vec(),
			hex!("3e0f2c689744e55be80300003e0800001bda478d77d6c33addd274f6802a7284f8be483504bbc963d50b0857f457ca69").to_vec(),
			hex!("3e1c643c9d90ab7427080000e8030000a77ea7d6dee800cf737999ea6b5de7abace4e4d9336cc9d14cad92699931a535").to_vec(),
			hex!("3e1fc502e2b07e96e803000027080000c6441d6967e9b776f0370af73bb06aa9515ad27a10b53ff7393da61f8162be1f").to_vec(),
			hex!("3e29b296823383d7e80300004c080000f434e45a5b74f98880767169214528b5c4439942cd1c4309d09d6eb548e8c926").to_vec(),
			hex!("3e3ba901905f80c024080000e8030000e6fd550482fb6209127dacc57e4b326cb79d76596dbfc51a0dd2f5485a72b9a9").to_vec(),
			hex!("3e43d73bfd0011312a080000e8030000710cb8bb29093c8f77c20f5ede8f22f3b10cfa1fabf18e70409de15ec23944df").to_vec(),
			hex!("3e4f36708366b722d0070000e8030000dfd4aa4514e6acafcace188a294b8f5ff81712f05fa3b824e4dd168127101580").to_vec(),
			hex!("3e5351db2428a52c4d080000e803000095ce736a7c6a72c08b0b8d49e8b0d7ea21a69d0f3938f15ee116f3be0323670a").to_vec(),
			hex!("3e55ca0b91260bbdd7070000e8030000387fddf5b0642679e076aaf48fba2b2f2e866497cdadc8beee94ef3b70011e42").to_vec(),
			hex!("3e6fe8fcbc5314b84c080000e8030000e6b7d897b76212e737f36aad983d29046111061997c570fee79f6f6882de3e7e").to_vec(),
			hex!("3e77dfdb8adb10f78f10a5df8742c545057e5170500373c672c9975fb42bd6b2cfd6119ea9a355fb061c2661214c5958").to_vec(),
			hex!("3e7913c5068de7ece80300002a0800000d627e8e01ba6619aa3f7383718a9f824909ce8479cd2f009f5e2baeb23e9998").to_vec(),
			hex!("3e7b9ae336e44cf849080000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3e7d99738139957de8030000ea0300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3e99246104cf41564b080000e80300005102112cbc3c93e6f2491146132ee043bad798bc1db870f00605df447e29be82").to_vec(),
			hex!("3ea0c4f025fc646725080000e80300001c41f4cf354b008ead90a1848ad8eb7c971004a7d601dbe34c0861c72f2370f2").to_vec(),
			hex!("3ece433339688292e8030000250800008554e3797f4d6bcbc441c8c360ed689c57f190d696beca782ab778109fb21bf6").to_vec(),
			hex!("3ee82ccb5cb954bae80300002c080000ce041f205c5639125128c7f70774741be5b7b34639b30aad6dc4320f5463901c").to_vec(),
			hex!("3f0004b49d95320d9021994c850f25b8e385a259772211246037413843b474d01d815daa0c5f682d658885e9ae6e14fe57a5").to_vec(),
			hex!("40ea030000d0070000d1070000d7070000e7070000000800002408000025080000270800002a0800002c0800003e080000490800004b0800004c0800004d080000").to_vec(),
			hex!("56ff6f7d467b87a9e803000080f5db15f556f5c4809fdd5d3e8c7ce8b9d0c7306c76a3034ad542936dcc74f7ef").to_vec(),
			hex!("5e414cb008e0e61e46722aa60abdd672806b743d4bad2f155515fdabdf0b6e7952cbbde469da064791bcec5418f25f684d").to_vec(),
			hex!("5ee678799d3eff024253b90e84927cc680fec134782558e6aa609441f3e800744713ce49fb43040932074aaec4e8b8f8e3").to_vec(),
			hex!("80001480ba0fa958e23322acb5883078a7ed208c002c368c1e0640d6d6d98d39d0619b5b8051763bc1c23ed47253babf64afdb5868a57917f801cd11606405d3c803bff096").to_vec(),
			hex!("800060801d3027fa8df4225fddffc1ce0f7cced62013b4712a12f8cde0b9b6f3ae7a78e14c5e7b9012096b41c4eb3aaf947f6ea429080000").to_vec(),
			hex!("8000848051a8ecbb57640b25357003a2c8404b329fe56ae730514a238420771b8010f519802665115226983291438599ceb37967c42a9476dc562598f9ea1bdef2d8334747").to_vec(),
			hex!("800110801062413ca3cc77aaf4d5d6fc2ab0f92d756c9175178ada03377761abf0890c07800ebe650369ce0e3ce85b22816181f598cc6ecf7a3b22314357ab4181b9ccb867").to_vec(),
			hex!("80011080fc91db52354ad06d0f845562420f7936337b06c2f4959d26f00878003373f434804a49ff61d3190c87f0a6bff4eb0661cf6907f6e3b77e04f25b8ecba914297b70").to_vec(),
			hex!("8002a4806231212da6baa80044a1d72059b7d9ea47a832d554708b48f95f3b1ae818400480da37fddb8d343fdb9450281b5a7b89a4fd89595c457fbdcdd8f6c13e58040491802cb5cf0b71237e1c5c90f198ee0e7de47b53ae0d16d5efac1ed89cca9b847d1180c6494da6d7e7a4952ca0d7b232c3866f7592109a2c2d3292ffd4f41ae4447ab6").to_vec(),
			hex!("800401801e226c962da28b0639e3affe37b1b0f9e26a5cb3d5e1aaebfad5a8e89429c05180073d2ffc2d5c08423ebe357fe876182f2ff80855a20e7e8f2376bfe1abddf6b3").to_vec(),
			hex!("80040480caed81d35effe27bcafdf50daeae64f24f6fbaf3135cc7fb5e17cc509c332a2a80e1af12e9054e5b39d83866c1ee03b7f3c2041a679e6f27463f69263c09ec78cf").to_vec(),
			hex!("80040480ef8369476cf4dfacbaa24ccd3bd094453b876f624359482a1995239ca70cc4f6800fe6b03639ff2739e42b263a64b97458bbb7b04a7f13a7dd10b77ba5c3d3940e").to_vec(),
			hex!("80046c8017dee19fb1888ef7a5bbe38b6454a5f621e208db03ebef2897b1bc2199240808807e7f3429aacde46db62c8a4263405d567c9261d11cffc8bae2ef4ab2510a48b8808f83f0d8e6399e9f9d10c3c89b614e318848dfb7ecead89b137ab1fe2fa968f98044a94f786a205e7159f3bbe090d844ac27748b680959697b4b7bdeb85c5f47dd8073e31309cd2d56a902d2ecc00fc39063d81cafc4de97cf371309cf135f641d5c").to_vec(),
			hex!("800802801d79c3436485a9c1173a679f70877d551c8a84cefe54edf4e0867ee117f94fed80d4fa184dad7a3c7c443d478ce0aa58afc3ec264d3aae00943cad72c34a32b4a7").to_vec(),
			hex!("80082080b43e88f85f2d14dc60a130c29e39b4b5201182a30a9b04141397556b4356e1c3485ead6eef5c4b1c68eaa71ea17a02d9de0400").to_vec(),
			hex!("80106f80fca96f7cd27fef556cd361bee696532434d4820934a57c329c4d927b874e9b9f8076365ef7e5bd0d0f42f498cd62a36ad27739c3c741143a5b71039a65a90d8fa280d6976eb32786962cf50707a3471004eed1741ce866c9e0eafd983d60c5dddc148084d3a7753434b742e57cbd8570dac34f73211b8a99070304399935a40c857dab80fc4d3427b6462b268fac95ecdf755f237ae533e963882da5cf70fd330d8de1f280053d9db3b062ab428e37b03b05ebb5c033b0d0e76b5d59dbb52dcadf8e6a659c802c4ed677cf83d0cf1106da0ed5163fbf7a04e699e553826305b965956d7abcc9").to_vec(),
			hex!("801080809ca86eedb0f39eb5d7d4a05387d1ba54963b16eecf5d518af15bf057853a59d680339f920b1e559d1ceda19ee1d5335e713a97a79a4474f2fd5884be18fb7449dc").to_vec(),
			hex!("801117806083fccc5ad9489e8fffd469466a4206a743d8dbbc8fb301059daa1d198c86288077b7b1af409a8997625ea767d881ff79dd3c4d1b472e1f0a1fa3c4c4f96324cf8066e43787bf816f635f506ea250ddd8d1ad193cd2681afafbb56d0bc343cea6a9805397010ea8adce59d2d62f2442e91110fa15fa9643c51e8793ff4e8f7f77ac1e8047d306502909a31f46f0fa655debc2ea6dbe1edf3666abb2a0aea3f5913a78d98035fff38ca806c91ccffb246e7f40f524e201e60f2915ed2431daa281d913dbcd").to_vec(),
			hex!("801eff80b4cae9c834f4de3e5c5ba5f5f4b2808c3bb03fc399660f9f9f652bb5f3a9b75980550e5b2fc17d5f529f33dc284b6a35522b63a2631eaafd07de2b8dbb75e73c2180fb085333efae166f53bc63a050305f9341f5f0399883f487d8643faa5f0ed7d080c958175468eac0933646bf4576983887b31e54f6de527541c8b52203a59ff1a0809f6b9ffff9ee064a3263c07887136d4e232f2d2cbf7355037b92d65b53f32e7f8004e85658be70231f424ac9a280a0838d95a1fb68facd6dd27b288c018e409c4980fe910d14c185251f4308b96cdefb8137e0c9578760a56526add9ecf687fef5408019b079ff41ab32de041e499880bf6da24cf0105945272d64b692da3b158faf53800b4b93629b1eeadb2a2e416c2c0bf1fca0bcd69f7d7da4572661b60117a29158809b4223cc76ca875fb19a319d0a7689e99430f9130581617f8b296864fe31135680ac6aa9a8fed7844d63c1cffc128c36c170fd975b3d84ab946357f4f6e64daf6a805d3371bea33e9fa3d763a18db4be8d40016c3647090768b76776b61a0d9141ce").to_vec(),
			hex!("8020808082456e54dee67b858ea53059bb160edd6e5433cdc0b689406a6e0b8eb2758e198028321f6f6443ccad255f46f30debb49462c3ec50e79853e134852b96329b86f9").to_vec(),
			hex!("802800808553cc052d210285f729cfb3fb728c5021ebb5a16e0f5f081df4e50c7c561f93805afebdd7aab9e13859b1cca4516d9c85fefb8b76a968a033eb934547cbebeb7b").to_vec(),
			hex!("802f3780edcf379572daadb00f28d23265a5f9a5c345acf399b7efe1a9214e3acca68fa680d26f9c2151e0617794c68d6faddf9ac2c697903a191992c4f4e772a747d517e480ac273487988b33d642882171b7289f55eab6d4c6c286c405a0bc2d016846cc0e80bcefe00d529f2fc348a9237751595123f720f875b835f0863af355ba69f3674a8030011bc1da5291d9e00cac484b33115ec2d90e97cf4fb8edc2a6f0e94fb1874980d31a0e0f4aa371d2ea946c4c48e0aed0e31f9c97e95d2b65b0777350475c30858070b1c4c86280018fb8ca4927765e98275960e4a743547d557cd82ef7aa5c1a538087b6e1ffb09333e27845e171c52cd89dede1a783813388a71d25be01551d782b80866d6ed2e7f305f3353514ac55839a9799e86bb24c4313a4efd4ff5bf42fec8a8010f79b987ac137d23660a0baefaaa97b3d00dafa80c96283c3f2360ebee77ac7").to_vec(),
			hex!("803e9d80807ac633ddba304f0d64ecba016dca9662f149975f97631a54f4ce1491099dde803a07e78b5f3fc27a6b7ee4a9cd7bbc752a2ad4763972de52b74a10bd59917dce80d2e506f695e2cc1ab43354d0a6246993a7f209d4e23832d14c44df1e65bd3c0680d57143f068172a116f9816e516e5a172d673923a3728279c64e3255e49180f5e80c5d70ba380fcb9c9fc7afd581c192b52e6d22d62eb57b6a9608a79c3c3030e598032e18c9ffdf8655d32dae489fb849eeb58b2630d3fd095ab8efee115a56d7e23803c291cb0d7170f7a801499c66aa95b2aef8fa7431eace9843569957b91cad7f58027857da13cb393a02549f9544ad98c08bf67c08d94ca9345744f86997f54a0478023139cb9e9a48914faca60c6262f49b493626ff71dbaa8bb585addafe589c7218085715d2eba5615ec744050979c4abfcff500060665384ba9dff3f8edc8690fa4").to_vec(),
			hex!("80400180001f62a30ff19499eab277e5beb96cdaaa6e9078e48339b0e1fad96ca81f7df2805f0d9277342011b4e8dbb736d529366bb4a75d29ad08470814f1eba7d3fb7590").to_vec(),
			hex!("804040808661c412e1aa17d1444477e1706cc21411d5e4b649d465d61c475b4bcfa2fc33804113745ff20a53cd45c65432e99f461e7139078fa4f09ee7f4fb78a2eb16bcc2").to_vec(),
			hex!("8044015456b032492225337bea0300002000000000000000005456ff6f7d467b87a9e803000020000000000000000054566e75077b23ad2427080000200600000089010000").to_vec(),
			hex!("80490080e9bcbdb2ea42be3c991ebd04e9687ad42b4dfb7e968ebf3dc1df6e49b5ee0e5d805c6ae09b871fc396ad8e624bb6b80667fe8dc9e601f0186abff782e6359d75a980b89708d626efc69cf2a063986d3abf78f247d6a5c4d181c4711f520d62867572").to_vec(),
			hex!("804c834856b032492225337bea0300001404e80300005856aa5e225c309a382f0800002408d0070000d70700008063677d9e4bf66b9091c650ef3fc0749de98274aee4e97c317bff0bff0bfdedb180932624aa03db3929aa9a46659461380a4ee4491f50360f3fc7a1d048d2f43d5448566d13b2c21d52eb360800001404d0070000807a66a29e1da45c3e901d6144514963d2ffc40b999a4b770baf406109d3ba6598").to_vec(),
			hex!("804e83806e737e80f34720c65f30ae9be538353ab7b3e38bd80c51eacf2cee66c5d101d08024a5f69c2ed353e6680eca623eb199dd3a2e08271b8f27d992137db14700a828805d6127059fd45a2ed0d9c8f1908b1183e30184ff718f43f961929f1c4479dc6a807b03018fd03d5e3d517268c71da8ece79fb96bdfd71554eef108deaab624d1b3807c91d2c508293ae41f5f6f00f987828bc9fe187ab8b5b42d2b795aa2fcc077508037fa7bf9c2668fc7e3e0c6b7891a01209b6f5e2b123ce836a1bdf33752fd3db280230b2e27d27d36ef81faf1fadb6a7f2be997ebca450b75e19a1e3ad738e1a308").to_vec(),
			hex!("804ff7808f7e88c2b231ca0837d5fd4aaae147d01468a5e95c44520c661980699db34cd98091a742afdeb071d693f41f172076063c33a2190ecf018fcc4a2c9f3dc83de383802361f257a4c05ab0f9c35a457758625161df045bd50d39de215053532f3f04da80c2aa92ed2df69b12932b0a65f51d9aa72063b3c7bce68caaf8978ede53f6fffc80f857f201f8939e36fa8ced7f61dc100bccbc308a4511a3d8d122637b00973559803476d83e68bf203dd4719ac3b86ac3289438e32c3c04eebc5331377a3f29f349809fd8bcf8719a55d4321b4061756fa14e88ee93d492b00ca5c6076aae4dc0e9c480bf25efc42d65e7c29695df1b82a71d357ffbb27f49277950993d48c54147ea6180c453ea27118e369491563a131e945323273f89e63323024d48e6b213cc19444080d8e44ef13ac0272fadc6fe84edf7e438f3be1d7cdd05aec4db54c432382607328063663e1e8348c4b27ce97720268c770fc19caee96091343852137b064dc4828580a7a9cb6f704e8a6c801a937ca3b783a8ee65a6c61f991c70c66ee0b4c87f6ec1").to_vec(),
			hex!("805c8380587dbeb711feb47f76323fc62b9cf685fa9965ee17cc407b071b3ddf8701a2fa8091c5f4ce6c19b0ef4227812539f892b302fcab1091aae529693ee88905cf7e0580e4017499976842429b8298449869a0a110f236cebd2d53518b4051752262bb09804c18698e8d8b25d14f5f3f940e094712c6705323ca98cc9ffcc851ac7b0e387380f2daba2187907f5993c52f8e491f9a17b6a57becdf2efc57d80302a10d25808b80d50a9daa66e6e3fafbf2b6545c4f8f7a0e067dd8f2df3099b5740953e51ba22f80f6ff29e199d2d578bc1628db1ff34c7b723ad8a7c1764003cea88fb670a1013e").to_vec(),
			hex!("806100801e00dd72c7c50e7b5c8a060eb76510537b704f3e3f4957664ba8a42a989dcd3880dec8af6e436add8d3f4c08e8618852d28d1eb9b3f6fe888462b6f51b1f970581800c71da2ab7c4489af77d366af1d0dfa7e3934193ef91dd1935ae3e03ccb0f7fb").to_vec(),
			hex!("8075888054655eb684d417b2cf9db260bb601cbd4a5e7b2b9c9f12b9bd99f118d95199158077016fda2645b9f713e5649a49e46115d16c98ca61b697a006139557b650597d8069865b54cc0d45b2d489522ec2f664f39b8952983ac0f49d48c4b20158fe3dd8804cb1678f035dfadba663fca5ed94d97f1ec695249d04ef8efd69eb01024085bf8039ceeeb409398cad685c6434afccdb160cb9684388fcf1756d27a2add046ab4680108756cd035e04d6fbed805f0bc56a828e163e6385bbd79178829afa180ad29c80113bcb1f6e72a674e1b8204b1c9d13c6f0028108d081242a9c8ea14a025b1a5b").to_vec(),
			hex!("807f03809ccc64d1497a77dbedac27e5e33ab6e824e7e849d7f8eeb11a46ab46659c04cb80bc62ec1de7c57f415cc9e0ad7e6d1800a2b09c90638e22c24a5219063ada1e74807a927184e7eb4a92fd3161f5bd73614721b3314dbad2f554338934cc1e78dc5680cb104ca21aadb06ea617a60966ebf40c43129a3d066b1ea6e17c5a7b69c6e91680ca24ec0aac89892f1aa6e3e62e2f282bebec882bf8046ea6a16c2a17e2fe72208036505d98c8566ad188979e9467cc4175539e361d51dc8913ab0a0d49c218eab780da680453e8ffcc8af3546df953f8ff5408b48d07112fae2e5e04173c840f167d8012a32bcac04aee219d16f8a229e91ceb8b6fca49cbee1298969ba780b67f13508070d39e30f90aca2ed4e5a1c726abc33b0cc5160d374fbad9db5554811cf910d9").to_vec(),
			hex!("807fdd801bcacfc6e6480226ad9aef6fd056c800199adf83d95a35af1d0bdcbdf03a45b380ebb53747f08061980c9bff1322e1d0e506286ddb0a8164641fd604550371aa16807af50c02adeb268770c95e5a80ed695efe9485a12af6b6fff9e83634647d20b58059f4009b1b42c19253442876c9804ad174a2f1ed7ad5650077044af9a5353d61801a5bec8436c876222d99b4a21ab8a554fda92be495a9fa852d8c64c35183b6e580f500e0cc9c04a33aaf3275152fb08e8b1f746ff42601cbe63f602e564dab1c16800a2708a8c1c27e7d43ba2ffe2990752b7da6200e7b294f91d10a5dfa255eee088050d8fe3f74fad81df76ec8851ba9c50d4f39b263b7b9e704162a416f3d907fe5806c3f9af579d7477067c1cef624612d29057cef3a152f4c67e0d110405404fbf7804e885c22a02598bf62ed20d526d41927c05160c905d3e7ca49a94ed0e57db88e80028abb399094a7bf31dc820a9cfbb38e4f95e556f29c3e481a286710593eeaaf803a020ce3fe5dd0b0d75e6271ce9c2a51cdb22e37da1733ddb252e8f02096bf3480aa6cc13c04143cd4656c462c4810503745b8f40522ed0f83d92e66e2c8bada7e").to_vec(),
			hex!("808008807230a92286e1baeb9e410cd0f031f13bfaec3821e375fff2e2268f170b8d775e801977ec0fa48ec459bd0f5b9a929de1d4cfadb9344bb318d9eabd0e6d42cd5249").to_vec(),
			hex!("808017344607000020aaaa0a000000400078810088003044000020aaaa0a00000040003044000020aaaa0a0000004000344603000020aaaa0a0000004000344603000020aaaa0a0000004000344608000020aaaa0a0000004000").to_vec(),
			hex!("8088148050678a79a055b782ca38378a9a3d322a9d90abbe3f1be431cddb9e78825d3272801b5433326d99da1761205b4cee5c6ce94b99d849ca93395bbb15d6c211fae3e680ea7d8ce0ce7c02f05276d13eb66f740228831b20ce13f41d74d18aa3c4a76b3f802ecfff1113d6fbe55a765237dc87effb29317696b62fed39c763086b627ba14a").to_vec(),
			hex!("80910880859145393581d070f54d3214c17b7264ccb48928d4059a0e5024e20b2c6502db80c1ad4997417ad21ccd355c8b446d8f22b6b1dcaf5fed4fe3cd41bc01ca49dbda80599c4b7df21ca43186f4a20a7f6dab8eef01cf4d965a88f7e367d81a072c3ce4808630604d318d99c4de824d3b2a12d1fd54a6677ffa6d766227e2f296fb28a40b").to_vec(),
			hex!("80a6f380157e2ba07e7dcd5869e4c52019584b0b6593f47a13b575c0ef6b0bc2ee28a49e80bd3fc768fcef6cd8866d1ff49b8d17643bea0226757cdc0554ef3829724cdc6580634598730c864ce8525b53d710952607911a5ae1022faed5ae0e9141a5ca50b5800fd77edc4f6a21912f95a3277075edf33f810c18003641a01608e3b88b60f57680c0a2a615ba87f44169fd40e6e8e771824ea9101ae18f65752313faa608528ffb80d13d817534246dce1cce364fe94b61fff5b127610caeadcbb4df92f31c6cd6d580a4918b93dd88fe29f6d2601bb856af3e8422206989e2068f1ff94df0966dae8380b6f8e4185cf7e04c542ba01f4ab46edff54a980078c31b3f4af25f793f6c2052807b4157ca4e66d953ce027ee18a2a8cf2441763c4b894a9496750d3ef4d61ffd1802b79ed508c32ff44ad387c17c998a3994cc698d88b9d40207e46b5573bbbb37e").to_vec(),
			hex!("80c00080ae7d11dee7d4c65f73260a12af8050140bab892bc6a391912df2e43753e11a0b80155e565ae7f3ea93207b3fccbb33854963a4bbe616b2fc134b034257e2c55129").to_vec(),
			hex!("80c08980e8aa6bd49a2bf6a0f62ae9610d4e4d48b2c9e0e9f9c7202ab450384137c70cd38029188d231035b83a68d03d939ea827320480771476ec2af23052863941814ace80a00107025fd4295d48fefe3af59eb243387560b4de68d12be5120e8702f00dc680c6279d0cab3d47e47119915812024de5323dbc8772c8d31554820f5032d6d51680f33c4ac10651e46c1fb370747312dc3a4fca43f12f8eb0072d2398963a3e5072").to_vec(),
			hex!("80c39c805bce01dd905b92ef3e9007c2569e54bd457b30ec5eff34334e1fa3895c351ae88043a6a3eb51a0c05f4157612ebb9200b1f8bfd6276c7115f6c9dcd892fc7977aa80229d58a677d8445805c43cd1bf3f71a6e9d1bd270dbb45fef7e6f461fc02422b80787fdd75ffc48b03b19ec3b923f600b3c9010ec8be3bd363794baca878d0dde3805bbc7ed9bf94dcfa398acd40b78e3e34025b489a9ef7b25b196025cccfed8c9e80096233891b1941f94a448ac77ab4b30c879092fc0a62c800ac3edda18ab2cb2280c54aeb5267f45e5d1682d685eb8b2e80c6c7494541330d0b7d53daf32868a34c806ac7ab463c1505a5ec3f5bb91254b292467dd593ce222e151afb7e5d0013654c").to_vec(),
			hex!("80dc0080943782ac497a1fda6104b1edb43febcea56af70e26298b428e825acb6bb5d09780bccf533e0e80a957bb29f2965ddc4865e61f2d6a9095e17ef334fe658d721a4a80b604f0d9c4143fd23f6b9f7c2f82b8fcc199d75fcff286b426f467b9c83a701d806672e3babe19a72c4830e866ab9962867f9e567d23ec77c3c2c5d52b5cd229228004d4c3c69fd0de3901fe4062ef94b2e7e99e89ad603c86e4531824009947272b").to_vec(),
			hex!("80e6778065c35cfe27a746e21930af413ca62167331b05ecd4dc9ad61683b932e6d52ab380a266a7519dd0a4f76beffc1048904c9989deb94a90d8f20c1127fbab6dc4d1f98097679df04789eac59989b2424bb4e2af650c5c809d0098ddb2da844cc33bf87680a9e9dd724dd503df5f2c29e01e074697d4a0ed8b66b013ba135e561a398a9e348067365525ae7a69a26b7cbc7ad726524d3546faedc74ecc8bd6d40b831ff6c863808d5e166ad2fbaebb8fa5dab49385ea4ac863e5fc95a5c3c7eaa106715138e32d801db281200abacbb8bc06b72079e921704e707f3094c19679b363d79c978b8d9180725eb7af94abf259a7d7dadfeffcfdda9d7ec6d83fa105e26bc6d54d69ed3ce780a357c8e72b4c08409e6ece6b74b619ecd0ca23f634164c88027a9a2333be7c0980a2eb40cab1042f698f1d26780e43b07df40ad8760b5d86e07d8ef0e96cc9e0cf80cefba9a803b01b23f8c2f96432efedd9cf6eb6894e07893d11d915623fb04b52").to_vec(),
			hex!("80eae4801ec01457df7975f40ce32b660ffa6b1d0ba422c26416fbe6bd1cc2e8efd06db380f5317243fe29fbc20c872f8114ead6dfb53d318b5231fae7d596439dc4bb887680141c96628ecdcc4a1abbf13f3945d96bb8d01e9991a0a3ab2e8ad8f21e7669e0807d348c5e2c9669c686432e10716949d8fb15540390fd9b318c2f36735ad21263808e4f04d8061a7dd06e1e39778e540799d58f84ec50f89b34462f1464af6e7ab6800e13b2d869bebfaf452db48fa91a34d7810bd1fe808f6060228842313d5e256a8078deff86df6e6d1552046cbf115c532e2af1a2211ae9062c95113531bf1229738047654a8507596f3ad8dac86246927029ec83b1a64734bd9b4e3f414668ac9fa0809a14e4f273040a9a0e92787f5900a1755dfbd4d7c85493d704bd23746934e21f").to_vec(),
			hex!("80f9dd80b4554afcd19d1bb4ee031e4c7b24fcd0ce53b8c3510d2e8efb2e184fa4d87af2800b6cee639b5703da9ebcad7f651d104c52f838626ef70a401fab45a649f7693780cd022ca63f92cb51ac362940b4b3bc78402dc7c3b0e57aee973d07caa69d9a0c80fdde7a1ec684ab8ada1cff869b8a1fd755d4cbb3a0b0b0339cc77b3af4337f3d801c342643397645f0e7f332bd56a95c2e9bfbca82b0036b2007deb4d176e57417804edaa8724a9e892ea9ad7024634774a129bdbc2ad65073124e30e6a9088bf53a80bd087457dbb73f36194d60ed5ea1772e4021817dd401e87f564c3c29629fd5ea80947ea4a5027a0dd7f20837ea1481f31e2954b022332cbe221090bab8a6afda2b80d956263ff5026bada73fc43f6a12e039d201506263d1e111c2ba21e352d726e3808b6c69266b751b7c9e74825164be0af002313d7762a873dd80bd58004ddd5097804db0a5589ac4f893e633a2a219150afd601bc7ec800bfe2482af3047af2c63fe8015e9d3816afa8d370e4d2c359acce94f02f9e5e37e43ad40652c41dfcff4a2a8").to_vec(),
			hex!("80ffff80be1571ae08d48b7220e7d0a4c48e02a86ee9fa56210cb5afd346f02ba295a0588050801508c559c63fa8093bf558d0955a0386d6dcbfde87c2284bd0758de79ee6803e2f8ce769df2855ca35959e5da471db5de12b625cc9ae979b61d8c0906ddf3f8020aa6c4b67f40285819f7772a7487c9a7006b2f01fade11b4302c222b853240780a6422e2639231d9ba5a80e5534b56de4131ae11aff7fbf1b2bf8b76c79f9beb080ad5e7a6b0248173e15b68abfc1b855d2a567287527e692be56f02bef1156ecd180de152a7dbf39eab9677969b1927fb511460f7d2e8d56e831fd4e1d0191c9d513805242844558c2562fabcb126edc1344102d320ac54186f5f70866aa13052dcef78002ece6f310da597437aa26e0630ce774bae37d293bf6ab05c0f9554a36fb57f580247351fe2c0c94cd5be241dea98eb31185d61be9b4940667bb718e3b3022a53f80e2eab41e748d970fe7664b3737c573a362437c4b26645f044f29b8ff5f391b7b804822e701a92ad48872298bf1518122c736a96f9538a2cfa288f9049780c6588d8040c1f47a9c3bd873299b49cc0c41ab10f422205def1aedecf170e78751d2eb5d8055c0305bb0ce5fbb595b28e1ebe7133086ac4070de8004c5a4917ed99672be3d80fff7ea646bd1d1e611e32bf907ea3e0e28f429f1ce52bedf36b320875d6b253a8084e60837e53f1997dd4f1cf3bfec073665fb6ed55f516e3d619b220daf6d9a37").to_vec(),
			hex!("91033db0dbf16a804f215ef79ce2e73fec521ddde5500669d9f221b2553f82213ac7be6c63016310c85fd2f09f320c57f3a427229479f21d2e2c4e41881610b377df9b361c42b88327a7787c474826fb5c1594330f013c20ba634158f16012ea42512298ba020c066175726120c42872080000000004525053529018b3d23116dd0c0f6c42ca9af5c3247cdfe045f66916b6cb6f7c36e63bcb6c0d52c3ea0405617572610101dee7df8f5eaa76ed31fbd8d2c0e72b629602c2125a514ed2238de2ee3d96205fdbef7b5e22fcbe0356daf29fc21b5f40ce6a46e4add4918edcb789d8fa5cb084").to_vec(),
			hex!("9d007f03cfdce586301014700e2c2593d1c08063828bd4fdc2dfbebc2d7a771be214522df151c03801e2f9c0f2f3a8e8547851505f0e7b9012096b41c4eb3aaf947f6ea429080100685f0d9ef3b78afddab7f5c7142131132ad420cf00000000000000585f02275f64c354954352b71eea39cfaca210cf0000004c5f0ec2d17a76153ff51817f12d9cfc3c7f040080d2705ed6fb4282e60c9bfb3cefb5f1c1dd6743438b0988ac5e304cbdc7d26782").to_vec(),
			hex!("9d0da05ca59913bc38a8630590f2627c17dd80aea6cfa49d9700ee710473d5ded5e451d25d2828d31b2f3aa6cb4cc32077f7d780d7a01b4ccb277fb3b91cefaa0a9a2a043d38b98eeb6d19012fd4a3702ef39ba080dfeb24124eb02e900d4c59ec8de843786b7732e8229ef9b4d356f9ec6c55da31505f0e7b9012096b41c4eb3aaf947f6ea42908000080af1b5b29387bd9eb8c289a9a83430e8bc5d6b8311d5a7ea5c07e19e87cc2fad680cace1b4bc0cc4d171084fd79c024a8dcfeb076a13798e482ba028ee3bebb2469806bed3687e40385e2906a69b1c2f58a2301a03687585330f23a70c8fc7ae3d45980b544aa34b22c8ce065d7e280d46d0af733fe8907a6c96eb8d272156be37ef0b8806daa3588f32a96573c74e0d73444c4647c6bd2b2719b0b7716b11d5c8e644dd780af28e0cde6aed89ffee12c107290bc7ebda4b4c7f52e4f9cbbae651317d77ade").to_vec(),
			hex!("9e710b30bd2eab0352ddcc26417aa1945fc380360c98cd291f697953f9d412ff4d0af185ed19732597d8e7bab79827975a75b080f5f8c81ef962222ad9965645f12378bb4e92277351a2a2fb4e1c5dad5fc67f7480767f45959df560ac956f70aeb283e3f7a7709fea1a8e3d3503faff25819998768039c3a8f881a2b35493955da2bd70141f7c0967536e21cd5ea855c06723c440a1505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f03c716fb8fff3de61a883bb76adb34a20400801521660ade511634526812a8b200538fc88c0e91974efea95ad2d575f98d7d8b4c5f0f4993f016e2d2f8e5f43be7bb259486040080b1706dc05d957e1f7acbca40732604dcc2915764ababe89549a14ff4ff1ac6678097ff984a9229d194b352e7795790c2493a2f3a8320f38a14cbcd7989f3f138a6").to_vec(),
			hex!("9e7fefc408aac59dbfe80a72ac8e3ce5fbff801c902cbe419e7cea75b1d971cbbf91d733d711f134307162e1359cf85d02971680f62ce159296d30b0975fa703c88335deeafabe3c047f59f37deea5d4b74d0bd180138529b20e95fdf40c44b169b73ed43ba9ff86a452f57f04a47cf430ade1da6580c5826688dec3bf07d8a59796cea9e5d137bad97b39087f972e3ba9f1fd8290c780a38e2ce5933ec05307fc6e11f82592d62e8236da22a7746995618599c0de149680f816d91768618ca81638e13078656803ff9c35fb9563cf7e5391554aa924904a80249ac884f757608079745ec844acd182411e5bbc83bdf670fa6e52171a169eff80ff3730246e45762e9b43f5d5d1523d7a5763e832869ecf8d0db6371ff5728a00805d2639b55fadd848a806cb9836a6f9e9bd6c1cd41d685419b8e7acbb10a7f95080b93a2b5374b471f766cb752688932c1d85996cee41632f7cc6a66cba65e1b1918081cb5232aac42f95f060fd98133aa8aa34d1b3f43c87a79bf25c13b7b795405080c517058e981c0e77d9a1de87646b2184fd91d1f541ca2a6094cf51b43a562282802e03d2c5f1d5cb5743f237dd38123bda5354eab3b56b1f6a4579fdd2906a24ba804a07eecd8261b82a2f42e04a8181a8b0802abd207f011ad733c120a7c08e8f0c80d8463698b1dc2c93bb8ed8d71e08b5df853bd8636f7253ab70340230c7b1420d").to_vec(),
			hex!("9eb6f36e027abb2091cfb5110ab5087ff96e685f06155b3cd9a8c9e5e9a23fd5dc13a5ed208a51e41000000000685f08316cbf8fa0da822a20ac1c55bf1be3201988000000000000505f0e7b9012096b41c4eb3aaf947f6ea429080000804bd46f742ac297629048454589d184e741637f0091daa79fa945ba03ddd1d6bf809d3fd79275a68cdcae96054d764f718cd8cdcfcaffba58588647a7356d9a4978807ec61560ce82446104a222a65f51572ac3b6f7d716fefb7809e719d38a184f32800d49fef039517cc312c00412803ca1df50ac6d90c50541f649a9c85b83c0fdd8804520ce64a97bc4d16457066733ae81aafd0620ff5cf2b11fcf6371812ccc67e480e4db9def26e8a8108dbf0b33b30a2e769ccc12375e27fd66c0de24ec8f0183ee80f78f092d55cd5da8278ba761b0439f1c8d498d17c208fc02858df491051748c8685f090e2fbf2d792cb324bffa9427fe1f0e2080ad3a01d3af3a01").to_vec(),
			hex!("9ede3d8a54d27e44a9d5ce189618f22d3008505f0e7b9012096b41c4eb3aaf947f6ea4290809004c5f03b4123b2e186e07fb7bad5dda5f55c00400807273d96691e5d9c9c7bfe351d367c9b0aba25ed1ffb23da3a59d4b549792a212").to_vec(),
			hex!("9ef78c98723ddc9073523ef3beefda0c1044808e07d68ab52fc6ec49d640dacf27a9aa100a173aad683d4c1cf1c1212b7c805280e283a5f10c6f8a8b6cc5b4f97351a7a14d384967e8b37dc17290e7cb813b5d4b809a8025095f0fb1cf12f83b2799110508a9d2bb3060ec9c805ed39d483d18cbcb").to_vec(),
			hex!("9f012b746dcf32e843354583c9702cc020f9ff5c5702a6fc915ccc55a0300800002408d0070000d707000080bfadc9bbb2c3ca2b38cd11b725b0f41a4d082a542db8367be0c14911e8bc668e80c0caa3a1941089d9694945f064fff6cd5482f9e49ecd94eb0bc4985cdcb9f43b800d93a67b11fa746acf6c5c7fa9b58f529112824c157144bf2bb2217ccf12485a805a3b37efc61813edd3841e2d309299c89b92a311184e065ff44b48ad8da1f5ff6c57073de59802de4637e8070000340cd0070000d7070000250800006c570c58f3b5989bb72cdf070000340cd0070000d1070000e707000080770f754c658cc038f95b520d1b1e4d00c10877e482be592b8685fa8ba7cb57f880e98895c9c0ffbf97c65956ba272c22887aa35468434c9f85e1e1381d31e1e38180cafce73d6ce28a72801c89e30eb0fbf937fc0178266c70f95e6165ce78d3adb180239c34f9ca90136889810a2033709e5bcf7d0f0f6bd6aa989a06d0deb76321de804fa3dc756442cb94a5a1157ee2ddde94d5aa5848f4cee0ea4ff7aeceaedbd0f18000a78ab1fcfa723fc6f48e95bcfa3f49bd8df60228f60a97babbb80f9245741c5c570c7327a2a48bf2b1490800002408e80300003e080000").to_vec(),
			hex!("9f06604cff828a6e3f579ca6c59ace013dffff8046d6839da9b1762c432e22c47bb81fd13a8505c1032adf14d33fb3e56a5b5a4e802368ac8e3f37dcdb00892f09699313eb0961806e5dfbe70a8da32d2662da3509800251d1f3f0760d8ee45113d9361e4052aabcf943551f5b0e417f97c59a56267580b225bda2be53cc70b25787fbc1c6871c71b4761312ac2904deebea34fff47ba880284a8101c45c1b5d6980444e4b0909b89240730c88a6ee703ac68baae9ce8cef8060b8dbacca7fcfa41880ed8b278270d23fbe6a729afa898df66f54350280d37080a31480b37aef49729615200d1e02073b17d1586372c1c311e6c7766e22acdec380a1577c644b07e9b1d055558a9db1f7f148c2e306485ab49ee4adf81155d96bcd809024a3e65ec27e536eec7626c009a5ad963a0fd8884bdff1c8485d0eda743cb1801494ed9af0b1ce7e24c925d7a638ae1e9ffcd74f99aafb6182487136c8cd77af80bc31c56a62a007f2ea743791875b3836de5e9b39c033d4056c4c8470102bb8cc808c175bebe62adf16e68047a411f420c47fe92bd0feee598fa188fb9669fb16a5803d871197a77befc58120e4810577e9f62bb20a6f052ffed11abbac8785dbc1c3800d3b94c93cae77412b8f009dc8ca97a8d9cf28585ae9f65ecacb7d31b36d7827801df0b7b316a1485c2ede799d49ef2cd2198b8dcc47773226dbbdaed89bf8f6b2806ea6e427f303ebbafe87019bc4a14b3afa9300bc013ba2e99aa5ff53f8b8f68d").to_vec(),
			hex!("9f0ad157e461d71fd4c1f936839a5f1f3ef8df8008ef8ee2ab5466cfcbe2251cd0aa4c9e43b4a15a6a2919ebe78c3cef323bc37a8045add92157c7b68d3fbfe254d814c30861b567ca1a261eef264dd0a21fe5a0cc58570c88433df862dbcb2408000020000000000000000080f1f90ebe2449756caa238a37a4f622baa474567d5d3178bc84cf4d94f4e4a9c45857073de59802de4637e807000020000000000000000058570c58f3b5989bb72cdf07000020000000000000000080a43a9cadb8df327bd035615f93d1cc99719da39113502a1dd4ce6f099d47e5c3808f6f5121aee45b4e788e40c5cf493fd9e0be05187cce23b1c861f7bcb3b1feaf80813e3bb93186f01cab4b632ba8f5873a1289855d3a258dd74a38c272ce61761980588cf3f41206413f7c6dfe3ff1d85befce030efe50a3b8e8a4453b87d3aea0ef5857073ba61bc4d713354b08000020000000000000000058570c7327a2a48bf2b149080000200000000000000000").to_vec(),
			hex!("9f0b3c252fcb29d88eff4f3de5de4476c3ffff805dbc9e79e89180fd3de52a8b370615d6e3efb7ad2fa76a429e728c69479a7ae380580670bdf4d75905b6e4d8e2215733f20bc5e01d9b847e643e3befeb8970274e804c0d171573c7030de511f3703c68532730beb5a52f193f0f63d9c59e08b54cd680928422820c6cb15b7cf3ea5eaf13dcf8a395ec9475cc5fe38841ca6b1ddd4a838050874a109d806f943211735f71a0181b845945d7ab3ac6c57941ea7e37eb664c80912f03b9d49581f4183e858cd6ae4ad1c11c65179af3b7fc8ddc7f3948763ff18043328b278ba2aad2426147bd5358aa0dbc49faa2dbaac46aafae1917d4250da2806a9b721dec5fe4c55dec7ed0c0a9b8255cfb5a5fff9703153bafae69e31f11dd80f31edf814a9a05a1452d27f2a780bd5e2c347c720c4195e49f5c182df6f06a9f8086b40811ed944230fc898865cc0efe0362d079e2b9522eeaa2b90d911085545880e41216b375b93e08ba9e9fc64a873c0598f7a7aa1a27c418f8d50b908246ba15805effdc2235030c3fdefb24a5f11205045b908bc9d35d8fda68e8adbb1fbb2cf88013a652d9a22e40230e6479db36acb95fee197676eaf92adf6b1e08418e0a9d9a80c2412d5e3e033f685d03653fc90dc474ad8e793db9844e421d56c302c5e9fb1780b0370d966ce4557c5b881e6d7d5cbf9f5d76a5fe5b786ebc26ebf59a0f1a83728061ad74598bfc911b2cf8a110eeddcad28ab5f98fbf629a68d0470c92143e5ab2").to_vec(),
			hex!("9f0d3719f5b0b12c7105c073c507445948f9ff5c5702a6fc915ccc55a0300800002408d0070000d407000080b7c6e2167110e8b651eb693a5bbfb83b6f968091478222e136a68389f2cd385c80e6086b406a930613d6f03e4d1bbaa36c00c53c176b59f4d9fa63a837fb0cade87c570c88433df862dbcb240800004410e8030000d0070000d4070000e7070000805a3b37efc61813edd3841e2d309299c89b92a311184e065ff44b48ad8da1f5ff5c57073de59802de4637e80700002408d0070000250800006c570c58f3b5989bb72cdf070000340cd0070000d1070000e707000080dbd75e09babf2a19db3fedf382d7e7a16978cd02c781b1ccae2849c29a605f15806f95921fe3f4084c32869ee6a76db36d2c982664a628869469cb658c847ebe7380cafce73d6ce28a72801c89e30eb0fbf937fc0178266c70f95e6165ce78d3adb18097fe80188ec468eb8ee172ddc2f8a6606482f09058b3fc0034596be62867ab09804fa3dc756442cb94a5a1157ee2ddde94d5aa5848f4cee0ea4ff7aeceaedbd0f18000a78ab1fcfa723fc6f48e95bcfa3f49bd8df60228f60a97babbb80f9245741c5c570c7327a2a48bf2b1490800002408e80300003e080000").to_vec(),
			hex!("bf0e02656c61795f64697370617463685f71756575655f72656d61696e696e675f63617061636974791c60808f6e2b238160338d09b9777042423f2c080d2554575b8b4c8282606e91f0b2b480e229e6382cb05058145a936a2c33a28e998a98fbb4a9123e2d5108a5613bcbc780462c6fd312f1d8c48aae32e5bd6866bb8395478ba334c30720f035938f5eeea9802413ada492771a8e2130c6128d13c09432ef58f80106c0e17c07fa97bb23ec1d80b0018a90e5093fb5d579d76c73bf1b65fe79d9d1e09b4a3654a6d9475aca50a0").to_vec(),
			hex!("e80300000090010000900100000000000000000000005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000010305fad7a0ae358701d8c8dd382d43f172b19589419d3844cd707bcbdd463df9005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000010321ba2a7cc1014a5ff7391e9c9c4773f3133e862e8619ca83745c7e766df60d005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000104e90800749e0619fa92da0fe3cef4e06ec8c796d43d2b33a14213cee46fbed4005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000109513aa4f46c7c18e0ee5b1e7996bc8546f7c06b954e7a9d4e95a8660d3f1521005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000011516234f766160ea3efeeac6c6358e47ba7002349c17dd1883bc45ff01caa47b005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000011c98883ab5530bfc8a4d2079286a4bcbdece1933fac167cff73f2755c9bd5c56005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001252c8d2a85ed57e843f2cd9cb00a186b1d75f75476bf5349e4c807dc62be5201005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000133e900262e234fae90bdae257a930c0c337fbdfd82b8084ee0243909f3b7de90005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000014c690ea012bb62e31b5c3fcdaba06b8278fadbce8e99ec0c8fcdfadd5a6b0876005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000016278c3f2e3e9c118a9005fe5a544cc278b6052472e4b1cc32b0a7e7643359a68005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000163677a48bf325234e5d67d153253bf2f0e8c9995e8e042ea42decc21893d4ae9005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000016a1bfca2dddf6aaaf52c5eba07427a96e989f94910a8ec6796a0a39f1202c7c1005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000017f70f81377f6fc1aa09570a4179b81b594e7b8ebfabd0718d3a0a7491d3036c6005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000018072df6d730db3b65fbe4b122b6fb90669cce964ce3178843bc41b9596fe9435005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000018d1f26e6793d2b4827c57aa4bb6e943d784555d10b725984a52e3878ca3ce9ce005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001927b6c271063253bea0f1a895d4ceab2f22a5dfb4136c80e0d986391cbb55502005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e8030000009001000090010000000000000000000199e1aa4d30ef8c00aaca69110093953dea2219f8fd572f356e505ddad889abf7005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e803000000900100009001000000000000000000019abfc99687d3363b2cdd538c081f2c762a7cfe58832907811bd8d6baba868602005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001b05bb7ec2cc7615f5d28f566185505040426f8471d5f6f8becfb01c16d92f630005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001c7b859bb7dc7c5191327cfa0ee8c0109c64dad0c6fb1b5bef8b9e499a1fbcd80005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001ea30fb596f7d9bbf5a4781c984efb25126d451992053e765640bac38557ab6a4005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001ef3c3e05abf570a01ad79bbbca691748f29d8b21ae38f6c5ea757f58806beeae005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001efbab7ee5590e76b60710d698eaa93c76267d04fd5947146d3a2884ff80707b7005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
			hex!("e80300000090010000900100000000000000000001f6a0f0bf50ff677934c2d37d99926ffe5d007e24ff32f8d665acfd3662377a4e005039278c0400000000000000000000005039278c0400000000000000000000").to_vec(),
		];

        let encode = |nodes: Vec<Vec<u8>>| {
            let mut proof = crate::util::encode_scale_compact_usize(nodes.len())
                .as_ref()
                .to_vec();
            for mut node in nodes {
                let mut node_length = crate::util::encode_scale_compact_usize(node.len())
                    .as_ref()
                    .to_vec();
                proof.append(&mut node_length);
                proof.append(&mut node);
            }
            proof
        };

        super::decode_and_verify_proof(super::Config {
            proof: encode(ok_nodes),
        })
        .unwrap();

        super::decode_and_verify_proof(super::Config {
            proof: encode(fail_nodes),
        })
        .unwrap();
    }
}
