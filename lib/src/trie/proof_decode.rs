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

use alloc::vec::Vec;
use core::{fmt, iter, ops};

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

    struct InProgressEntry<'a> {
        index_in_proof: usize,
        range_in_proof: ops::Range<usize>,
        decode_result: Result<
            trie_node::Decoded<'a, trie_node::DecodedPartialKey<'a>, &'a [u8]>,
            trie_node::Error,
        >,
    }

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
    let entries_by_merkle_value = {
        // TODO: don't use a Vec?
        let (_, decoded_proof) = nom::combinator::all_consuming(nom::combinator::flat_map(
            crate::util::nom_scale_compact_usize,
            |num_elems| nom::multi::many_m_n(num_elems, num_elems, crate::util::nom_bytes_decode),
        ))(config.proof.as_ref())
        .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| Error::InvalidFormat)?;

        let entries_by_merkle_value = decoded_proof
            .iter()
            .copied()
            .enumerate()
            .map(
                |(proof_entry_num, proof_entry)| -> ([u8; 32], InProgressEntry) {
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
                        InProgressEntry {
                            index_in_proof: proof_entry_num,
                            range_in_proof: proof_entry_offset
                                ..(proof_entry_offset + proof_entry.len()),
                            decode_result: trie_node::decode(proof_entry),
                        },
                    )
                },
            )
            .collect::<hashbrown::HashMap<_, _, fnv::FnvBuildHasher>>();

        // Using a hashmap has the consequence that if multiple proof entries were identical, only
        // one would be tracked. This allows us to make sure that the proof doesn't contain
        // multiple identical entries.
        if entries_by_merkle_value.len() != decoded_proof.len() {
            return Err(Error::DuplicateProofEntry);
        }

        entries_by_merkle_value
    };

    // Start by iterating over each element of the proof, and keep track of elements that are
    // decodable but aren't mentioned in any other element. This gives us the tries roots.
    let trie_roots = {
        let mut maybe_trie_roots = entries_by_merkle_value
            .keys()
            .collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();
        for (hash, InProgressEntry { decode_result, .. }) in entries_by_merkle_value.iter() {
            let Ok(decoded) = decode_result else {
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
    let mut entries: Vec<Entry> = Vec::with_capacity(entries_by_merkle_value.len());

    let mut trie_roots_with_entries =
        hashbrown::HashMap::with_capacity_and_hasher(trie_roots.len(), Default::default());

    // Keep track of the proof entries that haven't been visited when traversing.
    let mut unvisited_proof_entries =
        (0..entries_by_merkle_value.len()).collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();

    // We repeat this operation for every trie root.
    for trie_root_hash in trie_roots {
        struct StackEntry<'a> {
            range_in_proof: ops::Range<usize>,
            index_in_entries: usize,
            num_visited_children: u8,
            children_node_values: [Option<&'a [u8]>; 16],
        }

        // Keep track of the number of entries before this trie root.
        // This allows us to truncate `entries` to this value in case of decoding failure.
        let num_entries_before_current_trie_root = entries.len();

        // Keep track of the indices of the proof entries that are visited when traversing this trie.
        let mut visited_proof_entries_during_trie =
            Vec::with_capacity(entries_by_merkle_value.len());

        // TODO: configurable capacity?
        let mut visited_entries_stack: Vec<StackEntry> = Vec::with_capacity(24);

        loop {
            // Find which node to visit next.
            // This is the next child of the node at the top of the stack, or if the node at
            // the top of the stack doesn't have any child, we pop it and continue iterating.
            // If the stack is empty, we are necessarily at the first iteration.
            let (visited_node_entry_range, visited_node_decoded) =
                match visited_entries_stack.last_mut() {
                    None => {
                        // Stack is empty.
                        // Because we immediately `break` after popping the last element, the stack
                        // can only ever be empty at the very start.
                        let InProgressEntry {
                            index_in_proof: root_position,
                            range_in_proof: root_range,
                            decode_result,
                        } = entries_by_merkle_value.get(&trie_root_hash[..]).unwrap();
                        visited_proof_entries_during_trie.push(*root_position);
                        // If the node can't be decoded, we ignore the entire trie and jump
                        // to the next one.
                        let Ok(decoded) = decode_result.clone() else {
                            debug_assert_eq!(num_entries_before_current_trie_root, entries.len());
                            break;
                        };
                        (root_range.clone(), decoded)
                    }
                    Some(StackEntry {
                        num_visited_children: stack_top_visited_children,
                        ..
                    }) if *stack_top_visited_children == 16 => {
                        // We have visited all the children of the top of the stack. Pop the node from
                        // the stack.
                        let Some(StackEntry {
                            index_in_entries: stack_top_index_in_entries,
                            ..
                        }) = visited_entries_stack.pop()
                        else {
                            unreachable!()
                        };

                        // Update the value of `child_entries_follow_up`
                        // and `children_present_in_proof_bitmap` of the parent.
                        if let Some(&StackEntry {
                            index_in_entries: parent_index_in_entries,
                            num_visited_children: parent_children_visited,
                            ..
                        }) = visited_entries_stack.last()
                        {
                            entries[parent_index_in_entries].child_entries_follow_up +=
                                entries[stack_top_index_in_entries].child_entries_follow_up + 1;
                            entries[parent_index_in_entries].children_present_in_proof_bitmap |=
                                1 << (parent_children_visited - 1);
                        }

                        // If we popped the last node of the stack, we have finished the iteration.
                        if visited_entries_stack.is_empty() {
                            trie_roots_with_entries
                                .insert(*trie_root_hash, num_entries_before_current_trie_root);
                            // Remove the visited entries from `unvisited_proof_entries`.
                            // Note that it is questionable what to do if the same entry is visited
                            // multiple times. In case where multiple storage branches are identical,
                            // the sender of the proof should de-duplicate the identical nodes. For
                            // this reason, it could be legitimate for the same proof entry to be
                            // visited multiple times.
                            for entry_num in visited_proof_entries_during_trie {
                                unvisited_proof_entries.remove(&entry_num);
                            }
                            break;
                        } else {
                            continue;
                        }
                    }
                    Some(StackEntry {
                        range_in_proof: stack_top_proof_range,
                        num_visited_children: stack_top_visited_children,
                        children_node_values: stack_top_children,
                        ..
                    }) => {
                        // Find the next child of the top of the stack.
                        let stack_top_entry = &proof_as_ref[stack_top_proof_range.clone()];

                        // Find the index of the next child (that we are about to visit).
                        let next_child_to_visit = stack_top_children
                            .iter()
                            .skip(usize::from(*stack_top_visited_children))
                            .position(|c| c.is_some())
                            .map(|idx| u8::try_from(idx).unwrap() + *stack_top_visited_children)
                            .unwrap_or(16);

                        // `continue` if all children have been visited. The next iteration will
                        // pop the stack entry.
                        if next_child_to_visit == 16 {
                            *stack_top_visited_children = 16;
                            continue;
                        }
                        *stack_top_visited_children = next_child_to_visit + 1;

                        // The value of the child node is either directly inlined (if less
                        // than 32 bytes) or is a hash.
                        let child_node_value =
                            stack_top_children[usize::from(next_child_to_visit)].unwrap();
                        debug_assert!(child_node_value.len() <= 32); // Guaranteed by decoding API.
                        if child_node_value.len() < 32 {
                            let offset = stack_top_proof_range.start
                                + if !child_node_value.is_empty() {
                                    child_node_value.as_ptr() as usize
                                        - stack_top_entry.as_ptr() as usize
                                } else {
                                    0
                                };
                            debug_assert!(offset == 0 || offset >= stack_top_proof_range.start);
                            debug_assert!(
                                offset <= (stack_top_proof_range.start + stack_top_entry.len())
                            );

                            let child_range_in_proof = offset..(offset + child_node_value.len());

                            // Decodes the child.
                            // If the node can't be decoded, we ignore the entire trie and jump
                            // to the next one.
                            let Ok(child_decoded) =
                                trie_node::decode(&proof_as_ref[child_range_in_proof.clone()])
                            else {
                                entries.truncate(num_entries_before_current_trie_root);
                                break;
                            };

                            (child_range_in_proof, child_decoded)
                        } else if let Some(&InProgressEntry {
                            index_in_proof: child_position,
                            range_in_proof: ref child_entry_range,
                            ref decode_result,
                        }) = entries_by_merkle_value.get(child_node_value)
                        {
                            // If the node value of the child is less than 32 bytes long, it should
                            // have been inlined instead of given separately.
                            if child_entry_range.end - child_entry_range.start < 32 {
                                return Err(Error::UnexpectedHashedNode);
                            }

                            visited_proof_entries_during_trie.push(child_position);

                            // If the node can't be decoded, we ignore the entire trie and jump
                            // to the next one.
                            let Ok(decoded) = decode_result.clone() else {
                                entries.truncate(num_entries_before_current_trie_root);
                                break;
                            };
                            (child_entry_range.clone(), decoded)
                        } else {
                            // Child is a hash that was not found in the proof. Simply continue
                            // iterating, in order to try to find the follow-up child.
                            continue;
                        }
                    }
                };

            // All nodes must either have a child or a storage value or be the root.
            if visited_node_decoded.children_bitmap() == 0
                && matches!(
                    visited_node_decoded.storage_value,
                    trie_node::StorageValue::None
                )
                && !visited_entries_stack.is_empty()
            {
                return Err(Error::NonRootBranchNodeWithNoValue);
            }

            // Nodes with no storage value and one children are forbidden.
            if visited_node_decoded
                .children
                .iter()
                .filter(|c| c.is_some())
                .count()
                == 1
                && matches!(
                    visited_node_decoded.storage_value,
                    trie_node::StorageValue::None
                )
            {
                return Err(Error::NodeWithNoValueAndOneChild);
            }

            // Add an entry for this node in the final list of entries.
            entries.push(Entry {
                parent_entry_index: visited_entries_stack.last().map(|entry| {
                    (
                        entry.index_in_entries,
                        nibble::Nibble::try_from(entry.num_visited_children - 1).unwrap(),
                    )
                }),
                range_in_proof: visited_node_entry_range.clone(),
                storage_value_in_proof: match visited_node_decoded.storage_value {
                    trie_node::StorageValue::None => None,
                    trie_node::StorageValue::Hashed(value_hash) => {
                        if let Some(&InProgressEntry {
                            index_in_proof: value_position,
                            range_in_proof: ref value_entry_range,
                            ..
                        }) = entries_by_merkle_value.get(&value_hash[..])
                        {
                            visited_proof_entries_during_trie.push(value_position);
                            Some(value_entry_range.clone())
                        } else {
                            None
                        }
                    }
                    trie_node::StorageValue::Unhashed(v) => {
                        let offset = if !v.is_empty() {
                            v.as_ptr() as usize - proof_as_ref.as_ptr() as usize
                        } else {
                            0
                        };
                        debug_assert!(offset == 0 || offset >= visited_node_entry_range.start);
                        debug_assert!(offset <= visited_node_entry_range.end);
                        Some(offset..offset + v.len())
                    }
                },
                child_entries_follow_up: 0,          // Filled later.
                children_present_in_proof_bitmap: 0, // Filled later.
            });

            // Add the visited node to the stack. The next iteration will either go to its first
            // child, or pop the node from the stack.
            visited_entries_stack.push(StackEntry {
                range_in_proof: visited_node_entry_range,
                index_in_entries: entries.len() - 1,
                num_visited_children: 0,
                children_node_values: visited_node_decoded.children,
            });
        }
    }

    // The entire reason why we track the unvisited proof entries is to return this error if
    // necessary.
    if !unvisited_proof_entries.is_empty() {
        return Err(Error::UnusedProofEntry);
    }

    drop(entries_by_merkle_value);
    Ok(DecodedTrieProof {
        proof: config.proof,
        entries,
        trie_roots: trie_roots_with_entries,
    })
}

/// Decoded Merkle proof. The proof is guaranteed valid.
pub struct DecodedTrieProof<T> {
    /// The proof itself.
    proof: T,

    /// All entries in the proof, in lexicographic order. Ordering between trie roots is
    /// unspecified.
    entries: Vec<Entry>,

    ///
    /// Given that hashes are verified to actually match their values, there is no risk of
    /// HashDoS attack.
    // TODO: is that true? ^ depends on whether there are a lot of storage values
    trie_roots: hashbrown::HashMap<[u8; 32], usize, fnv::FnvBuildHasher>,
}

struct Entry {
    /// Index within [`DecodedTrieProof::entries`] of the parent of this entry and child direction
    /// nibble, or `None` if it is the root.
    parent_entry_index: Option<(usize, nibble::Nibble)>,

    /// Range within [`DecodedTrieProof::proof`] of the node value of this entry.
    range_in_proof: ops::Range<usize>,

    /// Range within [`DecodedTrieProof::proof`] of the unhashed storage value of this entry.
    /// `None` if the entry doesn't have any storage entry or if it's missing from the proof.
    storage_value_in_proof: Option<ops::Range<usize>>,

    // TODO: doc
    children_present_in_proof_bitmap: u16,

    /// Given an entry of index `N`, it is always followed with `k` entries that correspond to the
    /// sub-tree of that entry, where `k` is equal to [`Entry::child_entries_follow_up`]. In order
    /// to jump to the next sibling of that entry, jump to `N + 1 + k`. If `k` is non-zero, then
    /// entry `N + 1` corresponds to the first child of the entry of index `N`.
    child_entries_follow_up: usize,
    // TODO: by adding the partial key, we should be able to avoid decoding the entry while iterating down the trie
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

                    struct DummyNibbles<'a, T: AsRef<[u8]>>(EntryKeyIter<'a, T>);
                    impl<'a, T: AsRef<[u8]>> fmt::Debug for DummyNibbles<'a, T> {
                        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                            let mut any_written = false;
                            for nibble in self.0.clone() {
                                any_written = true;
                                write!(f, "{:x}", nibble)?
                            }
                            if !any_written {
                                write!(f, "∅")?
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
    // TODO: paragraph below not true anymore
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
    // TODO: ordering between trie roots unspecified
    // TODO: consider not returning a Vec
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

                if key.clone().count() % 2 != 0 {
                    return None;
                }

                let key = nibble::nibbles_to_bytes_suffix_extend(key).collect();
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
    // TODO: ordering between trie roots unspecified
    pub fn iter_ordered(
        &'_ self,
    ) -> impl Iterator<Item = (EntryKey<'_, EntryKeyIter<'_, T>>, ProofEntry<'_, T>)> + '_ {
        let proof = self.proof.as_ref();

        self.trie_roots
            .iter()
            .flat_map(|(trie_root_hash, &trie_root_entry_index)| {
                self.entries
                    .iter()
                    .enumerate()
                    .skip(trie_root_entry_index)
                    .take(self.entries[trie_root_entry_index].child_entries_follow_up + 1)
                    .map(|(entry_index, entry)| {
                        let key = EntryKey {
                            trie_root_hash,
                            key: EntryKeyIter::new(self, entry_index),
                        };

                        let Ok(entry_index_decoded) =
                            trie_node::decode(&proof[entry.range_in_proof.clone()])
                        else {
                            // Proof has been checked to be entirely decodable.
                            unreachable!()
                        };

                        let entry = ProofEntry {
                            merkle_value: if let Some((parent_index, parent_nibble)) =
                                self.entries[entry_index].parent_entry_index
                            {
                                let Ok(parent_decoded) = trie_node::decode(
                                    &proof[self.entries[parent_index].range_in_proof.clone()],
                                ) else {
                                    // Proof has been checked to be entirely decodable.
                                    unreachable!()
                                };
                                parent_decoded.children[usize::from(parent_nibble)]
                                    .as_ref()
                                    .unwrap()
                            } else {
                                trie_root_hash
                            },
                            node_value: &self.proof.as_ref()[entry.range_in_proof.clone()],
                            partial_key_nibbles: entry_index_decoded.partial_key,
                            unhashed_storage_value: entry
                                .storage_value_in_proof
                                .as_ref()
                                .map(|range| &proof[range.clone()]),
                            trie_node_info: TrieNodeInfo {
                                children: Children {
                                    children: {
                                        let mut children = core::array::from_fn(|_| Child::NoChild);
                                        let mut i = entry_index + 1;
                                        for child_num in 0..16 {
                                            let Some(child_merkle_value) =
                                                entry_index_decoded.children[child_num]
                                            else {
                                                continue;
                                            };
                                            if entry.children_present_in_proof_bitmap
                                                & (1 << child_num)
                                                != 0
                                            {
                                                children[child_num] = Child::InProof {
                                                    child_key: EntryKeyIter::new(self, i),
                                                    merkle_value: child_merkle_value,
                                                };
                                                i += self.entries[i].child_entries_follow_up;
                                                i += 1;
                                            } else {
                                                children[child_num] = Child::AbsentFromProof {
                                                    merkle_value: child_merkle_value,
                                                };
                                            }
                                        }
                                        children
                                    },
                                },
                                storage_value: match (
                                    entry_index_decoded.storage_value,
                                    &entry.storage_value_in_proof,
                                ) {
                                    (trie_node::StorageValue::Unhashed(value), _) => {
                                        StorageValue::Known {
                                            value,
                                            inline: true,
                                        }
                                    }
                                    (trie_node::StorageValue::Hashed(_), Some(value_range)) => {
                                        StorageValue::Known {
                                            value: &proof[value_range.clone()],
                                            inline: false,
                                        }
                                    }
                                    (trie_node::StorageValue::Hashed(hash), None) => {
                                        StorageValue::HashKnownValueMissing(hash)
                                    }
                                    (trie_node::StorageValue::None, _v) => {
                                        debug_assert!(_v.is_none());
                                        StorageValue::None
                                    }
                                },
                            },
                        };

                        (key, entry)
                    })
            })
    }

    /// Returns the key of the closest ancestor to the given key that can be found in the proof.
    /// If `key` is in the proof, returns `key`.
    pub fn closest_ancestor_in_proof<'a>(
        &'a self,
        trie_root_merkle_value: &[u8; 32],
        mut key: impl Iterator<Item = nibble::Nibble>,
    ) -> Result<Option<EntryKeyIter<'a, T>>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // If the proof doesn't contain any entry for the requested trie, then we have no
        // information about the node whatsoever.
        // This check is necessary because we assume below that a lack of ancestor means that the
        // key is outside of the trie.
        let Some(&(mut iter_entry)) = self.trie_roots.get(trie_root_merkle_value) else {
            return Err(IncompleteProofError());
        };

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                unreachable!()
            };

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (key.next(), iter_entry_partial_key_iter.next()) {
                    (Some(a), Some(b)) if a == b => {}
                    (_, Some(_)) => {
                        // Mismatch in partial key. Closest ancestor is the parent entry.
                        let Some((parent_entry, _)) = self.entries[iter_entry].parent_entry_index
                        else {
                            // Key is completely outside of the trie.
                            return Ok(None);
                        };
                        return Ok(Some(EntryKeyIter::new(self, parent_entry)));
                    }
                    (Some(child_num), None) => {
                        if let Some(_) = iter_entry_decoded.children[usize::from(child_num)] {
                            // Key points to child. Update `iter_entry` and continue.
                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete.
                            if children_present_in_proof_bitmap & (1 << u8::from(child_num)) == 0 {
                                return Err(IncompleteProofError());
                            }

                            for c in 0..u8::from(child_num) {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }
                            iter_entry += 1;
                        } else {
                            // Key points to non-existing child. Closest ancestor is `iter_entry`.
                            return Ok(Some(EntryKeyIter::new(self, iter_entry)));
                        }
                        break;
                    }
                    (None, None) => {
                        // Exact match. Closest ancestor is `iter_entry`.
                        return Ok(Some(EntryKeyIter::new(self, iter_entry)));
                    }
                }
            }
        }
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
        mut key: impl Iterator<Item = nibble::Nibble>,
    ) -> Result<TrieNodeInfo<'_, T>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // Find the starting point of the requested trie.
        let Some((mut iter_entry_merkle_value, mut iter_entry)) = self
            .trie_roots
            .get_key_value(trie_root_merkle_value)
            .map(|(k, v)| (&k[..], *v))
        else {
            return Err(IncompleteProofError());
        };

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                // Proof has been checked to be entirely decodable.
                unreachable!()
            };

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (key.next(), iter_entry_partial_key_iter.next()) {
                    (Some(a), Some(b)) if a == b => {}
                    (Some(_), Some(_)) => {
                        // Mismatch in partial key. No node with the requested key in the trie.
                        return Ok(TrieNodeInfo {
                            storage_value: StorageValue::None,
                            children: Children {
                                children: core::array::from_fn(|_| Child::NoChild),
                            },
                        });
                    }
                    (None, Some(a)) => {
                        // Input key is a subslice of `iter_entry`'s key.
                        // One has one descendant that is `iter_entry`.
                        let mut children = core::array::from_fn(|_| Child::NoChild);
                        children[usize::from(a)] = Child::InProof {
                            child_key: EntryKeyIter::new(self, iter_entry),
                            merkle_value: iter_entry_merkle_value,
                        };
                        return Ok(TrieNodeInfo {
                            storage_value: StorageValue::None,
                            children: Children { children },
                        });
                    }
                    (Some(child_num), None) => {
                        if let Some(child) = iter_entry_decoded.children[usize::from(child_num)] {
                            // Key points in the direction of a child.
                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete.
                            if children_present_in_proof_bitmap & (1 << u8::from(child_num)) == 0 {
                                return Err(IncompleteProofError());
                            }

                            // Child is present in the proof. Update `iter_entry` and continue.
                            iter_entry_merkle_value = child;
                            for c in 0..u8::from(child_num) {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }
                            iter_entry += 1;
                            break;
                        } else {
                            // Key points to non-existing child.
                            return Ok(TrieNodeInfo {
                                storage_value: StorageValue::None,
                                children: Children {
                                    children: core::array::from_fn(|_| Child::NoChild),
                                },
                            });
                        }
                    }
                    (None, None) => {
                        // Exact match. Trie node is `iter_entry`.
                        return Ok(TrieNodeInfo {
                            storage_value: match (
                                iter_entry_decoded.storage_value,
                                &self.entries[iter_entry].storage_value_in_proof,
                            ) {
                                (trie_node::StorageValue::Unhashed(value), _) => {
                                    StorageValue::Known {
                                        value,
                                        inline: true,
                                    }
                                }
                                (trie_node::StorageValue::Hashed(_), Some(value_range)) => {
                                    StorageValue::Known {
                                        value: &proof[value_range.clone()],
                                        inline: false,
                                    }
                                }
                                (trie_node::StorageValue::Hashed(hash), None) => {
                                    StorageValue::HashKnownValueMissing(hash)
                                }
                                (trie_node::StorageValue::None, _v) => {
                                    debug_assert!(_v.is_none());
                                    StorageValue::None
                                }
                            },
                            children: Children {
                                children: {
                                    let mut children = core::array::from_fn(|_| Child::NoChild);
                                    let mut i = iter_entry + 1;
                                    for child_num in 0..16 {
                                        let Some(child_merkle_value) =
                                            iter_entry_decoded.children[child_num]
                                        else {
                                            continue;
                                        };
                                        if self.entries[iter_entry].children_present_in_proof_bitmap
                                            & (1 << child_num)
                                            != 0
                                        {
                                            children[child_num] = Child::InProof {
                                                child_key: EntryKeyIter::new(self, i),
                                                merkle_value: child_merkle_value,
                                            };
                                            i += self.entries[i].child_entries_follow_up;
                                            i += 1;
                                        } else {
                                            children[child_num] = Child::AbsentFromProof {
                                                merkle_value: child_merkle_value,
                                            };
                                        }
                                    }
                                    children
                                },
                            },
                        });
                    }
                }
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
        match self
            .trie_node_info(
                trie_root_merkle_value,
                nibble::bytes_to_nibbles(key.iter().copied()),
            )?
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
    pub fn next_key(
        &'_ self,
        trie_root_merkle_value: &[u8; 32],
        key_before: impl Iterator<Item = nibble::Nibble>,
        mut or_equal: bool,
        prefix: impl Iterator<Item = nibble::Nibble>,
        branch_nodes: bool,
    ) -> Result<Option<EntryKeyIter<'_, T>>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // The implementation below might continue iterating `prefix` even after it has returned
        // `None`, thus we have to fuse it.
        let mut prefix = prefix.fuse();

        // The implementation below might continue iterating `key_before` even after it has
        // returned `None`, thus we have to fuse it.
        // Furthermore, `key_before` might be modified in the implementation below. When that
        // happens, de do this by setting it to `either::Right`.
        let mut key_before = either::Left(key_before.fuse());

        // Find the starting point of the requested trie.
        let Some(&(mut iter_entry)) = self.trie_roots.get(trie_root_merkle_value) else {
            return Err(IncompleteProofError());
        };

        // If `true`, then it was determined that `key_before` was after the last child of
        // `iter_entry`. The next iteration must find `iter_entry`'s next sibling.
        let mut iterating_up: bool = false;

        // Indicates the depth of ancestors of `iter_entry` that match `prefix`.
        // For example, if the value is 2, then `iter_entry`'s parent and grandparent match
        //`prefix`, but `iter_entry`'s grandparent parent does not.
        let mut prefix_match_iter_entry_ancestor_depth = 0;

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                // Proof has been checked to be entirely decodable.
                unreachable!()
            };

            if iterating_up {
                debug_assert!(matches!(key_before, either::Right(_)));
                debug_assert!(or_equal);

                // It was determined that `key_before` was after the last child of `iter_entry`.
                // The next iteration must find `iter_entry`'s next sibling.

                if prefix_match_iter_entry_ancestor_depth == 0 {
                    // `prefix` only matches `iter_entry` and not its parent and
                    // thus wouldn't match `iter_entry`'s sibling or uncle.
                    // Therefore, the next node is `None`.
                    return Ok(None);
                }

                // Go to `iter_entry`'s next sibling, if any.
                let Some((parent_entry, parent_to_child_nibble)) =
                    self.entries[iter_entry].parent_entry_index
                else {
                    // `iter_entry` is the root of the trie. `key_before` is therefore
                    // after the last entry of the trie.
                    return Ok(None);
                };

                let Some(child_num) = iter_entry_decoded
                    .children
                    .iter()
                    .skip(usize::from(parent_to_child_nibble) + 1)
                    .position(|c| c.is_some())
                    .map(|n| n + usize::from(parent_to_child_nibble) + 1)
                else {
                    // No child found. Continue iterating up.
                    iterating_up = true;
                    iter_entry = parent_entry;
                    prefix_match_iter_entry_ancestor_depth -= 1;
                    continue;
                };

                // Found a next sibling.

                let children_present_in_proof_bitmap =
                    self.entries[parent_entry].children_present_in_proof_bitmap;

                // If the child isn't present in the proof, then the proof is
                // incomplete. While in some situations we could prove that the child
                // is necessarily the next key, there is no way to know its full key.
                if children_present_in_proof_bitmap & (1 << child_num) == 0 {
                    return Err(IncompleteProofError());
                }

                // `iter_entry` is still pointing to the child at index `parent_to_child_nibble`.
                // Since we're jumping to its next sibling, all we have to do is skip over it
                // and its descedants.
                iter_entry += 1;
                iter_entry += self.entries[iter_entry].child_entries_follow_up;
                iterating_up = false;
            }

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (
                    key_before.next(),
                    prefix.next(),
                    iter_entry_partial_key_iter.next(),
                ) {
                    (Some(k), Some(p), Some(pk)) if k == p && p == pk => {
                        // Continue descending down the tree.
                    }
                    (None, Some(p), Some(pk)) if p == pk => {
                        // Continue descending down the tree.
                    }
                    (Some(k), None, Some(pk)) if k == pk => {
                        // Continue descending down the tree.
                    }
                    (None, None, Some(_)) => {
                        // Exact match. Due to the `branch_nodes` setting, we can't just
                        // return `iter_entry` and instead continue iterating.
                        or_equal = true;
                    }
                    (Some(k), None, Some(pk)) if k < pk => {
                        // `key_before` points to somewhere between `iter_entry`'s parent
                        // and `iter_entry`. Due to the `branch_nodes` setting, we can't just
                        // return `iter_entry` and instead continue iterating.
                        key_before = either::Right(iter::empty().fuse());
                        or_equal = true;
                    }
                    (Some(k), Some(p), _) if k > p => {
                        // `key_before` is strictly superior to `prefix`. The next key is
                        // thus necessarily `None`.
                        // Note that this is not a situation that is expected to be common, as
                        // doing such a call is pointless.
                        return Ok(None);
                    }
                    (Some(k), Some(p), Some(pk)) if k < p && p == pk => {
                        // The key and prefix diverge.
                        // We know that there isn't any key in the trie between `key_before`
                        // and `prefix`.
                        // Starting next iteration, the next node matching the prefix
                        // will be the result.
                        key_before = either::Right(iter::empty().fuse());
                        or_equal = true;
                    }
                    (_, Some(p), Some(pk)) => {
                        debug_assert!(p != pk); // Other situations covered by other match blocks.

                        // Mismatch between prefix and partial key. No matter the value of
                        // `key_before` There is no node in the trie that starts with `prefix`.
                        return Ok(None);
                    }
                    (Some(k), None, Some(pk)) if k < pk => {
                        // `key_before` points to somewhere between `iter_entry`'s parent
                        // and `iter_entry`. We know that `iter_entry` necessarily matches
                        // the prefix. The next key is necessarily `iter_entry`.
                        return Ok(Some(EntryKeyIter::new(self, iter_entry)));
                    }
                    (Some(k), None, Some(pk)) => {
                        debug_assert!(k > pk); // Checked above.

                        // `key_before` points to somewhere between the last child of `iter_entry`
                        // and its next sibling.
                        // The next key is thus the next sibling of `iter_entry`.
                        iterating_up = true;
                        key_before = either::Right(iter::empty().fuse());
                        or_equal = true;
                        break;
                    }
                    (None, None, None)
                        if or_equal
                            && (branch_nodes
                                || !matches!(
                                    iter_entry_decoded.storage_value,
                                    trie_node::StorageValue::None,
                                )) =>
                    {
                        // Exact match. Next key is `iter_entry`.
                        return Ok(Some(EntryKeyIter::new(self, iter_entry)));
                    }
                    (key_before_nibble, prefix_nibble, None) => {
                        // The moment when we have finished traversing a node and go to the
                        // next one is the most complicated situation.

                        // We know for sure that `iter_entry` can't be returned, as it is covered
                        // by the other match variants above. Therefore, `key_before_nibble` equal
                        // to `None` is the same as if it is equal to `0`.
                        let key_before_nibble = match key_before_nibble {
                            Some(n) => u8::from(n),
                            None => {
                                or_equal = true;
                                0
                            }
                        };

                        // Try to find the first child that is after `key_before`.
                        if let Some(child_num) = iter_entry_decoded
                            .children
                            .iter()
                            .skip(usize::from(key_before_nibble))
                            .position(|c| c.is_some())
                            .map(|n| n + usize::from(key_before_nibble))
                        {
                            // Found a child. Make sure that it matches the prefix nibble.
                            if prefix_nibble.map_or(false, |p| child_num != usize::from(p)) {
                                // Child doesn't match prefix. No next key.
                                return Ok(None);
                            }

                            // Continue iterating down through the child that has been found.

                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete. While in some situations we could prove that the child
                            // is necessarily the next key, there is no way to know its full key.
                            if children_present_in_proof_bitmap & (1 << key_before_nibble) == 0 {
                                return Err(IncompleteProofError());
                            }

                            for c in 0..key_before_nibble {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }

                            iter_entry += 1;
                            prefix_match_iter_entry_ancestor_depth += 1;
                            if usize::from(key_before_nibble) != child_num {
                                key_before = either::Right(iter::empty().fuse());
                                or_equal = true;
                            }
                            break;
                        } else {
                            // Childless branch nodes are forbidden. This is checked when
                            // decoding the proof.
                            debug_assert!(!matches!(
                                iter_entry_decoded.storage_value,
                                trie_node::StorageValue::None,
                            ));

                            // `key_before` is after the last child of `iter_entry`. The next
                            // node is thus a sibling or uncle of `iter_entry`.
                            iterating_up = true;
                            key_before = either::Right(iter::empty().fuse());
                            or_equal = true;
                            break;
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
    pub fn closest_descendant_merkle_value(
        &'_ self,
        trie_root_merkle_value: &[u8; 32],
        mut key: impl Iterator<Item = nibble::Nibble>,
    ) -> Result<Option<&'_ [u8]>, IncompleteProofError> {
        let proof = self.proof.as_ref();

        // Find the starting point of the requested trie.
        let Some((mut iter_entry_merkle_value, mut iter_entry)) = self
            .trie_roots
            .get_key_value(trie_root_merkle_value)
            .map(|(k, v)| (&k[..], *v))
        else {
            return Err(IncompleteProofError());
        };

        loop {
            let Ok(iter_entry_decoded) =
                trie_node::decode(&proof[self.entries[iter_entry].range_in_proof.clone()])
            else {
                // Proof has been checked to be entirely decodable.
                unreachable!()
            };

            let mut iter_entry_partial_key_iter = iter_entry_decoded.partial_key;
            loop {
                match (key.next(), iter_entry_partial_key_iter.next()) {
                    (Some(a), Some(b)) if a == b => {}
                    (Some(_), Some(_)) => {
                        // Mismatch in partial key. No descendant.
                        return Ok(None);
                    }
                    (None, Some(_)) => {
                        // Input key is a subslice of `iter_entry`'s key.
                        // Descendant is thus `iter_entry`.
                        return Ok(Some(iter_entry_merkle_value));
                    }
                    (Some(child_num), None) => {
                        if let Some(child) = iter_entry_decoded.children[usize::from(child_num)] {
                            // Key points in the direction of a child.
                            let children_present_in_proof_bitmap =
                                self.entries[iter_entry].children_present_in_proof_bitmap;

                            // If the child isn't present in the proof, then the proof is
                            // incomplete, unless the input key doesn't have any nibble anymore,
                            // in which case we know that the closest descendant is this child,
                            // even if it's not present.
                            if children_present_in_proof_bitmap & (1 << u8::from(child_num)) == 0 {
                                if key.next().is_none() {
                                    return Ok(Some(child));
                                } else {
                                    return Err(IncompleteProofError());
                                }
                            }

                            // Child is present in the proof. Update `iter_entry` and continue.
                            iter_entry_merkle_value = child;
                            for c in 0..u8::from(child_num) {
                                if children_present_in_proof_bitmap & (1 << c) != 0 {
                                    iter_entry += 1;
                                    iter_entry += self.entries[iter_entry].child_entries_follow_up;
                                }
                            }
                            iter_entry += 1;
                            break;
                        } else {
                            // Key points to non-existing child. We know that there's no
                            // descendant.
                            return Ok(None);
                        }
                    }
                    (None, None) => {
                        // Exact match. Closest descendant is `iter_entry`.
                        return Ok(Some(iter_entry_merkle_value));
                    }
                }
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
    /// All nodes must either have children or a storage value or be the root node.
    NonRootBranchNodeWithNoValue,
    /// Found node with no storage value and exact one child.
    NodeWithNoValueAndOneChild,
}

pub struct EntryKeyIter<'a, T> {
    proof: &'a DecodedTrieProof<T>,
    target_entry: usize,
    /// [`EntryKeyIter::entry_key_iterator`] is the `target_entry_depth_remaining` nth ancestor
    /// of [`EntryKeyIter::target_entry`].
    target_entry_depth_remaining: usize,
    /// `None` if iteration is finished.
    entry_key_iterator: Option<trie_node::DecodedPartialKey<'a>>,
}

impl<'a, T: AsRef<[u8]>> EntryKeyIter<'a, T> {
    fn new(proof: &'a DecodedTrieProof<T>, target_entry: usize) -> Self {
        // Find the number of nodes between `target_entry` and the trie root.
        let mut entry_iter = target_entry;
        let mut target_entry_depth_remaining = 0;
        loop {
            if let Some((parent, _)) = proof.entries[entry_iter].parent_entry_index {
                target_entry_depth_remaining += 1;
                entry_iter = parent;
            } else {
                break;
            }
        }

        let Ok(decoded_entry) = trie_node::decode(
            &proof.proof.as_ref()[proof.entries[entry_iter].range_in_proof.clone()],
        ) else {
            unreachable!()
        };

        EntryKeyIter {
            proof,
            target_entry,
            target_entry_depth_remaining,
            entry_key_iterator: Some(decoded_entry.partial_key),
        }
    }
}

impl<'a, T: AsRef<[u8]>> Iterator for EntryKeyIter<'a, T> {
    type Item = nibble::Nibble;

    fn next(&mut self) -> Option<Self::Item> {
        // `entry_key_iterator` is `None` only if the iteration is finished, as a way to fuse
        // the iterator.
        let Some(entry_key_iterator) = &mut self.entry_key_iterator else {
            return None;
        };

        // Still yielding from `entry_key_iterator`.
        if let Some(nibble) = entry_key_iterator.next() {
            return Some(nibble);
        }

        // `entry_key_iterator` has finished iterating. Update the local state for the next node
        // in the hierarchy.
        if self.target_entry_depth_remaining == 0 {
            // Iteration finished.
            self.entry_key_iterator = None;
            return None;
        }
        self.target_entry_depth_remaining -= 1;

        // Find the `target_entry_depth_remaining`th ancestor of `target_entry`.
        let mut entry_iter = self.target_entry;
        for _ in 0..self.target_entry_depth_remaining {
            let Some((parent, _)) = self.proof.entries[entry_iter].parent_entry_index else {
                unreachable!()
            };
            entry_iter = parent;
        }

        // Store the partial key of `entry_iter` in `entry_key_iterator`, so that it starts being
        // yielded at the next iteration.
        self.entry_key_iterator = Some(
            trie_node::decode(
                &self.proof.proof.as_ref()[self.proof.entries[entry_iter].range_in_proof.clone()],
            )
            .unwrap_or_else(|_| unreachable!())
            .partial_key,
        );

        // Yield the "parent-child nibble" of `entry_iter`.
        Some(
            self.proof.entries[entry_iter]
                .parent_entry_index
                .unwrap_or_else(|| unreachable!())
                .1,
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // We know we're going to yield `self.target_entry_depth_remaining` "parent-child nibbles".
        // We add to that the size hint of `entry_key_iterator`.
        let entry_key_iterator = self
            .entry_key_iterator
            .as_ref()
            .map_or(0, |i| i.size_hint().0);
        (entry_key_iterator + self.target_entry_depth_remaining, None)
    }
}

impl<'a, T: AsRef<[u8]>> iter::FusedIterator for EntryKeyIter<'a, T> {}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for EntryKeyIter<'a, T> {
    fn clone(&self) -> Self {
        EntryKeyIter {
            proof: self.proof,
            target_entry: self.target_entry,
            target_entry_depth_remaining: self.target_entry_depth_remaining,
            entry_key_iterator: self.entry_key_iterator.clone(),
        }
    }
}

impl<'a, T: AsRef<[u8]>> fmt::Debug for EntryKeyIter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut any_printed = false;
        for nibble in self.clone() {
            any_printed = true;
            write!(f, "{:x}", nibble)?;
        }
        if !any_printed {
            write!(f, "∅")?;
        }
        Ok(())
    }
}

/// Information about an entry in the proof.
#[derive(Debug)]
pub struct ProofEntry<'a, T> {
    /// Information about the node of the trie associated to this entry.
    pub trie_node_info: TrieNodeInfo<'a, T>,

    /// Merkle value of that proof entry.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub merkle_value: &'a [u8],

    /// Node value of that proof entry.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub node_value: &'a [u8],

    /// Partial key of that proof entry.
    ///
    /// > **Note**: This is a low-level information. If you're not familiar with how the trie
    /// >           works, you most likely don't need this.
    pub partial_key_nibbles: trie_node::DecodedPartialKey<'a>,

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

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for ProofEntry<'a, T> {
    fn clone(&self) -> Self {
        ProofEntry {
            trie_node_info: self.trie_node_info.clone(),
            merkle_value: self.merkle_value,
            node_value: self.node_value,
            partial_key_nibbles: self.partial_key_nibbles.clone(),
            unhashed_storage_value: self.unhashed_storage_value,
        }
    }
}

/// Information about a node of the trie.
///
/// > **Note**: This structure might represent a node that doesn't actually exist in the trie.
#[derive(Debug)]
pub struct TrieNodeInfo<'a, T> {
    /// Storage value of the node, if any.
    pub storage_value: StorageValue<'a>,
    /// Which children the node has.
    pub children: Children<'a, T>,
}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for TrieNodeInfo<'a, T> {
    fn clone(&self) -> Self {
        TrieNodeInfo {
            storage_value: self.storage_value,
            children: self.children.clone(),
        }
    }
}

/// See [`TrieNodeInfo::children`].
pub struct Children<'a, T> {
    children: [Child<'a, T>; 16],
}

/// Information about a specific child in the list of children.
pub enum Child<'a, T> {
    /// Child exists and can be found in the proof.
    InProof {
        /// Key of the child. Always starts with the key of its parent.
        child_key: EntryKeyIter<'a, T>,
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

impl<'a, T> Child<'a, T> {
    /// Returns the Merkle value of this child. `None` if the child doesn't exist.
    pub fn merkle_value(&self) -> Option<&'a [u8]> {
        match self {
            Child::InProof { merkle_value, .. } => Some(merkle_value),
            Child::AbsentFromProof { merkle_value } => Some(merkle_value),
            Child::NoChild => None,
        }
    }
}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for Child<'a, T> {
    fn clone(&self) -> Self {
        match self {
            Child::AbsentFromProof { merkle_value } => Child::AbsentFromProof { merkle_value },
            Child::InProof {
                child_key,
                merkle_value,
            } => Child::InProof {
                child_key: child_key.clone(),
                merkle_value,
            },
            Child::NoChild => Child::NoChild,
        }
    }
}

impl<'a, T> Children<'a, T> {
    /// Returns `true` if a child in the direction of the given nibble is present.
    pub fn has_child(&self, nibble: nibble::Nibble) -> bool {
        match self.children[usize::from(u8::from(nibble))] {
            Child::InProof { .. } | Child::AbsentFromProof { .. } => true,
            Child::NoChild => false,
        }
    }

    /// Returns the information about the child in the given direction.
    pub fn child(&self, direction: nibble::Nibble) -> Child<'a, T> {
        self.children[usize::from(u8::from(direction))].clone()
    }

    /// Returns an iterator of 16 items, one for each child.
    pub fn children(
        &'_ self,
    ) -> impl DoubleEndedIterator + ExactSizeIterator<Item = Child<'a, T>> + '_ {
        self.children.iter().cloned()
    }
}

// We need to implement `Clone` manually, otherwise Rust adds an implicit `T: Clone` requirements.
impl<'a, T> Clone for Children<'a, T> {
    fn clone(&self) -> Self {
        Children {
            children: self.children.clone(),
        }
    }
}

impl<'a, T> fmt::Debug for Children<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Binary::fmt(&self, f)
    }
}

impl<'a, T> fmt::Binary for Children<'a, T> {
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
    use core::iter;
    use trie::Nibble;

    use crate::trie;

    // Key/value taken from the Polkadot genesis block.
    const EXAMPLE_PROOF: &[u8] = &[
        24, 212, 125, 1, 84, 37, 150, 173, 176, 93, 97, 64, 193, 112, 172, 71, 158, 223, 124, 253,
        90, 163, 83, 87, 89, 10, 207, 229, 209, 26, 128, 77, 148, 78, 80, 13, 20, 86, 253, 218,
        123, 142, 199, 249, 229, 199, 148, 205, 131, 25, 79, 5, 147, 228, 234, 53, 5, 128, 63, 147,
        128, 78, 76, 108, 66, 34, 183, 71, 229, 7, 0, 142, 241, 222, 240, 99, 187, 13, 45, 238,
        173, 241, 126, 244, 177, 14, 113, 98, 77, 58, 12, 248, 28, 128, 36, 31, 44, 6, 242, 46,
        197, 137, 104, 251, 104, 212, 50, 49, 158, 37, 230, 200, 250, 163, 173, 44, 92, 169, 238,
        72, 242, 232, 237, 21, 142, 36, 128, 173, 138, 104, 35, 73, 50, 38, 152, 70, 188, 64, 36,
        10, 71, 207, 216, 216, 133, 123, 29, 129, 225, 103, 191, 178, 76, 148, 122, 76, 218, 217,
        230, 128, 200, 69, 144, 227, 159, 139, 121, 162, 105, 74, 210, 191, 126, 114, 88, 175, 104,
        107, 71, 47, 56, 176, 100, 187, 206, 125, 8, 64, 73, 49, 164, 48, 128, 92, 114, 242, 91,
        27, 99, 4, 209, 102, 103, 226, 118, 111, 161, 169, 6, 203, 8, 23, 136, 235, 69, 2, 120,
        125, 247, 195, 89, 116, 18, 177, 123, 128, 110, 33, 197, 241, 162, 74, 25, 102, 21, 180,
        229, 179, 109, 33, 40, 12, 220, 200, 0, 152, 193, 226, 188, 232, 238, 175, 48, 30, 153, 81,
        118, 116, 128, 66, 79, 26, 205, 128, 186, 7, 74, 44, 232, 209, 128, 191, 52, 136, 165, 202,
        145, 203, 129, 251, 169, 108, 140, 60, 29, 51, 234, 203, 177, 129, 96, 128, 94, 132, 157,
        92, 20, 140, 163, 97, 165, 90, 44, 155, 56, 78, 23, 206, 145, 158, 147, 108, 203, 128, 17,
        164, 247, 37, 4, 233, 249, 61, 184, 205, 128, 237, 208, 5, 161, 73, 92, 112, 37, 13, 119,
        248, 28, 36, 193, 90, 153, 25, 240, 52, 247, 152, 61, 248, 229, 5, 229, 58, 90, 247, 180,
        2, 19, 128, 18, 160, 221, 144, 73, 123, 101, 49, 43, 218, 103, 234, 21, 153, 101, 120, 238,
        179, 137, 27, 202, 134, 102, 149, 26, 50, 102, 18, 65, 142, 49, 67, 177, 4, 128, 85, 93,
        128, 67, 251, 73, 124, 27, 42, 123, 158, 79, 235, 89, 244, 16, 193, 162, 158, 40, 178, 166,
        40, 255, 156, 96, 3, 224, 128, 246, 185, 250, 221, 149, 249, 128, 110, 141, 145, 27, 104,
        24, 3, 142, 183, 200, 83, 74, 248, 231, 142, 153, 32, 161, 171, 141, 147, 156, 54, 211,
        230, 155, 10, 30, 89, 40, 17, 11, 128, 186, 77, 63, 84, 57, 87, 244, 34, 180, 12, 142, 116,
        175, 157, 224, 10, 203, 235, 168, 21, 74, 252, 165, 122, 127, 128, 251, 188, 254, 187, 30,
        74, 128, 61, 27, 143, 92, 241, 120, 139, 41, 69, 55, 184, 253, 45, 52, 172, 236, 70, 70,
        167, 98, 124, 108, 211, 210, 3, 154, 246, 79, 245, 209, 151, 109, 128, 231, 98, 15, 33,
        207, 19, 150, 79, 41, 211, 75, 167, 8, 195, 180, 78, 164, 94, 161, 28, 88, 251, 190, 221,
        162, 157, 19, 71, 11, 200, 12, 160, 128, 249, 138, 174, 79, 131, 216, 27, 241, 93, 136, 1,
        158, 92, 48, 61, 124, 25, 208, 82, 78, 132, 199, 20, 224, 95, 97, 81, 124, 222, 11, 19,
        130, 128, 213, 24, 250, 245, 102, 253, 196, 208, 69, 9, 74, 190, 55, 43, 179, 187, 236,
        212, 117, 63, 118, 219, 140, 65, 186, 159, 192, 21, 85, 139, 242, 58, 128, 144, 143, 153,
        17, 38, 209, 44, 231, 172, 213, 85, 8, 255, 30, 125, 255, 165, 111, 116, 36, 1, 225, 129,
        79, 193, 70, 150, 88, 167, 140, 122, 127, 128, 1, 176, 160, 141, 160, 200, 50, 83, 213,
        192, 203, 135, 114, 134, 192, 98, 218, 47, 83, 10, 228, 36, 254, 37, 69, 55, 121, 65, 253,
        1, 105, 19, 53, 5, 128, 179, 167, 128, 162, 159, 172, 127, 125, 250, 226, 29, 5, 217, 80,
        110, 125, 166, 81, 91, 127, 161, 173, 151, 15, 248, 118, 222, 53, 241, 190, 194, 89, 158,
        192, 2, 128, 91, 103, 114, 220, 106, 78, 118, 4, 200, 208, 101, 36, 121, 249, 91, 52, 54,
        7, 194, 217, 19, 140, 89, 238, 183, 153, 216, 91, 244, 59, 107, 191, 128, 61, 18, 190, 203,
        106, 75, 153, 25, 221, 199, 197, 151, 61, 4, 238, 215, 105, 108, 131, 79, 144, 199, 121,
        252, 31, 207, 115, 80, 204, 194, 141, 107, 128, 95, 51, 235, 207, 25, 31, 221, 207, 59, 63,
        52, 110, 195, 54, 193, 5, 199, 75, 64, 164, 211, 93, 253, 160, 197, 146, 242, 190, 160, 0,
        132, 233, 128, 247, 100, 199, 51, 214, 227, 87, 113, 169, 178, 106, 31, 168, 107, 155, 236,
        89, 116, 43, 4, 111, 105, 139, 230, 193, 64, 175, 16, 115, 137, 125, 61, 128, 205, 59, 200,
        195, 206, 60, 248, 53, 159, 115, 113, 161, 51, 22, 240, 47, 210, 43, 2, 163, 211, 39, 104,
        74, 43, 97, 244, 164, 126, 0, 34, 184, 128, 218, 117, 42, 250, 235, 146, 93, 83, 0, 228,
        91, 133, 16, 82, 197, 248, 169, 197, 170, 232, 132, 241, 93, 100, 118, 78, 223, 150, 27,
        139, 34, 200, 128, 191, 31, 169, 199, 228, 201, 67, 64, 219, 175, 215, 92, 190, 1, 108,
        152, 13, 14, 93, 91, 78, 118, 130, 63, 161, 30, 97, 98, 144, 20, 195, 75, 128, 79, 84, 161,
        94, 93, 81, 208, 43, 132, 232, 202, 233, 76, 152, 51, 174, 129, 229, 107, 143, 11, 104, 77,
        37, 127, 111, 114, 46, 230, 108, 173, 249, 128, 148, 131, 63, 178, 220, 232, 199, 141, 68,
        60, 214, 120, 110, 12, 1, 216, 151, 74, 75, 119, 156, 23, 142, 245, 230, 107, 73, 224, 33,
        221, 127, 26, 225, 2, 159, 12, 93, 121, 93, 2, 151, 190, 86, 2, 122, 75, 36, 100, 227, 51,
        151, 96, 146, 128, 243, 50, 255, 85, 106, 191, 93, 175, 13, 52, 82, 61, 247, 200, 205, 19,
        105, 188, 182, 173, 187, 35, 164, 128, 147, 191, 7, 10, 151, 17, 191, 52, 128, 56, 41, 52,
        19, 74, 169, 25, 181, 156, 22, 255, 141, 232, 217, 122, 127, 220, 194, 68, 142, 163, 39,
        178, 111, 68, 0, 93, 117, 109, 23, 133, 135, 128, 129, 214, 52, 20, 11, 54, 206, 3, 28, 75,
        108, 98, 102, 226, 167, 193, 157, 154, 136, 227, 143, 221, 138, 210, 58, 189, 61, 178, 14,
        113, 79, 105, 128, 253, 225, 112, 65, 242, 47, 9, 96, 157, 121, 219, 227, 141, 204, 206,
        252, 170, 193, 57, 199, 161, 15, 178, 59, 210, 132, 193, 196, 146, 176, 4, 253, 128, 210,
        135, 173, 29, 10, 222, 101, 230, 77, 57, 105, 244, 171, 133, 163, 112, 118, 129, 96, 49,
        67, 140, 234, 11, 248, 195, 59, 123, 43, 198, 195, 48, 141, 8, 159, 3, 230, 211, 193, 251,
        21, 128, 94, 223, 208, 36, 23, 46, 164, 129, 125, 255, 255, 128, 21, 40, 51, 227, 74, 133,
        46, 151, 81, 207, 192, 249, 84, 174, 184, 53, 225, 248, 67, 147, 107, 169, 151, 152, 83,
        164, 14, 67, 153, 55, 37, 95, 128, 106, 54, 224, 173, 35, 251, 50, 36, 255, 246, 230, 219,
        98, 4, 132, 99, 167, 242, 124, 203, 146, 246, 91, 78, 52, 138, 205, 90, 122, 163, 160, 104,
        128, 39, 182, 224, 153, 193, 21, 129, 251, 46, 138, 207, 59, 107, 148, 234, 237, 68, 34,
        119, 185, 167, 76, 231, 249, 34, 246, 227, 191, 41, 89, 134, 123, 128, 253, 12, 194, 200,
        70, 219, 106, 158, 209, 154, 113, 93, 108, 60, 212, 106, 72, 183, 244, 9, 136, 60, 112,
        178, 212, 201, 120, 179, 6, 222, 55, 158, 128, 171, 0, 138, 120, 195, 64, 245, 204, 117,
        217, 156, 219, 144, 89, 81, 147, 102, 134, 68, 92, 131, 71, 25, 190, 33, 247, 98, 11, 149,
        13, 205, 92, 128, 109, 134, 175, 84, 213, 223, 177, 192, 111, 63, 239, 221, 90, 67, 8, 97,
        192, 209, 158, 37, 250, 212, 186, 208, 124, 110, 112, 212, 166, 121, 240, 184, 128, 243,
        94, 220, 84, 0, 182, 102, 31, 177, 230, 251, 167, 197, 153, 200, 186, 137, 20, 88, 209, 68,
        0, 3, 15, 165, 6, 153, 154, 25, 114, 54, 159, 128, 116, 108, 218, 160, 183, 218, 46, 156,
        56, 100, 151, 31, 80, 241, 45, 155, 66, 129, 248, 4, 213, 162, 219, 166, 235, 224, 105, 89,
        178, 169, 251, 71, 128, 46, 207, 222, 17, 69, 100, 35, 200, 127, 237, 128, 104, 244, 20,
        165, 186, 68, 235, 227, 174, 145, 176, 109, 20, 204, 35, 26, 120, 212, 171, 166, 142, 128,
        246, 85, 41, 24, 51, 164, 156, 242, 61, 5, 123, 177, 92, 66, 211, 119, 197, 93, 80, 245,
        136, 83, 41, 6, 11, 10, 170, 178, 34, 131, 203, 177, 128, 140, 149, 251, 43, 98, 186, 243,
        7, 24, 184, 51, 14, 246, 138, 82, 124, 151, 193, 188, 153, 96, 48, 67, 83, 34, 77, 138,
        138, 232, 138, 121, 213, 128, 69, 193, 182, 217, 144, 74, 225, 113, 213, 115, 189, 206,
        186, 160, 81, 66, 216, 22, 72, 189, 190, 177, 108, 238, 221, 197, 74, 14, 209, 93, 62, 43,
        128, 168, 234, 25, 50, 130, 254, 133, 182, 72, 23, 7, 9, 28, 119, 201, 33, 142, 161, 157,
        233, 20, 231, 89, 80, 146, 95, 232, 100, 0, 251, 12, 176, 128, 194, 34, 206, 171, 83, 85,
        234, 164, 29, 168, 7, 20, 111, 46, 45, 247, 255, 100, 140, 62, 139, 187, 109, 142, 226, 50,
        116, 186, 114, 69, 81, 177, 128, 8, 241, 66, 220, 60, 89, 191, 17, 81, 200, 41, 236, 239,
        234, 53, 145, 158, 128, 69, 61, 181, 233, 102, 159, 90, 115, 137, 154, 170, 81, 102, 238,
        128, 79, 29, 33, 251, 220, 1, 128, 196, 222, 136, 107, 244, 15, 145, 223, 194, 32, 43, 62,
        182, 212, 37, 72, 212, 118, 144, 128, 65, 221, 97, 123, 184,
    ];

    const EXAMPLE_PROOF_STATE_ROOT: &[u8; 32] = &[
        41, 208, 217, 114, 205, 39, 203, 197, 17, 233, 88, 159, 203, 122, 69, 6, 213, 235, 106,
        158, 141, 242, 5, 240, 4, 114, 229, 171, 53, 74, 78, 23,
    ];

    #[test]
    fn empty_is_valid() {
        let _ = super::decode_and_verify_proof(super::Config { proof: &[0] }).unwrap();
    }

    #[test]
    fn storage_value_works() {
        let decoded = super::decode_and_verify_proof(super::Config {
            proof: EXAMPLE_PROOF,
        })
        .unwrap();

        assert_eq!(
            decoded
                .storage_value(EXAMPLE_PROOF_STATE_ROOT, &hex::decode("9c5d795d0297be56027a4b2464e3339763e6d3c1fb15805edfd024172ea4817d7081542596adb05d6140c170ac479edf7cfd5aa35357590acfe5d11a804d944e").unwrap())
                .unwrap().unwrap().0,
            &hex::decode("0d1456fdda7b8ec7f9e5c794cd83194f0593e4ea").unwrap()[..]
        );

        assert!(
            decoded
                .storage_value(EXAMPLE_PROOF_STATE_ROOT, &hex::decode("9c5d795d0297be56027a4b2464e3339763e6d3c1fb15805edfd024172ea4817d7081542596adb05d6140c170ac479edf7cfd5aa35357590acfe5d11a804d944e25").unwrap())
                .unwrap().is_none()
        );

        assert!(matches!(
            decoded.storage_value(
                EXAMPLE_PROOF_STATE_ROOT,
                &hex::decode(
                    "9c5d795d0297be56027a4b2464e3339763e6d3c1fb15805edfd024172ea4817d7000"
                )
                .unwrap()
            ),
            Err(super::IncompleteProofError())
        ));

        assert!(matches!(
            decoded.storage_value(&[0; 32], &[]),
            Err(super::IncompleteProofError())
        ));
    }

    #[test]
    fn next_key_works() {
        let decoded = super::decode_and_verify_proof(super::Config {
            proof: EXAMPLE_PROOF,
        })
        .unwrap();

        assert_eq!(
            decoded
                .next_key(
                    EXAMPLE_PROOF_STATE_ROOT,
                    iter::empty(),
                    true,
                    iter::empty(),
                    true
                )
                .unwrap()
                .unwrap()
                .collect::<Vec<_>>(),
            &[]
        );

        assert_eq!(
            decoded
                .next_key(
                    EXAMPLE_PROOF_STATE_ROOT,
                    [
                        9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4,
                        0xb, 2, 4, 6, 4, 0xe, 3, 3, 3, 9, 7
                    ]
                    .into_iter()
                    .map(|n| Nibble::try_from(n).unwrap()),
                    true,
                    iter::empty(),
                    true
                )
                .unwrap()
                .unwrap()
                .collect::<Vec<_>>(),
            [
                9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4, 0xb, 2,
                4, 6, 4, 0xe, 3, 3, 3, 9, 7
            ]
            .into_iter()
            .map(|n| Nibble::try_from(n).unwrap())
            .collect::<Vec<_>>()
        );

        assert_eq!(
            decoded
                .next_key(
                    EXAMPLE_PROOF_STATE_ROOT,
                    [
                        9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4,
                        0xb, 2, 4, 6, 4, 0xe, 3, 3, 3, 9
                    ]
                    .into_iter()
                    .map(|n| Nibble::try_from(n).unwrap()),
                    false,
                    iter::empty(),
                    true
                )
                .unwrap()
                .unwrap()
                .collect::<Vec<_>>(),
            [
                9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4, 0xb, 2,
                4, 6, 4, 0xe, 3, 3, 3, 9, 7
            ]
            .into_iter()
            .map(|n| Nibble::try_from(n).unwrap())
            .collect::<Vec<_>>()
        );

        assert!(matches!(
            decoded.next_key(
                EXAMPLE_PROOF_STATE_ROOT,
                [
                    9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4, 0xb,
                    2, 4, 6, 4, 0xe, 3, 3, 3, 9
                ]
                .into_iter()
                .map(|n| Nibble::try_from(n).unwrap()),
                false,
                iter::empty(),
                false
            ),
            Err(super::IncompleteProofError())
        ));

        assert!(decoded
            .next_key(
                EXAMPLE_PROOF_STATE_ROOT,
                [
                    9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4, 0xb,
                    2, 4, 6, 4, 0xe, 3, 3, 3, 9, 7
                ]
                .into_iter()
                .map(|n| Nibble::try_from(n).unwrap()),
                true,
                [
                    9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4, 0xb,
                    2, 4, 6, 4, 0xe, 3, 3, 3, 9, 7, 0
                ]
                .into_iter()
                .map(|n| Nibble::try_from(n).unwrap()),
                true
            )
            .unwrap()
            .is_none());

        assert!(decoded
            .next_key(
                EXAMPLE_PROOF_STATE_ROOT,
                [
                    9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4, 0xb,
                    2, 4, 6, 4, 0xe, 3, 3, 3, 9, 7
                ]
                .into_iter()
                .map(|n| Nibble::try_from(n).unwrap()),
                true,
                [
                    9, 0xc, 5, 0xd, 7, 9, 5, 0xd, 0, 2, 9, 7, 0xb, 0xe, 5, 6, 0, 2, 7, 0xa, 4, 0xb,
                    2, 4, 6, 4, 0xe, 3, 3, 3, 0xa
                ]
                .into_iter()
                .map(|n| Nibble::try_from(n).unwrap()),
                true
            )
            .unwrap()
            .is_none());

        // TODO: more tests
    }

    #[test]
    fn closest_descendant_merkle_value_works() {
        let decoded = super::decode_and_verify_proof(super::Config {
            proof: EXAMPLE_PROOF,
        })
        .unwrap();

        assert_eq!(
            decoded
                .closest_descendant_merkle_value(
                    EXAMPLE_PROOF_STATE_ROOT,
                    trie::bytes_to_nibbles([].into_iter())
                )
                .unwrap()
                .unwrap(),
            &EXAMPLE_PROOF_STATE_ROOT[..]
        );

        assert_eq!(
            decoded
                .closest_descendant_merkle_value(
                    EXAMPLE_PROOF_STATE_ROOT,
                    [super::nibble::Nibble::try_from(1).unwrap()].into_iter()
                )
                .unwrap()
                .unwrap(),
            &[
                36, 31, 44, 6, 242, 46, 197, 137, 104, 251, 104, 212, 50, 49, 158, 37, 230, 200,
                250, 163, 173, 44, 92, 169, 238, 72, 242, 232, 237, 21, 142, 36
            ][..]
        );

        assert!(matches!(
            dbg!(decoded.closest_descendant_merkle_value(
                EXAMPLE_PROOF_STATE_ROOT,
                [
                    super::nibble::Nibble::try_from(1).unwrap(),
                    super::nibble::Nibble::try_from(0).unwrap()
                ]
                .into_iter()
            )),
            Err(super::IncompleteProofError())
        ));

        assert!(decoded
            .closest_descendant_merkle_value(
                EXAMPLE_PROOF_STATE_ROOT,
                [super::nibble::Nibble::try_from(0xe).unwrap()].into_iter()
            )
            .unwrap()
            .is_none());

        assert!(decoded
            .closest_descendant_merkle_value(
                EXAMPLE_PROOF_STATE_ROOT,
                [
                    super::nibble::Nibble::try_from(0xe).unwrap(),
                    super::nibble::Nibble::try_from(0).unwrap()
                ]
                .into_iter()
            )
            .unwrap()
            .is_none());

        assert_eq!(
            decoded
                .closest_descendant_merkle_value(
                    EXAMPLE_PROOF_STATE_ROOT,
                    trie::bytes_to_nibbles(
                        [156, 93, 121, 93, 2, 151, 190, 86, 2, 122, 75, 36, 100, 227].into_iter()
                    )
                )
                .unwrap()
                .unwrap(),
            &[
                94, 132, 157, 92, 20, 140, 163, 97, 165, 90, 44, 155, 56, 78, 23, 206, 145, 158,
                147, 108, 203, 128, 17, 164, 247, 37, 4, 233, 249, 61, 184, 205
            ][..]
        );

        assert!(decoded
            .closest_descendant_merkle_value(
                EXAMPLE_PROOF_STATE_ROOT,
                trie::bytes_to_nibbles(
                    [156, 93, 121, 93, 2, 151, 190, 86, 2, 122, 75, 36, 100, 228].into_iter()
                )
            )
            .unwrap()
            .is_none());

        assert_eq!(
            decoded
                .closest_descendant_merkle_value(
                    EXAMPLE_PROOF_STATE_ROOT,
                    trie::bytes_to_nibbles(
                        [156, 93, 121, 93, 2, 151, 190, 86, 2, 122, 75, 36, 100, 227, 51, 151]
                            .into_iter()
                    )
                )
                .unwrap()
                .unwrap(),
            &[
                94, 132, 157, 92, 20, 140, 163, 97, 165, 90, 44, 155, 56, 78, 23, 206, 145, 158,
                147, 108, 203, 128, 17, 164, 247, 37, 4, 233, 249, 61, 184, 205
            ][..]
        );

        assert!(decoded
            .closest_descendant_merkle_value(
                EXAMPLE_PROOF_STATE_ROOT,
                trie::bytes_to_nibbles(
                    [
                        156, 93, 121, 93, 2, 151, 190, 86, 2, 122, 75, 36, 100, 227, 51, 151, 99,
                        230, 211, 193, 251, 21, 128, 94, 223, 208, 36, 23, 46, 164, 129, 125, 112,
                        129, 84, 37, 150, 173, 176, 93, 97, 64, 193, 112, 172, 71, 158, 223, 124,
                        253, 90, 163, 83, 87, 89, 10, 207, 229, 209, 26, 128, 77, 148, 78, 0
                    ]
                    .into_iter()
                )
            )
            .unwrap()
            .is_none());

        assert_eq!(
            decoded
                .closest_descendant_merkle_value(
                    EXAMPLE_PROOF_STATE_ROOT,
                    trie::bytes_to_nibbles(
                        [
                            156, 93, 121, 93, 2, 151, 190, 86, 2, 122, 75, 36, 100, 227, 51, 151,
                            99, 230, 211, 193, 251, 21, 128, 94, 223, 208, 36, 23, 46, 164, 129,
                            125, 112, 129, 84, 37, 150, 173, 176, 93, 97, 64, 193, 112, 172, 71,
                            158, 223, 124, 253, 90, 163, 83, 87, 89, 10, 207, 229, 209, 26, 128,
                            77, 148, 78
                        ]
                        .into_iter()
                    )
                )
                .unwrap()
                .unwrap(),
            &[
                205, 59, 200, 195, 206, 60, 248, 53, 159, 115, 113, 161, 51, 22, 240, 47, 210, 43,
                2, 163, 211, 39, 104, 74, 43, 97, 244, 164, 126, 0, 34, 184
            ][..]
        );

        assert_eq!(
            decoded
                .closest_descendant_merkle_value(
                    EXAMPLE_PROOF_STATE_ROOT,
                    trie::bytes_to_nibbles(
                        [
                            156, 93, 121, 93, 2, 151, 190, 86, 2, 122, 75, 36, 100, 227, 51, 151,
                            99, 230, 211, 193, 251, 21, 128, 94, 223, 208, 36, 23, 46, 164, 129,
                            125, 112, 129, 84, 37, 150, 173, 176, 93, 97, 64, 193, 112, 172, 71,
                            158, 223, 124, 253, 90, 163, 83, 87, 89, 10, 207, 229, 209, 26, 128,
                            77, 148
                        ]
                        .into_iter()
                    )
                )
                .unwrap()
                .unwrap(),
            &[
                205, 59, 200, 195, 206, 60, 248, 53, 159, 115, 113, 161, 51, 22, 240, 47, 210, 43,
                2, 163, 211, 39, 104, 74, 43, 97, 244, 164, 126, 0, 34, 184
            ][..]
        );
    }

    // TODO: test closest_ancestor

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
                iter::empty()
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
                iter::empty()
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
    fn storage_values_that_decode_are_ignored() {
        // This test makes sure that if a storage value found in a proof accidentally successfully
        // decodes as a trie node with an invalid inline child, the decoding doesn't return an
        // error and instead simply ignores it.
        // It is a regression test for <https://github.com/smol-dot/smoldot/pull/1362>.
        super::decode_and_verify_proof(super::Config {
            proof: &[
                249, 1, 97, 3, 0, 0, 48, 0, 0, 80, 0, 0, 170, 170, 10, 0, 0, 0, 64, 0, 251, 255, 0,
                0, 128, 0, 0, 0, 10, 0, 0, 0, 16, 14, 0, 0, 88, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 80, 0, 0, 200, 0, 0, 30, 0, 0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 0, 144, 1,
                0, 30, 0, 0, 0, 0, 144, 1, 0, 4, 1, 0, 32, 0, 0, 128, 112, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 16, 39, 0, 0, 128, 178, 230, 14, 128, 195, 201, 1, 128, 150, 152, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 1, 0, 0, 0, 1, 3,
                0, 0, 0, 1, 44, 1, 0, 0, 6, 0, 0, 0, 88, 2, 0, 0, 3, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0,
                0, 30, 0, 0, 0, 6, 0, 0, 0, 2, 0, 0, 0, 20, 0, 0, 0, 2, 0, 0, 0, 132, 1, 26, 118,
                193, 65, 215, 141, 49, 213, 102, 164, 117, 129, 154, 43, 143, 110, 86, 199, 140,
                245, 110, 51, 237, 121, 42, 47, 47, 177, 40, 203, 202, 36, 176, 54, 255, 111, 125,
                70, 123, 135, 169, 232, 3, 0, 0, 55, 141, 18, 33, 9, 228, 96, 214, 20, 250, 8, 137,
                170, 69, 232, 172, 124, 235, 254, 141, 126, 228, 181, 218, 29, 19, 92, 105, 118,
                141, 224, 39, 176, 54, 255, 111, 125, 70, 123, 135, 169, 232, 3, 0, 0, 129, 135,
                152, 88, 195, 254, 195, 247, 51, 254, 46, 63, 2, 174, 41, 56, 235, 208, 20, 207,
                49, 241, 253, 205, 183, 68, 150, 100, 236, 72, 25, 68, 192, 61, 0, 39, 9, 46, 239,
                5, 69, 232, 3, 0, 0, 215, 7, 0, 0, 32, 27, 15, 127, 205, 121, 190, 185, 62, 204, 1,
                128, 50, 46, 101, 201, 82, 198, 120, 168, 186, 95, 17, 179, 17, 1, 121, 26, 173,
                104, 57, 17, 192, 61, 0, 40, 140, 20, 28, 114, 29, 232, 3, 0, 0, 77, 8, 0, 0, 61,
                150, 210, 254, 230, 222, 187, 225, 31, 60, 227, 34, 93, 204, 79, 11, 98, 237, 182,
                161, 121, 26, 170, 252, 182, 97, 250, 173, 5, 61, 182, 149, 192, 61, 0, 171, 145,
                207, 1, 20, 216, 232, 3, 0, 0, 0, 8, 0, 0, 81, 2, 17, 44, 188, 60, 147, 230, 242,
                73, 17, 70, 19, 46, 224, 67, 186, 215, 152, 188, 29, 184, 112, 240, 6, 5, 223, 68,
                126, 41, 190, 130, 192, 61, 4, 23, 57, 95, 192, 189, 223, 234, 3, 0, 0, 232, 3, 0,
                0, 81, 2, 17, 44, 188, 60, 147, 230, 242, 73, 17, 70, 19, 46, 224, 67, 186, 215,
                152, 188, 29, 184, 112, 240, 6, 5, 223, 68, 126, 41, 190, 130, 192, 61, 6, 56, 2,
                208, 248, 212, 114, 232, 3, 0, 0, 231, 7, 0, 0, 211, 146, 25, 139, 229, 251, 35,
                14, 202, 17, 207, 172, 147, 76, 96, 238, 221, 50, 95, 138, 123, 115, 63, 159, 253,
                208, 81, 93, 175, 47, 136, 177, 192, 61, 10, 24, 216, 208, 25, 70, 203, 44, 8, 0,
                0, 232, 3, 0, 0, 108, 191, 211, 90, 169, 83, 96, 196, 220, 49, 111, 155, 130, 94,
                97, 0, 165, 137, 151, 12, 188, 17, 233, 113, 124, 6, 130, 189, 36, 94, 191, 43,
                192, 61, 10, 187, 47, 43, 177, 201, 79, 62, 8, 0, 0, 232, 3, 0, 0, 84, 177, 25, 92,
                85, 110, 50, 152, 111, 126, 60, 169, 206, 199, 73, 245, 186, 191, 14, 129, 210,
                101, 163, 185, 103, 110, 14, 53, 128, 9, 113, 135, 192, 61, 11, 121, 2, 180, 48,
                50, 139, 232, 3, 0, 0, 73, 8, 0, 0, 81, 2, 17, 44, 188, 60, 147, 230, 242, 73, 17,
                70, 19, 46, 224, 67, 186, 215, 152, 188, 29, 184, 112, 240, 6, 5, 223, 68, 126, 41,
                190, 130, 192, 61, 11, 128, 7, 157, 139, 153, 243, 232, 3, 0, 0, 36, 8, 0, 0, 110,
                144, 217, 165, 46, 204, 221, 194, 25, 70, 185, 24, 72, 39, 165, 170, 124, 143, 40,
                213, 47, 85, 169, 60, 207, 55, 153, 41, 242, 31, 44, 197, 192, 61, 11, 161, 105,
                169, 49, 149, 179, 232, 3, 0, 0, 209, 7, 0, 0, 135, 0, 122, 33, 98, 228, 190, 91,
                165, 67, 33, 82, 45, 82, 1, 202, 184, 9, 75, 180, 170, 93, 204, 3, 168, 110, 140,
                205, 208, 22, 160, 219, 192, 61, 12, 2, 1, 227, 42, 232, 107, 209, 7, 0, 0, 232, 3,
                0, 0, 151, 238, 85, 106, 200, 180, 9, 113, 172, 175, 77, 132, 69, 70, 173, 83, 112,
                166, 204, 254, 181, 105, 213, 253, 229, 127, 105, 146, 101, 32, 248, 137, 192, 61,
                12, 128, 141, 84, 168, 147, 123, 232, 3, 0, 0, 75, 8, 0, 0, 81, 2, 17, 44, 188, 60,
                147, 230, 242, 73, 17, 70, 19, 46, 224, 67, 186, 215, 152, 188, 29, 184, 112, 240,
                6, 5, 223, 68, 126, 41, 190, 130, 192, 61, 15, 17, 49, 183, 245, 75, 8, 0, 8, 0, 0,
                232, 3, 0, 0, 81, 2, 17, 44, 188, 60, 147, 230, 242, 73, 17, 70, 19, 46, 224, 67,
                186, 215, 152, 188, 29, 184, 112, 240, 6, 5, 223, 68, 126, 41, 190, 130, 192, 62,
                0, 83, 243, 142, 189, 253, 66, 231, 7, 0, 0, 232, 3, 0, 0, 21, 35, 22, 233, 213,
                153, 239, 52, 243, 111, 234, 26, 149, 63, 107, 6, 33, 211, 74, 32, 57, 27, 6, 207,
                207, 43, 66, 151, 86, 40, 118, 87, 192, 62, 4, 210, 161, 90, 181, 17, 39, 232, 3,
                0, 0, 208, 7, 0, 0, 4, 243, 195, 134, 53, 116, 171, 92, 152, 71, 180, 32, 53, 111,
                224, 6, 36, 236, 114, 64, 222, 202, 177, 0, 182, 61, 165, 91, 219, 109, 231, 158,
                192, 62, 15, 44, 104, 151, 68, 229, 91, 232, 3, 0, 0, 62, 8, 0, 0, 151, 85, 185,
                250, 155, 84, 76, 229, 101, 161, 127, 21, 135, 253, 52, 187, 111, 33, 157, 167, 72,
                225, 37, 14, 50, 216, 238, 248, 248, 120, 205, 152, 192, 62, 28, 100, 60, 157, 144,
                171, 116, 39, 8, 0, 0, 232, 3, 0, 0, 61, 228, 198, 210, 121, 188, 255, 91, 53, 54,
                69, 220, 240, 77, 12, 65, 152, 229, 254, 250, 154, 180, 171, 174, 11, 6, 197, 14,
                24, 225, 246, 33, 192, 62, 31, 197, 2, 226, 176, 126, 150, 232, 3, 0, 0, 39, 8, 0,
                0, 198, 68, 29, 105, 103, 233, 183, 118, 240, 55, 10, 247, 59, 176, 106, 169, 81,
                90, 210, 122, 16, 181, 63, 247, 57, 61, 166, 31, 129, 98, 190, 31, 192, 62, 41,
                178, 150, 130, 51, 131, 215, 232, 3, 0, 0, 76, 8, 0, 0, 244, 52, 228, 90, 91, 116,
                249, 136, 128, 118, 113, 105, 33, 69, 40, 181, 196, 67, 153, 66, 205, 28, 67, 9,
                208, 157, 110, 181, 72, 232, 201, 38, 192, 62, 59, 169, 1, 144, 95, 128, 192, 36,
                8, 0, 0, 232, 3, 0, 0, 230, 253, 85, 4, 130, 251, 98, 9, 18, 125, 172, 197, 126,
                75, 50, 108, 183, 157, 118, 89, 109, 191, 197, 26, 13, 210, 245, 72, 90, 114, 185,
                169, 192, 62, 67, 215, 59, 253, 0, 17, 49, 42, 8, 0, 0, 232, 3, 0, 0, 229, 151,
                103, 245, 113, 165, 120, 53, 181, 68, 32, 121, 167, 109, 115, 147, 51, 88, 61, 65,
                7, 86, 248, 78, 201, 162, 131, 172, 234, 74, 244, 251, 192, 62, 79, 54, 112, 131,
                102, 183, 34, 208, 7, 0, 0, 232, 3, 0, 0, 103, 90, 111, 142, 18, 131, 50, 58, 146,
                163, 192, 192, 163, 97, 68, 225, 108, 169, 162, 224, 10, 170, 248, 209, 151, 63,
                150, 132, 66, 203, 45, 207, 192, 62, 83, 81, 219, 36, 40, 165, 44, 77, 8, 0, 0,
                232, 3, 0, 0, 149, 206, 115, 106, 124, 106, 114, 192, 139, 11, 141, 73, 232, 176,
                215, 234, 33, 166, 157, 15, 57, 56, 241, 94, 225, 22, 243, 190, 3, 35, 103, 10,
                192, 62, 85, 202, 11, 145, 38, 11, 189, 215, 7, 0, 0, 232, 3, 0, 0, 56, 127, 221,
                245, 176, 100, 38, 121, 224, 118, 170, 244, 143, 186, 43, 47, 46, 134, 100, 151,
                205, 173, 200, 190, 238, 148, 239, 59, 112, 1, 30, 66, 192, 62, 111, 232, 252, 188,
                83, 20, 184, 76, 8, 0, 0, 232, 3, 0, 0, 230, 183, 216, 151, 183, 98, 18, 231, 55,
                243, 106, 173, 152, 61, 41, 4, 97, 17, 6, 25, 151, 197, 112, 254, 231, 159, 111,
                104, 130, 222, 62, 126, 192, 62, 119, 223, 219, 138, 219, 16, 247, 143, 16, 165,
                223, 135, 66, 197, 69, 55, 102, 164, 3, 102, 154, 246, 238, 148, 174, 113, 65, 150,
                173, 230, 159, 47, 183, 165, 25, 168, 157, 123, 104, 30, 195, 80, 69, 135, 156, 46,
                163, 192, 62, 121, 19, 197, 6, 141, 231, 236, 232, 3, 0, 0, 42, 8, 0, 0, 128, 59,
                7, 78, 184, 18, 34, 172, 243, 49, 234, 200, 81, 99, 228, 166, 85, 34, 117, 116,
                166, 178, 215, 164, 76, 198, 91, 77, 70, 53, 206, 43, 192, 62, 123, 154, 227, 54,
                228, 76, 248, 73, 8, 0, 0, 232, 3, 0, 0, 81, 2, 17, 44, 188, 60, 147, 230, 242, 73,
                17, 70, 19, 46, 224, 67, 186, 215, 152, 188, 29, 184, 112, 240, 6, 5, 223, 68, 126,
                41, 190, 130, 192, 62, 125, 153, 115, 129, 57, 149, 125, 232, 3, 0, 0, 234, 3, 0,
                0, 81, 2, 17, 44, 188, 60, 147, 230, 242, 73, 17, 70, 19, 46, 224, 67, 186, 215,
                152, 188, 29, 184, 112, 240, 6, 5, 223, 68, 126, 41, 190, 130, 192, 62, 153, 36,
                97, 4, 207, 65, 86, 75, 8, 0, 0, 232, 3, 0, 0, 81, 2, 17, 44, 188, 60, 147, 230,
                242, 73, 17, 70, 19, 46, 224, 67, 186, 215, 152, 188, 29, 184, 112, 240, 6, 5, 223,
                68, 126, 41, 190, 130, 192, 62, 160, 196, 240, 37, 252, 100, 103, 37, 8, 0, 0, 232,
                3, 0, 0, 223, 185, 89, 118, 226, 133, 142, 166, 9, 163, 159, 64, 35, 26, 188, 140,
                53, 108, 48, 49, 229, 232, 1, 60, 200, 8, 118, 255, 72, 9, 96, 30, 192, 62, 206,
                67, 51, 57, 104, 130, 146, 232, 3, 0, 0, 37, 8, 0, 0, 66, 254, 119, 40, 12, 101,
                64, 103, 226, 73, 149, 42, 100, 35, 59, 64, 66, 200, 132, 87, 131, 144, 254, 33,
                133, 8, 50, 55, 196, 146, 241, 150, 192, 62, 232, 44, 203, 92, 185, 84, 186, 232,
                3, 0, 0, 44, 8, 0, 0, 62, 187, 190, 68, 94, 177, 253, 116, 133, 112, 96, 78, 161,
                187, 87, 37, 212, 0, 180, 198, 182, 53, 194, 21, 88, 152, 119, 207, 237, 195, 90,
                9, 200, 63, 0, 4, 180, 157, 149, 50, 13, 144, 33, 153, 76, 133, 15, 37, 184, 227,
                133, 162, 89, 119, 34, 17, 36, 96, 55, 65, 56, 67, 180, 116, 208, 29, 129, 93, 170,
                12, 95, 104, 45, 101, 136, 133, 233, 174, 110, 20, 254, 87, 165, 5, 1, 64, 234, 3,
                0, 0, 208, 7, 0, 0, 209, 7, 0, 0, 215, 7, 0, 0, 231, 7, 0, 0, 0, 8, 0, 0, 36, 8, 0,
                0, 37, 8, 0, 0, 39, 8, 0, 0, 42, 8, 0, 0, 44, 8, 0, 0, 62, 8, 0, 0, 73, 8, 0, 0,
                75, 8, 0, 0, 76, 8, 0, 0, 77, 8, 0, 0, 180, 86, 255, 111, 125, 70, 123, 135, 169,
                232, 3, 0, 0, 128, 219, 10, 131, 230, 56, 122, 129, 211, 80, 123, 155, 53, 216, 39,
                58, 194, 18, 17, 30, 231, 17, 210, 11, 206, 79, 177, 111, 226, 103, 216, 183, 15,
                196, 94, 65, 76, 176, 8, 224, 230, 30, 70, 114, 42, 166, 10, 189, 214, 114, 128,
                33, 241, 183, 89, 20, 103, 186, 98, 8, 119, 1, 11, 225, 217, 154, 29, 152, 198, 15,
                79, 41, 78, 47, 52, 60, 22, 92, 162, 158, 255, 42, 61, 196, 94, 230, 120, 121, 157,
                62, 255, 2, 66, 83, 185, 14, 132, 146, 124, 198, 128, 29, 182, 208, 142, 77, 250,
                108, 18, 67, 91, 75, 235, 139, 100, 111, 228, 73, 113, 213, 240, 173, 79, 81, 197,
                219, 218, 131, 93, 165, 176, 105, 39, 21, 1, 128, 0, 20, 128, 39, 144, 14, 91, 130,
                157, 91, 18, 149, 77, 162, 20, 175, 75, 15, 2, 103, 162, 202, 5, 51, 232, 112, 49,
                106, 48, 198, 76, 24, 101, 250, 12, 128, 164, 21, 237, 225, 206, 155, 246, 215,
                186, 11, 95, 28, 134, 173, 249, 51, 229, 224, 164, 189, 49, 249, 124, 12, 223, 1,
                146, 240, 92, 221, 239, 113, 224, 128, 0, 96, 128, 105, 62, 182, 93, 212, 141, 152,
                21, 65, 79, 191, 208, 169, 217, 153, 194, 14, 178, 54, 67, 134, 194, 134, 236, 204,
                134, 126, 69, 138, 20, 244, 100, 76, 94, 123, 144, 18, 9, 107, 65, 196, 235, 58,
                175, 148, 127, 110, 164, 41, 8, 0, 0, 21, 1, 128, 0, 132, 128, 186, 28, 192, 80,
                77, 249, 201, 163, 76, 229, 59, 170, 235, 88, 253, 158, 76, 183, 44, 79, 42, 245,
                24, 171, 191, 194, 37, 247, 74, 131, 62, 39, 128, 38, 101, 17, 82, 38, 152, 50,
                145, 67, 133, 153, 206, 179, 121, 103, 196, 42, 148, 118, 220, 86, 37, 152, 249,
                234, 27, 222, 242, 216, 51, 71, 71, 21, 1, 128, 1, 16, 128, 9, 58, 62, 213, 97, 13,
                210, 5, 10, 1, 165, 252, 5, 204, 60, 117, 216, 243, 136, 184, 223, 7, 134, 241,
                133, 146, 117, 16, 5, 95, 183, 0, 128, 101, 36, 173, 199, 56, 96, 161, 163, 95,
                220, 100, 157, 157, 182, 37, 94, 27, 161, 52, 25, 64, 86, 82, 116, 143, 224, 39,
                42, 231, 195, 190, 79, 21, 1, 128, 1, 16, 128, 185, 102, 197, 105, 241, 189, 112,
                27, 231, 66, 119, 254, 113, 105, 78, 56, 229, 32, 28, 104, 56, 10, 237, 214, 234,
                173, 11, 30, 131, 188, 43, 45, 128, 14, 190, 101, 3, 105, 206, 14, 60, 232, 91, 34,
                129, 97, 129, 245, 152, 204, 110, 207, 122, 59, 34, 49, 67, 87, 171, 65, 129, 185,
                204, 184, 103, 29, 2, 128, 2, 164, 128, 98, 49, 33, 45, 166, 186, 168, 0, 68, 161,
                215, 32, 89, 183, 217, 234, 71, 168, 50, 213, 84, 112, 139, 72, 249, 95, 59, 26,
                232, 24, 64, 4, 128, 229, 86, 253, 119, 78, 183, 52, 147, 198, 35, 185, 41, 210,
                36, 27, 63, 108, 17, 166, 247, 52, 121, 74, 47, 16, 131, 52, 202, 254, 141, 221,
                220, 128, 22, 186, 70, 170, 190, 43, 216, 171, 16, 49, 164, 192, 177, 82, 101, 247,
                19, 85, 217, 105, 84, 82, 118, 199, 144, 102, 118, 173, 136, 81, 125, 139, 128, 70,
                201, 211, 160, 140, 52, 211, 15, 213, 5, 26, 103, 201, 243, 21, 51, 92, 70, 68,
                145, 195, 25, 230, 3, 183, 243, 1, 19, 56, 201, 201, 183, 21, 1, 128, 4, 1, 128,
                30, 34, 108, 150, 45, 162, 139, 6, 57, 227, 175, 254, 55, 177, 176, 249, 226, 106,
                92, 179, 213, 225, 170, 235, 250, 213, 168, 232, 148, 41, 192, 81, 128, 7, 61, 47,
                252, 45, 92, 8, 66, 62, 190, 53, 127, 232, 118, 24, 47, 47, 248, 8, 85, 162, 14,
                126, 143, 35, 118, 191, 225, 171, 221, 246, 179, 21, 1, 128, 4, 4, 128, 142, 128,
                246, 15, 223, 166, 228, 216, 107, 254, 221, 146, 163, 131, 211, 62, 96, 95, 230,
                88, 238, 131, 214, 214, 169, 50, 60, 58, 12, 107, 219, 172, 128, 225, 175, 18, 233,
                5, 78, 91, 57, 216, 56, 102, 193, 238, 3, 183, 243, 194, 4, 26, 103, 158, 111, 39,
                70, 63, 105, 38, 60, 9, 236, 120, 207, 21, 1, 128, 4, 4, 128, 239, 131, 105, 71,
                108, 244, 223, 172, 186, 162, 76, 205, 59, 208, 148, 69, 59, 135, 111, 98, 67, 89,
                72, 42, 25, 149, 35, 156, 167, 12, 196, 246, 128, 15, 230, 176, 54, 57, 255, 39,
                57, 228, 43, 38, 58, 100, 185, 116, 88, 187, 183, 176, 74, 127, 19, 167, 221, 16,
                183, 123, 165, 195, 211, 148, 14, 161, 2, 128, 4, 108, 128, 21, 183, 195, 164, 157,
                34, 208, 32, 48, 32, 81, 127, 117, 125, 42, 211, 19, 47, 197, 30, 224, 164, 228,
                177, 179, 174, 133, 85, 224, 125, 236, 233, 128, 5, 142, 100, 250, 63, 51, 102, 58,
                191, 73, 133, 86, 77, 157, 128, 254, 129, 194, 214, 209, 106, 128, 46, 128, 222,
                50, 176, 135, 228, 229, 132, 162, 128, 143, 131, 240, 216, 230, 57, 158, 159, 157,
                16, 195, 200, 155, 97, 78, 49, 136, 72, 223, 183, 236, 234, 216, 155, 19, 122, 177,
                254, 47, 169, 104, 249, 128, 226, 145, 161, 62, 29, 45, 111, 198, 215, 236, 45, 49,
                25, 57, 59, 121, 38, 26, 6, 27, 22, 229, 173, 82, 161, 54, 9, 202, 158, 222, 247,
                226, 128, 42, 117, 67, 138, 234, 238, 79, 46, 237, 81, 94, 211, 32, 107, 224, 128,
                220, 53, 107, 4, 226, 16, 2, 240, 1, 143, 223, 55, 152, 112, 209, 149, 21, 1, 128,
                8, 2, 128, 29, 121, 195, 67, 100, 133, 169, 193, 23, 58, 103, 159, 112, 135, 125,
                85, 28, 138, 132, 206, 254, 84, 237, 244, 224, 134, 126, 225, 23, 249, 79, 237,
                128, 212, 250, 24, 77, 173, 122, 60, 124, 68, 61, 71, 140, 224, 170, 88, 175, 195,
                236, 38, 77, 58, 174, 0, 148, 60, 173, 114, 195, 74, 50, 180, 167, 220, 128, 8, 32,
                128, 200, 225, 19, 175, 65, 108, 15, 91, 245, 96, 57, 186, 231, 154, 252, 226, 196,
                5, 155, 114, 52, 31, 231, 84, 121, 155, 23, 74, 248, 214, 82, 116, 72, 94, 173,
                110, 239, 92, 75, 28, 104, 234, 167, 30, 161, 122, 2, 217, 222, 4, 0, 169, 3, 128,
                16, 111, 128, 252, 169, 111, 124, 210, 127, 239, 85, 108, 211, 97, 190, 230, 150,
                83, 36, 52, 212, 130, 9, 52, 165, 124, 50, 156, 77, 146, 123, 135, 78, 155, 159,
                128, 118, 54, 94, 247, 229, 189, 13, 15, 66, 244, 152, 205, 98, 163, 106, 210, 119,
                57, 195, 199, 65, 20, 58, 91, 113, 3, 154, 101, 169, 13, 143, 162, 128, 214, 151,
                110, 179, 39, 134, 150, 44, 245, 7, 7, 163, 71, 16, 4, 238, 209, 116, 28, 232, 102,
                201, 224, 234, 253, 152, 61, 96, 197, 221, 220, 20, 128, 140, 66, 249, 51, 155, 64,
                204, 197, 179, 224, 185, 94, 186, 231, 71, 62, 142, 174, 235, 110, 29, 84, 40, 72,
                123, 153, 8, 24, 239, 144, 162, 78, 128, 73, 76, 35, 3, 224, 104, 245, 170, 22,
                101, 89, 66, 102, 79, 38, 6, 247, 133, 195, 101, 94, 35, 142, 133, 0, 230, 216,
                151, 86, 173, 99, 67, 128, 118, 54, 246, 80, 237, 77, 64, 77, 122, 173, 9, 245,
                249, 209, 190, 30, 99, 124, 94, 145, 109, 5, 97, 24, 91, 16, 222, 118, 211, 218,
                182, 217, 128, 6, 224, 127, 165, 31, 198, 32, 42, 219, 23, 52, 38, 217, 241, 132,
                138, 111, 113, 110, 213, 166, 200, 152, 80, 207, 152, 107, 61, 173, 237, 225, 153,
                21, 1, 128, 16, 128, 128, 162, 231, 121, 64, 38, 82, 125, 222, 190, 110, 59, 117,
                195, 119, 83, 156, 250, 10, 119, 79, 100, 94, 197, 124, 14, 241, 25, 122, 220, 76,
                252, 24, 128, 51, 159, 146, 11, 30, 85, 157, 28, 237, 161, 158, 225, 213, 51, 94,
                113, 58, 151, 167, 154, 68, 116, 242, 253, 88, 132, 190, 24, 251, 116, 73, 220, 37,
                3, 128, 17, 23, 128, 96, 131, 252, 204, 90, 217, 72, 158, 143, 255, 212, 105, 70,
                106, 66, 6, 167, 67, 216, 219, 188, 143, 179, 1, 5, 157, 170, 29, 25, 140, 134, 40,
                128, 119, 183, 177, 175, 64, 154, 137, 151, 98, 94, 167, 103, 216, 129, 255, 121,
                221, 60, 77, 27, 71, 46, 31, 10, 31, 163, 196, 196, 249, 99, 36, 207, 128, 224,
                139, 126, 218, 65, 159, 164, 1, 42, 240, 25, 148, 233, 39, 3, 211, 254, 4, 235,
                166, 148, 238, 235, 23, 229, 235, 231, 236, 211, 151, 194, 200, 128, 57, 25, 103,
                24, 47, 116, 198, 179, 179, 98, 130, 75, 44, 58, 64, 167, 148, 156, 192, 146, 160,
                107, 203, 191, 65, 122, 156, 135, 60, 193, 94, 164, 128, 71, 211, 6, 80, 41, 9,
                163, 31, 70, 240, 250, 101, 93, 235, 194, 234, 109, 190, 30, 223, 54, 102, 171,
                178, 160, 174, 163, 245, 145, 58, 120, 217, 128, 242, 161, 250, 223, 31, 70, 182,
                93, 93, 123, 37, 89, 54, 229, 112, 22, 127, 45, 89, 190, 236, 165, 93, 209, 44,
                217, 80, 179, 214, 114, 26, 7, 61, 6, 128, 30, 255, 128, 224, 239, 217, 114, 71,
                189, 38, 205, 232, 77, 47, 243, 106, 119, 93, 124, 72, 98, 64, 26, 160, 237, 23,
                247, 138, 150, 242, 69, 237, 162, 61, 73, 128, 85, 14, 91, 47, 193, 125, 95, 82,
                159, 51, 220, 40, 75, 106, 53, 82, 43, 99, 162, 99, 30, 170, 253, 7, 222, 43, 141,
                187, 117, 231, 60, 33, 128, 34, 60, 85, 159, 51, 19, 15, 5, 223, 58, 20, 80, 102,
                28, 97, 204, 30, 224, 41, 182, 59, 151, 149, 137, 194, 218, 232, 103, 246, 165,
                180, 230, 128, 115, 80, 40, 68, 179, 87, 240, 30, 121, 226, 240, 56, 25, 35, 39,
                49, 88, 75, 47, 4, 19, 144, 183, 32, 80, 141, 53, 189, 126, 158, 125, 212, 128, 68,
                6, 170, 129, 41, 101, 157, 12, 50, 49, 193, 252, 191, 210, 178, 171, 84, 88, 139,
                33, 234, 79, 125, 194, 20, 236, 163, 196, 159, 116, 20, 190, 128, 4, 232, 86, 88,
                190, 112, 35, 31, 66, 74, 201, 162, 128, 160, 131, 141, 149, 161, 251, 104, 250,
                205, 109, 210, 123, 40, 140, 1, 142, 64, 156, 73, 128, 14, 233, 222, 123, 22, 122,
                67, 76, 65, 77, 43, 58, 130, 100, 116, 86, 236, 163, 177, 69, 87, 238, 190, 250,
                232, 14, 26, 208, 226, 0, 72, 238, 128, 147, 54, 250, 178, 243, 117, 250, 237, 22,
                11, 106, 54, 248, 77, 9, 200, 78, 37, 12, 233, 166, 61, 173, 208, 53, 9, 153, 173,
                12, 48, 97, 136, 128, 144, 148, 5, 12, 135, 74, 240, 239, 153, 47, 73, 203, 207,
                133, 52, 101, 108, 205, 165, 57, 26, 89, 35, 77, 51, 116, 47, 103, 9, 203, 97, 134,
                128, 167, 34, 193, 31, 251, 159, 112, 161, 80, 194, 93, 253, 88, 214, 109, 108,
                119, 6, 65, 19, 142, 92, 146, 77, 101, 40, 211, 219, 217, 176, 33, 53, 128, 172,
                106, 169, 168, 254, 215, 132, 77, 99, 193, 207, 252, 18, 140, 54, 193, 112, 253,
                151, 91, 61, 132, 171, 148, 99, 87, 244, 246, 230, 77, 175, 106, 128, 93, 51, 113,
                190, 163, 62, 159, 163, 215, 99, 161, 141, 180, 190, 141, 64, 1, 108, 54, 71, 9, 7,
                104, 183, 103, 118, 182, 26, 13, 145, 65, 206, 21, 1, 128, 32, 128, 128, 130, 69,
                110, 84, 222, 230, 123, 133, 142, 165, 48, 89, 187, 22, 14, 221, 110, 84, 51, 205,
                192, 182, 137, 64, 106, 110, 11, 142, 178, 117, 142, 25, 128, 40, 50, 31, 111, 100,
                67, 204, 173, 37, 95, 70, 243, 13, 235, 180, 148, 98, 195, 236, 80, 231, 152, 83,
                225, 52, 133, 43, 150, 50, 155, 134, 249, 21, 1, 128, 40, 0, 128, 133, 83, 204, 5,
                45, 33, 2, 133, 247, 41, 207, 179, 251, 114, 140, 80, 33, 235, 181, 161, 110, 15,
                95, 8, 29, 244, 229, 12, 124, 86, 31, 147, 128, 200, 118, 89, 49, 88, 144, 241, 1,
                68, 156, 8, 70, 184, 188, 125, 15, 172, 81, 209, 112, 120, 18, 196, 84, 228, 83,
                174, 48, 0, 115, 31, 196, 53, 5, 128, 47, 55, 128, 237, 207, 55, 149, 114, 218,
                173, 176, 15, 40, 210, 50, 101, 165, 249, 165, 195, 69, 172, 243, 153, 183, 239,
                225, 169, 33, 78, 58, 204, 166, 143, 166, 128, 210, 111, 156, 33, 81, 224, 97, 119,
                148, 198, 141, 111, 173, 223, 154, 194, 198, 151, 144, 58, 25, 25, 146, 196, 244,
                231, 114, 167, 71, 213, 23, 228, 128, 125, 241, 8, 196, 99, 144, 50, 249, 52, 210,
                98, 164, 54, 238, 35, 127, 38, 3, 168, 153, 233, 72, 21, 50, 52, 248, 83, 255, 52,
                108, 131, 21, 128, 188, 239, 224, 13, 82, 159, 47, 195, 72, 169, 35, 119, 81, 89,
                81, 35, 247, 32, 248, 117, 184, 53, 240, 134, 58, 243, 85, 186, 105, 243, 103, 74,
                128, 48, 1, 27, 193, 218, 82, 145, 217, 224, 12, 172, 72, 75, 51, 17, 94, 194, 217,
                14, 151, 207, 79, 184, 237, 194, 166, 240, 233, 79, 177, 135, 73, 128, 241, 221,
                177, 252, 135, 34, 158, 84, 213, 138, 204, 241, 232, 22, 130, 191, 153, 56, 5, 51,
                237, 136, 118, 28, 148, 160, 155, 88, 99, 47, 71, 40, 128, 112, 177, 196, 200, 98,
                128, 1, 143, 184, 202, 73, 39, 118, 94, 152, 39, 89, 96, 228, 167, 67, 84, 125, 85,
                124, 216, 46, 247, 170, 92, 26, 83, 128, 135, 182, 225, 255, 176, 147, 51, 226,
                120, 69, 225, 113, 197, 44, 216, 157, 237, 225, 167, 131, 129, 51, 136, 167, 29,
                37, 190, 1, 85, 29, 120, 43, 128, 88, 81, 223, 88, 223, 42, 110, 223, 90, 61, 50,
                123, 95, 10, 254, 207, 224, 31, 237, 93, 54, 207, 198, 199, 43, 126, 78, 151, 33,
                243, 248, 36, 128, 16, 247, 155, 152, 122, 193, 55, 210, 54, 96, 160, 186, 239,
                170, 169, 123, 61, 0, 218, 250, 128, 201, 98, 131, 195, 242, 54, 14, 190, 231, 122,
                199, 53, 5, 128, 62, 157, 128, 128, 122, 198, 51, 221, 186, 48, 79, 13, 100, 236,
                186, 1, 109, 202, 150, 98, 241, 73, 151, 95, 151, 99, 26, 84, 244, 206, 20, 145, 9,
                157, 222, 128, 47, 15, 222, 193, 146, 207, 255, 121, 51, 241, 15, 1, 133, 151, 161,
                174, 74, 215, 135, 52, 77, 196, 86, 144, 8, 69, 1, 196, 81, 2, 55, 71, 128, 210,
                229, 6, 246, 149, 226, 204, 26, 180, 51, 84, 208, 166, 36, 105, 147, 167, 242, 9,
                212, 226, 56, 50, 209, 76, 68, 223, 30, 101, 189, 60, 6, 128, 213, 113, 67, 240,
                104, 23, 42, 17, 111, 152, 22, 229, 22, 229, 161, 114, 214, 115, 146, 58, 55, 40,
                39, 156, 100, 227, 37, 94, 73, 24, 15, 94, 128, 197, 215, 11, 163, 128, 252, 185,
                201, 252, 122, 253, 88, 28, 25, 43, 82, 230, 210, 45, 98, 235, 87, 182, 169, 96,
                138, 121, 195, 195, 3, 14, 89, 128, 50, 225, 140, 159, 253, 248, 101, 93, 50, 218,
                228, 137, 251, 132, 158, 235, 88, 178, 99, 13, 63, 208, 149, 171, 142, 254, 225,
                21, 165, 109, 126, 35, 128, 60, 41, 28, 176, 215, 23, 15, 122, 128, 20, 153, 198,
                106, 169, 91, 42, 239, 143, 167, 67, 30, 172, 233, 132, 53, 105, 149, 123, 145,
                202, 215, 245, 128, 39, 133, 125, 161, 60, 179, 147, 160, 37, 73, 249, 84, 74, 217,
                140, 8, 191, 103, 192, 141, 148, 202, 147, 69, 116, 79, 134, 153, 127, 84, 160, 71,
                128, 35, 19, 156, 185, 233, 164, 137, 20, 250, 202, 96, 198, 38, 47, 73, 180, 147,
                98, 111, 247, 29, 186, 168, 187, 88, 90, 221, 175, 229, 137, 199, 33, 128, 133,
                113, 93, 46, 186, 86, 21, 236, 116, 64, 80, 151, 156, 74, 191, 207, 245, 0, 6, 6,
                101, 56, 75, 169, 223, 243, 248, 237, 200, 105, 15, 164, 21, 1, 128, 64, 1, 128, 0,
                31, 98, 163, 15, 241, 148, 153, 234, 178, 119, 229, 190, 185, 108, 218, 170, 110,
                144, 120, 228, 131, 57, 176, 225, 250, 217, 108, 168, 31, 125, 242, 128, 249, 46,
                148, 69, 46, 66, 42, 104, 200, 216, 85, 87, 137, 237, 63, 209, 60, 196, 49, 192,
                191, 38, 233, 191, 118, 82, 142, 216, 26, 156, 193, 64, 21, 1, 128, 64, 64, 128,
                134, 97, 196, 18, 225, 170, 23, 209, 68, 68, 119, 225, 112, 108, 194, 20, 17, 213,
                228, 182, 73, 212, 101, 214, 28, 71, 91, 75, 207, 162, 252, 51, 128, 65, 19, 116,
                95, 242, 10, 83, 205, 69, 198, 84, 50, 233, 159, 70, 30, 113, 57, 7, 143, 164, 240,
                158, 231, 244, 251, 120, 162, 235, 22, 188, 194, 21, 1, 128, 68, 1, 84, 86, 176,
                50, 73, 34, 37, 51, 123, 234, 3, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 84, 86, 255,
                111, 125, 70, 123, 135, 169, 232, 3, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 84, 86, 110,
                117, 7, 123, 35, 173, 36, 39, 8, 0, 0, 32, 6, 0, 0, 0, 137, 1, 0, 0, 153, 1, 128,
                73, 0, 128, 233, 188, 189, 178, 234, 66, 190, 60, 153, 30, 189, 4, 233, 104, 122,
                212, 43, 77, 251, 126, 150, 142, 191, 61, 193, 223, 110, 73, 181, 238, 14, 93, 128,
                185, 13, 158, 186, 83, 79, 165, 165, 31, 72, 171, 210, 38, 127, 50, 18, 114, 249,
                230, 155, 108, 59, 253, 194, 206, 37, 6, 216, 125, 27, 184, 41, 128, 184, 151, 8,
                214, 38, 239, 198, 156, 242, 160, 99, 152, 109, 58, 191, 120, 242, 71, 214, 165,
                196, 209, 129, 196, 113, 31, 82, 13, 98, 134, 117, 114, 141, 2, 128, 76, 131, 72,
                86, 176, 50, 73, 34, 37, 51, 123, 234, 3, 0, 0, 20, 4, 232, 3, 0, 0, 88, 86, 170,
                94, 34, 92, 48, 154, 56, 47, 8, 0, 0, 36, 8, 208, 7, 0, 0, 215, 7, 0, 0, 128, 99,
                103, 125, 158, 75, 246, 107, 144, 145, 198, 80, 239, 63, 192, 116, 157, 233, 130,
                116, 174, 228, 233, 124, 49, 123, 255, 11, 255, 11, 253, 237, 177, 128, 147, 38,
                36, 170, 3, 219, 57, 41, 170, 154, 70, 101, 148, 97, 56, 10, 78, 228, 73, 31, 80,
                54, 15, 63, 199, 161, 208, 72, 210, 244, 61, 84, 72, 86, 109, 19, 178, 194, 29, 82,
                235, 54, 8, 0, 0, 20, 4, 208, 7, 0, 0, 128, 122, 102, 162, 158, 29, 164, 92, 62,
                144, 29, 97, 68, 81, 73, 99, 210, 255, 196, 11, 153, 154, 75, 119, 11, 175, 64, 97,
                9, 211, 186, 101, 152, 169, 3, 128, 78, 131, 128, 110, 115, 126, 128, 243, 71, 32,
                198, 95, 48, 174, 155, 229, 56, 53, 58, 183, 179, 227, 139, 216, 12, 81, 234, 207,
                44, 238, 102, 197, 209, 1, 208, 128, 208, 168, 47, 69, 46, 74, 211, 132, 214, 176,
                83, 246, 172, 80, 233, 147, 133, 240, 29, 34, 155, 56, 83, 209, 207, 164, 199, 245,
                220, 226, 214, 222, 128, 11, 157, 19, 143, 50, 247, 148, 224, 15, 243, 73, 153, 2,
                196, 64, 26, 4, 54, 83, 240, 24, 94, 108, 55, 120, 101, 134, 66, 251, 140, 75, 74,
                128, 244, 210, 119, 200, 199, 64, 98, 131, 82, 250, 163, 192, 168, 115, 1, 157, 32,
                223, 177, 179, 70, 101, 175, 241, 12, 112, 183, 141, 45, 215, 177, 237, 128, 193,
                190, 173, 227, 220, 226, 149, 160, 42, 237, 100, 179, 133, 176, 218, 254, 52, 202,
                40, 149, 39, 112, 103, 202, 6, 130, 125, 148, 201, 172, 136, 105, 128, 55, 250,
                123, 249, 194, 102, 143, 199, 227, 224, 198, 183, 137, 26, 1, 32, 155, 111, 94, 43,
                18, 60, 232, 54, 161, 189, 243, 55, 82, 253, 61, 178, 128, 35, 11, 46, 39, 210,
                125, 54, 239, 129, 250, 241, 250, 219, 106, 127, 43, 233, 151, 235, 202, 69, 11,
                117, 225, 154, 30, 58, 215, 56, 225, 163, 8, 61, 6, 128, 79, 247, 128, 110, 72,
                222, 57, 57, 166, 76, 0, 123, 20, 217, 211, 99, 120, 187, 51, 76, 170, 148, 20,
                128, 44, 107, 96, 133, 131, 75, 39, 141, 226, 247, 228, 128, 135, 163, 143, 250,
                249, 11, 230, 192, 216, 160, 222, 84, 121, 145, 184, 8, 216, 20, 240, 64, 3, 67,
                252, 168, 69, 115, 176, 134, 187, 242, 83, 50, 128, 35, 97, 242, 87, 164, 192, 90,
                176, 249, 195, 90, 69, 119, 88, 98, 81, 97, 223, 4, 91, 213, 13, 57, 222, 33, 80,
                83, 83, 47, 63, 4, 218, 128, 77, 127, 112, 89, 14, 141, 56, 240, 135, 157, 140,
                218, 70, 61, 130, 167, 111, 107, 119, 1, 191, 43, 122, 64, 237, 163, 143, 169, 70,
                232, 166, 144, 128, 79, 27, 98, 187, 162, 185, 125, 241, 65, 212, 21, 178, 231, 59,
                139, 244, 164, 154, 238, 38, 25, 16, 18, 201, 91, 103, 240, 6, 192, 31, 183, 127,
                128, 52, 118, 216, 62, 104, 191, 32, 61, 212, 113, 154, 195, 184, 106, 195, 40,
                148, 56, 227, 44, 60, 4, 238, 188, 83, 49, 55, 122, 63, 41, 243, 73, 128, 159, 216,
                188, 248, 113, 154, 85, 212, 50, 27, 64, 97, 117, 111, 161, 78, 136, 238, 147, 212,
                146, 176, 12, 165, 198, 7, 106, 174, 77, 192, 233, 196, 128, 191, 37, 239, 196, 45,
                101, 231, 194, 150, 149, 223, 27, 130, 167, 29, 53, 127, 251, 178, 127, 73, 39,
                121, 80, 153, 61, 72, 197, 65, 71, 234, 97, 128, 238, 40, 205, 29, 44, 203, 83, 63,
                252, 5, 25, 248, 58, 27, 47, 234, 5, 233, 8, 182, 135, 8, 24, 194, 155, 203, 65,
                236, 97, 78, 223, 113, 128, 199, 137, 228, 102, 135, 141, 249, 7, 4, 233, 39, 181,
                208, 72, 5, 26, 195, 191, 11, 118, 231, 30, 123, 150, 186, 223, 4, 31, 131, 245,
                158, 167, 128, 99, 102, 62, 30, 131, 72, 196, 178, 124, 233, 119, 32, 38, 140, 119,
                15, 193, 156, 174, 233, 96, 145, 52, 56, 82, 19, 123, 6, 77, 196, 130, 133, 128,
                192, 71, 141, 90, 184, 112, 148, 175, 8, 254, 145, 129, 239, 41, 240, 54, 154, 70,
                64, 188, 250, 19, 103, 108, 201, 186, 234, 172, 134, 155, 112, 250, 169, 3, 128,
                92, 131, 128, 88, 125, 190, 183, 17, 254, 180, 127, 118, 50, 63, 198, 43, 156, 246,
                133, 250, 153, 101, 238, 23, 204, 64, 123, 7, 27, 61, 223, 135, 1, 162, 250, 128,
                145, 197, 244, 206, 108, 25, 176, 239, 66, 39, 129, 37, 57, 248, 146, 179, 2, 252,
                171, 16, 145, 170, 229, 41, 105, 62, 232, 137, 5, 207, 126, 5, 128, 228, 1, 116,
                153, 151, 104, 66, 66, 155, 130, 152, 68, 152, 105, 160, 161, 16, 242, 54, 206,
                189, 45, 83, 81, 139, 64, 81, 117, 34, 98, 187, 9, 128, 190, 197, 105, 170, 91,
                205, 186, 171, 44, 185, 44, 122, 135, 154, 169, 46, 83, 36, 23, 36, 137, 93, 129,
                158, 103, 10, 146, 34, 232, 176, 188, 3, 128, 74, 14, 87, 204, 19, 105, 84, 56, 63,
                16, 23, 48, 78, 153, 226, 236, 33, 115, 115, 219, 232, 182, 157, 235, 127, 27, 183,
                187, 168, 160, 21, 217, 128, 213, 10, 157, 170, 102, 230, 227, 250, 251, 242, 182,
                84, 92, 79, 143, 122, 14, 6, 125, 216, 242, 223, 48, 153, 181, 116, 9, 83, 229, 27,
                162, 47, 128, 246, 255, 41, 225, 153, 210, 213, 120, 188, 22, 40, 219, 31, 243, 76,
                123, 114, 58, 216, 167, 193, 118, 64, 3, 206, 168, 143, 182, 112, 161, 1, 62, 153,
                1, 128, 97, 0, 128, 63, 64, 243, 32, 167, 212, 79, 208, 87, 141, 203, 191, 166,
                145, 121, 200, 153, 94, 216, 129, 218, 188, 74, 30, 226, 20, 148, 249, 139, 18,
                238, 204, 128, 222, 200, 175, 110, 67, 106, 221, 141, 63, 76, 8, 232, 97, 136, 82,
                210, 141, 30, 185, 179, 246, 254, 136, 132, 98, 182, 245, 27, 31, 151, 5, 129, 128,
                12, 113, 218, 42, 183, 196, 72, 154, 247, 125, 54, 106, 241, 208, 223, 167, 227,
                147, 65, 147, 239, 145, 221, 25, 53, 174, 62, 3, 204, 176, 247, 251, 169, 3, 128,
                117, 136, 128, 84, 101, 94, 182, 132, 212, 23, 178, 207, 157, 178, 96, 187, 96, 28,
                189, 74, 94, 123, 43, 156, 159, 18, 185, 189, 153, 241, 24, 217, 81, 153, 21, 128,
                218, 21, 64, 95, 185, 99, 133, 159, 156, 182, 201, 221, 109, 107, 149, 229, 31,
                149, 219, 170, 149, 152, 91, 0, 7, 82, 19, 20, 5, 144, 122, 95, 128, 194, 102, 200,
                251, 124, 176, 138, 225, 34, 42, 78, 39, 138, 150, 90, 16, 97, 0, 119, 26, 88, 253,
                51, 98, 45, 191, 41, 161, 29, 72, 226, 7, 128, 76, 177, 103, 143, 3, 93, 250, 219,
                166, 99, 252, 165, 237, 148, 217, 127, 30, 198, 149, 36, 157, 4, 239, 142, 253,
                105, 235, 1, 2, 64, 133, 191, 128, 57, 206, 238, 180, 9, 57, 140, 173, 104, 92,
                100, 52, 175, 204, 219, 22, 12, 185, 104, 67, 136, 252, 241, 117, 109, 39, 162,
                173, 208, 70, 171, 70, 128, 16, 135, 86, 205, 3, 94, 4, 214, 251, 237, 128, 95, 11,
                197, 106, 130, 142, 22, 62, 99, 133, 187, 215, 145, 120, 130, 154, 250, 24, 10,
                210, 156, 128, 17, 59, 203, 31, 110, 114, 166, 116, 225, 184, 32, 75, 28, 157, 19,
                198, 240, 2, 129, 8, 208, 129, 36, 42, 156, 142, 161, 74, 2, 91, 26, 91, 177, 4,
                128, 127, 3, 128, 207, 181, 9, 54, 184, 244, 210, 220, 98, 100, 250, 186, 23, 86,
                143, 176, 212, 100, 128, 166, 31, 28, 117, 179, 93, 76, 132, 237, 99, 103, 212, 17,
                128, 86, 88, 133, 12, 118, 200, 224, 212, 199, 139, 77, 123, 82, 44, 198, 255, 122,
                120, 60, 230, 141, 183, 44, 244, 154, 244, 203, 47, 179, 17, 142, 188, 128, 122,
                146, 113, 132, 231, 235, 74, 146, 253, 49, 97, 245, 189, 115, 97, 71, 33, 179, 49,
                77, 186, 210, 245, 84, 51, 137, 52, 204, 30, 120, 220, 86, 128, 203, 16, 76, 162,
                26, 173, 176, 110, 166, 23, 166, 9, 102, 235, 244, 12, 67, 18, 154, 61, 6, 107, 30,
                166, 225, 124, 90, 123, 105, 198, 233, 22, 128, 214, 36, 25, 11, 216, 181, 93, 240,
                1, 130, 147, 137, 211, 153, 192, 113, 107, 187, 239, 163, 189, 201, 126, 149, 120,
                134, 35, 148, 175, 219, 173, 161, 128, 190, 247, 23, 190, 177, 146, 35, 141, 100,
                128, 102, 197, 160, 97, 56, 149, 91, 167, 109, 125, 149, 162, 15, 30, 2, 130, 124,
                239, 49, 158, 131, 152, 128, 218, 104, 4, 83, 232, 255, 204, 138, 243, 84, 109,
                249, 83, 248, 255, 84, 8, 180, 141, 7, 17, 47, 174, 46, 94, 4, 23, 60, 132, 15, 22,
                125, 128, 18, 163, 43, 202, 192, 74, 238, 33, 157, 22, 248, 162, 41, 233, 28, 235,
                139, 111, 202, 73, 203, 238, 18, 152, 150, 155, 167, 128, 182, 127, 19, 80, 128,
                10, 242, 182, 70, 219, 195, 62, 249, 143, 251, 36, 78, 116, 122, 8, 48, 112, 120,
                180, 106, 174, 79, 169, 202, 26, 7, 109, 218, 184, 122, 139, 137, 193, 6, 128, 127,
                221, 128, 27, 202, 207, 198, 230, 72, 2, 38, 173, 154, 239, 111, 208, 86, 200, 0,
                25, 154, 223, 131, 217, 90, 53, 175, 29, 11, 220, 189, 240, 58, 69, 179, 128, 89,
                200, 56, 161, 56, 38, 134, 86, 42, 29, 144, 117, 7, 29, 168, 82, 87, 55, 57, 250,
                159, 215, 16, 231, 168, 36, 177, 239, 210, 32, 227, 142, 128, 122, 245, 12, 2, 173,
                235, 38, 135, 112, 201, 94, 90, 128, 237, 105, 94, 254, 148, 133, 161, 42, 246,
                182, 255, 249, 232, 54, 52, 100, 125, 32, 181, 128, 89, 244, 0, 155, 27, 66, 193,
                146, 83, 68, 40, 118, 201, 128, 74, 209, 116, 162, 241, 237, 122, 213, 101, 0, 119,
                4, 74, 249, 165, 53, 61, 97, 128, 26, 91, 236, 132, 54, 200, 118, 34, 45, 153, 180,
                162, 26, 184, 165, 84, 253, 169, 43, 228, 149, 169, 250, 133, 45, 140, 100, 195,
                81, 131, 182, 229, 128, 245, 0, 224, 204, 156, 4, 163, 58, 175, 50, 117, 21, 47,
                176, 142, 139, 31, 116, 111, 244, 38, 1, 203, 230, 63, 96, 46, 86, 77, 171, 28, 22,
                128, 248, 4, 19, 26, 191, 122, 32, 139, 120, 170, 234, 204, 76, 212, 1, 107, 219,
                82, 153, 15, 16, 196, 133, 143, 35, 30, 37, 73, 145, 89, 12, 193, 128, 80, 216,
                254, 63, 116, 250, 216, 29, 247, 110, 200, 133, 27, 169, 197, 13, 79, 57, 178, 99,
                183, 185, 231, 4, 22, 42, 65, 111, 61, 144, 127, 229, 128, 108, 63, 154, 245, 121,
                215, 71, 112, 103, 193, 206, 246, 36, 97, 45, 41, 5, 124, 239, 58, 21, 47, 76, 103,
                224, 209, 16, 64, 84, 4, 251, 247, 128, 78, 136, 92, 34, 160, 37, 152, 191, 98,
                237, 32, 213, 38, 212, 25, 39, 192, 81, 96, 201, 5, 211, 231, 202, 73, 169, 78,
                208, 229, 125, 184, 142, 128, 2, 138, 187, 57, 144, 148, 167, 191, 49, 220, 130,
                10, 156, 251, 179, 142, 79, 149, 229, 86, 242, 156, 62, 72, 26, 40, 103, 16, 89,
                62, 234, 175, 128, 58, 2, 12, 227, 254, 93, 208, 176, 215, 94, 98, 113, 206, 156,
                42, 81, 205, 178, 46, 55, 218, 23, 51, 221, 178, 82, 232, 240, 32, 150, 191, 52,
                128, 142, 38, 228, 88, 187, 244, 156, 85, 26, 227, 56, 145, 64, 175, 223, 23, 182,
                199, 117, 195, 189, 62, 123, 202, 22, 221, 23, 56, 210, 4, 112, 128, 21, 1, 128,
                128, 8, 128, 114, 48, 169, 34, 134, 225, 186, 235, 158, 65, 12, 208, 240, 49, 241,
                59, 250, 236, 56, 33, 227, 117, 255, 242, 226, 38, 143, 23, 11, 141, 119, 94, 128,
                25, 119, 236, 15, 164, 142, 196, 89, 189, 15, 91, 154, 146, 157, 225, 212, 207,
                173, 185, 52, 75, 179, 24, 217, 234, 189, 14, 109, 66, 205, 82, 73, 105, 1, 128,
                128, 23, 52, 70, 7, 0, 0, 32, 170, 170, 10, 0, 0, 0, 64, 0, 120, 129, 0, 136, 0,
                48, 68, 0, 0, 32, 170, 170, 10, 0, 0, 0, 64, 0, 48, 68, 0, 0, 32, 170, 170, 10, 0,
                0, 0, 64, 0, 52, 70, 3, 0, 0, 32, 170, 170, 10, 0, 0, 0, 64, 0, 52, 70, 3, 0, 0,
                32, 170, 170, 10, 0, 0, 0, 64, 0, 52, 70, 8, 0, 0, 32, 170, 170, 10, 0, 0, 0, 64,
                0, 29, 2, 128, 136, 20, 128, 234, 21, 24, 31, 100, 187, 95, 231, 71, 251, 19, 154,
                253, 110, 100, 124, 82, 131, 178, 104, 66, 4, 196, 248, 141, 177, 223, 76, 0, 228,
                83, 18, 128, 27, 84, 51, 50, 109, 153, 218, 23, 97, 32, 91, 76, 238, 92, 108, 233,
                75, 153, 216, 73, 202, 147, 57, 91, 187, 21, 214, 194, 17, 250, 227, 230, 128, 32,
                214, 25, 226, 238, 153, 149, 25, 43, 174, 172, 178, 106, 150, 203, 125, 206, 251,
                91, 99, 210, 241, 85, 42, 66, 237, 6, 61, 193, 189, 151, 186, 128, 46, 207, 255,
                17, 19, 214, 251, 229, 90, 118, 82, 55, 220, 135, 239, 251, 41, 49, 118, 150, 182,
                47, 237, 57, 199, 99, 8, 107, 98, 123, 161, 74, 29, 2, 128, 145, 8, 128, 133, 145,
                69, 57, 53, 129, 208, 112, 245, 77, 50, 20, 193, 123, 114, 100, 204, 180, 137, 40,
                212, 5, 154, 14, 80, 36, 226, 11, 44, 101, 2, 219, 128, 193, 173, 73, 151, 65, 122,
                210, 28, 205, 53, 92, 139, 68, 109, 143, 34, 182, 177, 220, 175, 95, 237, 79, 227,
                205, 65, 188, 1, 202, 73, 219, 218, 128, 89, 156, 75, 125, 242, 28, 164, 49, 134,
                244, 162, 10, 127, 109, 171, 142, 239, 1, 207, 77, 150, 90, 136, 247, 227, 103,
                216, 26, 7, 44, 60, 228, 128, 134, 48, 96, 77, 49, 141, 153, 196, 222, 130, 77, 59,
                42, 18, 209, 253, 84, 166, 103, 127, 250, 109, 118, 98, 39, 226, 242, 150, 251, 40,
                164, 11, 53, 5, 128, 166, 243, 128, 21, 126, 43, 160, 126, 125, 205, 88, 105, 228,
                197, 32, 25, 88, 75, 11, 101, 147, 244, 122, 19, 181, 117, 192, 239, 107, 11, 194,
                238, 40, 164, 158, 128, 189, 63, 199, 104, 252, 239, 108, 216, 134, 109, 31, 244,
                155, 141, 23, 100, 59, 234, 2, 38, 117, 124, 220, 5, 84, 239, 56, 41, 114, 76, 220,
                101, 128, 99, 69, 152, 115, 12, 134, 76, 232, 82, 91, 83, 215, 16, 149, 38, 7, 145,
                26, 90, 225, 2, 47, 174, 213, 174, 14, 145, 65, 165, 202, 80, 181, 128, 15, 215,
                126, 220, 79, 106, 33, 145, 47, 149, 163, 39, 112, 117, 237, 243, 63, 129, 12, 24,
                0, 54, 65, 160, 22, 8, 227, 184, 139, 96, 245, 118, 128, 107, 32, 171, 215, 127,
                143, 187, 141, 115, 124, 79, 180, 191, 105, 14, 64, 212, 44, 22, 11, 231, 135, 97,
                141, 115, 93, 124, 209, 115, 18, 208, 73, 128, 116, 154, 99, 151, 231, 95, 142,
                228, 149, 59, 128, 92, 181, 121, 228, 237, 139, 48, 146, 202, 18, 247, 65, 221,
                161, 244, 136, 177, 31, 215, 244, 208, 128, 164, 145, 139, 147, 221, 136, 254, 41,
                246, 210, 96, 27, 184, 86, 175, 62, 132, 34, 32, 105, 137, 226, 6, 143, 31, 249,
                77, 240, 150, 109, 174, 131, 128, 182, 248, 228, 24, 92, 247, 224, 76, 84, 43, 160,
                31, 74, 180, 110, 223, 245, 74, 152, 0, 120, 195, 27, 63, 74, 242, 95, 121, 63,
                108, 32, 82, 128, 246, 130, 222, 70, 161, 135, 213, 246, 151, 152, 58, 44, 100, 78,
                150, 136, 157, 185, 31, 208, 3, 51, 127, 27, 240, 166, 51, 228, 250, 169, 144, 73,
                128, 200, 187, 251, 234, 132, 23, 208, 208, 84, 217, 123, 33, 92, 105, 114, 132,
                178, 124, 50, 65, 11, 214, 7, 177, 241, 51, 76, 150, 6, 102, 62, 134, 21, 1, 128,
                192, 0, 128, 131, 153, 94, 1, 103, 222, 119, 172, 133, 120, 175, 151, 150, 17, 22,
                54, 199, 229, 129, 31, 54, 222, 74, 1, 148, 94, 38, 18, 201, 214, 22, 113, 128, 21,
                94, 86, 90, 231, 243, 234, 147, 32, 123, 63, 204, 187, 51, 133, 73, 99, 164, 187,
                230, 22, 178, 252, 19, 75, 3, 66, 87, 226, 197, 81, 41, 161, 2, 128, 192, 137, 128,
                232, 170, 107, 212, 154, 43, 246, 160, 246, 42, 233, 97, 13, 78, 77, 72, 178, 201,
                224, 233, 249, 199, 32, 42, 180, 80, 56, 65, 55, 199, 12, 211, 128, 224, 87, 83,
                135, 21, 244, 39, 18, 36, 169, 72, 210, 115, 211, 106, 42, 160, 174, 193, 118, 90,
                116, 124, 46, 191, 89, 13, 54, 87, 121, 109, 157, 128, 228, 82, 11, 80, 231, 244,
                99, 162, 152, 108, 136, 47, 200, 194, 140, 94, 3, 75, 221, 134, 177, 11, 208, 104,
                137, 124, 105, 17, 58, 75, 74, 132, 128, 198, 39, 157, 12, 171, 61, 71, 228, 113,
                25, 145, 88, 18, 2, 77, 229, 50, 61, 188, 135, 114, 200, 211, 21, 84, 130, 15, 80,
                50, 214, 213, 22, 128, 154, 149, 239, 96, 134, 200, 120, 103, 76, 161, 98, 4, 132,
                239, 81, 118, 82, 246, 177, 177, 223, 183, 126, 143, 69, 160, 86, 135, 11, 45, 223,
                10, 45, 4, 128, 195, 156, 128, 91, 206, 1, 221, 144, 91, 146, 239, 62, 144, 7, 194,
                86, 158, 84, 189, 69, 123, 48, 236, 94, 255, 52, 51, 78, 31, 163, 137, 92, 53, 26,
                232, 128, 67, 166, 163, 235, 81, 160, 192, 95, 65, 87, 97, 46, 187, 146, 0, 177,
                248, 191, 214, 39, 108, 113, 21, 246, 201, 220, 216, 146, 252, 121, 119, 170, 128,
                34, 157, 88, 166, 119, 216, 68, 88, 5, 196, 60, 209, 191, 63, 113, 166, 233, 209,
                189, 39, 13, 187, 69, 254, 247, 230, 244, 97, 252, 2, 66, 43, 128, 120, 127, 221,
                117, 255, 196, 139, 3, 177, 158, 195, 185, 35, 246, 0, 179, 201, 1, 14, 200, 190,
                59, 211, 99, 121, 75, 172, 168, 120, 208, 221, 227, 128, 91, 188, 126, 217, 191,
                148, 220, 250, 57, 138, 205, 64, 183, 142, 62, 52, 2, 91, 72, 154, 158, 247, 178,
                91, 25, 96, 37, 204, 207, 237, 140, 158, 128, 9, 98, 51, 137, 27, 25, 65, 249, 74,
                68, 138, 199, 122, 180, 179, 12, 135, 144, 146, 252, 10, 98, 200, 0, 172, 62, 221,
                161, 138, 178, 203, 34, 128, 197, 74, 235, 82, 103, 244, 94, 93, 22, 130, 214, 133,
                235, 139, 46, 128, 198, 199, 73, 69, 65, 51, 13, 11, 125, 83, 218, 243, 40, 104,
                163, 76, 128, 106, 199, 171, 70, 60, 21, 5, 165, 236, 63, 91, 185, 18, 84, 178,
                146, 70, 125, 213, 147, 206, 34, 46, 21, 26, 251, 126, 93, 0, 19, 101, 76, 161, 2,
                128, 220, 0, 128, 148, 55, 130, 172, 73, 122, 31, 218, 97, 4, 177, 237, 180, 63,
                235, 206, 165, 106, 247, 14, 38, 41, 139, 66, 142, 130, 90, 203, 107, 181, 208,
                151, 128, 188, 207, 83, 62, 14, 128, 169, 87, 187, 41, 242, 150, 93, 220, 72, 101,
                230, 31, 45, 106, 144, 149, 225, 126, 243, 52, 254, 101, 141, 114, 26, 74, 128,
                182, 4, 240, 217, 196, 20, 63, 210, 63, 107, 159, 124, 47, 130, 184, 252, 193, 153,
                215, 95, 207, 242, 134, 180, 38, 244, 103, 185, 200, 58, 112, 29, 128, 102, 114,
                227, 186, 190, 25, 167, 44, 72, 48, 232, 102, 171, 153, 98, 134, 127, 158, 86, 125,
                35, 236, 119, 195, 194, 197, 213, 43, 92, 210, 41, 34, 128, 4, 212, 195, 198, 159,
                208, 222, 57, 1, 254, 64, 98, 239, 148, 178, 231, 233, 158, 137, 173, 96, 60, 134,
                228, 83, 24, 36, 0, 153, 71, 39, 43, 185, 5, 128, 230, 119, 128, 101, 195, 92, 254,
                39, 167, 70, 226, 25, 48, 175, 65, 60, 166, 33, 103, 51, 27, 5, 236, 212, 220, 154,
                214, 22, 131, 185, 50, 230, 213, 42, 179, 128, 162, 102, 167, 81, 157, 208, 164,
                247, 107, 239, 252, 16, 72, 144, 76, 153, 137, 222, 185, 74, 144, 216, 242, 12, 17,
                39, 251, 171, 109, 196, 209, 249, 128, 151, 103, 157, 240, 71, 137, 234, 197, 153,
                137, 178, 66, 75, 180, 226, 175, 101, 12, 92, 128, 157, 0, 152, 221, 178, 218, 132,
                76, 195, 59, 248, 118, 128, 169, 233, 221, 114, 77, 213, 3, 223, 95, 44, 41, 224,
                30, 7, 70, 151, 212, 160, 237, 139, 102, 176, 19, 186, 19, 94, 86, 26, 57, 138,
                158, 52, 128, 103, 54, 85, 37, 174, 122, 105, 162, 107, 124, 188, 122, 215, 38, 82,
                77, 53, 70, 250, 237, 199, 78, 204, 139, 214, 212, 11, 131, 31, 246, 200, 99, 128,
                141, 94, 22, 106, 210, 251, 174, 187, 143, 165, 218, 180, 147, 133, 234, 74, 200,
                99, 229, 252, 149, 165, 195, 199, 234, 161, 6, 113, 81, 56, 227, 45, 128, 29, 178,
                129, 32, 10, 186, 203, 184, 188, 6, 183, 32, 121, 233, 33, 112, 78, 112, 127, 48,
                148, 193, 150, 121, 179, 99, 215, 156, 151, 139, 141, 145, 128, 114, 94, 183, 175,
                148, 171, 242, 89, 167, 215, 218, 223, 239, 252, 253, 218, 157, 126, 198, 216, 63,
                161, 5, 226, 107, 198, 213, 77, 105, 237, 60, 231, 128, 146, 36, 115, 27, 55, 237,
                145, 44, 183, 4, 33, 201, 99, 237, 209, 235, 51, 106, 32, 213, 60, 9, 57, 182, 163,
                245, 218, 234, 214, 107, 72, 242, 128, 162, 235, 64, 202, 177, 4, 47, 105, 143, 29,
                38, 120, 14, 67, 176, 125, 244, 10, 216, 118, 11, 93, 134, 224, 125, 142, 240, 233,
                108, 201, 224, 207, 128, 63, 198, 192, 19, 206, 71, 211, 171, 29, 74, 196, 95, 31,
                187, 133, 183, 47, 183, 176, 84, 169, 3, 42, 223, 149, 19, 233, 128, 83, 40, 252,
                149, 177, 4, 128, 234, 228, 128, 30, 192, 20, 87, 223, 121, 117, 244, 12, 227, 43,
                102, 15, 250, 107, 29, 11, 164, 34, 194, 100, 22, 251, 230, 189, 28, 194, 232, 239,
                208, 109, 179, 128, 245, 49, 114, 67, 254, 41, 251, 194, 12, 135, 47, 129, 20, 234,
                214, 223, 181, 61, 49, 139, 82, 49, 250, 231, 213, 150, 67, 157, 196, 187, 136,
                118, 128, 194, 40, 244, 203, 244, 205, 138, 233, 198, 213, 95, 72, 209, 159, 238,
                126, 58, 56, 210, 147, 36, 99, 105, 52, 19, 143, 206, 177, 46, 227, 171, 125, 128,
                125, 52, 140, 94, 44, 150, 105, 198, 134, 67, 46, 16, 113, 105, 73, 216, 251, 21,
                84, 3, 144, 253, 155, 49, 140, 47, 54, 115, 90, 210, 18, 99, 128, 142, 79, 4, 216,
                6, 26, 125, 208, 110, 30, 57, 119, 142, 84, 7, 153, 213, 143, 132, 236, 80, 248,
                155, 52, 70, 47, 20, 100, 175, 110, 122, 182, 128, 14, 19, 178, 216, 105, 190, 191,
                175, 69, 45, 180, 143, 169, 26, 52, 215, 129, 11, 209, 254, 128, 143, 96, 96, 34,
                136, 66, 49, 61, 94, 37, 106, 128, 253, 12, 65, 64, 173, 144, 225, 238, 44, 180,
                157, 203, 71, 242, 142, 198, 73, 88, 85, 157, 189, 223, 217, 67, 145, 51, 136, 209,
                14, 131, 21, 183, 128, 1, 228, 69, 51, 15, 139, 33, 195, 6, 150, 124, 69, 163, 159,
                163, 217, 65, 94, 73, 99, 53, 26, 42, 116, 171, 217, 47, 83, 198, 75, 8, 210, 128,
                154, 20, 228, 242, 115, 4, 10, 154, 14, 146, 120, 127, 89, 0, 161, 117, 93, 251,
                212, 215, 200, 84, 147, 215, 4, 189, 35, 116, 105, 52, 226, 31, 61, 6, 128, 249,
                221, 128, 180, 85, 74, 252, 209, 157, 27, 180, 238, 3, 30, 76, 123, 36, 252, 208,
                206, 83, 184, 195, 81, 13, 46, 142, 251, 46, 24, 79, 164, 216, 122, 242, 128, 11,
                108, 238, 99, 155, 87, 3, 218, 158, 188, 173, 127, 101, 29, 16, 76, 82, 248, 56,
                98, 110, 247, 10, 64, 31, 171, 69, 166, 73, 247, 105, 55, 128, 147, 129, 191, 107,
                161, 132, 34, 44, 206, 215, 213, 223, 58, 65, 11, 206, 108, 25, 6, 216, 50, 69, 64,
                246, 161, 161, 135, 214, 136, 249, 79, 124, 128, 22, 202, 150, 185, 135, 85, 34,
                195, 57, 106, 179, 72, 74, 14, 194, 212, 173, 146, 143, 114, 63, 130, 210, 96, 204,
                198, 96, 170, 12, 98, 22, 238, 128, 28, 52, 38, 67, 57, 118, 69, 240, 231, 243, 50,
                189, 86, 169, 92, 46, 155, 251, 202, 130, 176, 3, 107, 32, 7, 222, 180, 209, 118,
                229, 116, 23, 128, 78, 218, 168, 114, 74, 158, 137, 46, 169, 173, 112, 36, 99, 71,
                116, 161, 41, 189, 188, 42, 214, 80, 115, 18, 78, 48, 230, 169, 8, 139, 245, 58,
                128, 189, 8, 116, 87, 219, 183, 63, 54, 25, 77, 96, 237, 94, 161, 119, 46, 64, 33,
                129, 125, 212, 1, 232, 127, 86, 76, 60, 41, 98, 159, 213, 234, 128, 148, 126, 164,
                165, 2, 122, 13, 215, 242, 8, 55, 234, 20, 129, 243, 30, 41, 84, 176, 34, 51, 44,
                190, 34, 16, 144, 186, 184, 166, 175, 218, 43, 128, 217, 86, 38, 63, 245, 2, 107,
                173, 167, 63, 196, 63, 106, 18, 224, 57, 210, 1, 80, 98, 99, 209, 225, 17, 194,
                186, 33, 227, 82, 215, 38, 227, 128, 23, 167, 5, 28, 95, 175, 89, 158, 228, 226,
                55, 133, 75, 142, 98, 105, 246, 154, 97, 107, 75, 109, 244, 117, 130, 13, 192, 89,
                133, 82, 33, 86, 128, 77, 176, 165, 88, 154, 196, 248, 147, 230, 51, 162, 162, 25,
                21, 10, 253, 96, 27, 199, 236, 128, 11, 254, 36, 130, 175, 48, 71, 175, 44, 99,
                254, 128, 21, 233, 211, 129, 106, 250, 141, 55, 14, 77, 44, 53, 154, 204, 233, 79,
                2, 249, 229, 227, 126, 67, 173, 64, 101, 44, 65, 223, 207, 244, 162, 168, 77, 8,
                128, 255, 255, 128, 255, 118, 170, 229, 83, 22, 64, 237, 172, 100, 35, 56, 139,
                238, 143, 61, 205, 215, 239, 27, 67, 96, 215, 3, 165, 31, 232, 216, 152, 225, 64,
                43, 128, 167, 136, 241, 115, 2, 128, 17, 236, 0, 253, 3, 41, 149, 31, 61, 136, 44,
                177, 91, 231, 167, 239, 179, 205, 53, 70, 255, 10, 249, 255, 39, 226, 128, 58, 22,
                172, 241, 130, 27, 64, 145, 25, 6, 130, 207, 165, 179, 133, 205, 152, 222, 86, 12,
                117, 54, 202, 10, 6, 44, 238, 132, 110, 14, 121, 149, 128, 40, 124, 213, 32, 210,
                230, 3, 164, 115, 137, 85, 145, 110, 7, 20, 255, 77, 37, 245, 126, 135, 122, 135,
                192, 62, 177, 217, 39, 188, 199, 186, 67, 128, 25, 87, 33, 113, 242, 130, 9, 27,
                90, 241, 90, 28, 219, 92, 177, 185, 57, 43, 68, 160, 2, 125, 68, 6, 52, 172, 25,
                86, 247, 180, 120, 237, 128, 222, 78, 240, 70, 19, 23, 177, 18, 221, 208, 146, 217,
                255, 207, 220, 10, 44, 135, 91, 164, 82, 88, 120, 208, 148, 204, 255, 249, 237,
                174, 185, 0, 128, 99, 120, 25, 105, 78, 116, 66, 208, 159, 241, 145, 207, 81, 158,
                6, 227, 18, 36, 164, 107, 182, 15, 18, 76, 111, 62, 31, 172, 207, 7, 61, 250, 128,
                84, 224, 106, 171, 118, 226, 77, 102, 191, 95, 180, 7, 212, 255, 213, 82, 222, 166,
                228, 182, 131, 242, 79, 32, 107, 165, 50, 133, 199, 128, 206, 131, 128, 158, 214,
                255, 19, 20, 17, 64, 1, 63, 38, 248, 57, 90, 199, 13, 49, 163, 43, 194, 21, 18, 89,
                133, 140, 10, 61, 244, 176, 45, 176, 240, 60, 128, 48, 213, 11, 228, 208, 79, 171,
                81, 48, 28, 111, 22, 128, 99, 191, 73, 198, 110, 53, 57, 252, 239, 38, 156, 95,
                167, 245, 155, 182, 214, 199, 74, 128, 144, 105, 144, 251, 167, 27, 20, 190, 249,
                250, 75, 198, 52, 125, 187, 215, 140, 10, 189, 206, 92, 58, 171, 114, 161, 110, 0,
                113, 235, 167, 36, 166, 128, 110, 83, 70, 17, 15, 10, 115, 95, 148, 208, 4, 113,
                172, 107, 65, 43, 100, 123, 114, 201, 204, 108, 186, 198, 248, 202, 189, 174, 10,
                81, 174, 149, 128, 231, 188, 123, 44, 107, 161, 10, 166, 138, 71, 163, 179, 24,
                201, 106, 11, 251, 84, 166, 95, 252, 10, 243, 173, 246, 221, 99, 248, 155, 166, 7,
                146, 128, 181, 234, 93, 109, 13, 71, 78, 181, 27, 27, 219, 117, 38, 212, 156, 15,
                132, 7, 224, 81, 168, 150, 23, 218, 71, 184, 124, 23, 209, 115, 49, 213, 128, 122,
                80, 119, 174, 137, 36, 36, 123, 244, 180, 235, 71, 24, 6, 253, 45, 87, 227, 51,
                125, 181, 34, 100, 96, 147, 4, 129, 250, 12, 165, 191, 24, 128, 206, 193, 11, 221,
                45, 101, 107, 193, 70, 96, 196, 168, 174, 64, 231, 107, 42, 210, 201, 237, 100, 49,
                71, 4, 111, 216, 222, 107, 135, 224, 169, 81, 153, 3, 145, 3, 162, 138, 86, 150,
                44, 139, 95, 167, 30, 228, 53, 164, 168, 224, 114, 19, 21, 191, 221, 102, 164, 103,
                241, 200, 115, 238, 239, 58, 174, 29, 89, 137, 254, 0, 98, 1, 59, 215, 12, 13, 239,
                25, 179, 210, 218, 45, 23, 154, 117, 64, 126, 173, 129, 59, 24, 57, 130, 111, 247,
                27, 70, 96, 208, 162, 101, 152, 38, 51, 142, 34, 26, 234, 50, 144, 93, 56, 207,
                226, 56, 145, 166, 252, 75, 215, 132, 55, 202, 178, 147, 90, 227, 157, 22, 243,
                121, 50, 214, 179, 184, 167, 12, 6, 97, 117, 114, 97, 32, 93, 197, 113, 8, 0, 0, 0,
                0, 4, 82, 80, 83, 82, 144, 75, 250, 140, 1, 140, 228, 232, 40, 215, 89, 136, 114,
                235, 90, 147, 241, 47, 215, 198, 210, 92, 196, 192, 0, 100, 222, 229, 179, 161, 43,
                112, 56, 10, 170, 231, 4, 5, 97, 117, 114, 97, 1, 1, 194, 46, 241, 223, 37, 26, 13,
                157, 119, 240, 86, 215, 13, 134, 172, 102, 246, 136, 29, 133, 40, 78, 57, 208, 150,
                43, 8, 118, 107, 9, 179, 47, 74, 146, 171, 225, 233, 152, 27, 110, 172, 92, 136,
                171, 71, 122, 191, 58, 157, 49, 95, 124, 16, 92, 34, 132, 167, 8, 238, 181, 98,
                150, 192, 130, 189, 2, 157, 0, 127, 3, 207, 220, 229, 134, 48, 16, 20, 112, 14, 44,
                37, 147, 209, 192, 128, 99, 130, 139, 212, 253, 194, 223, 190, 188, 45, 122, 119,
                27, 226, 20, 82, 45, 241, 81, 192, 56, 1, 226, 249, 192, 242, 243, 168, 232, 84,
                120, 81, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110,
                164, 41, 8, 1, 0, 104, 95, 13, 158, 243, 183, 138, 253, 218, 183, 245, 199, 20, 33,
                49, 19, 42, 212, 32, 207, 0, 0, 0, 0, 0, 0, 0, 88, 95, 2, 39, 95, 100, 195, 84,
                149, 67, 82, 183, 30, 234, 57, 207, 172, 162, 16, 207, 0, 0, 0, 76, 95, 14, 194,
                209, 122, 118, 21, 63, 245, 24, 23, 241, 45, 156, 252, 60, 127, 4, 0, 128, 210,
                112, 94, 214, 251, 66, 130, 230, 12, 155, 251, 60, 239, 181, 241, 193, 221, 103,
                67, 67, 139, 9, 136, 172, 94, 48, 76, 189, 199, 210, 103, 130, 65, 5, 157, 13, 160,
                92, 165, 153, 19, 188, 56, 168, 99, 5, 144, 242, 98, 124, 23, 221, 128, 235, 218,
                69, 149, 51, 230, 33, 211, 122, 83, 80, 36, 206, 81, 13, 38, 45, 225, 119, 62, 142,
                85, 217, 45, 165, 64, 27, 108, 212, 215, 99, 118, 128, 215, 160, 27, 76, 203, 39,
                127, 179, 185, 28, 239, 170, 10, 154, 42, 4, 61, 56, 185, 142, 235, 109, 25, 1, 47,
                212, 163, 112, 46, 243, 155, 160, 128, 223, 235, 36, 18, 78, 176, 46, 144, 13, 76,
                89, 236, 141, 232, 67, 120, 107, 119, 50, 232, 34, 158, 249, 180, 211, 86, 249,
                236, 108, 85, 218, 49, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175,
                148, 127, 110, 164, 41, 8, 0, 0, 128, 175, 27, 91, 41, 56, 123, 217, 235, 140, 40,
                154, 154, 131, 67, 14, 139, 197, 214, 184, 49, 29, 90, 126, 165, 192, 126, 25, 232,
                124, 194, 250, 214, 128, 202, 206, 27, 75, 192, 204, 77, 23, 16, 132, 253, 121,
                192, 36, 168, 220, 254, 176, 118, 161, 55, 152, 228, 130, 186, 2, 142, 227, 190,
                187, 36, 105, 128, 192, 179, 170, 134, 175, 231, 116, 99, 173, 194, 140, 108, 52,
                199, 26, 32, 14, 56, 136, 199, 37, 49, 68, 152, 69, 203, 27, 206, 111, 61, 139,
                228, 128, 181, 68, 170, 52, 178, 44, 140, 224, 101, 215, 226, 128, 212, 109, 10,
                247, 51, 254, 137, 7, 166, 201, 110, 184, 210, 114, 21, 107, 227, 126, 240, 184,
                128, 109, 170, 53, 136, 243, 42, 150, 87, 60, 116, 224, 215, 52, 68, 196, 100, 124,
                107, 210, 178, 113, 155, 11, 119, 22, 177, 29, 92, 142, 100, 77, 215, 128, 175, 40,
                224, 205, 230, 174, 216, 159, 254, 225, 44, 16, 114, 144, 188, 126, 189, 164, 180,
                199, 245, 46, 79, 156, 187, 174, 101, 19, 23, 215, 122, 222, 217, 4, 158, 113, 11,
                48, 189, 46, 171, 3, 82, 221, 204, 38, 65, 122, 161, 148, 95, 195, 128, 54, 12,
                152, 205, 41, 31, 105, 121, 83, 249, 212, 18, 255, 77, 10, 241, 133, 237, 25, 115,
                37, 151, 216, 231, 186, 183, 152, 39, 151, 90, 117, 176, 128, 228, 96, 161, 133,
                29, 55, 248, 183, 48, 239, 220, 221, 40, 33, 7, 101, 201, 211, 204, 85, 1, 57, 91,
                242, 41, 243, 224, 59, 182, 112, 25, 225, 128, 204, 80, 126, 60, 36, 231, 38, 92,
                39, 86, 213, 234, 91, 14, 178, 139, 215, 62, 83, 228, 109, 178, 146, 170, 185, 167,
                212, 87, 246, 138, 45, 107, 128, 73, 168, 238, 216, 159, 171, 151, 84, 227, 213,
                21, 93, 37, 214, 244, 3, 162, 0, 100, 139, 203, 229, 187, 176, 59, 227, 3, 13, 153,
                220, 223, 190, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127,
                110, 164, 41, 8, 0, 0, 76, 95, 3, 199, 22, 251, 143, 255, 61, 230, 26, 136, 59,
                183, 106, 219, 52, 162, 4, 0, 128, 79, 178, 157, 255, 221, 251, 231, 183, 195, 168,
                1, 228, 242, 43, 144, 78, 112, 207, 182, 129, 243, 116, 39, 6, 238, 0, 69, 165, 43,
                12, 177, 186, 76, 95, 15, 73, 147, 240, 22, 226, 210, 248, 229, 244, 59, 231, 187,
                37, 148, 134, 4, 0, 128, 70, 54, 90, 216, 167, 133, 150, 112, 51, 167, 114, 22,
                158, 185, 150, 66, 119, 69, 225, 19, 165, 184, 253, 41, 194, 213, 100, 182, 150,
                244, 1, 237, 128, 154, 129, 32, 100, 133, 127, 1, 135, 127, 54, 123, 4, 77, 41,
                133, 103, 244, 73, 44, 156, 224, 93, 187, 54, 182, 227, 156, 183, 90, 69, 211, 140,
                5, 8, 158, 127, 239, 196, 8, 170, 197, 157, 191, 232, 10, 114, 172, 142, 60, 229,
                251, 255, 128, 28, 144, 44, 190, 65, 158, 124, 234, 117, 177, 217, 113, 203, 191,
                145, 215, 51, 215, 17, 241, 52, 48, 113, 98, 225, 53, 156, 248, 93, 2, 151, 22,
                128, 246, 44, 225, 89, 41, 109, 48, 176, 151, 95, 167, 3, 200, 131, 53, 222, 234,
                250, 190, 60, 4, 127, 89, 243, 125, 238, 165, 212, 183, 77, 11, 209, 128, 108, 106,
                239, 252, 123, 178, 214, 53, 172, 161, 230, 103, 212, 45, 206, 237, 155, 51, 115,
                7, 202, 248, 65, 246, 67, 239, 177, 115, 205, 182, 160, 92, 128, 153, 49, 60, 253,
                8, 247, 69, 74, 78, 37, 77, 7, 70, 124, 114, 75, 142, 31, 138, 32, 252, 170, 184,
                231, 149, 235, 226, 10, 194, 239, 201, 139, 128, 163, 142, 44, 229, 147, 62, 192,
                83, 7, 252, 110, 17, 248, 37, 146, 214, 46, 130, 54, 218, 34, 167, 116, 105, 149,
                97, 133, 153, 192, 222, 20, 150, 128, 44, 212, 228, 232, 140, 23, 26, 9, 155, 125,
                236, 180, 181, 135, 7, 16, 254, 185, 55, 57, 35, 187, 112, 91, 60, 71, 243, 214,
                76, 69, 95, 49, 128, 36, 154, 200, 132, 247, 87, 96, 128, 121, 116, 94, 200, 68,
                172, 209, 130, 65, 30, 91, 188, 131, 189, 246, 112, 250, 110, 82, 23, 26, 22, 158,
                255, 128, 255, 55, 48, 36, 110, 69, 118, 46, 155, 67, 245, 213, 209, 82, 61, 122,
                87, 99, 232, 50, 134, 158, 207, 141, 13, 182, 55, 31, 245, 114, 138, 0, 128, 84,
                15, 134, 102, 153, 61, 75, 192, 41, 59, 118, 134, 14, 151, 178, 127, 253, 250, 164,
                236, 16, 186, 195, 72, 35, 244, 46, 79, 60, 79, 181, 250, 128, 125, 177, 42, 23,
                178, 140, 13, 11, 255, 231, 201, 197, 34, 202, 100, 42, 145, 237, 73, 158, 220,
                175, 49, 235, 152, 56, 239, 130, 163, 95, 118, 168, 128, 157, 153, 151, 253, 244,
                225, 184, 5, 16, 39, 191, 124, 108, 79, 221, 134, 216, 1, 190, 177, 204, 96, 197,
                60, 17, 134, 144, 72, 206, 47, 27, 77, 128, 120, 188, 171, 32, 209, 114, 55, 254,
                60, 149, 200, 80, 72, 100, 59, 142, 234, 198, 169, 179, 151, 76, 170, 7, 19, 226,
                8, 228, 21, 213, 186, 207, 128, 46, 3, 210, 197, 241, 213, 203, 87, 67, 242, 55,
                221, 56, 18, 59, 218, 83, 84, 234, 179, 181, 107, 31, 106, 69, 121, 253, 210, 144,
                106, 36, 186, 128, 74, 7, 238, 205, 130, 97, 184, 42, 47, 66, 224, 74, 129, 129,
                168, 176, 128, 42, 189, 32, 127, 1, 26, 215, 51, 193, 32, 167, 192, 142, 143, 12,
                128, 216, 70, 54, 152, 177, 220, 44, 147, 187, 142, 216, 215, 30, 8, 181, 223, 133,
                59, 216, 99, 111, 114, 83, 171, 112, 52, 2, 48, 199, 177, 66, 13, 125, 5, 158, 182,
                243, 110, 2, 122, 187, 32, 145, 207, 181, 17, 10, 181, 8, 127, 249, 110, 104, 95,
                6, 21, 91, 60, 217, 168, 201, 229, 233, 162, 63, 213, 220, 19, 165, 237, 32, 188,
                138, 227, 16, 0, 0, 0, 0, 104, 95, 8, 49, 108, 191, 143, 160, 218, 130, 42, 32,
                172, 28, 85, 191, 27, 227, 32, 196, 135, 0, 0, 0, 0, 0, 0, 80, 95, 14, 123, 144,
                18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0, 128, 234, 178,
                184, 124, 57, 146, 78, 36, 216, 223, 24, 129, 215, 19, 19, 190, 46, 219, 54, 192,
                222, 245, 96, 143, 196, 192, 128, 203, 127, 238, 98, 80, 128, 157, 63, 215, 146,
                117, 166, 140, 220, 174, 150, 5, 77, 118, 79, 113, 140, 216, 205, 207, 202, 255,
                186, 88, 88, 134, 71, 167, 53, 109, 154, 73, 120, 128, 63, 155, 5, 255, 94, 126,
                80, 205, 113, 90, 219, 210, 115, 53, 4, 152, 14, 225, 112, 21, 79, 129, 9, 131,
                181, 216, 150, 18, 36, 65, 21, 11, 128, 13, 73, 254, 240, 57, 81, 124, 195, 18,
                192, 4, 18, 128, 60, 161, 223, 80, 172, 109, 144, 197, 5, 65, 246, 73, 169, 200,
                91, 131, 192, 253, 216, 128, 2, 228, 22, 252, 234, 152, 215, 177, 232, 223, 73, 56,
                119, 185, 48, 114, 236, 202, 168, 96, 228, 42, 8, 26, 128, 215, 131, 30, 113, 167,
                70, 73, 128, 252, 251, 236, 40, 80, 81, 28, 11, 152, 150, 255, 68, 115, 104, 164,
                219, 25, 193, 89, 177, 30, 210, 59, 99, 197, 154, 142, 55, 84, 198, 138, 93, 128,
                105, 249, 88, 224, 100, 223, 75, 194, 147, 154, 226, 255, 242, 208, 63, 227, 182,
                150, 255, 184, 151, 87, 53, 25, 242, 184, 51, 182, 158, 165, 83, 22, 104, 95, 9,
                14, 47, 191, 45, 121, 44, 179, 36, 191, 250, 148, 39, 254, 31, 14, 32, 191, 230,
                57, 1, 23, 233, 57, 1, 113, 1, 158, 222, 61, 138, 84, 210, 126, 68, 169, 213, 206,
                24, 150, 24, 242, 45, 48, 8, 80, 95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58,
                175, 148, 127, 110, 164, 41, 8, 9, 0, 76, 95, 3, 180, 18, 59, 46, 24, 110, 7, 251,
                123, 173, 93, 218, 95, 85, 192, 4, 0, 128, 114, 115, 217, 102, 145, 229, 217, 201,
                199, 191, 227, 81, 211, 103, 201, 176, 171, 162, 94, 209, 255, 178, 61, 163, 165,
                157, 75, 84, 151, 146, 162, 18, 213, 1, 158, 247, 140, 152, 114, 61, 220, 144, 115,
                82, 62, 243, 190, 239, 218, 12, 16, 68, 128, 189, 101, 232, 147, 82, 103, 131, 19,
                218, 118, 10, 120, 104, 104, 121, 77, 44, 232, 221, 203, 185, 65, 18, 246, 246, 69,
                199, 220, 163, 233, 180, 239, 128, 226, 131, 165, 241, 12, 111, 138, 139, 108, 197,
                180, 249, 115, 81, 167, 161, 77, 56, 73, 103, 232, 179, 125, 193, 114, 144, 231,
                203, 129, 59, 93, 75, 128, 154, 128, 37, 9, 95, 15, 177, 207, 18, 248, 59, 39, 153,
                17, 5, 8, 169, 210, 187, 48, 96, 236, 156, 128, 94, 211, 157, 72, 61, 24, 203, 203,
                21, 7, 159, 1, 43, 116, 109, 207, 50, 232, 67, 53, 69, 131, 201, 112, 44, 192, 32,
                249, 255, 92, 87, 2, 166, 252, 145, 92, 204, 85, 160, 48, 8, 0, 0, 36, 8, 208, 7,
                0, 0, 215, 7, 0, 0, 128, 191, 173, 201, 187, 178, 195, 202, 43, 56, 205, 17, 183,
                37, 176, 244, 26, 77, 8, 42, 84, 45, 184, 54, 123, 224, 193, 73, 17, 232, 188, 102,
                142, 128, 192, 202, 163, 161, 148, 16, 137, 217, 105, 73, 69, 240, 100, 255, 246,
                205, 84, 130, 249, 228, 158, 205, 148, 235, 11, 196, 152, 92, 220, 185, 244, 59,
                128, 13, 147, 166, 123, 17, 250, 116, 106, 207, 108, 92, 127, 169, 181, 143, 82,
                145, 18, 130, 76, 21, 113, 68, 191, 43, 178, 33, 124, 207, 18, 72, 90, 128, 90, 59,
                55, 239, 198, 24, 19, 237, 211, 132, 30, 45, 48, 146, 153, 200, 155, 146, 163, 17,
                24, 78, 6, 95, 244, 75, 72, 173, 141, 161, 245, 255, 108, 87, 7, 61, 229, 152, 2,
                222, 70, 55, 232, 7, 0, 0, 52, 12, 208, 7, 0, 0, 215, 7, 0, 0, 37, 8, 0, 0, 108,
                87, 12, 88, 243, 181, 152, 155, 183, 44, 223, 7, 0, 0, 52, 12, 208, 7, 0, 0, 209,
                7, 0, 0, 231, 7, 0, 0, 128, 119, 15, 117, 76, 101, 140, 192, 56, 249, 91, 82, 13,
                27, 30, 77, 0, 193, 8, 119, 228, 130, 190, 89, 43, 134, 133, 250, 139, 167, 203,
                87, 248, 128, 233, 136, 149, 201, 192, 255, 191, 151, 198, 89, 86, 186, 39, 44, 34,
                136, 122, 163, 84, 104, 67, 76, 159, 133, 225, 225, 56, 29, 49, 225, 227, 129, 128,
                202, 252, 231, 61, 108, 226, 138, 114, 128, 28, 137, 227, 14, 176, 251, 249, 55,
                252, 1, 120, 38, 108, 112, 249, 94, 97, 101, 206, 120, 211, 173, 177, 128, 35, 156,
                52, 249, 202, 144, 19, 104, 137, 129, 10, 32, 51, 112, 158, 91, 207, 125, 15, 15,
                107, 214, 170, 152, 154, 6, 208, 222, 183, 99, 33, 222, 128, 79, 163, 220, 117,
                100, 66, 203, 148, 165, 161, 21, 126, 226, 221, 222, 148, 213, 170, 88, 72, 244,
                206, 224, 234, 79, 247, 174, 206, 174, 219, 208, 241, 128, 0, 167, 138, 177, 252,
                250, 114, 63, 198, 244, 142, 149, 188, 250, 63, 73, 189, 141, 246, 2, 40, 246, 10,
                151, 186, 187, 184, 15, 146, 69, 116, 28, 92, 87, 12, 115, 39, 162, 164, 139, 242,
                177, 73, 8, 0, 0, 36, 8, 232, 3, 0, 0, 62, 8, 0, 0, 141, 8, 159, 6, 96, 76, 255,
                130, 138, 110, 63, 87, 156, 166, 197, 154, 206, 1, 61, 255, 255, 128, 88, 34, 177,
                184, 213, 127, 244, 100, 227, 20, 43, 255, 238, 85, 187, 132, 35, 16, 184, 254, 9,
                172, 75, 93, 198, 229, 52, 222, 27, 159, 78, 138, 128, 35, 104, 172, 142, 63, 55,
                220, 219, 0, 137, 47, 9, 105, 147, 19, 235, 9, 97, 128, 110, 93, 251, 231, 10, 141,
                163, 45, 38, 98, 218, 53, 9, 128, 20, 148, 147, 139, 63, 200, 169, 174, 8, 196, 70,
                95, 247, 30, 243, 121, 199, 168, 205, 187, 70, 119, 200, 90, 249, 242, 192, 82,
                203, 177, 184, 14, 128, 100, 239, 8, 116, 141, 156, 46, 29, 171, 233, 15, 224, 107,
                135, 25, 70, 226, 97, 146, 12, 227, 173, 48, 221, 88, 141, 194, 15, 186, 105, 51,
                196, 128, 89, 52, 22, 50, 195, 242, 2, 81, 149, 157, 54, 165, 197, 251, 114, 73,
                119, 203, 171, 174, 104, 172, 42, 202, 181, 211, 182, 193, 81, 87, 164, 80, 128,
                234, 119, 182, 109, 207, 189, 182, 253, 167, 214, 134, 175, 134, 247, 158, 158, 50,
                236, 45, 141, 105, 158, 224, 92, 191, 0, 170, 75, 205, 221, 206, 250, 128, 53, 200,
                192, 186, 144, 133, 155, 224, 210, 23, 75, 245, 28, 124, 123, 114, 220, 84, 229,
                54, 42, 95, 100, 152, 87, 35, 105, 247, 51, 43, 248, 208, 128, 172, 226, 42, 215,
                90, 50, 155, 232, 38, 139, 227, 128, 250, 152, 98, 6, 199, 7, 254, 140, 196, 8,
                249, 193, 162, 76, 16, 87, 40, 196, 142, 22, 128, 39, 186, 108, 112, 14, 204, 60,
                28, 177, 228, 231, 69, 9, 135, 194, 220, 85, 131, 19, 66, 34, 237, 230, 201, 136,
                226, 39, 147, 68, 39, 234, 161, 128, 30, 209, 132, 153, 155, 209, 178, 175, 52,
                164, 50, 135, 204, 114, 12, 240, 95, 105, 105, 113, 69, 117, 238, 249, 99, 15, 94,
                231, 6, 212, 16, 133, 128, 18, 2, 203, 171, 83, 213, 43, 159, 23, 227, 82, 144, 32,
                250, 203, 55, 71, 244, 162, 232, 244, 150, 250, 234, 82, 106, 27, 18, 234, 175, 92,
                148, 128, 124, 209, 245, 55, 225, 115, 72, 162, 126, 5, 220, 119, 95, 153, 123, 15,
                43, 118, 187, 223, 102, 192, 39, 165, 179, 215, 52, 197, 85, 5, 193, 126, 128, 51,
                198, 32, 189, 209, 207, 75, 13, 206, 20, 250, 216, 154, 146, 12, 175, 150, 110, 78,
                39, 158, 250, 51, 90, 213, 32, 120, 30, 114, 148, 90, 206, 128, 204, 79, 197, 114,
                176, 171, 2, 117, 103, 86, 27, 180, 29, 123, 49, 95, 118, 130, 216, 244, 65, 183,
                205, 211, 76, 63, 160, 119, 244, 235, 203, 199, 128, 29, 240, 183, 179, 22, 161,
                72, 92, 46, 222, 121, 157, 73, 239, 44, 210, 25, 139, 141, 204, 71, 119, 50, 38,
                219, 189, 174, 216, 155, 248, 246, 178, 128, 82, 66, 5, 36, 1, 152, 64, 229, 7,
                151, 240, 170, 92, 157, 5, 7, 35, 136, 138, 147, 86, 86, 103, 75, 83, 75, 211, 96,
                213, 204, 82, 94, 181, 5, 159, 10, 209, 87, 228, 97, 215, 31, 212, 193, 249, 54,
                131, 154, 95, 31, 62, 248, 223, 128, 8, 239, 142, 226, 171, 84, 102, 207, 203, 226,
                37, 28, 208, 170, 76, 158, 67, 180, 161, 90, 106, 41, 25, 235, 231, 140, 60, 239,
                50, 59, 195, 122, 128, 69, 173, 217, 33, 87, 199, 182, 141, 63, 191, 226, 84, 216,
                20, 195, 8, 97, 181, 103, 202, 26, 38, 30, 239, 38, 77, 208, 162, 31, 229, 160,
                204, 88, 87, 12, 136, 67, 61, 248, 98, 219, 203, 36, 8, 0, 0, 32, 0, 0, 0, 0, 0, 0,
                0, 0, 128, 241, 249, 14, 190, 36, 73, 117, 108, 170, 35, 138, 55, 164, 246, 34,
                186, 164, 116, 86, 125, 93, 49, 120, 188, 132, 207, 77, 148, 244, 228, 169, 196,
                88, 87, 7, 61, 229, 152, 2, 222, 70, 55, 232, 7, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0,
                88, 87, 12, 88, 243, 181, 152, 155, 183, 44, 223, 7, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
                0, 128, 164, 58, 156, 173, 184, 223, 50, 123, 208, 53, 97, 95, 147, 209, 204, 153,
                113, 157, 163, 145, 19, 80, 42, 29, 212, 206, 111, 9, 157, 71, 229, 195, 128, 143,
                111, 81, 33, 174, 228, 91, 78, 120, 142, 64, 197, 207, 73, 63, 217, 224, 190, 5,
                24, 124, 206, 35, 177, 200, 97, 247, 188, 179, 177, 254, 175, 128, 129, 62, 59,
                185, 49, 134, 240, 28, 171, 75, 99, 43, 168, 245, 135, 58, 18, 137, 133, 93, 58,
                37, 141, 215, 74, 56, 194, 114, 206, 97, 118, 25, 128, 88, 140, 243, 244, 18, 6,
                65, 63, 124, 109, 254, 63, 241, 216, 91, 239, 206, 3, 14, 254, 80, 163, 184, 232,
                164, 69, 59, 135, 211, 174, 160, 239, 88, 87, 7, 59, 166, 27, 196, 215, 19, 53, 75,
                8, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 88, 87, 12, 115, 39, 162, 164, 139, 242, 177,
                73, 8, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 141, 8, 159, 11, 60, 37, 47, 203, 41, 216,
                142, 255, 79, 61, 229, 222, 68, 118, 195, 255, 255, 128, 186, 2, 77, 251, 27, 119,
                235, 204, 154, 30, 157, 205, 14, 70, 221, 206, 26, 248, 190, 53, 169, 248, 215,
                102, 127, 22, 153, 170, 150, 60, 142, 83, 128, 88, 6, 112, 189, 244, 215, 89, 5,
                182, 228, 216, 226, 33, 87, 51, 242, 11, 197, 224, 29, 155, 132, 126, 100, 62, 59,
                239, 235, 137, 112, 39, 78, 128, 127, 124, 184, 126, 147, 179, 243, 220, 0, 93, 59,
                10, 190, 112, 21, 62, 149, 241, 169, 121, 19, 21, 240, 140, 94, 116, 140, 138, 236,
                15, 173, 201, 128, 76, 225, 117, 86, 242, 58, 129, 175, 101, 207, 121, 248, 236,
                217, 110, 119, 134, 216, 29, 192, 60, 65, 35, 89, 88, 252, 119, 188, 104, 158, 57,
                245, 128, 78, 169, 169, 255, 44, 134, 205, 245, 72, 154, 1, 166, 32, 106, 200, 68,
                182, 249, 124, 40, 66, 84, 224, 147, 142, 125, 182, 80, 120, 26, 39, 31, 128, 146,
                145, 193, 190, 216, 82, 98, 158, 17, 140, 164, 135, 114, 86, 194, 103, 31, 109, 18,
                230, 232, 225, 175, 40, 53, 244, 200, 96, 209, 62, 72, 167, 128, 0, 180, 105, 140,
                181, 228, 43, 43, 36, 205, 143, 131, 124, 205, 195, 5, 102, 154, 145, 186, 8, 67,
                192, 26, 15, 199, 59, 101, 48, 0, 53, 245, 128, 161, 198, 218, 35, 203, 253, 34,
                149, 177, 76, 200, 110, 177, 4, 7, 196, 233, 155, 9, 75, 109, 31, 34, 218, 78, 83,
                241, 192, 254, 110, 255, 5, 128, 3, 0, 133, 165, 214, 107, 123, 40, 18, 43, 74,
                150, 52, 160, 41, 93, 171, 126, 14, 148, 111, 49, 83, 9, 46, 2, 123, 175, 28, 110,
                209, 6, 128, 146, 53, 91, 249, 190, 155, 223, 22, 203, 102, 253, 155, 173, 248,
                175, 162, 6, 252, 191, 144, 153, 107, 173, 176, 200, 125, 51, 5, 15, 110, 47, 44,
                128, 119, 230, 200, 24, 191, 194, 171, 95, 122, 99, 170, 120, 141, 31, 122, 89, 23,
                82, 100, 61, 27, 213, 242, 96, 216, 32, 9, 228, 77, 144, 244, 222, 128, 101, 89,
                78, 212, 192, 131, 159, 241, 123, 254, 208, 132, 135, 136, 91, 13, 208, 136, 99,
                198, 149, 191, 65, 210, 60, 42, 41, 75, 254, 226, 146, 227, 128, 107, 3, 234, 138,
                165, 154, 132, 211, 11, 43, 18, 123, 182, 92, 192, 8, 219, 216, 64, 227, 17, 191,
                26, 143, 139, 104, 253, 10, 176, 26, 94, 250, 128, 59, 99, 238, 65, 153, 171, 231,
                253, 38, 116, 1, 79, 48, 255, 135, 24, 227, 173, 198, 29, 51, 204, 9, 73, 107, 72,
                209, 61, 184, 247, 88, 169, 128, 221, 252, 191, 99, 26, 254, 145, 5, 214, 101, 73,
                64, 106, 200, 111, 44, 100, 241, 127, 95, 219, 37, 218, 105, 198, 122, 68, 51, 43,
                167, 40, 170, 128, 140, 145, 45, 99, 142, 237, 10, 243, 177, 193, 53, 40, 10, 240,
                6, 37, 224, 24, 159, 226, 99, 193, 200, 196, 5, 7, 170, 31, 206, 221, 0, 124, 1, 7,
                159, 13, 55, 25, 245, 176, 177, 44, 113, 5, 192, 115, 197, 7, 68, 89, 72, 249, 255,
                92, 87, 2, 166, 252, 145, 92, 204, 85, 160, 48, 8, 0, 0, 36, 8, 208, 7, 0, 0, 212,
                7, 0, 0, 128, 183, 198, 226, 22, 113, 16, 232, 182, 81, 235, 105, 58, 91, 191, 184,
                59, 111, 150, 128, 145, 71, 130, 34, 225, 54, 166, 131, 137, 242, 205, 56, 92, 128,
                230, 8, 107, 64, 106, 147, 6, 19, 214, 240, 62, 77, 27, 186, 163, 108, 0, 197, 60,
                23, 107, 89, 244, 217, 250, 99, 168, 55, 251, 12, 173, 232, 124, 87, 12, 136, 67,
                61, 248, 98, 219, 203, 36, 8, 0, 0, 68, 16, 232, 3, 0, 0, 208, 7, 0, 0, 212, 7, 0,
                0, 231, 7, 0, 0, 128, 90, 59, 55, 239, 198, 24, 19, 237, 211, 132, 30, 45, 48, 146,
                153, 200, 155, 146, 163, 17, 24, 78, 6, 95, 244, 75, 72, 173, 141, 161, 245, 255,
                92, 87, 7, 61, 229, 152, 2, 222, 70, 55, 232, 7, 0, 0, 36, 8, 208, 7, 0, 0, 37, 8,
                0, 0, 108, 87, 12, 88, 243, 181, 152, 155, 183, 44, 223, 7, 0, 0, 52, 12, 208, 7,
                0, 0, 209, 7, 0, 0, 231, 7, 0, 0, 128, 219, 215, 94, 9, 186, 191, 42, 25, 219, 63,
                237, 243, 130, 215, 231, 161, 105, 120, 205, 2, 199, 129, 177, 204, 174, 40, 73,
                194, 154, 96, 95, 21, 128, 111, 149, 146, 31, 227, 244, 8, 76, 50, 134, 158, 230,
                167, 109, 179, 109, 44, 152, 38, 100, 166, 40, 134, 148, 105, 203, 101, 140, 132,
                126, 190, 115, 128, 202, 252, 231, 61, 108, 226, 138, 114, 128, 28, 137, 227, 14,
                176, 251, 249, 55, 252, 1, 120, 38, 108, 112, 249, 94, 97, 101, 206, 120, 211, 173,
                177, 128, 151, 254, 128, 24, 142, 196, 104, 235, 142, 225, 114, 221, 194, 248, 166,
                96, 100, 130, 240, 144, 88, 179, 252, 0, 52, 89, 107, 230, 40, 103, 171, 9, 128,
                79, 163, 220, 117, 100, 66, 203, 148, 165, 161, 21, 126, 226, 221, 222, 148, 213,
                170, 88, 72, 244, 206, 224, 234, 79, 247, 174, 206, 174, 219, 208, 241, 128, 0,
                167, 138, 177, 252, 250, 114, 63, 198, 244, 142, 149, 188, 250, 63, 73, 189, 141,
                246, 2, 40, 246, 10, 151, 186, 187, 184, 15, 146, 69, 116, 28, 92, 87, 12, 115, 39,
                162, 164, 139, 242, 177, 73, 8, 0, 0, 36, 8, 232, 3, 0, 0, 62, 8, 0, 0, 65, 3, 191,
                14, 2, 101, 108, 97, 121, 95, 100, 105, 115, 112, 97, 116, 99, 104, 95, 113, 117,
                101, 117, 101, 95, 114, 101, 109, 97, 105, 110, 105, 110, 103, 95, 99, 97, 112, 97,
                99, 105, 116, 121, 28, 96, 128, 143, 110, 43, 35, 129, 96, 51, 141, 9, 185, 119,
                112, 66, 66, 63, 44, 8, 13, 37, 84, 87, 91, 139, 76, 130, 130, 96, 110, 145, 240,
                178, 180, 128, 226, 41, 230, 56, 44, 176, 80, 88, 20, 90, 147, 106, 44, 51, 162,
                142, 153, 138, 152, 251, 180, 169, 18, 62, 45, 81, 8, 165, 97, 59, 203, 199, 128,
                70, 44, 111, 211, 18, 241, 216, 196, 138, 174, 50, 229, 189, 104, 102, 187, 131,
                149, 71, 139, 163, 52, 195, 7, 32, 240, 53, 147, 143, 94, 238, 169, 128, 36, 19,
                173, 164, 146, 119, 26, 142, 33, 48, 198, 18, 141, 19, 192, 148, 50, 239, 88, 248,
                1, 6, 192, 225, 124, 7, 250, 151, 187, 35, 236, 29, 128, 176, 1, 138, 144, 229, 9,
                63, 181, 213, 121, 215, 108, 115, 191, 27, 101, 254, 121, 217, 209, 224, 155, 74,
                54, 84, 166, 217, 71, 90, 202, 80, 160, 212, 232, 3, 0, 0, 0, 144, 1, 0, 0, 144, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144,
                1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 5, 250, 215, 160, 174, 53, 135,
                1, 216, 200, 221, 56, 45, 67, 241, 114, 177, 149, 137, 65, 157, 56, 68, 205, 112,
                123, 203, 221, 70, 61, 249, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1,
                0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 187, 169, 88, 95, 20, 50, 224, 212,
                228, 182, 45, 208, 52, 119, 109, 35, 159, 124, 135, 152, 198, 95, 126, 249, 187,
                99, 157, 59, 15, 105, 136, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1,
                0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 9, 63, 161, 255, 207, 154, 191, 35,
                136, 18, 148, 241, 14, 197, 98, 46, 25, 230, 153, 104, 243, 18, 240, 181, 53, 168,
                8, 103, 28, 141, 179, 126, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1,
                0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 43, 148, 250, 148, 228, 172, 67, 132,
                171, 37, 135, 1, 37, 88, 34, 24, 14, 6, 232, 221, 72, 44, 182, 81, 110, 193, 28,
                201, 36, 93, 165, 93, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80,
                57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1, 0, 0,
                144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 63, 147, 92, 137, 75, 72, 220, 136, 53, 129,
                224, 54, 43, 157, 136, 1, 50, 158, 178, 236, 248, 83, 156, 227, 92, 237, 144, 14,
                124, 139, 136, 142, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 57,
                39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1, 0, 0,
                144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 64, 161, 143, 171, 210, 113, 241, 165, 228,
                252, 176, 225, 217, 111, 240, 26, 230, 134, 218, 228, 111, 176, 231, 168, 137, 44,
                236, 151, 248, 186, 85, 116, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144,
                1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 83, 202, 220, 165, 167, 190, 142,
                186, 19, 99, 201, 171, 165, 120, 28, 236, 246, 179, 188, 89, 243, 24, 46, 85, 230,
                254, 195, 85, 233, 80, 145, 22, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 98, 120, 195, 242, 227, 233,
                193, 24, 169, 0, 95, 229, 165, 68, 204, 39, 139, 96, 82, 71, 46, 75, 28, 195, 43,
                10, 126, 118, 67, 53, 154, 104, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 99, 103, 122, 72, 191, 50, 82,
                52, 229, 214, 125, 21, 50, 83, 191, 47, 14, 140, 153, 149, 232, 224, 66, 234, 66,
                222, 204, 33, 137, 61, 74, 233, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 106, 27, 252, 162, 221, 223,
                106, 170, 245, 44, 94, 186, 7, 66, 122, 150, 233, 137, 249, 73, 16, 168, 236, 103,
                150, 160, 163, 159, 18, 2, 199, 193, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 107, 193, 245, 68, 94, 138,
                210, 194, 81, 181, 247, 113, 165, 206, 101, 60, 10, 33, 77, 188, 96, 11, 153, 24,
                225, 30, 15, 32, 162, 92, 91, 9, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 115, 252, 71, 178, 133, 130,
                97, 235, 64, 231, 231, 59, 145, 36, 224, 75, 25, 215, 42, 236, 77, 160, 135, 194,
                55, 0, 40, 92, 22, 199, 202, 125, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 124, 234, 33, 244, 40, 178,
                179, 182, 15, 57, 170, 170, 56, 223, 142, 162, 42, 117, 217, 246, 63, 4, 107, 216,
                116, 7, 16, 33, 251, 197, 131, 236, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 127, 112, 248, 19, 119, 246,
                252, 26, 160, 149, 112, 164, 23, 155, 129, 181, 148, 231, 184, 235, 250, 189, 7,
                24, 211, 160, 167, 73, 29, 48, 54, 198, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0,
                0, 144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 141, 31, 38, 230, 121, 61,
                43, 72, 39, 197, 122, 164, 187, 110, 148, 61, 120, 69, 85, 209, 11, 114, 89, 132,
                165, 46, 56, 120, 202, 60, 233, 206, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 154, 191, 201, 150, 135, 211,
                54, 59, 44, 221, 83, 140, 8, 31, 44, 118, 42, 124, 254, 88, 131, 41, 7, 129, 27,
                216, 214, 186, 186, 134, 134, 2, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 157, 148, 176, 126, 153, 92,
                236, 87, 64, 254, 99, 40, 220, 29, 83, 165, 253, 178, 150, 132, 69, 68, 189, 252,
                102, 95, 73, 119, 143, 199, 15, 111, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0,
                144, 1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 162, 91, 15, 137, 154, 20, 246,
                251, 108, 89, 46, 42, 198, 137, 71, 121, 217, 190, 113, 191, 118, 21, 86, 14, 21,
                34, 210, 1, 46, 165, 40, 246, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144,
                1, 0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 176, 91, 183, 236, 44, 199, 97, 95,
                93, 40, 245, 102, 24, 85, 5, 4, 4, 38, 248, 71, 29, 95, 111, 139, 236, 251, 1, 193,
                109, 146, 246, 48, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 57,
                39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1, 0, 0,
                144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 209, 152, 216, 62, 41, 157, 198, 68, 91, 54,
                85, 17, 2, 164, 178, 234, 164, 122, 186, 205, 59, 6, 87, 181, 177, 228, 152, 71,
                92, 217, 221, 43, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 57,
                39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1, 0, 0,
                144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 239, 113, 245, 251, 30, 236, 202, 188, 231,
                148, 194, 209, 176, 66, 53, 218, 40, 45, 46, 102, 197, 7, 235, 91, 245, 236, 74,
                143, 143, 20, 12, 90, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80,
                57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1, 0, 0,
                144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 246, 160, 240, 191, 80, 255, 103, 121, 52,
                194, 211, 125, 153, 146, 111, 254, 93, 0, 126, 36, 255, 50, 248, 214, 101, 172,
                253, 54, 98, 55, 122, 78, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1,
                0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 247, 147, 254, 132, 40, 142, 13, 6,
                186, 140, 32, 40, 197, 149, 95, 102, 41, 231, 175, 29, 22, 170, 219, 135, 254, 155,
                86, 118, 200, 94, 75, 242, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 85, 1, 232, 3, 0, 0, 0, 144, 1,
                0, 0, 144, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 232, 199, 94, 105, 228, 156, 254,
                223, 31, 125, 134, 59, 237, 160, 34, 39, 41, 22, 232, 161, 187, 125, 69, 10, 227,
                1, 104, 252, 95, 14, 129, 0, 80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                80, 57, 39, 140, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        })
        .unwrap();
    }
}
