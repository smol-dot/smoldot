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
    let mut entries: Vec<Entry> = Vec::with_capacity(merkle_values.len());

    let mut trie_roots_with_entries =
        hashbrown::HashMap::with_capacity_and_hasher(trie_roots.len(), Default::default());

    // Keep track of the proof entries that haven't been visited when traversing.
    let mut unvisited_proof_entries =
        (0..merkle_values.len()).collect::<hashbrown::HashSet<_, fnv::FnvBuildHasher>>();

    // We repeat this operation for every trie root.
    for trie_root_hash in trie_roots {
        struct StackEntry<'a> {
            range_in_proof: ops::Range<usize>,
            index_in_entries: usize,
            num_visited_children: u8,
            children_node_values: [Option<&'a [u8]>; 16],
        }

        // TODO: configurable capacity?
        let mut visited_entries_stack: Vec<StackEntry> = Vec::with_capacity(24);

        loop {
            // Find which node to visit next.
            // This is the next child of the node at the top of the stack, or if the node at
            // the top of the stack doesn't have any child, we pop it and continue iterating.
            // If the stack is empty, we are necessarily at the first iteration.
            let visited_node_entry_range = match visited_entries_stack.last_mut() {
                None => {
                    // Stack is empty.
                    // Because we immediately `break` after popping the last element, the stack
                    // can only ever be empty at the very start.
                    let (root_position, root_range) =
                        merkle_values.get(&trie_root_hash[..]).unwrap().clone();
                    let _ = unvisited_proof_entries.remove(&root_position);
                    trie_roots_with_entries.insert(*trie_root_hash, entries.len());
                    root_range
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
                        offset..(offset + child_node_value.len())
                    } else if let Some(&(child_position, ref child_entry_range)) =
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
                        let _ = unvisited_proof_entries.remove(&child_position);
                        child_entry_range.clone()
                    } else {
                        // Child is a hash that was not found in the proof. Simply continue
                        // iterating, in order to try to find the follow-up child.
                        continue;
                    }
                }
            };

            // Decodes the proof entry.
            let visited_node_entry = &proof_as_ref[visited_node_entry_range.clone()];
            let visited_node_decoded =
                trie_node::decode(visited_node_entry).map_err(Error::InvalidNodeValue)?;

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
                        if let Some(&(value_position, ref value_entry_range)) =
                            merkle_values.get(&value_hash[..])
                        {
                            let _ = unvisited_proof_entries.remove(&value_position);
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
                        debug_assert!(
                            offset <= (visited_node_entry_range.start + visited_node_entry.len())
                        );
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
}
