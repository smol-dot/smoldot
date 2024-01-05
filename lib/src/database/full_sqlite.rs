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

//! Filesystem-backed database containing all the information about a chain.
//!
//! This module handles the persistent storage of the chain on disk.
//!
//! # Usage
//!
//! Use the [`open()`] function to create a new database or open an existing one. [`open()`]
//! returns a [`DatabaseOpen`] enum. This enum will contain either a [`SqliteFullDatabase`] object,
//! representing an access to the database, or a [`DatabaseEmpty`] if the database didn't exist or
//! is empty. If that is the case, use [`DatabaseEmpty::initialize`] in order to populate it and
//! obtain a [`SqliteFullDatabase`].
//!
//! Use [`SqliteFullDatabase::insert`] to insert a new block in the database. The block is assumed
//! to have been successfully verified prior to insertion. An error is returned if this block is
//! already in the database or isn't a descendant or ancestor of the latest finalized block.
//!
//! Use [`SqliteFullDatabase::set_finalized`] to mark a block already in the database as finalized.
//! Any block that isn't an ancestor or descendant will be removed. Reverting finalization is
//! not supported.
//!
//! In order to minimize disk usage, it is not possible to efficiently retrieve the storage items
//! of blocks that are ancestors of the finalized block. When a block is finalized, the storage of
//! its ancestors is lost, and the only way to reconstruct it is to execute all blocks starting
//! from the genesis to the desired one.
//!
//! # About errors handling
//!
//! Most of the functions and methods in this module return a `Result` containing notably an
//! [`CorruptedError`]. This kind of errors can happen if the operating system returns an error
//! when accessing the file system, or if the database has been corrupted, for example by the user
//! manually modifying it.
//!
//! There isn't much that can be done to properly handle an [`CorruptedError`]. The only
//! reasonable solutions are either to stop the program, or to delete the entire database and
//! recreate it.
//!
//! # Schema
//!
//! The SQL schema of the database, with explanatory comments, can be found in `open.rs`.
//!
//! # About blocking behavior
//!
//! This implementation uses the SQLite library, which isn't Rust-asynchronous-compatible. Many
//! functions will, with the help of the operating system, put the current thread to sleep while
//! waiting for an I/O operation to finish. In the context of asynchronous Rust, this is
//! undesirable.
//!
//! For this reason, you are encouraged to isolate the database in its own threads and never
//! access it directly from an asynchronous context.
//!

// TODO: better docs

#![cfg(feature = "database-sqlite")]
#![cfg_attr(docsrs, doc(cfg(feature = "database-sqlite")))]

use crate::{
    chain::chain_information,
    executor::{self, host},
    header, trie,
};

use alloc::borrow::Cow;
use core::{fmt, iter};
use parking_lot::Mutex;
use rusqlite::OptionalExtension as _;

pub use open::{open, Config, ConfigTy, DatabaseEmpty, DatabaseOpen};

mod open;
mod tests;

/// Returns an opaque string representing the version number of the SQLite library this binary
/// is using.
pub fn sqlite_version() -> &'static str {
    rusqlite::version()
}

/// An open database. Holds file descriptors.
pub struct SqliteFullDatabase {
    /// The SQLite connection.
    ///
    /// The database is constantly within a transaction.
    /// When the database is opened, `BEGIN TRANSACTION` is immediately run. We periodically
    /// call `COMMIT; BEGIN_TRANSACTION` when deemed necessary. `COMMIT` is basically the
    /// equivalent of `fsync`, and must be called carefully in order to not lose too much speed.
    database: Mutex<rusqlite::Connection>,

    /// Number of bytes used to encode the block number.
    block_number_bytes: usize,
}

impl SqliteFullDatabase {
    /// Returns the hash of the block in the database whose storage is currently accessible.
    pub fn best_block_hash(&self) -> Result<[u8; 32], CorruptedError> {
        let connection = self.database.lock();

        let val = meta_get_blob(&connection, "best")?.ok_or(CorruptedError::MissingMetaKey)?;
        if val.len() == 32 {
            let mut out = [0; 32];
            out.copy_from_slice(&val);
            Ok(out)
        } else {
            Err(CorruptedError::InvalidBlockHashLen)
        }
    }

    /// Returns the hash of the finalized block in the database.
    pub fn finalized_block_hash(&self) -> Result<[u8; 32], CorruptedError> {
        let database = self.database.lock();
        finalized_hash(&database)
    }

    /// Returns the SCALE-encoded header of the given block, or `None` if the block is unknown.
    ///
    /// > **Note**: If this method is called twice times in a row with the same block hash, it
    /// >           is possible for the first time to return `Some` and the second time to return
    /// >           `None`, in case the block has since been removed from the database.
    pub fn block_scale_encoded_header(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, CorruptedError> {
        let connection = self.database.lock();

        let out = connection
            .prepare_cached(r#"SELECT header FROM blocks WHERE hash = ?"#)
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .query_row((&block_hash[..],), |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        Ok(out)
    }

    /// Returns the hash of the parent of the given block, or `None` if the block is unknown.
    ///
    /// > **Note**: If this method is called twice times in a row with the same block hash, it
    /// >           is possible for the first time to return `Some` and the second time to return
    /// >           `None`, in case the block has since been removed from the database.
    pub fn block_parent(&self, block_hash: &[u8; 32]) -> Result<Option<[u8; 32]>, CorruptedError> {
        let connection = self.database.lock();

        let out = connection
            .prepare_cached(r#"SELECT parent_hash FROM blocks WHERE hash = ?"#)
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .query_row((&block_hash[..],), |row| row.get::<_, [u8; 32]>(0))
            .optional()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        Ok(out)
    }

    /// Returns the list of extrinsics of the given block, or `None` if the block is unknown.
    ///
    /// > **Note**: The list of extrinsics of a block is also known as its *body*.
    ///
    /// > **Note**: If this method is called twice times in a row with the same block hash, it
    /// >           is possible for the first time to return `Some` and the second time to return
    /// >           `None`, in case the block has since been removed from the database.
    pub fn block_extrinsics(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<impl ExactSizeIterator<Item = Vec<u8>>>, CorruptedError> {
        let connection = self.database.lock();

        // TODO: doesn't detect if block is absent

        let result = connection
            .prepare_cached(r#"SELECT extrinsic FROM blocks_body WHERE hash = ? ORDER BY idx ASC"#)
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .query_map((&block_hash[..],), |row| row.get::<_, Vec<u8>>(0))
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        Ok(Some(result.into_iter()))
    }

    /// Returns the hashes of the blocks given a block number.
    pub fn block_hash_by_number(
        &self,
        block_number: u64,
    ) -> Result<impl ExactSizeIterator<Item = [u8; 32]>, CorruptedError> {
        let connection = self.database.lock();
        let result = block_hashes_by_number(&connection, block_number)?;
        Ok(result.into_iter())
    }

    /// Returns the hash of the block of the best chain given a block number.
    pub fn best_block_hash_by_number(
        &self,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, CorruptedError> {
        let connection = self.database.lock();

        let block_number = match i64::try_from(block_number) {
            Ok(n) => n,
            Err(_) => return Ok(None),
        };

        let result = connection
            .prepare_cached(r#"SELECT hash FROM blocks WHERE number = ? AND is_best_chain = TRUE"#)
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .query_row((block_number,), |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))
            .and_then(|value| {
                let Some(value) = value else { return Ok(None) };
                Ok(Some(
                    <[u8; 32]>::try_from(&value[..])
                        .map_err(|_| CorruptedError::InvalidBlockHashLen)?,
                ))
            })?;

        Ok(result)
    }

    /// Returns a [`chain_information::ChainInformation`] struct containing the information about
    /// the current finalized state of the chain.
    ///
    /// This method is relatively expensive and should preferably not be called repeatedly.
    ///
    /// In order to avoid race conditions, the known finalized block hash must be passed as
    /// parameter. If the finalized block in the database doesn't match the hash passed as
    /// parameter, most likely because it has been updated in a parallel thread, a
    /// [`StorageAccessError::IncompleteStorage`] error is returned.
    // TODO: an IncompleteStorage error doesn't seem appropriate; also, why is it even a problem given that the chain information contains the finalized block anyway
    pub fn to_chain_information(
        &self,
        finalized_block_hash: &[u8; 32],
    ) -> Result<chain_information::ValidChainInformation, StorageAccessError> {
        if finalized_hash(&self.database.lock())? != *finalized_block_hash {
            return Err(StorageAccessError::IncompleteStorage);
        }

        let mut builder = chain_information::build::ChainInformationBuild::new(
            chain_information::build::Config {
                finalized_block_header: chain_information::build::ConfigFinalizedBlockHeader::Any {
                    scale_encoded_header: self
                        .block_scale_encoded_header(finalized_block_hash)?
                        .ok_or(StorageAccessError::UnknownBlock)?, // TODO: inappropriate error
                    known_finality: None,
                },
                runtime: {
                    let code = match self.block_storage_get(
                        finalized_block_hash,
                        iter::empty::<iter::Empty<_>>(),
                        trie::bytes_to_nibbles(b":code".iter().copied()).map(u8::from),
                    )? {
                        Some((code, _)) => code,
                        None => todo!(),
                    };
                    let heap_pages = match self.block_storage_get(
                        &finalized_block_hash,
                        iter::empty::<iter::Empty<_>>(),
                        trie::bytes_to_nibbles(b":heappages".iter().copied()).map(u8::from),
                    )? {
                        Some((hp, _)) => Some(hp),
                        None => None,
                    };
                    let Ok(heap_pages) =
                        executor::storage_heap_pages_to_value(heap_pages.as_deref())
                    else {
                        todo!()
                    };
                    let Ok(runtime) = host::HostVmPrototype::new(host::Config {
                        module: code,
                        heap_pages,
                        exec_hint: executor::vm::ExecHint::Oneshot,
                        allow_unresolved_imports: true,
                    }) else {
                        todo!()
                    };
                    runtime
                },
                block_number_bytes: self.block_number_bytes,
            },
        );

        // TODO: this whole code is racy because the database isn't locked
        loop {
            match builder {
                chain_information::build::ChainInformationBuild::Finished {
                    result: Ok(chain_information),
                    .. // TODO: runtime thrown away
                } => return Ok(chain_information),
                chain_information::build::ChainInformationBuild::Finished {
                    result: Err(_),
                    .. // TODO: runtime thrown away
                } => todo!(),
                chain_information::build::ChainInformationBuild::InProgress(
                    chain_information::build::InProgress::StorageGet(val),
                ) => {
                    // TODO: child trie support
                    let value = self.block_storage_get(finalized_block_hash, iter::empty::<iter::Empty<_>>(), trie::bytes_to_nibbles(val.key().as_ref().iter().copied()).map(u8::from))?;
                    let value = match value {
                        Some((val, vers)) => {
                            Some((iter::once(val), chain_information::build::TrieEntryVersion::try_from(vers).map_err(|_| StorageAccessError::Corrupted(CorruptedError::InvalidTrieEntryVersion))?))
                        }
                        None => None
                    };
                    builder = val.inject_value(value);
                }
                chain_information::build::ChainInformationBuild::InProgress(
                    chain_information::build::InProgress::NextKey(val),
                ) => {
                    // TODO: child trie support
                    let nk = self.block_storage_next_key(finalized_block_hash, iter::empty::<iter::Empty<_>>(), val.key().map(u8::from),val.prefix().map(u8::from), val.branch_nodes())?;
                    builder = val.inject_key(nk.map(|nibbles| nibbles.into_iter().map(|n| trie::Nibble::try_from(n).unwrap())));
                }
                chain_information::build::ChainInformationBuild::InProgress(
                    chain_information::build::InProgress::ClosestDescendantMerkleValue(val),
                ) => {
                    // TODO: child trie support
                    let mv = self.block_storage_closest_descendant_merkle_value(finalized_block_hash, iter::empty::<iter::Empty<_>>(), val.key().map(u8::from))?;
                    builder = val.inject_merkle_value(mv.as_deref());
                }
            }
        }
    }

    /// Insert a new block in the database.
    ///
    /// Must pass the header and body of the block.
    ///
    /// Blocks must be inserted in the correct order. An error is returned if the parent of the
    /// newly-inserted block isn't present in the database.
    ///
    /// > **Note**: It is not necessary for the newly-inserted block to be a descendant of the
    /// >           finalized block, unless `is_new_best` is true.
    ///
    pub fn insert<'a>(
        &self,
        scale_encoded_header: &[u8],
        is_new_best: bool,
        body: impl ExactSizeIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<(), InsertError> {
        // Calculate the hash of the new best block.
        let block_hash = header::hash_from_scale_encoded_header(scale_encoded_header);

        // Decode the header, as we will need various information from it.
        // TODO: this module shouldn't decode headers
        let header = header::decode(scale_encoded_header, self.block_number_bytes)
            .map_err(InsertError::BadHeader)?;

        // Locking is performed as late as possible.
        let mut database = self.database.lock();

        // Start a transaction to insert everything at once.
        let transaction = database
            .transaction()
            .map_err(|err| InsertError::Corrupted(CorruptedError::Internal(InternalError(err))))?;

        // Make sure that the block to insert isn't already in the database.
        if has_block(&transaction, &block_hash)? {
            return Err(InsertError::Duplicate);
        }

        // Make sure that the parent of the block to insert is in the database.
        if !has_block(&transaction, header.parent_hash)? {
            return Err(InsertError::MissingParent);
        }

        transaction
            .prepare_cached(
                "INSERT INTO blocks(number, hash, parent_hash, state_trie_root_hash, header, is_best_chain, justification) VALUES (?, ?, ?, ?, ?, FALSE, NULL)",
            )
            .unwrap()
            .execute((
                i64::try_from(header.number).unwrap(),
                &block_hash[..],
                &header.parent_hash[..],
                &header.state_root[..],
                scale_encoded_header
            ))
            .unwrap();

        {
            let mut statement = transaction
                .prepare_cached("INSERT INTO blocks_body(hash, idx, extrinsic) VALUES (?, ?, ?)")
                .unwrap();
            for (index, item) in body.enumerate() {
                statement
                    .execute((
                        &block_hash[..],
                        i64::try_from(index).unwrap(),
                        item.as_ref(),
                    ))
                    .unwrap();
            }
        }

        // Change the best chain to be the new block.
        if is_new_best {
            // It would be illegal to change the best chain to not overlay with the
            // finalized chain.
            if header.number <= finalized_num(&transaction)? {
                return Err(InsertError::BestNotInFinalizedChain);
            }

            set_best_chain(&transaction, &block_hash)?;
        }

        // If everything is successful, we commit.
        transaction
            .commit()
            .map_err(|err| InsertError::Corrupted(CorruptedError::Internal(InternalError(err))))?;

        Ok(())
    }

    // TODO: needs documentation
    // TODO: should we refuse inserting disjoint storage nodes?
    pub fn insert_trie_nodes<'a>(
        &self,
        new_trie_nodes: impl Iterator<Item = InsertTrieNode<'a>>,
        trie_entries_version: u8,
    ) -> Result<(), CorruptedError> {
        let mut database = self.database.lock();

        let transaction = database
            .transaction()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        {
            // TODO: should check whether the existing merkle values that are referenced from inserted nodes exist in the parent's storage
            // TODO: is it correct to have OR IGNORE everywhere?
            let mut insert_node_statement = transaction
                .prepare_cached("INSERT OR IGNORE INTO trie_node(hash, partial_key) VALUES(?, ?)")
                .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            let mut insert_node_storage_statement = transaction
                .prepare_cached("INSERT OR IGNORE INTO trie_node_storage(node_hash, value, trie_root_ref, trie_entry_version) VALUES(?, ?, ?, ?)")
                .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            let mut insert_child_statement = transaction
                .prepare_cached(
                    "INSERT OR IGNORE INTO trie_node_child(hash, child_num, child_hash) VALUES(?, ?, ?)",
                )
                .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            // TODO: if the iterator's `next()` function accesses the database, we deadlock
            for trie_node in new_trie_nodes {
                assert!(trie_node.partial_key_nibbles.iter().all(|n| *n < 16)); // TODO: document
                insert_node_statement
                    .execute((&trie_node.merkle_value, trie_node.partial_key_nibbles))
                    .map_err(|err: rusqlite::Error| CorruptedError::Internal(InternalError(err)))?;
                match trie_node.storage_value {
                    InsertTrieNodeStorageValue::Value {
                        value,
                        references_merkle_value,
                    } => {
                        insert_node_storage_statement
                            .execute((
                                &trie_node.merkle_value,
                                if !references_merkle_value {
                                    Some(&value)
                                } else {
                                    None
                                },
                                if references_merkle_value {
                                    Some(&value)
                                } else {
                                    None
                                },
                                trie_entries_version,
                            ))
                            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
                    }
                    InsertTrieNodeStorageValue::NoValue => {}
                }
                for (child_num, child) in trie_node.children_merkle_values.iter().enumerate() {
                    if let Some(child) = child {
                        let child_num =
                            vec![u8::try_from(child_num).unwrap_or_else(|_| unreachable!())];
                        insert_child_statement
                            .execute((&trie_node.merkle_value, child_num, child))
                            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
                    }
                }
            }
        }

        transaction
            .commit()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        Ok(())
    }

    /// Returns a list of trie nodes that are missing from the database and that belong to the
    /// state of a block whose number is superior or equal to the finalized block.
    ///
    /// The ordering of the returned trie nodes is unspecified.
    ///
    /// > **Note**: This function call is relatively expensive, and the API user is expected to
    /// >           cache the return value.
    pub fn finalized_and_above_missing_trie_nodes_unordered(
        &self,
    ) -> Result<Vec<MissingTrieNode>, CorruptedError> {
        let database = self.database.lock();

        let mut statement = database
            .prepare_cached(
                r#"
            WITH RECURSIVE
                -- List of all block hashes that are equal to the finalized block or above.
                finalized_and_above_blocks(block_hash) AS (
                    SELECT blocks.hash
                    FROM blocks
                    JOIN meta ON meta.key = "finalized"
                    WHERE blocks.number >= meta.value_number
                ),

                -- List of all trie nodes for these blocks.
                trie_nodes(block_hash, node_hash, node_key, is_present) AS (
                    SELECT  blocks.hash, blocks.state_trie_root_hash,
                            CASE WHEN trie_node.partial_key IS NULL THEN X'' ELSE trie_node.partial_key END,
                            trie_node.hash IS NOT NULL
                        FROM blocks
                        JOIN finalized_and_above_blocks
                            ON blocks.hash = finalized_and_above_blocks.block_hash
                        LEFT JOIN trie_node
                            ON trie_node.hash = blocks.state_trie_root_hash

                    UNION ALL
                    SELECT  trie_nodes.block_hash, trie_node_child.child_hash,
                            CASE WHEN trie_node.hash IS NULL THEN CAST(trie_nodes.node_key || trie_node_child.child_num AS BLOB)
                            ELSE CAST(trie_nodes.node_key || trie_node_child.child_num || trie_node.partial_key AS BLOB) END,
                            trie_node.hash IS NOT NULL
                        FROM trie_nodes
                        JOIN trie_node_child
                            ON trie_nodes.node_hash = trie_node_child.hash
                        LEFT JOIN trie_node
                            ON trie_node.hash = trie_node_child.child_hash
                        WHERE trie_nodes.is_present

                    UNION ALL
                    SELECT  trie_nodes.block_hash, trie_node_storage.trie_root_ref,
                            CASE WHEN trie_node.hash IS NULL THEN CAST(trie_nodes.node_key || X'10' AS BLOB)
                            ELSE CAST(trie_nodes.node_key || X'10' || trie_node.partial_key AS BLOB) END,
                            trie_node.hash IS NOT NULL
                        FROM trie_nodes
                        JOIN trie_node_storage
                            ON trie_nodes.node_hash = trie_node_storage.node_hash AND trie_node_storage.trie_root_ref IS NOT NULL
                        LEFT JOIN trie_node
                            ON trie_node.hash = trie_node_storage.trie_root_ref
                        WHERE trie_nodes.is_present
                )

            SELECT group_concat(HEX(trie_nodes.block_hash)), group_concat(CAST(blocks.number as TEXT)), trie_nodes.node_hash, group_concat(HEX(trie_nodes.node_key))
            FROM trie_nodes
            JOIN blocks ON blocks.hash = trie_nodes.block_hash
            WHERE is_present = false
            GROUP BY trie_nodes.node_hash
            "#)
            .map_err(|err| {
                CorruptedError::Internal(
                    InternalError(err),
                )
            })?;

        let results = statement
            .query_map((), |row| {
                let block_hashes = row.get::<_, String>(0)?;
                let block_numbers = row.get::<_, String>(1)?;
                let node_hash = row.get::<_, Vec<u8>>(2)?;
                let node_keys = row.get::<_, String>(3)?;
                Ok((block_hashes, block_numbers, node_hash, node_keys))
            })
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .map(|row| {
                let (block_hashes, block_numbers, trie_node_hash, node_keys) = match row {
                    Ok(r) => r,
                    Err(err) => return Err(CorruptedError::Internal(InternalError(err))),
                };

                let mut block_hashes_iter = block_hashes
                    .split(',')
                    .map(|hash| hex::decode(hash).unwrap());
                let mut block_numbers_iter = block_numbers
                    .split(',')
                    .map(|n| <u64 as core::str::FromStr>::from_str(n).unwrap());
                let mut node_keys_iter =
                    node_keys.split(',').map(|hash| hex::decode(hash).unwrap());

                let mut blocks = Vec::with_capacity(32);
                loop {
                    match (
                        block_hashes_iter.next(),
                        block_numbers_iter.next(),
                        node_keys_iter.next(),
                    ) {
                        (Some(hash), Some(number), Some(node_key)) => {
                            let hash = <[u8; 32]>::try_from(hash)
                                .map_err(|_| CorruptedError::InvalidBlockHashLen)?;
                            let mut trie_node_key_nibbles = Vec::with_capacity(node_key.len());
                            let mut parent_tries_paths_nibbles = Vec::with_capacity(node_key.len());
                            for nibble in node_key {
                                debug_assert!(nibble <= 16);
                                if nibble == 16 {
                                    parent_tries_paths_nibbles.push(trie_node_key_nibbles.clone());
                                    trie_node_key_nibbles.clear();
                                } else {
                                    trie_node_key_nibbles.push(nibble);
                                }
                            }

                            blocks.push(MissingTrieNodeBlock {
                                hash,
                                number,
                                parent_tries_paths_nibbles,
                                trie_node_key_nibbles,
                            })
                        }
                        (None, None, None) => break,
                        _ => {
                            // The iterators are supposed to have the same number of elements.
                            debug_assert!(false);
                            break;
                        }
                    }
                }

                let trie_node_hash = <[u8; 32]>::try_from(trie_node_hash)
                    .map_err(|_| CorruptedError::InvalidTrieHashLen)?;

                debug_assert!(!blocks.is_empty());

                Ok(MissingTrieNode {
                    blocks,
                    trie_node_hash,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Changes the finalized block to the given one.
    ///
    /// The block must have been previously inserted using [`SqliteFullDatabase::insert`],
    /// otherwise an error is returned.
    ///
    /// Blocks are expected to be valid in context of the chain. Inserting an invalid block can
    /// result in the database being corrupted.
    ///
    /// The block must be a descendant of the current finalized block. Reverting finalization is
    /// forbidden, as the database intentionally discards some information when finality is
    /// applied.
    ///
    /// > **Note**: This function doesn't remove any block from the database but simply moves
    /// >           the finalized block "cursor".
    ///
    pub fn set_finalized(
        &self,
        new_finalized_block_hash: &[u8; 32],
    ) -> Result<(), SetFinalizedError> {
        let mut database = self.database.lock();

        // Start a transaction to insert everything at once.
        let transaction = database.transaction().map_err(|err| {
            SetFinalizedError::Corrupted(CorruptedError::Internal(InternalError(err)))
        })?;

        // Fetch the header of the block to finalize.
        let new_finalized_header = block_header(&transaction, new_finalized_block_hash)?
            .ok_or(SetFinalizedError::UnknownBlock)?;
        let new_finalized_header = header::decode(&new_finalized_header, self.block_number_bytes)
            .map_err(CorruptedError::BlockHeaderCorrupted)
            .map_err(SetFinalizedError::Corrupted)?;

        // Fetch the current finalized block.
        let current_finalized = finalized_num(&transaction)?;

        // If the block to finalize is at the same height as the already-finalized
        // block, considering that the database only contains one block per height on
        // the finalized chain, and that the presence of the block to finalize in
        // the database has already been verified, it is guaranteed that the block
        // to finalize is already the one already finalized.
        // TODO: this comment is obsolete ^, should also compare the block hashes
        if new_finalized_header.number == current_finalized {
            return Ok(());
        }

        // Cannot set the finalized block to a past block. The database can't support
        // reverting finalization.
        if new_finalized_header.number < current_finalized {
            return Err(SetFinalizedError::RevertForbidden);
        }

        // At this point, we are sure that the operation will succeed unless the database is
        // corrupted.
        // Update the finalized block in meta.
        meta_set_number(&transaction, "finalized", new_finalized_header.number)?;

        // It is possible that the best block has been pruned.
        // TODO: ^ yeah, how do we handle that exactly ^ ?

        // If everything went well up to this point, commit the transaction.
        transaction.commit().map_err(|err| {
            SetFinalizedError::Corrupted(CorruptedError::Internal(InternalError(err)))
        })?;

        Ok(())
    }

    /// Removes from the database all blocks that aren't a descendant of the current finalized
    /// block.
    pub fn purge_finality_orphans(&self) -> Result<(), CorruptedError> {
        let mut database = self.database.lock();

        // TODO: untested

        let transaction = database
            .transaction()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        // Temporarily disable foreign key checks in order to make the insertion easier, as we
        // don't have to make sure that trie nodes are sorted.
        // Note that this is immediately disabled again when we `COMMIT` later down below.
        // TODO: is this really necessary?
        transaction
            .execute("PRAGMA defer_foreign_keys = ON", ())
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        let current_finalized = finalized_num(&transaction)?;

        let blocks = transaction
            .prepare_cached(
                r#"SELECT hash FROM blocks WHERE number <= ? AND is_best_chain = FALSE"#,
            )
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .query_map((current_finalized,), |row| row.get::<_, Vec<u8>>(0))
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        for block in blocks {
            purge_block(&transaction, &block)?;
        }

        // If everything went well up to this point, commit the transaction.
        transaction
            .commit()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        Ok(())
    }

    /// Returns the value associated with a node of the trie of the given block.
    ///
    /// `parent_tries_paths_nibbles` is a list of keys to follow in order to find the root of the
    /// trie into which `key_nibbles` should be searched.
    ///
    /// Beware that both `parent_tries_paths_nibbles` and `key_nibbles` must yield *nibbles*, in
    /// other words values strictly inferior to 16.
    ///
    /// Returns an error if the block or its storage can't be found in the database.
    ///
    /// # Panic
    ///
    /// Panics if any of the values yielded by `parent_tries_paths_nibbles` or `key_nibbles` is
    /// superior or equal to 16.
    ///
    pub fn block_storage_get(
        &self,
        block_hash: &[u8; 32],
        parent_tries_paths_nibbles: impl Iterator<Item = impl Iterator<Item = u8>>,
        key_nibbles: impl Iterator<Item = u8>,
    ) -> Result<Option<(Vec<u8>, u8)>, StorageAccessError> {
        // Process the iterators at the very beginning and before locking the database, in order
        // to avoid a deadlock in case the `next()` function of one of the iterators accesses
        // the database as well.
        let key_vectored = parent_tries_paths_nibbles
            .flat_map(|t| t.inspect(|n| assert!(*n < 16)).chain(iter::once(0x10)))
            .chain(key_nibbles.inspect(|n| assert!(*n < 16)))
            .collect::<Vec<_>>();

        let connection = self.database.lock();

        // TODO: could be optimized by having a different request when `parent_tries_paths_nibbles` is empty and when it isn't
        // TODO: trie_root_ref system untested
        // TODO: infinite loop if there's a loop in the trie; detect this
        let mut statement = connection
            .prepare_cached(
                r#"
            WITH RECURSIVE
                -- At the end of the recursive statement, `node_with_key` must always contain
                -- one and exactly one item where `search_remain` is either empty or null. Empty
                -- indicates that we have found a match, while null means that the search has
                -- been interrupted due to a storage entry not being in the database. If
                -- `search_remain` is empty, then `node_hash` is either a hash in case of a match
                -- or null in case there is no entry with the requested key. If `search_remain`
                -- is null, then `node_hash` is irrelevant.
                --
                -- In order to properly handle the situation where the key is empty, the initial
                -- request of the recursive table building must check whether the partial key of
                -- the root matches. In other words, all the entries of `node_with_key` (where
                -- `node_hash` is non-null) contain entries that are known to be in the database
                -- and after the partial key has already been verified to be correct.
                node_with_key(node_hash, search_remain) AS (
                        SELECT
                            IIF(COALESCE(SUBSTR(:key, 1, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key, trie_node.hash, NULL),
                            IIF(trie_node.partial_key IS NULL, NULL, COALESCE(SUBSTR(:key, 1 + LENGTH(trie_node.partial_key)), X''))
                        FROM blocks
                        LEFT JOIN trie_node ON blocks.state_trie_root_hash = trie_node.hash
                        WHERE blocks.hash = :block_hash
                    UNION ALL
                    SELECT
                        CASE
                            WHEN HEX(SUBSTR(node_with_key.search_remain, 1, 1)) = '10' THEN trie_node_storage.trie_root_ref
                            WHEN SUBSTR(node_with_key.search_remain, 2, LENGTH(trie_node.partial_key)) = trie_node.partial_key THEN trie_node_child.child_hash
                            ELSE NULL END,
                        CASE
                            WHEN HEX(SUBSTR(node_with_key.search_remain, 1, 1)) = '10' THEN SUBSTR(node_with_key.search_remain, 1)
                            WHEN trie_node_child.child_hash IS NULL THEN X''
                            WHEN trie_node.partial_key IS NULL THEN NULL
                            WHEN SUBSTR(node_with_key.search_remain, 2, LENGTH(trie_node.partial_key)) = trie_node.partial_key THEN SUBSTR(node_with_key.search_remain, 2 + LENGTH(trie_node.partial_key))
                            ELSE X'' END
                    FROM node_with_key
                        LEFT JOIN trie_node_child
                            ON node_with_key.node_hash = trie_node_child.hash
                            AND SUBSTR(node_with_key.search_remain, 1, 1) = trie_node_child.child_num
                        LEFT JOIN trie_node
                            ON trie_node.hash = trie_node_child.child_hash
                        LEFT JOIN trie_node_storage
                            ON node_with_key.node_hash = trie_node_storage.node_hash
                        WHERE LENGTH(node_with_key.search_remain) >= 1
                )
            SELECT COUNT(blocks.hash) >= 1, node_with_key.search_remain IS NULL, COALESCE(trie_node_storage.value, trie_node_storage.trie_root_ref), trie_node_storage.trie_entry_version
            FROM blocks
            JOIN node_with_key ON LENGTH(node_with_key.search_remain) = 0 OR node_with_key.search_remain IS NULL
            LEFT JOIN trie_node_storage ON node_with_key.node_hash = trie_node_storage.node_hash AND node_with_key.search_remain IS NOT NULL
            WHERE blocks.hash = :block_hash;
            "#)
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(
                    InternalError(err),
                ))
            })?;

        // In order to debug the SQL query above (for example in case of a failing test),
        // uncomment this block:
        //
        /*println!("{:?}", {
            let mut statement = connection
                    .prepare_cached(
                        r#"
                    WITH RECURSIVE
                        copy-paste the definition of node_with_key here

                    SELECT * FROM node_with_key"#).unwrap();
            statement
                .query_map(
                    rusqlite::named_params! {
                        ":block_hash": &block_hash[..],
                        ":key": key_vectored,
                    },
                    |row| {
                        let node_hash = row.get::<_, Option<Vec<u8>>>(0)?.map(hex::encode);
                        let search_remain = row.get::<_, Option<Vec<u8>>>(1)?;
                        Ok((node_hash, search_remain))
                    },
                )
                .unwrap()
                .collect::<Vec<_>>()
        });*/

        let (has_block, incomplete_storage, value, trie_entry_version) = statement
            .query_row(
                rusqlite::named_params! {
                    ":block_hash": &block_hash[..],
                    ":key": key_vectored,
                },
                |row| {
                    let has_block = row.get::<_, i64>(0)? != 0;
                    let incomplete_storage = row.get::<_, i64>(1)? != 0;
                    let value = row.get::<_, Option<Vec<u8>>>(2)?;
                    let trie_entry_version = row.get::<_, Option<i64>>(3)?;
                    Ok((has_block, incomplete_storage, value, trie_entry_version))
                },
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(InternalError(err)))
            })?;

        if !has_block {
            return Err(StorageAccessError::UnknownBlock);
        }

        if incomplete_storage {
            return Err(StorageAccessError::IncompleteStorage);
        }

        let Some(value) = value else { return Ok(None) };

        let trie_entry_version = u8::try_from(trie_entry_version.unwrap())
            .map_err(|_| CorruptedError::InvalidTrieEntryVersion)
            .map_err(StorageAccessError::Corrupted)?;
        Ok(Some((value, trie_entry_version)))
    }

    /// Returns the key in the storage that immediately follows or is equal to the key passed as
    /// parameter in the storage of the block.
    ///
    /// `key_nibbles` must be an iterator to the **nibbles** of the key.
    ///
    /// `prefix_nibbles` must be an iterator to nibbles. If the result of the function wouldn't
    /// start with this specific list of bytes, `None` is returned.
    ///
    /// `parent_tries_paths_nibbles` is a list of keys to follow in order to find the root of the
    /// trie into which `key_nibbles` should be searched.
    ///
    /// Returns `None` if `parent_tries_paths_nibbles` didn't lead to any trie, or if there is no
    /// next key.
    ///
    /// The key is returned in the same format as `key_nibbles`.
    ///
    /// If `branch_nodes` is `false`, then branch nodes (i.e. nodes with no value associated to
    /// them) are ignored during the search.
    ///
    /// > **Note**: Contrary to many other similar functions in smoldot, there is no `or_equal`
    /// >           parameter to this function. Instead, `or_equal` is implicitly `true`, and a
    /// >           value of `false` can be easily emulated by appending a `0` at the end
    /// >           of `key_nibbles`.
    ///
    /// # Panics
    ///
    /// Panics if any of the values yielded by `parent_tries_paths_nibbles`, `key_nibbles`, or
    /// `prefix_nibbles` is superior or equal to 16.
    ///
    pub fn block_storage_next_key(
        &self,
        block_hash: &[u8; 32],
        parent_tries_paths_nibbles: impl Iterator<Item = impl Iterator<Item = u8>>,
        key_nibbles: impl Iterator<Item = u8>,
        prefix_nibbles: impl Iterator<Item = u8>,
        branch_nodes: bool,
    ) -> Result<Option<Vec<u8>>, StorageAccessError> {
        // Process the iterators at the very beginning and before locking the database, in order
        // to avoid a deadlock in case the `next()` function of one of the iterators accesses
        // the database as well.
        let parent_tries_paths_nibbles = parent_tries_paths_nibbles
            .flat_map(|t| t.inspect(|n| assert!(*n < 16)).chain(iter::once(0x10)))
            .collect::<Vec<_>>();
        let parent_tries_paths_nibbles_length = parent_tries_paths_nibbles.len();
        let key_nibbles = {
            let mut v = parent_tries_paths_nibbles.clone();
            v.extend(key_nibbles.inspect(|n| assert!(*n < 16)));
            v
        };
        let prefix_nibbles = {
            let mut v = parent_tries_paths_nibbles;
            v.extend(prefix_nibbles.inspect(|n| assert!(*n < 16)));
            v
        };

        let connection = self.database.lock();

        // Sorry for that extremely complicated SQL statement. While the logic isn't actually very
        // complicated, we have to jump through many hoops in order to go around quirks in the
        // SQL language.
        // If you want to work on this SQL code, there is no miracle: write tests, and if a test
        // fails debug the content of `next_key` to find out where the iteration doesn't behave
        // as expected.
        // TODO: this algorithm relies the fact that leaf nodes always have a storage value, which isn't exactly clear in the schema ; however not relying on this makes it way harder to write
        // TODO: trie_root_ref system untested and most likely not working
        // TODO: infinite loop if there's a loop in the trie; detect this
        // TODO: could also check the prefix while iterating instead of only at the very end, which could maybe save many lookups
        let mut statement = connection
            .prepare_cached(
                r#"
            WITH RECURSIVE
                -- We build a temporary table `next_key`, inserting entries one after one as we
                -- descend the trie by trying to match entries with `:key`.
                -- At each iteration, `node_hash` is the root where to continue the search,
                -- `node_is_branch` is true if `node_hash` is a branch node, `node_full_key` is
                -- the key of `node_hash` (that we build along the way) and serves as the final
                -- result, and `key_search_remain` contains the `:key` that remains to be matched.
                -- Can also be NULL to indicate that the search ended because the node necessary to
                -- continue was missing from the database, in which case the values of
                -- `node_hash` and `node_is_branch` have irrelevant values, and the value of
                -- `node_full_key` is the "best known key".
                -- If `:skip_branches` is false, the search ends when `key_search_remain` is null
                -- or empty. If `:skip_branches` is true, the search ends when `key_search_remain`
                -- is null or empty and that `node_is_branch` is false.
                --
                -- `next_key` has zero elements if the block can't be found in the database or if
                -- the trie has no next key at all. These two situations need to be differentiated
                -- in the final SELECT statement.
                --
                -- When encountering a node, we follow both the child that exactly matches `:key`
                -- and also the first child that is strictly superior to `:key`. This is necessary
                -- because `:key` might be equal to something like `ffffffff...`, in which case the
                -- result will be after any equal match.
                -- This means that the number of entries in `next_key` at the end of the recursion
                -- is something like `2 * depth_in_trie(key)`.
                -- In order to obtain the final result, we take the entry in `next_key` with the
                -- minimal `node_full_key` amongst the ones that have finished the search.
                --
                -- Note that in the code below we do a lot of `COALESCE(SUBSTR(...), X'')`. This
                -- is because, for some reason, `SUBSTR(X'', ...)` always produces `NULL`. For this
                -- reason, it is also not possible to automatically pass NULL values
                -- through `SUSBTR`, and we have to use CASE/IIFs instead.
                next_key(node_hash, node_is_branch, node_full_key, key_search_remain) AS (
                        SELECT
                            CASE
                                WHEN trie_node.hash IS NULL
                                    THEN NULL
                                WHEN COALESCE(SUBSTR(:key, 1, LENGTH(trie_node.partial_key)), X'') <= trie_node.partial_key
                                    THEN trie_node.hash
                                ELSE
                                    NULL
                            END,
                            trie_node_storage.value IS NULL AND trie_node_storage.trie_root_ref IS NULL,
                            COALESCE(trie_node.partial_key, X''),
                            CASE
                                WHEN trie_node.partial_key IS NULL
                                    THEN NULL
                                WHEN COALESCE(SUBSTR(:key, 1, LENGTH(trie_node.partial_key)), X'') <= trie_node.partial_key
                                    THEN COALESCE(SUBSTR(:key, 1 + LENGTH(trie_node.partial_key)), X'')
                                ELSE
                                    X''   -- The partial key is strictly inferior to `:key`
                            END
                        FROM blocks
                        LEFT JOIN trie_node ON trie_node.hash = blocks.state_trie_root_hash
                        LEFT JOIN trie_node_storage ON trie_node_storage.node_hash = trie_node.hash
                        WHERE blocks.hash = :block_hash

                    UNION ALL
                        SELECT
                            COALESCE(trie_node.hash, trie_node_trieref.hash),
                            trie_node_storage.value IS NULL AND trie_node_storage.trie_root_ref IS NULL,
                            CASE
                                WHEN trie_node_child.child_num IS NULL
                                    THEN next_key.node_full_key
                                WHEN trie_node.partial_key IS NULL AND trie_node_trieref.partial_key IS NULL
                                    THEN CAST(next_key.node_full_key || trie_node_child.child_num AS BLOB)
                                ELSE
                                    CAST(next_key.node_full_key || trie_node_child.child_num || COALESCE(trie_node.partial_key, trie_node_trieref.partial_key) AS BLOB)
                            END,
                            CASE
                                WHEN trie_node_child.child_num IS NOT NULL AND trie_node.partial_key IS NULL
                                    THEN NULL    -- Child exists but is missing from database
                                WHEN HEX(SUBSTR(next_key.key_search_remain, 1, 1)) = '10' AND trie_node_trieref.hash IS NULL
                                    THEN NULL    -- Trie reference exists but is missing from database
                                WHEN SUBSTR(next_key.key_search_remain, 1, 1) = trie_node_child.child_num AND SUBSTR(next_key.key_search_remain, 2, LENGTH(trie_node.partial_key)) = trie_node.partial_key
                                    THEN SUBSTR(next_key.key_search_remain, 2 + LENGTH(trie_node.partial_key))    -- Equal match, continue iterating
                                WHEN SUBSTR(next_key.key_search_remain, 1, 1) = trie_node_child.child_num AND SUBSTR(next_key.key_search_remain, 2, LENGTH(trie_node.partial_key)) < trie_node.partial_key
                                    THEN X''     -- Searched key is before the node we are iterating to, thus we cut the search short
                                WHEN HEX(SUBSTR(next_key.key_search_remain, 1, 1)) = '10' AND COALESCE(SUBSTR(next_key.key_search_remain, 2, LENGTH(trie_node_trieref.partial_key)), X'') = trie_node_trieref.partial_key
                                    THEN COALESCE(SUBSTR(next_key.key_search_remain, 2 + LENGTH(trie_node_trieref.partial_key)), X'')
                                ELSE
                                    X''          -- Shouldn't be reachable.
                            END
                        FROM next_key

                        LEFT JOIN trie_node_child
                            ON next_key.node_hash = trie_node_child.hash
                            AND CASE WHEN LENGTH(next_key.key_search_remain) = 0 THEN TRUE
                                ELSE SUBSTR(next_key.key_search_remain, 1, 1) <= trie_node_child.child_num END
                        LEFT JOIN trie_node ON trie_node.hash = trie_node_child.child_hash

                        -- We want to keep only situations where `trie_node_child` is either
                        -- equal to the key, or the first child strictly superior to the key. In
                        -- order to do that, we try to find another child that is strictly
                        -- in-between the key and `trie_node_child`. In the `WHERE` clause at the
                        -- bottom, we only keep rows where `trie_node_child_before` is NULL.
                        LEFT JOIN trie_node_child AS trie_node_child_before
                            ON next_key.node_hash = trie_node_child_before.hash
                            AND trie_node_child_before.child_num < trie_node_child.child_num
                            AND (next_key.key_search_remain = X'' OR trie_node_child_before.child_num > SUBSTR(next_key.key_search_remain, 1, 1))

                        LEFT JOIN trie_node_storage AS trie_node_storage_trieref
                            ON HEX(SUBSTR(next_key.key_search_remain, 1, 1)) = '10' AND next_key.node_hash = trie_node_storage_trieref.node_hash AND trie_node_storage_trieref.trie_root_ref IS NOT NULL
                        LEFT JOIN trie_node AS trie_node_trieref
                            ON trie_node_trieref.hash = trie_node_storage_trieref.node_hash
                            AND COALESCE(SUBSTR(next_key.key_search_remain, 2, LENGTH(trie_node_trieref.partial_key)), X'') <= trie_node_trieref.partial_key

                        LEFT JOIN trie_node_storage
                            ON trie_node_storage.node_hash = COALESCE(trie_node.hash, trie_node_trieref.hash)

                        WHERE
                            -- Don't pull items that have already finished searching.
                            next_key.node_hash IS NOT NULL AND next_key.key_search_remain IS NOT NULL AND (next_key.key_search_remain != X'' OR (next_key.node_is_branch AND :skip_branches))
                            -- See explanation above.
                            AND trie_node_child_before.hash IS NULL
                            -- Don't generate an item if there's nowhere to go to.
                            AND (HEX(SUBSTR(next_key.key_search_remain, 1, 1)) = '10' OR trie_node_child.child_num IS NOT NULL)
                            -- Stop iterating if the child's partial key is before the searched key.
                            AND (trie_node.hash IS NULL OR NOT (COALESCE(SUBSTR(next_key.key_search_remain, 1, 1), X'') = trie_node_child.child_num AND COALESCE(SUBSTR(next_key.key_search_remain, 2, LENGTH(trie_node.partial_key)), X'') > trie_node.partial_key))
                ),

                -- Now keep only the entries of `next_key` which have finished iterating.
                terminal_next_key(incomplete_storage, node_full_key, output) AS (
                    SELECT
                        CASE
                            WHEN COALESCE(SUBSTR(node_full_key, 1, LENGTH(:prefix)), X'') != :prefix THEN FALSE
                            ELSE key_search_remain IS NULL
                        END,
                        node_full_key,
                        CASE
                            WHEN node_hash IS NULL THEN NULL
                            WHEN COALESCE(SUBSTR(node_full_key, 1, LENGTH(:prefix)), X'') = :prefix THEN node_full_key
                            ELSE NULL
                        END
                    FROM next_key
                    WHERE key_search_remain IS NULL OR (LENGTH(key_search_remain) = 0 AND (NOT :skip_branches OR NOT node_is_branch))
                )

            SELECT
                COUNT(blocks.hash) >= 1,
                COALESCE(terminal_next_key.incomplete_storage, FALSE),
                terminal_next_key.output
            FROM blocks
            LEFT JOIN terminal_next_key
            WHERE blocks.hash = :block_hash
                -- We pick the entry of `terminal_next_key` with the smallest full key. Note that
                -- it might seem like a good idea to not using any GROUP BY and instead just do
                -- `ORDER BY node_full_key ASC LIMIT 1`, but doing so sometimes leads to SQLite
                -- not picking the entry with the smallest full key for a reason I couldn't
                -- figure out.
                AND (terminal_next_key.node_full_key IS NULL OR terminal_next_key.node_full_key = (SELECT MIN(node_full_key) FROM terminal_next_key))
            LIMIT 1"#,
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(
                    InternalError(err),
                ))
            })?;

        // In order to debug the SQL query above (for example in case of a failing test),
        // uncomment this block:
        //
        /*println!("{:?}", {
            let mut statement = connection
                    .prepare_cached(
                        r#"
                    WITH RECURSIVE
                        copy-paste the definition of next_key here

                    SELECT * FROM next_key"#).unwrap();
            statement
                .query_map(
                    rusqlite::named_params! {
                        ":block_hash": &block_hash[..],
                        ":key": key_nibbles,
                        //":prefix": prefix_nibbles,
                        ":skip_branches": !branch_nodes
                    },
                    |row| {
                        let node_hash = row.get::<_, Option<Vec<u8>>>(0)?.map(hex::encode);
                        let node_is_branch = row.get::<_, Option<i64>>(1)?.map(|n| n != 0);
                        let node_full_key = row.get::<_, Option<Vec<u8>>>(2)?;
                        let search_remain = row.get::<_, Option<Vec<u8>>>(3)?;
                        Ok((node_hash, node_is_branch, node_full_key, search_remain))
                    },
                )
                .unwrap()
                .collect::<Vec<_>>()
        });*/

        let result = statement
            .query_row(
                rusqlite::named_params! {
                    ":block_hash": &block_hash[..],
                    ":key": key_nibbles,
                    ":prefix": prefix_nibbles,
                    ":skip_branches": !branch_nodes
                },
                |row| {
                    let block_is_known = row.get::<_, i64>(0)? != 0;
                    let incomplete_storage = row.get::<_, i64>(1)? != 0;
                    let next_key = row.get::<_, Option<Vec<u8>>>(2)?;
                    Ok((block_is_known, incomplete_storage, next_key))
                },
            )
            .optional()
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(InternalError(err)))
            })?;

        let Some((block_is_known, incomplete_storage, mut next_key)) = result else {
            return Ok(None);
        };

        if !block_is_known {
            return Err(StorageAccessError::UnknownBlock);
        }

        if incomplete_storage {
            return Err(StorageAccessError::IncompleteStorage);
        }

        if parent_tries_paths_nibbles_length != 0 {
            next_key = next_key.map(|nk| nk[parent_tries_paths_nibbles_length..].to_vec());
        }

        Ok(next_key)
    }

    /// Returns the Merkle value of the trie node in the storage that is the closest descendant
    /// of the provided key.
    ///
    /// `key_nibbles` must be an iterator to the **nibbles** of the key.
    ///
    /// `parent_tries_paths_nibbles` is a list of keys to follow in order to find the root of the
    /// trie into which `key_nibbles` should be searched.
    ///
    /// Returns `None` if `parent_tries_paths_nibbles` didn't lead to any trie, or if there is no
    /// such descendant.
    ///
    /// # Panics
    ///
    /// Panics if any of the values yielded by `parent_tries_paths_nibbles` or `key_nibbles` is
    /// superior or equal to 16.
    ///
    pub fn block_storage_closest_descendant_merkle_value(
        &self,
        block_hash: &[u8; 32],
        parent_tries_paths_nibbles: impl Iterator<Item = impl Iterator<Item = u8>>,
        key_nibbles: impl Iterator<Item = u8>,
    ) -> Result<Option<Vec<u8>>, StorageAccessError> {
        // Process the iterators at the very beginning and before locking the database, in order
        // to avoid a deadlock in case the `next()` function of one of the iterators accesses
        // the database as well.
        let key_vectored = parent_tries_paths_nibbles
            .flat_map(|t| t.inspect(|n| assert!(*n < 16)).chain(iter::once(0x10)))
            .chain(key_nibbles.inspect(|n| assert!(*n < 16)))
            .collect::<Vec<_>>();

        let connection = self.database.lock();

        // TODO: trie_root_ref system untested
        // TODO: infinite loop if there's a loop in the trie; detect this
        let mut statement = connection
            .prepare_cached(
                r#"
            WITH RECURSIVE
                -- At the end of the recursive statement, `closest_descendant` must always contain
                -- at most one item where `search_remain` is either empty or null. Empty
                -- indicates that we have found a match, while null means that the search has
                -- been interrupted due to a storage entry not being in the database. If
                -- `search_remain` is null, then `node_hash` is irrelevant.
                -- If `closest_descendant` doesn't have any entry where `search_remain` is empty
                -- or null, then the request key doesn't have any descendant.
                closest_descendant(node_hash, search_remain) AS (
                    SELECT
                            blocks.state_trie_root_hash,
                            CASE
                                WHEN trie_node.partial_key IS NULL AND LENGTH(:key) = 0
                                    THEN X''   -- Trie root node isn't in database, but since key is empty we have a match anyway
                                WHEN trie_node.partial_key IS NULL AND LENGTH(:key) != 0
                                    THEN NULL  -- Trie root node isn't in database and we can't iterate further
                                ELSE
                                    COALESCE(SUBSTR(:key, 1 + LENGTH(trie_node.partial_key)), X'')
                            END
                        FROM blocks
                        LEFT JOIN trie_node ON blocks.state_trie_root_hash = trie_node.hash
                        WHERE blocks.hash = :block_hash
                            AND (
                                trie_node.partial_key IS NULL
                                OR COALESCE(SUBSTR(trie_node.partial_key, 1, LENGTH(:key)), X'') = :key
                                OR COALESCE(SUBSTR(:key, 1, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key
                            )

                    UNION ALL
                    SELECT
                            COALESCE(trie_node_child.child_hash, trie_node_storage.trie_root_ref),
                            CASE
                                WHEN trie_node_child.child_hash IS NULL AND HEX(SUBSTR(closest_descendant.search_remain, 1, 1)) != '10'
                                    THEN X''      -- No child matching the key.
                                WHEN trie_node_child.child_hash IS NOT NULL AND trie_node.hash IS NULL AND LENGTH(closest_descendant.search_remain) = 1
                                    THEN X''      -- Descendant node not in trie but we know that it's the result.
                                WHEN trie_node_child.child_hash IS NOT NULL AND trie_node.hash IS NULL
                                    THEN NULL     -- Descendant node not in trie.
                                WHEN COALESCE(SUBSTR(trie_node.partial_key, 1, LENGTH(closest_descendant.search_remain) - 1), X'') = COALESCE(SUBSTR(closest_descendant.search_remain, 2), X'')
                                        OR COALESCE(SUBSTR(closest_descendant.search_remain, 2, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key
                                    THEN SUBSTR(closest_descendant.search_remain, 2 + LENGTH(trie_node.partial_key))
                                ELSE
                                    X''           -- Unreachable.
                            END
                        FROM closest_descendant
                        LEFT JOIN trie_node_child ON closest_descendant.node_hash = trie_node_child.hash
                            AND SUBSTR(closest_descendant.search_remain, 1, 1) = trie_node_child.child_num
                        LEFT JOIN trie_node ON trie_node.hash = trie_node_child.child_hash
                        LEFT JOIN trie_node_storage
                            ON closest_descendant.node_hash = trie_node_storage.node_hash
                            AND HEX(SUBSTR(closest_descendant.search_remain, 1, 1)) = '10'
                            AND trie_node_storage.trie_root_ref IS NOT NULL
                        WHERE
                            LENGTH(closest_descendant.search_remain) >= 1
                            AND (
                                trie_node.hash IS NULL
                                OR COALESCE(SUBSTR(trie_node.partial_key, 1, LENGTH(closest_descendant.search_remain) - 1), X'') = COALESCE(SUBSTR(closest_descendant.search_remain, 2), X'')
                                OR COALESCE(SUBSTR(closest_descendant.search_remain, 2, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key
                            )
                )
            SELECT COUNT(blocks.hash) >= 1, closest_descendant.node_hash IS NOT NULL AND closest_descendant.search_remain IS NULL, closest_descendant.node_hash
            FROM blocks
            LEFT JOIN closest_descendant ON LENGTH(closest_descendant.search_remain) = 0 OR closest_descendant.search_remain IS NULL
            WHERE blocks.hash = :block_hash
            LIMIT 1"#,
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(
                    InternalError(err),
                ))
            })?;

        // In order to debug the SQL query above (for example in case of a failing test),
        // uncomment this block:
        //
        /*println!("{:?}", {
            let mut statement = connection
                    .prepare_cached(
                        r#"
                    WITH RECURSIVE
                        copy-paste the definition of closest_descendant here

                    SELECT * FROM closest_descendant"#).unwrap();
            statement
                .query_map(
                    rusqlite::named_params! {
                        ":block_hash": &block_hash[..],
                        ":key": key_vectored,
                    },
                    |row| {
                        let node_hash = row.get::<_, Option<Vec<u8>>>(0)?.map(hex::encode);
                        let search_remain = row.get::<_, Option<Vec<u8>>>(1)?;
                        Ok((node_hash, search_remain))
                    },
                )
                .unwrap()
                .collect::<Vec<_>>()
        });*/

        let (has_block, incomplete_storage, merkle_value) = statement
            .query_row(
                rusqlite::named_params! {
                    ":block_hash": &block_hash[..],
                    ":key": key_vectored,
                },
                |row| {
                    let has_block = row.get::<_, i64>(0)? != 0;
                    let incomplete_storage = row.get::<_, i64>(1)? != 0;
                    let merkle_value = row.get::<_, Option<Vec<u8>>>(2)?;
                    Ok((has_block, incomplete_storage, merkle_value))
                },
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(InternalError(err)))
            })?;

        if !has_block {
            return Err(StorageAccessError::UnknownBlock);
        }

        if incomplete_storage {
            return Err(StorageAccessError::IncompleteStorage);
        }

        Ok(merkle_value)
    }

    /// Inserts a block in the database and sets it as the finalized block.
    ///
    /// The parent of the block doesn't need to be present in the database.
    ///
    /// If the block is already in the database, it is replaced by the one provided.
    pub fn reset<'a>(
        &self,
        finalized_block_header: &[u8],
        finalized_block_body: impl ExactSizeIterator<Item = &'a [u8]>,
        finalized_block_justification: Option<Vec<u8>>,
    ) -> Result<(), CorruptedError> {
        // Start a transaction to insert everything in one go.
        let mut database = self.database.lock();
        let transaction = database
            .transaction()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        // Temporarily disable foreign key checks in order to make the initial insertion easier,
        // as we don't have to make sure that trie nodes are sorted.
        // Note that this is immediately disabled again when we `COMMIT`.
        transaction
            .execute("PRAGMA defer_foreign_keys = ON", ())
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        let finalized_block_hash = header::hash_from_scale_encoded_header(finalized_block_header);
        // TODO: this module shouldn't decode blocks
        let decoded = header::decode(finalized_block_header, self.block_number_bytes).unwrap();

        transaction
            .prepare_cached(
                "INSERT OR REPLACE INTO blocks(hash, parent_hash, state_trie_root_hash, number, header, is_best_chain, justification) VALUES(?, ?, ?, ?, ?, TRUE, ?)",
            )
            .unwrap()
            .execute((
                &finalized_block_hash[..],
                if decoded.number != 0 {
                    Some(&decoded.parent_hash[..])
                } else { None },
                &decoded.state_root[..],
                i64::try_from(decoded.number).unwrap(),
                finalized_block_header,
                finalized_block_justification.as_deref(),
            ))
            .unwrap();

        transaction
            .execute(
                "DELETE FROM blocks_body WHERE hash = ?",
                (&finalized_block_hash[..],),
            )
            .unwrap();

        {
            let mut statement = transaction
                .prepare_cached(
                    "INSERT OR IGNORE INTO blocks_body(hash, idx, extrinsic) VALUES(?, ?, ?)",
                )
                .unwrap();
            for (index, item) in finalized_block_body.enumerate() {
                statement
                    .execute((
                        &finalized_block_hash[..],
                        i64::try_from(index).unwrap(),
                        item,
                    ))
                    .unwrap();
            }
        }

        meta_set_blob(&transaction, "best", &finalized_block_hash[..]).unwrap();
        meta_set_number(&transaction, "finalized", decoded.number)?;

        transaction
            .commit()
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

        Ok(())
    }
}

impl fmt::Debug for SqliteFullDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SqliteFullDatabase").finish()
    }
}

impl Drop for SqliteFullDatabase {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            // The SQLite documentation recommends running `PRAGMA optimize` when the database
            // closes.
            // TODO: it is also recommended to do this every 2 hours
            let _ = self.database.get_mut().execute("PRAGMA optimize", ());
        }
    }
}

/// See [`SqliteFullDatabase::finalized_and_above_missing_trie_nodes_unordered`].
#[derive(Debug)]
pub struct MissingTrieNode {
    /// Blocks the trie node is known to belong to.
    ///
    /// Guaranteed to never be empty.
    ///
    /// Only contains blocks whose number is superior or equal to the latest finalized block
    /// number.
    pub blocks: Vec<MissingTrieNodeBlock>,
    /// Hash of the missing trie node.
    pub trie_node_hash: [u8; 32],
}

/// See [`MissingTrieNode::blocks`].
#[derive(Debug)]
pub struct MissingTrieNodeBlock {
    /// Hash of the block.
    pub hash: [u8; 32],
    /// Height of the block.
    pub number: u64,
    /// Path of the parent tries leading to the trie node.
    pub parent_tries_paths_nibbles: Vec<Vec<u8>>,
    /// Nibbles that compose the key of the trie node.
    pub trie_node_key_nibbles: Vec<u8>,
}

pub struct InsertTrieNode<'a> {
    pub merkle_value: Cow<'a, [u8]>,
    pub partial_key_nibbles: Cow<'a, [u8]>,
    pub children_merkle_values: [Option<Cow<'a, [u8]>>; 16],
    pub storage_value: InsertTrieNodeStorageValue<'a>,
}

pub enum InsertTrieNodeStorageValue<'a> {
    NoValue,
    Value {
        value: Cow<'a, [u8]>,
        /// If `true`, the value is equal to the Merkle value of the root of another trie.
        references_merkle_value: bool,
    },
}

/// Error while calling [`SqliteFullDatabase::insert`].
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum InsertError {
    /// Error accessing the database.
    #[display(fmt = "{_0}")]
    Corrupted(CorruptedError),
    /// Block was already in the database.
    Duplicate,
    /// Error when decoding the header to import.
    #[display(fmt = "Failed to decode header: {_0}")]
    BadHeader(header::Error),
    /// Parent of the block to insert isn't in the database.
    MissingParent,
    /// The new best block would be outside of the finalized chain.
    BestNotInFinalizedChain,
}

/// Error while calling [`SqliteFullDatabase::set_finalized`].
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum SetFinalizedError {
    /// Error accessing the database.
    Corrupted(CorruptedError),
    /// New finalized block isn't in the database.
    UnknownBlock,
    /// New finalized block must be a child of the previous finalized block.
    RevertForbidden,
}

/// Error while accessing the storage of the finalized block.
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum StorageAccessError {
    /// Error accessing the database.
    Corrupted(CorruptedError),
    /// Some trie nodes of the storage of the requested block hash are missing.
    IncompleteStorage,
    /// Requested block couldn't be found in the database.
    UnknownBlock,
}

/// Error in the content of the database.
// TODO: document and see if any entry is unused
#[derive(Debug, derive_more::Display)]
pub enum CorruptedError {
    /// Block numbers are expected to be 64 bits.
    // TODO: remove this and use stronger schema
    InvalidNumber,
    /// Finalized block number stored in the database doesn't match any block.
    InvalidFinalizedNum,
    /// A block hash is expected to be 32 bytes. This isn't the case.
    InvalidBlockHashLen,
    /// A trie hash is expected to be 32 bytes. This isn't the case.
    InvalidTrieHashLen,
    /// Values in the database are all well-formatted, but are incoherent.
    #[display(fmt = "Invalid chain information: {_0}")]
    InvalidChainInformation(chain_information::ValidityError),
    /// The parent of a block in the database couldn't be found in that same database.
    BrokenChain,
    /// Missing a key in the `meta` table.
    MissingMetaKey,
    /// Some parts of the database refer to a block by its hash, but the block's constituents
    /// couldn't be found.
    MissingBlockHeader,
    /// The header of a block in the database has failed to decode.
    #[display(fmt = "Corrupted block header: {_0}")]
    BlockHeaderCorrupted(header::Error),
    /// Multiple different consensus algorithms are mixed within the database.
    ConsensusAlgorithmMix,
    /// The information about a Babe epoch found in the database has failed to decode.
    InvalidBabeEpochInformation,
    /// The version information about a storage entry has failed to decode.
    InvalidTrieEntryVersion,
    #[display(fmt = "Internal error: {_0}")]
    Internal(InternalError),
}

/// Low-level database error, such as an error while accessing the file system.
#[derive(Debug, derive_more::Display)]
pub struct InternalError(rusqlite::Error);

fn meta_get_blob(
    database: &rusqlite::Connection,
    key: &str,
) -> Result<Option<Vec<u8>>, CorruptedError> {
    let value = database
        .prepare_cached(r#"SELECT value_blob FROM meta WHERE key = ?"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_row((key,), |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    Ok(value)
}

fn meta_get_number(
    database: &rusqlite::Connection,
    key: &str,
) -> Result<Option<u64>, CorruptedError> {
    let value = database
        .prepare_cached(r#"SELECT value_number FROM meta WHERE key = ?"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_row((key,), |row| row.get::<_, i64>(0))
        .optional()
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    Ok(value.map(|value| u64::from_ne_bytes(value.to_ne_bytes())))
}

fn meta_set_blob(
    database: &rusqlite::Connection,
    key: &str,
    value: &[u8],
) -> Result<(), CorruptedError> {
    database
        .prepare_cached(r#"INSERT OR REPLACE INTO meta(key, value_blob) VALUES (?, ?)"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute((key, value))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    Ok(())
}

fn meta_set_number(
    database: &rusqlite::Connection,
    key: &str,
    value: u64,
) -> Result<(), CorruptedError> {
    database
        .prepare_cached(r#"INSERT OR REPLACE INTO meta(key, value_number) VALUES (?, ?)"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute((key, i64::from_ne_bytes(value.to_ne_bytes())))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    Ok(())
}

fn has_block(database: &rusqlite::Connection, hash: &[u8]) -> Result<bool, CorruptedError> {
    database
        .prepare_cached(r#"SELECT COUNT(*) FROM blocks WHERE hash = ?"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_row((hash,), |row| Ok(row.get_unwrap::<_, i64>(0) != 0))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))
}

// TODO: the fact that the meta table stores blobs makes it impossible to use joins ; fix that
fn finalized_num(database: &rusqlite::Connection) -> Result<u64, CorruptedError> {
    meta_get_number(database, "finalized")?.ok_or(CorruptedError::MissingMetaKey)
}

fn finalized_hash(database: &rusqlite::Connection) -> Result<[u8; 32], CorruptedError> {
    let value = database
        .prepare_cached(r#"SELECT hash FROM blocks WHERE number = (SELECT value_number FROM meta WHERE key = "finalized")"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_row((), |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .ok_or(CorruptedError::InvalidFinalizedNum)?;

    if value.len() == 32 {
        let mut out = [0; 32];
        out.copy_from_slice(&value);
        Ok(out)
    } else {
        Err(CorruptedError::InvalidBlockHashLen)
    }
}

fn block_hashes_by_number(
    database: &rusqlite::Connection,
    number: u64,
) -> Result<Vec<[u8; 32]>, CorruptedError> {
    let number = match i64::try_from(number) {
        Ok(n) => n,
        Err(_) => return Ok(Vec::new()),
    };

    database
        .prepare_cached(r#"SELECT hash FROM blocks WHERE number = ?"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_map((number,), |row| row.get::<_, Vec<u8>>(0))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .map(|value| {
            let value = value.map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            <[u8; 32]>::try_from(&value[..]).map_err(|_| CorruptedError::InvalidBlockHashLen)
        })
        .collect::<Result<Vec<_>, _>>()
}

fn block_header(
    database: &rusqlite::Connection,
    hash: &[u8; 32],
) -> Result<Option<Vec<u8>>, CorruptedError> {
    database
        .prepare_cached(r#"SELECT header FROM blocks WHERE hash = ?"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_row((&hash[..],), |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .map_err(|err| CorruptedError::Internal(InternalError(err)))
}

fn set_best_chain(
    database: &rusqlite::Connection,
    new_best_block_hash: &[u8],
) -> Result<(), CorruptedError> {
    // TODO: can this not be embedded in the SQL statement below?
    let current_best = meta_get_blob(database, "best")?.ok_or(CorruptedError::MissingMetaKey)?;

    // TODO: untested except in the most basic situation
    // In the SQL below, the temporary table `changes` is built by walking down (highest to lowest
    // block number) the new best chain and old best chain. While walking down, the iteration
    // keeps track of the block hashes and their number. If the new best chain has a higher number
    // than the old best chain, then only the new best chain is iterated, and vice versa. If the
    // new and old best chain have the same number, they are both iterated, and it is possible to
    // compare the block hashes in order to know when to stop iterating. In the context of this
    // algorithm, a `NULL` block hash represents "one past the new/old best block", which allows
    // to not include the new/old best block in the temporary table until it needs to be included.
    database
        .prepare_cached(
            r#"
        WITH RECURSIVE
            changes(block_to_include, block_to_retract, block_to_include_number, block_to_retract_number) AS (
                SELECT NULL, NULL, blocks_inc.number + 1, blocks_ret.number + 1
                FROM blocks AS blocks_inc, blocks as blocks_ret
                WHERE blocks_inc.hash = :new_best AND blocks_ret.hash = :current_best
            UNION ALL
                SELECT
                    CASE WHEN changes.block_to_include_number >= changes.block_to_retract_number THEN
                        COALESCE(blocks_inc.parent_hash, :new_best)
                    ELSE
                        changes.block_to_include
                    END,
                    CASE WHEN changes.block_to_retract_number >= changes.block_to_include_number THEN
                        COALESCE(blocks_ret.parent_hash, :current_best)
                    ELSE
                        changes.block_to_retract
                    END,
                    CASE WHEN changes.block_to_include_number >= block_to_retract_number THEN changes.block_to_include_number - 1
                    ELSE changes.block_to_include_number END,
                    CASE WHEN changes.block_to_retract_number >= changes.block_to_include_number THEN changes.block_to_retract_number - 1
                    ELSE changes.block_to_retract_number END
                FROM changes
                LEFT JOIN blocks AS blocks_inc ON blocks_inc.hash = changes.block_to_include
                LEFT JOIN blocks AS blocks_ret ON blocks_ret.hash = changes.block_to_retract
                WHERE changes.block_to_include_number != changes.block_to_retract_number
                    OR COALESCE(blocks_inc.parent_hash, :new_best) != COALESCE(blocks_ret.parent_hash, :current_best)
            )
        UPDATE blocks SET is_best_chain = (blocks.hash = changes.block_to_include)
        FROM changes
        WHERE blocks.hash = changes.block_to_include OR blocks.hash = changes.block_to_retract;
            "#,
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute(rusqlite::named_params! {
            ":current_best": current_best,
            ":new_best": new_best_block_hash
        })
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

    meta_set_blob(database, "best", new_best_block_hash)?;
    Ok(())
}

fn purge_block(database: &rusqlite::Connection, hash: &[u8]) -> Result<(), CorruptedError> {
    purge_block_storage(database, hash)?;
    database
        .prepare_cached("DELETE FROM blocks_body WHERE hash = ?")
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute((hash,))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    database
        .prepare_cached("DELETE FROM blocks WHERE hash = ?")
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute((hash,))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    Ok(())
}

fn purge_block_storage(database: &rusqlite::Connection, hash: &[u8]) -> Result<(), CorruptedError> {
    // TODO: untested

    let state_trie_root_hash = database
        .prepare_cached(r#"SELECT state_trie_root_hash FROM blocks WHERE hash = ?"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_row((hash,), |row| row.get::<_, Vec<u8>>(0))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

    database
        .prepare_cached(
            r#"
            UPDATE blocks SET state_trie_root_hash = NULL
            WHERE hash = :block_hash
        "#,
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute(rusqlite::named_params! {
            ":block_hash": hash,
        })
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

    // TODO: doesn't delete everything in the situation where a single node with a merkle value is referenced multiple times from the same trie
    // TODO: currently doesn't follow `trie_root_ref`
    database
        .prepare_cached(r#"
            WITH RECURSIVE
                to_delete(node_hash) AS (
                    SELECT trie_node.hash
                        FROM trie_node
                        LEFT JOIN blocks ON blocks.hash != :block_hash AND blocks.state_trie_root_hash = trie_node.hash
                        LEFT JOIN trie_node_storage ON trie_node_storage.trie_root_ref = trie_node.hash
                        WHERE trie_node.hash = :state_trie_root_hash AND blocks.hash IS NULL AND trie_node_storage.node_hash IS NULL
                    UNION ALL
                    SELECT trie_node_child.child_hash
                        FROM to_delete
                        JOIN trie_node_child ON trie_node_child.hash = to_delete.node_hash
                        LEFT JOIN blocks ON blocks.state_trie_root_hash = trie_node_child.child_hash
                        LEFT JOIN trie_node_storage ON trie_node_storage.trie_root_ref = to_delete.node_hash
                        WHERE blocks.hash IS NULL AND trie_node_storage.node_hash IS NULL
                )
            DELETE FROM trie_node
            WHERE hash IN (SELECT node_hash FROM to_delete)
        "#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute(rusqlite::named_params! {
            ":state_trie_root_hash": &state_trie_root_hash,
            ":block_hash": hash,
        })
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    Ok(())
}
