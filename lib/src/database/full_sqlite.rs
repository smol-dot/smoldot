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

use crate::{chain::chain_information, header, util};

use alloc::borrow::Cow;
use core::{fmt, iter, num::NonZeroU64};
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
    /// [`StorageAccessError::StoragePruned`] error is returned.
    pub fn to_chain_information(
        &self,
        finalized_block_hash: &[u8; 32],
    ) -> Result<chain_information::ValidChainInformation, StorageAccessError> {
        let connection = self.database.lock();
        if finalized_hash(&connection)? != *finalized_block_hash {
            return Err(StorageAccessError::StoragePruned);
        }

        let finalized_block_header = block_header(&connection, finalized_block_hash)?
            .ok_or(CorruptedError::MissingBlockHeader)?;

        let finality = match (
            grandpa_authorities_set_id(&connection)?,
            grandpa_finalized_triggered_authorities(&connection)?,
            grandpa_finalized_scheduled_change(&connection)?,
        ) {
            (
                Some(after_finalized_block_authorities_set_id),
                finalized_triggered_authorities,
                finalized_scheduled_change,
            ) => chain_information::ChainInformationFinality::Grandpa {
                after_finalized_block_authorities_set_id,
                finalized_triggered_authorities,
                finalized_scheduled_change,
            },
            (None, auth, None) if auth.is_empty() => {
                chain_information::ChainInformationFinality::Outsourced
            }
            _ => {
                return Err(StorageAccessError::Corrupted(
                    CorruptedError::ConsensusAlgorithmMix,
                ))
            }
        };

        let consensus = match (
            meta_get_number(&connection, "aura_slot_duration")?,
            meta_get_number(&connection, "babe_slots_per_epoch")?,
            meta_get_blob(&connection, "babe_finalized_next_epoch")?,
        ) {
            (None, Some(slots_per_epoch), Some(finalized_next_epoch)) => {
                let slots_per_epoch = expect_nz_u64(slots_per_epoch)?;
                let finalized_next_epoch_transition =
                    Box::new(decode_babe_epoch_information(&finalized_next_epoch)?);
                let finalized_block_epoch_information =
                    meta_get_blob(&connection, "babe_finalized_epoch")?
                        .map(|v| decode_babe_epoch_information(&v))
                        .transpose()?
                        .map(Box::new);
                chain_information::ChainInformationConsensus::Babe {
                    finalized_block_epoch_information,
                    finalized_next_epoch_transition,
                    slots_per_epoch,
                }
            }
            (Some(slot_duration), None, None) => {
                let slot_duration = expect_nz_u64(slot_duration)?;
                let finalized_authorities_list = aura_finalized_authorities(&connection)?;
                chain_information::ChainInformationConsensus::Aura {
                    finalized_authorities_list,
                    slot_duration,
                }
            }
            (None, None, None) => chain_information::ChainInformationConsensus::Unknown,
            _ => {
                return Err(StorageAccessError::Corrupted(
                    CorruptedError::ConsensusAlgorithmMix,
                ))
            }
        };

        match chain_information::ValidChainInformation::try_from(
            chain_information::ChainInformation {
                finalized_block_header: {
                    let header = header::decode(&finalized_block_header, self.block_number_bytes)
                        .map_err(CorruptedError::BlockHeaderCorrupted)
                        .map_err(StorageAccessError::Corrupted)?;
                    Box::new(header.into())
                },
                consensus,
                finality,
            },
        ) {
            Ok(ci) => Ok(ci),
            Err(err) => Err(StorageAccessError::Corrupted(
                CorruptedError::InvalidChainInformation(err),
            )),
        }
    }

    /// Insert a new block in the database.
    ///
    /// Must pass the header and body of the block, and the changes to the storage that this block
    /// performs relative to its parent.
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
        new_trie_nodes: impl Iterator<Item = InsertTrieNode<'a>>,
        trie_entries_version: u8,
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

        // Temporarily disable foreign key checks in order to make the insertion easier, as we
        // don't have to make sure that trie nodes are sorted.
        // Note that this is immediately disabled again when we `COMMIT` later down below.
        transaction
            .execute("PRAGMA defer_foreign_keys = ON", ())
            .map_err(|err| InsertError::Corrupted(CorruptedError::Internal(InternalError(err))))?;

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

        // Insert the changes in trie nodes.
        insert_storage(
            &transaction,
            Some(&header.parent_hash[..]),
            new_trie_nodes,
            trie_entries_version,
        )
        .map_err(InsertError::Corrupted)?;

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

        // Now update the finalized block storage.
        for height in current_finalized + 1..=new_finalized_header.number {
            let block_hash = {
                let list = block_hashes_by_number(&transaction, height)?;
                debug_assert_eq!(list.len(), 1);
                list.into_iter().next().ok_or(SetFinalizedError::Corrupted(
                    CorruptedError::MissingBlockHeader,
                ))?
            };

            let block_header = block_header(&transaction, &block_hash)?.ok_or(
                SetFinalizedError::Corrupted(CorruptedError::MissingBlockHeader),
            )?;
            let block_header = header::decode(&block_header, self.block_number_bytes)
                .map_err(CorruptedError::BlockHeaderCorrupted)
                .map_err(SetFinalizedError::Corrupted)?;

            // TODO: the code below is very verbose and redundant with other similar code in smoldot ; could be improved

            if let Some((new_epoch, next_config)) = block_header.digest.babe_epoch_information() {
                let epoch = meta_get_blob(&transaction, "babe_finalized_next_epoch")?.unwrap(); // TODO: don't unwrap
                let decoded_epoch = decode_babe_epoch_information(&epoch)?;
                transaction.execute(r#"INSERT OR REPLACE INTO meta(key, value_blob) SELECT "babe_finalized_epoch", value_blob FROM meta WHERE key = "babe_finalized_next_epoch""#, ()).unwrap();

                let slot_number = block_header
                    .digest
                    .babe_pre_runtime()
                    .unwrap()
                    .slot_number();
                let slots_per_epoch =
                    expect_nz_u64(meta_get_number(&transaction, "babe_slots_per_epoch")?.unwrap())?; // TODO: don't unwrap

                let new_epoch = if let Some(next_config) = next_config {
                    chain_information::BabeEpochInformation {
                        epoch_index: decoded_epoch.epoch_index.checked_add(1).unwrap(),
                        start_slot_number: Some(
                            decoded_epoch
                                .start_slot_number
                                .unwrap_or(slot_number)
                                .checked_add(slots_per_epoch.get())
                                .unwrap(),
                        ),
                        authorities: new_epoch.authorities.map(Into::into).collect(),
                        randomness: *new_epoch.randomness,
                        c: next_config.c,
                        allowed_slots: next_config.allowed_slots,
                    }
                } else {
                    chain_information::BabeEpochInformation {
                        epoch_index: decoded_epoch.epoch_index.checked_add(1).unwrap(),
                        start_slot_number: Some(
                            decoded_epoch
                                .start_slot_number
                                .unwrap_or(slot_number)
                                .checked_add(slots_per_epoch.get())
                                .unwrap(),
                        ),
                        authorities: new_epoch.authorities.map(Into::into).collect(),
                        randomness: *new_epoch.randomness,
                        c: decoded_epoch.c,
                        allowed_slots: decoded_epoch.allowed_slots,
                    }
                };

                meta_set_blob(
                    &transaction,
                    "babe_finalized_next_epoch",
                    &encode_babe_epoch_information(From::from(&new_epoch)),
                )?;
            }

            // TODO: implement Aura

            if grandpa_authorities_set_id(&transaction)?.is_some() {
                for grandpa_digest_item in block_header.digest.logs().filter_map(|d| match d {
                    header::DigestItemRef::GrandpaConsensus(gp) => Some(gp),
                    _ => None,
                }) {
                    // TODO: implement items other than ScheduledChange
                    if let header::GrandpaConsensusLogRef::ScheduledChange(change) =
                        grandpa_digest_item
                    {
                        assert_eq!(change.delay, 0); // TODO: not implemented if != 0

                        transaction
                            .execute("DELETE FROM grandpa_triggered_authorities", ())
                            .unwrap();

                        let mut statement = transaction.prepare_cached("INSERT INTO grandpa_triggered_authorities(idx, public_key, weight) VALUES(?, ?, ?)").unwrap();
                        for (index, item) in change.next_authorities.enumerate() {
                            statement
                                .execute((
                                    i64::try_from(index).unwrap(),
                                    &item.public_key[..],
                                    i64::from_ne_bytes(item.weight.get().to_ne_bytes()),
                                ))
                                .unwrap();
                        }

                        transaction.execute(r#"UPDATE meta SET value_number = value_number + 1 WHERE key = "grandpa_authorities_set_id""#, ()).unwrap();
                    }
                }
            }
        }

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
        let connection = self.database.lock();

        // TODO: could be optimized by having a different request when `parent_tries_paths_nibbles` is empty and when it isn't
        // TODO: trie_root_ref system untested
        let mut statement = connection
            .prepare_cached(
                r#"
            WITH RECURSIVE
                node_with_key(node_hash, search_remain) AS (
                    SELECT trie_node.hash, COALESCE(SUBSTR(:key, 1 + LENGTH(trie_node.partial_key)), X'')
                        FROM blocks, trie_node
                        WHERE blocks.hash = :block_hash AND blocks.state_trie_root_hash = trie_node.hash AND COALESCE(SUBSTR(:key, 1, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key
                    UNION ALL
                    SELECT COALESCE(trie_node.hash, trie_node_storage.trie_root_ref), COALESCE(SUBSTR(node_with_key.search_remain, 2 + LENGTH(trie_node.partial_key)), SUBSTR(node_with_key.search_remain, 1))
                        FROM node_with_key
                        LEFT JOIN trie_node_child ON node_with_key.node_hash = trie_node_child.hash AND SUBSTR(node_with_key.search_remain, 1, 1) = trie_node_child.child_num
                        LEFT JOIN trie_node ON trie_node.hash = trie_node_child.child_hash AND SUBSTR(node_with_key.search_remain, 2, LENGTH(trie_node.partial_key)) = trie_node.partial_key
                        LEFT JOIN trie_node_storage ON node_with_key.node_hash = trie_node_storage.node_hash AND trie_node_storage.trie_root_ref IS NOT NULL AND HEX(SUBSTR(node_with_key.search_remain, 1, 1)) = '10'
                        WHERE LENGTH(node_with_key.search_remain) >= 1 AND (trie_node.hash IS NOT NULL OR trie_node_storage.trie_root_ref IS NOT NULL)
                )
            SELECT COUNT(blocks.hash) >= 1, COUNT(trie_node.hash) >= 1, COALESCE(trie_node_storage.value, trie_node_storage.trie_root_ref), trie_node_storage.trie_entry_version
            FROM blocks
            LEFT JOIN trie_node ON trie_node.hash = blocks.state_trie_root_hash
            LEFT JOIN node_with_key ON LENGTH(node_with_key.search_remain) = 0
            LEFT JOIN trie_node_storage ON node_with_key.node_hash = trie_node_storage.node_hash
            WHERE blocks.hash = :block_hash;
            "#)
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(
                    InternalError(err),
                ))
            })?;

        let key_vectored = parent_tries_paths_nibbles
            .flat_map(|t| t.inspect(|n| assert!(*n < 16)).chain(iter::once(0x10)))
            .chain(key_nibbles.inspect(|n| assert!(*n < 16)))
            .collect::<Vec<_>>();

        let (has_block, block_has_storage, value, trie_entry_version) = statement
            .query_row(
                rusqlite::named_params! {
                    ":block_hash": &block_hash[..],
                    ":key": key_vectored,
                },
                |row| {
                    let has_block = row.get::<_, i64>(0)? != 0;
                    let block_has_storage = row.get::<_, i64>(1)? != 0;
                    let value = row.get::<_, Option<Vec<u8>>>(2)?;
                    let trie_entry_version = row.get::<_, Option<i64>>(3)?;
                    Ok((has_block, block_has_storage, value, trie_entry_version))
                },
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(InternalError(err)))
            })?;

        if !has_block {
            return Err(StorageAccessError::UnknownBlock);
        }

        if !block_has_storage {
            return Err(StorageAccessError::StoragePruned);
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
        let connection = self.database.lock();

        // TODO: this algorithm relies the fact that leaf nodes always have a storage value, which isn't exactly clear in the schema ; however not relying on this makes it way harder to write
        // TODO: trie_root_ref system untested and most likely not working
        let mut statement = connection
            .prepare_cached(
                r#"
            WITH RECURSIVE
                next_key(node_hash, node_is_branch, node_full_key, search_remain) AS (
                        SELECT
                            trie_node.hash,
                            trie_node_storage.value IS NULL AND trie_node_storage.trie_root_ref IS NULL,
                            trie_node.partial_key,
                            COALESCE(SUBSTR(:key, 1 + LENGTH(trie_node.partial_key)), X'')
                        FROM blocks
                        JOIN trie_node ON blocks.state_trie_root_hash = trie_node.hash
                            AND COALESCE(SUBSTR(:key, 1, LENGTH(trie_node.partial_key)), X'') <= trie_node.partial_key
                        LEFT JOIN trie_node_storage ON trie_node_storage.node_hash = trie_node.hash
                        WHERE blocks.hash = :block_hash
                            AND COALESCE(SUBSTR(trie_node.partial_key, 1, LENGTH(:prefix)), X'') = COALESCE(SUBSTR(:prefix, 1, LENGTH(trie_node.partial_key)), X'')
                    UNION ALL
                        SELECT
                            COALESCE(trie_node.hash, trie_node_trieref.hash),
                            trie_node_storage.value IS NULL AND trie_node_storage.trie_root_ref IS NULL,
                            CAST(next_key.node_full_key || trie_node_child.child_num || COALESCE(trie_node.partial_key, trie_node_trieref.partial_key) AS BLOB)
                                AS node_full_key,
                            CASE SUBSTR(next_key.search_remain, 1, 1) = trie_node_child.child_num AND SUBSTR(next_key.search_remain, 2, LENGTH(trie_node.partial_key)) = trie_node.partial_key
                                WHEN TRUE THEN SUBSTR(next_key.search_remain, 2 + LENGTH(trie_node.partial_key))
                                ELSE CASE HEX(SUBSTR(next_key.search_remain, 1, 1)) = '10' AND COALESCE(SUBSTR(next_key.search_remain, 2, LENGTH(trie_node_trieref.partial_key)), X'') = trie_node_trieref.partial_key
                                    WHEN TRUE THEN COALESCE(SUBSTR(next_key.search_remain, 2 + LENGTH(trie_node_trieref.partial_key)), X'')
                                    ELSE X'' END
                                END
                        FROM next_key

                        LEFT JOIN trie_node_child
                            ON next_key.node_hash = trie_node_child.hash
                            AND CASE LENGTH(next_key.search_remain)
                                WHEN 0 THEN next_key.node_is_branch AND :skip_branches
                                ELSE SUBSTR(next_key.search_remain, 1, 1) <= trie_node_child.child_num END
                        LEFT JOIN trie_node ON trie_node.hash = trie_node_child.child_hash
                            AND CASE SUBSTR(next_key.search_remain, 1, 1) = trie_node_child.child_num
                                WHEN TRUE THEN SUBSTR(next_key.search_remain, 2, LENGTH(trie_node.partial_key)) <= trie_node.partial_key
                                ELSE TRUE END

                        LEFT JOIN trie_node_child AS trie_node_child_before
                            ON next_key.node_hash = trie_node_child_before.hash
                            AND trie_node_child_before.child_num < trie_node_child.child_num
                            AND trie_node_child_before.child_num > SUBSTR(next_key.search_remain, 1, 1)

                        LEFT JOIN trie_node_storage AS trie_node_storage_trieref
                            ON next_key.node_hash = trie_node_storage_trieref.node_hash AND trie_node_storage_trieref.trie_root_ref IS NOT NULL AND HEX(SUBSTR(next_key.search_remain, 1, 1)) = '10'
                        LEFT JOIN trie_node AS trie_node_trieref
                            ON trie_node_trieref.hash = trie_node_storage_trieref.node_hash
                            AND COALESCE(SUBSTR(next_key.search_remain, 2, LENGTH(trie_node_trieref.partial_key)), X'') <= trie_node_trieref.partial_key

                        LEFT JOIN trie_node_storage
                            ON trie_node_storage.node_hash = COALESCE(trie_node.hash, trie_node_trieref.hash)

                        WHERE trie_node_child_before.hash IS NULL
                            AND (trie_node.hash IS NOT NULL OR trie_node_trieref.hash IS NOT NULL)
                            AND COALESCE(SUBSTR(node_full_key, 1, LENGTH(:prefix)), X'') <= COALESCE(SUBSTR(:prefix, 1, LENGTH(node_full_key)), X'')
                )

            SELECT
                COUNT(trie_node.hash) >= 1,
                CASE COALESCE(SUBSTR(MIN(next_key.node_full_key), 1, LENGTH(:prefix)), X'') = :prefix
                    WHEN TRUE THEN MIN(next_key.node_full_key)
                    ELSE NULL END
            FROM blocks
            LEFT JOIN trie_node ON trie_node.hash = blocks.state_trie_root_hash
            LEFT JOIN next_key ON LENGTH(next_key.search_remain) = 0
            WHERE blocks.hash = :block_hash
            GROUP BY blocks.hash, trie_node.hash
            LIMIT 1"#,
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(
                    InternalError(err),
                ))
            })?;

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

        let result = statement
            .query_row(
                rusqlite::named_params! {
                    ":block_hash": &block_hash[..],
                    ":key": key_nibbles,
                    ":prefix": prefix_nibbles,
                    ":skip_branches": !branch_nodes
                },
                |row| {
                    let block_has_storage = row.get::<_, i64>(0)? != 0;
                    let next_key = row.get::<_, Option<Vec<u8>>>(1)?;
                    Ok((block_has_storage, next_key))
                },
            )
            .optional()
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(InternalError(err)))
            })?;

        let Some((block_has_storage, mut next_key)) = result else {
            return Err(StorageAccessError::UnknownBlock);
        };

        if !block_has_storage {
            return Err(StorageAccessError::StoragePruned);
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
        let connection = self.database.lock();

        // TODO: trie_root_ref system untested
        let mut statement = connection
            .prepare_cached(
                r#"
            WITH RECURSIVE
                closest_descendant(node_hash, search_remain) AS (
                    SELECT trie_node.hash, COALESCE(SUBSTR(:key, 1 + LENGTH(trie_node.partial_key)), X'')
                        FROM blocks, trie_node
                        WHERE blocks.hash = :block_hash AND blocks.state_trie_root_hash = trie_node.hash
                            AND (
                                COALESCE(SUBSTR(trie_node.partial_key, 1, LENGTH(:key)), X'') = :key
                                OR COALESCE(SUBSTR(:key, 1, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key
                            )
                    UNION ALL
                    SELECT
                            COALESCE(trie_node.hash, trie_node_storage.trie_root_ref),
                            COALESCE(SUBSTR(closest_descendant.search_remain, 2 + LENGTH(trie_node.partial_key)), SUBSTR(closest_descendant.search_remain, 1), X'')
                        FROM closest_descendant
                        LEFT JOIN trie_node_child ON closest_descendant.node_hash = trie_node_child.hash
                            AND SUBSTR(closest_descendant.search_remain, 1, 1) = trie_node_child.child_num
                        LEFT JOIN trie_node ON trie_node.hash = trie_node_child.child_hash
                            AND (
                                COALESCE(SUBSTR(trie_node.partial_key, 1, LENGTH(closest_descendant.search_remain) - 1), X'') = COALESCE(SUBSTR(closest_descendant.search_remain, 2), X'')
                                OR COALESCE(SUBSTR(closest_descendant.search_remain, 2, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key
                            )
                        LEFT JOIN trie_node_storage ON closest_descendant.node_hash = trie_node_storage.node_hash AND trie_node_storage.trie_root_ref IS NOT NULL AND HEX(SUBSTR(closest_descendant.search_remain, 1, 1)) = '10'
                        WHERE LENGTH(closest_descendant.search_remain) >= 1 AND (trie_node.hash IS NOT NULL OR trie_node_storage.trie_root_ref IS NOT NULL)
                )
            SELECT COUNT(blocks.hash) >= 1, COUNT(trie_node.hash) >= 1, closest_descendant.node_hash
            FROM blocks
            LEFT JOIN trie_node ON trie_node.hash = blocks.state_trie_root_hash
            LEFT JOIN closest_descendant ON LENGTH(closest_descendant.search_remain) = 0
            WHERE blocks.hash = :block_hash
            LIMIT 1"#,
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(
                    InternalError(err),
                ))
            })?;

        let key_vectored = parent_tries_paths_nibbles
            .flat_map(|t| t.inspect(|n| assert!(*n < 16)).chain(iter::once(0x10)))
            .chain(key_nibbles.inspect(|n| assert!(*n < 16)))
            .collect::<Vec<_>>();

        let (has_block, block_has_storage, merkle_value) = statement
            .query_row(
                rusqlite::named_params! {
                    ":block_hash": &block_hash[..],
                    ":key": key_vectored,
                },
                |row| {
                    let has_block = row.get::<_, i64>(0)? != 0;
                    let block_has_storage = row.get::<_, i64>(1)? != 0;
                    let merkle_value = row.get::<_, Option<Vec<u8>>>(2)?;
                    Ok((has_block, block_has_storage, merkle_value))
                },
            )
            .map_err(|err| {
                StorageAccessError::Corrupted(CorruptedError::Internal(InternalError(err)))
            })?;

        if !has_block {
            return Err(StorageAccessError::UnknownBlock);
        }

        if !block_has_storage {
            return Err(StorageAccessError::StoragePruned);
        }

        Ok(merkle_value)
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
    SameAsParent,
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
    /// Storage of the block hash passed as parameter is no longer in the database.
    StoragePruned,
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

// TODO: foreign keys checks should temporarily be disabled because we insert entries in the wrong order; either clearly document this or solve this programmatically
fn insert_storage<'a>(
    database: &rusqlite::Connection,
    parent_block_hash: Option<&[u8]>,
    new_trie_nodes: impl Iterator<Item = InsertTrieNode<'a>>,
    entries_version: u8,
) -> Result<(), CorruptedError> {
    // Create a temporary table where we store the newly-created trie nodes that must inherit the
    // storage value of the parent block. These trie nodes are processed later.
    database
        .execute(
            r#"
        CREATE TEMPORARY TABLE temp_pending_parent_copies(
            node_hash BLOB NOT NULL PRIMARY KEY
        );
    "#,
            (),
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

    // Create a temporary table where we store the newly-created trie nodes. This is necessary
    // later in order to know how to walk up the path of trie nodes hashes to find the root.
    database
        .execute(
            r#"
        CREATE TEMPORARY TABLE temp_newly_inserted_trie_nodes(
            node_hash BLOB NOT NULL PRIMARY KEY
        );
    "#,
            (),
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

    // TODO: should check whether the existing merkle values that are referenced from inserted nodes exist in the parent's storage
    // TODO: is it correct to have OR IGNORE everywhere?
    let mut insert_node_statement = database
        .prepare_cached("INSERT OR IGNORE INTO trie_node(hash, partial_key) VALUES(?, ?)")
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    let mut insert_temporary_node_statement = database
        .prepare_cached("INSERT OR IGNORE INTO temp_newly_inserted_trie_nodes(node_hash) VALUES(?)")
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    let mut insert_node_storage_statement = database
        .prepare_cached("INSERT OR IGNORE INTO trie_node_storage(node_hash, value, trie_root_ref, trie_entry_version) VALUES(?, ?, ?, ?)")
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    let mut insert_node_storage_copy_statement = database
        .prepare_cached(r#"INSERT OR IGNORE INTO temp_pending_parent_copies(node_hash) VALUES (?)"#)
        .map_err(|err: rusqlite::Error| CorruptedError::Internal(InternalError(err)))?;
    let mut insert_child_statement = database
        .prepare_cached(
            "INSERT OR IGNORE INTO trie_node_child(hash, child_num, child_hash) VALUES(?, ?, ?)",
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    for trie_node in new_trie_nodes {
        assert!(trie_node.partial_key_nibbles.iter().all(|n| *n < 16)); // TODO: document
        insert_temporary_node_statement
            .execute((&trie_node.merkle_value,))
            .map_err(|err: rusqlite::Error| CorruptedError::Internal(InternalError(err)))?;
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
                        entries_version,
                    ))
                    .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            }
            InsertTrieNodeStorageValue::SameAsParent => {
                // TODO: error if parent_block_hash is None

                insert_node_storage_copy_statement
                    .execute((&trie_node.merkle_value,))
                    .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            }
            InsertTrieNodeStorageValue::NoValue => {}
        }
        for (child_num, child) in trie_node.children_merkle_values.iter().enumerate() {
            if let Some(child) = child {
                let child_num = vec![u8::try_from(child_num).unwrap_or_else(|_| unreachable!())];
                insert_child_statement
                    .execute((&trie_node.merkle_value, child_num, child))
                    .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            }
        }
    }

    // For each node in `temp_pending_parent_copies`, determine its full key by walking up the
    // trie, find the corresponding node in the parent block, and copy the value from there.
    // Note that the algorithm below ignores orphan nodes (i.e. trie nodes that aren't connected
    // to the graph), as it is detected above.
    // TODO: not detected above yet ^
    // TODO: consider reference counting the storage values?
    // TODO: DRY with getting a value?
    // TODO: doesn't properly work with feature `trie_root_ref`
    // TODO: will be an infinite loop if trie is recursive, can this happen?
    database
        .prepare_cached(
            r#"
        WITH RECURSIVE
            insertions(node_hash, copy_from_base, copy_from_relative_key) AS (
                SELECT node_hash, node_hash, X'' FROM temp_pending_parent_copies
                UNION ALL
                SELECT insertions.node_hash, COALESCE(temp_newly_inserted_trie_nodes_parent.node_hash, temp_newly_inserted_trie_nodes_ref.node_hash), CAST(COALESCE(trie_node_child.child_num, X'') || trie_node.partial_key || insertions.copy_from_relative_key AS BLOB)
                    FROM insertions
                    JOIN trie_node ON trie_node.hash = insertions.copy_from_base
                    LEFT JOIN trie_node_child ON trie_node_child.child_hash = insertions.copy_from_base
                    LEFT JOIN temp_newly_inserted_trie_nodes AS temp_newly_inserted_trie_nodes_parent ON temp_newly_inserted_trie_nodes_parent.node_hash = trie_node_child.hash
                    LEFT JOIN trie_node_storage ON trie_node_storage.trie_root_ref = insertions.copy_from_base
                    LEFT JOIN temp_newly_inserted_trie_nodes AS temp_newly_inserted_trie_nodes_ref ON temp_newly_inserted_trie_nodes_ref.node_hash = trie_node_storage.node_hash
                    WHERE insertions.copy_from_base IS NOT NULL
                        AND (temp_newly_inserted_trie_nodes_parent.node_hash IS NULL) = (trie_node_child.hash IS NULL)
                        AND (temp_newly_inserted_trie_nodes_ref.node_hash IS NULL) = (trie_node_storage.node_hash IS NULL)
            ),
            node_with_key(node_hash, search_node_hash, search_remain) AS (
                SELECT insertions.node_hash, trie_node.hash, COALESCE(SUBSTR(insertions.copy_from_relative_key, 1 + LENGTH(trie_node.partial_key)), X'')
                    FROM insertions
                    JOIN trie_node ON COALESCE(SUBSTR(insertions.copy_from_relative_key, 1, LENGTH(trie_node.partial_key)), X'') = trie_node.partial_key
                    JOIN blocks ON blocks.hash = :parent_block_hash AND blocks.state_trie_root_hash = trie_node.hash
                    WHERE insertions.copy_from_base IS NULL
                UNION ALL
                SELECT node_with_key.node_hash, trie_node.hash, SUBSTR(node_with_key.search_remain, 2 + LENGTH(trie_node.partial_key))
                    FROM node_with_key
                    JOIN trie_node_child ON node_with_key.search_node_hash = trie_node_child.hash AND SUBSTR(node_with_key.search_remain, 1, 1) = trie_node_child.child_num
                    JOIN trie_node ON trie_node.hash = trie_node_child.child_hash AND SUBSTR(node_with_key.search_remain, 2, LENGTH(trie_node.partial_key)) = trie_node.partial_key
                    WHERE LENGTH(node_with_key.search_remain) >= 1
            )
        INSERT OR IGNORE INTO trie_node_storage(node_hash, value, trie_root_ref, trie_entry_version)
        SELECT node_with_key.node_hash, trie_node_storage.value, trie_node_storage.trie_root_ref, trie_node_storage.trie_entry_version
        FROM node_with_key
        JOIN trie_node_storage ON node_with_key.search_node_hash = trie_node_storage.node_hash
        WHERE LENGTH(node_with_key.search_remain) = 0;
            "#,
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .execute(rusqlite::named_params! {
            ":parent_block_hash": parent_block_hash,
        })
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

    database
        .execute(
            r#"
        DROP TABLE temp_pending_parent_copies;
    "#,
            (),
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;
    database
        .execute(
            r#"
        DROP TABLE temp_newly_inserted_trie_nodes;
    "#,
            (),
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?;

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

fn grandpa_authorities_set_id(
    database: &rusqlite::Connection,
) -> Result<Option<u64>, CorruptedError> {
    meta_get_number(database, "grandpa_authorities_set_id")
}

fn grandpa_finalized_triggered_authorities(
    database: &rusqlite::Connection,
) -> Result<Vec<header::GrandpaAuthority>, CorruptedError> {
    database
        .prepare_cached(
            r#"SELECT public_key, weight FROM grandpa_triggered_authorities ORDER BY idx ASC"#,
        )
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_map((), |row| {
            let pk = row.get::<_, Vec<u8>>(0)?;
            let weight = row.get::<_, i64>(1)?;
            Ok((pk, weight))
        })
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .map(|result| {
            let (public_key, weight) =
                result.map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            let public_key = <[u8; 32]>::try_from(&public_key[..])
                .map_err(|_| CorruptedError::InvalidBlockHashLen)?;
            let weight = NonZeroU64::new(u64::from_ne_bytes(weight.to_ne_bytes()))
                .ok_or(CorruptedError::InvalidNumber)?;
            Ok(header::GrandpaAuthority { public_key, weight })
        })
        .collect::<Result<Vec<_>, _>>()
}

fn grandpa_finalized_scheduled_change(
    database: &rusqlite::Connection,
) -> Result<Option<(u64, Vec<header::GrandpaAuthority>)>, CorruptedError> {
    if let Some(height) = meta_get_number(database, "grandpa_scheduled_target")? {
        // TODO: duplicated from above except different table name
        let out = database
            .prepare_cached(
                r#"SELECT public_key, weight FROM grandpa_scheduled_authorities ORDER BY idx ASC"#,
            )
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .query_map((), |row| {
                let pk = row.get::<_, Vec<u8>>(0)?;
                let weight = row.get::<_, i64>(1)?;
                Ok((pk, weight))
            })
            .map_err(|err| CorruptedError::Internal(InternalError(err)))?
            .map(|result| {
                let (public_key, weight) =
                    result.map_err(|err| CorruptedError::Internal(InternalError(err)))?;
                let public_key = <[u8; 32]>::try_from(&public_key[..])
                    .map_err(|_| CorruptedError::InvalidBlockHashLen)?;
                let weight = NonZeroU64::new(u64::from_ne_bytes(weight.to_ne_bytes()))
                    .ok_or(CorruptedError::InvalidNumber)?;
                Ok(header::GrandpaAuthority { public_key, weight })
            })
            .collect::<Result<Vec<_>, CorruptedError>>()?;

        Ok(Some((height, out)))
    } else {
        Ok(None)
    }
}

fn expect_nz_u64(value: u64) -> Result<NonZeroU64, CorruptedError> {
    NonZeroU64::new(value).ok_or(CorruptedError::InvalidNumber)
}

fn aura_finalized_authorities(
    database: &rusqlite::Connection,
) -> Result<Vec<header::AuraAuthority>, CorruptedError> {
    database
        .prepare_cached(r#"SELECT public_key FROM aura_finalized_authorities ORDER BY idx ASC"#)
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .query_map((), |row| row.get::<_, Vec<u8>>(0))
        .map_err(|err| CorruptedError::Internal(InternalError(err)))?
        .map(|result| {
            let public_key = result.map_err(|err| CorruptedError::Internal(InternalError(err)))?;
            let public_key = <[u8; 32]>::try_from(&public_key[..])
                .map_err(|_| CorruptedError::InvalidBlockHashLen)?;
            Ok(header::AuraAuthority { public_key })
        })
        .collect::<Result<Vec<_>, CorruptedError>>()
}

fn encode_babe_epoch_information(info: chain_information::BabeEpochInformationRef) -> Vec<u8> {
    let mut out = Vec::with_capacity(69 + info.authorities.len() * 40);
    out.extend_from_slice(&info.epoch_index.to_le_bytes());
    if let Some(start_slot_number) = info.start_slot_number {
        out.extend_from_slice(&[1]);
        out.extend_from_slice(&start_slot_number.to_le_bytes());
    } else {
        out.extend_from_slice(&[0]);
    }
    out.extend_from_slice(util::encode_scale_compact_usize(info.authorities.len()).as_ref());
    for authority in info.authorities {
        out.extend_from_slice(authority.public_key);
        out.extend_from_slice(&authority.weight.to_le_bytes());
    }
    out.extend_from_slice(info.randomness);
    out.extend_from_slice(&info.c.0.to_le_bytes());
    out.extend_from_slice(&info.c.1.to_le_bytes());
    out.extend_from_slice(match info.allowed_slots {
        header::BabeAllowedSlots::PrimarySlots => &[0],
        header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots => &[1],
        header::BabeAllowedSlots::PrimaryAndSecondaryVrfSlots => &[2],
    });
    out
}

fn decode_babe_epoch_information(
    value: &[u8],
) -> Result<chain_information::BabeEpochInformation, CorruptedError> {
    let result = nom::combinator::all_consuming(nom::combinator::map(
        nom::sequence::tuple((
            nom::number::streaming::le_u64,
            util::nom_option_decode(nom::number::streaming::le_u64),
            nom::combinator::flat_map(crate::util::nom_scale_compact_usize, |num_elems| {
                nom::multi::many_m_n(
                    num_elems,
                    num_elems,
                    nom::combinator::map(
                        nom::sequence::tuple((
                            nom::bytes::streaming::take(32u32),
                            nom::number::streaming::le_u64,
                        )),
                        move |(public_key, weight)| header::BabeAuthority {
                            public_key: TryFrom::try_from(public_key).unwrap(),
                            weight,
                        },
                    ),
                )
            }),
            nom::bytes::streaming::take(32u32),
            nom::sequence::tuple((
                nom::number::streaming::le_u64,
                nom::number::streaming::le_u64,
            )),
            nom::branch::alt((
                nom::combinator::map(nom::bytes::streaming::tag(&[0]), |_| {
                    header::BabeAllowedSlots::PrimarySlots
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[1]), |_| {
                    header::BabeAllowedSlots::PrimaryAndSecondaryPlainSlots
                }),
                nom::combinator::map(nom::bytes::streaming::tag(&[2]), |_| {
                    header::BabeAllowedSlots::PrimaryAndSecondaryVrfSlots
                }),
            )),
        )),
        |(epoch_index, start_slot_number, authorities, randomness, c, allowed_slots)| {
            chain_information::BabeEpochInformation {
                epoch_index,
                start_slot_number,
                authorities,
                randomness: TryFrom::try_from(randomness).unwrap(),
                c,
                allowed_slots,
            }
        },
    ))(value)
    .map(|(_, v)| v)
    .map_err(|_: nom::Err<nom::error::Error<&[u8]>>| ());

    let result = match result {
        Ok(r) if r.validate().is_ok() => Ok(r),
        Ok(_) | Err(()) => Err(()),
    };

    result.map_err(|()| CorruptedError::InvalidBabeEpochInformation)
}
