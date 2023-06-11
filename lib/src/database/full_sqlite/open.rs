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

//! Database opening code.
//!
//! Contains everything related to the opening and initialization of the database.

// TODO:remove all the unwraps in this module that shouldn't be there

use super::{
    encode_babe_epoch_information, AccessError, CorruptedError, InternalError, SqliteFullDatabase,
};
use crate::{
    chain::chain_information,
    trie::{self, trie_structure},
};

use std::{fs, path::Path};

/// Opens the database using the given [`Config`].
///
/// Note that this doesn't return a [`SqliteFullDatabase`], but rather a [`DatabaseOpen`].
pub fn open(config: Config) -> Result<DatabaseOpen, InternalError> {
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE |
        rusqlite::OpenFlags::SQLITE_OPEN_CREATE |
        // The "no mutex" option opens SQLite in "multi-threaded" mode, meaning that it can safely
        // be used from multiple threads as long as we don't access the connection from multiple
        // threads *at the same time*. Since we put the connection behind a `Mutex`, and that the
        // underlying library implements `!Sync` for `Connection` as a safety measure anyway, it
        // is safe to enable this option.
        // See https://www.sqlite.org/threadsafe.html
        rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;

    let database = match config.ty {
        ConfigTy::Disk(path) => {
            // We put a `/v1/` behind the path in case we change the schema.
            let path = path.join("v1");
            // Ignoring errors in `create_dir_all`, in order to avoid making the API of this
            // function more complex. If `create_dir_all` fails, opening the database will most
            // likely fail too.
            let _ = fs::create_dir_all(&path);
            rusqlite::Connection::open_with_flags(path.join("database.sqlite"), flags)
        }
        ConfigTy::Memory => rusqlite::Connection::open_in_memory_with_flags(flags),
    }
    .map_err(InternalError)?;

    // The underlying SQLite wrapper maintains a cache of prepared statements. We set it to a
    // value superior to the number of different queries we make.
    database.set_prepared_statement_cache_capacity(64);

    database
        .execute_batch(
            r#"
-- See https://sqlite.org/pragma.html and https://www.sqlite.org/wal.html
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA locking_mode = EXCLUSIVE;
PRAGMA auto_vacuum = FULL;
PRAGMA encoding = 'UTF-8';
PRAGMA trusted_schema = false;
PRAGMA foreign_keys = 1;

/*
Contains all the "global" values in the database.
A value must be present either in `value_blob` or `value_number` depending on the type of data.

Keys in that table:

 - `best` (blob): Hash of the best block.

 - `finalized` (number): Height of the finalized block, as a 64bits big endian number.

 - `grandpa_authorities_set_id` (number): Id of the authorities set that must finalize the block
 right after the finalized block. The value is 0 at the genesis block, and increased by 1 at every
 authorities change. Missing if and only if the chain doesn't use Grandpa.

 - `grandpa_scheduled_target` (number): Height of the block where the authorities found in
 `grandpa_scheduled_authorities` will be triggered. Blocks whose height is strictly higher than
 this value must be finalized using the new set of authorities. This authority change must have
 been scheduled in or before the finalized block. Missing if no change is scheduled or if the
 chain doesn't use Grandpa.

 - `aura_slot_duration` (number): Duration of an Aura slot in milliseconds. Missing if and only if
 the chain doesn't use Aura.

 - `babe_slots_per_epoch` (number): Number of slots per Babe epoch. Missing if and only if the
 chain doesn't use Babe.

 - `babe_finalized_epoch` (blob): SCALE encoding of a structure that contains the information
 about the Babe epoch used for the finalized block. Missing if and only if the finalized
 block is block #0 or the chain doesn't use Babe.

 - `babe_finalized_next_epoch` (blob): SCALE encoding of a structure that contains the information
 about the Babe epoch that follows the one described by `babe_finalized_epoch`. If the
 finalized block is block #0, then this contains information about epoch #0. Missing if and
 only if the chain doesn't use Babe.

*/
CREATE TABLE IF NOT EXISTS meta(
    key STRING NOT NULL PRIMARY KEY,
    value_blob BLOB,
    value_number INTEGER,
    -- Either `value_blob` or `value_number` must be NULL but not both.
    CHECK((value_blob IS NULL OR value_number IS NULL) AND (value_blob IS NOT NULL OR value_number IS NOT NULL))
);

/*
List of all trie nodes of all blocks whose trie is stored in the database.
*/
CREATE TABLE IF NOT EXISTS trie_node(
    hash BLOB NOT NULL PRIMARY KEY
);

/*
Storage associated to a trie node.
For each entry in `trie_node` there exists either 0 or 1 entry in `trie_node_storage` indicating
the storage value associated to this node.
*/
CREATE TABLE IF NOT EXISTS trie_node_storage(
    node_hash BLOB NOT NULL PRIMARY KEY,
    value BLOB NOT NULL,
    trie_entry_version INTEGER NOT NULL,
    FOREIGN KEY (node_hash) REFERENCES trie_node(hash) ON UPDATE CASCADE ON DELETE CASCADE
);

/*
Parent-child relationship between trie nodes.
*/
CREATE TABLE IF NOT EXISTS trie_node_child(
    hash BLOB NOT NULL,
    child_num INTEGER NOT NULL,
    child_hash BLOB NOT NULL,
    PRIMARY KEY (hash, child_num),
    FOREIGN KEY (hash) REFERENCES trie_node(hash) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (child_hash) REFERENCES trie_node(hash) ON UPDATE CASCADE ON DELETE RESTRICT
);

/*
List of all known blocks, indexed by their hash or number.
*/
CREATE TABLE IF NOT EXISTS blocks(
    hash BLOB NOT NULL PRIMARY KEY,
    parent_hash BLOB,  -- NULL only for the genesis block
    state_trie_root_hash BLOB,  -- NULL if the block storage isn't in the database
    number INTEGER NOT NULL,
    header BLOB NOT NULL,
    justification BLOB,
    UNIQUE(number, hash),
    FOREIGN KEY (parent_hash) REFERENCES blocks(hash) ON UPDATE CASCADE ON DELETE RESTRICT,
    FOREIGN KEY (state_trie_root_hash) REFERENCES trie_node(hash) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS blocks_by_number ON blocks(number);

/*
Each block has a body made from 0+ extrinsics (in practice, there's always at least one extrinsic,
but the database supports 0). This table contains these extrinsics.
The `idx` field contains the index between `0` and `num_extrinsics - 1`. The values in `idx` must
be contiguous for each block.
*/
CREATE TABLE IF NOT EXISTS blocks_body(
    hash BLOB NOT NULL,
    idx INTEGER NOT NULL,
    extrinsic BLOB NOT NULL,
    UNIQUE(hash, idx),
    CHECK(length(hash) == 32),
    FOREIGN KEY (hash) REFERENCES blocks(hash) ON UPDATE CASCADE ON DELETE CASCADE
);

/*
List of public keys and weights of the GrandPa authorities that must finalize the children of the
finalized block. Empty if the chain doesn't use Grandpa.
*/
CREATE TABLE IF NOT EXISTS grandpa_triggered_authorities(
    idx INTEGER NOT NULL PRIMARY KEY,
    public_key BLOB NOT NULL,
    weight INTEGER NOT NULL,
    CHECK(length(public_key) == 32)
);

/*
List of public keys and weights of the GrandPa authorities that will be triggered at the block
found in `grandpa_scheduled_target` (see `meta`). Empty if the chain doesn't use Grandpa.
*/
CREATE TABLE IF NOT EXISTS grandpa_scheduled_authorities(
    idx INTEGER NOT NULL PRIMARY KEY,
    public_key BLOB NOT NULL,
    weight INTEGER NOT NULL,
    CHECK(length(public_key) == 32)
);

/*
List of public keys of the Aura authorities that must author the children of the finalized block.
*/
CREATE TABLE IF NOT EXISTS aura_finalized_authorities(
    idx INTEGER NOT NULL PRIMARY KEY,
    public_key BLOB NOT NULL,
    CHECK(length(public_key) == 32)
);

    "#,
        )
        .map_err(InternalError)?;

    // `PRAGMA` queries can't be parametrized, and thus we have to use `format!`.
    database
        .execute(
            &format!(
                "PRAGMA cache_size = {}",
                0i64.saturating_sub_unsigned(
                    u64::try_from((config.cache_size.saturating_sub(1) / 1024).saturating_add(1))
                        .unwrap_or(u64::max_value()),
                )
            ),
            (),
        )
        .map_err(InternalError)?;

    let is_empty = database
        .prepare_cached("SELECT COUNT(*) FROM meta WHERE key = ?")
        .map_err(InternalError)?
        .query_row(("best",), |row| row.get::<_, i64>(0))
        .map_err(InternalError)?
        == 0;

    // The database is *always* within a transaction.
    database
        .execute("BEGIN TRANSACTION", ())
        .map_err(InternalError)?;

    Ok(if !is_empty {
        DatabaseOpen::Open(SqliteFullDatabase {
            database: parking_lot::Mutex::new(database),
            block_number_bytes: config.block_number_bytes, // TODO: consider storing this value in the DB and check it when opening
        })
    } else {
        DatabaseOpen::Empty(DatabaseEmpty {
            database,
            block_number_bytes: config.block_number_bytes,
        })
    })
}

/// Configuration for the database.
#[derive(Debug)]
pub struct Config<'a> {
    /// Type of database.
    pub ty: ConfigTy<'a>,

    /// Number of bytes used to encode the block number.
    pub block_number_bytes: usize,

    /// Maximum allowed size, in bytes, of the SQLite cache.
    pub cache_size: usize,
}

/// Type of database.
#[derive(Debug)]
pub enum ConfigTy<'a> {
    /// Store the database on disk. Path to the directory containing the database.
    Disk(&'a Path),
    /// Store the database in memory. The database is discarded on destruction.
    Memory,
}

/// Either existing database or database prototype.
pub enum DatabaseOpen {
    /// A database already existed and has now been opened.
    Open(SqliteFullDatabase),

    /// Either a database has just been created, or there existed a database but it is empty.
    ///
    /// > **Note**: The situation where a database existed but is empty can happen if you have
    /// >           previously called [`open`] then dropped the [`DatabaseOpen`] object without
    /// >           filling the newly-created database with data.
    Empty(DatabaseEmpty),
}

/// An open database. Holds file descriptors.
pub struct DatabaseEmpty {
    /// See the similar field in [`SqliteFullDatabase`].
    database: rusqlite::Connection,

    /// See the similar field in [`SqliteFullDatabase`].
    block_number_bytes: usize,
}

impl DatabaseEmpty {
    /// Inserts the given [`chain_information::ChainInformationRef`] in the database prototype in
    /// order to turn it into an actual database.
    ///
    /// Must also pass the body, justification, and state of the storage of the finalized block.
    pub fn initialize<'a>(
        self,
        chain_information: impl Into<chain_information::ChainInformationRef<'a>>,
        finalized_block_body: impl ExactSizeIterator<Item = &'a [u8]>,
        finalized_block_justification: Option<Vec<u8>>,
        finalized_block_storage_main_trie_entries: impl Iterator<Item = (&'a [u8], &'a [u8])> + Clone,
        finalized_block_state_version: u8,
    ) -> Result<SqliteFullDatabase, AccessError> {
        let chain_information = chain_information.into();

        let finalized_block_hash = chain_information
            .finalized_block_header
            .hash(self.block_number_bytes);

        let scale_encoded_finalized_block_header = chain_information
            .finalized_block_header
            .scale_encoding(self.block_number_bytes)
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            });

        // Temporarily disable foreign key checks in order to make the initial insertion easier,
        // as we don't have to make sure that trie nodes are sorted.
        // Note that this is immediately disabled again when we `COMMIT`.
        self.database
            .execute("PRAGMA defer_foreign_keys = ON", ())
            .unwrap(); // TODO: don't unwrap

        {
            // TODO: make the user build this, it's really inappropriate here
            let mut trie_structure = trie_structure::TrieStructure::new();
            for (key, value) in finalized_block_storage_main_trie_entries {
                match trie_structure.node(trie::bytes_to_nibbles(key.iter().copied())) {
                    trie_structure::Entry::Vacant(e) => {
                        e.insert_storage_value().insert(
                            (Some(value), None::<trie::trie_node::MerkleValueOutput>),
                            (None, None),
                        );
                    }
                    trie_structure::Entry::Occupied(trie_structure::NodeAccess::Branch(mut e)) => {
                        *e.user_data() = (Some(value), None);
                        e.insert_storage_value();
                    }
                    trie_structure::Entry::Occupied(trie_structure::NodeAccess::Storage(_)) => {
                        // Duplicate entry.
                        panic!()
                    }
                }
            }

            // Calculate the Merkle values of the nodes.
            for node_index in trie_structure
                .iter_ordered()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                let mut node_access = trie_structure.node_by_index(node_index).unwrap();

                let children = core::array::from_fn::<_, 16, _>(|n| {
                    node_access
                        .child(trie::Nibble::try_from(u8::try_from(n).unwrap()).unwrap())
                        .map(|mut child| child.user_data().1.as_ref().unwrap().clone())
                });

                let is_root_node = node_access.is_root_node();
                let partial_key = node_access.partial_key().collect::<Vec<_>>().into_iter();

                // We have to hash the storage value ahead of time if necessary due to borrow
                // checking difficulties.
                let storage_value_hashed = match (
                    node_access.user_data().0.as_ref(),
                    finalized_block_state_version,
                ) {
                    (Some(v), 1) => {
                        if v.len() >= 33 {
                            Some(blake2_rfc::blake2b::blake2b(32, &[], v))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                let storage_value = match (
                    node_access.user_data().0.as_ref(),
                    storage_value_hashed.as_ref(),
                ) {
                    (_, Some(storage_value_hashed)) => trie::trie_node::StorageValue::Hashed(
                        <&[u8; 32]>::try_from(storage_value_hashed.as_bytes()).unwrap(),
                    ),
                    (Some(v), None) => trie::trie_node::StorageValue::Unhashed(&v[..]),
                    (None, _) => trie::trie_node::StorageValue::None,
                };

                let merkle_value = trie::trie_node::calculate_merkle_value(
                    trie::trie_node::Decoded {
                        children,
                        partial_key,
                        storage_value,
                    },
                    is_root_node,
                )
                .unwrap();

                node_access.into_user_data().1 = Some(merkle_value);
            }

            // Now insert the entries.
            let mut insert_node_statement = self
                .database
                .prepare_cached("INSERT INTO trie_node(hash) VALUES(?)")
                .unwrap();
            let mut insert_node_storage_statement = self
                .database
                .prepare_cached("INSERT INTO trie_node_storage(node_hash, value, trie_entry_version) VALUES(?, ?, ?)")
                .unwrap();
            let mut insert_child_statement = self
                .database
                .prepare_cached(
                    "INSERT INTO trie_node_child(hash, child_num, child_hash) VALUES(?, ?, ?)",
                )
                .unwrap();
            for node_index in trie_structure
                .iter_unordered()
                .collect::<Vec<_>>()
                .into_iter()
            {
                let (storage_value, Some(merkle_value)) = &trie_structure[node_index]
                    else { unreachable!() };
                let merkle_value = merkle_value.clone(); // Cloning to solve borrow checker restriction.
                insert_node_statement
                    .execute((merkle_value.as_ref(),))
                    .unwrap(); // TODO: don't unwrap
                if let Some(storage_value) = storage_value {
                    insert_node_storage_statement
                        .execute((
                            merkle_value.as_ref(),
                            storage_value,
                            finalized_block_state_version,
                        ))
                        .unwrap(); // TODO: don't unwrap
                }

                let mut node_access = trie_structure.node_by_index(node_index).unwrap();
                for child_index in (0..16).map(|n| trie::Nibble::try_from(n).unwrap()) {
                    if let Some(mut child) = node_access.child(child_index) {
                        insert_child_statement
                            .execute((
                                merkle_value.as_ref(),
                                u8::from(child_index),
                                child.user_data().1.as_ref().unwrap().as_ref(),
                            ))
                            .unwrap(); // TODO: don't unwrap
                    }
                }
            }
        }

        self
            .database
            .prepare_cached(
                "INSERT INTO blocks(hash, parent_hash, state_trie_root_hash, number, header, justification) VALUES(?, ?, ?, ?, ?, ?)",
            )
            .unwrap()
            .execute((
                &finalized_block_hash[..],
                if chain_information.finalized_block_header.number != 0 {
                    Some(&chain_information.finalized_block_header.parent_hash[..])
                } else { None },
                &chain_information.finalized_block_header.state_root[..],
                i64::try_from(chain_information.finalized_block_header.number).unwrap(),
                &scale_encoded_finalized_block_header[..],
                finalized_block_justification.as_deref(),
            ))
            .unwrap();

        {
            let mut statement = self
                .database
                .prepare_cached("INSERT INTO blocks_body(hash, idx, extrinsic) VALUES(?, ?, ?)")
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

        super::meta_set_blob(&self.database, "best", &finalized_block_hash[..]).unwrap();
        super::meta_set_number(
            &self.database,
            "finalized",
            chain_information.finalized_block_header.number,
        )?;

        match &chain_information.finality {
            chain_information::ChainInformationFinalityRef::Outsourced => {}
            chain_information::ChainInformationFinalityRef::Grandpa {
                finalized_triggered_authorities,
                after_finalized_block_authorities_set_id,
                finalized_scheduled_change,
            } => {
                super::meta_set_number(
                    &self.database,
                    "grandpa_authorities_set_id",
                    *after_finalized_block_authorities_set_id,
                )?;

                let mut statement = self
                    .database
                    .prepare_cached("INSERT INTO grandpa_triggered_authorities(idx, public_key, weight) VALUES(?, ?, ?)")
                    .unwrap();
                for (index, item) in finalized_triggered_authorities.iter().enumerate() {
                    statement
                        .execute((
                            i64::try_from(index).unwrap(),
                            &item.public_key[..],
                            i64::from_ne_bytes(item.weight.get().to_ne_bytes()),
                        ))
                        .unwrap();
                }

                if let Some((height, list)) = finalized_scheduled_change {
                    super::meta_set_number(&self.database, "grandpa_scheduled_target", *height)?;

                    let mut statement = self
                        .database
                        .prepare_cached("INSERT INTO grandpa_scheduled_authorities(idx, public_key, weight) VALUES(?, ?, ?)")
                        .unwrap();
                    for (index, item) in list.iter().enumerate() {
                        statement
                            .execute((
                                i64::try_from(index).unwrap(),
                                &item.public_key[..],
                                i64::from_ne_bytes(item.weight.get().to_ne_bytes()),
                            ))
                            .unwrap();
                    }
                }
            }
        }

        match &chain_information.consensus {
            chain_information::ChainInformationConsensusRef::Unknown => {}
            chain_information::ChainInformationConsensusRef::Aura {
                finalized_authorities_list,
                slot_duration,
            } => {
                super::meta_set_number(&self.database, "aura_slot_duration", slot_duration.get())
                    .unwrap();

                let mut statement = self
                    .database
                    .prepare_cached(
                        "INSERT INTO aura_finalized_authorities(idx, public_key) VALUES(?, ?)",
                    )
                    .unwrap();
                for (index, item) in finalized_authorities_list.clone().enumerate() {
                    statement
                        .execute((i64::try_from(index).unwrap(), &item.public_key[..]))
                        .unwrap();
                }
            }
            chain_information::ChainInformationConsensusRef::Babe {
                slots_per_epoch,
                finalized_next_epoch_transition,
                finalized_block_epoch_information,
            } => {
                super::meta_set_number(
                    &self.database,
                    "babe_slots_per_epoch",
                    slots_per_epoch.get(),
                )
                .unwrap();
                super::meta_set_blob(
                    &self.database,
                    "babe_finalized_next_epoch",
                    &encode_babe_epoch_information(finalized_next_epoch_transition.clone())[..],
                )
                .unwrap();

                if let Some(finalized_block_epoch_information) = finalized_block_epoch_information {
                    super::meta_set_blob(&self.database, "babe_finalized_epoch", &encode_babe_epoch_information(
            finalized_block_epoch_information.clone(),
        )[..]).unwrap();
                }
            }
        }

        super::flush(&self.database)?;

        Ok(SqliteFullDatabase {
            database: parking_lot::Mutex::new(self.database),
            block_number_bytes: self.block_number_bytes,
        })
    }
}
