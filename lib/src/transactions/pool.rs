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

//! General-purpose transactions pool.
//!
//! The transactions pool is a complex data structure that holds a list of pending transactions,
//! in other words transactions that should later be included in blocks, and a list of
//! transactions that have been included in non-finalized blocks.
//!
//! See the [parent module's documentation](..) for an overview of transactions.
//!
//! # Overview
//!
//! The transactions pool stores a list of transactions that the local node desires to include in
//! blocks, and a list of transactions that have already been included in blocks. Each of these
//! transactions is either validated or not. A transaction in a block is assumed to always succeed
//! validation. A validated transaction that isn't present in any block is a transaction that is
//! assumed to be includable in a block in the future.
//!
//! The order in which transactions can be included in a block follows a complex system of
//! "provided" and "required" tags. A transaction that *requires* some tags can only be included
//! after all these tags have been *provided* by transactions earlier in the chain.
//!
//! The transactions pool isn't only about deciding which transactions to include in a block when
//! authoring, but also about tracking the status of interesting transactions between the moment
//! they become interesting and the moment the block they are included in becomes finalized. This
//! is relevant both if the local node can potentially author blocks or not.
//!
//! The transactions pool tracks the height of the *best* chain, and only of the best chain. More
//! precisely, it is aware of the height of the current best block. Forks are tracked.
//!
//! # Usage
//!
//! A [`Pool`] is a collection of transactions. Each transaction in the pool exposes three
//! properties:
//!
//! - Whether or not it has been validated, and if yes, the block against which it has been
//! validated and the characteristics of the transaction (as provided by the runtime). These
//! characterstics are: the tags it provides and requires, its longevity, and its priority.
//! See [the `validate` module](../validate) for more information.
//! - The height of the block, if any, in which the transaction has been included.
//! - A so-called user data, an opaque field controlled by the API user.
//!
//! Use [`Pool::add_unvalidated`] to add to the pool a transaction that should be included in a
//! block at a later point in time.
//!
//! When a new block is considered as best, use [`Pool::retract_blocks`] to remove all the re-orged
//! blocks, then [`Pool::append_empty_block`] and
//! [`Pool::best_block_add_transaction_by_scale_encoding`] to add the new block(s). The
//! transactions that are passed to [`Pool::best_block_add_transaction_by_scale_encoding`] are
//! added to the pool.
//!
//! Use [`Pool::unvalidated_transactions`] to obtain the list of transactions that should be
//! validated. Validation should be performed using the [`validate`](../validate) module, and
//! the result reported with [`Pool::set_validation_result`].
//!
//! Use [`Pool::remove_included`] when a block has been finalized to remove from the pool the
//! transactions that are present in the finalized block and below.
//!
//! When authoring a block, use [`Pool::append_empty_block`] and
//! [`Pool::best_block_includable_transactions`] to determine which transaction to include
//! next. Use [`Pool::best_block_add_transaction_by_id`] when the transaction has been included.
//!
//! # Out of scope
//!
//! The following are examples of things that are related transactions pool to but out of scope of
//! this data structure:
//!
//! - Watching the state of transactions.
//! - Sending transactions to other peers.
//!

// TODO: this code is completely untested

use alloc::{
    collections::{btree_set, BTreeSet},
    vec::Vec,
};
use core::{fmt, iter, mem, ops};
use hashbrown::HashSet;

pub use super::validate::ValidTransaction;

/// Identifier of a transaction stored within the [`Pool`].
///
/// Identifiers can be re-used by the pool. In other words, a transaction id can compare equal to
/// an older transaction id that is no longer in the pool.
//
// Implementation note: corresponds to indices within [`Pool::transactions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(usize);

/// Configuration for [`Pool::new`].
pub struct Config {
    /// Number of transactions to initially allocate memory for.
    ///
    /// > **Note**: This should take into account the fact that the pool will contain the
    /// >           transactions included in new blocks. In other words, it should be equal to
    /// >           `expected_max_reorg_depth * expected_max_transactions_per_block +
    /// >           max_concurrent_desired_transactions`.
    pub capacity: usize,

    /// Height of the finalized block at initialization.
    ///
    /// The [`Pool`] doesn't track which block is finalized. This value is only used to initialize
    /// the best block number. The field could also have been called `best_block_height`, but doing
    /// so might created confusion.
    ///
    /// Non-finalized blocks should be added to the pool after initialization using
    /// [`Pool::append_empty_block`].
    pub finalized_block_height: u64,

    /// Seed for randomness used to avoid HashDoS attacks.
    pub randomness_seed: [u8; 16],
}

/// Data structure containing transactions. See the module-level documentation for more info.
pub struct Pool<TTx> {
    /// Actual list of transactions.
    transactions: slab::Slab<Transaction<TTx>>,

    /// List of transactions (represented as indices within [`Pool::transactions`]) whose status
    /// is "not validated".
    // TODO: shrink_to_fit from time to time?
    not_validated: HashSet<TransactionId, fnv::FnvBuildHasher>,

    /// Transaction ids (i.e. indices within [`Pool::transactions`]) indexed by the BLAKE2 hash
    /// of the bytes of the transaction.
    by_hash: BTreeSet<([u8; 32], TransactionId)>,

    /// Transaction ids (i.e. indices within [`Pool::transactions`]) indexed by the block height
    /// in which the transaction is included.
    by_height: BTreeSet<(u64, TransactionId)>,

    /// Validated transaction ids (i.e. indices within [`Pool::transactions`]) that are includable
    /// in the chain, indexed by the priority value provided by the validation.
    includable: BTreeSet<(u64, TransactionId)>,

    /// Validated transaction ids (i.e. indices within [`Pool::transactions`]) indexed by the
    /// block height at which their validation expires.
    by_validation_expiration: BTreeSet<(u64, TransactionId)>,

    /// List of all tags that are in the `provides` or `requires` tag lists of any of the validated
    /// transactions.
    // TODO: shrink_to_fit from time to time?
    tags: hashbrown::HashMap<Vec<u8>, TagInfo, crate::util::SipHasherBuild>,

    /// Height of the latest best block, as known from the pool.
    best_block_height: u64,
}

/// Entry in [`Pool::transactions`].
struct Transaction<TTx> {
    /// Bytes corresponding to the SCALE-encoded transaction.
    scale_encoded: Vec<u8>,

    /// If `Some`, contains the outcome of the validation of this transaction and the block height
    /// it was validated against.
    validation: Option<(u64, ValidTransaction)>,

    /// If `Some`, the height of the block at which the transaction has been included.
    included_block_height: Option<u64>,

    /// User data chosen by the user.
    user_data: TTx,
}

/// Entry in [`Pool::tags`].
struct TagInfo {
    /// List of validated transactions that have the tag in their `provides` tags list.
    // TODO: shrink_to_fit from time to time?
    provided_by: hashbrown::HashSet<TransactionId, fnv::FnvBuildHasher>,

    /// List of validated transactions that have the tag in their `requires` tags list.
    // TODO: shrink_to_fit from time to time?
    required_by: hashbrown::HashSet<TransactionId, fnv::FnvBuildHasher>,

    /// Number of transactions in [`TagInfo::provided_by`] that are included in the chain.
    ///
    /// Note that a value strictly superior to 1 indicates some kind of bug in the logic of the
    /// runtime. However, we don't care about this in the pool and just want the pool to function
    /// properly.
    known_to_be_included_in_chain: usize,
}

impl<TTx> Pool<TTx> {
    /// Initializes a new transactions pool.
    pub fn new(config: Config) -> Self {
        Pool {
            transactions: slab::Slab::with_capacity(config.capacity),
            not_validated: HashSet::with_capacity_and_hasher(config.capacity, Default::default()),
            by_hash: BTreeSet::new(),
            by_height: BTreeSet::new(),
            includable: BTreeSet::new(),
            by_validation_expiration: BTreeSet::new(),
            tags: hashbrown::HashMap::with_capacity_and_hasher(
                8,
                crate::util::SipHasherBuild::new(config.randomness_seed),
            ),
            best_block_height: config.finalized_block_height,
        }
    }

    /// Returns true if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Returns the number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Inserts a new non-validated transaction in the pool.
    pub fn add_unvalidated(&mut self, scale_encoded: Vec<u8>, user_data: TTx) -> TransactionId {
        self.add_unvalidated_inner(scale_encoded, None, user_data)
    }

    /// Inserts a new non-validated transaction in the pool.
    fn add_unvalidated_inner(
        &mut self,
        scale_encoded: impl AsRef<[u8]> + Into<Vec<u8>>,
        included_block_height: Option<u64>,
        user_data: TTx,
    ) -> TransactionId {
        let hash = blake2_hash(scale_encoded.as_ref());

        let tx_id = TransactionId(self.transactions.insert(Transaction {
            scale_encoded: scale_encoded.into(),
            validation: None,
            included_block_height,
            user_data,
        }));

        let _was_inserted = self.by_hash.insert((hash, tx_id));
        debug_assert!(_was_inserted);

        let _was_inserted = self.not_validated.insert(tx_id);
        debug_assert!(_was_inserted);

        if let Some(included_block_height) = included_block_height {
            let _was_inserted = self.by_height.insert((included_block_height, tx_id));
            debug_assert!(_was_inserted);
        }

        tx_id
    }

    /// Removes from the pool the transaction with the given identifier.
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid.
    ///
    #[track_caller]
    pub fn remove(&mut self, id: TransactionId) -> TTx {
        self.unvalidate_transaction(id);
        let _removed = self.not_validated.remove(&id);
        debug_assert!(_removed);

        let tx = self.transactions.remove(id.0);

        if let Some(included_block_height) = tx.included_block_height {
            let _removed = self.by_height.remove(&(included_block_height, id));
            debug_assert!(_removed);
        }

        let _removed = self.by_hash.remove(&(blake2_hash(&tx.scale_encoded), id));
        debug_assert!(_removed);

        tx.user_data
    }

    /// Removes from the pool all the transactions that are included in a block whose height is
    /// inferior or equal to the one passed as parameter.
    ///
    /// Use this method when a block has been finalized.
    ///
    /// The returned iterator is guaranteed to remove all transactions even if it is dropped
    /// eagerly.
    pub fn remove_included(
        &'_ mut self,
        block_inferior_of_equal: u64,
    ) -> impl Iterator<Item = (TransactionId, TTx)> + '_ {
        // First, unvalidate all the transactions that we are going to remove.
        // This is done separately ahead of time in order to guarantee that there is no state
        // mismatch when `unvalidate_transaction` is entered.
        for tx_id in self
            .by_height
            .range(
                (0, TransactionId(usize::min_value()))
                    ..=(block_inferior_of_equal, TransactionId(usize::max_value())),
            )
            .map(|(_, id)| *id)
            .collect::<Vec<_>>()
        {
            self.unvalidate_transaction(tx_id);
        }

        // Extracts all the transactions that we are about to remove from `by_height`.
        let to_remove = {
            let remaining_txs = self.by_height.split_off(&(
                block_inferior_of_equal + 1,
                TransactionId(usize::min_value()),
            ));
            mem::replace(&mut self.by_height, remaining_txs)
        };

        struct ToRemoveIterator<'a, TTx> {
            pool: &'a mut Pool<TTx>,
            transactions: btree_set::IntoIter<(u64, TransactionId)>,
        }

        impl<'a, TTx> Iterator for ToRemoveIterator<'a, TTx>
        where
            // `FusedIterator` is necessary in order for the `Drop` implementation to not panic.
            btree_set::IntoIter<(u64, TransactionId)>: iter::FusedIterator,
        {
            type Item = (TransactionId, TTx);

            fn next(&mut self) -> Option<Self::Item> {
                let (_height, tx_id) = self.transactions.next()?;

                let tx = self.pool.transactions.remove(tx_id.0);
                debug_assert!(tx.validation.is_none());
                debug_assert_eq!(tx.included_block_height, Some(_height));

                let _removed = self
                    .pool
                    .by_hash
                    .remove(&(blake2_hash(&tx.scale_encoded), tx_id));
                debug_assert!(_removed);

                Some((tx_id, tx.user_data))
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                self.transactions.size_hint()
            }
        }

        impl<'a, TTx> ExactSizeIterator for ToRemoveIterator<'a, TTx> where
            btree_set::IntoIter<(u64, TransactionId)>: ExactSizeIterator
        {
        }

        impl<'a, TTx> Drop for ToRemoveIterator<'a, TTx> {
            fn drop(&mut self) {
                // Drain the rest of the iterator in order to remove the transactions even if
                // the iterator is dropped early.
                while self.next().is_some() {}
            }
        }

        ToRemoveIterator {
            pool: self,
            transactions: to_remove.into_iter(),
        }
    }

    /// Returns a list of transactions whose state is "not validated", their user data, and the
    /// height of the block they should be validated against.
    ///
    /// The block height a transaction should be validated against is always equal to either the
    /// block at which it has been included minus one, or the current best block. It is yielded by
    /// the iterator for convenience, to avoid writing error-prone code.
    pub fn unvalidated_transactions(
        &'_ self,
    ) -> impl ExactSizeIterator<Item = (TransactionId, &TTx, u64)> + '_ {
        self.not_validated.iter().copied().map(move |tx_id| {
            let tx = self.transactions.get(tx_id.0).unwrap();
            let height = tx
                .included_block_height
                .map(|n| n.checked_sub(1).unwrap())
                .unwrap_or(self.best_block_height);
            (tx_id, &tx.user_data, height)
        })
    }

    /// Returns the list of all transactions within the pool.
    pub fn iter(&'_ self) -> impl Iterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.transactions
            .iter()
            .map(|(id, tx)| (TransactionId(id), &tx.user_data))
    }

    /// Returns the list of all transactions within the pool.
    pub fn iter_mut(&'_ mut self) -> impl Iterator<Item = (TransactionId, &'_ mut TTx)> + '_ {
        self.transactions
            .iter_mut()
            .map(|(id, tx)| (TransactionId(id), &mut tx.user_data))
    }

    /// Returns the block height at which the given transaction has been included.
    ///
    /// A transaction has been included if it has been added to the pool with
    /// [`Pool::best_block_add_transaction_by_scale_encoding`] or
    /// [`Pool::best_block_add_transaction_by_id`].
    ///
    /// Returns `None` if the identifier is invalid or the transaction doesn't belong to any
    /// block.
    pub fn included_block_height(&self, id: TransactionId) -> Option<u64> {
        self.transactions.get(id.0)?.included_block_height
    }

    /// Returns the bytes associated with a given transaction.
    ///
    /// Returns `None` if the identifier is invalid.
    pub fn scale_encoding(&self, id: TransactionId) -> Option<&[u8]> {
        Some(&self.transactions.get(id.0)?.scale_encoded)
    }

    /// Finds the transactions in the pool whose bytes are `scale_encoded`.
    ///
    /// This operation has a complexity of `O(log n)` where `n` is the number of entries in the
    /// pool.
    pub fn transactions_by_scale_encoding(
        &'_ self,
        scale_encoded: &[u8],
    ) -> impl Iterator<Item = TransactionId> + '_ {
        let hash = blake2_hash(scale_encoded);
        self.by_hash
            .range(
                (hash, TransactionId(usize::min_value()))
                    ..=(hash, TransactionId(usize::max_value())),
            )
            .map(|(_, tx_id)| *tx_id)
    }

    /// Returns the best block height according to the pool.
    ///
    /// This initially corresponds to the value in [`Config::finalized_block_height`], is
    /// incremented by one every time [`Pool::append_empty_block`], and is decreased when
    /// [`Pool::retract_blocks`] is called.
    pub fn best_block_height(&self) -> u64 {
        self.best_block_height
    }

    /// Adds a block to the chain tracked by the transactions pool.
    pub fn append_empty_block(&mut self) {
        self.best_block_height = self.best_block_height.checked_add(1).unwrap();

        // Un-validate the transactions whose validation longevity has expired.
        for tx_id in self
            .by_validation_expiration
            .range(
                (0, TransactionId(usize::min_value()))
                    ..=(self.best_block_height, TransactionId(usize::max_value())),
            )
            .map(|(_, id)| *id)
            .collect::<Vec<_>>()
        {
            self.unvalidate_transaction(tx_id);
        }
    }

    /// Pop a certain number of blocks from the list of blocks.
    ///
    /// Transactions that were included in these blocks remain in the transactions pool.
    ///
    /// Returns the list of transactions that were in blocks that have been retracted, with the
    /// height of the block at which they were.
    ///
    /// # Panic
    ///
    /// Panics if `num_to_retract > self.best_block_height()`, in other words if the block number
    /// would go in the negative.
    ///
    pub fn retract_blocks(
        &mut self,
        num_to_retract: u64,
    ) -> impl Iterator<Item = (TransactionId, u64)> {
        // Checks that there's no transaction included above `self.best_block_height`.
        debug_assert!(self
            .by_height
            .range(
                (
                    self.best_block_height + 1,
                    TransactionId(usize::min_value()),
                )..,
            )
            .next()
            .is_none());

        // Update `best_block_height` as first step, in order to panic sooner in case of underflow.
        self.best_block_height = self.best_block_height.checked_sub(num_to_retract).unwrap();

        // List of transactions that were included in these blocks.
        let transactions_to_retract = self
            .by_height
            .range(
                (
                    self.best_block_height + 1,
                    TransactionId(usize::min_value()),
                )..,
            )
            .map(|(block_height, tx_id)| (*tx_id, *block_height))
            .collect::<Vec<_>>();

        // Set `included_block_height` to `None` for each of them.
        for (transaction_id, _) in &transactions_to_retract {
            self.unvalidate_transaction(*transaction_id);

            let tx_data = self.transactions.get_mut(transaction_id.0).unwrap();
            debug_assert!(tx_data.included_block_height.unwrap() > self.best_block_height);
            self.by_height
                .remove(&(tx_data.included_block_height.unwrap(), *transaction_id));
            tx_data.included_block_height = None;
        }

        // Return retracted transactions from highest block to lowest block.
        transactions_to_retract.into_iter().rev()
    }

    /// Returns all the transactions that can be included in the highest block.
    ///
    /// Use this function if you are currently authoring a block.
    ///
    /// The transactions are returned by decreasing priority. Re-ordering the transactions might
    /// lead to the runtime returning errors. It is safe, however, to skip some transactions
    /// altogether if desired.
    pub fn best_block_includable_transactions(
        &'_ self,
    ) -> impl Iterator<Item = (TransactionId, &'_ TTx)> + '_ {
        self.includable
            .iter()
            .rev()
            .map(|(_, tx_id)| (*tx_id, &self.transactions[tx_id.0].user_data))
    }

    /// Adds a single-SCALE-encoded transaction to the highest block.
    ///
    /// The transaction is compared against the list of non-included transactions that are already
    /// in the pool. If a non-included transaction with the same bytes is found, it is switched to
    /// the "included" state and [`AppendBlockTransaction::NonIncludedUpdated`] is returned.
    /// Otherwise, [`AppendBlockTransaction::Unknown`] is returned and the transaction can be
    /// inserted in the pool.
    ///
    /// > **Note**: This function is equivalent to calling
    /// >           [`Pool::transactions_by_scale_encoding`], removing the transactions that are
    /// >           already included (see [`Pool::included_block_height`]), then calling
    /// >           [`Pool::best_block_add_transaction_by_id`] with one of the transactions
    /// >           that remain.
    pub fn best_block_add_transaction_by_scale_encoding<'a, 'b>(
        &'a mut self,
        bytes: &'b [u8],
    ) -> AppendBlockTransaction<'a, 'b, TTx> {
        let non_included = {
            let hash = blake2_hash(bytes);
            self.by_hash
                .range(
                    (hash, TransactionId(usize::min_value()))
                        ..=(hash, TransactionId(usize::max_value())),
                )
                .find(|(_, tx_id)| {
                    self.transactions
                        .get(tx_id.0)
                        .unwrap()
                        .included_block_height
                        .is_none()
                })
                .map(|(_, tx_id)| *tx_id)
        };

        if let Some(tx_id) = non_included {
            debug_assert_eq!(self.transactions[tx_id.0].scale_encoded, bytes);
            self.best_block_add_transaction_by_id(tx_id);
            AppendBlockTransaction::NonIncludedUpdated {
                id: tx_id,
                user_data: &mut self.transactions[tx_id.0].user_data,
            }
        } else {
            AppendBlockTransaction::Unknown(Vacant { inner: self, bytes })
        }
    }

    /// Adds a transaction to the block being appended.
    ///
    /// # Panic
    ///
    /// Panics if the transaction with the given id is invalid.
    /// Panics if the transaction with the given id was already included in the chain.
    ///
    pub fn best_block_add_transaction_by_id(&mut self, id: TransactionId) {
        // Sanity check.
        assert!(self.transactions[id.0].included_block_height.is_none());

        // We can in principle always discard the current validation status of the transaction.
        // However, if the transaction has been validated against the parent of the block, we want
        // to keep this validation status as an optimization.
        // Since updating the status of a transaction is a rather complicated state change, the
        // approach taken here is to always un-validate the transaction then re-validate it.
        let revalidation = if let Some(validation) = self.transactions[id.0].validation.as_ref() {
            if validation.0 + 1 == self.best_block_height {
                Some(validation.clone())
            } else {
                None
            }
        } else {
            None
        };
        self.unvalidate_transaction(id);

        // Mark the transaction as included.
        self.transactions[id.0].included_block_height = Some(self.best_block_height);
        self.by_height.insert((self.best_block_height, id));

        // Re-set the validation status of the transaction that was extracted earlier.
        if let Some((block_number_validated_against, result)) = revalidation {
            self.set_validation_result(id, block_number_validated_against, result);
        }
    }

    /// Sets the outcome of validating the transaction with the given identifier.
    ///
    /// The block number must be the block number against which the transaction has been
    /// validated.
    ///
    /// Has no effect if the transaction has been included in the chain and the validation has
    /// been performed against a block other than the parent of the block in which it was included.
    ///
    /// Has no effect if the transaction has already been validated against the same or a higher
    /// block.
    ///
    /// > **Note**: If the transaction validation fails, use [`Pool::remove`] to remove the
    /// >           transaction instead. Invalid transactions stay invalid forever and thus aren't
    /// >           meant to be left in the pool.
    ///
    /// # Panic
    ///
    /// Panics if the transaction with the given id is invalid.
    ///
    pub fn set_validation_result(
        &mut self,
        id: TransactionId,
        block_number_validated_against: u64,
        result: ValidTransaction,
    ) {
        // If the transaction has been included in a block, immediately return if the validation
        // has been performed against a different block.
        if self
            .transactions
            .get(id.0)
            .unwrap()
            .included_block_height
            .map_or(false, |b| b != block_number_validated_against + 1)
        {
            return;
        }

        // Immediately return if the transaction has been validated against a better block.
        if self
            .transactions
            .get(id.0)
            .unwrap()
            .validation
            .as_ref()
            .map_or(false, |(b, _)| *b >= block_number_validated_against)
        {
            return;
        }

        // If the transaction was already validated, we don't try to update all the fields of
        // `self` as it would be rather complicated. Instead we mark the transaction as not
        // validated then mark it again as validated.
        self.unvalidate_transaction(id);
        debug_assert!(self.transactions[id.0].validation.is_none());

        // Whether the transaction can be included at the head of the chain. Set to `false` below
        // if there is a reason why not.
        let mut includable = self.transactions[id.0].included_block_height.is_none();

        for tag in &result.provides {
            let tag_info = self.tags.entry(tag.clone()).or_insert_with(|| TagInfo {
                provided_by: Default::default(),
                required_by: Default::default(),
                known_to_be_included_in_chain: 0,
            });

            if self.transactions[id.0].included_block_height.is_some() {
                tag_info.known_to_be_included_in_chain += 1;

                if tag_info.known_to_be_included_in_chain == 1 {
                    // All other transactions that provide the same tag are not longer includable.
                    for other_tx_id in &tag_info.provided_by {
                        let _was_in = self.includable.remove(&(
                            self.transactions[other_tx_id.0]
                                .validation
                                .as_ref()
                                .unwrap()
                                .1
                                .priority,
                            *other_tx_id,
                        ));
                        debug_assert!(_was_in);
                    }

                    // All other transactions that require this tag are now includable.
                    for other_tx_id in &tag_info.required_by {
                        let _was_inserted = self.includable.insert((
                            self.transactions[other_tx_id.0]
                                .validation
                                .as_ref()
                                .unwrap()
                                .1
                                .priority,
                            *other_tx_id,
                        ));
                        debug_assert!(_was_inserted);
                    }
                }
            }

            if tag_info.known_to_be_included_in_chain >= 1 {
                includable = false;
            }

            tag_info.provided_by.insert(id);
        }

        for tag in &result.requires {
            let tag_info = self.tags.entry(tag.clone()).or_insert_with(|| TagInfo {
                provided_by: Default::default(),
                required_by: Default::default(),
                known_to_be_included_in_chain: 0,
            });

            tag_info.required_by.insert(id);

            if tag_info.known_to_be_included_in_chain == 0 {
                includable = false;
            }
        }

        self.by_validation_expiration.insert((
            block_number_validated_against.saturating_add(result.longevity.get()),
            id,
        ));

        if includable {
            self.includable.insert((result.priority, id));
        }

        self.transactions[id.0].validation = Some((block_number_validated_against, result));
    }

    /// Sets a transaction's status to "not validated".
    ///
    /// # Panic
    ///
    /// Panics if the identifier is invalid.
    ///
    fn unvalidate_transaction(&mut self, tx_id: TransactionId) {
        // No effect if wasn't validated.
        let Some((block_height_validated_against, validation)) = self.transactions[tx_id.0].validation.take()
            else { return; };

        // We don't care in this context whether the transaction was includable or not, and we
        // call `remove` in both cases.
        self.includable.remove(&(validation.priority, tx_id));

        for tag in validation.provides {
            let tag_info = self.tags.get_mut(&tag).unwrap();

            let _was_in = tag_info.provided_by.remove(&tx_id);
            debug_assert!(_was_in);

            if self.transactions[tx_id.0].included_block_height.is_some() {
                tag_info.known_to_be_included_in_chain -= 1;

                if tag_info.known_to_be_included_in_chain == 0 {
                    // All other transactions that provide the same tag are now includable.
                    // Note that in practice they most likely are not, but we prioritize the
                    // consistency and simplify of the pool implementation rather than trying to
                    // be smart.
                    for other_tx_id in &tag_info.provided_by {
                        let _was_inserted = self.includable.insert((
                            self.transactions[other_tx_id.0]
                                .validation
                                .as_ref()
                                .unwrap()
                                .1
                                .priority,
                            *other_tx_id,
                        ));
                        debug_assert!(_was_inserted);
                    }

                    // All other transactions that require this tag are no longer includable.
                    for other_tx_id in &tag_info.required_by {
                        let _was_in = self.includable.remove(&(
                            self.transactions[other_tx_id.0]
                                .validation
                                .as_ref()
                                .unwrap()
                                .1
                                .priority,
                            *other_tx_id,
                        ));
                        debug_assert!(_was_in);
                    }
                }
            }

            if tag_info.provided_by.is_empty() && tag_info.required_by.is_empty() {
                self.tags.remove(&tag).unwrap();
            }
        }

        for tag in validation.requires {
            let tag_info = self.tags.get_mut(&tag).unwrap();

            let _was_in = tag_info.required_by.remove(&tx_id);
            debug_assert!(_was_in);

            if tag_info.provided_by.is_empty() && tag_info.required_by.is_empty() {
                self.tags.remove(&tag).unwrap();
            }
        }

        self.not_validated.insert(tx_id);

        let _was_in = self.by_validation_expiration.remove(&(
            block_height_validated_against.saturating_add(validation.longevity.get()),
            tx_id,
        ));
        debug_assert!(_was_in);
    }
}

impl<TTx> ops::Index<TransactionId> for Pool<TTx> {
    type Output = TTx;

    fn index(&self, index: TransactionId) -> &Self::Output {
        &self.transactions[index.0].user_data
    }
}

impl<TTx> ops::IndexMut<TransactionId> for Pool<TTx> {
    fn index_mut(&mut self, index: TransactionId) -> &mut Self::Output {
        &mut self.transactions[index.0].user_data
    }
}

impl<TTx: fmt::Debug> fmt::Debug for Pool<TTx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list()
            .entries(
                self.transactions
                    .iter()
                    .map(|t| (TransactionId(t.0), &t.1.user_data)),
            )
            .finish()
    }
}

/// See [`Pool::best_block_add_transaction_by_scale_encoding`].
#[derive(Debug)]
pub enum AppendBlockTransaction<'a, 'b, TTx> {
    /// Transaction to add isn't in the list of non-included transactions. It can be added to the
    /// pool.
    Unknown(Vacant<'a, 'b, TTx>),
    /// Transaction to add is present in the list of non-included transactions. It is now
    /// considered included.
    NonIncludedUpdated {
        /// Identifier of the non-included transaction with the same bytes.
        id: TransactionId,
        /// User data stored alongside with that transaction.
        user_data: &'a mut TTx,
    },
}

/// See [`AppendBlockTransaction::Unknown`].
pub struct Vacant<'a, 'b, TTx> {
    inner: &'a mut Pool<TTx>,
    bytes: &'b [u8],
}

impl<'a, 'b, TTx> Vacant<'a, 'b, TTx> {
    /// Inserts the transaction in the pool.
    pub fn insert(self, user_data: TTx) -> TransactionId {
        self.inner
            .add_unvalidated_inner(self.bytes, Some(self.inner.best_block_height), user_data)
    }
}

impl<'a, 'b, TTx: fmt::Debug> fmt::Debug for Vacant<'a, 'b, TTx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}

/// Utility. Calculates the BLAKE2 hash of the given bytes.
fn blake2_hash(bytes: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(blake2_rfc::blake2b::blake2b(32, &[], bytes).as_bytes()).unwrap()
}

// TODO: needs tests
