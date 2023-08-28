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

//! Background synchronization service.
//!
//! The [`ConsensusService`] manages a background task dedicated to synchronizing the chain with
//! the network and authoring blocks.
//! Importantly, its design is oriented towards the particular use case of the full node.

// TODO: doc
// TODO: re-review this once finished

use crate::{database_thread, jaeger_service, network_service, LogCallback, LogLevel};

use core::num::NonZeroU32;
use futures_channel::{mpsc, oneshot};
use futures_util::{future, stream, FutureExt as _, SinkExt as _, StreamExt as _};
use hashbrown::HashSet;
use smol::lock::Mutex;
use smoldot::{
    author,
    chain::chain_information,
    database::full_sqlite,
    executor, header,
    identity::keystore,
    informant::HashDisplay,
    libp2p,
    network::{self, protocol::BlockData},
    sync::all,
    trie,
    verify::body_only::{self, TrieEntryVersion},
};
use std::{
    array,
    borrow::Cow,
    iter, mem,
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Configuration for a [`ConsensusService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(future::BoxFuture<'static, ()>) + Send>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Database to use to read and write information about the chain.
    pub database: Arc<database_thread::DatabaseThread>,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// Hash of the genesis block.
    ///
    /// > **Note**: At the time of writing of this comment, the value in this field is used only
    /// >           to compare against a known genesis hash and print a warning.
    pub genesis_block_hash: [u8; 32],

    /// Stores of key to use for all block-production-related purposes.
    pub keystore: Arc<keystore::Keystore>,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (Arc<network_service::NetworkService>, usize),

    /// Receiver for events coming from the network, as returned by
    /// [`network_service::NetworkService::new`].
    pub network_events_receiver: stream::BoxStream<'static, network_service::Event>,

    /// Service to use to report traces.
    pub jaeger_service: Arc<jaeger_service::JaegerService>,

    /// A node has the authorization to author a block during a slot.
    ///
    /// In order for the network to perform well, a block should be authored and propagated
    /// throughout the peer-to-peer network before the end of the slot. In order for this to
    /// happen, the block creation process itself should end a few seconds before the end of the
    /// slot. This threshold after which the block creation should end is determined by this value.
    ///
    /// The moment in the slot when the authoring ends is determined by
    /// `slot_duration * slot_duration_author_ratio / u16::max_value()`.
    /// For example, passing `u16::max_value()` means that the entire slot is used. Passing
    /// `u16::max_value() / 2` means that half of the slot is used.
    ///
    /// A typical value is `43691_u16`, representing 2/3 of a slot.
    ///
    /// Note that this value doesn't determine the moment when creating the block has ended, but
    /// the moment when creating the block should start its final phase.
    pub slot_duration_author_ratio: u16,
}

/// Identifier for a blocks request to be performed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BlocksRequestId(usize);

/// Summary of the state of the [`ConsensusService`].
#[derive(Debug, Clone)]
pub struct SyncState {
    pub best_block_number: u64,
    pub best_block_hash: [u8; 32],
    pub finalized_block_number: u64,
    pub finalized_block_hash: [u8; 32],
}

/// Background task that verifies blocks and emits requests.
pub struct ConsensusService {
    /// Used to communicate with the background task. Also used for the background task to detect
    /// a shutdown.
    to_background_tx: Mutex<mpsc::Sender<ToBackground>>,
}

enum ToBackground {
    GetSyncState {
        result_tx: oneshot::Sender<SyncState>,
    },
}

/// Potential error when calling [`ConsensusService::new`].
#[derive(Debug, derive_more::Display)]
pub enum InitError {
    /// Error accessing the database.
    DatabaseAccess(full_sqlite::AccessError),
    /// Error parsing the header of a block in the database.
    InvalidHeader(header::Error),
    /// `:code` key is missing from the finalized block storage.
    FinalizedCodeMissing,
    /// Error parsing the `:heappages` of the finalized block.
    FinalizedHeapPagesInvalid(executor::InvalidHeapPagesError),
    /// Error initializing the runtime of the finalized block.
    FinalizedRuntimeInit(executor::host::NewErr),
}

impl ConsensusService {
    /// Initializes the [`ConsensusService`] with the given configuration.
    pub async fn new(config: Config) -> Result<Arc<Self>, InitError> {
        // Perform the initial access to the database to load a bunch of information.
        let (
            finalized_block_number,
            finalized_heap_pages,
            finalized_code,
            best_block_hash,
            best_block_number,
            finalized_chain_information,
        ) = config
            .database
            .with_database({
                let block_number_bytes = config.block_number_bytes;
                move |database| {
                    // If the previous run of the full node crashed, the database will contain
                    // blocks that are no longer useful in any way. We purge them all here.
                    database
                        .purge_finality_orphans()
                        .map_err(InitError::DatabaseAccess)?;

                    let finalized_block_hash = database
                        .finalized_block_hash()
                        .map_err(InitError::DatabaseAccess)?;
                    let finalized_block_number = header::decode(
                        &database
                            .block_scale_encoded_header(&finalized_block_hash)
                            .map_err(InitError::DatabaseAccess)?
                            .unwrap(), // A panic here would indicate a bug in the database code.
                        block_number_bytes,
                    )
                    .map_err(InitError::InvalidHeader)?
                    .number;
                    let best_block_hash = database.best_block_hash().unwrap();
                    let best_block_number = header::decode(
                        &database
                            .block_scale_encoded_header(&best_block_hash)
                            .map_err(InitError::DatabaseAccess)?
                            .unwrap(), // A panic here would indicate a bug in the database code.
                        block_number_bytes,
                    )
                    .map_err(InitError::InvalidHeader)?
                    .number;
                    let finalized_chain_information =
                        match database.to_chain_information(&finalized_block_hash) {
                            Ok(info) => info,
                            Err(full_sqlite::StorageAccessError::Access(err)) => {
                                return Err(InitError::DatabaseAccess(err))
                            }
                            Err(full_sqlite::StorageAccessError::Pruned)
                            | Err(full_sqlite::StorageAccessError::UnknownBlock) => unreachable!(),
                        };
                    let finalized_code = match database.block_storage_get(
                        &finalized_block_hash,
                        iter::empty::<iter::Empty<_>>(),
                        trie::bytes_to_nibbles(b":code".iter().copied()).map(u8::from),
                    ) {
                        Ok(Some((code, _))) => code,
                        Ok(None) => return Err(InitError::FinalizedCodeMissing),
                        Err(full_sqlite::StorageAccessError::Access(err)) => {
                            return Err(InitError::DatabaseAccess(err))
                        }
                        Err(full_sqlite::StorageAccessError::Pruned)
                        | Err(full_sqlite::StorageAccessError::UnknownBlock) => unreachable!(),
                    };
                    let finalized_heap_pages = match database.block_storage_get(
                        &finalized_block_hash,
                        iter::empty::<iter::Empty<_>>(),
                        trie::bytes_to_nibbles(b":heappages".iter().copied()).map(u8::from),
                    ) {
                        Ok(Some((hp, _))) => Some(hp),
                        Ok(None) => None,
                        Err(full_sqlite::StorageAccessError::Access(err)) => {
                            return Err(InitError::DatabaseAccess(err))
                        }
                        Err(full_sqlite::StorageAccessError::Pruned)
                        | Err(full_sqlite::StorageAccessError::UnknownBlock) => unreachable!(),
                    };
                    Ok((
                        finalized_block_number,
                        finalized_heap_pages,
                        finalized_code,
                        best_block_hash,
                        best_block_number,
                        finalized_chain_information,
                    ))
                }
            })
            .await?;

        // The Kusama chain contains a fork hardcoded in the official Polkadot client.
        // See <https://github.com/paritytech/polkadot/blob/93f45f996a3d5592a57eba02f91f2fc2bc5a07cf/node/service/src/grandpa_support.rs#L111-L216>
        // Because we don't want to support this in smoldot, a warning is printed instead if we
        // recognize Kusama.
        // See also <https://github.com/paritytech/smoldot/issues/1866>.
        if config.genesis_block_hash
            == [
                176, 168, 212, 147, 40, 92, 45, 247, 50, 144, 223, 183, 230, 31, 135, 15, 23, 180,
                24, 1, 25, 122, 20, 156, 169, 54, 84, 73, 158, 163, 218, 254,
            ]
            && finalized_block_number <= 1500988
        {
            config.log_callback.log(
                LogLevel::Warn,
                "The Kusama chain is known to be borked at block #1491596. The official Polkadot \
                client works around this issue by hardcoding a fork in its source code. Smoldot \
                does not support this hardcoded fork and will thus fail to sync past this block."
                    .to_string(),
            );
        }

        let mut sync = all::AllSync::new(all::Config {
            chain_information: finalized_chain_information,
            block_number_bytes: config.block_number_bytes,
            allow_unknown_consensus_engines: false,
            sources_capacity: 32,
            blocks_capacity: {
                // This is the maximum number of blocks between two consecutive justifications.
                1024
            },
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZeroU32::new(3).unwrap(),
            download_ahead_blocks: {
                // Assuming a verification speed of 1k blocks/sec and a 99th download time
                // percentile of two second, the number of blocks to download ahead of time
                // in order to not block is 2000.
                // In practice, however, the verification speed and download speed depend on
                // the chain and the machine of the user.
                NonZeroU32::new(2000).unwrap()
            },
            full_mode: true,
            code_trie_node_hint: None,
        });

        let finalized_runtime = {
            // Builds the runtime of the finalized block.
            // Assumed to always be valid, otherwise the block wouldn't have been
            // saved in the database, hence the large number of unwraps here.
            let heap_pages = executor::storage_heap_pages_to_value(finalized_heap_pages.as_deref())
                .map_err(InitError::FinalizedHeapPagesInvalid)?;
            executor::host::HostVmPrototype::new(executor::host::Config {
                module: finalized_code,
                heap_pages,
                exec_hint: executor::vm::ExecHint::CompileAheadOfTime, // TODO: probably should be decided by the optimisticsync
                allow_unresolved_imports: false,
            })
            .map_err(InitError::FinalizedRuntimeInit)?
        };

        let block_author_sync_source = sync.add_source(None, best_block_number, best_block_hash);

        let (block_requests_finished_tx, block_requests_finished_rx) = mpsc::channel(0);
        let (to_background_tx, to_background_rx) = mpsc::channel(4);

        let background_sync = SyncBackground {
            sync,
            block_author_sync_source,
            block_authoring: None,
            authored_block: None,
            slot_duration_author_ratio: config.slot_duration_author_ratio,
            keystore: config.keystore,
            finalized_runtime: Arc::new(Mutex::new(Some(finalized_runtime))),
            network_service: config.network_service.0,
            network_chain_index: config.network_service.1,
            to_background_rx,
            from_network_service: config.network_events_receiver,
            database: config.database,
            peers_source_id_map: Default::default(),
            tasks_executor: config.tasks_executor,
            log_callback: config.log_callback,
            block_requests_finished_tx,
            block_requests_finished_rx,
            jaeger_service: config.jaeger_service,
        };

        background_sync.start();

        Ok(Arc::new(ConsensusService {
            to_background_tx: Mutex::new(to_background_tx),
        }))
    }

    /// Returns a summary of the state of the service.
    ///
    /// > **Important**: This doesn't represent the content of the database.
    // TODO: maybe remove this in favour of the database; seems like a better idea
    pub async fn sync_state(&self) -> SyncState {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background_tx
            .lock()
            .await
            .send(ToBackground::GetSyncState { result_tx })
            .await;
        result_rx.await.unwrap()
    }
}

struct SyncBackground {
    /// State machine containing the list of all the peers, all the non-finalized blocks, and all
    /// the network requests in progress.
    ///
    /// Each peer holds a struct containing either information about a networking peer, or `None`
    /// if this is the "special source" representing the local block authoring. Only one source
    /// must contain `None` and its id must be [`SyncBackground::block_author_sync_source`].
    ///
    /// Each block holds its runtime if it has been verified.
    ///
    /// Some of the sources can represent networking peers that have already been disconnected. If
    /// that is the case, no new request is started against these sources but existing requests
    /// are allowed to finish.
    /// This "trick" is necessary in order to not cancel requests that have already been started
    /// against a peer when it disconnects and that might already have a response.
    ///
    /// Each on-going request has a corresponding background task that sends its result to
    /// [`SyncBackground::block_requests_finished_rx`].
    sync: all::AllSync<(), Option<NetworkSourceInfo>, NonFinalizedBlock>,

    /// Source within the [`SyncBackground::sync`] to use to import locally-authored blocks.
    block_author_sync_source: all::SourceId,

    /// State of the authoring. If `None`, the builder should be (re)created. If `Some`, also
    /// contains the list of public keys that were loaded from the keystore when creating the
    /// builder.
    ///
    /// The difference between a value of `None` and a value of `Some(Builder::Idle)` is that
    /// `None` indicates that we should try to author a block as soon as possible, while `Idle`
    /// means that we shouldn't try again until some event occurs (at which point this field is
    /// set to `None`). For instance, if the operation of building a block fails, the state is set
    /// to `Idle` so as to avoid trying to create a block over and over again.
    // TODO: this list of public keys is a bit hacky
    block_authoring: Option<(author::build::Builder, Vec<[u8; 32]>)>,

    /// See [`Config::slot_duration_author_ratio`].
    slot_duration_author_ratio: u16,

    /// After a block has been authored, it is inserted here while waiting for the `sync` to
    /// import it. Contains the block height, the block hash, the SCALE-encoded block header, and
    /// the list of SCALE-encoded extrinsics of the block.
    authored_block: Option<(u64, [u8; 32], Vec<u8>, Vec<Vec<u8>>)>,

    /// See [`Config::keystore`].
    keystore: Arc<keystore::Keystore>,

    /// Runtime of the latest finalized block.
    ///
    /// The runtime is extracted when necessary then put back it place.
    ///
    /// The `Arc` is shared with [`NonFinalizedBlock::Verified::runtime`].
    finalized_runtime: Arc<Mutex<Option<executor::host::HostVmPrototype>>>,

    /// Used to receive messages from the frontend service, and to detect when it shuts down.
    to_background_rx: mpsc::Receiver<ToBackground>,

    /// Service managing the connections to the networking peers.
    network_service: Arc<network_service::NetworkService>,

    /// Index, within the [`SyncBackground::network_service`], of the chain that this sync service
    /// is syncing from. This value must be passed as parameter when starting requests on the
    /// network service.
    network_chain_index: usize,

    /// Stream of events coming from the [`SyncBackground::network_service`]. Used to know what
    /// happens on the peer-to-peer network.
    from_network_service: stream::BoxStream<'static, network_service::Event>,

    /// For each networking peer, the identifier of the source in [`SyncBackground::sync`].
    /// This map is kept up-to-date with the "chain connections" of the network service. Whenever
    /// a connection is established with a peer, an entry is inserted in this map and a source is
    /// added to [`SyncBackground::sync`], and whenever a connection is closed, the map entry and
    /// source are removed.
    peers_source_id_map: hashbrown::HashMap<libp2p::PeerId, all::SourceId, fnv::FnvBuildHasher>,

    /// See [`Config::tasks_executor`].
    tasks_executor: Box<dyn FnMut(future::BoxFuture<'static, ()>) + Send>,

    /// See [`Config::log_callback`].
    log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Block requests that have been emitted on the networking service and that are still in
    /// progress. Each entry in this field also has an entry in [`SyncBackground::sync`].
    block_requests_finished_rx: mpsc::Receiver<(
        all::RequestId,
        all::SourceId,
        Result<Vec<BlockData>, network_service::BlocksRequestError>,
    )>,

    /// Sending side of [`SyncBackground::block_requests_finished_rx`].
    block_requests_finished_tx: mpsc::Sender<(
        all::RequestId,
        all::SourceId,
        Result<Vec<BlockData>, network_service::BlocksRequestError>,
    )>,

    /// See [`Config::database`].
    database: Arc<database_thread::DatabaseThread>,

    /// How to report events about blocks.
    jaeger_service: Arc<jaeger_service::JaegerService>,
}

#[derive(Clone)]
enum NonFinalizedBlock {
    NotVerified,
    Verified {
        /// Runtime of the block. Generally either identical to its parent's runtime, or a
        /// different one.
        ///
        /// The `Arc` is shared with [`SyncBackground::finalized_runtime`].
        runtime: Arc<Mutex<Option<executor::host::HostVmPrototype>>>,
    },
}

/// Information about a source in the sync state machine.
#[derive(Debug, Clone)]
struct NetworkSourceInfo {
    /// Identity of the peer according to the networking.
    peer_id: libp2p::PeerId,
    /// If `true`, this peer is considered disconnected by the network, and no new request should
    /// be started against it.
    is_disconnected: bool,
}

impl SyncBackground {
    fn start(mut self) {
        // This function is a small hack because I didn't find a better way to store the executor
        // within `Background` while at the same time spawning the `Background` using said
        // executor.
        let mut actual_executor =
            mem::replace(&mut self.tasks_executor, Box::new(|_| unreachable!()));
        let (tx, rx) = oneshot::channel();
        actual_executor(Box::pin(async move {
            let actual_executor = rx.await.unwrap();
            self.tasks_executor = actual_executor;
            self.run().await;
        }));
        tx.send(actual_executor).unwrap_or_else(|_| panic!());
    }

    async fn run(mut self) {
        loop {
            self.start_network_requests().await;
            let (new_self, must_loop_again_asap) = self.process_blocks().await;
            self = new_self;

            // Creating the block authoring state and prepare a future that is ready when something
            // related to the block authoring is ready.
            // TODO: refactor as a separate task?
            let mut authoring_ready_future = {
                // TODO: overhead to call best_block_consensus() multiple times
                let local_authorities = {
                    let namespace_filter = match self.sync.best_block_consensus() {
                        chain_information::ChainInformationConsensusRef::Aura { .. } => {
                            Some(keystore::KeyNamespace::Aura)
                        }
                        chain_information::ChainInformationConsensusRef::Babe { .. } => {
                            Some(keystore::KeyNamespace::Babe)
                        }
                        chain_information::ChainInformationConsensusRef::Unknown => {
                            // In `Unknown` mode, all keys are accepted and there is no
                            // filter on the namespace, as we can't author blocks anyway.
                            // TODO: is that correct?
                            None
                        }
                    };

                    // Calling `keys()` on the keystore is racy, but that's considered
                    // acceptable and part of the design of the node.
                    self.keystore
                        .keys()
                        .await
                        .filter(|(namespace, _)| namespace_filter.map_or(true, |n| *namespace == n))
                        .map(|(_, key)| key)
                        .collect::<Vec<_>>() // TODO: collect overhead :-/
                };

                let block_authoring =
                    match (&mut self.block_authoring, self.sync.best_block_consensus()) {
                        (Some(ba), _) => Some(ba),
                        (
                            block_authoring @ None,
                            chain_information::ChainInformationConsensusRef::Aura {
                                finalized_authorities_list, // TODO: field name not appropriate; should probably change the chain_information module
                                slot_duration,
                            },
                        ) => Some(
                            block_authoring.insert((
                                author::build::Builder::new(author::build::Config {
                                    consensus: author::build::ConfigConsensus::Aura {
                                        current_authorities: finalized_authorities_list,
                                        local_authorities: local_authorities.iter(),
                                        now_from_unix_epoch: SystemTime::now()
                                            .duration_since(SystemTime::UNIX_EPOCH)
                                            .unwrap(),
                                        slot_duration,
                                    },
                                }),
                                local_authorities,
                            )),
                        ),
                        (None, chain_information::ChainInformationConsensusRef::Babe { .. }) => {
                            None // TODO: the block authoring doesn't support Babe at the moment
                        }
                        (None, _) => todo!(),
                    };

                match &block_authoring {
                    Some((author::build::Builder::Ready(_), _)) => {
                        future::Either::Left(future::Either::Left(future::ready(Instant::now())))
                    }
                    Some((author::build::Builder::WaitSlot(when), _)) => {
                        let delay = (UNIX_EPOCH + when.when())
                            .duration_since(SystemTime::now())
                            .unwrap_or_else(|_| Duration::new(0, 0));
                        future::Either::Right(future::FutureExt::fuse(smol::Timer::after(delay)))
                    }
                    None => future::Either::Left(future::Either::Right(future::pending())),
                    Some((author::build::Builder::Idle, _)) => {
                        // If the block authoring is idle, which happens in case of error,
                        // sleep for an arbitrary duration before resetting it.
                        // This prevents the authoring from trying over and over again to generate
                        // a bad block.
                        let delay = Duration::from_secs(2);
                        future::Either::Right(future::FutureExt::fuse(smol::Timer::after(delay)))
                    }
                }
            };

            futures_util::select! {
                _ = authoring_ready_future => {
                    // Ready to author a block. Call `author_block()`.
                    // While a block is being authored, the whole syncing state machine is
                    // deliberately frozen.
                    match self.block_authoring {
                        Some((author::build::Builder::Ready(_), _)) => {
                            self.author_block().await;
                            continue;
                        }
                        Some((author::build::Builder::WaitSlot(when), local_authorities)) => {
                            self.block_authoring = Some((author::build::Builder::Ready(when.start()), local_authorities));
                            self.author_block().await;
                            continue;
                        }
                        Some((author::build::Builder::Idle, _)) => {
                            self.block_authoring = None;
                            continue;
                        }
                        None => {
                            unreachable!()
                        }
                    }
                },

                frontend_event = self.to_background_rx.next().fuse() => {
                    // TODO: this isn't processed quickly enough when under load
                    match frontend_event {
                        Some(ToBackground::GetSyncState { result_tx }) => {
                            let _ = result_tx.send(SyncState {
                                best_block_hash: self.sync.best_block_hash(),
                                best_block_number: self.sync.best_block_number(),
                                finalized_block_hash: self.sync.finalized_block_header().hash(self.sync.block_number_bytes()),
                                finalized_block_number: self.sync.finalized_block_header().number,
                            });
                        },
                        None => {
                            // Shutdown.
                            return
                        },
                    }
                },

                network_event = self.from_network_service.next().fuse() => {
                    // We expect the network events channel to never shut down.
                    let network_event = network_event.unwrap();

                    match network_event {
                        network_service::Event::Connected { peer_id, chain_index, best_block_number, best_block_hash }
                            if chain_index == self.network_chain_index =>
                        {
                            // Most of the time, we insert a new source in the state machine.
                            // However, a source of that `PeerId` might already exist but be
                            // considered as disconnected. If that is the case, we simply mark it
                            // as no longer disconnected.
                            match self.peers_source_id_map.entry(peer_id) {
                                hashbrown::hash_map::Entry::Occupied(entry) => {
                                    let id = *entry.get();
                                    let is_disconnected = &mut self.sync[id].as_mut().unwrap().is_disconnected;
                                    debug_assert!(*is_disconnected);
                                    *is_disconnected = false;
                                }
                                hashbrown::hash_map::Entry::Vacant(entry) => {
                                    let id = self.sync.add_source(Some(NetworkSourceInfo {
                                        peer_id: entry.key().clone(),
                                        is_disconnected: false,
                                    }), best_block_number, best_block_hash);
                                    entry.insert(id);
                                }
                            }
                        },
                        network_service::Event::Disconnected { peer_id, chain_index }
                            if chain_index == self.network_chain_index =>
                        {
                            // Sources that disconnect are only immediately removed from the sync
                            // state machine if they have no request in progress. If that is not
                            // the case, they are instead only marked as disconnected.
                            let id = *self.peers_source_id_map.get(&peer_id).unwrap();
                            if self.sync.source_num_ongoing_requests(id) == 0 {
                                self.peers_source_id_map.remove(&peer_id).unwrap();
                                let (_, mut _requests) = self.sync.remove_source(id);
                                debug_assert!(_requests.next().is_none());
                            } else {
                                let is_disconnected = &mut self.sync[id].as_mut().unwrap().is_disconnected;
                                debug_assert!(!*is_disconnected);
                                *is_disconnected = true;
                            }
                        },
                        network_service::Event::BlockAnnounce { chain_index, peer_id, scale_encoded_header, is_best }
                            if chain_index == self.network_chain_index =>
                        {
                            let _jaeger_span = self
                                .jaeger_service
                                .block_announce_process_span(&header::hash_from_scale_encoded_header(&scale_encoded_header));

                            let id = *self.peers_source_id_map.get(&peer_id).unwrap();
                            // TODO: log the outcome
                            match self.sync.block_announce(id, scale_encoded_header, is_best) {
                                all::BlockAnnounceOutcome::HeaderVerify => {},
                                all::BlockAnnounceOutcome::TooOld { .. } => {},
                                all::BlockAnnounceOutcome::AlreadyInChain => {},
                                all::BlockAnnounceOutcome::NotFinalizedChain => {},
                                all::BlockAnnounceOutcome::Discarded => {},
                                all::BlockAnnounceOutcome::StoredForLater {} => {},
                                all::BlockAnnounceOutcome::InvalidHeader(_) => unreachable!(),
                            }
                        },
                        _ => {
                            // Different chain index.
                        }
                    }
                },

                (request_id, source_id, result) = self.block_requests_finished_rx.select_next_some() => {
                    // TODO: clarify this piece of code
                    let result = result.map_err(|_| ());
                    let (_, response_outcome) = self.sync.blocks_request_response(request_id, result.map(|v| v.into_iter().map(|block| all::BlockRequestSuccessBlock {
                        scale_encoded_header: block.header.unwrap(), // TODO: don't unwrap
                        scale_encoded_extrinsics: block.body.unwrap(), // TODO: don't unwrap
                        scale_encoded_justifications: block.justifications
                            .unwrap_or_default()
                            .into_iter()
                            .map(|j| all::Justification { engine_id: j.engine_id, justification: j.justification })
                            .collect(),
                        user_data: NonFinalizedBlock::NotVerified,
                    })));

                    match response_outcome {
                        all::ResponseOutcome::Outdated
                        | all::ResponseOutcome::Queued
                        | all::ResponseOutcome::NotFinalizedChain { .. }
                        | all::ResponseOutcome::AllAlreadyInChain { .. } => {
                        }
                    }

                    // If the source was actually disconnected and has no other request in
                    // progress, we clean it up.
                    if self.sync[source_id].as_ref().map_or(false, |info| info.is_disconnected)
                        && self.sync.source_num_ongoing_requests(source_id) == 0
                    {
                        let (info, mut _requests) = self.sync.remove_source(source_id);
                        debug_assert!(_requests.next().is_none());
                        self.peers_source_id_map.remove(&info.unwrap().peer_id).unwrap();
                    }
                },

                () = if must_loop_again_asap { either::Left(future::ready(())) } else { either::Right(future::pending()) }.fuse() => {
                    // This block exists just so that we continue looping if `must_loop_again_asap`
                    // is `true`.
                }
            }
        }
    }

    /// Authors a block, then imports it and gossips it out.
    ///
    /// # Panic
    ///
    /// The [`SyncBackground::block_authoring`] must be [`author::build::Builder::Ready`].
    ///
    async fn author_block(&mut self) {
        let (authoring_start, local_authorities) = match self.block_authoring.take() {
            Some((author::build::Builder::Ready(authoring), local_authorities)) => {
                (authoring, local_authorities)
            }
            _ => panic!(),
        };

        // TODO: it is possible that the current best block is already the same authoring slot as the slot we want to claim ; unclear how to solve this

        let parent_number = self.sync.best_block_number();
        self.log_callback.log(
            LogLevel::Debug,
            format!(
                "block-author-start; parent_hash={}; parent_number={}",
                HashDisplay(&self.sync.best_block_hash()),
                parent_number,
            ),
        );

        // We would like to create a span for authoring the new block, but the trace id depends on
        // the block hash, which is only known at the end.
        let block_author_jaeger_start_time = mick_jaeger::StartTime::now();

        // Determine when the block should stop being authored.
        //
        // In order for the network to perform well, a block should be authored and propagated
        // throughout the peer-to-peer network before the end of the slot. In order for this
        // to happen, the block creation process itself should end a few seconds before the
        // end of the slot.
        //
        // Most parts of the block authorship can't be accelerated, in particular the
        // initialization and the signing at the end. This end of authoring threshold is only
        // checked when deciding whether to continue including more transactions in the block.
        // TODO: use this
        // TODO: Substrate nodes increase the time available for authoring if it detects that slots have been skipped, in order to account for the possibility that the initialization of a block or the inclusion of an extrinsic takes too long
        let authoring_end = {
            let start = authoring_start.slot_start_from_unix_epoch();
            let end = authoring_start.slot_end_from_unix_epoch();
            debug_assert!(start < end);
            debug_assert!(SystemTime::now() >= SystemTime::UNIX_EPOCH + start);
            SystemTime::UNIX_EPOCH
                + start
                + (end - start) * u32::from(self.slot_duration_author_ratio)
                    / u32::from(u16::max_value())
        };

        // Actual block production now happening.
        let (new_block_header, new_block_body, authoring_logs) = {
            let parent_hash = self.sync.best_block_hash();
            let parent_runtime_arc =
                if self.sync.best_block_number() != self.sync.finalized_block_header().number {
                    let NonFinalizedBlock::Verified {
                        runtime: parent_runtime_arc,
                    } = &self.sync[(self.sync.best_block_number(), &self.sync.best_block_hash())]
                    else {
                        unreachable!()
                    };
                    parent_runtime_arc.clone()
                } else {
                    self.finalized_runtime.clone()
                };
            let parent_runtime = parent_runtime_arc.try_lock().unwrap().take().unwrap();

            // Start the block authoring process.
            let mut block_authoring = {
                authoring_start.start(author::build::AuthoringStartConfig {
                    block_number_bytes: self.sync.block_number_bytes(),
                    parent_hash: &self.sync.best_block_hash(),
                    parent_number: self.sync.best_block_number(),
                    now_from_unix_epoch: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap(),
                    parent_runtime,
                    block_body_capacity: 0, // TODO: could be set to the size of the tx pool
                    max_log_level: 0,
                    calculate_trie_changes: true,
                })
            };

            // The block authoring process jumps through various states, interrupted when it needs
            // access to the storage of the best block.
            loop {
                match block_authoring {
                    author::build::BuilderAuthoring::Seal(seal) => {
                        // This is the last step of the authoring. The block creation is
                        // successful, and the only thing remaining to do is sign the block
                        // header. Signing is done through `self.keystore`.

                        // TODO: correct key namespace
                        let data_to_sign = seal.to_sign();
                        let sign_future = self.keystore.sign(
                            keystore::KeyNamespace::Aura,
                            &local_authorities[seal.authority_index()],
                            &data_to_sign,
                        );

                        let success = match sign_future.await {
                            Ok(signature) => seal.inject_sr25519_signature(signature),
                            Err(error) => {
                                // Because the keystore is subject to race conditions, it is
                                // possible for this situation to happen if the key has been
                                // removed from the keystore in parallel of the block authoring
                                // process, or the key is maybe no longer accessible because of
                                // another issue.
                                self.log_callback.log(
                                    LogLevel::Warn,
                                    format!("block-author-signing-error; error={}", error),
                                );
                                self.block_authoring = None;
                                return;
                            }
                        };

                        // Put back the parent runtime that we extracted.
                        *parent_runtime_arc.try_lock().unwrap() = Some(success.parent_runtime);

                        break (success.scale_encoded_header, success.body, success.logs);
                    }

                    author::build::BuilderAuthoring::Error {
                        error,
                        parent_runtime,
                    } => {
                        // Block authoring process stopped because of an error.

                        // Put back the parent runtime that we extracted.
                        *parent_runtime_arc.try_lock().unwrap() = Some(parent_runtime);

                        // In order to prevent the block authoring from restarting immediately
                        // after and failing again repeatedly, we switch the block authoring to
                        // the same state as if it had successfully generated a block.
                        self.block_authoring = Some((author::build::Builder::Idle, Vec::new()));
                        // TODO: log the runtime logs
                        self.log_callback.log(
                            LogLevel::Warn,
                            format!("block-author-error; error={}", error),
                        );
                        return;
                    }

                    // Part of the block production consists in adding transactions to the block.
                    // These transactions are extracted from the transactions pool.
                    author::build::BuilderAuthoring::ApplyExtrinsic(apply) => {
                        // TODO: actually implement including transactions in the blocks
                        block_authoring = apply.finish();
                    }
                    author::build::BuilderAuthoring::ApplyExtrinsicResult { result, resume } => {
                        if let Err(error) = result {
                            // TODO: include transaction bytes or something?
                            self.log_callback.log(
                                LogLevel::Warn,
                                format!(
                                    "block-author-transaction-inclusion-error; error={}",
                                    error
                                ),
                            );
                        }

                        // TODO: actually implement including transactions in the blocks
                        block_authoring = resume.finish();
                    }

                    // Access to the best block storage.
                    author::build::BuilderAuthoring::StorageGet(req) => {
                        let parent_paths = req.child_trie().map(|child_trie| {
                            trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                                .map(u8::from)
                                .collect::<Vec<_>>()
                        });
                        let key = trie::bytes_to_nibbles(req.key().as_ref().iter().copied())
                            .map(u8::from)
                            .collect::<Vec<_>>();
                        let value = self
                            .database
                            .with_database(move |db| {
                                db.block_storage_get(
                                    &parent_hash,
                                    parent_paths.into_iter().map(|p| p.into_iter()),
                                    key.iter().copied(),
                                )
                            })
                            .await
                            .expect("database access error");

                        block_authoring = req.inject_value(value.as_ref().map(|(val, vers)| {
                            (
                                iter::once(&val[..]),
                                TrieEntryVersion::try_from(*vers).expect("corrupted database"),
                            )
                        }));
                    }
                    author::build::BuilderAuthoring::ClosestDescendantMerkleValue(req) => {
                        let parent_paths = req.child_trie().map(|child_trie| {
                            trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                                .map(u8::from)
                                .collect::<Vec<_>>()
                        });
                        let key_nibbles = req.key().map(u8::from).collect::<Vec<_>>();

                        let merkle_value = self
                            .database
                            .with_database(move |db| {
                                db.block_storage_closest_descendant_merkle_value(
                                    &parent_hash,
                                    parent_paths.into_iter().map(|p| p.into_iter()),
                                    key_nibbles.iter().copied(),
                                )
                            })
                            .await
                            .expect("database access error");

                        block_authoring =
                            req.inject_merkle_value(merkle_value.as_ref().map(|v| &v[..]));
                    }
                    author::build::BuilderAuthoring::NextKey(req) => {
                        let parent_paths = req.child_trie().map(|child_trie| {
                            trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                                .map(u8::from)
                                .collect::<Vec<_>>()
                        });
                        let key_nibbles = req
                            .key()
                            .map(u8::from)
                            .chain(if req.or_equal() { None } else { Some(0u8) })
                            .collect::<Vec<_>>();
                        let prefix_nibbles = req.prefix().map(u8::from).collect::<Vec<_>>();

                        let branch_nodes = req.branch_nodes();
                        let next_key = self
                            .database
                            .with_database(move |db| {
                                db.block_storage_next_key(
                                    &parent_hash,
                                    parent_paths.into_iter().map(|p| p.into_iter()),
                                    key_nibbles.iter().copied(),
                                    prefix_nibbles.iter().copied(),
                                    branch_nodes,
                                )
                            })
                            .await
                            .expect("database access error");

                        block_authoring = req
                            .inject_key(next_key.map(|k| {
                                k.into_iter().map(|b| trie::Nibble::try_from(b).unwrap())
                            }));
                    }
                    author::build::BuilderAuthoring::OffchainStorageSet(req) => {
                        // Ignore offchain storage writes at the moment.
                        block_authoring = req.resume();
                    }
                }
            }
        };

        // Block has now finished being generated.
        let new_block_hash = header::hash_from_scale_encoded_header(&new_block_header);
        self.log_callback.log(
            LogLevel::Info,
            format!(
                "block-generated; hash={}; body_len={}; runtime_logs={:?}",
                HashDisplay(&new_block_hash),
                new_block_body.len(),
                authoring_logs
            ),
        );
        let _jaeger_span = self
            .jaeger_service
            .block_authorship_span(&new_block_hash, block_author_jaeger_start_time);

        // Print a warning if generating the block has taken more time than expected.
        // This can happen because the node is completely overloaded, is running on a slow machine,
        // or if the runtime code being executed contains a very heavy operation.
        // In any case, there is not much that a node operator can do except try increase the
        // performance of their machine.
        match authoring_end.elapsed() {
            Ok(now_minus_end) if now_minus_end < Duration::from_millis(500) => {}
            _ => {
                self.log_callback.log(
                    LogLevel::Warn,
                    format!(
                        "block-generation-too-long; hash={}",
                        HashDisplay(&new_block_hash)
                    ),
                );
            }
        }

        // Switch the block authoring to a state where we won't try to generate a new block again
        // until something new happens.
        // TODO: nothing prevents the node from generating two blocks at the same height at the moment
        self.block_authoring = Some((author::build::Builder::Idle, Vec::new()));

        // The next step is to import the block in `self.sync`. This is done by pretending that
        // the local node is a source of block similar to networking peers.
        match self.sync.block_announce(
            self.block_author_sync_source,
            new_block_header.clone(),
            true, // Since the new block is a child of the current best block, it always becomes the new best.
        ) {
            all::BlockAnnounceOutcome::HeaderVerify
            | all::BlockAnnounceOutcome::StoredForLater
            | all::BlockAnnounceOutcome::Discarded => {}
            all::BlockAnnounceOutcome::TooOld { .. }
            | all::BlockAnnounceOutcome::AlreadyInChain
            | all::BlockAnnounceOutcome::NotFinalizedChain
            | all::BlockAnnounceOutcome::InvalidHeader(_) => unreachable!(),
        }

        debug_assert!(self.authored_block.is_none());
        self.authored_block = Some((
            parent_number + 1,
            new_block_hash,
            new_block_header,
            new_block_body,
        ));
    }

    /// Starts all the new network requests that should be started.
    // TODO: handle obsolete requests
    async fn start_network_requests(&mut self) {
        loop {
            // `desired_requests()` returns, in decreasing order of priority, the requests
            // that should be started in order for the syncing to proceed. We simply pick the
            // first request, but enforce one ongoing request per source.
            let (source_id, _, mut request_info) = match self.sync.desired_requests().find(
                |(source_id, source_info, request_details)| {
                    if source_info
                        .as_ref()
                        .map_or(false, |info| info.is_disconnected)
                    {
                        // Source is a networking source that has already been disconnected.
                        false
                    } else if *source_id != self.block_author_sync_source {
                        // Remote source.
                        self.sync.source_num_ongoing_requests(*source_id) == 0
                    } else {
                        // Locally-authored blocks source.
                        match (request_details, &self.authored_block) {
                            (
                                all::DesiredRequest::BlocksRequest {
                                    first_block_hash: None,
                                    first_block_height,
                                    ..
                                },
                                Some((authored_height, _, _, _)),
                            ) if first_block_height == authored_height => true,
                            (
                                all::DesiredRequest::BlocksRequest {
                                    first_block_hash: Some(first_block_hash),
                                    first_block_height,
                                    ..
                                },
                                Some((authored_height, authored_hash, _, _)),
                            ) if first_block_hash == authored_hash
                                && first_block_height == authored_height =>
                            {
                                true
                            }
                            _ => false,
                        }
                    }
                },
            ) {
                Some(v) => v,
                None => break,
            };

            // Before notifying the syncing of the request, clamp the number of blocks to the
            // number of blocks we expect to receive.
            request_info.num_blocks_clamp(NonZeroU64::new(64).unwrap());

            match request_info {
                all::DesiredRequest::BlocksRequest { .. }
                    if source_id == self.block_author_sync_source =>
                {
                    self.log_callback.log(
                        LogLevel::Debug,
                        "queue-locally-authored-block-for-import".to_string(),
                    );

                    let (_, block_hash, scale_encoded_header, scale_encoded_extrinsics) =
                        self.authored_block.take().unwrap();

                    let _jaeger_span = self.jaeger_service.block_import_queue_span(&block_hash);

                    // Create a request that is immediately answered right below.
                    let request_id = self.sync.add_request(source_id, request_info.into(), ());

                    // TODO: announce the block on the network, but only after it's been imported
                    self.sync.blocks_request_response(
                        request_id,
                        Ok(iter::once(all::BlockRequestSuccessBlock {
                            scale_encoded_header,
                            scale_encoded_extrinsics,
                            scale_encoded_justifications: Vec::new(),
                            user_data: NonFinalizedBlock::NotVerified,
                        })),
                    );
                }

                all::DesiredRequest::BlocksRequest {
                    first_block_hash,
                    first_block_height,
                    ascending,
                    num_blocks,
                    request_headers,
                    request_bodies,
                    request_justification,
                } => {
                    let peer_id = {
                        let info = self.sync[source_id].clone().unwrap();
                        // Disconnected sources are filtered out above.
                        debug_assert!(!info.is_disconnected);
                        info.peer_id
                    };

                    // TODO: add jaeger span

                    let request = self.network_service.clone().blocks_request(
                        peer_id,
                        self.network_chain_index,
                        network::protocol::BlocksRequestConfig {
                            start: if let Some(first_block_hash) = first_block_hash {
                                network::protocol::BlocksRequestConfigStart::Hash(first_block_hash)
                            } else {
                                network::protocol::BlocksRequestConfigStart::Number(
                                    first_block_height,
                                )
                            },
                            desired_count: NonZeroU32::new(
                                u32::try_from(num_blocks.get()).unwrap_or(u32::max_value()),
                            )
                            .unwrap(),
                            direction: if ascending {
                                network::protocol::BlocksRequestDirection::Ascending
                            } else {
                                network::protocol::BlocksRequestDirection::Descending
                            },
                            fields: network::protocol::BlocksRequestFields {
                                header: request_headers,
                                body: request_bodies,
                                justifications: request_justification,
                            },
                        },
                    );

                    let request_id = self.sync.add_request(source_id, request_info.into(), ());

                    (self.tasks_executor)(Box::pin({
                        let mut block_requests_finished_tx =
                            self.block_requests_finished_tx.clone();
                        async move {
                            let result = request.await;
                            let _ = block_requests_finished_tx
                                .send((request_id, source_id, result))
                                .await;
                        }
                    }));
                }
                all::DesiredRequest::GrandpaWarpSync { .. }
                | all::DesiredRequest::StorageGetMerkleProof { .. }
                | all::DesiredRequest::RuntimeCallMerkleProof { .. } => {
                    // Not used in "full" mode.
                    unreachable!()
                }
            }
        }
    }

    async fn process_blocks(mut self) -> (Self, bool) {
        // The sync state machine can be in a few various states. At the time of writing:
        // idle, verifying header, verifying block, verifying grandpa warp sync proof,
        // verifying storage proof.
        // If the state is one of the "verifying" states, perform the actual verification and
        // loop again until the sync is in an idle state.
        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        // TODO: move this?
        let block_number_bytes = self.sync.block_number_bytes();

        match self.sync.process_one() {
            all::ProcessOne::AllSync(idle) => {
                self.sync = idle;
                (self, false)
            }
            all::ProcessOne::VerifyWarpSyncFragment(_)
            | all::ProcessOne::WarpSyncBuildRuntime(_)
            | all::ProcessOne::WarpSyncBuildChainInformation(_)
            | all::ProcessOne::WarpSyncFinished { .. } => unreachable!(),
            all::ProcessOne::VerifyBlock(verify) => {
                let when_verification_started = Instant::now();
                let mut database_accesses_duration = Duration::new(0, 0);
                let mut runtime_build_duration = Duration::new(0, 0);
                let hash_to_verify = verify.hash();

                let _jaeger_span = self.jaeger_service.block_verify_span(&hash_to_verify);

                let (is_new_best, header_verification_success) =
                    match verify.verify_header(unix_time) {
                        all::HeaderVerifyOutcome::Success {
                            is_new_best,
                            success,
                        } => (is_new_best, success),
                        all::HeaderVerifyOutcome::Error { sync, error } => {
                            // Print a separate warning because it is important for the user
                            // to be aware of the verification failure.
                            // `error` is last because it's quite big.
                            self.log_callback.log(
                                LogLevel::Warn,
                                format!(
                                    "failed-block-verification; hash={}; error={}",
                                    HashDisplay(&hash_to_verify),
                                    error
                                ),
                            );
                            self.sync = sync;
                            return (self, true);
                        }
                    };

                let parent_hash = *header_verification_success.parent_hash();
                let parent_info = header_verification_success.parent_user_data().map(|b| {
                    let NonFinalizedBlock::Verified { runtime } = b else {
                        unreachable!()
                    };
                    runtime.clone()
                });
                let parent_runtime_arc = parent_info
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| self.finalized_runtime.clone());
                let parent_runtime = parent_runtime_arc.try_lock().unwrap().take().unwrap();

                let parent_scale_encoded_header =
                    header_verification_success.parent_scale_encoded_header();
                let mut body_verification = body_only::verify(body_only::Config {
                    parent_runtime,
                    parent_block_header: header::decode(
                        &parent_scale_encoded_header,
                        block_number_bytes,
                    )
                    .unwrap(),
                    now_from_unix_epoch: unix_time,
                    // TODO: shouldn't have to decode here
                    block_header: header::decode(
                        header_verification_success.scale_encoded_header(),
                        block_number_bytes,
                    )
                    .unwrap(),
                    block_number_bytes,
                    block_body: header_verification_success
                        .scale_encoded_extrinsics()
                        .unwrap(),
                    max_log_level: 3,
                    calculate_trie_changes: true,
                });

                // TODO: check this block against the chain spec's badBlocks
                loop {
                    match body_verification {
                        body_only::Verify::Finished(Err((error, parent_runtime))) => {
                            // Print a separate warning because it is important for the user
                            // to be aware of the verification failure.
                            // `error` is last because it's quite big.
                            self.log_callback.log(
                                LogLevel::Warn,
                                format!(
                                    "failed-block-verification; hash={}; height={}; \
                                total_duration={:?}; error={}",
                                    HashDisplay(&hash_to_verify),
                                    header_verification_success.height(),
                                    when_verification_started.elapsed(),
                                    error
                                ),
                            );
                            *parent_runtime_arc.try_lock().unwrap() = Some(parent_runtime);
                            self.sync = header_verification_success.reject_bad_block();
                            return (self, true);
                        }
                        body_only::Verify::Finished(Ok(body_only::Success {
                            storage_changes,
                            state_trie_version,
                            parent_runtime,
                            new_runtime,
                            ..
                        })) => {
                            // Insert the block in the database.
                            let when_database_access_started = Instant::now();
                            self.database
                                .with_database_detached({
                                    let scale_encoded_header = header_verification_success.scale_encoded_header().to_vec();
                                    move |database| {
                                        // TODO: overhead for building the SCALE encoding of the header
                                        let result = database.insert(
                                            &scale_encoded_header,
                                            is_new_best,
                                            iter::empty::<Vec<u8>>(), // TODO:,no /!\
                                            storage_changes.trie_changes_iter_ordered().unwrap().filter_map(
                                                |(_child_trie, key, change)| {
                                                    let body_only::TrieChange::InsertUpdate {
                                                        new_merkle_value,
                                                        partial_key,
                                                        children_merkle_values,
                                                        new_storage_value
                                                    } = &change
                                                        else { return None };

                                                    // TODO: this punches through abstraction layers; maybe add some code to runtime_host to indicate this?
                                                    let references_merkle_value = key.iter().copied()
                                                        .zip(trie::bytes_to_nibbles(b":child_storage:".iter().copied()))
                                                        .all(|(a, b)| a == b);

                                                    Some(full_sqlite::InsertTrieNode {
                                                        merkle_value: (&new_merkle_value[..]).into(),
                                                        children_merkle_values: array::from_fn(|n| {
                                                            children_merkle_values[n]
                                                                .as_ref()
                                                                .map(|v| From::from(&v[..]))
                                                        }),
                                                        storage_value: match new_storage_value {
                                                            body_only::TrieChangeStorageValue::Modified {
                                                                new_value: Some(value),
                                                            } => full_sqlite::InsertTrieNodeStorageValue::Value {
                                                                value: Cow::Borrowed(value),
                                                                references_merkle_value,
                                                            },
                                                            body_only::TrieChangeStorageValue::Modified {
                                                                new_value: None,
                                                            } => full_sqlite::InsertTrieNodeStorageValue::NoValue,
                                                            body_only::TrieChangeStorageValue::Unmodified => {
                                                                full_sqlite::InsertTrieNodeStorageValue::SameAsParent
                                                            }
                                                        },
                                                        partial_key_nibbles: partial_key
                                                            .iter()
                                                            .map(|n| u8::from(*n))
                                                            .collect::<Vec<_>>()
                                                            .into(),
                                                    })
                                                },
                                            ),
                                            u8::from(state_trie_version),
                                        );

                                        match result {
                                            Ok(()) => {}
                                            Err(full_sqlite::InsertError::Duplicate) => {} // TODO: this should be an error ; right now we silence them because non-finalized blocks aren't loaded from the database at startup, resulting in them being downloaded again
                                            Err(err) => panic!("{}", err),
                                        }
                                    }
                                })
                                .await;
                            database_accesses_duration += when_database_access_started.elapsed();

                            let height = header_verification_success.height();
                            let scale_encoded_header =
                                header_verification_success.scale_encoded_header().to_vec();

                            self.log_callback.log(
                                LogLevel::Debug,
                                format!(
                                    "block-verification-success; hash={}; height={}; \
                                total_duration={:?}; database_accesses_duration={:?}; \
                                runtime_build_duration={:?}; is_new_best={:?}",
                                    HashDisplay(&hash_to_verify),
                                    height,
                                    when_verification_started.elapsed(),
                                    database_accesses_duration,
                                    runtime_build_duration,
                                    is_new_best
                                ),
                            );

                            // Processing has made a step forward.

                            *parent_runtime_arc.try_lock().unwrap() = Some(parent_runtime);

                            self.sync =
                                header_verification_success.finish(NonFinalizedBlock::NotVerified);

                            // Store the storage of the children.
                            self.sync[(height, &hash_to_verify)] = NonFinalizedBlock::Verified {
                                runtime: if let Some(new_runtime) = new_runtime {
                                    Arc::new(Mutex::new(Some(new_runtime)))
                                } else {
                                    parent_runtime_arc
                                },
                            };

                            if is_new_best {
                                // Update the networking.
                                let fut = self.network_service.set_local_best_block(
                                    self.network_chain_index,
                                    self.sync.best_block_hash(),
                                    self.sync.best_block_number(),
                                );
                                fut.await;

                                // Reset the block authoring, in order to potentially build a
                                // block on top of this new best.
                                self.block_authoring = None;
                            }

                            // Announce the newly-verified block to all the sources that might
                            // not be aware of it. We can never be guaranteed that a certain
                            // source does *not* know about a block, however it is not a big
                            // problem to send a block announce to a source that already knows
                            // about that block. For this reason, the list of sources we send
                            // the block announce to is `all_sources - sources_that_know_it`.
                            //
                            // Note that not sending block announces to sources that already
                            // know that block means that these sources might also miss the
                            // fact that our local best block has been updated. This is in
                            // practice not a problem either.
                            let sources_to_announce_to = {
                                let mut all_sources =
                                    self.sync
                                        .sources()
                                        .collect::<HashSet<_, fnv::FnvBuildHasher>>();
                                for knows in
                                    self.sync.knows_non_finalized_block(height, &hash_to_verify)
                                {
                                    all_sources.remove(&knows);
                                }
                                all_sources
                            };

                            for source_id in sources_to_announce_to {
                                let peer_id = match &self.sync[source_id] {
                                    Some(info) if !info.is_disconnected => &info.peer_id,
                                    _ => continue,
                                };

                                if self
                                    .network_service
                                    .clone()
                                    .send_block_announce(
                                        peer_id.clone(),
                                        0,
                                        scale_encoded_header.clone(),
                                        is_new_best,
                                    )
                                    .await
                                    .is_ok()
                                {
                                    // Note that `try_add_known_block_to_source` might have
                                    // no effect, which is not a problem considering that this
                                    // block tracking is mostly about optimizations and
                                    // politeness.
                                    self.sync.try_add_known_block_to_source(
                                        source_id,
                                        height,
                                        hash_to_verify,
                                    );
                                }
                            }

                            return (self, true);
                        }

                        body_only::Verify::StorageGet(req) => {
                            let when_database_access_started = Instant::now();
                            let parent_paths = req.child_trie().map(|child_trie| {
                                trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                    .chain(trie::bytes_to_nibbles(
                                        child_trie.as_ref().iter().copied(),
                                    ))
                                    .map(u8::from)
                                    .collect::<Vec<_>>()
                            });
                            let key = trie::bytes_to_nibbles(req.key().as_ref().iter().copied())
                                .map(u8::from)
                                .collect::<Vec<_>>();
                            let value = self
                                .database
                                .with_database(move |db| {
                                    db.block_storage_get(
                                        &parent_hash,
                                        parent_paths.into_iter().map(|p| p.into_iter()),
                                        key.iter().copied(),
                                    )
                                })
                                .await
                                .expect("database access error");
                            let value = value.as_ref().map(|(val, vers)| {
                                (
                                    iter::once(&val[..]),
                                    TrieEntryVersion::try_from(*vers).expect("corrupted database"),
                                )
                            });

                            database_accesses_duration += when_database_access_started.elapsed();
                            body_verification = req.inject_value(value);
                        }
                        body_only::Verify::StorageClosestDescendantMerkleValue(req) => {
                            let when_database_access_started = Instant::now();

                            let parent_paths = req.child_trie().map(|child_trie| {
                                trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                    .chain(trie::bytes_to_nibbles(
                                        child_trie.as_ref().iter().copied(),
                                    ))
                                    .map(u8::from)
                                    .collect::<Vec<_>>()
                            });
                            let key_nibbles = req.key().map(u8::from).collect::<Vec<_>>();

                            let merkle_value = self
                                .database
                                .with_database(move |db| {
                                    db.block_storage_closest_descendant_merkle_value(
                                        &parent_hash,
                                        parent_paths.into_iter().map(|p| p.into_iter()),
                                        key_nibbles.iter().copied(),
                                    )
                                })
                                .await
                                .expect("database access error");

                            database_accesses_duration += when_database_access_started.elapsed();
                            body_verification =
                                req.inject_merkle_value(merkle_value.as_ref().map(|v| &v[..]));
                        }
                        body_only::Verify::StorageNextKey(req) => {
                            let when_database_access_started = Instant::now();

                            let parent_paths = req.child_trie().map(|child_trie| {
                                trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                    .chain(trie::bytes_to_nibbles(
                                        child_trie.as_ref().iter().copied(),
                                    ))
                                    .map(u8::from)
                                    .collect::<Vec<_>>()
                            });
                            let key_nibbles = req
                                .key()
                                .map(u8::from)
                                .chain(if req.or_equal() { None } else { Some(0u8) })
                                .collect::<Vec<_>>();
                            let prefix_nibbles = req.prefix().map(u8::from).collect::<Vec<_>>();

                            let branch_nodes = req.branch_nodes();
                            let next_key = self
                                .database
                                .with_database(move |db| {
                                    db.block_storage_next_key(
                                        &parent_hash,
                                        parent_paths.into_iter().map(|p| p.into_iter()),
                                        key_nibbles.iter().copied(),
                                        prefix_nibbles.iter().copied(),
                                        branch_nodes,
                                    )
                                })
                                .await
                                .expect("database access error");

                            database_accesses_duration += when_database_access_started.elapsed();
                            body_verification = req.inject_key(next_key.map(|k| {
                                k.into_iter().map(|b| trie::Nibble::try_from(b).unwrap())
                            }));
                        }
                        body_only::Verify::OffchainStorageSet(req) => {
                            // Ignore offchain storage writes at the moment.
                            body_verification = req.resume();
                        }
                        body_only::Verify::RuntimeCompilation(rt) => {
                            let before_runtime_build = Instant::now();
                            let outcome = rt.build();
                            runtime_build_duration += before_runtime_build.elapsed();
                            body_verification = outcome;
                        }
                    }
                }
            }

            all::ProcessOne::VerifyFinalityProof(verify) => {
                match verify.perform(rand::random()) {
                    (
                        sync_out,
                        all::FinalityProofVerifyOutcome::NewFinalized {
                            mut finalized_blocks,
                            updates_best_block,
                        },
                    ) => {
                        self.log_callback.log(
                            LogLevel::Debug,
                            "finality-proof-verification; outcome=success".to_string(),
                        );
                        self.sync = sync_out;

                        if updates_best_block {
                            let fut = self.network_service.set_local_best_block(
                                self.network_chain_index,
                                self.sync.best_block_hash(),
                                self.sync.best_block_number(),
                            );
                            fut.await;

                            // Reset the block authoring, in order to potentially build a
                            // block on top of this new best.
                            self.block_authoring = None;
                        }

                        let finalized_block = finalized_blocks.pop().unwrap();
                        let NonFinalizedBlock::Verified { runtime } = finalized_block.user_data
                        else {
                            unreachable!()
                        };
                        self.finalized_runtime = runtime;
                        let new_finalized_hash =
                            finalized_block.header.hash(self.sync.block_number_bytes());
                        // TODO: what if best block changed?
                        self.database
                            .with_database_detached(move |database| {
                                database.set_finalized(&new_finalized_hash).unwrap();
                            })
                            .await;
                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::GrandpaCommitPending) => {
                        self.log_callback.log(
                            LogLevel::Debug,
                            "finality-proof-verification; outcome=pending".to_string(),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::AlreadyFinalized) => {
                        self.log_callback.log(
                            LogLevel::Debug,
                            "finality-proof-verification; outcome=already-finalized".to_string(),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::GrandpaCommitError(error)) => {
                        self.log_callback.log(
                            LogLevel::Warn,
                            format!("finality-proof-verification-failure; error={}", error),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::JustificationError(error)) => {
                        self.log_callback.log(
                            LogLevel::Warn,
                            format!("finality-proof-verification-failure; error={}", error),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                }
            }
        }
    }
}
