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

#![deny(rustdoc::broken_intra_doc_links)]
// TODO: #![deny(unused_crate_dependencies)] doesn't work because some deps are used only by the binary, figure if this can be fixed?

use futures_channel::oneshot;
use futures_util::{stream, FutureExt as _, StreamExt as _};
use smol::future;
use smoldot::{
    chain, chain_spec,
    database::full_sqlite,
    executor, header,
    identity::keystore,
    informant::HashDisplay,
    libp2p::{
        connection, multiaddr,
        peer_id::{self, PeerId},
    },
};
use std::{
    borrow::Cow, future::Future, iter, net::SocketAddr, path::PathBuf, pin::Pin, sync::Arc, thread,
    time::Duration,
};

mod consensus_service;
mod database_thread;
mod jaeger_service;
mod json_rpc_service;
mod network_service;
mod util;

#[derive(Debug)]
pub struct Config<'a> {
    /// Chain to connect to.
    pub chain: ChainConfig<'a>,
    /// If [`Config::chain`] contains a parachain, this field contains the configuration of the
    /// relay chain.
    pub relay_chain: Option<ChainConfig<'a>>,
    /// Ed25519 private key of network identity.
    pub libp2p_key: [u8; 32],
    /// List of addresses to listen on.
    pub listen_addresses: Vec<multiaddr::Multiaddr>,
    /// Bind point of the JSON-RPC server. If `None`, no server is started.
    pub json_rpc_address: Option<SocketAddr>,
    /// Address of a Jaeger agent to send traces to. If `None`, do not send Jaeger traces.
    pub jaeger_agent: Option<SocketAddr>,
    // TODO: option is a bit weird
    pub show_informant: bool,
    // TODO: option is a bit weird
    pub informant_colors: bool,
}

#[derive(Debug)]
pub struct ChainConfig<'a> {
    /// Specification of the chain.
    pub chain_spec: Cow<'a, [u8]>,
    /// Identity and address of nodes to try to connect to on startup.
    pub additional_bootnodes: Vec<(peer_id::PeerId, multiaddr::Multiaddr)>,
    /// List of secret phrases to insert in the keystore of the node. Used to author blocks.
    // TODO: also automatically add the same keys through ed25519?
    pub keystore_memory: Vec<[u8; 64]>,
    /// Path to the SQLite database. If `None`, the database is opened in memory.
    pub sqlite_database_path: Option<PathBuf>,
    /// Maximum size, in bytes, of the cache SQLite uses.
    pub sqlite_cache_size: usize,
    /// Path to the directory where cryptographic keys are stored on disk.
    ///
    /// If `None`, no keys are stored in disk.
    pub keystore_path: Option<PathBuf>,
}

/// Runs the node using the given configuration. Catches `SIGINT` signals and stops if one is
/// detected.
// TODO: should return an error if something bad happens instead of panicking
pub async fn run_until(config: Config<'_>, until: Pin<Box<dyn Future<Output = ()>>>) {
    let chain_spec = {
        smoldot::chain_spec::ChainSpec::from_json_bytes(&config.chain.chain_spec)
            .expect("Failed to decode chain specs")
    };

    // TODO: don't unwrap?
    let genesis_chain_information = chain_spec.to_chain_information().unwrap().0;

    let relay_chain_spec = config.relay_chain.as_ref().map(|rc| {
        smoldot::chain_spec::ChainSpec::from_json_bytes(&rc.chain_spec)
            .expect("Failed to decode relay chain chain specs")
    });

    // TODO: don't unwrap?
    let relay_genesis_chain_information = relay_chain_spec
        .as_ref()
        .map(|relay_chain_spec| relay_chain_spec.to_chain_information().unwrap().0);

    // Create an executor where tasks are going to be spawned onto.
    let executor = Arc::new(smol::Executor::new());
    for n in 0..thread::available_parallelism()
        .map(|n| n.get() - 1)
        .unwrap_or(3)
    {
        let executor = executor.clone();

        let spawn_result = thread::Builder::new()
            .name(format!("tasks-pool-{}", n))
            .spawn(move || smol::block_on(executor.run(future::pending::<()>())));

        // Ignore a failure to spawn a thread, as we're going to run tasks on the current thread
        // later down this function.
        if let Err(err) = spawn_result {
            log::warn!("tasks-pool-thread-spawn-failure; err={}", err);
        }
    }

    let (database, database_existed) = {
        let (db, existed) = open_database(
            &chain_spec,
            genesis_chain_information.as_ref(),
            config.chain.sqlite_database_path,
            config.chain.sqlite_cache_size,
            config.show_informant,
        )
        .await;

        (Arc::new(database_thread::DatabaseThread::from(db)), existed)
    };

    let relay_chain_database = if let Some(relay_chain) = &config.relay_chain {
        Some(Arc::new(database_thread::DatabaseThread::from(
            open_database(
                relay_chain_spec.as_ref().unwrap(),
                relay_genesis_chain_information.as_ref().unwrap().as_ref(),
                relay_chain.sqlite_database_path.clone(),
                relay_chain.sqlite_cache_size,
                config.show_informant,
            )
            .await
            .0,
        )))
    } else {
        None
    };

    let database_finalized_block_hash = database
        .with_database(|db| db.finalized_block_hash().unwrap())
        .await;
    let database_finalized_block_number = header::decode(
        &database
            .with_database(move |db| {
                db.block_scale_encoded_header(&database_finalized_block_hash)
                    .unwrap()
                    .unwrap()
            })
            .await,
        chain_spec.block_number_bytes().into(),
    )
    .unwrap()
    .number;

    let noise_key = connection::NoiseKey::new(&config.libp2p_key);
    let local_peer_id =
        peer_id::PublicKey::Ed25519(*noise_key.libp2p_public_ed25519_key()).into_peer_id();

    let genesis_block_hash = genesis_chain_information
        .as_ref()
        .finalized_block_header
        .hash(chain_spec.block_number_bytes().into());

    let jaeger_service = jaeger_service::JaegerService::new(jaeger_service::Config {
        tasks_executor: &mut |task| executor.spawn(task).detach(),
        service_name: local_peer_id.to_string(),
        jaeger_agent: config.jaeger_agent,
    })
    .await
    .unwrap();

    let (network_service, network_events_receivers) =
        network_service::NetworkService::new(network_service::Config {
            listen_addresses: config.listen_addresses,
            num_events_receivers: 2 + if relay_chain_database.is_some() { 1 } else { 0 },
            chains: iter::once(network_service::ChainConfig {
                fork_id: chain_spec.fork_id().map(|n| n.to_owned()),
                block_number_bytes: usize::from(chain_spec.block_number_bytes()),
                database: database.clone(),
                has_grandpa_protocol: matches!(
                    genesis_chain_information.as_ref().finality,
                    chain::chain_information::ChainInformationFinalityRef::Grandpa { .. }
                ),
                genesis_block_hash,
                best_block: {
                    let block_number_bytes = chain_spec.block_number_bytes();
                    database
                        .with_database(move |database| {
                            let hash = database.finalized_block_hash().unwrap();
                            let header = database.block_scale_encoded_header(&hash).unwrap().unwrap();
                            let number = header::decode(&header, block_number_bytes.into(),).unwrap().number;
                            (number, hash)
                        })
                        .await
                },
                bootstrap_nodes: {
                    let mut list = Vec::with_capacity(
                        chain_spec.boot_nodes().len() + config.chain.additional_bootnodes.len(),
                    );

                    for node in chain_spec.boot_nodes() {
                        match node {
                            chain_spec::Bootnode::UnrecognizedFormat(raw) => {
                                panic!("Failed to parse bootnode in chain specification: {raw}")
                            }
                            chain_spec::Bootnode::Parsed { multiaddr, peer_id } => {
                                let multiaddr: multiaddr::Multiaddr = match multiaddr.parse() {
                                    Ok(a) => a,
                                    Err(_) => panic!(
                                        "Failed to parse bootnode in chain specification: {multiaddr}"
                                    ),
                                };
                                let peer_id = PeerId::from_bytes(peer_id.to_vec()).unwrap();
                                list.push((peer_id, multiaddr));
                            }
                        }
                    }

                    list.extend(config.chain.additional_bootnodes);
                    list
                },
            })
            .chain(
                if let Some(relay_chains_specs) = &relay_chain_spec {
                    Some(network_service::ChainConfig {
                        fork_id: relay_chains_specs.fork_id().map(|n| n.to_owned()),
                        block_number_bytes: usize::from(relay_chains_specs.block_number_bytes()),
                        database: relay_chain_database.clone().unwrap(),
                        has_grandpa_protocol: matches!(
                            relay_genesis_chain_information.as_ref().unwrap().as_ref().finality,
                            chain::chain_information::ChainInformationFinalityRef::Grandpa { .. }
                        ),
                        genesis_block_hash: relay_genesis_chain_information
                            .as_ref()
                            .unwrap()
                            .as_ref().finalized_block_header
                            .hash(chain_spec.block_number_bytes().into(),),
                        best_block: relay_chain_database
                            .as_ref()
                            .unwrap()
                            .with_database({
                                let block_number_bytes = chain_spec.block_number_bytes();
                                move |db| {
                                    let hash = db.finalized_block_hash().unwrap();
                                    let header = db.block_scale_encoded_header(&hash).unwrap().unwrap();
                                    let number = header::decode(&header, block_number_bytes.into()).unwrap().number;
                                    (number, hash)
                                }
                            })
                            .await,
                        bootstrap_nodes: {
                            let mut list =
                                Vec::with_capacity(relay_chains_specs.boot_nodes().len());
                            for node in relay_chains_specs.boot_nodes() {
                                match node {
                                    chain_spec::Bootnode::UnrecognizedFormat(raw) => {
                                        panic!("Failed to parse bootnode in chain specification: {raw}")
                                    }
                                    chain_spec::Bootnode::Parsed { multiaddr, peer_id } => {
                                        let multiaddr: multiaddr::Multiaddr = match multiaddr.parse() {
                                            Ok(a) => a,
                                            Err(_) => panic!(
                                                "Failed to parse bootnode in chain specification: {multiaddr}"
                                            ),
                                        };
                                        let peer_id = PeerId::from_bytes(peer_id.to_vec()).unwrap();
                                        list.push((peer_id, multiaddr));
                                    }
                                }
                            }
                            list
                        },
                    })
                } else {
                    None
                }
                .into_iter(),
            )
            .collect(),
            identify_agent_version: concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")).to_owned(),
            noise_key,
            tasks_executor: {
                let executor = executor.clone();
                Box::new(move |task| executor.spawn(task).detach())
            },
            jaeger_service: jaeger_service.clone(),
        })
        .await
        .unwrap();

    let mut network_events_receivers = network_events_receivers.into_iter();

    let keystore = Arc::new({
        let mut keystore = keystore::Keystore::new(config.chain.keystore_path, rand::random())
            .await
            .unwrap();
        for private_key in config.chain.keystore_memory {
            keystore.insert_sr25519_memory(keystore::KeyNamespace::all(), &private_key);
        }
        keystore
    });

    let consensus_service = consensus_service::ConsensusService::new(consensus_service::Config {
        tasks_executor: {
            let executor = executor.clone();
            Box::new(move |task| executor.spawn(task).detach())
        },
        genesis_block_hash,
        network_events_receiver: network_events_receivers.next().unwrap(),
        network_service: (network_service.clone(), 0),
        database,
        block_number_bytes: usize::from(chain_spec.block_number_bytes()),
        keystore,
        jaeger_service: jaeger_service.clone(),
        slot_duration_author_ratio: 43691_u16,
    })
    .await;

    let relay_chain_consensus_service = if let Some(relay_chain_database) = relay_chain_database {
        Some(
            consensus_service::ConsensusService::new(consensus_service::Config {
                tasks_executor: {
                    let executor = executor.clone();
                    Box::new(move |task| executor.spawn(task).detach())
                },
                genesis_block_hash: relay_genesis_chain_information
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .finalized_block_header
                    .hash(usize::from(
                        relay_chain_spec.as_ref().unwrap().block_number_bytes(),
                    )),
                network_events_receiver: network_events_receivers.next().unwrap(),
                network_service: (network_service.clone(), 1),
                database: relay_chain_database,
                block_number_bytes: usize::from(
                    relay_chain_spec.as_ref().unwrap().block_number_bytes(),
                ),
                keystore: Arc::new({
                    let mut keystore = keystore::Keystore::new(
                        config.relay_chain.as_ref().unwrap().keystore_path.clone(),
                        rand::random(),
                    )
                    .await
                    .unwrap();
                    for private_key in &config.relay_chain.as_ref().unwrap().keystore_memory {
                        keystore.insert_sr25519_memory(keystore::KeyNamespace::all(), private_key);
                    }
                    keystore
                }),
                jaeger_service, // TODO: consider passing a different jaeger service with a different service name
                slot_duration_author_ratio: 43691_u16,
            })
            .await,
        )
    } else {
        None
    };

    // Start the JSON-RPC service.
    // It only needs to be kept alive in order to function.
    //
    // Note that initialization can panic if, for example, the port is already occupied. It is
    // preferable to fail to start the node altogether rather than make the user believe that they
    // are connected to the JSON-RPC endpoint of the node while they are in reality connected to
    // something else.
    let _json_rpc_service = if let Some(bind_address) = config.json_rpc_address {
        let result = json_rpc_service::JsonRpcService::new(json_rpc_service::Config {
            tasks_executor: { &mut |task| executor.spawn(task).detach() },
            bind_address,
        })
        .await;

        Some(match result {
            Ok(service) => service,
            Err(err) => panic!("failed to initialize JSON-RPC endpoint: {err}"),
        })
    } else {
        None
    };

    log::info!(
        "successful-initialization; local_peer_id={}; database_is_new={:?}; \
        finalized_block_hash={}; finalized_block_number={}",
        local_peer_id,
        !database_existed,
        HashDisplay(&database_finalized_block_hash),
        database_finalized_block_number,
    );

    // Spawn the task printing the informant.
    // This is not just a dummy task that just prints on the output, but is actually the main
    // task that holds everything else alive. Without it, all the services that we have created
    // above would be cleanly dropped and nothing would happen.
    // For this reason, it must be spawned even if no informant is started, in which case we simply
    // inhibit the printing.
    let main_task = executor.spawn({
        let mut main_network_events_receiver = network_events_receivers.next().unwrap();

        async move {
            let mut informant_timer = if config.show_informant {
                smol::Timer::interval(Duration::from_millis(100))
            } else {
                smol::Timer::never()
            };
            let mut network_known_best = None;

            enum Event {
                NetworkEvent(network_service::Event),
                Informant,
            }

            loop {
                match future::or(
                    async {
                        informant_timer.next().await;
                        Event::Informant
                    },
                    async {
                        Event::NetworkEvent(main_network_events_receiver.next().await.unwrap())
                    },
                )
                .await
                {
                    Event::Informant => {
                        // We end the informant line with a `\r` so that it overwrites itself
                        // every time. If any other line gets printed, it will overwrite the
                        // informant, and the informant will then print itself below, which is
                        // a fine behaviour.
                        let sync_state = consensus_service.sync_state().await;
                        eprint!(
                            "{}\r",
                            smoldot::informant::InformantLine {
                                enable_colors: config.informant_colors,
                                chain_name: chain_spec.name(),
                                relay_chain: if let Some(relay_chain_spec) = &relay_chain_spec {
                                    let relay_sync_state = relay_chain_consensus_service
                                        .as_ref()
                                        .unwrap()
                                        .sync_state()
                                        .await;
                                    Some(smoldot::informant::RelayChain {
                                        chain_name: relay_chain_spec.name(),
                                        best_number: relay_sync_state.best_block_number,
                                    })
                                } else {
                                    None
                                },
                                max_line_width: terminal_size::terminal_size()
                                    .map_or(80, |(w, _)| w.0.into()),
                                num_peers: u64::try_from(network_service.num_peers(0).await)
                                    .unwrap_or(u64::max_value()),
                                num_network_connections: u64::try_from(
                                    network_service.num_established_connections().await
                                )
                                .unwrap_or(u64::max_value()),
                                best_number: sync_state.best_block_number,
                                finalized_number: sync_state.finalized_block_number,
                                best_hash: &sync_state.best_block_hash,
                                finalized_hash: &sync_state.finalized_block_hash,
                                network_known_best,
                            }
                        );
                    }

                    Event::NetworkEvent(network_event) => {
                        // Update `network_known_best`.
                        match network_event {
                            network_service::Event::BlockAnnounce {
                                chain_index: 0,
                                scale_encoded_header,
                                ..
                            } => match (
                                network_known_best,
                                header::decode(
                                    &scale_encoded_header,
                                    usize::from(chain_spec.block_number_bytes()),
                                ),
                            ) {
                                (Some(n), Ok(header)) if n >= header.number => {}
                                (_, Ok(header)) => network_known_best = Some(header.number),
                                (_, Err(_)) => {
                                    // Do nothing if the block is invalid. This is just for the
                                    // informant and not for consensus-related purposes.
                                }
                            },
                            network_service::Event::Connected {
                                chain_index: 0,
                                best_block_number,
                                ..
                            } => match network_known_best {
                                Some(n) if n >= best_block_number => {}
                                _ => network_known_best = Some(best_block_number),
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    });

    debug_assert!(network_events_receivers.next().is_none());

    // Run tasks in the current thread until the provided future finishes.
    let _ = executor.run(until).await;

    if config.show_informant {
        // Adding a new line after the informant so that the user's shell doesn't
        // overwrite it.
        eprintln!();
    }

    // Stop the task that holds everything alive, in order to start dropping the services.
    drop(main_task);

    // TODO: consider waiting for all the tasks to have ended, unfortunately that's not really possible
}

/// Opens the database from the file system, or create a new database if none is found.
///
/// If `db_path` is `None`, open the database in memory instead.
///
/// The returned boolean is `true` if the database existed before.
///
/// # Panic
///
/// Panics if the database can't be open. This function is expected to be called from the `main`
/// function.
///
async fn open_database(
    chain_spec: &chain_spec::ChainSpec,
    genesis_chain_information: chain::chain_information::ChainInformationRef<'_>,
    db_path: Option<PathBuf>,
    sqlite_cache_size: usize,
    show_progress: bool,
) -> (full_sqlite::SqliteFullDatabase, bool) {
    // The `unwrap()` here can panic for example in case of access denied.
    match background_open_database(
        db_path.clone(),
        chain_spec.block_number_bytes().into(),
        sqlite_cache_size,
        show_progress,
    )
    .await
    .unwrap()
    {
        // Database already exists and contains data.
        full_sqlite::DatabaseOpen::Open(database) => {
            if database.block_hash_by_number(0).unwrap().next().unwrap()
                != genesis_chain_information
                    .finalized_block_header
                    .hash(chain_spec.block_number_bytes().into())
            {
                panic!("Mismatch between database and chain specification. Shutting down node.");
            }

            (database, true)
        }

        // The database doesn't exist or is empty.
        full_sqlite::DatabaseOpen::Empty(empty) => {
            let genesis_storage = chain_spec.genesis_storage().into_genesis_items().unwrap(); // TODO: return error instead

            // In order to determine the state_version of the genesis block, we need to compile
            // the runtime.
            // TODO: return errors instead of panicking
            let state_version = executor::host::HostVmPrototype::new(executor::host::Config {
                module: genesis_storage.value(b":code").unwrap(),
                heap_pages: executor::storage_heap_pages_to_value(
                    genesis_storage.value(b":heappages"),
                )
                .unwrap(),
                exec_hint: executor::vm::ExecHint::Oneshot,
                allow_unresolved_imports: true,
            })
            .unwrap()
            .runtime_version()
            .decode()
            .state_version
            .map(u8::from)
            .unwrap_or(0);

            // The finalized block is the genesis block. As such, it has an empty body and
            // no justification.
            let database = empty
                .initialize(
                    genesis_chain_information,
                    iter::empty(),
                    None,
                    genesis_storage.iter(),
                    state_version,
                )
                .unwrap();
            (database, false)
        }
    }
}

/// Since opening the database can take a long time, this utility function performs this operation
/// in the background while showing a small progress bar to the user.
///
/// If `path` is `None`, the database is opened in memory.
async fn background_open_database(
    path: Option<PathBuf>,
    block_number_bytes: usize,
    sqlite_cache_size: usize,
    show_progress: bool,
) -> Result<full_sqlite::DatabaseOpen, full_sqlite::InternalError> {
    let (tx, rx) = oneshot::channel();
    let mut rx = rx.fuse();

    let thread_spawn_result = thread::Builder::new().name("database-open".into()).spawn({
        let path = path.clone();
        move || {
            let result = full_sqlite::open(full_sqlite::Config {
                block_number_bytes,
                cache_size: sqlite_cache_size,
                ty: if let Some(path) = &path {
                    full_sqlite::ConfigTy::Disk(path)
                } else {
                    full_sqlite::ConfigTy::Memory
                },
            });
            let _ = tx.send(result);
        }
    });

    // Fall back to opening the database on the same thread if the thread spawn failed.
    if thread_spawn_result.is_err() {
        return full_sqlite::open(full_sqlite::Config {
            block_number_bytes,
            cache_size: sqlite_cache_size,
            ty: if let Some(path) = &path {
                full_sqlite::ConfigTy::Disk(path)
            } else {
                full_sqlite::ConfigTy::Memory
            },
        });
    }

    let mut progress_timer =
        stream::StreamExt::fuse(smol::Timer::after(Duration::from_millis(200)));

    let mut next_progress_icon = ['-', '\\', '|', '/'].iter().copied().cycle();

    loop {
        futures_util::select! {
            res = rx => return res.unwrap(),
            _ = progress_timer.next() => {
                if show_progress {
                    eprint!("    Opening database... {}\r", next_progress_icon.next().unwrap());
                }
            }
        }
    }
}
