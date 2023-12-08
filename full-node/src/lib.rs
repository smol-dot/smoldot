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

use futures_util::{future, StreamExt as _};
use rand::RngCore as _;
use smol::lock::Mutex;
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
    trie,
};
use std::{array, borrow::Cow, io, iter, mem, net::SocketAddr, path::PathBuf, sync::Arc};

mod consensus_service;
mod database_thread;
mod jaeger_service;
mod json_rpc_service;
mod network_service;
mod util;

pub struct Config<'a> {
    /// Chain to connect to.
    pub chain: ChainConfig<'a>,
    /// If [`Config::chain`] contains a parachain, this field contains the configuration of the
    /// relay chain.
    pub relay_chain: Option<ChainConfig<'a>>,
    /// Ed25519 private key of network identity.
    pub libp2p_key: Box<[u8; 32]>,
    /// List of addresses to listen on.
    pub listen_addresses: Vec<multiaddr::Multiaddr>,
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(future::BoxFuture<'static, ()>) + Send + Sync>,
    /// Function called whenever a part of the node wants to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,
    /// Address of a Jaeger agent to send traces to. If `None`, do not send Jaeger traces.
    pub jaeger_agent: Option<SocketAddr>,
}

/// See [`ChainConfig::json_rpc_listen`].
#[derive(Debug, Clone)]
pub struct JsonRpcListenConfig {
    /// Bind point of the JSON-RPC server.
    pub address: SocketAddr,
    /// Maximum number of JSON-RPC clients that can be connected at the same time.
    pub max_json_rpc_clients: u32,
}

/// Allow generating logs.
///
/// Implemented on closures.
///
/// > **Note**: The `log` crate isn't used because dependencies complete pollute the logs.
pub trait LogCallback {
    /// Add a log entry.
    fn log(&self, log_level: LogLevel, message: String);
}

impl<T: ?Sized + Fn(LogLevel, String)> LogCallback for T {
    fn log(&self, log_level: LogLevel, message: String) {
        (*self)(log_level, message)
    }
}

/// Log level of a log entry.
#[derive(Debug)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

#[derive(Debug)]
pub struct ChainConfig<'a> {
    /// Specification of the chain.
    pub chain_spec: Cow<'a, [u8]>,
    /// Identity and address of nodes to try to connect to on startup.
    pub additional_bootnodes: Vec<(peer_id::PeerId, multiaddr::Multiaddr)>,
    /// List of secret phrases to insert in the keystore of the node. Used to author blocks.
    // TODO: also automatically add the same keys through ed25519?
    pub keystore_memory: Vec<Box<[u8; 64]>>,
    /// Path to the SQLite database. If `None`, the database is opened in memory.
    pub sqlite_database_path: Option<PathBuf>,
    /// Maximum size, in bytes, of the cache SQLite uses.
    pub sqlite_cache_size: usize,
    /// Path to the directory where cryptographic keys are stored on disk.
    ///
    /// If `None`, no keys are stored in disk.
    pub keystore_path: Option<PathBuf>,
    /// Configuration of the JSON-RPC server. If `None`, no TCP server is started.
    pub json_rpc_listen: Option<JsonRpcListenConfig>,
}

/// Running client. As long as this object is alive, the client reads/writes the database and has
/// a JSON-RPC server open.
pub struct Client {
    json_rpc_service: json_rpc_service::JsonRpcService,
    relay_chain_json_rpc_service: Option<json_rpc_service::JsonRpcService>,
    consensus_service: Arc<consensus_service::ConsensusService>,
    relay_chain_consensus_service: Option<Arc<consensus_service::ConsensusService>>,
    network_service: Arc<network_service::NetworkService>,
    network_known_best: Arc<Mutex<Option<u64>>>,
}

impl Client {
    /// Returns the address the JSON-RPC server is listening on.
    ///
    /// Returns `None` if and only if [`ChainConfig::json_rpc_listen`] was `None`
    /// in [`Config::chain`].
    pub fn json_rpc_server_addr(&self) -> Option<SocketAddr> {
        self.json_rpc_service.listen_addr()
    }

    /// Returns the address the relay chain JSON-RPC server is listening on.
    ///
    /// Returns `None` if and only if [`Config::relay_chain`] was `None` or if
    /// [`ChainConfig::json_rpc_listen`] was `None` in [`Config::relay_chain`].
    pub fn relay_chain_json_rpc_server_addr(&self) -> Option<SocketAddr> {
        self.relay_chain_json_rpc_service
            .as_ref()
            .and_then(|j| j.listen_addr())
    }

    /// Returns the best block according to the networking.
    pub async fn network_known_best(&self) -> Option<u64> {
        *self.network_known_best.lock().await
    }

    /// Returns the current total number of peers of the client.
    // TODO: weird API
    pub async fn num_peers(&self) -> u64 {
        u64::try_from(self.network_service.num_total_peers().await).unwrap_or(u64::max_value())
    }

    /// Returns the current total number of network connections of the client.
    // TODO: weird API
    pub async fn num_network_connections(&self) -> u64 {
        u64::try_from(self.network_service.num_connections().await).unwrap_or(u64::max_value())
    }

    // TODO: not the best API
    pub async fn sync_state(&self) -> consensus_service::SyncState {
        self.consensus_service.sync_state().await
    }

    // TODO: not the best API
    pub async fn relay_chain_sync_state(&self) -> Option<consensus_service::SyncState> {
        if let Some(s) = &self.relay_chain_consensus_service {
            Some(s.sync_state().await)
        } else {
            None
        }
    }

    /// Adds a JSON-RPC request to the queue of requests of the virtual endpoint of the chain.
    ///
    /// The virtual endpoint doesn't have any limit.
    pub fn send_json_rpc_request(&self, request: String) {
        self.json_rpc_service.send_request(request)
    }

    /// Returns the new JSON-RPC response or notification for requests sent using
    /// [`Client::send_json_rpc_request`].
    ///
    /// If this function is called multiple times simultaneously, only one invocation will receive
    /// each response. Which one is unspecified.
    pub async fn next_json_rpc_response(&self) -> String {
        self.json_rpc_service.next_response().await
    }

    /// Adds a JSON-RPC request to the queue of requests of the virtual endpoint of the
    /// relay chain.
    ///
    /// The virtual endpoint doesn't have any limit.
    pub fn relay_chain_send_json_rpc_request(
        &self,
        request: String,
    ) -> Result<(), RelayChainSendJsonRpcRequestError> {
        let Some(relay_chain_json_rpc_service) = &self.relay_chain_json_rpc_service else {
            return Err(RelayChainSendJsonRpcRequestError::NoRelayChain);
        };

        relay_chain_json_rpc_service.send_request(request);
        Ok(())
    }

    /// Returns the new JSON-RPC response or notification for requests sent using
    /// [`Client::relay_chain_send_json_rpc_request`].
    ///
    /// If this function is called multiple times simultaneously, only one invocation will receive
    /// each response. Which one is unspecified.
    ///
    /// If [`Config::relay_chain`] was `None`, this function waits indefinitely.
    pub async fn relay_chain_next_json_rpc_response(&self) -> String {
        if let Some(relay_chain_json_rpc_service) = &self.relay_chain_json_rpc_service {
            relay_chain_json_rpc_service.next_response().await
        } else {
            future::pending().await
        }
    }
}

/// Error potentially returned by [`start`].
#[derive(Debug, derive_more::Display)]
pub enum StartError {
    /// Failed to parse the chain specification.
    ChainSpecParse(chain_spec::ParseError),
    /// Error building the chain information of the genesis block.
    InvalidGenesisInformation(chain_spec::FromGenesisStorageError),
    /// Failed to parse the chain specification of the relay chain.
    RelayChainSpecParse(chain_spec::ParseError),
    /// Error building the chain information of the genesis block of the relay chain.
    InvalidRelayGenesisInformation(chain_spec::FromGenesisStorageError),
    /// Error initializing the networking service.
    NetworkInit(network_service::InitError),
    /// Error initializing the JSON-RPC service.
    JsonRpcServiceInit(json_rpc_service::InitError),
    /// Error initializing the JSON-RPC service of the relay chain.
    RelayChainJsonRpcServiceInit(json_rpc_service::InitError),
    ConsensusServiceInit(consensus_service::InitError),
    RelayChainConsensusServiceInit(consensus_service::InitError),
    /// Error initializing the keystore of the chain.
    KeystoreInit(io::Error),
    /// Error initializing the keystore of the relay chain.
    RelayChainKeystoreInit(io::Error),
    /// Error initializing the Jaeger service.
    JaegerInit(io::Error),
}

/// Error potentially returned by [`Client::relay_chain_send_json_rpc_request`].
#[derive(Debug, derive_more::Display)]
pub enum RelayChainSendJsonRpcRequestError {
    /// There is no relay chain to send the JSON-RPC request to.
    NoRelayChain,
}

/// Runs the node using the given configuration.
// TODO: this function has several code paths that panic instead of returning an error; it is especially unclear what to do in case of database corruption, given that a database corruption would crash the node later on anyway
pub async fn start(mut config: Config<'_>) -> Result<Client, StartError> {
    let chain_spec = {
        chain_spec::ChainSpec::from_json_bytes(&config.chain.chain_spec)
            .map_err(StartError::ChainSpecParse)?
    };

    // TODO: don't just throw away the runtime
    let genesis_chain_information = chain_spec
        .to_chain_information()
        .map_err(StartError::InvalidGenesisInformation)?
        .0;

    let relay_chain_spec = match &config.relay_chain {
        Some(cfg) => Some(
            chain_spec::ChainSpec::from_json_bytes(&cfg.chain_spec)
                .map_err(StartError::RelayChainSpecParse)?,
        ),
        None => None,
    };

    // TODO: don't just throw away the runtime
    let relay_genesis_chain_information = match &relay_chain_spec {
        Some(r) => Some(
            r.to_chain_information()
                .map_err(StartError::InvalidRelayGenesisInformation)?
                .0,
        ),
        None => None,
    };

    // The `protocolId` field of chain specifications is deprecated. Print a warning.
    if chain_spec.protocol_id().is_some() {
        config.log_callback.log(
            LogLevel::Warn,
            format!("chain-spec-has-protocol-id; chain={}", chain_spec.id()),
        );
    }
    if let Some(relay_chain_spec) = &relay_chain_spec {
        if relay_chain_spec.protocol_id().is_some() {
            config.log_callback.log(
                LogLevel::Warn,
                format!(
                    "chain-spec-has-protocol-id; chain={}",
                    relay_chain_spec.id()
                ),
            );
        }
    }

    // The `telemetryEndpoints` field of chain specifications isn't supported.
    if chain_spec.telemetry_endpoints().count() != 0 {
        config.log_callback.log(
            LogLevel::Warn,
            format!(
                "chain-spec-has-telemetry-endpoints; chain={}",
                chain_spec.id()
            ),
        );
    }
    if let Some(relay_chain_spec) = &relay_chain_spec {
        if relay_chain_spec.telemetry_endpoints().count() != 0 {
            config.log_callback.log(
                LogLevel::Warn,
                format!(
                    "chain-spec-has-telemetry-endpoints; chain={}",
                    relay_chain_spec.id()
                ),
            );
        }
    }

    // Printing the SQLite version number can be useful for debugging purposes for example in case
    // a query fails.
    config.log_callback.log(
        LogLevel::Debug,
        format!("sqlite-version; version={}", full_sqlite::sqlite_version()),
    );

    let (database, database_existed) = {
        let (db, existed) = open_database(
            &chain_spec,
            genesis_chain_information.as_ref(),
            config.chain.sqlite_database_path,
            config.chain.sqlite_cache_size,
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

    let noise_key = {
        let mut noise_static_key = zeroize::Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *noise_static_key);
        connection::NoiseKey::new(&config.libp2p_key, &noise_static_key)
    };
    zeroize::Zeroize::zeroize(&mut *config.libp2p_key);
    let local_peer_id =
        peer_id::PublicKey::Ed25519(*noise_key.libp2p_public_ed25519_key()).into_peer_id();

    let genesis_block_hash = genesis_chain_information
        .as_ref()
        .finalized_block_header
        .hash(chain_spec.block_number_bytes().into());

    let jaeger_service = jaeger_service::JaegerService::new(jaeger_service::Config {
        tasks_executor: &mut |task| (config.tasks_executor)(task),
        service_name: local_peer_id.to_string(),
        jaeger_agent: config.jaeger_agent,
    })
    .await
    .map_err(StartError::JaegerInit)?;

    let (network_service, network_service_chain_ids, network_events_receivers) =
        network_service::NetworkService::new(network_service::Config {
            listen_addresses: config.listen_addresses,
            num_events_receivers: 2 + if relay_chain_database.is_some() { 1 } else { 0 },
            chains: iter::once(network_service::ChainConfig {
                log_name: chain_spec.id().to_owned(),
                fork_id: chain_spec.fork_id().map(|n| n.to_owned()),
                block_number_bytes: usize::from(chain_spec.block_number_bytes()),
                database: database.clone(),
                grandpa_protocol_finalized_block_height: if matches!(
                    genesis_chain_information.as_ref().finality,
                    chain::chain_information::ChainInformationFinalityRef::Grandpa { .. }
                ) {
                    Some({
                        let block_number_bytes = chain_spec.block_number_bytes();
                        database
                            .with_database(move |database| {
                                let hash = database.finalized_block_hash().unwrap();
                                let header = database.block_scale_encoded_header(&hash).unwrap().unwrap();
                                header::decode(&header, block_number_bytes.into(),).unwrap().number
                            })
                            .await
                    })
                } else {
                    None
                },
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
                max_in_peers: 25,
                max_slots: 15,
                bootstrap_nodes: {
                    let mut list = Vec::with_capacity(
                        chain_spec.boot_nodes().len() + config.chain.additional_bootnodes.len(),
                    );

                    for node in chain_spec.boot_nodes() {
                        match node {
                            chain_spec::Bootnode::UnrecognizedFormat(raw) => {
                                config.log_callback.log(
                                    LogLevel::Warn,
                                    format!("bootnode-unrecognized-addr; value={:?}", raw),
                                );
                            }
                            chain_spec::Bootnode::Parsed { multiaddr, peer_id } => {
                                let multiaddr: multiaddr::Multiaddr = match multiaddr.parse() {
                                    Ok(a) => a,
                                    Err(_) => {
                                        config.log_callback.log(
                                            LogLevel::Warn,
                                            format!("bootnode-unrecognized-addr; value={:?}", multiaddr),
                                        );
                                        continue;
                                    },
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
                        log_name: relay_chains_specs.id().to_owned(),
                        fork_id: relay_chains_specs.fork_id().map(|n| n.to_owned()),
                        block_number_bytes: usize::from(relay_chains_specs.block_number_bytes()),
                        database: relay_chain_database.clone().unwrap(),
                        grandpa_protocol_finalized_block_height: if matches!(
                            genesis_chain_information.as_ref().finality,
                            chain::chain_information::ChainInformationFinalityRef::Grandpa { .. }
                        ) {
                            Some(relay_chain_database
                                .as_ref()
                                .unwrap()
                                .with_database({
                                    let block_number_bytes = chain_spec.block_number_bytes();
                                    move |db| {
                                        let hash = db.finalized_block_hash().unwrap();
                                        let header = db.block_scale_encoded_header(&hash).unwrap().unwrap();
                                        header::decode(&header, block_number_bytes.into()).unwrap().number
                                    }
                                })
                                .await)
                        } else {
                            None
                        },
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
                        max_in_peers: 25,
                        max_slots: 15,
                        bootstrap_nodes: {
                            let mut list =
                                Vec::with_capacity(relay_chains_specs.boot_nodes().len());
                            for node in relay_chains_specs.boot_nodes() {
                                match node {
                                    chain_spec::Bootnode::UnrecognizedFormat(raw) => {
                                        config.log_callback.log(
                                            LogLevel::Warn,
                                            format!("relay-chain-bootnode-unrecognized-addr; value={:?}", raw),
                                        );
                                    }
                                    chain_spec::Bootnode::Parsed { multiaddr, peer_id } => {
                                        let multiaddr: multiaddr::Multiaddr = match multiaddr.parse() {
                                            Ok(a) => a,
                                            Err(_) => {
                                                config.log_callback.log(
                                                    LogLevel::Warn,
                                                    format!("relay-chain-bootnode-unrecognized-addr; value={:?}", multiaddr),
                                                );
                                                continue;
                                            }
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
                let executor = config.tasks_executor.clone();
                Box::new(move |task| executor(task))
            },
            log_callback: config.log_callback.clone(),
            jaeger_service: jaeger_service.clone(),
        })
        .await
        .map_err(StartError::NetworkInit)?;

    let mut network_events_receivers = network_events_receivers.into_iter();

    let keystore = Arc::new({
        let mut keystore = keystore::Keystore::new(config.chain.keystore_path, rand::random())
            .await
            .map_err(StartError::KeystoreInit)?;
        for mut private_key in config.chain.keystore_memory {
            keystore.insert_sr25519_memory(keystore::KeyNamespace::all(), &private_key);
            zeroize::Zeroize::zeroize(&mut *private_key);
        }
        keystore
    });

    let consensus_service = consensus_service::ConsensusService::new(consensus_service::Config {
        tasks_executor: {
            let executor = config.tasks_executor.clone();
            Box::new(move |task| executor(task))
        },
        log_callback: config.log_callback.clone(),
        genesis_block_hash,
        network_events_receiver: network_events_receivers.next().unwrap(),
        network_service: (network_service.clone(), network_service_chain_ids[0]),
        database: database.clone(),
        block_number_bytes: usize::from(chain_spec.block_number_bytes()),
        keystore,
        jaeger_service: jaeger_service.clone(),
        slot_duration_author_ratio: 43691_u16,
    })
    .await
    .map_err(StartError::ConsensusServiceInit)?;

    let relay_chain_consensus_service = if let Some(relay_chain_database) = &relay_chain_database {
        Some(
            consensus_service::ConsensusService::new(consensus_service::Config {
                tasks_executor: {
                    let executor = config.tasks_executor.clone();
                    Box::new(move |task| executor(task))
                },
                log_callback: config.log_callback.clone(),
                genesis_block_hash: relay_genesis_chain_information
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .finalized_block_header
                    .hash(usize::from(
                        relay_chain_spec.as_ref().unwrap().block_number_bytes(),
                    )),
                network_events_receiver: network_events_receivers.next().unwrap(),
                network_service: (network_service.clone(), network_service_chain_ids[1]),
                database: relay_chain_database.clone(),
                block_number_bytes: usize::from(
                    relay_chain_spec.as_ref().unwrap().block_number_bytes(),
                ),
                keystore: Arc::new({
                    let mut keystore = keystore::Keystore::new(
                        config.relay_chain.as_ref().unwrap().keystore_path.clone(),
                        rand::random(),
                    )
                    .await
                    .map_err(StartError::RelayChainKeystoreInit)?;
                    for mut private_key in
                        mem::take(&mut config.relay_chain.as_mut().unwrap().keystore_memory)
                    {
                        keystore.insert_sr25519_memory(keystore::KeyNamespace::all(), &private_key);
                        zeroize::Zeroize::zeroize(&mut *private_key);
                    }
                    keystore
                }),
                jaeger_service, // TODO: consider passing a different jaeger service with a different service name
                slot_duration_author_ratio: 43691_u16,
            })
            .await
            .map_err(StartError::RelayChainConsensusServiceInit)?,
        )
    } else {
        None
    };

    // Start the JSON-RPC service.
    // It only needs to be kept alive in order to function.
    //
    // Note that initialization can fail if, for example, the port is already occupied. It is
    // preferable to fail to start the node altogether rather than make the user believe that they
    // are connected to the JSON-RPC endpoint of the node while they are in reality connected to
    // something else.
    let json_rpc_service = json_rpc_service::JsonRpcService::new(json_rpc_service::Config {
        tasks_executor: config.tasks_executor.clone(),
        log_callback: config.log_callback.clone(),
        database,
        consensus_service: consensus_service.clone(),
        network_service: (network_service.clone(), network_service_chain_ids[0]),
        bind_address: config.chain.json_rpc_listen.as_ref().map(|cfg| cfg.address),
        max_parallel_requests: 32,
        max_json_rpc_clients: config
            .chain
            .json_rpc_listen
            .map_or(0, |cfg| cfg.max_json_rpc_clients),
        chain_name: chain_spec.name().to_owned(),
        chain_type: chain_spec.chain_type().to_owned(),
        chain_properties_json: chain_spec.properties().to_owned(),
        chain_is_live: chain_spec.has_live_network(),
        genesis_block_hash: genesis_chain_information
            .as_ref()
            .finalized_block_header
            .hash(usize::from(chain_spec.block_number_bytes())),
    })
    .await
    .map_err(StartError::JsonRpcServiceInit)?;

    // Start the JSON-RPC service of the relay chain.
    // See remarks above.
    let relay_chain_json_rpc_service = if let Some(relay_chain_cfg) = config.relay_chain {
        let relay_chain_spec = relay_chain_spec.as_ref().unwrap();
        Some(
            json_rpc_service::JsonRpcService::new(json_rpc_service::Config {
                tasks_executor: config.tasks_executor.clone(),
                log_callback: config.log_callback.clone(),
                database: relay_chain_database.clone().unwrap(),
                consensus_service: relay_chain_consensus_service.clone().unwrap(),
                network_service: (network_service.clone(), network_service_chain_ids[1]),
                bind_address: relay_chain_cfg
                    .json_rpc_listen
                    .as_ref()
                    .map(|cfg| cfg.address),
                max_parallel_requests: 32,
                max_json_rpc_clients: relay_chain_cfg
                    .json_rpc_listen
                    .map_or(0, |cfg| cfg.max_json_rpc_clients),
                chain_name: relay_chain_spec.name().to_owned(),
                chain_type: relay_chain_spec.chain_type().to_owned(),
                chain_properties_json: relay_chain_spec.properties().to_owned(),
                chain_is_live: relay_chain_spec.has_live_network(),
                genesis_block_hash: relay_genesis_chain_information
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .finalized_block_header
                    .hash(usize::from(relay_chain_spec.block_number_bytes())),
            })
            .await
            .map_err(StartError::JsonRpcServiceInit)?,
        )
    } else {
        None
    };

    // Spawn the task printing the informant.
    // This is not just a dummy task that just prints on the output, but is actually the main
    // task that holds everything else alive. Without it, all the services that we have created
    // above would be cleanly dropped and nothing would happen.
    // For this reason, it must be spawned even if no informant is started, in which case we simply
    // inhibit the printing.
    let network_known_best = Arc::new(Mutex::new(None));
    (config.tasks_executor)(Box::pin({
        let mut main_network_events_receiver = network_events_receivers.next().unwrap();
        let network_service_chain_id = network_service_chain_ids[0];
        let network_known_best = network_known_best.clone();

        // TODO: shut down this task if the client stops?
        async move {
            loop {
                let network_event = main_network_events_receiver.next().await.unwrap();
                let mut network_known_best = network_known_best.lock().await;

                match network_event {
                    network_service::Event::BlockAnnounce {
                        chain_id,
                        scale_encoded_header,
                        ..
                    } if chain_id == network_service_chain_id => match (
                        *network_known_best,
                        header::decode(
                            &scale_encoded_header,
                            usize::from(chain_spec.block_number_bytes()),
                        ),
                    ) {
                        (Some(n), Ok(header)) if n >= header.number => {}
                        (_, Ok(header)) => *network_known_best = Some(header.number),
                        (_, Err(_)) => {
                            // Do nothing if the block is invalid. This is just for the
                            // informant and not for consensus-related purposes.
                        }
                    },
                    network_service::Event::Connected {
                        chain_id,
                        best_block_number,
                        ..
                    } if chain_id == network_service_chain_id => match *network_known_best {
                        Some(n) if n >= best_block_number => {}
                        _ => *network_known_best = Some(best_block_number),
                    },
                    _ => {}
                }
            }
        }
    }));

    config.log_callback.log(
        LogLevel::Info,
        format!(
            "successful-initialization; local_peer_id={}; database_is_new={:?}; \
                finalized_block_hash={}; finalized_block_number={}",
            local_peer_id,
            !database_existed,
            HashDisplay(&database_finalized_block_hash),
            database_finalized_block_number
        ),
    );

    debug_assert!(network_events_receivers.next().is_none());
    Ok(Client {
        consensus_service,
        relay_chain_consensus_service,
        json_rpc_service,
        relay_chain_json_rpc_service,
        network_service,
        network_known_best,
    })
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
) -> (full_sqlite::SqliteFullDatabase, bool) {
    // The `unwrap()` here can panic for example in case of access denied.
    match full_sqlite::open(full_sqlite::Config {
        block_number_bytes: chain_spec.block_number_bytes().into(),
        cache_size: sqlite_cache_size,
        ty: if let Some(path) = &db_path {
            full_sqlite::ConfigTy::Disk {
                path,
                memory_map_size: 1000000000, // TODO: make configurable
            }
        } else {
            full_sqlite::ConfigTy::Memory
        },
    })
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
            // TODO: consider not throwing away the runtime
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

            // The chain specification only contains trie nodes that have a storage value attached
            // to them, while the database needs to know all trie nodes (including branch nodes).
            // The good news is that we can determine the latter from the former, which we do
            // here.
            // TODO: consider moving this block to the chain spec module
            // TODO: poorly optimized
            let mut trie_structure = {
                let mut trie_structure = trie::trie_structure::TrieStructure::new();
                for (key, value) in genesis_storage.iter() {
                    match trie_structure.node(trie::bytes_to_nibbles(key.iter().copied())) {
                        trie::trie_structure::Entry::Vacant(e) => {
                            e.insert_storage_value().insert(
                                (Some(value), None::<trie::trie_node::MerkleValueOutput>),
                                (None, None),
                            );
                        }
                        trie::trie_structure::Entry::Occupied(
                            trie::trie_structure::NodeAccess::Branch(mut e),
                        ) => {
                            *e.user_data() = (Some(value), None);
                            e.insert_storage_value();
                        }
                        trie::trie_structure::Entry::Occupied(
                            trie::trie_structure::NodeAccess::Storage(_),
                        ) => {
                            // Duplicate entry.
                            panic!() // TODO: don't panic?
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
                    let storage_value_hashed =
                        match (node_access.user_data().0.as_ref(), state_version) {
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
                        trie::HashFunction::Blake2,
                        is_root_node,
                    )
                    .unwrap();

                    node_access.into_user_data().1 = Some(merkle_value);
                }

                trie_structure
            };

            // Build the iterator of trie nodes.
            let genesis_storage_full_trie = trie_structure
                .iter_unordered()
                .collect::<Vec<_>>()
                .into_iter()
                .map(|node_index| {
                    let (storage_value, Some(merkle_value)) = &trie_structure[node_index] else {
                        unreachable!()
                    };
                    // Cloning to solve borrow checker restriction. // TODO: optimize?
                    let storage_value = if let Some(storage_value) = storage_value {
                        // TODO: child tries support?
                        full_sqlite::InsertTrieNodeStorageValue::Value {
                            value: Cow::Owned(storage_value.to_vec()),
                            references_merkle_value: false,
                        }
                    } else {
                        full_sqlite::InsertTrieNodeStorageValue::NoValue
                    };
                    let merkle_value = merkle_value.as_ref().to_owned();
                    let mut node_access = trie_structure.node_by_index(node_index).unwrap();

                    full_sqlite::InsertTrieNode {
                        storage_value,
                        merkle_value: Cow::Owned(merkle_value),
                        children_merkle_values: array::from_fn::<_, 16, _>(|n| {
                            let child_index =
                                trie::Nibble::try_from(u8::try_from(n).unwrap()).unwrap();
                            node_access.child(child_index).map(|mut child| {
                                Cow::Owned(child.user_data().1.as_ref().unwrap().as_ref().to_vec())
                            })
                        }),
                        partial_key_nibbles: Cow::Owned(
                            node_access.partial_key().map(u8::from).collect::<Vec<_>>(),
                        ),
                    }
                });

            // The finalized block is the genesis block. As such, it has an empty body and
            // no justification.
            let database = empty
                .initialize(
                    genesis_chain_information,
                    iter::empty(),
                    None,
                    genesis_storage_full_trie,
                    state_version,
                )
                .unwrap();
            (database, false)
        }
    }
}
