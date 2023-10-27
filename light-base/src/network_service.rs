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

//! Background network service.
//!
//! The [`NetworkService`] manages background tasks dedicated to connecting to other nodes.
//! Importantly, its design is oriented towards the particular use case of the light client.
//!
//! The [`NetworkService`] spawns one background task (using [`PlatformRef::spawn_task`]) for
//! each active connection.
//!
//! The objective of the [`NetworkService`] in general is to try stay connected as much as
//! possible to the nodes of the peer-to-peer network of the chain, and maintain open substreams
//! with them in order to send out requests (e.g. block requests) and notifications (e.g. block
//! announces).
//!
//! Connectivity to the network is performed in the background as an implementation detail of
//! the service. The public API only allows emitting requests and notifications towards the
//! already-connected nodes.
//!
//! An important part of the API is the list of channel receivers of [`Event`] returned by
//! [`NetworkService::new`]. These channels inform the foreground about updates to the network
//! connectivity.

use crate::platform::{self, address_parse, PlatformRef};

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::{self, Vec},
};
use core::{cmp, mem, pin::Pin, task::Poll, time::Duration};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{future, stream, StreamExt as _};
use hashbrown::{HashMap, HashSet};
use itertools::Itertools as _;
use rand_chacha::rand_core::SeedableRng as _;
use smoldot::{
    header,
    informant::{BytesDisplay, HashDisplay},
    libp2p::{
        connection,
        multiaddr::{self, Multiaddr},
        peer_id::{self, PeerId},
    },
    network::{basic_peering_strategy, protocol, service},
};

pub use service::{ChainId, EncodedMerkleProof, QueueNotificationError};

mod tasks;

/// Configuration for a [`NetworkService`].
pub struct Config<TPlat> {
    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Value sent back for the agent version when receiving an identification request.
    pub identify_agent_version: String,

    /// Key to use for the encryption layer of all the connections. Gives the node its identity.
    pub noise_key: connection::NoiseKey,

    /// Number of event receivers returned by [`NetworkService::new`].
    pub num_events_receivers: usize,

    /// List of chains to connect to. Chains are later referred to by their index in this list.
    pub chains: Vec<ConfigChain>,
}

/// See [`Config::chains`].
///
/// Note that this configuration is intentionally missing a field containing the bootstrap
/// nodes of the chain. Bootstrap nodes are supposed to be added afterwards by calling
/// [`NetworkService::discover`].
pub struct ConfigChain {
    /// Name of the chain, for logging purposes.
    pub log_name: String,

    /// Hash of the genesis block of the chain. Sent to other nodes in order to determine whether
    /// the chains match.
    ///
    /// > **Note**: Be aware that this *must* be the *genesis* block, not any block known to be
    /// >           in the chain.
    pub genesis_block_hash: [u8; 32],

    /// Number and hash of the current best block. Can later be updated with
    /// [`NetworkService::set_local_best_block`].
    pub best_block: (u64, [u8; 32]),

    /// Optional identifier to insert into the networking protocol names. Used to differentiate
    /// between chains with the same genesis hash.
    pub fork_id: Option<String>,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// Must be `Some` if and only if the chain uses the GrandPa networking protocol. Contains the
    /// number of the finalized block at the time of the initialization.
    pub grandpa_protocol_finalized_block_height: Option<u64>,
}

pub struct NetworkService<TPlat: PlatformRef> {
    /// Names of the various chains the network service connects to. Used only for logging
    /// purposes.
    log_chain_names: hashbrown::HashMap<ChainId, String, fnv::FnvBuildHasher>,

    /// Channel to send messages to the background task.
    messages_tx: async_channel::Sender<ToBackground>,

    /// Event notified when the [`NetworkService`] is destroyed.
    on_service_killed: event_listener::Event,

    /// Dummy to hold the `TPlat` type.
    marker: core::marker::PhantomData<TPlat>,
}

impl<TPlat: PlatformRef> NetworkService<TPlat> {
    /// Initializes the network service with the given configuration.
    ///
    /// Returns the networking service, plus a list of receivers on which events are pushed.
    /// All of these receivers must be polled regularly to prevent the networking service from
    /// slowing down.
    pub async fn new(
        config: Config<TPlat>,
    ) -> (
        Arc<Self>,
        Vec<ChainId>,
        Vec<stream::BoxStream<'static, Event>>,
    ) {
        let (event_senders, event_receivers): (Vec<_>, Vec<_>) = (0..config.num_events_receivers)
            .map(|_| async_channel::bounded(16))
            .unzip();

        let mut log_chain_names =
            hashbrown::HashMap::with_capacity_and_hasher(config.chains.len(), Default::default());
        let mut chain_ids = Vec::with_capacity(config.chains.len());

        let mut network = service::ChainNetwork::new(service::Config {
            chains_capacity: config.chains.len(),
            connections_capacity: 32,
            noise_key: config.noise_key,
            handshake_timeout: Duration::from_secs(8),
            randomness_seed: {
                let mut seed = [0; 32];
                config.platform.fill_random_bytes(&mut seed);
                seed
            },
        });

        for chain in config.chains {
            // TODO: can panic in case of duplicate chain, how do we handle that?
            let chain_id = network
                .add_chain(service::ChainConfig {
                    grandpa_protocol_config: if let Some(commit_finalized_height) =
                        chain.grandpa_protocol_finalized_block_height
                    {
                        // TODO: dummy values
                        Some(service::GrandpaState {
                            commit_finalized_height,
                            round_number: 1,
                            set_id: 0,
                        })
                    } else {
                        None
                    },
                    fork_id: chain.fork_id.clone(),
                    block_number_bytes: chain.block_number_bytes,
                    best_hash: chain.best_block.1,
                    best_number: chain.best_block.0,
                    genesis_hash: chain.genesis_block_hash,
                    role: protocol::Role::Light,
                    allow_inbound_block_requests: false,
                })
                .unwrap();

            log_chain_names.insert(chain_id, chain.log_name);
            chain_ids.push(chain_id);
        }

        let on_service_killed = event_listener::Event::new();

        let (messages_tx, messages_rx) = async_channel::bounded(32);

        // Spawn task starts a discovery request at a periodic interval.
        // This is done through a separate task due to ease of implementation.
        config.platform.spawn_task(
            "network-discovery".into(),
            Box::pin({
                let platform = config.platform.clone();
                let messages_tx = messages_tx.clone();
                async move {
                    let mut next_discovery = Duration::from_secs(5);

                    loop {
                        platform.sleep(next_discovery).await;
                        next_discovery = cmp::min(next_discovery * 2, Duration::from_secs(120));

                        if messages_tx
                            .send(ToBackground::StartDiscovery)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                .or(on_service_killed.listen())
            }),
        );

        // Spawn main task that processes the network service.
        let task = Box::pin(
            background_task(BackgroundTask {
                randomness: rand_chacha::ChaCha20Rng::from_seed({
                    let mut seed = [0; 32];
                    config.platform.fill_random_bytes(&mut seed);
                    seed
                }),
                identify_agent_version: config.identify_agent_version,
                log_chain_names: log_chain_names.clone(),
                messages_tx: messages_tx.clone(),
                peering_strategy: basic_peering_strategy::BasicPeeringStrategy::new(),
                network,
                platform: config.platform.clone(),
                event_senders: either::Left(event_senders),
                important_nodes: HashSet::with_capacity_and_hasher(16, Default::default()),
                active_connections: HashMap::with_capacity_and_hasher(32, Default::default()),
                messages_rx,
                blocks_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                grandpa_warp_sync_requests: HashMap::with_capacity_and_hasher(
                    8,
                    Default::default(),
                ),
                storage_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                call_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                kademlia_find_node_requests: HashMap::with_capacity_and_hasher(
                    2,
                    Default::default(),
                ),
            })
            .or(on_service_killed.listen()),
        );

        config
            .platform
            .spawn_task("network-service".into(), async move {
                task.await;
                log::debug!(target: "network", "Shutdown")
            });

        let final_network_service = Arc::new(NetworkService {
            log_chain_names,
            messages_tx,
            on_service_killed,
            marker: core::marker::PhantomData,
        });

        // Adjust the event receivers to keep the `final_network_service` alive.
        let event_receivers = event_receivers
            .into_iter()
            .map(|rx| {
                let mut final_network_service = Some(final_network_service.clone());
                rx.chain(stream::poll_fn(move |_| {
                    drop(final_network_service.take());
                    Poll::Ready(None)
                }))
                .boxed()
            })
            .collect();

        (final_network_service, chain_ids, event_receivers)
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    pub async fn blocks_request(
        self: Arc<Self>,
        target: PeerId,
        chain_id: ChainId,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
    ) -> Result<Vec<protocol::BlockData>, BlocksRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartBlocksRequest {
                target: target.clone(),
                chain_id,
                config,
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        let result = rx.await.unwrap();

        match &result {
            Ok(blocks) => {
                log::debug!(
                    target: "network",
                    "Connections({}) => BlocksRequest(chain={}, num_blocks={}, block_data_total_size={})",
                    target,
                    self.log_chain_names[&chain_id],
                    blocks.len(),
                    BytesDisplay(blocks.iter().fold(0, |sum, block| {
                        let block_size = block.header.as_ref().map_or(0, |h| h.len()) +
                            block.body.as_ref().map_or(0, |b| b.iter().fold(0, |s, e| s + e.len())) +
                            block.justifications.as_ref().into_iter().flat_map(|l| l.iter()).fold(0, |s, j| s + j.justification.len());
                        sum + u64::try_from(block_size).unwrap()
                    }))
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connections({}) => BlocksRequest(chain={}, error={:?})",
                    target,
                    self.log_chain_names[&chain_id],
                    err
                );
            }
        }

        if !log::log_enabled!(log::Level::Debug) {
            match &result {
                Ok(_) | Err(BlocksRequestError::NoConnection) => {}
                Err(BlocksRequestError::Request(service::BlocksRequestError::Request(err)))
                    if !err.is_protocol_error() => {}
                Err(err) => {
                    log::warn!(
                        target: "network",
                        "Error in block request with {}. This might indicate an incompatibility. Error: {}",
                        target,
                        err
                    );
                }
            }
        }

        result
    }

    /// Sends a grandpa warp sync request to the given peer.
    // TODO: more docs
    pub async fn grandpa_warp_sync_request(
        self: Arc<Self>,
        target: PeerId,
        chain_id: ChainId,
        begin_hash: [u8; 32],
        timeout: Duration,
    ) -> Result<service::EncodedGrandpaWarpSyncResponse, WarpSyncRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartWarpSyncRequest {
                target: target.clone(),
                chain_id,
                begin_hash,
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        let result = rx.await.unwrap();

        match &result {
            Ok(response) => {
                // TODO: print total bytes size
                let decoded = response.decode();
                log::debug!(
                    target: "network",
                    "Connections({}) => WarpSyncRequest(chain={}, num_fragments={}, finished={:?})",
                    target,
                    self.log_chain_names[&chain_id],
                    decoded.fragments.len(),
                    decoded.is_finished,
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connections({}) => WarpSyncRequest(chain={}, error={:?})",
                    target,
                    self.log_chain_names[&chain_id],
                    err,
                );
            }
        }

        result
    }

    pub async fn set_local_best_block(
        &self,
        chain_id: ChainId,
        best_hash: [u8; 32],
        best_number: u64,
    ) {
        self.messages_tx
            .send(ToBackground::SetLocalBestBlock {
                chain_id,
                best_hash,
                best_number,
            })
            .await
            .unwrap();
    }

    pub async fn set_local_grandpa_state(
        &self,
        chain_id: ChainId,
        grandpa_state: service::GrandpaState,
    ) {
        self.messages_tx
            .send(ToBackground::SetLocalGrandpaState {
                chain_id,
                grandpa_state,
            })
            .await
            .unwrap();
    }

    /// Sends a storage proof request to the given peer.
    // TODO: more docs
    pub async fn storage_proof_request(
        self: Arc<Self>,
        chain_id: ChainId,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]> + Clone>>,
        timeout: Duration,
    ) -> Result<service::EncodedMerkleProof, StorageProofRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartStorageProofRequest {
                target: target.clone(),
                chain_id,
                config: protocol::StorageProofRequestConfig {
                    block_hash: config.block_hash,
                    keys: config
                        .keys
                        .map(|key| key.as_ref().to_vec()) // TODO: to_vec() overhead
                        .collect::<Vec<_>>()
                        .into_iter(),
                },
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        let result = rx.await.unwrap();

        match &result {
            Ok(items) => {
                let decoded = items.decode();
                log::debug!(
                    target: "network",
                    "Connections({}) => StorageProofRequest(chain={}, total_size={})",
                    target,
                    self.log_chain_names[&chain_id],
                    BytesDisplay(u64::try_from(decoded.len()).unwrap()),
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connections({}) => StorageProofRequest(chain={}, error={:?})",
                    target,
                    self.log_chain_names[&chain_id],
                    err
                );
            }
        }

        result
    }

    /// Sends a call proof request to the given peer.
    ///
    /// See also [`NetworkService::call_proof_request`].
    // TODO: more docs
    pub async fn call_proof_request(
        self: Arc<Self>,
        chain_id: ChainId,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::CallProofRequestConfig<'_, impl Iterator<Item = impl AsRef<[u8]>>>,
        timeout: Duration,
    ) -> Result<EncodedMerkleProof, CallProofRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartCallProofRequest {
                target: target.clone(),
                chain_id,
                config: protocol::CallProofRequestConfig {
                    block_hash: config.block_hash,
                    method: config.method.into_owned().into(),
                    parameter_vectored: config
                        .parameter_vectored
                        .map(|v| v.as_ref().to_vec()) // TODO: to_vec() overhead
                        .collect::<Vec<_>>()
                        .into_iter(),
                },
                timeout,
                result: tx,
            })
            .await
            .unwrap();

        let result = rx.await.unwrap();

        match &result {
            Ok(items) => {
                let decoded = items.decode();
                log::debug!(
                    target: "network",
                    "Connections({}) => CallProofRequest({}, total_size: {})",
                    target,
                    self.log_chain_names[&chain_id],
                    BytesDisplay(u64::try_from(decoded.len()).unwrap())
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connections({}) => CallProofRequest({}, {})",
                    target,
                    self.log_chain_names[&chain_id],
                    err
                );
            }
        }

        result
    }

    /// Announces transaction to the peers we are connected to.
    ///
    /// Returns a list of peers that we have sent the transaction to. Can return an empty `Vec`
    /// if we didn't send the transaction to any peer.
    ///
    /// Note that the remote doesn't confirm that it has received the transaction. Because
    /// networking is inherently unreliable, successfully sending a transaction to a peer doesn't
    /// necessarily mean that the remote has received it. In practice, however, the likelihood of
    /// a transaction not being received are extremely low. This can be considered as known flaw.
    pub async fn announce_transaction(
        self: Arc<Self>,
        chain_id: ChainId,
        transaction: &[u8],
    ) -> Vec<PeerId> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::AnnounceTransaction {
                chain_id,
                transaction: transaction.to_vec(), // TODO: ovheread
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// See [`service::ChainNetwork::gossip_send_block_announce`].
    pub async fn send_block_announce(
        self: Arc<Self>,
        target: &PeerId,
        chain_id: ChainId,
        scale_encoded_header: &[u8],
        is_best: bool,
    ) -> Result<(), QueueNotificationError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::SendBlockAnnounce {
                target: target.clone(), // TODO: overhead
                chain_id,
                scale_encoded_header: scale_encoded_header.to_vec(), // TODO: overhead
                is_best,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Marks the given peers as belonging to the given chain, and adds some addresses to these
    /// peers to the address book.
    ///
    /// The `important_nodes` parameter indicates whether these nodes are considered note-worthy
    /// and should have additional logging.
    pub async fn discover(
        &self,
        chain_id: ChainId,
        list: impl IntoIterator<Item = (PeerId, impl IntoIterator<Item = Multiaddr>)>,
        important_nodes: bool,
    ) {
        self.messages_tx
            .send(ToBackground::Discover {
                chain_id,
                // TODO: overhead
                list: list
                    .into_iter()
                    .map(|(peer_id, addrs)| {
                        (peer_id, addrs.into_iter().collect::<Vec<_>>().into_iter())
                    })
                    .collect::<Vec<_>>()
                    .into_iter(),
                important_nodes,
            })
            .await
            .unwrap();
    }

    /// Returns a list of nodes (their [`PeerId`] and multiaddresses) that we know are part of
    /// the network.
    ///
    /// Nodes that are discovered might disappear over time. In other words, there is no guarantee
    /// that a node that has been added through [`NetworkService::discover`] will later be
    /// returned by [`NetworkService::discovered_nodes`].
    pub async fn discovered_nodes(
        &self,
        chain_id: ChainId,
    ) -> impl Iterator<Item = (PeerId, impl Iterator<Item = Multiaddr>)> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::DiscoveredNodes {
                chain_id,
                result: tx,
            })
            .await
            .unwrap();

        rx.await
            .unwrap()
            .into_iter()
            .map(|(peer_id, addrs)| (peer_id, addrs.into_iter()))
    }

    /// Returns an iterator to the list of [`PeerId`]s that we have an established connection
    /// with.
    pub async fn peers_list(&self, chain_id: ChainId) -> impl Iterator<Item = PeerId> {
        let (tx, rx) = oneshot::channel();
        self.messages_tx
            .send(ToBackground::PeersList {
                chain_id,
                result: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap().into_iter()
    }
}

impl<TPlat: PlatformRef> Drop for NetworkService<TPlat> {
    fn drop(&mut self) {
        self.on_service_killed.notify(usize::max_value());
    }
}

/// Event that can happen on the network service.
#[derive(Debug, Clone)]
pub enum Event {
    Connected {
        peer_id: PeerId,
        chain_id: ChainId,
        role: protocol::Role,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    },
    Disconnected {
        peer_id: PeerId,
        chain_id: ChainId,
    },
    BlockAnnounce {
        peer_id: PeerId,
        chain_id: ChainId,
        announce: service::EncodedBlockAnnounce,
    },
    GrandpaNeighborPacket {
        peer_id: PeerId,
        chain_id: ChainId,
        finalized_block_height: u64,
    },
    /// Received a GrandPa commit message from the network.
    GrandpaCommitMessage {
        peer_id: PeerId,
        chain_id: ChainId,
        message: service::EncodedGrandpaCommitMessage,
    },
}

/// Error returned by [`NetworkService::blocks_request`].
#[derive(Debug, derive_more::Display)]
pub enum BlocksRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display(fmt = "{_0}")]
    Request(service::BlocksRequestError),
}

/// Error returned by [`NetworkService::grandpa_warp_sync_request`].
#[derive(Debug, derive_more::Display)]
pub enum WarpSyncRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the request.
    #[display(fmt = "{_0}")]
    Request(service::GrandpaWarpSyncRequestError),
}

/// Error returned by [`NetworkService::storage_proof_request`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum StorageProofRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Storage proof request is too large and can't be sent.
    RequestTooLarge,
    /// Error during the request.
    #[display(fmt = "{_0}")]
    Request(service::StorageProofRequestError),
}

/// Error returned by [`NetworkService::call_proof_request`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum CallProofRequestError {
    /// No established connection with the target.
    NoConnection,
    /// Call proof request is too large and can't be sent.
    RequestTooLarge,
    /// Error during the request.
    #[display(fmt = "{_0}")]
    Request(service::CallProofRequestError),
}

impl CallProofRequestError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        match self {
            CallProofRequestError::Request(err) => err.is_network_problem(),
            CallProofRequestError::RequestTooLarge => false,
            CallProofRequestError::NoConnection => true,
        }
    }
}

enum ToBackground {
    ConnectionMessage {
        connection_id: service::ConnectionId,
        message: service::ConnectionToCoordinator,
    },
    // TODO: serialize the request before sending over channel
    StartBlocksRequest {
        target: PeerId, // TODO: takes by value because of future longevity issue
        chain_id: ChainId,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
        result: oneshot::Sender<Result<Vec<protocol::BlockData>, BlocksRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartWarpSyncRequest {
        target: PeerId,
        chain_id: ChainId,
        begin_hash: [u8; 32],
        timeout: Duration,
        result:
            oneshot::Sender<Result<service::EncodedGrandpaWarpSyncResponse, WarpSyncRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartStorageProofRequest {
        chain_id: ChainId,
        target: PeerId,
        config: protocol::StorageProofRequestConfig<vec::IntoIter<Vec<u8>>>,
        timeout: Duration,
        result: oneshot::Sender<Result<service::EncodedMerkleProof, StorageProofRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartCallProofRequest {
        chain_id: ChainId,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::CallProofRequestConfig<'static, vec::IntoIter<Vec<u8>>>,
        timeout: Duration,
        result: oneshot::Sender<Result<service::EncodedMerkleProof, CallProofRequestError>>,
    },
    SetLocalBestBlock {
        chain_id: ChainId,
        best_hash: [u8; 32],
        best_number: u64,
    },
    SetLocalGrandpaState {
        chain_id: ChainId,
        grandpa_state: service::GrandpaState,
    },
    AnnounceTransaction {
        chain_id: ChainId,
        transaction: Vec<u8>,
        result: oneshot::Sender<Vec<PeerId>>,
    },
    SendBlockAnnounce {
        target: PeerId,
        chain_id: ChainId,
        scale_encoded_header: Vec<u8>,
        is_best: bool,
        result: oneshot::Sender<Result<(), QueueNotificationError>>,
    },
    Discover {
        chain_id: ChainId,
        list: vec::IntoIter<(PeerId, vec::IntoIter<Multiaddr>)>,
        important_nodes: bool,
    },
    DiscoveredNodes {
        chain_id: ChainId,
        result: oneshot::Sender<Vec<(PeerId, Vec<Multiaddr>)>>,
    },
    PeersList {
        chain_id: ChainId,
        result: oneshot::Sender<Vec<PeerId>>,
    },
    StartDiscovery,
}

struct BackgroundTask<TPlat: PlatformRef> {
    /// See [`Config::platform`].
    platform: TPlat,

    /// Random number generator.
    randomness: rand_chacha::ChaCha20Rng,

    /// Value provided through [`Config::identify_agent_version`].
    identify_agent_version: String,

    /// Names of the various chains the network service connects to. Used only for logging
    /// purposes.
    // TODO: add a user data to the network state machine
    log_chain_names: hashbrown::HashMap<ChainId, String, fnv::FnvBuildHasher>,

    /// Channel to send messages to the background task.
    messages_tx: async_channel::Sender<ToBackground>,

    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<TPlat::Instant>,

    /// All known peers and their addresses.
    peering_strategy: basic_peering_strategy::BasicPeeringStrategy<ChainId, TPlat::Instant>,

    /// List of nodes that are considered as important for logging purposes.
    // TODO: should also detect whenever we fail to open a block announces substream with any of these peers
    important_nodes: HashSet<PeerId, fnv::FnvBuildHasher>,

    /// Sending events through the public API.
    ///
    /// Contains either senders, or a `Future` that is currently sending an event and will yield
    /// the senders back once it is finished.
    event_senders: either::Either<
        Vec<async_channel::Sender<Event>>,
        Pin<Box<dyn future::Future<Output = Vec<async_channel::Sender<Event>>> + Send>>,
    >,

    messages_rx: async_channel::Receiver<ToBackground>,

    active_connections: HashMap<
        service::ConnectionId,
        async_channel::Sender<service::CoordinatorToConnection>,
        fnv::FnvBuildHasher,
    >,

    blocks_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<Vec<protocol::BlockData>, BlocksRequestError>>,
        fnv::FnvBuildHasher,
    >,

    grandpa_warp_sync_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<service::EncodedGrandpaWarpSyncResponse, WarpSyncRequestError>>,
        fnv::FnvBuildHasher,
    >,

    storage_proof_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<service::EncodedMerkleProof, StorageProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    call_proof_requests: HashMap<
        service::SubstreamId,
        oneshot::Sender<Result<service::EncodedMerkleProof, CallProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    kademlia_find_node_requests: HashMap<service::SubstreamId, ChainId, fnv::FnvBuildHasher>,
}

async fn background_task<TPlat: PlatformRef>(mut task: BackgroundTask<TPlat>) {
    loop {
        // TODO: this is hacky; instead, should be cleaned up as a response to an event from the service; no such event exists yet
        task.active_connections.retain(|_, tx| !tx.is_closed());

        enum WhatHappened {
            Message(ToBackground),
            NetworkEvent(service::Event),
            CanAssignSlot(PeerId, ChainId),
            CanStartConnect(PeerId),
            CanOpenGossip(PeerId, ChainId),
            MessageToConnection {
                connection_id: service::ConnectionId,
                message: service::CoordinatorToConnection,
            },
            EventSendersReady,
        }

        let what_happened = {
            let message_received =
                async { WhatHappened::Message(task.messages_rx.next().await.unwrap()) };
            let can_generate_event = matches!(task.event_senders, either::Left(_));
            let service_event = async {
                if let Some(event) = can_generate_event
                    .then(|| task.network.next_event())
                    .flatten()
                {
                    WhatHappened::NetworkEvent(event)
                } else if let Some(start_connect) = {
                    let x = task.network.unconnected_desired().next().cloned();
                    x
                } {
                    WhatHappened::CanStartConnect(start_connect)
                } else if let Some((peer_id, chain_id)) = {
                    let x = task
                        .network
                        .connected_unopened_gossip_desired()
                        .next()
                        .map(|(peer_id, chain_id, _)| (peer_id.clone(), chain_id));
                    x
                } {
                    WhatHappened::CanOpenGossip(peer_id, chain_id)
                } else if let Some((connection_id, message)) =
                    task.network.pull_message_to_connection()
                {
                    WhatHappened::MessageToConnection {
                        connection_id,
                        message,
                    }
                } else if let Some((peer_id, chain_id)) = task.log_chain_names.keys().find_map(|chain_id| {
                    // TODO: 4 is an arbitrary constant, make configurable
                    if task
                        .network
                        .gossip_desired_num(*chain_id, service::GossipKind::ConsensusTransactions)
                        >= 4
                    {
                        return None;
                    }
    
                    match task.peering_strategy.pick_assignable_peer(chain_id, &task.platform.now()) {
                        basic_peering_strategy::AssignablePeer::Assignable(peer_id) => {
                            Some((peer_id.clone(), *chain_id))
                        }
                        basic_peering_strategy::AssignablePeer::AllPeersBanned { .. }  // TODO: handle `AllPeersBanned` by waking up when a ban expires
                        | basic_peering_strategy::AssignablePeer::NoPeer => None,
                    }
                }) {
                    WhatHappened::CanAssignSlot(peer_id, chain_id) 
                } else {
                    future::pending().await
                }
            };
            let finished_sending_event = async {
                if let either::Right(event_sending_future) = &mut task.event_senders {
                    let event_senders = event_sending_future.await;
                    task.event_senders = either::Left(event_senders);
                    WhatHappened::EventSendersReady
                } else {
                    future::pending().await
                }
            };

            message_received
                .or(service_event)
                .or(finished_sending_event)
                .await
        };

        let event_to_dispatch: Event = match what_happened {
            WhatHappened::EventSendersReady => {
                // Nothing to do. Just loop again, as we can now generate events.
                continue;
            }
            WhatHappened::Message(ToBackground::ConnectionMessage {
                connection_id,
                message,
            }) => {
                task.network
                    .inject_connection_message(connection_id, message);
                continue;
            }
            WhatHappened::Message(ToBackground::StartBlocksRequest {
                target,
                chain_id,
                config,
                timeout,
                result,
            }) => {
                match task
                    .network
                    .start_blocks_request(&target, chain_id, config.clone(), timeout)
                {
                    Ok(substream_id) => {
                        match &config.start {
                            protocol::BlocksRequestConfigStart::Hash(hash) => {
                                log::debug!(
                                    target: "network",
                                    "Connections({}) <= BlocksRequest(chain={}, start={}, num={}, descending={:?}, header={:?}, body={:?}, justifications={:?})",
                                    target, task.log_chain_names[&chain_id], HashDisplay(hash),
                                    config.desired_count.get(),
                                    matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                                    config.fields.header, config.fields.body, config.fields.justifications
                                );
                            }
                            protocol::BlocksRequestConfigStart::Number(number) => {
                                log::debug!(
                                    target: "network",
                                    "Connections({}) <= BlocksRequest(chain={}, start=#{}, num={}, descending={:?}, header={:?}, body={:?}, justifications={:?})",
                                    target, task.log_chain_names[&chain_id], number,
                                    config.desired_count.get(),
                                    matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                                    config.fields.header, config.fields.body, config.fields.justifications
                                );
                            }
                        }

                        task.blocks_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestError::NoConnection) => {
                        let _ = result.send(Err(BlocksRequestError::NoConnection));
                    }
                }

                continue;
            }
            WhatHappened::Message(ToBackground::StartWarpSyncRequest {
                target,
                chain_id,
                begin_hash,
                timeout,
                result,
            }) => {
                match task
                    .network
                    .start_grandpa_warp_sync_request(&target, chain_id, begin_hash, timeout)
                {
                    Ok(substream_id) => {
                        log::debug!(
                            target: "network", "Connections({}) <= WarpSyncRequest(chain={}, start={})",
                            target, task.log_chain_names[&chain_id], HashDisplay(&begin_hash)
                        );

                        task.grandpa_warp_sync_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestError::NoConnection) => {
                        let _ = result.send(Err(WarpSyncRequestError::NoConnection));
                    }
                }

                continue;
            }
            WhatHappened::Message(ToBackground::StartStorageProofRequest {
                chain_id,
                target,
                config,
                timeout,
                result,
            }) => {
                match task.network.start_storage_proof_request(
                    &target,
                    chain_id,
                    config.clone(),
                    timeout,
                ) {
                    Ok(substream_id) => {
                        log::debug!(
                            target: "network",
                            "Connections({}) <= StorageProofRequest(chain={}, block={})",
                            target,
                            task.log_chain_names[&chain_id],
                            HashDisplay(&config.block_hash)
                        );

                        task.storage_proof_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestMaybeTooLargeError::NoConnection) => {
                        let _ = result.send(Err(StorageProofRequestError::NoConnection));
                    }
                    Err(service::StartRequestMaybeTooLargeError::RequestTooLarge) => {
                        let _ = result.send(Err(StorageProofRequestError::RequestTooLarge));
                    }
                };

                continue;
            }
            WhatHappened::Message(ToBackground::StartCallProofRequest {
                chain_id,
                target,
                config,
                timeout,
                result,
            }) => {
                match task.network.start_call_proof_request(
                    &target,
                    chain_id,
                    config.clone(),
                    timeout,
                ) {
                    Ok(substream_id) => {
                        log::debug!(
                            target: "network",
                            "Connections({}) <= CallProofRequest({}, {}, {})",
                            target,
                            task.log_chain_names[&chain_id],
                            HashDisplay(&config.block_hash),
                            config.method
                        );

                        task.call_proof_requests.insert(substream_id, result);
                    }
                    Err(service::StartRequestMaybeTooLargeError::NoConnection) => {
                        let _ = result.send(Err(CallProofRequestError::NoConnection));
                    }
                    Err(service::StartRequestMaybeTooLargeError::RequestTooLarge) => {
                        let _ = result.send(Err(CallProofRequestError::RequestTooLarge));
                    }
                };

                continue;
            }
            WhatHappened::Message(ToBackground::SetLocalBestBlock {
                chain_id,
                best_hash,
                best_number,
            }) => {
                task.network
                    .set_chain_local_best_block(chain_id, best_hash, best_number);
                continue;
            }
            WhatHappened::Message(ToBackground::SetLocalGrandpaState {
                chain_id,
                grandpa_state,
            }) => {
                log::debug!(
                    target: "network",
                    "Chain({}) <= SetLocalGrandpaState(set_id: {}, commit_finalized_height: {})",
                    task.log_chain_names[&chain_id],
                    grandpa_state.set_id,
                    grandpa_state.commit_finalized_height,
                );

                // TODO: log the list of peers we sent the packet to

                task.network
                    .gossip_broadcast_grandpa_state_and_update(chain_id, grandpa_state);
                continue;
            }
            WhatHappened::Message(ToBackground::AnnounceTransaction {
                chain_id,
                transaction,
                result,
            }) => {
                let mut sent_peers = Vec::with_capacity(16); // TODO: capacity?

                // TODO: keep track of which peer knows about which transaction, and don't send it again

                // TODO: collecting in a Vec :-/
                for peer in task
                    .network
                    .gossip_connected_peers(chain_id, service::GossipKind::ConsensusTransactions)
                    .cloned()
                    .collect::<Vec<_>>()
                {
                    if task
                        .network
                        .gossip_send_transaction(&peer, chain_id, &transaction)
                        .is_ok()
                    {
                        sent_peers.push(peer);
                    };
                }

                let _ = result.send(sent_peers);
                continue;
            }
            WhatHappened::Message(ToBackground::SendBlockAnnounce {
                target,
                chain_id,
                scale_encoded_header,
                is_best,
                result,
            }) => {
                let _ = result.send(task.network.gossip_send_block_announce(
                    &target,
                    chain_id,
                    &scale_encoded_header,
                    is_best,
                ));
                continue;
            }
            WhatHappened::Message(ToBackground::Discover {
                chain_id,
                list,
                important_nodes,
            }) => {
                for (peer_id, addrs) in list {
                    if important_nodes {
                        task.important_nodes.insert(peer_id.clone());
                    }

                    for addr in addrs {
                        task.peering_strategy
                            .insert_address(&peer_id, addr.into_vec());
                    }

                    task.peering_strategy.insert_chain_peer(chain_id, peer_id);
                }

                continue;
            }
            WhatHappened::Message(ToBackground::DiscoveredNodes { chain_id, result }) => {
                // TODO: consider returning Vec<u8>s for the addresses?
                let _ = result.send(
                    task.peering_strategy
                        .chain_peers_unordered(&chain_id)
                        .map(|peer_id| {
                            let addrs = task
                                .peering_strategy
                                .peer_addresses(peer_id)
                                .map(|a| Multiaddr::try_from(a.to_owned()).unwrap())
                                .collect::<Vec<_>>();
                            (peer_id.clone(), addrs)
                        })
                        .collect::<Vec<_>>(),
                );
                continue;
            }
            WhatHappened::Message(ToBackground::PeersList { chain_id, result }) => {
                let _ = result.send(
                    task.network
                        .gossip_connected_peers(
                            chain_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .cloned()
                        .collect(),
                );
                continue;
            }
            WhatHappened::Message(ToBackground::StartDiscovery) => {
                for chain_id in task.log_chain_names.keys() {
                    let random_peer_id = {
                        let mut pub_key = [0; 32];
                        rand_chacha::rand_core::RngCore::fill_bytes(
                            &mut task.randomness,
                            &mut pub_key,
                        );
                        PeerId::from_public_key(&peer_id::PublicKey::Ed25519(pub_key))
                    };

                    // TODO: select target closest to the random peer instead
                    let target = task
                        .network
                        .gossip_connected_peers(
                            *chain_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .next()
                        .map(|p| p.clone());

                    if let Some(target) = target {
                        let substream_id = match task.network.start_kademlia_find_node_request(
                            &target,
                            *chain_id,
                            &random_peer_id,
                            Duration::from_secs(20),
                        ) {
                            Ok(s) => s,
                            Err(service::StartRequestError::NoConnection) => unreachable!(),
                        };

                        let _prev_value = task
                            .kademlia_find_node_requests
                            .insert(substream_id, *chain_id);
                        debug_assert!(_prev_value.is_none());
                    } else {
                        // TODO: log message
                    }
                }

                continue;
            }
            WhatHappened::NetworkEvent(service::Event::HandshakeFinished {
                peer_id,
                expected_peer_id,
                id,
            }) => {
                let remote_addr =
                    Multiaddr::try_from(task.network.connection_remote_addr(id).to_owned())
                        .unwrap(); // TODO: review this unwrap
                if let Some(expected_peer_id) = expected_peer_id.as_ref().filter(|p| **p != peer_id)
                {
                    log::debug!(target: "network", "Connections({}, {}) => HandshakePeerIdMismatch(actual={})", expected_peer_id, remote_addr, peer_id);

                    task.peering_strategy
                        .remove_address(expected_peer_id, remote_addr.as_ref());
                    task.peering_strategy
                        .insert_connected_address(&peer_id, remote_addr.clone().into_vec());
                } else {
                    log::debug!(target: "network", "Connections({}, {}) => HandshakeFinished", peer_id, remote_addr);
                }
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::PreHandshakeDisconnected {
                address,
                expected_peer_id,
                ..
            }) => {
                if let Some(expected_peer_id) = expected_peer_id {
                    task.peering_strategy
                        .disconnect_addr(&expected_peer_id, &address)
                        .unwrap();
                    let address = Multiaddr::try_from(address).unwrap();
                    log::debug!(target: "network", "Connections({}, {}) => Shutdown(handshake_finished=false)", expected_peer_id, address);
                }
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::Disconnected {
                address, peer_id, ..
            }) => {
                task.peering_strategy
                    .disconnect_addr(&peer_id, &address)
                    .unwrap();
                let address = Multiaddr::try_from(address).unwrap();
                log::debug!(target: "network", "Connections({}, {}) => Shutdown(handshake_finished=true)", peer_id, address);
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::BlockAnnounce {
                chain_id,
                peer_id,
                announce,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => BlockAnnounce(best_hash={}, is_best={})",
                    peer_id,
                    &task.log_chain_names[&chain_id],
                    HashDisplay(&header::hash_from_scale_encoded_header(announce.decode().scale_encoded_header)),
                    announce.decode().is_best
                );
                Event::BlockAnnounce {
                    chain_id,
                    peer_id,
                    announce,
                }
            }
            WhatHappened::NetworkEvent(service::Event::GossipConnected {
                peer_id,
                chain_id,
                role,
                best_number,
                best_hash,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                log::debug!(
                    target: "network",
                    "Gossip({}, {}) => Opened(best_height={}, best_hash={})",
                    peer_id,
                    &task.log_chain_names[&chain_id],
                    best_number,
                    HashDisplay(&best_hash)
                );
                Event::Connected {
                    peer_id,
                    chain_id,
                    role,
                    best_block_number: best_number,
                    best_block_hash: best_hash,
                }
            }
            WhatHappened::NetworkEvent(service::Event::GossipOpenFailed {
                peer_id,
                chain_id,
                error,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                log::debug!(
                    target: "network",
                    "Gossip({}, {}) => OpenFailed(error={:?})",
                    &task.log_chain_names[&chain_id],
                    peer_id, error,
                );
                log::debug!(
                    target: "connections",
                    "{}Slots ∌ {}", // TODO:
                    &task.log_chain_names[&chain_id],
                    peer_id
                );
                // Note that peer doesn't necessarily have an out slot, as this event might happen
                // as a result of an inbound gossip connection.
                task.network.gossip_remove_desired(
                    chain_id,
                    &peer_id,
                    service::GossipKind::ConsensusTransactions,
                );
                if let service::GossipConnectError::GenesisMismatch { .. } = error {
                    task.peering_strategy
                        .unassign_slot_and_remove_chain_peer(&chain_id, &peer_id);
                } else {
                    task.peering_strategy.unassign_slot_and_ban(
                        &chain_id,
                        &peer_id,
                        task.platform.now() + Duration::from_secs(15),
                    );
                }
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::GossipDisconnected {
                peer_id,
                chain_id,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => GossipDisconnected",
                    peer_id,
                    &task.log_chain_names[&chain_id],
                );
                log::debug!(
                    target: "connections",
                    "{}Slots ∌ {}", // TODO:
                    &task.log_chain_names[&chain_id],
                    peer_id
                );
                // Note that peer doesn't necessarily have an out slot, as this event might happen
                // as a result of an inbound gossip connection.
                task.peering_strategy.unassign_slot_and_ban(
                    &chain_id,
                    &peer_id,
                    task.platform.now() + Duration::from_secs(10),
                );
                task.network.gossip_remove_desired(
                    chain_id,
                    &peer_id,
                    service::GossipKind::ConsensusTransactions,
                );
                Event::Disconnected { peer_id, chain_id }
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                substream_id,
                response: service::RequestResult::Blocks(response),
            }) => {
                let _ = task
                    .blocks_requests
                    .remove(&substream_id)
                    .unwrap()
                    .send(response.map_err(BlocksRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                substream_id,
                response: service::RequestResult::GrandpaWarpSync(response),
            }) => {
                let _ = task
                    .grandpa_warp_sync_requests
                    .remove(&substream_id)
                    .unwrap()
                    .send(response.map_err(WarpSyncRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                substream_id,
                response: service::RequestResult::StorageProof(response),
            }) => {
                let _ = task
                    .storage_proof_requests
                    .remove(&substream_id)
                    .unwrap()
                    .send(response.map_err(StorageProofRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                substream_id,
                response: service::RequestResult::CallProof(response),
            }) => {
                let _ = task
                    .call_proof_requests
                    .remove(&substream_id)
                    .unwrap()
                    .send(response.map_err(CallProofRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                substream_id,
                response: service::RequestResult::KademliaFindNode(Ok(nodes)),
            }) => {
                let chain_id = task
                    .kademlia_find_node_requests
                    .remove(&substream_id)
                    .unwrap();

                log::debug!(
                    target: "connections", "On chain {}, discovered: {}",
                    &task.log_chain_names[&chain_id],
                    nodes.iter().map(|(p, _)| p.to_string()).join(", ")
                );

                for (peer_id, addrs) in nodes {
                    let mut valid_addrs = Vec::with_capacity(addrs.len());
                    for addr in addrs {
                        match Multiaddr::try_from(addr) {
                            Ok(a) => valid_addrs.push(a),
                            Err(err) => {
                                log::debug!(
                                    target: "connections",
                                    "Discovery => InvalidAddress({})",
                                    hex::encode(&err.addr)
                                );
                                continue;
                            }
                        }
                    }

                    if !valid_addrs.is_empty() {
                        task.peering_strategy
                            .insert_chain_peer(chain_id, peer_id.clone());
                    }

                    for addr in valid_addrs {
                        task.peering_strategy
                            .insert_address(&peer_id, addr.into_vec());
                    }
                }

                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                substream_id,
                response: service::RequestResult::KademliaFindNode(Err(error)),
            }) => {
                let chain_id = task
                    .kademlia_find_node_requests
                    .remove(&substream_id)
                    .unwrap();

                log::debug!(
                    target: "connections",
                    "Discovery({}) => {:?}",
                    &task.log_chain_names[&chain_id],
                    error
                );

                // No error is printed if the request fails due to a benign networking error such
                // as an unresponsive peer.
                match error {
                    service::KademliaFindNodeError::RequestFailed(err)
                        if !err.is_protocol_error() => {}

                    service::KademliaFindNodeError::RequestFailed(
                        service::RequestError::Substream(
                            connection::established::RequestError::ProtocolNotAvailable,
                        ),
                    ) => {
                        // TODO: remove this warning in a long time
                        log::warn!(
                            target: "connections",
                            "Problem during discovery on {}: protocol not available. \
                            This might indicate that the version of Substrate used by \
                            the chain doesn't include \
                            <https://github.com/paritytech/substrate/pull/12545>.",
                            &task.log_chain_names[&chain_id]
                        );
                    }
                    _ => {
                        log::warn!(
                            target: "connections",
                            "Problem during discovery on {}: {}",
                            &task.log_chain_names[&chain_id],
                            error
                        );
                    }
                }

                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult { .. }) => {
                // We never start any other kind of requests.
                unreachable!()
            }
            WhatHappened::NetworkEvent(service::Event::GossipInDesired {
                peer_id,
                chain_id,
                kind: service::GossipKind::ConsensusTransactions,
            }) => {
                // The networking state machine guarantees that `GossipInDesired`
                // can't happen if we are already opening an out slot, which we do
                // immediately.
                // TODO: add debug_assert! ^
                if task
                    .network
                    .opened_gossip_undesired_by_chain(chain_id)
                    .count()
                    < 4
                {
                    log::debug!(
                        target: "connections",
                        "InSlots({}) ∋ {}",
                        &task.log_chain_names[&chain_id],
                        peer_id
                    );
                    task.network
                        .gossip_open(
                            chain_id,
                            &peer_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .unwrap();
                } else {
                    log::debug!(
                        target: "connections",
                        "Connections({}) => GossipInDesiredRejected(chain={}, error=full)",
                        peer_id,
                        &task.log_chain_names[&chain_id],
                    );
                    task.network
                        .gossip_close(
                            chain_id,
                            &peer_id,
                            service::GossipKind::ConsensusTransactions,
                        )
                        .unwrap();
                }

                continue;
            }
            WhatHappened::NetworkEvent(service::Event::GossipInDesiredCancel { .. }) => {
                // Can't happen as we already instantaneously accept or reject gossip in requests.
                unreachable!()
            }
            WhatHappened::NetworkEvent(service::Event::IdentifyRequestIn {
                peer_id,
                substream_id,
            }) => {
                log::debug!(
                    target: "network",
                    "Connections({}) => IdentifyRequest",
                    peer_id,
                );
                task.network
                    .respond_identify(substream_id, &task.identify_agent_version);
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::BlocksRequestIn { .. }) => unreachable!(),
            WhatHappened::NetworkEvent(service::Event::RequestInCancel { .. }) => {
                // All incoming requests are immediately answered.
                unreachable!()
            }
            WhatHappened::NetworkEvent(service::Event::GrandpaNeighborPacket {
                chain_id,
                peer_id,
                state,
            }) => {
                log::debug!(
                    target: "network",
                    "Gossip({}, {}) => GrandpaNeighborPacket(round_number={}, set_id={}, commit_finalized_height={})",
                    peer_id,
                    &task.log_chain_names[&chain_id],
                    state.round_number,
                    state.set_id,
                    state.commit_finalized_height,
                );
                Event::GrandpaNeighborPacket {
                    chain_id,
                    peer_id,
                    finalized_block_height: state.commit_finalized_height,
                }
            }
            WhatHappened::NetworkEvent(service::Event::GrandpaCommitMessage {
                chain_id,
                peer_id,
                message,
            }) => {
                log::debug!(
                    target: "network",
                    "Gossip({}, {}) => GrandpaCommitMessage(target_block_hash={})",
                    peer_id,
                    &task.log_chain_names[&chain_id],
                    HashDisplay(message.decode().message.target_hash),
                );
                Event::GrandpaCommitMessage {
                    chain_id,
                    peer_id,
                    message,
                }
            }
            WhatHappened::NetworkEvent(service::Event::ProtocolError { peer_id, error }) => {
                // TODO: handle properly?
                log::warn!(
                    target: "network",
                    "Connections({}) => ProtocolError(error={:?})",
                    peer_id,
                    error,
                );

                // TODO: disconnect peer
                continue;
            }
            WhatHappened::CanAssignSlot(peer_id, chain_id) => {
                task.peering_strategy.assign_slot(&chain_id, &peer_id);

                log::debug!(
                    target: "connections",
                    "OutSlots({}) ∋ {}",
                    &task.log_chain_names[&chain_id],
                    peer_id
                );

                task.network.gossip_insert_desired(
                    chain_id,
                    peer_id,
                    service::GossipKind::ConsensusTransactions,
                );

                continue;
            }
            WhatHappened::CanStartConnect(peer_id) => {
                // TODO: restore rate limiting

                let Some(multiaddr) = task.peering_strategy.addr_to_connected(&peer_id) else {
                    // There is no address for that peer in the address book.
                    task.network.gossip_remove_desired_all(
                        &peer_id,
                        service::GossipKind::ConsensusTransactions,
                    );
                    task.peering_strategy.unassign_slots_and_ban(
                        &peer_id,
                        task.platform.now() + Duration::from_secs(10),
                    );
                    continue;
                };

                let multiaddr = match multiaddr::Multiaddr::try_from(multiaddr.to_owned()) {
                    Ok(a) => a,
                    Err(multiaddr::FromVecError { addr }) => {
                        // Address is in an invalid format.
                        let _was_in = task.peering_strategy.remove_address(&peer_id, &addr);
                        debug_assert!(_was_in);
                        continue;
                    }
                };

                let address = address_parse::multiaddr_to_address(&multiaddr)
                    .ok()
                    .filter(|addr| {
                        task.platform.supports_connection_type(match &addr {
                            address_parse::AddressOrMultiStreamAddress::Address(addr) => {
                                From::from(addr)
                            }
                            address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(
                                addr,
                            ) => From::from(addr),
                        })
                    });

                let Some(address) = address else {
                    // Address is in an invalid format or isn't supported by the platform.
                    let _was_in = task
                        .peering_strategy
                        .remove_address(&peer_id, multiaddr.as_ref());
                    debug_assert!(_was_in);
                    continue;
                };

                log::debug!(
                    target: "connections",
                    "Connections({}) <= StartConnecting({})",
                    peer_id,
                    multiaddr
                );

                let (coordinator_to_connection_tx, coordinator_to_connection_rx) =
                    async_channel::bounded(8);
                let task_name = format!("connection-{}-{}", peer_id, multiaddr);

                let connection_id = match address {
                    address_parse::AddressOrMultiStreamAddress::Address(_) => {
                        let (connection_id, connection_task) =
                            task.network.add_single_stream_connection(
                                task.platform.now(),
                                service::SingleStreamHandshakeKind::MultistreamSelectNoiseYamux {
                                    is_initiator: true,
                                },
                                multiaddr.clone().into_vec(),
                                Some(peer_id.clone()),
                            );

                        task.platform.spawn_task(
                            task_name.into(),
                            tasks::single_stream_connection_task::<TPlat>(
                                multiaddr,
                                task.platform.clone(),
                                connection_id,
                                connection_task,
                                coordinator_to_connection_rx,
                                task.messages_tx.clone(),
                            ),
                        );

                        connection_id
                    }
                    address_parse::AddressOrMultiStreamAddress::MultiStreamAddress(
                        platform::MultiStreamAddress::WebRtc {
                            ip,
                            port,
                            remote_certificate_sha256,
                        },
                    ) => {
                        // TODO: we unfortunately need to know the local TLS certificate in order to
                        // insert the connection, and this local TLS certificate can only be given
                        // to us by the platform implementation, leading to this `await` here which
                        // really shouldn't exist. For the moment it's fine because the only implementations
                        // of multistream connections returns very quickly, but in theory this `await`
                        // could block for a long time.
                        let connection = task
                            .platform
                            .connect_multistream(platform::MultiStreamAddress::WebRtc {
                                ip,
                                port,
                                remote_certificate_sha256,
                            })
                            .await
                            .unwrap_or_else(|_| unreachable!()); // TODO: don't unwrap, again we know that the only implementation that exists never unwraps here, but in theory it's possible

                        // Convert the SHA256 hashes into multihashes.
                        let local_tls_certificate_multihash = [12u8, 32]
                            .into_iter()
                            .chain(connection.local_tls_certificate_sha256.into_iter())
                            .collect();
                        debug_assert_eq!(
                            // TODO: check is a bit stupid given that the remote certificate is just passed through
                            remote_certificate_sha256,
                            connection.remote_tls_certificate_sha256
                        );
                        let remote_tls_certificate_multihash = [12u8, 32]
                            .into_iter()
                            .chain(remote_certificate_sha256.into_iter())
                            .collect();

                        let (connection_id, connection_task) =
                            task.network.add_multi_stream_connection(
                                task.platform.now(),
                                service::MultiStreamHandshakeKind::WebRtc {
                                    is_initiator: true,
                                    local_tls_certificate_multihash,
                                    remote_tls_certificate_multihash,
                                },
                                multiaddr.clone().into_vec(),
                                Some(peer_id.clone()),
                            );

                        task.platform.spawn_task(
                            task_name.into(),
                            tasks::webrtc_multi_stream_connection_task::<TPlat>(
                                connection.connection,
                                multiaddr.to_string(),
                                task.platform.clone(),
                                connection_id,
                                connection_task,
                                coordinator_to_connection_rx,
                                task.messages_tx.clone(),
                            ),
                        );

                        connection_id
                    }
                };

                let _prev_value = task
                    .active_connections
                    .insert(connection_id, coordinator_to_connection_tx);
                debug_assert!(_prev_value.is_none());

                continue;
            }
            WhatHappened::CanOpenGossip(peer_id, chain_id) => {
                task.network
                    .gossip_open(
                        chain_id,
                        &peer_id,
                        service::GossipKind::ConsensusTransactions,
                    )
                    .unwrap();

                log::debug!(
                    target: "network",
                    "Gossip({}, {}) <= Open",
                    peer_id,
                    &task.log_chain_names[&chain_id],
                );

                continue;
            }
            WhatHappened::MessageToConnection {
                connection_id,
                message,
            } => {
                // Note that it is critical for the sending to not take too long here, in order to not
                // block the process of the network service.
                // In particular, if sending the message to the connection is blocked due to sending
                // a message on the connection-to-coordinator channel, this will result in a deadlock.
                // For this reason, the connection task is always ready to immediately accept a message
                // on the coordinator-to-connection channel.
                task.active_connections
                    .get_mut(&connection_id)
                    .unwrap()
                    .send(message)
                    .await
                    .unwrap();
                continue;
            }
        };

        // Dispatch the event to the various senders.

        // We made sure that the senders were ready before generating an event.
        let either::Left(event_senders) = &mut task.event_senders else {
            unreachable!()
        };

        let mut event_senders = mem::take(event_senders);
        task.event_senders = either::Right(Box::pin(async move {
            // This little `if` avoids having to do `event.clone()` if we don't have to.
            if event_senders.len() == 1 {
                let _ = event_senders[0].send(event_to_dispatch).await;
            } else {
                for sender in event_senders.iter_mut() {
                    // For simplicity we don't get rid of closed senders because senders
                    // aren't supposed to close, and that leaving closed senders in the
                    // list doesn't have any consequence other than one extra iteration
                    // every time.
                    let _ = sender.send(event_to_dispatch.clone()).await;
                }
            }

            event_senders
        }));
    }
}
