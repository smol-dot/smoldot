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

use crate::{platform::PlatformRef, util};

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec::{self, Vec},
};
use core::{cmp, mem, num::NonZeroUsize, pin::Pin, task::Poll, time::Duration};
use futures_channel::oneshot;
use futures_lite::FutureExt as _;
use futures_util::{future, stream, StreamExt as _};
use hashbrown::{hash_map, HashMap, HashSet};
use itertools::Itertools as _;
use smoldot::{
    header,
    informant::{BytesDisplay, HashDisplay},
    libp2p::{connection, multiaddr::Multiaddr, peer_id::PeerId, peers},
    network::{protocol, service},
};

pub use service::EncodedMerkleProof;

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

    /// Number of the finalized block at the time of the initialization.
    pub finalized_block_height: u64,

    /// Number and hash of the current best block. Can later be updated with
    /// [`NetworkService::set_local_best_block`].
    pub best_block: (u64, [u8; 32]),

    /// Optional identifier to insert into the networking protocol names. Used to differentiate
    /// between chains with the same genesis hash.
    pub fork_id: Option<String>,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// If true, the chain uses the GrandPa networking protocol.
    pub has_grandpa_protocol: bool,
}

pub struct NetworkService<TPlat: PlatformRef> {
    /// Names of the various chains the network service connects to. Used only for logging
    /// purposes.
    log_chain_names: Vec<String>,

    /// Channel to send messages to the background task.
    messages_tx: async_channel::Sender<ToBackground<TPlat>>,

    /// Event notified when the [`NetworkService`] is destroyed.
    on_service_killed: event_listener::Event,
}

impl<TPlat: PlatformRef> NetworkService<TPlat> {
    /// Initializes the network service with the given configuration.
    ///
    /// Returns the networking service, plus a list of receivers on which events are pushed.
    /// All of these receivers must be polled regularly to prevent the networking service from
    /// slowing down.
    pub async fn new(config: Config<TPlat>) -> (Arc<Self>, Vec<stream::BoxStream<'static, Event>>) {
        let (event_senders, event_receivers): (Vec<_>, Vec<_>) = (0..config.num_events_receivers)
            .map(|_| async_channel::bounded(16))
            .unzip();

        let num_chains = config.chains.len();
        let mut chains = Vec::with_capacity(num_chains);
        let mut log_chain_names = Vec::with_capacity(num_chains);

        for chain in config.chains {
            chains.push(service::ChainConfig {
                in_slots: 3,
                out_slots: 4,
                grandpa_protocol_config: if chain.has_grandpa_protocol {
                    // TODO: dummy values
                    Some(service::GrandpaState {
                        commit_finalized_height: chain.finalized_block_height,
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
            });

            log_chain_names.push(chain.log_name);
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
        config.platform.spawn_task(
            "network-service".into(),
            Box::pin(
                background_task(BackgroundTask {
                    identify_agent_version: config.identify_agent_version,
                    log_chain_names: log_chain_names.clone(),
                    messages_tx: messages_tx.clone(),
                    network: service::ChainNetwork::new(service::Config {
                        now: config.platform.now(),
                        chains,
                        connections_capacity: 32,
                        peers_capacity: 8,
                        max_addresses_per_peer: NonZeroUsize::new(5).unwrap(),
                        noise_key: config.noise_key,
                        handshake_timeout: Duration::from_secs(8),
                        randomness_seed: rand::random(),
                    }),
                    platform: config.platform.clone(),
                    event_senders: either::Left(event_senders),
                    slots_assign_backoff: HashMap::with_capacity_and_hasher(
                        32,
                        util::SipHasherBuild::new(rand::random()),
                    ),
                    important_nodes: HashSet::with_capacity_and_hasher(16, Default::default()),
                    active_connections: HashMap::with_capacity_and_hasher(32, Default::default()),
                    messages_rx,
                    blocks_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                    grandpa_warp_sync_requests: HashMap::with_capacity_and_hasher(
                        8,
                        Default::default(),
                    ),
                    storage_proof_requests: HashMap::with_capacity_and_hasher(
                        8,
                        Default::default(),
                    ),
                    call_proof_requests: HashMap::with_capacity_and_hasher(8, Default::default()),
                    kademlia_discovery_operations: HashMap::with_capacity_and_hasher(
                        2,
                        Default::default(),
                    ),
                })
                .or(on_service_killed.listen()),
            ),
        );

        let final_network_service = Arc::new(NetworkService {
            log_chain_names,
            messages_tx,
            on_service_killed,
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

        (final_network_service, event_receivers)
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    pub async fn blocks_request(
        self: Arc<Self>,
        target: PeerId,
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
    ) -> Result<Vec<protocol::BlockData>, BlocksRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartBlocksRequest {
                target: target.clone(),
                chain_index,
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
                    "Connection({}) => BlocksRequest(chain={}, num_blocks={}, block_data_total_size={})",
                    target,
                    self.log_chain_names[chain_index],
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
                    "Connection({}) => BlocksRequest(chain={}, error={:?})",
                    target,
                    self.log_chain_names[chain_index],
                    err
                );
            }
        }

        if !log::log_enabled!(log::Level::Debug) {
            match &result {
                Ok(_)
                | Err(BlocksRequestError::NoConnection)
                | Err(BlocksRequestError::Request(service::BlocksRequestError::EmptyResponse))
                | Err(BlocksRequestError::Request(service::BlocksRequestError::NotVerifiable)) => {}
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
        chain_index: usize,
        begin_hash: [u8; 32],
        timeout: Duration,
    ) -> Result<service::EncodedGrandpaWarpSyncResponse, GrandpaWarpSyncRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartGrandpaWarpSyncRequest {
                target: target.clone(),
                chain_index,
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
                    "Connection({}) => GrandpaWarpSyncRequest(chain={}, num_fragments={}, finished={:?})",
                    target,
                    self.log_chain_names[chain_index],
                    decoded.fragments.len(),
                    decoded.is_finished,
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => GrandpaWarpSyncRequest(chain={}, error={:?})",
                    target,
                    self.log_chain_names[chain_index],
                    err,
                );
            }
        }

        result
    }

    pub async fn set_local_best_block(
        &self,
        chain_index: usize,
        best_hash: [u8; 32],
        best_number: u64,
    ) {
        self.messages_tx
            .send(ToBackground::SetLocalBestBlock {
                chain_index,
                best_hash,
                best_number,
            })
            .await
            .unwrap();
    }

    pub async fn set_local_grandpa_state(
        &self,
        chain_index: usize,
        grandpa_state: service::GrandpaState,
    ) {
        self.messages_tx
            .send(ToBackground::SetLocalGrandpaState {
                chain_index,
                grandpa_state,
            })
            .await
            .unwrap();
    }

    /// Sends a storage proof request to the given peer.
    // TODO: more docs
    pub async fn storage_proof_request(
        self: Arc<Self>,
        chain_index: usize,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]> + Clone>>,
        timeout: Duration,
    ) -> Result<service::EncodedMerkleProof, StorageProofRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartStorageProofRequest {
                target: target.clone(),
                chain_index,
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
                    "Connection({}) => StorageProofRequest(chain={}, total_size={})",
                    target,
                    self.log_chain_names[chain_index],
                    BytesDisplay(u64::try_from(decoded.len()).unwrap()),
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => StorageProofRequest(chain={}, error={:?})",
                    target,
                    self.log_chain_names[chain_index],
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
        chain_index: usize,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::CallProofRequestConfig<'_, impl Iterator<Item = impl AsRef<[u8]>>>,
        timeout: Duration,
    ) -> Result<EncodedMerkleProof, CallProofRequestError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::StartCallProofRequest {
                target: target.clone(),
                chain_index,
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
                    "Connection({}) => CallProofRequest({}, total_size: {})",
                    target,
                    self.log_chain_names[chain_index],
                    BytesDisplay(u64::try_from(decoded.len()).unwrap())
                );
            }
            Err(err) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => CallProofRequest({}, {})",
                    target,
                    self.log_chain_names[chain_index],
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
        chain_index: usize,
        transaction: &[u8],
    ) -> Vec<PeerId> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::AnnounceTransaction {
                chain_index,
                transaction: transaction.to_vec(), // TODO: ovheread
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// See [`service::ChainNetwork::send_block_announce`].
    pub async fn send_block_announce(
        self: Arc<Self>,
        target: &PeerId,
        chain_index: usize,
        scale_encoded_header: &[u8],
        is_best: bool,
    ) -> Result<(), QueueNotificationError> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::SendBlockAnnounce {
                target: target.clone(), // TODO: overhead
                chain_index,
                scale_encoded_header: scale_encoded_header.to_vec(), // TODO: overhead
                is_best,
                result: tx,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// See [`service::ChainNetwork::discover`].
    ///
    /// The `important_nodes` parameter indicates whether these nodes are considered note-worthy
    /// and should have additional logging.
    pub async fn discover(
        &self,
        now: &TPlat::Instant,
        chain_index: usize,
        list: impl IntoIterator<Item = (PeerId, impl IntoIterator<Item = Multiaddr>)>,
        important_nodes: bool,
    ) {
        self.messages_tx
            .send(ToBackground::Discover {
                now: now.clone(), // TODO: overhead
                chain_index,
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
        chain_index: usize,
    ) -> impl Iterator<Item = (PeerId, impl Iterator<Item = Multiaddr>)> {
        let (tx, rx) = oneshot::channel();

        self.messages_tx
            .send(ToBackground::DiscoveredNodes {
                chain_index,
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
    pub async fn peers_list(&self) -> impl Iterator<Item = PeerId> {
        let (tx, rx) = oneshot::channel();
        self.messages_tx
            .send(ToBackground::PeersList { result: tx })
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
        chain_index: usize,
        role: protocol::Role,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    },
    Disconnected {
        peer_id: PeerId,
        chain_index: usize,
    },
    BlockAnnounce {
        peer_id: PeerId,
        chain_index: usize,
        announce: service::EncodedBlockAnnounce,
    },
    GrandpaNeighborPacket {
        peer_id: PeerId,
        chain_index: usize,
        finalized_block_height: u64,
    },
    /// Received a GrandPa commit message from the network.
    GrandpaCommitMessage {
        peer_id: PeerId,
        chain_index: usize,
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
pub enum GrandpaWarpSyncRequestError {
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

/// Error returned by [`NetworkService::send_block_announce`].
#[derive(Debug, derive_more::Display)]
pub enum QueueNotificationError {
    /// No established connection with the target.
    NoConnection,
    /// Error during the queuing.
    #[display(fmt = "{_0}")]
    Queue(peers::QueueNotificationError),
}

enum ToBackground<TPlat: PlatformRef> {
    ConnectionAttemptOkSingleStream {
        pending_id: service::PendingId,
        connection: TPlat::Stream,
        expected_peer_id: PeerId,
        multiaddr: Multiaddr,
        handshake_kind: service::SingleStreamHandshakeKind,
    },
    ConnectionAttemptOkMultiStream {
        pending_id: service::PendingId,
        connection: TPlat::MultiStream,
        expected_peer_id: PeerId,
        multiaddr: Multiaddr,
        handshake_kind: service::MultiStreamHandshakeKind,
    },
    ConnectionAttemptErr {
        pending_id: service::PendingId,
        expected_peer_id: PeerId,
        is_bad_addr: bool,
    },
    ConnectionMessage {
        connection_id: service::ConnectionId,
        message: service::ConnectionToCoordinator,
    },
    // TODO: serialize the request before sending over channel
    StartBlocksRequest {
        target: PeerId, // TODO: takes by value because of future longevity issue
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
        timeout: Duration,
        result: oneshot::Sender<Result<Vec<protocol::BlockData>, BlocksRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartGrandpaWarpSyncRequest {
        target: PeerId,
        chain_index: usize,
        begin_hash: [u8; 32],
        timeout: Duration,
        result: oneshot::Sender<
            Result<service::EncodedGrandpaWarpSyncResponse, GrandpaWarpSyncRequestError>,
        >,
    },
    // TODO: serialize the request before sending over channel
    StartStorageProofRequest {
        chain_index: usize,
        target: PeerId,
        config: protocol::StorageProofRequestConfig<vec::IntoIter<Vec<u8>>>,
        timeout: Duration,
        result: oneshot::Sender<Result<service::EncodedMerkleProof, StorageProofRequestError>>,
    },
    // TODO: serialize the request before sending over channel
    StartCallProofRequest {
        chain_index: usize,
        target: PeerId, // TODO: takes by value because of futures longevity issue
        config: protocol::CallProofRequestConfig<'static, vec::IntoIter<Vec<u8>>>,
        timeout: Duration,
        result: oneshot::Sender<Result<service::EncodedMerkleProof, CallProofRequestError>>,
    },
    SetLocalBestBlock {
        chain_index: usize,
        best_hash: [u8; 32],
        best_number: u64,
    },
    SetLocalGrandpaState {
        chain_index: usize,
        grandpa_state: service::GrandpaState,
    },
    AnnounceTransaction {
        chain_index: usize,
        transaction: Vec<u8>,
        result: oneshot::Sender<Vec<PeerId>>,
    },
    SendBlockAnnounce {
        target: PeerId,
        chain_index: usize,
        scale_encoded_header: Vec<u8>,
        is_best: bool,
        result: oneshot::Sender<Result<(), QueueNotificationError>>,
    },
    Discover {
        now: TPlat::Instant,
        chain_index: usize,
        list: vec::IntoIter<(PeerId, vec::IntoIter<Multiaddr>)>,
        important_nodes: bool,
    },
    DiscoveredNodes {
        chain_index: usize,
        result: oneshot::Sender<Vec<(PeerId, Vec<Multiaddr>)>>,
    },
    PeersList {
        result: oneshot::Sender<Vec<PeerId>>,
    },
    StartDiscovery,
}

struct BackgroundTask<TPlat: PlatformRef> {
    /// See [`Config::platform`].
    platform: TPlat,

    /// Value provided through [`Config::identify_agent_version`].
    identify_agent_version: String,

    /// Names of the various chains the network service connects to. Used only for logging
    /// purposes.
    log_chain_names: Vec<String>,

    /// Channel to send messages to the background task.
    messages_tx: async_channel::Sender<ToBackground<TPlat>>,

    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<TPlat::Instant>,

    /// List of nodes that are considered as important for logging purposes.
    // TODO: should also detect whenever we fail to open a block announces substream with any of these peers
    important_nodes: HashSet<PeerId, fnv::FnvBuildHasher>,

    /// List of peer and chain index tuples for which no outbound slot should be assigned.
    ///
    /// The values are the moment when the ban expires.
    slots_assign_backoff: HashMap<(PeerId, usize), TPlat::Instant, util::SipHasherBuild>,

    /// Sending events through the public API.
    ///
    /// Contains either senders, or a `Future` that is currently sending an event and will yield
    /// the senders back once it is finished.
    event_senders: either::Either<
        Vec<async_channel::Sender<Event>>,
        Pin<Box<dyn future::Future<Output = Vec<async_channel::Sender<Event>>> + Send>>,
    >,

    messages_rx: async_channel::Receiver<ToBackground<TPlat>>,

    active_connections: HashMap<
        service::ConnectionId,
        async_channel::Sender<service::CoordinatorToConnection<TPlat::Instant>>,
        fnv::FnvBuildHasher,
    >,

    blocks_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<Result<Vec<protocol::BlockData>, BlocksRequestError>>,
        fnv::FnvBuildHasher,
    >,

    grandpa_warp_sync_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<
            Result<service::EncodedGrandpaWarpSyncResponse, GrandpaWarpSyncRequestError>,
        >,
        fnv::FnvBuildHasher,
    >,

    storage_proof_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<Result<service::EncodedMerkleProof, StorageProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    call_proof_requests: HashMap<
        service::OutRequestId,
        oneshot::Sender<Result<service::EncodedMerkleProof, CallProofRequestError>>,
        fnv::FnvBuildHasher,
    >,

    kademlia_discovery_operations:
        HashMap<service::KademliaOperationId, usize, fnv::FnvBuildHasher>,
}

async fn background_task<TPlat: PlatformRef>(mut task: BackgroundTask<TPlat>) {
    loop {
        // TODO: this is hacky; instead, should be cleaned up as a response to an event from the service; no such event exists yet
        task.active_connections.retain(|_, tx| !tx.is_closed());

        // TODO: handle differently
        // TODO: doc
        for chain_index in 0..task.log_chain_names.len() {
            let now = task.platform.now();

            // Clean up the content of `slots_assign_backoff`.
            // TODO: the background task should be woken up when the ban expires
            // TODO: O(n)
            task.slots_assign_backoff
                .retain(|_, expiration| *expiration > now);

            loop {
                let peer_id = task
                    .network
                    .slots_to_assign(chain_index)
                    .find(|peer_id| {
                        !task
                            .slots_assign_backoff
                            .contains_key(&((**peer_id).clone(), chain_index)) // TODO: spurious cloning
                    })
                    .cloned();

                let Some(peer_id) = peer_id else { break };
                log::debug!(
                    target: "connections",
                    "OutSlots({}) ∋ {}",
                    &task.log_chain_names[chain_index],
                    peer_id
                );
                task.network.assign_out_slot(chain_index, peer_id);
            }
        }

        enum WhatHappened<TPlat: PlatformRef> {
            Message(ToBackground<TPlat>),
            NetworkEvent(service::Event),
            StartConnect(service::StartConnect<TPlat::Instant>),
            MessageToConnection {
                connection_id: service::ConnectionId,
                message: service::CoordinatorToConnection<TPlat::Instant>,
            },
            EventSendersReady,
        }

        let what_happened = {
            let message_received =
                async { WhatHappened::Message(task.messages_rx.next().await.unwrap()) };
            let can_generate_event = matches!(task.event_senders, either::Left(_));
            let service_event = async {
                if let (true, Some(event)) = (
                    can_generate_event,
                    task.network.next_event(task.platform.now()),
                ) {
                    WhatHappened::NetworkEvent(event)
                } else if let Some(start_connect) =
                    task.network.next_start_connect(|| task.platform.now())
                {
                    WhatHappened::StartConnect(start_connect)
                } else if let Some((connection_id, message)) =
                    task.network.pull_message_to_connection()
                {
                    WhatHappened::MessageToConnection {
                        connection_id,
                        message,
                    }
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
            WhatHappened::Message(ToBackground::ConnectionAttemptOkSingleStream {
                pending_id,
                connection,
                expected_peer_id,
                multiaddr,
                handshake_kind,
            }) => {
                let (connection_id, connection_task) = task
                    .network
                    .pending_outcome_ok_single_stream(pending_id, handshake_kind);
                log::debug!(
                    target: "connections",
                    "Pending({:?}, {}) => Connection through {}",
                    pending_id,
                    expected_peer_id,
                    multiaddr
                );

                let (coordinator_to_connection_tx, coordinator_to_connection_rx) =
                    async_channel::bounded(8);
                let _prev_value = task
                    .active_connections
                    .insert(connection_id, coordinator_to_connection_tx);
                debug_assert!(_prev_value.is_none());

                //TODO: task name
                task.platform.spawn_task(
                    "".into(),
                    tasks::single_stream_connection_task::<TPlat>(
                        connection,
                        task.platform.clone(),
                        connection_id,
                        connection_task,
                        coordinator_to_connection_rx,
                        task.messages_tx.clone(),
                    ),
                );

                continue;
            }
            WhatHappened::Message(ToBackground::ConnectionAttemptOkMultiStream {
                pending_id,
                connection,
                expected_peer_id,
                multiaddr,
                handshake_kind,
            }) => {
                let (connection_id, connection_task) = task
                    .network
                    .pending_outcome_ok_multi_stream(pending_id, handshake_kind);
                log::debug!(
                    target: "connections",
                    "Pending({:?}, {}) => Connection through {}",
                    pending_id,
                    expected_peer_id,
                    multiaddr
                );

                let (coordinator_to_connection_tx, coordinator_to_connection_rx) =
                    async_channel::bounded(8);
                let _prev_value = task
                    .active_connections
                    .insert(connection_id, coordinator_to_connection_tx);
                debug_assert!(_prev_value.is_none());

                //TODO: task name
                task.platform.spawn_task(
                    "".into(),
                    tasks::webrtc_multi_stream_connection_task::<TPlat>(
                        connection,
                        task.platform.clone(),
                        connection_id,
                        connection_task,
                        coordinator_to_connection_rx,
                        task.messages_tx.clone(),
                    ),
                );

                continue;
            }
            WhatHappened::Message(ToBackground::ConnectionAttemptErr {
                pending_id,
                expected_peer_id,
                is_bad_addr,
            }) => {
                task.network.pending_outcome_err(pending_id, is_bad_addr);
                for chain_index in 0..task.network.num_chains() {
                    task.unassign_slot_and_ban(chain_index, expected_peer_id.clone());
                }
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
                chain_index,
                config,
                timeout,
                result,
            }) => {
                // The call to `start_blocks_request` below panics if we have no active connection.
                if !task.network.can_start_requests(&target) {
                    let _ = result.send(Err(BlocksRequestError::NoConnection));
                    continue;
                }

                match &config.start {
                    protocol::BlocksRequestConfigStart::Hash(hash) => {
                        log::debug!(
                            target: "network",
                            "Connection({}) <= BlocksRequest(chain={}, start={}, num={}, descending={:?}, header={:?}, body={:?}, justifications={:?})",
                            target, task.log_chain_names[chain_index], HashDisplay(hash),
                            config.desired_count.get(),
                            matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                            config.fields.header, config.fields.body, config.fields.justifications
                        );
                    }
                    protocol::BlocksRequestConfigStart::Number(number) => {
                        log::debug!(
                            target: "network",
                            "Connection({}) <= BlocksRequest(chain={}, start=#{}, num={}, descending={:?}, header={:?}, body={:?}, justifications={:?})",
                            target, task.log_chain_names[chain_index], number,
                            config.desired_count.get(),
                            matches!(config.direction, protocol::BlocksRequestDirection::Descending),
                            config.fields.header, config.fields.body, config.fields.justifications
                        );
                    }
                }

                let request_id = task.network.start_blocks_request(
                    task.platform.now(),
                    &target,
                    chain_index,
                    config,
                    timeout,
                );

                task.blocks_requests.insert(request_id, result);
                continue;
            }
            WhatHappened::Message(ToBackground::StartGrandpaWarpSyncRequest {
                target,
                chain_index,
                begin_hash,
                timeout,
                result,
            }) => {
                // The call to `start_grandpa_warp_sync_request` below panics if we have no
                // active connection.
                if !task.network.can_start_requests(&target) {
                    let _ = result.send(Err(GrandpaWarpSyncRequestError::NoConnection));
                    continue;
                }

                log::debug!(
                    target: "network", "Connection({}) <= GrandpaWarpSyncRequest(chain={}, start={})",
                    target, task.log_chain_names[chain_index], HashDisplay(&begin_hash)
                );

                let request_id = task.network.start_grandpa_warp_sync_request(
                    task.platform.now(),
                    &target,
                    chain_index,
                    begin_hash,
                    timeout,
                );

                task.grandpa_warp_sync_requests.insert(request_id, result);
                continue;
            }
            WhatHappened::Message(ToBackground::StartStorageProofRequest {
                chain_index,
                target,
                config,
                timeout,
                result,
            }) => {
                // The call to `start_storage_proof_request` below panics if we have no active
                // connection.
                if !task.network.can_start_requests(&target) {
                    let _ = result.send(Err(StorageProofRequestError::NoConnection));
                    continue;
                }

                log::debug!(
                    target: "network",
                    "Connection({}) <= StorageProofRequest(chain={}, block={})",
                    target,
                    task.log_chain_names[chain_index],
                    HashDisplay(&config.block_hash)
                );

                let request_id = match task.network.start_storage_proof_request(
                    task.platform.now(),
                    &target,
                    chain_index,
                    config,
                    timeout,
                ) {
                    Ok(r) => r,
                    Err(service::StartRequestError::RequestTooLarge) => {
                        // TODO: consider dealing with the problem of requests too large internally by sending multiple requests
                        let _ = result.send(Err(StorageProofRequestError::RequestTooLarge));
                        continue;
                    }
                };

                task.storage_proof_requests.insert(request_id, result);
                continue;
            }
            WhatHappened::Message(ToBackground::StartCallProofRequest {
                chain_index,
                target,
                config,
                timeout,
                result,
            }) => {
                // The call to `start_call_proof_request` below panics if we have no active connection.
                if !task.network.can_start_requests(&target) {
                    let _ = result.send(Err(CallProofRequestError::NoConnection));
                    continue;
                }

                log::debug!(
                    target: "network",
                    "Connection({}) <= CallProofRequest({}, {}, {})",
                    target,
                    task.log_chain_names[chain_index],
                    HashDisplay(&config.block_hash),
                    config.method
                );

                let request_id = match task.network.start_call_proof_request(
                    task.platform.now(),
                    &target,
                    chain_index,
                    config,
                    timeout,
                ) {
                    Ok(r) => r,
                    Err(service::StartRequestError::RequestTooLarge) => {
                        let _ = result.send(Err(CallProofRequestError::RequestTooLarge));
                        continue;
                    }
                };

                task.call_proof_requests.insert(request_id, result);
                continue;
            }
            WhatHappened::Message(ToBackground::SetLocalBestBlock {
                chain_index,
                best_hash,
                best_number,
            }) => {
                task.network
                    .set_local_best_block(chain_index, best_hash, best_number);
                continue;
            }
            WhatHappened::Message(ToBackground::SetLocalGrandpaState {
                chain_index,
                grandpa_state,
            }) => {
                log::debug!(
                    target: "network",
                    "Chain({}) <= SetLocalGrandpaState(set_id: {}, commit_finalized_height: {})",
                    task.log_chain_names[chain_index],
                    grandpa_state.set_id,
                    grandpa_state.commit_finalized_height,
                );

                // TODO: log the list of peers we sent the packet to

                task.network
                    .set_local_grandpa_state(chain_index, grandpa_state);
                continue;
            }
            WhatHappened::Message(ToBackground::AnnounceTransaction {
                chain_index,
                transaction,
                result,
            }) => {
                let mut sent_peers = Vec::with_capacity(16); // TODO: capacity?

                // TODO: keep track of which peer knows about which transaction, and don't send it again

                // TODO: collecting in a Vec :-/
                for peer in task
                    .network
                    .opened_transactions_substream(chain_index)
                    .cloned()
                    .collect::<Vec<_>>()
                {
                    if task
                        .network
                        .announce_transaction(&peer, chain_index, &transaction)
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
                chain_index,
                scale_encoded_header,
                is_best,
                result,
            }) => {
                // The call to `send_block_announce` below panics if we have no active substream.
                if !task.network.can_send_block_announces(&target, chain_index) {
                    let _ = result.send(Err(QueueNotificationError::NoConnection));
                    continue;
                }

                let res = task
                    .network
                    .send_block_announce(&target, chain_index, &scale_encoded_header, is_best)
                    .map_err(QueueNotificationError::Queue);

                let _ = result.send(res);
                continue;
            }
            WhatHappened::Message(ToBackground::Discover {
                now,
                chain_index,
                list,
                important_nodes,
            }) => {
                for (peer_id, addrs) in list {
                    if important_nodes {
                        task.important_nodes.insert(peer_id.clone());
                    }

                    task.network.discover(&now, chain_index, peer_id, addrs);
                }

                continue;
            }
            WhatHappened::Message(ToBackground::DiscoveredNodes {
                chain_index,
                result,
            }) => {
                let _ = result.send(
                    task.network
                        .discovered_nodes(chain_index)
                        .map(|(peer_id, addresses)| {
                            (peer_id.clone(), addresses.cloned().collect::<Vec<_>>())
                        })
                        .collect::<Vec<_>>(),
                );

                continue;
            }
            WhatHappened::Message(ToBackground::PeersList { result }) => {
                let _ = result.send(task.network.peers_list().cloned().collect::<Vec<_>>());
                continue;
            }
            WhatHappened::Message(ToBackground::StartDiscovery) => {
                for chain_index in 0..task.log_chain_names.len() {
                    let operation_id = task
                        .network
                        .start_kademlia_discovery_round(task.platform.now(), chain_index);

                    let _prev_value = task
                        .kademlia_discovery_operations
                        .insert(operation_id, chain_index);
                    debug_assert!(_prev_value.is_none());
                }

                continue;
            }
            WhatHappened::NetworkEvent(service::Event::Connected(peer_id)) => {
                log::debug!(target: "network", "Connected({})", peer_id);
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::Disconnected {
                peer_id,
                chain_indices,
            }) => {
                log::debug!(target: "network", "Disconnected({})", peer_id);
                if !chain_indices.is_empty() {
                    // TODO: properly implement when multiple chains
                    if chain_indices.len() == 1 {
                        log::debug!(
                            target: "network",
                            "Connection({}, {}) => ChainDisconnected",
                            peer_id,
                            &task.log_chain_names[chain_indices[0]],
                        );

                        Event::Disconnected {
                            peer_id,
                            chain_index: chain_indices[0],
                        }
                    } else {
                        todo!()
                    }
                } else {
                    continue;
                }
            }
            WhatHappened::NetworkEvent(service::Event::BlockAnnounce {
                chain_index,
                peer_id,
                announce,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => BlockAnnounce(best_hash={}, is_best={})",
                    peer_id,
                    &task.log_chain_names[chain_index],
                    HashDisplay(&header::hash_from_scale_encoded_header(announce.decode().scale_encoded_header)),
                    announce.decode().is_best
                );
                Event::BlockAnnounce {
                    chain_index,
                    peer_id,
                    announce,
                }
            }
            WhatHappened::NetworkEvent(service::Event::ChainConnected {
                peer_id,
                chain_index,
                role,
                best_number,
                best_hash,
                slot_ty: _,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => ChainConnected(best_height={}, best_hash={})",
                    peer_id,
                    &task.log_chain_names[chain_index],
                    best_number,
                    HashDisplay(&best_hash)
                );
                Event::Connected {
                    peer_id,
                    chain_index,
                    role,
                    best_block_number: best_number,
                    best_block_hash: best_hash,
                }
            }
            WhatHappened::NetworkEvent(service::Event::ChainConnectAttemptFailed {
                peer_id,
                chain_index,
                unassigned_slot_ty,
                error,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => ChainConnectAttemptFailed(error={:?})",
                    &task.log_chain_names[chain_index],
                    peer_id, error,
                );
                log::debug!(
                    target: "connections",
                    "{}Slots({}) ∌ {}",
                    match unassigned_slot_ty {
                        service::SlotTy::Inbound => "In",
                        service::SlotTy::Outbound => "Out",
                    },
                    &task.log_chain_names[chain_index],
                    peer_id
                );
                task.unassign_slot_and_ban(chain_index, peer_id);
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::ChainDisconnected {
                peer_id,
                chain_index,
                unassigned_slot_ty,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => ChainDisconnected",
                    peer_id,
                    &task.log_chain_names[chain_index],
                );
                log::debug!(
                    target: "connections",
                    "{}Slots({}) ∌ {}",
                    match unassigned_slot_ty {
                        service::SlotTy::Inbound => "In",
                        service::SlotTy::Outbound => "Out",
                    },
                    &task.log_chain_names[chain_index],
                    peer_id
                );
                task.unassign_slot_and_ban(chain_index, peer_id.clone());
                Event::Disconnected {
                    peer_id,
                    chain_index,
                }
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                request_id,
                response: service::RequestResult::Blocks(response),
            }) => {
                let _ = task
                    .blocks_requests
                    .remove(&request_id)
                    .unwrap()
                    .send(response.map_err(BlocksRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                request_id,
                response: service::RequestResult::GrandpaWarpSync(response),
            }) => {
                let _ = task
                    .grandpa_warp_sync_requests
                    .remove(&request_id)
                    .unwrap()
                    .send(response.map_err(GrandpaWarpSyncRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                request_id,
                response: service::RequestResult::StorageProof(response),
            }) => {
                let _ = task
                    .storage_proof_requests
                    .remove(&request_id)
                    .unwrap()
                    .send(response.map_err(StorageProofRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult {
                request_id,
                response: service::RequestResult::CallProof(response),
            }) => {
                let _ = task
                    .call_proof_requests
                    .remove(&request_id)
                    .unwrap()
                    .send(response.map_err(CallProofRequestError::Request));
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::RequestResult { .. }) => {
                // We never start any other kind of requests.
                unreachable!()
            }
            WhatHappened::NetworkEvent(service::Event::KademliaDiscoveryResult {
                operation_id,
                result,
            }) => {
                let chain_index = task
                    .kademlia_discovery_operations
                    .remove(&operation_id)
                    .unwrap();
                match result {
                    Ok(nodes) => {
                        log::debug!(
                            target: "connections", "On chain {}, discovered: {}",
                            &task.log_chain_names[chain_index],
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

                            task.network.discover(
                                &task.platform.now(),
                                chain_index,
                                peer_id,
                                valid_addrs,
                            );
                        }
                    }
                    Err(error) => {
                        log::debug!(
                            target: "connections",
                            "Discovery => {:?}",
                            error
                        );

                        // No error is printed if the error is about the fact that we have
                        // 0 peers, as this tends to happen quite frequently at initialization
                        // and there is nothing that can be done against this error anyway.
                        // No error is printed either if the request fails due to a benign
                        // networking error such as an unresponsive peer.
                        match error {
                            service::DiscoveryError::NoPeer => {}
                            service::DiscoveryError::FindNode(
                                service::KademliaFindNodeError::RequestFailed(err),
                            ) if !err.is_protocol_error() => {}
                            service::DiscoveryError::FindNode(
                                service::KademliaFindNodeError::RequestFailed(
                                    peers::RequestError::Substream(
                                        connection::established::RequestError::ProtocolNotAvailable,
                                    ),
                                ),
                            ) => {
                                // TODO: remove this warning in a long time
                                log::warn!(
                                    target: "connections",
                                    "Problem during discovery on {}: protocol not available. \
                                    This might indicate that the version of Substrate used by \
                                    the chain doesn't include \
                                    <https://github.com/paritytech/substrate/pull/12545>.",
                                    &task.log_chain_names[chain_index]
                                );
                            }
                            _ => {
                                log::warn!(
                                    target: "connections",
                                    "Problem during discovery on {}: {}",
                                    &task.log_chain_names[chain_index],
                                    error
                                );
                            }
                        }
                    }
                }

                continue;
            }
            WhatHappened::NetworkEvent(service::Event::InboundSlotAssigned {
                peer_id,
                chain_index,
            }) => {
                log::debug!(
                    target: "connections",
                    "InSlots({}) ∋ {}",
                    &task.log_chain_names[chain_index],
                    peer_id
                );
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::IdentifyRequestIn {
                peer_id,
                request_id,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}) => IdentifyRequest",
                    peer_id,
                );
                task.network
                    .respond_identify(request_id, &task.identify_agent_version);
                continue;
            }
            WhatHappened::NetworkEvent(service::Event::BlocksRequestIn { .. }) => unreachable!(),
            WhatHappened::NetworkEvent(service::Event::RequestInCancel { .. }) => {
                // All incoming requests are immediately answered.
                unreachable!()
            }
            WhatHappened::NetworkEvent(service::Event::GrandpaNeighborPacket {
                chain_index,
                peer_id,
                state,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => GrandpaNeighborPacket(round_number={}, set_id={}, commit_finalized_height={})",
                    peer_id,
                    &task.log_chain_names[chain_index],
                    state.round_number,
                    state.set_id,
                    state.commit_finalized_height,
                );
                Event::GrandpaNeighborPacket {
                    chain_index,
                    peer_id,
                    finalized_block_height: state.commit_finalized_height,
                }
            }
            WhatHappened::NetworkEvent(service::Event::GrandpaCommitMessage {
                chain_index,
                peer_id,
                message,
            }) => {
                log::debug!(
                    target: "network",
                    "Connection({}, {}) => GrandpaCommitMessage(target_block_hash={})",
                    peer_id,
                    &task.log_chain_names[chain_index],
                    HashDisplay(message.decode().message.target_hash),
                );
                Event::GrandpaCommitMessage {
                    chain_index,
                    peer_id,
                    message,
                }
            }
            WhatHappened::NetworkEvent(service::Event::ProtocolError { peer_id, error }) => {
                // TODO: handle properly?
                log::warn!(
                    target: "network",
                    "Connection({}) => ProtocolError(error={:?})",
                    peer_id,
                    error,
                );

                for chain_index in 0..task.network.num_chains() {
                    task.unassign_slot_and_ban(chain_index, peer_id.clone());
                }
                continue;
            }
            WhatHappened::StartConnect(start_connect) => {
                // TODO: restore rate limiting
                let is_important = task
                    .important_nodes
                    .contains(&start_connect.expected_peer_id);

                let task_name = format!(
                    "connection-{}-{}",
                    start_connect.expected_peer_id, start_connect.multiaddr
                );

                // Perform the connection process in a separate task.
                let connect_task = tasks::connection_task(
                    start_connect,
                    task.platform.clone(),
                    task.messages_tx.clone(),
                    is_important,
                );

                // Sending the new task might fail in case a shutdown is happening, in which case
                // we don't really care about the state of anything anymore.
                // The sending here is normally very quick.
                task.platform
                    .spawn_task(task_name.into(), Box::pin(connect_task));
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

impl<TPlat: PlatformRef> BackgroundTask<TPlat> {
    fn unassign_slot_and_ban(&mut self, chain_index: usize, peer_id: PeerId) {
        self.network.unassign_slot(chain_index, &peer_id);

        let new_expiration = self.platform.now() + Duration::from_secs(20); // TODO: arbitrary constant
        match self.slots_assign_backoff.entry((peer_id, chain_index)) {
            hash_map::Entry::Occupied(e) if *e.get() < new_expiration => {
                *e.into_mut() = new_expiration;
            }
            hash_map::Entry::Occupied(_) => {}
            hash_map::Entry::Vacant(e) => {
                e.insert(new_expiration);
            }
        }
    }
}
