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

use crate::util::{leb128, protobuf};

use super::{
    super::{
        connection::{established, noise},
        read_write::ReadWrite,
    },
    ConnectionToCoordinator, ConnectionToCoordinatorInner, CoordinatorToConnection,
    CoordinatorToConnectionInner, InboundTy, NotificationsOutErr, PeerId, ShutdownCause,
    SubstreamFate, SubstreamId,
};

use alloc::{collections::VecDeque, string::ToString as _, sync::Arc, vec::Vec};
use core::{
    cmp,
    hash::Hash,
    ops::{Add, Sub},
    time::Duration,
};

/// State machine dedicated to a single multi-stream connection.
pub struct MultiStreamConnectionTask<TNow, TSubId> {
    connection: MultiStreamConnectionTaskInner<TNow, TSubId>,
}
enum MultiStreamConnectionTaskInner<TNow, TSubId> {
    /// Connection is still in its handshake phase.
    Handshake {
        /// Substream that has been opened to perform the handshake, if any.
        opened_substream: Option<TSubId>,

        /// Noise handshake in progress. Always `Some`, except to be temporarily extracted.
        handshake: Option<noise::HandshakeInProgress>,

        /// All incoming data for the handshake substream is first transferred to this buffer.
        // TODO: this is very suboptimal code, instead the parsing should be done in a streaming way
        handshake_read_buffer: Vec<u8>,

        handshake_read_buffer_partial_read: usize,

        /// Other substreams, besides [`MultiStreamConnectionTaskInner::Handshake::opened_substream`],
        /// that have been opened. For each substream, contains a boolean indicating whether the
        /// substream is outbound (`true`) or inbound (`false`).
        ///
        /// Due to the asynchronous nature of the protocol, it is not a logic error to open
        /// additional substreams before the handshake has finished. The remote might think that
        /// the handshake has finished while the local node hasn't finished processing it yet.
        ///
        /// These substreams aren't processed as long as the handshake hasn't finished. It is,
        /// however, important to remember that substreams have been opened.
        extra_open_substreams: hashbrown::HashMap<TSubId, bool, fnv::FnvBuildHasher>,

        /// State machine used once the connection has been established. Unused during the
        /// handshake, but created ahead of time. Always `Some`, except to be temporarily
        /// extracted.
        established:
            Option<established::MultiStream<TNow, TSubId, either::Either<SubstreamId, usize>>>,
    },

    /// Connection has been fully established.
    Established {
        established: established::MultiStream<TNow, TSubId, either::Either<SubstreamId, usize>>,

        /// If `Some`, contains the substream that was used for the handshake. This substream
        /// is meant to be closed as soon as possible.
        handshake_substream: Option<TSubId>,

        /// If `Some`, then no `HandshakeFinished` message has been sent back yet.
        handshake_finished_message_to_send: Option<PeerId>,

        /// Because outgoing substream ids are assigned by the coordinator, we maintain a mapping
        /// of the "outer ids" to "inner ids".
        outbound_substreams_map:
            hashbrown::HashMap<SubstreamId, established::SubstreamId, fnv::FnvBuildHasher>,

        /// After a [`ConnectionToCoordinatorInner::NotificationsInOpenCancel`] is emitted, an
        /// entry is added to this list. If the coordinator accepts or refuses a substream in this
        /// list, the acceptance/refusal is dismissed.
        notifications_in_open_cancel_acknowledgments: VecDeque<established::SubstreamId>,

        /// After a `NotificationsInOpenCancel` is emitted by the connection, an
        /// entry is added to this list. If the coordinator accepts or refuses a substream in this
        /// list, the acceptance/refusal is dismissed.
        // TODO: this works only because SubstreamIds aren't reused
        inbound_negotiated_cancel_acknowledgments:
            hashbrown::HashSet<established::SubstreamId, fnv::FnvBuildHasher>,

        /// Messages about inbound accept cancellations to send back.
        inbound_accept_cancel_events: VecDeque<established::SubstreamId>,
    },

    /// Connection has finished its shutdown. A [`ConnectionToCoordinatorInner::ShutdownFinished`]
    /// message has been sent and is waiting to be acknowledged.
    ShutdownWaitingAck {
        /// What has initiated the shutdown.
        initiator: ShutdownInitiator,

        /// `None` if the [`ConnectionToCoordinatorInner::StartShutdown`] message has already
        /// been sent to the coordinator. `Some` if the message hasn't been sent yet.
        start_shutdown_message_to_send: Option<Option<ShutdownCause>>,

        /// `true` if the [`ConnectionToCoordinatorInner::ShutdownFinished`] message has already
        /// been sent to the coordinator.
        shutdown_finish_message_sent: bool,
    },

    /// Connection has finished its shutdown and its shutdown has been acknowledged. There is
    /// nothing more to do except stop the connection task.
    ShutdownAcked {
        /// What has initiated the shutdown.
        initiator: ShutdownInitiator,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ShutdownInitiator {
    /// The coordinator sent a [`CoordinatorToConnectionInner::StartShutdown`] message.
    Coordinator,
    /// [`MultiStreamConnectionTask::reset`] has been called.
    Api,
}

impl<TNow, TSubId> MultiStreamConnectionTask<TNow, TSubId>
where
    TNow: Clone + Add<Duration, Output = TNow> + Sub<TNow, Output = Duration> + Ord,
    TSubId: Clone + PartialEq + Eq + Hash,
{
    // Note that the parameters of this function are a bit rough and undocumented, as this is
    // a function only called from the parent module.
    pub(super) fn new(
        randomness_seed: [u8; 32],
        now: TNow,
        handshake: noise::HandshakeInProgress,
        max_inbound_substreams: usize,
        substreams_capacity: usize,
        max_protocol_name_len: usize,
        ping_protocol: Arc<str>,
    ) -> Self {
        MultiStreamConnectionTask {
            connection: MultiStreamConnectionTaskInner::Handshake {
                handshake: Some(handshake),
                opened_substream: None,
                handshake_read_buffer: Vec::new(),
                handshake_read_buffer_partial_read: 0,
                extra_open_substreams: hashbrown::HashMap::with_capacity_and_hasher(
                    0,
                    Default::default(),
                ),
                established: Some(established::MultiStream::webrtc(established::Config {
                    max_inbound_substreams,
                    substreams_capacity,
                    max_protocol_name_len,
                    randomness_seed,
                    ping_protocol: ping_protocol.to_string(), // TODO: cloning :-/
                    ping_interval: Duration::from_secs(20),   // TODO: hardcoded
                    ping_timeout: Duration::from_secs(10),    // TODO: hardcoded
                    first_out_ping: now + Duration::from_secs(2), // TODO: hardcoded
                })),
            },
        }
    }

    /// Pulls a message to send back to the coordinator.
    ///
    /// This function takes ownership of `self` and optionally yields it back. If the first
    /// option contains `None`, then no more message will be generated and the
    /// [`MultiStreamConnectionTask`] has vanished. This will happen after the connection has been
    /// shut down or reset.
    /// It is possible for `self` to not be yielded back even if substreams are still open, in
    /// which case the API user should abruptly reset the connection, for example by sending a
    /// TCP RST flag.
    ///
    /// If any message is returned, it is the responsibility of the API user to send it to the
    /// coordinator.
    /// Do not attempt to buffer the message being returned, as it would work against the
    /// back-pressure strategy used internally. As soon as a message is returned, it should be
    /// delivered. If the coordinator is busy at the moment a message should be delivered, then
    /// the entire thread of execution dedicated to this [`MultiStreamConnectionTask`] should be
    /// paused until the coordinator is ready and the message delivered.
    ///
    /// Messages aren't generated spontaneously. In other words, you don't need to periodically
    /// call this function just in case there's a new message. Messages are always generated after
    /// [`MultiStreamConnectionTask::substream_read_write`],
    /// [`MultiStreamConnectionTask::add_substream`], or [`MultiStreamConnectionTask::reset`]
    /// has been called. Multiple messages can happen in a row.
    ///
    /// Because this function frees space in a buffer, processing substreams again after it
    /// has returned might read/write more data and generate an event again. In other words,
    /// the API user should call [`MultiStreamConnectionTask::substream_read_write`] and
    /// [`MultiStreamConnectionTask::pull_message_to_coordinator`] repeatedly in a loop until no
    /// more message is generated.
    pub fn pull_message_to_coordinator(
        mut self,
    ) -> (Option<Self>, Option<ConnectionToCoordinator>) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Handshake { .. } => (Some(self), None),
            MultiStreamConnectionTaskInner::Established {
                established,
                outbound_substreams_map,
                handshake_finished_message_to_send,
                notifications_in_open_cancel_acknowledgments,
                inbound_negotiated_cancel_acknowledgments,
                inbound_accept_cancel_events,
                ..
            } => {
                if let Some(remote_peer_id) = handshake_finished_message_to_send.take() {
                    return (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::HandshakeFinished(remote_peer_id),
                        }),
                    );
                }

                if let Some(substream_id) = inbound_accept_cancel_events.pop_front() {
                    return (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::InboundAcceptedCancel {
                                _id: substream_id,
                            },
                        }),
                    );
                }

                let event = match established.pull_event() {
                    Some(established::Event::NewOutboundSubstreamsForbidden) => {
                        // TODO: handle properly
                        self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                            start_shutdown_message_to_send: Some(None),
                            shutdown_finish_message_sent: false,
                            initiator: ShutdownInitiator::Coordinator,
                        };
                        Some(ConnectionToCoordinatorInner::StartShutdown(None))
                    }
                    Some(established::Event::InboundError(err)) => {
                        Some(ConnectionToCoordinatorInner::InboundError(err))
                    }
                    Some(established::Event::InboundNegotiated { id, protocol_name }) => {
                        Some(ConnectionToCoordinatorInner::InboundNegotiated { id, protocol_name })
                    }
                    Some(established::Event::InboundNegotiatedCancel { id, .. }) => {
                        inbound_negotiated_cancel_acknowledgments.insert(id);
                        None
                    }
                    Some(established::Event::InboundAcceptedCancel { id, .. }) => {
                        Some(ConnectionToCoordinatorInner::InboundAcceptedCancel { _id: id })
                    }
                    Some(established::Event::RequestIn { id, request, .. }) => {
                        let either::Right(protocol_index) = established[id] else {
                            panic!()
                        };
                        Some(ConnectionToCoordinatorInner::RequestIn {
                            id,
                            protocol_index,
                            request,
                        })
                    }
                    Some(established::Event::Response {
                        response,
                        user_data,
                        ..
                    }) => {
                        let either::Left(outer_substream_id) = user_data else {
                            panic!()
                        };
                        outbound_substreams_map.remove(&outer_substream_id).unwrap();
                        Some(ConnectionToCoordinatorInner::Response {
                            response,
                            id: outer_substream_id,
                        })
                    }
                    Some(established::Event::NotificationsInOpen { id, handshake, .. }) => {
                        let either::Right(protocol_index) = established[id] else {
                            panic!()
                        };
                        Some(ConnectionToCoordinatorInner::NotificationsInOpen {
                            id,
                            protocol_index,
                            handshake,
                        })
                    }
                    Some(established::Event::NotificationsInOpenCancel { id, .. }) => {
                        notifications_in_open_cancel_acknowledgments.push_back(id);
                        Some(ConnectionToCoordinatorInner::NotificationsInOpenCancel { id })
                    }
                    Some(established::Event::NotificationIn { id, notification }) => {
                        Some(ConnectionToCoordinatorInner::NotificationIn { id, notification })
                    }
                    Some(established::Event::NotificationsInClose { id, outcome, .. }) => {
                        Some(ConnectionToCoordinatorInner::NotificationsInClose { id, outcome })
                    }
                    Some(established::Event::NotificationsOutResult { id, result }) => {
                        let (outer_substream_id, result) = match result {
                            Ok(r) => {
                                let either::Left(outer_substream_id) = established[id] else {
                                    panic!()
                                };
                                (outer_substream_id, Ok(r))
                            }
                            Err((err, ud)) => {
                                let either::Left(outer_substream_id) = ud else {
                                    panic!()
                                };
                                outbound_substreams_map.remove(&outer_substream_id);
                                (outer_substream_id, Err(NotificationsOutErr::Substream(err)))
                            }
                        };

                        Some(ConnectionToCoordinatorInner::NotificationsOutResult {
                            id: outer_substream_id,
                            result,
                        })
                    }
                    Some(established::Event::NotificationsOutCloseDemanded { id }) => {
                        let either::Left(outer_substream_id) = established[id] else {
                            panic!()
                        };
                        Some(
                            ConnectionToCoordinatorInner::NotificationsOutCloseDemanded {
                                id: outer_substream_id,
                            },
                        )
                    }
                    Some(established::Event::NotificationsOutReset { user_data, .. }) => {
                        let either::Left(outer_substream_id) = user_data else {
                            panic!()
                        };
                        outbound_substreams_map.remove(&outer_substream_id);
                        Some(ConnectionToCoordinatorInner::NotificationsOutReset {
                            id: outer_substream_id,
                        })
                    }
                    Some(established::Event::PingOutSuccess) => {
                        Some(ConnectionToCoordinatorInner::PingOutSuccess)
                    }
                    Some(established::Event::PingOutFailed) => {
                        Some(ConnectionToCoordinatorInner::PingOutFailed)
                    }
                    None => None,
                };

                (
                    Some(self),
                    event.map(|ev| ConnectionToCoordinator { inner: ev }),
                )
            }
            MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                start_shutdown_message_to_send,
                shutdown_finish_message_sent,
                ..
            } => {
                if let Some(reason) = start_shutdown_message_to_send.take() {
                    debug_assert!(!*shutdown_finish_message_sent);
                    (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::StartShutdown(reason),
                        }),
                    )
                } else if !*shutdown_finish_message_sent {
                    debug_assert!(start_shutdown_message_to_send.is_none());
                    *shutdown_finish_message_sent = true;
                    (
                        Some(self),
                        Some(ConnectionToCoordinator {
                            inner: ConnectionToCoordinatorInner::ShutdownFinished,
                        }),
                    )
                } else {
                    (Some(self), None)
                }
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. } => (None, None),
        }
    }

    /// Injects a message that has been pulled from the coordinator.
    ///
    /// Calling this function might generate data to send to the connection. You should call
    /// [`MultiStreamConnectionTask::desired_outbound_substreams`] and
    /// [`MultiStreamConnectionTask::substream_read_write`] after this function has returned.
    pub fn inject_coordinator_message(&mut self, message: CoordinatorToConnection<TNow>) {
        match (message.inner, &mut self.connection) {
            (
                CoordinatorToConnectionInner::AcceptInbound {
                    substream_id,
                    inbound_ty,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    inbound_negotiated_cancel_acknowledgments,
                    inbound_accept_cancel_events,
                    ..
                },
            ) => {
                let (inbound_ty, protocol_index) = match inbound_ty {
                    InboundTy::Notifications {
                        protocol_index,
                        max_handshake_size,
                    } => (
                        established::InboundTy::Notifications { max_handshake_size },
                        protocol_index,
                    ),
                    InboundTy::Request {
                        protocol_index,
                        request_max_size,
                    } => (
                        established::InboundTy::Request { request_max_size },
                        protocol_index,
                    ),
                    InboundTy::Ping => (established::InboundTy::Ping, 0),
                };

                if !inbound_negotiated_cancel_acknowledgments.remove(&substream_id) {
                    established.accept_inbound(
                        substream_id,
                        inbound_ty,
                        either::Right(protocol_index),
                    );
                } else {
                    inbound_accept_cancel_events.push_back(substream_id)
                }
            }
            (
                CoordinatorToConnectionInner::RejectInbound { substream_id },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    inbound_negotiated_cancel_acknowledgments,
                    ..
                },
            ) => {
                if !inbound_negotiated_cancel_acknowledgments.remove(&substream_id) {
                    established.reject_inbound(substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::StartRequest {
                    protocol_name,
                    request_data,
                    timeout,
                    max_response_size,
                    substream_id,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                let inner_substream_id = established.add_request(
                    protocol_name,
                    request_data,
                    timeout,
                    max_response_size,
                    either::Left(substream_id),
                );
                let _prev_value = outbound_substreams_map.insert(substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::OpenOutNotifications {
                    max_handshake_size,
                    protocol_name,
                    handshake,
                    now,
                    substream_id: outer_substream_id,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                let inner_substream_id = established.open_notifications_substream(
                    protocol_name,
                    max_handshake_size,
                    handshake,
                    now + Duration::from_secs(20), // TODO: make configurable
                    either::Left(outer_substream_id),
                );

                let _prev_value =
                    outbound_substreams_map.insert(outer_substream_id, inner_substream_id);
                debug_assert!(_prev_value.is_none());
            }
            (
                CoordinatorToConnectionInner::CloseOutNotifications { substream_id },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound notification substream
                // while the `CloseOutNotifications` message was being delivered, or that the API
                // user close the substream before the message about the substream being closed
                // was delivered to the coordinator.
                if let Some(inner_substream_id) = outbound_substreams_map.remove(&substream_id) {
                    established.close_notifications_substream(inner_substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::QueueNotification {
                    substream_id,
                    notification,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    outbound_substreams_map,
                    ..
                },
            ) => {
                // It is possible that the remote has closed the outbound notification substream
                // while a `QueueNotification` message was being delivered, or that the API user
                // queued a notification before the message about the substream being closed was
                // delivered to the coordinator.
                // If that happens, we intentionally silently discard the message, causing the
                // notification to not be sent. This is consistent with the guarantees about
                // notifications delivered that are documented in the public API.
                if let Some(inner_substream_id) = outbound_substreams_map.get(&substream_id) {
                    established.write_notification_unbounded(*inner_substream_id, notification);
                }
            }
            (
                CoordinatorToConnectionInner::AnswerRequest {
                    substream_id,
                    response,
                },
                MultiStreamConnectionTaskInner::Established { established, .. },
            ) => match established.respond_in_request(substream_id, response) {
                Ok(()) => {}
                Err(established::RespondInRequestError::SubstreamClosed) => {
                    // As documented, answering an obsolete request is simply ignored.
                }
            },
            (
                CoordinatorToConnectionInner::AcceptInNotifications {
                    substream_id,
                    handshake,
                    max_notification_size,
                },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_open_cancel_acknowledgments,
                    ..
                },
            ) => {
                if let Some(idx) = notifications_in_open_cancel_acknowledgments
                    .iter()
                    .position(|s| *s == substream_id)
                {
                    notifications_in_open_cancel_acknowledgments.remove(idx);
                } else {
                    established.accept_in_notifications_substream(
                        substream_id,
                        handshake,
                        max_notification_size,
                    );
                }
            }
            (
                CoordinatorToConnectionInner::RejectInNotifications { substream_id },
                MultiStreamConnectionTaskInner::Established {
                    established,
                    notifications_in_open_cancel_acknowledgments,
                    ..
                },
            ) => {
                if let Some(idx) = notifications_in_open_cancel_acknowledgments
                    .iter()
                    .position(|s| *s == substream_id)
                {
                    notifications_in_open_cancel_acknowledgments.remove(idx);
                } else {
                    established.reject_in_notifications_substream(substream_id);
                }
            }
            (
                CoordinatorToConnectionInner::StartShutdown { .. },
                MultiStreamConnectionTaskInner::Handshake { .. }
                | MultiStreamConnectionTaskInner::Established { .. },
            ) => {
                // TODO: implement proper shutdown
                self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    start_shutdown_message_to_send: Some(None),
                    shutdown_finish_message_sent: false,
                    initiator: ShutdownInitiator::Coordinator,
                };
            }
            (
                CoordinatorToConnectionInner::AcceptInbound { .. }
                | CoordinatorToConnectionInner::RejectInbound { .. }
                | CoordinatorToConnectionInner::AcceptInNotifications { .. }
                | CoordinatorToConnectionInner::RejectInNotifications { .. }
                | CoordinatorToConnectionInner::StartRequest { .. }
                | CoordinatorToConnectionInner::AnswerRequest { .. }
                | CoordinatorToConnectionInner::OpenOutNotifications { .. }
                | CoordinatorToConnectionInner::CloseOutNotifications { .. }
                | CoordinatorToConnectionInner::QueueNotification { .. },
                MultiStreamConnectionTaskInner::Handshake { .. }
                | MultiStreamConnectionTaskInner::ShutdownAcked { .. },
            ) => unreachable!(),
            (
                CoordinatorToConnectionInner::AcceptInbound { .. }
                | CoordinatorToConnectionInner::RejectInbound { .. }
                | CoordinatorToConnectionInner::AcceptInNotifications { .. }
                | CoordinatorToConnectionInner::RejectInNotifications { .. }
                | CoordinatorToConnectionInner::StartRequest { .. }
                | CoordinatorToConnectionInner::AnswerRequest { .. }
                | CoordinatorToConnectionInner::OpenOutNotifications { .. }
                | CoordinatorToConnectionInner::CloseOutNotifications { .. }
                | CoordinatorToConnectionInner::QueueNotification { .. },
                MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. },
            )
            | (
                CoordinatorToConnectionInner::StartShutdown,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Api,
                    ..
                },
            ) => {
                // There might still be some messages coming from the coordinator after the
                // connection task has sent a message indicating that it has shut down. This is
                // due to the concurrent nature of the API and doesn't indicate a bug. These
                // messages are simply ignored by the connection task.
            }
            (
                CoordinatorToConnectionInner::ShutdownFinishedAck,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    start_shutdown_message_to_send: start_shutdown_message_sent,
                    shutdown_finish_message_sent,
                    initiator,
                },
            ) => {
                debug_assert!(
                    start_shutdown_message_sent.is_none() && *shutdown_finish_message_sent
                );
                self.connection = MultiStreamConnectionTaskInner::ShutdownAcked {
                    initiator: *initiator,
                };
            }
            (
                CoordinatorToConnectionInner::StartShutdown,
                MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Coordinator,
                    ..
                }
                | MultiStreamConnectionTaskInner::ShutdownAcked { .. },
            ) => unreachable!(),
            (CoordinatorToConnectionInner::ShutdownFinishedAck, _) => unreachable!(),
        }
    }

    /// Returns the number of new outbound substreams that the state machine would like to see
    /// opened.
    ///
    /// This value doesn't change automatically over time but only after a call to
    /// [`MultiStreamConnectionTask::substream_read_write`],
    /// [`MultiStreamConnectionTask::inject_coordinator_message`],
    /// [`MultiStreamConnectionTask::add_substream`], or
    /// [`MultiStreamConnectionTask::reset_substream`].
    ///
    /// Note that the user is expected to track the number of substreams that are currently being
    /// opened. For example, if this function returns 2 and there are already 2 substreams
    /// currently being opened, then there is no need to open any additional one.
    pub fn desired_outbound_substreams(&self) -> u32 {
        match &self.connection {
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream, ..
            } => {
                if opened_substream.is_none() {
                    1
                } else {
                    0
                }
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.desired_outbound_substreams()
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => 0,
        }
    }

    /// Notifies the state machine that a new substream has been opened.
    ///
    /// `outbound` indicates whether the substream has been opened by the remote (`false`) or
    /// locally (`true`).
    ///
    /// If `outbound` is `true`, then the value returned by
    /// [`MultiStreamConnectionTask::desired_outbound_substreams`] will decrease by one.
    ///
    /// # Panic
    ///
    /// Panics if there already exists a substream with an identical identifier.
    ///
    pub fn add_substream(&mut self, id: TSubId, outbound: bool) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream: ref mut opened_substream @ None,
                ..
            } if outbound => {
                *opened_substream = Some(id);
            }
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream,
                extra_open_substreams,
                ..
            } => {
                assert!(opened_substream.as_ref().map_or(true, |open| *open != id));
                // TODO: add a limit to the number allowed?
                let _was_in = extra_open_substreams.insert(id, outbound);
                assert!(_was_in.is_none());
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.add_substream(id, outbound)
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: reset the substream or something?
            }
        }
    }

    /// Sets the state of the connection to "reset".
    ///
    /// This should be called if the remote abruptly closes the connection, such as with a TCP/IP
    /// RST flag.
    ///
    /// After this function has been called, it is illegal to call
    /// [`MultiStreamConnectionTask::substream_read_write`] or
    /// [`MultiStreamConnectionTask::reset`] again.
    ///
    /// Calling this function might have generated messages for the coordinator.
    /// [`MultiStreamConnectionTask::pull_message_to_coordinator`] should be called afterwards in
    /// order to process these messages.
    ///
    /// # Panic
    ///
    /// Panics if [`MultiStreamConnectionTask::reset`] has been called in the past.
    ///
    pub fn reset(&mut self) {
        match self.connection {
            MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                initiator: ShutdownInitiator::Api,
                ..
            }
            | MultiStreamConnectionTaskInner::ShutdownAcked {
                initiator: ShutdownInitiator::Api,
                ..
            } => {
                // It is illegal to call `reset` a second time.
                panic!()
            }
            MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                ref mut initiator, ..
            }
            | MultiStreamConnectionTaskInner::ShutdownAcked {
                ref mut initiator, ..
            } => {
                // Mark the initiator as being the API in order to track proper API usage.
                *initiator = ShutdownInitiator::Api;
            }
            _ => {
                self.connection = MultiStreamConnectionTaskInner::ShutdownWaitingAck {
                    initiator: ShutdownInitiator::Api,
                    shutdown_finish_message_sent: false,
                    start_shutdown_message_to_send: Some(Some(ShutdownCause::RemoteReset)),
                };
            }
        }
    }

    /// Immediately destroys the substream with the given identifier.
    ///
    /// The given identifier is now considered invalid by the state machine.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    ///
    pub fn reset_substream(&mut self, substream_id: &TSubId) {
        match &mut self.connection {
            MultiStreamConnectionTaskInner::Established {
                handshake_substream,
                ..
            } if handshake_substream
                .as_ref()
                .map_or(false, |s| s == substream_id) =>
            {
                *handshake_substream = None;
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.reset_substream(substream_id)
            }
            MultiStreamConnectionTaskInner::Handshake {
                opened_substream: Some(opened_substream),
                handshake_read_buffer,
                ..
            } if opened_substream == substream_id => {
                // TODO: the handshake has failed, kill the connection?
                handshake_read_buffer.clear();
            }
            MultiStreamConnectionTaskInner::Handshake {
                extra_open_substreams,
                ..
            } => {
                let _was_in = extra_open_substreams.remove(substream_id).is_some();
                assert!(_was_in);
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: panic if substream id invalid?
            }
        }
    }

    /// Reads/writes data on the substream.
    ///
    /// If the method returns [`SubstreamFate::Reset`], then the substream is now considered dead
    /// according to the state machine and its identifier is now invalid. If the reading or
    /// writing side of the substream was still open, then the user should reset that substream.
    ///
    /// In the case of a WebRTC connection, the [`ReadWrite::incoming_buffer`] and
    /// [`ReadWrite::write_bytes_queueable`] must always be `Some`.
    ///
    /// # Panic
    ///
    /// Panics if there is no substream with that identifier.
    /// Panics if this is a WebRTC connection, and the reading or writing side is closed.
    ///
    #[must_use]
    pub fn substream_read_write(
        &mut self,
        substream_id: &TSubId,
        read_write: &'_ mut ReadWrite<'_, TNow>,
    ) -> SubstreamFate {
        // In WebRTC, the reading and writing sides are never closed.
        // Note that the `established::MultiStream` state machine also performs this check, but
        // we do it here again because we're not necessarily in the ̀`established` state.
        assert!(read_write.incoming_buffer.is_some() && read_write.write_bytes_queueable.is_some());

        match &mut self.connection {
            MultiStreamConnectionTaskInner::Handshake {
                handshake,
                opened_substream,
                handshake_read_buffer,
                handshake_read_buffer_partial_read,
                established,
                extra_open_substreams,
            } if opened_substream
                .as_ref()
                .map_or(false, |s| s == substream_id) =>
            {
                // TODO: check the handshake timeout

                // The Noise data is not directly the data of the substream. Instead, everything
                // is wrapped within a Protobuf frame. For this reason, we first transfer the data
                // to a buffer.
                //
                // According to the libp2p WebRTC spec, a frame and its length prefix must not be
                // larger than 16kiB, meaning that the read buffer never has to exceed this size.
                // TODO: this is very suboptimal; improve
                if let Some(incoming_buffer) = read_write.incoming_buffer {
                    // TODO: reset the substream if `remote_writing_side_closed`
                    let max_to_transfer =
                        cmp::min(incoming_buffer.len(), 16384 - handshake_read_buffer.len());
                    handshake_read_buffer.extend_from_slice(&incoming_buffer[..max_to_transfer]);
                    debug_assert!(handshake_read_buffer.len() <= 16384);
                    read_write.advance_read(max_to_transfer);
                }

                // Try to parse the content of `handshake_read_buffer`.
                // If the content of `handshake_read_buffer` is an incomplete frame, the flags
                // will be `None` and the message will be `&[]`.
                let (protobuf_frame_size, flags, message_within_frame) = {
                    let mut parser = nom::combinator::complete::<_, _, nom::error::Error<&[u8]>, _>(
                        nom::combinator::map_parser(
                            nom::multi::length_data(crate::util::leb128::nom_leb128_usize),
                            protobuf::message_decode! {
                                #[optional] flags = 1 => protobuf::enum_tag_decode,
                                #[optional] message = 2 => protobuf::bytes_tag_decode,
                            },
                        ),
                    );

                    match nom::Finish::finish(parser(handshake_read_buffer)) {
                        Ok((rest, framed_message)) => {
                            let protobuf_frame_size = handshake_read_buffer.len() - rest.len();
                            (
                                protobuf_frame_size,
                                framed_message.flags,
                                framed_message.message.unwrap_or(&[][..]),
                            )
                        }
                        Err(err) if err.code == nom::error::ErrorKind::Eof => {
                            // TODO: reset the substream if incoming_buffer is full, as it means that the frame is too large, and remove the debug_assert below
                            debug_assert!(handshake_read_buffer.len() < 16384);
                            (0, None, &[][..])
                        }
                        Err(_) => {
                            // Message decoding error.
                            // TODO: no, handshake failed
                            return SubstreamFate::Reset;
                        }
                    }
                };

                let mut sub_read_write = ReadWrite {
                    now: read_write.now.clone(),
                    incoming_buffer: Some(
                        &message_within_frame[*handshake_read_buffer_partial_read..],
                    ),
                    read_bytes: 0,
                    write_buffers: Vec::new(),
                    write_bytes_queued: read_write.write_bytes_queued,
                    // Don't write out more than one frame.
                    // TODO: this `10` is here for the length and protobuf frame size and is a bit hacky
                    write_bytes_queueable: Some(
                        cmp::min(read_write.write_bytes_queueable.unwrap(), 16384)
                            .saturating_sub(10),
                    ),
                    wake_up_after: None,
                };

                let handshake_outcome = handshake.take().unwrap().read_write(&mut sub_read_write);
                *handshake_read_buffer_partial_read += sub_read_write.read_bytes;
                if let Some(wake_up_after) = &sub_read_write.wake_up_after {
                    read_write.wake_up_after(wake_up_after)
                }

                // Send out the message that the Noise handshake has written
                // into `intermediary_write_buffer`.
                if sub_read_write.write_bytes_queued != read_write.write_bytes_queued {
                    let written_bytes =
                        sub_read_write.write_bytes_queued - read_write.write_bytes_queued;
                    drop(sub_read_write);

                    // TODO: don't do the encoding manually but use the protobuf module?
                    let tag = protobuf::tag_encode(2, 2).collect::<Vec<_>>();
                    let data_len = leb128::encode_usize(written_bytes).collect::<Vec<_>>();
                    let libp2p_prefix =
                        leb128::encode_usize(tag.len() + data_len.len()).collect::<Vec<_>>();

                    // The spec mentions that a frame plus its length prefix shouldn't exceed
                    // 16kiB. This is normally ensured by forbidding the substream from writing
                    // more data than would fit in 16kiB.
                    debug_assert!(libp2p_prefix.len() + tag.len() + data_len.len() <= 16384);

                    read_write.write_out(libp2p_prefix);
                    read_write.write_out(tag);
                    read_write.write_out(data_len);
                }

                if protobuf_frame_size != 0
                    && message_within_frame.len() <= *handshake_read_buffer_partial_read
                {
                    // If the substream state machine has processed all the data within
                    // `read_buffer`, process the flags of the current protobuf frame and
                    // discard that protobuf frame so that at the next iteration we pick
                    // up the rest.

                    // Discard the data.
                    *handshake_read_buffer_partial_read = 0;
                    *handshake_read_buffer = handshake_read_buffer
                        .split_at(protobuf_frame_size)
                        .1
                        .to_vec();

                    // Process the flags.
                    // TODO: ignore FIN and treat any other flag as error
                    if flags.map_or(false, |f| f != 0) {
                        todo!()
                    }
                }

                match handshake_outcome {
                    Ok(noise::NoiseHandshake::InProgress(handshake_update)) => {
                        *handshake = Some(handshake_update);
                        SubstreamFate::Continue
                    }
                    Err(_err) => todo!("{:?}", _err), // TODO: /!\
                    Ok(noise::NoiseHandshake::Success {
                        cipher: _,
                        remote_peer_id,
                    }) => {
                        // The handshake has succeeded and we will transition into "established"
                        // mode.
                        // However the rest of the body of this function still needs to deal with
                        // the substream used for the handshake.
                        // We close the writing side. If the reading side is closed, we indicate
                        // that the substream is dead. If the reading side is still open, we
                        // indicate that it's not dead and store it in the state machine while
                        // waiting for it to be closed by the remote.
                        read_write.close_write();
                        let handshake_substream_still_open = read_write.incoming_buffer.is_some();

                        let mut established = established.take().unwrap();
                        for (substream_id, outbound) in extra_open_substreams.drain() {
                            established.add_substream(substream_id, outbound);
                        }

                        self.connection = MultiStreamConnectionTaskInner::Established {
                            established,
                            handshake_finished_message_to_send: Some(remote_peer_id),
                            handshake_substream: if handshake_substream_still_open {
                                Some(opened_substream.take().unwrap())
                            } else {
                                None
                            },
                            outbound_substreams_map: hashbrown::HashMap::with_capacity_and_hasher(
                                0,
                                Default::default(),
                            ),
                            notifications_in_open_cancel_acknowledgments: VecDeque::with_capacity(
                                4,
                            ),
                            inbound_negotiated_cancel_acknowledgments:
                                hashbrown::HashSet::with_capacity_and_hasher(2, Default::default()),
                            inbound_accept_cancel_events: VecDeque::with_capacity(2),
                        };

                        if handshake_substream_still_open {
                            SubstreamFate::Continue
                        } else {
                            SubstreamFate::Reset
                        }
                    }
                }
            }
            MultiStreamConnectionTaskInner::Established {
                handshake_substream,
                ..
            } if handshake_substream
                .as_ref()
                .map_or(false, |s| s == substream_id) =>
            {
                // Close the writing side. If the reading side is closed, we indicate that the
                // substream is dead. If the reading side is still open, we indicate that it's not
                // dead and simply wait for the remote to close it.
                // TODO: kill the connection if the remote sends more data?
                read_write.close_write();
                if read_write.incoming_buffer.is_none() {
                    *handshake_substream = None;
                    SubstreamFate::Reset
                } else {
                    SubstreamFate::Continue
                }
            }
            MultiStreamConnectionTaskInner::Established { established, .. } => {
                established.substream_read_write(substream_id, read_write)
            }
            MultiStreamConnectionTaskInner::Handshake {
                extra_open_substreams,
                ..
            } => {
                assert!(extra_open_substreams.contains_key(substream_id));
                // Don't do anything. Don't read or write. Instead we wait for the handshake to
                // be finished.
                SubstreamFate::Continue
            }
            MultiStreamConnectionTaskInner::ShutdownAcked { .. }
            | MultiStreamConnectionTaskInner::ShutdownWaitingAck { .. } => {
                // TODO: panic if substream id invalid?
                SubstreamFate::Reset
            }
        }
    }
}
