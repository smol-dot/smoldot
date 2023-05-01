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

use crate::{bindings, timers::Delay};

use smoldot::libp2p::multihash;
use smoldot_light::platform::{ConnectError, PlatformSubstreamDirection};

use core::{future, mem, pin, str, task, time::Duration};
use std::{
    borrow::Cow,
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// Total number of bytes that all the connections created through [`Platform`] combined have
/// received.
pub static TOTAL_BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);
/// Total number of bytes that all the connections created through [`Platform`] combined have
/// sent.
pub static TOTAL_BYTES_SENT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub(crate) struct Platform;

impl Platform {
    pub fn new() -> Self {
        Self {}
    }
}

// TODO: this trait implementation was written before GATs were stable in Rust; now that the associated types have lifetimes, it should be possible to considerably simplify this code
impl smoldot_light::platform::PlatformRef for Platform {
    type Delay = Delay;
    type Yield = Yield;
    type Instant = Instant;
    type Connection = ConnectionWrapper; // Entry in the ̀`CONNECTIONS` map.
    type Stream = StreamWrapper; // Entry in the ̀`STREAMS` map and a read buffer.
    type ConnectFuture = pin::Pin<
        Box<
            dyn future::Future<
                    Output = Result<
                        smoldot_light::platform::PlatformConnection<Self::Stream, Self::Connection>,
                        ConnectError,
                    >,
                > + Send,
        >,
    >;
    type StreamUpdateFuture<'a> = pin::Pin<Box<dyn future::Future<Output = ()> + Send + 'a>>;
    type NextSubstreamFuture<'a> = pin::Pin<
        Box<
            dyn future::Future<
                    Output = Option<(
                        Self::Stream,
                        smoldot_light::platform::PlatformSubstreamDirection,
                    )>,
                > + Send
                + 'a,
        >,
    >;

    fn now_from_unix_epoch(&self) -> Duration {
        // The documentation of `now_from_unix_epoch()` mentions that it's ok to panic if we're
        // before the UNIX epoch.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| panic!())
    }

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) -> Self::Delay {
        Delay::new(duration)
    }

    fn sleep_until(&self, when: Self::Instant) -> Self::Delay {
        Delay::new_at(when)
    }

    fn spawn_task(
        &self,
        _task_name: Cow<str>,
        task: pin::Pin<Box<dyn future::Future<Output = ()> + Send>>,
    ) {
        let (runnable, task) = async_task::spawn(task, |runnable| {
            super::networking_tasks_queue()
                .push(runnable)
                .unwrap_or_else(|_| panic!());
            super::TASKS_QUEUE_LEN.fetch_add(1, Ordering::SeqCst);
            super::NETWORKING_TASKS_QUEUE_LEN.fetch_add(1, Ordering::SeqCst);
            #[cfg(target_family = "wasm")]
            unsafe {
                // Note: this might cause two threads to wake up, but is in practice never going
                // to happen, and even if it does happen isn't a problem.
                core::arch::wasm::memory_atomic_notify((&super::TASKS_QUEUE_LEN).as_ptr(), 1);
                core::arch::wasm::memory_atomic_notify((&super::NETWORKING_TASKS_QUEUE_LEN).as_ptr(), 1);
            }
        });

        runnable.schedule();
        task.detach();
    }

    fn client_name(&self) -> Cow<str> {
        env!("CARGO_PKG_NAME").into()
    }

    fn client_version(&self) -> Cow<str> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn yield_after_cpu_intensive(&self) -> Self::Yield {
        Yield { has_yielded: false }
    }

    fn connect(&self, url: &str) -> Self::ConnectFuture {
        let mut lock = STATE.try_lock().unwrap();

        let connection_id = lock.next_connection_id;
        lock.next_connection_id += 1;

        let mut error_buffer_index = [0u8; 5];

        let ret_code = unsafe {
            bindings::connection_new(
                connection_id,
                u32::try_from(url.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(url.as_bytes().len()).unwrap(),
                u32::try_from(&mut error_buffer_index as *mut [u8; 5] as usize).unwrap(),
            )
        };

        let result = if ret_code != 0 {
            let error_message = bindings::get_buffer(u32::from_le_bytes(
                <[u8; 4]>::try_from(&error_buffer_index[0..4]).unwrap(),
            ));
            Err(ConnectError {
                message: str::from_utf8(&error_message).unwrap().to_owned(),
                is_bad_addr: error_buffer_index[4] != 0,
            })
        } else {
            let _prev_value = lock.connections.insert(
                connection_id,
                Connection {
                    inner: ConnectionInner::NotOpen,
                    something_happened: event_listener::Event::new(),
                },
            );
            debug_assert!(_prev_value.is_none());

            Ok(())
        };

        Box::pin(async move {
            result?;

            // Wait until the connection state is no longer `ConnectionInner::NotOpen`.
            let mut lock = loop {
                let something_happened = {
                    let mut lock = STATE.try_lock().unwrap();
                    let connection = lock.connections.get_mut(&connection_id).unwrap();

                    if !matches!(connection.inner, ConnectionInner::NotOpen) {
                        break lock;
                    }

                    connection.something_happened.listen()
                };

                something_happened.await
            };
            let lock = &mut *lock;

            let connection = lock.connections.get_mut(&connection_id).unwrap();

            match &mut connection.inner {
                ConnectionInner::NotOpen => unreachable!(),
                ConnectionInner::SingleStreamMsNoiseYamux { write_closable } => {
                    debug_assert!(lock.streams.contains_key(&(connection_id, None)));

                    let read_buffer = ReadBuffer {
                        buffer: Vec::new().into(),
                        buffer_first_offset: 0,
                    };

                    Ok(smoldot_light::platform::PlatformConnection::SingleStreamMultistreamSelectNoiseYamux(
                        StreamWrapper { connection_id, stream_id: None, read_buffer, is_reset: false, writable_bytes: 0, write_closable: *write_closable, write_closed: false },
                    ))
                }
                ConnectionInner::MultiStreamWebRtc {
                    connection_handles_alive,
                    local_tls_certificate_multihash,
                    remote_tls_certificate_multihash,
                    ..
                } => {
                    *connection_handles_alive += 1;
                    Ok(
                        smoldot_light::platform::PlatformConnection::MultiStreamWebRtc {
                            connection: ConnectionWrapper(connection_id),
                            local_tls_certificate_multihash: local_tls_certificate_multihash
                                .clone(),
                            remote_tls_certificate_multihash: remote_tls_certificate_multihash
                                .clone(),
                        },
                    )
                }
                ConnectionInner::Reset {
                    message,
                    connection_handles_alive,
                } => {
                    // Note that it is possible for the state to have transitionned to (for
                    // example) `ConnectionInner::SingleStreamMsNoiseYamux` and then immediately
                    // to `Reset`, but we don't really care about that corner case.
                    debug_assert_eq!(*connection_handles_alive, 0);
                    let message = mem::take(message);
                    lock.connections.remove(&connection_id).unwrap();
                    Err(ConnectError {
                        message,
                        is_bad_addr: false,
                    })
                }
            }
        })
    }

    fn next_substream<'a>(
        &self,
        ConnectionWrapper(connection_id): &'a mut Self::Connection,
    ) -> Self::NextSubstreamFuture<'a> {
        let connection_id = *connection_id;

        Box::pin(async move {
            let (stream_id, direction, initial_writable_bytes) = loop {
                let something_happened = {
                    let mut lock = STATE.try_lock().unwrap();
                    let connection = lock.connections.get_mut(&connection_id).unwrap();

                    match &mut connection.inner {
                        ConnectionInner::Reset { .. } => return None,
                        ConnectionInner::MultiStreamWebRtc {
                            opened_substreams_to_pick_up,
                            connection_handles_alive,
                            ..
                        } => {
                            if let Some((substream, direction, initial_writable_bytes)) =
                                opened_substreams_to_pick_up.pop_front()
                            {
                                *connection_handles_alive += 1;
                                break (substream, direction, initial_writable_bytes);
                            }
                        }
                        ConnectionInner::NotOpen
                        | ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                            unreachable!()
                        }
                    }

                    connection.something_happened.listen()
                };

                something_happened.await
            };

            Some((
                StreamWrapper {
                    connection_id,
                    stream_id: Some(stream_id),
                    read_buffer: ReadBuffer {
                        buffer: Vec::<u8>::new().into(),
                        buffer_first_offset: 0,
                    },
                    is_reset: false,
                    writable_bytes: usize::try_from(initial_writable_bytes).unwrap(),
                    write_closable: false, // Note: this is currently hardcoded for WebRTC.
                    write_closed: false,
                },
                direction,
            ))
        })
    }

    fn open_out_substream(&self, ConnectionWrapper(connection_id): &mut Self::Connection) {
        match STATE
            .try_lock()
            .unwrap()
            .connections
            .get(connection_id)
            .unwrap()
            .inner
        {
            ConnectionInner::MultiStreamWebRtc { .. } => unsafe {
                bindings::connection_stream_open(*connection_id)
            },
            ConnectionInner::Reset { .. } => {}
            ConnectionInner::NotOpen | ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                unreachable!()
            }
        }
    }

    fn update_stream<'a>(
        &self,
        StreamWrapper {
            connection_id,
            stream_id,
            read_buffer,
            is_reset,
            writable_bytes,
            ..
        }: &'a mut Self::Stream,
    ) -> Self::StreamUpdateFuture<'a> {
        Box::pin(async move {
            loop {
                if *is_reset {
                    future::pending::<()>().await;
                }

                let listener = {
                    let mut lock = STATE.try_lock().unwrap();
                    let stream = lock.streams.get_mut(&(*connection_id, *stream_id)).unwrap();

                    if stream.reset {
                        *is_reset = true;
                        return;
                    }

                    let mut shall_return = false;

                    // Move the next buffer from `STATE` into `read_buffer`.
                    if read_buffer.buffer_first_offset == read_buffer.buffer.len() {
                        if let Some(msg) = stream.messages_queue.pop_front() {
                            stream.messages_queue_total_size -= msg.len();
                            read_buffer.buffer = msg;
                            read_buffer.buffer_first_offset = 0;
                            shall_return = true;
                        }
                    }

                    if stream.writable_bytes_extra != 0 {
                        // As documented, the number of writable bytes must never exceed the
                        // initial writable bytes value. As such, this can't overflow unless there
                        // is a bug on the JavaScript side.
                        *writable_bytes += stream.writable_bytes_extra;
                        stream.writable_bytes_extra = 0;
                        shall_return = true;
                    }

                    if shall_return {
                        return;
                    }

                    stream.something_happened.listen()
                };

                listener.await
            }
        })
    }

    fn read_buffer<'a>(
        &self,
        StreamWrapper {
            read_buffer,
            is_reset,
            ..
        }: &'a mut Self::Stream,
    ) -> smoldot_light::platform::ReadBuffer<'a> {
        if *is_reset {
            return smoldot_light::platform::ReadBuffer::Reset;
        }

        // TODO: doesn't detect closed

        smoldot_light::platform::ReadBuffer::Open(
            &read_buffer.buffer[read_buffer.buffer_first_offset..],
        )
    }

    fn advance_read_cursor(
        &self,
        StreamWrapper {
            read_buffer,
            is_reset,
            ..
        }: &mut Self::Stream,
        bytes: usize,
    ) {
        assert!(!*is_reset);
        assert!(bytes <= read_buffer.buffer.len() - read_buffer.buffer_first_offset);
        read_buffer.buffer_first_offset += bytes;
        debug_assert!(read_buffer.buffer_first_offset <= read_buffer.buffer.len());
    }

    fn writable_bytes(
        &self,
        StreamWrapper {
            is_reset,
            writable_bytes,
            write_closed,
            ..
        }: &mut Self::Stream,
    ) -> usize {
        if *is_reset || *write_closed {
            return 0;
        }

        *writable_bytes
    }

    fn send(
        &self,
        StreamWrapper {
            connection_id,
            stream_id,
            write_closed,
            writable_bytes,
            ..
        }: &mut Self::Stream,
        data: &[u8],
    ) {
        assert!(!*write_closed);

        let mut lock = STATE.try_lock().unwrap();
        let stream = lock.streams.get_mut(&(*connection_id, *stream_id)).unwrap();

        if stream.reset {
            return;
        }

        assert!(data.len() <= *writable_bytes);
        *writable_bytes -= data.len();

        // `unwrap()` is ok as there's no way that `data.len()` doesn't fit in a `u64`.
        TOTAL_BYTES_SENT.fetch_add(u64::try_from(data.len()).unwrap(), Ordering::Relaxed);

        unsafe {
            bindings::stream_send(
                *connection_id,
                stream_id.unwrap_or(0),
                u32::try_from(data.as_ptr() as usize).unwrap(),
                u32::try_from(data.len()).unwrap(),
            );
        }
    }

    fn close_send(
        &self,
        StreamWrapper {
            connection_id,
            stream_id,
            write_closable,
            write_closed,
            ..
        }: &mut Self::Stream,
    ) {
        assert!(!*write_closed);

        let mut lock = STATE.try_lock().unwrap();
        let stream = lock.streams.get_mut(&(*connection_id, *stream_id)).unwrap();

        if stream.reset {
            return;
        }

        if *write_closable {
            unsafe {
                bindings::stream_send_close(*connection_id, stream_id.unwrap_or(0));
            }
        }

        *write_closed = true;
    }
}

pub(crate) struct Yield {
    has_yielded: bool,
}

impl future::Future for Yield {
    type Output = ();

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        if !self.has_yielded {
            self.has_yielded = true;
            cx.waker().wake_by_ref();
            task::Poll::Pending
        } else {
            task::Poll::Ready(())
        }
    }
}

pub(crate) struct StreamWrapper {
    connection_id: u32,
    stream_id: Option<u32>,
    read_buffer: ReadBuffer,
    /// `true` if the remote has reset the stream and `update_stream` has since then been called.
    is_reset: bool,
    writable_bytes: usize,
    write_closable: bool,
    write_closed: bool,
}

impl Drop for StreamWrapper {
    fn drop(&mut self) {
        let mut lock = STATE.try_lock().unwrap();
        let lock = &mut *lock;

        let connection = lock.connections.get_mut(&self.connection_id).unwrap();
        let removed_stream = lock
            .streams
            .remove(&(self.connection_id, self.stream_id))
            .unwrap();

        let remove_connection = match &mut connection.inner {
            ConnectionInner::NotOpen => unreachable!(),
            ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                if !removed_stream.reset {
                    unsafe {
                        bindings::reset_connection(self.connection_id);
                    }
                }

                debug_assert!(self.stream_id.is_none());
                true
            }
            ConnectionInner::MultiStreamWebRtc {
                connection_handles_alive,
                ..
            } => {
                if !removed_stream.reset {
                    unsafe {
                        bindings::connection_stream_reset(
                            self.connection_id,
                            self.stream_id.unwrap(),
                        )
                    }
                }
                *connection_handles_alive -= 1;
                let remove_connection = *connection_handles_alive == 0;
                if remove_connection {
                    unsafe {
                        bindings::reset_connection(self.connection_id);
                    }
                }
                remove_connection
            }
            ConnectionInner::Reset {
                connection_handles_alive,
                ..
            } => {
                *connection_handles_alive -= 1;
                let remove_connection = *connection_handles_alive == 0;
                if remove_connection {
                    unsafe {
                        bindings::reset_connection(self.connection_id);
                    }
                }
                remove_connection
            }
        };

        if remove_connection {
            lock.connections.remove(&self.connection_id).unwrap();
        }
    }
}

pub(crate) struct ConnectionWrapper(u32);

impl Drop for ConnectionWrapper {
    fn drop(&mut self) {
        let mut lock = STATE.try_lock().unwrap();

        let connection = lock.connections.get_mut(&self.0).unwrap();
        let (remove_connection, reset_connection) = match &mut connection.inner {
            ConnectionInner::NotOpen | ConnectionInner::SingleStreamMsNoiseYamux { .. } => {
                unreachable!()
            }
            ConnectionInner::MultiStreamWebRtc {
                connection_handles_alive,
                ..
            } => {
                *connection_handles_alive -= 1;
                let v = *connection_handles_alive == 0;
                (v, v)
            }
            ConnectionInner::Reset { .. } => (true, false),
        };

        if remove_connection {
            lock.connections.remove(&self.0).unwrap();
        }
        if reset_connection {
            unsafe {
                bindings::reset_connection(self.0);
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref STATE: Mutex<NetworkState> = Mutex::new(NetworkState {
        next_connection_id: 0,
        connections: hashbrown::HashMap::with_capacity_and_hasher(32, Default::default()),
        streams: BTreeMap::new(),
    });
}

/// All the connections and streams that are alive.
///
/// Single-stream connections have one entry in `connections` and one entry in `streams` (with
/// a `stream_id` always equal to `None`).
/// Multi-stream connections have one entry in `connections` and zero or more entries in `streams`.
struct NetworkState {
    next_connection_id: u32,
    connections: hashbrown::HashMap<u32, Connection, fnv::FnvBuildHasher>,
    streams: BTreeMap<(u32, Option<u32>), Stream>,
}

struct Connection {
    /// Type of connection and extra fields that depend on the type.
    inner: ConnectionInner,
    /// Event notified whenever one of the fields above is modified.
    something_happened: event_listener::Event,
}

enum ConnectionInner {
    NotOpen,
    SingleStreamMsNoiseYamux {
        /// True if the stream can be closed.
        write_closable: bool,
    },
    MultiStreamWebRtc {
        /// List of substreams that the host (i.e. JavaScript side) has reported have been opened,
        /// but that haven't been reported through
        /// [`smoldot_light::platform::PlatformRef::next_substream`] yet.
        opened_substreams_to_pick_up: VecDeque<(u32, PlatformSubstreamDirection, u32)>,
        /// Number of objects (connections and streams) in the [`Platform`] API that reference
        /// this connection. If it switches from 1 to 0, the connection must be removed.
        connection_handles_alive: u32,
        /// Multihash encoding of the TLS certificate used by the local node at the DTLS layer.
        local_tls_certificate_multihash: Vec<u8>,
        /// Multihash encoding of the TLS certificate used by the remote node at the DTLS layer.
        remote_tls_certificate_multihash: Vec<u8>,
    },
    /// [`bindings::connection_reset`] has been called
    Reset {
        /// Message given by the bindings to justify the closure.
        message: String,
        /// Number of objects (connections and streams) in the [`Platform`] API that reference
        /// this connection. If it switches from 1 to 0, the connection must be removed.
        connection_handles_alive: u32,
    },
}

struct Stream {
    /// `true` if [`bindings::stream_reset`] has been called.
    reset: bool,
    /// Sum of the writable bytes reported through [`bindings::stream_writable_bytes`] or
    /// `initial_writable_bytes` that haven't been processed yet in a call to
    /// `update_stream`.
    writable_bytes_extra: usize,
    /// List of messages received through [`bindings::stream_message`]. Must never contain
    /// empty messages.
    messages_queue: VecDeque<Box<[u8]>>,
    /// Total size of all the messages stored in [`Stream::messages_queue`].
    messages_queue_total_size: usize,
    /// Event notified whenever one of the fields above is modified, such as a new message being
    /// queued.
    something_happened: event_listener::Event,
}

struct ReadBuffer {
    /// Buffer containing incoming data.
    buffer: Box<[u8]>,

    /// The first bytes of [`ReadBuffer::buffer`] have already been processed are not considered
    /// not part of the read buffer anymore.
    buffer_first_offset: usize,
}

pub(crate) fn connection_open_single_stream(
    connection_id: u32,
    handshake_ty: u32,
    initial_writable_bytes: u32,
    write_closable: u32,
) {
    assert_eq!(handshake_ty, 0);

    let mut lock = STATE.try_lock().unwrap();
    let lock = &mut *lock;

    let connection = lock.connections.get_mut(&connection_id).unwrap();

    debug_assert!(matches!(connection.inner, ConnectionInner::NotOpen));
    connection.inner = ConnectionInner::SingleStreamMsNoiseYamux {
        write_closable: write_closable != 0,
    };

    let _prev_value = lock.streams.insert(
        (connection_id, None),
        Stream {
            reset: false,
            messages_queue: VecDeque::with_capacity(8),
            messages_queue_total_size: 0,
            something_happened: event_listener::Event::new(),
            writable_bytes_extra: usize::try_from(initial_writable_bytes).unwrap(),
        },
    );
    debug_assert!(_prev_value.is_none());

    connection.something_happened.notify(usize::max_value());
}

pub(crate) fn connection_open_multi_stream(connection_id: u32, handshake_ty: Vec<u8>) {
    let (_, (local_tls_certificate_multihash, remote_tls_certificate_multihash)) =
        nom::sequence::preceded(
            nom::bytes::complete::tag::<_, _, nom::error::Error<&[u8]>>(&[0]),
            nom::sequence::tuple((
                move |b| {
                    multihash::MultihashRef::from_bytes_partial(b)
                        .map(|(a, b)| (b, a))
                        .map_err(|_| {
                            nom::Err::Failure(nom::error::make_error(
                                b,
                                nom::error::ErrorKind::Verify,
                            ))
                        })
                },
                move |b| {
                    multihash::MultihashRef::from_bytes_partial(b)
                        .map(|(a, b)| (b, a))
                        .map_err(|_| {
                            nom::Err::Failure(nom::error::make_error(
                                b,
                                nom::error::ErrorKind::Verify,
                            ))
                        })
                },
            )),
        )(&handshake_ty[..])
        .expect("invalid handshake type provided to connection_open_multi_stream");

    let mut lock = STATE.try_lock().unwrap();
    let connection = lock.connections.get_mut(&connection_id).unwrap();

    debug_assert!(matches!(connection.inner, ConnectionInner::NotOpen));

    connection.inner = ConnectionInner::MultiStreamWebRtc {
        opened_substreams_to_pick_up: VecDeque::with_capacity(8),
        connection_handles_alive: 0,
        local_tls_certificate_multihash: local_tls_certificate_multihash.to_vec(),
        remote_tls_certificate_multihash: remote_tls_certificate_multihash.to_vec(),
    };
    connection.something_happened.notify(usize::max_value());
}

pub(crate) fn stream_writable_bytes(connection_id: u32, stream_id: u32, bytes: u32) {
    let mut lock = STATE.try_lock().unwrap();

    let connection = lock.connections.get_mut(&connection_id).unwrap();

    // For single stream connections, the docs of this function mentions that `stream_id` can be
    // any value.
    let actual_stream_id = match connection.inner {
        ConnectionInner::MultiStreamWebRtc { .. } => Some(stream_id),
        ConnectionInner::SingleStreamMsNoiseYamux { .. } => None,
        ConnectionInner::Reset { .. } | ConnectionInner::NotOpen => unreachable!(),
    };

    let stream = lock
        .streams
        .get_mut(&(connection_id, actual_stream_id))
        .unwrap();
    debug_assert!(!stream.reset);

    // As documented, the number of writable bytes must never exceed the initial writable bytes
    // value. As such, this can't overflow unless there is a bug on the JavaScript side.
    stream.writable_bytes_extra += usize::try_from(bytes).unwrap();
    stream.something_happened.notify(usize::max_value());
}

pub(crate) fn stream_message(connection_id: u32, stream_id: u32, message: Vec<u8>) {
    let mut lock = STATE.try_lock().unwrap();

    let connection = lock.connections.get_mut(&connection_id).unwrap();

    // For single stream connections, the docs of this function mentions that `stream_id` can be
    // any value.
    let actual_stream_id = match connection.inner {
        ConnectionInner::MultiStreamWebRtc { .. } => Some(stream_id),
        ConnectionInner::SingleStreamMsNoiseYamux { .. } => None,
        ConnectionInner::Reset { .. } | ConnectionInner::NotOpen => unreachable!(),
    };

    let stream = lock
        .streams
        .get_mut(&(connection_id, actual_stream_id))
        .unwrap();
    debug_assert!(!stream.reset);

    TOTAL_BYTES_RECEIVED.fetch_add(u64::try_from(message.len()).unwrap(), Ordering::Relaxed);

    // Ignore empty message to avoid all sorts of problems.
    if message.is_empty() {
        return;
    }

    // There is unfortunately no way to instruct the browser to back-pressure connections to
    // remotes.
    // In order to avoid DoS attacks, we refuse to buffer more than a certain amount of data per
    // connection. This limit is completely arbitrary, and this is in no way a robust solution
    // because this limit isn't in sync with any other part of the code. In other words, it could
    // be legitimate for the remote to buffer a large amount of data.
    // This corner case is handled by discarding the messages that would go over the limit. While
    // this is not a great solution, going over that limit can be considered as a fault from the
    // remote, the same way as it would be a fault from the remote to forget to send some bytes,
    // and thus should be handled in a similar way by the higher level code.
    // A better way to handle this would be to kill the connection abruptly. However, this would
    // add a lot of complex code in this module, and the effort is clearly not worth it for this
    // niche situation.
    // See <https://github.com/smol-dot/smoldot/issues/109>.
    // TODO: do this properly eventually ^
    // TODO: move this limit check in the browser-specific code so that NodeJS and Deno don't suffer from it?
    if stream.messages_queue_total_size >= 25 * 1024 * 1024 {
        return;
    }

    stream.messages_queue_total_size += message.len();
    stream.messages_queue.push_back(message.into_boxed_slice());
    stream.something_happened.notify(usize::max_value());
}

pub(crate) fn connection_stream_opened(
    connection_id: u32,
    stream_id: u32,
    outbound: u32,
    initial_writable_bytes: u32,
) {
    let mut lock = STATE.try_lock().unwrap();
    let lock = &mut *lock;

    let connection = lock.connections.get_mut(&connection_id).unwrap();
    if let ConnectionInner::MultiStreamWebRtc {
        opened_substreams_to_pick_up,
        ..
    } = &mut connection.inner
    {
        let _prev_value = lock.streams.insert(
            (connection_id, Some(stream_id)),
            Stream {
                reset: false,
                messages_queue: VecDeque::with_capacity(8),
                messages_queue_total_size: 0,
                something_happened: event_listener::Event::new(),
                writable_bytes_extra: usize::try_from(initial_writable_bytes).unwrap(),
            },
        );

        if _prev_value.is_some() {
            panic!("same stream_id used multiple times in connection_stream_opened")
        }

        opened_substreams_to_pick_up.push_back((
            stream_id,
            if outbound != 0 {
                PlatformSubstreamDirection::Outbound
            } else {
                PlatformSubstreamDirection::Inbound
            },
            initial_writable_bytes,
        ));

        connection.something_happened.notify(usize::max_value())
    } else {
        panic!()
    }
}

pub(crate) fn connection_reset(connection_id: u32, message: Vec<u8>) {
    let mut lock = STATE.try_lock().unwrap();
    let connection = lock.connections.get_mut(&connection_id).unwrap();

    let connection_handles_alive = match &connection.inner {
        ConnectionInner::NotOpen => 0,
        ConnectionInner::SingleStreamMsNoiseYamux { .. } => 1, // TODO: I believe that this is correct but a bit confusing; might be helpful to refactor with an enum or something
        ConnectionInner::MultiStreamWebRtc {
            connection_handles_alive,
            ..
        } => *connection_handles_alive,
        ConnectionInner::Reset { .. } => unreachable!(),
    };

    connection.inner = ConnectionInner::Reset {
        connection_handles_alive,
        message: str::from_utf8(&message)
            .unwrap_or_else(|_| panic!("non-UTF-8 message"))
            .to_owned(),
    };

    connection.something_happened.notify(usize::max_value());

    for ((_, _), stream) in lock.streams.range_mut(
        (connection_id, Some(u32::min_value()))..=(connection_id, Some(u32::max_value())),
    ) {
        stream.reset = true;
        stream.something_happened.notify(usize::max_value());
    }
    if let Some(stream) = lock.streams.get_mut(&(connection_id, None)) {
        stream.reset = true;
        stream.something_happened.notify(usize::max_value());
    }
}

pub(crate) fn stream_reset(connection_id: u32, stream_id: u32) {
    // Note that, as documented, it is illegal to call this function on single-stream substreams.
    // We can thus assume that the `stream_id` is valid.
    let mut lock = STATE.try_lock().unwrap();
    let stream = lock
        .streams
        .get_mut(&(connection_id, Some(stream_id)))
        .unwrap();
    stream.reset = true;
    stream.something_happened.notify(usize::max_value());
}
