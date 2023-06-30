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

use crate::{LogCallback, LogLevel};
use smol::{future, stream::StreamExt as _};
use smoldot::json_rpc::{service, websocket_server};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    pin::Pin,
    sync::Arc,
};

mod requests_handler;

/// Configuration for a [`JsonRpcService`].
pub struct Config {
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Where to bind the WebSocket server.
    pub bind_address: SocketAddr,

    /// Maximum number of requests to process in parallel.
    pub max_parallel_requests: u32,
}

/// Running JSON-RPC service. Holds a server open for as long as it is alive.
pub struct JsonRpcService {
    /// This events listener is notified when the service is dropped.
    service_dropped: event_listener::Event,

    /// Address the server is listening on. Not necessarily equal to [`Config::bind_address`].
    listen_addr: SocketAddr,
}

impl Drop for JsonRpcService {
    fn drop(&mut self) {
        self.service_dropped.notify(usize::max_value());
    }
}

impl JsonRpcService {
    /// Initializes a new [`JsonRpcService`].
    pub async fn new(config: Config) -> Result<Self, InitError> {
        let server = {
            let result = websocket_server::WsServer::new(websocket_server::Config {
                bind_address: config.bind_address,
                capacity: 1,
                max_frame_size: 4096,
                send_buffer_len: 16384,
            })
            .await;

            match result {
                Ok(server) => server,
                Err(error) => {
                    return Err(InitError::ListenError {
                        bind_address: config.bind_address,
                        error,
                    })
                }
            }
        };

        let listen_addr = match server.local_addr() {
            Ok(addr) => addr,
            Err(error) => {
                return Err(InitError::ListenError {
                    bind_address: config.bind_address,
                    error,
                })
            }
        };

        let service_dropped = event_listener::Event::new();
        let on_service_dropped = service_dropped.listen();

        let (to_requests_handlers, from_background) = async_channel::bounded(8);
        for _ in 0..config.max_parallel_requests {
            requests_handler::spawn_requests_handler(requests_handler::Config {
                tasks_executor: config.tasks_executor.clone(),
                receiver: from_background.clone(),
            });
        }

        let (to_background, from_client_io_tasks) = async_channel::unbounded();

        let background = JsonRpcBackground {
            server,
            on_service_dropped,
            tasks_executor: config.tasks_executor.clone(),
            log_callback: config.log_callback,
            to_requests_handlers,
            from_client_io_tasks,
            to_background,
        };

        (config.tasks_executor)(Box::pin(async move { background.run().await }));

        Ok(JsonRpcService {
            service_dropped,
            listen_addr,
        })
    }

    /// Returns the address the server is listening on. Not necessarily equal
    /// to [`Config::bind_address`].
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr.clone()
    }
}

/// Error potentially returned by [`JsonRpcService::new`].
#[derive(Debug, derive_more::Display)]
pub enum InitError {
    /// Failed to listen on the server address.
    #[display(fmt = "Failed to listen on TCP address {bind_address}: {error}")]
    ListenError {
        /// Address that was attempted.
        bind_address: SocketAddr,
        /// Error returned by the operating system.
        error: io::Error,
    },
}

struct JsonRpcBackground {
    /// State machine of the WebSocket server. Holds the TCP socket.
    server: websocket_server::WsServer<JsonRpcClientConnection>,

    /// Event notified when the frontend is dropped.
    on_service_dropped: event_listener::EventListener,

    /// See [`Config::tasks_executor`].
    tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// See [`Config::log_callback`].
    log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Channel used to send requests to the tasks that process said requests.
    to_requests_handlers: async_channel::Sender<requests_handler::Message>,

    /// Receives responses and notifications from the client I/O tasks.
    from_client_io_tasks: async_channel::Receiver<(websocket_server::ConnectionId, String)>,

    /// Sending side of [`JsonRpcBackground::from_client_io_tasks`].
    to_background: async_channel::Sender<(websocket_server::ConnectionId, String)>,
}

struct JsonRpcClientConnection {
    /// Sends requests.
    to_client_io_task: async_channel::Sender<String>,

    /// Address to the client as provided by the operating system.
    address: SocketAddr,
}

impl JsonRpcBackground {
    async fn run(mut self) {
        loop {
            let Some(event) = future::or(
                async { Some(either::Left(self.from_client_io_tasks.next().await.unwrap())) },
                future::or(
                    async { (&mut self.on_service_dropped).await; None },
                    async { Some(either::Right(self.server.next_event().await)) }
                )
            ).await
                else { return };

            match event {
                either::Right(websocket_server::Event::ConnectionOpen { address, .. }) => {
                    self.log_callback.log(
                        LogLevel::Debug,
                        format!("incoming-connection; address={}", address),
                    );
                    let (client_main_task, io) = service::client_main_task(service::Config {
                        max_active_subscriptions: 128,
                        max_pending_requests: NonZeroU32::new(64).unwrap(),
                        serialized_requests_io_channel_size_hint: NonZeroUsize::new(8).unwrap(),
                    });
                    let (to_client_io_task, from_background) = async_channel::bounded(4);
                    let connection_id = self.server.accept(JsonRpcClientConnection {
                        to_client_io_task,
                        address,
                    });
                    spawn_client_io_task(
                        &self.tasks_executor,
                        from_background,
                        self.to_background.clone(),
                        io,
                        connection_id,
                    );
                    spawn_client_main_task(
                        &&self.tasks_executor,
                        self.to_requests_handlers.clone(),
                        client_main_task,
                    );
                }
                either::Right(websocket_server::Event::ConnectionError {
                    user_data: JsonRpcClientConnection { address, .. },
                    ..
                }) => {
                    self.log_callback.log(
                        LogLevel::Debug,
                        format!("connection-closed; address={}", address),
                    );
                }
                either::Right(websocket_server::Event::TextFrame {
                    message,
                    user_data: json_rpc_connection,
                    ..
                }) => {
                    self.log_callback.log(
                        LogLevel::Debug,
                        format!(
                            "request; address={}; request={}",
                            json_rpc_connection.address,
                            crate::util::truncated_str(
                                message.chars().filter(|c| !c.is_control()),
                                128
                            )
                        ),
                    );
                    json_rpc_connection
                        .to_client_io_task
                        .send(message)
                        .await
                        .unwrap();
                }

                either::Left((connection_id, response)) => {
                    // TODO: this is completely racy, as the `connection_id` can be obsolete
                    // TODO: log the response
                    self.server.queue_send(connection_id, response);
                }
            };
        }
    }
}

fn spawn_client_io_task(
    tasks_executor: &Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,
    mut from_background: async_channel::Receiver<String>,
    to_background: async_channel::Sender<(websocket_server::ConnectionId, String)>,
    io: service::SerializedRequestsIo,
    connection_id: websocket_server::ConnectionId,
) {
    tasks_executor(Box::pin(async move {
        loop {
            match future::or(
                async { either::Left(from_background.next().await) },
                async { either::Right(io.wait_next_response().await) },
            )
            .await
            {
                either::Left(None) => return,
                either::Left(Some(request)) => {
                    match io.try_send_request(request) {
                        Ok(()) => {}
                        Err(service::TrySendRequestError {
                            cause: service::TrySendRequestErrorCause::MalformedJson(_),
                            ..
                        }) => {}
                        Err(service::TrySendRequestError {
                            cause: service::TrySendRequestErrorCause::ClientMainTaskDestroyed,
                            ..
                        }) => {
                            unreachable!()
                        }
                        Err(service::TrySendRequestError {
                            cause: service::TrySendRequestErrorCause::TooManyPendingRequests,
                            ..
                        }) => {
                            // TODO: shouldn't use `try_send_request` but just a blocking `send_request`
                            todo!()
                        }
                    }
                }
                either::Right(Ok(response)) => {
                    let _ = to_background.send((connection_id, response)).await;
                }
                either::Right(Err(service::WaitNextResponseError::ClientMainTaskDestroyed)) => {
                    unreachable!()
                }
            }
        }
    }));
}

fn spawn_client_main_task(
    tasks_executor: &Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,
    to_requests_handlers: async_channel::Sender<requests_handler::Message>,
    mut client_main_task: service::ClientMainTask,
) {
    tasks_executor(Box::pin(async move {
        loop {
            match client_main_task.run_until_event().await {
                service::Event::HandleRequest {
                    task,
                    request_process,
                } => {
                    client_main_task = task;
                    to_requests_handlers
                        .send(requests_handler::Message::Request(request_process))
                        .await
                        .unwrap();
                }
                service::Event::HandleSubscriptionStart {
                    task,
                    subscription_start,
                } => {
                    client_main_task = task;
                    to_requests_handlers
                        .send(requests_handler::Message::SubscriptionStart(
                            subscription_start,
                        ))
                        .await
                        .unwrap();
                }
                service::Event::SubscriptionDestroyed { task, .. } => {
                    client_main_task = task;
                }
                service::Event::SerializedRequestsIoClosed => {
                    // JSON-RPC client has disconnected.
                    return;
                }
            }
        }
    }));
}
