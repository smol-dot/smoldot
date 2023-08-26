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
use futures_util::FutureExt;
use smol::{
    future,
    net::{TcpListener, TcpStream},
};
use smoldot::json_rpc::service;
use std::{
    future::Future,
    io, mem,
    net::SocketAddr,
    num::NonZeroU32,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

pub use service::ParseError as RequestParseError;

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

    /// Maximum number of JSON-RPC clients until new ones are rejected.
    pub max_json_rpc_clients: u32,

    /// Name of the chain, as found in the chain specification.
    pub chain_name: String,

    /// JSON-encoded properties of the chain, as found in the chain specification.
    pub chain_properties_json: String,

    /// Hash of the genesis block.
    pub genesis_block_hash: [u8; 32],
}

/// Running JSON-RPC service. Holds a server open for as long as it is alive.
///
/// In addition to a TCP/IP server, this service also provides a virtual JSON-RPC endpoint that
/// can be used through [`JsonRpcService::send_request`] and [`JsonRpcService::next_response`].
pub struct JsonRpcService {
    /// This events listener is notified when the service is dropped.
    service_dropped: event_listener::Event,

    /// Address the server is listening on. Not necessarily equal to [`Config::bind_address`].
    listen_addr: SocketAddr,

    /// I/O for the virtual endpoint.
    virtual_client_io: service::SerializedRequestsIo,
}

impl Drop for JsonRpcService {
    fn drop(&mut self) {
        self.service_dropped.notify(usize::max_value());
    }
}

impl JsonRpcService {
    /// Initializes a new [`JsonRpcService`].
    pub async fn new(config: Config) -> Result<Self, InitError> {
        let tcp_listener = match TcpListener::bind(&config.bind_address).await {
            Ok(s) => s,
            Err(error) => {
                return Err(InitError::ListenError {
                    bind_address: config.bind_address,
                    error,
                })
            }
        };

        let listen_addr = match tcp_listener.local_addr() {
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

        let (virtual_client_main_task, virtual_client_io) =
            service::client_main_task(service::Config {
                max_active_subscriptions: u32::max_value(),
                max_pending_requests: NonZeroU32::new(u32::max_value()).unwrap(),
            });

        spawn_client_main_task(
            &config.tasks_executor,
            to_requests_handlers.clone(),
            virtual_client_main_task,
        );

        for _ in 0..config.max_parallel_requests {
            requests_handler::spawn_requests_handler(requests_handler::Config {
                tasks_executor: config.tasks_executor.clone(),
                receiver: from_background.clone(),
                chain_name: config.chain_name.clone(),
                chain_properties_json: config.chain_properties_json.clone(),
                genesis_block_hash: config.genesis_block_hash,
            });
        }

        let background = JsonRpcBackground {
            tcp_listener,
            on_service_dropped,
            tasks_executor: config.tasks_executor.clone(),
            log_callback: config.log_callback,
            to_requests_handlers,
            num_json_rpc_clients: Arc::new(AtomicU32::new(0)),
            max_json_rpc_clients: config.max_json_rpc_clients,
        };

        (config.tasks_executor)(Box::pin(async move { background.run().await }));

        Ok(JsonRpcService {
            service_dropped,
            listen_addr,
            virtual_client_io,
        })
    }

    /// Returns the address the server is listening on. Not necessarily equal
    /// to [`Config::bind_address`].
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr.clone()
    }

    /// Adds a JSON-RPC request to the queue of requests of the virtual endpoint.
    ///
    /// The virtual endpoint doesn't have any limit.
    ///
    /// Returns an error if the JSON-RPC request is malformed.
    pub fn send_request(&self, request: String) -> Result<(), RequestParseError> {
        match self.virtual_client_io.try_send_request(request) {
            Ok(()) => Ok(()),
            Err(err) => match err.cause {
                service::TrySendRequestErrorCause::MalformedJson(err) => return Err(err),
                service::TrySendRequestErrorCause::TooManyPendingRequests
                | service::TrySendRequestErrorCause::ClientMainTaskDestroyed => unreachable!(),
            },
        }
    }

    /// Returns the new JSON-RPC response or notification for requests sent using
    /// [`JsonRpcService::send_request`].
    ///
    /// If this function is called multiple times simultaneously, only one invocation will receive
    /// each response. Which one is unspecified.
    pub async fn next_response(&self) -> String {
        match self.virtual_client_io.wait_next_response().await {
            Ok(r) => r,
            Err(service::WaitNextResponseError::ClientMainTaskDestroyed) => unreachable!(),
        }
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
    /// TCP listener for new incoming connections.
    tcp_listener: TcpListener,

    /// Event notified when the frontend is dropped.
    on_service_dropped: event_listener::EventListener,

    /// See [`Config::tasks_executor`].
    tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// See [`Config::log_callback`].
    log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Channel used to send requests to the tasks that process said requests.
    to_requests_handlers: async_channel::Sender<requests_handler::Message>,

    /// Number of clients currently alive.
    num_json_rpc_clients: Arc<AtomicU32>,

    /// See [`Config::max_json_rpc_clients`].
    max_json_rpc_clients: u32,
}

impl JsonRpcBackground {
    async fn run(mut self) {
        loop {
            let Some(accept_result) = future::or(
                async {
                    (&mut self.on_service_dropped).await;
                    None
                },
                async { Some(self.tcp_listener.accept().await) },
            )
            .await
            else {
                return;
            };

            let (tcp_socket, address) = match accept_result {
                Ok(v) => v,
                Err(error) => {
                    // Failing to accept an incoming TCP connection generally happens due to
                    // the limit of file descriptors being reached.
                    // Sleep a little bit and try again.
                    self.log_callback.log(
                        LogLevel::Warn,
                        format!("json-rpc-tcp-listener-error; error={error}"),
                    );
                    smol::Timer::after(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // New incoming TCP connection.

            // Try to increase `num_json_rpc_clients`. Fails if the maximum is reached.
            if self
                .num_json_rpc_clients
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                    if old_value < self.max_json_rpc_clients {
                        // Considering that `old_value < max`, and `max` fits in a `u32` by
                        // definition, then `old_value + 1` also always fits in a `u32`. QED.
                        // There's no risk of overflow.
                        Some(old_value + 1)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                // Reject the socket without sending back anything. Sending back a status
                // code would require allocating resources for that socket, which we
                // specifically don't want to do.
                self.log_callback.log(
                    LogLevel::Debug,
                    format!("json-rpc-incoming-connection-rejected; address={}", address),
                );
                smol::Timer::after(Duration::from_millis(50)).await;
                continue;
            }

            // Spawn two tasks: one for the socket I/O, and one to process requests.
            self.log_callback.log(
                LogLevel::Debug,
                format!("json-rpc-incoming-connection; address={}", address),
            );
            let (client_main_task, io) = service::client_main_task(service::Config {
                max_active_subscriptions: 128,
                max_pending_requests: NonZeroU32::new(64).unwrap(),
            });
            spawn_client_io_task(
                &self.tasks_executor,
                self.log_callback.clone(),
                tcp_socket,
                address,
                io,
                self.num_json_rpc_clients.clone(),
            );
            spawn_client_main_task(
                &self.tasks_executor,
                self.to_requests_handlers.clone(),
                client_main_task,
            );
        }
    }
}

fn spawn_client_io_task(
    tasks_executor: &Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,
    log_callback: Arc<dyn LogCallback + Send + Sync>,
    tcp_socket: TcpStream,
    socket_address: SocketAddr,
    io: service::SerializedRequestsIo,
    num_json_rpc_clients: Arc<AtomicU32>,
) {
    let run_future = async move {
        // Perform the WebSocket handshake.
        let (mut ws_sender, mut ws_receiver) = {
            let mut ws_server = soketto::handshake::Server::new(tcp_socket);

            // TODO: enabling the `deflate` extension leads to "flate stream corrupted" errors
            //let deflate = soketto::extension::deflate::Deflate::new(soketto::Mode::Server);
            //ws_server.add_extension(Box::new(deflate));

            let key = match ws_server.receive_request().await {
                Ok(req) => req.key(),
                Err(error) => {
                    log_callback.log(
                        LogLevel::Debug,
                        format!(
                            "json-rpc-connection-error; address={socket_address}, error={error}"
                        ),
                    );
                    return;
                }
            };

            let accept = soketto::handshake::server::Response::Accept {
                key,
                protocol: None,
            };

            match ws_server.send_response(&accept).await {
                Ok(()) => {}
                Err(error) => {
                    log_callback.log(
                        LogLevel::Debug,
                        format!(
                            "json-rpc-connection-error; address={socket_address}, error={error}"
                        ),
                    );
                    return;
                }
            }

            ws_server.into_builder().finish()
        };

        // Create a future responsible for pulling responses and sending them back.
        let sending_future = async {
            let mut must_flush_asap = false;

            loop {
                // If `must_flush_asap`, we simply peek for the next response but without awaiting.
                // If `!must_flush_asap`, we wait for as long as necessary.
                let maybe_response = if must_flush_asap {
                    io.wait_next_response().now_or_never()
                } else {
                    Some(io.wait_next_response().await)
                };

                match maybe_response {
                    None => {
                        if let Err(err) = ws_sender.flush().await {
                            break Err(err.to_string());
                        }
                        must_flush_asap = false;
                    }
                    Some(Ok(response)) => {
                        log_callback.log(
                            LogLevel::Debug,
                            format!(
                                "json-rpc-response; address={}; response={}",
                                socket_address,
                                crate::util::truncated_str(
                                    response.chars().filter(|c| !c.is_control()),
                                    128
                                )
                            ),
                        );

                        if let Err(err) = ws_sender.send_text_owned(response).await {
                            break Err(err.to_string());
                        }
                        must_flush_asap = true;
                    }
                    Some(Err(service::WaitNextResponseError::ClientMainTaskDestroyed)) => {
                        // The client main task never closes by itself but only as a consequence
                        // to the I/O task closing.
                        unreachable!()
                    }
                };
            }
        };

        // Create a future responsible for pulling messages from the socket and sending them to
        // the main task.
        let receiving_future = async {
            let mut message = Vec::new();
            loop {
                message.clear();

                match ws_receiver.receive_data(&mut message).await {
                    Ok(soketto::Data::Binary(_)) => {
                        break Err("Unexpected binary frame".to_string());
                    }
                    Ok(soketto::Data::Text(_)) => {} // Handled below.
                    Err(soketto::connection::Error::Closed) => break Ok(()),
                    Err(err) => {
                        break Err(err.to_string());
                    }
                }

                let request = match String::from_utf8(mem::take(&mut message)) {
                    Ok(r) => r,
                    Err(error) => {
                        break Err(format!("Non-UTF8 text frame: {error}"));
                    }
                };

                log_callback.log(
                    LogLevel::Debug,
                    format!(
                        "json-rpc-request; address={}; request={}",
                        socket_address,
                        crate::util::truncated_str(
                            request.chars().filter(|c| !c.is_control()),
                            128
                        )
                    ),
                );

                match io.send_request(request).await {
                    Ok(()) => {}
                    Err(service::SendRequestError {
                        cause: service::SendRequestErrorCause::ClientMainTaskDestroyed,
                        ..
                    }) => {
                        // The client main task never closes by itself but only as a
                        // consequence to the I/O task closing.
                        unreachable!()
                    }
                    Err(service::SendRequestError {
                        cause: service::SendRequestErrorCause::MalformedJson(error),
                        ..
                    }) => {
                        break Err(format!("Malformed JSON-RPC request: {error}"));
                    }
                }
            }
        };

        // Run these two futures until completion.
        match future::or(sending_future, receiving_future).await {
            Ok(()) => {
                log_callback.log(
                    LogLevel::Debug,
                    format!("json-rpc-connection-closed; address={socket_address}"),
                );
            }
            Err(error) => {
                log_callback.log(
                    LogLevel::Debug,
                    format!("json-rpc-connection-error; address={socket_address}, error={error}"),
                );
            }
        }
    };

    tasks_executor(Box::pin(async move {
        run_future.await;
        num_json_rpc_clients.fetch_sub(1, Ordering::Release);
    }))
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
