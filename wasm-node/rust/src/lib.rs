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

//! Contains a light client implementation usable from a browser environment.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(unused_crate_dependencies)]

extern crate alloc;

use alloc::{
    boxed::Box,
    string::{String, ToString as _},
    sync::Arc,
    vec::Vec,
};
use async_lock::Mutex;
use core::{num::NonZeroU32, pin::Pin, str, task};
use futures_util::{stream, Stream as _, StreamExt as _};
use smoldot_light::HandleRpcError;

pub mod bindings;

mod allocator;
mod init;
mod platform;
mod timers;

static CLIENT: Mutex<init::Client<platform::PlatformRef, ()>> = Mutex::new(init::Client {
    smoldot: smoldot_light::Client::new(platform::PLATFORM_REF),
    chains: slab::Slab::new(),
});

fn init(max_log_level: u32) {
    init::init(max_log_level);
}

fn add_chain(
    chain_spec: Vec<u8>,
    database_content: Vec<u8>,
    json_rpc_max_pending_requests: u32,
    json_rpc_max_subscriptions: u32,
    potential_relay_chains: Vec<u8>,
) -> u32 {
    let mut client_lock = CLIENT.try_lock().unwrap();

    // Fail any new chain initialization if we're running low on memory space, which can
    // realistically happen as Wasm is a 32 bits platform. This avoids potentially running into
    // OOM errors. The threshold is completely empirical and should probably be updated
    // regularly to account for changes in the implementation.
    if allocator::total_alloc_bytes() >= usize::max_value() - 400 * 1024 * 1024 {
        let chain_id = client_lock.chains.insert(init::Chain::Erroneous {
            error:
                "Wasm node is running low on memory and will prevent any new chain from being added"
                    .into(),
        });

        return u32::try_from(chain_id).unwrap();
    }

    // Retrieve the potential relay chains parameter passed through the FFI layer.
    let potential_relay_chains: Vec<_> = {
        assert_eq!(potential_relay_chains.len() % 4, 0);
        potential_relay_chains
            .chunks(4)
            .map(|c| u32::from_le_bytes(<[u8; 4]>::try_from(c).unwrap()))
            .filter_map(|c| {
                if let Some(init::Chain::Healthy {
                    smoldot_chain_id, ..
                }) = client_lock.chains.get(usize::try_from(c).ok()?)
                {
                    Some(*smoldot_chain_id)
                } else {
                    None
                }
            })
            .collect()
    };

    // Insert the chain in the client.
    let smoldot_light::AddChainSuccess {
        chain_id: smoldot_chain_id,
        json_rpc_responses,
    } = match client_lock
        .smoldot
        .add_chain(smoldot_light::AddChainConfig {
            user_data: (),
            specification: str::from_utf8(&chain_spec)
                .unwrap_or_else(|_| panic!("non-utf8 chain spec")),
            database_content: str::from_utf8(&database_content)
                .unwrap_or_else(|_| panic!("non-utf8 database content")),
            json_rpc: if let Some(json_rpc_max_pending_requests) =
                NonZeroU32::new(json_rpc_max_pending_requests)
            {
                smoldot_light::AddChainConfigJsonRpc::Enabled {
                    max_pending_requests: json_rpc_max_pending_requests,
                    // Note: the PolkadotJS UI is very heavy in terms of subscriptions.
                    max_subscriptions: json_rpc_max_subscriptions,
                }
            } else {
                smoldot_light::AddChainConfigJsonRpc::Disabled
            },
            potential_relay_chains: potential_relay_chains.into_iter(),
        }) {
        Ok(c) => c,
        Err(error) => {
            let chain_id = client_lock.chains.insert(init::Chain::Erroneous {
                error: error.to_string(),
            });

            return u32::try_from(chain_id).unwrap();
        }
    };

    let outer_chain_id = client_lock.chains.insert(init::Chain::Healthy {
        smoldot_chain_id,
        json_rpc_response: None,
        json_rpc_response_info: Box::new(bindings::JsonRpcResponseInfo { ptr: 0, len: 0 }),
        json_rpc_responses_rx: None,
    });

    let outer_chain_id_u32 = u32::try_from(outer_chain_id).unwrap();

    // We wrap the JSON-RPC responses stream into a proper stream in order to be able to guarantee
    // that `poll_next()` always operates on the same future.
    let json_rpc_responses = json_rpc_responses.map(|json_rpc_responses| {
        stream::unfold(json_rpc_responses, |mut json_rpc_responses| async {
            // The stream ends when we remove the chain. Once the chain is removed, the user
            // cannot poll the stream anymore. Therefore it is safe to unwrap the result here.
            let msg = json_rpc_responses.next().await.unwrap();
            Some((msg, json_rpc_responses))
        })
        .boxed()
    });

    if let init::Chain::Healthy {
        json_rpc_responses_rx,
        ..
    } = client_lock.chains.get_mut(outer_chain_id).unwrap()
    {
        *json_rpc_responses_rx = json_rpc_responses;
    }

    outer_chain_id_u32
}

fn remove_chain(chain_id: u32) {
    let mut client_lock = CLIENT.try_lock().unwrap();

    match client_lock
        .chains
        .remove(usize::try_from(chain_id).unwrap())
    {
        init::Chain::Healthy {
            smoldot_chain_id,
            json_rpc_responses_rx,
            ..
        } => {
            // We've polled the JSON-RPC receiver with a waker that calls
            // `json_rpc_responses_non_empty`. Once the sender is destroyed, this waker will be
            // called in order to inform of the destruction. We don't want that to happen.
            // Therefore, we poll the receiver again with a dummy "no-op" waker for the sole
            // purpose of erasing the previously-registered waker.
            if let Some(mut json_rpc_responses_rx) = json_rpc_responses_rx {
                let _ = Pin::new(&mut json_rpc_responses_rx).poll_next(
                    &mut task::Context::from_waker(futures_util::task::noop_waker_ref()),
                );
            }

            let () = client_lock.smoldot.remove_chain(smoldot_chain_id);
        }
        init::Chain::Erroneous { .. } => {}
    }
}

fn chain_is_ok(chain_id: u32) -> u32 {
    let client_lock = CLIENT.try_lock().unwrap();
    if matches!(
        client_lock
            .chains
            .get(usize::try_from(chain_id).unwrap())
            .unwrap(),
        init::Chain::Healthy { .. }
    ) {
        1
    } else {
        0
    }
}

fn chain_error_len(chain_id: u32) -> u32 {
    let client_lock = CLIENT.try_lock().unwrap();
    match client_lock
        .chains
        .get(usize::try_from(chain_id).unwrap())
        .unwrap()
    {
        init::Chain::Healthy { .. } => 0,
        init::Chain::Erroneous { error } => u32::try_from(error.as_bytes().len()).unwrap(),
    }
}

fn chain_error_ptr(chain_id: u32) -> u32 {
    let client_lock = CLIENT.try_lock().unwrap();
    match client_lock
        .chains
        .get(usize::try_from(chain_id).unwrap())
        .unwrap()
    {
        init::Chain::Healthy { .. } => 0,
        init::Chain::Erroneous { error } => {
            u32::try_from(error.as_bytes().as_ptr() as usize).unwrap()
        }
    }
}

fn json_rpc_send(json_rpc_request: Vec<u8>, chain_id: u32) -> u32 {
    // As mentioned in the documentation, the bytes *must* be valid UTF-8.
    let json_rpc_request: String = String::from_utf8(json_rpc_request)
        .unwrap_or_else(|_| panic!("non-UTF-8 JSON-RPC request"));

    let mut client_lock = CLIENT.try_lock().unwrap();
    let client_chain_id = match client_lock
        .chains
        .get(usize::try_from(chain_id).unwrap())
        .unwrap()
    {
        init::Chain::Healthy {
            smoldot_chain_id, ..
        } => *smoldot_chain_id,
        init::Chain::Erroneous { .. } => panic!(),
    };

    match client_lock
        .smoldot
        .json_rpc_request(json_rpc_request, client_chain_id)
    {
        Ok(()) => 0,
        Err(HandleRpcError::TooManyPendingRequests { .. }) => 1,
    }
}

fn json_rpc_responses_peek(chain_id: u32) -> u32 {
    let mut client_lock = CLIENT.try_lock().unwrap();
    match client_lock
        .chains
        .get_mut(usize::try_from(chain_id).unwrap())
        .unwrap()
    {
        init::Chain::Healthy {
            json_rpc_response,
            json_rpc_responses_rx,
            json_rpc_response_info,
            ..
        } => {
            if json_rpc_response.is_none() {
                if let Some(json_rpc_responses_rx) = json_rpc_responses_rx.as_mut() {
                    loop {
                        match Pin::new(&mut *json_rpc_responses_rx).poll_next(
                            &mut task::Context::from_waker(
                                &Arc::new(JsonRpcResponsesNonEmptyWaker { chain_id }).into(),
                            ),
                        ) {
                            task::Poll::Ready(Some(response)) if response.is_empty() => {
                                // The API of `json_rpc_responses_peek` says that a length of 0
                                // indicates that the queue is empty. For this reason, we skip
                                // this response.
                                // This is a pretty niche situation, but at least we handle it
                                // properly.
                            }
                            task::Poll::Ready(Some(response)) => {
                                debug_assert!(!response.is_empty());
                                *json_rpc_response = Some(response);
                                break;
                            }
                            task::Poll::Ready(None) => unreachable!(),
                            task::Poll::Pending => break,
                        }
                    }
                }
            }

            // Note that we might be returning the last item in the queue. In principle, this means
            // that the next time an entry is added to the queue, `json_rpc_responses_non_empty`
            // should be called. Due to the way the implementation works, this will not happen
            // until the user calls `json_rpc_responses_peek`. However, this is not a problem:
            // it is impossible for the user to observe that the queue is empty, and as such there
            // is simply not correct implementation of the API that can't work because of this
            // property.

            match &json_rpc_response {
                Some(rp) => {
                    debug_assert!(!rp.is_empty());
                    json_rpc_response_info.ptr = rp.as_bytes().as_ptr() as u32;
                    json_rpc_response_info.len = rp.as_bytes().len() as u32;
                }
                None => {
                    json_rpc_response_info.ptr = 0;
                    json_rpc_response_info.len = 0;
                }
            }

            (&**json_rpc_response_info) as *const bindings::JsonRpcResponseInfo as usize as u32
        }
        _ => panic!(),
    }
}

fn json_rpc_responses_pop(chain_id: u32) {
    let mut client_lock = CLIENT.try_lock().unwrap();
    match client_lock
        .chains
        .get_mut(usize::try_from(chain_id).unwrap())
        .unwrap()
    {
        init::Chain::Healthy {
            json_rpc_response, ..
        } => *json_rpc_response = None,
        _ => panic!(),
    }
}

struct JsonRpcResponsesNonEmptyWaker {
    chain_id: u32,
}

impl alloc::task::Wake for JsonRpcResponsesNonEmptyWaker {
    fn wake(self: Arc<Self>) {
        unsafe { bindings::json_rpc_responses_non_empty(self.chain_id) }
    }
}

/// List of light tasks waiting to be executed.
static TASKS_QUEUE: crossbeam_queue::SegQueue<async_task::Runnable> =
    crossbeam_queue::SegQueue::new();

fn advance_execution() {
    // This function executes one task then returns. This ensures that the Wasm doesn't use up
    // all the available CPU of the host.

    let Some(runnable) = TASKS_QUEUE.pop() else {
        return;
    };

    runnable.run();

    if !TASKS_QUEUE.is_empty() {
        unsafe {
            bindings::advance_execution_ready();
        }
    }
}
