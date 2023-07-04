// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

use core::num::NonZeroUsize;

use alloc::{borrow::ToOwned as _, boxed::Box, format, string::String, sync::Arc};
use async_lock::Mutex;
use futures_channel::oneshot;
use futures_lite::{FutureExt as _, StreamExt as _};
use futures_util::{future, stream::AbortRegistration, FutureExt as _};
use smoldot::{
    header,
    informant::HashDisplay,
    json_rpc::{methods, service},
};

use crate::{platform::PlatformRef, runtime_service};

use super::Cache;

pub(super) enum Message<TPlat: PlatformRef> {
    SubscriptionStart(service::SubscriptionStartProcess),
    SubscriptionDestroyed {
        subscription_id: String,
    },
    RecentBlockRuntimeAccess {
        block_hash: [u8; 32],
        result_tx: oneshot::Sender<Option<runtime_service::RuntimeAccess<TPlat>>>,
    },
}

// Spawn one task dedicated to filling the `Cache` with new blocks from the runtime service.
pub(super) fn start_task<TPlat: PlatformRef>(
    cache: Arc<Mutex<Cache>>,
    platform: TPlat,
    log_target: String,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    requests_rx: async_channel::Receiver<Message<TPlat>>,
    abort_registration: AbortRegistration,
) {
    // TODO: this is actually racy, as a block subscription task could report a new block to a client, and then client can query it, before this block has been been added to the cache
    // TODO: extract to separate function
    platform.clone().spawn_task(
        format!("{}-cache-populate", log_target).into(),
        Box::pin({
            future::Abortable::new(
                async move {
                    loop {
                        let mut cache_lock = cache.lock().await;

                        // Subscribe to new runtime service blocks in order to push them in the
                        // cache as soon as they are available.
                        // The buffer size should be large enough so that, if the CPU is busy, it
                        // doesn't become full before the execution of this task resumes.
                        // The maximum number of pinned block is ignored, as this maximum is a way to
                        // avoid malicious behaviors. This code is by definition not considered
                        // malicious.
                        let subscribe_all = runtime_service
                            .subscribe_all(
                                "json-rpc-blocks-cache",
                                32,
                                NonZeroUsize::new(usize::max_value()).unwrap(),
                            )
                            .await;

                        cache_lock.subscription_id = Some(subscribe_all.new_blocks.id());
                        cache_lock.recent_pinned_blocks.clear();
                        debug_assert!(cache_lock.recent_pinned_blocks.cap().get() >= 1);

                        let finalized_block_hash = header::hash_from_scale_encoded_header(
                            &subscribe_all.finalized_block_scale_encoded_header,
                        );
                        cache_lock.recent_pinned_blocks.put(
                            finalized_block_hash,
                            subscribe_all.finalized_block_scale_encoded_header,
                        );

                        for block in subscribe_all.non_finalized_blocks_ancestry_order {
                            if cache_lock.recent_pinned_blocks.len()
                                == cache_lock.recent_pinned_blocks.cap().get()
                            {
                                let (hash, _) = cache_lock.recent_pinned_blocks.pop_lru().unwrap();
                                subscribe_all.new_blocks.unpin_block(&hash).await;
                            }

                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            cache_lock
                                .recent_pinned_blocks
                                .put(hash, block.scale_encoded_header);
                        }

                        drop(cache_lock);

                        run(Task {
                            cache: cache.clone(),
                            log_target: log_target.clone(),
                            runtime_service,
                            new_blocks: subscribe_all.new_blocks,
                            requests_rx,
                            // TODO: all the subscriptions are dropped if the task returns
                            all_heads_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                                8,
                                Default::default(),
                            ),
                            new_heads_subscriptions: hashbrown::HashMap::with_capacity_and_hasher(
                                8,
                                Default::default(),
                            ),
                        })
                        .await;

                        panic!() // TODO: not implemented correctly
                    }
                },
                abort_registration,
            )
            .map(|_: Result<(), _>| ())
        }),
    );
}

struct Task<TPlat: PlatformRef> {
    cache: Arc<Mutex<Cache>>,
    log_target: String,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    new_blocks: runtime_service::Subscription<TPlat>,
    requests_rx: async_channel::Receiver<Message<TPlat>>,
    // TODO: shrink_to_fit?
    all_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
    // TODO: shrink_to_fit?
    new_heads_subscriptions: hashbrown::HashMap<String, service::Subscription, fnv::FnvBuildHasher>,
}

async fn run<TPlat: PlatformRef>(mut task: Task<TPlat>) {
    loop {
        match task
            .new_blocks
            .next()
            .map(either::Left)
            .or(task.requests_rx.next().map(either::Right))
            .await
        {
            either::Left(Some(runtime_service::Notification::Block(block))) => {
                let mut cache = task.cache.lock().await;

                if cache.recent_pinned_blocks.len() == cache.recent_pinned_blocks.cap().get() {
                    let (hash, _) = cache.recent_pinned_blocks.pop_lru().unwrap();
                    task.new_blocks.unpin_block(&hash).await;
                }

                let json_rpc_header = match methods::Header::from_scale_encoded_header(
                    &block.scale_encoded_header,
                    task.runtime_service.block_number_bytes(),
                ) {
                    Ok(h) => h,
                    Err(error) => {
                        log::warn!(
                            target: &task.log_target,
                            "`chain_subscribeAllHeads` or `chain_subscribeNewHeads` subscription \
                            has skipped block due to undecodable header. Hash: {}. Error: {}",
                            HashDisplay(&header::hash_from_scale_encoded_header(
                                &block.scale_encoded_header
                            )),
                            error,
                        );
                        continue;
                    }
                };

                let hash = header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                cache
                    .recent_pinned_blocks
                    .put(hash, block.scale_encoded_header);

                drop(cache);

                for (subscription_id, subscription) in &mut task.all_heads_subscriptions {
                    subscription
                        .send_notification(methods::ServerToClient::chain_allHead {
                            subscription: subscription_id.as_str().into(),
                            result: json_rpc_header.clone(),
                        })
                        .await;
                }

                if block.is_new_best {
                    for (subscription_id, subscription) in &mut task.new_heads_subscriptions {
                        subscription
                            .send_notification(methods::ServerToClient::chain_newHead {
                                subscription: subscription_id.as_str().into(),
                                result: json_rpc_header.clone(),
                            })
                            .await;
                    }
                }
            }
            either::Left(Some(runtime_service::Notification::Finalized { .. })) => {}
            either::Left(Some(runtime_service::Notification::BestBlockChanged {
                hash, ..
            })) => {
                // TODO: report a chain_newHead subscription
            }

            either::Right(Some(Message::SubscriptionStart(request))) => match request.request() {
                methods::MethodCall::chain_subscribeAllHeads {} => {
                    let subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    task.all_heads_subscriptions
                        .insert(subscription_id, subscription);
                }
                methods::MethodCall::chain_subscribeNewHeads {} => {
                    let subscription = request.accept();
                    let subscription_id = subscription.subscription_id().to_owned();
                    // TODO: must immediately send the current best block
                    task.new_heads_subscriptions
                        .insert(subscription_id, subscription);
                }
                _ => unreachable!(), // TODO: stronger typing to avoid this?
            },

            either::Right(Some(Message::SubscriptionDestroyed { subscription_id })) => {
                task.all_heads_subscriptions.remove(&subscription_id);
                task.new_heads_subscriptions.remove(&subscription_id);
                // TODO: shrink_to_fit?
            }

            either::Right(Some(Message::RecentBlockRuntimeAccess {
                block_hash,
                result_tx,
            })) => {
                let cache_lock = task.cache.lock().await;
                let access = if cache_lock.recent_pinned_blocks.contains(&block_hash) {
                    // The runtime service has the block pinned, meaning that we can ask the runtime
                    // service to perform the call.
                    task.runtime_service
                        .pinned_block_runtime_access(
                            cache_lock.subscription_id.unwrap(),
                            &block_hash,
                        )
                        .await
                        .ok()
                } else {
                    None
                };

                let _ = result_tx.send(access);
            }

            either::Left(None) | either::Right(None) => {
                break;
            }
        }
    }
}
