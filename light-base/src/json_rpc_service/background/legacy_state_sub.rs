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

use alloc::{format, sync::Arc};
use futures_util::{future, stream::AbortRegistration, FutureExt};
use smoldot::header;

use crate::{platform::PlatformRef, runtime_service};

use super::Background;

// Spawn one task dedicated to filling the `Cache` with new blocks from the runtime service.
pub(super) fn start_task<TPlat: PlatformRef>(
    me: Arc<Background<TPlat>>,
    abort_registration: AbortRegistration,
) {
    // TODO: this is actually racy, as a block subscription task could report a new block to a client, and then client can query it, before this block has been been added to the cache
    // TODO: extract to separate function
    me.platform
        .clone()
        .spawn_task(format!("{}-cache-populate", me.log_target).into(), {
            future::Abortable::new(
                async move {
                    loop {
                        let mut cache = me.cache.lock().await;

                        // Subscribe to new runtime service blocks in order to push them in the
                        // cache as soon as they are available.
                        // The buffer size should be large enough so that, if the CPU is busy, it
                        // doesn't become full before the execution of this task resumes.
                        // The maximum number of pinned block is ignored, as this maximum is a way to
                        // avoid malicious behaviors. This code is by definition not considered
                        // malicious.
                        let mut subscribe_all = me
                            .runtime_service
                            .subscribe_all(
                                "json-rpc-blocks-cache",
                                32,
                                NonZeroUsize::new(usize::max_value()).unwrap(),
                            )
                            .await;

                        cache.subscription_id = Some(subscribe_all.new_blocks.id());
                        cache.recent_pinned_blocks.clear();
                        debug_assert!(cache.recent_pinned_blocks.cap().get() >= 1);

                        let finalized_block_hash = header::hash_from_scale_encoded_header(
                            &subscribe_all.finalized_block_scale_encoded_header,
                        );
                        cache.recent_pinned_blocks.put(
                            finalized_block_hash,
                            subscribe_all.finalized_block_scale_encoded_header,
                        );

                        for block in subscribe_all.non_finalized_blocks_ancestry_order {
                            if cache.recent_pinned_blocks.len()
                                == cache.recent_pinned_blocks.cap().get()
                            {
                                let (hash, _) = cache.recent_pinned_blocks.pop_lru().unwrap();
                                subscribe_all.new_blocks.unpin_block(&hash).await;
                            }

                            let hash =
                                header::hash_from_scale_encoded_header(&block.scale_encoded_header);
                            cache
                                .recent_pinned_blocks
                                .put(hash, block.scale_encoded_header);
                        }

                        drop(cache);

                        loop {
                            let notification = subscribe_all.new_blocks.next().await;
                            match notification {
                                Some(runtime_service::Notification::Block(block)) => {
                                    let mut cache = me.cache.lock().await;

                                    if cache.recent_pinned_blocks.len()
                                        == cache.recent_pinned_blocks.cap().get()
                                    {
                                        let (hash, _) =
                                            cache.recent_pinned_blocks.pop_lru().unwrap();
                                        subscribe_all.new_blocks.unpin_block(&hash).await;
                                    }

                                    let hash = header::hash_from_scale_encoded_header(
                                        &block.scale_encoded_header,
                                    );
                                    cache
                                        .recent_pinned_blocks
                                        .put(hash, block.scale_encoded_header);
                                }
                                Some(runtime_service::Notification::Finalized { .. })
                                | Some(runtime_service::Notification::BestBlockChanged {
                                    ..
                                }) => {}
                                None => break,
                            }
                        }
                    }
                },
                abort_registration,
            )
            .map(|_: Result<(), _>| ())
            .boxed()
        });
}
