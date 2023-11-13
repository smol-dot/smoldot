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

use crate::{database_thread, LogCallback};

use futures_channel::oneshot;
use futures_lite::{Future, StreamExt as _};
use smol::lock::Mutex;
use smoldot::{executor, trie};
use std::{
    iter,
    num::NonZeroUsize,
    pin::{self, Pin},
    sync::Arc,
};

/// Configuration of the service.
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Database to access blocks.
    pub database: Arc<database_thread::DatabaseThread>,

    /// Number of entries in the cache of runtimes.
    pub num_cache_entries: NonZeroUsize,
}

/// A running runtime caches service.
pub struct RuntimeCachesService {
    to_background: Mutex<async_channel::Sender<Message>>,
}

/// Message sent from the frontend to the background task.
enum Message {
    Get {
        block_hash: [u8; 32],
        result_tx: oneshot::Sender<Result<Arc<executor::host::HostVmPrototype>, GetError>>,
    },
}

impl RuntimeCachesService {
    /// Start a new service.
    pub fn new(config: Config) -> Self {
        let (to_background, from_foreground) = async_channel::bounded(16);

        (config.tasks_executor)(Box::pin(async move {
            let mut from_foreground = pin::pin!(from_foreground);
            let mut cache =
                lru::LruCache::<[u8; 32], Result<_, GetError>>::new(config.num_cache_entries);

            loop {
                match from_foreground.next().await {
                    Some(Message::Get {
                        block_hash,
                        result_tx,
                    }) => {
                        // Look in the cache.
                        if let Some(cache_entry) = cache.get(&block_hash) {
                            let _ = result_tx.send(cache_entry.clone());
                            continue;
                        }

                        let (code, heap_pages) = config
                            .database
                            .with_database(move |database| {
                                let code = database.block_storage_get(
                                    &block_hash,
                                    iter::empty::<iter::Empty<_>>(),
                                    trie::bytes_to_nibbles(b":code".iter().copied()).map(u8::from),
                                );
                                let heap_pages = database.block_storage_get(
                                    &block_hash,
                                    iter::empty::<iter::Empty<_>>(),
                                    trie::bytes_to_nibbles(b":heappages".iter().copied())
                                        .map(u8::from),
                                );
                                (code, heap_pages)
                            })
                            .await;

                        let runtime = match (code, heap_pages) {
                            (Ok(Some((code, _))), Ok(heap_pages)) => {
                                match executor::storage_heap_pages_to_value(
                                    heap_pages.as_ref().map(|(h, _)| &h[..]),
                                ) {
                                    Ok(heap_pages) => executor::host::HostVmPrototype::new(
                                        executor::host::Config {
                                            module: &code,
                                            heap_pages,
                                            exec_hint: executor::vm::ExecHint::CompileAheadOfTime,
                                            allow_unresolved_imports: true, // TODO: configurable? or if not, document
                                        },
                                    )
                                    .map_err(GetError::InvalidRuntime),
                                    Err(_) => Err(GetError::InvalidHeapPages),
                                }
                            }
                            (Ok(None), Ok(_)) => Err(GetError::NoCode),
                            (Err(database_thread::StorageAccessError::UnknownBlock), _)
                            | (_, Err(database_thread::StorageAccessError::UnknownBlock)) => {
                                // Note that we don't put the `CorruptedError` in the cache, in
                                // case the database somehow recovers.
                                let _ = result_tx.send(Err(GetError::UnknownBlock));
                                continue;
                            }
                            (Err(database_thread::StorageAccessError::StoragePruned), _)
                            | (_, Err(database_thread::StorageAccessError::StoragePruned)) => {
                                // Note that we don't put the `CorruptedError` in the cache, in
                                // case the database somehow recovers.
                                let _ = result_tx.send(Err(GetError::Pruned));
                                continue;
                            }
                            (Err(database_thread::StorageAccessError::Corrupted(_)), _)
                            | (_, Err(database_thread::StorageAccessError::Corrupted(_))) => {
                                // Note that we don't put the `CorruptedError` in the cache, in
                                // case the database somehow recovers.
                                let _ = result_tx.send(Err(GetError::CorruptedDatabase));
                                continue;
                            }
                        };

                        let runtime = runtime.map(Arc::new);
                        cache.put(block_hash, runtime.clone());
                        let _ = result_tx.send(runtime);
                    }
                    None => {
                        // Stop the service.
                        return;
                    }
                }
            }
        }));

        RuntimeCachesService {
            to_background: Mutex::new(to_background),
        }
    }

    /// Obtains the runtime corresponding to a certain block.
    pub async fn get(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Arc<executor::host::HostVmPrototype>, GetError> {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background
            .lock()
            .await
            .send(Message::Get {
                block_hash,
                result_tx,
            })
            .await;
        result_rx.await.unwrap()
    }
}

/// Error potentially returned by [`RuntimeCachesService::get`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum GetError {
    /// Requested block couldn't be found in the database.
    UnknownBlock,
    /// Storage of requested block is no longer in the database.
    Pruned,
    /// Block doesn't have any storage entry at the key `:code`.
    NoCode,
    /// Invalid storage entry at `:heappages`.
    InvalidHeapPages,
    /// Database is corrupted.
    CorruptedDatabase,
    /// Impossible to compile the runtime.
    InvalidRuntime(executor::host::NewErr),
}
