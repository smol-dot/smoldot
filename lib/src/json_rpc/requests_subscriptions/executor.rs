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

//! FIFO queue of futures.
//!
//! This module provides the [`TasksQueue`] struct, which consists in a queue of `future`s.
//! The futures in the queue must yield `()`.
//!
//! Use [`TasksQueue::push`] to add a future to the back of the queue.
//!
//! Use [`TasksQueue::run_one`] to pull a future from the queue and poll it. If the queue is
//! empty, this function waits until a future enters the queue. If the future finishes executing,
//! then it is destroyed. Otherwise, it is added to the back of the queue once it is ready to be
//! polled again.
//!
//! [`TasksQueue::run_one`] can be called multiple times in parallel.

// Note: believe or not, but I couldn't find a library that does this in the Rust ecosystem.

use alloc::sync::{Arc, Weak};
use async_lock::Mutex;
use core::{fmt, future::Future, pin::Pin, sync::atomic, task};
use futures_util::future::BoxFuture;

/// See [the module-level documentation](..).
pub struct TasksQueue {
    queue: crossbeam_queue::SegQueue<QueuedTask>,
    item_pushed_to_queue: event_listener::Event,
    sleeping_tasks: Mutex<slab::Slab<BoxFuture<'static, ()>>>,
}

enum QueuedTask {
    Task(BoxFuture<'static, ()>),
    InSlab(usize),
    PutToSleep(BoxFuture<'static, ()>, Arc<Waker>),
}

impl TasksQueue {
    /// Creates a new empty queue.
    pub fn new() -> Arc<Self> {
        Arc::new(TasksQueue {
            queue: crossbeam_queue::SegQueue::new(),
            item_pushed_to_queue: event_listener::Event::new(),
            sleeping_tasks: Mutex::new(slab::Slab::new()),
        })
    }

    /// Pushes a task to the end of the queue.
    pub fn push(self: &Arc<Self>, future: BoxFuture<'static, ()>) {
        self.queue.push(QueuedTask::Task(future));
        self.item_pushed_to_queue.notify_additional(1);
    }

    /// Pops a task from the head of the queue and polls it.
    ///
    /// If the queue is empty, this function waits until one is available.
    ///
    /// If the task being polled finishes, it is then destroyed. If the task is pending, is gets
    /// pushed to the queue of the queue as soon as it is waken up.
    pub async fn run_one(self: &Arc<Self>) {
        // Pop a future from the queue, or waits until there is an item in the queue.
        let task = {
            let mut listener = None;

            loop {
                {
                    // We need to lock the mutex *before* popping from the queue, as otherwise
                    // the user could cancel the locking future and the popped item would be
                    // thrown away.
                    let mut sleeping_tasks_lock = self.sleeping_tasks.lock().await;

                    if let Some(task) = self.queue.pop() {
                        match task {
                            QueuedTask::Task(t) => break t,
                            QueuedTask::InSlab(index) => break sleeping_tasks_lock.remove(index),
                            QueuedTask::PutToSleep(task, waker) => {
                                // Prepare to store `NotPolling(task_index)` in `waker.state`.
                                let task_index = sleeping_tasks_lock.insert(task);
                                debug_assert_ne!(task_index, POLLING);
                                debug_assert_ne!(task_index, WOKE_UP);

                                // Store `NotPolling` if equal to `Polling`.
                                match waker.state.compare_exchange(
                                    POLLING,
                                    task_index,
                                    atomic::Ordering::Relaxed,
                                    atomic::Ordering::Relaxed,
                                ) {
                                    Ok(_) => continue,
                                    Err(_actual_val) => {
                                        // The only way we could reach here is if `Waker::wake()`
                                        // has been called, in which case it has replaced `Polling`
                                        // with `WokeUp`. In that case, use the task immediately.
                                        debug_assert_eq!(_actual_val, WOKE_UP);
                                        break sleeping_tasks_lock.remove(task_index);
                                    }
                                }
                            }
                        };
                    }
                }

                match listener.take() {
                    None => listener = Some(self.item_pushed_to_queue.listen()),
                    Some(l) => l.await,
                }
            }
        };

        // Poll it.
        // Importantly, after the task has been extracted we no longer perform any asynchronous
        // operation, as otherwise this asynchronous operation could be cancelled and the task
        // silently thrown away.
        self.run_inner(task);
    }

    /// Polls a future with a `Waker` that pushes back the future to the back of the queue once
    /// ready to be polled again.
    fn run_inner(self: &Arc<Self>, mut task: BoxFuture<'static, ()>) {
        let waker = Arc::new(Waker {
            tasks_queue: Arc::downgrade(self),
            // Initialize `state` to `Polling`.
            state: atomic::AtomicUsize::new(POLLING),
        });

        match Pin::new(&mut task).poll(&mut task::Context::from_waker(&waker.clone().into())) {
            task::Poll::Ready(()) => {}
            task::Poll::Pending => {
                self.queue.push(QueuedTask::PutToSleep(task, waker));
                self.item_pushed_to_queue.notify_additional(1);
            }
        }
    }
}

impl fmt::Debug for TasksQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TasksQueue").finish()
    }
}

/// `Waker` that it used when polling tasks.
struct Waker {
    /// A `Weak` is used in order to avoid cyclic references.
    tasks_queue: Weak<TasksQueue>,

    /// The `AtomicUsize` in this field is equivalent to the following enum:
    /// ```
    /// enum State {
    ///     Polling,
    ///     NotPolling(usize),
    ///     WokeUp,
    /// }
    /// ```
    ///
    /// The state `WokeUp` is represented as `-1`, the state `Polling` is represented as
    /// `-2`, and any other value represents `NotPolling`.
    ///
    /// `WokeUp` means that the task has already woken up successfully.
    /// `Polling` means that the task hasn't been woken up yet, and that we are currently
    /// polling or have just finished polling (in which case the task is in
    /// `QueuedTask::PutToSleep`) the task.
    /// `NotPolling` means that the task hasn't been woken up yet, and that the task is in the
    /// sleeping tasks list at the given index.
    ///
    /// Because the value in `NotPolling` is an index within a slab, and that the values in the
    /// slab are more than 1 byte in size, the index can't ever reach `usize::max_value()`. It
    /// is therefore safe to use `-1` and `-2` are dummy values (and even if it wasn't, we'd have
    /// a logic error and not an undefined behavior).
    state: atomic::AtomicUsize,
}

/// See [`Waker::state`].
const WOKE_UP: usize = usize::max_value();
/// See [`Waker::state`].
const POLLING: usize = usize::max_value() - 1;

impl alloc::task::Wake for Waker {
    fn wake(self: Arc<Self>) {
        // Store `WokeUp` in `state`, and examine what is inside.
        match self.state.swap(WOKE_UP, atomic::Ordering::Relaxed) {
            val if val == WOKE_UP || val == POLLING => {}
            idx => {
                // Any value other than `WOKE_UP` or `POLLING` represents a sleeping task.
                // Note that the `Arc` containing `tasks_queue` is normally supposed to be alive,
                // but it is possible that it is not in the niche situation where a task get woken
                // up while the queue is currently being destroyed.
                let Some(tasks_queue) = self.tasks_queue.upgrade() else { return };
                tasks_queue.queue.push(QueuedTask::InSlab(idx));
                tasks_queue.item_pushed_to_queue.notify_additional(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic;
    use futures_util::{SinkExt as _, StreamExt as _};

    #[test]
    fn no_race_condition() {
        // Push a lot of tasks in the queue. Each task sleeps a couple times then increments a
        // counter. We check, at the end, that the counter has the expected value.
        async_std::task::block_on(async move {
            let queue = super::TasksQueue::new();
            let counter = Arc::new(atomic::AtomicUsize::new(0));

            const NUM_TASKS: usize = 100000;

            // Spawn background tasks that will run the futures.
            // A message is sent on `finished_tx` as soon as one executor detects that the
            // counter has reached the target value.
            // Note that we use a `ThreadPool` rather that spawn futures with
            // `async_std::task::spawn`, as at the end of the test all executors but one will be
            // stuck sleeping, and we preferably don't want them to leak.
            let threads_pool = futures_executor::ThreadPool::new().unwrap();
            let (finished_tx, mut finished_rx) = futures_channel::mpsc::channel::<()>(0);
            for _ in 0..4 {
                let queue = queue.clone();
                let counter = counter.clone();
                let mut finished_tx = finished_tx.clone();
                threads_pool.spawn_ok(async move {
                    loop {
                        queue.run_one().await;
                        if counter.load(atomic::Ordering::SeqCst) == NUM_TASKS {
                            finished_tx.send(()).await.unwrap();
                            break;
                        }
                    }
                });
            }

            // Spawn the tasks themselves.
            for _ in 0..NUM_TASKS {
                let counter = counter.clone();
                queue.push(Box::pin(async move {
                    // Note that the randomness doesn't have uniform distrib, but we don't care.
                    for _ in 0..(rand::random::<usize>() % 5) {
                        if (rand::random::<usize>() % 10) == 0 {
                            async_std::task::yield_now().await;
                        }
                        let num_us = rand::random::<u64>() % 50000;
                        async_std::task::sleep(core::time::Duration::from_micros(num_us)).await;
                    }

                    counter.fetch_add(1, atomic::Ordering::SeqCst);
                }));
            }

            // Stop the test as soon as one executor is finished, as only one executor will
            // actually detect the limit and the others will be sleeping.
            finished_rx.next().await.unwrap();
            assert_eq!(counter.load(atomic::Ordering::SeqCst), NUM_TASKS);
        })
    }

    #[test]
    fn tasks_destroyed_when_queue_destroyed() {
        // Push infinite tasks in the queue. These tasks share an `Arc`. Destroy the queue. Verify
        // that the `Arc` is stale.
        async_std::task::block_on(async move {
            let queue = super::TasksQueue::new();
            let counter = Arc::new(());

            // Spawn the tasks themselves.
            for _ in 0..1000 {
                let counter = counter.clone();
                queue.push(Box::pin(async move {
                    // Sleep for twelve hours, which basically means infinitely.
                    async_std::task::sleep(core::time::Duration::from_secs(12 * 3600)).await;
                    drop(counter);
                }));
            }

            // Execute tasks a bit.
            for _ in 0..100 {
                queue.run_one().await;
            }

            // Then drop the queue and make sure that there's no clone of `counter` remaining.
            let _ = Arc::into_inner(queue).unwrap();
            let () = Arc::into_inner(counter).unwrap();
        })
    }
}
