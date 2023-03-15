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
//! Use [`TasksQueue::add`] to add a future to the back of the queue.
//!
//! Use [`TasksQueue::run_once`] to pull a future from the queue and poll it. If the queue is
//! empty, this function waits until a future enters the queue. If the future finishes executing,
//! then it is destroyed. Otherwise, it is added to the back of the queue once it is ready to be
//! polled again.
//!
//! [`TasksQueue::run_once`] can be called multiple times in parallel.

// Note: believe or not, but I couldn't find a library that does this in the Rust ecosystem.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::{future::Future as _, pin::Pin, ptr, sync::atomic, task};
use futures::future::BoxFuture;

/// See [the module-level documentation](..).
pub struct TasksQueue {
    queue: crossbeam_queue::SegQueue<BoxFuture<'static, ()>>,
    item_pushed_to_queue: event_listener::Event,
}

impl TasksQueue {
    /// Creates a new empty queue.
    pub fn new() -> Arc<Self> {
        Arc::new(TasksQueue {
            queue: crossbeam_queue::SegQueue::new(),
            item_pushed_to_queue: event_listener::Event::new(),
        })
    }

    /// Pushes a task to the end of the queue.
    pub fn push(self: &Arc<Self>, future: BoxFuture<'static, ()>) {
        self.queue.push(future);
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
                if let Some(task) = self.queue.pop() {
                    break task;
                }

                match listener.take() {
                    None => listener = Some(self.item_pushed_to_queue.listen()),
                    Some(l) => l.await,
                }
            }
        };

        // Poll it.
        self.run_inner(task);
    }

    /// Polls a future with a waker that pushes back the future to the back of the queue once
    /// ready to be polled again.
    fn run_inner(self: &Arc<Self>, mut task: BoxFuture<'static, ()>) {
        struct Waker {
            tasks_queue: Weak<TasksQueue>,

            // While the easy solution here would be to use a `Mutex`, mutexes are unfortunately
            // not available in no_std environments. `parking_lot` notably uses the clock for some
            // reason, which is something we don't want.
            // The good news is we don't need a `Mutex`. The bad news is that not using one makes
            // things more complicated and requires using unsafe code.
            //
            // The `AtomicPtr` in this field is equivalent to the following enum:
            // ```
            // enum State {
            //     Polling,
            //     NotPolling(BoxFuture<'static, ()>),
            //     WokeUp,
            // }
            // ```
            //
            // The state `WokeUp` is represented with a null pointer, the state `Polling` is
            // represented as `invalid_non_null_ptr!()`, and any other pointer represents
            // `NotPolling`.
            //
            // `WokeUp` means that the task has already woken up successfully.
            // `Polling` means that the task hasn't been woken up yet, and that we are currently
            // (or have just finished) polling the task.
            // `NotPolling` means that the task hasn't been woken up yet, and that we are no
            // longer polling the task.
            //
            // The distinction between `Polling` and `NotPolling` is necessary because we can't
            // store the task in the waker while it is still being polled.
            state: atomic::AtomicPtr<BoxFuture<'static, ()>>,
        }

        // In order to represent `Polling`, we use a pointer to a static variable. The pointer
        // is invalid (because we convert it to the wrong type), but the important point here is
        // that it isn't null and can't accidentally be equal to a pointer to `task`.
        static DUMMY_POINTED_VALUE: usize = 0;
        macro_rules! invalid_non_null_ptr {
            () => {
                (&DUMMY_POINTED_VALUE as *const usize as *mut usize as *mut BoxFuture<'static, ()>)
            };
        }

        impl alloc::task::Wake for Waker {
            fn wake(self: Arc<Self>) {
                // Store `WokeUp` (i.e. null) in `state`, and examine what is inside.
                match self.state.swap(ptr::null_mut(), atomic::Ordering::Relaxed) {
                    ptr if ptr.is_null() || ptr == invalid_non_null_ptr!() => {}
                    task_ptr => {
                        // Any value other than null or `invalid_non_null_ptr!()` represents a
                        // valid task.
                        // If the state is `NotPolling`, push this task back to the queue.
                        let task = unsafe { Box::from_raw(task_ptr) };
                        let Some(tasks_queue) = self.tasks_queue.upgrade() else { return };
                        tasks_queue.push(*task);
                    }
                }
            }
        }

        let waker = Arc::new(Waker {
            tasks_queue: Arc::downgrade(self),
            // Initialize `state` to `Polling`.
            state: atomic::AtomicPtr::new(invalid_non_null_ptr!()),
        });

        match Pin::new(&mut task).poll(&mut task::Context::from_waker(&waker.clone().into())) {
            task::Poll::Ready(()) => {}
            task::Poll::Pending => {
                // Prepare to store `NotPolling(task)` in `state`.
                let task_ptr = Box::into_raw(Box::new(task));
                debug_assert_ne!(task_ptr, invalid_non_null_ptr!());

                // Store `NotPolling` if equal to `Polling`.
                match waker.state.compare_exchange(
                    invalid_non_null_ptr!(),
                    task_ptr,
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed,
                ) {
                    Ok(_) => {}
                    Err(_actual_val) => {
                        // The only way we could reach here is if `wake()` has been called,
                        // in which case it has replaced `Polling` with `WokeUp` (i.e. null).
                        // In that case, push the task to the back of the queue.
                        debug_assert!(_actual_val.is_null());
                        let task = unsafe { Box::from_raw(task_ptr) };
                        self.push(*task);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic;
    use futures::{SinkExt as _, StreamExt as _};

    #[test]
    fn no_race_condition() {
        // Push a lot of tasks in the queue. Each task sleeps a couple times then increments a
        // counter. We check, at the end, that the counter has the expected value.
        async_std::task::block_on(async move {
            let queue = super::TasksQueue::new();
            let counter = Arc::new(atomic::AtomicU64::new(0));

            const NUM_TASKS: u64 = 100000;

            // Spawn background tasks that will run the futures.
            // A message is sent on `finished_tx` as soon as one executor detects that the
            // counter has reached the target value.
            // Note that we use a `ThreadPool` rather that spawn futures with
            // `async_std::task::spawn`, as at the end of the test all executors but one will be
            // stuck sleeping, and we preferably don't want them to leak.
            let threads_pool = futures::executor::ThreadPool::new().unwrap();
            let (finished_tx, mut finished_rx) = futures::channel::mpsc::channel::<()>(0);
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
            let _ = finished_rx.next().await.unwrap();
            assert_eq!(counter.load(atomic::Ordering::SeqCst), NUM_TASKS);
        })
    }
}
