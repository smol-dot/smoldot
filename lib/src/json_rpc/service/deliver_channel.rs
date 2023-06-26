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

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// TODO: this implementation could probably be optimized, but well, it works

// TODO: should be bounded
pub fn deliver_channel<T>() -> (DeliverSender<T>, DeliverReceiver<T>) {
    let common = Arc::new(Common {
        queue: crossbeam_queue::SegQueue::new(),
        num_senders_alive: AtomicUsize::new(1),
        sender_did_something: event_listener::Event::new(),
        receiver_is_dead: AtomicBool::new(false),
        receiver_did_something: event_listener::Event::new(),
    });

    let tx = DeliverSender {
        common: common.clone(),
    };
    let rx = DeliverReceiver { common };
    (tx, rx)
}

pub struct DeliverSender<T> {
    common: Arc<Common<T>>,
}

impl<T> DeliverSender<T> {
    /// Sends the given payload to the receiver and waits for it to have been received.
    ///
    /// If the [`DeliverReceiver`] has been dropped, an error is returned with the original value.
    pub async fn deliver(&mut self, payload: T) -> Result<(), T> {
        let message = Arc::new(atomic_take::AtomicTake::new(payload));

        self.common.queue.push(message.clone());
        self.common.sender_did_something.notify(1);

        let mut waiter = None;
        loop {
            if message.is_taken() {
                return Ok(());
            }

            if self.common.receiver_is_dead.load(Ordering::Acquire) {
                return match message.take() {
                    Some(payload) => Err(payload),
                    None => Ok(()),
                };
            }

            if let Some(waiter) = waiter.take() {
                waiter.await;
            } else {
                waiter = Some(self.common.receiver_did_something.listen());
            }
        }
    }
}

impl<T> Clone for DeliverSender<T> {
    fn clone(&self) -> Self {
        self.common
            .num_senders_alive
            .fetch_add(1, Ordering::Release);
        DeliverSender {
            common: self.common.clone(),
        }
    }
}

impl<T> Drop for DeliverSender<T> {
    fn drop(&mut self) {
        let _num_remain = self
            .common
            .num_senders_alive
            .fetch_sub(1, Ordering::Release);
        debug_assert!(_num_remain != usize::max_value()); // Check for underflow.
        self.common.sender_did_something.notify(usize::max_value());
    }
}

pub struct DeliverReceiver<T> {
    common: Arc<Common<T>>,
}

impl<T> DeliverReceiver<T> {
    /// Returns the next item that was sent. If no item is available, waits until one is.
    ///
    /// Returns `None` if all the [`DeliverSender`]s have been dropped.
    pub async fn next(&mut self) -> Option<T> {
        let message: Arc<atomic_take::AtomicTake<T>> = {
            let mut waiter = None;
            loop {
                if let Some(item) = self.common.queue.pop() {
                    break item;
                }

                if self.common.num_senders_alive.load(Ordering::Acquire) == 0 {
                    return None;
                }

                if let Some(waiter) = waiter.take() {
                    waiter.await;
                } else {
                    waiter = Some(self.common.sender_did_something.listen());
                }
            }
        };

        let payload = message.take().unwrap();
        self.common
            .receiver_did_something
            .notify(usize::max_value());
        Some(payload)
    }
}

impl<T> Drop for DeliverReceiver<T> {
    fn drop(&mut self) {
        self.common.receiver_is_dead.store(true, Ordering::Release);
        self.common
            .receiver_did_something
            .notify(usize::max_value());
    }
}

struct Common<T> {
    queue: crossbeam_queue::SegQueue<Arc<atomic_take::AtomicTake<T>>>,
    /// `true` if the sending side is dead.
    num_senders_alive: AtomicUsize,
    /// Notified after an element has been pushed to the queue, or after a sender died.
    sender_did_something: event_listener::Event,
    /// `true` if the receiving side is dead.
    receiver_is_dead: AtomicBool,
    /// Notified after an element has been popped from the queue, or after a receiver died.
    receiver_did_something: event_listener::Event,
}
