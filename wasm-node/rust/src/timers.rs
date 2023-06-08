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

//! This module provides the `Delay` struct, which implement `Future` and becomes ready after a
//! certain time.
//!
//! In order to optimize performances, we avoid invoking the FFI once per timer. Instead, the FFI
//! is only used in order to wake up when the earliest timer finishes, then restarted for the next
//! timer.

use crate::bindings;

use core::{
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    future, mem,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use std::{collections::BTreeSet, sync::Mutex, time::Instant};

pub(crate) fn timer_finished() {
    process_timers();
}

/// `Future` that automatically wakes up after a certain amount of time has elapsed.
pub struct Delay {
    /// Index in `TIMERS::timers`. Guaranteed to have `is_obsolete` equal to `false`.
    /// If `None`, then this timer is already ready.
    timer_id: Option<usize>,
}

impl Delay {
    pub fn new(after: Duration) -> Self {
        let now = Instant::now();
        Self::new_inner(now + after, now)
    }

    pub fn new_at(when: Instant) -> Self {
        Self::new_inner(when, Instant::now())
    }

    fn new_inner(when: Instant, now: Instant) -> Self {
        // Small optimization because sleeps of 0 seconds are frequent.
        if when <= now {
            return Delay { timer_id: None };
        }

        // Because we're in a single-threaded environment, `try_lock()` should always succeed.
        let mut lock = TIMERS.try_lock().unwrap();

        let timer_id = lock.timers.insert(Timer {
            is_finished: false,
            is_obsolete: false,
            waker: None,
        });

        let time_zero = lock.time_zero.get_or_insert_with(Instant::now);
        let when_from_time_zero = when - *time_zero;
        lock.timers_queue.insert(QueuedTimer {
            when_from_time_zero,
            timer_id,
        });

        // If the timer that has just been inserted is the one that ends the soonest, then
        // actually start the callback that will process timers.
        // Ideally we would instead cancel or update the deadline of the previous call to
        // `start_timer`, but this isn't possible.
        if lock
            .timers_queue
            .first()
            .unwrap_or_else(|| unreachable!())
            .timer_id
            == timer_id
        {
            start_timer(when - now);
        }

        Delay {
            timer_id: Some(timer_id),
        }
    }
}

impl future::Future for Delay {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let timer_id = match self.timer_id {
            Some(id) => id,
            None => return Poll::Ready(()),
        };

        // Because we're in a single-threaded environment, `try_lock()` should always succeed.
        let mut lock = TIMERS.try_lock().unwrap();
        debug_assert!(!lock.timers[timer_id].is_obsolete);

        if lock.timers[timer_id].is_finished {
            lock.timers.remove(timer_id);
            self.timer_id = None;
            return Poll::Ready(());
        }

        lock.timers[timer_id].waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Delay {
    fn drop(&mut self) {
        let timer_id = match self.timer_id {
            Some(id) => id,
            None => return,
        };

        // Because we're in a single-threaded environment, `try_lock()` should always succeed.
        let mut lock = TIMERS.try_lock().unwrap();
        debug_assert!(!lock.timers[timer_id].is_obsolete);

        if lock.timers[timer_id].is_finished {
            lock.timers.remove(timer_id);
            return;
        }

        lock.timers[timer_id].is_obsolete = true;
        lock.timers[timer_id].waker = None;
    }
}

static TIMERS: Mutex<Timers> = Mutex::new(Timers {
    timers_queue: BTreeSet::new(),
    timers: slab::Slab::new(),
    time_zero: None,
});

struct Timers {
    /// Same entries as `timer`, but ordered based on when they're finished (from soonest to
    /// latest). Items are only ever removed from [`process_timers`] when they finish, even if
    /// the corresponding [`Delay`] is destroyed.
    timers_queue: BTreeSet<QueuedTimer>,

    /// List of all timers.
    timers: slab::Slab<Timer>,

    /// Arbitrary point in time set at initialization and that never changes. All moments in time
    /// are represented by `Duration`s relative to this value.
    /// Initially set to `None` and initialized to `now` the first time a timer is created.
    time_zero: Option<Instant>,
}

struct Timer {
    /// If `true`, then this timer has elapsed.
    is_finished: bool,
    /// If `true`, then the corresponding `Delay` has been destroyed or no longer points to this
    /// item.
    is_obsolete: bool,
    /// How to wake up the `Delay`.
    waker: Option<Waker>,
}

struct QueuedTimer {
    when_from_time_zero: Duration,

    // Entry in `TIMERS::timers`. Guaranteed to always have `is_finished` equal to `false`.
    timer_id: usize,
}

impl PartialEq for QueuedTimer {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.cmp(other), Ordering::Equal)
    }
}

impl Eq for QueuedTimer {}

impl PartialOrd for QueuedTimer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Ord for QueuedTimer {
    fn cmp(&self, other: &Self) -> Ordering {
        // `when_from_time_zero` takes higher priority in the ordering.
        match self.when_from_time_zero.cmp(&other.when_from_time_zero) {
            Ordering::Equal => self.timer_id.cmp(&other.timer_id),
            ord => ord,
        }
    }
}

/// Marks as ready all the timers in `TIMERS` that are finished.
fn process_timers() {
    // Because we're in a single-threaded environment, `try_lock()` should always succeed.
    let mut lock = TIMERS.try_lock().unwrap();
    let lock = &mut *lock;

    // `lock.time_zero` is initialized the first time a timer is created. We never process timers
    // before a timer is created.
    let time_zero = lock.time_zero.as_ref().unwrap_or_else(|| unreachable!());
    let now = Instant::now();

    // Note that this function can be called spuriously.
    // For example, `process_timers` can be scheduled twice from two different timers, and the
    // first call leads to both timers being finished, after which the second call will be
    // spurious.

    // We remove all the queued timers whose `when_from_time_zero` is inferior to `now`.
    let expired_timers = {
        let timers_remaining = lock.timers_queue.split_off(&QueuedTimer {
            when_from_time_zero: now - *time_zero,
            // Note that `split_off` returns values greater or equal, meaning that if a timer had
            // a `timer_id` equal to `max_value()` it would erroneously be returned instead of being
            // left in the collection as expected. For obvious reasons, a `timer_id` of
            // `usize::max_value()` is impossible, so this isn't a problem.
            timer_id: usize::max_value(),
        });

        mem::replace(&mut lock.timers_queue, timers_remaining)
    };

    // Wake up the expired timers.
    for timer in expired_timers {
        debug_assert!(timer.when_from_time_zero <= now - *time_zero);
        debug_assert!(!lock.timers[timer.timer_id].is_finished);
        lock.timers[timer.timer_id].is_finished = true;
        if let Some(waker) = lock.timers[timer.timer_id].waker.take() {
            waker.wake();
        }
    }

    // Figure out the next time (relative to `time_zero`) we should call `process_timers`.
    //
    // This iterates through all the elements in `timers_queue` until a valid one is found.
    let next_wakeup: Option<Duration> = loop {
        let next_timer = match lock.timers_queue.first() {
            Some(t) => t,
            None => break None,
        };

        // The `Delay` corresponding to the iterated timer has been destroyed. Removing it and
        // `continue`.
        if lock.timers[next_timer.timer_id].is_obsolete {
            let next_timer_id = next_timer.timer_id;
            lock.timers.remove(next_timer_id);
            lock.timers_queue
                .pop_first()
                .unwrap_or_else(|| unreachable!());
            continue;
        }

        // Iterated timer is not ready.
        break Some(next_timer.when_from_time_zero);
    };

    if let Some(next_wakeup) = next_wakeup {
        start_timer(*time_zero + next_wakeup - now);
    } else {
        // Clean up memory a bit. Hopefully this doesn't impact performances too much.
        if !lock.timers.is_empty() && lock.timers.capacity() > lock.timers.len() * 8 {
            lock.timers.shrink_to_fit();
        }
    }
}

/// Instructs the environment to call [`process_timers`] after the given duration.
fn start_timer(duration: Duration) {
    // Note that ideally `duration` should be rounded up in order to make sure that it is not
    // truncated, but the precision of an `f64` is so high and the precision of the operating
    // system generally so low that this is not worth dealing with.
    unsafe { bindings::start_timer(duration.as_secs_f64() * 1000.0) }
}
