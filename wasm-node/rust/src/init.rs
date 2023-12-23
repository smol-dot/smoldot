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

use crate::{allocator, bindings, platform, timers::Delay};

use alloc::{boxed::Box, format, string::String};
use core::{sync::atomic::Ordering, time::Duration};
use futures_util::stream;
use smoldot::informant::BytesDisplay;
use smoldot_light::platform::PlatformRef;

pub(crate) struct Client<TPlat: smoldot_light::platform::PlatformRef, TChain> {
    pub(crate) smoldot: smoldot_light::Client<TPlat, TChain>,

    /// List of all chains that have been added by the user.
    pub(crate) chains: slab::Slab<Chain>,
}

pub(crate) enum Chain {
    Healthy {
        smoldot_chain_id: smoldot_light::ChainId,

        /// JSON-RPC responses that is at the front of the queue according to the API. If `Some`,
        /// a pointer to the string is referenced to within
        /// [`Chain::Healthy::json_rpc_response_info`].
        json_rpc_response: Option<String>,
        /// Information about [`Chain::Healthy::json_rpc_response`]. A pointer to this struct is
        /// sent over the FFI layer to the JavaScript. As such, the pointer must never be
        /// invalidated.
        json_rpc_response_info: Box<bindings::JsonRpcResponseInfo>,
        /// Receiver for JSON-RPC responses sent by the client. `None` if JSON-RPC requests are
        /// disabled on this chain.
        /// While this could in principle be a [`smoldot_light::JsonRpcResponses`], we wrap it
        /// within a [`futures_util::Stream`] in order to guarantee that the `waker` that we
        /// register doesn't get cleaned up.
        json_rpc_responses_rx: Option<stream::BoxStream<'static, String>>,
    },
    Erroneous {
        error: String,
    },
}

pub(crate) fn init(max_log_level: u32) {
    // Try initialize the logging.
    if let Ok(_) = log::set_logger(&LOGGER) {
        log::set_max_level(match max_log_level {
            0 => log::LevelFilter::Off,
            1 => log::LevelFilter::Error,
            2 => log::LevelFilter::Warn,
            3 => log::LevelFilter::Info,
            4 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
    }

    // First things first, print the version in order to make it easier to debug issues by
    // reading logs provided by third parties.
    log::info!(
        target: "smoldot",
        "Smoldot v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Spawn a constantly-running task that periodically prints the total memory usage of
    // the node.
    platform::PLATFORM_REF.spawn_task(
        "memory-printer".into(),
        async move {
            let mut previous_read_bytes = 0;
            let mut previous_sent_bytes = 0;
            let interval = 60;

            loop {
                Delay::new(Duration::from_secs(interval)).await;

                // For the unwrap below to fail, the quantity of allocated would have to
                // not fit in a `u64`, which as of 2021 is basically impossible.
                let mem = u64::try_from(allocator::total_alloc_bytes()).unwrap();

                // Due to the way the calculation below is performed, sending or receiving
                // more than `type_of(TOTAL_BYTES_RECEIVED or TOTAL_BYTES_SENT)::max_value`
                // bytes within an interval will lead to an erroneous value being shown to the
                // user. At the time of writing of this comment, they are 64bits, so we just
                // assume that this can't happen. If it does happen, the fix would consist in
                // increasing the size of `TOTAL_BYTES_RECEIVED` or `TOTAL_BYTES_SENT`.

                let bytes_rx = platform::TOTAL_BYTES_RECEIVED.load(Ordering::Relaxed);
                let avg_dl = bytes_rx.wrapping_sub(previous_read_bytes) / interval;
                previous_read_bytes = bytes_rx;

                let bytes_tx = platform::TOTAL_BYTES_SENT.load(Ordering::Relaxed);
                let avg_up = bytes_tx.wrapping_sub(previous_sent_bytes) / interval;
                previous_sent_bytes = bytes_tx;

                // Note that we also print the version at every interval, in order to increase
                // the chance of being able to know the version in case of truncated logs.
                log::info!(
                    target: "smoldot",
                    "Smoldot v{}. Current memory usage: {}. Average download: {}/s. Average upload: {}/s.",
                    env!("CARGO_PKG_VERSION"),
                    BytesDisplay(mem),
                    BytesDisplay(avg_dl),
                    BytesDisplay(avg_up)
                );
            }
        },
    );
}

/// Stops execution, providing a string explaining what happened.
#[cfg(not(any(test, feature = "std")))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let message = alloc::string::ToString::to_string(info);

    unsafe {
        bindings::panic(
            u32::try_from(message.as_bytes().as_ptr() as usize).unwrap(),
            u32::try_from(message.as_bytes().len()).unwrap(),
        );

        // Even though this code is intended to only ever be compiled for Wasm, it might, for
        // various reasons, be compiled for the host platform as well. We use platform-specific
        // code to make sure that it compiles for all platforms.
        #[cfg(target_arch = "wasm32")]
        core::arch::wasm32::unreachable();
        #[cfg(not(target_arch = "wasm32"))]
        unreachable!();
    }
}

/// Implementation of [`log::Log`] that sends out logs to the FFI.
struct Logger;
static LOGGER: Logger = Logger;

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let target = record.target();
        let message = format!("{}", record.args());

        unsafe {
            bindings::log(
                record.level() as usize as u32,
                u32::try_from(target.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(target.as_bytes().len()).unwrap(),
                u32::try_from(message.as_bytes().as_ptr() as usize).unwrap(),
                u32::try_from(message.as_bytes().len()).unwrap(),
            )
        }
    }

    fn flush(&self) {}
}
