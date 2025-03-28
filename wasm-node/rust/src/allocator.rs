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

//! This module contains the `#[global_allocator]` used by the wasm node. This allocator is very
//! simple, apart from the fact that it counts the total number of bytes that have been allocated.
//! This value can then be retrieved by calling [`total_alloc_bytes`].

use core::{alloc, sync::atomic};

/// Returns the total number of bytes that have been allocated through the Rust `alloc` crate
/// throughout the entire Wasm node.
pub fn total_alloc_bytes() -> usize {
    ALLOCATOR.total.load(atomic::Ordering::Relaxed)
}

struct AllocCounter {
    /// Use the `dlmalloc` allocator. This is the library that the Rust standard library uses in
    /// the context of Wasm.
    /// See <https://github.com/rust-lang/rust/tree/1.47.0/library/std/src/sys/wasm>.
    inner: dlmalloc::GlobalDlmalloc,

    /// Total number of bytes allocated.
    total: atomic::AtomicUsize,
}

#[global_allocator]
static ALLOCATOR: AllocCounter = AllocCounter {
    inner: dlmalloc::GlobalDlmalloc,
    total: atomic::AtomicUsize::new(0),
};

unsafe impl alloc::GlobalAlloc for AllocCounter {
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut u8 {
        unsafe {
            let ret = self.inner.alloc(layout);
            if !ret.is_null() {
                self.total
                    .fetch_add(layout.size(), atomic::Ordering::Relaxed);
            }
            ret
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::Layout) {
        unsafe {
            self.total
                .fetch_sub(layout.size(), atomic::Ordering::Relaxed);
            self.inner.dealloc(ptr, layout);
        }
    }

    unsafe fn alloc_zeroed(&self, layout: alloc::Layout) -> *mut u8 {
        unsafe {
            let ret = self.inner.alloc_zeroed(layout);
            if !ret.is_null() {
                self.total
                    .fetch_add(layout.size(), atomic::Ordering::Relaxed);
            }
            ret
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: alloc::Layout, new_size: usize) -> *mut u8 {
        unsafe {
            let ret = self.inner.realloc(ptr, layout, new_size);
            if !ret.is_null() {
                if new_size >= layout.size() {
                    self.total
                        .fetch_add(new_size - layout.size(), atomic::Ordering::Relaxed);
                } else {
                    self.total
                        .fetch_sub(layout.size() - new_size, atomic::Ordering::Relaxed);
                }
            }
            ret
        }
    }
}
