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

use alloc::{collections::VecDeque, vec::Vec};

#[derive(Clone)]
pub struct VecWithOffset(pub Vec<u8>, pub usize);

impl AsRef<[u8]> for VecWithOffset {
    fn as_ref(&self) -> &[u8] {
        &self.0[self.1..]
    }
}

// TODO: PartialEq/Eq?!
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteQueue {
    /// Buffer of buffers to be written out.
    // TODO: is it a good idea to have an unbounded VecDeque?
    // TODO: call shrink_to_fit from time to time?
    // TODO: instead of storing `Vec<u8>`s, consider storing a generic `B` and let the user manually write a `B` to the output buffer
    write_buffers: VecDeque<Vec<u8>>,
    /// Number of bytes in `self.write_buffers[0]` has have already been written out to the
    /// socket.
    first_write_buffer_offset: usize,
}

impl WriteQueue {
    pub fn new() -> Self {
        WriteQueue {
            write_buffers: VecDeque::with_capacity(16),
            first_write_buffer_offset: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        debug_assert!(!self.write_buffers.is_empty() || self.first_write_buffer_offset == 0);
        self.write_buffers.is_empty()
    }

    pub fn push_back(&mut self, data: Vec<u8>) {
        debug_assert!(!self.write_buffers.is_empty() || self.first_write_buffer_offset == 0);
        self.write_buffers.push_back(data);
    }

    pub fn queued_bytes(&self) -> usize {
        self.write_buffers.iter().fold(0, |n, buf| n + buf.len()) - self.first_write_buffer_offset
    }

    pub fn extract_some(&mut self, max_size: usize) -> VecWithOffset {
        let first_buf_avail = self.write_buffers[0].len() - self.first_write_buffer_offset;

        if first_buf_avail <= max_size {
            let out = VecWithOffset(
                self.write_buffers.pop_front().unwrap(),
                self.first_write_buffer_offset,
            );
            self.first_write_buffer_offset = 0;
            out
        } else {
            let out = VecWithOffset(
                self.write_buffers[0][self.first_write_buffer_offset..][..max_size].to_vec(),
                0,
            );
            self.first_write_buffer_offset += max_size;
            out
        }
    }
}
