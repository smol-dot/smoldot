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

use core::cmp;

use alloc::{collections::VecDeque, vec::Vec};

// TODO: documentation

#[must_use]
pub struct ReadWrite<'a, TNow> {
    pub now: TNow,

    /// Pointer to a buffer of socket data ready to be processed.
    ///
    /// Contains `None` if the remote has closed their writing side of the socket.
    pub incoming_buffer: Option<&'a [u8]>,

    /// Total number of bytes that have been read from [`ReadWrite::incoming_buffer`].
    ///
    /// [`ReadWrite::incoming_buffer`] must have been advanced after these bytes.
    pub read_bytes: usize,

    /// List of buffers containing data to the written out. The consumer of the [`ReadWrite`] is
    /// expected to add buffers.
    // TODO: consider changing the inner `Vec` to `Box<dyn AsRef<[u8]>>`
    pub write_buffers: Vec<Vec<u8>>,

    /// Amount of data already queued, both outside and including [`ReadWrite::write_buffers`].
    pub write_bytes_queued: usize,

    /// Number of additional bytes that are allowed to be pushed to [`ReadWrite::write_buffers`].
    /// `None` if the writing side of the stream is closed.
    pub write_bytes_queueable: Option<usize>,

    /// If `Some`, the socket must be waken up after the given `TNow` is reached.
    pub wake_up_after: Option<TNow>,
}

impl<'a, TNow> ReadWrite<'a, TNow> {
    /// Returns true if the connection should be considered dead. That is, both
    /// [`ReadWrite::incoming_buffer`] is `None` and [`ReadWrite::write_bytes_queueable`] is `None`.
    pub fn is_dead(&self) -> bool {
        self.incoming_buffer.is_none() && self.write_bytes_queueable.is_none()
    }

    /// Discards the first `num` bytes of [`ReadWrite::incoming_buffer`] and adds them to
    /// [`ReadWrite::read_bytes`].
    ///
    /// # Panic
    ///
    /// Panics if `num` is superior to the size of the available buffer.
    ///
    pub fn advance_read(&mut self, num: usize) {
        if let Some(ref mut incoming_buffer) = self.incoming_buffer {
            self.read_bytes += num;
            *incoming_buffer = &incoming_buffer[num..];
        } else {
            assert_eq!(num, 0);
        }
    }

    /// Sets the writing side of the connection to closed.
    ///
    /// This is simply a shortcut for setting [`ReadWrite::write_bytes_queueable`] to `None`.
    pub fn close_write(&mut self) {
        self.write_bytes_queueable = None;
    }

    /// Returns the size of the data available in the incoming buffer.
    pub fn incoming_buffer_available(&self) -> usize {
        self.incoming_buffer.as_ref().map_or(0, |buf| buf.len())
    }

    /// Shortcut to [`ReadWrite::advance_read`], passing as parameter the value of
    /// [`ReadWrite::incoming_buffer_available`]. This discards all the incoming data.
    pub fn discard_all_incoming(&mut self) {
        let len = self.incoming_buffer_available();
        self.advance_read(len);
    }

    /// Returns an iterator that pops bytes from [`ReadWrite::incoming_buffer`]. Whenever the
    /// iterator advances, [`ReadWrite::read_bytes`] is increased by 1.
    pub fn incoming_bytes_iter<'b>(&'b mut self) -> IncomingBytes<'a, 'b, TNow> {
        IncomingBytes { me: self }
    }

    /// Extracts a certain number of bytes from [`ReadWrite::incoming_buffer`] and updates
    /// [`ReadWrite::read_bytes`].
    ///
    /// # Panic
    ///
    /// Panics if `N` is super to the number of bytes available.
    ///
    pub fn read_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out: [u8; N] = [0; N];
        match self.incoming_buffer {
            Some(buf) => {
                assert!(buf.len() >= N);
                out.copy_from_slice(&buf[..N]);
                self.advance_read(N);
            }
            None => assert_eq!(N, 0),
        };
        out
    }

    /// Copies as much as possible from the content of `data` to [`ReadWrite::write_buffers`]
    /// and updates [`ReadWrite::write_bytes_queued`] and [`ReadWrite::write_bytes_queueable`].
    /// The bytes that have been written are removed from `data`.
    pub fn write_from_vec_deque(&mut self, data: &mut VecDeque<u8>) {
        let (slice1, slice2) = data.as_slices();

        let to_copy1 = cmp::min(slice1.len(), self.write_bytes_queueable.unwrap_or(0));
        let to_copy2 = if to_copy1 == slice1.len() {
            cmp::min(
                slice2.len(),
                self.write_bytes_queueable.unwrap_or(0) - to_copy1,
            )
        } else {
            0
        };

        let total_tocopy = to_copy1 + to_copy2;

        if total_tocopy == 0 {
            return;
        }

        self.write_buffers.push(slice1[..to_copy1].to_vec());
        self.write_buffers.push(slice2[..to_copy2].to_vec());

        self.write_bytes_queued += total_tocopy;
        *self.write_bytes_queueable.as_mut().unwrap() -= total_tocopy;

        for _ in 0..total_tocopy {
            data.pop_front();
        }
    }

    /// Adds the `data` to [`ReadWrite::write_buffers`], increases
    /// [`ReadWrite::write_bytes_queued`], and decreases [`ReadWrite::write_bytes_queueable`].
    ///
    /// # Panic
    ///
    /// Panics if `data.len() > write_bytes_queueable`.
    /// Panics if the writing side is closed and `data` isn't empty.
    ///
    // TODO: is this function necessary? it seems dangerous due to the panic regarding queuable bytes
    pub fn write_out(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        assert!(data.len() <= self.write_bytes_queueable.unwrap_or(0));
        self.write_bytes_queued += data.len();
        *self.write_bytes_queueable.as_mut().unwrap() -= data.len();
        self.write_buffers.push(data);
    }

    /// Sets [`ReadWrite::wake_up_after`] to `min(wake_up_after, after)`.
    pub fn wake_up_after(&mut self, after: &TNow)
    where
        TNow: Clone + Ord,
    {
        match self.wake_up_after {
            Some(ref mut t) if *t < *after => {}
            Some(ref mut t) => *t = after.clone(),
            ref mut t @ None => *t = Some(after.clone()),
        }
    }
}

/// See [`ReadWrite::incoming_bytes_iter`].
pub struct IncomingBytes<'a, 'b, TNow> {
    me: &'b mut ReadWrite<'a, TNow>,
}

impl<'a, 'b, TNow> Iterator for IncomingBytes<'a, 'b, TNow> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        match &mut self.me.incoming_buffer {
            Some(ref mut buf) => {
                if buf.is_empty() {
                    return None;
                }

                let byte = buf[0];
                *buf = &buf[1..];
                self.me.read_bytes += 1;
                Some(byte)
            }
            None => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.me.incoming_buffer {
            Some(b) => (b.len(), Some(b.len())),
            None => (0, Some(0)),
        }
    }
}

impl<'a, 'b, TNow> ExactSizeIterator for IncomingBytes<'a, 'b, TNow> {}

#[cfg(test)]
mod tests {
    use super::ReadWrite;

    #[test]
    fn incoming_bytes_iter() {
        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: Some(&[1, 2, 3]),
            read_bytes: 2,
            write_buffers: Vec::new(),
            write_bytes_queued: 0,
            write_bytes_queueable: None,
            wake_up_after: None,
        };

        let mut iter = rw.incoming_bytes_iter();
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.len(), 2);

        assert_eq!(rw.read_bytes, 3);

        let mut iter = rw.incoming_bytes_iter();
        assert_eq!(iter.len(), 2);
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);

        assert_eq!(rw.read_bytes, 5);
        let mut iter = rw.incoming_bytes_iter();
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn advance_read() {
        let buf = [1, 2, 3];
        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: Some(&buf),
            read_bytes: 5,
            write_buffers: Vec::new(),
            write_bytes_queued: 0,
            write_bytes_queueable: None,
            wake_up_after: None,
        };

        rw.advance_read(1);
        assert_eq!(rw.incoming_buffer.as_ref().unwrap(), &[2, 3]);
        assert_eq!(rw.read_bytes, 6);

        rw.advance_read(2);
        assert!(rw.incoming_buffer.as_ref().unwrap().is_empty());
        assert_eq!(rw.read_bytes, 8);
    }

    #[test]
    fn write_out() {
        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: None,
            read_bytes: 0,
            write_buffers: Vec::new(),
            write_bytes_queued: 11,
            write_bytes_queueable: Some(10),
            wake_up_after: None,
        };

        rw.write_out(b"hello".to_vec());
        assert_eq!(rw.write_buffers.len(), 1);
        assert_eq!(rw.write_bytes_queued, 16);
        assert_eq!(rw.write_bytes_queueable, Some(5));
    }

    #[test]
    fn write_from_vec_deque_smaller() {
        let mut input = [1, 2, 3, 4].iter().cloned().collect();

        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: None,
            read_bytes: 0,
            write_buffers: Vec::new(),
            write_bytes_queueable: Some(5),
            write_bytes_queued: 5,
            wake_up_after: None,
        };

        rw.write_from_vec_deque(&mut input);
        assert!(input.is_empty());
        assert_eq!(rw.write_bytes_queued, 9);
        assert_eq!(rw.write_bytes_queueable, Some(1));
    }

    #[test]
    fn write_from_vec_deque_larger() {
        let mut input = [1, 2, 3, 4, 5, 6].iter().cloned().collect();

        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: None,
            read_bytes: 0,
            write_buffers: Vec::new(),
            write_bytes_queueable: Some(5),
            write_bytes_queued: 5,
            wake_up_after: None,
        };

        rw.write_from_vec_deque(&mut input);
        assert_eq!(input.into_iter().collect::<Vec<_>>(), &[6]);
        assert_eq!(rw.write_bytes_queued, 10);
        assert_eq!(rw.write_bytes_queueable, Some(0));
    }
}
