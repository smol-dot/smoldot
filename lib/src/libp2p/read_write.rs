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

use core::{cmp, mem};

use alloc::{collections::VecDeque, vec::Vec};

// TODO: documentation

#[must_use]
pub struct ReadWrite<TNow> {
    pub now: TNow,

    /// Buffer of socket data ready to be processed.
    pub incoming_buffer: Vec<u8>,

    /// Number of bytes that [`ReadWrite::incoming_buffer`] should contain. `None` if the remote
    /// has closed their reading side of the socket.
    pub expected_incoming_bytes: Option<usize>,

    /// Total number of bytes that have been read from [`ReadWrite::incoming_buffer`].
    ///
    /// [`ReadWrite::incoming_buffer`] must have been advanced after these bytes.
    // TODO: is this field actually useful?
    pub read_bytes: usize,

    /// List of buffers containing data to the written out. The consumer of the [`ReadWrite`] is
    /// expected to add buffers.
    // TODO: consider changing the inner `Vec` to `Box<dyn AsRef<[u8]>>`
    pub write_buffers: Vec<Vec<u8>>,

    /// Amount of data already queued, both outside and including [`ReadWrite::write_buffers`].
    // TODO: is this field actually useful?
    pub write_bytes_queued: usize,

    /// Number of additional bytes that are allowed to be pushed to [`ReadWrite::write_buffers`].
    /// `None` if the writing side of the stream is closed.
    pub write_bytes_queueable: Option<usize>,

    /// If `Some`, the socket must be waken up after the given `TNow` is reached.
    pub wake_up_after: Option<TNow>,
}

impl<TNow> ReadWrite<TNow> {
    /// Returns true if the connection should be considered dead. That is, both
    /// [`ReadWrite::expected_incoming_bytes`] is `None` and [`ReadWrite::write_bytes_queueable`]
    /// is `None`.
    pub fn is_dead(&self) -> bool {
        self.expected_incoming_bytes.is_none() && self.write_bytes_queueable.is_none()
    }

    /// Sets the writing side of the connection to closed.
    ///
    /// This is simply a shortcut for setting [`ReadWrite::write_bytes_queueable`] to `None`.
    pub fn close_write(&mut self) {
        self.write_bytes_queueable = None;
    }

    /// Returns the size of the data available in the incoming buffer.
    pub fn incoming_buffer_available(&self) -> usize {
        self.incoming_buffer.len()
    }

    /// Discards all the incoming data. Updates [`ReadWrite::read_bytes`] and decreases
    /// [`ReadWrite::expected_incoming_bytes`] by the number of consumed bytes.
    pub fn discard_all_incoming(&mut self) {
        self.read_bytes += self.incoming_buffer.len();
        if let Some(expected_incoming_bytes) = &mut self.expected_incoming_bytes {
            *expected_incoming_bytes =
                expected_incoming_bytes.saturating_sub(self.incoming_buffer.len());
        }
        self.incoming_buffer.clear();
    }

    /// Extract a certain number of bytes from the read buffer.
    ///
    /// On success, updates [`ReadWrite::read_bytes`] and decreases
    /// [`ReadWrite::expected_incoming_bytes`] by the number of consumed bytes.
    ///
    /// If not enough bytes are available, returns `None` and sets
    /// [`ReadWrite::expected_incoming_bytes`] to the requested number of bytes.
    pub fn incoming_bytes_take(
        &mut self,
        num: usize,
    ) -> Result<Option<Vec<u8>>, IncomingBytesTakeError> {
        let Some(expected_incoming_bytes) = self.expected_incoming_bytes.as_mut() else {
            return Err(IncomingBytesTakeError::ReadClosed);
        };

        if self.incoming_buffer.len() < num {
            *expected_incoming_bytes = num;
            return Ok(None);
        }

        self.read_bytes += num;
        *expected_incoming_bytes = expected_incoming_bytes.saturating_sub(num);

        if self.incoming_buffer.len() == num {
            Ok(Some(mem::take(&mut self.incoming_buffer)))
        } else if self.incoming_buffer.len() - num < num.saturating_mul(2) {
            let remains = self.incoming_buffer.split_at(num).1.to_vec();
            self.incoming_buffer.truncate(num);
            Ok(Some(mem::replace(&mut self.incoming_buffer, remains)))
        } else {
            let to_ret = self.incoming_buffer.split_at(num).0.to_vec();
            self.incoming_buffer.copy_within(num.., 0);
            self.incoming_buffer
                .truncate(self.incoming_buffer.len() - num);
            Ok(Some(to_ret))
        }
    }

    /// Extract an LEB128-encoded number from the start of the read buffer.
    ///
    /// On success, updates [`ReadWrite::read_bytes`] and decreases
    /// [`ReadWrite::expected_incoming_bytes`] by the number of consumed bytes.
    ///
    /// If not enough bytes are available, returns `None` and sets
    /// [`ReadWrite::expected_incoming_bytes`] to the required number of bytes.
    ///
    /// Must be passed the maximum value that this function can return on success. An error is
    /// returned if the value sent by the remote is higher than this maximum. This parameter,
    /// while not strictly necessary, is here for safety, as it is easy to forget to check the
    /// value against a maximum.
    pub fn incoming_bytes_take_leb128(
        &mut self,
        max_decoded_number: usize,
    ) -> Result<Option<usize>, IncomingBytesTakeLeb128Error> {
        let Some(expected_incoming_bytes) = self.expected_incoming_bytes.as_mut() else {
            return Err(IncomingBytesTakeLeb128Error::ReadClosed);
        };

        match crate::util::leb128::nom_leb128_usize::<nom::error::Error<&[u8]>>(
            &self.incoming_buffer,
        ) {
            Ok((rest, num)) => {
                if num > max_decoded_number {
                    // TODO: consider detecting earlier if `TooLarge` is reached; for example is max is 20 we know that it can't be more than one byte
                    return Err(IncomingBytesTakeLeb128Error::TooLarge);
                }

                let consumed_bytes = self.incoming_buffer.len() - rest.len();
                if !rest.is_empty() {
                    self.incoming_buffer.copy_within(consumed_bytes.., 0);
                    self.incoming_buffer
                        .truncate(self.incoming_buffer.len() - consumed_bytes);
                } else {
                    self.incoming_buffer.clear();
                }
                self.read_bytes += consumed_bytes;
                *expected_incoming_bytes = expected_incoming_bytes.saturating_sub(consumed_bytes);
                Ok(Some(num))
            }
            Err(nom::Err::Incomplete(nom::Needed::Size(num))) => {
                *expected_incoming_bytes = self.incoming_buffer.len() + num.get();
                Ok(None)
            }
            Err(nom::Err::Incomplete(nom::Needed::Unknown)) => {
                *expected_incoming_bytes = self.incoming_buffer.len() + 1;
                Ok(None)
            }
            Err(_) => Err(IncomingBytesTakeLeb128Error::InvalidLeb128),
        }
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

/// Error potentially returned by [`ReadWrite::incoming_bytes_take`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum IncomingBytesTakeError {
    /// Reading side of the stream is closed.
    ReadClosed,
}

/// Error potentially returned by [`ReadWrite::incoming_bytes_take_leb128`].
#[derive(Debug, Clone, derive_more::Display)]
pub enum IncomingBytesTakeLeb128Error {
    /// Invalid LEB128 number.
    InvalidLeb128,
    /// Reading side of the stream is closed.
    ReadClosed,
    /// Number of bytes decoded is larger than expected.
    TooLarge,
}

#[cfg(test)]
mod tests {
    use super::{IncomingBytesTakeError, ReadWrite};

    #[test]
    fn take_bytes() {
        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: vec![0x80; 64],
            expected_incoming_bytes: Some(12),
            read_bytes: 2,
            write_buffers: Vec::new(),
            write_bytes_queued: 0,
            write_bytes_queueable: None,
            wake_up_after: None,
        };

        let buffer = rw.incoming_bytes_take(5).unwrap().unwrap();
        assert_eq!(buffer, &[0x80, 0x80, 0x80, 0x80, 0x80]);
        assert_eq!(rw.incoming_buffer.len(), 59);
        assert_eq!(rw.read_bytes, 5);
        assert_eq!(rw.expected_incoming_bytes, Some(7));

        assert!(matches!(rw.incoming_bytes_take(1000), Ok(None)));
        assert_eq!(rw.read_bytes, 5);
        assert_eq!(rw.expected_incoming_bytes, Some(1000));

        let buffer = rw.incoming_bytes_take(57).unwrap().unwrap();
        assert_eq!(buffer.len(), 57);
        assert_eq!(rw.incoming_buffer.len(), 2);
        assert_eq!(rw.read_bytes, 62);
        assert_eq!(rw.expected_incoming_bytes, Some(1000 - 57));
    }

    #[test]
    fn take_bytes_closed() {
        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: vec![0x80; 64],
            expected_incoming_bytes: None,
            read_bytes: 2,
            write_buffers: Vec::new(),
            write_bytes_queued: 0,
            write_bytes_queueable: None,
            wake_up_after: None,
        };

        assert!(matches!(
            rw.incoming_bytes_take(1000),
            Err(IncomingBytesTakeError::ReadClosed)
        ));
        assert_eq!(rw.expected_incoming_bytes, None);

        let buffer = rw.incoming_bytes_take(5).unwrap().unwrap();
        assert_eq!(buffer, &[0x80, 0x80, 0x80, 0x80, 0x80]);
        assert_eq!(rw.incoming_buffer.len(), 59);
        assert_eq!(rw.read_bytes, 5);
        assert_eq!(rw.expected_incoming_bytes, None);

        assert!(matches!(
            rw.incoming_bytes_take(1000),
            Err(IncomingBytesTakeError::ReadClosed)
        ));
        assert_eq!(rw.expected_incoming_bytes, None);
    }

    #[test]
    fn write_out() {
        let mut rw = ReadWrite {
            now: 0,
            incoming_buffer: Vec::new(),
            expected_incoming_bytes: None,
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
            incoming_buffer: Vec::new(),
            expected_incoming_bytes: None,
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
            incoming_buffer: Vec::new(),
            expected_incoming_bytes: None,
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
