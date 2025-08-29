// Smoldot
// Copyright (C) 2024  Pierre Krieger
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

use core::{fmt, iter, ops};

/// Index of an entry within the [`ResponsesQueue`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryIndex(usize);

/// One can think of this data structure as a linked list, except that indices aren't linear
/// (i.e. item 4 doesn't necessarily follow item 3) and do not change when entries are added or
/// removed.
pub struct ResponsesQueue<T> {
    container: slab::Slab<Entry<T>>,

    first_entry: usize,
    last_entry: usize,
}

struct Entry<T> {
    value: T,
    next_entry: usize,
}

impl<T> ResponsesQueue<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        ResponsesQueue {
            container: slab::Slab::with_capacity(capacity),
            first_entry: 0,
            last_entry: 0,
        }
    }

    pub fn push_back(&mut self, value: T) -> EntryIndex {
        let container_was_empty = self.container.is_empty();

        let new_entry_index = self.container.insert(Entry {
            value,
            next_entry: 0,
        });

        if container_was_empty {
            self.first_entry = new_entry_index;
        } else {
            self.container[self.last_entry].next_entry = new_entry_index;
        }

        self.last_entry = new_entry_index;

        EntryIndex(new_entry_index)
    }

    pub fn pop_front(&mut self) -> Option<(EntryIndex, T)> {
        if self.container.is_empty() {
            return None;
        }

        let entry_index = self.first_entry;
        let Some(entry) = self.container.try_remove(entry_index) else {
            unreachable!()
        };

        self.first_entry = entry.next_entry;
        Some((EntryIndex(entry_index), entry.value))
    }
}

impl<T> ops::Index<EntryIndex> for ResponsesQueue<T> {
    type Output = T;

    fn index(&self, index: EntryIndex) -> &Self::Output {
        &self.container[index.0].value
    }
}

impl<T> ops::IndexMut<EntryIndex> for ResponsesQueue<T> {
    fn index_mut(&mut self, index: EntryIndex) -> &mut Self::Output {
        &mut self.container[index.0].value
    }
}

impl<T: fmt::Debug> fmt::Debug for ResponsesQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                iter::successors(
                    if self.container.is_empty() {
                        None
                    } else {
                        Some(self.first_entry)
                    },
                    |&index| {
                        if index == self.last_entry {
                            None
                        } else {
                            Some(self.container[index].next_entry)
                        }
                    },
                )
                .map(|index| &self.container[index].value),
            )
            .finish()
    }
}
