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

use core::fmt::{self, Write as _};

/// Returns an opaque object implementing the `fmt::Display` trait. Truncates the given `char`
/// yielding iterator to the given number of elements, and if the limit is reached adds a `…` at
/// the end.
pub fn truncated_str<'a>(
    input: impl Iterator<Item = char> + Clone + 'a,
    limit: usize,
) -> impl fmt::Display + 'a {
    struct Iter<I>(I, usize);

    impl<I: Iterator<Item = char> + Clone> fmt::Display for Iter<I> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut counter = 0;
            for c in self.0.clone() {
                f.write_char(c)?;

                counter += 1;
                if counter >= self.1 {
                    f.write_char('…')?;
                    break;
                }
            }

            Ok(())
        }
    }

    Iter(input, limit)
}
