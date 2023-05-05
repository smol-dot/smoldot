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

import { default as wasmBase64 } from './module/autogen/wasm.js';
import { inflate } from 'pako';

/**
 * Compiles and returns the smoldot WebAssembly binary.
 */
export async function compileModule(): Promise<WebAssembly.Module> {
    // The actual Wasm bytecode is base64-decoded then deflate-decoded from a constant found in a
    // different file.
    // This is suboptimal compared to using `instantiateStreaming`, but it is the most
    // cross-platform cross-bundler approach.
    return WebAssembly.compile(inflate(Buffer.from(wasmBase64, 'base64')));
}
