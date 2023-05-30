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

/// <reference lib="dom" />

import { default as wasmBase64 } from './internals/bytecode/wasm.js';
import { classicDecode } from './internals/base64.js'
import { SmoldotBytecode } from './public-types.js';

/**
 * Compiles and returns the smoldot WebAssembly binary.
 */
export async function compileBytecode(): Promise<SmoldotBytecode> {
    // The actual Wasm bytecode is base64-decoded then deflate-decoded from a constant found in a
    // different file.
    // This is suboptimal compared to using `instantiateStreaming`, but it is the most
    // cross-platform cross-bundler approach.
    return WebAssembly.compile(await zlibInflate(classicDecode(wasmBase64)))
        .then((m) => { return { wasm: m } });
}

/**
 * Applies the zlib inflate algorithm on the buffer.
 */
async function zlibInflate(buffer: Uint8Array): Promise<Uint8Array> {
    // This code has been copy-pasted from the official streams draft specification.
    // At the moment, it is found here: https://wicg.github.io/compression/#example-deflate-compress
    const ds = new DecompressionStream('deflate');
    const writer = ds.writable.getWriter();
    writer.write(buffer);
    writer.close();
    const output = [];
    const reader = ds.readable.getReader();
    let totalSize = 0;
    while (true) {
        const { value, done } = await reader.read();
        if (done)
            break;
        output.push(value);
        totalSize += value.byteLength;
    }
    const concatenated = new Uint8Array(totalSize);
    let offset = 0;
    for (const array of output) {
        concatenated.set(array, offset);
        offset += array.byteLength;
    }
    return concatenated;
}
