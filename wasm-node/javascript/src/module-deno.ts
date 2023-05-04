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

/**
 * Compiles and returns the smoldot WebAssembly binary.
 */
export async function compileModule(): Promise<WebAssembly.Module> {
    // The actual Wasm bytecode is base64-decoded then deflate-decoded from a constant found in a
    // different file.
    // This is suboptimal compared to using `instantiateStreaming`, but it is the most
    // cross-platform cross-bundler approach.
    return zlibInflate(trustedBase64Decode(wasmBase64)).then(((bytecode) => WebAssembly.compile(bytecode)));
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

/**
 * Decodes a base64 string.
 *
 * The input is assumed to be correct.
 */
function trustedBase64Decode(base64: string): Uint8Array {
    // This code is a bit sketchy due to the fact that we decode into a string, but it seems to
    // work.
    const binaryString = atob(base64);
    const size = binaryString.length;
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}


// Deno type definitions copy-pasted below, filtered to keep only what is necessary.
// The code below is under MIT license.

/*
MIT License

Copyright 2018-2022 the Deno authors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


// Original can be found here: https://github.com/denoland/deno/blob/main/ext/web/lib.deno_web.d.ts
/**
 * An API for decompressing a stream of data.
 *
 * @example
 * ```ts
 * const input = await Deno.open("./file.txt.gz");
 * const output = await Deno.create("./file.txt");
 *
 * await input.readable
 *   .pipeThrough(new DecompressionStream("gzip"))
 *   .pipeTo(output.writable);
 * ```
 */
declare class DecompressionStream {
    /**
     * Creates a new `DecompressionStream` object which decompresses a stream of
     * data.
     *
     * Throws a `TypeError` if the format passed to the constructor is not
     * supported.
     */
    constructor(format: string);

    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
}
