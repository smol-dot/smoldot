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

import * as instance from './instance/raw-instance.js';

export async function run(messagePort: MessagePort, cpuRateLimit: number) {
    const wasmModule = await new Promise((resolve) => {
        messagePort.onmessage = (msg) => resolve(msg.data);
    }) as { module: WebAssembly.Module, memory: WebAssembly.Memory };

    const config: instance.Config = {
        onWasmPanic: (_message) => {
            // TODO: completetly unclear what to do
            throw new Error(_message);
        },
        logCallback: (_level, _target, _message) => {
            // TODO: ?!?!
            console.log(_message);
        },
        wasmModule,
        cpuRateLimit,
        executeNonNetworkingTasks: true,
        threadTy: { ty: "secondary", startPtr: 0 },  // TODO: no, pass correct pointer
    };

    const platformBindings = {
        performanceNow: () => {
            return performance.now()
        },
        getRandomValues: (buffer: Uint8Array) => {
            const crypto = globalThis.crypto;
            if (!crypto)
                throw new Error('randomness not available');

            // Browsers have this completely undocumented behavior (it's not even part of a spec)
            // that for some reason `getRandomValues` can't be called on arrayviews back by
            // `SharedArrayBuffer`s and they throw an exception if you try.
            if (buffer.buffer instanceof ArrayBuffer)
                crypto.getRandomValues(buffer);
            else {
                const tmpArray = new Uint8Array(buffer.length);
                crypto.getRandomValues(tmpArray);
                buffer.set(tmpArray);
            }
        },
        connect: null,
    };

    const [_instance, _bufferIndices, executor] = await instance.startInstance(config, platformBindings);
    await executor;
}
