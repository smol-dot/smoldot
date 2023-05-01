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

import { performance } from 'node:perf_hooks';
import { randomFillSync } from 'node:crypto';

import * as instance from './instance/raw-instance.js';

// TODO: stronger typing? see "branded types"
export async function run(wasmModule: any) {
    const config: instance.Config = {
        onWasmPanic: (_message) => {
            // TODO: completetly unclear what to do
        },
        logCallback: (_level, _target, _message) => {
            // TODO: ?!?!
        },
        wasmModule: wasmModule,
        cpuRateLimit: 1.0, // TODO: make configurable
    };

    const platformBindings = {
        trustedBase64DecodeAndZlibInflate: (_input: any) => {
            // TODO: don't pass this
            throw new Error();
        },
        performanceNow: () => {
            return performance.now()
        },
        getRandomValues: (buffer: Uint8Array) => {
            if (buffer.length >= 1024 * 1024)
                throw new Error('getRandomValues buffer too large')
            randomFillSync(buffer)
        },
        connect: () => {
            throw new Error();
        }
    };

    const [_instance, _bufferIndices, executor] = await instance.startInstance(config, platformBindings);
    await executor;
}
