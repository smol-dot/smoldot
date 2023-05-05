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

import * as instance from './instance/remote.js'
import { performance } from 'node:perf_hooks';
import { randomFillSync } from 'node:crypto';

/**
 * Runs the CPU-heavy parts of smoldot. Must be passed a port whose other end is passed to
 * `ClientOptions.portToWorker`.
 *
 * Returns a `Promise` that is ready when the smoldot client is shut down (either because it
 * crashes or intentionally with a call to `Client.terminate`).
 * Since this function is asynchronous, this `Promise` is wrapped around another `Promise`. In
 * other words, the outer `Promise` is ready when execution starts, and the inner `Promise` is
 * ready when execution ends.
 */
export async function run(messagePort: MessagePort): Promise<Promise<void>> {
    const whenShutdown = await instance.startInstanceServer({
        envVars: [],
        performanceNow: () => {
            return performance.now()
        },
        getRandomValues: (buffer) => {
            if (buffer.length >= 1024 * 1024)
                throw new Error('getRandomValues buffer too large')
            randomFillSync(buffer)
        },
    }, messagePort);

    return whenShutdown;
}
