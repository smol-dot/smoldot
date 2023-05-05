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

export async function run(messagePort: MessagePort, cpuRateLimit: number): Promise<Promise<void>> {
    const whenShutdown = await instance.startInstanceServer<ParsedAddress>({
        cpuRateLimit,  // TODO: must be sanitized
        envVars: [],
        maxLogLevel: 3,
        performanceNow: () => {
            return performance.now()
        },
        getRandomValues: (buffer) => {
            if (buffer.length >= 1024 * 1024)
                throw new Error('getRandomValues buffer too large')
            randomFillSync(buffer)
        },
        parseMultiaddr: (address) => {
            // TODO: ignores config options; also code resuse
            const wsParsed = address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss|tls\/ws)$/);
            const tcpParsed = address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)$/);

            if (wsParsed != null) {
                const proto = (wsParsed[4] == 'ws') ? 'ws' : 'wss';
                const url = (wsParsed[1] == 'ip6') ?
                    (proto + "://[" + wsParsed[2] + "]:" + wsParsed[3]) :
                    (proto + "://" + wsParsed[2] + ":" + wsParsed[3]);

                return { success: true, address: { ty: "websocket", url } }
            } else if (tcpParsed != null) {
                return { success: true, address: { ty: "tcp", hostname: tcpParsed[2]!, port: parseInt(tcpParsed[3]!) } }

            } else {
                return { success: false, error: 'Unrecognized multiaddr format' }
            }
        },
    }, messagePort);

    return whenShutdown;
}

type ParsedAddress =
    { ty: "tcp", hostname: string, port: number } |
    { ty: "websocket", url: string }
