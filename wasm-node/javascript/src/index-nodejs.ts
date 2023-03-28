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

// Note: if you modify these imports, please test both the ModuleJS and CommonJS generated
// bindings. JavaScript being JavaScript, some libraries (such as `websocket`) have issues working
// with both at the same time.

import { Client, ClientOptions, start as innerStart } from './client.js'
import { Connection, ConnectionError, ConnectionConfig } from './instance/instance.js';

import { WebSocket } from 'ws';
import { inflate } from 'pako';

import { performance } from 'node:perf_hooks';
import { createConnection as nodeCreateConnection } from 'node:net';
import { randomFillSync } from 'node:crypto';

export {
  AddChainError,
  AddChainOptions,
  AlreadyDestroyedError,
  Chain,
  Client,
  ClientOptions,
  CrashError,
  MalformedJsonRpcError,
  QueueFullError,
  JsonRpcDisabledError,
  LogCallback
} from './client.js';

/**
 * Initializes a new client. This is a pre-requisite to connecting to a blockchain.
 *
 * Can never fail.
 *
 * @param options Configuration of the client. Defaults to `{}`.
 */
export function start(options?: ClientOptions): Client {
  options = options || {};

  return innerStart(options || {}, {
    trustedBase64DecodeAndZlibInflate: (input) => {
        return Promise.resolve(inflate(Buffer.from(input, 'base64')))
    },
    registerShouldPeriodicallyYield: (_callback) => {
      return [true, () => {}]
    },
    performanceNow: () => {
        return performance.now()
    },
    getRandomValues: (buffer) => {
      if (buffer.length >= 1024 * 1024)
        throw new Error('getRandomValues buffer too large')
      randomFillSync(buffer)
    },
    connect: (config) => {
      return connect(config, options?.forbidTcp || false, options?.forbidWs || false, options?.forbidNonLocalWs || false, options?.forbidWss || false)
    }
  })
}

/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws {@link ConnectionError} If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
function connect(config: ConnectionConfig, forbidTcp: boolean, forbidWs: boolean, forbidNonLocalWs: boolean, forbidWss: boolean): Connection {
    // Attempt to parse the multiaddress.
    // TODO: remove support for `/wss` in a long time (https://github.com/paritytech/smoldot/issues/1940)
    const wsParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)\/(ws|wss|tls\/ws)$/);
    const tcpParsed = config.address.match(/^\/(ip4|ip6|dns4|dns6|dns)\/(.*?)\/tcp\/(.*?)$/);

    if (wsParsed != null) {
        const proto = (wsParsed[4] == 'ws') ? 'ws' : 'wss';
        if (
            (proto == 'ws' && forbidWs) ||
            (proto == 'ws' && wsParsed[2] != 'localhost' && wsParsed[2] != '127.0.0.1' && forbidNonLocalWs) ||
            (proto == 'wss' && forbidWss)
        ) {
            throw new ConnectionError('Connection type not allowed');
        }

        const url = (wsParsed[1] == 'ip6') ?
            (proto + "://[" + wsParsed[2] + "]:" + wsParsed[3]) :
            (proto + "://" + wsParsed[2] + ":" + wsParsed[3]);

        const socket = new WebSocket(url);
        socket.binaryType = 'arraybuffer';

        const bufferedAmountCheck = { quenedUnreportedBytes: 0, nextTimeout: 10 };
        const checkBufferedAmount = () => {
            if (socket.readyState != 1)
                return;
            const bufferedAmount = socket.bufferedAmount;
            const wasSent = bufferedAmountCheck.quenedUnreportedBytes - bufferedAmount;
            bufferedAmountCheck.quenedUnreportedBytes = bufferedAmount;
            if (bufferedAmount != 0) {
                setTimeout(checkBufferedAmount, bufferedAmountCheck.nextTimeout);
                bufferedAmountCheck.nextTimeout *= 2;
                if (bufferedAmountCheck.nextTimeout > 500)
                    bufferedAmountCheck.nextTimeout = 500;
            }
            // Note: it is important to call `onWritableBytes` at the very end, as it might
            // trigger a call to `send`.
            config.onWritableBytes(wasSent);
        };

        socket.onopen = () => {
            config.onOpen({ type: 'single-stream', handshake: 'multistream-select-noise-yamux', initialWritableBytes: 1024 * 1024, writeClosable: false });
        };
        socket.onclose = (event) => {
            const message = "Error code " + event.code + (!!event.reason ? (": " + event.reason) : "");
            config.onConnectionReset(message);
            socket.onopen = () => { };
            socket.onclose = () => { };
            socket.onmessage = () => { };
            socket.onerror = () => { };
        };
        socket.onerror = (event) => {
            config.onConnectionReset(event.message);
            socket.onopen = () => { };
            socket.onclose = () => { };
            socket.onmessage = () => { };
            socket.onerror = () => { };
        };
        socket.onmessage = (msg) => {
            config.onMessage(new Uint8Array(msg.data as ArrayBuffer));
        };

        return {
            reset: (): void => {
                // We can't set these fields to null because the TypeScript definitions don't
                // allow it, but we can set them to dummy values.
                socket.onopen = () => { };
                socket.onclose = () => { };
                socket.onmessage = () => { };
                socket.onerror = () => { };
                socket.close();
            },
            send: (data: Uint8Array): void => {
                socket.send(data);
                if (bufferedAmountCheck.quenedUnreportedBytes == 0) {
                  bufferedAmountCheck.nextTimeout = 10;
                  setTimeout(checkBufferedAmount, 10);
                }
                bufferedAmountCheck.quenedUnreportedBytes += data.length;
            },
            closeSend: (): void => { throw new Error('Wrong connection type') },
            openOutSubstream: () => { throw new Error('Wrong connection type') }
        };

    } else if (tcpParsed != null) {
        // `net` module will be missing when we're not in NodeJS.
        if (forbidTcp) {
            throw new ConnectionError('TCP connections not available');
        }

        const socket = nodeCreateConnection({
            host: tcpParsed[2],
            port: parseInt(tcpParsed[3]!, 10),
        });

        // Number of bytes queued using `socket.write` and where `write` has returned false.
        const drainingBytes = { num: 0 };

        socket.setNoDelay();

        socket.on('connect', () => {
            if (socket.destroyed) return;
            config.onOpen({
                type: 'single-stream', handshake: 'multistream-select-noise-yamux',
                initialWritableBytes: socket.writableHighWaterMark, writeClosable: true
            });
        });
        socket.on('close', (hasError) => {
            if (socket.destroyed) return;
            // NodeJS doesn't provide a reason why the closing happened, but only
            // whether it was caused by an error.
            const message = hasError ? "Error" : "Closed gracefully";
            config.onConnectionReset(message);
        });
        socket.on('error', () => { });
        socket.on('data', (message) => {
            if (socket.destroyed) return;
            config.onMessage(new Uint8Array(message.buffer));
        });
        socket.on('drain', () => {
            // The bytes queued using `socket.write` and where `write` has returned false have now
            // been sent. Notify the API that it can write more data.
            if (socket.destroyed) return;
            const val = drainingBytes.num;
            drainingBytes.num = 0;
            config.onWritableBytes(val);
        });

        return {
            reset: (): void => {
                socket.destroy();
            },
            send: (data: Uint8Array): void => {
                const dataLen = data.length;
                const allWritten = socket.write(data);
                if (allWritten) {
                    setImmediate(() => {
                        if (!socket.writable) return;
                        config.onWritableBytes(dataLen)
                    });
                } else {
                    drainingBytes.num += dataLen;
                }
            },
            closeSend: (): void => {
                socket.end();
            },
            openOutSubstream: () => { throw new Error('Wrong connection type') }
        };

    } else {
        throw new ConnectionError('Unrecognized multiaddr format');
    }
}
