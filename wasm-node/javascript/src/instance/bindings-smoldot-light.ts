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

//! Exports a function that provides bindings for the bindings found in the Rust part of the code.
//!
//! In order to use this code, call the function passing an object, then fill the `instance` field
//! of that object with the Wasm instance.

import * as buffer from './buffer.js';
import type { SmoldotWasmInstance } from './bindings.js';

export interface Config<A> {
    instance?: SmoldotWasmInstance,

    /**
     * Array used to store the buffers provided to the Rust code.
     *
     * When `buffer_size` or `buffer_index` are called, the buffer is found here.
     */
    bufferIndices: Array<Uint8Array>,

    parseMultiaddr(address: string): { success: true, address: A } | { success: false, error: string };

    /**
     * Closure to call when the Wasm instance calls `panic`.
     *
     * This callback will always be invoked from within a binding called the Wasm instance.
     */
    onPanic: (message: string) => never,

    logCallback: (level: number, target: string, message: string) => void,
    jsonRpcResponsesNonEmptyCallback: (chainId: number) => void,
    advanceExecutionReadyCallback: () => void,
    currentTaskCallback?: (taskName: string | null) => void,

    newConnection: (connectionId: number, address: A) => void,
    connectionReset: (connectionId: number) => void,
    connectionStreamOpened: (connectionId: number) => void,
    connectionStreamReset: (connectionId: number, streamId: number) => void,
    streamSent: (connectionId: number, data: Uint8Array, streamId?: number) => void,
    streamSendClosed: (connectionId: number, streamId?: number) => void,
}

export default function <A>(config: Config<A>): { imports: WebAssembly.ModuleImports, killAll: () => void } {
    // Object containing a boolean indicating whether the `killAll` function has been invoked by
    // the user.
    const killedTracked = { killed: false };

    const killAll = () => {
        killedTracked.killed = true;
        // TODO: kill timers?
    };

    const imports = {
        // Must exit with an error. A human-readable message can be found in the WebAssembly
        // memory in the given buffer.
        panic: (ptr: number, len: number) => {
            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const message = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), ptr, len);
            config.onPanic(message);
        },

        buffer_size: (bufferIndex: number) => {
            const buf = config.bufferIndices[bufferIndex]!;
            return buf.byteLength;
        },

        buffer_copy: (bufferIndex: number, targetPtr: number) => {
            const instance = config.instance!;
            targetPtr = targetPtr >>> 0;

            const buf = config.bufferIndices[bufferIndex]!;
            new Uint8Array(instance.exports.memory.buffer).set(buf, targetPtr);
        },

        advance_execution_ready: () => {
            config.advanceExecutionReadyCallback();
        },

        // Used by the Rust side to notify that a JSON-RPC response or subscription notification
        // is available in the queue of JSON-RPC responses.
        json_rpc_responses_non_empty: (chainId: number) => {
            if (killedTracked.killed) return;
            config.jsonRpcResponsesNonEmptyCallback(chainId);
        },

        // Used by the Rust side to emit a log entry.
        // See also the `max_log_level` parameter in the configuration.
        log: (level: number, targetPtr: number, targetLen: number, messagePtr: number, messageLen: number) => {
            if (killedTracked.killed) return;

            const instance = config.instance!;

            targetPtr >>>= 0;
            targetLen >>>= 0;
            messagePtr >>>= 0;
            messageLen >>>= 0;

            if (config.logCallback) {
                const mem = new Uint8Array(instance.exports.memory.buffer);
                let target = buffer.utf8BytesToString(mem, targetPtr, targetLen);
                let message = buffer.utf8BytesToString(mem, messagePtr, messageLen);
                config.logCallback(level, target, message);
            }
        },

        // Must call `timer_finished` after the given number of milliseconds has elapsed.
        start_timer: (ms: number) => {
            if (killedTracked.killed) return;

            const instance = config.instance!;

            // In both NodeJS and browsers, if `setTimeout` is called with a value larger than
            // 2147483647, the delay is for some reason instead set to 1.
            // As mentioned in the documentation of `start_timer`, it is acceptable to end the
            // timer before the given number of milliseconds has passed.
            if (ms > 2147483647)
                ms = 2147483647;

            // In browsers, `setTimeout` works as expected when `ms` equals 0. However, NodeJS
            // requires a minimum of 1 millisecond (if `0` is passed, it is automatically replaced
            // with `1`) and wants you to use `setImmediate` instead.
            if (ms < 1 && typeof setImmediate === "function") {
                setImmediate(() => {
                    if (killedTracked.killed) return;
                    try {
                        instance.exports.timer_finished();
                    } catch (_error) { }
                })
            } else {
                setTimeout(() => {
                    if (killedTracked.killed) return;
                    try {
                        instance.exports.timer_finished();
                    } catch (_error) { }
                }, ms)
            }
        },

        // Must create a new connection object. This implementation stores the created object in
        // `connections`.
        connection_new: (connectionId: number, addrPtr: number, addrLen: number, errorBufferIndexPtr: number) => {
            const instance = config.instance!;

            addrPtr >>>= 0;
            addrLen >>>= 0;
            errorBufferIndexPtr >>>= 0;

            const address = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), addrPtr, addrLen);
            const result = config.parseMultiaddr(address);
            if (result.success) {
                config.newConnection(connectionId, result.address)
                return 0
            } else {
                const mem = new Uint8Array(instance.exports.memory.buffer);
                config.bufferIndices[0] = new TextEncoder().encode(result.error)
                buffer.writeUInt32LE(mem, errorBufferIndexPtr, 0);
                buffer.writeUInt8(mem, errorBufferIndexPtr + 4, 1);  // TODO: remove isBadAddress param since it's always true
                return 1;
            }

            /*if (!!connections[connectionId]) {
                throw new Error("internal error: connection already allocated");
            }

            const address = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), addrPtr, addrLen);
            const parseResult = config.parseMultiaddr(address);

            if (parseResult.success) {
                if (killedTracked.killed)
                    throw new Error("killAll invoked");

                const connec = config.connect({
                    address: parseResult.address,
                    onOpen: (info) => {
                        if (killedTracked.killed) return;
                        try {
                            switch (info.type) {
                                case 'single-stream': {
                                    instance.exports.connection_open_single_stream(connectionId, 0, info.initialWritableBytes, info.writeClosable ? 1 : 0);
                                    break
                                }
                                case 'multi-stream': {
                                    const handshakeTy = new Uint8Array(1 + info.localTlsCertificateMultihash.length + info.remoteTlsCertificateMultihash.length);
                                    buffer.writeUInt8(handshakeTy, 0, 0);
                                    handshakeTy.set(info.localTlsCertificateMultihash, 1)
                                    handshakeTy.set(info.remoteTlsCertificateMultihash, 1 + info.localTlsCertificateMultihash.length)
                                    config.bufferIndices[0] = handshakeTy;
                                    instance.exports.connection_open_multi_stream(connectionId, 0);
                                    delete config.bufferIndices[0]
                                    break
                                }
                            }
                        } catch (_error) { }
                    },
                    onConnectionReset: (message: string) => {
                        if (killedTracked.killed) return;
                        try {
                            config.bufferIndices[0] = new TextEncoder().encode(message);
                            instance.exports.connection_reset(connectionId, 0);
                            delete config.bufferIndices[0]
                        } catch (_error) { }
                    },
                    onWritableBytes: (numExtra, streamId) => {
                        if (killedTracked.killed) return;
                        try {
                            instance.exports.stream_writable_bytes(
                                connectionId,
                                streamId || 0,
                                numExtra,
                            );
                        } catch (_error) { }
                    },
                    onMessage: (message: Uint8Array, streamId?: number) => {
                        if (killedTracked.killed) return;
                        try {
                            config.bufferIndices[0] = message;
                            instance.exports.stream_message(connectionId, streamId || 0, 0);
                            delete config.bufferIndices[0]
                        } catch (_error) { }
                    },
                    onStreamOpened: (streamId: number, direction: 'inbound' | 'outbound', initialWritableBytes) => {
                        if (killedTracked.killed) return;
                        try {
                            instance.exports.connection_stream_opened(
                                connectionId,
                                streamId,
                                direction === 'outbound' ? 1 : 0,
                                initialWritableBytes
                            );
                        } catch (_error) { }
                    },
                    onStreamReset: (streamId: number) => {
                        if (killedTracked.killed) return;
                        try {
                            instance.exports.stream_reset(connectionId, streamId);
                        } catch (_error) { }
                    }

                });

                connections[connectionId] = connec;
                return 0;

            } else {
                const mem = new Uint8Array(instance.exports.memory.buffer);
                config.bufferIndices[0] = new TextEncoder().encode(parseResult.error)
                buffer.writeUInt32LE(mem, errorBufferIndexPtr, 0);
                buffer.writeUInt8(mem, errorBufferIndexPtr + 4, 1); // TODO: remove isBadAddress param since it's always true
                return 1;
            }*/
        },

        // Must close and destroy the connection object.
        reset_connection: (connectionId: number) => {
            config.connectionReset(connectionId);
        },

        // Opens a new substream on a multi-stream connection.
        connection_stream_open: (connectionId: number) => {
            config.connectionStreamOpened(connectionId);
        },

        // Closes a substream on a multi-stream connection.
        connection_stream_reset: (connectionId: number, streamId: number) => {
            config.connectionStreamReset(connectionId, streamId);
        },

        // Must queue the data found in the WebAssembly memory at the given pointer. It is assumed
        // that this function is called only when the connection is in an open state.
        stream_send: (connectionId: number, streamId: number, ptr: number, len: number) => {
            if (killedTracked.killed) return;

            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const data = new Uint8Array(instance.exports.memory.buffer).slice(ptr, ptr + len);
            config.streamSent(connectionId, data, streamId); // TODO: docs says the streamId is provided only for multi-stream connections, but here it's always provided
        },

        stream_send_close: (connectionId: number, streamId: number) => {
            config.streamSendClosed(connectionId, streamId); // TODO: docs says the streamId is provided only for multi-stream connections, but here it's always provided
        },

        current_task_entered: (ptr: number, len: number) => {
            if (killedTracked.killed) return;

            const instance = config.instance!;

            ptr >>>= 0;
            len >>>= 0;

            const taskName = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), ptr, len);
            if (config.currentTaskCallback)
                config.currentTaskCallback(taskName);
        },

        current_task_exit: () => {
            if (killedTracked.killed) return;
            if (config.currentTaskCallback)
                config.currentTaskCallback(null);
        }
    };

    return { imports, killAll }
}
