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

import * as instance from './raw-instance.js';
import { AlreadyDestroyedError } from '../client.js';

/**
 * Thrown in case the underlying client encounters an unexpected crash.
 *
 * This is always an internal bug in smoldot and is never supposed to happen.
 */
export class CrashError extends Error {
    constructor(message: string) {
        super(message);
    }
}

/**
 * Thrown in case a malformed JSON-RPC request is sent.
 */
export class MalformedJsonRpcError extends Error {
    constructor() {
        super("JSON-RPC request is malformed");
    }
}

/**
 * Thrown in case the buffer of JSON-RPC requests is full and cannot accept any more request.
 */
export class QueueFullError extends Error {
    constructor() {
        super("JSON-RPC requests queue is full");
    }
}

/**
 * Connection to a remote node.
 *
 * At any time, a connection can be in one of the three following states:
 *
 * - `Opening` (initial state)
 * - `Open`
 * - `Reset`
 *
 * When in the `Opening` or `Open` state, the connection can transition to the `Reset` state
 * if the remote closes the connection or refuses the connection altogether. When that
 * happens, `config.onReset` is called. Once in the `Reset` state, the connection cannot
 * transition back to another state.
 *
 * Initially in the `Opening` state, the connection can transition to the `Open` state if the
 * remote accepts the connection. When that happens, `config.onOpen` is called.
 *
 * When in the `Open` state, the connection can receive messages. When a message is received,
 * `config.onMessage` is called.
 *
 * @see connect
 */
export interface Connection {
    /**
     * Transitions the connection or one of its substreams to the `Reset` state.
     *
     * If the connection is of type "single-stream", the whole connection must be shut down.
     * If the connection is of type "multi-stream", a `streamId` can be provided, in which case
     * only the given substream is shut down.
     *
     * The `config.onReset` or `config.onStreamReset` callbacks are **not** called.
     *
     * The transition is performed in the background.
     * If the whole connection is to be shut down, none of the callbacks passed to the `Config`
     * must be called again. If only a substream is shut down, the `onStreamReset` and `onMessage`
     * callbacks must not be called again with that substream.
     */
    reset(streamId?: number): void;

    /**
     * Queues data to be sent on the given connection.
     *
     * The connection and stream must currently be in the `Open` state.
     *
     * The number of bytes must never exceed the number of "writable bytes" of the stream.
     * `onWritableBytes` can be used in order to notify that more writable bytes are available.
     *
     * The `streamId` must be provided if and only if the connection is of type "multi-stream".
     * It indicates which substream to send the data on.
     *
     * Must not be called after `closeSend` has been called.
     */
    send(data: Uint8Array, streamId?: number): void;

    /**
     * Closes the writing side of the given stream of the given connection.
     *
     * Never called for connection types where this isn't possible to implement (i.e. WebSocket
     * and WebRTC at the moment).
     *
     * The connection and stream must currently be in the `Open` state.
     *
     * Implicitly sets the "writable bytes" of the stream to zero.
     *
     * The `streamId` must be provided if and only if the connection is of type "multi-stream".
     * It indicates which substream to send the data on.
     *
     * Must only be called once per stream.
     */
    closeSend(streamId?: number): void;

    /**
     * Start opening an additional outbound substream on the given connection.
     *
     * The state of the connection must be `Open`. This function must only be called for
     * connections of type "multi-stream".
     *
     * The `onStreamOpened` callback must later be called with an outbound direction.
     * 
     * Note that no mechanism exists in this API to handle the situation where a substream fails
     * to open, as this is not supposed to happen. If you need to handle such a situation, either
     * try again opening a substream again or reset the entire connection.
     */
    openOutSubstream(): void;
}

/**
 * Configuration for a connection.
 *
 * @see connect
 */
export interface ConnectionConfig<C> {
    /**
     * Parsed multiaddress, as returned by the `parseMultiaddr` function.
     */
    address: C,

    /**
     * Callback called when the connection transitions from the `Opening` to the `Open` state.
     *
     * Must only be called once per connection.
     */
    onOpen: (info:
        {
            type: 'single-stream', handshake: 'multistream-select-noise-yamux',
            initialWritableBytes: number, writeClosable: boolean
        } |
        {
            type: 'multi-stream', handshake: 'webrtc',
            localTlsCertificateMultihash: Uint8Array,
            remoteTlsCertificateMultihash: Uint8Array,
        }
    ) => void;

    /**
     * Callback called when the connection transitions to the `Reset` state.
     *
     * It it **not** called if `Connection.reset` is manually called by the API user.
     */
    onConnectionReset: (message: string) => void;

    /**
     * Callback called when a new substream has been opened.
     *
     * This function must only be called for connections of type "multi-stream".
     */
    onStreamOpened: (streamId: number, direction: 'inbound' | 'outbound', initialWritableBytes: number) => void;

    /**
     * Callback called when a stream transitions to the `Reset` state.
     *
     * It it **not** called if `Connection.resetStream` is manually called by the API user.
     *
     * This function must only be called for connections of type "multi-stream".
     */
    onStreamReset: (streamId: number) => void;

    /**
     * Callback called when some data sent using {@link Connection.send} has effectively been
     * written on the stream, meaning that some buffer space is now free.
     *
     * Can only happen while the connection is in the `Open` state.
     *
     * This callback must not be called after `closeSend` has been called.
     *
     * The `streamId` parameter must be provided if and only if the connection is of type
     * "multi-stream".
     *
     * Only a number of bytes equal to the size of the data provided to {@link Connection.send}
     * must be reported. In other words, the `initialWritableBytes` must never be exceeded.
     */
    onWritableBytes: (numExtra: number, streamId?: number) => void;

    /**
     * Callback called when a message sent by the remote has been received.
     *
     * Can only happen while the connection is in the `Open` state.
     *
     * The `streamId` parameter must be provided if and only if the connection is of type
     * "multi-stream".
     */
    onMessage: (message: Uint8Array, streamId?: number) => void;
}

/**
 * Emitted by `connect` if the multiaddress couldn't be parsed or contains an invalid protocol.
 *
 * @see connect
 */
export class ConnectionError extends Error {
    constructor(message: string) {
        super(message);
    }
}

/**
 * Contains the configuration of the instance.
 */
export interface Config {
    wasmModule: Promise<WebAssembly.Module>,
    logCallback: (level: number, target: string, message: string) => void
    maxLogLevel: number;
    cpuRateLimit: number,
}

/**
 * Contains functions that the client will use when it needs to leverage the platform.
 */
export interface PlatformBindings<A> extends instance.PlatformBindings {
    /**
     * Tries to open a new connection using the given configuration.
     *
     * @see Connection
     * @throws {@link ConnectionError} If the multiaddress couldn't be parsed or contains an invalid protocol.
     */
    connect(config: ConnectionConfig<A>): Connection;

    parseMultiaddr(address: string): { success: true, address: A } | { success: false, error: string };
}

export interface Instance {
    request: (request: string, chainId: number) => void
    nextJsonRpcResponse: (chainId: number) => Promise<string>
    addChain: (chainSpec: string, databaseContent: string, potentialRelayChains: number[], disableJsonRpc: boolean) => Promise<{ success: true, chainId: number } | { success: false, error: string }>
    removeChain: (chainId: number) => void
    startShutdown: () => void
}

export function start<A>(configMessage: Config, platformBindings: PlatformBindings<A>): Instance {

    // This variable represents the state of the instance, and serves two different purposes:
    //
    // - At initialization, it is a Promise containing the Wasm VM is still initializing.
    // - After the Wasm VM has finished initialization, contains the `WebAssembly.Instance` object.
    //
    let state: { initialized: false, promise: Promise<instance.Instance> } | { initialized: true, instance: instance.Instance };

    const crashError: { error?: CrashError } = {};

    const currentTask: { name: string | null } = { name: null };

    const printError = { printError: true }

    const connections: Map<number, Connection> = new Map();

    // Contains the information of each chain that is currently alive.
    let chains: Map<number, {
        jsonRpcResponsesPromises: JsonRpcResponsesPromise[],
    }> = new Map();

    const initPromise = (async (): Promise<instance.Instance> => {
        const module = await configMessage.wasmModule;

        // Start initialization of the Wasm VM.
        const config: instance.Config<A> = {
            eventCallback: (event) => {
                switch (event.ty) {
                    case "wasm-panic": {
                        // TODO: consider obtaining a backtrace here
                        crashError.error = new CrashError(event.message);
                        if (!printError.printError)
                            return;
                        console.error(
                            "Smoldot has panicked" +
                            (currentTask.name ? (" while executing task `" + currentTask.name + "`") : "") +
                            ". This is a bug in smoldot. Please open an issue at " +
                            "https://github.com/smol-dot/smoldot/issues with the following message:\n" +
                            event.message
                        );
                        for (const chain of Array.from(chains.values())) {
                            for (const promise of chain.jsonRpcResponsesPromises) {
                                promise.reject(crashError.error)
                            }
                            chain.jsonRpcResponsesPromises = [];
                        }
                        break
                    }
                    case "log": {
                        configMessage.logCallback(event.level, event.target, event.message)
                        break;
                    }
                    case "json-rpc-responses-non-empty": {
                        // Notify every single promise found in `jsonRpcResponsesPromises`.
                        const promises = chains.get(event.chainId)!.jsonRpcResponsesPromises;
                        while (promises.length !== 0) {
                            promises.shift()!.resolve();
                        }
                        break;
                    }
                    case "current-task": {
                        currentTask.name = event.taskName;
                        break;
                    }
                    case "new-connection": {
                        const connectionId = event.connectionId;
                        connections.set(connectionId, platformBindings.connect({
                            address: event.address,
                            onConnectionReset(message) {
                                if (!state.initialized)
                                    throw new Error();
                                connections.delete(connectionId);
                                state.instance.connectionReset(connectionId, message);
                            },
                            onMessage(message, streamId) {
                                if (!state.initialized)
                                    throw new Error();
                                state.instance.streamMessage(connectionId, message, streamId);
                            },
                            onStreamOpened(streamId, direction, initialWritableBytes) {
                                if (!state.initialized)
                                    throw new Error();
                                state.instance.streamOpened(connectionId, streamId, direction, initialWritableBytes);
                            },
                            onOpen(info) {
                                if (!state.initialized)
                                    throw new Error();
                                state.instance.connectionOpened(connectionId, info);
                            },
                            onWritableBytes(numExtra, streamId) {
                                if (!state.initialized)
                                    throw new Error();
                                state.instance.streamWritableBytes(connectionId, numExtra, streamId);
                            },
                            onStreamReset(streamId) {
                                if (!state.initialized)
                                    throw new Error();
                                state.instance.streamReset(connectionId, streamId);
                            },
                        }));
                        break;
                    }
                    case "connection-reset": {
                        const connection = connections.get(event.connectionId)!;
                        connection.reset();
                        connections.delete(event.connectionId);
                        break;
                    }
                    case "connection-stream-open": {
                        const connection = connections.get(event.connectionId)!;
                        connection.openOutSubstream();
                        break;
                    }
                    case "connection-stream-reset": {
                        const connection = connections.get(event.connectionId)!;
                        connection.reset(event.streamId);
                        break;
                    }
                    case "stream-send": {
                        const connection = connections.get(event.connectionId)!;
                        connection.send(event.data, event.streamId);
                        break;
                    }
                    case "stream-send-close": {
                        const connection = connections.get(event.connectionId)!;
                        connection.closeSend(event.streamId);
                        break;
                    }
                }
            },
            parseMultiaddr: platformBindings.parseMultiaddr,
            platformBindings,
            wasmModule: module,
            cpuRateLimit: configMessage.cpuRateLimit,
            maxLogLevel: configMessage.maxLogLevel,
        };

        return await instance.startInstance(config)
    })();

    state = {
        initialized: false, promise: initPromise.then((instance) => {
            state = { initialized: true, instance };
            return instance;
        })
    };

    async function queueOperation<T>(operation: (instance: instance.Instance) => T): Promise<T> {
        // What to do depends on the type of `state`.
        // See the documentation of the `state` variable for information.
        if (!state.initialized) {
            // A message has been received while the Wasm VM is still initializing. Queue it for when
            // initialization is over.
            return state.promise.then((instance) => operation(instance))

        } else {
            // Everything is already initialized. Process the message synchronously.
            return operation(state.instance)
        }
    }

    return {
        request: (request: string, chainId: number) => {
            // Because `request` is passed as parameter an identifier returned by `addChain`, it is
            // always the case that the Wasm instance is already initialized. The only possibility for
            // it to not be the case is if the user completely invented the `chainId`.
            if (!state.initialized)
                throw new Error("Internal error");
            if (crashError.error)
                throw crashError.error;

            let retVal;
            try {
                retVal = state.instance.request(request, chainId);
            } catch (_error) {
                console.assert(crashError.error);
                throw crashError.error
            }

            switch (retVal) {
                case 0: break;
                case 1: throw new MalformedJsonRpcError();
                case 2: throw new QueueFullError();
                default: throw new Error("Internal error: unknown json_rpc_send error code: " + retVal)
            }
        },

        nextJsonRpcResponse: async (chainId: number): Promise<string> => {
            // Because `nextJsonRpcResponse` is passed as parameter an identifier returned by `addChain`,
            // it is always the case that the Wasm instance is already initialized. The only possibility
            // for it to not be the case is if the user completely invented the `chainId`.
            if (!state.initialized)
                throw new Error("Internal error");

            while (true) {
                if (crashError.error)
                    throw crashError.error;

                // Try to pop a message from the queue.
                try {
                    const message = state.instance.peekJsonRpcResponse(chainId);
                    if (message)
                        return message;
                } catch (_error) {
                    console.assert(crashError.error);
                    throw crashError.error
                }

                // If no message is available, wait for one to be.
                await new Promise((resolve, reject) => {
                    chains.get(chainId)!.jsonRpcResponsesPromises.push({ resolve: () => resolve(undefined), reject })
                });
            }
        },

        addChain: (chainSpec: string, databaseContent: string, potentialRelayChains: number[], disableJsonRpc: boolean): Promise<{ success: true, chainId: number } | { success: false, error: string }> => {
            return queueOperation((instance) => {
                if (crashError.error)
                    throw crashError.error;

                try {
                    const result = instance.addChain(chainSpec, databaseContent, potentialRelayChains, disableJsonRpc);
                    if (result.success) {
                        console.assert(!chains.has(result.chainId));
                        chains.set(result.chainId, {
                            jsonRpcResponsesPromises: new Array()
                        });
                    }

                    return result;

                } catch (_error) {
                    console.assert(crashError.error);
                    throw crashError.error
                }
            })
        },

        removeChain: (chainId: number) => {
            // Because `removeChain` is passed as parameter an identifier returned by `addChain`, it is
            // always the case that the Wasm instance is already initialized. The only possibility for
            // it to not be the case is if the user completely invented the `chainId`.
            if (!state.initialized)
                throw new Error("Internal error");
            if (crashError.error)
                throw crashError.error;

            // Removing the chain synchronously avoids having to deal with race conditions such as a
            // JSON-RPC response corresponding to a chain that is going to be deleted but hasn't been yet.
            // These kind of race conditions are already delt with within smoldot.
            console.assert(chains.has(chainId));
            for (const { reject } of chains.get(chainId)!.jsonRpcResponsesPromises) {
                reject(new AlreadyDestroyedError());
            }
            chains.delete(chainId);
            try {
                state.instance.removeChain(chainId);
            } catch (_error) {
                console.assert(crashError.error);
                throw crashError.error
            }
        },

        startShutdown: () => {
            return queueOperation((instance) => {
                // `startShutdown` is a bit special in its handling of crashes.
                // Shutting down will lead to `onWasmPanic` being called at some point, possibly during
                // the call to `start_shutdown` itself. As such, we move into "don't print errors anymore"
                // mode even before calling `start_shutdown`.
                //
                // Furthermore, if a crash happened in the past, there is no point in throwing an
                // exception when the user wants the shutdown to happen.
                if (crashError.error)
                    return;
                try {
                    printError.printError = false
                    instance.startShutdown()
                } catch (_error) {
                }
            })
        }
    }

}

interface JsonRpcResponsesPromise {
    resolve: () => void,
    reject: (error: Error) => void,
}
