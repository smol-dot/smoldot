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

import * as buffer from './buffer.js';
import * as instance from './raw-instance.js';
import { SmoldotWasmInstance } from './bindings.js';
import { AlreadyDestroyedError } from '../client.js';

export { PlatformBindings, ConnectionError, ConnectionConfig, Connection } from './raw-instance.js';

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
 * Contains the configuration of the instance.
 */
export interface Config {
    wasmModule: Promise<WebAssembly.Module>,
    logCallback: (level: number, target: string, message: string) => void
    maxLogLevel: number;
    cpuRateLimit: number,
}

export interface Instance {
    request: (request: string, chainId: number) => void
    nextJsonRpcResponse: (chainId: number) => Promise<string>
    addChain: (chainSpec: string, databaseContent: string, potentialRelayChains: number[], disableJsonRpc: boolean) => Promise<{ success: true, chainId: number } | { success: false, error: string }>
    removeChain: (chainId: number) => void
    startShutdown: () => void
}

export function start(configMessage: Config, platformBindings: instance.PlatformBindings): Instance {

    // This variable represents the state of the instance, and serves two different purposes:
    //
    // - At initialization, it is a Promise containing the Wasm VM is still initializing.
    // - After the Wasm VM has finished initialization, contains the `WebAssembly.Instance` object.
    //
    let state: { initialized: false, promise: Promise<[SmoldotWasmInstance, Array<Uint8Array>]> } | { initialized: true, instance: SmoldotWasmInstance, bufferIndices: Array<Uint8Array> };

    const crashError: { error?: CrashError } = {};

    const currentTask: { name: string | null } = { name: null };

    const printError = { printError: true }

    // Contains the information of each chain that is currently alive.
    let chains: Map<number, {
        jsonRpcResponsesPromises: JsonRpcResponsesPromise[],
    }> = new Map();

    const initPromise = (async (): Promise<[SmoldotWasmInstance, Array<Uint8Array>]> => {
        const module = await configMessage.wasmModule;

        // Start initialization of the Wasm VM.
        const config: instance.Config = {
            onWasmPanic: (message) => {
                // TODO: consider obtaining a backtrace here
                crashError.error = new CrashError(message);
                if (!printError.printError)
                    return;
                console.error(
                    "Smoldot has panicked" +
                    (currentTask.name ? (" while executing task `" + currentTask.name + "`") : "") +
                    ". This is a bug in smoldot. Please open an issue at " +
                    "https://github.com/smol-dot/smoldot/issues with the following message:\n" +
                    message
                );
                for (const chain of Array.from(chains.values())) {
                    for (const promise of chain.jsonRpcResponsesPromises) {
                        promise.reject(crashError.error)
                    }
                    chain.jsonRpcResponsesPromises = [];
                }
            },
            logCallback: (level, target, message) => {
                configMessage.logCallback(level, target, message)
            },
            wasmModule: module,
            jsonRpcResponsesNonEmptyCallback: (chainId) => {
                // Notify every single promise found in `jsonRpcResponsesPromises`.
                const promises = chains.get(chainId)!.jsonRpcResponsesPromises;
                while (promises.length !== 0) {
                    promises.shift()!.resolve();
                }
            },
            currentTaskCallback: (taskName) => {
                currentTask.name = taskName
            },
            cpuRateLimit: configMessage.cpuRateLimit,
            maxLogLevel: configMessage.maxLogLevel,
        };

        return await instance.startInstance(config, platformBindings)
    })();

    state = {
        initialized: false, promise: initPromise.then(([instance, bufferIndices]) => {
            state = { initialized: true, instance, bufferIndices };
            return [instance, bufferIndices];
        })
    };

    async function queueOperation<T>(operation: (instance: SmoldotWasmInstance, bufferIndices: Array<Uint8Array>) => T): Promise<T> {
        // What to do depends on the type of `state`.
        // See the documentation of the `state` variable for information.
        if (!state.initialized) {
            // A message has been received while the Wasm VM is still initializing. Queue it for when
            // initialization is over.
            return state.promise.then(([instance, bufferIndices]) => operation(instance, bufferIndices))

        } else {
            // Everything is already initialized. Process the message synchronously.
            return operation(state.instance, state.bufferIndices)
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
                state.bufferIndices[0] = new TextEncoder().encode(request)
                retVal = state.instance.exports.json_rpc_send(0, chainId) >>> 0;
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
                    const mem = new Uint8Array(state.instance.exports.memory.buffer);
                    const responseInfo = state.instance.exports.json_rpc_responses_peek(chainId) >>> 0;
                    const ptr = buffer.readUInt32LE(mem, responseInfo) >>> 0;
                    const len = buffer.readUInt32LE(mem, responseInfo + 4) >>> 0;

                    // `len === 0` means "queue is empty" according to the API.
                    // In that situation, queue the resolve/reject.
                    if (len !== 0) {
                        const message = buffer.utf8BytesToString(mem, ptr, len);
                        state.instance.exports.json_rpc_responses_pop(chainId);
                        return message;
                    }
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
            return queueOperation((instance, bufferIndices) => {
                if (crashError.error)
                    throw crashError.error;

                try {
                    // `add_chain` unconditionally allocates a chain id. If an error occurs, however, this chain
                    // id will refer to an *erroneous* chain. `chain_is_ok` is used below to determine whether it
                    // has succeeeded or not.
                    // Note that `add_chain` properly de-allocates buffers even if it failed.
                    bufferIndices[0] = new TextEncoder().encode(chainSpec)
                    bufferIndices[1] = new TextEncoder().encode(databaseContent)
                    const potentialRelayChainsEncoded = new Uint8Array(potentialRelayChains.length * 4)
                    for (let idx = 0; idx < potentialRelayChains.length; ++idx) {
                        buffer.writeUInt32LE(potentialRelayChainsEncoded, idx * 4, potentialRelayChains[idx]!);
                    }
                    bufferIndices[2] = potentialRelayChainsEncoded
                    const chainId = instance.exports.add_chain(0, 1, disableJsonRpc ? 0 : 1, 2);

                    delete bufferIndices[0]
                    delete bufferIndices[1]
                    delete bufferIndices[2]

                    if (instance.exports.chain_is_ok(chainId) != 0) {
                        console.assert(!chains.has(chainId));
                        chains.set(chainId, {
                            jsonRpcResponsesPromises: new Array()
                        });
                        return { success: true, chainId };
                    } else {
                        const errorMsgLen = instance.exports.chain_error_len(chainId) >>> 0;
                        const errorMsgPtr = instance.exports.chain_error_ptr(chainId) >>> 0;
                        const errorMsg = buffer.utf8BytesToString(new Uint8Array(instance.exports.memory.buffer), errorMsgPtr, errorMsgLen);
                        instance.exports.remove_chain(chainId);
                        return { success: false, error: errorMsg };
                    }
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
                state.instance.exports.remove_chain(chainId);
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
                    instance.exports.start_shutdown()
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
