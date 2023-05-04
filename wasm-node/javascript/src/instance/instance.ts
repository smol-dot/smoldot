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

import { PlatformBindings, Connection } from '../client.js';
import * as instance from './raw-instance.js';
import { AlreadyDestroyedError, CrashError, MalformedJsonRpcError, QueueFullError } from '../public-types.js';

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

    const addChainResults: Array<(outcome: { success: true, chainId: number } | { success: false, error: string }) => void> = new Array();

    // Contains the information of each chain that is currently alive.
    let chains: Map<number, {
        jsonRpcResponsesPromises: JsonRpcResponsesPromise[],
    }> = new Map();

    const initPromise = (async (): Promise<instance.Instance> => {
        const module = await configMessage.wasmModule;

        // Start initialization of the Wasm VM.
        const config: instance.Config<A> = {
            envVars: [],
            parseMultiaddr: platformBindings.parseMultiaddr,
            getRandomValues: platformBindings.getRandomValues,
            performanceNow: platformBindings.performanceNow,
            wasmModule: module,
            cpuRateLimit: configMessage.cpuRateLimit,
            maxLogLevel: configMessage.maxLogLevel,
        };

        const eventCallback = (event: instance.Event<A>) => {
            switch (event.ty) {
                case "wasm-panic": {
                    // TODO: consider obtaining a backtrace here
                    crashError.error = new CrashError(event.message);
                    connections.forEach((connec) => connec.reset());
                    connections.clear();
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
                case "add-chain-result": {
                    (addChainResults.shift()!)(event);
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
        };

        return await instance.startLocalInstance(config, eventCallback)
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
            return queueOperation(async (instance) => {
                if (crashError.error)
                    throw crashError.error;

                try {
                    const promise = new Promise<{ success: true, chainId: number } | { success: false, error: string }>((resolve) => addChainResults.push(resolve));
                    instance.addChain(chainSpec, databaseContent, potentialRelayChains, disableJsonRpc);
                    const result = await promise;
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
            }).then((p) => p)
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
