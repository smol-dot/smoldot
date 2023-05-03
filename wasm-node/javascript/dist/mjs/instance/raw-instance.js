// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
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
import { default as smoldotLightBindingsBuilder } from './bindings-smoldot-light.js';
import { default as wasiBindingsBuilder } from './bindings-wasi.js';
export { ConnectionError } from './bindings-smoldot-light.js';
export function startInstance(config, platformBindings) {
    return __awaiter(this, void 0, void 0, function* () {
        let killAll;
        const bufferIndices = new Array;
        // Callback called when `advance_execution_ready` is called by the Rust code, if any.
        const advanceExecutionPromise = { value: null };
        // Used to bind with the smoldot-light bindings. See the `bindings-smoldot-light.js` file.
        const smoldotJsConfig = Object.assign({ bufferIndices, connect: platformBindings.connect, onPanic: (message) => {
                killAll();
                config.onWasmPanic(message);
                throw new Error();
            }, advanceExecutionReadyCallback: () => {
                if (advanceExecutionPromise.value)
                    advanceExecutionPromise.value();
                advanceExecutionPromise.value = null;
            } }, config);
        // Used to bind with the Wasi bindings. See the `bindings-wasi.js` file.
        const wasiConfig = {
            envVars: [],
            getRandomValues: platformBindings.getRandomValues,
            performanceNow: platformBindings.performanceNow,
            onProcExit: (retCode) => {
                killAll();
                config.onWasmPanic(`proc_exit called: ${retCode}`);
                throw new Error();
            }
        };
        const { imports: smoldotBindings, killAll: smoldotBindingsKillAll } = smoldotLightBindingsBuilder(smoldotJsConfig);
        killAll = smoldotBindingsKillAll;
        // Start the Wasm virtual machine.
        // The Rust code defines a list of imports that must be fulfilled by the environment. The second
        // parameter provides their implementations.
        const result = yield WebAssembly.instantiate(config.wasmModule, {
            // The functions with the "smoldot" prefix are specific to smoldot.
            "smoldot": smoldotBindings,
            // As the Rust code is compiled for wasi, some more wasi-specific imports exist.
            "wasi_snapshot_preview1": wasiBindingsBuilder(wasiConfig),
        });
        const instance = result;
        smoldotJsConfig.instance = instance;
        wasiConfig.instance = instance;
        // Smoldot requires an initial call to the `init` function in order to do its internal
        // configuration.
        instance.exports.init(config.maxLogLevel);
        (() => __awaiter(this, void 0, void 0, function* () {
            // In order to avoid calling `setTimeout` too often, we accumulate sleep up until
            // a certain threshold.
            let missingSleep = 0;
            // Extract (to make sure the value doesn't change) and sanitize `cpuRateLimit`.
            let cpuRateLimit = config.cpuRateLimit;
            if (isNaN(cpuRateLimit))
                cpuRateLimit = 1.0;
            if (cpuRateLimit > 1.0)
                cpuRateLimit = 1.0;
            if (cpuRateLimit < 0.0)
                cpuRateLimit = 0.0;
            const periodicallyYield = { value: false };
            const [periodicallyYieldInit, unregisterCallback] = platformBindings.registerShouldPeriodicallyYield((newValue) => {
                periodicallyYield.value = newValue;
            });
            periodicallyYield.value = periodicallyYieldInit;
            let now = platformBindings.performanceNow();
            while (true) {
                const whenReadyAgain = new Promise((resolve) => advanceExecutionPromise.value = resolve);
                const outcome = instance.exports.advance_execution();
                if (outcome === 0) {
                    unregisterCallback();
                    break;
                }
                const afterExec = platformBindings.performanceNow();
                const elapsed = afterExec - now;
                now = afterExec;
                // In order to enforce the rate limiting, we stop executing for a certain
                // amount of time.
                // The base equation here is: `(sleep + elapsed) * rateLimit == elapsed`,
                // from which the calculation below is derived.
                const sleep = elapsed * (1.0 / cpuRateLimit - 1.0);
                missingSleep += sleep;
                if (missingSleep > (periodicallyYield ? 5 : 1000)) {
                    // `setTimeout` has a maximum value, after which it will overflow. 🤦
                    // See <https://developer.mozilla.org/en-US/docs/Web/API/setTimeout#maximum_delay_value>
                    // While adding a cap technically skews the CPU rate limiting algorithm, we don't
                    // really care for such extreme values.
                    if (missingSleep > 2147483646) // Doc says `> 2147483647`, but I don't really trust their pedanticism so let's be safe
                        missingSleep = 2147483646;
                    yield new Promise((resolve) => setTimeout(resolve, missingSleep));
                    missingSleep = 0;
                }
                yield whenReadyAgain;
                const afterWait = platformBindings.performanceNow();
                missingSleep -= (afterWait - now);
                if (missingSleep < 0)
                    missingSleep = 0;
                now = afterWait;
            }
        }))();
        return [instance, bufferIndices];
    });
}
