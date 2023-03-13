# Introduction

`smoldot` is an alternative client of [Substrate](https://github.com/paritytech/substrate)-based chains, including [Polkadot](https://github.com/paritytech/polkadot/).

This repository contains the following components:

- `/lib`: An unopinionated Rust library named `smoldot` of general-purpose primitives that relate to Substrate and Polkadot. Serves as a base for the other components.
  - 📦 <https://crates.io/crates/smoldot>
  - 📚 <https://docs.rs/smoldot> (latest published version)
  - 📚 <https://smol-dot.github.io/smoldot/doc-rust/smoldot/index.html> (latest commit)
  - Has an unstable API.

- `/light-base`: A platform-agnostic Rust library named `smoldot-light` that can connect to a Substrate-based chain as a light client. Serves as the base for the `wasm-node` component below.
  - 📦 <https://crates.io/crates/smoldot-light>
  - 📚 <https://docs.rs/smoldot-light> (latest published version)
  - 📚 <https://smol-dot.github.io/smoldot/doc-rust/smoldot_light/index.html> (latest commit)
  - Has a semi-stable API that might change occasionally in minor ways.

- `/wasm-node`: A JavaScript package that can connect to a Substrate-based chains as a light client, using the `smoldot-light` Rust library in its internals. Works both in the browser and on NodeJS/Deno. **This is the main component of this repository. The development mostly focuses around it, and the name `smoldot` generally refers to this component in particular.**
  - 📦 NPM: <https://www.npmjs.com/package/smoldot>
  - 📦 Deno.land/x: <https://deno.land/x/smoldot2> (URL to import: `https://deno.land/x/smoldot2/index-deno.js`)
  - 📄 CHANGELOG: <https://github.com/smol-dot/smoldot/blob/main/wasm-node/CHANGELOG.md>
  - 📚 <https://smol-dot.github.io/smoldot/doc-javascript/> (latest commit)
  - Has a stable API that rarely changes.

- `/full-node`: A work-in-progress prototype of a full node binary that can connect to Substrate-base chains. Doesn't yet support many features that the official client supports.

## Does smoldot support &lt;blockchain&gt;?

Smoldot pledges to support the Polkadot, Kusama, Westend, and Rococo chains, where "support" means "everything works as intended".

Because Polkadot, Kusama, Westend, and Rococo were built using the Substrate framework, smoldot has to support most features found in the Substrate repository. Consequently, smoldot is able to connect to most Substrate-based chains.
However, given that Substrate is a very generic framework that doesn't offer any specification, and that any user of Substrate can in principle modify most aspects of it in any way they want, it is not possible to offer a guarantee that smoldot is compatible with all Substrate-based chains.

# About the repository

## License

The source code in this repository is distributed under the GPLv3 license. See the <LICENSE> file.

This source code comes with absolutely no warranty. Use at your own risk.

Due to the history of this repository, the code written in 2022 and before belongs to Parity Technologies. Code written in 2023 and later belongs to individual contributors.

## Governance and contributions

This project operates under the typical "benevolent dictator" model. The main maintener, @tomaka, is being remunerated to work on the source code through Polkadot treasury proposals.

Pull requests are welcome. However, if your changes are substantial, you are strongly encouraged to first discuss the nature of the changes through an issue or discussion. In general, unless the changes you are making are trivial, you are never wrong if you first open an issue instead of a pull request.

Anyone contributing to this project pledges to propose a welcoming, constructive, and respectful environment for everyone. Trolling, harassment, or sexual advances aren't tolerated.

## Security

While the light client is fully maintained, please be aware that at the moment the full node is completely experimental. While none of the source code in this repository comes with any guarantee, it is even more true for the full node. You are at the moment strongly encouraged to not run a validator using the smoldot full node in a production environment, as it could result in a loss of money.

The smoldot light client does in no way have access to any private key (with the exception of the networking private key, which isn't sensitive). Any transaction (such as a balance transfer) is signed *before* being provided to smoldot. While it is possible for smoldot to contain for example a remote code execution issue that could lead to an attacker reading a private key, this type of issue is extremely unlikely to happen. Using the smoldot light client isn't inherently more risky than using a JSON-RPC server, and in most likelihood the worst that could happen is "things aren't working".

**The following are considered critical security issues**. If you find such an issue, please use the GitHub private disclosure feature found at <https://github.com/smol-dot/smoldot/security/advisories>:

- Smoldot believes that a certain block has been finalized, when it is not actually the case on the blockchain it is connected to.
- Remote arbitrary memory accesses.
- Remote code executions.

**The following are considered security issues and are given particular attention**. Given the extreme difficulty, monetary risk, and extremely low potential of reward for an attacker to exploit these issues, it is not problematic to publicly disclose them:

- Smoldot crashes due to a certain exchange of messages on the libp2p networking level, including a high volume of data.
- Smoldot crashes due to a certain exchange of messages on the JSON-RPC requests level, including a high volume of JSON-RPC requests.
- A response to a JSON-RPC request provides incorrect or incomplete information. In the context of the light client, this doesn't apply to the legacy JSON-RPC requests that can't be implemented properly due to techincal reasons. A warning is printed when a legacy JSON-RPC request is called.

Where "crash" includes: Rust panics, JavaScript exceptions (except for the ones documented), infinite loops, or allocating an ever increasing amount of memory (a.k.a. a "memory leak").

**Is not considered a security issue**:

- **The smoldot light client believes that a certain block exists or is valid, while in reality it isn't valid**. A light client has no way to determine for sure whether a block is valid. Only finality should be relied upon when accuracy is critical.
- Smoldot crashes due to an intended use of its API. Note that "API" here doesn't include the content or volume of JSON-RPC requests, as smoldot is meant to be resilient to malicious JSON-RPC requests or to a huge volume of JSON-RPC requests.
- Smoldot runs out of memory because it is being asked to connect to a high number of chains at the same time. The precise limit to the number of chains depends on the amount of memory available.
- Being able to determine the identity (including the IP address) of the sender of a transaction sent using smoldot. This aspect could be improved in the future, but at the moment the Polkadot network protocol doesn't provide enough tools to make anonymity possible.
- Smoldot failing to connect to a certain chain. While this isn't a *security* issue, please open an issue regardless.
- A transaction sent through smoldot not being included in the chain in a certain time period. While this isn't a *security* issue, please open an issue regardless.

## Building manually

### Wasm light node

In order to run the wasm light node, you must have installed [rustup](https://rustup.rs/).

The wasm light node can be tested with `cd wasm-node/javascript` and `npm install; npm start`. This will compile the smoldot wasm light node and start a WebSocket server capable of answering JSON-RPC requests. This demo will print a list of URLs that you can navigate to in order to connect to a certain chain. For example you can navigate to <https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944%2Fwestend2> in order to interact with the Westend chain.

> Note: The `npm start` command starts a small JavaScript shim, on top of the wasm light node, that hard codes the chain to Westend and starts the WebSocket server. The wasm light node itself can connect to a variety of different chains (not only Westend) and doesn't start any server.

### Full client

The full client is a binary similar to the official Polkadot client, and can be tested with `cargo run`.

> Note: The `Cargo.toml` contains a section `[profile.dev] opt-level = 2`, and as such `cargo run` alone should give performances close to the ones in release mode.

The following list is a best-effort list of packages that must be available on the system in order to compile the full node:

- `clang` or `gcc`
- `pkg-config`
- `sqlite`
