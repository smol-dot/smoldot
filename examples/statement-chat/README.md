# Statement Chat

A simple chat application using the statement distribution protocol via smoldot.

This is a simplified version that demonstrates text-based chat using the Statement Store Protocol. Image sharing and Bitswap features have been removed for simplicity.

## Prerequisites

1. A running local Rococo relay chain with at least one parachain
2. Chain specs for both the relay chain and parachain
3. Bun runtime (for development)

## Setup

### 1. Start a local network

Use zombienet or another tool to start a local Polkadot/Substrate network:

```bash
# Example with zombienet (from polkadot-sdk directory)
zombienet spawn zombienet/examples/rococo-local.toml
```

### 2. Get chain specs

Export the chain specs from your running network:

```bash
# Create chain-specs directory
mkdir -p public/chain-specs

# Get relay chain spec (from a running node)
curl -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method":"sync_state_genSyncSpec", "params":[true]}' \
  http://localhost:9944 | jq -r '.result' > public/chain-specs/rococo-local.json

# Get parachain spec (adjust port if needed)
curl -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method":"sync_state_genSyncSpec", "params":[true]}' \
  http://localhost:9988 | jq -r '.result' > public/chain-specs/parachain.json
```

### 3. Run the dev server

```bash
./dev.sh
```

Or manually:

```bash
bun install
bun run dev
```

Open http://localhost:5173 in your browser.

## Usage

1. Wait for smoldot to connect to both the relay chain and parachain
2. Enter a topic (32-byte hex hash) or use the default
3. Click "Subscribe to Topic"
4. Type a message and click "Send" or press Enter
5. Messages from other peers subscribed to the same topic will appear

## How it works

- Uses smoldot as a light client to connect to the network
- Calls `statement_subscribe` RPC to subscribe to specific topics
- Calls `statement_submit` RPC to send statements
- Receives `statement_notification` events from the network
- Statements are signed using Ed25519 keypairs stored in localStorage

## Chain Spec Format

The chain specs should be in the light-client-friendly format with embedded
bootnodes. You can generate these using the `sync_state_genSyncSpec` RPC method.

## Topics

Topics are 32-byte hex values (64 hex characters with 0x prefix) used to filter statements. All clients subscribed to the same topic will receive each other's messages.
