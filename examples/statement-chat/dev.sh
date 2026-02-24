#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "Statement Chat - Development Setup"
echo ""

# Check for required files
if [ ! -f "public/chain-specs/rococo-local.json" ]; then
    echo "Error: Chain spec not found at public/chain-specs/rococo-local.json"
    echo "Please run your local network and export the chain specs first."
    echo ""
    echo "Example commands:"
    echo "  mkdir -p public/chain-specs"
    echo "  curl -H \"Content-Type: application/json\" \\"
    echo "    -d '{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"sync_state_genSyncSpec\", \"params\":[true]}' \\"
    echo "    http://localhost:9944 | jq -r '.result' > public/chain-specs/rococo-local.json"
    exit 1
fi

if [ ! -f "public/chain-specs/parachain.json" ]; then
    echo "Error: Chain spec not found at public/chain-specs/parachain.json"
    echo "Please run your local network and export the chain specs first."
    exit 1
fi

# Write default config
RPC_PORT=${RPC_PORT:-9944}
echo "{\"wsUrl\": \"ws://127.0.0.1:$RPC_PORT\"}" > public/config.json
echo "Wrote WebSocket URL to public/config.json (using port $RPC_PORT)"

echo ""
echo "Installing dependencies with bun..."
bun install

echo ""
echo "Building smoldot..."
cd ../../wasm-node/javascript
npm run build

echo ""
echo "Starting dev server with bun..."
cd ../../examples/statement-chat
pkill -f "server.ts" 2>/dev/null || true
sleep 1
bun run dev
