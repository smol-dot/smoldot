/**
 * Interface that the Wasm module exports. Contains the functions that are exported by the Rust
 * code.
 *
 * Must match the bindings found in the Rust code.
 */
export interface SmoldotWasmExports extends WebAssembly.Exports {
    memory: WebAssembly.Memory;
    init: (maxLogLevel: number) => void;
    advance_execution: () => number;
    start_shutdown: () => void;
    add_chain: (chainSpecBufferIndex: number, databaseContentBufferIndex: number, jsonRpcRunning: number, potentialRelayChainsBufferIndex: number) => number;
    remove_chain: (chainId: number) => void;
    chain_is_ok: (chainId: number) => number;
    chain_error_len: (chainId: number) => number;
    chain_error_ptr: (chainId: number) => number;
    json_rpc_send: (textBufferIndex: number, chainId: number) => number;
    json_rpc_responses_peek: (chainId: number) => number;
    json_rpc_responses_pop: (chainId: number) => void;
    timer_finished: () => void;
    connection_open_single_stream: (connectionId: number, handshakeTy: number, initialWritableBytes: number, writeClosable: number) => void;
    connection_open_multi_stream: (connectionId: number, handshakeTyBufferIndex: number) => void;
    stream_writable_bytes: (connectionId: number, streamId: number, numBytes: number) => void;
    stream_message: (connectionId: number, streamId: number, bufferIndex: number) => void;
    connection_stream_opened: (connectionId: number, streamId: number, outbound: number, initialWritableBytes: number) => void;
    connection_reset: (connectionId: number, bufferIndex: number) => void;
    stream_reset: (connectionId: number, streamId: number) => void;
}
export interface SmoldotWasmInstance extends WebAssembly.Instance {
    readonly exports: SmoldotWasmExports;
}
