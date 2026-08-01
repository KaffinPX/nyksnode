## RPC

The Nyks node has a built-in RPC module for whatever purposes you need it for.

It's designed to support multiple transports, but only HTTP is supported for now.

### Enabling

RPC can be enabled with `--rpc-listen <ip>:<port>`.

Methods are grouped into namespaces, which can be individually exposed with `rpc-modules` using the same flag style. This lets you isolate which parts of the node are reachable over RPC, so you can expose only what you need instead of opening up everything.

Available namespaces:

* `Node` - endpoints for general node info
* `Network` - endpoints for peer and networking info
* `Chain` - endpoints for querying blockchain tip state
* `Mining` - endpoints for mining/composing processes
* `Archival` - endpoints for historical data which won't be needed for consensus itself in future
* `Mempool` - endpoints for inspecting mempool status
* `Wallet` - endpoints for serving external wallets

### Request Format

Requests are sent as a JSON POST body:

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "node_network",
  "params": []
}
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "result": "testnet-0"
}
```

For the full list of RPC methods, see [`rpc/core/src/api/ops.rs`](https://github.com/Nyksnet/node/blob/master/rpc/core/src/api/ops.rs).
