# Upgrader

**nyks-upgrader** is a command-line tool for upgrading primitive Nyks transaction proofs.

## Command-Line Options

| Option | Description | Default |
|---------|-------------|---------|
| `--rpc-url <URL>` | JSON-RPC HTTP endpoint to connect to. | **Required** |
| `--address <ADDRESS>` | Recipient of the gobbling rewards. | **Required** |
| `--network <NETWORK>` | Network to upgrade transactions on. | `Main` |
| `--fee <AMOUNT>` | Reward charged per transaction (specified in coins). | `1` coin |
