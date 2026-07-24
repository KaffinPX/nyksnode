# Nyksnode

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub CI](https://github.com/Nyksnet/node/actions/workflows/main.yml/badge.svg)](https://github.com/Nyksnet/node/actions/workflows/main.yml)

Nyksnode is the reference implementation for the [Nyks](https://nyks.tech/) protocol.

## Disclaimer

> [!CAUTION]
> This software uses novel and untested cryptography. Use at own risk, and invest only that which
> you can afford to lose.

> [!IMPORTANT]
> If a catastrophic vulnerability is discovered in the protocol, it might be restarted from genesis.

## Installing

> [!IMPORTANT]
> Any commit except the one tagged `release` is considered an _unstable development_ commit and thus carries a
> higher risk of database corruption and/or loss of funds. However, known bug fixes make their way into `master`
> before being part of a release.

## Compile from Source

### Linux (Debian/Ubuntu)

- Install [Rust](https://rustup.rs/).
- Install the required dependencies:
  ```bash
  sudo apt update
  sudo apt install -y build-essential clang cmake libleveldb-dev libsnappy-dev
  ```
- Checkout the latest stable branch (optional):
  ```bash
  git checkout release
  ```
- Build and install:
  ```bash
  make install-linux
  ```

### Windows

- Install [Rust](https://rustup.rs/).
- Install [CMake](https://cmake.org/download/).
- Checkout the latest stable branch (optional):
  ```powershell
  git checkout release
  ```
- Build and install:
  ```powershell
  cargo install --locked --path nyks-node
  cargo install --locked --path nyks-wallet
  ```

### macOS

- Install [Rust](https://rustup.rs/).
- Install the required dependencies:
  ```bash
  brew install cmake leveldb
  ```
- Checkout the latest stable branch (optional):
  ```bash
  git checkout release
  ```
- Build and install:
  ```bash
  make install
  ```

## Public Testnet

Nyks is currently **testnet-only**. There is no mainnet yet.

To join the public testnet, start your node with:

```bash
--network testnet --peer /ip4/79.137.32.232/tcp/9798
```

The node will connect to the public bootstrap peer and begin syncing automatically.

## Crash Procedures

If any cryptographic data ends up in an invalid state, and the node crashes as a result, please copy
your entire data directory and share it publicly. If you're not on `main`net it should be OK to
share `./wallet_data`, which contains your secret key, as well. If you are on mainnet, don't share any
of these files with anyone because doing so will put your funds at risk.

## Restarting Node from the Genesis Block

In order to restart your node from the genesis block, you should delete these folders:

- `<data_directory>/<network>/blocks/`
- `<data_directory>/<network>/databases/`

