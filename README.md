# mimir-mediator

A mediator server for the Mimir messaging protocol, built on top of the [Yggdrasil](https://yggdrasil-network.github.io/) overlay network.

## Overview

mimir-mediator handles chat operations — authentication, group management, message routing, invites, and member permissions — over Yggdrasil using a compact TLV-based binary protocol.
Messages are persisted in a Turso (libSQL) database with an in-memory + on-disk hybrid cache (Moka + redb) for fast delivery.

## Building

```bash
cargo build --release
```

## Usage

```
mimir-mediator [options]

Options:
  -p, --peer URI        Yggdrasil peer URI (repeatable, at least one required)
  -c, --cache-days DAYS Days to cache messages (default: 1)
  -h, --help            Show help
```

Example:

```bash
./mimir-mediator -p tcp://some-peer:12345 -p tls://another-peer:12345
```

On first run the server generates an Ed25519 keypair and saves it to `mediator.key`.

## License

This project is licensed under the [MPL License](LICENSE).