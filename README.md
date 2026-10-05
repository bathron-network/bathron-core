# BATHRON Core

BATHRON provides programmable settlement anchored in Bitcoin, with Bitcoin facts verified by every
node without an oracle. M1 is the pivot settlement asset: Settlement Providers (SPs) handle BTC/M1
and Liquidity Providers (LPs) handle X/M1. Third parties build applications using the protocol's
primitives.

**Network status:** <https://bathron.org/docs/status.html>

This repository contains the BATHRON node, RPC client and build files. SPs carry an Operator identity
and may also produce blocks; an Operator identity is optional for LPs.

[Website](https://bathron.org) · [Overview](https://bathron.org/docs/overview.html) ·
[Trust model](https://bathron.org/docs/trust.html) · [Operators](https://bathron.org/docs/operators.html) ·
[Script reference](https://bathron.org/docs/script.html) ·
[Transaction RPC](https://bathron.org/docs/rpc-transactions.html)

## Consensus engine

The next BATHRON consensus engine, **N**, is specified in [bathron-network/n-spec](https://github.com/bathron-network/n-spec)
(v0.7, architecture frozen candidate, not mainnet-qualified). This repository does not implement N yet: it contains the legacy
DMM consensus, tagged `legacy-dmm-final`.

## Provenance

BATHRON is derived from [PIVX](https://github.com/PIVX-Project/PIVX). Original copyright notices are retained in
[COPYING](COPYING). Private development began in December 2025, with more than 1,400 commits across all branches.
This public tree is an export of that work. The full development history is planned for publication in this
repository.

## Build and run

### Build

On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
    libssl-dev libevent-dev bsdmainutils python3 libboost-all-dev libsodium-dev libzmq3-dev
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)
```

This produces `src/bathrond` (daemon) and `src/bathron-cli` (RPC client). See the
[node guide](https://bathron.org/docs/node.html) for installation and operation, and
[releases](https://github.com/bathron-network/bathron-core/releases) for published binaries.

### Run a peer node

Network status: <https://bathron.org/docs/status.html>.

## Security

Report vulnerabilities privately to [security@bathron.org](mailto:security@bathron.org), not in a
public issue. See [SECURITY.md](SECURITY.md).
