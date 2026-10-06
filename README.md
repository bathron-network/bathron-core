# BATHRON Core

BATHRON is being built for programmable settlement rooted in Bitcoin, with Bitcoin facts verified
by every node without an oracle. M0 is the only settlement asset in the current application draft:
Settlement Providers (SPs) handle BTC/M0 and Liquidity Providers (LPs) handle X/M0. Third parties
build applications using the protocol's primitives.

**Network status:** <https://bathron.org/docs/status.html>

This repository contains the legacy DMM node, RPC client and build files.

SPs and LPs are roles outside consensus; neither requires a registered identity. A producer is a
registered identity selected to produce a block. There is no native finality in N.

[Website](https://bathron.org) · [Overview](https://bathron.org/docs/overview.html) ·
[Trust model](https://bathron.org/docs/trust.html) · [Producers](https://bathron.org/docs/producers.html) ·
[Covenants and timelocks](https://bathron.org/docs/covenants.html) ·
[Settlement](https://bathron.org/docs/settlement.html)

## Consensus engine

The next BATHRON consensus engine, **N**, is specified in [bathron-network/n-spec](https://github.com/bathron-network/n-spec)
(v0.7, architecture frozen candidate, not mainnet-qualified). This repository does not implement N yet: it contains the legacy
DMM consensus, tagged `legacy-dmm-final`.

## Provenance

BATHRON is derived from [PIVX](https://github.com/PIVX-Project/PIVX). Original copyright notices are retained in
[COPYING](COPYING). Private development began in December 2025, with more than 1,400 commits across all branches.
This public tree is a controlled export of that work. The full development history is planned for publication in this
repository, after review. See [How this project is built](https://bathron.org/docs/how-this-project-is-built.html).

## Build and run

These instructions build the legacy DMM software. No public network runs today; see
[Network status](https://bathron.org/docs/status.html).

### Build

On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
    libssl-dev libevent-dev bsdmainutils python3 libboost-all-dev libsodium-dev libzmq3-dev
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)
```

This produces `src/bathrond` (daemon) and `src/bathron-cli` (RPC client). Published [releases](https://github.com/bathron-network/bathron-core/releases) belong to the legacy DMM network.
See [Network status](https://bathron.org/docs/status.html) for the current network state.

### Network availability

Network status: <https://bathron.org/docs/status.html>.

## Security

Report vulnerabilities privately to [security@bathron.org](mailto:security@bathron.org), not in a
public issue. See [SECURITY.md](SECURITY.md).
