# BATHRON

> **An experimental settlement kernel for Bitcoin.** Public testnet, no mainnet, no proven market.

BATHRON is a functional testnet for conditional Bitcoin settlement: covenants, Bitcoin-header
verification in consensus, confidential internal transfers and fast finality, so applications can
coordinate two settlement legs without giving one intermediary unrestricted custody. It has no
token sale, premine, block reward, treasury or yield, and its internal units are neither an
investment nor a redeemable claim on Bitcoin.

This repository holds the **node, build files and `SECURITY.md`**. All conceptual documentation
lives in one canonical place — this README does not duplicate it:

- 📖 **Documentation:** <https://bathron.org/docs/>
- 📖 **Documentation source:** <https://github.com/bathron-network/bathron-network.github.io/tree/main/docs/src>
- 🔒 **Security model:** <https://bathron.org/docs/learn/security-model.html> · report privately to security@bathron.org (see [`SECURITY.md`](SECURITY.md))
- 🧠 **Consensus & finality:** <https://bathron.org/docs/learn/consensus.html>
- 🚀 **Run a peer node:** <https://bathron.org/docs/getting-started/run-a-node.html>
- 📦 **Releases:** <https://github.com/bathron-network/bathron-core/releases>

## ⚠️ Experimental

This is experimental software running a **measurement network with a disposable genesis**. There is
no mainnet, and the complete cross-chain safety model is not yet formally specified or externally
reviewed. Do not treat the internal units (M0/M1) as an investment or a redeemable claim on Bitcoin.

The current network exists to **measure** the consensus under real conditions, not to serve users.
Its operator set is closed while the open-admission threat model is still being worked out, so
anyone can run a **peer node** and verify the chain, but operator registration is not open. The
Bitcoin source for burn verification is **Testnet4**, which proves the burn→claim→mint flow — not
mainnet-equivalent economic security.

## Build

On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential libtool autotools-dev automake pkg-config \
    libssl-dev libevent-dev bsdmainutils python3 libboost-all-dev libsodium-dev libzmq3-dev
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j$(nproc)
```

This produces `src/bathrond` (daemon) and `src/bathron-cli` (RPC client). macOS instructions and
release binaries: <https://bathron.org/docs/getting-started/run-a-node.html>.

## Run a peer node on the measurement network

Only the public seed is needed to sync — no RPC access and no operator address are required:

```bash
mkdir -p ~/.bathron
printf 'testnet=1\n[test]\naddnode=57.131.33.151\n' > ~/.bathron/bathron.conf
# release package: binaries are in bin/ — from a source build they are in src/
./bin/bathrond -testnet -daemon
./bin/bathron-cli -testnet getblockhash 0
# expected genesis (measurement network, epoch 4):
# 691b0a7e8cb0e7ee159ef7a4fa10d9c6ddb2d5282e5bac7447846459ff54c730
./bin/bathron-cli -testnet getblockcount   # syncs to the network tip
```

Block explorer: canonical source at
[bathron-network/bathron-explorer](https://github.com/bathron-network/bathron-explorer).

Verify that the genesis hash above matches before trusting any peer.

---

*One canonical documentation source. Everything else links to it — see
<https://bathron.org/docs/>.*
