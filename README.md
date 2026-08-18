# BATHRON

> **An open settlement protocol. Bitcoin remains the final asset.** Public testnet, no mainnet, no
> proven market — see [Status & claims](https://bathron.org/docs/consensus/status-and-claims.html).

This repository holds the **node, build files and `SECURITY.md`**. It does not restate the
protocol's positioning, economics, security model or status: those have exactly one canonical
source, and this README links to it.

- 📖 **Documentation (canonical):** <https://bathron.org/docs/> — start with
  [Start here](https://bathron.org/docs/start-here.html)
- 📖 **Documentation source:** <https://github.com/bathron-network/bathron-network.github.io/tree/main/docs/src>
  ([documentation policy](https://bathron.org/docs/reference/documentation-policy.html))
- 📊 **Status & claims** — what runs, what is not proven, what is never claimed:
  <https://bathron.org/docs/consensus/status-and-claims.html>
- 🔒 **Security model:** <https://bathron.org/docs/consensus/security-model.html> · report
  privately to security@bathron.org (see [`SECURITY.md`](SECURITY.md))
- 🧠 **Consensus & finality:** <https://bathron.org/docs/consensus/production-and-finality.html>
- 🚀 **Run a peer node:** <https://bathron.org/docs/operate/run-a-node.html>
- 📦 **Releases:** <https://github.com/bathron-network/bathron-core/releases>

## ⚠️ Experimental

This is experimental software running a **measurement network with a disposable genesis**. There is
no mainnet. Anyone can run a **peer node** and verify the chain; **operator registration is not
open** while the open-admission threat model is worked. The Bitcoin source read by consensus is
**Bitcoin testnet4**. Everything else about what is and is not proven is on the
[Status & claims](https://bathron.org/docs/consensus/status-and-claims.html) page — this file
does not repeat it.

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
release binaries: <https://bathron.org/docs/operate/run-a-node.html>.

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

*One canonical documentation source — <https://bathron.org/docs/>. Where this README and the
documentation disagree on a claimed capability, the documentation's
[Status & claims](https://bathron.org/docs/consensus/status-and-claims.html) page prevails.*
