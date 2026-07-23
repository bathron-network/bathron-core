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
- 🚀 **Run a node / join the public testnet:** <https://bathron.org/docs/getting-started/run-a-node.html>
- 📦 **Releases:** <https://github.com/bathron-network/bathron-core/releases>

## ⚠️ Experimental

This is experimental software running a **public testnet with a disposable genesis**. There is no
mainnet, and the complete cross-chain safety model is not yet formally specified or externally
reviewed. Do not treat the internal units (M0/M1) as an investment or a redeemable claim on Bitcoin.

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

## Join the public testnet

Only the public seed is needed to join — no RPC access and no operator address are required:

```bash
mkdir -p ~/.bathron
printf 'testnet=1\n[test]\naddnode=57.131.33.151\n' > ~/.bathron/bathron.conf
./src/bathrond -testnet -daemon
./src/bathron-cli -testnet getblockhash 0
# expected genesis:
# 0d241620b8beb492fd21bd8a92295260a4afa1b82e1bd816d18323cc3c98ea71
./src/bathron-cli -testnet getblockcount   # syncs to the network tip
```

Verify that the genesis hash above matches before trusting any peer.

---

*One canonical documentation source. Everything else links to it — see
<https://bathron.org/docs/>.*
