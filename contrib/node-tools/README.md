# BATHRON Node Tools

> **Historical DMM testnet documentation.** Network status: <https://bathron.org/docs/status.html>.

Tools for BATHRON node operators. Anyone running a node can run these daemons — header
publication and burn-claim submission are open to any node (`publishbtcheaders`,
`submitburnclaim`); no permission or registration is involved.

> **Network:** the former DMM measurement network read **Bitcoin testnet4**. The two daemons below
> default to a testnet4 Bitcoin Core (`~/.bitcoin-testnet4`). Network status: <https://bathron.org/docs/status.html>.
> How Bitcoin facts enter consensus: <https://bathron.org/docs/bitcoin-facts.html>.

## Why run these?

- **More SPV header publishers** — any node can carry Bitcoin headers into consensus; more
  independent publishers means less reliance on any single one.
- **More burn-claim submitters** — anyone can claim a burn for anyone (credits go to the address
  in the burn metadata, never to the submitter).

## Tools

### burn_signet.sh — historical (previous testnet only)

> ⚠️ **Historical.** This script burns on Bitcoin **signet**, which was the Bitcoin source of the
> signet-era public testnet. The former DMM measurement network read **testnet4**: a signet burn
> was **not** visible to it and minted nothing. The script is kept for
> reference only; a testnet4 equivalent is not shipped in this directory. Current burn rules
> and the status of application formats are documented at
> <https://bathron.org/docs/burns.html>.

Historical usage (signet-era testnet):

```bash
./burn_signet.sh <bathron_address> <amount_sats>

# Example: burn 10,000 sats (0.0001 BTC) to alice's address
./burn_signet.sh yJYD2bfYYBe6qAojSzMKX949H7QoQifNAo 10000
```

The script:
1. Converts the BATHRON address to hash160
2. Builds the OP_RETURN metadata (`BATHRON|01|T|<hash160>`)
3. Creates a TX with a P2WSH(OP_FALSE) burn output (provably unspendable)
4. Verifies BP08 compliance before broadcast
5. Broadcasts and saves burn info for tracking

**Burn output (P2WSH of the canonical burn script, `tb1…` on both signet and testnet4):** `tb1qdc6qh88lkdaf3899gnntk7q293ufq8flkvmnsa59zx3sv9a05qwsdh5h09`

After broadcast, the burn claim daemon (or anyone running it) will detect the burn, submit `TX_BURN_CLAIM`, and M0BTC will be minted automatically after K=6 confirmations.

**Min burn:** 1,000 sats (signet-era parameters).

### btc_header_daemon.sh

Syncs BTC headers into BATHRON's SPV chain. Polls your local Bitcoin node and submits headers to your BATHRON node, which then broadcasts `TX_BTC_HEADERS` to the network.

```
BTC Node --> [this daemon] --> submitbtcheaders --> btcspv
                                                      |
                              auto-publisher (60s) --> TX_BTC_HEADERS --> all nodes
```

### btc_burn_claim_daemon.sh

Scans BTC blocks for BATHRON burn transactions (OP_RETURN with `BATHRON` magic) and auto-submits `TX_BURN_CLAIM` on the BATHRON network. Burns are fee-free and credits go to the destination encoded in the burn metadata.

```
BTC Node --> [scan for burns] --> [check if claimed] --> submitburnclaimproof
                                                              |
                                                              v
                                                    TX_BURN_CLAIM (fee-free)
                                                              |
                                                    K confirmations later
                                                              |
                                                    TX_MINT_M0BTC (auto)
```

## Requirements

- **Bitcoin Core** with `txindex=1` — **testnet4** for the former DMM measurement network
- **bathrond** running and synced
- `bitcoin-cli` and `bathron-cli` accessible
- `jq` installed

## Quick Start

```bash
# 1. Configure paths (or use defaults)
export BTC_CLI=/path/to/bitcoin-cli
export BTC_DATADIR=/path/to/.bitcoin-testnet4
export BATHRON_CLI=/path/to/bathron-cli

# 2. Start BTC header sync
./btc_header_daemon.sh start

# 3. Start burn claim daemon
./btc_burn_claim_daemon.sh start

# 4. Check status
./btc_header_daemon.sh status
./btc_burn_claim_daemon.sh status
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BTC_CLI` | `~/bitcoin-28.1/bin/bitcoin-cli` | Path to bitcoin-cli |
| `BTC_DATADIR` | `~/.bitcoin-testnet4` | Bitcoin data directory |
| `BTC_CONF` | `$BTC_DATADIR/bitcoin.conf` | Bitcoin config file |
| `BATHRON_CLI` | `~/bathron-cli` | Path to bathron-cli |
| `INTERVAL` | `120` (headers) / `300` (burns) | Poll interval in seconds |

## Commands

Both daemons support the same commands:

```bash
./btc_header_daemon.sh start      # Start in background
./btc_header_daemon.sh stop       # Stop daemon
./btc_header_daemon.sh status     # Check status + sync progress
./btc_header_daemon.sh once       # Run one cycle (for testing)
./btc_header_daemon.sh logs       # Tail daemon logs
```

The burn claim daemon also supports:

```bash
./btc_burn_claim_daemon.sh bootstrap   # Aggressive scan for initial setup
```

## How Burns Work

1. User sends BTC to an unspendable P2WSH address with an OP_RETURN containing: `BATHRON|01|<NET>|<DEST_HASH160>`
2. This daemon detects the burn after K=6 confirmations
3. Submits `TX_BURN_CLAIM` with merkle proof (fee-free)
4. After K confirmations on BATHRON, `TX_MINT_M0BTC` is created automatically
5. M0BTC is credited to the destination address encoded in the burn

Anyone can submit the claim - it doesn't matter who runs the daemon. The M0BTC always goes to the address specified by the burner.

## License

Same as BATHRON Core.
