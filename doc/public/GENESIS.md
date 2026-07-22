# BATHRON Genesis Specification

**Version:** 1.1
**Date:** 2026-07-12
**Status:** CANONICAL
**Consolidates:** 09-TESTNET-GENESIS.md, 12-BTC-BURN-GENESIS.md, GENESIS-SAFE.md

> **Terminology.** Publicly, the burn-backed consensus identities are **Settlement
> Operators** — see [SETTLEMENT-OPERATORS.md](SETTLEMENT-OPERATORS.md) for the operator
> model (neutral protocol, public track record, app-level selection). This document
> describes consensus mechanics, so it keeps the internal lineage names (`masternode`,
> `ProReg`, `protx_*`) that the code and RPCs use.

---

## Table of Contents

1. [Principles](#1-principles)
2. [Consensus Boundaries](#2-consensus-boundaries)
3. [Architecture](#3-architecture)
4. [Testnet Genesis (Implemented)](#4-testnet-genesis-implemented)
5. [Mainnet Genesis (Planned)](#5-mainnet-genesis-planned)
6. [Burn Discovery & Minting](#6-burn-discovery--minting)
7. [Key Management](#7-key-management)
8. [Verification & Gates](#8-verification--gates)
9. [Post-Genesis Operations](#9-post-genesis-operations)
10. [Troubleshooting](#10-troubleshooting)
11. [Files Reference](#11-files-reference)
12. [Appendix: Mainnet Data Structures](#appendix-a-mainnet-data-structures)
13. [Appendix: Regulatory Defense](#appendix-b-regulatory-defense)

---

## 1. Principles

### Zero Premint

All M0 originates from SPV-verified BTC burns. No coinbase rewards, no treasury, no hardcoded distribution.

```
A5: M0_total(N) = M0_total(N-1) + BurnClaims
    Coinbase = 0 always (fees only)
    Block reward = 0 always
    Treasury = 0 (none exists)
```

### One Path

Burns on Bitcoin → SPV verification → TX_BURN_CLAIM → K blocks finality → TX_MINT_M0BTC. Same path for genesis and runtime. Testnet and mainnet differ only in timing (pre-launch vs live discovery), not mechanism.

### Deterministic Minting

Every node independently computes the expected TX_MINT_M0BTC. If the block producer's TX doesn't match, the block is rejected. No manual intervention possible.

### Burn Sourcing: Testnet vs Mainnet

| | Testnet | Mainnet |
|---|---------|---------|
| Burns | Auto-discovered from BTC Signet | Pre-collected during a public burn window |
| Headers | Published as TX_BTC_HEADERS (SPV) | Published as TX_BTC_HEADERS (SPV) from BTC mainnet |
| K_FINALITY | 20 | 100 |
| K_BTC_CONFS | 6 | 24 |
| Checkpoint | 286000 (Signet) | 800000 (Mainnet) |

---

## 2. Consensus Boundaries

### What Consensus GUARANTEES

| Guarantee | Description | Enforcement |
|-----------|-------------|-------------|
| **A5** | `M0_total(N) = M0_total(N-1) + BurnClaims` | Block validation |
| **A6** | `M0_vaulted == M1_supply` | TX validation |
| **A9** | `btc_supply(checkpoint) == expected` | Circuit breaker |
| **BTC Burns** | M0 created iff valid BTC burn exists (SPV-verified, K confs, BCS v1.0 format, not duplicate) | Consensus |
| **Lock/Unlock** | M0 ↔ M1 at 1:1, instant, permissionless, reversible | Consensus rule, not price promise |
| **Finality** | HU Finality: BFT quorum of the block's ECVRF-sampled operator committee — **one vote per unique operator**, threshold ⌈2/3·min(E,N)⌉ (E=128) — reached in ~1 minute; finalized ⇒ irreversible (conflicting chains rejected even with more chainwork). ECDSA/secp256k1, not probabilistic | BFT consensus |
| **HTLC** | Executes exactly as scripted (claim: preimage+sig, refund: timeout+sig) | Script engine |
| **OP_TEMPLATEVERIFY** | Spending TX must match committed template | Script engine |

### What Consensus DOES NOT DEFINE

Price, peg, stablecoin, token, reserve, backing, collateral ratio, liquidation, issuer, whitelist, blacklist, admin, upgrade authority, treasury, M2, wrapped token, synthetic, derivative.

**If a concept is not listed above, it does not exist at consensus level.**

### What Consensus REFUSES

- Oracle dependency (any external data not verifiable on-chain)
- Economic parameters (interest rates, fees, thresholds, yield)
- Price awareness (no price feed, no target value)
- Privileged actors (no admin keys, no emergency powers)
- Redemption promise (burn is one-way; protocol provides settlement, not redemption)

---

## 3. Architecture

### Network Topology

| Node          | Host                  | Role                                                  |
|---------------|-----------------------|-------------------------------------------------------|
| Seed          | `57.131.33.151:27171` | Public P2P entry + BTC SPV daemons — carries **no consensus key** |
| Operators ×4  | *not published*       | 4 independent operator nodes (2 masternodes each)     |

Current public testnet genesis (block 0):
`0d241620b8beb492fd21bd8a92295260a4afa1b82e1bd816d18323cc3c98ea71`

The live testnet runs **8 masternodes under 4 distinct operator keys**. Block
**production** rotates deterministically across all operators (DMM — one block ≈ 60 s,
everyone in turn, no single "miner"); **finality** counts **one vote per operator** (an
operator running several masternodes still casts a single vote). The seed is a plain
peer: it holds no operator key, and operator addresses are deliberately not published —
joining the network requires only the seed above.

### Consensus Parameters

```cpp
consensus.nDMMBootstrapHeight = 250;      // testnet (mainnet 10, regtest 2): cold-start
                                          //   window — unsigned / unconfirmed-MN blocks
                                          //   allowed up to this height
consensus.nStaleChainTimeout = 600;       // 10 min cold start recovery
consensus.nHuLeaderTimeoutSeconds = 45;   // Leader timeout
consensus.nHuFallbackRecoverySeconds = 15;// Fallback window
```

### Block Structure

**Canonical layout (the model — every block is SPV-validated, no genesis bypass):**

```
Block 0   Genesis coinbase (empty, 0 reward)
Block 1   TX_MINT_M0BTC — mints M0 from SPV-verified BTC burns
          (validated exactly like any later block; NO premine, NO bypass)
Block 2   ProReg — masternode registrations
Block 3+  Autonomous network: DMM production (~60 s) + HU finality
```

The disposable **testnet** genesis reaches the same end-state over a longer bootstrap
window (up to `nDMMBootstrapHeight = 250`): Block 1 publishes the BTC header chain into
consensus (`TX_BTC_HEADERS` → `btcheadersdb`), following blocks catch the headers up and
SPV-verify the auto-discovered burns, the mint follows after K=20 finality blocks, then
ProReg registers the masternodes (**8 MNs across 4 operators**). **Mainnet** uses the same
flow with a short window (`nDMMBootstrapHeight = 10`) and real Bitcoin. Either way, no burn
is ever hardcoded — every minted sat traces to an SPV-verified BTC burn.

### Constants

| Constant | Testnet | Mainnet | Purpose |
|----------|---------|---------|---------|
| `BTC_CHECKPOINT` | 286000 (Signet) | 800000 | SPV starting point |
| `BATHRON_MAGIC` | `42415448524f4e` | Same | "BATHRON" hex in OP_RETURN |
| `K_FINALITY` | 20 | 100 | Blocks before mint eligibility |
| `K_BTC_CONFS` | 6 | 24 | Required BTC confirmations |
| `MIN_BURN_SATS` | 1000 | 1000 | Dust protection |
| `MAX_MINT_CLAIMS_PER_BLOCK` | 100 | 100 | Per-block mint cap |
| `MAX_BURN_CLAIMS_PER_BLOCK` | 50 | 50 | Per-block claim submission cap |
| `nDMMBootstrapHeight` | 250 | 10 | Bootstrap window (regtest 2) |

---

## 4. Testnet Genesis (Implemented)

### Orchestration: `deploy_to_vps.sh --genesis`

7-step pipeline with `--resume-from=N` support:

| Step | Function | What It Does |
|------|----------|--------------|
| 1 | `genesis_step_1_spv_prepare` | Sync BTC headers on Seed from Signet, create btcspv backup |
| 2 | `genesis_step_2_create` | Run `genesis_bootstrap_seed.sh` on Seed (isolated, no peers) |
| 3 | `genesis_step_3_configure` | Distribute operator key(s), configure the masternode signing node(s) |
| 4 | `genesis_step_4_distribute` | Package chain data, distribute to all 5 nodes (parallel SCP) |
| 5 | `genesis_step_5_start` | Start bathrond on all nodes |
| 6 | `genesis_step_6_verify` | 3-gate verification (height, BTC headers, consensus hash) |
| 7 | `genesis_step_7_seed_daemons` | Start header daemon + burn claim daemon on Seed |

### Bootstrap Script: `genesis_bootstrap_seed.sh`

Runs on the Seed node in an isolated datadir (`/tmp/bathron_bootstrap`):

```
Phase 0: Setup
  ├── Kill all bathrond, wipe /tmp/bathron_bootstrap
  ├── Restore btcspv LevelDB from backup
  ├── Start bathrond in -noconnect -listen=0
  └── Verify btcspv tip >= 286001

Phase 1: Block 1 (TX_BTC_HEADERS)
  ├── generatebootstrap 1
  └── Verify: type 33 TX present, zero type 31

Phase 2: Header Catch-Up
  └── Loop generatebootstrap until btcheadersdb.tip >= BTC_tip - 6

Phase 3: Burn Discovery
  ├── Scan BTC Signet blocks [286301, safe_height]
  ├── For each OP_RETURN with BATHRON magic → submitburnclaimproof
  └── Set burn scan progress for daemon handoff

Phase 4: K-Finality → Phase 5: Auto-Mint → Phase 6: MN Registration
  ├── 20 finality blocks
  ├── TX_MINT_M0BTC auto-created by block assembler (from SPV-verified burns)
  ├── Masternodes registered via protx_register (v3, VRF operator pubkey required)
  │     — 8 MNs spread across 4 distinct operator keys (VRF_NUM_OPERATORS)
  └── Operator keys saved to ~/.BathronKey/operators.json (array of operators)
```

### Properties

- **Zero hardcoded burns** — all discovered from BTC Signet
- **Idempotent** — safely re-runnable from scratch
- **New burns auto-claimed** — runtime daemon picks up where genesis left off

### Commands

```bash
# Full genesis
./contrib/testnet/deploy_to_vps.sh --genesis

# Resume from step 4
./contrib/testnet/deploy_to_vps.sh --genesis --resume-from=4

# Status
./contrib/testnet/deploy_to_vps.sh --status
```

### Expected State

```bash
$ bathron-cli -testnet getblockcount
252

$ bathron-cli -testnet getbtcheadersstatus | jq '.tip_height'
291289

$ bathron-cli -testnet listburnclaims final 100 | jq 'length'
34
```

---

## 5. Mainnet Genesis (Planned)

### Difference from Testnet

Mainnet uses the **same** burn → SPV → mint → ProReg flow as testnet — the differences are
operational, not architectural:

- **Burn source** is Bitcoin **mainnet** (not Signet), anchored at SPV checkpoint 800000.
- **Pre-collected burns**: there is no chain yet to submit TX_BURN_CLAIM to, so burns are
  gathered during a public burn window before launch, then claimed and minted during the
  bootstrap window.
- **The genesis block is mined and pinned**: its hash + merkle root are hardcoded and
  asserted in `chainparams.cpp`, so every node validates against the exact same genesis.
- **Short bootstrap window** (`nDMMBootstrapHeight = 10`): `generatebootstrap` is permitted
  ONLY while height < 10 (the launcher PoW-mines the cold-start blocks), then the RPC
  refuses forever — no post-launch manual mining.

**Zero premine, zero bypass** — every bootstrap block still carries a burn-backed
`TX_MINT_M0BTC` and a real `ProRegTx`; each mint traces to an SPV-verified BTC burn, exactly
as at runtime. (The earlier height-0 "genesis-burns commitment root" design was retired —
there is no genesis SPV bypass.)

### Pre-Launch Timeline

```
Day -30: Announce burn procedure, open testnet for testing
Day -7:  Open MAINNET burn window (anyone can burn BTC)
Day -1:  Cutoff block announced (height H), wait K=24 confirmations
         Publish the collected burn list for community verification
Day 0:   GENESIS — mined+pinned genesis block, then bootstrap blocks (height < 10)
         SPV-verify and mint the pre-collected burns, and register the masternodes
Day 1+:  New burns via runtime TX_BURN_CLAIM (live SPV)
```

### Burn Format (BCS v1.0)

```
OP_RETURN: BATHRON|01|<NET>|<DEST_HASH160>  (29 bytes)
Burn output: P2WSH(OP_FALSE)               (provably unspendable)
P2WSH hash: SHA256(0x00) = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
```

### Mine + Pin the Genesis Block

```cpp
// chainparams.cpp — the mainnet genesis is mined once and pinned (tamper-evident):
assert(consensus.hashGenesisBlock == uint256S("00000ade..."));  // nBits/nTime/nNonce fixed
assert(genesis.hashMerkleRoot     == uint256S("e356723e..."));
```

There is no external burns/headers file and no commitment root. Instead:
1. The genesis block is mined with the project's own genesis miner, and its hash + merkle
   root are hardcoded and asserted — a node that boots past the asserts is on the canonical
   genesis; any tampering fails.
2. The launcher PoW-mines the cold-start blocks via `generatebootstrap` (mainnet-gated to
   height < `nDMMBootstrapHeight` = 10, then permanently refused).
3. Pre-collected burns are SPV-verified against `btcheadersdb` (header + merkle proof) and
   minted via `TX_MINT_M0BTC` — the ordinary claim → mint path, no height-0 injection.

### Genesis State Initialization

```
Height 0:      Mined + pinned genesis coinbase (empty, 0 reward). M0BTC_supply = 0.
Heights 1..9:  Bootstrap window (< nDMMBootstrapHeight = 10) — launcher-mined:
                 ├── BTC headers published into consensus (TX_BTC_HEADERS)
                 ├── Pre-collected burns SPV-verified → TX_MINT_M0BTC
                 │     (M0BTC_supply grows to Σ burnedSats; A5/A6/A7 hold each block)
                 └── Masternodes registered via ProRegTx (v3, VRF pubkey)
Height 10+:    Autonomous protocol — DMM production, HU finality,
               runtime TX_BURN_CLAIM / lock / unlock / settlement.
```

### Security

- The genesis block hash + merkle root are pinned in source (tamper-evident) — a modified
  genesis fails the compiled-in asserts.
- Genesis burns are **SPV-verified during the bootstrap window**, not embedded — the same
  proof path as runtime claims. No burn is hardcoded.
- No late additions — missed the window → wait for a runtime TX_BURN_CLAIM.
- Anyone can verify: BTC burn TXs are public, the pre-launch burn list is published, and the
  genesis hash is in the source.
- Founder burns use the same format and rules as public burns

---

## 6. Burn Discovery & Minting

### Discovery (Testnet: Live, Mainnet: Pre-Launch)

**Testnet scan logic** (used by both `genesis_bootstrap_seed.sh` and `btc_burn_claim_daemon.sh`):

```bash
# For each BTC block:
block=$(bitcoin-cli getblock $hash 2)
# Filter TXs with OP_RETURN containing BATHRON magic (6a1d42415448524f4e)
# Submit each via: bathron-cli submitburnclaimproof $raw_tx $merkleblock
```

**Mainnet:** Burns collected during pre-launch window, verified, embedded in genesis_burns.json.

### Minting Pipeline

```
TX_BURN_CLAIM accepted (mempool → block)
    → BurnClaimRecord created: status=PENDING
    → K blocks pass (20 testnet / 100 mainnet)
    → Block producer: CreateMintM0BTC(height)
        → Query all PENDING claims where height > claim_height + K
        → Sort eligible by txid (canonical, deterministic)
        → Cap at MAX_MINT_CLAIMS_PER_BLOCK (100)
        → Create TX_MINT_M0BTC: one P2PKH output per claim
        → nValue = record.burnedSats (1:1)
        → Empty vin (money creation)
    → ALL nodes verify: independently compute expected TX, hash must match
    → BurnClaimRecord updated: status=FINAL
```

### Rejection Codes

| Code | Description |
|------|-------------|
| `burnclaim-btc-header-missing` | BTC header not in btcheadersdb |
| `burnclaim-merkle-invalid` | Merkle proof verification failed |
| `burnclaim-duplicate` | Burn already claimed |
| `burnclaim-amount-zero` | No valid burn output found |

---

## 7. Key Management

### Storage Structure

```
~/.BathronKey/           # drwx------ (700)
├── operators.json       # MN operator keys (array; generated on Seed, distributed to signing daemons)
├── wallet.json          # Main wallet (1 per VPS)
├── evm.json             # EVM wallet (if applicable)
└── btc.json             # BTC wallet (if applicable)
```

### operators.json

Holds the **array of distinct operators** (one finality vote each, each with its VRF pubkey)
plus the per-masternode owner records. Written on Seed at genesis; each operator secret is
then loaded on its own signing daemon (`-mnoperatorprivatekey`) — one operator key per
daemon, or only the locally-loaded operator ever votes finality.

```json
{
  "num_operators": 5,
  "operators": [
    {"index": 0, "wif": "<secret>", "pubkey": "03...", "vrf_pubkey": "..."},
    {"index": 1, "wif": "<secret>", "pubkey": "03...", "vrf_pubkey": "..."}
    // ... one entry per distinct operator
  ],
  "masternodes": [
    {"mn": 1, "operator_index": 0, "proTxHash": "...", "owner": "...", "payout": "..."}
    // ... 8 masternodes mapped to operators
  ]
}
```

### Rules

1. **NEVER** commit `~/.BathronKey/` to git
2. **NEVER** hardcode WIFs in scripts
3. **ALWAYS** read keys at runtime
4. Operator key regenerated at each genesis
5. One wallet per VPS — never shared

---

## 8. Verification & Gates

### 3-Gate System (genesis_step_6_verify)

| Gate | Check | Threshold |
|------|-------|-----------|
| **Height** | All nodes at height >= 5 | 3 retries, 10s apart |
| **BTC Headers** | `btcheadersstatus.tip_height >= 286000` on all nodes | First try |
| **Consensus** | Same `getblockhash` at common height | Unanimous |

### Health Check (post-verification)

- Daemon count = 1 per node
- Block heights match
- Headers == blocks (no IBD)
- Peer connectivity >= 4

### Mainnet Startup Verification

```cpp
// FATAL if any check fails:
VerifyGenesisBurnsCommitment()    // File hash matches commitment
PreloadGenesisHeaderChain()       // Header chain valid and linked
VerifyGenesisBurnProof(burn)      // SPV proof + ancestry + format (BCS v1.0)
```

---

## 9. Post-Genesis Operations

### BTC Header Daemon (`btc_header_daemon.sh`)

- Publishes new BTC headers as TX_BTC_HEADERS
- Keeps btcheadersdb in sync with BTC chain
- Required for validating new burn claims

### Burn Claim Daemon (`btc_burn_claim_daemon.sh`)

- Scans BTC every 5 minutes for new burns
- Submits TX_BURN_CLAIM for each new burn found
- Persistent state in settlement DB (reorg-safe)
- Deduplication: `checkburnclaim` + consensus rejection
- SPV-capped: never scans beyond btcheadersdb tip

### New Burn Flow (Fully Automatic)

```
BTC burn (OP_RETURN "BATHRON|01|T|dest_hash")
    → btc_burn_claim_daemon detects
    → TX_BURN_CLAIM submitted
    → Consensus validates (SPV proof, format, uniqueness)
    → K blocks later → TX_MINT_M0BTC automatic
    → M0 credited to destination
```

---

## 10. Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| "btcspv tip too low" | BTC Signet not synced on Seed | Start BTC daemon, wait, re-run step 1 |
| "no burns found" | BTC_CHECKPOINT after all burns | Verify `bitcoin-cli -signet getblockcount` > 286326 |
| "zero mints after K blocks" | Burns not finalized yet | Check debug.log, bootstrap handles automatically |
| "bad-protx-dup-owner" | MN collateral conflict | Full genesis reset (no --resume-from) |
| Fork after genesis | Nodes have different chain data | Re-run steps 4+5 |
| "no MNs found on-chain" | Operator key mismatch | Check `~/.BathronKey/operators.json` |
| 0 peers | `addnode` not in `[test]` section | Fix bathron.conf section placement |
| EvoDB inconsistent | Corrupt state | `bathron-cli stop && bathrond -reindex` |

---

## 11. Files Reference

### Scripts

| File | Purpose |
|------|---------|
| `contrib/testnet/deploy_to_vps.sh` | 7-step genesis orchestrator |
| `contrib/testnet/genesis_bootstrap_seed.sh` | Bootstrap (runs on Seed, isolated) |
| `contrib/testnet/btc_burn_claim_daemon.sh` | Live burn scanner (post-genesis) |
| `contrib/testnet/btc_header_daemon.sh` | BTC header publisher (post-genesis) |

### C++ Consensus

| File | Purpose |
|------|---------|
| `src/blockassembler.cpp` | TX_MINT_M0BTC creation (automatic) |
| `src/burnclaim/burnclaim.cpp` | Burn claim validation + CreateMintM0BTC |
| `src/btcspv/btcspv.cpp` | BTC SPV verification (PoW, merkle, checkpoints) |
| `src/btcheaders/btcheaders.cpp` | TX_BTC_HEADERS validation (R1-R7 rules) |
| `src/masternode/specialtx_validation.cpp` | Per-type TX dispatch (CheckSpecialTx) |
| `src/consensus/tx_verify.cpp` | Generic TX validation |
| `src/chainparams.cpp` | Network parameters, checkpoints |

---

## Appendix A: Mainnet Data Structures

The mainnet genesis uses the **same** on-chain structures as testnet and runtime — there are
no genesis-only data structures. (The previously-planned commitment-root design —
`GenesisBurn`, `GENESIS_BURNS_COMMITMENT`, and external `genesis_burns.json` /
`genesis_btc_headers.bin` files — was **retired** in favour of mine+pin + a burn-backed
bootstrap window.)

### Pinned genesis block (chainparams.cpp)

The genesis block is mined once with the project's genesis miner and pinned:

```
hashGenesisBlock   — asserted at startup (nBits / nTime / nNonce fixed)
hashMerkleRoot     — asserted at startup
```

A node that boots past these asserts is on the canonical genesis; any tampering fails.

### Bootstrap window (height < nDMMBootstrapHeight = 10)

```
- Launcher PoW-mines the cold-start blocks (generatebootstrap, mainnet-gated to
  height < 10, then permanently refused).
- Pre-collected burns are SPV-verified (btcheadersdb header + merkle proof) and minted
  via TX_MINT_M0BTC — the ordinary BurnClaimRecord → mint path, no height-0 injection.
- Masternodes registered via ProRegTx (v3, VRF operator pubkey required).
- M0BTC_supply = Σ minted burnedSats; A5/A6/A7 hold from the first block.
```

### Runtime (height >= nDMMBootstrapHeight)

Same as testnet: TX_BURN_CLAIM → K confirmations → TX_MINT_M0BTC, DMM production, HU finality.

---

## Appendix B: Regulatory Defense

### Canonical Statements

```
TRUE:
  "Bathron verifies BTC burns via SPV"
  "M0 records the quantity of BTC destroyed, satoshi for satoshi"
  "M1 represents locked M0 at 1:1"
  "The protocol provides ~1 minute finality"
  "The protocol provides primitives used by explicitly specified atomic swaps"

FALSE (never say these):
  "Bathron is a stablecoin"
  "M1 is pegged to BTC"
  "Bathron guarantees M1 = 1 BTC"
  "Bathron issues tokens"
  "Bathron provides yield"
  "Bathron has reserves"
```

### If Asked

| Question | Answer |
|----------|--------|
| "Is this a stablecoin?" | No. No concept of price stability at consensus level. |
| "Who issues M1?" | No one. M1 is created by consensus when M0 is locked. |
| "Is there a peg?" | No. 1:1 is an accounting identity, not a price target. |
| "Who controls the protocol?" | No one. No admin keys or upgrade authority. |
| "Is there a reserve?" | No. The BTC is destroyed, not held for redemption; M0 is an internal accounting unit. |
| "Can users create stablecoins on Bathron?" | Users can create any script. The protocol does not classify them. |

### The Distinction

```
WHAT THE PROTOCOL DOES:           WHAT IT DOES NOT DO:
  Verify BTC burns (SPV)            Promise prices
  Maintain M0/M1 accounting         Issue tokens
  Execute scripts as written         Manage reserves
  Provide finality                   Stabilize anything
                                     Redeem to BTC

THE PROTOCOL IS A SETTLEMENT KERNEL. IT IS NOT A MONETARY POLICY.
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.2 | 2026-07-22 | Public testnet rebuild: current live network = **8 MNs / 4 operators** (genesis 0d241620…); seed 57.131.33.151:27171 published as the public P2P entry (carries no consensus key); operator addresses not published. |
| 1.1 | 2026-07-12 | Consensus-model refresh: HU finality = per-operator ECVRF committee, threshold ⌈2/3·min(E,N)⌉ (E=128), one vote per operator (was "2/3 MN quorum"); multi-operator testnet (9 MNs / 5 operators, operators.json = array); nDMMBootstrapHeight 250/10/2 (was 3/5); mainnet genesis = mine+pin + burn-backed bootstrap window (commitment-root design retired); mainnet SPV checkpoint 800000 |
| 1.0 | 2026-02-13 | Consolidated from 09-TESTNET-GENESIS v3.0, 12-BTC-BURN-GENESIS v1.6, GENESIS-SAFE v1.0 |
