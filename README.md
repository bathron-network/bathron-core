# BATHRON

> **An experimental settlement kernel for Bitcoin.**

BATHRON is a functional testnet for conditional Bitcoin settlement. It combines covenants,
Bitcoin-header verification in consensus, confidential internal transfers and fast finality so
applications can coordinate two settlement legs without giving one intermediary unrestricted
custody of the client funds.

BATHRON has no token sale, premine, block reward, treasury or yield. Its internal units are not
offered as an investment and are not a redeemable claim on Bitcoin.

**Live testnet:** genesis `0d241620b8beb492fd21bd8a92295260a4afa1b82e1bd816d18323cc3c98ea71` ·
seed node `57.131.33.151:27171` · **No mainnet** · Adoption and the
commercial model remain unproven.

## Join the public testnet

Build (see *Compilation* below), then point a fresh node at the public seed —
no RPC is exposed, no operator address is needed:

```bash
mkdir -p ~/.bathron
printf 'testnet=1\n[test]\naddnode=57.131.33.151\n' > ~/.bathron/bathron.conf
./src/bathrond -testnet -daemon
./src/bathron-cli -testnet getblockhash 0
# expected: 0d241620b8beb492fd21bd8a92295260a4afa1b82e1bd816d18323cc3c98ea71
./src/bathron-cli -testnet getblockcount   # syncs to the network tip
```

---

## The problem

A Bitcoin payment can prove that value moved, but many transactions require a second condition:
delivery, a counter-payment, a deadline or a verified event. Existing solutions usually add a
custodian, federation, oracle or human arbitrator. BATHRON tests whether those conditions can
instead be expressed as contracts whose execution is verified by the network.

The initial product hypothesis is a **conditional BTC settlement service**:

1. A Clearing Provider (CP) gives the client a quote in the assets the client already uses.
2. The two settlement legs are committed with explicit execution and timeout paths.
3. BATHRON holds the programmable internal state needed to evaluate the conditions.
4. Liquidity Providers (LPs) supply inventory and quotes; the CP charges disclosed fees and
   spreads for routing, capital and operations.
5. Settlement Operators run consensus and finality. They do not set prices or rank providers.

The target experience is that a client sends and receives BTC without buying or managing M0 or
M1. That client-protection flow is a design target, not yet a production guarantee: the complete
timelock and reorganisation specification still requires formalisation and external review.

---

## Who provides the service and why

BATHRON splits "run the ledger" from "run the business". The protocol enforces the money rules;
**professionals provide the service and the liquidity.** Three roles — a single company may hold
one, two or all three:

- **Settlement Operator** — the consensus identity. Produces blocks and votes finality. Registers
  by locking M0 collateral that can only originate from a verified, irreversible BTC destruction.
  Sets no prices and ranks no one.
- **Clearing Provider (CP)** — the client-facing service. Quotes, orchestrates the two legs,
  handles timeouts, offers an SLA, and is paid through disclosed fees and spreads.
- **Liquidity Provider (LP)** — the capital. Holds inventory and quotes a specific pair.

The client never buys or manages M0/M1. The loop is:

```
client ──quote──▶ CP ──routes──▶ LP (inventory)
   ▲                │
   └──BTC / asset───┘   settled on ── Settlement Operators (consensus + finality)
```

Why a builder may choose to run an operator: an app brings **flow**; flow may generate fees and
service revenue for whoever settles it — so the app's creator may run one, the way exchanges run
their own Bitcoin nodes. Those revenues are a **market hypothesis, not a guarantee**. Whether
identifiable, M0-collateralised operators who also run the service behave well enough for a market
to form is the **institutional hypothesis BATHRON tests** — not an assumption.

---

## Security in one screen

Every node fully validates every block; finality sits **on top of** validation, never bypassing
it. So the **money supply is inviolable by the signing set** — but transaction *ordering and
liveness* are not. What a coalition reaching the 2/3 finality threshold can and cannot do:

| Action | Threshold coalition? |
|---|---|
| Create M0 without a valid burn | **No** (rejected by every node) |
| Change M0↔M1 accounting | **No** (consensus-strict) |
| Spend a client's key / force a Bitcoin transaction | **No** |
| Censor a claim, or continue past it to a timeout | **Yes / potentially yes** |
| Stall finality | **Yes** |
| Produce conflicting certificates | **Yes, with enough equivocation** |
| Make a node auto-accept a rollback of a height it already finalized | **No** — conflicting finalized history is rejected; the real risk is a **split + social recovery**, not a silent rollback |

Operator identity and its public track record raise the *commercial* cost of misbehaving; they do
**not** replace the assumption that fewer than one third of operators are byzantine, and they do
not prove legal identity or future honesty. Economic openness and Sybil resistance remain to be
demonstrated — the current testnet operator set is project-controlled. Full model:
**[SECURITY-MODEL.md](doc/public/SECURITY-MODEL.md)**.

---

## What the testnet has demonstrated

- a Bitcoin Merkle proof checked against the Bitcoin header chain carried in BATHRON consensus;
- a proven Bitcoin payment releasing a covenant through `TX_CONFIRMED` and CTV;
- confidential internal transfers using Sapling;
- an M1 HTLC on BATHRON paired with a P2WSH HTLC on Bitcoin signet using one preimage;
- consensus invariants preventing block producers from creating M0 without verified burns or
  breaking the internal M0↔M1 accounting equality.

These components have run on the testnet. A production-ready, generally atomic CP service has
not yet been specified, audited or launched.

---

## Why an internal settlement asset exists

Conditional contracts need an asset whose state the BATHRON consensus can lock, transfer and
release. Native BTC cannot be moved by BATHRON: the network can verify Bitcoin facts, but it
cannot command a Bitcoin transaction.

BATHRON therefore uses two internal accounting states:

```text
BTC --irreversible, SPV-proven destruction--> M0
M0 -------------lock 1:1-------------------> M1
M1 -------------unlock 1:1-----------------> M0
```

- **M0** can be created only after a verified BTC destruction. The BTC is destroyed, not held in
  reserve; M0 is therefore not “backed by” or redeemable for that BTC.
- **M1** is created by locking M0 and is used as programmable settlement state. The protocol
  enforces M0↔M1 accounting at 1:1, but it does not guarantee an external BTC price or exit.
- CPs and LPs, not retail clients, bear the inventory and liquidity risk in the target service.

The burn is an acquisition cost for professional inventory, not the product and not an invitation
for the public to acquire an internal coin.

---

## Relevant capabilities

| Capability | BATHRON testnet |
|---|---|
| Covenant templates | `OP_TEMPLATEVERIFY` |
| Bitcoin facts in consensus | `OP_BTCSTATEVERIFY` + `TX_CONFIRMED` |
| Relative and absolute timelocks | CSV/BIP68 + CLTV |
| Signatures over messages | `OP_CHECKSIGFROMSTACK` |
| Confidential internal transfers | Sapling |
| Fee-only block production | `block_reward = 0`, coinbase = fees |
| Fast finality | HU committee finality, approximately one minute on the current testnet |

The strongest differentiated primitive is simple: **a Bitcoin fact verified in consensus can
release a covenant on BATHRON without asking an oracle to attest that fact.** Escrow,
delivery-versus-payment and OTC workflows are application hypotheses built from this primitive.

---

## What BATHRON does not claim

- It is not CLS and does not have central-bank accounts, regulated settlement membership or
  equivalent legal finality.
- It is not a bridge holding BTC for redemption.
- It is not a retail payment coin, stablecoin or yield product.
- It is not mainnet and has no proven market.
- It does not beat Lightning for simple instant payments or stablecoins as a unit of account.
- It cannot guarantee that professional liquidity will exist; that is the principal commercial
  hypothesis to test.

The next proof is economic rather than rhetorical: a real CP must show that fees and spreads can
cover inventory, liquidity, capital and operating costs while clients receive a useful
conditional-settlement service.

*BATHRON — conditional Bitcoin settlement, tested in public before it is promised.*
