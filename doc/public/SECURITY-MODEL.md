# BATHRON Security Model

> How trust actually works on BATHRON: what the protocol enforces, what it does
> not, and which properties are still hypotheses to be tested. Read together with
> [SETTLEMENT-OPERATORS.md](SETTLEMENT-OPERATORS.md) (the operator identity) and
> [GENESIS.md](GENESIS.md) (consensus mechanics).

This page separates three things that are easy to conflate: what is a **fact today**
(true in the code), what is a **design goal** (intended but not yet built), and what
is an **economic hypothesis** (unproven, to be demonstrated). Each claim below is
tagged accordingly.

---

## 1. The four ideas in two minutes

1. **The protocol enforces invariants; professionals provide the service and the
   liquidity.** Consensus guarantees the money rules (below). Quotes, execution,
   timeouts, inventory and pricing live in the application layer, run by Clearing
   Providers and Liquidity Providers. *(fact + design)*
2. **Operator identity and its track record create commercial deterrence, but they
   do not replace the BFT assumption.** A registered identity has an up-front,
   externally verifiable acquisition cost and a public history; neither proves legal
   identity nor future honesty, and neither substitutes for "fewer than one third of
   operators are byzantine." *(fact + hypothesis)*
3. **A malicious quorum cannot create M0 without a verified burn, but it can censor,
   stall finality, or produce conflicting views.** The money supply is inviolable by
   the signing set; transaction *ordering and liveness* are not. *(fact)*
4. **Economic openness and Sybil resistance remain to be demonstrated.** The launch
   is project-controlled — the maintainer's infrastructure runs the operators, without
   any proven protocol-level admission restriction. Whether an open set stays
   below the byzantine threshold, and at what collateral price, is unproven.
   *(hypothesis)*

---

## 2. What consensus enforces (invariants) — fact

Every node validates every block fully; finality is a layer **on top of** full
validation, never a bypass. These hold regardless of who signs:

- **A5 — `M0_total(N) = M0_total(N-1) + BurnClaims`.** M0 can only be created by a
  BTC destruction proven via SPV against the Bitcoin header chain carried in
  consensus. Signing a block does not forge a burn.
- **A6 — `M0_vaulted == M1_supply`.** M0↔M1 accounting is 1:1 and consensus-strict.
- **A7/A9 — supply cap and canonical-chain checks.** The tracked BTC chain must be
  the real Bitcoin chain (halving-boundary checkpoints; reorgs below a pinned
  checkpoint or a finalized burn are rejected).
- **`block_reward = 0`, coinbase = recycled fees, treasury = 0.** No issuance path
  exists other than verified burns.

Consequence: **the money supply is inviolable by the finality quorum.** A quorum,
even a hypothetically malicious one, cannot mint M0, break M0↔M1 parity, pay itself
a reward, or make an invalid transaction valid — honest nodes reject any block that
tries, whatever signatures it carries.

---

## 3. The BFT assumption — fact + hypothesis

Finality is a BFT vote: threshold `ceil(2/3 · min(E, N))` over **unique operators**
(one operator = one vote, whatever its size or age; E is a fixed committee cap of
128). Safety and liveness of *ordering* rest on the standard assumption that **fewer
than one third of operators are byzantine.**

- **Today — fact:** the current testnet operator set is **project-controlled** — the
  maintainer's infrastructure runs the operators (≥ 4 distinct at the 3f+1 floor).
  This means no *independent* adversary currently holds a fraction of the set, so the
  external-adversary scenarios below are not being exercised. It does **not** demonstrate
  byzantine resistance under open admission, and it does **not** remove the risk of
  software bugs, operator-key compromise, or a correlated failure of the project's own
  infrastructure (shared hosting, shared operator, single maintainer).
- **Open network — hypothesis:** when independent, untrusted operators can register, the
  < 1/3 assumption must hold economically. That is the open question of section 7, not a
  property the current set already provides.

Identity and reputation (section 5) raise the *commercial* cost of misbehaving; they
do **not** raise the byzantine threshold. The threshold is still 1/3.

---

## 4. Security in one screen — the 2/3 matrix (fact)

What a coalition that reaches the finality threshold can and cannot do:

| Action | Can a threshold coalition do it? |
|---|---|
| Create M0 without a valid burn | **No** — rejected by every node (A5) |
| Change M0↔M1 accounting | **No** — rejected by consensus (A6) |
| Spend a client's key | **No** — it does not hold the key |
| Force a Bitcoin transaction | **No** — BATHRON can read Bitcoin, not command it |
| Censor a specific claim | **Yes** — omit it from the blocks it produces, or refuse to finalize the blocks that include it |
| Continue the chain without the claim until a timeout | **Potentially yes** — censorship plus time can push a leg to its refund path |
| Stall finality | **Yes** — withhold votes so blocks stop finalizing |
| Produce conflicting certificates | **Yes, with enough equivocation** across a partition |
| Make a node that already finalized height H auto-accept a rollback of H | **No** — `HasConflictingFinality` / `WouldViolateHuFinality` reject a conflicting block at a finalized height, even with more chainwork. The real risk is a **split / divergent views** between partitions and a **social recovery**, not a silent rollback |

Read the last row carefully: **a competing branch does not simply replace finality
on nodes that already finalized.** Those nodes reject it. What an equivocating
coalition can cause is two groups of nodes holding different views until operators
and the community reconcile them out of band.

---

## 5. Collateral and external cost (fact) — no "backing" anywhere

The causal chain is precise, and it is **not** "burn BTC → operator identity":

```
BTC destruction        → M0 creation        (SPV-verified, irreversible)
M0 acquisition         → collateral lock    (own a burn, or buy M0 from a third party)
collateral lock        → MN / operator registration
```

- The **destroyed BTC is never recoverable.** It is not held, not reserved, not
  redeemable. M0 is never "backed by" or "adossé à" that BTC.
- The **M0 used as collateral is currently locked but recoverable on exit**: spending
  the collateral outpoint de-registers the operator and returns the M0 to its owner.
  Locked ≠ destroyed.
- An operator **need not have burned the BTC itself.** It can acquire M0 from a third
  party who did. The external acquisition cost is therefore a **market price that
  depends on M0 liquidity**, not a fixed protocol charge.
- The current registration floor is **0.01 BTC-equivalent**. This is a **launch
  parameter, not a proven Sybil price.** Whether it is high enough to deter a Sybil
  operator set in an open network is exactly the unproven question of section 7.

The finality threshold is over **distinct, eligible operator identities**, not over an
amount of collateral. To reach it, an attacker must acquire enough M0 to register
**enough separate identities** to make up the applicable threshold — each identity is a
separate registration with its own locked collateral. Owning a large amount of M0 in one
place is not, by itself, a threshold.

There is **no slashing.** Deterrence against a registered operator is (a) the up-front
acquisition cost, paid before it can act, and (b) a PoSe ban for missed block production.
The ban is **not a certain financial loss**: it removes the identity from the active set,
so its only cost is the **possible loss of future service/fee opportunities — revenues
that are themselves unproven**. An attacker who registers the identities keeps their
locked M0; the attack's cost is what it paid to acquire that M0 (a liquidity-dependent
market price) plus any forgone future opportunity, not the loss of its capital.

---

## 6. The role of reputation (fact + design + hypothesis)

Reputation is a **commercial** signal, measured and weighed by applications. It is not
a consensus input and it is not a security guarantee. Precisely:

- **Age and on-chain history cannot be fabricated instantly** *(fact)*: registration
  height and blocks produced are chain facts. A brand-new identity cannot present a
  three-year record.
- They **do not prove legal identity or future honesty** *(fact)*: a long history is
  evidence of past behaviour, not a bond on the next block.
- **Deterministic finality-participation** (a chain-anchored "uptime" primitive) is
  **roadmap, not current state** *(design)*: today, who signed finality is gossip, not
  chain data.
- **CP/LP metrics** (settled volume, latency, incident-free streak) are
  **application/indexer facts, not consensus** *(fact)*: any indexer can derive them;
  nothing in consensus consumes them.
- **Volume and reputation can be manipulated** (wash volume, self-dealing, selective
  disclosure) *(fact)*: a credible reputation layer therefore requires an **external
  methodology** — independent measurement, not the operator's own claims.

We do not claim "reputation cannot be bought." We claim the narrower, testable thing:
*a specific identity's age and public history cannot be back-dated*, while everything
built on top of them still needs independent verification.

---

## 7. What is not yet demonstrated (hypothesis) — pre-mainnet work

Honest open items, none of which the current project-controlled operator set resolves:

- **Sybil resistance of an open operator set.** The 0.01 BTC-equivalent floor is a
  launch parameter; a mainnet Sybil-cost analysis and collateral re-pricing are open.
- **Value-at-risk bound per finality window.** Capping settled value per window
  bounds what a one-time captured committee could touch; not yet specified.
- **External audit of the VRF finality module** — the sole finality path — is a hard
  pre-mainnet gate. An internal audit exists; an external one does not.
- **A binding operator ↔ CP/LP identity link.** The protocol does **not** yet require
  a consensus operator to be the same entity as the CP or LP that sells a service on
  top of it (see [SETTLEMENT-OPERATORS.md](SETTLEMENT-OPERATORS.md) §5). That binding
  is the **institutional hypothesis to test**, currently an off-chain attestation
  (`verifymessage`), not a consensus fact.
- **A productised, externally reviewed atomic-settlement flow.** The cross-chain
  timelock/reorg specification is not yet formalised or audited.

---

## 8. Censorship, liveness, and social recovery (fact)

- **Censorship / liveness are not money-safety.** A threshold coalition can slow,
  stall, or omit an operation — either by leaving it out of the blocks it produces, or
  by refusing to finalize the blocks that include it — but it cannot inflate or steal.
  These are different guarantees and BATHRON keeps them separate on purpose.
- **Recovery from a split is social, not automatic.** Because finalized nodes reject
  conflicting history, a partition is resolved by operators and the community agreeing
  on a canonical view and, if needed, resetting — the testnet genesis is disposable by
  design. There is no on-chain mechanism that silently re-converges divergent finalized
  views.
- **The burn kill switch is a node-local policy flag, not a global admin button**
  (`-btcburnsenabled`, default on). A node with it off simply stops relaying new
  `TX_BURN_CLAIM` into its own mempool and stops originating a mint when it produces a
  block. It is **deliberately not a consensus rule**: a node with it off still accepts
  a valid block that contains a burn from a node that has it on, so divergent settings
  **cannot fork the chain**. To actually pause burns network-wide, a coordinated
  majority of block *producers* must set it — any producer that leaves it on still
  mints. It blocks local origination/relay; it does not block acceptance.

---

## 9. Comparison with Bitcoin (factual, no ranking)

BATHRON and Bitcoin close different attack surfaces with different assumptions; neither
is claimed superior in general.

| | Bitcoin | BATHRON |
|---|---|---|
| Who may extend the chain | anyone with hashpower | a registered, identifiable operator set |
| Sybil cost | cumulative proof-of-work + continuous operating cost | M0 collateral (from burned BTC) + public history + external service revenue |
| Invalid blocks | rejected by every full node | rejected by every full node |
| Censoring a tx | possible for a hashpower majority | possible for a threshold operator coalition |
| Reversing settled history | probabilistic, harder with depth (cost = redoing work) | rejected outright at finalized heights; residual risk = split + social recovery |
| Recovery model | longest-chain reconvergence | reject-conflicting-finality + off-chain reconciliation |

Both prevent invalid blocks. Their costs of censorship and recovery, and the
assumptions each relies on, differ — that is the honest comparison, not a "better than
miners" claim.

---

*Facts are enforced in code today; design goals are intended but unbuilt; hypotheses
are unproven. This document is written so the three are never confused.*
