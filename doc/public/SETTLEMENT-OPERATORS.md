# Settlement Operators — the neutral operator network

> Public companion to [GENESIS.md](GENESIS.md) (consensus mechanics),
> [SECURITY-MODEL.md](SECURITY-MODEL.md) (trust model and the 2/3 matrix) and
> [WHY-BATHRON.md](WHY-BATHRON.md) (value proposition). This document defines
> what a Settlement Operator is, what the protocol publishes about them, what
> the protocol deliberately refuses to do, and how applications are expected
> to build on top.
>
> Throughout, claims are tagged **[fact]** (true in the code today),
> **[design]** (intended, not yet built) or **[hypothesis]** (economic, unproven).

---

## 1. One idea

**An irreversible BTC-origin cost, turned into locked collateral, registers an
identity; it does not create a revenue stream.**

The causal chain is precise — it is *not* "burn BTC → operator identity":

```
BTC destruction   → M0 creation          (SPV-verified, irreversible)   [fact]
M0 acquisition    → collateral lock       (own a burn, or buy M0)        [fact]
collateral lock   → operator registration (produce blocks, vote finality)[fact]
```

A Settlement Operator is a consensus identity whose registration collateral is M0.
Because every M0 unit can only originate from a verified BTC destruction, the identity
has an up-front, externally verifiable acquisition cost. Two things follow that this
document never blurs:

- The **destroyed BTC is never recoverable** — it is not held, reserved or redeemable.
  M0 is never "backed by" that BTC. **[fact]**
- The **M0 posted as collateral is locked but recoverable on exit** — spending the
  collateral outpoint de-registers the operator and returns the M0 to its owner.
  Locked ≠ destroyed. **[fact]**

An operator **need not have burned the BTC itself**: it can acquire M0 from a third
party who did, so the external acquisition cost is a **market price that depends on M0
liquidity**, not a fixed protocol charge. **[fact]** The current registration floor is
**0.01 BTC-equivalent** — a **launch parameter, not a proven Sybil price**; whether it
deters a Sybil operator set in an open network is unproven. **[hypothesis]**

There is no staking yield, no block reward, no inflation, no treasury. **[fact]** An
operator earns nothing from the protocol except recycled transaction fees when it
produces a block. If operating is worth doing, it is because of the **services** an
operator sells on top of its identity — not because the protocol prints for it.

---

## 2. The protocol publishes facts — it never ranks

The protocol's job ends at publishing verifiable facts about each operator.
It never says "this operator is better." Applications decide what *better* means.

Facts the node already publishes today (public RPCs) — **[fact]**:

| Fact | Where |
|---|---|
| Operator identity (operator key, masternode proTxHash) | `listoperators`, `protx_list` |
| Age (registration height) | `protx_list` |
| Service endpoint | `listoperators` |
| Masternodes per operator | `listoperators` |
| Blocks produced, share vs expected share, deviation | `listoperators`, `listmnstats` |
| Liveness policing score (PoSe) | `protx_list` |
| Finality quorum parameters and health | `getfinalitystatus` |

Facts that are **not yet chain-anchored**:

- **Deterministic finality-participation proof** — the true "uptime" primitive —
  is **[design]**, not current state. Today, who signed finality is gossip, not chain
  data; embedding it deterministically is a known pre-open-network consensus item.
- **Cumulative service counters** (settled volume, HTLC counts, incident-free streak)
  are **application/indexer facts, not consensus** **[fact]**: any indexer can derive
  them; nothing in consensus consumes them.

What this identity actually offers is narrow and testable: **a specific operator's
registration height and on-chain block history cannot be back-dated or fabricated
instantly** **[fact]**. It does **not** prove the operator's legal identity or its
future honesty **[fact]**. And because volume and reputation can be manipulated (wash
volume, self-dealing, selective disclosure), any reputation built on these facts
**requires an external measurement methodology**, not the operator's own claims
**[fact]**. We therefore do **not** claim "reputation cannot be bought"; we claim only
that a given identity's public age and history are un-forgeable after the fact.

```
Operator ID        <identifier>          # chain fact
Registered         <height>              # chain fact, un-backdatable
Locked collateral  <locked M0 amount>    # chain fact
Supply origin      verified BTC burn     # system-level: all M0 comes from a burn...
                                          # ...but this operator need not have done it
Participation      <measured value>      # gossip today; deterministic = [design]
Blocks produced    <measured count>      # chain fact
Application events <indexer-derived>     # application layer, not consensus
Incidents          <third-party method>  # requires external methodology
```

---

## 3. What the protocol will NEVER do (neutrality guarantees) — [fact]

These are design commitments, all true in the code today. They constrain the
*protocol*; they are not claims about operator honesty (see
[SECURITY-MODEL.md](SECURITY-MODEL.md) for what a malicious quorum can still do):

- **No block reward, no inflation, no treasury.** Coinbase = recycled fees,
  always (`block_reward = 0`).
- **No operator payments.** The Dash-style operator-reward mechanism was
  removed entirely; there is no protocol payment split of any kind.
- **No reputation-weighted consensus.** One operator = one vote, whatever its
  age, size, or track record. Finality threshold is `ceil(2/3 · min(E, N))`
  over unique operators. Reputation raises the *commercial* cost of misbehaving; it
  does **not** raise the 1/3 byzantine threshold.
- **No protocol ranking.** RPCs expose metrics; nothing in consensus consumes
  them.
- **No slashing.** Deterrence = the up-front acquisition cost (Sybil cost paid in
  advance) + a PoSe ban for missed block production. The ban is **not a certain
  financial loss and not confiscation**: it removes the identity from the active set,
  so its only cost is the **possible loss of future service/fee opportunities —
  revenues that are themselves unproven**. A bug in slashing logic can destroy honest
  operators' funds; the risk is not worth it.

The consensus stays simple and hard to game. Competition, reputation, and
business models evolve freely one layer up.

---

## 4. Applications choose their operators

The protocol only knows Settlement Operators. **Applications choose which ones
they want to use.** The protocol never references an application and never
favors an operator.

Every application defines its own settlement policy:

```
Application
    │
    ▼
Settlement policy
    ├── AUTO            (any live operator)
    ├── Recommended     (the app's default, user can override)
    ├── Pinned          (the app's own operator, with user consent)
    └── User choice     (bring your own)
```

Examples of policies the public metrics make possible:

- A wallet that only routes through operators with > 99.95 % uptime, > 3 years
  of age, and a clean incident history.
- A DEX that runs a request-for-quote across five providers and settles through
  whichever bids best — the user never knows which one won.
- A bank that operates its own Settlement Operators, exactly as it runs its own
  servers today.
- A small app that pins its creator's operator, because that is the simplest
  thing that works.

This is the Internet playbook: the network publishes routes and packets and
never says Cloudflare is better than Akamai — the market builds that layer.

**What selection is, and is not.** Choosing or pinning an Operator, a CP or an LP
establishes a **service relationship, a route or an endpoint** for that application and
its users. It does **not** create a private committee, and it does **not** change the
global consensus/finality set: every node still validates every block and finality is
still voted by the whole eligible operator set, whatever any single application selected.
Application-layer selection and consensus-layer membership are separate things.

---

## 5. Consensus and commercial roles

Vocabulary matters, so BATHRON separates three responsibilities. A single company
may hold one, two, or all three — they are roles, not necessarily distinct entities:

- **Settlement Operator** — the M0-collateralised *consensus* identity: registers
  masternodes, produces blocks, votes finality, accumulates the public track
  record. This document.
- **Clearing Provider (CP)** — a *service* role: giving the client a quote,
  orchestrating execution and timeout paths, and offering an SLA.
- **Liquidity Provider (LP)** — a *capital* role: holding inventory and quoting
  a specific pair. A CP may run its own LP or aggregate several LPs.

Two facts to keep straight:

- CP/LP metrics (execution history, capacity, price, latency) are **application-layer
  facts, measured and weighed by whoever consumes the service — not consensus**.
  **[fact]**
- **The protocol does not yet bind a consensus operator identity to the CP/LP entity
  that sells a service on top of it.** A provider need not control consensus, and an
  operator is not automatically a provider. Linking the two is today an off-chain
  signed attestation (`verifymessage`), not a chain guarantee. **[fact]**

That missing binding is not an oversight — it is the **institutional hypothesis
BATHRON exists to test** **[hypothesis]**: that identifiable, M0-collateralised operators
who also run the client-facing service will behave well enough, often enough, for a
market to form around their public track records. The protocol deliberately does not
assume the answer; see [SECURITY-MODEL.md](SECURITY-MODEL.md) §7.

Why builders may choose to run operators anyway: an application brings **flow**, and flow
may generate fees and service revenue for whatever operator settles it — so the
application's creator has an incentive to run one, the same way serious exchanges run
their own Bitcoin nodes. No protocol subsidy is needed to make that rational. Those
revenues are a **market hypothesis, not a guarantee**, and whether it happens at scale is
part of the same open question.

---

## 6. A note on naming

Internally, the code and RPC surface keep their lineage names: `masternode`,
`protx_*`, `listmnstats`, `mnsync`. Renaming working consensus code buys
nothing and risks regressions.

Publicly, BATHRON does not speak of "masternodes": the term drags a decade of
proof-of-stake/inflation-reward associations that simply do not describe this
network. The public vocabulary is **Settlement Operator** — an identity
collateralised with M0, a public history you accumulate, and a business you may build.

*The protocol stays neutral. The market does the rest.*
