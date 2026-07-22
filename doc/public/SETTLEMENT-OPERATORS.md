# Settlement Operators — the neutral operator network

> Public companion to [GENESIS.md](GENESIS.md) (consensus mechanics) and
> [WHY-BATHRON.md](WHY-BATHRON.md) (value proposition). This document defines
> what a Settlement Operator is, what the protocol publishes about them, what
> the protocol deliberately refuses to do, and how applications are expected
> to build on top.

---

## 1. One idea

**An irreversible BTC-origin cost registers an identity; it does not create a revenue stream.**

```
Burn BTC
  │
  ▼
Settlement Operator identity
  │
  ├── right to produce blocks (DMM) and vote finality (HU)
  ├── public, chain-anchored track record
  └── whatever services the operator decides to sell on top
```

A Settlement Operator is a consensus identity whose registration collateral is M0.
Every M0 unit can originate only from a verified BTC destruction, so the identity
has an up-front, externally verifiable acquisition cost. The destroyed BTC is not
held as backing or available for redemption.

There is no staking yield, no block reward, no inflation, no treasury. An
operator earns nothing from the protocol except recycled transaction fees when
it produces a block. If operating is worth doing, it is because of the
**services** an operator sells on top of its identity — not because the
protocol prints for it.

---

## 2. The protocol publishes facts — it never ranks

The protocol's job ends at publishing verifiable facts about each operator.
It never says "this operator is better." Applications decide what *better* means.

Facts the node already publishes today (public RPCs):

| Fact | Where |
|---|---|
| Operator identity (operator key, masternode proTxHash) | `listoperators`, `protx_list` |
| Age (registration height) | `protx_list` |
| Service endpoint | `listoperators` |
| Masternodes per operator | `listoperators` |
| Blocks produced, share vs expected share, deviation | `listoperators`, `listmnstats` |
| Liveness policing score (PoSe) | `protx_list` |
| Finality quorum parameters and health | `getfinalitystatus` |

Facts that need more work (roadmap, in the open-network hardening track):

- **Deterministic finality-participation proof** — the true "uptime" primitive.
  Today, who signed finality is gossip, not chain data; making it deterministic
  (e.g. the producer embeds the previous block's signature bitmap) is a known
  pre-open-network consensus item.
- **Cumulative service counters** (settled volume, HTLC counts, incident-free
  streak) — derivable from the chain by any indexer; no consensus change needed.

A reputation like this cannot be bought. It can only be **built**, block by
block, in public:

```
Operator ID        <identifier>
Registered         <height>
Origin cost        <verified amount>
Participation      <measured value>
Blocks produced    <measured count>
Application events <indexer-derived count>
Incidents          <third-party methodology>
```

---

## 3. What the protocol will NEVER do (neutrality guarantees)

These are design commitments, all true in the code today:

- **No block reward, no inflation, no treasury.** Coinbase = recycled fees,
  always (`block_reward = 0`).
- **No operator payments.** The Dash-style operator-reward mechanism was
  removed entirely; there is no protocol payment split of any kind.
- **No reputation-weighted consensus.** One operator = one vote, whatever its
  age, size, or track record. Finality threshold is `ceil(2/3 · min(E, N))`
  over unique operators.
- **No protocol ranking.** RPCs expose metrics; nothing in consensus consumes
  them.
- **No slashing.** Deterrence = the up-front BTC burn (Sybil cost paid in
  advance) + PoSe ban (loss of future fees). A bug in slashing logic can
  destroy honest operators' funds; the risk is not worth it.

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

---

## 5. Consensus and commercial roles

Vocabulary matters, so BATHRON separates three responsibilities:

- **Settlement Operator** — the M0-collateralised *consensus* identity: registers
  masternodes, produces blocks, votes finality, accumulates the public track
  record. This document.
- **Clearing Provider (CP)** — a *service* role: giving the client a quote,
  orchestrating execution and timeout paths, and offering an SLA.
- **Liquidity Provider (LP)** — a *capital* role: holding inventory and quoting
  a specific pair. A CP may run its own LP or aggregate several LPs.

The reputation card is anchored to the **operator identity**. CP/LP metrics
(execution history, capacity, price, latency) are application-layer facts,
measured and weighed by whoever consumes the service. A commercial provider
need not control consensus, and an operator is not automatically a provider.

Why builders end up running operators: an application brings **flow**, flow
brings fees and service revenue to whatever operator settles it — so the
application's creator naturally runs one, the same way serious exchanges run
their own Bitcoin nodes. No protocol subsidy is needed to make that rational.

---

## 6. A note on naming

Internally, the code and RPC surface keep their lineage names: `masternode`,
`protx_*`, `listmnstats`, `mnsync`. Renaming working consensus code buys
nothing and risks regressions.

Publicly, BATHRON does not speak of "masternodes": the term drags a decade of
proof-of-stake/inflation-reward associations that simply do not describe this
network. The public vocabulary is **Settlement Operator** — an identity you
burn for, a reputation you build, a business you run.

*The protocol stays neutral. The market does the rest.*
