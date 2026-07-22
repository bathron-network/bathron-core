# Security Policy

> **Experimental testnet software.** BATHRON is an experimental settlement kernel running
> on a disposable public testnet. It carries **no mainnet**, no real value, and — as of this
> writing — **no external security audit** has been performed. Test funds only. Do not use it
> to hold or move value you cannot afford to lose entirely.

## Supported versions

Only the current testnet development line is supported. There is no long-term-support or
back-port policy during the experimental phase.

| Version | Supported |
|---|---|
| current testnet line (`v0.9.x-testnet`) | ✅ security reports accepted |
| anything older | ❌ upgrade first |

## Reporting a vulnerability

Report privately. **Do not open a public issue, PR, or social post for an exploitable
vulnerability**, and do not publish exploit code or details before coordinated disclosure.

- **Private vulnerability reports (canonical):** `security@bathron.org` — created, tested
  and actively monitored (confirmed by the project owner, 2026-07-22).
- General (non-security) enquiries: `contact@bathron.org`.

Please include, to the extent you can:

- affected component and version / commit SHA;
- a clear description of the issue and its impact;
- reproduction steps or a proof of concept (kept private);
- the network and configuration used (testnet parameters, node version);
- your assessment of severity and any suggested mitigation.

## Scope

In scope: **consensus** (block validation, finality, monetary invariants A5/A6/A7/A9), the
**SPV / Bitcoin-integration** path (headers, burn verification, reorg handling), **wallets**
and key handling, the **RPC** surface, the **Clearing Provider / Liquidity Provider** flows
and their SDK, and the **block explorer**.

Out of scope for now: denial-of-service that merely stalls the *experimental* testnet
(known and accepted — the network is resettable by genesis reset), third-party
infrastructure not operated by the project, and social-engineering of maintainers.

## What to expect (no invented timelines)

- **Acknowledgement:** the reporting inbox (`security@bathron.org`) is actively monitored; we
  aim to acknowledge a valid report and begin qualification promptly, though no fixed
  response-time SLA is promised during the experimental phase.
- **Qualification:** we assess reproducibility, scope and severity, and confirm or dispute
  the finding with evidence.
- **Coordinated disclosure:** we work with the reporter on a disclosure timeline; public
  details are released only after a fix or an explicit decision, with credit to the reporter
  if they wish.

## No bug-bounty program

There is **no monetary reward program** at this time. We will not promise a bounty that does
not exist. Recognition (credit in release notes / this file) is offered for valid,
responsibly-disclosed reports.

## Known limitations (stated up front)

- No external security audit has been completed. Internal adversarial audits exist but do not
  substitute for independent review.
- On the open testnet, low-cost Sybil identities can stall block finality (liveness only — the
  monetary invariants hold regardless; the network is resettable). This is a documented,
  accepted property of the experimental phase, not an accepted report target.
- The conditional-settlement guarantee ("settled per quote or refunded by timeout") is a
  design objective whose complete cross-chain safety model is **not yet formally specified or
  externally reviewed**.
