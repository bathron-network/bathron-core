# Security Policy

This repository contains the **legacy DMM implementation**, not N. No public network runs today;
see [Network status](https://bathron.org/docs/status.html). No external security audit has been
performed. An external audit is a precondition before any public network carries value.

The current application draft defines M0 as the only settlement asset. SPs and LPs are roles
outside consensus and do not require a registered identity; producers are registered identities
selected to produce blocks. There is no native finality in N.

## Supported versions

Security reports concerning the published legacy DMM code are accepted. It is retained for
reference and is not a supported public network deployment. N has no public implementation yet.
There is no long-term-support or back-port policy during this experimental phase.

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

In scope: **legacy DMM consensus** (block validation, quorum certificates, supply invariants A5/A6/A7/A9), the
**SPV / Bitcoin-integration** path (headers, burn verification, reorg handling), **wallets**
and key handling, the **RPC** surface, the **Settlement Provider / Liquidity Provider** flows
and their SDK, and the **block explorer**.

Out of scope: third-party infrastructure not operated by the project and social-engineering
of maintainers. Reports about the published code should state the affected version and provide
reproduction evidence; the former DMM testnet is no longer running.

## What to expect (no invented timelines)

- **Acknowledgement:** the reporting inbox (`security@bathron.org`) is actively monitored; we
  aim to acknowledge a valid report and begin qualification promptly, though no fixed
  response-time SLA is promised during the experimental phase.
- **Qualification:** we assess reproducibility, scope and severity, and confirm or dispute
  the finding with evidence.
- **Coordinated disclosure:** we work with the reporter on a disclosure timeline; public
  details are released only after a fix, with credit to the reporter
  if they wish.

## No bug-bounty program

There is **no monetary reward program** at this time. We will not promise a bounty that does
not exist. Recognition (credit in release notes / this file) is offered for valid,
responsibly-disclosed reports.

## Known limitations

See [Known limitations](https://bathron.org/docs/limitations.html) for qualification still open,
initial project-managed producers, bootstrap trust and the absence of an external audit.
[Network status](https://bathron.org/docs/status.html) records network availability.
