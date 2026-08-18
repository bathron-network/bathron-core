# Contributing to BATHRON

BATHRON is an open settlement protocol for Bitcoin, currently on a public
testnet (see <https://bathron.org/docs/consensus/status-and-claims.html>).
This public repository is the reference implementation, populated by a
controlled export (each publication is a flat commit with a `.PROVENANCE.txt`
carrying the source commit id and tree hash). **Pull requests against it cannot
be merged directly** — the next export would overwrite them — but they are
read, and accepted changes are applied upstream and credited.

## How to contribute today

- **Issues** are the best channel: bug reports, consensus questions, security
  concerns. Include your `bathrond --version`, the network (testnet), and
  steps to reproduce.
- **Security-sensitive findings**: please do NOT open a public issue first —
  use the contact in the README and allow time for a fix to ship.
- **Patches**: open an issue describing the change and attach a patch or a
  branch link. Consensus-critical code (`src/state/`, `src/masternode/`,
  `src/btcspv/`, `src/burnclaim/`, `src/htlc/`, `src/consensus/`) is held to
  the strictest bar: deterministic, no floating point for money, invariants
  A5/A6/A7 preserved, unit tests included.

## Code conventions

- C++17, Bitcoin-Core-derived style; match the surrounding code.
- Build: `./autogen.sh && ./configure --without-gui && make`.
- Tests: configure with `--enable-tests`, then run
  `src/test/test_bathron`. Note that the money-critical suites (settlement,
  A6, burn-claim, btcheaders-reorg, ...) are disabled-by-default and only run
  when named explicitly via `--run_test=<suite,...>`.

## License

By contributing, you agree that your contributions are licensed under the MIT
license (see [COPYING](COPYING)).
