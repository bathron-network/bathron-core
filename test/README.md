# BATHRON test layers

The C++ unit/consensus suites live in [`src/test/`](../src/test/README.md)
(`test_bathron`, driven by `contrib/testnet/local_ci.sh` — a bare run skips the
disabled-by-default consensus suites; always use local_ci or explicit
`--run_test`).

This directory contains the remaining tool-level harnesses:

- `util/` — `bitcoin-util-test.py` exercises `bathron-tx` end to end
  (vectors in `util/data/`, driven by `make check`), plus `rpcauth-test.py`.
- `fuzz/` — libFuzzer targets and `fuzz/test_runner.py`
  (see `doc/fuzzing.md` if present, or contrib notes).
- `lint/` — shell/source linters.
- `config.ini.in` — build-time paths consumed by the harnesses above.

The Bitcoin-style python *functional* test framework (`test/functional/`,
`test_runner.py`) was removed with the legacy subsystems it exercised; live
end-to-end validation happens on the real fleet via `contrib/testnet/`
(deploy, genesis, redteam and soak scripts).
