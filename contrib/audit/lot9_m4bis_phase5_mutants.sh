#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4-BIS PHASE 5 — MUTANTS on the DETERMINISTIC scale harness
# =============================================================================
#
# The scale suite is a SIMULATION and is never presented otherwise: 361 operators
# and a 10 080-block horizon are out of reach of a local process laboratory, so
# the properties are pinned deterministically instead. An assertion that cannot
# distinguish the correct implementation from a wrong one proves nothing — the
# lesson M3 taught when a payload-chosen-expiry mutant SURVIVED because the test
# only ever exercised sequence 1. So each property here gets a mutant, and the
# mutant must turn the suite red.
#
#   M5a  reinstate the retired 360 clamp        -> recovery unreachable past 360
#   M5b  make leader selection O(rawSlot)       -> the O(1) timing bound breaks
#   M5c  shorten the shipped lease horizon      -> the constant assertion breaks
#   M5d  truncate the recovery permutation      -> a live signer becomes unreachable
#
# A mutant that SURVIVES is reported as a surviving mutant, never quietly dropped.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$REPO"
# Both the deterministic scale suite AND its e2e block-verdict twin: M5a once
# SURVIVED because the suite fed rawSlot literals to SelectScheduledLeader and
# never traversed GetRawProducerSlot (where the clamp lives). The time-path and
# block-verdict cases close that hole.
SUITE="consensus_lot9_m4_scale,consensus_lot9_m4_scale_e2e"
BP="src/masternode/blockproducer.cpp"
CP="src/chainparams.cpp"
BACKUP=$(mktemp -d /home/ubuntu/lot9-lab7bis/mutants.XXXXXX)
cp "$BP" "$BACKUP/blockproducer.cpp"
cp "$CP" "$BACKUP/chainparams.cpp"
restore() { cp "$BACKUP/blockproducer.cpp" "$BP"; cp "$BACKUP/chainparams.cpp" "$CP"; }
trap restore EXIT

build_and_run() {
    if ! nice -n 10 make -j2 -C src test/test_bathron >/dev/null 2>&1; then
        echo "BUILD FAILED"; return 2
    fi
    if src/test/test_bathron --run_test="$SUITE" >/dev/null 2>&1; then
        echo "GREEN"; return 0
    fi
    echo "RED"; return 1
}

echo "=== baseline (must be GREEN) ==="
echo "  $(build_and_run)"

run_mutant() {
    local name="$1" desc="$2"
    echo
    echo "=== $name — $desc ==="
    local r; r=$(build_and_run)
    echo "  result: $r"
    if [ "$r" != "RED" ]; then
        echo "  *** MUTANT SURVIVED — the property is NOT actually pinned ***"
    fi
    restore
}

# ── M5a — put the 360 clamp back. With P = 361 the recovery mode becomes
# unreachable: a stalled chain could never recover. This is the exact defect the
# clamp removal fixed, so the suite must catch its return.
python3 - <<'EOF'
p='src/masternode/blockproducer.cpp'; s=open(p).read()
old = "    return 1 + (extra / window);   // O(1): no loop, no allocation, no clamp"
assert old in s, "M5a anchor not found"
s = s.replace(old, "    { const int64_t _s = 1 + (extra / window); return _s > 360 ? 360 : _s; }  // MUTANT M5a")
open(p,'w').write(s)
EOF
run_mutant "M5a" "the retired 360 clamp is back"

# ── M5b — make selection proportional to rawSlot. Correct results, catastrophic
# cost: a peer that timestamps a block far in the future would hang every
# validator. The suite asserts elapsed time precisely so this cannot pass.
python3 - <<'EOF'
p='src/masternode/blockproducer.cpp'; s=open(p).read()
old = "    out.nRawSlot = nRawSlot;\n    if (nRawSlot < 0) return false;"
assert old in s, "M5b anchor not found"
s = s.replace(old, old + "\n    // MUTANT M5b: cost proportional to rawSlot instead of O(1).\n"
                        "    { volatile int64_t _spin = 0; for (int64_t _k = 0; _k < nRawSlot; ++_k) _spin += _k; }")
open(p,'w').write(s)
EOF
run_mutant "M5b" "leader selection made O(rawSlot)"

# ── M5c — silently shorten the shipped horizon. The whole point of PHASE 4 is
# that the consensus parameter is NOT shortened; the constant must be pinned.
sed -i 's/nOperatorLeaseBlocks = 10080/nOperatorLeaseBlocks = 1008/g' "$CP"
run_mutant "M5c" "lease horizon shortened 10080 -> 1008"

# ── M5d — truncate the recovery permutation so it no longer covers every
# identity. A live signer could then be structurally unreachable and the chain
# would never recover even with an honest operator online.
python3 - <<'EOF'
p='src/masternode/blockproducer.cpp'; s=open(p).read()
old = "    out.nIndex = (size_t)((turn + recoverySlot) % R);"
assert old in s, "M5d anchor not found"
s = s.replace(old, "    out.nIndex = (size_t)((turn + recoverySlot) % (R > 8 ? 8 : R));  // MUTANT M5d")
open(p,'w').write(s)
EOF
run_mutant "M5d" "recovery permutation truncated to the first 8 identities"

echo
echo "=== restoring and re-verifying the baseline ==="
restore
echo "  $(build_and_run)"
