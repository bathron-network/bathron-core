#!/usr/bin/env bash
# =============================================================================
# LOT 9 — MUTANT M5a, the last coverage hole (executed, not claimed)
# =============================================================================
#
# WHY THIS EXISTS. M5a reinstates the retired 360-slot clamp in
# GetRawProducerSlot. It SURVIVED the M4-BIS phase-5 run, and the reason is
# instructive: the scale suite fed rawSlot LITERALS to SelectScheduledLeader and
# never traversed GetRawProducerSlot at all, so the mutated function was simply
# not on the tested path. A suite that cannot tell the correct implementation
# from a wrong one proves nothing.
#
# The hole is closed by two cases that go through TIME:
#   consensus_lot9_m4_scale/the_time_path_elects_the_recovery_leader_past_the_clamp
#       P = 361, time -> rawSlot 361..364, asserts the resolved LEADER (not just
#       the slot number) against the literal-slot election on the same sets.
#   consensus_lot9_m4_scale_e2e/a_block_past_the_clamp_is_judged_by_the_unclamped_leader
#       a REAL block at an nTime mapping past the clamp: the unclamped leader's
#       block becomes the tip, the clamped leader's block does NOT and is marked
#       invalid. The VERDICT, not a number.
#
# The mutant must turn BOTH suites red. Restoration is verified by SHA256 — the
# file must come back byte-identical, not merely "close enough".
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$REPO"
SUITES="consensus_lot9_m4_scale,consensus_lot9_m4_scale_e2e"
BP="src/masternode/blockproducer.cpp"
BACKUP=$(mktemp -d /home/ubuntu/lot9-lab7bis/m5a.XXXXXX)
cp "$BP" "$BACKUP/blockproducer.cpp"
SHA_BEFORE=$(sha256sum "$BP" | cut -d' ' -f1)
restore() { cp "$BACKUP/blockproducer.cpp" "$BP"; }
trap restore EXIT

build_and_run() {
    if ! nice -n 10 make -j2 -C src test/test_bathron >/dev/null 2>&1; then
        echo "BUILD FAILED"; return 2
    fi
    if src/test/test_bathron --run_test="$SUITES" >/dev/null 2>&1; then
        echo "GREEN"; return 0
    fi
    echo "RED"; return 1
}

echo "=== baseline (must be GREEN) — $BP sha256=${SHA_BEFORE:0:16}… ==="
B=$(build_and_run); echo "  $B"
[ "$B" = "GREEN" ] || { echo "baseline is not green — refusing to mutate"; exit 1; }

echo
echo "=== M5a — the retired 360 clamp is back in GetRawProducerSlot ==="
python3 - <<'EOF'
p = 'src/masternode/blockproducer.cpp'
s = open(p).read()
old = "    return 1 + (extra / window);   // O(1): no loop, no allocation, no clamp"
assert old in s, "M5a anchor not found — the code moved, update this script"
s = s.replace(old, "    { const int64_t _s = 1 + (extra / window); return _s > 360 ? 360 : _s; }  // MUTANT M5a")
open(p, 'w').write(s)
EOF
grep -q 'MUTANT M5a' "$BP" || { echo "the mutation did not apply"; exit 1; }
R=$(build_and_run); echo "  result: $R"
SURVIVED=0
[ "$R" = "RED" ] || { echo "  *** MUTANT M5a SURVIVED — the property is NOT pinned ***"; SURVIVED=1; }

echo
echo "=== restore, byte-for-byte, and re-verify ==="
restore
SHA_AFTER=$(sha256sum "$BP" | cut -d' ' -f1)
[ "$SHA_AFTER" = "$SHA_BEFORE" ] || { echo "RESTORE MISMATCH: $SHA_AFTER != $SHA_BEFORE"; exit 1; }
grep -q 'MUTANT' "$BP" && { echo "a MUTANT marker survived the restore"; exit 1; }
echo "  sha256 restored identical (${SHA_AFTER:0:16}…)"
B=$(build_and_run); echo "  baseline: $B"
[ "$B" = "GREEN" ] || { echo "baseline did not come back green"; exit 1; }

[ "$SURVIVED" = "0" ] || { echo "VERDICT: M5a SURVIVED"; exit 1; }
echo "VERDICT: M5a EXECUTED and KILLED; source restored byte-for-byte"
