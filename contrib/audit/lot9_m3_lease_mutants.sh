#!/usr/bin/env bash
# =============================================================================
# LOT 9 M3 — DECLARED MUTANTS of the lease rules, executed (never just claimed)
# =============================================================================
#
# The two mutants the M3 handoff declared, scripted so any future run can
# re-execute them instead of trusting a prose claim:
#
#   M2  renewal expiry becomes sequence * horizon   -> the e2e double-renewal
#       case must go RED (it exists precisely because M2 once SURVIVED a
#       single-renewal test: sequence 1 cannot distinguish the two formulas).
#   M4  the sequence rule is disabled               -> the e2e replay case must
#       go RED (a replayed renewal gets ADMITTED to the mempool).
#
# A mutant that SURVIVES is reported as a surviving mutant, never quietly
# dropped. The baseline is proven GREEN before and after.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$REPO"
SUITES="consensus_lot9_m3_lease,consensus_lot9_m3_lease_e2e"
DM="src/masternode/deterministicmns.cpp"
SV="src/masternode/specialtx_validation.cpp"
BACKUP=$(mktemp -d /home/ubuntu/lot9-lab7bis/lease-mutants.XXXXXX)
cp "$DM" "$BACKUP/deterministicmns.cpp"
cp "$SV" "$BACKUP/specialtx_validation.cpp"
restore() { cp "$BACKUP/deterministicmns.cpp" "$DM"; cp "$BACKUP/specialtx_validation.cpp" "$SV"; }
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

echo "=== baseline (must be GREEN) ==="
B=$(build_and_run); echo "  $B"
[ "$B" = "GREEN" ] || { echo "baseline is not green — refusing to mutate"; exit 1; }

FAILED=0

echo
echo "=== M2 — renewal expiry becomes sequence * horizon ==="
# The RENEWAL path only (the registration path at its own site is not the
# target); the two sites differ by dmnState vs newState.
grep -q 'newState->nLeaseExpiryHeight = nHeight + consensus.nOperatorLeaseBlocks;' "$DM" \
    || { echo "M2 anchor not found — the code moved, update this script"; exit 1; }
sed -i 's|newState->nLeaseExpiryHeight = nHeight + consensus.nOperatorLeaseBlocks;|newState->nLeaseExpiryHeight = nHeight + (int)newState->nLeaseSequence * consensus.nOperatorLeaseBlocks;  // MUTANT M2|' "$DM"
R=$(build_and_run); echo "  result: $R"
if [ "$R" != "RED" ]; then echo "  *** MUTANT M2 SURVIVED ***"; FAILED=1; fi
restore

echo
echo "=== M4 — the sequence rule is disabled ==="
grep -q 'if (pl.nLeaseSequence != mn->pdmnState->nLeaseSequence + 1) {' "$SV" \
    || { echo "M4 anchor not found — the code moved, update this script"; exit 1; }
sed -i 's|if (pl.nLeaseSequence != mn->pdmnState->nLeaseSequence + 1) {|if (false) {  // MUTANT M4|' "$SV"
R=$(build_and_run); echo "  result: $R"
if [ "$R" != "RED" ]; then echo "  *** MUTANT M4 SURVIVED ***"; FAILED=1; fi
restore

echo
echo "=== restoring and re-verifying the baseline ==="
B=$(build_and_run); echo "  $B"
[ "$B" = "GREEN" ] || { echo "baseline did not come back green"; exit 1; }

if [ "$FAILED" = "1" ]; then
    echo "VERDICT: at least one lease mutant SURVIVED"; exit 1
fi
echo "VERDICT: both declared lease mutants EXECUTED and KILLED, baseline green"
