#!/usr/bin/env bash
# =============================================================================
# lot6_mutation_check.sh — the DECLARED mutation that guards LOT 6 (AUD-012)
# =============================================================================
#
# WHY THIS EXISTS. LOT 6's central claim is that `ReAddBlockIndexCandidates()`
# is NECESSARY on InvalidateBlock's failure paths: without it, blocks peeled off
# the active chain by a partial rollback are valid, have data, and sort at or
# above the new tip, yet are absent from setBlockIndexCandidates — exactly what
# CheckBlockIndex's membership assert forbids.
#
# That claim is only worth the paper it is on if a regression deleting the
# helper turns something RED. An independent review measured that under the
# mutation the FULL 908-case binary fails 4 times, all inside one suite that is
# compiled ONLY with ./configure --enable-lab-finality-hook. No workflow passed
# that flag, so the entire proof was unenforced: delete the helper and every
# check in the project stays green. This script closes that.
#
# WHAT IT GUARANTEES, and the two directions matter equally:
#   * the mutation still APPLIES to today's source (anchor found, diff is
#     exactly the expected one-line removal) — otherwise the guard has silently
#     stopped guarding anything;
#   * the mutation is KILLED (the suite exits non-zero AND the expected
#     assertions are the ones that fail) — otherwise the helper is not proven.
# A mutant that no longer applies is treated as a FAILURE, not as a pass.
#
# ISOLATION. All work happens in a throwaway `git worktree` on real disk (NOT
# $TMPDIR — see WORKDIR below). The caller's tree is never edited, never rebuilt,
# never left dirty, so this is safe to run on the build VPS next to a live tree.
#
# Usage: contrib/audit/lot6_mutation_check.sh [--keep] [--only1|--only2]
#   --keep   leave the temp worktree in place for inspection (prints its path)
#   --only1  run only mutant #1 (helper removed)   — used by the CI job split
#   --only2  run only mutant #2 (narrow rescan)    — used by the CI job split
# Default (no --only*) runs BOTH mutants, as before.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KEEP=0
RUN1=1
RUN2=1
for arg in "$@"; do
  case "$arg" in
    --keep)  KEEP=1 ;;
    --only1) RUN2=0 ;;
    --only2) RUN1=0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done
if [ "$RUN1" = 0 ] && [ "$RUN2" = 0 ]; then
  echo "--only1 and --only2 are mutually exclusive"; exit 2
fi

# ccache: the mutant worktrees live at DIFFERENT absolute paths from the caller's
# tree, so without a common base dir every object is a cache MISS (measured 6.4%
# hit rate — the reason the single-job CI run overran its 90-minute budget).
# CCACHE_BASEDIR rewrites absolute paths below it into relative ones, making the
# caller's build, both mutant builds and any later run share one cache. Honour a
# caller-provided value (the CI workflow sets it to the runner's work dir).
export CCACHE_BASEDIR="${CCACHE_BASEDIR:-$(dirname "$REPO_ROOT")}"

FAIL=0
ok()  { echo "  PASS: $*"; }
ko()  { echo "  FAIL: $*"; FAIL=1; }
step(){ echo; echo "════ $* ════"; }

# The declared mutation: remove the failure-path call. Anchored on the two lines
# that follow it, so a rename or a move breaks the anchor loudly instead of
# silently mutating the wrong place.
TARGET_REL="src/validation.cpp"
ANCHOR_BEFORE='            ReAddBlockIndexCandidates();'
ANCHOR_AFTER='            if (IsLocalFinalityRefusal(state)) {'

# What mutant #1 must break. Both are asserted: a non-zero RC alone could come from
# an unrelated failure or a build error.
EXPECT_SUITE="consensus_lot6_r6_rescan"
EXPECT_MARKER="is not a candidate"

# MUTANT #2 — the NARROW RESCAN. The helper re-admits every valid block that no longer
# sorts below the tip; the tempting (and wrong) reading is "only the blocks strictly
# between the new tip and the original tip". Those are exactly the blocks in
# vToMarkChild, so narrowing the failure-path call to that vector is a faithful
# encoding of the mistaken invariant. It must be killed by the LATERAL suite — an
# independent review pointed out that this kill lived only in a handoff document and
# was enforced nowhere, which is the same defect this whole script exists to remove.
ANCHOR2_BEFORE='            ReAddBlockIndexCandidates();'
ANCHOR2_AFTER='            if (IsLocalFinalityRefusal(state)) {'
MUT2_REPLACEMENT='            for (CBlockIndex* w : vToMarkChild) setBlockIndexCandidates.insert(w);   // MUTANT: narrow rescan'
EXPECT_SUITE2="consensus_lot6_lateral"
EXPECT_MARKER2="is INSUFFICIENT"

# WORKDIR: deliberately NOT $TMPDIR. On the build VPS /tmp is a 5.8 GiB tmpfs, and a
# full worktree build there fills it — which does not merely slow things down, it makes
# any CONCURRENT test run abort, because the test harness also creates its datadirs in
# /tmp. Measured while writing this: 850 of 911 cases aborted. Default to a sibling of
# the repo (real disk); override with LOT6_MUT_WORKDIR.
WORKDIR_BASE="${LOT6_MUT_WORKDIR:-$(dirname "$REPO_ROOT")}"
mkdir -p "$WORKDIR_BASE" 2>/dev/null || true
AVAIL_KB="$(df -Pk "$WORKDIR_BASE" | awk 'NR==2 {print $4}')"
if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -lt 4194304 ]; then
  echo "  FAIL: only $((AVAIL_KB/1024)) MiB free at $WORKDIR_BASE; a worktree build needs ~4 GiB."
  echo "        Set LOT6_MUT_WORKDIR to a filesystem with space."
  exit 1
fi
WORK="$(mktemp -d "$WORKDIR_BASE/lot6-mutation-XXXXXX")"
WT="$WORK/wt"
cleanup() {
  if [ "$KEEP" = 1 ]; then
    echo; echo "worktree kept at: $WT"
    return
  fi
  # Remove BOTH worktrees (LOW-5 from the final review: the trap used to forget
  # $WT2, leaving a stale .git/worktrees entry on an unexpected death).
  git -C "$REPO_ROOT" worktree remove --force "$WT" >/dev/null 2>&1 || true
  git -C "$REPO_ROOT" worktree remove --force "$WORK/wt2" >/dev/null 2>&1 || true
  git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"

if [ "$RUN1" = 1 ]; then

step "0. isolated worktree at the caller's exact HEAD"
if git -C "$REPO_ROOT" worktree add --detach "$WT" "$HEAD_SHA" >/dev/null 2>&1; then
  ok "worktree created at $HEAD_SHA (caller's tree untouched)"
else
  ko "could not create the isolated worktree"; exit 1
fi

step "1. the declared mutation still APPLIES to today's source"
python3 - "$WT/$TARGET_REL" "$ANCHOR_BEFORE" "$ANCHOR_AFTER" <<'PY'
import sys
path, before, after = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read()
needle = before + "\n" + after
n = src.count(needle)
if n != 1:
    sys.stderr.write("ANCHOR-COUNT %d (expected exactly 1)\n" % n)
    sys.exit(3)
open(path, "w").write(src.replace(needle, after, 1))
PY
rc=$?
if [ "$rc" = 3 ]; then
  ko "the mutation anchor is gone or ambiguous — the guard no longer guards anything"
  echo "     expected exactly one occurrence of:"
  echo "       $ANCHOR_BEFORE"
  echo "       $ANCHOR_AFTER"
  exit 1
elif [ "$rc" != 0 ]; then
  ko "mutation script error (rc=$rc)"; exit 1
fi

# Verify the diff is EXACTLY the expected one-line removal — never trust a
# textual substitution without reading back what it did.
DIFF_STAT="$(git -C "$WT" diff --numstat -- "$TARGET_REL")"
ADDED="$(echo "$DIFF_STAT"   | awk '{print $1}')"
REMOVED="$(echo "$DIFF_STAT" | awk '{print $2}')"
REMOVED_LINE="$(git -C "$WT" diff -U0 -- "$TARGET_REL" | grep '^-[^-]' | sed 's/^-//')"
if [ "$ADDED" = "0" ] && [ "$REMOVED" = "1" ] && [ "$REMOVED_LINE" = "$ANCHOR_BEFORE" ]; then
  ok "diff is exactly the declared one-line removal (+0 / -1)"
else
  ko "diff is NOT the declared mutation (+$ADDED / -$REMOVED)"
  git -C "$WT" diff -- "$TARGET_REL" | head -20
  exit 1
fi

step "2. build the mutant with the seam ON"
cd "$WT" || exit 1
{
  ./autogen.sh &&
  ./configure --without-gui --disable-bench --enable-tests --enable-lab-finality-hook \
      ${CC:+CC="$CC"} ${CXX:+CXX="$CXX"} &&
  make -j"$(nproc)" -C src test/test_bathron
} > "$WORK/build.log" 2>&1
if [ $? -ne 0 ]; then
  ko "the mutant did not build — cannot conclude anything about the helper"
  tail -25 "$WORK/build.log"
  exit 1
fi
ok "mutant built"

# The seam must actually be compiled in, or the proof suite would not exist and
# a green run would mean nothing.
if grep -q "^#define BATHRON_ENABLE_LAB_FINALITY_HOOK 1" src/config/bathron-config.h; then
  ok "seam compiled in (BATHRON_ENABLE_LAB_FINALITY_HOOK)"
else
  ko "the seam is NOT compiled — the proof suite does not exist in this binary"; exit 1
fi

step "3. the mutant must be KILLED"
set +e
./src/test/test_bathron --run_test="$EXPECT_SUITE" --report_level=detailed > "$WORK/mutant.log" 2>&1
MUT_RC=$?
set -e
echo "  mutant RC = $MUT_RC"
grep -E "assertions out of|test cases out of" "$WORK/mutant.log" | sed 's/^/     /'

if [ "$MUT_RC" -eq 0 ]; then
  ko "THE MUTANT SURVIVED: removing ReAddBlockIndexCandidates changes nothing that is tested"
  exit 1
fi
ok "mutant exits non-zero (RC=$MUT_RC)"

# RC != 0 is not enough on its own: it must fail for the RIGHT reason.
if grep -q "$EXPECT_MARKER" "$WORK/mutant.log"; then
  ok "failure is the expected one ('$EXPECT_MARKER')"
  grep "$EXPECT_MARKER" "$WORK/mutant.log" | head -4 | sed 's/^/     /'
else
  ko "the mutant failed, but NOT on the expected assertion — the guard is measuring something else"
  grep -E "error" "$WORK/mutant.log" | head -5 | sed 's/^/     /'
  exit 1
fi

fi # RUN1

if [ "$RUN2" = 1 ]; then

# ─────────────────────────────────────────────────────────────────────────────
# MUTANT #2 — narrow rescan, in a SECOND isolated worktree
# ─────────────────────────────────────────────────────────────────────────────
cd "$REPO_ROOT" || exit 1
WT2="$WORK/wt2"
step "4. MUTANT #2 — narrow rescan must still apply"
if ! git -C "$REPO_ROOT" worktree add --detach "$WT2" "$HEAD_SHA" >/dev/null 2>&1; then
  ko "could not create the second isolated worktree"; exit 1
fi
python3 - "$WT2/$TARGET_REL" "$ANCHOR2_BEFORE" "$ANCHOR2_AFTER" "$MUT2_REPLACEMENT" <<'PY2'
import sys
path, before, after, repl = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
src = open(path).read()
needle = before + "\n" + after
if src.count(needle) != 1:
    sys.stderr.write("ANCHOR2-COUNT %d (expected exactly 1)\n" % src.count(needle))
    sys.exit(3)
open(path, "w").write(src.replace(needle, repl + "\n" + after, 1))
PY2
rc2=$?
if [ "$rc2" != 0 ]; then
  ko "mutant #2 anchor is gone or ambiguous (rc=$rc2) — this guard stopped guarding"
  git -C "$REPO_ROOT" worktree remove --force "$WT2" >/dev/null 2>&1
  exit 1
fi
D2="$(git -C "$WT2" diff --numstat -- "$TARGET_REL")"
A2="$(echo "$D2" | awk '{print $1}')"; R2="$(echo "$D2" | awk '{print $2}')"
if [ "$A2" = "1" ] && [ "$R2" = "1" ]; then
  ok "mutant #2 diff is exactly the declared one-line swap (+1 / -1)"
else
  ko "mutant #2 diff is NOT the declared swap (+$A2 / -$R2)"
  git -C "$WT2" diff -- "$TARGET_REL" | head -20
  git -C "$REPO_ROOT" worktree remove --force "$WT2" >/dev/null 2>&1
  exit 1
fi

step "5. MUTANT #2 must be KILLED by the LATERAL suite"
cd "$WT2" || exit 1
{
  ./autogen.sh &&
  ./configure --without-gui --disable-bench --enable-tests --enable-lab-finality-hook \
      ${CC:+CC="$CC"} ${CXX:+CXX="$CXX"} &&
  make -j"$(nproc)" -C src test/test_bathron
} > "$WORK/build2.log" 2>&1
if [ $? -ne 0 ]; then
  ko "mutant #2 did not build"; tail -20 "$WORK/build2.log"
  cd "$REPO_ROOT"; git worktree remove --force "$WT2" >/dev/null 2>&1; exit 1
fi
set +e
./src/test/test_bathron --run_test="$EXPECT_SUITE2" --report_level=detailed > "$WORK/mutant2.log" 2>&1
MUT2_RC=$?
set -e
echo "  mutant #2 RC = $MUT2_RC"
if [ "$MUT2_RC" -eq 0 ]; then
  ko "MUTANT #2 SURVIVED: a rescan narrowed to the strictly-between blocks is not detected"
  cd "$REPO_ROOT"; git worktree remove --force "$WT2" >/dev/null 2>&1; exit 1
fi
if grep -q "$EXPECT_MARKER2" "$WORK/mutant2.log"; then
  ok "mutant #2 killed on the expected assertion ('$EXPECT_MARKER2')"
  grep "$EXPECT_MARKER2" "$WORK/mutant2.log" | head -2 | sed 's/^/     /'
else
  ko "mutant #2 failed, but NOT on the expected assertion"
  grep -E "error" "$WORK/mutant2.log" | head -4 | sed 's/^/     /'
  cd "$REPO_ROOT"; git worktree remove --force "$WT2" >/dev/null 2>&1; exit 1
fi
cd "$REPO_ROOT"; git worktree remove --force "$WT2" >/dev/null 2>&1

fi # RUN2

step "RESULT"
if [ "$FAIL" = 0 ]; then
  echo "  LOT 6 mutation guard: OK — every requested mutant was killed."
  [ "$RUN1" = 1 ] && echo "    #1 helper removed      -> killed by $EXPECT_SUITE"
  [ "$RUN2" = 1 ] && echo "    #2 rescan narrowed     -> killed by $EXPECT_SUITE2"
  exit 0
fi
echo "  LOT 6 mutation guard: FAILED"
exit 1
