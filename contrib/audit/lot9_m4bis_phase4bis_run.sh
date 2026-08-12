#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4-BIS PHASE 4-BIS — launcher for the renewal proof on the real chain
# =============================================================================
#
# Prepares a WORKING COPY of the h=10200 laboratory datadirs (the pristine
# snapshot is never touched), starts a MIXED fleet — n1..n5 on the candidate
# binary, n6..n8 on the EXACT binary that produced blocks 1..10200 — meshes it
# with PERSISTENT addnode (the `onetry` form silently gave up once and
# fabricated a partition; never again), funds n1, and hands over to
# lot9_m4bis_phase4bis_renewal_proof.py for the measurements.
#
# Env:
#   NEW_BIN   candidate bathrond           (required)
#   OLD_BIN   preserved phase-4 bathrond   (required — sha 72bf1dba…)
#   SNAPSHOT  pristine h=10200 datadirs    (default ~/lot9-lab7bis/SNAPSHOT-h10200-pristine)
#   LAB       working copy                 (default ~/lot9-lab7bis/phase4bis)
set -uo pipefail

NEW_BIN="${NEW_BIN:?set NEW_BIN to the candidate bathrond}"
OLD_BIN="${OLD_BIN:?set OLD_BIN to the preserved phase-4 bathrond}"
SNAPSHOT="${SNAPSHOT:-/home/ubuntu/lot9-lab7bis/SNAPSHOT-h10200-pristine}"
LAB="${LAB:-/home/ubuntu/lot9-lab7bis/phase4bis}"
NODES=8
PREMINE_WIF="cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_BIN="${CLI_BIN:-$(dirname "$NEW_BIN")/bathron-cli}"

die() { echo "FAIL: $*" >&2; exit 1; }
cli() { local i="$1"; shift; "$CLI_BIN" -datadir="$LAB/n$i" -regtest "$@"; }

[ -x "$NEW_BIN" ] || die "NEW_BIN not executable: $NEW_BIN"
[ -x "$OLD_BIN" ] || die "OLD_BIN not executable: $OLD_BIN"
[ -d "$SNAPSHOT/n1" ] || die "snapshot not found at $SNAPSHOT"

echo "=== 0. working copy (snapshot stays pristine) ==="
if [ -d "$LAB" ]; then
    for i in $(seq 1 $NODES); do
        [ -f "$LAB/n$i/PID" ] && kill "$(cat "$LAB/n$i/PID")" 2>/dev/null
    done
    sleep 3
    rm -rf "$LAB"
fi
mkdir -p "$LAB"
cp -a "$SNAPSHOT"/n[1-8] "$LAB/"
chmod -R u+w "$LAB"
for i in $(seq 1 $NODES); do rm -f "$LAB/n$i/regtest/.lock" "$LAB/n$i/PID"; done
echo "sha256(new)=$(sha256sum "$NEW_BIN" | cut -c1-16)…  sha256(old)=$(sha256sum "$OLD_BIN" | cut -c1-16)…"

echo "=== 1. mixed fleet: n1-n5 candidate, n6-n8 the phase-4 binary ==="
# The chain lived under an accelerated MOCK clock: the tip is dated days ahead
# of the wall clock, and a plain restart aborts on the "block from the future"
# startup check. Resume the laboratory's clock at startup with -mocktime; the
# proof driver keeps advancing it from there, never backwards.
MOCK=$(python3 -c "
import json,sys
try:
    print(json.load(open('$SNAPSHOT/phase4.state.json'))['clock'] + 70)
except Exception as e:
    sys.exit('cannot read the lab clock: %s' % e)")
[ -n "$MOCK" ] || die "no lab clock — refusing to start a fleet that would abort"
echo "resuming the laboratory clock at $MOCK"
for i in $(seq 1 $NODES); do
    BIN="$NEW_BIN"; [ "$i" -ge 6 ] && BIN="$OLD_BIN"
    nohup "$BIN" -datadir="$LAB/n$i" -regtest -mocktime="$MOCK" -printtoconsole=1 >> "$LAB/n$i/node.log" 2>&1 &
    echo "$!" > "$LAB/n$i/PID"
done
for i in $(seq 1 $NODES); do
    ok=0
    for _ in $(seq 1 120); do
        if cli "$i" getblockcount >/dev/null 2>&1; then ok=1; break; fi
        sleep 1
    done
    [ "$ok" = 1 ] || { tail -5 "$LAB/n$i/node.log"; die "node $i: RPC timeout"; }
done

echo "=== 2. PERSISTENT mesh + verification (no onetry, ever) ==="
for i in $(seq 1 $NODES); do
    for j in $(seq 1 $NODES); do
        [ "$i" = "$j" ] && continue
        pj="$(cat "$LAB/n$j/P2PPORT")"
        cli "$i" addnode "127.0.0.1:$pj" add >/dev/null 2>&1 || true
    done
done
sleep 5
for i in $(seq 1 $NODES); do
    c="$(cli "$i" getconnectioncount 2>/dev/null || echo 0)"
    [ "$c" -ge 2 ] || die "node $i has only $c peer(s) — refusing to measure on a partition"
done
echo "mesh verified: every node has >= 2 peers"

echo "=== 3. fee funds on n1 ==="
# getbalance returns an object; amounts are in sats.
bal_total() { cli 1 getbalance 2>/dev/null | python3 -c "
import json,sys
b = json.load(sys.stdin)
print(b['total'] if isinstance(b, dict) else b)" 2>/dev/null || echo 0; }
BAL="$(bal_total)"
if [ "${BAL%%.*}" -le 0 ] 2>/dev/null || [ -z "$BAL" ]; then
    cli 1 importprivkey "$PREMINE_WIF" "premine" false >/dev/null 2>&1
    cli 1 rescanblockchain 0 >/dev/null 2>&1 || die "premine rescan failed on n1"
    BAL="$(bal_total)"
fi
echo "n1 balance: $BAL sats"

echo "=== 4. measurements ==="
LAB="$LAB" NODES=$NODES python3 "$HERE/lot9_m4bis_phase4bis_renewal_proof.py"
