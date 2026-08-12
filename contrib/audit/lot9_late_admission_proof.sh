#!/usr/bin/env bash
# =============================================================================
# LOT 9 — LATE ADMISSION on the AGED, RENEWED chain (reconciliation follow-up)
# =============================================================================
#
# M4-BIS measured ordinary admission at h=89 on a young chain. This proves the
# SAME ordinary path — collateral, own keys, no allowlist — still works after
# 10 000+ blocks, seven expiries and five renewals: a fresh operator registers
# on the phase-4bis chain (h≈10266), enters the schedule at its epoch snapshot,
# gets a FULL lease (registrationHeight + 10080), and the finality population
# grows without a hiccup in lag.
#
# Uses the phase4bis datadirs AS THEY ARE (post-renewal). Restarts the fleet
# with the laboratory clock, registers op9 from n1's wallet, advances across
# two epoch boundaries, and measures.
set -uo pipefail

BIN="${BIN:?set BIN to the candidate bathrond}"
CLI_BIN="${CLI_BIN:-$(dirname "$BIN")/bathron-cli}"
LAB="${LAB:-/home/ubuntu/lot9-lab7bis/phase4bis}"
NODES=8
HORIZON=10080
EPOCH_LEN=60

die() { echo "FAIL: $*" >&2; exit 1; }
cli() { local i="$1"; shift; "$CLI_BIN" -datadir="$LAB/n$i" -regtest "$@"; }

echo "=== 0. restart the renewed fleet with its clock ==="
for i in $(seq 1 $NODES); do
    [ -f "$LAB/n$i/PID" ] && kill "$(cat "$LAB/n$i/PID")" 2>/dev/null
done
sleep 3
# The chain lived under mocktime; resume safely AHEAD of the tip time (a clock
# ahead of the tip is fine — a tip "from the future" is not).
BASE=$(python3 -c "import json; print(json.load(open('/home/ubuntu/lot9-lab7bis/SNAPSHOT-h10200-pristine/phase4.state.json'))['clock'])")
CLOCK=$(( BASE + 8000 ))
for i in $(seq 1 $NODES); do
    rm -f "$LAB/n$i/regtest/.lock"
    nohup "$BIN" -datadir="$LAB/n$i" -regtest -mocktime="$CLOCK" -printtoconsole=1 >> "$LAB/n$i/node.log" 2>&1 &
    echo $! > "$LAB/n$i/PID"
done
for i in $(seq 1 $NODES); do
    ok=0
    for _ in $(seq 1 120); do cli "$i" getblockcount >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
    [ "$ok" = 1 ] || { tail -5 "$LAB/n$i/node.log"; die "node $i: RPC timeout"; }
done
for i in $(seq 1 $NODES); do
    for j in $(seq 1 $NODES); do
        [ "$i" = "$j" ] && continue
        cli "$i" addnode "127.0.0.1:$(cat "$LAB/n$j/P2PPORT")" add >/dev/null 2>&1 || true
    done
done
sleep 4
H0=$(cli 1 getblockcount); echo "fleet up at h=$H0"

advance_to() {   # mine (via mocktime) until n1 reaches $1
    local target="$1" prev h stall=0
    while :; do
        h=$(cli 1 getblockcount); [ "$h" -ge "$target" ] && break
        prev=$h
        TIP_T=$(cli 1 getblock "$(cli 1 getbestblockhash)" | python3 -c "import json,sys; print(json.load(sys.stdin)['time'])")
        [ "$CLOCK" -lt $(( TIP_T + 65 )) ] && CLOCK=$(( TIP_T + 65 ))
        for k in $(seq 1 24); do
            for i in $(seq 1 $NODES); do cli "$i" setmocktime "$CLOCK" >/dev/null 2>&1; done
            for _ in $(seq 1 20); do
                h=$(cli 1 getblockcount); [ "$h" -gt "$prev" ] && break 2
                sleep 0.05
            done
            CLOCK=$(( CLOCK + 30 ))
        done
        [ "$h" -gt "$prev" ] || { stall=$((stall+1)); [ "$stall" -ge 6 ] && die "production stalled at $h"; }
    done
}

echo "=== 1. baseline: renewed population, finality alive ==="
FIN0=$(cli 1 getfinalitystatus)
echo "$FIN0" | grep -E 'finality_lag|operators' | head -2

echo "=== 2. ordinary registration of a FRESH operator (op9) ==="
OPADDR=$(cli 1 getnewaddress "late-op"); OPWIF=$(cli 1 dumpprivkey "$OPADDR")
OPPUB=$(cli 1 validateaddress "$OPADDR" | python3 -c "import json,sys; print(json.load(sys.stdin)['pubkey'])")
VRFPUB=$(cli 1 getvrfpubkey "$OPWIF" | tr -d '" \n')
OWNER=$(cli 1 getnewaddress); VOTING=$(cli 1 getnewaddress)
PAYOUT=$(cli 1 getnewaddress); COLL=$(cli 1 getnewaddress)
P1PORT=$(cat "$LAB/n1/P2PPORT")
PROTX=$(cli 1 protx_register_fund "$COLL" "127.0.0.1:$((P1PORT + 500))" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" 2>&1 | tr -d '"')
case "$PROTX" in [0-9a-f]*) : ;; *) die "protx_register_fund: $PROTX" ;; esac
advance_to $(( $(cli 1 getblockcount) + 2 ))
REG_H=$(cli 1 protx_list true false true | python3 -c "
import json,sys
for e in json.load(sys.stdin):
    if e.get('proTxHash') == '$PROTX':
        print(e['dmnstate']['registeredHeight']); break
else: sys.exit('op9 not found on chain')")
echo "op9=${PROTX:0:16}… registered at h=$REG_H"

echo "=== 3. the lease granted is FULL horizon from registration ==="
read -r EXPIRY SEQ <<< "$(cli 1 protx_list true false true | python3 -c "
import json,sys
for e in json.load(sys.stdin):
    if e.get('proTxHash') == '$PROTX':
        d = e['dmnstate']; print(d['leaseExpiryHeight'], d['leaseSequence']); break")"
[ "$EXPIRY" = "$(( REG_H + HORIZON ))" ] || die "op9 expiry $EXPIRY != registeredHeight + $HORIZON"
[ "$SEQ" = "0" ] || die "op9 initial sequence $SEQ != 0"
echo "lease: sequence 0, expiry $EXPIRY = $REG_H + $HORIZON"

echo "=== 4. cross two epoch boundaries; the population must GROW ==="
OPS_BEFORE=$(cli 1 getquorum "$(cli 1 getblockcount)" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_operators'])")
ANCHOR=41
H=$(cli 1 getblockcount)
B2=$(( ANCHOR + ( (H - ANCHOR) / EPOCH_LEN + 2 ) * EPOCH_LEN ))
advance_to $(( B2 + 2 ))
H2=$(cli 1 getblockcount)
OPS_AFTER=$(cli 1 getquorum "$H2" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_operators'])")
echo "operators: $OPS_BEFORE before -> $OPS_AFTER after boundary $B2 (h=$H2)"
# MEMBERSHIP, not head-count: on an aged chain other leases keep expiring while
# the newcomer enters (measured: op8's expiry offset op9's admission, 6 -> 6).
# The admission proof is that op9's operator key IS in the epoch set.
OP9PUB=$(cli 1 protx_list true false true | python3 -c "
import json,sys
for e in json.load(sys.stdin):
    if e.get('proTxHash') == '$PROTX':
        print(e['dmnstate']['operatorPubKey']); break")
cli 1 getquorum "$H2" | python3 -c "
import json,sys
q = json.load(sys.stdin)
ops = [o['operator'] for o in q.get('operators', [])]
sys.exit(0 if '$OP9PUB' in ops else 1)" \
    || die "op9 ($OP9PUB) is NOT in the epoch operator set after boundary $B2"
echo "op9 IS in the epoch operator set (membership proven; count may be offset by other expiries)"

echo "=== 5. finality still alive, one tip everywhere ==="
advance_to $(( H2 + 8 ))
sleep 2
LAG=$(cli 1 getfinalitystatus | python3 -c "import json,sys; print(json.load(sys.stdin)['finality_lag'])")
[ "$LAG" -le 1 ] || die "finality lag $LAG after the admission"
TIP=$(cli 1 getbestblockhash)
for i in $(seq 2 $NODES); do
    [ "$(cli "$i" getbestblockhash)" = "$TIP" ] || die "node $i is not on the common tip"
done
echo "finality_lag=$LAG, 8/8 nodes on tip ${TIP:0:16}…"

echo
echo "PASS — a fresh operator admitted the ORDINARY way on the aged, renewed"
echo "       chain: full lease from registration, enters at its epoch snapshot"
echo "       ($OPS_BEFORE -> $OPS_AFTER operators), finality stays at lag $LAG."
