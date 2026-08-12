#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4 PHASE D — OPEN ADMISSION of an eighth operator, after launch
# =============================================================================
#
# No allowlist, no project control: the eighth operator joins through the ORDINARY
# transaction path (collateral + signature), and consensus decides. The point to
# MEASURE is that it changes nothing in the current epoch and enters at a
# deterministic future snapshot, identically on every node.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/tmp/claude-1000/-home-ubuntu/e0e4288f-8616-4be7-8b44-455c8a5c28f1/scratchpad}"
LAB="$(cat "$SCRATCH/lot9lab7.state")"
NODES=7
cli() { local i="$1"; shift; "$REPO/src/bathron-cli" -datadir="$LAB/n$i" -regtest "$@" 2>/dev/null; }
tip_time() { cli 1 getblock "$(cli 1 getbestblockhash)" | grep -o '"time": [0-9]*' | awk '{print $2}'; }
advance() {
    local t; t=$(( $(tip_time) + 60 + 5 ))
    for i in $(seq 1 $NODES); do cli "$i" setmocktime "$t" >/dev/null 2>&1; done
    local h0; h0=$(cli 1 getblockcount)
    for _ in $(seq 1 40); do [ "$(cli 1 getblockcount)" -gt "$h0" ] && return 0; sleep 0.25; done
    return 1
}
epoch_of() {   # epoch index of a height, anchored (activation = bootstrap + 1)
    local h="$1" boot len act
    boot=$(grep -o 'labbootstrapheight=[0-9]*' "$LAB/n1/bathron.conf" | cut -d= -f2)
    act=$(( boot + 1 )); len=60
    echo $(( (h - act) / len ))
}

H0=$(cli 1 getblockcount)
echo "=== D.0 — state before admission ==="
echo "height=$H0  epoch=$(epoch_of "$H0")  operators=$(cli 1 getquorum "$H0" | grep -o '\"total_operators\": [0-9]*' | awk '{print $2}')"

echo
echo "=== D.1 — build the eighth identity (fresh keys, no privilege) ==="
OPADDR=$(cli 1 getnewaddress "op8src"); OPWIF=$(cli 1 dumpprivkey "$OPADDR")
OPPUB=$(cli 1 validateaddress "$OPADDR" | grep -o '"pubkey": "[0-9a-f]*"' | cut -d'"' -f4)
VRFPUB=$(cli 1 getvrfpubkey "$OPWIF" | tr -d '" \n')
OWNER=$(cli 1 getnewaddress "owner8"); VOTING=$(cli 1 getnewaddress "voting8")
PAYOUT=$(cli 1 getnewaddress "payout8"); COLL=$(cli 1 getnewaddress "coll8")
echo "op8 pub=${OPPUB:0:16}… vrf=${VRFPUB:0:16}…"

echo
echo "=== D.2 — register through the ORDINARY path ==="
TXID=$(cli 1 protx_register_fund "$COLL" "127.0.0.1:30008" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" | tr -d '"')
case "$TXID" in
    [0-9a-f]*) echo "ProRegTx accepted: ${TXID:0:16}…" ;;
    *) echo "ADMISSION REFUSED: $TXID"; exit 1 ;;
esac
advance || echo "WARN: no block produced to confirm the registration"
H1=$(cli 1 getblockcount)
echo "confirmed at height $H1 (epoch $(epoch_of "$H1"))"

echo
echo "=== D.3 — duplicate collateral / duplicate identity must be REFUSED ==="
DUP=$(cli 1 protx_register_fund "$COLL" "127.0.0.1:30008" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" 2>&1 | head -3 | tr '\n' ' ')
echo "second identical registration -> ${DUP:0:120}"

echo
echo "=== D.4 — NO effect on the current epoch ==="
for _ in $(seq 1 3); do advance >/dev/null; done
H2=$(cli 1 getblockcount)
OPS_NOW=$(cli 1 getquorum "$H2" | grep -o '"total_operators": [0-9]*' | awk '{print $2}')
echo "height=$H2 epoch=$(epoch_of "$H2") operators_in_schedule=$OPS_NOW"
echo "(expected: still 7 while the epoch of admission is not over)"

echo
echo "=== D.5 — drive to the next epoch boundary and re-measure ==="
BOOT=$(grep -o 'labbootstrapheight=[0-9]*' "$LAB/n1/bathron.conf" | cut -d= -f2)
ACT=$(( BOOT + 1 ))
CUR_EPOCH=$(epoch_of "$H2")
# the snapshot that will first contain the registration is epochStart-30 > H1
TARGET=$(( ACT + (CUR_EPOCH + 2) * 60 ))
echo "driving to height $TARGET (epoch $(( CUR_EPOCH + 2 ))) …"
while [ "$(cli 1 getblockcount)" -lt "$TARGET" ]; do
    advance || { echo "STALL while driving to the boundary at height $(cli 1 getblockcount)"; break; }
done
H3=$(cli 1 getblockcount)
OPS_AFTER=$(cli 1 getquorum "$H3" | grep -o '"total_operators": [0-9]*' | awk '{print $2}')
echo "height=$H3 epoch=$(epoch_of "$H3") operators_in_schedule=$OPS_AFTER"
echo "(expected: 8 — the admission took effect at a FUTURE snapshot, not the current one)"

echo
echo "=== D.6 — identical view on all seven nodes ==="
for i in $(seq 1 $NODES); do
    printf "n%s h=%s ops=%s tip=%s\n" "$i" "$(cli $i getblockcount)" \
        "$(cli $i getquorum "$H3" | grep -o '"total_operators": [0-9]*' | awk '{print $2}')" \
        "$(cli $i getbestblockhash | head -c 16)"
done
