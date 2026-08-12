#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4-BIS PHASE 3 — REAL ADMISSION OF AN EIGHTH OPERATOR, AFTER LAUNCH
# =============================================================================
#
# No allowlist and no project switch: the eighth operator joins through the
# ORDINARY transaction path (its own collateral, its own keys) and consensus
# decides alone. Three things must be MEASURED, not asserted:
#
#   * the running epoch does NOT move — an admission cannot change the calendar
#     the network is currently executing;
#   * the newcomer enters at a DETERMINISTIC FUTURE snapshot, the same one on
#     every node;
#   * the finality threshold follows the population: ceil(2/3·7)=5 -> ceil(2/3·8)=6.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/home/ubuntu/lot9-lab7bis}"
LAB="$(cat "$SCRATCH/lot9lab7.state")"
NODES=7
c() { local i="$1"; shift; "$REPO/src/bathron-cli" -datadir="$LAB/n$i" -regtest "$@" 2>/dev/null; }

BOOT=$(grep -o 'labbootstrapheight=[0-9]*' "$LAB/n1/bathron.conf" | cut -d= -f2)
ACT=$(( BOOT + 1 ))
LEN=60
DEPTH=30
epoch_of()    { echo $(( ($1 - ACT) / LEN )); }
epoch_start() { echo $(( ACT + $1 * LEN )); }
snap_of()     { local es; es=$(epoch_start "$1"); local h=$(( es - DEPTH )); local a=$(( ACT - 1 ));
                [ "$h" -gt "$a" ] && echo "$h" || echo "$a"; }

tip_time() { c 1 getblock "$(c 1 getbestblockhash)" | grep -o '"time": [0-9]*' | awk '{print $2}'; }
CLOCK=0
advance() {
    local base; base=$(( $(tip_time) + 65 ))
    [ "$CLOCK" -lt "$base" ] && CLOCK="$base"
    local h0; h0=$(c 1 getblockcount)
    for _ in $(seq 1 24); do
        for i in $(seq 1 $NODES); do c "$i" setmocktime "$CLOCK" >/dev/null 2>&1; done
        for _ in $(seq 1 8); do [ "$(c 1 getblockcount)" -gt "$h0" ] && return 0; sleep 0.25; done
        CLOCK=$(( CLOCK + 30 ))
    done
    return 1
}
ops_at() { c 1 getquorum "$1" | grep -o '"total_operators": [0-9]*' | awk '{print $2}'; }
thr_at() { c 1 getquorum "$1" | grep -o '"finality_threshold": [0-9]*' | awk '{print $2}'; }

H0=$(c 1 getblockcount)
echo "############ 3.0 — before the admission ############"
echo "height=$H0  epoch=$(epoch_of "$H0")  activation=$ACT  epochLength=$LEN  snapshotDepth=$DEPTH"
echo "operators in the running schedule: $(ops_at "$H0")   finality threshold: $(thr_at "$H0")"

echo
echo "############ 3.1 — the eighth identity: fresh keys, zero privilege ############"
OPADDR=$(c 1 getnewaddress op8src); OPWIF=$(c 1 dumpprivkey "$OPADDR")
OPPUB=$(c 1 validateaddress "$OPADDR" | grep -o '"pubkey": "[0-9a-f]*"' | head -1 | cut -d'"' -f4)
VRFPUB=$(c 1 getvrfpubkey "$OPWIF" | tr -d '" \n')
OWNER=$(c 1 getnewaddress owner8); VOTING=$(c 1 getnewaddress voting8)
PAYOUT=$(c 1 getnewaddress payout8); COLL=$(c 1 getnewaddress coll8)
echo "op8 operator=${OPPUB:0:16}…  vrf=${VRFPUB:0:16}…"
echo "distinct from the seven: $( { for i in $(seq 1 7); do sed -n 2p "$LAB/op$i.id"; done; echo "$OPPUB"; } | sort -u | wc -l)/8 keys"

echo
echo "############ 3.2 — register through the ORDINARY path ############"
TXID=$(c 1 protx_register_fund "$COLL" "127.0.0.1:30008" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" | tr -d '"')
case "$TXID" in
    [0-9a-f]*) echo "ProRegTx accepted: ${TXID:0:16}…" ;;
    *) echo "ADMISSION REFUSED: $TXID"; exit 1 ;;
esac
advance >/dev/null || echo "WARN: no block confirmed the registration"
H1=$(c 1 getblockcount)
echo "confirmed at height $H1 (epoch $(epoch_of "$H1"))"
echo "registered identities now: $(c 1 protx_list | grep -c proTxHash)"

echo
echo "############ 3.3 — a duplicate identity must be REFUSED ############"
DUP=$(c 1 protx_register_fund "$COLL" "127.0.0.1:30008" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" 2>&1 | head -3 | tr '\n' ' ')
echo "second identical registration -> ${DUP:0:150}"

echo
echo "############ 3.4 — the RUNNING epoch must not move ############"
for _ in $(seq 1 3); do advance >/dev/null; done
H2=$(c 1 getblockcount)
echo "height=$H2 epoch=$(epoch_of "$H2")  operators in schedule=$(ops_at "$H2")  threshold=$(thr_at "$H2")"
echo "(expected: still 7 and 5 — the newcomer is confirmed but not yet in a snapshot)"

echo
echo "############ 3.5 — which snapshot will FIRST contain it, deterministically ############"
E_NOW=$(epoch_of "$H2")
TARGET_EPOCH=""
for e in $(seq "$E_NOW" $(( E_NOW + 4 ))); do
    S=$(snap_of "$e")
    if [ "$S" -ge "$H1" ]; then TARGET_EPOCH=$e; break; fi
done
TARGET_SNAP=$(snap_of "$TARGET_EPOCH")
TARGET_START=$(epoch_start "$TARGET_EPOCH")
echo "registration height $H1 -> first epoch whose snapshot is at or after it: epoch $TARGET_EPOCH"
echo "  its snapshot height = $TARGET_SNAP, its first block = $TARGET_START"

echo
echo "############ 3.6 — drive there and re-measure ############"
while [ "$(c 1 getblockcount)" -lt "$TARGET_START" ]; do
    advance >/dev/null || { echo "STALL at $(c 1 getblockcount)"; break; }
    H=$(c 1 getblockcount)
    case $H in *0|*5) printf "  … h=%s epoch=%s ops=%s\n" "$H" "$(epoch_of "$H")" "$(ops_at "$H")";; esac
done
H3=$(c 1 getblockcount)
echo "height=$H3 epoch=$(epoch_of "$H3")  operators=$(ops_at "$H3")  threshold=$(thr_at "$H3")"
echo "(expected: 8 operators, threshold 6 = ceil(2/3·8))"

echo
echo "############ 3.7 — identical on all seven nodes ############"
for i in $(seq 1 $NODES); do
    printf "n%s h=%-4s ops@%s=%-3s thr=%-3s tip=%s\n" "$i" "$(c $i getblockcount)" "$H3" \
      "$(c $i getquorum "$H3" | grep -o '"total_operators": [0-9]*' | awk '{print $2}')" \
      "$(c $i getquorum "$H3" | grep -o '"finality_threshold": [0-9]*' | awk '{print $2}')" \
      "$(c $i getbestblockhash | head -c 16)"
done
echo "finality: $(c 1 getfinalitystatus | grep -oE '"(last_finalized_height|finality_lag|quorum_threshold|operators)": [0-9-]*' | tr '\n' ' ')"
echo "PoSe bans: $(c 1 protx_list | grep -c '"PoSeBanHeight": [0-9]')   fatal latches n1: $(grep -c 'CONSENSUS DB FATAL' "$LAB/n1/node.log")"
echo "$TXID" > "$LAB/op8.protx"; printf '%s\n%s\n%s\n' "$OPWIF" "$OPPUB" "$VRFPUB" > "$LAB/op8.id"
