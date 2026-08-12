#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4 PHASE C — drive the 7-operator laboratory and MEASURE it
# =============================================================================
#
# Advances mocktime in lockstep across the seven nodes (never a sleep as a
# consensus gate) and, for every block, records what the SCHEDULE predicted and
# what was actually produced. Emits a CSV plus a summary.
#
#   ./lot9_lab7_run.sh <nblocks>
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/tmp/claude-1000/-home-ubuntu/e0e4288f-8616-4be7-8b44-455c8a5c28f1/scratchpad}"
LAB="$(cat "$SCRATCH/lot9lab7.state")"
NODES=7
N="${1:-500}"
CSV="$SCRATCH/lot9_lab7_blocks.csv"

cli() { local i="$1"; shift; "$REPO/src/bathron-cli" -datadir="$LAB/n$i" -regtest "$@" 2>/dev/null; }

echo "height,producer_operator,schedule_status,raw_slot,recovery,total_operators,threshold,finalized,lag" > "$CSV"

H=$(cli 1 getblockcount)
TIP_TIME=$(cli 1 getblock "$(cli 1 getbestblockhash)" | grep -o '"time": [0-9]*' | awk '{print $2}')
echo "start height=$H  tip time=$TIP_TIME  target=+$N blocks"

produced=0
stalls=0
for step in $(seq 1 $(( N * 3 )) ); do
    [ "$produced" -ge "$N" ] && break
    TIP_TIME=$(( TIP_TIME + 60 ))
    for i in $(seq 1 $NODES); do cli "$i" setmocktime $(( TIP_TIME + 5 )) >/dev/null; done

    # Wait for the scheduled producer to publish — bounded, and a timeout is a
    # MEASURED stall, never silently retried away.
    NEWH="$H"
    for _ in $(seq 1 40); do
        NEWH=$(cli 1 getblockcount)
        [ "$NEWH" -gt "$H" ] && break
        sleep 0.25
    done
    if [ "$NEWH" -le "$H" ]; then
        stalls=$(( stalls + 1 ))
        echo "STALL at height $H (mocktime $TIP_TIME)"
        continue
    fi

    H="$NEWH"
    produced=$(( produced + 1 ))
    Q=$(cli 1 getquorum "$H")
    PROD=$(echo "$Q" | grep -o '"producer_operator": "[0-9a-f]*"' | cut -d'"' -f4)
    ST=$(echo "$Q" | grep -o '"schedule_status": "[a-z_]*"' | cut -d'"' -f4)
    SLOT=$(echo "$Q" | grep -o '"schedule_raw_slot": [0-9-]*' | awk '{print $2}')
    REC=$(echo "$Q" | grep -o '"schedule_recovery_mode": [a-z]*' | awk '{print $2}')
    TOT=$(echo "$Q" | grep -o '"total_operators": [0-9]*' | awk '{print $2}')
    THR=$(echo "$Q" | grep -o '"finality_threshold": [0-9]*' | awk '{print $2}')
    F=$(cli 1 getfinalitystatus)
    FIN=$(echo "$F" | grep -o '"last_finalized_height": [0-9]*' | awk '{print $2}')
    LAG=$(echo "$F" | grep -o '"finality_lag": [0-9-]*' | awk '{print $2}')
    echo "$H,$PROD,$ST,$SLOT,$REC,$TOT,$THR,$FIN,$LAG" >> "$CSV"

    if [ $(( produced % 50 )) = 0 ]; then
        echo "  … $produced/$N  height=$H  finalized=$FIN  lag=$LAG"
    fi
done

echo
echo "=== SUMMARY ==="
echo "blocks produced : $produced"
echo "stalls observed : $stalls"
echo "--- producer distribution (operator pubkey -> blocks) ---"
tail -n +2 "$CSV" | cut -d, -f2 | sort | uniq -c | sort -rn
echo "--- schedule status histogram ---"
tail -n +2 "$CSV" | cut -d, -f3 | sort | uniq -c
echo "--- raw slot histogram (0 = primary) ---"
tail -n +2 "$CSV" | cut -d, -f4 | sort -n | uniq -c
echo "--- recovery-mode blocks ---"
tail -n +2 "$CSV" | cut -d, -f5 | sort | uniq -c
echo "--- finality lag: max / last ---"
tail -n +2 "$CSV" | cut -d, -f9 | sort -n | tail -1
tail -n 1 "$CSV" | cut -d, -f9
echo "--- tips across the seven nodes ---"
for i in $(seq 1 $NODES); do printf "n%s h=%s tip=%s\n" "$i" "$(cli $i getblockcount)" "$(cli $i getbestblockhash | head -c 16)"; done
echo "CSV: $CSV"
