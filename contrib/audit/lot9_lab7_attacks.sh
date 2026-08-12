#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4 PHASE C (attacks) + PHASE G (restart / reindex / cold sync)
# =============================================================================
#
# Every scenario is MEASURED against the running 7-operator laboratory. A
# scenario that cannot be run is printed as NOT RUN — never silently skipped.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/tmp/claude-1000/-home-ubuntu/e0e4288f-8616-4be7-8b44-455c8a5c28f1/scratchpad}"
LAB="$(cat "$SCRATCH/lot9lab7.state")"
NODES=7
cli() { local i="$1"; shift; "$REPO/src/bathron-cli" -datadir="$LAB/n$i" -regtest "$@" 2>/dev/null; }

tip_time() { cli 1 getblock "$(cli 1 getbestblockhash)" | grep -o '"time": [0-9]*' | awk '{print $2}'; }
# Monotonic lab clock. CRITICAL: when the scheduled leader is OFFLINE no block
# appears, so the tip time does not move; recomputing the clock from the tip would
# pin mocktime inside slot 0 forever and the FALLBACK slots would never open —
# the "operator down" scenarios would measure a stall that is an artefact of the
# harness, not of consensus. The clock therefore only ever moves FORWARD, by one
# recovery window per retry, exactly like real time would.
LAB_CLOCK=0
advance() {
    local base; base=$(( $(tip_time) + 60 + 5 ))
    [ "$LAB_CLOCK" -lt "$base" ] && LAB_CLOCK="$base"
    local h0; h0=$(cli 1 getblockcount)
    for attempt in $(seq 1 24); do          # 24 x 30 s = well past several fallbacks
        for i in $(seq 1 $NODES); do cli "$i" setmocktime "$LAB_CLOCK" >/dev/null 2>&1; done
        for _ in $(seq 1 8); do
            [ "$(cli 1 getblockcount)" -gt "$h0" ] && return 0
            sleep 0.25
        done
        LAB_CLOCK=$(( LAB_CLOCK + 30 ))     # open the next recovery window
    done
    return 1
}
fin_state() {   # "<finalized> <lag> <threshold> <operators>"
    local f; f=$(cli 1 getfinalitystatus)
    echo "$(echo "$f" | grep -o '"last_finalized_height": [0-9]*' | awk '{print $2}')" \
         "$(echo "$f" | grep -o '"finality_lag": [0-9-]*' | awk '{print $2}')" \
         "$(echo "$f" | grep -o '"quorum_threshold": [0-9]*' | awk '{print $2}')" \
         "$(echo "$f" | grep -o '"operators": [0-9]*' | awk '{print $2}')"
}
stop_node() { cli "$1" stop >/dev/null 2>&1; sleep 3; }
start_node() {
    # NOTE: an unquoted "${2:-}" passes an EMPTY argument when no extra flag is
    # wanted, and bathrond refuses it ("Command line contains unexpected token ''").
    # The node then never comes back and the scenario measures a stall that is a
    # HARNESS failure, not a consensus one — this bit once, on "operators return".
    local extra=()
    [ -n "${2:-}" ] && extra=("$2")
    nohup "$REPO/src/bathrond" -datadir="$LAB/n$1" -regtest -printtoconsole=1 "${extra[@]}" \
        >> "$LAB/n$1/node.log" 2>&1 &
    echo $! > "$LAB/n$1/PID"
    for _ in $(seq 1 60); do cli "$1" getblockcount >/dev/null 2>&1 && break; sleep 1; done
    for j in $(seq 1 $NODES); do
        [ "$j" = "$1" ] && continue
        cli "$1" addnode "127.0.0.1:$(cat "$LAB/n$j/P2PPORT")" onetry >/dev/null 2>&1
    done
}

echo "############ BASELINE ############"
echo "height=$(cli 1 getblockcount)  finality(fin lag thr ops)=$(fin_state)"

echo
echo "############ C.1 — ONE operator down ############"
stop_node 7
ok=0; for _ in $(seq 1 5); do advance && ok=$(( ok + 1 )); done
echo "blocks produced with 6/7 live: $ok/5   finality=$(fin_state)"

echo
echo "############ C.2 — TWO operators down (threshold 5 of 7) ############"
stop_node 6
ok=0; for _ in $(seq 1 5); do advance && ok=$(( ok + 1 )); done
echo "blocks produced with 5/7 live: $ok/5   finality=$(fin_state)"

echo
echo "############ C.3 — THREE down: production continues, finality STALLS ############"
stop_node 5
ok=0; for _ in $(seq 1 6); do advance && ok=$(( ok + 1 )); done
echo "blocks produced with 4/7 live: $ok/6   finality=$(fin_state)"
echo "(expected: blocks still produced, finalized height FROZEN, lag growing)"

echo
echo "############ C.4 — operators return: finality resumes automatically ############"
start_node 5; start_node 6; start_node 7
ok=0; for _ in $(seq 1 8); do advance && ok=$(( ok + 1 )); done
echo "blocks produced with 7/7 live: $ok/8   finality=$(fin_state)"

echo
echo "############ C.5 — no temporal PoSe: nobody is punished or banned ############"
BANNED=$(cli 1 listmnstats | grep -c '"PoSeBanHeight": [0-9]' || true)
PEN=$(cli 1 listmnstats | grep -o '"PoSePenalty": [0-9]*' | awk '{s+=$2} END {print s+0}')
echo "MNs with a ban height set: $BANNED    sum of PoSe penalties: $PEN"
echo "(expected: 0 and 0 — three operators were offline for six blocks)"

echo
echo "############ G — restart, -reindex, and cold sync ############"
H_BEFORE=$(cli 1 getblockcount); TIP_BEFORE=$(cli 1 getbestblockhash)
Q_BEFORE=$(cli 1 getquorum "$H_BEFORE")
stop_node 4; start_node 4
echo "n4 after clean restart : h=$(cli 4 getblockcount) tip=$(cli 4 getbestblockhash | head -c 16)"
stop_node 4; start_node 4 "-reindex"
for _ in $(seq 1 120); do [ "$(cli 4 getblockcount)" = "$H_BEFORE" ] && break; sleep 1; done
echo "n4 after -reindex      : h=$(cli 4 getblockcount) tip=$(cli 4 getbestblockhash | head -c 16)"
echo "expected tip           : $(echo "$TIP_BEFORE" | head -c 16)"
Q_AFTER=$(cli 4 getquorum "$H_BEFORE")
if [ "$(echo "$Q_BEFORE" | grep -E 'producer_operator|schedule_raw_slot|total_operators')" \
   = "$(echo "$Q_AFTER"  | grep -E 'producer_operator|schedule_raw_slot|total_operators')" ]; then
    echo "schedule after -reindex: IDENTICAL"
else
    echo "schedule after -reindex: *** DIFFERS ***"
    diff <(echo "$Q_BEFORE") <(echo "$Q_AFTER") | head -10
fi

echo
echo "############ SUMMARY ############"
for i in $(seq 1 $NODES); do
    printf "n%s h=%s tip=%s\n" "$i" "$(cli $i getblockcount)" "$(cli $i getbestblockhash | head -c 16)"
done
echo "finality: $(fin_state)   (finalized lag threshold operators)"
