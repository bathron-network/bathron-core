#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4-BIS PHASE 2 — OPERATORS RETURN: finality_lag must come back to ZERO
# =============================================================================
#
# M4 measured the loss of finality (3 of 7 down, threshold 5) but never showed the
# RECOVERY as an explicit number: a harness bug (an empty argv element) had kept
# the nodes from restarting, and "finality does not resume" was read as a
# consensus defect when it was mine. So the mandated deliverable here is the one
# number that was missing: finality_lag returning to 0, printed at every step.
#
# Nothing is asserted from a sleep: mocktime drives the clock, and the lab clock
# is MONOTONIC — when the scheduled leader is offline no block appears and the tip
# time does not move, so a clock recomputed from the tip would freeze in slot 0
# and the fallback slots would never open.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/home/ubuntu/lot9-lab7bis}"
LAB="$(cat "$SCRATCH/lot9lab7.state")"
NODES=7
c() { local i="$1"; shift; "$REPO/src/bathron-cli" -datadir="$LAB/n$i" -regtest "$@" 2>/dev/null; }

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
lag()  { c 1 getfinalitystatus | grep -o '"finality_lag": [0-9-]*' | awk '{print $2}'; }
fin()  { c 1 getfinalitystatus | grep -o '"last_finalized_height": [0-9]*' | awk '{print $2}'; }
thr()  { c 1 getfinalitystatus | grep -o '"quorum_threshold": [0-9]*' | awk '{print $2}'; }
ops()  { c 1 getfinalitystatus | grep -o '"operators": [0-9]*' | awk '{print $2}'; }
alive(){ local n=0; for i in $(seq 1 $NODES); do c "$i" getblockcount >/dev/null 2>&1 && n=$((n+1)); done; echo $n; }
row()  { printf "  h=%-4s finalized=%-4s lag=%-4s threshold=%s/%s  alive=%s/%s\n" \
           "$(c 1 getblockcount)" "$(fin)" "$(lag)" "$(thr)" "$(ops)" "$(alive)" "$NODES"; }

stop_node() { c "$1" stop >/dev/null 2>&1; sleep 3; }
start_node() {
    # An unquoted "${2:-}" would pass an EMPTY argv element and bathrond refuses it
    # ("Command line contains unexpected token ''"). That is the exact harness bug
    # that made M4 misread a dead node as a dead consensus.
    local extra=(); [ -n "${2:-}" ] && extra=("$2")
    nohup "$REPO/src/bathrond" -datadir="$LAB/n$1" -regtest -printtoconsole=1 "${extra[@]}" \
        >> "$LAB/n$1/node.log" 2>&1 &
    echo $! > "$LAB/n$1/PID"
    for _ in $(seq 1 90); do c "$1" getblockcount >/dev/null 2>&1 && break; sleep 1; done
    c "$1" setmocktime "$CLOCK" >/dev/null 2>&1
    remesh
}

# `addnode … onetry` makes ONE attempt and gives up silently. A node that is still
# opening its ports when the call lands ends up with ZERO peers, keeps its own
# operator key, and happily produces blocks ALONE — a partition manufactured by the
# harness. Measured here on the first run of this phase: nodes 5/6/7 came back up,
# sat at 0 peers, mined their own forks, and "finality never recovers" looked like a
# consensus defect. Use the PERSISTENT form and do not proceed until the mesh is
# real; the reconnect itself is what must be verified, never assumed.
remesh() {
    for i in $(seq 1 $NODES); do
        for j in $(seq 1 $NODES); do
            [ "$i" = "$j" ] && continue
            c "$i" addnode "127.0.0.1:$(cat "$LAB/n$j/P2PPORT")" add >/dev/null 2>&1
        done
    done
    for _ in $(seq 1 30); do
        local min; min=$(for i in $(seq 1 $NODES); do c "$i" getconnectioncount; done | sort -n | head -1)
        [ "${min:-0}" -ge 4 ] 2>/dev/null && return 0
        sleep 2
    done
    echo "  WARNING: mesh incomplete (min peers $(for i in $(seq 1 $NODES); do c "$i" getconnectioncount; done | sort -n | head -1))"
}

echo "############ 2.0 — BASELINE, seven operators ############"
for _ in $(seq 1 3); do advance >/dev/null; done
row

echo
echo "############ 2.1 — THREE operators stopped: below the threshold ############"
stop_node 5; stop_node 6; stop_node 7
FROZEN_AT=$(fin)
for i in $(seq 1 6); do advance >/dev/null || echo "  (no block on attempt $i)"; row; done
echo "  finality frozen at $FROZEN_AT -> now $(fin)   (production must continue)"

echo
echo "############ 2.2 — THE OPERATORS RETURN ############"
start_node 5; start_node 6; start_node 7
echo "  restarted; alive=$(alive)/$NODES"
row

echo
echo "############ 2.3 — lag must come back to ZERO, printed every block ############"
ZERO_AT=""
for i in $(seq 1 12); do
    advance >/dev/null || echo "  (no block on attempt $i)"
    row
    L=$(lag)
    if [ "${L:-9}" = "0" ] && [ -z "$ZERO_AT" ]; then
        ZERO_AT=$(c 1 getblockcount)
        echo "  >>> finality_lag reached 0 at height $ZERO_AT"
    fi
done

echo
echo "############ 2.4 — VERDICT ############"
if [ -n "$ZERO_AT" ]; then
    echo "finality_lag RETURNED TO 0 at height $ZERO_AT, and the backlog from $FROZEN_AT was caught up."
else
    echo "finality_lag did NOT return to 0 — final lag=$(lag), finalized=$(fin), tip=$(c 1 getblockcount)"
fi
echo "PoSe bans across the outage: $(c 1 protx_list | grep -c '"PoSeBanHeight": [0-9]')"
echo "sum of PoSe penalties     : $(c 1 protx_list | grep -o '"PoSePenalty": [0-9]*' | awk '{s+=$2} END {print s+0}')"
echo "fatal latches on n1       : $(grep -c 'CONSENSUS DB FATAL' "$LAB/n1/node.log")"
for i in $(seq 1 $NODES); do
    printf "n%s h=%s tip=%s\n" "$i" "$(c $i getblockcount)" "$(c $i getbestblockhash | head -c 16)"
done
