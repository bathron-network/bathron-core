#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4-BIS PHASE 6 — COLD SYNC FROM AN EMPTY DATADIR
# =============================================================================
#
# A node that has never seen the chain must rebuild the SAME tip AND the SAME
# schedule from the network alone — no snapshot handed to it, no state copied.
# This is the property that decides whether a newcomer can join a running
# network, and it is the one an epoch-anchored schedule could silently break:
# the snapshot of every past epoch has to be re-derivable from blocks only.
#
# What is compared, at several heights and not just the tip:
#   * best block hash;
#   * schedule_status, producer_operator, schedule_raw_slot, total_operators;
#   * the finality view.
#
# A node joining a mocktime laboratory must be given the clock BEFORE it meshes:
# otherwise every peer looks hours away and the handshake is refused
# ("timeOffset too large"). That is a laboratory artefact, not a product fact —
# real networks run on real time — but it silently produces a zero-peer node
# that looks like a sync failure.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/home/ubuntu/lot9-lab7bis}"
LAB="$(cat "$SCRATCH/lot9lab7.state")"
NODES=${NODES:-8}
COLD=9
c() { local i="$1"; shift; "$REPO/src/bathron-cli" -datadir="$LAB/n$i" -regtest "$@" 2>/dev/null; }

TIP_H=$(c 1 getblockcount)
TIP_HASH=$(c 1 getbestblockhash)
echo "############ 6.0 — the chain the newcomer must rebuild ############"
echo "height=$TIP_H tip=$TIP_HASH"

echo
echo "############ 6.1 — a genuinely EMPTY datadir ############"
rm -rf "$LAB/n$COLD"
mkdir -p "$LAB/n$COLD"
P=$(( $(cat "$LAB/n1/P2PPORT") + 100 )); R=$(( P + 1 ))
echo "$P" > "$LAB/n$COLD/P2PPORT"; echo "$R" > "$LAB/n$COLD/RPCPORT"
PW=$(head -c 32 /dev/urandom | sha256sum | head -c 32)
sed -e "s/^rpcuser=.*/rpcuser=lab$COLD/" -e "s/^rpcpassword=.*/rpcpassword=$PW/" \
    -e "s/^port=.*/port=$P/" -e "s/^rpcport=.*/rpcport=$R/" \
    "$LAB/n1/bathron.conf" | grep -v '^mnoperatorprivatekey\|^masternode=' > "$LAB/n$COLD/bathron.conf"
echo "no operator key, no wallet, no copied state — only the P2P network"
ls -A "$LAB/n$COLD" | tr '\n' ' '; echo

echo
echo "############ 6.2 — start it and give it the laboratory clock ############"
nohup "$REPO/src/bathrond" -datadir="$LAB/n$COLD" -regtest -printtoconsole=1 \
    > "$LAB/n$COLD/node.log" 2>&1 &
echo $! > "$LAB/n$COLD/PID"
for _ in $(seq 1 120); do c "$COLD" getblockcount >/dev/null 2>&1 && break; sleep 1; done
CLOCK=$(c 1 getblock "$(c 1 getbestblockhash)" | grep -o '"time": [0-9]*' | awk '{print $2}')
CLOCK=$(( CLOCK + 65 ))
for i in $(seq 1 $NODES) $COLD; do c "$i" setmocktime "$CLOCK" >/dev/null 2>&1; done
for j in $(seq 1 $NODES); do c "$COLD" addnode "127.0.0.1:$(cat "$LAB/n$j/P2PPORT")" onetry >/dev/null 2>&1; done
sleep 5
echo "peers=$(c $COLD getconnectioncount)"

echo
echo "############ 6.3 — sync from block zero ############"
T0=$(date +%s)
for _ in $(seq 1 900); do
    H=$(c "$COLD" getblockcount)
    [ "${H:-0}" -ge "$TIP_H" ] 2>/dev/null && break
    for i in $(seq 1 $NODES) $COLD; do c "$i" setmocktime "$CLOCK" >/dev/null 2>&1; done
    sleep 1
done
T1=$(date +%s)
echo "cold node height=$(c $COLD getblockcount) after $((T1-T0))s   peers=$(c $COLD getconnectioncount)"
echo "cold tip = $(c $COLD getbestblockhash)"
echo "ref  tip = $TIP_HASH"
[ "$(c $COLD getbestblockhash)" = "$TIP_HASH" ] && echo ">>> TIP IDENTICAL" || echo ">>> *** TIP DIFFERS ***"

echo
echo "############ 6.4 — the SCHEDULE must match, at several heights ############"
BOOT=$(grep -o 'labbootstrapheight=[0-9]*' "$LAB/n1/bathron.conf" | cut -d= -f2)
ACT=$(( BOOT + 1 ))
DIFFS=0
for H in "$ACT" $(( ACT + 1 )) $(( ACT + 60 )) $(( ACT + 120 )) $(( TIP_H / 2 )) $(( TIP_H - 10 )) "$TIP_H"; do
    [ "$H" -gt "$TIP_H" ] && continue
    A=$(c 1     getquorum "$H" | grep -E '"(schedule_status|producer_operator|schedule_raw_slot|total_operators|finality_threshold)"')
    B=$(c $COLD getquorum "$H" | grep -E '"(schedule_status|producer_operator|schedule_raw_slot|total_operators|finality_threshold)"')
    if [ "$A" = "$B" ]; then
        printf "  h=%-6s IDENTICAL  %s\n" "$H" "$(echo "$A" | grep -o '"total_operators": [0-9]*')"
    else
        printf "  h=%-6s *** DIFFERS ***\n" "$H"; diff <(echo "$A") <(echo "$B") | head -6
        DIFFS=$(( DIFFS + 1 ))
    fi
done

echo
echo "############ 6.5 — verdict ############"
echo "schedule mismatches: $DIFFS"
echo "cold node finality : $(c $COLD getfinalitystatus | grep -oE '"(last_finalized_height|finality_lag|quorum_threshold|operators)": [0-9-]*' | tr '\n' ' ')"
echo "ref  node finality : $(c 1     getfinalitystatus | grep -oE '"(last_finalized_height|finality_lag|quorum_threshold|operators)": [0-9-]*' | tr '\n' ' ')"
echo "fatal latches on the cold node: $(grep -c 'CONSENSUS DB FATAL' "$LAB/n$COLD/node.log")"
