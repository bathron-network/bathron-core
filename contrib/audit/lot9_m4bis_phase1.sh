#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4-BIS PHASE 1 — ATTACK ON THE LAST BOOTSTRAP BLOCK (the frontier)
# =============================================================================
#
# The first epoch anchors on `activation - 1` = the LAST BOOTSTRAP BLOCK. That
# single block therefore fixes the operator set of the whole first epoch, and its
# author is a single, unconstrained producer (bootstrap blocks are mined, exempt
# from the producer check). The mandated question is precise:
#
#   can a SINGLE producer REPLACE or REMOVE operators already confirmed
#   before the frontier?     -> if yes: HIGH, STOP.
#
# Adding is a different question (it costs a collateral, i.e. burned BTC) and is
# measured separately below; censorship is measured too, since delaying an
# admission is not the same as removing a confirmed one.
#
# The attacker here is node 1: it authors the frontier block and it holds ITS OWN
# operator key — but not the other operators' keys. That is the real adversary.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/home/ubuntu/lot9-lab7bis}"
LAB="$(cat "$SCRATCH/lot9lab7.state")"
NODES=7
c() { local i="$1"; shift; "$REPO/src/bathron-cli" -datadir="$LAB/n$i" -regtest "$@" 2>&1; }
fatals() { grep -c 'CONSENSUS DB FATAL' "$LAB/n1/node.log" 2>/dev/null || echo 0; }

VICTIM=$(cat "$LAB/op7.protx")           # an operator confirmed long before the frontier
ATTACKER_OPWIF=$(sed -n 1p "$LAB/op1.id")  # the frontier producer's OWN operator key
ATTACKER_OWNER=$(sed -n 4p "$LAB/op1.id")  # ... and its own owner address

echo "############ 1.0 — state one block before the frontier ############"
BOOT=$(grep -o 'labbootstrapheight=[0-9]*' "$LAB/n1/bathron.conf" | cut -d= -f2)
echo "height=$(c 1 getblockcount)  bootstrap window ends at $BOOT  activation=$((BOOT+1))"
echo "epoch-0 snapshot height = $BOOT  (the LAST BOOTSTRAP BLOCK — the frontier)"
echo "victim operator (registered at height 7): ${VICTIM:0:16}…"
echo "operators confirmed before the frontier: $(c 1 protx_list valid_only true | grep -c proTxHash)"

echo
echo "############ 1.1 — REMOVE a confirmed operator (the HIGH criterion) ############"
echo "-- attacker calls protx_update_revoke on the victim, with its OWN operator key --"
R=$(c 1 protx_update_revoke "$VICTIM" "$ATTACKER_OPWIF" 1 | head -3 | tr '\n' ' ')
echo "result: ${R:0:200}"

echo
echo "############ 1.2 — REPLACE the victim's operator key (registrar) ############"
NEWPUB=$(c 1 validateaddress "$(c 1 getnewaddress attacker_new)" | grep -o '"pubkey": "[0-9a-f]*"' | cut -d'"' -f4)
NEWVRF=$(c 1 getvrfpubkey "$ATTACKER_OPWIF" | tr -d '" \n')
echo "-- attacker rewrites the victim's operator pubkey to one it controls --"
R=$(c 1 protx update_registrar "$VICTIM" "$NEWPUB" "$ATTACKER_OWNER" "$ATTACKER_OWNER" "$ATTACKER_OPWIF" "$NEWVRF" | head -3 | tr '\n' ' ')
echo "result: ${R:0:200}"

echo
echo "############ 1.3 — REPLACE the victim's service endpoint ############"
R=$(c 1 protx_update_service "$VICTIM" "127.0.0.1:39999" "$ATTACKER_OPWIF" | head -3 | tr '\n' ' ')
echo "result: ${R:0:200}"

echo
echo "############ 1.4 — did the confirmed set move at all? ############"
echo "operators still registered: $(c 1 protx_list valid_only true | grep -c proTxHash)"
echo "victim still present      : $(c 1 protx_list valid_only true | grep -c "$VICTIM")"

echo
echo "############ 1.5 — mine the FRONTIER BLOCK itself and read epoch 0 ############"
FA=$(fatals)
c 1 generatebootstrap 1 >/dev/null 2>&1
sleep 2
echo "height after the frontier block: $(c 1 getblockcount)"
echo "new fatal latches: $(( $(fatals) - FA ))"
echo "-- the schedule at the FIRST scheduled block, resolved from the frontier --"
c 1 getquorum "$((BOOT+1))" 2>/dev/null | grep -E 'height|finality_threshold|total_operators|schedule_status' \
  || echo "(height $((BOOT+1)) not reached yet — resolved below after crossing)"

echo
echo "############ 1.6 — cross the activation and measure snapshot PROTECTION ############"
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
for _ in $(seq 1 6); do advance >/dev/null || echo "STALL at $(c 1 getblockcount)"; done
H=$(c 1 getblockcount)
echo "height=$H   nodes alive=$(for i in $(seq 1 $NODES); do c $i getblockcount >/dev/null 2>&1 && echo x; done | wc -l)/$NODES"
c 1 getquorum "$((BOOT+1))" | grep -E '"height"|finality_threshold|total_operators|schedule_status|producer_operator'
FIN=$(c 1 getfinalitystatus | grep -o '"last_finalized_height": [0-9]*' | awk '{print $2}')
echo "last_finalized_height = $FIN   (frontier block = $BOOT)"
if [ "${FIN:-0}" -gt "$BOOT" ]; then
    echo ">>> the frontier block is BURIED under a finalized block: rewriting it would"
    echo ">>> have to rewrite a finalized height, which HasConflictingFinality refuses."
else
    echo ">>> frontier NOT yet protected by finality — exposure window still open."
fi

echo
echo "############ 1.7 — the epoch-0 set, identical on all seven nodes ############"
for i in $(seq 1 $NODES); do
    printf "n%s ops=%s status=%s\n" "$i" \
      "$(c $i getquorum "$((BOOT+1))" | grep -o '"total_operators": [0-9]*' | awk '{print $2}')" \
      "$(c $i getquorum "$((BOOT+1))" | grep -o '"schedule_status": "[a-z_]*"' | cut -d'"' -f4)"
done
