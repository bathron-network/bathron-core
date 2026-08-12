#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4 PHASE A — build the 7-operator LABORATORY genesis
# =============================================================================
#
# Registers SEVEN distinct operators (distinct operator keys, distinct VRF keys,
# distinct owner/voting/payout addresses) inside the bootstrap window, so they
# are the operator set of the FIRST anchored epoch. Collateral is funded from
# the LAB premine — a laboratory convenience that proves NOTHING about A5 and is
# compiled out of release builds.
#
# Everything runs against node 1 over loopback RPC; the operator WIFs are then
# distributed one per node so each daemon can produce for its own operator.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
SCRATCH="${SCRATCH:-/tmp/claude-1000/-home-ubuntu/e0e4288f-8616-4be7-8b44-455c8a5c28f1/scratchpad}"
LABSTATE="$SCRATCH/lot9lab7.state"
LAB="$(cat "$LABSTATE")"
CLI1() { "$REPO/src/bathron-cli" -datadir="$LAB/n1" -regtest "$@"; }
NODES=7
PREMINE_WIF="cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR"

die() { echo "ERROR: $*" >&2; exit 1; }

echo "=== PHASE A.1 — premine import (LAB ONLY, no A5 meaning) ==="
CLI1 importprivkey "$PREMINE_WIF" "premine" false >/dev/null 2>&1
CLI1 rescanblockchain 0 >/dev/null 2>&1
BAL=$(CLI1 getbalance | grep -o '"m0": [0-9]*' | head -1 | awk '{print $2}')
[ "${BAL:-0}" -gt 0 ] || die "premine not spendable (is the binary built with --enable-lab-premine?)"
echo "premine m0 = $BAL sats"

echo "=== PHASE A.2 — seven distinct operator identities ==="
for i in $(seq 1 $NODES); do
    OPADDR=$(CLI1 getnewaddress "opsrc$i")
    OPWIF=$(CLI1 dumpprivkey "$OPADDR")
    # NOTE: validateaddress exposes the pubkey; getaddressinfo does not.
    OPPUB=$(CLI1 validateaddress "$OPADDR" | grep -o '"pubkey": "[0-9a-f]*"' | head -1 | cut -d'"' -f4)
    VRFPUB=$(CLI1 getvrfpubkey "$OPWIF" | tr -d '"' | tr -d ' \n')
    OWNER=$(CLI1 getnewaddress "owner$i")
    VOTING=$(CLI1 getnewaddress "voting$i")
    PAYOUT=$(CLI1 getnewaddress "payout$i")
    [ -n "$OPPUB" ] && [ -n "$VRFPUB" ] || die "failed to derive operator/VRF pubkey for $i"
    printf '%s\n%s\n%s\n%s\n%s\n%s\n' "$OPWIF" "$OPPUB" "$VRFPUB" "$OWNER" "$VOTING" "$PAYOUT" > "$LAB/op$i.id"
    echo "op$i: pub=${OPPUB:0:16}… vrf=${VRFPUB:0:16}… owner=$OWNER"
done

# Distinctness is a REQUIREMENT of the lab (7 real operators, not 7 aliases).
DISTINCT_OP=$(for i in $(seq 1 $NODES); do sed -n 2p "$LAB/op$i.id"; done | sort -u | wc -l)
DISTINCT_VRF=$(for i in $(seq 1 $NODES); do sed -n 3p "$LAB/op$i.id"; done | sort -u | wc -l)
[ "$DISTINCT_OP" = "$NODES" ] || die "operator keys are not distinct ($DISTINCT_OP/$NODES)"
[ "$DISTINCT_VRF" = "$NODES" ] || die "VRF keys are not distinct ($DISTINCT_VRF/$NODES)"
echo "distinct operator keys: $DISTINCT_OP/$NODES   distinct VRF keys: $DISTINCT_VRF/$NODES"

echo "=== PHASE A.3 — register the seven, inside the bootstrap window ==="
BOOT=$(grep -o 'labbootstrapheight=[0-9]*' "$LAB/n1/bathron.conf" | cut -d= -f2)
for i in $(seq 1 $NODES); do
    OPPUB=$(sed -n 2p "$LAB/op$i.id");  VRFPUB=$(sed -n 3p "$LAB/op$i.id")
    OWNER=$(sed -n 4p "$LAB/op$i.id");  VOTING=$(sed -n 5p "$LAB/op$i.id")
    PAYOUT=$(sed -n 6p "$LAB/op$i.id")
    COLLADDR=$(CLI1 getnewaddress "coll$i")
    IPPORT="127.0.0.1:$(( 30000 + i ))"
    TXID=$(CLI1 protx_register_fund "$COLLADDR" "$IPPORT" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" 2>&1 | tr -d '"')
    case "$TXID" in
        [0-9a-f]*) echo "op$i registered: proTx=${TXID:0:16}…"; echo "$TXID" > "$LAB/op$i.protx" ;;
        *) die "protx_register_fund failed for op$i: $TXID" ;;
    esac
    CLI1 generatebootstrap 1 >/dev/null 2>&1   # confirm it inside the window
done

H=$(CLI1 getblockcount)
echo "height after registrations: $H (bootstrap window ends at $BOOT, activation $((BOOT+1)))"
[ "$H" -le "$BOOT" ] || die "registrations spilled past the bootstrap window — the lab geometry is wrong"

echo "=== PHASE A.4 — distribute one operator key per node ==="
for i in $(seq 1 $NODES); do
    WIF=$(sed -n 1p "$LAB/op$i.id")
    PROTX=$(cat "$LAB/op$i.protx")
    cat >> "$LAB/n$i/bathron.conf" <<EOF
masternode=1
mnoperatorprivatekey=$WIF
EOF
    echo "node $i <- operator $i (proTx ${PROTX:0:16}…)"
done

echo "=== PHASE A.5 — the registered set, as consensus sees it ==="
CLI1 protx_list valid_only true 2>/dev/null | head -20
echo "registered count: $(CLI1 protx_list 2>/dev/null | grep -c '^  "')"
echo
echo "PHASE A complete. Restart the nodes to load their operator keys, then drive"
echo "the chain past the activation height with mocktime."
