#!/usr/bin/env bash
# =============================================================================
# LOT 9 M3 — protx_renew_lease, live single-node smoke test
# =============================================================================
#
# The boost suite consensus_lot9_m3_lease_e2e proves the CONSENSUS path with a
# hand-funded transaction. It cannot reach the piece that was actually missing
# for months: the CONSTRUCTION path — wallet funding, the chain-bound operator
# signature, the fee, the RPC. That code only exists inside a running daemon
# with a wallet, so it is measured here, against a real node.
#
# What this asserts, on a real chain:
#   1. protx_renew_lease builds, funds, signs and broadcasts a TX_OPERATOR_LEASE;
#   2. the transaction is mined;
#   3. leaseSequence advances by EXACTLY one, twice in a row (prev+1, not "1");
#   4. leaseExpiryHeight equals inclusionHeight + nOperatorLeaseBlocks, both
#      times — so the horizon does not scale with the sequence.
#
# Requires a binary built with --enable-lab-premine: on a release-configured
# build the regtest genesis has no spendable outputs, so no fee can be paid and
# no lease can be constructed. Refuses to run otherwise rather than report a
# green that measured nothing.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BATHROND="${BATHROND:-$REPO/src/bathrond}"
BATHRONCLI="${BATHRONCLI:-$REPO/src/bathron-cli}"
SCRATCH="${SCRATCH:-/tmp/lot9-m3-lease-smoke}"
BOOTSTRAP_HEIGHT="${BOOTSTRAP_HEIGHT:-200}"
PREMINE_WIF="cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR"

DATADIR="$SCRATCH/node"
CLI() { "$BATHRONCLI" -datadir="$DATADIR" -regtest "$@"; }

die() { echo "FAIL: $*" >&2; cleanup; exit 1; }
cleanup() {
    [ -f "$DATADIR/PID" ] && kill "$(cat "$DATADIR/PID")" 2>/dev/null
    sleep 2
}
trap cleanup EXIT

#! Read one field out of the MN entry for $1 in `protx_list detailed`.
mn_field() {
    CLI protx_list true false false 2>/dev/null | python3 -c "
import json,sys
protx, field = sys.argv[1], sys.argv[2]
for mn in json.load(sys.stdin):
    if mn.get('proTxHash') == protx:
        print(mn['dmnstate'][field]); break
else:
    sys.exit('proTx not found in protx_list')
" "$1" "$2"
}

[ -x "$BATHROND" ] || die "bathrond not found at $BATHROND"
grep -q "BATHRON_ENABLE_LAB_PREMINE 1" "$REPO/src/config/bathron-config.h" 2>/dev/null \
    || die "binary is NOT built with --enable-lab-premine — the regtest genesis would have no spendable coins, so nothing could be measured"

echo "=== 0. single regtest node ==="
rm -rf "$SCRATCH"; mkdir -p "$DATADIR"
PORT=$(( 24000 + (RANDOM % 10000) )); RPCPORT=$(( PORT + 1 ))
cat > "$DATADIR/bathron.conf" <<EOF
regtest=1
server=1
daemon=0
listen=0
dnsseed=0
discover=0
upnp=0
natpmp=0
txindex=1
rpcuser=smoke
rpcpassword=$(head -c 32 /dev/urandom | sha256sum | head -c 32)
labbootstrapheight=$BOOTSTRAP_HEIGHT
[regtest]
port=$PORT
rpcport=$RPCPORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
EOF
nohup "$BATHROND" -datadir="$DATADIR" -regtest -printtoconsole=1 > "$DATADIR/node.log" 2>&1 &
echo "$!" > "$DATADIR/PID"
for _ in $(seq 1 90); do CLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
CLI getblockcount >/dev/null 2>&1 || { tail -20 "$DATADIR/node.log"; die "RPC never came up"; }

echo "=== 1. premine (LAB ONLY — no A5 meaning) ==="
CLI importprivkey "$PREMINE_WIF" "premine" false >/dev/null 2>&1
CLI rescanblockchain 0 >/dev/null 2>&1
for _ in 1 2; do CLI generatebootstrap 1 >/dev/null 2>&1 || die "generatebootstrap failed"; done

echo "=== 2. register one operator inside the bootstrap window ==="
OPADDR=$(CLI getnewaddress "op")
OPWIF=$(CLI dumpprivkey "$OPADDR")
OPPUB=$(CLI validateaddress "$OPADDR" | python3 -c "import json,sys; print(json.load(sys.stdin)['pubkey'])")
VRFPUB=$(CLI getvrfpubkey "$OPWIF" | tr -d '" \n')
OWNER=$(CLI getnewaddress "owner"); VOTING=$(CLI getnewaddress "voting")
PAYOUT=$(CLI getnewaddress "payout"); COLL=$(CLI getnewaddress "coll")
PROTX=$(CLI protx_register_fund "$COLL" "127.0.0.1:30001" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" 2>&1 | tr -d '"')
case "$PROTX" in [0-9a-f]*) : ;; *) die "protx_register_fund: $PROTX" ;; esac
CLI generatebootstrap 1 >/dev/null 2>&1
echo "proTx = ${PROTX:0:16}…"

HORIZON=10080   # consensus.nOperatorLeaseBlocks — pinned by consensus_lot9_m4_scale_tests
SEQ0=$(mn_field "$PROTX" leaseSequence)   || die "leaseSequence not exposed by protx_list"
EXP0=$(mn_field "$PROTX" leaseExpiryHeight)
REG=$(mn_field "$PROTX" registeredHeight)
echo "at registration: sequence=$SEQ0 expiry=$EXP0 (registeredHeight=$REG)"
[ "$SEQ0" = "0" ] || die "expected sequence 0 at registration, got $SEQ0"
[ "$EXP0" = "$((REG + HORIZON))" ] || die "registration expiry $EXP0 != registeredHeight+$HORIZON"

renew_once() {
    local label="$1" prev_seq="$2"
    local txid; txid=$(CLI protx_renew_lease "$PROTX" "$OPWIF" 2>&1 | tr -d '"')
    case "$txid" in [0-9a-f]*) : ;; *) die "$label: protx_renew_lease: $txid" ;; esac
    CLI getrawmempool | grep -q "$txid" || die "$label: the renewal never reached the mempool"
    CLI generatebootstrap 1 >/dev/null 2>&1
    local h; h=$(CLI getrawtransaction "$txid" true 2>/dev/null | python3 -c "
import json,sys
tx=json.load(sys.stdin)
print(tx.get('height', tx.get('confirmations') and -1 or -1))" 2>/dev/null)
    # The reliable inclusion height: the block the tx landed in.
    local blockhash; blockhash=$(CLI getrawtransaction "$txid" true | python3 -c "import json,sys; print(json.load(sys.stdin)['blockhash'])")
    h=$(CLI getblock "$blockhash" | python3 -c "import json,sys; print(json.load(sys.stdin)['height'])")

    local seq exp
    seq=$(mn_field "$PROTX" leaseSequence)
    exp=$(mn_field "$PROTX" leaseExpiryHeight)
    echo "$label: tx=${txid:0:16}… included at height $h -> sequence=$seq expiry=$exp"
    [ "$seq" = "$((prev_seq + 1))" ] || die "$label: sequence must be prev+1 ($((prev_seq + 1))), got $seq"
    [ "$exp" = "$((h + HORIZON))" ] || die "$label: expiry must be inclusionHeight+$HORIZON ($((h + HORIZON))), got $exp"
    LAST_HEIGHT="$h"; LAST_EXPIRY="$exp"
}

echo "=== 3. first renewal ==="
renew_once "renewal#1" "$SEQ0"
H1="$LAST_HEIGHT"; E1="$LAST_EXPIRY"

echo "=== 4. a few blocks, then a second renewal ==="
# Different inclusion height, so an expiry that ignored it cannot land on the
# right number by coincidence.
for _ in 1 2 3; do CLI generatebootstrap 1 >/dev/null 2>&1; done
renew_once "renewal#2" "$((SEQ0 + 1))"
H2="$LAST_HEIGHT"; E2="$LAST_EXPIRY"

[ "$H2" -gt "$((H1 + 1))" ] || die "the two inclusions must differ in height ($H1 vs $H2)"
[ "$((E2 - E1))" = "$((H2 - H1))" ] \
    || die "the horizon changed between renewals: expiry delta $((E2 - E1)) != height delta $((H2 - H1))"

echo
echo "=== 5. the countdown is visible to the operator ==="
CLI protx_list true false false | python3 -c "
import json,sys
for mn in json.load(sys.stdin):
    s = mn['dmnstate']
    print('  proTx %s… sequence=%s expiry=%s' % (mn['proTxHash'][:16], s['leaseSequence'], s['leaseExpiryHeight']))
"

echo
echo "PASS — protx_renew_lease builds, funds, signs and broadcasts a real"
echo "       TX_OPERATOR_LEASE; sequence advanced $SEQ0 -> $((SEQ0+1)) -> $((SEQ0+2))"
echo "       and expiry tracked the inclusion height both times."
