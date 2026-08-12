#!/usr/bin/env bash
# =============================================================================
# LOT 9 M3 — daemon auto-renewal (-leaseautorenew), live single-node smoke test
# =============================================================================
#
# Proves the OPT-IN auto-renewer actually renews: no RPC is called, no operator
# intervenes, and the on-chain lease moves anyway once half the horizon is
# consumed.
#
# The shipped horizon is 10080 blocks (~7 days) — unreachable in a test, and
# precisely why this path could otherwise only be asserted by reading the code.
# `-lableaseblocks` (LAB-ONLY, regtest-only, compiled out of release builds)
# shortens the horizon so the SAME rule runs on a timescale a test can reach.
#
# Also checks the other half of the decision: with auto-renewal OFF the node
# says so loudly at startup, because an operator who does not know renewal
# exists is exactly how the finality population drains.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BATHROND="${BATHROND:-$REPO/src/bathrond}"
BATHRONCLI="${BATHRONCLI:-$REPO/src/bathron-cli}"
SCRATCH="${SCRATCH:-/tmp/lot9-m3-autorenew-smoke}"
PREMINE_WIF="cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR"

# Horizon short enough to cross in a few blocks; renewal triggers at half of it.
LEASE_BLOCKS="${LEASE_BLOCKS:-40}"
RENEW_INTERVAL=30          # the monitor's floor, so the test does not idle
BOOTSTRAP_HEIGHT=200

DATADIR="$SCRATCH/node"
CLI() { "$BATHRONCLI" -datadir="$DATADIR" -regtest "$@"; }

die() { echo "FAIL: $*" >&2; stop_node; exit 1; }
stop_node() {
    if [ -f "$DATADIR/PID" ]; then kill "$(cat "$DATADIR/PID")" 2>/dev/null; fi
    for _ in $(seq 1 30); do CLI getblockcount >/dev/null 2>&1 || break; sleep 1; done
}
start_node() {
    nohup "$BATHROND" -datadir="$DATADIR" -regtest -printtoconsole=1 >> "$DATADIR/node.log" 2>&1 &
    echo "$!" > "$DATADIR/PID"
    for _ in $(seq 1 90); do CLI getblockcount >/dev/null 2>&1 && return 0; sleep 1; done
    tail -20 "$DATADIR/node.log"; die "RPC never came up"
}
trap stop_node EXIT

mn_field() {
    CLI protx_list true false false 2>/dev/null | python3 -c "
import json,sys
protx, field = sys.argv[1], sys.argv[2]
for mn in json.load(sys.stdin):
    if mn.get('proTxHash') == protx:
        print(mn['dmnstate'][field]); break
else:
    sys.exit('proTx not found')
" "$1" "$2"
}

# Field of OUR masternode in getactivemnstatus (the operator-facing view — the
# jittered start height and the last auto-renewal attempt live here).
amn_field() {
    CLI getactivemnstatus 2>/dev/null | python3 -c "
import json,sys
protx, field = sys.argv[1], sys.argv[2]
for mn in json.load(sys.stdin).get('masternodes', []):
    if mn.get('proTxHash') == protx:
        print(mn.get(field, '')); break
else:
    sys.exit('proTx not found in getactivemnstatus')
" "$1" "$2"
}

[ -x "$BATHROND" ] || die "bathrond not found at $BATHROND"
grep -q "BATHRON_ENABLE_LAB_PREMINE 1" "$REPO/src/config/bathron-config.h" 2>/dev/null \
    || die "binary is NOT built with --enable-lab-premine — -lableaseblocks would not exist and there would be no spendable premine"

echo "=== 0. node, with a SHORT lease horizon (lab-only) ==="
rm -rf "$SCRATCH"; mkdir -p "$DATADIR"
PORT=$(( 24000 + (RANDOM % 10000) )); RPCPORT=$(( PORT + 1 ))
cat > "$DATADIR/bathron.conf" <<EOF
regtest=1
server=1
daemon=0
listen=1
dnsseed=0
discover=0
upnp=0
natpmp=0
txindex=1
rpcuser=smoke
rpcpassword=$(head -c 32 /dev/urandom | sha256sum | head -c 32)
labbootstrapheight=$BOOTSTRAP_HEIGHT
lableaseblocks=$LEASE_BLOCKS
[regtest]
port=$PORT
rpcport=$RPCPORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
EOF
start_node
grep -q "lease=$LEASE_BLOCKS" "$DATADIR/node.log" || die "the lab lease override did not take effect"
echo "lease horizon = $LEASE_BLOCKS blocks (renewal triggers at $((LEASE_BLOCKS / 2)) remaining)"

echo "=== 1. premine + one registered operator ==="
CLI importprivkey "$PREMINE_WIF" "premine" false >/dev/null 2>&1
CLI rescanblockchain 0 >/dev/null 2>&1
for _ in 1 2; do CLI generatebootstrap 1 >/dev/null 2>&1 || die "generatebootstrap failed"; done
OPADDR=$(CLI getnewaddress "op"); OPWIF=$(CLI dumpprivkey "$OPADDR")
OPPUB=$(CLI validateaddress "$OPADDR" | python3 -c "import json,sys; print(json.load(sys.stdin)['pubkey'])")
VRFPUB=$(CLI getvrfpubkey "$OPWIF" | tr -d '" \n')
OWNER=$(CLI getnewaddress "owner"); VOTING=$(CLI getnewaddress "voting")
PAYOUT=$(CLI getnewaddress "payout"); COLL=$(CLI getnewaddress "coll")
PROTX=$(CLI protx_register_fund "$COLL" "127.0.0.1:$((PORT + 100))" "$OWNER" "$OPPUB" "$VOTING" "$PAYOUT" "$VRFPUB" 2>&1 | tr -d '"')
case "$PROTX" in [0-9a-f]*) : ;; *) die "protx_register_fund: $PROTX" ;; esac
CLI generatebootstrap 1 >/dev/null 2>&1
SEQ0=$(mn_field "$PROTX" leaseSequence); EXP0=$(mn_field "$PROTX" leaseExpiryHeight)
echo "proTx=${PROTX:0:16}… sequence=$SEQ0 expiry=$EXP0"

echo
echo "=== 2. restart as an operator WITHOUT auto-renewal — the warning must be loud ==="
stop_node
cat >> "$DATADIR/bathron.conf" <<EOF
masternode=1
mnoperatorprivatekey=$OPWIF
leaserenewinterval=$RENEW_INTERVAL
EOF
start_node
grep -q "OPERATOR-LEASE: monitor enabled, auto-renewal OFF" "$DATADIR/node.log" \
    || die "a masternode with auto-renewal off did not say so at startup"
echo "startup warning present:"
grep -m1 "auto-renewal OFF" "$DATADIR/node.log" | sed 's/^/  /'

echo
echo "=== 3. enable auto-renewal and consume half the horizon ==="
stop_node
echo "leaseautorenew=1" >> "$DATADIR/bathron.conf"
start_node
grep -q "OPERATOR-LEASE: monitor enabled, auto-renewal ON" "$DATADIR/node.log" \
    || die "auto-renewal did not report itself enabled"

# Auto-renewal begins at a DETERMINISTICALLY JITTERED height inside
# [expiry - L/2, expiry - L/4) — read it from getactivemnstatus (which also
# proves the observability field), and mine INTO the slot.
TARGET=$(amn_field "$PROTX" leaseAutorenewStartHeight)
case "$TARGET" in [0-9]*) : ;; *) die "getactivemnstatus did not expose leaseAutorenewStartHeight" ;; esac
[ "$TARGET" -ge $(( EXP0 - LEASE_BLOCKS / 2 )) ] || die "jittered start $TARGET is before the renewal window"
[ "$TARGET" -lt $(( EXP0 - LEASE_BLOCKS / 4 )) ] || die "jittered start $TARGET eats into the safety margin"
while [ "$(CLI getblockcount)" -lt "$TARGET" ]; do
    CLI generatebootstrap 1 >/dev/null 2>&1 || die "generatebootstrap failed while advancing"
done
echo "height=$(CLI getblockcount), expiry=$EXP0, jittered start=$TARGET -> slot open"

echo
echo "=== 4. wait for the daemon to renew BY ITSELF (no RPC call) ==="
RENEWED=0
for _ in $(seq 1 12); do
    sleep 10
    # The renewal lands in the mempool; a block is needed to make it chain state.
    if [ -n "$(CLI getrawmempool | tr -d '[] \n')" ]; then
        CLI generatebootstrap 1 >/dev/null 2>&1
    fi
    SEQ=$(mn_field "$PROTX" leaseSequence 2>/dev/null || echo "$SEQ0")
    if [ "$SEQ" != "$SEQ0" ]; then RENEWED=1; break; fi
done
[ "$RENEWED" = "1" ] || {
    echo "--- lease monitor log ---"; grep "OPERATOR-LEASE" "$DATADIR/node.log" | tail -10
    die "the daemon never renewed on its own"
}

SEQ1=$(mn_field "$PROTX" leaseSequence); EXP1=$(mn_field "$PROTX" leaseExpiryHeight)
echo "auto-renewed: sequence $SEQ0 -> $SEQ1, expiry $EXP0 -> $EXP1"
[ "$SEQ1" = "$((SEQ0 + 1))" ] || die "auto-renewal must advance the sequence by exactly one"
[ "$EXP1" -gt "$EXP0" ] || die "auto-renewal did not push the expiry out"
grep -q "OPERATOR-LEASE: auto-renewed" "$DATADIR/node.log" || die "the renewal was not logged"
grep -m1 "auto-renewed" "$DATADIR/node.log" | sed 's/^/  /'

# The attempt must be visible over RPC too, not only in the log.
LASTRES=$(amn_field "$PROTX" leaseAutorenewLastResult)
[ "$LASTRES" = "success" ] || die "getactivemnstatus reports last result '$LASTRES', want 'success'"
echo "getactivemnstatus: leaseAutorenewLastResult=success, txid=$(amn_field "$PROTX" leaseAutorenewLastTxid | cut -c1-16)…"

echo
echo "PASS — with leaseautorenew=1 the daemon renewed its own lease unprompted"
echo "       (sequence $SEQ0 -> $SEQ1, expiry $EXP0 -> $EXP1); with it off it warned at startup."
