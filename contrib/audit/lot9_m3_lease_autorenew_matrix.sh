#!/usr/bin/env bash
# =============================================================================
# LOT 9 M3 — auto-renewal FAILURE MATRIX (HARNESS — shortened horizon)
# =============================================================================
#
# ⚠️ HARNESS, and labeled as such: every scenario here runs with the lease
# horizon shortened via `-lableaseblocks` (LAB-ONLY, regtest-only, compiled out
# of release builds). That proves the SCHEDULER and the FAILURE VISIBILITY are
# operational; it does NOT re-prove the consensus rule at its real value — that
# proof is lot9_m4bis_phase4bis_run.sh, on the real 10 080-block chain.
#
# Matrix (each scenario measured, each failure must be VISIBLE, none may crash):
#   A  auto-renew OFF            -> explicit startup warning
#   B  ON, funded, unlocked      -> renews by itself; RPC shows success
#   C  ON, wallet LOCKED         -> visible failure (log + RPC), daemon alive
#   D  ON, wallet EMPTY          -> visible insufficient-funds, daemon alive
#   E  4 operators together      -> jittered start heights actually SPREAD
#   F  restart inside the window -> renewal still happens after the restart
#   G  pending renewal           -> monitor does NOT double-submit (mempool)
#
# Scenario A and B are also covered by lot9_m3_lease_autorenew_smoke.sh; they
# are re-run here so the matrix stands alone in one PASS/FAIL.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BATHROND="${BATHROND:-$REPO/src/bathrond}"
BATHRONCLI="${BATHRONCLI:-$REPO/src/bathron-cli}"
SCRATCH="${SCRATCH:-/tmp/lot9-m3-autorenew-matrix}"
PREMINE_WIF="cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR"
LEASE_BLOCKS=40
RENEW_INTERVAL=30
BOOTSTRAP_HEIGHT=300

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
mine_to() {
    while [ "$(CLI getblockcount)" -lt "$1" ]; do
        CLI generatebootstrap 1 >/dev/null 2>&1 || die "generatebootstrap failed"
    done
}
wait_result() {   # wait_result <proTx> <expected leaseAutorenewLastResult> <tries>
    local ptx="$1" want="$2" tries="${3:-12}" got=""
    for _ in $(seq 1 "$tries"); do
        sleep 10
        got="$(amn_field "$ptx" leaseAutorenewLastResult 2>/dev/null || echo '')"
        [ "$got" = "$want" ] && return 0
    done
    echo "--- monitor log ---"; grep "OPERATOR-LEASE" "$DATADIR/node.log" | tail -8
    die "leaseAutorenewLastResult: want '$want', got '$got'"
}
# The daemon enforces ONE operator key per daemon (Operator-Centric model): one
# key manages N masternodes. So the four identities share the SAME operator key
# — four proTxHashes, four leases, four DISTINCT jittered slots (the jitter is
# keyed on proTxHash), all renewed by one daemon. Exactly the multi-MN shape.
register_mn() {   # register_mn <label> <operatorPub> <operatorWif> -> echoes PROTX
    local owner voting payout coll protx vrf
    vrf=$(CLI getvrfpubkey "$3" | tr -d '" \n')
    owner=$(CLI getnewaddress); voting=$(CLI getnewaddress)
    payout=$(CLI getnewaddress); coll=$(CLI getnewaddress)
    protx=$(CLI protx_register_fund "$coll" "127.0.0.1:$((PORT + 100 + RANDOM % 100))" \
            "$owner" "$2" "$voting" "$payout" "$vrf" 2>&1 | tr -d '"')
    case "$protx" in [0-9a-f]*) : ;; *) die "protx_register_fund($1): $protx" ;; esac
    CLI generatebootstrap 1 >/dev/null 2>&1
    echo "$protx"
}

[ -x "$BATHROND" ] || die "bathrond not found at $BATHROND"
grep -q "BATHRON_ENABLE_LAB_PREMINE 1" "$REPO/src/config/bathron-config.h" 2>/dev/null \
    || die "binary is NOT built with --enable-lab-premine"

echo "=== 0. node (HARNESS: lease horizon $LEASE_BLOCKS blocks) ==="
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
rpcuser=matrix
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
CLI importprivkey "$PREMINE_WIF" "premine" false >/dev/null 2>&1
CLI rescanblockchain 0 >/dev/null 2>&1
for _ in 1 2; do CLI generatebootstrap 1 >/dev/null 2>&1 || die "generatebootstrap failed"; done

echo "=== E-prep. FOUR identities registered together under ONE operator key ==="
OPADDR=$(CLI getnewaddress "op"); OPWIF=$(CLI dumpprivkey "$OPADDR")
OPPUB=$(CLI validateaddress "$OPADDR" | python3 -c "import json,sys; print(json.load(sys.stdin)['pubkey'])")
P1=$(register_mn mn1 "$OPPUB" "$OPWIF")
P2=$(register_mn mn2 "$OPPUB" "$OPWIF")
P3=$(register_mn mn3 "$OPPUB" "$OPWIF")
P4=$(register_mn mn4 "$OPPUB" "$OPWIF")
echo "identities: ${P1:0:8} ${P2:0:8} ${P3:0:8} ${P4:0:8} (one operator key)"

echo
echo "=== A. auto-renew OFF -> explicit warning ==="
stop_node
cat >> "$DATADIR/bathron.conf" <<EOF
masternode=1
mnoperatorprivatekey=$OPWIF
leaserenewinterval=$RENEW_INTERVAL
EOF
start_node
grep -q "OPERATOR-LEASE: monitor enabled, auto-renewal OFF" "$DATADIR/node.log" \
    || die "A: no explicit OFF warning at startup"
echo "A PASS: $(grep -m1 'auto-renewal OFF' "$DATADIR/node.log" | cut -c1-100)…"

echo
echo "=== E. jitter SPREADS the four start heights ==="
STARTS=""
for p in $P1 $P2 $P3 $P4; do
    s=$(amn_field "$p" leaseAutorenewStartHeight)
    case "$s" in [0-9]*) : ;; *) die "E: no leaseAutorenewStartHeight for ${p:0:8}" ;; esac
    STARTS="$STARTS $s"
done
DISTINCT=$(echo "$STARTS" | tr ' ' '\n' | sed '/^$/d' | sort -un | wc -l)
echo "start heights:$STARTS ($DISTINCT distinct)"
[ "$DISTINCT" -ge 2 ] || die "E: all four operators share one start height — no spread"

# The jitter ORDER differs per run (that is the point). The later scenarios must
# not assume P1 comes first: C and B/F work on the EARLIEST slot (only that
# window opens while we sit at its height), G on the LATEST (still unrenewed
# when its turn comes).
FIRST=""; S_FIRST=999999; LAST=""; S_LAST=0
for p in $P1 $P2 $P3 $P4; do
    s=$(amn_field "$p" leaseAutorenewStartHeight)
    if [ "$s" -lt "$S_FIRST" ]; then S_FIRST=$s; FIRST=$p; fi
    if [ "$s" -gt "$S_LAST" ];  then S_LAST=$s;  LAST=$p;  fi
done
[ "$S_LAST" -gt "$S_FIRST" ] || die "E: degenerate jitter (all slots equal)"
echo "earliest slot: ${FIRST:0:8}@$S_FIRST — latest: ${LAST:0:8}@$S_LAST"

echo
echo "=== C. wallet LOCKED -> visible failure, no crash ==="
stop_node
echo "leaseautorenew=1" >> "$DATADIR/bathron.conf"
start_node
grep -q "auto-renewal ON" "$DATADIR/node.log" || die "C: auto-renewal not enabled"
WALLET_PASS="matrix-pass-$RANDOM"
CLI encryptwallet "$WALLET_PASS" >/dev/null 2>&1   # shuts the node down
for _ in $(seq 1 30); do CLI getblockcount >/dev/null 2>&1 || break; sleep 1; done
start_node
# Enter the EARLIEST jittered slot with the wallet locked the whole time —
# generatebootstrap mines to a hardcoded address, no wallet involved, so there
# is no unlock window and no race with the monitor.
mine_to "$S_FIRST"
wait_result "$FIRST" "wallet-locked" 12
CLI getblockcount >/dev/null 2>&1 || die "C: daemon died after a locked-wallet failure"
grep -q "wallet is LOCKED" "$DATADIR/node.log" || die "C: no explicit locked-wallet log line"
echo "C PASS: visible wallet-locked failure, daemon alive"

echo
echo "=== B/F. unlock + RESTART inside the window -> it renews after the restart ==="
SEQ_BEFORE=$(mn_field "$FIRST" leaseSequence)
stop_node          # F: restart INSIDE the renewal window, before any success
start_node
CLI walletpassphrase "$WALLET_PASS" 999999 >/dev/null 2>&1 || die "B: unlock failed"
wait_result "$FIRST" "success" 18
if [ -n "$(CLI getrawmempool | tr -d '[] \n')" ]; then CLI generatebootstrap 1 >/dev/null 2>&1; fi
SEQ_AFTER=$(mn_field "$FIRST" leaseSequence)
[ "$SEQ_AFTER" = "$((SEQ_BEFORE + 1))" ] || die "B/F: sequence $SEQ_BEFORE -> $SEQ_AFTER, want +1"
echo "B/F PASS: renewed after restart-in-window (sequence $SEQ_BEFORE -> $SEQ_AFTER)"

echo
echo "=== G. a pending renewal is NOT double-submitted ==="
# Pin the assertion to the LATEST-slot identity: its window has not opened yet,
# so it is still at sequence 0. Identities renewed earlier have had their
# horizon RESTART at confirmation — their second-generation windows may
# legitimately open along the way, which is the scheduler doing its job, not a
# double submit. The property proved here: across two monitor passes with the
# renewal(s) pending, the mempool set is STABLE (nothing resubmitted), and the
# pinned identity's sequence advances by exactly one.
SEQL=$(mn_field "$LAST" leaseSequence)
[ "$SEQL" = "0" ] || die "G: expected ${LAST:0:8} (latest slot $S_LAST) still at sequence 0, got $SEQL"
mine_to "$S_LAST"
sleep $(( RENEW_INTERVAL + 5 ))
POOL_A="$(CLI getrawmempool | tr -d '[] "\n' | sort 2>/dev/null || true)"
sleep $(( RENEW_INTERVAL + 5 ))    # a second monitor pass with the txs still pending
POOL_B="$(CLI getrawmempool | tr -d '[] "\n' | sort 2>/dev/null || true)"
[ "$POOL_A" = "$POOL_B" ] || die "G: mempool changed between two passes with renewals pending — double submit?"
[ -n "$(CLI getrawmempool | tr -d '[] \n')" ] || die "G: no pending renewal at the latest slot"
CLI generatebootstrap 1 >/dev/null 2>&1
SEQLb=$(mn_field "$LAST" leaseSequence)
[ "$SEQLb" = "1" ] || die "G: ${LAST:0:8} sequence 0 -> $SEQLb, want exactly 1"
echo "G PASS: pending set stable across two passes, ${LAST:0:8} renewed exactly once (0 -> 1)"

echo
echo "=== D. EMPTY wallet -> visible insufficient-funds, no crash ==="
# Drain the wallet COMPLETELY: send the whole balance (fee subtracted from the
# amount) to a genesis premine address whose key this wallet does NOT hold.
CLI walletpassphrase "$WALLET_PASS" 999999 >/dev/null 2>&1
FOREIGN=$(CLI getblock "$(CLI getblockhash 0)" 2 | python3 -c "
import json,sys
b = json.load(sys.stdin)
outs = b['tx'][0]['vout']
spk = outs[4]['scriptPubKey']
addrs = spk.get('addresses') or ([spk['address']] if 'address' in spk else [])
print(addrs[0])")
[ -n "$FOREIGN" ] || die "D: could not extract a foreign premine address from genesis"
# getbalance returns an object (amounts in sats); the transfer RPC is sendmany.
# Drain only what is SPENDABLE: `total` includes the MN collaterals, which are
# LOCKED and excluded from coin selection — asking for them fails the send.
bal_total() { CLI getbalance | python3 -c "
import json,sys
b = json.load(sys.stdin)
if isinstance(b, dict):
    print(int(b['total']) - int(b.get('locked', 0)) - int(b.get('immature', 0)))
else:
    print(int(b))"; }
BAL=$(bal_total)
CLI sendmany "" "{\"$FOREIGN\": $BAL}" 0 "" "[\"$FOREIGN\"]" >/dev/null 2>&1 \
    || die "D: drain send failed (balance $BAL)"
CLI generatebootstrap 1 >/dev/null 2>&1
echo "wallet drained to $(bal_total) sats (sent to foreign $FOREIGN)"
# Force the next attempt: advance to the earliest identity's NEXT jittered slot
# (its lease was renewed in B/F, so the next window is one horizon later).
NEXT=$(amn_field "$FIRST" leaseAutorenewStartHeight)
mine_to "$NEXT"
wait_result "$FIRST" "insufficient-funds" 12
CLI getblockcount >/dev/null 2>&1 || die "D: daemon died on insufficient funds"
echo "D PASS: visible insufficient-funds failure, daemon alive"

echo
echo "PASS — auto-renew matrix (HARNESS, shortened horizon): OFF warning, renew,"
echo "       locked-wallet and empty-wallet failures visible without a crash,"
echo "       jitter spreads co-registered operators, restart-in-window renews,"
echo "       no double-submission of a pending renewal."
