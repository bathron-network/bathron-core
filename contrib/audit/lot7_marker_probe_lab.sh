#!/usr/bin/env bash
set -uo pipefail
BIN="$HOME/BATHRON/src"; D="/tmp/l7-lab-$$"; rm -rf "$D"; mkdir -p "$D"
CLI(){ "$BIN/bathron-cli" -datadir="$D" -regtest "$@"; }
cat > "$D/bathron.conf" <<CFG
regtest=1
server=1
daemon=0
debug=1
[regtest]
rpcuser=l7
rpcpassword=$(head -c16 /dev/urandom|xxd -p)
rpcport=29777
CFG
nohup "$BIN/bathrond" -datadir="$D" -regtest -printtoconsole=0 >/dev/null 2>&1 &
PID=$!; echo "$PID" > "$D/PID"
for i in $(seq 1 60); do CLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
CLI importprivkey cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR premine true >/dev/null 2>&1
CLI generate 30 >/dev/null 2>&1
echo "height après premine: $(CLI getblockcount)"
# LOCK: M0 -> M1
echo "── lock 50000 ──"; CLI lock 50000 2>&1 | head -c 120; echo
CLI generate 2 >/dev/null 2>&1
# UNLOCK: M1 -> M0 (exerce CheckUnlock lisant receipt+vault)
echo "── unlock 20000 ──"; CLI unlock 20000 2>&1 | head -c 120; echo
CLI generate 2 >/dev/null 2>&1
# TRANSFER M1
RCPT=$(CLI getwalletstate true 2>/dev/null | python3 -c "import sys,json
try:
 d=json.load(sys.stdin); rs=d.get('receipts') or d.get('m1_receipts') or []
 print(rs[0]['outpoint'] if rs else '')
except: print('')" 2>/dev/null)
ADDR=$(CLI getnewaddress 2>/dev/null)
echo "── transfer_m1 receipt=$RCPT ──"; [ -n "$RCPT" ] && CLI transfer_m1 "$RCPT" "$ADDR" 2>&1 | head -c 120; echo
CLI generate 2 >/dev/null 2>&1
echo "height final: $(CLI getblockcount)"
CLI stop >/dev/null 2>&1; sleep 3; kill -9 "$PID" 2>/dev/null
echo "=== PROBE (chemin bloc = ConnectBlock, chemin mempool = AcceptToMemoryPool) ==="
grep "LOT7-PROBE" "$D/regtest/debug.log" | tail -40
echo "=== DIVERGENCE settlement/htlc markers (SH=0) ? ==="
grep "LOT7-PROBE" "$D/regtest/debug.log" | grep -c "SH=0" || echo 0
echo "=== désync parent (eqS=0 sur type non-null avec parent) ? ==="
grep "LOT7-PROBE" "$D/regtest/debug.log" | grep -vE "expectedParent=NULL" | grep -c "eqS=0" || echo 0
cp "$D/regtest/debug.log" /tmp/claude-1000/-home-ubuntu/12def40b-638a-4759-bd5c-88d139847c6f/scratchpad/l7debug.log 2>/dev/null
rm -rf "$D"
