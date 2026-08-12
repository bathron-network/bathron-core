#!/usr/bin/env bash
set -uo pipefail
BIN="$HOME/BATHRON/src"; D="/tmp/l7-lab2-$$"; rm -rf "$D"; mkdir -p "$D"
CLI(){ "$BIN/bathron-cli" -datadir="$D" -regtest "$@"; }
cat > "$D/bathron.conf" <<CFG
regtest=1
server=1
daemon=0
debug=1
[regtest]
rpcuser=l7
rpcpassword=$(head -c16 /dev/urandom|xxd -p)
rpcport=29778
CFG
start(){ nohup "$BIN/bathrond" -datadir="$D" -regtest -printtoconsole=0 "$@" >/dev/null 2>&1 & echo $! > "$D/PID"; for i in $(seq 1 60); do CLI getblockcount >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
start
CLI importprivkey cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR premine true >/dev/null 2>&1
CLI generate 30 >/dev/null 2>&1
CLI lock 40000 >/dev/null 2>&1; CLI generate 2 >/dev/null 2>&1
H=$(CLI getblockcount); TIP=$(CLI getbestblockhash)
echo "height=$H tip=${TIP:0:16}"
# DISCONNECT: invalidateblock du tip -> UndoSpecialTxsInBlock
echo "── invalidateblock (disconnect/undo) ──"; CLI invalidateblock "$TIP" 2>&1 | head -c 80; echo
echo "  après invalidate: height=$(CLI getblockcount)"
CLI reconsiderblock "$TIP" >/dev/null 2>&1; CLI generate 1 >/dev/null 2>&1
# REPLAY: restart propre puis -reindex
CLI stop >/dev/null 2>&1; sleep 3
echo "── restart -reindex (replay) ──"
start -reindex && echo "  reindex OK height=$(CLI getblockcount)" || echo "  reindex refusé"
CLI stop >/dev/null 2>&1; sleep 3; kill -9 "$(cat $D/PID)" 2>/dev/null
echo "=== markers pendant UNDO et REPLAY (eqS doit rester 1 sur parent réel) ==="
grep "LOT7-PROBE" "$D/regtest/debug.log" 2>/dev/null | grep -vE "expectedParent=NULL" | tail -12
echo "=== undo markers WriteBestBlock(prev) ? cohérence settlement/htlc ==="
grep -E "ATOMICITY|CONSENSUS DB FATAL|inconsistent|will rebuild" "$D/regtest/debug.log" 2>/dev/null | tail -6
rm -rf "$D"
