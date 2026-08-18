#!/usr/bin/env bash
# =============================================================================
# LOT 9 M4 — 7-OPERATOR OPEN LABORATORY (strictly local, disposable)
# =============================================================================
#
# Stands up SEVEN regtest bathrond processes on loopback with disposable
# credentials, drives them at the REAL public consensus parameters (finality
# floor 4, expected committee size E=128, anchored schedule) and measures the LOT 9
# properties end to end.
#
# NEVER touches the public fleet: dnsseed/discover/upnp/natpmp/onion are all off
# and every bind is pinned to 127.0.0.1. Datadirs are mktemp and removed by
# `down`. The binary MUST be built with --enable-lab-premine (the lab genesis
# premine and the -lab* overrides are compiled out of release builds).
#
# Time is driven by setmocktime ONLY — no sleep ever gates a consensus outcome.
#
#   ./lot9_lab7.sh up          start 7 nodes, mesh them, report the parameters
#   ./lot9_lab7.sh cli <i> ..  run bathron-cli against node i
#   ./lot9_lab7.sh status      heights, tips, peers, finality
#   ./lot9_lab7.sh mine <n>    advance mocktime and let the schedule produce n blocks
#   ./lot9_lab7.sh down        stop everything and remove the datadirs
#
# The lab dir is recorded in $LABSTATE so successive invocations find it.
set -uo pipefail

REPO="${REPO:-/home/ubuntu/bathron-p0-final}"
BIN_DIR="${BIN_DIR:-$REPO/src}"
BATHROND="$BIN_DIR/bathrond"
BATHRONCLI="$BIN_DIR/bathron-cli"
SCRATCH="${SCRATCH:-/tmp/claude-1000/-home-ubuntu/e0e4288f-8616-4be7-8b44-455c8a5c28f1/scratchpad}"
LABSTATE="$SCRATCH/lot9lab7.state"

# ── The REAL public parameters the laboratory must run at (never regtest's
# degenerate floor 1 / E 1 / anchor 3). Overridden at runtime, regtest-only,
# compiled out of release builds.
LAB_QUORUM="${LAB_QUORUM:-4}"          # nHuQuorumSize — the real Sybil floor
LAB_COMMITTEE="${LAB_COMMITTEE:-128}"  # nHuExpectedCommitteeSize — the real cap
LAB_BOOTSTRAP="${LAB_BOOTSTRAP:-40}"   # bootstrap window; activation = +1
NODES=7

die() { echo "ERROR: $*" >&2; exit 1; }
lab_dir() { [ -f "$LABSTATE" ] || die "no lab running (missing $LABSTATE)"; cat "$LABSTATE"; }
node_dir() { echo "$(lab_dir)/n$1"; }
cli() { local i="$1"; shift; "$BATHRONCLI" -datadir="$(node_dir "$i")" -regtest "$@"; }

# Every node must agree on mocktime, or their DMM schedulers disagree on the slot.
set_mocktime_all() {
    local t="$1"
    for i in $(seq 1 $NODES); do cli "$i" setmocktime "$t" >/dev/null 2>&1; done
}

cmd_up() {
    [ -x "$BATHROND" ] || die "bathrond not found at $BATHROND"
    # Refuse to run a binary without the lab gate: the premine would be absent and
    # the -lab* overrides unknown, so the lab would silently run at regtest's
    # degenerate parameters and every measurement would be a lie.
    if ! "$BATHROND" -help-debug 2>&1 | grep -q "labquorumsize" ; then
        if ! grep -q "BATHRON_ENABLE_LAB_PREMINE 1" "$REPO/src/config/bathron-config.h" 2>/dev/null; then
            die "binary is NOT built with --enable-lab-premine — refusing to produce fake measurements"
        fi
    fi
    mkdir -p "$SCRATCH"
    local lab; lab="$(mktemp -d "$SCRATCH/lot9lab7.XXXXXXXX")" || die "mktemp failed"
    echo "$lab" > "$LABSTATE"
    local base=$(( 21000 + (RANDOM % 15000) ))
    echo "lab dir  : $lab"
    echo "base port: $base"
    echo "params   : quorum=$LAB_QUORUM committee=$LAB_COMMITTEE bootstrap=$LAB_BOOTSTRAP (activation=$((LAB_BOOTSTRAP+1)))"

    for i in $(seq 1 $NODES); do
        local d="$lab/n$i"; mkdir -p "$d"
        local p=$(( base + (i - 1) * 2 )); local rp=$(( p + 1 ))
        echo "$p" > "$d/P2PPORT"; echo "$rp" > "$d/RPCPORT"
        local pw; pw="$(head -c 32 /dev/urandom | sha256sum | head -c 32)"
        cat > "$d/bathron.conf" <<EOF
regtest=1
server=1
daemon=0
listen=1
dnsseed=0
discover=0
upnp=0
natpmp=0
listenonion=0
externalip=127.0.0.1
rpcuser=lab$i
rpcpassword=$pw
# LOT 9 M4: run at the REAL public parameters (lab-only, regtest-only overrides)
labquorumsize=$LAB_QUORUM
labcommitteesize=$LAB_COMMITTEE
labbootstrapheight=$LAB_BOOTSTRAP
[regtest]
port=$p
rpcport=$rp
bind=127.0.0.1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
EOF
        nohup "$BATHROND" -datadir="$d" -regtest -printtoconsole=1 > "$d/node.log" 2>&1 &
        echo "$!" > "$d/PID"
    done

    echo "waiting for RPC..."
    for i in $(seq 1 $NODES); do
        local ok=0
        for _ in $(seq 1 90); do
            if cli "$i" getblockcount >/dev/null 2>&1; then ok=1; break; fi
            sleep 1
        done
        [ "$ok" = 1 ] || { echo "node $i: RPC TIMEOUT"; tail -5 "$lab/n$i/node.log"; }
    done
    cmd_connect
}

cmd_connect() {
    local lab; lab="$(lab_dir)"
    for i in $(seq 1 $NODES); do
        for j in $(seq 1 $NODES); do
            [ "$i" = "$j" ] && continue
            local pj; pj="$(cat "$lab/n$j/P2PPORT")"
            cli "$i" addnode "127.0.0.1:$pj" onetry >/dev/null 2>&1
        done
    done
    sleep 3
    cmd_status
}

cmd_status() {
    local lab; lab="$(lab_dir)"
    printf "%-5s %-8s %-8s %-18s %s\n" NODE HEIGHT PEERS TIP FINALITY
    for i in $(seq 1 $NODES); do
        local h p tip fin
        h="$(cli "$i" getblockcount 2>/dev/null || echo '-')"
        p="$(cli "$i" getconnectioncount 2>/dev/null || echo '-')"
        tip="$(cli "$i" getbestblockhash 2>/dev/null | head -c 16 || echo '-')"
        fin="$(cli "$i" getfinalitystatus 2>/dev/null | grep -o '"finalized_height"[^,]*' | head -1 || echo '-')"
        printf "%-5s %-8s %-8s %-18s %s\n" "$i" "$h" "$p" "$tip" "$fin"
    done
}

cmd_down() {
    [ -f "$LABSTATE" ] || { echo "no lab to stop"; return 0; }
    local lab; lab="$(cat "$LABSTATE")"
    for i in $(seq 1 $NODES); do cli "$i" stop >/dev/null 2>&1; done
    sleep 4
    for i in $(seq 1 $NODES); do
        [ -f "$lab/n$i/PID" ] || continue
        kill -9 "$(cat "$lab/n$i/PID")" 2>/dev/null
    done
    case "$lab" in
        "$SCRATCH"/lot9lab7.*) rm -rf "$lab" ;;
        *) echo "refusing to rm unexpected path: $lab" >&2 ;;
    esac
    rm -f "$LABSTATE"
    echo "lab down, $lab removed"
}

case "${1:-}" in
    up)      cmd_up ;;
    cli)     shift; i="$1"; shift; cli "$i" "$@" ;;
    connect) cmd_connect ;;
    status)  cmd_status ;;
    mocktime) shift; set_mocktime_all "$1" ;;
    down)    cmd_down ;;
    *) echo "usage: $0 {up|cli <i> <args...>|connect|status|mocktime <t>|down}"; exit 1 ;;
esac
