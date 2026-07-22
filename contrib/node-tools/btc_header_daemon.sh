#!/usr/bin/env bash
# ==============================================================================
# btc_header_daemon.sh - BTC Header Sync Daemon for BATHRON Testnet
# ==============================================================================
#
# This daemon runs on the Seed node and:
#   1. Polls BTC Signet for new blocks (every 2 minutes)
#   2. Fetches missing headers from BTC node
#   3. Submits them to BATHRON btcspv via submitbtcheaders RPC
#   4. The auto-publisher (btcheaders_publisher.cpp) then creates TX_BTC_HEADERS
#
# Flow:
#   BTC Signet → [this daemon] → submitbtcheaders → btcspv
#                                                      ↓
#                              auto-publisher (60s) → TX_BTC_HEADERS → btcheadersdb
#
# Requirements:
#   - bitcoin-cli configured for Signet (~/.bitcoin-signet/bitcoin.conf)
#   - bathron-cli configured for testnet
#   - Run on the public seed node (set PUBLIC_SEED_HOST at deployment)
#
# Usage:
#   ./btc_header_daemon.sh start      # Start daemon in background
#   ./btc_header_daemon.sh stop       # Stop daemon
#   ./btc_header_daemon.sh status     # Check if running + sync status
#   ./btc_header_daemon.sh once       # Run one sync cycle (for testing)
#   ./btc_header_daemon.sh logs       # Tail daemon logs
#
# Files:
#   PID:  /tmp/btc_header_daemon.pid
#   LOG:  /tmp/btc_header_daemon.log
#
# ==============================================================================

set -euo pipefail

# Configuration
INTERVAL=120                    # Check every 2 minutes
MAX_HEADERS_PER_BATCH=100       # Max headers per submitbtcheaders call
PID_FILE="/tmp/btc_header_daemon.pid"
LOG_FILE="/tmp/btc_header_daemon.log"

# Bitcoin CLI (Signet)
BTC_CLI="${BTC_CLI:-$HOME/bitcoin-27.0/bin/bitcoin-cli}"
BTC_CONF="${BTC_CONF:-$HOME/.bitcoin-signet/bitcoin.conf}"
BTC_CMD="$BTC_CLI -conf=$BTC_CONF"

# BATHRON CLI
BATHRON_CLI="${BATHRON_CLI:-$HOME/bathron-cli}"
BATHRON_CMD="$BATHRON_CLI -testnet"

# Colors (for terminal output)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==============================================================================
# Logging
# ==============================================================================
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $*"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${RED}[ERROR]${NC} $*"
}

# ==============================================================================
# Helper Functions
# ==============================================================================

# Get BTC Signet tip height
get_btc_tip() {
    $BTC_CMD getblockcount 2>/dev/null || echo "-1"
}

# Get BATHRON btcspv tip height
get_spv_tip() {
    $BATHRON_CMD getbtcsyncstatus 2>/dev/null | grep -o '"tip_height": *[0-9]*' | grep -o '[0-9]*' || echo "-1"
}

# Get BATHRON btcheadersdb tip (on-chain consensus)
get_headers_tip() {
    $BATHRON_CMD getbtcheadersstatus 2>/dev/null | grep -o '"tip_height": *[0-9]*' | grep -o '[0-9]*' || echo "-1"
}

# Get raw header hex from BTC at height
get_btc_header_hex() {
    local height="$1"
    local hash=$($BTC_CMD getblockhash "$height" 2>/dev/null) || return 1
    $BTC_CMD getblockheader "$hash" false 2>/dev/null || return 1
}

# Submit headers to BATHRON btcspv
submit_headers() {
    local headers_hex="$1"
    $BATHRON_CMD submitbtcheaders "$headers_hex" 2>/dev/null
}

# ==============================================================================
# Sync Logic
# ==============================================================================
sync_once() {
    # Get current tips
    local btc_tip=$(get_btc_tip)
    local spv_tip=$(get_spv_tip)
    local headers_tip=$(get_headers_tip)

    if [[ "$btc_tip" == "-1" ]]; then
        log_error "Cannot reach BTC Signet node"
        return 1
    fi

    if [[ "$spv_tip" == "-1" ]]; then
        log_error "Cannot reach BATHRON node"
        return 1
    fi

    local diff=$((btc_tip - spv_tip))

    log "BTC=$btc_tip, SPV=$spv_tip, Headers=$headers_tip, diff=$diff"

    if [[ $diff -le 0 ]]; then
        log_success "btcspv is synced with BTC Signet"
        return 0
    fi

    # Calculate how many to fetch
    local to_fetch=$diff
    if [[ $to_fetch -gt $MAX_HEADERS_PER_BATCH ]]; then
        to_fetch=$MAX_HEADERS_PER_BATCH
    fi

    local start_height=$((spv_tip + 1))
    local end_height=$((start_height + to_fetch - 1))

    log "Fetching $to_fetch headers ($start_height to $end_height)..."

    # Fetch headers and concatenate
    local headers_hex=""
    local fetched=0

    for h in $(seq $start_height $end_height); do
        local header=$(get_btc_header_hex "$h")
        if [[ -z "$header" ]]; then
            log_error "Failed to get header at height $h"
            break
        fi
        headers_hex="${headers_hex}${header}"
        fetched=$((fetched + 1))

        # Progress every 20 headers
        if [[ $((fetched % 20)) -eq 0 ]]; then
            log "  Fetched $fetched/$to_fetch headers..."
        fi
    done

    if [[ $fetched -eq 0 ]]; then
        log_error "No headers fetched"
        return 1
    fi

    log "Submitting $fetched headers to btcspv..."

    # Submit to BATHRON
    local result=$(submit_headers "$headers_hex" 2>&1)

    # Check for accepted > 0 (RPC returns accepted/rejected counts)
    local accepted=$(echo "$result" | grep -o '"accepted": *[0-9]*' | grep -o '[0-9]*')
    local rejected=$(echo "$result" | grep -o '"rejected": *[0-9]*' | grep -o '[0-9]*')
    local new_tip=$(echo "$result" | grep -o '"tip_height": *[0-9]*' | grep -o '[0-9]*')

    if [[ -n "$accepted" && "$accepted" -gt 0 && "$rejected" == "0" ]]; then
        log_success "Submitted $accepted headers, new SPV tip: $new_tip"

        # Log remaining
        local new_diff=$((btc_tip - new_tip))
        if [[ $new_diff -gt 0 ]]; then
            log "Still $new_diff headers behind, will sync in next cycle"
        fi
        return 0
    elif [[ -n "$accepted" && "$accepted" -gt 0 ]]; then
        # Some accepted, some rejected
        log_warn "Partial success: accepted=$accepted, rejected=$rejected, tip=$new_tip"
        return 0
    else
        log_error "Submit failed: $result"
        return 1
    fi
}

# ==============================================================================
# Daemon Loop
# ==============================================================================
daemon_loop() {
    log "=========================================="
    log "BTC Header Daemon starting"
    log "  BTC CLI: $BTC_CMD"
    log "  BATHRON CLI: $BATHRON_CMD"
    log "  Interval: ${INTERVAL}s"
    log "  Max headers/batch: $MAX_HEADERS_PER_BATCH"
    log "=========================================="

    # Initial sync
    sync_once || true

    # Main loop
    while true; do
        sleep "$INTERVAL"
        sync_once || true
    done
}

# ==============================================================================
# Commands
# ==============================================================================
cmd_start() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_error "Daemon already running (PID $pid)"
            exit 1
        else
            rm -f "$PID_FILE"
        fi
    fi

    log "Starting daemon..."

    # Verify dependencies
    if ! $BTC_CMD getblockcount >/dev/null 2>&1; then
        log_error "Cannot connect to BTC Signet node"
        log "  Check: $BTC_CMD getblockcount"
        exit 1
    fi

    if ! $BATHRON_CMD getblockcount >/dev/null 2>&1; then
        log_error "Cannot connect to BATHRON node"
        log "  Check: $BATHRON_CMD getblockcount"
        exit 1
    fi

    # Start in background with all necessary variables and functions
    nohup bash -c "
        # Variables
        INTERVAL=$INTERVAL
        MAX_HEADERS_PER_BATCH=$MAX_HEADERS_PER_BATCH
        LOG_FILE='$LOG_FILE'
        BTC_CMD='$BTC_CMD'
        BATHRON_CMD='$BATHRON_CMD'
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        NC='\033[0m'

        # Functions
        $(declare -f log log_success log_warn log_error get_btc_tip get_spv_tip get_headers_tip get_btc_header_hex submit_headers sync_once daemon_loop)

        # Run daemon
        daemon_loop
    " >> "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        log_success "Daemon started (PID $pid)"
        log "  Log: $LOG_FILE"
        log "  PID: $PID_FILE"
    else
        log_error "Daemon failed to start, check $LOG_FILE"
        exit 1
    fi
}

cmd_stop() {
    if [[ ! -f "$PID_FILE" ]]; then
        log_warn "PID file not found, daemon may not be running"
        return 0
    fi

    local pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        log "Stopping daemon (PID $pid)..."
        kill "$pid"
        sleep 2
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Daemon still running, sending SIGKILL..."
            kill -9 "$pid"
        fi
        rm -f "$PID_FILE"
        log_success "Daemon stopped"
    else
        log_warn "Daemon not running (stale PID file)"
        rm -f "$PID_FILE"
    fi
}

cmd_status() {
    echo ""
    echo "======================================"
    echo "  BTC Header Daemon Status"
    echo "======================================"
    echo ""

    # Check daemon process
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "Daemon:     ${GREEN}RUNNING${NC} (PID $pid)"
        else
            echo -e "Daemon:     ${RED}DEAD${NC} (stale PID $pid)"
        fi
    else
        echo -e "Daemon:     ${YELLOW}STOPPED${NC}"
    fi

    # Check BTC node
    local btc_tip=$(get_btc_tip)
    if [[ "$btc_tip" == "-1" ]]; then
        echo -e "BTC Signet: ${RED}UNREACHABLE${NC}"
    else
        echo -e "BTC Signet: ${GREEN}OK${NC} (tip=$btc_tip)"
    fi

    # Check BATHRON node
    local spv_tip=$(get_spv_tip)
    local headers_tip=$(get_headers_tip)
    if [[ "$spv_tip" == "-1" ]]; then
        echo -e "BATHRON SPV:   ${RED}UNREACHABLE${NC}"
    else
        echo -e "BATHRON SPV:   ${GREEN}OK${NC} (tip=$spv_tip)"
        echo -e "BATHRON Chain: tip=$headers_tip (on-chain consensus)"
    fi

    # Sync status
    if [[ "$btc_tip" != "-1" && "$spv_tip" != "-1" ]]; then
        local diff=$((btc_tip - spv_tip))
        if [[ $diff -le 0 ]]; then
            echo -e "Sync:       ${GREEN}SYNCED${NC}"
        elif [[ $diff -lt 10 ]]; then
            echo -e "Sync:       ${YELLOW}$diff blocks behind${NC}"
        else
            echo -e "Sync:       ${RED}$diff blocks behind${NC}"
        fi
    fi

    echo ""

    # Last log entries
    if [[ -f "$LOG_FILE" ]]; then
        echo "Last 5 log entries:"
        tail -5 "$LOG_FILE" | sed 's/^/  /'
    fi
    echo ""
}

cmd_once() {
    log "Running single sync cycle..."
    sync_once
}

cmd_logs() {
    if [[ -f "$LOG_FILE" ]]; then
        tail -f "$LOG_FILE"
    else
        log_error "Log file not found: $LOG_FILE"
    fi
}

cmd_help() {
    cat <<EOF
BTC Header Daemon for BATHRON Testnet

Syncs BTC Signet headers to BATHRON btcspv, enabling TX_BTC_HEADERS publishing.

Usage:
  $0 start       Start daemon in background
  $0 stop        Stop daemon
  $0 status      Check daemon status + sync status
  $0 once        Run one sync cycle (testing)
  $0 logs        Tail daemon logs
  $0 help        Show this help

Files:
  PID:  $PID_FILE
  LOG:  $LOG_FILE

Environment:
  BTC_CLI       Path to bitcoin-cli (default: ~/bitcoin-27.0/bin/bitcoin-cli)
  BTC_CONF      Bitcoin config file (default: ~/.bitcoin-signet/bitcoin.conf)
  BATHRON_CLI      Path to bathron-cli (default: ~/bathron-cli)
  INTERVAL      Sync interval in seconds (default: 120)

Architecture:
  BTC Signet ──[this daemon]──> submitbtcheaders ──> btcspv
                                                        │
                              auto-publisher (60s) <────┘
                                      │
                                      v
                             TX_BTC_HEADERS (on-chain)
                                      │
                                      v
                              btcheadersdb (all nodes)

Limits:
  - Max 100 headers per submitbtcheaders call
  - Auto-publisher creates TX_BTC_HEADERS every 60s
  - Max 1 TX_BTC_HEADERS per BATHRON block
  - Max 100 BTC headers per TX_BTC_HEADERS
EOF
}

# ==============================================================================
# Main
# ==============================================================================
CMD="${1:-help}"

case "$CMD" in
    start)  cmd_start;;
    stop)   cmd_stop;;
    status) cmd_status;;
    once)   cmd_once;;
    logs)   cmd_logs;;
    help|-h|--help) cmd_help;;
    *)      log_error "Unknown command: $CMD"; cmd_help; exit 1;;
esac
