#!/usr/bin/env bash
# ==============================================================================
# btc_burn_claim_daemon.sh - Auto-claim BTC burns for BATHRON Testnet
# ==============================================================================
#
# This daemon runs alongside btc_header_daemon.sh and:
#   1. Scans BTC Signet blocks for BATHRON burns
#   2. Checks if they're already claimed on BATHRON
#   3. Auto-submits TX_BURN_CLAIM for unclaimed burns
#
# Flow:
#   BTC Signet → [scan for BATHRON] → [check BATHRON DB] → submitburnclaim
#
# Requirements:
#   - bitcoin-cli configured for Signet with txindex=1
#   - bathron-cli configured for testnet
#   - Run on the public seed node (set PUBLIC_SEED_HOST at deployment)
#
# Usage:
#   ./btc_burn_claim_daemon.sh start      # Start daemon in background
#   ./btc_burn_claim_daemon.sh stop       # Stop daemon
#   ./btc_burn_claim_daemon.sh status     # Check status
#   ./btc_burn_claim_daemon.sh once       # Run one scan cycle
#   ./btc_burn_claim_daemon.sh logs       # Tail daemon logs
#
# Files:
#   PID:   /tmp/btc_burn_claim_daemon.pid
#   LOG:   /tmp/btc_burn_claim_daemon.log
#   STATE: /tmp/btc_burn_claim_daemon.state (last scanned height)
#
# ==============================================================================

set -euo pipefail

# Configuration
INTERVAL=300                    # Check every 5 minutes
K_CONFIRMATIONS=6               # Required BTC confirmations (Signet)
PID_FILE="/tmp/btc_burn_claim_daemon.pid"
LOG_FILE="/tmp/btc_burn_claim_daemon.log"
STATE_FILE="/tmp/btc_burn_claim_daemon.state"

# Bitcoin CLI (Signet)
BTC_CLI="${BTC_CLI:-$HOME/bitcoin-27.0/bin/bitcoin-cli}"
BTC_DATADIR="${BTC_DATADIR:-$HOME/.bitcoin-signet}"
BTC_CONF="${BTC_CONF:-$BTC_DATADIR/bitcoin.conf}"
BTC_CMD="$BTC_CLI -datadir=$BTC_DATADIR"

# BATHRON CLI (BATHRON_CMD can be overridden for bootstrap with different datadir)
BATHRON_CLI="${BATHRON_CLI:-$HOME/bathron-cli}"
BATHRON_CMD="${BATHRON_CMD:-$BATHRON_CLI -testnet}"

# BATHRON magic bytes (hex)
# B=42 A=41 T=54 H=48 R=52 O=4f N=4e
BATHRON_MAGIC="42415448524f4e"  # "BATHRON" in hex

# Colors
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
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $*"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${GREEN}[OK]${NC} $*" >&2
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*"
    echo "$msg" >> "$LOG_FILE"
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# ==============================================================================
# Helper Functions (F3 RPCs - persistent, reorg-safe)
# ==============================================================================

get_btc_tip() {
    $BTC_CMD getblockcount 2>/dev/null || echo "-1"
}

# F3: Get last scanned from DB (persistent) with fallback to legacy statefile
get_last_scanned() {
    # Try F3 RPC first (persistent in settlement DB)
    local status=$($BATHRON_CMD getburnscanstatus 2>/dev/null || echo "")
    if [[ -n "$status" ]]; then
        local last_height=$(echo "$status" | jq -r '.last_height // empty' 2>/dev/null)
        if [[ -n "$last_height" && "$last_height" != "null" ]]; then
            echo "$last_height"
            return
        fi
    fi

    # Fallback to legacy statefile (for migration)
    if [[ -f "$STATE_FILE" ]]; then
        log "Using legacy statefile (will migrate to DB)"
        cat "$STATE_FILE"
    else
        # Start from SPV min height (Signet checkpoint)
        echo "286300"  # BTC Signet checkpoint - just before first known burn (286326)
    fi
}

# F3: Save progress to DB (persistent, reorg-safe)
save_last_scanned() {
    local height="$1"
    local hash="$2"

    # Use F3 RPC for persistent storage
    if [[ -n "$hash" ]]; then
        # Gate 2: Verify hash coherence before writing
        # Re-fetch hash from SPV to detect reorgs that happened during scan
        local current_spv_hash=$(get_spv_hash "$height")
        if [[ -n "$current_spv_hash" && "$current_spv_hash" != "$hash" ]]; then
            log_warn "SPV reorg detected at height $height: expected=$hash got=$current_spv_hash"
            log_warn "  Not advancing progress, will retry next cycle"
            return 1
        fi

        local result=$($BATHRON_CMD setburnscanprogress "$height" "$hash" 2>&1)
        if echo "$result" | grep -q '"success".*true'; then
            # Also update legacy statefile during migration period
            echo "$height" > "$STATE_FILE"
            return 0
        else
            log_warn "setburnscanprogress failed: $result"
            # Fallback to legacy statefile
            echo "$height" > "$STATE_FILE"
        fi
    else
        # No hash provided, use legacy only
        echo "$height" > "$STATE_FILE"
    fi
}

# F3: Check if btc_txid is already claimed (clean, minimal RPC)
is_already_claimed() {
    local btc_txid="$1"

    # Use F3 checkburnclaim RPC (simple bool response)
    local result=$($BATHRON_CMD checkburnclaim "$btc_txid" 2>/dev/null || echo "")

    if echo "$result" | jq -e '.exists == true' >/dev/null 2>&1; then
        return 0  # Already claimed
    fi

    return 1  # Not claimed
}

# F3: Get next scan range from core (respects SPV state)
get_scan_range() {
    local max_blocks="${1:-100}"
    $BATHRON_CMD getburnscanrange "$max_blocks" 2>/dev/null || echo ""
}

# Extract BATHRON burns from a block
# Returns: txid|raw_tx|burn_output_index for each burn found
find_burns_in_block() {
    local height="$1"
    local block_hash=$($BTC_CMD getblockhash "$height" 2>/dev/null) || return

    # Get block with full TX data (verbosity=2)
    local block_json=$($BTC_CMD getblock "$block_hash" 2 2>/dev/null) || return

    # Parse TXs and look for BATHRON OP_RETURN
    echo "$block_json" | jq -r '.tx[] | select(.vout[]?.scriptPubKey.asm | startswith("OP_RETURN")) | .txid' 2>/dev/null | while read txid; do
        if [[ -n "$txid" ]]; then
            # Get raw TX and check for BATHRON
            local raw_tx=$($BTC_CMD getrawtransaction "$txid" 2>/dev/null) || continue

            # Check if contains "BATHRON" magic in OP_RETURN
            # 6a = OP_RETURN, 1d = push 29 bytes, then BATHRON (42415448524f4e)
            if echo "$raw_tx" | grep -qi "6a1d42415448524f4e"; then
                echo "$txid"
            fi
        fi
    done
}

# Submit a burn claim to BATHRON
# Uses submitburnclaimproof for automatic merkle proof extraction by BATHRON core.
# Falls back to Python script if that fails.
submit_claim() {
    local btc_txid="$1"
    local height="$2"

    # Get raw TX
    local raw_tx=$($BTC_CMD getrawtransaction "$btc_txid" 2>/dev/null)
    if [[ -z "$raw_tx" ]]; then
        log_error "Failed to get raw TX for $btc_txid"
        return 1
    fi

    # Get CMerkleBlock proof from Bitcoin Core
    local merkleblock=$($BTC_CMD gettxoutproof "[\"$btc_txid\"]" 2>/dev/null)
    if [[ -z "$merkleblock" ]]; then
        log_error "Failed to get merkle proof for $btc_txid"
        return 1
    fi

    log "Submitting claim: btc_txid=$btc_txid"

    # Try the simplified RPC first (BATHRON core parses CMerkleBlock)
    local result=$($BATHRON_CMD submitburnclaimproof "$raw_tx" "$merkleblock" 2>&1)

    if echo "$result" | grep -q '"txid"'; then
        local bathron_txid=$(echo "$result" | jq -r '.txid')
        local btc_height=$(echo "$result" | jq -r '.btc_height')
        log_success "Claim submitted! BATHRON txid: $bathron_txid (BTC height: $btc_height)"
        return 0
    fi

    # Fallback: use Python script to compute merkle proof (more reliable)
    log "  Trying fallback with Python merkle proof..."
    if [[ -f /tmp/compute_merkle.py ]]; then
        local proof_json=$(python3 /tmp/compute_merkle.py "$btc_txid" 2>/dev/null)
        if [[ -n "$proof_json" ]] && echo "$proof_json" | jq -e '.match == true' >/dev/null 2>&1; then
            local tx_index=$(echo "$proof_json" | jq -r '.tx_index')
            local block_hash=$(echo "$proof_json" | jq -r '.block_hash')
            local proof_height=$(echo "$proof_json" | jq -r '.height')
            local proof_array=$(echo "$proof_json" | jq -c '.proof')

            result=$($BATHRON_CMD submitburnclaim "$raw_tx" "$block_hash" "$proof_height" "$proof_array" "$tx_index" 2>&1)

            if echo "$result" | grep -q '"txid"'; then
                local bathron_txid=$(echo "$result" | jq -r '.txid')
                log_success "Claim submitted (fallback)! BATHRON txid: $bathron_txid"
                return 0
            fi
        fi
    fi

    log_error "Claim failed: $result"
    return 1
}

# ==============================================================================
# Main Scan Logic (F3: uses persistent DB state + reorg detection)
# ==============================================================================

# Get full SPV status and parse all needed fields
# Sets globals: SPV_TIP, SPV_SYNCED, SPV_HEADERS_AHEAD
SPV_TIP=0
SPV_SYNCED="false"
SPV_HEADERS_AHEAD=999

fetch_spv_status() {
    local status=$($BATHRON_CMD getbtcheadersstatus 2>/dev/null || echo "")
    if [[ -n "$status" && "$status" != "null" ]]; then
        SPV_TIP=$(echo "$status" | jq -r '.tip_height // 0')
        SPV_HEADERS_AHEAD=$(echo "$status" | jq -r '.headers_ahead // 999')
        # Gate 1: Consider synced if headers_ahead <= 10 (small lag is OK)
        if [[ "$SPV_HEADERS_AHEAD" -le 10 ]]; then
            SPV_SYNCED="true"
        else
            SPV_SYNCED="false"
        fi
    else
        SPV_TIP=0
        SPV_SYNCED="false"
        SPV_HEADERS_AHEAD=999
    fi
}

# Get block hash from LOCAL SPV (not external BTC node)
# This ensures hash is valid for setburnscanprogress validation
get_spv_hash() {
    local height="$1"
    local header=$($BATHRON_CMD getbtcheader "$height" 2>/dev/null || echo "")
    if [[ -n "$header" ]]; then
        echo "$header" | jq -r '.hash // empty'
    fi
}

scan_once() {
    local btc_tip=$(get_btc_tip)
    local last_scanned=$(get_last_scanned)

    if [[ "$btc_tip" == "-1" ]]; then
        log_error "Cannot reach BTC Signet node"
        return 1
    fi

    # Fetch SPV status (sets SPV_TIP, SPV_SYNCED, SPV_HEADERS_AHEAD)
    fetch_spv_status
    if [[ "$SPV_TIP" == "0" ]]; then
        log_warn "SPV not ready (tip=0), waiting for headers..."
        return 0
    fi

    # Gate 1: Don't scan if SPV headers_ahead is too large (publisher lagging)
    if [[ "$SPV_SYNCED" != "true" ]]; then
        log_warn "SPV publisher lagging (tip=$SPV_TIP, headers_ahead=$SPV_HEADERS_AHEAD), waiting..."
        return 0
    fi

    local spv_tip=$SPV_TIP

    # Calculate safe height (with K confirmations) - capped by SPV tip
    local safe_height=$((btc_tip - K_CONFIRMATIONS))

    # CRITICAL: Never scan beyond what local SPV knows
    # setburnscanprogress validates hash against local SPV best chain
    if [[ $safe_height -gt $spv_tip ]]; then
        log "Capping scan to SPV tip (safe=$safe_height, spv_tip=$spv_tip)"
        safe_height=$spv_tip
    fi

    if [[ $safe_height -le $last_scanned ]]; then
        log "No new confirmed blocks to scan (tip=$btc_tip, safe=$safe_height, spv=$spv_tip, last=$last_scanned)"
        return 0
    fi

    log "Scanning blocks $((last_scanned + 1)) to $safe_height (BTC tip=$btc_tip, SPV tip=$spv_tip)"

    local claims_found=0
    local claims_submitted=0
    local last_hash=""

    for height in $(seq $((last_scanned + 1)) $safe_height); do
        # Get block hash from LOCAL SPV (not external BTC node!)
        # This ensures the hash is valid for setburnscanprogress
        local block_hash=$(get_spv_hash "$height")
        if [[ -z "$block_hash" ]]; then
            log_warn "Cannot get SPV hash for height $height, stopping scan"
            break
        fi

        # Find burns in this block (still uses external BTC for TX data)
        local burns=$(find_burns_in_block "$height")

        if [[ -n "$burns" ]]; then
            while read btc_txid; do
                if [[ -n "$btc_txid" ]]; then
                    claims_found=$((claims_found + 1))
                    log "Found BATHRON burn: $btc_txid at height $height"

                    # F3: Check if already claimed (clean RPC)
                    if is_already_claimed "$btc_txid"; then
                        log "  Already claimed, skipping"
                        continue
                    fi

                    # Submit claim
                    if submit_claim "$btc_txid" "$height"; then
                        claims_submitted=$((claims_submitted + 1))
                    fi
                fi
            done <<< "$burns"
        fi

        # F3: Update state with hash from LOCAL SPV (persistent + reorg-safe)
        if ! save_last_scanned "$height" "$block_hash"; then
            log_warn "Stopping scan due to SPV reorg at height $height"
            break
        fi
        last_hash="$block_hash"

        # Progress log every 100 blocks
        if [[ $((height % 100)) -eq 0 ]]; then
            log "  Scanned up to block $height..."
        fi
    done

    log_success "Scan complete: found=$claims_found, submitted=$claims_submitted"
    return 0
}

# ==============================================================================
# Daemon Loop
# ==============================================================================
daemon_loop() {
    log "=========================================="
    log "BTC Burn Claim Daemon starting"
    log "  BTC CLI: $BTC_CMD"
    log "  BATHRON CLI: $BATHRON_CMD"
    log "  Interval: ${INTERVAL}s"
    log "  K confirmations: $K_CONFIRMATIONS"
    log "=========================================="

    # Initial scan
    scan_once || true

    # Main loop
    while true; do
        sleep "$INTERVAL"
        scan_once || true
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

    # Start in background
    nohup bash -c "
        INTERVAL=$INTERVAL
        K_CONFIRMATIONS=$K_CONFIRMATIONS
        LOG_FILE=\"$LOG_FILE\"
        STATE_FILE=\"$STATE_FILE\"
        BTC_CMD=\"$BTC_CMD\"
        BATHRON_CMD=\"$BATHRON_CMD\"
        BATHRON_MAGIC=\"$BATHRON_MAGIC\"
        SPV_TIP=0
        SPV_SYNCED=\"false\"
        SPV_HEADERS_AHEAD=999
        RED='$RED'
        GREEN='$GREEN'
        YELLOW='$YELLOW'
        BLUE='$BLUE'
        NC='$NC'

        $(declare -f log log_success log_warn log_error)
        $(declare -f get_btc_tip get_last_scanned save_last_scanned)
        $(declare -f is_already_claimed find_burns_in_block submit_claim)
        $(declare -f fetch_spv_status get_spv_hash scan_once daemon_loop)

        daemon_loop
    " >> "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        log_success "Daemon started (PID $pid)"
        log "  Log: $LOG_FILE"
        log "  State: $STATE_FILE"
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
    echo "  BTC Burn Claim Daemon Status (F3)"
    echo "======================================"
    echo ""

    # Check daemon process
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "Daemon:       ${GREEN}RUNNING${NC} (PID $pid)"
        else
            echo -e "Daemon:       ${RED}DEAD${NC} (stale PID $pid)"
        fi
    else
        echo -e "Daemon:       ${YELLOW}STOPPED${NC}"
    fi

    # Check BTC node
    local btc_tip=$(get_btc_tip)
    if [[ "$btc_tip" == "-1" ]]; then
        echo -e "BTC Signet:   ${RED}UNREACHABLE${NC}"
    else
        echo -e "BTC Signet:   ${GREEN}OK${NC} (tip=$btc_tip)"
    fi

    # Check BATHRON node
    local bathron_tip=$($BATHRON_CMD getblockcount 2>/dev/null || echo "-1")
    if [[ "$bathron_tip" == "-1" ]]; then
        echo -e "BATHRON Node: ${RED}UNREACHABLE${NC}"
    else
        echo -e "BATHRON Node: ${GREEN}OK${NC} (tip=$bathron_tip)"
    fi

    # Check SPV headers (LOCAL - this is what limits our scan)
    fetch_spv_status
    local spv_tip=$SPV_TIP
    if [[ "$spv_tip" == "0" ]]; then
        echo -e "SPV Headers:  ${RED}NOT READY${NC}"
    else
        if [[ "$btc_tip" != "-1" ]]; then
            local spv_gap=$((btc_tip - spv_tip))
            local sync_status=""
            if [[ "$SPV_SYNCED" == "true" ]]; then
                sync_status=", synced"
            else
                sync_status=", ahead=$SPV_HEADERS_AHEAD"
            fi
            if [[ $spv_gap -le 6 ]]; then
                echo -e "SPV Headers:  ${GREEN}OK${NC} (tip=$spv_tip, gap=$spv_gap$sync_status)"
            else
                echo -e "SPV Headers:  ${YELLOW}BEHIND${NC} (tip=$spv_tip, gap=$spv_gap$sync_status)"
            fi
        else
            echo -e "SPV Headers:  ${GREEN}OK${NC} (tip=$spv_tip)"
        fi
    fi

    # F3: Get burnscan status from core (persistent DB)
    echo ""
    echo "--- F3 Burnscan Status (DB) ---"
    local f3_status=$($BATHRON_CMD getburnscanstatus 2>/dev/null || echo "")
    if [[ -n "$f3_status" ]]; then
        local f3_height=$(echo "$f3_status" | jq -r '.last_height // "not_set"')
        local f3_hash=$(echo "$f3_status" | jq -r '.last_hash // "not_set"' | head -c 16)
        local f3_behind=$(echo "$f3_status" | jq -r '.blocks_behind // 0')
        local f3_synced=$(echo "$f3_status" | jq -r '.synced // false')
        local f3_spv_tip=$(echo "$f3_status" | jq -r '.spv_tip_height // 0')

        echo -e "DB Height:    $f3_height"
        echo -e "DB Hash:      ${f3_hash}..."
        echo -e "SPV Tip:      $f3_spv_tip"
        if [[ "$f3_synced" == "true" ]]; then
            echo -e "Status:       ${GREEN}SYNCED${NC}"
        else
            echo -e "Status:       ${YELLOW}$f3_behind blocks behind${NC}"
        fi
    else
        echo -e "Status:       ${YELLOW}RPC unavailable (old core?)${NC}"
    fi

    # Legacy statefile (for comparison during migration)
    echo ""
    echo "--- Legacy Statefile ---"
    if [[ -f "$STATE_FILE" ]]; then
        local legacy_height=$(cat "$STATE_FILE")
        echo -e "File Height:  $legacy_height"
    else
        echo -e "File:         ${YELLOW}not found${NC}"
    fi

    # Scan status (combined view)
    echo ""
    echo "--- Scan Progress ---"
    local last_scanned=$(get_last_scanned)
    if [[ "$btc_tip" != "-1" ]]; then
        local safe_height=$((btc_tip - K_CONFIRMATIONS))
        # Cap by SPV tip (can't scan beyond what local SPV knows)
        if [[ "$spv_tip" != "0" && $safe_height -gt $spv_tip ]]; then
            safe_height=$spv_tip
        fi
        local behind=$((safe_height - last_scanned))
        if [[ $behind -le 0 ]]; then
            echo -e "Scan:         ${GREEN}UP TO DATE${NC} (last=$last_scanned)"
        else
            echo -e "Scan:         ${YELLOW}$behind blocks behind${NC} (last=$last_scanned, safe=$safe_height)"
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
    log "Running single scan cycle..."
    scan_once
}

cmd_logs() {
    if [[ -f "$LOG_FILE" ]]; then
        tail -f "$LOG_FILE"
    else
        log_error "Log file not found: $LOG_FILE"
    fi
}

cmd_bootstrap() {
    # Bootstrap mode: aggressive scanning for genesis setup
    # Runs continuously with short interval until all burns found
    log "=========================================="
    log "Bootstrap mode - aggressive burn discovery"
    log "=========================================="

    local bootstrap_interval=5  # Short interval for bootstrap
    local max_iterations=600    # Max ~50 minutes

    for ((i=1; i<=max_iterations; i++)); do
        scan_once || true

        # Check if we're caught up
        local btc_tip=$(get_btc_tip)
        local scan_status=$($BATHRON_CMD getburnscanstatus 2>/dev/null || echo "{}")
        local last_scanned=$(echo "$scan_status" | jq -r '.last_height // 0')
        local claims=$($BATHRON_CMD listburnclaims 2>/dev/null | jq 'length' 2>/dev/null || echo 0)

        # Done when scan reached near BTC tip
        if [[ $last_scanned -ge $((btc_tip - 10)) ]]; then
            log_success "Bootstrap scan complete: scanned to $last_scanned, $claims burns found"
            return 0
        fi

        # Progress every 10 iterations
        if [[ $((i % 10)) -eq 0 ]]; then
            log "Bootstrap progress: scan=$last_scanned, claims=$claims, iteration=$i"
        fi

        sleep "$bootstrap_interval"
    done

    log_warn "Bootstrap timeout after $max_iterations iterations"
}

cmd_help() {
    cat <<EOF
BTC Burn Claim Daemon for BATHRON Testnet (F3 Migration)

Auto-claims BATHRON BTC burns on BATHRON network.

Usage:
  $0 start       Start daemon in background
  $0 stop        Stop daemon
  $0 status      Check daemon status (shows F3 DB + legacy)
  $0 once        Run one scan cycle (testing)
  $0 bootstrap   Aggressive scan mode for genesis setup
  $0 logs        Tail daemon logs
  $0 help        Show this help

Files:
  PID:   $PID_FILE
  LOG:   $LOG_FILE
  STATE: $STATE_FILE (legacy, migrating to DB)

F3 RPCs (persistent, reorg-safe):
  getburnscanstatus      Get scan progress from settlement DB
  setburnscanprogress    Save progress (height + hash) to DB
  checkburnclaim         Check if burn already claimed (bool)
  getburnscanrange       Get next batch range to scan

Environment:
  BTC_CLI       Path to bitcoin-cli (default: ~/bitcoin-27.0/bin/bitcoin-cli)
  BTC_CONF      Bitcoin config file (default: ~/.bitcoin-signet/bitcoin.conf)
  BATHRON_CLI   Path to bathron-cli (default: ~/bathron-cli)
  INTERVAL      Scan interval in seconds (default: 300)

How it works:
  1. Reads progress from F3 DB (fallback: legacy statefile)
  2. Scans BTC Signet blocks for BATHRON OP_RETURN burns
  3. Waits for K=$K_CONFIRMATIONS confirmations
  4. Checks if burn is already claimed (checkburnclaim RPC)
  5. Submits TX_BURN_CLAIM for unclaimed burns (fee-free!)
  6. Saves progress to F3 DB with block hash (reorg detection)

Anti-spam:
  - TX_BURN_CLAIM has 0 fees (no cost to claim)
  - Duplicate claims rejected by mempool
  - MIN_BURN_SATS = 1000 (dust protection)
  - MAX_BURN_CLAIMS_PER_BLOCK = 50

Architecture:
  Core = primitives (RPCs) ; Tools = scripts consuming primitives.
  This daemon is a "permissionless tool" using F3 core RPCs.

Note: Burns are credited to the address encoded in BATHRON metadata,
not to whoever submits the claim. Anyone can claim for anyone!
EOF
}

# ==============================================================================
# Main
# ==============================================================================
CMD="${1:-help}"

case "$CMD" in
    start)      cmd_start;;
    stop)       cmd_stop;;
    status)     cmd_status;;
    once)       cmd_once;;
    bootstrap)  cmd_bootstrap;;
    logs)       cmd_logs;;
    help|-h|--help) cmd_help;;
    *)          log_error "Unknown command: $CMD"; cmd_help; exit 1;;
esac
