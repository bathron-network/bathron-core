#!/bin/bash
#
# burn_signet.sh - Create and send a BTC burn transaction on Signet
#
# Usage: ./burn_signet.sh <bathron_address> <amount_sats>
#
# Example: ./burn_signet.sh yJYD2bfYYBe6qAojSzMKX949H7QoQifNAo 10000
#
# Burn Format (BP08 compliant):
#   Output[0]: OP_RETURN "BATHRON" + version + network + hash160 (metadata, 0 sats)
#              = 7 bytes + 1 byte + 1 byte + 20 bytes = 29 bytes total
#   Output[1]: P2WSH(OP_FALSE) (X sats - provably unspendable, STANDARD tx)
#
# P2WSH(OP_FALSE) = SHA256(0x00) - the script always fails, coins destroyed forever.
# This is a standard transaction that Bitcoin Core will relay without issues.
#

set -e

# Config - detect BTC CLI location
if [ -f "/home/ubuntu/bitcoin-27.0/bin/bitcoin-cli" ]; then
    BTCDIR="/home/ubuntu/.bitcoin-signet"
    BTCCLI="/home/ubuntu/bitcoin-27.0/bin/bitcoin-cli -datadir=$BTCDIR"
elif [ -f "/home/ubuntu/bitcoin/bin/bitcoin-cli" ]; then
    BTCDIR="/home/ubuntu/.bitcoin-signet"
    BTCCLI="/home/ubuntu/bitcoin/bin/bitcoin-cli -signet -datadir=$BTCDIR"
elif [ -f "/home/ubuntu/BATHRON/BTCTESTNET/bitcoin-27.0/bin/bitcoin-cli" ]; then
    BTCDIR="/home/ubuntu/BATHRON/BTCTESTNET/data"
    BTCCLI="/home/ubuntu/BATHRON/BTCTESTNET/bitcoin-27.0/bin/bitcoin-cli -datadir=$BTCDIR"
else
    echo "Error: bitcoin-cli not found"
    exit 1
fi

# P2WSH(OP_FALSE) Burn Address - Provably Unspendable
# Script: OP_FALSE (0x00) - always fails, coins are destroyed forever
# SHA256(0x00) = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
# This is a STANDARD transaction - Bitcoin Core will relay it
BURN_ADDR="tb1qdc6qh88lkdaf3899gnntk7q293ufq8flkvmnsa59zx3sv9a05qwsdh5h09"
BURN_SCRIPT_HASH="6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       BATHRON Signet Burn Script             ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Burn Address: $BURN_ADDR${NC}"
echo -e "${BLUE}P2WSH(OP_FALSE) - provably unspendable, standard Bitcoin tx${NC}"
echo ""

# Parse args (support --yes flag)
AUTO_CONFIRM=false
POSITIONAL_ARGS=()

for arg in "$@"; do
    case $arg in
        --yes|-y)
            AUTO_CONFIRM=true
            ;;
        *)
            POSITIONAL_ARGS+=("$arg")
            ;;
    esac
done

if [ "${#POSITIONAL_ARGS[@]}" -lt 2 ]; then
    echo -e "${RED}Usage: $0 <bathron_address> <amount_sats> [--yes]${NC}"
    echo ""
    echo "Example: $0 yJYD2bfYYBe6qAojSzMKX949H7QoQifNAo 10000"
    echo "         $0 yJYD2bfYYBe6qAojSzMKX949H7QoQifNAo 10000 --yes  # Skip confirmation"
    echo ""
    echo "This will burn <amount_sats> sBTC and create a claim for <bathron_address>"
    exit 1
fi

BATHRON_ADDR="${POSITIONAL_ARGS[0]}"
BURN_SATS="${POSITIONAL_ARGS[1]}"

# Minimum burn check
if [ "$BURN_SATS" -lt 1000 ]; then
    echo -e "${RED}Error: Minimum burn is 1000 sats${NC}"
    exit 1
fi

# Step 1: Convert BATHRON address to hash160
echo -e "${YELLOW}[1/5] Converting BATHRON address to hash160...${NC}"

HASH160=$(python3 << EOF
import hashlib

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_decode(s):
    n = 0
    for c in s:
        n = n * 58 + ALPHABET.index(c)
    h = '%050x' % n
    return bytes.fromhex(h)

def base58check_decode(addr):
    decoded = base58_decode(addr)
    payload = decoded[:-4]
    checksum = decoded[-4:]
    expected_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected_checksum:
        raise ValueError(f"Invalid checksum for address {addr}")
    return payload[1:].hex()

try:
    result = base58check_decode("$BATHRON_ADDR")
    print(result)
except Exception as e:
    print(f"ERROR:{e}", file=__import__('sys').stderr)
    exit(1)
EOF
)

if [ -z "$HASH160" ] || [ ${#HASH160} -ne 40 ]; then
    echo -e "${RED}Error: Invalid BATHRON address${NC}"
    exit 1
fi

echo "  BATHRON Address: $BATHRON_ADDR"
echo "  Hash160:      $HASH160"

# Step 2: Build OP_RETURN metadata
echo ""
echo -e "${YELLOW}[2/5] Building metadata...${NC}"

MAGIC="42415448524f4e"    # "BATHRON" in hex (7 bytes)
VERSION="01"              # Protocol version (1 byte)
NETWORK="54"              # 'T' = testnet (0x54 = ASCII 'T')
METADATA="${MAGIC}${VERSION}${NETWORK}${HASH160}"
echo "  Format: BATHRON + v1 + network(testnet) + hash160"
echo "  Hex: $METADATA (29 bytes)"

# Step 3: Check wallet balance
echo ""
echo -e "${YELLOW}[3/5] Checking wallet balance...${NC}"

# Load wallet if needed (try bathronburn first, then burn_test)
WALLET_NAME=""
for w in bathronburn burn_test fake_user test; do
    if $BTCCLI loadwallet "$w" 2>/dev/null || $BTCCLI -rpcwallet="$w" getbalance &>/dev/null; then
        WALLET_NAME="$w"
        break
    fi
done
if [ -z "$WALLET_NAME" ]; then
    echo -e "${RED}Error: No wallet found (tried: bathronburn, burn_test, fake_user, test)${NC}"
    exit 1
fi
echo "  Using wallet: $WALLET_NAME"

# Unlock any UTXOs locked by previous interrupted runs
# (fundrawtransaction uses lockUnspents:true which leaves UTXOs locked if script fails)
LOCKED_COUNT=$($BTCCLI -rpcwallet=$WALLET_NAME listlockunspent 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
if [ "$LOCKED_COUNT" -gt 0 ]; then
    $BTCCLI -rpcwallet=$WALLET_NAME lockunspent true "[]" >/dev/null 2>&1 || true
    echo "  (Unlocked $LOCKED_COUNT previously locked UTXOs)"
fi

BALANCE=$($BTCCLI -rpcwallet=$WALLET_NAME getbalance 2>/dev/null || echo "0")
BALANCE_SATS=$(echo "$BALANCE * 100000000" | bc | cut -d. -f1)
echo "  Balance: $BALANCE BTC ($BALANCE_SATS sats)"

# Need burn amount + fee
FEE_SATS=500
NEEDED_SATS=$((BURN_SATS + FEE_SATS + 1000))  # Extra buffer

if [ "$BALANCE_SATS" -lt "$NEEDED_SATS" ]; then
    echo -e "${RED}Error: Insufficient balance. Need at least $NEEDED_SATS sats${NC}"
    echo ""
    echo "Get signet coins from:"
    echo "  - https://signetfaucet.com/"
    echo "  - https://alt.signetfaucet.com/"
    echo ""
    FAUCET_ADDR=$($BTCCLI -rpcwallet=$WALLET_NAME getnewaddress "faucet" "bech32")
    echo "Your faucet address: $FAUCET_ADDR"
    exit 1
fi

# Step 4: Create the burn transaction
echo ""
echo -e "${YELLOW}[4/5] Creating burn transaction...${NC}"

# Convert burn amount to BTC
BURN_BTC=$(echo "scale=8; $BURN_SATS / 100000000" | bc | sed 's/^\./0./')

# Get change address
CHANGE_ADDR=$($BTCCLI -rpcwallet=$WALLET_NAME getrawchangeaddress "bech32")

echo "  Burn amount: $BURN_SATS sats ($BURN_BTC BTC)"
echo "  Burn to:     $BURN_ADDR"
echo "  Metadata:    OP_RETURN $METADATA"
echo "  Change to:   $CHANGE_ADDR"

# Create transaction with:
# - Output 0: OP_RETURN metadata (0 sats)
# - Output 1: Burn address (burn amount)
# - Output 2: Change (auto-calculated)

# Using fundrawtransaction to handle coin selection
OUTPUTS="{\"data\":\"$METADATA\",\"$BURN_ADDR\":$BURN_BTC}"

# Create raw tx (empty inputs, will be funded)
RAW_TX=$($BTCCLI -rpcwallet=$WALLET_NAME createrawtransaction "[]" "$OUTPUTS")

# Fund the transaction (adds inputs and change)
# NOTE: fee_rate is sat/vB (integer), feeRate is BTC/kvB (decimal)
# changePosition=2 ensures: [0]=OP_RETURN, [1]=burn, [2]=change (BP08 compliant)
FUNDED=$($BTCCLI -rpcwallet=$WALLET_NAME fundrawtransaction "$RAW_TX" "{\"changeAddress\":\"$CHANGE_ADDR\",\"changePosition\":2,\"lockUnspents\":true,\"fee_rate\":10}")
FUNDED_TX=$(echo "$FUNDED" | python3 -c "import json,sys; print(json.load(sys.stdin)['hex'])")
FEE=$(echo "$FUNDED" | python3 -c "import json,sys; print(json.load(sys.stdin)['fee'])")

echo "  Fee: $FEE BTC"

# Step 5: Sign and broadcast
echo ""
echo -e "${YELLOW}[5/5] Signing and broadcasting...${NC}"

SIGNED=$($BTCCLI -rpcwallet=$WALLET_NAME signrawtransactionwithwallet "$FUNDED_TX")
SIGNED_TX=$(echo "$SIGNED" | python3 -c "import json,sys; print(json.load(sys.stdin)['hex'])")
COMPLETE=$(echo "$SIGNED" | python3 -c "import json,sys; print(json.load(sys.stdin)['complete'])")

if [ "$COMPLETE" != "True" ]; then
    echo -e "${RED}Error: Transaction signing failed${NC}"
    exit 1
fi

# Decode and show
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                  Transaction Details                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"

# BP08 Compliance Verification and Display (hardened version)
# - Uses env vars instead of JSON injection (safer)
# - Verifies exact METADATA payload (not just size)
echo ""
echo -e "${YELLOW}Verifying BP08 compliance...${NC}"

export TX_JSON="$($BTCCLI decoderawtransaction "$SIGNED_TX")"
export EXPECTED_METADATA="$METADATA"
export EXPECTED_BURN_ADDR="$BURN_ADDR"

python3 << 'PY'
import json, os, sys

tx = json.loads(os.environ["TX_JSON"])
burn_addr = os.environ["EXPECTED_BURN_ADDR"]
expected_metadata = os.environ["EXPECTED_METADATA"].lower()

# Verify exactly 1 burn output
burns = sum(1 for v in tx["vout"] if v["scriptPubKey"].get("address") == burn_addr)
if burns != 1:
    print(f"  ERROR: Expected exactly 1 burn output, got {burns}")
    raise SystemExit(1)
print("  [OK] Exactly 1 burn output (P2WSH)")

# Verify exactly 1 OP_RETURN output
nulldata = [v for v in tx["vout"] if v["scriptPubKey"].get("type") == "nulldata"]
if len(nulldata) != 1:
    print(f"  ERROR: Expected exactly 1 OP_RETURN output, got {len(nulldata)}")
    raise SystemExit(1)

# Extract and verify OP_RETURN payload
asm = nulldata[0]["scriptPubKey"].get("asm", "")
parts = asm.split()
if len(parts) < 2:
    print("  ERROR: OP_RETURN asm missing payload")
    raise SystemExit(1)

hex_data = parts[1].lower()
byte_len = len(hex_data) // 2

# Check size (29 bytes for BATHRON format)
if byte_len != 29:
    print(f"  ERROR: OP_RETURN is {byte_len} bytes, expected 29")
    raise SystemExit(1)
print("  [OK] OP_RETURN metadata is exactly 29 bytes")

# Check exact payload matches expected METADATA
if hex_data != expected_metadata:
    print("  ERROR: OP_RETURN payload mismatch")
    print(f"    expected: {expected_metadata}")
    print(f"    got:      {hex_data}")
    raise SystemExit(1)
print("  [OK] OP_RETURN payload matches expected METADATA")

print("  BP08 compliance verified!")
print()
print(f"  TXID:    {tx['txid']}")
print(f"  Size:    {tx['vsize']} vbytes")
print("  Outputs:")
for i, out in enumerate(tx["vout"]):
    spk = out["scriptPubKey"]
    t = spk.get("type", "unknown")
    sats = int(round(out["value"] * 100000000))
    if t == "nulldata":
        print(f"    [{i}] METADATA: 0 sats (OP_RETURN)")
    else:
        addr = spk.get("address", "(no address)")
        if addr == burn_addr:
            print(f"    [{i}] BURN:     {sats} sats -> {addr}")
        else:
            print(f"    [{i}] CHANGE:   {sats} sats -> {addr}")
PY

echo ""
if [ "$AUTO_CONFIRM" = true ]; then
    echo -e "${YELLOW}Auto-confirm enabled, broadcasting...${NC}"
    REPLY="y"
else
    echo -e "${YELLOW}Broadcast transaction? (y/N)${NC}"
    read -n 1 -r
    echo ""
fi

if [[ $REPLY =~ ^[Yy]$ ]]; then
    TXID=$($BTCCLI -rpcwallet=$WALLET_NAME sendrawtransaction "$SIGNED_TX")

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  BURN SUCCESSFUL!                         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  TXID: $TXID"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Wait for 6 confirmations (~1 hour)"
    echo "     Check: $BTCCLI gettransaction $TXID | grep confirmations"
    echo ""
    echo "  2. Get block info and merkle proof:"
    echo "     BLOCK=\$($BTCCLI gettransaction $TXID | python3 -c \"import json,sys; print(json.load(sys.stdin)['blockhash'])\")"
    echo "     PROOF=\$($BTCCLI gettxoutproof '[\"$TXID\"]')"
    echo ""
    echo "  3. Submit claim to BATHRON testnet:"
    echo "     bathron-cli -testnet submitburnclaim <raw_tx> <block_hash> <height> <proof> <index>"
    echo ""

    # Save burn info for later
    BURN_INFO_DIR="$(dirname $BTCDIR)/burns"
    BURN_INFO_FILE="${BURN_INFO_DIR}/${TXID}.json"
    mkdir -p "$BURN_INFO_DIR"
    cat > "$BURN_INFO_FILE" << JSONEOF
{
  "txid": "$TXID",
  "bathron_address": "$BATHRON_ADDR",
  "hash160": "$HASH160",
  "burn_sats": $BURN_SATS,
  "burn_address": "$BURN_ADDR",
  "timestamp": "$(date -Iseconds)",
  "status": "pending_confirmations"
}
JSONEOF
    echo "  Burn info saved to: $BURN_INFO_FILE"

else
    echo ""
    echo "Transaction NOT broadcast."
    echo ""
    echo "Signed TX (for manual broadcast):"
    echo "$SIGNED_TX"
fi
