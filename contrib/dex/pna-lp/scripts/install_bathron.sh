#!/bin/bash
# =============================================================================
# install_bathron.sh - Install a BATHRON node for an LP (build from source)
# =============================================================================
#
# Public-safe: builds bathrond/bathron-cli from the public source (no SSH keys,
# no internal fleet endpoints). Falls back to a published release tarball if
# BATHRON_RELEASE_URL is set and the build toolchain is unavailable.
# =============================================================================

set -e
export DEBIAN_FRONTEND=noninteractive

INSTALL_DIR="$HOME/bathron"
DATA_DIR="$HOME/.bathron"
SRC_DIR="$HOME/bathron-src"
PROGRESS_FILE="/tmp/m1_install_progress.txt"

REPO_URL="${BATHRON_REPO_URL:-https://github.com/AdonisPhusis/BATHRON.git}"
# Optional: a published release with prebuilt linux-x86_64 bathrond/bathron-cli.
# Leave empty to always build from source.
RELEASE_URL="${BATHRON_RELEASE_URL:-https://github.com/AdonisPhusis/BATHRON/releases/download/v0.9.0-testnet}"

# Testnet RPC port (migrated to the 2717x family 2026-07-12; was PIVX-derived 51475).
RPC_PORT=27175

log_progress() { echo "$1|$2" > "$PROGRESS_FILE"; echo "[$(date '+%H:%M:%S')] $2"; }

if [ -x "$INSTALL_DIR/bin/bathrond" ]; then
    log_progress "100|Already installed"; exit 0
fi
mkdir -p "$INSTALL_DIR/bin"

# --- Step 1: build dependencies -------------------------------------------
log_progress "10|Installing build dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential libtool autotools-dev automake pkg-config bsdmainutils \
    python3 git curl \
    libssl-dev libevent-dev libboost-all-dev libsodium-dev libzmq3-dev

# --- Step 2: get binaries: build from source (primary) --------------------
build_from_source() {
    log_progress "25|Cloning source ($REPO_URL)..."
    rm -rf "$SRC_DIR"
    git clone --depth 1 "$REPO_URL" "$SRC_DIR"
    cd "$SRC_DIR"
    log_progress "40|Building bathrond (this takes a few minutes)..."
    ./autogen.sh
    ./configure --without-gui --disable-tests --disable-bench
    make -j"$(nproc)"
    cp -f src/bathrond src/bathron-cli "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/"*
    log_progress "65|Built from source"
}

download_release() {
    [ -n "$RELEASE_URL" ] || return 1
    log_progress "40|Downloading release binaries..."
    curl -fsSL "$RELEASE_URL/bathrond"    -o "$INSTALL_DIR/bin/bathrond"    || return 1
    curl -fsSL "$RELEASE_URL/bathron-cli" -o "$INSTALL_DIR/bin/bathron-cli" || return 1
    chmod +x "$INSTALL_DIR/bin/"*
    log_progress "65|Installed from release"
}

if ! build_from_source; then
    log_progress "40|Source build failed — trying release binaries..."
    download_release || { log_progress "100|Error: could not build or download BATHRON binaries"; exit 1; }
fi

# --- Step 3: config -------------------------------------------------------
log_progress "70|Configuring..."
mkdir -p "$DATA_DIR"
RPC_USER="lp$(date +%s | tail -c 5)"
RPC_PASS=$(openssl rand -hex 16)

cat > "$DATA_DIR/bathron.conf" << EOF
# BATHRON Testnet configuration for a PnA LP
testnet=1
server=1
daemon=1

# RPC (local only)
rpcuser=$RPC_USER
rpcpassword=$RPC_PASS
rpcallowip=127.0.0.1
rpcbind=127.0.0.1

# Peers (testnet P2P) — set PUBLIC_SEED to the dedicated public seed host(s).
# TODO-PUBLIC-SEED: the public testnet seeds are provisioned at launch on
# machines dedicated to the public network (never the historical dev/prod fleet).
# Until PUBLIC_SEED is set, no peer is hardcoded (rely on documented seeds).
${PUBLIC_SEED:+addnode=$PUBLIC_SEED}

# Performance
dbcache=256
maxconnections=20
EOF

cat > "$DATA_DIR/.lp_credentials" << EOF
RPC_USER=$RPC_USER
RPC_PASS=$RPC_PASS
RPC_URL=http://127.0.0.1:$RPC_PORT
EOF

# --- Step 4: PATH ---------------------------------------------------------
if ! grep -q "bathron/bin" ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$HOME/bathron/bin:$PATH"' >> ~/.bashrc
fi

log_progress "100|Installation complete!"
echo ""
echo "BATHRON installed."
echo "  Binary: $INSTALL_DIR/bin/bathrond"
echo "  Config: $DATA_DIR/bathron.conf  (testnet RPC on 127.0.0.1:$RPC_PORT)"
echo "  Start:  $INSTALL_DIR/bin/bathrond -testnet"
