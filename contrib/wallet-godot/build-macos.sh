#!/bin/bash
# BATHRON Wallet macOS Builder - Build everything locally, no GitHub Actions
# Usage: ./build-macos.sh [--skip-daemon] [--skip-godot]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/macos-bundle"
APP_BUNDLE="$BUILD_DIR/BATHRON-Wallet.app"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  BATHRON Wallet macOS Builder                                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

# Parse args
SKIP_DAEMON=false
SKIP_GODOT=false
for arg in "$@"; do
    case $arg in
        --skip-daemon) SKIP_DAEMON=true ;;
        --skip-godot) SKIP_GODOT=true ;;
    esac
done

# ==============================================================================
# Step 1: Check dependencies
# ==============================================================================
echo -e "\n${YELLOW}[1/6] Checking dependencies...${NC}"

check_brew() {
    if ! command -v brew &> /dev/null; then
        echo -e "${RED}Homebrew not found. Install from https://brew.sh${NC}"
        exit 1
    fi
}

check_dep() {
    if ! brew list "$1" &> /dev/null; then
        echo -e "${YELLOW}Installing $1...${NC}"
        brew install "$1"
    else
        echo -e "  ✓ $1"
    fi
}

check_brew
check_dep libsodium
check_dep libevent
check_dep zeromq
check_dep boost
check_dep openssl@3
check_dep gmp
check_dep automake
check_dep libtool
check_dep pkg-config

# ==============================================================================
# Step 2: Compile bathrond and bathron-cli
# ==============================================================================
if [ "$SKIP_DAEMON" = false ]; then
    echo -e "\n${YELLOW}[2/6] Compiling bathrond and bathron-cli...${NC}"

    cd "$ROOT_DIR"

    # Set up environment
    export ACLOCAL_PATH="/opt/homebrew/share/aclocal"
    export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:/opt/homebrew/opt/openssl@3/lib/pkgconfig"
    export LDFLAGS="-L/opt/homebrew/lib -L/opt/homebrew/opt/openssl@3/lib"
    export CPPFLAGS="-I/opt/homebrew/include -I/opt/homebrew/opt/openssl@3/include"
    export PATH="/opt/homebrew/opt/libtool/libexec/gnubin:$PATH"

    # Create empty libboost_system.a if needed (header-only in modern boost)
    if [ ! -f /opt/homebrew/lib/libboost_system.a ]; then
        echo "" | clang -x c -c - -o /tmp/empty.o
        ar rcs /opt/homebrew/lib/libboost_system.a /tmp/empty.o 2>/dev/null || \
            sudo ar rcs /opt/homebrew/lib/libboost_system.a /tmp/empty.o
    fi

    if [ ! -f "$ROOT_DIR/src/bathrond" ] || [ "$1" = "--rebuild" ]; then
        ./autogen.sh
        ./configure --without-gui --disable-tests --disable-bench \
            --with-boost=/opt/homebrew --with-boost-libdir=/opt/homebrew/lib \
            LDFLAGS="$LDFLAGS" CPPFLAGS="$CPPFLAGS"
        make -j$(sysctl -n hw.ncpu)
    else
        echo -e "  ✓ bathrond already compiled (use --rebuild to recompile)"
    fi

    if [ ! -f "$ROOT_DIR/src/bathrond" ]; then
        echo -e "${RED}Compilation failed - bathrond not found${NC}"
        exit 1
    fi
    echo -e "  ✓ bathrond compiled"
    echo -e "  ✓ bathron-cli compiled"
else
    echo -e "\n${YELLOW}[2/6] Skipping daemon compilation${NC}"
fi

# ==============================================================================
# Step 3: Check/Download Godot
# ==============================================================================
echo -e "\n${YELLOW}[3/6] Checking Godot...${NC}"

GODOT_APP="/Applications/Godot.app"
GODOT_BIN="$GODOT_APP/Contents/MacOS/Godot"
GODOT_VERSION="4.3-stable"
TEMPLATES_DIR="$HOME/Library/Application Support/Godot/export_templates/4.3.stable"

if [ ! -x "$GODOT_BIN" ]; then
    echo -e "  Downloading Godot $GODOT_VERSION..."
    curl -L -o /tmp/godot.zip "https://github.com/godotengine/godot/releases/download/${GODOT_VERSION}/Godot_v${GODOT_VERSION}_macos.universal.zip"
    unzip -q /tmp/godot.zip -d /tmp/
    sudo mv /tmp/Godot.app "$GODOT_APP"
    rm /tmp/godot.zip
fi
echo -e "  ✓ Godot installed: $($GODOT_BIN --version)"

if [ ! -d "$TEMPLATES_DIR" ]; then
    echo -e "  Downloading export templates..."
    curl -L -o /tmp/templates.tpz "https://github.com/godotengine/godot/releases/download/${GODOT_VERSION}/Godot_v${GODOT_VERSION}_export_templates.tpz"
    mkdir -p "$TEMPLATES_DIR"
    unzip -q /tmp/templates.tpz -d /tmp/templates
    mv /tmp/templates/templates/* "$TEMPLATES_DIR/"
    rm -rf /tmp/templates /tmp/templates.tpz
fi
echo -e "  ✓ Export templates installed"

# ==============================================================================
# Step 4: Export Godot project
# ==============================================================================
if [ "$SKIP_GODOT" = false ]; then
    echo -e "\n${YELLOW}[4/6] Exporting Godot project...${NC}"

    cd "$SCRIPT_DIR"
    mkdir -p export

    # Import project first (generates .godot folder)
    "$GODOT_BIN" --headless --import . 2>&1 || true
    sleep 2

    # Export
    "$GODOT_BIN" --headless --export-release "macOS" "export/BATHRON-Wallet.app" 2>&1 || true

    if [ -d "export/BATHRON-Wallet.app" ]; then
        echo -e "  ✓ Godot export complete"
    else
        echo -e "${RED}  Godot export failed${NC}"
        ls -la export/ || true
        exit 1
    fi
else
    echo -e "\n${YELLOW}[4/6] Skipping Godot export${NC}"
fi

# ==============================================================================
# Step 5: Download Sapling params
# ==============================================================================
echo -e "\n${YELLOW}[5/6] Checking Sapling parameters...${NC}"

PARAMS_DIR="$ROOT_DIR/build/params"
mkdir -p "$PARAMS_DIR"

if [ ! -f "$PARAMS_DIR/sapling-spend.params" ]; then
    echo -e "  Downloading sapling-spend.params (~50MB)..."
    curl -L -o "$PARAMS_DIR/sapling-spend.params" https://download.z.cash/downloads/sapling-spend.params
fi
echo -e "  ✓ sapling-spend.params"

if [ ! -f "$PARAMS_DIR/sapling-output.params" ]; then
    echo -e "  Downloading sapling-output.params..."
    curl -L -o "$PARAMS_DIR/sapling-output.params" https://download.z.cash/downloads/sapling-output.params
fi
echo -e "  ✓ sapling-output.params"

# ==============================================================================
# Step 6: Create final bundle
# ==============================================================================
echo -e "\n${YELLOW}[6/6] Creating app bundle...${NC}"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

GODOT_EXPORT="$SCRIPT_DIR/export/BATHRON-Wallet.app"

if [ -d "$GODOT_EXPORT" ]; then
    echo -e "  Copying Godot export as base..."
    cp -R "$GODOT_EXPORT" "$APP_BUNDLE"

    # Find the Godot executable
    GODOT_EXE=$(find "$APP_BUNDLE/Contents/MacOS" -type f -perm +111 ! -name "*.sh" 2>/dev/null | head -1)
    if [ -n "$GODOT_EXE" ]; then
        GODOT_EXE_NAME=$(basename "$GODOT_EXE")
        echo -e "  Godot executable: $GODOT_EXE_NAME"

        # Rename to .bin (we'll wrap it with launcher)
        mv "$GODOT_EXE" "$APP_BUNDLE/Contents/MacOS/${GODOT_EXE_NAME}.bin"

        # Rename PCK to match
        if [ -f "$APP_BUNDLE/Contents/Resources/BATHRON Wallet.pck" ]; then
            mv "$APP_BUNDLE/Contents/Resources/BATHRON Wallet.pck" "$APP_BUNDLE/Contents/Resources/${GODOT_EXE_NAME}.bin.pck"
        fi
    else
        GODOT_EXE_NAME="BATHRON-Wallet"
    fi
else
    echo -e "  Creating bundle structure..."
    mkdir -p "$APP_BUNDLE/Contents/MacOS"
    mkdir -p "$APP_BUNDLE/Contents/Resources"
    GODOT_EXE_NAME="BATHRON-Wallet"
fi

# Copy daemon binaries
echo -e "  Copying bathrond and bathron-cli..."
cp "$ROOT_DIR/src/bathrond" "$APP_BUNDLE/Contents/MacOS/"
cp "$ROOT_DIR/src/bathron-cli" "$APP_BUNDLE/Contents/MacOS/"
chmod +x "$APP_BUNDLE/Contents/MacOS/bathrond"
chmod +x "$APP_BUNDLE/Contents/MacOS/bathron-cli"

# Bundle dylibs
echo -e "  Bundling dynamic libraries..."
mkdir -p "$APP_BUNDLE/Contents/Frameworks"

DYLIBS=(
    "/opt/homebrew/opt/libsodium/lib/libsodium.dylib"
    "/opt/homebrew/opt/libevent/lib/libevent-2.1.dylib"
    "/opt/homebrew/opt/libevent/lib/libevent_pthreads-2.1.dylib"
    "/opt/homebrew/opt/zeromq/lib/libzmq.5.dylib"
    "/opt/homebrew/opt/boost/lib/libboost_filesystem.dylib"
    "/opt/homebrew/opt/boost/lib/libboost_thread.dylib"
    "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib"
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
)

for lib in "${DYLIBS[@]}"; do
    if [ -f "$lib" ]; then
        cp -L "$lib" "$APP_BUNDLE/Contents/Frameworks/"
        echo -e "    ✓ $(basename $lib)"
    fi
done

# Fix library paths in binaries
echo -e "  Fixing library paths..."
for binary in "$APP_BUNDLE/Contents/MacOS/bathrond" "$APP_BUNDLE/Contents/MacOS/bathron-cli"; do
    otool -L "$binary" | grep "/opt/homebrew" | awk '{print $1}' | while read dep; do
        libname=$(basename "$dep")
        if [ -f "$APP_BUNDLE/Contents/Frameworks/$libname" ]; then
            install_name_tool -change "$dep" "@executable_path/../Frameworks/$libname" "$binary"
        fi
    done
done

# Fix inter-library dependencies
for lib in "$APP_BUNDLE/Contents/Frameworks/"*.dylib; do
    otool -L "$lib" | grep "/opt/homebrew" | awk '{print $1}' | while read dep; do
        libname=$(basename "$dep")
        if [ -f "$APP_BUNDLE/Contents/Frameworks/$libname" ]; then
            install_name_tool -change "$dep" "@executable_path/../Frameworks/$libname" "$lib"
        fi
    done
    install_name_tool -id "@executable_path/../Frameworks/$(basename $lib)" "$lib"
done

# Copy Sapling params
echo -e "  Copying Sapling parameters..."
mkdir -p "$APP_BUNDLE/Contents/Resources/params"
cp "$PARAMS_DIR/"*.params "$APP_BUNDLE/Contents/Resources/params/"

# Create launcher script
echo -e "  Creating launcher script..."
LAUNCHER="$APP_BUNDLE/Contents/MacOS/$GODOT_EXE_NAME"
{
    echo '#!/bin/bash'
    echo 'DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"'
    echo 'RESOURCES="$(dirname "$DIR")/Resources"'
    echo 'MACOS_DATA="$HOME/Library/Application Support/BATHRON"'
    echo 'MACOS_PARAMS="$HOME/Library/Application Support/BATHRONParams"'
    echo ''
    echo '# First-run: create symlink for compatibility'
    echo 'if [ ! -L "$HOME/.bathron" ] && [ ! -d "$HOME/.bathron" ]; then'
    echo '  ln -s "$MACOS_DATA" "$HOME/.bathron"'
    echo 'fi'
    echo ''
    echo '# First-run: install Sapling params'
    echo 'if [ ! -f "$MACOS_PARAMS/sapling-spend.params" ]; then'
    echo '  mkdir -p "$MACOS_PARAMS"'
    echo '  cp "$RESOURCES/params/"*.params "$MACOS_PARAMS/" 2>/dev/null || true'
    echo 'fi'
    echo ''
    echo '# First-run: create config. TODO-PUBLIC-SEED: set PUBLIC_SEED to the'
    echo '# dedicated public testnet seed (provisioned at launch, never the'
    echo '# historical dev/prod fleet). No peer is hardcoded until it is set.'
    echo 'if [ ! -f "$MACOS_DATA/bathron.conf" ]; then'
    echo '  mkdir -p "$MACOS_DATA"'
    echo '  echo "server=1" > "$MACOS_DATA/bathron.conf"'
    echo '  [ -n "$PUBLIC_SEED" ] && echo "addnode=$PUBLIC_SEED" >> "$MACOS_DATA/bathron.conf"'
    echo 'fi'
    echo ''
    echo '# Start daemon if not running'
    echo 'if [ ! -f "$MACOS_DATA/testnet5/.lock" ]; then'
    echo '  "$DIR/bathrond" -testnet -daemon'
    echo '  sleep 3'
    echo 'fi'
    echo ''
    echo '# Launch wallet UI'
    echo "if [ -x \"\$DIR/${GODOT_EXE_NAME}.bin\" ]; then"
    echo "  exec \"\$DIR/${GODOT_EXE_NAME}.bin\" \"\$@\""
    echo 'else'
    echo '  osascript -e '\''display dialog "BATHRON daemon started. Wallet UI not found." buttons {"OK"}'\'''
    echo 'fi'
} > "$LAUNCHER"
chmod +x "$LAUNCHER"

# Create ZIP
echo -e "  Creating ZIP archive..."
cd "$BUILD_DIR"
zip -r -q ../BATHRON-Wallet-macOS-arm64.zip BATHRON-Wallet.app

# Summary
echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Build Complete!                                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "App Bundle: ${YELLOW}$APP_BUNDLE${NC}"
echo -e "ZIP File:   ${YELLOW}$ROOT_DIR/build/BATHRON-Wallet-macOS-arm64.zip${NC}"
echo ""
du -sh "$APP_BUNDLE"
du -sh "$ROOT_DIR/build/BATHRON-Wallet-macOS-arm64.zip"
echo ""
echo -e "To test: ${GREEN}open \"$APP_BUNDLE\"${NC}"
