#!/bin/bash
# Create BATHRON Wallet macOS .app bundle
# Combines Godot wallet + bathrond daemon into a single distributable app

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WALLET_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build/macos-bundle"
APP_NAME="BATHRON-Wallet"
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ============================================================================
# FUNCTIONS
# ============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for Godot
    if ! command -v godot &> /dev/null; then
        # Try common macOS paths
        if [ -f "/Applications/Godot.app/Contents/MacOS/Godot" ]; then
            GODOT="/Applications/Godot.app/Contents/MacOS/Godot"
        elif [ -f "$HOME/Applications/Godot.app/Contents/MacOS/Godot" ]; then
            GODOT="$HOME/Applications/Godot.app/Contents/MacOS/Godot"
        else
            log_error "Godot not found. Install Godot 4.x or set GODOT env var."
            exit 1
        fi
    else
        GODOT="godot"
    fi

    log_info "Using Godot: $GODOT"

    # Check for bathrond binary
    if [ ! -f "${PROJECT_ROOT}/src/bathrond" ]; then
        log_error "bathrond not found. Build it first with: make"
        exit 1
    fi

    # Check for bathron-cli binary
    if [ ! -f "${PROJECT_ROOT}/src/bathron-cli" ]; then
        log_error "bathron-cli not found. Build it first with: make"
        exit 1
    fi
}

create_bundle_structure() {
    log_info "Creating bundle structure..."

    rm -rf "$APP_BUNDLE"
    mkdir -p "$APP_BUNDLE/Contents/MacOS"
    mkdir -p "$APP_BUNDLE/Contents/Resources"
    mkdir -p "$APP_BUNDLE/Contents/Frameworks"
}

create_info_plist() {
    log_info "Creating Info.plist..."

    cat > "$APP_BUNDLE/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>BATHRON-Wallet</string>
    <key>CFBundleIconFile</key>
    <string>icon.icns</string>
    <key>CFBundleIdentifier</key>
    <string>org.bathron.wallet</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>BATHRON Wallet</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2025 BATHRON Developers</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.finance</string>
</dict>
</plist>
EOF
}

export_godot_project() {
    log_info "Exporting Godot project for macOS..."

    # Create export_presets.cfg if it doesn't exist
    if [ ! -f "$WALLET_ROOT/export_presets.cfg" ]; then
        create_export_presets
    fi

    cd "$WALLET_ROOT"

    # Export to a temporary zip, then extract
    "$GODOT" --headless --export-release "macOS" "${BUILD_DIR}/godot_export.zip" 2>/dev/null || {
        log_warn "Godot export failed, trying alternative method..."
        # If export fails, just copy the project files
        cp -r "$WALLET_ROOT"/*.gd "$APP_BUNDLE/Contents/Resources/" 2>/dev/null || true
        cp -r "$WALLET_ROOT/scripts" "$APP_BUNDLE/Contents/Resources/" 2>/dev/null || true
        cp -r "$WALLET_ROOT/scenes" "$APP_BUNDLE/Contents/Resources/" 2>/dev/null || true
    }

    # If export succeeded, extract it
    if [ -f "${BUILD_DIR}/godot_export.zip" ]; then
        unzip -o "${BUILD_DIR}/godot_export.zip" -d "${BUILD_DIR}/godot_temp"
        # Move the .app contents
        if [ -d "${BUILD_DIR}/godot_temp/BATHRON Wallet.app" ]; then
            cp -r "${BUILD_DIR}/godot_temp/BATHRON Wallet.app/Contents/MacOS/"* "$APP_BUNDLE/Contents/MacOS/"
            cp -r "${BUILD_DIR}/godot_temp/BATHRON Wallet.app/Contents/Resources/"* "$APP_BUNDLE/Contents/Resources/" 2>/dev/null || true
        fi
        rm -rf "${BUILD_DIR}/godot_temp" "${BUILD_DIR}/godot_export.zip"
    fi
}

create_export_presets() {
    log_info "Creating Godot export presets..."

    cat > "$WALLET_ROOT/export_presets.cfg" << 'EOF'
[preset.0]

name="macOS"
platform="macOS"
runnable=true
dedicated_server=false
custom_features=""
export_filter="all_resources"
include_filter=""
exclude_filter=""
export_path=""
encryption_include_filters=""
encryption_exclude_filters=""
encrypt_pck=false
encrypt_directory=false

[preset.0.options]

custom_template/debug=""
custom_template/release=""
application/icon=""
application/bundle_identifier="org.bathron.wallet"
application/signature=""
application/app_category="public.app-category.finance"
application/short_version="1.0.0"
application/version="1.0.0"
application/copyright="Copyright 2025 BATHRON Developers"
display/high_res=true
codesign/codesign=0
codesign/identity=""
codesign/certificate_file=""
codesign/certificate_password=""
codesign/provisioning_profile=""
codesign/entitlements/app_sandbox/enabled=false
notarization/notarization=0
EOF
}

copy_daemon_binaries() {
    log_info "Copying daemon binaries..."

    cp "${PROJECT_ROOT}/src/bathrond" "$APP_BUNDLE/Contents/MacOS/"
    cp "${PROJECT_ROOT}/src/bathron-cli" "$APP_BUNDLE/Contents/MacOS/"

    # Make them executable
    chmod +x "$APP_BUNDLE/Contents/MacOS/bathrond"
    chmod +x "$APP_BUNDLE/Contents/MacOS/bathron-cli"

    log_info "Binaries copied: bathrond, bathron-cli"
}

create_launcher_script() {
    log_info "Creating launcher script..."

    # Create a launcher that ensures daemon is started before GUI
    cat > "$APP_BUNDLE/Contents/MacOS/BATHRON-Wallet" << 'EOF'
#!/bin/bash
# BATHRON Wallet Launcher
# Starts bathrond daemon if needed, then launches the GUI

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON="$SCRIPT_DIR/bathrond"
GUI="$SCRIPT_DIR/BATHRON-Wallet.x86_64"  # or BATHRON-Wallet.arm64

# Check if this is ARM or Intel
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    GUI="$SCRIPT_DIR/BATHRON-Wallet.arm64"
else
    GUI="$SCRIPT_DIR/BATHRON-Wallet.x86_64"
fi

# Fallback to any available binary
if [ ! -f "$GUI" ]; then
    for bin in "$SCRIPT_DIR/BATHRON-Wallet".*; do
        if [ -x "$bin" ] && [ "$bin" != "$0" ]; then
            GUI="$bin"
            break
        fi
    done
fi

# Start daemon if not running (testnet by default)
if [ ! -f "$HOME/.bathron/testnet5/.lock" ]; then
    echo "Starting bathrond daemon..."
    "$DAEMON" -testnet -daemon &
    sleep 2
fi

# Launch GUI
if [ -f "$GUI" ]; then
    exec "$GUI" "$@"
else
    echo "GUI binary not found. Running daemon-only mode."
    echo "Use bathron-cli to interact: $SCRIPT_DIR/bathron-cli -testnet <command>"
fi
EOF

    chmod +x "$APP_BUNDLE/Contents/MacOS/BATHRON-Wallet"
}

copy_resources() {
    log_info "Copying resources..."

    # Copy icon if exists
    if [ -f "$WALLET_ROOT/icon.icns" ]; then
        cp "$WALLET_ROOT/icon.icns" "$APP_BUNDLE/Contents/Resources/"
    elif [ -f "$WALLET_ROOT/icon.png" ]; then
        # Convert PNG to ICNS if possible
        if command -v sips &> /dev/null; then
            sips -s format icns "$WALLET_ROOT/icon.png" --out "$APP_BUNDLE/Contents/Resources/icon.icns" 2>/dev/null || true
        fi
    fi

    # Copy default config
    if [ -f "$PROJECT_ROOT/contrib/testnet/bathron.conf.template" ]; then
        cp "$PROJECT_ROOT/contrib/testnet/bathron.conf.template" "$APP_BUNDLE/Contents/Resources/bathron.conf.default"
    fi
}

create_dmg() {
    log_info "Creating DMG installer..."

    DMG_NAME="${APP_NAME}-macOS.dmg"
    DMG_PATH="${BUILD_DIR}/${DMG_NAME}"

    # Remove existing DMG
    rm -f "$DMG_PATH"

    # Create DMG
    if command -v hdiutil &> /dev/null; then
        hdiutil create -volname "$APP_NAME" -srcfolder "$APP_BUNDLE" -ov -format UDZO "$DMG_PATH"
        log_info "DMG created: $DMG_PATH"
    else
        log_warn "hdiutil not available, skipping DMG creation"
        # Create zip instead
        cd "$BUILD_DIR"
        zip -r "${APP_NAME}-macOS.zip" "${APP_NAME}.app"
        log_info "ZIP created: ${BUILD_DIR}/${APP_NAME}-macOS.zip"
    fi
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    log_info "=== BATHRON Wallet macOS Bundle Creator ==="
    log_info "Project root: $PROJECT_ROOT"
    log_info "Wallet root: $WALLET_ROOT"
    log_info "Build dir: $BUILD_DIR"

    check_prerequisites
    create_bundle_structure
    create_info_plist
    copy_daemon_binaries
    create_launcher_script
    copy_resources

    # Try Godot export (optional - can work without GUI for now)
    # export_godot_project

    log_info ""
    log_info "=== Bundle created successfully! ==="
    log_info "Location: $APP_BUNDLE"
    log_info ""
    log_info "Contents:"
    ls -la "$APP_BUNDLE/Contents/MacOS/"

    # Optionally create DMG
    if [ "$1" = "--dmg" ]; then
        create_dmg
    fi
}

main "$@"
