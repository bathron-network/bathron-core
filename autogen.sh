#!/bin/sh
# Copyright (c) 2013-2016 The Bitcoin Core developers
# Copyright (c) 2025 The BATHRON Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -e
srcdir="$(dirname $0)"
cd "$srcdir"

# Load Rust/Cargo if available (required for Sapling)
if [ -f "$HOME/.cargo/env" ]; then
  . "$HOME/.cargo/env"
fi

# Initialize submodules if needed
if [ ! -d "src/secp256k1/.git" ] || [ ! -d "src/leveldb/.git" ]; then
  echo "Initializing git submodules..."
  git submodule update --init --recursive 2>/dev/null || true
fi

# Fix leveldb if submodule is incomplete (missing source files)
if [ ! -f "src/leveldb/db/builder.cc" ]; then
  echo "Leveldb submodule incomplete, cloning manually..."
  rm -rf src/leveldb
  git clone --depth 1 --branch 1.22 https://github.com/google/leveldb.git src/leveldb
  echo "Leveldb 1.22 installed"
fi

if [ -z ${LIBTOOLIZE} ] && GLIBTOOLIZE="$(command -v glibtoolize)"; then
  LIBTOOLIZE="${GLIBTOOLIZE}"
  export LIBTOOLIZE
fi
command -v autoreconf >/dev/null || \
  (echo "configuration failed, please install autoconf first" && exit 1)

# On macOS with Homebrew, ensure pkg.m4 is available for PKG_CHECK_MODULES
# This macro is required by configure.ac but may not be in the default aclocal path
if [ -d "/opt/homebrew/share/aclocal" ]; then
  # Apple Silicon Mac (M1/M2/M3/M4)
  BREW_ACLOCAL="/opt/homebrew/share/aclocal"
elif [ -d "/usr/local/share/aclocal" ]; then
  # Intel Mac or manual Homebrew install
  BREW_ACLOCAL="/usr/local/share/aclocal"
fi

# Create build-aux/m4 directory if it doesn't exist
# (required by AC_CONFIG_MACRO_DIRS in configure.ac)
mkdir -p build-aux/m4

if [ -n "$BREW_ACLOCAL" ] && [ -f "$BREW_ACLOCAL/pkg.m4" ]; then
  echo "Copying pkg.m4 from Homebrew: $BREW_ACLOCAL/pkg.m4"
  cp "$BREW_ACLOCAL/pkg.m4" build-aux/m4/
fi

autoreconf --install --force --warnings=all
