#!/bin/bash
# =============================================================================
# package_macos_portable.sh — build the SELF-CONTAINED macOS portable package
# =============================================================================
# Reproduces the layout of the released assets (e.g. v0.9.3-public-testnet):
#
#   bathron-<TAG>-macos-<ARCH>/
#     bin/bathrond  bin/bathron-cli        (install names rewritten)
#     lib/*.dylib                          (Boost, libevent, ZMQ, sodium, ...)
#     README.md  RUN-ON-MACOS.txt  BUILD-INFO.txt  SHA256SUMS  COPYING  INSTALL
#     licenses/
#
# Binaries and dylibs reference their dependencies via @loader_path, so the
# package runs anywhere without Homebrew. Everything is codesigned AD HOC
# (`codesign -s -`) — NOT notarized, NOT Developer-ID.
#
# RUN ON macOS (arm64), from a repo already built with the public INSTALL
# recipe (autogen + configure --without-gui --disable-tests --disable-bench +
# make). No patches, no private inputs.
#
# Usage:  ./contrib/devtools/package_macos_portable.sh <TAG> [OUTDIR]
#   TAG     e.g. v0.9.4-public-testnet (must match the checked-out tag)
#   OUTDIR  default: ./release-package
# =============================================================================
set -euo pipefail

TAG="${1:?usage: package_macos_portable.sh <TAG> [OUTDIR]}"
OUTDIR="${2:-release-package}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARCH="$(uname -m)"   # arm64 expected
[ "$(uname -s)" = "Darwin" ] || { echo "ERROR: run this on macOS"; exit 1; }

NAME="bathron-${TAG}-macos-${ARCH}"
STAGE="$OUTDIR/$NAME"
BINARIES=(bathrond bathron-cli)

for b in "${BINARIES[@]}"; do
  [ -x "$ROOT/src/$b" ] || { echo "ERROR: $ROOT/src/$b missing — build first"; exit 1; }
done
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
TAGDESC="$(git -C "$ROOT" describe --tags --dirty 2>/dev/null || echo unknown)"
case "$TAGDESC" in *-dirty) echo "ERROR: dirty worktree — package only clean tags"; exit 1;; esac

rm -rf "$STAGE"; mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/licenses"

# --- copy binaries ----------------------------------------------------------
for b in "${BINARIES[@]}"; do cp "$ROOT/src/$b" "$STAGE/bin/"; done

# --- bundle non-system dylibs recursively, rewrite to @loader_path ----------
# System deps stay: /usr/lib, /System. Everything else (Homebrew, local) is
# copied into lib/ and re-referenced.
list_deps() { otool -L "$1" | awk 'NR>1 {print $1}' | grep -vE '^(/usr/lib|/System)' || true; }
declare -a QUEUE=()
for b in "${BINARIES[@]}"; do QUEUE+=("$STAGE/bin/$b"); done
declare -A SEEN=()
while [ ${#QUEUE[@]} -gt 0 ]; do
  f="${QUEUE[0]}"; QUEUE=("${QUEUE[@]:1}")
  for dep in $(list_deps "$f"); do
    base="$(basename "$dep")"
    # resolve @loader_path/@rpath sources against already-copied libs
    src="$dep"
    case "$dep" in @*) src="$STAGE/lib/$base";; esac
    if [ -z "${SEEN[$base]:-}" ]; then
      SEEN[$base]=1
      [ -f "$STAGE/lib/$base" ] || cp "$src" "$STAGE/lib/$base"
      chmod u+w "$STAGE/lib/$base"
      install_name_tool -id "@loader_path/$base" "$STAGE/lib/$base"
      QUEUE+=("$STAGE/lib/$base")
    fi
    case "$f" in
      */bin/*) install_name_tool -change "$dep" "@loader_path/../lib/$base" "$f" ;;
      *)       install_name_tool -change "$dep" "@loader_path/$base"        "$f" ;;
    esac
  done
done

# --- docs & licenses --------------------------------------------------------
cp "$ROOT/README.md" "$STAGE/README.md" 2>/dev/null || cp "$ROOT/README_PUBLIC.md" "$STAGE/README.md"
cp "$ROOT/COPYING" "$STAGE/COPYING"
cp "$ROOT/INSTALL" "$STAGE/INSTALL" 2>/dev/null || true
# third-party license notices, if collected in the repo
[ -d "$ROOT/contrib/debian/copyright" ] && cp -r "$ROOT/contrib/debian/copyright" "$STAGE/licenses/" 2>/dev/null || true

cat > "$STAGE/RUN-ON-MACOS.txt" <<RUNEOF
LANCER BATHRON SUR macOS (Apple Silicon)
=========================================

Paquet AUTONOME : décompressez-le n importe où, les binaires trouvent leurs
bibliothèques dans lib/ via @loader_path. Homebrew n est PAS nécessaire.

  tar -xzf ${NAME}-portable.tar.gz
  cd ${NAME}
  ./bin/bathrond -testnet -daemon
  ./bin/bathron-cli -testnet getblockhash 0

SIGNATURE
  Binaires et dylibs signés en AD HOC (codesign --sign -).
  Paquet NON notarized et NON signé Developer-ID Apple.

AVANT TOUT : VÉRIFIEZ LE SHA-256
  Comparez le hash de l archive et des binaires au SHA256SUMS publié par une
  source de confiance :
     shasum -a 256 ${NAME}-portable.tar.gz
     cd ${NAME} && shasum -a 256 -c SHA256SUMS
  Ne poursuivez que si les hashes correspondent.

SI GATEKEEPER BLOQUE (téléchargement navigateur → quarantaine)
  Option 1 (recommandée) — autoriser au cas par cas via l interface :
     Tentez de lancer ./bin/bathrond, puis
     Réglages Système > Confidentialité et sécurité > "Ouvrir quand même".
     Vous gardez ainsi la protection Gatekeeper active.

  Option 2 — vérifier la signature ad hoc localement :
     codesign -dv ./bin/bathrond        # doit afficher "Signature=adhoc"
     codesign --verify --strict ./bin/bathrond

  Option 3 (avancé, dernier recours) — retirer l attribut de quarantaine,
  UNIQUEMENT après avoir vérifié le SHA-256 ci-dessus :
     xattr -dr com.apple.quarantine ${NAME}
RUNEOF

cat > "$STAGE/BUILD-INFO.txt" <<INFOEOF
BATHRON macOS Apple Silicon (${ARCH}) — paquet portable autonome
Source : https://github.com/bathron-network/bathron-core.git
Tag    : ${TAG}
Commit : ${COMMIT}
Build  : autogen.sh + configure --without-gui --disable-tests --disable-bench + make (recette publique INSTALL, aucun patch)
Arch   : Mach-O 64-bit executable ${ARCH}

Ce paquet embarque ses dépendances dans lib/ (Boost, libevent, ZeroMQ, libsodium).
Binaires et dylibs référencent leurs dépendances via @loader_path : Homebrew N EST PAS requis.
Dépendances système seulement : /usr/lib, /System.
Signature : ad hoc (codesign -s -). NON notarized, NON Developer-ID.
Empaqueté par : contrib/devtools/package_macos_portable.sh
INFOEOF

# --- ad hoc codesign --------------------------------------------------------
for f in "$STAGE"/bin/* "$STAGE"/lib/*.dylib; do codesign --force --sign - "$f"; done

# --- inner SHA256SUMS then archive ------------------------------------------
( cd "$STAGE" && { shasum -a 256 bin/* lib/*.dylib RUN-ON-MACOS.txt BUILD-INFO.txt; } > SHA256SUMS )
( cd "$OUTDIR" && tar -czf "${NAME}-portable.tar.gz" "$NAME" )
echo ""
echo "== paquet : $OUTDIR/${NAME}-portable.tar.gz =="
shasum -a 256 "$OUTDIR/${NAME}-portable.tar.gz"
echo "Vérif rapide : tar -xzf, cd, ./bin/bathrond -version, shasum -c SHA256SUMS"
