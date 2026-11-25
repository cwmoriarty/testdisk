#!/usr/bin/env bash
# Sync embedded apple-explorer C11 library from cwmoriarty/apple-explorer.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLE_EXPLORER_REF="${1:-v0.1.0}"
APPLE_EXPLORER_V010_SHA256="9ddefbdd7c3278d41cc1d03bec099c734ed71ac6c58129337c070c447053025e"

TMP_WORK="$(mktemp -d /tmp/sync_apple_explorer_XXXXXX)"
trap 'rm -rf "$TMP_WORK"' EXIT

ARCHIVE="$TMP_WORK/apple-explorer.tar.gz"
SRC_DIR="$TMP_WORK/src_extract"
mkdir -p "$SRC_DIR"

if [ "$APPLE_EXPLORER_REF" = "v0.1.0" ]; then
    APPLE_EXPLORER_URL="https://github.com/cwmoriarty/apple-explorer/releases/download/v0.1.0/apple-explorer-0.1.0.tar.gz"
    curl -fsSL -o "$ARCHIVE" "$APPLE_EXPLORER_URL"
    echo "${APPLE_EXPLORER_V010_SHA256}  ${ARCHIVE}" | shasum -a 256 -c - >/dev/null
else
    APPLE_EXPLORER_URL="https://github.com/cwmoriarty/apple-explorer/archive/${APPLE_EXPLORER_REF}.tar.gz"
    curl -fsSL -o "$ARCHIVE" "$APPLE_EXPLORER_URL"
fi

tar -xzf "$ARCHIVE" --strip-components=1 -C "$SRC_DIR"

DEST_DIR="$HERE/third_party/apple_explorer"
mkdir -p "$DEST_DIR/include" "$DEST_DIR/src"

cp -p "$SRC_DIR/LICENSE" "$DEST_DIR/LICENSE"
cp -p "$SRC_DIR/README.md" "$DEST_DIR/README.md"
cp -p "$SRC_DIR/include/apple_explorer.h" "$DEST_DIR/include/apple_explorer.h"
cp -p "$SRC_DIR/src/aex_internal.h" "$DEST_DIR/src/aex_internal.h"
for f in crypto_compress.c container.c fs_hfs.c fs_apfs.c; do
    cp -p "$SRC_DIR/src/$f" "$DEST_DIR/src/$f"
done

echo "Synced cwmoriarty/apple-explorer ${APPLE_EXPLORER_REF} into third_party/apple_explorer"
