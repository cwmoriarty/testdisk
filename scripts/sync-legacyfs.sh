#!/usr/bin/env bash
# Sync embedded legacyfs C11 library from official cwmoriarty/legacyfs release archive.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEGACYFS_VERSION="0.1.0"
LEGACYFS_URL="https://github.com/cwmoriarty/legacyfs/releases/download/v${LEGACYFS_VERSION}/legacyfs-${LEGACYFS_VERSION}.tar.gz"
LEGACYFS_SHA256="8be357369af32bd309122e8d4deca1da5d39e5efadbd77fa2017555a2c4be97d"

TMP_WORK="$(mktemp -d /tmp/sync_legacyfs_XXXXXX)"
trap 'rm -rf "$TMP_WORK"' EXIT

ARCHIVE="$TMP_WORK/legacyfs-${LEGACYFS_VERSION}.tar.gz"
curl -fsSL -o "$ARCHIVE" "$LEGACYFS_URL"
echo "${LEGACYFS_SHA256}  ${ARCHIVE}" | shasum -a 256 -c - >/dev/null

tar -xzf "$ARCHIVE" -C "$TMP_WORK"
SRC_DIR="$TMP_WORK/legacyfs-${LEGACYFS_VERSION}"
DEST_DIR="$HERE/third_party/legacyfs"
mkdir -p "$DEST_DIR"

cp -p "$SRC_DIR/LICENSE" "$DEST_DIR/LICENSE"
cp -p "$SRC_DIR/include/legacyfs.h" "$DEST_DIR/legacyfs.h"
cp -p "$SRC_DIR/src/internal.h" "$DEST_DIR/internal.h"
for f in core.c probe.c fs_reiserfs.c fs_minix_sysv.c fs_cramfs_romfs.c fs_squashfs_erofs.c fs_iso9660.c fs_ufs_jfs.c; do
    cp -p "$SRC_DIR/src/$f" "$DEST_DIR/$f"
done

echo "Synced cwmoriarty/legacyfs v${LEGACYFS_VERSION} into third_party/legacyfs"
