#!/usr/bin/env bash
#
# test_corrupted_fuzz.sh
# Automated ASan/UBSan legacyfs and apple-explorer fuzzing and corrupted-image stress suite
# Verifies zero crashes across >= 5,000 in-process sanitizer mutations and
# >= 150 intentionally damaged MBR, GPT, HFS, HFS+, APFS, Unix filesystem, and carved-archive images.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -x "$ROOT_DIR/src/testdisk-ng" ]; then
  TESTDISK="$ROOT_DIR/src/testdisk-ng"
  FIDENTIFY="$ROOT_DIR/src/fidentify"
elif command -v testdisk-ng >/dev/null 2>&1; then
  TESTDISK="$(command -v testdisk-ng)"
  FIDENTIFY="$(command -v fidentify)"
else
  echo "Error: testdisk-ng binary not found in $ROOT_DIR/src or PATH. Run 'make' first."
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/testdisk_fuzz_XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "========================================================================"
echo " Starting Corrupted-Image and Sanitizer Fuzz Suite"
echo " Working directory: $TMP_DIR"
echo "========================================================================"

# Part 1: Compile embedded legacyfs v0.2.0 with ASan and UBSan and run 2,500 mutations
echo -n "[Fuzz 1/3] Running 2,500 ASan/UBSan in-process legacyfs v0.2.0 mutations... "

FUZZ_SRC="$TMP_DIR/fuzz_legacyfs_runner.c"
FUZZ_BIN="$TMP_DIR/fuzz_legacyfs_runner"

cat > "$FUZZ_SRC" << 'EOF'
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "legacyfs.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const uint8_t *data;
  size_t size;
} fuzz_slice_t;

static int fuzz_read_cb(void *ctx, uint64_t offset, size_t length, void *buffer)
{
  const fuzz_slice_t *s = (const fuzz_slice_t *)ctx;
  if(offset > s->size || s->size - (size_t)offset < length)
    return 5;
  memcpy(buffer, s->data + (size_t)offset, length);
  return 0;
}

typedef struct {
  legacyfs_t *fs;
  int depth;
  int budget;
} fuzz_walk_t;

static int fuzz_dir_cb(void *user_ctx, const char *name, uint64_t ino, legacyfs_ftype_t ftype);

static void fuzz_exercise_ino(fuzz_walk_t *w, uint64_t ino)
{
  legacyfs_attr_t attr;
  if(w->budget <= 0)
    return;
  w->budget--;

  if(legacyfs_getattr(w->fs, ino, &attr) != 0)
    return;

  if(attr.ftype == LEGACYFS_FT_REG)
  {
    uint8_t buf[512];
    size_t got = 0;
    (void)legacyfs_read(w->fs, ino, 0, sizeof(buf), buf, &got);
    if(attr.size > 256ULL)
      (void)legacyfs_read(w->fs, ino, attr.size - 128ULL, 128U, buf, &got);
  }
  else if(attr.ftype == LEGACYFS_FT_SYMLINK)
  {
    char target[256];
    size_t len = 0;
    (void)legacyfs_readlink(w->fs, ino, target, sizeof(target), &len);
  }
  else if(attr.ftype == LEGACYFS_FT_DIR && w->depth < 4)
  {
    w->depth++;
    (void)legacyfs_readdir(w->fs, ino, fuzz_dir_cb, w);
    w->depth--;
  }
}

static int fuzz_dir_cb(void *user_ctx, const char *name, uint64_t ino, legacyfs_ftype_t ftype)
{
  fuzz_walk_t *w = (fuzz_walk_t *)user_ctx;
  (void)ftype;
  if(w->budget <= 0)
    return 1;
  if(name == NULL || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;
  fuzz_exercise_ino(w, ino);
  return (w->budget <= 0) ? 1 : 0;
}

static void fuzz_one_input(const uint8_t *data, size_t size)
{
  fuzz_slice_t slice = { data, size };
  legacyfs_probe_info_t pinfo;
  int prc = legacyfs_probe_io(fuzz_read_cb, &slice, size, &pinfo);

  if(prc == 0 && pinfo.can_mount_ro)
  {
    legacyfs_t *fs = NULL;
    if(legacyfs_open_io(fuzz_read_cb, &slice, size, LEGACYFS_KIND_UNKNOWN, &fs) == 0 && fs != NULL)
    {
      legacyfs_statfs_t st;
      fuzz_walk_t w = { fs, 0, 32 };
      uint64_t dummy = 0;
      (void)legacyfs_statfs(fs, &st);
      fuzz_exercise_ino(&w, legacyfs_root_ino(fs));
      (void)legacyfs_lookup_path(fs, "/etc/passwd", &dummy);
      legacyfs_close(fs);
    }
  }

  if(size >= 4)
  {
    static const legacyfs_kind_t mountable[] = {
      LEGACYFS_KIND_REISERFS, LEGACYFS_KIND_MINIX, LEGACYFS_KIND_CRAMFS,
      LEGACYFS_KIND_ROMFS, LEGACYFS_KIND_ISO9660, LEGACYFS_KIND_SQUASHFS,
      LEGACYFS_KIND_EROFS, LEGACYFS_KIND_UFS, LEGACYFS_KIND_JFS,
      LEGACYFS_KIND_SYSV, LEGACYFS_KIND_BTRFS, LEGACYFS_KIND_XFS,
      LEGACYFS_KIND_UDF
    };
    legacyfs_kind_t forced = mountable[data[0] % (sizeof(mountable) / sizeof(mountable[0]))];
    legacyfs_t *fs = NULL;
    if(legacyfs_open_io(fuzz_read_cb, &slice, size, forced, &fs) == 0 && fs != NULL)
    {
      fuzz_walk_t w = { fs, 0, 16 };
      fuzz_exercise_ino(&w, legacyfs_root_ino(fs));
      legacyfs_close(fs);
    }
  }
}

static uint64_t xorshift64(uint64_t *state)
{
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;
  return x;
}

static void seed_corrupted_template(uint8_t *buf, size_t cap, uint32_t variant, uint64_t *rng)
{
  uint32_t mutations;
  uint32_t m;
  memset(buf, 0, cap);
  switch(variant % 13U)
  {
    case 0:
      if(cap >= 70000)
      {
        memcpy(buf + 65536 + 52, "ReIsEr2Fs", 9);
        buf[65536 + 44] = 0x00; buf[65536 + 45] = 0x10;
        buf[65536 + 8] = 17;
      }
      break;
    case 1:
      if(cap >= 4096)
      {
        buf[1024 + 24] = 0x5A; buf[1024 + 25] = 0x4D;
        buf[1024 + 28] = 0x00; buf[1024 + 29] = 0x04;
      }
      break;
    case 2:
      if(cap >= 1024)
      {
        buf[0] = 0x45; buf[1] = 0x3D; buf[2] = 0xCD; buf[3] = 0x28;
        memcpy(buf + 16, "Compressed ROMFS", 16);
      }
      break;
    case 3:
      if(cap >= 1024)
      {
        memcpy(buf, "-rom1fs-", 8);
        buf[10] = 0x04;
      }
      break;
    case 4:
      if(cap >= 40960)
      {
        buf[32768] = 1;
        memcpy(buf + 32769, "CD001", 5);
        buf[32774] = 1;
      }
      break;
    case 5:
      if(cap >= 1024)
      {
        memcpy(buf, "hsqs", 4);
        buf[13] = 0x10; buf[28] = 4; buf[41] = 0x04;
      }
      break;
    case 6:
      if(cap >= 4096)
      {
        buf[1024] = 0xE2; buf[1025] = 0xE1; buf[1026] = 0xF5; buf[1027] = 0xE0;
        buf[1024 + 12] = 12;
      }
      break;
    case 7:
      if(cap >= 70000)
      {
        buf[65536 + 1372] = 0x19; buf[65536 + 1373] = 0x01;
        buf[65536 + 1374] = 0x54; buf[65536 + 1375] = 0x19;
        buf[65536 + 49] = 0x10; buf[65536 + 53] = 0x10;
      }
      break;
    case 8:
      if(cap >= 40960)
      {
        memcpy(buf + 32768, "JFS1", 4);
        buf[32768 + 4] = 1;
        buf[32768 + 17] = 0x10;
      }
      break;
    case 9:
      if(cap >= 2048)
      {
        buf[512 + 504] = 0x20; buf[512 + 505] = 0x7E;
        buf[512 + 506] = 0x18; buf[512 + 507] = 0xFD;
      }
      break;
    case 10:
      if(cap >= 75000)
      {
        memcpy(buf + 65536 + 64, "_BHRfS_M", 8);
        buf[65536 + 145] = 0x10;
        buf[65536 + 149] = 0x10;
        buf[65536 + 81] = 0x20;
      }
      break;
    case 11:
      if(cap >= 8192)
      {
        memcpy(buf, "XFSB", 4);
        buf[6] = 0x10;
        buf[104] = 0x02;
        buf[120] = 12; buf[123] = 3; buf[124] = 8;
        buf[87] = 64; buf[91] = 1; buf[63] = 64;
      }
      break;
    case 12:
      if(cap >= 140000)
      {
        memcpy(buf + 32769, "NSR03", 5);
        buf[256 * 512] = 2;
        buf[256 * 512 + 13] = 1;
        buf[256 * 512 + 17] = 0x10;
        buf[256 * 512 + 20] = 32;
      }
      break;
  }

  mutations = 8U + (uint32_t)(xorshift64(rng) % 64U);
  for(m = 0; m < mutations; m++)
  {
    size_t idx = (size_t)(xorshift64(rng) % cap);
    uint8_t mode = (uint8_t)(xorshift64(rng) & 3U);
    if(mode == 0)
      buf[idx] ^= (uint8_t)(1U << (xorshift64(rng) & 7U));
    else if(mode == 1)
      buf[idx] = 0xFFU;
    else if(mode == 2)
      buf[idx] = 0x00U;
    else
      buf[idx] = (uint8_t)xorshift64(rng);
  }
}

int main(void)
{
  const uint32_t iterations = 2500U;
  const size_t max_cap = 160U * 1024U;
  static const size_t tiny_sizes[] = { 0, 1, 7, 31, 64, 511, 512, 1023, 2048, 4096 };
  uint8_t *buf = (uint8_t *)malloc(max_cap);
  uint64_t rng = 0xC0FFEE123456789BULL;
  size_t t, k;
  uint32_t i;

  if(buf == NULL)
    return 1;

  for(t = 0; t < sizeof(tiny_sizes) / sizeof(tiny_sizes[0]); t++)
  {
    for(k = 0; k < tiny_sizes[t]; k++)
      buf[k] = (uint8_t)xorshift64(&rng);
    fuzz_one_input(buf, tiny_sizes[t]);
  }

  for(i = 0; i < iterations; i++)
  {
    size_t active_sz = (i % 5U == 0U)
        ? (size_t)(xorshift64(&rng) % 8192U)
        : max_cap;
    if(active_sz > 0)
      seed_corrupted_template(buf, active_sz, i, &rng);
    fuzz_one_input(buf, active_sz);
  }

  free(buf);
  return 0;
}
EOF

CC_BIN="${CC:-cc}"
LFS_DIR="$ROOT_DIR/third_party/legacyfs"
LFS_SRCS=(
  "$LFS_DIR/core.c"
  "$LFS_DIR/probe.c"
  "$LFS_DIR/fs_reiserfs.c"
  "$LFS_DIR/fs_minix_sysv.c"
  "$LFS_DIR/fs_cramfs_romfs.c"
  "$LFS_DIR/fs_squashfs_erofs.c"
  "$LFS_DIR/fs_iso9660.c"
  "$LFS_DIR/fs_ufs_jfs.c"
  "$LFS_DIR/fs_btrfs.c"
  "$LFS_DIR/fs_xfs.c"
  "$LFS_DIR/fs_udf.c"
)

"$CC_BIN" -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$LFS_DIR" "$FUZZ_SRC" "${LFS_SRCS[@]}" -lz -o "$FUZZ_BIN"

ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
  "$FUZZ_BIN"
echo "PASSED"

# Part 2: Compile embedded apple-explorer v0.1.0 with ASan and UBSan and run 2,500 mutations
echo -n "[Fuzz 2/3] Running 2,500 ASan/UBSan in-process apple-explorer v0.1.0 mutations... "

AEX_FUZZ_SRC="$TMP_DIR/fuzz_aex_runner.c"
AEX_FUZZ_BIN="$TMP_DIR/fuzz_aex_runner"

cat > "$AEX_FUZZ_SRC" << 'EOF'
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "apple_explorer.h"
#include "aex_internal.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const uint8_t *data;
  size_t size;
} aex_fuzz_slice_t;

static int aex_fuzz_read_cb(void *ctx, uint64_t off, size_t len, void *buf)
{
  const aex_fuzz_slice_t *s = (const aex_fuzz_slice_t *)ctx;
  if (off > s->size || len > s->size - (size_t)off)
    return -EIO;
  memcpy(buf, s->data + (size_t)off, len);
  return 0;
}

typedef struct {
  aex_t *fs;
  int depth;
  int budget;
} aex_fuzz_walk_t;

static int aex_fuzz_dir_cb(void *user_ctx, const char *name, uint64_t ino, aex_ftype_t ftype);

static void aex_fuzz_exercise_ino(aex_fuzz_walk_t *w, uint64_t ino)
{
  aex_attr_t attr;
  if (w->budget <= 0)
    return;
  w->budget--;

  if (aex_getattr(w->fs, ino, &attr) != 0)
    return;

  if (attr.ftype == AEX_FT_REG)
  {
    uint8_t buf[512];
    size_t got = 0;
    (void)aex_read(w->fs, ino, 0, sizeof(buf), buf, &got);
    (void)aex_read_rsrc(w->fs, ino, 0, sizeof(buf), buf, &got);
    if (attr.size > 256ULL)
      (void)aex_read(w->fs, ino, attr.size - 128ULL, 128U, buf, &got);
  }
  else if (attr.ftype == AEX_FT_SYMLINK)
  {
    char target[256];
    size_t len = 0;
    (void)aex_readlink(w->fs, ino, target, sizeof(target), &len);
  }
  else if (attr.ftype == AEX_FT_DIR && w->depth < 5)
  {
    w->depth++;
    (void)aex_readdir(w->fs, ino, aex_fuzz_dir_cb, w);
    w->depth--;
  }
}

static int aex_fuzz_dir_cb(void *user_ctx, const char *name, uint64_t ino, aex_ftype_t ftype)
{
  aex_fuzz_walk_t *w = (aex_fuzz_walk_t *)user_ctx;
  (void)ftype;
  if (w->budget <= 0)
    return 1;
  if (name == NULL || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;
  aex_fuzz_exercise_ino(w, ino);
  return (w->budget <= 0) ? 1 : 0;
}

static void aex_fuzz_one_input(const uint8_t *data, size_t size)
{
  aex_fuzz_slice_t sl = { data, size };
  aex_stream_t *st = NULL;
  aex_t *fs = NULL;

  if (aex_stream_open_io(aex_fuzz_read_cb, &sl, size, &st) == 0 && st != NULL)
  {
    aex_partition_desc_t parts[8];
    size_t pcnt = 0;
    (void)aex_list_partitions(st, parts, 8U, &pcnt);
    aex_stream_close(st);
  }

  if (aex_open_io(aex_fuzz_read_cb, &sl, size, NULL, &fs) == 0 && fs != NULL)
  {
    aex_snapshot_desc_t snaps[4];
    size_t scnt = 0;
    uint64_t tot = 0, used = 0, dummy = 0;
    uint32_t bsz = 0;
    aex_fuzz_walk_t w = { fs, 0, 32 };
    (void)aex_statfs(fs, &tot, &used, &bsz);
    (void)aex_list_snapshots(fs, snaps, 4U, &scnt);
    aex_fuzz_exercise_ino(&w, aex_root_ino(fs));
    (void)aex_lookup_path(fs, "/Backups.backupdb", &dummy);
    (void)aex_lookup_path(fs, "/Backups", &dummy);
    aex_close(fs);
  }
}

static uint64_t aex_xorshift64(uint64_t *state)
{
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;
  return x;
}

static void seed_apple_corrupted_template(uint8_t *buf, size_t cap, uint32_t variant, uint64_t *rng)
{
  uint32_t mutations;
  uint32_t m;
  memset(buf, 0, cap);
  switch (variant % 5U)
  {
    case 0: /* Classic HFS ('BD') */
      if (cap >= 4096U)
      {
        buf[1024] = 0x42; buf[1025] = 0x44;
        buf[1024 + 19] = 64;
        buf[1024 + 22] = 0x02; /* 512 */
        buf[1024 + 29] = 4;
        buf[1024 + 148] = 0x04; /* cat size 1024 */
        buf[1024 + 153] = 2;
        buf[2048 + 8] = 1;
        buf[2048 + 27] = 1;
        buf[2048 + 32] = 0x02;
        buf[2560 + 8] = 0xFF;
        buf[2560 + 11] = 2;
      }
      break;
    case 1: /* HFS+ ('H+') with catalog + attributes B-trees */
      if (cap >= 24576U)
      {
        buf[1024] = 0x48; buf[1025] = 0x2B;
        buf[1024 + 3] = 4;
        buf[1024 + 42] = 0x10; /* 4096 */
        buf[1024 + 47] = 16;
        buf[1024 + 272 + 6] = 0x20;
        buf[1024 + 272 + 19] = 2;
        buf[1024 + 272 + 23] = 2;
        buf[8192 + 8] = 1;
        buf[8192 + 27] = 1;
        buf[8192 + 32] = 0x10;
        buf[12288 + 8] = 0xFF;
        buf[12288 + 11] = 3;
      }
      break;
    case 2: /* HFSX ('HX') */
      if (cap >= 16384U)
      {
        buf[1024] = 0x48; buf[1025] = 0x58;
        buf[1024 + 3] = 5;
        buf[1024 + 42] = 0x10;
        buf[1024 + 47] = 8;
      }
      break;
    case 3: /* APFS ('NXSB' + 'APSB' + Fletcher-64) */
      if (cap >= 32768U)
      {
        memcpy(buf + 32, "NXSB", 4);
        buf[36] = 0x00; buf[37] = 0x10; /* 4096 */
        buf[40] = 8;
        buf[104] = 2;
        buf[112] = 6;
        buf[160] = 1;
        buf[184] = 100;
        aex_put_le64(buf + 0, aex_fletcher64(buf, 4096U));
        buf[4096 + 48] = 2;
        aex_put_le64(buf + 4096, aex_fletcher64(buf + 4096, 4096U));
        memcpy(buf + 12288 + 32, "APSB", 4);
        buf[12288 + 128] = 4;
        buf[12288 + 136] = 200;
        aex_put_le64(buf + 12288, aex_fletcher64(buf + 12288, 4096U));
      }
      break;
    case 4: /* APM / GPT wrapper with Apple partition */
      if (cap >= 16384U)
      {
        buf[512] = 0x50; buf[513] = 0x4D; /* 'PM' */
        buf[512 + 7] = 2;
        buf[512 + 11] = 8;
        buf[512 + 15] = 16;
        memcpy(buf + 512 + 48, "Apple_HFS", 9);
        buf[4096 + 1024] = 0x48; buf[4096 + 1025] = 0x2B;
        buf[4096 + 1024 + 42] = 0x10;
      }
      break;
  }

  mutations = 6U + (uint32_t)(aex_xorshift64(rng) % 48U);
  for (m = 0; m < mutations; m++)
  {
    size_t idx = (size_t)(aex_xorshift64(rng) % cap);
    uint8_t mode = (uint8_t)(aex_xorshift64(rng) & 3U);
    if (mode == 0)
      buf[idx] ^= (uint8_t)(1U << (aex_xorshift64(rng) & 7U));
    else if (mode == 1)
      buf[idx] = 0xFFU;
    else if (mode == 2)
      buf[idx] = 0x00U;
    else
      buf[idx] = (uint8_t)aex_xorshift64(rng);
  }
}

int main(void)
{
  const uint32_t iterations = 2500U;
  const size_t max_cap = 64U * 1024U;
  static const size_t tiny_sizes[] = { 0, 1, 7, 31, 64, 511, 512, 1024, 2048, 4096 };
  uint8_t *buf = (uint8_t *)malloc(max_cap);
  uint64_t rng = 0xA11CE5EED9876543ULL;
  size_t t, k;
  uint32_t i;

  if (buf == NULL)
    return 1;

  for (t = 0; t < sizeof(tiny_sizes) / sizeof(tiny_sizes[0]); t++)
  {
    for (k = 0; k < tiny_sizes[t]; k++)
      buf[k] = (uint8_t)aex_xorshift64(&rng);
    aex_fuzz_one_input(buf, tiny_sizes[t]);
  }

  for (i = 0; i < iterations; i++)
  {
    size_t active_sz = (i % 5U == 0U)
        ? (size_t)(aex_xorshift64(&rng) % 8192U)
        : max_cap;
    if (active_sz > 0)
      seed_apple_corrupted_template(buf, active_sz, i, &rng);
    aex_fuzz_one_input(buf, active_sz);
  }

  free(buf);
  return 0;
}
EOF

AEX_DIR="$ROOT_DIR/third_party/apple_explorer"
AEX_SRCS=(
  "$AEX_DIR/src/crypto_compress.c"
  "$AEX_DIR/src/container.c"
  "$AEX_DIR/src/fs_hfs.c"
  "$AEX_DIR/src/fs_apfs.c"
)

"$CC_BIN" -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$AEX_DIR/include" -I"$AEX_DIR/src" "$AEX_FUZZ_SRC" "${AEX_SRCS[@]}" -o "$AEX_FUZZ_BIN"

ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
  "$AEX_FUZZ_BIN"
echo "PASSED"

# Part 3: Generate 150 corrupted partition, Apple/Unix filesystem, and carved-archive images
# and exercise testdisk-ng /list, testdisk-ng /cmd advanced extraction, and fidentify --check
echo -n "[Fuzz 3/3] Stress-testing 150 damaged disk, Apple/Unix filesystem, and carved images... "

CORRUPT_DIR="$TMP_DIR/corrupt_corpus"
CARVE_DIR="$TMP_DIR/corrupt_carve"
mkdir -p "$CORRUPT_DIR" "$CARVE_DIR"

python3 - <<EOF
import os, random, struct

rng = random.Random(20261124)
corrupt_dir = "$CORRUPT_DIR"
carve_dir = "$CARVE_DIR"

def mutate_bytes(raw: bytearray, count: int) -> bytearray:
    if len(raw) == 0:
        return raw
    for _ in range(count):
        idx = rng.randrange(len(raw))
        mode = rng.randrange(4)
        if mode == 0:
            raw[idx] ^= (1 << rng.randrange(8))
        elif mode == 1:
            raw[idx] = 0xFF
        elif mode == 2:
            raw[idx] = 0x00
        else:
            raw[idx] = rng.randrange(256)
    return raw

# 1. Generate 60 damaged MBR, GPT, ReiserFS, CramFS, XFS, Btrfs, and UDF disk images
for i in range(60):
    kind = i % 6
    if kind == 0:
        # Damaged MBR with overlapping/overflowing LBA entries or truncated tail
        sz = [0, 1, 63, 511, 512, 4096, 65536][i % 7]
        buf = bytearray(sz)
        if sz >= 512:
            struct.pack_into("<BBBBBBBBII", buf, 446, 0x80, 0xFF, 0xFF, 0xFF, 0x83, 0xFF, 0xFF, 0xFF, 0xFFFFFFF0, 0xFFFFFFFF)
            struct.pack_into("<BBBBBBBBII", buf, 462, 0x00, 0x00, 0x01, 0x00, 0x07, 0xFE, 0xFF, 0xFF, 1, 0x7FFFFFFF)
            buf[510:512] = b"\x55\xAA"
        mutate_bytes(buf, 12)
    elif kind == 1:
        # Damaged GPT header with extreme num_partition_entries / invalid sizes
        buf = bytearray(32768)
        buf[510:512] = b"\x55\xAA"
        buf[450] = 0xEE
        buf[512:520] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", buf, 520, 0x00010000, 92, 0, 0, 1, 0xFFFFFFFFFFFFFFFF, 34, 2)
        struct.pack_into("<QIII", buf, 584, 2, 0xFFFFFFF0, 128, 0)
        mutate_bytes(buf, 16)
    elif kind == 2:
        # Damaged XFS v5 in MBR partition
        part = bytearray(65536)
        part[0:4] = b"XFSB"
        struct.pack_into(">II", part, 4, 4096, 0)
        struct.pack_into(">Q", part, 56, 64)
        struct.pack_into(">HHHH", part, 100, 5, 512, 512, 8)
        part[120:125] = bytes([12, 9, 9, 3, 6])
        mutate_bytes(part, 24)
        buf = bytearray(2048 * 512 + len(part))
        struct.pack_into("<BBBBBBBBII", buf, 446, 0x80, 0, 1, 0, 0x83, 0xFE, 0xFF, 0xFF, 2048, len(part) // 512)
        buf[510:512] = b"\x55\xAA"
        buf[2048 * 512:] = part
    elif kind == 3:
        # Damaged Btrfs in MBR partition (cyclic root / corrupt sys_chunk_array)
        part = bytearray(131072)
        part[65536 + 64:65536 + 72] = b"_BHRfS_M"
        struct.pack_into("<Q", part, 65536 + 80, 0x100000)
        struct.pack_into("<II", part, 65536 + 144, 4096, 4096)
        struct.pack_into("<I", part, 65536 + 160, 2048)
        struct.pack_into("<I", part, 65536 + 233, 4096)
        mutate_bytes(part, 32)
        buf = bytearray(2048 * 512 + len(part))
        struct.pack_into("<BBBBBBBBII", buf, 446, 0x80, 0, 1, 0, 0x83, 0xFE, 0xFF, 0xFF, 2048, len(part) // 512)
        buf[510:512] = b"\x55\xAA"
        buf[2048 * 512:] = part
    elif kind == 4:
        # Damaged UDF in MBR partition
        part = bytearray(160 * 2048)
        part[32769:32774] = b"NSR03"
        avdp = 256 * 512
        struct.pack_into("<H", part, avdp, 2)
        struct.pack_into("<III", part, avdp + 12, 256, 65536, 32)
        mutate_bytes(part, 32)
        buf = bytearray(2048 * 512 + len(part))
        struct.pack_into("<BBBBBBBBII", buf, 446, 0x80, 0, 1, 0, 0x07, 0xFE, 0xFF, 0xFF, 2048, len(part) // 512)
        buf[510:512] = b"\x55\xAA"
        buf[2048 * 512:] = part
    else:
        # Damaged ReiserFS / CramFS hybrid
        part = bytearray(81920)
        part[65536 + 52:65536 + 61] = b"ReIsEr2Fs"
        struct.pack_into("<HH", part, 65536 + 40, 99, 4096)
        mutate_bytes(part, 28)
        buf = bytearray(2048 * 512 + len(part))
        struct.pack_into("<BBBBBBBBII", buf, 446, 0x80, 0, 1, 0, 0x83, 0xFE, 0xFF, 0xFF, 2048, len(part) // 512)
        buf[510:512] = b"\x55\xAA"
        buf[2048 * 512:] = part

    with open(os.path.join(corrupt_dir, f"disk_{i:03d}.img"), "wb") as f:
        f.write(buf)

# 1b. Generate 30 damaged Classic HFS, HFS+ Backups.backupdb, and APFS disk images
import binascii

def wrap_gpt_apple(part: bytearray, is_apfs: bool) -> bytearray:
    secs = max(8, (len(part) + 511) // 512)
    start_lba = 64
    end_lba = start_lba + secs - 1
    total_lba = end_lba + 64
    disk = bytearray(total_lba * 512)
    struct.pack_into("<BBBBBBBBII", disk, 446, 0x00, 0, 2, 0, 0xEE, 0xFE, 0xFF, 0xFF, 1, total_lba - 1)
    disk[510:512] = b"\x55\xAA"
    entries = bytearray(128 * 128)
    guid_hi = 0x7C3457EF if is_apfs else 0x48465300
    entries[0:16] = struct.pack("<IHH8s", guid_hi, 0x0000, 0x11AA, bytes([0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC]))
    entries[16:32] = bytes(range(1, 17))
    struct.pack_into("<QQQ", entries, 32, start_lba, end_lba, 0)
    ecrc = binascii.crc32(entries) & 0xFFFFFFFF
    disk[2 * 512:34 * 512] = entries
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ16sQIII", hdr, 8, 0x00010000, 92, 0, 0, 1, total_lba - 1, 34, total_lba - 34, bytes(16), 2, 128, 128, ecrc)
    struct.pack_into("<I", hdr, 16, binascii.crc32(hdr) & 0xFFFFFFFF)
    disk[512:512 + 92] = hdr
    alt_tbl = total_lba - 33
    disk[alt_tbl * 512:(alt_tbl + 32) * 512] = entries
    bhdr = bytearray(92)
    bhdr[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ16sQIII", bhdr, 8, 0x00010000, 92, 0, 0, total_lba - 1, 1, 34, total_lba - 34, bytes(16), alt_tbl, 128, 128, ecrc)
    struct.pack_into("<I", bhdr, 16, binascii.crc32(bhdr) & 0xFFFFFFFF)
    disk[(total_lba - 1) * 512:(total_lba - 1) * 512 + 92] = bhdr
    disk[start_lba * 512:start_lba * 512 + len(part)] = part
    return disk

for j in range(30):
    akind = j % 3
    if akind == 0:
        # Damaged Classic HFS in MBR (0xAF): cyclic leaf nodes / overflowing record offsets / huge file sizes
        part = bytearray(65536)
        struct.pack_into(">H", part, 1024, 0x4244)
        struct.pack_into(">HI", part, 1024 + 18, 64, 512)
        struct.pack_into(">H", part, 1024 + 28, 4)
        struct.pack_into(">H", part, 1024 + 34, 16)
        struct.pack_into(">IHH", part, 1024 + 146, 2048, 0, 4)
        part[2048 + 8] = 1
        struct.pack_into(">I", part, 2048 + 24, 1)
        struct.pack_into(">H", part, 2048 + 32, 512)
        part[2560 + 8] = 0xFF
        struct.pack_into(">I", part, 2560 + 0, 1)  # cyclic fLink -> self!
        struct.pack_into(">H", part, 2560 + 10, 64)
        mutate_bytes(part, 24)
        buf = bytearray(2048 * 512 + len(part))
        struct.pack_into("<BBBBBBBBII", buf, 446, 0x80, 0, 1, 0, 0xAF, 0xFE, 0xFF, 0xFF, 2048, len(part) // 512)
        buf[510:512] = b"\x55\xAA"
        buf[2048 * 512:] = part
    elif akind == 1:
        # Damaged HFS+ in GPT: dangling/self-referential Backups.backupdb hard links & truncated decmpfs xattrs
        part = bytearray(65536)
        struct.pack_into(">HH", part, 1024, 0x482B, 4)
        struct.pack_into(">III", part, 1024 + 40, 4096, 16, 4)
        struct.pack_into(">Q", part, 1024 + 272, 8192)
        struct.pack_into(">III", part, 1024 + 272 + 12, 2, 2, 2)
        part[8192 + 8] = 1
        struct.pack_into(">I", part, 8192 + 24, 1)
        struct.pack_into(">H", part, 8192 + 32, 4096)
        part[12288 + 8] = 0xFF
        struct.pack_into(">I", part, 12288, 1)  # cyclic leaf loop
        struct.pack_into(">H", part, 12288 + 10, 12)
        mutate_bytes(part, 28)
        buf = wrap_gpt_apple(part, False)
    else:
        # Damaged APFS in GPT: corrupted checkpoint ring, cyclic OMAP/FS B-tree, extreme dstream sizes
        part = bytearray(65536)
        part[32:36] = b"NXSB"
        struct.pack_into("<IQ", part, 36, 4096, 16)
        struct.pack_into("<IIQQ", part, 104, 4, 0, 10, 14)
        struct.pack_into("<QQ", part, 160, 1, 0)
        struct.pack_into("<Q", part, 184, 100)
        part[12288 + 32:12288 + 36] = b"APSB"
        struct.pack_into("<QQQ", part, 12288 + 128, 4, 200, 8)
        mutate_bytes(part, 32)
        buf = wrap_gpt_apple(part, True)

    with open(os.path.join(corrupt_dir, f"disk_{60 + j:03d}.img"), "wb") as f:
        f.write(buf)

# 2. Generate 60 damaged/truncated Zstd, LZ4, IVF, CR3, AVIF, and BRAW carved samples
for i in range(60):
    kind = i % 6
    if kind == 0:
        # Damaged / truncated Zstd frames (reserved bits, block_type=3, huge block_size, 5-byte truncation)
        raw = bytearray(b"\x28\xb5\x2f\xfd\x24\x10\xff\xff\xff" + os.urandom(24))
    elif kind == 1:
        # Damaged / truncated LZ4 frames (missing EndMark, 0x7FFFFFFF block size, bad version bits)
        raw = bytearray(b"\x04\x22\x4d\x18\x64\x70\x00\xff\xff\xff\x7f" + os.urandom(24))
    elif kind == 2:
        # Damaged / truncated IVF containers (zero dimensions, huge frame_size, truncated header)
        raw = bytearray(struct.pack("<4sHH4sHHIIII", b"DKIF", 0, 32, b"AV01", 1920, 1080, 0, 0, 999999, 0) + b"\xff\xff\xff\x7f")
    elif kind == 3:
        # Damaged CR3 atom sizes (size=1 64-bit overflow, size=3 invalid, unclosed mdat)
        raw = bytearray(struct.pack(">I4s4sI4s", 20, b"ftyp", b"crx ", 1, b"crx ") + struct.pack(">I4sQ", 1, b"mdat", 0xFFFFFFFFFFFFFFFF))
    elif kind == 4:
        # Damaged AVIF
        raw = bytearray(struct.pack(">I4s4sI4s", 20, b"ftyp", b"avif", 0, b"avif") + b"\x00\x00\x00\x03meta")
    else:
        # Damaged BRAW
        raw = bytearray(struct.pack(">I4s4sI4s", 20, b"ftyp", b"braw", 1, b"braw") + b"\xff\xff\xff\xffbxml")

    mutate_bytes(raw, rng.randrange(1, 8))
    if i % 5 == 0:
        raw = raw[:rng.randrange(0, min(12, len(raw)))]
    with open(os.path.join(carve_dir, f"sample_{i:03d}.bin"), "wb") as f:
        f.write(raw)
EOF

run_no_crash() {
  set +e
  "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ge 128 ]; then
    echo "FAILED: process crashed with signal (exit code $rc) on command: $*"
    exit 1
  fi
}

WORK_SUB="$TMP_DIR/cmd_work"
mkdir -p "$WORK_SUB"

IMG_COUNT=0
for img in "$CORRUPT_DIR"/disk_*.img; do
  run_no_crash "$TESTDISK" /list "$img"
  (
    cd "$WORK_SUB"
    TERM=xterm run_no_crash "$TESTDISK" /log /cmd "$img" advanced,list,recursive,filecopy,quit,quit
    chmod -R u+w "$WORK_SUB" 2>/dev/null || true
    rm -rf "$WORK_SUB"/*
  )
  IMG_COUNT=$((IMG_COUNT + 1))
done

run_no_crash "$FIDENTIFY" --check "$CARVE_DIR"
run_no_crash "$FIDENTIFY" --check "$CORRUPT_DIR"

CARVE_COUNT="$(ls -1 "$CARVE_DIR"/sample_*.bin | wc -l | tr -d ' ')"
TOTAL_COUNT=$((IMG_COUNT + CARVE_COUNT))
if [ "$TOTAL_COUNT" -lt 140 ]; then
  echo "FAILED: expected at least 140 corrupted test files, ran $TOTAL_COUNT"
  exit 1
fi

echo "PASSED ($TOTAL_COUNT damaged images and 5,000 ASan/UBSan mutations, 0 crashes)"

echo "========================================================================"
echo " Corrupted-image and sanitizer fuzz suite passed."
echo "========================================================================"
exit 0
