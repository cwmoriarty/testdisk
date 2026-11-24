#!/usr/bin/env bash
#
# test_corrupted_fuzz.sh
# Automated ASan/UBSan legacyfs fuzzing and corrupted-image stress suite
# Verifies zero crashes across >= 2,500 in-process sanitizer mutations and
# >= 120 intentionally damaged MBR, GPT, filesystem, and carved-archive images.
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
echo -n "[Fuzz 1/2] Running 2,500 ASan/UBSan in-process legacyfs v0.2.0 mutations... "

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

# Part 2: Generate 120 corrupted partition, filesystem, and carved-archive images
# and exercise testdisk-ng /list, testdisk-ng /cmd advanced extraction, and fidentify --check
echo -n "[Fuzz 2/2] Stress-testing 120 damaged disk, filesystem, and carved images... "

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
    rm -rf "$WORK_SUB"/*
  )
  IMG_COUNT=$((IMG_COUNT + 1))
done

run_no_crash "$FIDENTIFY" --check "$CARVE_DIR"
run_no_crash "$FIDENTIFY" --check "$CORRUPT_DIR"

CARVE_COUNT="$(ls -1 "$CARVE_DIR"/sample_*.bin | wc -l | tr -d ' ')"
TOTAL_COUNT=$((IMG_COUNT + CARVE_COUNT))
if [ "$TOTAL_COUNT" -lt 100 ]; then
  echo "FAILED: expected at least 100 corrupted test files, ran $TOTAL_COUNT"
  exit 1
fi

echo "PASSED ($TOTAL_COUNT damaged images and 2,500 ASan/UBSan mutations, 0 crashes)"

echo "========================================================================"
echo " Corrupted-image and sanitizer fuzz suite passed."
echo "========================================================================"
exit 0
