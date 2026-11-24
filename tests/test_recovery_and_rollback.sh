#!/usr/bin/env bash
#
# test_recovery_and_rollback.sh
# Automated integration test suite for TestDisk-NG and PhotoRec-NG
# Verifies partition inspection, safety rollback snapshot, --undo restoration, and file carving signatures.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Resolve binary paths (check in build dir first, then PATH)
if [ -x "$ROOT_DIR/src/testdisk-ng" ]; then
  TESTDISK="$ROOT_DIR/src/testdisk-ng"
  PHOTOREC="$ROOT_DIR/src/photorec-ng"
  FIDENTIFY="$ROOT_DIR/src/fidentify"
elif command -v testdisk-ng >/dev/null 2>&1; then
  TESTDISK="$(command -v testdisk-ng)"
  PHOTOREC="$(command -v photorec-ng)"
  FIDENTIFY="$(command -v fidentify)"
else
  echo "Error: testdisk-ng binary not found in $ROOT_DIR/src or PATH. Run 'make' first."
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/testdisk_test_XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "========================================================================"
echo " Starting TestDisk-NG & PhotoRec-NG Automated Test Suite"
echo " Working directory: $TMP_DIR"
echo " TestDisk binary:   $TESTDISK"
echo " PhotoRec binary:   $PHOTOREC"
echo " FIdentify binary:  $FIDENTIFY"
echo "========================================================================"

# Test 1: Verify version strings and CLI flags
echo -n "[Test 1/6] Checking binary versions and CLI options... "
TD_VER="$("$TESTDISK" /version)"
echo "$TD_VER" | grep -q "TestDisk-NG" || { echo "FAILED: testdisk-ng /version"; exit 1; }
echo "$TD_VER" | grep -q "legacyfs lib: 0.1.0" || { echo "FAILED: legacyfs lib version missing in /version"; exit 1; }

PH_VER="$("$PHOTOREC" /version)"
echo "$PH_VER" | grep -q "PhotoRec-NG" || { echo "FAILED: photorec-ng /version"; exit 1; }

HELP_OUT="$("$TESTDISK" --help)"
echo "$HELP_OUT" | grep -q -- "--undo" || { echo "FAILED: --undo option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--snapshot" || { echo "FAILED: --snapshot option missing in help"; exit 1; }
echo "PASSED"

# Test 2: Create synthetic disk image with valid MBR partition table
echo -n "[Test 2/6] Creating synthetic disk image and verifying geometry parsing... "
DISK_IMG="$TMP_DIR/synthetic_disk.img"
# Create 10MB zeroed disk image
dd if=/dev/zero of="$DISK_IMG" bs=1048576 count=10 status=none

# Write a valid MBR partition table with Python
python3 - <<EOF
with open("$DISK_IMG", "r+b") as f:
    # Seek to partition table entry 1 at offset 446 (0x1BE)
    f.seek(446)
    # Status: 0x80 (bootable), start CHS: 0/1/1
    # Type: 0x83 (Linux native)
    # End CHS: 1/254/63
    # Start LBA: 2048 (0x00000800)
    # Sector count: 18432 (0x00004800)
    part_entry = bytearray([
        0x80, 0x01, 0x01, 0x00,
        0x83, 0xFE, 0xFF, 0xFF,
        0x00, 0x08, 0x00, 0x00,
        0x00, 0x48, 0x00, 0x00
    ])
    f.write(part_entry)
    # Boot signature at offset 510
    f.seek(510)
    f.write(b"\x55\xAA")
EOF

LIST_OUT="$("$TESTDISK" /list "$DISK_IMG")"
echo "$LIST_OUT" | grep -q "Disk $DISK_IMG" || { echo "FAILED: disk listing"; exit 1; }
echo "$LIST_OUT" | grep -q "Linux" || { echo "FAILED: Linux partition not detected in listing"; exit 1; }
echo "PASSED"

# Test 3: Safety Rollback Journal Creation
echo -n "[Test 3/6] Testing safety rollback journal snapshot capture... "
cd "$TMP_DIR"
SNAP_OUT="$("$TESTDISK" --snapshot "$DISK_IMG" "Automated Pre-test Backup")"
echo "$SNAP_OUT" | grep -q "Created safety rollback journal:" || { echo "FAILED: snapshot creation output"; exit 1; }

JOURNAL_FILE="$(ls testdisk_undo_*.bin 2>/dev/null | head -n 1)"
if [ -z "$JOURNAL_FILE" ] || [ ! -f "$JOURNAL_FILE" ]; then
  echo "FAILED: Rollback journal file not found in $TMP_DIR"
  exit 1
fi

# Verify format magic TDUNDO01
python3 - <<EOF
with open("$JOURNAL_FILE", "rb") as f:
    magic = f.read(8)
    assert magic == b"TDUNDO01", f"Bad magic in rollback file: {magic}"
EOF
echo "PASSED ($JOURNAL_FILE)"

# Test 4: Simulate partition destruction & restore via --undo
echo -n "[Test 4/6] Corrupting partition sectors and verifying --undo restoration... "
# Save original 64 sectors for byte-level verification
dd if="$DISK_IMG" of="$TMP_DIR/orig_head.bin" bs=512 count=64 status=none

# Deliberately zero out partition table and boot sector
dd if=/dev/zero of="$DISK_IMG" bs=512 count=64 conv=notrunc status=none

# Verify corrupted state (no Linux partition recognized)
CORRUPT_LIST="$("$TESTDISK" /list "$DISK_IMG" || true)"
if echo "$CORRUPT_LIST" | grep -q "Linux"; then
  echo "FAILED: Linux partition still detected after zeroing"
  exit 1
fi

# Run rollback restore non-interactively
RESTORE_OUT="$("$TESTDISK" --undo "$JOURNAL_FILE" "$DISK_IMG" --yes)"
echo "$RESTORE_OUT" | grep -q "SUCCESS: Rollback completed successfully" || {
  echo "FAILED: rollback restore command output"
  echo "$RESTORE_OUT"
  exit 1
}

# Verify restored 64 sectors match the original pre-corruption sectors exactly
dd if="$DISK_IMG" of="$TMP_DIR/restored_head.bin" bs=512 count=64 status=none
cmp "$TMP_DIR/orig_head.bin" "$TMP_DIR/restored_head.bin" || {
  echo "FAILED: Restored sectors do not match original sectors"
  exit 1
}

# Confirm partition list recognizes Linux partition again
VERIFIED_LIST="$("$TESTDISK" /list "$DISK_IMG")"
echo "$VERIFIED_LIST" | grep -q "Linux" || { echo "FAILED: Linux partition not found after rollback"; exit 1; }
echo "PASSED (100% byte-for-byte sector restoration)"

# Test 5: PhotoRec FIdentify Signature Verification
echo -n "[Test 5/6] Testing file signature identification with FIdentify... "
SAMPLE_DIR="$TMP_DIR/samples"
mkdir -p "$SAMPLE_DIR"

# Generate valid minimal file format samples with Python
python3 - <<EOF
import base64, zipfile

# Sample 1: JPEG
with open("$SAMPLE_DIR/sample.jpg", "wb") as f:
    f.write(base64.b64decode("/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA="))

# Sample 2: PNG
with open("$SAMPLE_DIR/sample.png", "wb") as f:
    f.write(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="))

# Sample 3: ZIP
with zipfile.ZipFile("$SAMPLE_DIR/sample.zip", "w") as z:
    z.writestr("test.txt", "TestDisk-NG PhotoRec verification")

# Sample 4: PDF
with open("$SAMPLE_DIR/sample.pdf", "wb") as f:
    f.write(b"%PDF-1.7\n1 0 obj\n<<\n>>\nendobj\n")
EOF

F_OUT="$("$FIDENTIFY" "$SAMPLE_DIR")"
echo "$F_OUT" | grep -q "sample.jpg: jpg" || { echo "FAILED: JPEG identification"; exit 1; }
echo "$F_OUT" | grep -q "sample.png: png" || { echo "FAILED: PNG identification"; exit 1; }
echo "$F_OUT" | grep -q "sample.zip: zip" || { echo "FAILED: ZIP identification"; exit 1; }
echo "$F_OUT" | grep -q "sample.pdf: pdf" || { echo "FAILED: PDF identification"; exit 1; }
echo "PASSED"

# Test 6: Multi-filesystem directory listing and file extraction via legacyfs (ReiserFS v3.6 and CramFS)
echo -n "[Test 6/6] Testing legacyfs directory listing and file copy (ReiserFS v3.6 and CramFS)... "
RFS_IMG="$TMP_DIR/reiser_disk.img"
CRAM_IMG="$TMP_DIR/cram_disk.img"

python3 - <<EOF
import struct, zlib

PART_LBA = 2048
PART_SECTORS = 4096
PART_OFF = PART_LBA * 512
PART_BYTES = PART_SECTORS * 512

def make_mbr_image(part_bytes):
    disk = bytearray(PART_OFF + PART_BYTES)
    # MBR entry 1 at 446: Linux 0x83, LBA 2048, 4096 sectors
    disk[446:462] = struct.pack("<BBBBBBBBII", 0x80, 0, 1, 0, 0x83, 0xFE, 0xFF, 0xFF, PART_LBA, PART_SECTORS)
    disk[510:512] = b"\x55\xAA"
    disk[PART_OFF:PART_OFF + len(part_bytes)] = part_bytes
    return disk

# 1. Build ReiserFS v3.6 partition with /etc/hostname -> "reiserfs-recovered-host\n"
BSIZE = 4096
NBLOCKS = PART_BYTES // BSIZE
rfs = bytearray(PART_BYTES)
sb = 65536
struct.pack_into("<III", rfs, sb + 0, NBLOCKS, NBLOCKS - 25, 20) # root leaf at block 20
struct.pack_into("<H", rfs, sb + 40, 2)     # tree height 2
struct.pack_into("<H", rfs, sb + 44, BSIZE)
struct.pack_into("<H", rfs, sb + 50, 1)     # REISERFS_VALID_FS
rfs[sb + 52:sb + 61] = b"ReIsEr2Fs"
rfs[sb + 100:sb + 111] = b"RFS_RECOVER"

def v2_key(dir_id, obj_id, off, ktype):
    return struct.pack("<IIQ", dir_id, obj_id, (off & 0x0FFFFFFFFFFFFFFF) | (ktype << 60))

def sd_v2(mode, size):
    buf = bytearray(44)
    struct.pack_into("<HHIQII", buf, 0, mode, 0, 1, size, 1000, 1000)
    struct.pack_into("<I", buf, 28, 1700000000)
    return buf

leaf = 20 * BSIZE
# 6 items in sorted key order:
# 0: (1, 2, 0, SD) root dir
# 1: (1, 2, 1, DIR) -> "etc"=(2, 10)
# 2: (2, 10, 0, SD) /etc dir
# 3: (2, 10, 1, DIR) -> "hostname"=(10, 20)
# 4: (10, 20, 0, SD) /etc/hostname regular file
# 5: (10, 20, 1, DIRECT) payload
payload = b"reiserfs-recovered-host\n"
struct.pack_into("<HH", rfs, leaf + 0, 1, 6)

cursor = BSIZE
items = []

# Item 0: root SD
body = sd_v2(0o040755, 48)
cursor -= len(body); rfs[leaf + cursor:leaf + cursor + len(body)] = body
items.append((v2_key(1, 2, 0, 0), 0xFFFF, len(body), cursor, 1))

# Item 1: root DIR ("etc" -> (2, 10))
d1 = bytearray(32)
d1[16:20] = b"etc\x00"
struct.pack_into("<IIIHH", d1, 0, 1, 2, 10, 16, 4)
cursor -= len(d1); rfs[leaf + cursor:leaf + cursor + len(d1)] = d1
items.append((v2_key(1, 2, 1, 3), 1, len(d1), cursor, 1))

# Item 2: /etc SD
body = sd_v2(0o040755, 48)
cursor -= len(body); rfs[leaf + cursor:leaf + cursor + len(body)] = body
items.append((v2_key(2, 10, 0, 0), 0xFFFF, len(body), cursor, 1))

# Item 3: /etc DIR ("hostname" -> (10, 20))
d2 = bytearray(32)
d2[16:25] = b"hostname\x00"
struct.pack_into("<IIIHH", d2, 0, 1, 10, 20, 16, 4)
cursor -= len(d2); rfs[leaf + cursor:leaf + cursor + len(d2)] = d2
items.append((v2_key(2, 10, 1, 3), 1, len(d2), cursor, 1))

# Item 4: /etc/hostname SD
body = sd_v2(0o100644, len(payload))
cursor -= len(body); rfs[leaf + cursor:leaf + cursor + len(body)] = body
items.append((v2_key(10, 20, 0, 0), 0xFFFF, len(body), cursor, 1))

# Item 5: /etc/hostname DIRECT tail-packed item (offset starts at 1 in ReiserFS v3.6)
cursor -= len(payload); rfs[leaf + cursor:leaf + cursor + len(payload)] = payload
items.append((v2_key(10, 20, 1, 2), 0xFFFF, len(payload), cursor, 1))

for idx, (k, cnt, ilen, iloc, ver) in enumerate(items):
    ih_off = leaf + 24 + idx * 24
    rfs[ih_off:ih_off + 16] = k
    struct.pack_into("<HHHH", rfs, ih_off + 16, cnt, ilen, iloc, ver)

with open("$RFS_IMG", "wb") as f:
    f.write(make_mbr_image(rfs))

# 2. Build CramFS (zlib) partition with /firmware.txt
cram = bytearray(8192)
cmsg = b"cramfs-zlib-recovered-payload\n"
comp = zlib.compress(cmsg, 9)

def cram_inode(mode, size, namelen_bytes, off_bytes):
    w0 = (mode & 0xFFFF) | (1000 << 16)
    w1 = (size & 0xFFFFFF) | (100 << 24)
    w2 = ((namelen_bytes >> 2) & 0x3F) | ((off_bytes >> 2) << 6)
    return struct.pack("<III", w0, w1, w2)

file_off = 512
struct.pack_into("<I", cram, file_off, file_off + 4 + len(comp))
cram[file_off + 4:file_off + 4 + len(comp)] = comp

dir_off = 256
# "firmware.txt\x00" padded to 16 bytes -> total entry 12 + 16 = 28 bytes
cram[dir_off:dir_off + 12] = cram_inode(0o100644, len(cmsg), 16, file_off)
cram[dir_off + 12:dir_off + 25] = b"firmware.txt\x00"

struct.pack_into("<II", cram, 0, 0x28CD3D45, 4096)
cram[16:32] = b"Compressed ROMFS"
cram[48:57] = b"CRAM_PART"
cram[64:76] = cram_inode(0o040755, 28, 0, dir_off)

with open("$CRAM_IMG", "wb") as f:
    f.write(make_mbr_image(cram))
EOF

RFS_OUT_DIR="$TMP_DIR/rfs_extract"
mkdir -p "$RFS_OUT_DIR"
(cd "$RFS_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$RFS_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
[ -f "$RFS_OUT_DIR/etc/hostname" ] || { echo "FAILED: ReiserFS /etc/hostname not extracted"; cat "$RFS_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^reiserfs-recovered-host$" "$RFS_OUT_DIR/etc/hostname" || { echo "FAILED: ReiserFS content mismatch"; exit 1; }

CRAM_OUT_DIR="$TMP_DIR/cram_extract"
mkdir -p "$CRAM_OUT_DIR"
(cd "$CRAM_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$CRAM_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
[ -f "$CRAM_OUT_DIR/firmware.txt" ] || { echo "FAILED: CramFS /firmware.txt not extracted"; cat "$CRAM_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^cramfs-zlib-recovered-payload$" "$CRAM_OUT_DIR/firmware.txt" || { echo "FAILED: CramFS content mismatch"; exit 1; }
echo "PASSED"

echo "========================================================================"
echo " All 6 automated integration test suites passed successfully!"
echo "========================================================================"
exit 0
