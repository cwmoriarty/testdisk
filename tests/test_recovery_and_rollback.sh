#!/usr/bin/env bash
#
# test_recovery_and_rollback.sh
# Automated integration test suite for TestDisk-NG and PhotoRec-NG
# Verifies partition inspection, safety rollback snapshot, --undo restoration,
# handoff CLI flags, PhotoRec-NG file signature identification, and legacyfs tree extraction.
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
  chmod -R u+w "$TMP_DIR" 2>/dev/null || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "========================================================================"
echo " Starting TestDisk-NG and PhotoRec-NG Automated Test Suite"
echo " Working directory: $TMP_DIR"
echo " TestDisk binary:   $TESTDISK"
echo " PhotoRec binary:   $PHOTOREC"
echo " FIdentify binary:  $FIDENTIFY"
echo "========================================================================"

# Test 1: Verify version strings and CLI flags
echo -n "[Test 1/8] Checking binary versions and CLI options... "
TD_VER="$("$TESTDISK" /version)"
echo "$TD_VER" | grep -q "TestDisk-NG" || { echo "FAILED: testdisk-ng /version"; exit 1; }
echo "$TD_VER" | grep -q "Version: 7.4.0" || { echo "FAILED: expected Version: 7.4.0 in /version"; exit 1; }
echo "$TD_VER" | grep -q "legacyfs lib: 0.2.0" || { echo "FAILED: legacyfs lib 0.2.0 missing in /version"; exit 1; }
echo "$TD_VER" | grep -q "apple-explorer lib: 0.1.0" || { echo "FAILED: apple-explorer lib 0.1.0 missing in /version"; exit 1; }

PH_VER="$("$PHOTOREC" /version)"
echo "$PH_VER" | grep -q "PhotoRec-NG" || { echo "FAILED: photorec-ng /version"; exit 1; }

HELP_OUT="$("$TESTDISK" --help)"
echo "$HELP_OUT" | grep -q -- "--undo" || { echo "FAILED: --undo option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--snapshot" || { echo "FAILED: --snapshot option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--auto-snapshot" || { echo "FAILED: --auto-snapshot option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--handoff-report" || { echo "FAILED: --handoff-report option missing in help"; exit 1; }
echo "PASSED"

# Test 2: Create synthetic disk image with valid MBR partition table
echo -n "[Test 2/8] Creating synthetic disk image and verifying geometry parsing... "
DISK_IMG="$TMP_DIR/synthetic_disk.img"
dd if=/dev/zero of="$DISK_IMG" bs=1048576 count=10 status=none

python3 - <<EOF
with open("$DISK_IMG", "r+b") as f:
    f.seek(446)
    part_entry = bytearray([
        0x80, 0x01, 0x01, 0x00,
        0x83, 0xFE, 0xFF, 0xFF,
        0x00, 0x08, 0x00, 0x00,
        0x00, 0x48, 0x00, 0x00
    ])
    f.write(part_entry)
    f.seek(510)
    f.write(b"\x55\xAA")
EOF

LIST_OUT="$("$TESTDISK" /list "$DISK_IMG")"
echo "$LIST_OUT" | grep -q "Disk $DISK_IMG" || { echo "FAILED: disk listing"; exit 1; }
echo "$LIST_OUT" | grep -q "Linux" || { echo "FAILED: Linux partition not detected in listing"; exit 1; }
echo "PASSED"

# Test 3: Safety Rollback Journal Creation
echo -n "[Test 3/8] Testing safety rollback journal snapshot capture... "
cd "$TMP_DIR"
SNAP_OUT="$("$TESTDISK" --snapshot "$DISK_IMG" "Automated Pre-test Backup")"
echo "$SNAP_OUT" | grep -q "Created safety rollback journal:" || { echo "FAILED: snapshot creation output"; exit 1; }

JOURNAL_FILE="$(ls testdisk_undo_*.bin 2>/dev/null | head -n 1)"
if [ -z "$JOURNAL_FILE" ] || [ ! -f "$JOURNAL_FILE" ]; then
  echo "FAILED: Rollback journal file not found in $TMP_DIR"
  exit 1
fi

python3 - <<EOF
with open("$JOURNAL_FILE", "rb") as f:
    magic = f.read(8)
    assert magic == b"TDUNDO01", f"Bad magic in rollback file: {magic}"
EOF
echo "PASSED ($JOURNAL_FILE)"

# Test 4: Simulate partition destruction and restore via --undo
echo -n "[Test 4/8] Corrupting partition sectors and verifying --undo restoration... "
dd if="$DISK_IMG" of="$TMP_DIR/orig_head.bin" bs=512 count=64 status=none
dd if=/dev/zero of="$DISK_IMG" bs=512 count=64 conv=notrunc status=none

CORRUPT_LIST="$("$TESTDISK" /list "$DISK_IMG" || true)"
if echo "$CORRUPT_LIST" | grep -q "Linux"; then
  echo "FAILED: Linux partition still detected after zeroing"
  exit 1
fi

RESTORE_OUT="$("$TESTDISK" --undo "$JOURNAL_FILE" "$DISK_IMG" --yes)"
echo "$RESTORE_OUT" | grep -q "SUCCESS: Rollback completed successfully" || {
  echo "FAILED: rollback restore command output"
  echo "$RESTORE_OUT"
  exit 1
}

dd if="$DISK_IMG" of="$TMP_DIR/restored_head.bin" bs=512 count=64 status=none
cmp "$TMP_DIR/orig_head.bin" "$TMP_DIR/restored_head.bin" || {
  echo "FAILED: Restored sectors do not match original sectors"
  exit 1
}

VERIFIED_LIST="$("$TESTDISK" /list "$DISK_IMG")"
echo "$VERIFIED_LIST" | grep -q "Linux" || { echo "FAILED: Linux partition not found after rollback"; exit 1; }
echo "PASSED (100% byte-for-byte sector restoration)"

# Test 5: One-Click Recovery Handoff Flags (--auto-snapshot and --handoff-report)
echo -n "[Test 5/8] Testing --auto-snapshot and --handoff-report handoff flow... "
HANDOFF_DIR="$TMP_DIR/handoff_test"
mkdir -p "$HANDOFF_DIR"
HANDOFF_JSON="$HANDOFF_DIR/montserrat_report.json"
printf '{"source":"Montserrat","health":"degraded"}\n' > "$HANDOFF_JSON"

HANDOFF_OUT="$(cd "$HANDOFF_DIR" && "$TESTDISK" --auto-snapshot --handoff-report "$HANDOFF_JSON" /log /list "$DISK_IMG")"
echo "$HANDOFF_OUT" | grep -q "Created safety rollback journal:" || { echo "FAILED: --auto-snapshot did not create journal"; exit 1; }
echo "$HANDOFF_OUT" | grep -q "Linux" || { echo "FAILED: --auto-snapshot did not continue into /list"; exit 1; }
AUTO_JOURNAL="$(ls "$HANDOFF_DIR"/testdisk_undo_*.bin 2>/dev/null | head -n 1)"
[ -n "$AUTO_JOURNAL" ] && [ -f "$AUTO_JOURNAL" ] || { echo "FAILED: auto-snapshot journal missing on disk"; exit 1; }
grep -q "Montserrat handoff diagnostic report: $HANDOFF_JSON" "$HANDOFF_DIR/testdisk.log" || {
  echo "FAILED: handoff report path missing from testdisk.log"
  cat "$HANDOFF_DIR/testdisk.log" || true
  exit 1
}

# Verify --auto-snapshot logs a warning and continues safely on a tiny (<512B) image
TINY_IMG="$HANDOFF_DIR/tiny_subsector.img"
dd if=/dev/zero of="$TINY_IMG" bs=64 count=1 status=none
TINY_OUT="$(cd "$HANDOFF_DIR" && "$TESTDISK" --auto-snapshot /log /list "$TINY_IMG" 2>&1 || true)"
echo "$TINY_OUT" | grep -qi "Warning:" || { echo "FAILED: expected warning on tiny image auto-snapshot"; exit 1; }
echo "PASSED"

# Test 6: PhotoRec FIdentify Signature Verification (including zst, lz4, ivf, cr3, avif, braw)
echo -n "[Test 6/8] Testing file signature identification with FIdentify... "
SAMPLE_DIR="$TMP_DIR/samples"
mkdir -p "$SAMPLE_DIR"

python3 - <<EOF
import base64, struct, zipfile

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

# Sample 5: Zstandard (.zst) - RFC 8878 single-segment raw frame + optional checksum disabled
zst_payload = b"zstd-recovered-archive"
zst_bh = 1 | (0 << 1) | (len(zst_payload) << 3)
with open("$SAMPLE_DIR/sample.zst", "wb") as f:
    f.write(b"\x28\xb5\x2f\xfd" + bytes([0x20, len(zst_payload)]) + struct.pack("<I", zst_bh)[:3] + zst_payload)

# Sample 6: LZ4 Frame (.lz4) - Version 01, B.Indep=1, BD=64KB, 1 uncompressed block + EndMark
lz4_payload = b"lz4-frame-recovered-data"
with open("$SAMPLE_DIR/sample.lz4", "wb") as f:
    f.write(b"\x04\x22\x4d\x18\x60\x40\x82" + struct.pack("<I", 0x80000000 | len(lz4_payload)) + lz4_payload + b"\x00\x00\x00\x00")

# Sample 7: AV1 IVF Video Container (.ivf) - 32B DKIF header + 1 AV01 OBU frame
ivf_frame = b"\x12\x00\x0a\x00\x00\x00\x00\x00"
with open("$SAMPLE_DIR/sample.ivf", "wb") as f:
    f.write(struct.pack("<4sHH4sHHIIII", b"DKIF", 0, 32, b"AV01", 640, 360, 30, 1, 1, 0))
    f.write(struct.pack("<IQ", len(ivf_frame), 0) + ivf_frame)

# Sample 8: Canon RAW (.cr3) - ISO BMFF ftyp crx
with open("$SAMPLE_DIR/sample.cr3", "wb") as f:
    f.write(struct.pack(">I4s4sI4s4s", 24, b"ftyp", b"crx ", 1, b"crx ", b"isom"))
    f.write(struct.pack(">I4s8s", 16, b"moov", b"\x00" * 8))
    f.write(struct.pack(">I4s8s", 16, b"mdat", b"cr3-raw0"))

# Sample 9: AV1 Image (.avif) - ISO BMFF ftyp avif
with open("$SAMPLE_DIR/sample.avif", "wb") as f:
    f.write(struct.pack(">I4s4sI4s4s", 24, b"ftyp", b"avif", 0, b"mif1", b"avif"))
    f.write(struct.pack(">I4s8s", 16, b"meta", b"\x00" * 8))
    f.write(struct.pack(">I4s8s", 16, b"mdat", b"avifimg0"))

# Sample 10: Blackmagic RAW (.braw) - ISO BMFF ftyp braw
with open("$SAMPLE_DIR/sample.braw", "wb") as f:
    f.write(struct.pack(">I4s4sI4s4s", 24, b"ftyp", b"braw", 1, b"braw", b"qt  "))
    f.write(struct.pack(">I4s8s", 16, b"bxml", b"<braw/>\n"))
    f.write(struct.pack(">I4s8s", 16, b"mdat", b"brawfrm0"))
EOF

F_OUT="$("$FIDENTIFY" "$SAMPLE_DIR")"
echo "$F_OUT" | grep -q "sample.jpg: jpg" || { echo "FAILED: JPEG identification"; exit 1; }
echo "$F_OUT" | grep -q "sample.png: png" || { echo "FAILED: PNG identification"; exit 1; }
echo "$F_OUT" | grep -q "sample.zip: zip" || { echo "FAILED: ZIP identification"; exit 1; }
echo "$F_OUT" | grep -q "sample.pdf: pdf" || { echo "FAILED: PDF identification"; exit 1; }
echo "$F_OUT" | grep -q "sample.zst: zst" || { echo "FAILED: Zstandard (.zst) identification"; echo "$F_OUT"; exit 1; }
echo "$F_OUT" | grep -q "sample.lz4: lz4" || { echo "FAILED: LZ4 (.lz4) identification"; echo "$F_OUT"; exit 1; }
echo "$F_OUT" | grep -q "sample.ivf: ivf" || { echo "FAILED: IVF (.ivf) identification"; echo "$F_OUT"; exit 1; }
echo "$F_OUT" | grep -q "sample.cr3: cr3" || { echo "FAILED: Canon CR3 (.cr3) identification"; echo "$F_OUT"; exit 1; }
echo "$F_OUT" | grep -q "sample.avif: avif" || { echo "FAILED: AVIF (.avif) identification"; echo "$F_OUT"; exit 1; }
echo "$F_OUT" | grep -q "sample.braw: braw" || { echo "FAILED: BRAW (.braw) identification"; echo "$F_OUT"; exit 1; }

F_CHK="$("$FIDENTIFY" --check "$SAMPLE_DIR")"
echo "$F_CHK" | grep -q "sample.zst: zst file_size=31" || { echo "FAILED: Zstandard exact size check"; echo "$F_CHK"; exit 1; }
echo "$F_CHK" | grep -q "sample.lz4: lz4 file_size=39" || { echo "FAILED: LZ4 exact size check"; echo "$F_CHK"; exit 1; }
echo "$F_CHK" | grep -q "sample.ivf: ivf file_size=52" || { echo "FAILED: IVF exact size check"; echo "$F_CHK"; exit 1; }

# Verify PhotoRec-NG raw disk carving recovers exact byte lengths for zst, lz4, ivf, cr3, avif, braw
CARVE_IMG="$TMP_DIR/carve_raw.dd"
CARVE_OUT="$TMP_DIR/carve_recup"
python3 - <<EOF
import os, subprocess

disk = bytearray(256 * 512)
expected = {}
for idx, name in enumerate(["sample.zst", "sample.lz4", "sample.ivf", "sample.cr3", "sample.avif", "sample.braw"], start=1):
    with open(os.path.join("$SAMPLE_DIR", name), "rb") as sf:
        raw = sf.read()
    off = idx * 16 * 512
    disk[off:off + len(raw)] = raw
    expected[os.path.splitext(name)[1]] = len(raw)

with open("$CARVE_IMG", "wb") as f:
    f.write(disk)

env = dict(os.environ, TERM="xterm")
subprocess.run(
    ["$PHOTOREC", "/d", "$CARVE_OUT", "/cmd", "$CARVE_IMG", "partition_none,options,mode_ext2,fileopt,everything,enable,search"],
    cwd="$TMP_DIR", env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)

carved = {}
for root, _, files in os.walk("$TMP_DIR"):
    if "carve_recup" not in root:
        continue
    for fn in files:
        ext = os.path.splitext(fn)[1]
        carved[ext] = os.path.getsize(os.path.join(root, fn))

for ext, exp_len in expected.items():
    assert carved.get(ext) == exp_len, f"Carved {ext} length {carved.get(ext)} != expected {exp_len}"
EOF
echo "PASSED"

# Test 7: Multi-filesystem directory listing and file extraction via legacyfs v0.2.0
# (ReiserFS v3.6, CramFS, XFS v5, Btrfs, and UDF)
echo -n "[Test 7/8] Testing legacyfs v0.2.0 extraction (ReiserFS, CramFS, XFS v5, Btrfs, UDF)... "
RFS_IMG="$TMP_DIR/reiser_disk.img"
CRAM_IMG="$TMP_DIR/cram_disk.img"
XFS_IMG="$TMP_DIR/xfs_disk.img"
BTRFS_IMG="$TMP_DIR/btrfs_disk.img"
UDF_IMG="$TMP_DIR/udf_disk.img"

python3 - <<EOF
import struct, zlib

PART_LBA = 2048
PART_SECTORS = 4096
PART_OFF = PART_LBA * 512
PART_BYTES = PART_SECTORS * 512

def make_mbr_image(part_bytes, part_type=0x83):
    disk = bytearray(PART_OFF + PART_BYTES)
    disk[446:462] = struct.pack("<BBBBBBBBII", 0x80, 0, 1, 0, part_type, 0xFE, 0xFF, 0xFF, PART_LBA, PART_SECTORS)
    disk[510:512] = b"\x55\xAA"
    disk[PART_OFF:PART_OFF + len(part_bytes)] = part_bytes
    return disk

# 1. ReiserFS v3.6 partition with /etc/hostname
BSIZE = 4096
NBLOCKS = PART_BYTES // BSIZE
rfs = bytearray(PART_BYTES)
sb = 65536
struct.pack_into("<III", rfs, sb + 0, NBLOCKS, NBLOCKS - 25, 20)
struct.pack_into("<H", rfs, sb + 40, 2)
struct.pack_into("<H", rfs, sb + 44, BSIZE)
struct.pack_into("<H", rfs, sb + 50, 1)
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
payload = b"reiserfs-recovered-host\n"
struct.pack_into("<HH", rfs, leaf + 0, 1, 6)
cursor = BSIZE
items = []

body = sd_v2(0o040755, 48)
cursor -= len(body); rfs[leaf + cursor:leaf + cursor + len(body)] = body
items.append((v2_key(1, 2, 0, 0), 0xFFFF, len(body), cursor, 1))

d1 = bytearray(32)
d1[16:20] = b"etc\x00"
struct.pack_into("<IIIHH", d1, 0, 1, 2, 10, 16, 4)
cursor -= len(d1); rfs[leaf + cursor:leaf + cursor + len(d1)] = d1
items.append((v2_key(1, 2, 1, 3), 1, len(d1), cursor, 1))

body = sd_v2(0o040755, 48)
cursor -= len(body); rfs[leaf + cursor:leaf + cursor + len(body)] = body
items.append((v2_key(2, 10, 0, 0), 0xFFFF, len(body), cursor, 1))

d2 = bytearray(32)
d2[16:25] = b"hostname\x00"
struct.pack_into("<IIIHH", d2, 0, 1, 10, 20, 16, 4)
cursor -= len(d2); rfs[leaf + cursor:leaf + cursor + len(d2)] = d2
items.append((v2_key(2, 10, 1, 3), 1, len(d2), cursor, 1))

body = sd_v2(0o100644, len(payload))
cursor -= len(body); rfs[leaf + cursor:leaf + cursor + len(body)] = body
items.append((v2_key(10, 20, 0, 0), 0xFFFF, len(body), cursor, 1))

cursor -= len(payload); rfs[leaf + cursor:leaf + cursor + len(payload)] = payload
items.append((v2_key(10, 20, 1, 2), 0xFFFF, len(payload), cursor, 1))

for idx, (k, cnt, ilen, iloc, ver) in enumerate(items):
    ih_off = leaf + 24 + idx * 24
    rfs[ih_off:ih_off + 16] = k
    struct.pack_into("<HHHH", rfs, ih_off + 16, cnt, ilen, iloc, ver)

with open("$RFS_IMG", "wb") as f:
    f.write(make_mbr_image(rfs))

# 2. CramFS (zlib) partition with /firmware.txt
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
cram[dir_off:dir_off + 12] = cram_inode(0o100644, len(cmsg), 16, file_off)
cram[dir_off + 12:dir_off + 25] = b"firmware.txt\x00"

struct.pack_into("<II", cram, 0, 0x28CD3D45, 4096)
cram[16:32] = b"Compressed ROMFS"
cram[48:57] = b"CRAM_PART"
cram[64:76] = cram_inode(0o040755, 28, 0, dir_off)

with open("$CRAM_IMG", "wb") as f:
    f.write(make_mbr_image(cram))

# 3. XFS v5 partition with /srv.log
xfs_bsize = 4096
xfs_nblocks = 64
xfs = bytearray(xfs_nblocks * xfs_bsize)
struct.pack_into(">IIQ", xfs, 0, 0x58465342, xfs_bsize, xfs_nblocks)
struct.pack_into(">Q", xfs, 56, 64)
struct.pack_into(">II", xfs, 84, xfs_nblocks, 1)
struct.pack_into(">HHHH", xfs, 100, 5, 512, 512, 8)
xfs[108:119] = b"XFS_RECOVER"
xfs[120] = 12  # blocklog
xfs[121] = 9   # sectlog
xfs[122] = 9   # inodelog
xfs[123] = 3   # inopblog
xfs[124] = 6   # agblklog
struct.pack_into(">I", xfs, 208, 1)  # INCOMPAT_FTYPE

di_root = 8 * xfs_bsize
struct.pack_into(">HHBB", xfs, di_root, 0x494E, 0o040755, 3, 1)
struct.pack_into(">I", xfs, di_root + 16, 2)
sf = di_root + 176
xfs[sf + 0] = 1
xfs[sf + 1] = 0
struct.pack_into(">I", xfs, sf + 2, 64)
xfs[sf + 6] = 7
struct.pack_into(">H", xfs, sf + 7, 0x60)
xfs[sf + 9:sf + 16] = b"srv.log"
xfs[sf + 16] = 1
struct.pack_into(">I", xfs, sf + 17, 65)
struct.pack_into(">Q", xfs, di_root + 56, 21)

xfs_msg = b"xfs-v5-extent-recovered-log\n"
di_file = 8 * xfs_bsize + 512
struct.pack_into(">HHBB", xfs, di_file, 0x494E, 0o100644, 3, 2)
struct.pack_into(">I", xfs, di_file + 16, 1)
struct.pack_into(">QQ", xfs, di_file + 56, len(xfs_msg), 1)
struct.pack_into(">I", xfs, di_file + 76, 1)
bmbt_hi = (0 << 9) | (20 >> 43)
bmbt_lo = ((20 & ((1 << 43) - 1)) << 21) | 1
struct.pack_into(">QQ", xfs, di_file + 176, bmbt_hi, bmbt_lo)
xfs[20 * xfs_bsize:20 * xfs_bsize + len(xfs_msg)] = xfs_msg

with open("$XFS_IMG", "wb") as f:
    f.write(make_mbr_image(xfs))

# 4. Btrfs partition with zlib-compressed /snap.txt
btrfs_sz = 256 * 1024
btrfs = bytearray(btrfs_sz)
nodesz = 4096
bsb = 65536
struct.pack_into("<Q", btrfs, bsb + 48, PART_OFF + bsb)
btrfs[bsb + 64:bsb + 72] = b"_BHRfS_M"
struct.pack_into("<Q", btrfs, bsb + 80, 0x100000)
struct.pack_into("<QQQ", btrfs, bsb + 112, btrfs_sz, 65536, 256)
struct.pack_into("<II", btrfs, bsb + 144, 4096, nodesz)
struct.pack_into("<I", btrfs, bsb + 160, 97)
struct.pack_into("<I", btrfs, bsb + 233, 4096)  # dev_item.sector_size
btrfs[bsb + 299:bsb + 312] = b"BTRFS_RECOVER"

def btrfs_key(oid, ktype, koff):
    return struct.pack("<QBQ", oid, ktype, koff)

btrfs[bsb + 811:bsb + 828] = btrfs_key(256, 228, 0x100000)
ch = bsb + 828
struct.pack_into("<Q", btrfs, ch + 0, 131072)
struct.pack_into("<H", btrfs, ch + 44, 1)
struct.pack_into("<QQ", btrfs, ch + 48, 1, 131072)

rt = 131072
struct.pack_into("<I", btrfs, rt + 96, 1)
ritem_sz = 200
ritem_off = nodesz - 101 - ritem_sz
btrfs[rt + 101:rt + 118] = btrfs_key(5, 132, 0)
struct.pack_into("<II", btrfs, rt + 118, ritem_off, ritem_sz)
struct.pack_into("<Q", btrfs, rt + 101 + ritem_off + 176, 0x101000)

btrfs_msg = b"btrfs-zlib-recovered-snapshot\n"
btrfs_comp = zlib.compress(btrfs_msg, 9)
btrfs[139264:139264 + len(btrfs_comp)] = btrfs_comp

ft = 135168
struct.pack_into("<I", btrfs, ft + 96, 4)
bcur = nodesz - 101

def btrfs_inode(mode, size):
    ib = bytearray(160)
    struct.pack_into("<Q", ib, 0, 1)
    struct.pack_into("<QQ", ib, 16, size, 4096)
    struct.pack_into("<IIII", ib, 40, 1, 1000, 1000, mode)
    struct.pack_into("<Q", ib, 136, 1700000000)
    return ib

def btrfs_add(idx, oid, ktype, koff, body_bytes):
    global bcur
    bcur -= len(body_bytes)
    btrfs[ft + 101 + bcur:ft + 101 + bcur + len(body_bytes)] = body_bytes
    itp = ft + 101 + idx * 25
    btrfs[itp:itp + 17] = btrfs_key(oid, ktype, koff)
    struct.pack_into("<II", btrfs, itp + 17, bcur, len(body_bytes))

btrfs_add(0, 256, 1, 0, btrfs_inode(0o040755, 64))
de = bytearray(38)
de[0:17] = btrfs_key(257, 1, 0)
struct.pack_into("<HB", de, 27, 8, 1)
de[30:38] = b"snap.txt"
btrfs_add(1, 256, 96, 2, de)
btrfs_add(2, 257, 1, 0, btrfs_inode(0o100644, len(btrfs_msg)))
ext = bytearray(53)
struct.pack_into("<Q", ext, 8, len(btrfs_msg))
ext[16] = 1  # ZLIB
ext[20] = 1  # REG
struct.pack_into("<QQQQ", ext, 21, 0x102000, len(btrfs_comp), 0, len(btrfs_msg))
btrfs_add(3, 257, 108, 0, ext)

with open("$BTRFS_IMG", "wb") as f:
    f.write(make_mbr_image(btrfs))

# 5. UDF partition (2048B blocks, CS0 UTF-16BE filename /video.txt)
udf_bsize = 2048
udf = bytearray(300 * udf_bsize)
udf[32769:32774] = b"NSR03"

avdp = 256 * udf_bsize
struct.pack_into("<H", udf, avdp + 0, 2)
struct.pack_into("<III", udf, avdp + 12, 256, 4 * udf_bsize, 32)

pd = 32 * udf_bsize
struct.pack_into("<H", udf, pd + 0, 5)
struct.pack_into("<II", udf, pd + 188, 64, 200)

lvd = 33 * udf_bsize
struct.pack_into("<H", udf, lvd + 0, 6)
udf[lvd + 84] = 8
udf[lvd + 85:lvd + 93] = b"UDF_DISC"
udf[lvd + 84 + 127] = 9
struct.pack_into("<I", udf, lvd + 212, udf_bsize)
struct.pack_into("<II", udf, lvd + 248, udf_bsize, 0)

struct.pack_into("<H", udf, 34 * udf_bsize, 8)

fsd = 64 * udf_bsize
struct.pack_into("<H", udf, fsd + 0, 256)
struct.pack_into("<II", udf, fsd + 400, udf_bsize, 1)

fids = bytearray(60)
struct.pack_into("<H", fids, 0, 257)
fids[18] = 0
fids[19] = 19
struct.pack_into("<II", fids, 20, udf_bsize, 2)
fids[38] = 16  # CS0 UTF-16BE
fids[39:57] = "video.txt".encode("utf-16-be")

rfe = 65 * udf_bsize
struct.pack_into("<H", udf, rfe + 0, 261)
udf[rfe + 27] = 4  # directory
struct.pack_into("<H", udf, rfe + 34, 3)  # inline AD_IN_ICB
struct.pack_into("<Q", udf, rfe + 56, len(fids))
struct.pack_into("<I", udf, rfe + 172, len(fids))
udf[rfe + 176:rfe + 176 + len(fids)] = fids

udf_msg = b"udf-archival-recovered-payload\n"
ffe = 66 * udf_bsize
struct.pack_into("<H", udf, ffe + 0, 261)
udf[ffe + 27] = 5  # regular file
struct.pack_into("<H", udf, ffe + 34, 0)  # short_ad
struct.pack_into("<Q", udf, ffe + 56, len(udf_msg))
struct.pack_into("<I", udf, ffe + 172, 8)
struct.pack_into("<II", udf, ffe + 176, len(udf_msg), 4)
udf[68 * udf_bsize:68 * udf_bsize + len(udf_msg)] = udf_msg

with open("$UDF_IMG", "wb") as f:
    f.write(make_mbr_image(udf, 0x07))
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

XFS_OUT_DIR="$TMP_DIR/xfs_extract"
mkdir -p "$XFS_OUT_DIR"
(cd "$XFS_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$XFS_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
[ -f "$XFS_OUT_DIR/srv.log" ] || { echo "FAILED: XFS v5 /srv.log not extracted"; cat "$XFS_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^xfs-v5-extent-recovered-log$" "$XFS_OUT_DIR/srv.log" || { echo "FAILED: XFS v5 content mismatch"; exit 1; }

BTRFS_OUT_DIR="$TMP_DIR/btrfs_extract"
mkdir -p "$BTRFS_OUT_DIR"
(cd "$BTRFS_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$BTRFS_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
[ -f "$BTRFS_OUT_DIR/snap.txt" ] || { echo "FAILED: Btrfs /snap.txt not extracted"; cat "$BTRFS_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^btrfs-zlib-recovered-snapshot$" "$BTRFS_OUT_DIR/snap.txt" || { echo "FAILED: Btrfs content mismatch"; exit 1; }

UDF_OUT_DIR="$TMP_DIR/udf_extract"
mkdir -p "$UDF_OUT_DIR"
(cd "$UDF_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$UDF_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
[ -f "$UDF_OUT_DIR/video.txt" ] || { echo "FAILED: UDF /video.txt not extracted"; cat "$UDF_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^udf-archival-recovered-payload$" "$UDF_OUT_DIR/video.txt" || { echo "FAILED: UDF content mismatch"; exit 1; }
echo "PASSED"

# Test 8: Apple filesystem directory listing and extraction via apple-explorer v0.1.0
# (Classic HFS, HFS+ with Backups.backupdb hard links + decmpfs, APFS checkpoint ring + /Backups timeline)
echo -n "[Test 8/8] Testing apple-explorer v0.1.0 extraction (Classic HFS, HFS+ Backups.backupdb, APFS snapshots)... "
HFS_IMG="$TMP_DIR/classic_hfs_disk.img"
HFSP_TM_IMG="$TMP_DIR/hfsp_tm_disk.img"
APFS_SNAP_IMG="$TMP_DIR/apfs_snap_disk.img"

python3 - <<EOF
import binascii, struct

PART_LBA = 2048
PART_OFF = PART_LBA * 512

def make_mbr_apple_image(part_bytes, part_type=0xAF):
    secs = (len(part_bytes) + 511) // 512
    disk = bytearray(PART_OFF + secs * 512)
    disk[446:462] = struct.pack("<BBBBBBBBII", 0x80, 0, 1, 0, part_type, 0xFE, 0xFF, 0xFF, PART_LBA, secs)
    disk[510:512] = b"\x55\xAA"
    disk[PART_OFF:PART_OFF + len(part_bytes)] = part_bytes
    return disk

def make_gpt_apfs_image(part_bytes):
    part_secs = (len(part_bytes) + 511) // 512
    start_lba = 64
    end_lba = start_lba + part_secs - 1
    total_lba = end_lba + 64
    disk = bytearray(total_lba * 512)
    # Protective MBR
    struct.pack_into("<BBBBBBBBII", disk, 446, 0x00, 0, 2, 0, 0xEE, 0xFE, 0xFF, 0xFF, 1, total_lba - 1)
    disk[510:512] = b"\x55\xAA"

    # Partition entry 0: Apple APFS GUID 7C3457EF-0000-11AA-AA11-00306543ECAC
    entries = bytearray(128 * 128)
    apfs_guid = struct.pack("<IHH8s", 0x7C3457EF, 0x0000, 0x11AA, bytes([0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC]))
    uniq_guid = bytes(range(1, 17))
    entries[0:16] = apfs_guid
    entries[16:32] = uniq_guid
    struct.pack_into("<QQQ", entries, 32, start_lba, end_lba, 0)
    entries[56:56 + 20] = "APFSBackup".encode("utf-16-le")
    entries_crc = binascii.crc32(entries) & 0xFFFFFFFF

    # Primary GPT header at LBA 1 + entries at LBA 2..33
    disk[2 * 512:34 * 512] = entries
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ16sQIII", hdr, 8,
        0x00010000, 92, 0, 0,
        1, total_lba - 1, 34, total_lba - 34,
        bytes(range(17, 33)), 2, 128, 128, entries_crc)
    struct.pack_into("<I", hdr, 16, binascii.crc32(hdr) & 0xFFFFFFFF)
    disk[1 * 512:1 * 512 + 92] = hdr

    # Backup GPT entries + Backup GPT header at total_lba - 1
    alt_table_lba = total_lba - 33
    disk[alt_table_lba * 512:(alt_table_lba + 32) * 512] = entries
    bhdr = bytearray(92)
    bhdr[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ16sQIII", bhdr, 8,
        0x00010000, 92, 0, 0,
        total_lba - 1, 1, 34, total_lba - 34,
        bytes(range(17, 33)), alt_table_lba, 128, 128, entries_crc)
    struct.pack_into("<I", bhdr, 16, binascii.crc32(bhdr) & 0xFFFFFFFF)
    disk[(total_lba - 1) * 512:(total_lba - 1) * 512 + 92] = bhdr

    disk[start_lba * 512:start_lba * 512 + len(part_bytes)] = part_bytes
    return disk

# 1. Classic HFS ('BD') partition with /ReadMe.txt
hfs = bytearray(65536)
mdb = 1024
struct.pack_into(">H", hfs, mdb + 0, 0x4244)
struct.pack_into(">HI", hfs, mdb + 18, 64, 512)
struct.pack_into(">H", hfs, mdb + 28, 4)
struct.pack_into(">H", hfs, mdb + 34, 40)
hfs[mdb + 36] = 9
hfs[mdb + 37:mdb + 46] = b"RetroMac9"
struct.pack_into(">IHH", hfs, mdb + 146, 1024, 0, 2)

n0 = 2048
hfs[n0 + 8] = 1
struct.pack_into(">H", hfs, n0 + 10, 1)
struct.pack_into(">I", hfs, n0 + 24, 1)
struct.pack_into(">H", hfs, n0 + 32, 512)
struct.pack_into(">H", hfs, n0 + 510, 14)

n1 = 2560
hfs[n1 + 8] = 0xFF
struct.pack_into(">H", hfs, n1 + 10, 2)
r0 = 14
hfs[n1 + r0] = 15
struct.pack_into(">I", hfs, n1 + r0 + 2, 1)
hfs[n1 + r0 + 6] = 9
hfs[n1 + r0 + 7:n1 + r0 + 16] = b"RetroMac9"
d0 = r0 + 16
hfs[n1 + d0] = 1
struct.pack_into(">I", hfs, n1 + d0 + 6, 2)

hfs_msg = b"classic-hfs-recovered-readme\n"
r1 = 110
hfs[n1 + r1] = 16
struct.pack_into(">I", hfs, n1 + r1 + 2, 2)
hfs[n1 + r1 + 6] = 10
hfs[n1 + r1 + 7:n1 + r1 + 17] = b"ReadMe.txt"
d1 = r1 + 18
hfs[n1 + d1] = 2
struct.pack_into(">I", hfs, n1 + d1 + 20, 16)
struct.pack_into(">I", hfs, n1 + d1 + 26, len(hfs_msg))
struct.pack_into(">HH", hfs, n1 + d1 + 74, 2, 1)
struct.pack_into(">HH", hfs, n1 + 508, r1, r0)
hfs[2048 + 2 * 512:2048 + 2 * 512 + len(hfs_msg)] = hfs_msg
# Mirror MDB to backup offset (len - 1024)
hfs[len(hfs) - 1024:len(hfs) - 512] = hfs[mdb:mdb + 512]

with open("$HFS_IMG", "wb") as f:
    f.write(make_mbr_apple_image(hfs, 0xAF))

# 2. HFS+ ('H+') partition with Backups.backupdb directory hard links + com.apple.decmpfs
bsz = 4096
hfsp = bytearray(16 * bsz)
vh = 1024
struct.pack_into(">HH", hfsp, vh + 0, 0x482B, 4)
struct.pack_into(">III", hfsp, vh + 40, bsz, len(hfsp) // bsz, 8)
# Catalog file at blocks 2..3
struct.pack_into(">Q", hfsp, vh + 272, 2 * bsz)
struct.pack_into(">III", hfsp, vh + 272 + 12, 2, 2, 2)
# Attributes file at blocks 4..5
struct.pack_into(">Q", hfsp, vh + 352, 2 * bsz)
struct.pack_into(">III", hfsp, vh + 352 + 12, 2, 4, 2)

cn0 = 2 * bsz
hfsp[cn0 + 8] = 1
struct.pack_into(">H", hfsp, cn0 + 10, 1)
struct.pack_into(">I", hfsp, cn0 + 24, 1)
struct.pack_into(">H", hfsp, cn0 + 32, bsz)
struct.pack_into(">H", hfsp, cn0 + bsz - 2, 14)

cn1 = 3 * bsz
hfsp[cn1 + 8] = 0xFF
rec_offs = []
cur = 14

def add_hfsp_key(node, off, parent_id, u16_units):
    klen = 6 + 2 * len(u16_units)
    struct.pack_into(">HIH", node, off, klen, parent_id, len(u16_units))
    for idx, ch in enumerate(u16_units):
        struct.pack_into(">H", node, off + 8 + idx * 2, ch)
    return off + 2 + klen

def add_folder(parent_id, u16_units, cnid):
    global cur
    rec_offs.append(cur)
    cur = add_hfsp_key( hfsp, cn1 + cur, parent_id, u16_units ) - cn1
    struct.pack_into(">H", hfsp, cn1 + cur, 1)
    struct.pack_into(">I", hfsp, cn1 + cur + 8, cnid)
    cur += 88

add_folder(1, [ord(c) for c in "TimeMachineHD"], 2)
pdd_units = [0, 0, 0, 0] + [ord(c) for c in "HFS+ Private Directory Data\r"]
add_folder(2, pdd_units, 20)
add_folder(2, [ord(c) for c in "Backups.backupdb"], 30)
add_folder(30, [ord(c) for c in "MacBookPro"], 31)
add_folder(31, [ord(c) for c in "2026-11-24-090000"], 32)

# Directory hard link stub Documents (parent 32, CNID 33 -> special.iNodeNum = 777, 'fldr'/'hlnk')
rec_offs.append(cur)
cur = add_hfsp_key(hfsp, cn1 + cur, 32, [ord(c) for c in "Documents"]) - cn1
struct.pack_into(">H", hfsp, cn1 + cur, 2)
struct.pack_into(">I", hfsp, cn1 + cur + 8, 33)
struct.pack_into(">HIII", hfsp, cn1 + cur + 42, 0o100444, 777, 0x666C6472, 0x686C6E6B)
cur += 248

# Target shared directory dir_777 inside Private Directory Data (parent 20, CNID 50)
add_folder(20, [ord(c) for c in "dir_777"], 50)

# Compressed file budget.txt inside dir_777 (parent 50, CNID 51, UF_COMPRESSED)
rec_offs.append(cur)
cur = add_hfsp_key(hfsp, cn1 + cur, 50, [ord(c) for c in "budget.txt"]) - cn1
struct.pack_into(">H", hfsp, cn1 + cur, 2)
struct.pack_into(">I", hfsp, cn1 + cur + 8, 51)
hfsp[cn1 + cur + 41] = 0x20
struct.pack_into(">H", hfsp, cn1 + cur + 42, 0o100644)
cur += 248

struct.pack_into(">H", hfsp, cn1 + 10, len(rec_offs))
for idx, ro in enumerate(rec_offs):
    struct.pack_into(">H", hfsp, cn1 + bsz - 2 * (idx + 1), ro)

an0 = 4 * bsz
hfsp[an0 + 8] = 1
struct.pack_into(">H", hfsp, an0 + 10, 1)
struct.pack_into(">I", hfsp, an0 + 24, 1)
struct.pack_into(">H", hfsp, an0 + 32, bsz)
struct.pack_into(">H", hfsp, an0 + bsz - 2, 14)

an1 = 5 * bsz
hfsp[an1 + 8] = 0xFF
struct.pack_into(">H", hfsp, an1 + 10, 1)
aoff = 14
attr_name = "com.apple.decmpfs"
aklen = 12 + 2 * len(attr_name)
struct.pack_into(">HHIIH", hfsp, an1 + aoff, aklen, 0, 51, 0, len(attr_name))
for idx, ch in enumerate(attr_name):
    struct.pack_into(">H", hfsp, an1 + aoff + 14 + idx * 2, ord(ch))
budget_msg = b"hfsp-timemachine-recovered-budget\n"
aval = an1 + aoff + 2 + aklen
struct.pack_into(">IIII", hfsp, aval + 0, 0x10, 0, 0, 16 + 1 + len(budget_msg))
struct.pack_into("<IIQ", hfsp, aval + 16, 0x636D7066, 3, len(budget_msg))
hfsp[aval + 32] = 0xFF
hfsp[aval + 33:aval + 33 + len(budget_msg)] = budget_msg
struct.pack_into(">H", hfsp, an1 + bsz - 2, aoff)
hfsp[len(hfsp) - 1024:len(hfsp) - 512] = hfsp[vh:vh + 512]

with open("$HFSP_TM_IMG", "wb") as f:
    f.write(make_mbr_apple_image(hfsp, 0xAF))

# 3. APFS ('NXSB' + 'APSB') in GPT with Fletcher-64 checkpoint ring + /Backups snapshot timeline
def apfs_fletcher64(blk):
    mod = 0xFFFFFFFF
    s1 = 0
    s2 = 0
    for off in range(8, len(blk), 4):
        w = struct.unpack_from("<I", blk, off)[0]
        s1 = (s1 + w) % mod
        s2 = (s2 + s1) % mod
    c1 = mod - ((s1 + s2) % mod)
    c2 = mod - ((s1 + c1) % mod)
    return (c2 << 32) | c1

def seal_apfs(buf, blk_idx, oid, xid, otype, osub=0):
    base = blk_idx * 4096
    struct.pack_into("<QQII", buf, base + 8, oid, xid, otype, osub)
    ck = apfs_fletcher64(buf[base:base + 4096])
    struct.pack_into("<Q", buf, base + 0, ck)

apfs_blocks = 16
apfs = bytearray(apfs_blocks * 4096)

# Block 0: older NXSB (xid=15) pointing to checkpoint descriptor ring at blocks 12..13 (len=2)
# Block 12: latest valid NXSB (xid=20)
# Block 13: torn/uncommitted NXSB (xid=25 with invalid Fletcher-64 checksum, must be skipped)
for bidx, xid, corrupt in [(0, 15, False), (12, 20, False), (13, 25, True)]:
    b = bidx * 4096
    struct.pack_into("<IIQ", apfs, b + 32, 0x4253584E, 4096, apfs_blocks)
    struct.pack_into("<IIQQ", apfs, b + 104, 2, 0, 12, 14)  # xp_desc_blocks=2, xp_desc_base=12
    struct.pack_into("<Q", apfs, b + 160, 1 if xid == 20 else 0)  # only xid=20 points to valid container omap=1
    struct.pack_into("<Q", apfs, b + 184, 100)
    seal_apfs(apfs, bidx, 1, xid, 0x80000001)
    if corrupt:
        apfs[b + 0] ^= 0xFF

# Block 1: Container OMAP -> tree at block 2
struct.pack_into("<Q", apfs, 1 * 4096 + 48, 2)
seal_apfs(apfs, 1, 1, 20, 0x0000000B)

# Block 2: Container OMAP B-tree: (oid=100, xid=20) -> paddr=3
b2 = 2 * 4096
struct.pack_into("<HHIHH", apfs, b2 + 32, 0x0007, 0, 1, 0, 64)
struct.pack_into("<HH", apfs, b2 + 56, 0, 16)
struct.pack_into("<QQ", apfs, b2 + 120, 100, 20)
struct.pack_into("<Q", apfs, b2 + (4056 - 16) + 8, 3)
seal_apfs(apfs, 2, 2, 20, 0x40000002, 0x0000000B)

# Block 3 (Live APSB xid=20) and Block 9 (Snapshot APSB xid=10)
for bidx, xid, is_snap in [(3, 20, False), (9, 10, True)]:
    b = bidx * 4096
    struct.pack_into("<I", apfs, b + 32, 0x42535041)
    struct.pack_into("<Q", apfs, b + 56, 1)
    struct.pack_into("<Q", apfs, b + 88, 12)
    struct.pack_into("<QQ", apfs, b + 128, 4, 200)
    if not is_snap:
        struct.pack_into("<Q", apfs, b + 152, 8)
        struct.pack_into("<Q", apfs, b + 216, 1)
    struct.pack_into("<Q", apfs, b + 264, 1)
    apfs[b + 704:b + 716] = b"TMBackupAPFS"
    struct.pack_into("<H", apfs, b + 964, 0x0080)
    seal_apfs(apfs, bidx, 100, xid, 0x4000000D)

# Block 4: Volume OMAP -> tree at block 5
struct.pack_into("<Q", apfs, 4 * 4096 + 48, 5)
seal_apfs(apfs, 4, 4, 20, 0x0000000B)

# Block 5: Volume OMAP B-tree: (200, 10)->6 and (200, 20)->7
b5 = 5 * 4096
struct.pack_into("<HHIHH", apfs, b5 + 32, 0x0007, 0, 2, 0, 64)
struct.pack_into("<HHHH", apfs, b5 + 56, 0, 16, 16, 32)
struct.pack_into("<QQQQ", apfs, b5 + 120, 200, 10, 200, 20)
struct.pack_into("<Q", apfs, b5 + (4056 - 16) + 8, 6)
struct.pack_into("<Q", apfs, b5 + (4056 - 32) + 8, 7)
seal_apfs(apfs, 5, 5, 20, 0x40000002, 0x0000000B)

class LeafBuilder:
    def __init__(self, blk_idx):
        self.base = blk_idx * 4096
        struct.pack_into("<HHIHH", apfs, self.base + 32, 0x0003, 0, 0, 0, 256)
        self.count = 0
        self.kcur = 0
        self.vcur = 0
    def add(self, k, v):
        kbase = self.base + 56 + 256
        vend = self.base + 4056
        self.vcur += len(v)
        apfs[kbase + self.kcur:kbase + self.kcur + len(k)] = k
        apfs[vend - self.vcur:vend - self.vcur + len(v)] = v
        struct.pack_into("<HHHH", apfs, self.base + 56 + self.count * 8, self.kcur, len(k), self.vcur, len(v))
        self.kcur += len(k)
        self.count += 1
        struct.pack_into("<I", apfs, self.base + 36, self.count)

snap_txt = b"apfs-snapshot-v1-historical-note\n"
live_txt = b"apfs-live-v2-current-note\n"
apfs[10 * 4096:10 * 4096 + len(snap_txt)] = snap_txt
apfs[11 * 4096:11 * 4096 + len(live_txt)] = live_txt

for blk_idx, xid, dblk, payload in [(6, 10, 10, snap_txt), (7, 20, 11, live_txt)]:
    lb = LeafBuilder(blk_idx)
    iv = bytearray(92)
    struct.pack_into("<QQ", iv, 0, 1, 2)
    struct.pack_into("<I", iv, 56, 1)
    struct.pack_into("<H", iv, 80, 0o040755)
    lb.add(struct.pack("<Q", (3 << 60) | 2), iv)

    dk = struct.pack("<QI", (9 << 60) | 2, 9) + b"note.txt\x00"
    dv = bytearray(18)
    struct.pack_into("<Q", dv, 0, 16)
    struct.pack_into("<H", dv, 16, 8)
    lb.add(dk, dv)

    fiv = bytearray(140)
    struct.pack_into("<QQ", fiv, 0, 2, 16)
    struct.pack_into("<I", fiv, 56, 1)
    struct.pack_into("<H", fiv, 80, 0o100644)
    struct.pack_into("<HHBBHQQ", fiv, 92, 1, 40, 8, 0, 40, len(payload), 4096)
    lb.add(struct.pack("<Q", (3 << 60) | 16), fiv)

    lb.add(struct.pack("<QQ", (8 << 60) | 16, 0), struct.pack("<QQQ", 4096, dblk, 0))
    seal_apfs(apfs, blk_idx, 200, xid, 0x00000002, 0x0000000E)

# Block 8: Snapshot metadata B-tree
sllb = LeafBuilder(8)
sname = b"com.apple.TimeMachine.2026-11-24-103000.backup\x00"
sv = bytearray(50 + len(sname))
struct.pack_into("<QQ", sv, 8, 9, 1732450000 * 1000000000)
struct.pack_into("<H", sv, 48, len(sname))
sv[50:50 + len(sname)] = sname
sllb.add(struct.pack("<Q", (1 << 60) | 10), sv)
seal_apfs(apfs, 8, 8, 20, 0x00000002, 0x00000010)

with open("$APFS_SNAP_IMG", "wb") as f:
    f.write(make_gpt_apfs_image(apfs))
EOF

HFS_OUT_DIR="$TMP_DIR/hfs_extract"
mkdir -p "$HFS_OUT_DIR"
(cd "$HFS_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$HFS_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
[ -f "$HFS_OUT_DIR/ReadMe.txt" ] || { echo "FAILED: Classic HFS /ReadMe.txt not extracted"; cat "$HFS_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^classic-hfs-recovered-readme$" "$HFS_OUT_DIR/ReadMe.txt" || { echo "FAILED: Classic HFS content mismatch"; exit 1; }

HFSP_OUT_DIR="$TMP_DIR/hfsp_tm_extract"
mkdir -p "$HFSP_OUT_DIR"
(cd "$HFSP_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$HFSP_TM_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
HFSP_BUDGET="$HFSP_OUT_DIR/Backups.backupdb/MacBookPro/2026-11-24-090000/Documents/budget.txt"
[ -f "$HFSP_BUDGET" ] || { echo "FAILED: HFS+ Backups.backupdb hard-linked file not extracted"; cat "$HFSP_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^hfsp-timemachine-recovered-budget$" "$HFSP_BUDGET" || { echo "FAILED: HFS+ Backups.backupdb decmpfs content mismatch"; exit 1; }

APFS_OUT_DIR="$TMP_DIR/apfs_snap_extract"
mkdir -p "$APFS_OUT_DIR"
(cd "$APFS_OUT_DIR" && TERM=xterm "$TESTDISK" /log /cmd "$APFS_SNAP_IMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
[ -f "$APFS_OUT_DIR/note.txt" ] || { echo "FAILED: APFS live /note.txt not extracted"; cat "$APFS_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^apfs-live-v2-current-note$" "$APFS_OUT_DIR/note.txt" || { echo "FAILED: APFS live /note.txt content mismatch"; exit 1; }
APFS_HIST="$APFS_OUT_DIR/Backups/2026-11-24-103000/note.txt"
[ -f "$APFS_HIST" ] || { echo "FAILED: APFS /Backups snapshot /note.txt not extracted"; cat "$APFS_OUT_DIR/testdisk.log" || true; exit 1; }
grep -q "^apfs-snapshot-v1-historical-note$" "$APFS_HIST" || { echo "FAILED: APFS snapshot content mismatch"; exit 1; }

# Real macOS hdiutil GPT + APFS interoperability verification (gracefully skipped on Linux)
if [ "$(uname -s)" = "Darwin" ] && command -v hdiutil >/dev/null 2>&1; then
  HDI_SRC="$TMP_DIR/hdi_src"
  HDI_DMG="$TMP_DIR/real_macos_apfs.dmg"
  HDI_OUT="$TMP_DIR/hdi_extract"
  mkdir -p "$HDI_SRC/sub" "$HDI_OUT"
  printf 'real-macos-hdiutil-apfs-verified\n' > "$HDI_SRC/sub/real.txt"
  if hdiutil create -size 16m -layout GPTSPUD -fs APFS -volname RealAPFS -srcfolder "$HDI_SRC" -format UDRW -ov "$HDI_DMG" >/dev/null 2>&1; then
    (cd "$HDI_OUT" && TERM=xterm "$TESTDISK" /log /cmd "$HDI_DMG" advanced,list,recursive,filecopy,quit,quit >/dev/null 2>&1)
    [ -f "$HDI_OUT/sub/real.txt" ] || { echo "FAILED: real hdiutil APFS /sub/real.txt not extracted"; cat "$HDI_OUT/testdisk.log" || true; exit 1; }
    grep -q "^real-macos-hdiutil-apfs-verified$" "$HDI_OUT/sub/real.txt" || { echo "FAILED: real hdiutil APFS content mismatch"; exit 1; }
  fi
fi
echo "PASSED"

echo "========================================================================"
echo " All 8 automated integration test suites passed."
echo "========================================================================"
exit 0
