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
echo -n "[Test 1/7] Checking binary versions and CLI options... "
TD_VER="$("$TESTDISK" /version)"
echo "$TD_VER" | grep -q "TestDisk-NG" || { echo "FAILED: testdisk-ng /version"; exit 1; }
echo "$TD_VER" | grep -q "Version: 7.3.0" || { echo "FAILED: expected Version: 7.3.0 in /version"; exit 1; }
echo "$TD_VER" | grep -q "legacyfs lib: 0.2.0" || { echo "FAILED: legacyfs lib 0.2.0 missing in /version"; exit 1; }

PH_VER="$("$PHOTOREC" /version)"
echo "$PH_VER" | grep -q "PhotoRec-NG" || { echo "FAILED: photorec-ng /version"; exit 1; }

HELP_OUT="$("$TESTDISK" --help)"
echo "$HELP_OUT" | grep -q -- "--undo" || { echo "FAILED: --undo option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--snapshot" || { echo "FAILED: --snapshot option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--auto-snapshot" || { echo "FAILED: --auto-snapshot option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--handoff-report" || { echo "FAILED: --handoff-report option missing in help"; exit 1; }
echo "PASSED"

# Test 2: Create synthetic disk image with valid MBR partition table
echo -n "[Test 2/7] Creating synthetic disk image and verifying geometry parsing... "
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
echo -n "[Test 3/7] Testing safety rollback journal snapshot capture... "
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
echo -n "[Test 4/7] Corrupting partition sectors and verifying --undo restoration... "
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
echo -n "[Test 5/7] Testing --auto-snapshot and --handoff-report handoff flow... "
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
echo -n "[Test 6/7] Testing file signature identification with FIdentify... "
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
echo -n "[Test 7/7] Testing legacyfs v0.2.0 extraction (ReiserFS, CramFS, XFS v5, Btrfs, UDF)... "
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

echo "========================================================================"
echo " All 7 automated integration test suites passed."
echo "========================================================================"
exit 0
