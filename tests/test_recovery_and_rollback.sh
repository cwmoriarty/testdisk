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
echo -n "[Test 1/5] Checking binary versions and CLI options... "
TD_VER="$("$TESTDISK" /version)"
echo "$TD_VER" | grep -q "TestDisk-NG" || { echo "FAILED: testdisk-ng /version"; exit 1; }

PH_VER="$("$PHOTOREC" /version)"
echo "$PH_VER" | grep -q "PhotoRec-NG" || { echo "FAILED: photorec-ng /version"; exit 1; }

HELP_OUT="$("$TESTDISK" --help)"
echo "$HELP_OUT" | grep -q -- "--undo" || { echo "FAILED: --undo option missing in help"; exit 1; }
echo "$HELP_OUT" | grep -q -- "--snapshot" || { echo "FAILED: --snapshot option missing in help"; exit 1; }
echo "PASSED"

# Test 2: Create synthetic disk image with valid MBR partition table
echo -n "[Test 2/5] Creating synthetic disk image and verifying geometry parsing... "
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
echo -n "[Test 3/5] Testing safety rollback journal snapshot capture... "
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
echo -n "[Test 4/5] Corrupting partition sectors and verifying --undo restoration... "
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
echo -n "[Test 5/5] Testing file signature identification with FIdentify... "
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

echo "========================================================================"
echo " All 5 automated integration test suites passed successfully!"
echo "========================================================================"
exit 0
