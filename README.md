# TestDisk-NG and PhotoRec-NG

[![Build and Release](https://github.com/cwmoriarty/TestDisk-NG/actions/workflows/build.yml/badge.svg)](https://github.com/cwmoriarty/TestDisk-NG/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/cwmoriarty/TestDisk-NG?label=release)](https://github.com/cwmoriarty/TestDisk-NG/releases/latest)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL_v2%2B-blue.svg)](COPYING)

**TestDisk-NG** and **PhotoRec-NG** are terminal tools for partition recovery, filesystem inspection, directory extraction, and signature-based file carving.

Built on the foundation created by Christophe GRENIER, this edition provides an updated text user interface, automated safety rollback journals before disk writes, Apple and Unix filesystem browsing via embedded `apple-explorer` and `legacyfs` libraries, S.M.A.R.T. controller inspection, bad-sector read protection, and pre-compiled releases for macOS and Linux.

---

## Features and Improvements

- **Apple Filesystem Browsing (`apple-explorer` v0.1.0)**: Browse directories and copy files directly from Classic HFS, HFS+ and HFSX (including Time Machine `Backups.backupdb` directory hard-link resolution and `com.apple.decmpfs` transparent decompression), and APFS partitions (including Fletcher-64 checkpoint ring recovery and synthetic `/Snapshots` and `/Backups` Time Machine snapshot trees) using `[P] List Files` and `[C] Copy`.
- **Legacy and Unix Filesystem Browsing (`legacyfs` v0.2.0)**: Read-only directory listing and file extraction across Btrfs, XFS (through v5), ReiserFS, CramFS, JFS, UFS/UFS2, UDF, ISO9660, and SysV partitions without kernel drivers.
- **Updated Terminal Interface**: Structured layout with clear borders, row highlighting, and live status bars.
- **Media and Hardware Inspector**: Displays physical drive attributes, bus protocols (`[NVMe]`, `[USB]`, `[SATA]`, `[SD Card]`), logical and physical sector sizing (512e vs 4Kn), partition table maps, and privilege status.
- **Automated Safety Rollback Journal**: Before writing partition tables or boot sectors to media, TestDisk-NG saves an atomic binary snapshot (`testdisk_undo_<disk>_<timestamp>.bin`) capturing critical partition sectors (head MBR/GPT and tail backup GPT).
- **Single-Command Rollback (`--undo`)**: Revert disk modifications back to their captured sector state with CRC32 verification, alongside `--auto-snapshot` and `--handoff-report` flags for automated diagnostic handoffs.
- **S.M.A.R.T. Health Diagnostics**: Hardware health status reporting queried from device controllers.
- **Read Timeout and Bad Sector Protection**: Error monitoring that prevents terminal lockups during reads across failing blocks.
- **Live Search and Device Filtering**: Filter connected drives and disk images by typing keywords in the drive selection view.

---

## Installation

### Homebrew (macOS and Linux)

Install via the tap:

```bash
brew install cwmoriarty/tap/testdisk-ng
```

### Pre-Compiled Release Binaries

Pre-compiled binary archives are available on the [Releases](https://github.com/cwmoriarty/TestDisk-NG/releases/latest) page:

- **macOS (Apple Silicon arm64)**: `testdisk-ng-v7.4.0-macos-arm64.tar.gz`
- **macOS (Intel x86_64)**: `testdisk-ng-v7.4.0-macos-x86_64.tar.gz`
- **Linux (x86_64)**: `testdisk-ng-v7.4.0-linux-x86_64.tar.gz`

Extract the archive and run the binaries directly:

```bash
tar -xzf testdisk-ng-v7.4.0-macos-arm64.tar.gz
sudo ./bin/testdisk-ng
```

### Building From Source

#### Prerequisites

- **macOS**: `brew install autoconf automake libtool pkg-config ncurses`
- **Ubuntu/Debian**: `sudo apt-get install -y autoconf automake libtool pkg-config libncurses-dev libncursesw5-dev uuid-dev zlib1g-dev libjpeg-dev`
- **Fedora/RHEL**: `sudo dnf install -y autoconf automake libtool pkgconfig ncurses-devel libuuid-devel zlib-devel libjpeg-turbo-devel`

#### Compilation

```bash
git clone https://github.com/cwmoriarty/TestDisk-NG.git
cd TestDisk-NG
./autogen.sh
./configure --without-ewf --without-ntfs3g
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
sudo make install
```

---

## Usage

### TestDisk-NG: Partition Recovery and File Extraction

Start the interactive terminal interface (requires root permissions for raw drive access):

```bash
sudo testdisk-ng
```

#### Common Commands

- **List Detected Disks and Partitions**:
  ```bash
  sudo testdisk-ng /list
  sudo testdisk-ng /list /dev/rdisk2
  ```

- **Non-Interactive Directory Listing and File Copy**:
  Extract files from a supported partition (including Classic HFS, HFS+ `Backups.backupdb`, APFS snapshots, Btrfs, XFS, ReiserFS, or UDF) into the current working directory:
  ```bash
  testdisk-ng /log /cmd disk.img advanced,list,recursive,filecopy,quit,quit
  ```

- **Enable Debug Logging**:
  ```bash
  sudo testdisk-ng /log /debug
  ```

- **Manual Safety Rollback Snapshot**:
  Capture a pre-repair snapshot of critical partition sectors before making manual changes:
  ```bash
  sudo testdisk-ng --snapshot /dev/rdisk2 "Pre-repair backup"
  ```

- **Restore From a Safety Rollback Journal**:
  Revert disk sectors to a previous snapshot:
  ```bash
  # Interactive confirmation
  sudo testdisk-ng --undo testdisk_undo_rdisk2_20261120_123000.bin

  # Specify target device override
  sudo testdisk-ng --undo testdisk_undo_rdisk2_20261120_123000.bin /dev/rdisk2

  # Non-interactive restoration for scripts and automation
  sudo testdisk-ng --undo testdisk_undo_rdisk2_20261120_123000.bin /dev/rdisk2 --yes
  ```

### PhotoRec-NG: File Carving and Recovery

Recover lost photos, documents, archives, and media from memory cards, USB drives, and damaged filesystems:

```bash
sudo photorec-ng
```

To run non-interactively on an image:

```bash
sudo photorec-ng /cmd disk.img search
```

### FIdentify: File Signature Checker

Check whether PhotoRec-NG recognizes a specific file format header:

```bash
fidentify sample.jpg
```

---

## Supported Filesystems and Formats

### Filesystems (Partition Detection, Repair, and Directory Browsing)
- **Apple**: APFS (checkpoint ring, `/Snapshots`, Time Machine `/Backups`), HFS+ and HFSX (Catalog/Extents/Attributes B-trees, Time Machine `Backups.backupdb`, `decmpfs`), Classic HFS
- **DOS/Windows**: FAT12, FAT16, FAT32, exFAT, NTFS, ReFS
- **Linux**: ext2, ext3, ext4, Btrfs, CramFS, F2FS, GFS2, JFS, LUKS, LVM/LVM2, Linux RAID (MD), Linux Swap, XFS
- **Unix, BSD, and Optical**: BeFS, BSD disklabel (FreeBSD/OpenBSD/NetBSD), ISO9660, Netware NSS, ReiserFS (3.5, 3.6, 4), Sun Solaris disklabel, Sun ZFS, SysV, UDF, UFS/UFS2
- **Gaming and Virtualization**: VMware VMFS, Wii WBFS, Xbox FATX

### File Carving (PhotoRec Signature Recovery)
Recovers 480+ file extensions across documents (DOC/DOCX, PDF, RTF), archives and compressed streams (ZIP, 7Z, TAR, BZ2, GZ, ZSTD, LZ4), media and camera RAW (JPEG, PNG, AVIF, GIF, TIFF, CR3, BRAW, MP3, MP4, MOV, MKV, IVF, AVI), databases (SQL, DB, SQLite), and binary files.

---

## Automated Tests

Run the built-in test and sanitizer fuzz suites to verify partition recovery, Apple and Unix directory extraction, signature matching, rollback restoration, and corrupted-image handling:

```bash
make check
```

Or execute the test scripts directly:

```bash
./tests/test_recovery_and_rollback.sh
./tests/test_corrupted_fuzz.sh
```

---

## Authors and Attribution

- **Original Author**: Christophe GRENIER ([grenier@cgsecurity.org](mailto:grenier@cgsecurity.org))  
  Official Website: [https://www.cgsecurity.org](https://www.cgsecurity.org)
- **Maintenance**: Christopher W Moriarty ([oss@cwmoriarty.com](mailto:oss@cwmoriarty.com))  
  Release Date: November 2026

Both TestDisk-NG and PhotoRec-NG are open source software released under the **GNU General Public License v2 or later**.
