# TestDisk-NG & PhotoRec-NG

[![Build & Release](https://github.com/cwmoriarty/testdisk/actions/workflows/build.yml/badge.svg)](https://github.com/cwmoriarty/testdisk/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/cwmoriarty/testdisk?label=release)](https://github.com/cwmoriarty/testdisk/releases/latest)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL_v2%2B-blue.svg)](COPYING)

**TestDisk-NG** and **PhotoRec-NG** are modern, robust terminal tools for partition recovery, filesystem repair, and signature-based file carving.

Built on the foundation created by Christophe GRENIER, this updated edition introduces a modernized text user interface, automated safety rollback journals before disk writes, live hardware and S.M.A.R.T. controller inspection, bad-sector hang protection, and pre-compiled releases for macOS and Linux.

---

## Key Features & Improvements

- **Subdued Modern TUI**: Clean layout with neutral borders, unified row highlighting, and live status bars that replace high-contrast legacy screens.
- **Live Media & Hardware Inspector**: Real-time display of physical drive attributes, bus protocols (`[NVMe]`, `[USB]`, `[SATA]`, `[SD Card]`), logical and physical sector sizing (512e vs 4Kn), partition table maps, and root privilege status.
- **Automated Safety Rollback Journal**: Before writing partition tables or boot sectors to physical media, TestDisk-NG automatically saves an atomic binary snapshot (`testdisk_undo_<disk>_<timestamp>.bin`) capturing all critical partition sectors (head MBR/GPT and tail backup GPT).
- **One-Command Rollback (`--undo`)**: Easily revert unwanted disk modifications back to their exact previous state with CRC32 integrity verification.
- **S.M.A.R.T. Health Diagnostics**: Real-time hardware health status verification (`Verified`, `Degraded / Failing`, or bus status) queried directly from device controllers.
- **Read Timeout & Bad Sector Protection**: Continuous error monitoring that prevents terminal lockups during deep disk reads across failing blocks.
- **Live Search & Device Filtering**: Filter connected drives and disk images instantly by typing keywords directly in the drive selection view.

---

## Installation

### Homebrew (macOS & Linux)

Install directly via the tap:

```bash
brew install cwmoriarty/tap/testdisk-ng
```

### Pre-Compiled Release Binaries

Pre-compiled binary packages are available on the [Releases](https://github.com/cwmoriarty/testdisk/releases/latest) page:

- **macOS (Apple Silicon arm64)**: `testdisk-ng-v7.2-WIP-macos-arm64.tar.gz`
- **macOS (Intel x86_64)**: `testdisk-ng-v7.2-WIP-macos-x86_64.tar.gz`
- **Linux (x86_64)**: `testdisk-ng-v7.2-WIP-linux-x86_64.tar.gz`

Extract the archive and run the binaries directly:

```bash
tar -xzf testdisk-ng-v7.2-WIP-macos-arm64.tar.gz
sudo ./bin/testdisk-ng
```

### Building From Source

#### Prerequisites

- **macOS**: `brew install autoconf automake libtool pkg-config ncurses`
- **Ubuntu/Debian**: `sudo apt-get install -y autoconf automake libtool pkg-config libncurses-dev libncursesw5-dev uuid-dev zlib1g-dev libjpeg-dev`
- **Fedora/RHEL**: `sudo dnf install -y autoconf automake libtool pkgconfig ncurses-devel libuuid-devel zlib-devel libjpeg-turbo-devel`

#### Compilation

```bash
git clone https://github.com/cwmoriarty/testdisk.git
cd testdisk
./autogen.sh
./configure --without-ewf --without-ntfs3g
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
sudo make install
```

---

## Usage

### TestDisk-NG: Partition Recovery

Start the interactive terminal interface (requires root permissions for direct raw drive access):

```bash
sudo testdisk-ng
```

#### Common Commands

- **List Detected Disks & Partitions**:
  ```bash
  sudo testdisk-ng /list
  sudo testdisk-ng /list /dev/rdisk2
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

  # Non-interactive restoration (scripts & automation)
  sudo testdisk-ng --undo testdisk_undo_rdisk2_20261120_123000.bin /dev/rdisk2 --yes
  ```

### PhotoRec-NG: File Carving & Recovery

Recover lost photos, documents, and media from memory cards, USB keys, and corrupted filesystems:

```bash
sudo photorec-ng
```

To run non-interactively on an image:

```bash
sudo photorec-ng /cmd disk.img search
```

### FIdentify: File Signature Checker

Determine if PhotoRec-NG recognizes a specific file format header:

```bash
fidentify sample.jpg
```

---

## Supported Filesystems & Formats

### Filesystems (Partition Detection & Repair)
- **DOS/Windows**: FAT12, FAT16, FAT32, exFAT, NTFS
- **Linux**: ext2, ext3, ext4, btrfs, GFS2, JFS, LUKS, LVM/LVM2, Linux Raid (MD), Linux Swap, XFS
- **Apple**: HFS, HFS+, APFS
- **Unix & BSD**: BeFS, BSD disklabel (FreeBSD/OpenBSD/NetBSD), Netware NSS, ReiserFS (3.5, 3.6, 4), Sun Solaris i386 disklabel, Sun ZFS, UFS/UFS2
- **Gaming & Embedded**: CramFS, Wii WBFS, Xbox FATX

### File Carving (PhotoRec Signature Recovery)
Recovers 480+ file extensions across documents (DOC/DOCX, PDF, RTF), archives (ZIP, 7Z, TAR, BZ2, GZ), media (JPEG, PNG, GIF, TIFF, RAW, MP3, MP4, MOV, MKV, AVI), databases (SQL, DB, SQLite), and executable/binary files.

---

## Automated Tests

Run the built-in test suite to verify partition recovery, signature matching, and rollback integrity against synthetic disk images:

```bash
make check
```

Or execute the integration test script directly:

```bash
./tests/test_recovery_and_rollback.sh
```

---

## Authors & Attribution

- **Original Author**: Christophe GRENIER ([grenier@cgsecurity.org](mailto:grenier@cgsecurity.org))  
  Official Website: [https://www.cgsecurity.org](https://www.cgsecurity.org)
- **Modernization & Maintenance**: Christopher W Moriarty ([oss@cwmoriarty.com](mailto:oss@cwmoriarty.com))  
  Release Date: November 2026

Both TestDisk-NG and PhotoRec-NG are open source software released under the **GNU General Public License v2 or later**.
