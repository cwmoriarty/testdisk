# apple-explorer

Standalone C11 library, CLI, user-space mount driver, and zero-install portable Windows GUI for reading **Classic HFS**, **HFS+ / HFSX**, **APFS**, **FileVault 2**, **UDIF `.dmg`**, **`.sparsebundle` / `.backupbundle`**, **HFS+ `Backups.backupdb`**, and **APFS Time Machine Snapshots** across Windows 10/11, macOS, and Linux.

`apple-explorer` is designed as a self-contained native replacement for legacy Java-based HFSExplorer, adding APFS, FileVault 2 decryption, APFS snapshot timelines, Time Machine directory hard-link resolution, and Windows Explorer mounting with zero Java runtime or third-party DLL dependencies.

## Features

- **All Apple Filesystem Generations**:
  - **APFS (`NXSB` / `APSB`)**: Fletcher-64 checkpoint ring scanning (stepping back cleanly to the latest intact transaction on dirty drives), Object Map resolution, clones, symlinks, and `zlib` / `LZVN` / `LZFSE` `com.apple.decmpfs` transparent decompression.
  - **FileVault 2 Decryption**: Native APFS container and volume keybag unwrapping (`PBKDF2-HMAC-SHA256` + RFC 3394 AES key unwrap + `AES-XTS-128`).
  - **HFS+ and HFSX (`H+` / `HX`)**: Catalog, Extents Overflow, and Attributes B-trees, HFS-wrapped HFS+ volumes, resource forks, symlinks, file hard links, and `com.apple.decmpfs` decompression.
  - **Classic HFS (`BD`)**: Master Directory Blocks, MacRoman conversion, data forks, and resource forks.
- **Disk Image and Partition Containers**:
  - **`.sparsebundle` and `.backupbundle`**: Reassembles `Info.plist` + `bands/<hex>` slices on the fly (including encrypted `encrcdsa` headers) without modifying the bundle or running `fsck`.
  - **UDIF `.dmg` and `.sparseimage`**: Parses `koly` trailers and `blkx` `mish` block tables (raw, zero, zlib, and LZFSE runs) plus `sprs` sparse images.
  - **GPT, Apple Partition Map (`APM`), and MBR**: Automatic Apple partition discovery on raw physical drives (`\\.\PhysicalDriveN`, `/dev/rdiskN`, `/dev/sdX`) and multi-partition images.
- **Time Machine Traversal (Both Generations)**:
  - **Legacy HFS+ `Backups.backupdb`**: Resolves `fldr`/`hlnk` 0-byte directory hard-link stubs against `\0\0\0\0HFS+ Private Directory Data\r` so dated backups open as normal folders.
  - **Modern APFS Time Machine (`snap_meta_tree`)**: Exposes synthetic `/Snapshots/<name>/` and `/Backups/<YYYY-MM-DD-HHMMSS>/` directories rooted at each snapshot's historical `sblock_oid`.
- **Portable Zero-Install Windows Build + Explorer Mounting**:
  - **`AppleExplorer.exe`**: Single-file native Win32 split-pane GUI (unzip and run anywhere—no installer, Java JRE, or .NET runtime required).
  - **`apple-explorer.exe`**: CLI and Windows mount tool supporting built-in **Windows Projected File System (`ProjFS`)** folder projection and **WinFsp** drive letters, plus `apple-explorer-mount` (FUSE3 / FUSE-T) on macOS and Linux.

## Installation

### Windows 10 and 11 (Portable ZIP)

Download `apple-explorer-v0.1.0-windows-x64-portable.zip` from the [Releases](https://github.com/cwmoriarty/apple-explorer/releases) page, extract anywhere, and run `AppleExplorer.exe` (or `apple-explorer.exe` from PowerShell / Command Prompt).

### macOS and Linux (Homebrew or Source)

```bash
brew install cwmoriarty/tap/apple-explorer
```

Or build from source (zero external library dependencies required):

```bash
make
make check
sudo make install
```

## CLI Usage

```bash
# Inspect a .dmg, .sparsebundle, or physical disk
apple-explorer probe Backup.sparsebundle

# List partitions, APFS container volumes, or Time Machine snapshots
apple-explorer partitions DiskImage.dmg
apple-explorer volumes ExternalSSD.img
apple-explorer snapshots TimeMachineAPFS.img

# Browse or extract dated Time Machine backups (HFS+ Backups.backupdb or APFS /Backups)
apple-explorer ls Backup.sparsebundle /Backups.backupdb
apple-explorer extract TimeMachineAPFS.img /Backups/2026-11-24-103000/Users ./RestoredUsers

# Mount on Windows 10/11 via built-in ProjFS or on macOS/Linux via FUSE3
apple-explorer mount Backup.sparsebundle C:\Mounts\MacBackup --backend projfs
apple-explorer-mount Backup.sparsebundle /Volumes/MacBackup
```

## Ecosystem Integration

- **[Montserrat](https://github.com/cwmoriarty/montserrat)**: Uses `libappleexplorer` and `apple-explorer-mount` on macOS for mounting `.sparsebundle` / `.backupbundle` directories on Linux/NTFS/NAS drives and browsing `Backups.backupdb` and APFS snapshot timelines.
- **[TestDisk-NG](https://github.com/cwmoriarty/TestDisk-NG)**: Embeds `libappleexplorer` so `[P] List Files` can browse and copy files from damaged HFS, HFS+, `Backups.backupdb`, and APFS partitions.

## License

MIT License.
