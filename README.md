# EdgeOS

EdgeOS is an independent Unix-like kernel for x86_64 and AArch64. It is not a
Linux fork. Linux userspace is the compatibility target: the kernel loads Linux
ELF64 binaries and implements the Linux-facing system call and device
interfaces needed by existing software.

Development systems currently boot Debian with systemd on both architectures.
X11/XFCE, KDE Plasma on Wayland, Chromium, Firefox, LibreOffice and Docker have
all been run on EdgeOS development VMs using unmodified Debian packages.

This repository contains the kernel. Root filesystems, desktop packages and
virtual-machine management tools are separate projects.

## Current tree

| | Count |
| --- | ---: |
| Canonical Linux syscall IDs | 385 |
| Shared syscall handlers | 299 |
| AArch64 policies using shared handlers | 265 |
| BSD driver manifests | 258 |
| Buildable BSD driver packages | 253 |
| Source-locked BSD files | 2,862 |

The syscall figures come from `tools/syscalls/linux_syscall_inventory.json`.
The driver figures come from the generated BSD Bridge build plan and source
locks. These inventories are checked during the build.

## Kernel

Architecture directories contain entry code, context switching, interrupt
plumbing, page-table operations and platform bring-up. Process semantics, VFS,
networking, scheduling, IPC and Linux-visible behavior are shared. A feature
implemented in common code is built into both architecture targets.

| Area | Present in the tree |
| --- | --- |
| Processes | Linux ELF64 loading, `fork`, `vfork`, `clone`, `clone3`, exec, signals, pidfds and process waiting |
| Memory | VMAs, anonymous and file mappings, COW, `mmap`, `mprotect`, `mremap`, `madvise`, page cache and swap |
| IPC and events | pipes, Unix sockets, futexes, epoll, eventfd, timerfd, signalfd and inotify |
| VFS | path lookup, mounts, descriptors, permissions, procfs, sysfs, devtmpfs, devpts and OverlayFS |
| Storage | block cache, partitions, loop devices, device mapper, VirtIO Block/SCSI, NVMe, AHCI and ATA |
| Filesystems | ext2, ext4, FAT32, FUSE and readers for SquashFS, EROFS, XFS, Btrfs, exFAT, NTFS, ISO9660 and UDF |
| Network | IPv4, IPv6, TCP, UDP, Unix sockets, packet sockets, netlink, TUN/TAP, bridge, macvlan and ipvlan |
| Display | EFI GOP, framebuffer console, virtual terminals, DRM/KMS, fbdev, Bochs BGA, VMware SVGA and VirtIO GPU |
| Input and audio | PS/2, USB HID, VirtIO Input, touchpad support, HDA, AC97 and USB audio |
| Platform | ACPI/ACPICA, Device Tree, PCI/PCIe, MSI/MSI-X, SMP, timers, I2C, SMBus, TPM and watchdogs |

Linux ABI work is not finished. An inventory entry means that a route and
implementation exist; it does not mean every corner case matches every Linux
release. Hardware support has the same distinction: compiling a driver is not
proof that it has been tested on every device it recognizes.

## BSD Driver Bridge

The BSD Driver Bridge builds selected FreeBSD drivers from their upstream
source files. EdgeOS supplies the kernel services expected by those drivers;
device-specific state machines and recovery code remain upstream.

Imported files are kept under `src/compat/freebsd/upstream/`. Each package has
a manifest that records its upstream revision, source paths, license data,
capability requirements and a deterministic source digest. EdgeOS adaptation
belongs in `include/compat/freebsd/`, `src/compat/freebsd/` or a native frontend,
not in the imported driver.

The bridge provides source compatibility, not FreeBSD binary module
compatibility. Package and source checks reject missing files, unexpected
changes and unsupported capability combinations. See
[`docs/bsd-driver-bridge.md`](docs/bsd-driver-bridge.md) for the import and
validation rules.

## Build

The build requires GNU Make, Python 3, Clang/LLVM, LLD and NASM. The cross
toolchains used by the Makefile must also be available in `PATH`.

### x86_64

```sh
make defconfig
make -j"$(getconf _NPROCESSORS_ONLN)" kernel
```

Output: `out/edgeos.bin`

### AArch64 UEFI

```sh
make arm64_defconfig
make -j"$(getconf _NPROCESSORS_ONLN)" arm64-kernel
```

Output: `out/arm64/BOOTAA64.EFI`

Configuration menus:

```sh
make menuconfig
make arm64-menuconfig
```

The Makefile also has targets for x86_64 initramfs media, AArch64 UEFI media,
Raspberry Pi 4 and Raspberry Pi 5. An initramfs can be built from an existing
root filesystem:

```sh
make INITRAMFS_SOURCE_DIR=/path/to/rootfs initramfs
```

## Checks

Run both architecture builds after changing shared kernel code. The core
repository checks are:

```sh
make kconfig-check
make syscall-inventory-check
make cross-arch-unity-check
make bsd-driver-build-plan-check
make bsd-driver-manifest-check
```

Focused unit targets for the scheduler, VFS, memory manager, network stack,
filesystems and driver bridge are listed in the Makefile and under
`tools/tests/`.

## Source layout

```text
arch/                       defconfig files
config/                     boot and driver configuration
include/                    kernel, UAPI and compatibility headers
src/arch/                   architecture mechanisms
src/kernel/                 shared process and kernel services
src/mm/                     memory management
src/vfs/ and src/fs/        VFS and filesystems
src/net/                    network stack
src/drivers/                native drivers
src/compat/freebsd/         BSD Driver Bridge and imported sources
tools/                      build tools, inventories and tests
```

The architecture ownership rules are documented in
[`docs/kernel-layout.md`](docs/kernel-layout.md).

## License

Original EdgeOS code is licensed under the Mozilla Public License 2.0.
Imported files keep their original licenses and notices. See [`NOTICE.md`](NOTICE.md)
and the notices beside each imported source tree.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting changes.
