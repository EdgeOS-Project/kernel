# EdgeOS Kernel

EdgeOS is a from-scratch kernel for x86_64 and AArch64. The kernel provides a shared, Linux-compatible userspace ABI while keeping architecture-specific entry, interrupt, context-switching, and platform code isolated behind common interfaces.

This repository contains only the kernel, its build system, configuration definitions, integrated drivers, compatibility sources, and kernel validation tools. Distribution images, root filesystems, applications, and EdgeOS Workstation are maintained separately.

## Architectures

- x86_64 with BIOS/GRUB boot support
- AArch64 with UEFI and device-tree platform support

## Build

The build expects GNU Make, Python 3, Clang/LLVM, LLD, NASM, and the platform tools required by the selected architecture.

```sh
make defconfig
make -j"$(getconf _NPROCESSORS_ONLN)"
```

The x86_64 kernel is written to `out/edgeos.bin`.

For AArch64:

```sh
make arm64_defconfig
make -j"$(getconf _NPROCESSORS_ONLN)" arm64-kernel
```

The AArch64 UEFI kernel is written to `out/arm64/BOOTAA64.EFI`. Distribution repositories can package this payload with an initramfs or root filesystem.

Generated configuration, objects, disk images, and other build products are intentionally excluded from version control.

## Validation

The repository includes configuration, syscall inventory, cross-architecture sharing, BSD bridge, ABI, scheduler, filesystem, networking, and driver checks under `tools/tests` and related tool directories. Run the checks relevant to a change before submitting it.

## Source organization

- `src/`: shared kernel and architecture implementations
- `include/`: public and internal kernel headers
- `arch/`: architecture defconfig files
- `config/`: linker and boot configuration used by kernel builds
- `scripts/`: Kconfig implementation and checks
- `tools/`: kernel build, inventory, bridge, and validation tools
- `third_party/lwip/`: pinned lwIP sources used by the in-kernel network stack

## Licensing

Original EdgeOS kernel code is licensed under the Mozilla Public License 2.0. Vendored and compatibility sources retain their upstream notices and licenses. See `NOTICE.md` and the notices within each imported source tree.
