# Kernel configuration profiles

Status: configuration plumbing and compile validation in progress. Neither
minimal profile is certified for 16, 32, or 64 MiB. Desktop runtime regression
testing remains required before replacing a published image.

## Profiles

The existing `x86_64_defconfig` and `arm64_defconfig` remain the full profiles.
Their feature selections and runtime capacity defaults are preserved. Separate
`x86_64_buildroot_defconfig` and `arm64_buildroot_defconfig` files describe
experimental serial-only Buildroot guests with VirtIO networking and storage.
They are not desktop profiles and must not replace the full configurations.

Always use separate configuration, generated-header, object, and output paths
for each profile. Build artifacts belong on the mounted external artifact
volume. Configure using `scripts/kconfig/conf.py` with an explicit `--defconfig`,
`--config`, and `--autoconf`. ARM64 also needs `--makefile` and the
`ARM64_` make prefix. Pass the resulting paths to Make; do not share object
directories between profiles or run concurrent builds in the same directory.

## Implemented controls

- Runtime configuration contains 43 capacity controls, including mapping metadata.
  Defaults retain the existing desktop limits; ranges currently support reducing
  those limits, not arbitrary expansion beyond audited object representations.
- Task, descriptor, pipe, socket, notification, epoll, quota, FUSE, keyring,
  io_uring, DRM, framebuffer, and tmpfs reservations use the selected capacities.
- Pipe capacity cannot be lower than the 4096-byte atomic-write guarantee.
- Tmpfs metadata uses a power-of-two order so hash-table masks remain valid.
- `X86_KERNEL_LOAD_ADDRESS` controls physical ELF placement. The linker rejects
  misaligned addresses. Lower placement still needs firmware and boot testing.
- Disabled GPU, audio, KVM, and FUSE call sites encountered by the minimal
  builds have explicit configuration handling. This is not an audit of every
  possible feature combination.

Host-only tests are in `tools/tests/runtime_config_test.py`. They verify both
full-profile defaults, C header overrides, range handling, minimal-profile
resolution, and actual ELF linker placement. Run with `TMPDIR` on the external
artifact volume. These checks do not prove boot or application compatibility.

## Remaining work

September 5 batch validation: both full and minimal profiles link on x86_64
and AArch64. The five host configuration tests, DRM unit and sanitizer run,
ABI dispatch unit, and pipe unit pass. The x86 full profile retains
532,553,288 bytes of BSS. The minimal x86 profile still has 150,470,874 bytes
of BSS; its text is 2,849,075 bytes. The minimal ARM64 PE has 1,809,876 bytes
of text and 62,198,780 bytes of materialized data. These are image section
sizes, not measured guest working sets. No low-memory boot is claimed.

The small build still reserves large unconditional memory pools. In particular,
x86 physical-page metadata, mapped-file records and caches, memfd objects, the
early heap, and IPC storage still need capacity and feature-selection audits.
Many syscall switches disable the UAPI without removing all backing storage.
Source selection must be checked independently on each architecture, including
mixed full/minimal configurations. Dependency checks, disabled-subsystem tests,
and real boot tests are required before calling the configuration model complete.

Keep low-memory acceptance separate from 4/8/16 GiB full-system acceptance.
Record resolved configurations, kernel hashes, serial logs, and exercised
workloads. A linked image is not a successful boot.
