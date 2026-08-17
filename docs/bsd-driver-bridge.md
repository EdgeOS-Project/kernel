# EdgeOS BSD Driver Bridge

## Objective

The BSD Driver Bridge allows mature BSD-licensed kernel drivers to be compiled
from their original source files while EdgeOS supplies the operating-system
services they require. Driver state machines, queue handling, initialization,
recovery, and device-specific behavior remain in the upstream driver.

The bridge provides source compatibility. It does not provide FreeBSD binary
kernel-module compatibility.

## Source preservation contract

Imported driver files live under `src/compat/freebsd/upstream/` and remain
unchanged. They are vendored in the repository, so an external FreeBSD checkout
is not required to build or distribute EdgeOS. Each driver family has a manifest
under `config/bsd_drivers/manifests/` that pins the upstream repository commit
and locks the source tree. The source check must pass before an imported driver
is compiled. Every locked file must declare an allowed license or have an
explicit manifest exception with human-readable evidence. Advertising-clause
BSD source is rejected.

EdgeOS-specific work belongs in one of these locations:

- `include/compat/freebsd/` for source-compatible FreeBSD kernel interfaces.
- `src/compat/freebsd/` for shared bridge implementations.
- `src/bsd_frontend/` for EdgeOS subsystem integration.
- `tools/bsd_bridge/` for import, validation, interface generation, and update
  tooling.

An unsupported FreeBSD API must fail compilation or initialization explicitly.
It must not be implemented as a no-op or a false success path.

## Architecture

The bridge is divided into capability domains:

1. Base kernel types, allocation, synchronization, sleep and wakeup, callouts,
   taskqueues, and diagnostics.
2. FreeBSD kobj, newbus, module dependencies, device lifecycle, and generated
   `.m` interfaces.
3. PCI, MMIO, ACPI, FDT, interrupts, resources, and data-transfer services.
4. Optional subsystem frontends for network, block storage, CAM, USB, TTY,
   input, audio, and display.

All policy and capability-domain implementations are shared between x86_64 and
AArch64. Architecture code provides only the mechanisms that cannot be shared.

Imported translation units use an isolated include order. FreeBSD-compatible
headers are resolved before the vendored FreeBSD headers, while native EdgeOS
code continues to use the normal EdgeOS include tree. This prevents FreeBSD
kernel names from leaking into unrelated EdgeOS code.

## Driver package manifest

A manifest records:

- The exact upstream repository and commit.
- Locked source paths and their deterministic digest.
- Generated FreeBSD kobj interfaces.
- Driver modules and source files.
- Required bridge capability domains.
- Whether each module is currently built in or deliberately disabled.
- Package-local compatibility definitions used only by that package's
  unmodified sources.

Adding a driver whose capability domains are already implemented should require
only an unmodified source import, a manifest entry, build selection, and a real
runtime test. A driver that requires a new FreeBSD subsystem extends the shared
bridge instead of adding driver-local replacements.

For a single-module package, `create_package.py` creates the manifest, derives
direct capability requirements, validates licenses and both architectures, and
computes the deterministic source lock:

```sh
python3 tools/bsd_bridge/create_package.py \
  --id freebsd-example \
  --module example \
  --source sys/dev/example/example.c \
  --capability pci \
  --mode disabled
```

The default mode is `disabled`, so importing source cannot create a support
claim. Use `--mode builtin` only when every required capability is implemented;
the catalog still rejects it otherwise. The tool selects files already present
in the pinned upstream tree and never rewrites a driver source file.

Provider capability registries live under `config/bsd_drivers/capabilities/`.
Every capability is classified as `unsupported`, `partial`, `implemented`, or
`runtime-verified`. A builtin module may use only capabilities that are
implemented on both x86_64 and AArch64. The generated build plan rejects a
module that crosses this boundary, so inventory entries cannot accidentally
become false support claims.

The Make source inventory is generated from all manifests into
`out/bsd_bridge/packages.mk`. Disabled modules remain visible in the package
inventory but are not compiled or linked. Adding another package must not
require editing the main Makefile. Package definitions are applied with
source-specific build rules, so importing one driver family cannot change the
preprocessor environment of another family or of the shared bridge runtime.

The same catalog generates an in-kernel package registry. A package with
builtin modules moves through registered, starting, active, stopping, stopped,
or failed states as the shared SYSINIT and SYSUNINIT transaction runs. A
fully-disabled package remains visible as disabled. This lifecycle describes
source-built packages linked into EdgeOS; it is not a binary KLD loader.
Shared kernel code can inspect this state through
`include/compat/freebsd/edgeos/package.h`.

## Build and validation

The current built-in source packages include libfdt, iflib, the FreeBSD VirtIO
families, Intel em/igb and I225/I226 igc, and VMware vmxnet3. The package
manifests are the authoritative inventory under
`config/bsd_drivers/manifests/`.

Run:

```sh
make bsd-driver-build-plan-check
make bsd-driver-package-registry-check
make bsd-driver-manifest-check
make bsd-driver-dependency-report
make bsd-driver-interface-check
```

The source check verifies the pinned FreeBSD commit, detects tracked changes,
checks every declared source and interface, and validates the deterministic
source-tree digest. Interface generation runs FreeBSD's own BSD-licensed
`makeobjops.awk` in a temporary directory so the vendored source remains
untouched.

Runtime acceptance remains device-specific. A successful build is not driver
support. Network drivers must transmit and receive, block drivers must complete
real reads and writes, input drivers must produce events, and display drivers
must produce usable output on both supported EdgeOS architectures.
