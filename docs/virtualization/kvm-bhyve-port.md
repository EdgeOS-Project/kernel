# EdgeOS KVM Facade and FreeBSD vmm Port

## Design boundary

EdgeOS implements the Linux KVM userspace ABI in EdgeOS-owned code. Linux KVM
kernel source and Linux KVM UAPI headers are not implementation inputs. Public
KVM documentation, CPU architecture manuals, and black-box traces from
unmodified QEMU are treated as interoperability specifications.

The hardware virtualization implementation comes from the BSD-licensed
FreeBSD kernel vmm subsystem. EdgeOS does not expose the bhyve device API and
does not import the bhyve command-line program or its userspace device model.
The translation boundary is:

```text
unmodified QEMU -accel kvm
        |
EdgeOS-owned KVM ioctl, mmap, and descriptor facade
        |
EdgeOS KVM object and capability translation
        |
EdgeOS FreeBSD-vmm adaptation layer
        |
FreeBSD vmm VM/SVM/VMX/VGIC, memory, interrupt, timer, and IOMMU code
```

## Upstream source policy

The source baseline is FreeBSD commit
`bb5c77e9d281d6def6835d48249898764bc6a5fe`. The complete `sys/dev/vmm`,
`sys/amd64/vmm`, and `sys/arm64/vmm` directories are vendored without changes.
Their combined source lock contains 106 files. EdgeOS changes belong outside
those directories in adapters. A necessary upstream-file change must be
declared as a patched source with its original digest and reason before it can
pass the source gate.

Run the import preflight and source gate with:

```sh
python3 tools/bsd_vmm/import_sources.py \
  --source-root /Volumes/EdwardData/EdgeOS/reference/third_party_kernel/freebsd-src \
  --check
make bsd-bridge-source-gate
```

## Clean-room ABI evidence

Raw request numbers are recorded from unmodified QEMU on the x86_64 KVM debug
host with `strace -e raw=ioctl`. The first implemented requests were observed
as follows:

| Operation | Raw request |
| --- | ---: |
| Get API version | `0x0000ae00` |
| Create VM | `0x0000ae01` |
| Check extension | `0x0000ae03` |
| Get vCPU mmap size | `0x0000ae04` |
| Create vCPU | `0x0000ae41` |
| Set userspace memory region | `0x4020ae46` |
| Run vCPU | `0x0000ae80` |

Capability responses are allowlisted after the corresponding translation and
backend path pass tests. Unknown or incomplete capabilities return zero. This
prevents QEMU from selecting a path that EdgeOS cannot complete.

The first facade layer dispatches system and VM requests, creates VM and vCPU
descriptors transactionally, rolls backend objects back when descriptor
installation fails, and preserves parent VM lifetime while vCPU descriptors
remain open. Syscall adapters must copy and validate pointer arguments before
calling the architecture-neutral facade.

## Validation gates

The minimum gates for each batch are source-lock and license verification,
host unit tests with AddressSanitizer and UndefinedBehaviorSanitizer, and
x86_64 plus AArch64 freestanding compilation. Runtime milestones use AArch64
HVF locally and x86_64 KVM on `edgeosamd64vm`. TCG results are diagnostic only.

Migration, nested virtualization, and PCI passthrough are required x86_64
completion gates. PCI passthrough remains a physical-host gate until an IOMMU
host with an assignable device is available.
