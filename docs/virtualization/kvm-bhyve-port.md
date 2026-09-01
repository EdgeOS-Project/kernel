# EdgeOS KVM Facade and FreeBSD vmm Port

## Design boundary

EdgeOS implements the Linux KVM userspace ABI in EdgeOS-owned code. Linux KVM
kernel source and Linux KVM UAPI headers are not implementation inputs. Public
KVM documentation, CPU architecture manuals, and black-box traces from
unmodified QEMU are treated as interoperability specifications.

The hardware virtualization implementation comes from the BSD-licensed
FreeBSD kernel vmm subsystem. EdgeOS does not expose the bhyve device API and
does not use the bhyve command-line ABI. Required bhyve userspace policies,
such as ARM PSCI/SMCCC exit handling, are translated into the EdgeOS KVM
adapter so an unmodified QEMU process observes KVM behavior.
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
`sys/amd64/vmm`, and `sys/arm64/vmm` directories, their required architecture
headers, and the ARM64 EL2 entry stub are vendored as a locked baseline. The
source lock contains 159 files. EdgeOS changes normally belong outside those
directories in adapters. A necessary upstream-file change must be
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
| Get dirty log | `0x4010ae42` |
| Set userspace memory region | `0x4020ae46` |
| Set userspace memory region 2 | `0x40a0ae49` |
| Run vCPU | `0x0000ae80` |

Capability responses are allowlisted after the corresponding translation and
backend path pass tests. Unknown or incomplete capabilities return zero. This
prevents QEMU from selecting a path that EdgeOS cannot complete.

The first facade layer dispatches system and VM requests, creates VM and vCPU
descriptors transactionally, rolls backend objects back when descriptor
installation fails, and preserves parent VM lifetime while vCPU descriptors
remain open. Device creation has the same transaction boundary: failure to
copy the installed descriptor to userspace closes that descriptor after the
runtime lock is released, which tears down the device without deadlocking its
descriptor-release callback. `KVM_CREATE_DEVICE_TEST` probes backend support
without installing a descriptor or retaining a device object. Syscall adapters
must copy and validate pointer arguments before calling the
architecture-neutral facade.

## x86_64 execution model

The x86_64 adapter selects the imported FreeBSD SVM or VMX backend from the
physical CPU vendor. It translates QEMU's KVM CPUID, MSR, vCPU state,
in-kernel interrupt-controller, PIT, clock, dirty-log, and migration requests
without exposing the bhyve userspace ABI. On AMD hosts, Linux-compatible safe
handling is provided for the legacy and extended performance counters and the
architectural AMD configuration MSRs that QEMU restores during vCPU setup.
On Intel hosts, the adapter enables unrestricted guests, restores the host
selectors and GS base required by VMX, masks INVPCID when the outer hypervisor
cannot expose it, and disables nested APICv controls that Linux KVM cannot
nest. Unknown guest MSRs inject `#GP` unless userspace MSR exits were explicitly
enabled, matching the Linux KVM behavior used by `rdmsr_safe()` probes.

An EdgeOS VMM kick is a coalesced, per-CPU NMI. This is required when a vCPU is
executing a nested SVM guest because an ordinary host timer or reschedule IPI
cannot reliably force an exit from L2 through the outer Linux KVM layer. The
NMI handler consumes only kicks that EdgeOS marked as VMM requests, so guest
NMI injection remains separate from host vCPU scheduling. The CPUID facade
also hides TSC-deadline timer support until that deadline path is implemented.

Guest-memory metadata uses chunked retained-page records and chunked pmap
mapping records. Sequential guest physical mappings use a tail insertion fast
path. This avoids one allocator arena allocation and one full linked-list scan
per 4 KiB page, allowing QEMU to register memory slots beyond the former
256 MiB boundary without raising a fixed allocator limit.

The retained AMD hardware record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-x86-linux-512m-final-20260831/serial.log`.
It proves the complete Linux KVM to EdgeOS/bhyve SVM to unmodified QEMU KVM to
Debian 6.12.90 chain with a 512 MiB inner guest. The required markers are
`EDGE_X86_LINUX_BOOT_PASS`, `EDGE_X86_LINUX_BENCHMARK_PASS`, and
`EDGE_X86_LINUX_QEMU_EXECUTION_PASS`. The benchmark touched 536,870,912 bytes
and completed the CPU, memory, and `getpid` workloads. The serial-log SHA-256
is `5d001d407e20a3c4671f9a5baa3415454c43b2b16efd90be6ad5239aefc59d63`.
The post-UAPI-completion AMD regression is retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-uapi-completion-20260831/serial.log`.
It repeats the 512 MiB Debian boot, benchmark, and clean-QEMU-exit markers;
the measured memory pass reached 1,948 MiB/s. Its serial-log SHA-256 is
`37781470dda76751107cf0be0947704533da06a9e484e0802955c3bfc316c9cb`.
The robust-single-step contract now translates Linux `KVM_SET_GUEST_DEBUG`
into the bhyve SVM `RFLAGS_TF` or VMX monitor-trap capability. Debug, breakpoint,
and monitor-trap exits return `KVM_EXIT_DEBUG`; single-step exits include the
DR6 BS bit required by the Linux ABI. Hardware breakpoints now save the guest's
DR0-DR3, DR6, and DR7 state, install the debugger state transactionally, route
the resulting SVM or VMX debug exception to `KVM_EXIT_DEBUG`, and restore the
guest state when debugging is disabled. The permanent AMD hardware probe first
single-steps one instruction, installs an execution breakpoint at the next RIP,
validates the DR6 B0 exit, disables debugging, and runs the guest to HLT. Its
current retained serial record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-hw-breakpoint-v1-20260831/serial.log`
with SHA-256
`3e3f6d57eb43e93983474d450b04f1f49476b565956462753b4868d18e51ea78`.
The matching Apple HVF ARM64 nested regression retained the EL2 handoff,
timer, interrupt, guest-I/O, and final execution markers at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-hw-breakpoint-v1-20260831/serial.log`
with SHA-256
`24afd59136c1ff529df8b2056356cc4eddce05523a35236573aea64d2e0a9091`.
The following current-kernel Debian 6.12.90 regression again reached PID 1,
completed the benchmark at 1,694 MiB/s, and exited QEMU cleanly. It is retained
at `/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-guest-debug-regression-20260831/serial.log`
with SHA-256
`7d3db7f164437ab7ea40999568b79d781868544914a3ea67692d30c71ed23850`.
The Intel VMX gate passed on a Core i5-8500T Proxmox VE 9.0.4 host. The
disposable acceptance environment was a two-vCPU privileged LXC with
`/dev/kvm` passed through and all VM images stored on its external-volume
mount. The clean two-vCPU UAPI record is retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/intel-vmx-20260831/serial-intel-vmx-clean-uapi.log`.
It contains `EDGE_KVM_UAPI_PASS`; its SHA-256 is
`401afa8ed9868be30f8b004bf2a3da0d55af9e983a7ff12cf6c178e950722ae9`.

The current nested Debian 6.12.90 record is retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-intel-linux-clean-final-20260901/serial.log`.
It proves a two-vCPU EdgeOS host, unmodified QEMU `-accel kvm`, a two-vCPU
Linux guest using the ordinary APIC path, Linux PID 1, the CPU, 512 MiB memory,
and `getpid` workloads, and clean inner and outer ACPI shutdown. The required
markers are `EDGE_X86_LINUX_BOOT_PASS`, `EDGE_X86_LINUX_BENCHMARK_PASS`, and
`EDGE_X86_LINUX_QEMU_EXECUTION_PASS`. Linux reports that it brought up two CPUs,
and the outer QEMU process exits after the guest powers down. The serial-log
SHA-256 is
`694ed0dd7f512996bb2790725c3c8583745a0e67cfe8ccf0f112e9102103cfc5`.
The Intel APIC-mode, SMP, and clean-shutdown gates are therefore closed. The
runtime now wakes eventfd readers and writers on counter transitions and yields
out of `KVM_RUN` when another runnable EdgeOS task needs the CPU, allowing QEMU's
main loop to process the guest's final ACPI power event without starving behind
its vCPU threads.

## ARM64 execution model

EdgeOS preserves EL2 when firmware enters the kernel there, installs the
FreeBSD hypervisor stub before dropping the host kernel to EL1, and uses the
upstream non-VHE or VHE vmm path selected at runtime. The KVM adapter translates
ARM core, system, and VFP register IDs, memory slots, VGICv3 device attributes,
MMIO exits, PSCI power state, and reset or shutdown events.

The direct register ABI keeps Linux KVM's `SP_EL0` and `SP_EL1` as distinct
state: the former maps to the upstream EL2 context's `SP_EL0`, while the latter
maps to bhyve's guest stack-pointer register. `SPSR_EL1` maps to upstream vmm
state and the other four KVM SPSR slots are retained by the adapter. All five
SPSR IDs are included in `KVM_GET_REG_LIST`. `KVM_IRQ_LINE` routes SPIs through
the upstream VM interrupt API and per-vCPU PPIs through VGIC injection; invalid
IRQ types and ranges are rejected before entering the backend.

VGICv3 creation uses the KVM device-control path. A test-only create validates
the requested device type and flags but does not allocate or attach a VGIC.
The backend VGIC attach remains deferred until QEMU has both requested
initialization and supplied distributor and redistributor addresses. QEMU 10
sends the initialize attribute during device realization and supplies the
addresses later from its machine-init-done notifier, so the adapter accepts
that order and attaches the upstream VGIC when the second condition arrives.
`KVM_CAP_IRQCHIP` and `KVM_CAP_DEVICE_CTRL` are intentionally published
together: QEMU uses the former to select its in-kernel GIC model, while its ARM
architecture hook uses the latter to skip the legacy `KVM_CREATE_IRQCHIP` call
and select the VGIC device-control API.

Only implemented KVM capabilities are published. In particular, the current
ARM backend publishes PSCI 0.2, VGIC device control, user memory, and immediate
exit. It rejects PMU, SVE, pointer authentication, and 32-bit EL1 vCPU feature
bits until their backend state is implemented.

Apple HVF without the `virt` machine's `virtualization=on` property runs EdgeOS
as an EL1 guest and validates only graceful absence of nested virtualization.
Current QEMU HVF on supported Apple Silicon and macOS can instead enable EL2
with `-machine virt,virtualization=on`. EdgeOS then installs the imported bhyve
EL2 stub before entering its EL1 host kernel, so this is a hardware-accelerated
nested ARM KVM acceptance path rather than TCG emulation.

### ARM64 QEMU/KVM acceptance image

`tools/kvm/build_arm64_qemu_acceptance.sh` builds a task-owned 768 MiB UEFI
image below `/Volumes/EdwardData/EdgeOS/tmp`. It copies the existing ARM64
Debian rootfs, installs Debian's unmodified `qemu-system-arm` package inside an
ARM64 container, and selects the static EdgeOS-owned `/edge-kvm-init` launcher
through a dedicated `rdinit=` command line. The launcher executes
`/usr/bin/qemu-system-aarch64` with
`-machine virt,accel=kvm,gic-version=3,its=off -cpu host`; it does not use a
patched QEMU binary or a bhyve userspace API. The ARM64 initramfs maximum is
512 MiB so the packaged QEMU runtime can be unpacked without weakening the
per-image inode limit.

The command disables the QEMU `virt` machine's optional ITS device. FreeBSD's
ARM64 vmm provides a virtual GICv3 distributor and redistributors but no virtual
ITS backend, so EdgeOS does not advertise the Linux KVM ITS device type. This
does not disable CPU virtualization, GICv3 interrupt delivery, PCI INTx, or
userspace-emulated device operation. PCI MSI through an in-kernel ITS remains
outside the imported bhyve capability set.

Build a reproducible image with a unique task slug:

```sh
tools/kvm/build_arm64_qemu_acceptance.sh kvm-arm64-physical-01
```

The embedded bare-metal guest writes
`EDGE_ARM64_QEMU_KVM_GUEST_IO_PASS` through the emulated PL011 and powers off
through PSCI. PID 1 then writes
`EDGE_ARM64_QEMU_KVM_GUEST_EXECUTION_PASS` only when unmodified QEMU exits with
status zero. Both markers, plus the EdgeOS bhyve-backend-ready marker, are
required for ARM hardware acceptance. `EDGE_ARM64_QEMU_KVM_STARTUP_BEGIN`
alone proves only that the acceptance payload reached userspace.

QEMU's direct ARM kernel loader starts the EFI application before ordinary
block-controller connection. The EdgeOS EFI loader therefore enumerates every
available Simple File System handle and recognizes QEMU's synthetic `cmdline`
and `initrd` files in addition to the normal disk paths. This allows a
reproducible nested-HVF launch with `-kernel`, `-initrd`, and
`virt,virtualization=on` while retaining the same unmodified Debian QEMU
payload inside EdgeOS.

After building the acceptance payload and ARM64 initramfs, run the complete
nested-HVF gate with:

```sh
tools/kvm/run_arm64_nested_hvf_acceptance.sh <task-slug>
```

The runner records the QEMU version and hashes, waits for every EL2, bhyve,
inner-QEMU, and guest-I/O marker, rejects failure markers, and terminates only
the QEMU process whose PID it created. It prints
`EDGE_ARM64_NESTED_HVF_ACCEPTANCE_PASS` only after the full marker set has been
observed.

For a full guest-OS gate, the Linux benchmark launcher runs the same unmodified
QEMU with a Debian ARM64 6.12 kernel and a static PID 1 initramfs. The inner
kernel command line enables the PL011 early console so failures before the
normal console registration remain visible. Acceptance requires
`EDGE_LINUX_BOOT_PASS`, `EDGE_LINUX_BENCHMARK_PASS`, and
`EDGE_ARM64_LINUX_QEMU_EXECUTION_PASS`; a QEMU process or the startup marker
alone is not a Linux boot result. The benchmark records a fixed CPU loop,
eight 64 MiB memory-write passes, and one million `getpid` system calls.
Select this runner profile with:

```sh
EDGE_KVM_ACCEPTANCE_PROFILE=linux \
  tools/kvm/run_arm64_nested_hvf_acceptance.sh <task-slug>
```

The default `bare` profile retains the deterministic timer, interrupt, and
guest-I/O payload. Both profiles reject an actual kernel panic without treating
the Linux `panic=-1` command-line option as a failure marker.

Set the outer EdgeOS boot option `kvm.trace=1` for bounded ARM64 backend
diagnostics. It reports VM, memory-slot, vCPU, VGIC, and the first exit stages
without changing the KVM ABI. Leave it disabled for performance measurements.
`KVM_RUN` retains its vCPU while running but does not hold the global KVM
object lock, allowing QEMU's device and interrupt threads to operate in
parallel. ARM identification-register masking also treats the DFR0 breakpoint,
watchpoint, and context-comparator counts as unsigned fields; treating the
value `0xf` as signed minus one would incorrectly advertise sixteen registers
on hosts that implement fewer and can make Linux fault during debug-register
initialization.

## Debug hosts and artifact locations

Build both architectures from the canonical repository on the Mac. Keep all
object trees, images, and logs below `/Volumes/EdwardData/EdgeOS`.

For x86_64 hardware acceptance, use the `edgeosamd64vm` SSH alias. Verify
`uname -m`, readable `/dev/kvm`, free space, and active QEMU processes before
staging a unique run under `/home/edgeos/edgeos-acceptance/<task>/`. Retain the
serial and QMP records under
`/Volumes/EdwardData/EdgeOS/logs/x86_64/<task>/`.

For ARM64, compile `arm64-kernel` on the Mac and use HVF for ordinary boot
regression. Use a task-owned copy of the EFI disk image; never overwrite a
shared VM disk. Retain serial output under
`/Volumes/EdwardData/EdgeOS/logs/arm64/<task>/`. Perform the final virtualization
run on an EL2-capable physical host, including a supported Apple Silicon nested
HVF host, and require unmodified AArch64 QEMU with `-accel kvm` to create a VM,
VGICv3, vCPUs, memory slots, and execute guest I/O.
The current acceptance rootfs carries Debian QEMU 10.0.11 package
`1:10.0.11+ds-0+deb13u1`; record the exact version and image hashes with each
physical run rather than treating that version as a permanent pin.

Before assigning a physical host to a completion gate, run the read-only
preflight inventory:

```sh
tools/kvm/check_physical_host.sh --require core
tools/kvm/check_physical_host.sh --require vfio
tools/kvm/check_physical_host.sh --require vdpa
```

The script reports independent `CORE_KVM`, `VFIO`, and `VDPA` readiness
markers, lists IOMMU-group membership and bound drivers, and includes the PCI
inventory when `lspci` is available. `VFIO=READY` means that KVM is usable and
the host exposes at least one IOMMU group; it does not assert that any listed
device is safe to detach. Device ownership and isolation must still be checked
before an acceptance run. `VDPA=READY` requires an actual `/dev/vhost-vdpa*`
device. The selected `--require` gate controls the exit status, while the
default inventory mode always exits successfully after reporting the host.

The current `edgeosamd64vm` inventory is retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-current-refresh-20260831/preflight-inventory.log`.
It reports an `AuthenticAMD` nested host with SVM and NPT, writable KVM access,
zero IOMMU groups, and no vhost-vDPA device. It therefore passes the core KVM
gate and intentionally fails the VFIO and vDPA physical-device gates. The
visible PCI topology is Hyper-V synthetic hardware and is not an assignable
AMD-Vi or Intel VT-d test device.

The ARM64 hardware gate passed on the local Apple Silicon host with macOS
26.6.2 and QEMU 11.1.50 using HVF nested virtualization. The retained serial
reproduction record is
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-nested-hvf-repro-20260831/serial.log`.
It contains the EL2-to-EL1 host handoff, bhyve hardware-backend readiness, inner
guest I/O, and final unmodified-QEMU execution markers. The serial-log SHA-256
is `34de129fb08669714f1d2b4c2192896264f2a9b403c2b36cdaca0ff6db39755f`.
The full Debian 6.12.94 nested-guest record is retained at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-vmcleanup-profile-pass-20260831/serial.log`.
It reaches PID 1 and records `EDGE_LINUX_BOOT_PASS`,
`EDGE_LINUX_BENCHMARK_PASS`, and `EDGE_ARM64_LINUX_QEMU_EXECUTION_PASS` after
QEMU closes the VM without an SMP-rendezvous teardown panic. Its serial-log
SHA-256 is `93b0eea91cc5bd5ce39316ef2aa5adbbb2c2c66e37fe1a1391cc66aa99a1dccc`.
The post-UAPI-completion regression is retained at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-uapi-completion-20260831/serial.log`.
It repeats all three Linux boot, benchmark, and clean-QEMU-exit markers with
serial-log SHA-256
`e483425463ac9b1e0b397673e354a16b270caf372ac3b854312fc204d6469884`.
The guest-debug interface addition was also rebuilt for AArch64, where the x86
request remains an explicit unsupported backend operation. The current Apple
HVF nested regression retained at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-guest-debug-arm64-full-runtime-20260831/serial.log`
repeats the timer-status, timer-interrupt, guest-I/O, and final execution pass
markers. Its serial-log SHA-256 is
`fca204839c1fff7c0a7592219c3aabe8d0fa175956653831b7ea0458880bdff5`.

## Validation gates

The minimum gates for each batch are source-lock and license verification,
host unit tests with AddressSanitizer and UndefinedBehaviorSanitizer, and
x86_64 plus AArch64 freestanding compilation. Runtime milestones use AArch64
HVF locally and x86_64 KVM on `edgeosamd64vm`. TCG results are diagnostic only.

Migration, nested virtualization, and PCI passthrough are required x86_64
completion gates. PCI passthrough remains a physical-host gate until an IOMMU
host with an assignable device is available.

The VFIO implementation uses EdgeOS-owned ABI and object policy rather than
Linux kernel source. The first VFIO layer implements the legacy type1 and
type1-v2 container model, viable IOMMU groups, container attachment ordering,
device lifetime, and page-aligned DMA map and unmap transactions. It accepts
QEMU's required ordering in which `VFIO_GROUP_SET_CONTAINER` precedes
`VFIO_SET_IOMMU`; backend group attachment is deferred until the IOMMU domain
exists and is rolled back transactionally if any group cannot attach. The
implementation also provides modern VFIO cdev binding, IOMMUFD IOAS
attachment, and association of both legacy groups and modern device files with
the owning KVM VM. IOAS map and unmap changes are
replayed transactionally into the bhyve `ppt` backend and are rolled back when
any attached device rejects a change. Legacy Type1 dirty logging, dirty-on-
unmap, enable/disable, VADDR unmap, and transactional unmap-all are implemented
with conservative dirty reporting. The remaining passthrough gate is a
physical Intel VT-d or AMD-Vi host with an assignable PCI function; nested KVM
without a host IOMMU is not accepted as proof of device isolation.

The vhost compatibility layer implements the shared memory and vring controls,
eventfd lifetime, network backend association, worker creation and vring worker
assignment, SCSI endpoint and missed-event state, and vsock guest CID and run
state. The current x86_64 runtime probe record at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-pmap-chunk-runtime-refresh-20260831/peripheral-serial.log`
contains `EDGE_VIRTUALIZATION_PERIPHERAL_PASS`. The vDPA UAPI now includes a
registered-device backend, device and backend feature negotiation, config and
status access, queue enablement, IOVA and group queries, ASID binding, config
eventfd lifetime, and suspend/resume. A path without a registered vDPA device
returns `ENODEV`; physical vDPA operation remains a device-backend gate.
The vDPA descriptor also supports the Linux-compatible IOTLB v2 message stream:
map, invalidate, and batch-boundary writes are translated to backend callbacks,
while miss and access-failure events are returned through descriptor reads.
The production file-descriptor path preserves the vDPA device identity across
open, retain, close, read, write, and ioctl operations.

IOMMUFD implements IOAS and VFIO compatibility, HWPT allocation, conservative
dirty tracking, and validated command dispatch through the current
`IOMMU_HW_QUEUE_ALLOC` command. The object layer supports file-backed IOAS
mappings with retained file references and process ownership transfer. Nested
VT-d/SMMUv3 invalidation,
fault queues, vIOMMU, vDevice, vEVENTQ, and hardware queues are exposed only
when a matching hardware backend exists. On current bhyve hosts these commands
return `EOPNOTSUPP` after full argument and object validation instead of
claiming unsupported hardware operation succeeded.

The production descriptor path also implements the QEMU process-transfer
capability probe precisely: `IOMMU_IOAS_CHANGE_PROCESS` on a context with no
DMA mappings is a successful no-op. A context containing ordinary user-VA
maps is rejected with `EINVAL`, while transferring actual file-backed pin
accounting requires a registered file resolver. The x86_64 production resolver
accepts an ordinary memfd only when the requested file range is already mapped
`MAP_SHARED` in the current process, retains that memfd through the IOAS map,
and translates the range to its actual user virtual address. Secret and KVM
guest memfds are rejected. Process transfer validates the complete retained
file-cookie set before atomically moving its accounting owner to the calling
process. The retained file pages and bhyve VM/GPA IOMMU mappings do not depend
on the new process using the previous user virtual address.
The AMD/KVM production record at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/iommufd-change-process-v4-20260831/serial.log`
boots EdgeOS, initializes the bhyve hardware backend, and completes an actual
`memfd_create`, `MAP_SHARED`, `IOMMU_IOAS_MAP_FILE`, removal of the original
user mapping, process-transfer, IOAS unmap, and close sequence. It contains
`EDGE_VIRTUALIZATION_PERIPHERAL_PASS`; the serial-log SHA-256 is
`13c2d6c9f172e49d2ea20ed847cdab3b546a926ec6f12e906f95607cfe41d833`.

The KVM dirty-log translation accepts `KVM_GET_DIRTY_LOG` only for a registered
memory slot with dirty logging enabled. The runtime copies the bitmap to
userspace in bounded 4096-byte chunks. On x86_64, the bhyve adapter walks the
active NPT or EPT leaf entries, atomically tests and clears the hardware dirty
bit, and advances the pmap generation when a bit was cleared so the imported
SVM or VMX entry path invalidates stale nested translations. The ARM64 adapter
uses stage-2 write protection for software dirty tracking. Enabling logging
write-protects the slot, an EL2 write fault marks the mapped page dirty and
restores write access, and clearing a bitmap range protects only the selected
pages again. Disabling logging restores writable mappings before discarding the
tracking state. Bitmap collection and clearing walk the mapping list once, so
the operation is linear in the number of mappings rather than pages times
mappings.

The x86_64 and ARM64 facades advertise
`KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2` with the
`KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE` flag. A VM can enable the mode through
`KVM_ENABLE_CAP`; subsequent `KVM_GET_DIRTY_LOG` requests preserve the NPT or
EPT dirty bits on x86_64 or the software dirty bitmap on ARM64, and
`KVM_CLEAR_DIRTY_LOG` clears only the aligned bitmap range selected by
userspace. On ARM64, clearing a selected page also reapplies stage-2 write
protection so its next write is observed. The runtime validates the slot,
range, alignment, reserved fields, and userspace bitmap before changing
backend state. `KVM_DIRTY_LOG_INITIALLY_SET` is not advertised.

The permanent x86 hardware probe executes a guest RAM write and verifies that
two manual-mode reads retain the dirty bit, a selective clear removes it, and
the rest of the KVM UAPI probe continues. Its AMD SVM record is retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-manual-dirty-log-20260831/serial.log`
with SHA-256
`93d2cb7694701c08f94e20c00b65f65d039376ca521091da3cf7fc568fe601af`.
The matching unmodified Debian 6.12.90 nested-QEMU boot and benchmark record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-manual-dirty-log-linux-20260831/serial.log`
with SHA-256
`38b338473b8b6a84ee37b52b6dbbd83d06c2f447d4b5dba4c561628729017183`.
An unmodified QEMU source-to-destination file migration resumed the guest
heartbeat and emitted `EDGE_X86_QEMU_KVM_MIGRATION_PASS`; its record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-manual-dirty-log-migration-20260831/serial.log`
with SHA-256
`70be4d0aa706cbe4537bccf60f345e42cbd6f8cb2bfd71b0599dea04c97cd336`.
The ARM64 Apple HVF regression retained all counter, timer, interrupt, guest-I/O,
and guest-execution markers at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-manual-dirty-log-arm64-20260831/serial.log`
with SHA-256
`c194014aa6e3c4d7773fd5e696c4836b2cb1516cbbfec59eefcd7a7f53c5d204`.
An unmodified QEMU AArch64 source-to-destination Unix migration with 64 MiB of
guest RAM completed dirty synchronization, transferred VGICv3 state, resumed
the destination, paused it to emit unambiguous completion markers, and resumed
it again. The retained record contains clean
`EDGE_ARM64_MIGRATION_DESTINATION_COMPLETE` and
`EDGE_ARM64_QEMU_KVM_MIGRATION_PASS` lines followed by destination heartbeats:
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-migration-marker-clean-20260831/serial.log`.
Its SHA-256 is
`a41241ae20937670002f45a642666224bfb8ebdc3c65ff33f6b00eb5340f4f93`.

The KVM facade implements `KVM_SET_USER_MEMORY_REGION2` for ordinary userspace
memory on both x86_64 and ARM64 and advertises `KVM_CAP_USER_MEMORY2`. It
validates all reserved fields before translating the request to the shared
bhyve memory-slot path. `KVM_CREATE_GUEST_MEMFD` now creates a size-fixed,
close-on-exec descriptor with Linux-compatible access boundaries: data I/O
returns `ESPIPE`, mapping returns `ENODEV`, resizing returns `EINVAL`, and only
hole-punch fallocate is accepted. Zero memory attributes are accepted and
validated by `KVM_SET_MEMORY_ATTRIBUTES`. `KVM_MEM_GUEST_MEMFD`, private memory
attributes, and their capabilities remain explicitly unsupported and
unadvertised until the bhyve backend provides an isolated SNP or TDX-equivalent
private-memory implementation. The facade also recognizes the remaining modern
QEMU request surface for dirty rings, nested state, MSR filters,
confidential-memory operations, guest debugging, and
architecture-specific finalization. Requests whose bhyve backend
is not implemented return `EOPNOTSUPP` and their capabilities are not
advertised. They do not fall through to `ENOTTY` or report false success.

The AMD SVM/NPT hardware record for the guest-memfd descriptor and memory
attribute validation is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-guest-memfd-20260831/serial.log`
with SHA-256
`6990beb5d8ba6ed6f05aff0901ee1dcaf1b7094745965da50e0bda8c1608d08c`.
The matching Apple HVF AArch64 run retained
`EDGE_ARM64_GUEST_MEMFD_UAPI_PASS` together with the nested QEMU timer,
interrupt, guest-I/O, and guest-execution markers at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-guest-memfd-bare-20260831/serial.log`
with SHA-256
`37426c077842346d86c9afbe8fe5c53119664a3d8f39271232310ba6ffe493b3`.

`KVM_PRE_FAULT_MEMORY` is implemented as a vCPU ioctl and
`KVM_CAP_PRE_FAULT_MEMORY` is advertised on both hardware backends. Each call
uses bhyve's GPA hold path to fault real stage-2 mappings in as read accesses;
it advances `gpa` and reduces `size`, preserves ignored padding, supports
partial progress at a memory-slot boundary, and validates alignment, overflow,
size, and flags according to the Linux ABI. The AMD SVM/NPT record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-prefault-20260831/serial.log`
with SHA-256
`3b7df16e542dc4a98ebe80cc36d454d4ca3149551654d8d68a0bd859f18833c7`.
The Apple HVF AArch64 run retained
`EDGE_ARM64_PRE_FAULT_MEMORY_UAPI_PASS` and all nested-QEMU execution markers
at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-prefault-20260831/serial.log`
with SHA-256
`54820c702065c4bcb7bd58d9810d40e9959c137955483042eef0b92ac924f0e2`.

The x86-only `KVM_TRANSLATE` vCPU ioctl now derives the current real,
protected, compatibility, or 64-bit CPU mode and flat, 32-bit, PAE, four-level,
or five-level paging mode from bhyve vCPU state. It delegates translation to
bhyve's no-fault guest page-table walker, uses supervisor read semantics like
Linux `kvm_mmu_gva_to_gpa_system()`, preserves ABI padding, and returns
`valid=0` with an invalid GPA for an unmapped or inaccessible page table. The
AMD SVM/NPT acceptance probe covers flat translation, an address outside any
memory slot, a real two-level 32-bit page walk, and an invalid PTE. Its serial
record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-translate-20260831/serial.log`
with SHA-256
`2731887966aac4a4a775299b1b9550c025491c90702423223b82ce431fbbf578`.
The common-runtime ARM64 regression, where this x86 ioctl remains
unimplemented, retained the EL2 handoff and all nested-QEMU timer, interrupt,
guest-I/O, and execution markers at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-translate-nested-20260831/serial.log`
with SHA-256
`2f5e060715223294f0cb3ddccd7ccfb8d9a6c19f96d85e9c36cfa31d058af621`.

The x86 system descriptor now implements `KVM_GET_MSR_FEATURE_INDEX_LIST`
and the system-fd form of `KVM_GET_MSRS`, including Linux-compatible
two-phase list sizing, partial processed-entry returns, and usercopy error
handling. AMD and Hygon hosts advertise `KVM_CAP_GET_MSR_FEATURES` and expose
`MSR_AMD64_DE_CFG` with a zero supported-feature mask until bhyve virtualizes
specific DE_CFG bits; Intel hosts do not falsely advertise that AMD feature.
The AMD SVM/NPT acceptance record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-feature-msr-20260831/serial.log`
with SHA-256
`c421e701e9ac6529f4fb3db515ae3b5d11e19a750a391048a11fca334101d127`.
The common-runtime Apple HVF regression retained the EL2 handoff, bhyve
backend, timer, interrupt, guest-I/O, and execution markers at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-feature-msr-final-20260831/serial.log`
with SHA-256
`53c5cf70974e82e360ba2ce3af690a8bbc7fdedc5c598715d7e3530c3bdc6f9b`.
The ARM64 bridge rule also names the KVM ABI and backend-operation headers as
explicit prerequisites, preventing a stale LLVM bitcode/object pair from
retaining an older backend structure layout after a public KVM header change.

`KVM_GET_STATS_FD` is implemented for VM and vCPU descriptors with the Linux
statistics-fd binary layout. The read-only anonymous descriptor supports
sequential `read`, positional `pread`, end-of-file reads, Linux-compatible
no-op `lseek`, always-ready poll state, shared offsets across duplicated
descriptors, and independent
VM or vCPU lifetime retention. VM data reports the current vCPU, device, and
memory-slot counts; vCPU data reports its identifier and cumulative run-call
count. The system descriptor returns `EINVAL`, matching the Linux `/dev/kvm`
oracle. The x86 acceptance probe validates the header, fixed 48-byte name
fields, offsets, identifiers, values, and end-of-file behavior on AMD SVM/NPT.
Its hardware record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-stats-fd-20260831/serial.log`
with SHA-256
`1c62769b6c2f22cfe6fe084c4ff9c56ad8fa66fa55028fc8033699398b951386`.
The matching Apple HVF run executed unmodified AArch64 QEMU and its inner
guest at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-stats-fd-20260831/serial.log`
with SHA-256
`359896b87247a29d6960656a87f5ca66aa969daee49e34ba38befb5c2da67f9c`.
The full Debian 6.12.94 nested boot, benchmark, and clean-QEMU-exit regression
is retained at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-arm64-stats-fd-linux-v2-20260831/serial.log`
with SHA-256
`a5cbb670f15f5fcf55b3019f62efc7c61368fc4868360f8d24d7a64d8ad10649`.
The current QEMU x86_64 and ARM64 named-ioctl inventory has no missing request
numbers. The runtime implements legacy PIT state, legacy CPUID installation,
and `KVM_GET_CPUID2`; it returns an empty valid list for emulated-only CPUID
because the backend advertises none. Unadvertised ARM MTE and counter controls,
PMU filters, Hyper-V eventfd, and Xen compatibility requests are recognized and
return `EOPNOTSUPP`. PPC and s390 requests are outside the supported EdgeOS
architecture set. Exact request encodings and structure sizes are locked by
the ABI unit test, and both the object and runtime layers have x86_64 and
AArch64 freestanding compile gates.
The vCPU path implements x86 NMI and external interrupt injection by translating
them into the bhyve-backed vCPU event state. Both x86 and ARM64 guest-debug
structure sizes have independent ABI regression assertions. The x86 UAPI
acceptance probe permanently tests enable, single-step exit, debug payload,
DR6 BS semantics, disable, continued guest execution, user-memory2 capability,
valid region2 registration, reserved-field rejection, and the guest-memfd
boundary. The AMD hardware record is retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-user-memory2-20260831/serial.log`
with SHA-256
`781a57b91ca36a98f0ae387cbb87bdf8b1e67e2dccd6de0fb96d4efa268804d6`.
The following Debian 6.12.90 nested-QEMU regression reached PID 1, completed
the benchmark, and exited QEMU cleanly. Its serial record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-user-memory2-linux-20260831/serial.log`
with SHA-256
`d0d0fcdeba70990a043d5c637fd6f801312991028dd6cd2fea87af64e77243c7`.
The matching Apple HVF ARM64 nested bare-metal gate is retained at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-user-memory2-arm64-20260831/serial.log`
with SHA-256
`70136582282a58d2e0586e274d6aaf8b2ed4cc85687e23625fb05eea2cc07100`.

Coalesced MMIO is now a functional bhyve-backed path rather than an unsupported
request. The VM owns a shared producer ring and up to 64 registered MMIO zones;
all vCPUs map the same ring at Linux KVM page offset 2 on x86_64 and offset 1 on
ARM64. Matching writes are published with acquire/release ordering, ioeventfd
keeps priority, and a full ring falls back to `KVM_EXIT_MMIO`. PIO coalescing is
not advertised. The permanent x86 UAPI probe validates the capability value,
zone registration, a hardware-generated ring entry, userspace consumption,
zone removal, and ordinary MMIO fallback. Its AMD SVM record is retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-coalesced-mmio-20260831/serial.log`
with SHA-256
`dcdc2950ebb61a308b06c865214fe8eddd5a6b9890a4dd67b0f9a21d8e05f8a8`.
The following Debian 6.12.90 nested-QEMU regression reached PID 1, completed
the benchmark, and exited QEMU cleanly. Its serial record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-coalesced-mmio-linux-20260831/serial.log`
with SHA-256
`2aae5ae18cfc6c54c671f12c963e7100aea1eb311b3b2d71ac35ece263a09084`.
The matching Apple HVF ARM64 bare-metal regression retained all timer, guest-I/O,
and final execution markers at
`/Volumes/EdwardData/EdgeOS/logs/arm64/kvm-coalesced-mmio-arm64-20260831/serial.log`
with SHA-256
`cf1d970150b42246435f857aefb85af24e068739c1a7162d07e5c645a16732a9`.

The x86_64 file-migration acceptance payload starts an unmodified Debian QEMU,
runs a heartbeat guest with `-accel kvm`, saves it through QMP migration, starts
a fresh destination QEMU against the migration stream, and requires resumed
guest output. The hardware run must contain
`EDGE_X86_MIGRATION_SOURCE_COMPLETE`, resumed heartbeat output, and
`EDGE_X86_QEMU_KVM_MIGRATION_PASS`, and must not contain a
`KVM_GET_DIRTY_LOG failed` warning. The current source-to-destination run is
retained at
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-pmap-chunk-runtime-refresh-20260831/migration-serial.log`.
Its marker emitter normalizes the matched debug-log evidence instead of copying
a concurrently growing file, so every acceptance marker occupies a complete
serial line. The corresponding expanded KVM ioctl record is
`/Volumes/EdwardData/EdgeOS/logs/x86_64/kvm-pmap-chunk-runtime-refresh-20260831/uapi-serial.log`.
