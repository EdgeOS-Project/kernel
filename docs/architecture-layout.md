# EdgeOS Kernel Source Layout

EdgeOS follows the Linux kernel's architecture ownership model: architecture
directories contain mechanisms that cannot be shared, while kernel policy and
Linux-visible behavior are implemented once in common code.

## Target tree

```text
include/
  arch/
    arm64/                 # ARM64 registers, frames, page tables, entry hooks
    x86_64/                # x86-64 registers, frames, page tables, entry hooks
  uapi/                    # Linux-compatible userspace ABI declarations
  kernel/                  # process, scheduler, signal, time, syscall interfaces
  mm/                      # architecture-neutral virtual-memory interfaces
  fs/                      # VFS and filesystem interfaces
  net/                     # sockets and network stack interfaces
  ipc/                     # pipes, futexes, SysV IPC, event and polling interfaces
  drivers/                 # shared driver interfaces
  lib/                     # freestanding common utilities

src/
  arch/
    arm64/
      boot/                # Generic UEFI handoff and early platform discovery
      entry/               # EL0 syscall, exception, signal-return, context switch
      kernel/              # IRQ controller, timer, CPU and TLS register handling
      mm/                  # ARM64 page-table format, TLB and cache maintenance
    x86_64/
      boot/                # Multiboot and early platform discovery
      entry/               # syscall, exception, signal-return, context switch
      kernel/              # APIC/PIC, timer, CPU and TLS register handling
      mm/                  # x86-64 page-table format and TLB maintenance
  init/                    # shared kernel initialization and init execution
  kernel/                  # process, scheduler, signal, time and syscall bodies
  mm/                      # mappings, address spaces, brk, mmap and page faults
  fs/                      # VFS, procfs, sysfs, devfs and concrete filesystems
  net/                     # Linux socket ABI and protocol stacks
  ipc/                     # Unix IPC, futex, epoll, eventfd, timerfd and signalfd
  drivers/
    firmware/              # ACPI, UEFI runtime and device-tree consumers
    block/                 # block core and storage drivers
    input/                 # input core and hardware transports
    net/                   # network core and hardware transports
    tty/                   # TTY, PTY and console drivers
    video/                 # fbdev, GOP handoff and GPU drivers
    virtio/                # transport plus device drivers
  lib/                     # strings, formatting and reusable data structures
```

## Ownership rules

1. Syscall numbers and register decoding are architecture-specific. Syscall
   implementations, errno behavior and Linux object semantics are common.
2. Trap and signal frame layouts are architecture-specific. Signal selection,
   disposition, masking, queueing and restart policy are common.
3. Page-table operations, TLB maintenance and user-entry mechanics are
   architecture-specific. VMAs, mapping policy, mmap, brk, COW and accounting
   are common.
4. Device discovery and bus transport may be architecture-specific. A device's
   queueing, state machine and subsystem integration are shared whenever the
   hardware interface is shared.
5. procfs, sysfs, VFS, ELF loading, networking, IPC, scheduling and process
   lifecycle code must never be placed below `arch/`.
6. Architecture hooks use the `arch_*` prefix and exchange common kernel types.
   Hooks must not expose an architecture-private process, descriptor, socket or
   filesystem model to common code.
7. Both architecture builds link the same common subsystem objects. A separate
   architecture-only implementation of Linux-visible behavior is not accepted.

## Migration order

The current tree predates this contract and is migrated incrementally so every
coherent step remains buildable:

1. Move misplaced VFS, procfs, sysfs, ELF and shared device code out of ARM64.
2. Introduce common task, file-description, socket and VM object definitions.
3. Split the ARM64 bootstrap process module by subsystem and connect it through
   narrow architecture hooks.
4. Move legacy x86-64 assembly and platform code into `arch/x86_64`.
5. Make both builds consume one explicit common source manifest.
6. Delete the superseded architecture-private implementations only after both
   architectures pass boot and userspace regression tests.
