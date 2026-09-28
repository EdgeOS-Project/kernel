# EdgeOS kernel layout

EdgeOS keeps Linux-visible policy in architecture-independent directories.
Architecture directories contain only CPU, MMU, interrupt, entry, context,
and firmware handoff mechanisms.

```text
include/
  arch/
    arm64/                 # AArch64 registers, frames, MMU and UEFI handoff
    x86_64/                # x86-64 registers, frames, paging and boot handoff
    task.h                 # architecture-neutral task hooks
    user.h                 # architecture-neutral user-copy hooks
  kernel/                  # process, scheduler, signal and syscall interfaces
  mm/                      # VM and physical-memory interfaces
  linux/                   # Linux ABI and UAPI-compatible definitions
  vfs/                     # VFS and filesystem interfaces
  net/                     # network subsystem interfaces
  drivers/                 # bus and device-class interfaces

src/
  arch/
    arm64/
      boot/                # Generic UEFI handoff and EL transition
      entry/               # vectors, syscall entry and context switch
      kernel/              # GIC, timer and CPU-local mechanisms
      mm/                  # AArch64 page tables and cache/TLB operations
    x86_64/
      boot/                # Multiboot/UEFI handoff
      entry/               # IDT entry, syscall entry and context switch
      kernel/              # APIC/PIC, timer and CPU-local mechanisms
      mm/                  # x86-64 page tables and cache/TLB operations
  kernel/                  # shared process, signal, scheduler and syscall code
  mm/                      # shared VM, mmap, COW and physical-memory policy
  fs/                      # VFS, procfs, sysfs and filesystems
  net/                     # sockets and shared network stack
  ipc/                     # futex, pipe, eventfd and System V/POSIX IPC
  drivers/                 # shared device and bus drivers
  console/                 # VT, fbcon and terminal policy
  elf/                     # shared ELF loading and Linux process image setup
```

## Dependency rule

Common code calls small `arch_*` hooks for user copy, address spaces, context
switching, TLS, signal-frame register access, timers, interrupts, and cache/TLB
maintenance. Architecture code must not implement syscall bodies, VFS policy,
process semantics, sockets, IPC, ELF policy, or Linux-visible errno behavior.

Both architecture targets must consume the same common source manifest. A new
Linux ABI feature is complete only when its body is shared and both targets
build it; architecture dispatch tables may differ only in syscall numbering and
register extraction.
