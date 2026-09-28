# Contributing to the EdgeOS Kernel

Keep architecture-neutral policy and behavior in shared code. Architecture directories should contain only mechanisms that genuinely differ, such as entry code, context switching, interrupt plumbing, and platform bring-up. A userspace-visible change must preserve equivalent behavior on x86_64 and AArch64 unless the architecture ABI requires a documented difference.

All source code, comments, commit messages, and repository documentation must be written in English.

Before submitting a change:

1. Start from the appropriate defconfig and confirm generated files are not staged.
2. Build both x86_64 and AArch64 when shared code is affected.
3. Run the focused unit and ABI checks for the changed subsystem.
4. Run the syscall inventory and cross-architecture sharing checks for ABI changes.
5. Keep third-party notices intact and do not add code whose license is incompatible with the repository.
6. Keep distribution images, root filesystems, local VM state, and build products out of this repository.

Prefer small, coherent commits that can be reviewed and reverted independently.
