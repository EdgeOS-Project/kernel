/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_X86_64_USER_LAYOUT_H
#define EDGEOS_ARCH_X86_64_USER_LAYOUT_H

/*
 * Fixed x86_64 userspace windows used by the current per-process page-table
 * implementation.  The low executable window ends where the kernel image
 * starts.  Its page-directory base is zero so Linux ET_EXEC images linked
 * below the traditional 0x400000 address can use the same demand-backed leaf
 * tables.  EDGE_USER_MIN_ADDR still excludes the null page from every
 * userspace range check.
 */
#define X86_USER_LOW_BASE    0x0000000000000000ULL
#define X86_USER_LOW_LIMIT   0x0000000008000000ULL
#define X86_USER_LOW_SIZE    (X86_USER_LOW_LIMIT - X86_USER_LOW_BASE)
#define X86_USER_INTERP_BASE 0x0000000040000000ULL
#define X86_USER_STACK_BASE  0x0000000040200000ULL
#define X86_USER_HEAP_BASE   0x0000000040400000ULL
#define X86_USER_BIGPIE_BASE 0x0000000050000000ULL
#define X86_USER_BIGPIE_SIZE (512ULL * 1024ULL * 1024ULL)
#define X86_USER_FIXED_WINDOW_SIZE (2ULL * 1024ULL * 1024ULL)

#endif /* EDGEOS_ARCH_X86_64_USER_LAYOUT_H */
