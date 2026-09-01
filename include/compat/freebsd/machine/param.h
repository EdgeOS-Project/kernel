/* SPDX-License-Identifier: MPL-2.0 */
/* Shared machine parameters for the EdgeOS FreeBSD driver bridge. */

#ifndef _MACHINE_PARAM_H_
#define _MACHINE_PARAM_H_

#include "../sys/_align.h"

#define STACKALIGNBYTES (16 - 1)

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#ifndef MACHINE
#define MACHINE "arm64"
#endif
#ifndef MACHINE_ARCH
#define MACHINE_ARCH "aarch64"
#endif
#ifndef MACHINE_ARCH32
#define MACHINE_ARCH32 "armv7"
#endif
#define CACHE_LINE_SHIFT 7
#define ALIGNED_POINTER(pointer, type) \
    ((((__uintptr_t)(pointer)) & (sizeof(type) - 1)) == 0)
#define MAXPAGESIZES 4
#define PCPU_PAGES 1
#define arm64_btop(value) ((__uintptr_t)(value) >> PAGE_SHIFT)
#define arm64_ptob(value) ((__uintptr_t)(value) << PAGE_SHIFT)
#elif defined(__x86_64__)
#ifndef MACHINE
#define MACHINE "amd64"
#endif
#ifndef MACHINE_ARCH
#define MACHINE_ARCH "amd64"
#endif
#ifndef MACHINE_ARCH32
#define MACHINE_ARCH32 "i386"
#endif
#define REDZONE_SZ 128
#define CACHE_LINE_SHIFT 6
#define ALIGNED_POINTER(pointer, type) 1
#define MAXPAGESIZES 3
#ifndef KERNBASE
#define KERNBASE 0x08000000UL
#endif
#define amd64_btop(value) ((__uintptr_t)(value) >> PAGE_SHIFT)
#define amd64_ptob(value) ((__uintptr_t)(value) << PAGE_SHIFT)
#else
#error "Unsupported EdgeOS FreeBSD driver bridge architecture"
#endif

/* EdgeOS owns SMP scheduling but imported subsystems still need per-CPU slots. */
#ifndef MAXCPU
#define MAXCPU 1024
#endif

#ifndef MAXMEMDOM
#define MAXMEMDOM 8
#endif

#define ALIGNBYTES _ALIGNBYTES
#define ALIGN(pointer) _ALIGN(pointer)

#define CACHE_LINE_SIZE (1 << CACHE_LINE_SHIFT)

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#ifndef PAGE_SIZE_4K
#define PAGE_SIZE_4K 4096
#endif
#ifndef PAGE_SHIFT_4K
#define PAGE_SHIFT_4K 12
#endif
#ifndef PAGE_SIZE_16K
#define PAGE_SIZE_16K 16384
#endif
#ifndef PAGE_SHIFT_16K
#define PAGE_SHIFT_16K 14
#endif
#ifndef PAGE_SHIFT_64K
#define PAGE_SHIFT_64K 16
#endif
#ifndef PAGE_SIZE_64K
#define PAGE_SIZE_64K (1 << PAGE_SHIFT_64K)
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE (1 << PAGE_SHIFT)
#endif
#ifndef PAGE_MASK
#define PAGE_MASK (PAGE_SIZE - 1)
#endif

#ifndef KSTACK_PAGES
#if defined(KASAN) || defined(KMSAN)
#define KSTACK_PAGES 6
#else
#define KSTACK_PAGES 4
#endif
#endif

#define KSTACK_GUARD_PAGES 1

#if (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    defined(PERTHREAD_SSP)
#define NO_PERTHREAD_SSP __nostackprotector
#else
#define NO_PERTHREAD_SSP
#endif

#endif
