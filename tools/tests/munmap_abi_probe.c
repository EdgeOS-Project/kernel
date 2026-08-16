/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux munmap ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_pread64 17
#define SYS_mincore 27
#define SYS_exit 60
#define SYS_ftruncate 77
#define SYS_memfd_create 319
#elif defined(__aarch64__)
#define SYS_ftruncate 46
#define SYS_close 57
#define SYS_write 64
#define SYS_pread64 67
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mincore 232
#define SYS_memfd_create 279
#else
#error "munmap_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22
#define ENOMEM 12

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PAGE_SIZE 4096u

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char digits[24];
    unsigned long magnitude;
    int position = (int)sizeof(digits);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       (long)(sizeof(digits) - (unsigned long)position),
                       0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int run_tests(void) {
    static const char name[] = "edgeos-munmap-probe";
    volatile uint8_t *mapping;
    volatile uint8_t *shared;
    uint8_t residency = 0;
    uint8_t readback = 0;
    long mapped;
    long shared_mapped;
    long descriptor;
    int failures = 0;

    failures += expect_result("zero length",
        raw_syscall6(SYS_munmap, PAGE_SIZE, 0, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("unaligned address",
        raw_syscall6(SYS_munmap, PAGE_SIZE + 1u, PAGE_SIZE,
                     0, 0, 0, 0), -EINVAL);
    failures += expect_result("range above address space",
        raw_syscall6(SYS_munmap, -PAGE_SIZE, PAGE_SIZE * 2u,
                     0, 0, 0, 0), 0);
    failures += expect_result("length rounding overflow",
        raw_syscall6(SYS_munmap, PAGE_SIZE, -1, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("unmapped range succeeds",
        raw_syscall6(SYS_munmap, PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);

    mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE * 3u,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", mapped > 0);
    if (mapped <= 0) return failures;
    mapping = (volatile uint8_t *)(uintptr_t)mapped;
    mapping[0] = 0x11u;
    mapping[PAGE_SIZE] = 0x22u;
    mapping[PAGE_SIZE * 2u] = 0x33u;
    failures += expect_result("remove middle page",
        raw_syscall6(SYS_munmap, mapped + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("middle page absent",
        raw_syscall6(SYS_mincore, mapped + PAGE_SIZE, PAGE_SIZE,
                     (long)&residency, 0, 0, 0), -ENOMEM);
    failures += expect_true("neighbors remain usable",
        mapping[0] == 0x11u && mapping[PAGE_SIZE * 2u] == 0x33u);
    failures += expect_result("repeat hole unmap",
        raw_syscall6(SYS_munmap, mapped + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("unmap range containing hole",
        raw_syscall6(SYS_munmap, mapped, PAGE_SIZE * 3u,
                     0, 0, 0, 0), 0);
    failures += expect_result("first page absent",
        raw_syscall6(SYS_mincore, mapped, PAGE_SIZE,
                     (long)&residency, 0, 0, 0), -ENOMEM);

    mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("short unmap mapping", mapped > 0);
    if (mapped > 0) {
        failures += expect_result("one byte rounds to page",
            raw_syscall6(SYS_munmap, mapped, 1, 0, 0, 0, 0), 0);
        failures += expect_result("short page absent",
            raw_syscall6(SYS_mincore, mapped, PAGE_SIZE,
                         (long)&residency, 0, 0, 0), -ENOMEM);
    }

    descriptor = raw_syscall6(SYS_memfd_create, (long)name, 0,
                              0, 0, 0, 0);
    failures += expect_true("memfd create", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect_result("memfd truncate",
            raw_syscall6(SYS_ftruncate, descriptor, PAGE_SIZE,
                         0, 0, 0, 0), 0);
        shared_mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
                                     PROT_READ | PROT_WRITE, MAP_SHARED,
                                     descriptor, 0);
        failures += expect_true("shared mapping", shared_mapped > 0);
        if (shared_mapped > 0) {
            shared = (volatile uint8_t *)(uintptr_t)shared_mapped;
            shared[91] = 0x6du;
            failures += expect_result("shared unmap",
                raw_syscall6(SYS_munmap, shared_mapped, PAGE_SIZE,
                             0, 0, 0, 0), 0);
            failures += expect_result("shared pread after unmap",
                raw_syscall6(SYS_pread64, descriptor, (long)&readback,
                             1, 91, 0, 0), 1);
            failures += expect_true("shared writeback", readback == 0x6du);
        }
        failures += expect_result("memfd close",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    if (!failures) print_text("MUNMAP_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
