/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mprotect ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mprotect 226
#else
#error "mprotect_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22
#define ENOMEM 12

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define PROT_GROWSDOWN 0x01000000u
#define PROT_GROWSUP 0x02000000u
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
    volatile uint8_t *mapping;
    long mapped;
    int failures = 0;

    failures += expect_result("zero length",
        raw_syscall6(SYS_mprotect, PAGE_SIZE, 0, PROT_READ,
                     0, 0, 0), 0);
    failures += expect_result("unaligned zero length",
        raw_syscall6(SYS_mprotect, PAGE_SIZE + 1u, 0, PROT_READ,
                     0, 0, 0), -EINVAL);
    failures += expect_result("invalid protection zero length",
        raw_syscall6(SYS_mprotect, PAGE_SIZE, 0,
                     UINT64_C(1) << 32, 0, 0, 0), 0);
    failures += expect_result("overflow range",
        raw_syscall6(SYS_mprotect, -PAGE_SIZE, PAGE_SIZE * 2u,
                     PROT_READ, 0, 0, 0), -ENOMEM);
    failures += expect_result("unmapped range",
        raw_syscall6(SYS_mprotect, PAGE_SIZE, PAGE_SIZE,
                     PROT_READ, 0, 0, 0), -ENOMEM);

    mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE * 3u, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", mapped > 0);
    if (mapped <= 0) return failures;
    mapping = (volatile uint8_t *)(uintptr_t)mapped;

    failures += expect_result("enable read write",
        raw_syscall6(SYS_mprotect, mapped, PAGE_SIZE * 3u,
                     PROT_READ | PROT_WRITE, 0, 0, 0), 0);
    mapping[0] = 0x11u;
    mapping[PAGE_SIZE] = 0x22u;
    mapping[PAGE_SIZE * 2u] = 0x33u;
    failures += expect_result("disable middle access",
        raw_syscall6(SYS_mprotect, mapped + PAGE_SIZE, PAGE_SIZE,
                     PROT_NONE, 0, 0, 0), 0);
    failures += expect_result("restore middle access",
        raw_syscall6(SYS_mprotect, mapped + PAGE_SIZE, PAGE_SIZE,
                     PROT_READ | PROT_WRITE, 0, 0, 0), 0);
    failures += expect_true("protection preserves data",
        mapping[0] == 0x11u && mapping[PAGE_SIZE] == 0x22u &&
        mapping[PAGE_SIZE * 2u] == 0x33u);
    failures += expect_result("growth flags conflict",
        raw_syscall6(SYS_mprotect, mapped, PAGE_SIZE,
                     PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP,
                     0, 0, 0), -EINVAL);
    failures += expect_result("growth flag on normal mapping",
        raw_syscall6(SYS_mprotect, mapped, PAGE_SIZE,
                     PROT_READ | PROT_GROWSDOWN, 0, 0, 0), -EINVAL);
    failures += expect_result("unknown protection",
        raw_syscall6(SYS_mprotect, mapped, PAGE_SIZE,
                     UINT64_C(1) << 32, 0, 0, 0), -EINVAL);

    failures += expect_result("remove middle page",
        raw_syscall6(SYS_munmap, mapped + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("range with hole",
        raw_syscall6(SYS_mprotect, mapped, PAGE_SIZE * 3u,
                     PROT_READ, 0, 0, 0), -ENOMEM);
    failures += expect_result("unmap first page",
        raw_syscall6(SYS_munmap, mapped, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("unmap final page",
        raw_syscall6(SYS_munmap, mapped + PAGE_SIZE * 2u, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    if (!failures) print_text("MPROTECT_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
