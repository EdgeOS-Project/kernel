/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux protection-key ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_pkey_mprotect 329
#define SYS_pkey_alloc 330
#define SYS_pkey_free 331
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_pkey_mprotect 288
#define SYS_pkey_alloc 289
#define SYS_pkey_free 290
#else
#error "pkey_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22
#define ENOSPC 28

#define PROT_READ 1
#define PROT_WRITE 2
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

static long pkey_mprotect_raw(uint64_t address, uint64_t length,
                              uint64_t protection, uint64_t key) {
    return raw_syscall6(SYS_pkey_mprotect, (long)address, (long)length,
                        (long)protection, (long)key, 0, 0);
}

static int run_tests(void) {
    volatile uint8_t *mapping;
    long allocated;
    long mapped;
    int supported;
    int failures = 0;

    failures += expect_result("allocation flags",
        raw_syscall6(SYS_pkey_alloc, 1, 0, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("allocation rights",
        raw_syscall6(SYS_pkey_alloc, 0, 4, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("free negative key",
        raw_syscall6(SYS_pkey_free, -1, 0, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("free key zero",
        raw_syscall6(SYS_pkey_free, 0, 0, 0, 0, 0, 0), -EINVAL);

    allocated = raw_syscall6(SYS_pkey_alloc, 0, 0, 0, 0, 0, 0);
    supported = allocated >= 0;
#ifdef PKEY_ABI_NATIVE
    failures += expect_true("allocation result",
        supported || allocated == -ENOSPC || allocated == -EINVAL);
#else
    failures += expect_result("unsupported allocation", allocated, -ENOSPC);
#endif

    mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", mapped > 0);
    if (mapped <= 0) return failures;
    mapping = (volatile uint8_t *)(uintptr_t)mapped;
    mapping[0] = 0x5au;

    failures += expect_result("ordinary pkey mprotect",
        pkey_mprotect_raw((uint64_t)mapped, PAGE_SIZE,
                          PROT_READ | PROT_WRITE, UINT64_MAX), 0);
    failures += expect_result("32-bit negative pkey",
        pkey_mprotect_raw((uint64_t)mapped, PAGE_SIZE,
                          PROT_READ | PROT_WRITE, UINT32_MAX), 0);
    failures += expect_result("unaligned address",
        pkey_mprotect_raw((uint64_t)mapped + 1u, PAGE_SIZE,
                          PROT_READ, UINT64_MAX), -EINVAL);

    if (supported) {
        failures += expect_true("positive allocated key", allocated > 0);
        failures += expect_result("allocated key protection",
            pkey_mprotect_raw((uint64_t)mapped, PAGE_SIZE,
                              PROT_READ | PROT_WRITE,
                              (uint64_t)allocated), 0);
        failures += expect_result("restore default protection",
            pkey_mprotect_raw((uint64_t)mapped, PAGE_SIZE,
                              PROT_READ | PROT_WRITE, UINT64_MAX), 0);
        failures += expect_result("free allocated key",
            raw_syscall6(SYS_pkey_free, allocated, 0, 0, 0, 0, 0), 0);
        failures += expect_result("double free allocated key",
            raw_syscall6(SYS_pkey_free, allocated, 0, 0, 0, 0, 0),
            -EINVAL);
    } else {
        failures += expect_result("unsupported key zero",
            pkey_mprotect_raw((uint64_t)mapped, PAGE_SIZE,
                              PROT_READ | PROT_WRITE, 0), -EINVAL);
        failures += expect_result("unsupported positive key",
            pkey_mprotect_raw((uint64_t)mapped, PAGE_SIZE,
                              PROT_READ | PROT_WRITE, 1), -EINVAL);
    }

    failures += expect_result("unmap page",
        raw_syscall6(SYS_munmap, mapped, PAGE_SIZE, 0, 0, 0, 0), 0);
    if (!failures) print_text("PKEY_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
