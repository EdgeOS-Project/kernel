/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux brk ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_brk 12
#define SYS_mincore 27
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_brk 214
#define SYS_mincore 232
#else
#error "brk_abi_probe requires a Linux 64-bit architecture"
#endif

#define ENOMEM 12
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
    volatile uint8_t *fresh_page;
    uint8_t residency = 0;
    unsigned long original;
    unsigned long page_start;
    unsigned long target;
    int failures = 0;

    original = (unsigned long)raw_syscall6(SYS_brk, 0, 0, 0, 0, 0, 0);
    failures += expect_true("initial break", original >= PAGE_SIZE);
    failures += expect_result("query is stable",
        raw_syscall6(SYS_brk, 0, 0, 0, 0, 0, 0), (long)original);
    failures += expect_result("below minimum keeps old break",
        raw_syscall6(SYS_brk, 1, 0, 0, 0, 0, 0), (long)original);
    failures += expect_result("high invalid address keeps old break",
        raw_syscall6(SYS_brk, -(long)PAGE_SIZE, 0, 0, 0, 0, 0),
        (long)original);

    page_start = (original + PAGE_SIZE - 1u) &
                 ~(unsigned long)(PAGE_SIZE - 1u);
    target = page_start + PAGE_SIZE + 123u;
    failures += expect_result("exact unaligned growth",
        raw_syscall6(SYS_brk, (long)target, 0, 0, 0, 0, 0),
        (long)target);
    failures += expect_result("grown query",
        raw_syscall6(SYS_brk, 0, 0, 0, 0, 0, 0), (long)target);

    fresh_page = (volatile uint8_t *)(uintptr_t)page_start;
    fresh_page[0] = 0x5au;
    fresh_page[PAGE_SIZE + 100u] = 0xa5u;
    failures += expect_true("grown pages writable",
        fresh_page[0] == 0x5au && fresh_page[PAGE_SIZE + 100u] == 0xa5u);

    failures += expect_result("exact shrink",
        raw_syscall6(SYS_brk, (long)original, 0, 0, 0, 0, 0),
        (long)original);
    failures += expect_result("shrunk page absent",
        raw_syscall6(SYS_mincore, (long)page_start, PAGE_SIZE,
                     (long)&residency, 0, 0, 0), -ENOMEM);

    failures += expect_result("exact regrowth",
        raw_syscall6(SYS_brk, (long)target, 0, 0, 0, 0, 0),
        (long)target);
    failures += expect_true("regrown pages are zero filled",
        fresh_page[0] == 0 && fresh_page[PAGE_SIZE + 100u] == 0);
    failures += expect_result("final shrink",
        raw_syscall6(SYS_brk, (long)original, 0, 0, 0, 0, 0),
        (long)original);
    failures += expect_result("final query",
        raw_syscall6(SYS_brk, 0, 0, 0, 0, 0, 0), (long)original);

    if (!failures) print_text("BRK_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
