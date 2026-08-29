/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mincore ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_brk 12
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mincore 27
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_brk 214
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mincore 232
#else
#error "mincore_abi_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22
#define ENOMEM 12

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

static long mincore_raw(uint64_t address, uint64_t length, void *vector) {
    return raw_syscall6(SYS_mincore, (long)address, (long)length,
                        (long)vector, 0, 0, 0);
}

static int run_tests(void) {
    uint8_t vector[3] = {0xaa, 0xaa, 0xaa};
    volatile uint8_t *mapping;
    uint64_t break_current;
    uint64_t break_page;
    uint64_t break_target;
    uint64_t stack_page;
    long mapped;
    int failures = 0;

    failures += expect_result("aligned zero length",
        mincore_raw(PAGE_SIZE, 0, 0), 0);
    failures += expect_result("unaligned zero length",
        mincore_raw(PAGE_SIZE + 1u, 0, 0), -EINVAL);
    failures += expect_result("overflow range",
        mincore_raw(UINT64_MAX & ~(uint64_t)(PAGE_SIZE - 1u),
                    PAGE_SIZE * 2u, vector), -ENOMEM);

    stack_page = (uint64_t)(uintptr_t)vector &
        ~(uint64_t)(PAGE_SIZE - 1u);
    failures += expect_result("implicit stack mapping",
        mincore_raw(stack_page, PAGE_SIZE, vector), 0);
    failures += expect_true("stack page resident", (vector[0] & 1u) != 0);

    break_current = (uint64_t)raw_syscall6(
        SYS_brk, 0, 0, 0, 0, 0, 0);
    break_page = break_current & ~(uint64_t)(PAGE_SIZE - 1u);
    break_target = break_page + PAGE_SIZE * 2u;
    failures += expect_result("grow program break",
        raw_syscall6(SYS_brk, (long)break_target, 0, 0, 0, 0, 0),
        (long)break_target);
    *(volatile uint8_t *)(uintptr_t)(break_page + PAGE_SIZE) = 0x5au;
    vector[0] = vector[1] = 0;
    failures += expect_result("program break mapping",
        mincore_raw(break_page, PAGE_SIZE * 2u, vector), 0);
    failures += expect_true("program break page resident",
        (vector[1] & 1u) != 0);

    mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE * 3u,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", mapped > 0);
    if (mapped <= 0) return failures;
    mapping = (volatile uint8_t *)(uintptr_t)mapped;

    failures += expect_result("mapped null vector",
        mincore_raw((uint64_t)mapped, PAGE_SIZE, 0), -EFAULT);
    failures += expect_result("mapped bad vector",
        mincore_raw((uint64_t)mapped, PAGE_SIZE, (void *)1), -EFAULT);
    failures += expect_result("unaligned mapping",
        mincore_raw((uint64_t)mapped + 1u, PAGE_SIZE, vector), -EINVAL);
    failures += expect_result("initial residency",
        mincore_raw((uint64_t)mapped, PAGE_SIZE * 3u, vector), 0);
    failures += expect_true("initial vector values",
        !(vector[0] & ~1u) && !(vector[1] & ~1u) && !(vector[2] & ~1u));

    mapping[0] = 0x31u;
    mapping[PAGE_SIZE * 2u] = 0x73u;
    vector[0] = vector[1] = vector[2] = 0;
    failures += expect_result("resident pages",
        mincore_raw((uint64_t)mapped, PAGE_SIZE * 3u, vector), 0);
    failures += expect_true("touched first page resident",
        (vector[0] & 1u) != 0);
    failures += expect_true("touched last page resident",
        (vector[2] & 1u) != 0);

    failures += expect_result("unmap middle page",
        raw_syscall6(SYS_munmap, mapped + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("range with hole",
        mincore_raw((uint64_t)mapped, PAGE_SIZE * 3u, vector), -ENOMEM);
    failures += expect_result("mapped prefix remains valid",
        mincore_raw((uint64_t)mapped, PAGE_SIZE, vector), 0);
    failures += expect_result("unmap complete range",
        raw_syscall6(SYS_munmap, mapped, PAGE_SIZE * 3u,
                     0, 0, 0, 0), 0);
    failures += expect_result("unmapped range",
        mincore_raw((uint64_t)mapped, PAGE_SIZE, vector), -ENOMEM);

    if (!failures) print_text("MINCORE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
