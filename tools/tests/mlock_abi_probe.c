/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux memory-locking ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mlock 149
#define SYS_munlock 150
#define SYS_mlockall 151
#define SYS_munlockall 152
#define SYS_mlock2 325
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_mlock 228
#define SYS_munlock 229
#define SYS_mlockall 230
#define SYS_munlockall 231
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_mlock2 284
#else
#error "mlock_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22
#define ENOMEM 12

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10
#define PAGE_SIZE 4096u

#define MLOCK_ONFAULT 1
#define MCL_CURRENT 1
#define MCL_FUTURE 2
#define MCL_ONFAULT 4

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
    long mapping;
    int failures = 0;

    failures += expect_result("mlock zero length",
        raw_syscall6(SYS_mlock, PAGE_SIZE, 0, 0, 0, 0, 0), 0);
    failures += expect_result("munlock zero length",
        raw_syscall6(SYS_munlock, PAGE_SIZE, 0, 0, 0, 0, 0), 0);
    failures += expect_result("mlock unaligned zero length",
        raw_syscall6(SYS_mlock, 1, 0, 0, 0, 0, 0), -ENOMEM);
    failures += expect_result("munlock unaligned zero length",
        raw_syscall6(SYS_munlock, 1, 0, 0, 0, 0, 0), -ENOMEM);
    failures += expect_result("mlock2 invalid zero length",
        raw_syscall6(SYS_mlock2, 1, 0, 2, 0, 0, 0), -EINVAL);
    failures += expect_result("mlock overflow",
        raw_syscall6(SYS_mlock, -PAGE_SIZE, PAGE_SIZE * 2u,
                     0, 0, 0, 0), -ENOMEM);
    failures += expect_result("munlock overflow",
        raw_syscall6(SYS_munlock, -PAGE_SIZE, PAGE_SIZE * 2u,
                     0, 0, 0, 0), -ENOMEM);
    failures += expect_result("mlock unmapped",
        raw_syscall6(SYS_mlock, PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), -ENOMEM);
    failures += expect_result("munlock unmapped",
        raw_syscall6(SYS_munlock, PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), -ENOMEM);

    mapping = raw_syscall6(SYS_mmap, 0, PAGE_SIZE * 3u,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", mapping > 0);
    if (mapping <= 0) return failures;

    failures += expect_result("unaligned lock rounds outward",
        raw_syscall6(SYS_mlock, mapping + 17, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("on-fault lock",
        raw_syscall6(SYS_mlock2, mapping, PAGE_SIZE * 2u,
                     MLOCK_ONFAULT, 0, 0, 0), 0);
    failures += expect_result("unlock mapped range",
        raw_syscall6(SYS_munlock, mapping + 17, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("remove middle page",
        raw_syscall6(SYS_munmap, mapping + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("lock across hole",
        raw_syscall6(SYS_mlock, mapping, PAGE_SIZE * 3u,
                     0, 0, 0, 0), -ENOMEM);
    failures += expect_result("unlock across hole",
        raw_syscall6(SYS_munlock, mapping, PAGE_SIZE * 3u,
                     0, 0, 0, 0), -ENOMEM);

    failures += expect_result("mlockall zero flags",
        raw_syscall6(SYS_mlockall, 0, 0, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("mlockall onfault alone",
        raw_syscall6(SYS_mlockall, MCL_ONFAULT, 0, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("mlockall invalid flags",
        raw_syscall6(SYS_mlockall, 8, 0, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("mlockall current onfault",
        raw_syscall6(SYS_mlockall, MCL_CURRENT | MCL_ONFAULT,
                     0, 0, 0, 0, 0), 0);
    failures += expect_result("munlockall",
        raw_syscall6(SYS_munlockall, 0, 0, 0, 0, 0, 0), 0);
    failures += expect_result("mlockall future",
        raw_syscall6(SYS_mlockall, MCL_FUTURE, 0, 0, 0, 0, 0), 0);
    failures += expect_result("munlockall future",
        raw_syscall6(SYS_munlockall, 0, 0, 0, 0, 0, 0), 0);

    failures += expect_result("unmap first page",
        raw_syscall6(SYS_munmap, mapping, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("unmap final page",
        raw_syscall6(SYS_munmap, mapping + PAGE_SIZE * 2u, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    if (!failures) print_text("MLOCK_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
