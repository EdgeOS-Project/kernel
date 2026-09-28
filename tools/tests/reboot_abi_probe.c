/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux reboot ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_setuid 105
#define SYS_reboot 169
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_reboot 142
#define SYS_setuid 146
#else
#error "reboot_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define EINVAL 22

#define REBOOT_MAGIC1 0xfee1deadu
#define REBOOT_MAGIC2 0x28121969u
#define REBOOT_CAD_OFF 0u

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

static int run_tests(void) {
    int failures = 0;

    failures += expect_result("bad primary magic",
        raw_syscall6(SYS_reboot, 0, REBOOT_MAGIC2, REBOOT_CAD_OFF,
                     0, 0, 0), -EINVAL);
    failures += expect_result("bad secondary magic",
        raw_syscall6(SYS_reboot, REBOOT_MAGIC1, 0, REBOOT_CAD_OFF,
                     0, 0, 0), -EINVAL);
    failures += expect_result("drop privilege",
        raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0), 0);
    failures += expect_result("valid command requires capability",
        raw_syscall6(SYS_reboot, REBOOT_MAGIC1, REBOOT_MAGIC2,
                     REBOOT_CAD_OFF, 0, 0, 0), -EPERM);
    failures += expect_result("permission checked before magic",
        raw_syscall6(SYS_reboot, 0, REBOOT_MAGIC2, REBOOT_CAD_OFF,
                     0, 0, 0), -EPERM);

    if (!failures) print_text("REBOOT_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
