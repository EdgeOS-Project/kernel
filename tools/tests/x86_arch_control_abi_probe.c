/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding x86_64 ABI probe for arch_prctl, iopl, and ioperm.
 */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x86_arch_control_abi_probe requires x86_64"
#endif

#define SYS_write 1
#define SYS_arch_prctl 158
#define SYS_iopl 172
#define SYS_ioperm 173
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_setuid 105

#define EPERM 1
#define EFAULT 14
#define EINVAL 22

#define ARCH_SET_GS 0x1001
#define ARCH_GET_GS 0x1004

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(a0), "S"(a1), "d"(a2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(
        SYS_write, 1, (long)&buffer[position],
        (long)(sizeof(buffer) - (unsigned)position), 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text(name);
    print_text(": result=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text(name);
    print_text(": condition failed\n");
    return 1;
}

static int test_arch_prctl(void) {
    const uint64_t marker = UINT64_C(0x12345000);
    uint64_t original = UINT64_MAX;
    uint64_t observed = UINT64_MAX;
    int failures = 0;

    failures += expect_result(
        "arch_prctl get original gs",
        raw_syscall6(SYS_arch_prctl, ARCH_GET_GS, (long)&original,
                     0, 0, 0, 0),
        0);
    failures += expect_result(
        "arch_prctl get gs null",
        raw_syscall6(SYS_arch_prctl, ARCH_GET_GS, 0, 0, 0, 0, 0),
        -EFAULT);
    failures += expect_result(
        "arch_prctl invalid code",
        raw_syscall6(SYS_arch_prctl, 0x7fffffff, 0, 0, 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "arch_prctl reject noncanonical gs",
        raw_syscall6(SYS_arch_prctl, ARCH_SET_GS, -1, 0, 0, 0, 0),
        -EPERM);
    failures += expect_result(
        "arch_prctl set gs",
        raw_syscall6(SYS_arch_prctl, ARCH_SET_GS, (long)marker,
                     0, 0, 0, 0),
        0);
    failures += expect_result(
        "arch_prctl get updated gs",
        raw_syscall6(SYS_arch_prctl, ARCH_GET_GS, (long)&observed,
                     0, 0, 0, 0),
        0);
    failures += expect_true(
        "arch_prctl gs roundtrip", observed == marker);
    failures += expect_result(
        "arch_prctl restore gs",
        raw_syscall6(SYS_arch_prctl, ARCH_SET_GS, (long)original,
                     0, 0, 0, 0),
        0);
    return failures;
}

static int test_privileged_io(void) {
    int failures = 0;

    failures += expect_result(
        "iopl invalid level",
        raw_syscall6(SYS_iopl, 4, 0, 0, 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "ioperm invalid range",
        raw_syscall6(SYS_ioperm, 65535, 2, 1, 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "iopl root level zero",
        raw_syscall6(SYS_iopl, 0, 0, 0, 0, 0, 0),
        0);
    failures += expect_result(
        "ioperm root enable",
        raw_syscall6(SYS_ioperm, 0, 1, 1, 0, 0, 0),
        0);
    return failures;
}

static int test_privileged_io_permission(void) {
    int status = -1;
    long child = raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);

    if (child < 0) return expect_true("fork permission child", 0);
    if (child == 0) {
        int failures = 0;
        failures += expect_result(
            "drop root identity",
            raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0),
            0);
        failures += expect_result(
            "iopl nonroot lower",
            raw_syscall6(SYS_iopl, 0, 0, 0, 0, 0, 0),
            0);
        failures += expect_result(
            "iopl nonroot raise permission",
            raw_syscall6(SYS_iopl, 3, 0, 0, 0, 0, 0),
            -EPERM);
        failures += expect_result(
            "ioperm nonroot permission",
            raw_syscall6(SYS_ioperm, 0, 1, 1, 0, 0, 0),
            -EPERM);
        (void)raw_syscall6(
            SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (raw_syscall6(
            SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child)
        return expect_true("wait permission child", 0);
    return expect_result("permission child status", status, 0);
}

START_ATTRIBUTES void _start(void) {
    int failures = 0;

    failures += test_arch_prctl();
    failures += test_privileged_io();
    failures += test_privileged_io_permission();
    if (failures) {
        print_text("X86_ARCH_CONTROL_ABI_PROBE_FAILED failures=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("X86_ARCH_CONTROL_ABI_PROBE_PASS\n");
    }
    (void)raw_syscall6(
        SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
