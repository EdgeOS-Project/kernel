/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux generic ioctl policy probe. It validates descriptor
 * ordering, unsigned request normalization, FIONBIO open-description state,
 * and close-on-exec descriptor state on both supported 64-bit architectures.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_fcntl 72
#define SYS_exit 60
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_ioctl 29
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_write 64
#define SYS_exit 93
#else
#error "ioctl_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EFAULT 14
#define ENOTTY 25

#define F_DUPFD 0
#define F_GETFD 1
#define F_GETFL 3
#define FD_CLOEXEC 1

#define O_NONBLOCK 0x800

#define FIONCLEX 0x5450
#define FIOCLEX 0x5451
#define FIONBIO 0x5421

static long raw_syscall6(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4,
                         long argument5) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = argument3;
    register long r8 __asm__("r8") = argument4;
    register long r9 __asm__("r9") = argument5;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    register long x4 __asm__("x4") = argument4;
    register long x5 __asm__("x5") = argument5;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall6(number, argument0, argument1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static void putdec(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        putstr("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    if (!magnitude) {
        putstr("0");
        return;
    }
    while (magnitude && position) {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    }
    (void)raw_syscall3(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned)position));
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": result=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}

static int expect_mask(const char *name, long value, long mask,
                       int expected_set) {
    int set = (value & mask) != 0;
    if (value >= 0 && set == expected_set) return 0;
    putstr(name);
    putstr(": value=");
    putdec(value);
    putstr("\n");
    return 1;
}

static int run_probe(void) {
    int descriptors[2] = {-1, -1};
    int enabled = 1;
    int disabled = 0;
    long duplicate = -1;
    long flags;
    int failures = 0;

    failures += expect_result("bad_descriptor_first",
        raw_syscall3(SYS_ioctl, -1, FIONBIO, 1), -EBADF);
    failures += expect_result("pipe2",
        raw_syscall2(SYS_pipe2, (long)descriptors, 0), 0);
    if (descriptors[0] < 0) goto out;

    failures += expect_result("fioclex",
        raw_syscall3(SYS_ioctl, descriptors[0], FIOCLEX, 1), 0);
    flags = raw_syscall3(SYS_fcntl, descriptors[0], F_GETFD, 0);
    failures += expect_result("fioclex_flags", flags, FD_CLOEXEC);
    failures += expect_result("fionclex",
        raw_syscall3(SYS_ioctl, descriptors[0], FIONCLEX, 1), 0);
    flags = raw_syscall3(SYS_fcntl, descriptors[0], F_GETFD, 0);
    failures += expect_result("fionclex_flags", flags, 0);

    failures += expect_result("fionbio_null",
        raw_syscall3(SYS_ioctl, descriptors[0], FIONBIO, 0), -EFAULT);
    failures += expect_result("fionbio_high_request_bits",
        raw_syscall3(SYS_ioctl, descriptors[0],
                     (long)FIONBIO | (1L << 32), (long)&enabled), 0);
    flags = raw_syscall3(SYS_fcntl, descriptors[0], F_GETFL, 0);
    failures += expect_mask("fionbio_enabled", flags, O_NONBLOCK, 1);

    duplicate = raw_syscall3(SYS_fcntl, descriptors[0], F_DUPFD, 10);
    if (duplicate < 0) {
        failures += expect_result("duplicate", duplicate, 10);
    } else {
        flags = raw_syscall3(SYS_fcntl, duplicate, F_GETFL, 0);
        failures += expect_mask("fionbio_shared_description", flags,
                                O_NONBLOCK, 1);
    }

    failures += expect_result("fionbio_disable",
        raw_syscall3(SYS_ioctl, descriptors[0], FIONBIO,
                     (long)&disabled), 0);
    flags = raw_syscall3(SYS_fcntl, descriptors[0], F_GETFL, 0);
    failures += expect_mask("fionbio_disabled", flags, O_NONBLOCK, 0);
    failures += expect_result("unknown_command",
        raw_syscall3(SYS_ioctl, descriptors[0], 0x12345678, 0),
        -ENOTTY);

out:
    if (duplicate >= 0) (void)raw_syscall1(SYS_close, duplicate);
    if (descriptors[0] >= 0) (void)raw_syscall1(SYS_close, descriptors[0]);
    if (descriptors[1] >= 0) (void)raw_syscall1(SYS_close, descriptors[1]);
    putstr(failures ? "IOCTL_ABI_PROBE_FAIL failures: " :
                      "IOCTL_ABI_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall1(SYS_exit, run_probe());
    for (;;) {}
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ __volatile__(
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
