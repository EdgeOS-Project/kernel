/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS pipe and pipe2 Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_pipe 22
#define SYS_fcntl 72
#define SYS_exit 60
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#else
#error "pipe_abi_probe requires a Linux 64-bit architecture"
#endif

#define O_WRONLY 0x0001
#define O_NONBLOCK 0x0800
#define O_CLOEXEC 0x80000
#define F_GETFD 1
#define F_GETFL 3
#define FD_CLOEXEC 1
#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22

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

static int bytes_equal(const char *left, const char *right,
                       unsigned long length) {
    for (unsigned long index = 0; index < length; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static void close_pair(int descriptors[2]) {
    if (descriptors[0] >= 0)
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    if (descriptors[1] >= 0)
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    descriptors[0] = descriptors[1] = -1;
}

static int test_pipe2(void) {
    static const char payload[] = "pipe";
    char observed[4] = {0, 0, 0, 0};
    int descriptors[2] = {-1, -1};
    long read_flags;
    long write_flags;
    int failures = 0;

    failures += expect_result("invalid flags before pointer",
        raw_syscall6(SYS_pipe2, 1, 0x40000000, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("bad output pointer",
        raw_syscall6(SYS_pipe2, 0, 0, 0, 0, 0, 0), -EFAULT);
    failures += expect_result("pipe2 create",
        raw_syscall6(SYS_pipe2, (long)descriptors,
                     O_NONBLOCK | O_CLOEXEC, 0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;

    failures += expect_result("read close-on-exec",
        raw_syscall6(SYS_fcntl, descriptors[0], F_GETFD, 0, 0, 0, 0),
        FD_CLOEXEC);
    failures += expect_result("write close-on-exec",
        raw_syscall6(SYS_fcntl, descriptors[1], F_GETFD, 0, 0, 0, 0),
        FD_CLOEXEC);
    read_flags = raw_syscall6(SYS_fcntl, descriptors[0], F_GETFL,
                              0, 0, 0, 0);
    write_flags = raw_syscall6(SYS_fcntl, descriptors[1], F_GETFL,
                               0, 0, 0, 0);
    failures += expect_true("read access and nonblocking",
        read_flags >= 0 && (read_flags & (O_WRONLY | O_NONBLOCK)) ==
                           O_NONBLOCK);
    failures += expect_true("write access and nonblocking",
        write_flags >= 0 && (write_flags & (O_WRONLY | O_NONBLOCK)) ==
                            (O_WRONLY | O_NONBLOCK));
    failures += expect_result("empty nonblocking read",
        raw_syscall6(SYS_read, descriptors[0], (long)observed,
                     sizeof(observed), 0, 0, 0), -EAGAIN);
    failures += expect_result("write read endpoint",
        raw_syscall6(SYS_write, descriptors[0], (long)payload,
                     sizeof(payload) - 1u, 0, 0, 0), -EBADF);
    failures += expect_result("read write endpoint",
        raw_syscall6(SYS_read, descriptors[1], (long)observed,
                     sizeof(observed), 0, 0, 0), -EBADF);
    failures += expect_result("pipe write",
        raw_syscall6(SYS_write, descriptors[1], (long)payload,
                     sizeof(payload) - 1u, 0, 0, 0), 4);
    failures += expect_result("pipe read",
        raw_syscall6(SYS_read, descriptors[0], (long)observed,
                     sizeof(observed), 0, 0, 0), 4);
    failures += expect_true("pipe payload",
                            bytes_equal(observed, payload, 4));
    close_pair(descriptors);
    return failures;
}

#if defined(__x86_64__)
static int test_legacy_pipe(void) {
    int descriptors[2] = {-1, -1};
    long read_flags;
    long write_flags;
    int failures = 0;

    failures += expect_result("legacy pipe create",
        raw_syscall6(SYS_pipe, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    failures += expect_result("legacy read descriptor flags",
        raw_syscall6(SYS_fcntl, descriptors[0], F_GETFD, 0, 0, 0, 0), 0);
    failures += expect_result("legacy write descriptor flags",
        raw_syscall6(SYS_fcntl, descriptors[1], F_GETFD, 0, 0, 0, 0), 0);
    read_flags = raw_syscall6(SYS_fcntl, descriptors[0], F_GETFL,
                              0, 0, 0, 0);
    write_flags = raw_syscall6(SYS_fcntl, descriptors[1], F_GETFL,
                               0, 0, 0, 0);
    failures += expect_true("legacy read blocking",
                            read_flags >= 0 && !(read_flags & O_NONBLOCK));
    failures += expect_true("legacy write blocking",
                            write_flags >= 0 && !(write_flags & O_NONBLOCK));
    close_pair(descriptors);
    return failures;
}
#endif

static int run_tests(void) {
    int failures = test_pipe2();
#if defined(__x86_64__)
    failures += test_legacy_pipe();
#endif
    if (!failures) print_text("PIPE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
