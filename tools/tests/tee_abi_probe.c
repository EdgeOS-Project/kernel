/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS tee Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_pipe2 293
#define SYS_tee 276
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_tee 77
#else
#error "tee_abi_probe requires a Linux 64-bit architecture"
#endif

#define SPLICE_F_NONBLOCK 0x02
#define EBADF 9
#define EAGAIN 11
#define EINVAL 22

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = (unsigned char *)destination;
    for (unsigned long index = 0; index < length; ++index)
        bytes[index] = (unsigned char)value;
    return destination;
}

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

static int expect_bytes(const char *name, const char *actual,
                        const char *expected, unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        if (actual[index] == expected[index]) continue;
        print_text("FAIL ");
        print_text(name);
        print_text("\n");
        return 1;
    }
    return 0;
}

static void close_pair(int descriptors[2]) {
    if (descriptors[0] >= 0)
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    if (descriptors[1] >= 0)
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    descriptors[0] = descriptors[1] = -1;
}

static int test_validation(void) {
    static const char byte = 'x';
    int first[2] = {-1, -1};
    int second[2] = {-1, -1};
    int failures = 0;
    failures += expect_result("invalid flags",
        raw_syscall6(SYS_tee, -1, -1, 1, 0x10, 0, 0), -EINVAL);
    failures += expect_result("invalid descriptors",
        raw_syscall6(SYS_tee, -1, -1, 1, 0, 0, 0), -EBADF);
    failures += expect_result("zero length",
        raw_syscall6(SYS_tee, -1, -1, 0, 0, 0, 0), 0);
    failures += expect_result("first pipe create",
        raw_syscall6(SYS_pipe2, (long)first, 0, 0, 0, 0, 0), 0);
    failures += expect_result("second pipe create",
        raw_syscall6(SYS_pipe2, (long)second, 0, 0, 0, 0, 0), 0);
    if (first[0] < 0 || second[0] < 0) return failures + 1;
    failures += expect_result("non-pipe input",
        raw_syscall6(SYS_tee, 1, second[1], 1, 0, 0, 0), -EINVAL);
    failures += expect_result("wrong input endpoint",
        raw_syscall6(SYS_tee, first[1], second[1], 1, 0, 0, 0),
        -EBADF);
    failures += expect_result("wrong output endpoint",
        raw_syscall6(SYS_tee, first[0], second[0], 1, 0, 0, 0),
        -EBADF);
    failures += expect_result("same pipe",
        raw_syscall6(SYS_tee, first[0], first[1], 1, 0, 0, 0),
        -EINVAL);
    failures += expect_result("seed for validation",
        raw_syscall6(SYS_write, first[1], (long)&byte, 1, 0, 0, 0), 1);
    close_pair(first);
    close_pair(second);
    return failures;
}

static int test_copy_without_consuming(void) {
    static const char payload[] = "tee-data";
    char source_observed[8] = {0};
    char output_observed[8] = {0};
    int source[2] = {-1, -1};
    int output[2] = {-1, -1};
    int failures = 0;
    failures += expect_result("copy source pipe create",
        raw_syscall6(SYS_pipe2, (long)source, 0, 0, 0, 0, 0), 0);
    failures += expect_result("copy output pipe create",
        raw_syscall6(SYS_pipe2, (long)output, 0, 0, 0, 0, 0), 0);
    if (source[0] < 0 || output[0] < 0) return failures + 1;
    failures += expect_result("seed source",
        raw_syscall6(SYS_write, source[1], (long)payload, 8, 0, 0, 0), 8);
    failures += expect_result("partial duplicate",
        raw_syscall6(SYS_tee, source[0], output[1], 4, 0, 0, 0), 4);
    failures += expect_result("duplicate remainder",
        raw_syscall6(SYS_tee, source[0], output[1], 4, 0, 0, 0), 4);
    failures += expect_result("read duplicate",
        raw_syscall6(SYS_read, output[0], (long)output_observed, 8,
                     0, 0, 0), 8);
    failures += expect_bytes("duplicate payload", output_observed,
                             "tee-tee-", 8);
    failures += expect_result("read source",
        raw_syscall6(SYS_read, source[0], (long)source_observed, 8,
                     0, 0, 0), 8);
    failures += expect_bytes("source remains intact", source_observed,
                             payload, 8);
    close_pair(source);
    close_pair(output);
    return failures;
}

static int test_empty_input(void) {
    char byte = 0;
    int source[2] = {-1, -1};
    int output[2] = {-1, -1};
    int failures = 0;
    failures += expect_result("empty source pipe create",
        raw_syscall6(SYS_pipe2, (long)source, 0, 0, 0, 0, 0), 0);
    failures += expect_result("empty output pipe create",
        raw_syscall6(SYS_pipe2, (long)output, 0, 0, 0, 0, 0), 0);
    if (source[0] < 0 || output[0] < 0) return failures + 1;
    failures += expect_result("empty nonblocking duplicate",
        raw_syscall6(SYS_tee, source[0], output[1], 1,
                     SPLICE_F_NONBLOCK, 0, 0), -EAGAIN);
    (void)raw_syscall6(SYS_close, source[1], 0, 0, 0, 0, 0);
    source[1] = -1;
    failures += expect_result("empty closed source",
        raw_syscall6(SYS_tee, source[0], output[1], 1, 0, 0, 0), 0);
    (void)raw_syscall6(SYS_close, output[1], 0, 0, 0, 0, 0);
    output[1] = -1;
    failures += expect_result("output remains empty",
        raw_syscall6(SYS_read, output[0], (long)&byte, 1,
                     0, 0, 0), 0);
    close_pair(source);
    close_pair(output);
    return failures;
}

static int run_tests(void) {
    int failures = 0;
    failures += test_validation();
    failures += test_copy_without_consuming();
    failures += test_empty_input();
    if (!failures) print_text("TEE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
