/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS vmsplice Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_fcntl 72
#define SYS_pipe2 293
#define SYS_vmsplice 278
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_vmsplice 75
#else
#error "vmsplice_abi_probe requires a Linux 64-bit architecture"
#endif

#define O_NONBLOCK 0x0800
#define F_GETFL 3
#define SPLICE_F_NONBLOCK 0x02
#define SPLICE_F_GIFT 0x08
#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22

struct test_iovec {
    uint64_t base;
    uint64_t length;
};

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

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
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

static int test_argument_validation(void) {
    char byte = 'x';
    struct test_iovec vector = {(uint64_t)&byte, 1};
    int descriptors[2] = {-1, -1};
    int failures = 0;
    failures += expect_result("invalid descriptor with zero vectors",
        raw_syscall6(SYS_vmsplice, -1, 0, 0, 0, 0, 0), -EBADF);
    failures += expect_result("pipe create",
        raw_syscall6(SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    failures += expect_result("zero vectors",
        raw_syscall6(SYS_vmsplice, descriptors[1], 0, 0, 0, 0, 0), 0);
    failures += expect_result("unknown flags",
        raw_syscall6(SYS_vmsplice, descriptors[1], (long)&vector, 1,
                     0x10, 0, 0), -EINVAL);
    failures += expect_result("too many vectors",
        raw_syscall6(SYS_vmsplice, descriptors[1], (long)&vector, 1025,
                     0, 0, 0), -EINVAL);
    failures += expect_result("null vector",
        raw_syscall6(SYS_vmsplice, descriptors[1], 0, 1, 0, 0, 0),
        -EFAULT);
    failures += expect_result("non-pipe descriptor",
        raw_syscall6(SYS_vmsplice, 1, (long)&vector, 1, 0, 0, 0),
        -EBADF);
    failures += expect_result("gift copy fallback",
        raw_syscall6(SYS_vmsplice, descriptors[1], (long)&vector, 1,
                     SPLICE_F_GIFT, 0, 0), 1);
    close_pair(descriptors);
    return failures;
}

static int test_write_direction(void) {
    static const char expected[] = "vmsplice";
    static const char first[] = "vm";
    static const char second[] = "splice";
    struct test_iovec vectors[2] = {
        {(uint64_t)first, 2},
        {(uint64_t)second, 6},
    };
    char observed[8] = {0};
    int descriptors[2] = {-1, -1};
    int failures = 0;
    failures += expect_result("write pipe create",
        raw_syscall6(SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    failures += expect_result("vector write",
        raw_syscall6(SYS_vmsplice, descriptors[1], (long)vectors, 2,
                     SPLICE_F_NONBLOCK, 0, 0), 8);
    failures += expect_true("write nonblock flag restored",
        (raw_syscall6(SYS_fcntl, descriptors[1], F_GETFL,
                      0, 0, 0, 0) & O_NONBLOCK) == 0);
    failures += expect_result("read vector payload",
        raw_syscall6(SYS_read, descriptors[0], (long)observed,
                     sizeof(observed), 0, 0, 0), 8);
    failures += expect_bytes("vector write payload", observed, expected, 8);
    close_pair(descriptors);
    return failures;
}

static int test_more_than_sixteen_vectors(void) {
    static const char expected = 'z';
    struct test_iovec vectors[17];
    char observed = 0;
    int descriptors[2] = {-1, -1};
    int failures = 0;
    for (unsigned long index = 0; index < 17; ++index) {
        vectors[index].base = (uint64_t)&expected;
        vectors[index].length = index == 16 ? 1 : 0;
    }
    failures += expect_result("seventeen-vector pipe create",
        raw_syscall6(SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    failures += expect_result("seventeen-vector write",
        raw_syscall6(SYS_vmsplice, descriptors[1], (long)vectors, 17,
                     0, 0, 0), 1);
    failures += expect_result("seventeen-vector read",
        raw_syscall6(SYS_read, descriptors[0], (long)&observed,
                     sizeof(observed), 0, 0, 0), 1);
    failures += expect_bytes("seventeen-vector payload", &observed,
                             &expected, 1);
    close_pair(descriptors);
    return failures;
}

static int test_read_direction(void) {
    static const char expected[] = "pipe-read";
    struct test_iovec vectors[2];
    char first[4] = {0};
    char second[5] = {0};
    int descriptors[2] = {-1, -1};
    int failures = 0;
    vectors[0].base = (uint64_t)first;
    vectors[0].length = sizeof(first);
    vectors[1].base = (uint64_t)second;
    vectors[1].length = sizeof(second);
    failures += expect_result("read pipe create",
        raw_syscall6(SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    failures += expect_result("seed read pipe",
        raw_syscall6(SYS_write, descriptors[1], (long)expected, 9,
                     0, 0, 0), 9);
    failures += expect_result("vector read",
        raw_syscall6(SYS_vmsplice, descriptors[0], (long)vectors, 2,
                     0, 0, 0), 9);
    failures += expect_bytes("vector read first", first, expected, 4);
    failures += expect_bytes("vector read second", second, expected + 4, 5);
    failures += expect_result("empty nonblocking read",
        raw_syscall6(SYS_vmsplice, descriptors[0], (long)vectors, 2,
                     SPLICE_F_NONBLOCK, 0, 0), -EAGAIN);
    failures += expect_true("read nonblock flag restored",
        (raw_syscall6(SYS_fcntl, descriptors[0], F_GETFL,
                      0, 0, 0, 0) & O_NONBLOCK) == 0);
    close_pair(descriptors);
    return failures;
}

static int run_tests(void) {
    int failures = 0;
    failures += test_argument_validation();
    failures += test_write_direction();
    failures += test_more_than_sixteen_vectors();
    failures += test_read_direction();
    if (!failures) print_text("VMSPLICE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
