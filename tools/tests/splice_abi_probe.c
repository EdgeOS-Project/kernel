/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux splice ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_nanosleep 35
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_splice 275
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_lseek 62
#define SYS_read 63
#define SYS_write 64
#define SYS_splice 76
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "splice_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define EFAULT 14
#define EBADF 9
#define EAGAIN 11
#define EINVAL 22
#define ESPIPE 29

#define AT_FDCWD -100
#define O_RDWR 2
#define O_CREAT 0x40
#define O_TRUNC 0x200
#define SEEK_SET 0
#define SEEK_CUR 1
#define SPLICE_F_NONBLOCK 0x02
#define SIGCHLD 17

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

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

static int bytes_equal(const void *left, const void *right,
                       unsigned long size) {
    const unsigned char *a = left;
    const unsigned char *b = right;
    while (size) {
        --size;
        if (a[size] != b[size]) return 0;
    }
    return 1;
}

static void bytes_zero(void *destination, unsigned long size) {
    unsigned char *bytes = destination;
    while (size) bytes[--size] = 0;
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

static long create_file(const char *path) {
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    return raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                        O_CREAT | O_TRUNC | O_RDWR, 0644, 0, 0);
}

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int run_tests(void) {
    static const char source_path[] = "/tmp/edgeos-splice-source";
    static const char target_path[] = "/tmp/edgeos-splice-target";
    static const char wait_path[] = "/tmp/edgeos-splice-wait";
    static const char source_data[] = "0123456789";
    static const char pipe_data[] = "ABCD";
    static const char target_data[] = "--------";
    static const char wait_data[] = "wake";
    int descriptors[2] = {-1, -1};
    char buffer[16];
    int64_t input_offset;
    int64_t output_offset;
    long source;
    long target;
    long result;
    int failures = 0;

    failures += expect_result("zero length precedes flag validation",
        raw_syscall6(SYS_splice, -1, 0, -1, 0, 0, 0x10), 0);
    failures += expect_result("zero length ignores descriptors",
        raw_syscall6(SYS_splice, -1, 0, -1, 0, 0, 0), 0);
    failures += expect_result("invalid descriptors",
        raw_syscall6(SYS_splice, -1, 0, -1, 0, 1, 0), -EBADF);

    source = create_file(source_path);
    target = create_file(target_path);
    failures += expect_true("create regular files", source >= 0 && target >= 0);
    if (source >= 0 && target >= 0) {
        failures += expect_result("write source",
            raw_syscall6(SYS_write, source, (long)source_data,
                         sizeof(source_data) - 1u, 0, 0, 0),
            sizeof(source_data) - 1u);
        failures += expect_result("rewind source",
            raw_syscall6(SYS_lseek, source, 0, SEEK_SET, 0, 0, 0), 0);
        failures += expect_result("write target",
            raw_syscall6(SYS_write, target, (long)target_data,
                         sizeof(target_data) - 1u, 0, 0, 0),
            sizeof(target_data) - 1u);
        failures += expect_result("rewind target",
            raw_syscall6(SYS_lseek, target, 0, SEEK_SET, 0, 0, 0), 0);
        failures += expect_result("file to file rejected",
            raw_syscall6(SYS_splice, source, 0, target, 0, 1, 0), -EINVAL);
    }

    if (source >= 0 && raw_syscall6(SYS_pipe2, (long)descriptors,
                                    0, 0, 0, 0, 0) == 0) {
        input_offset = 2;
        failures += expect_result("file to pipe",
            raw_syscall6(SYS_splice, source, (long)&input_offset,
                         descriptors[1], 0, 4, 0), 4);
        failures += expect_result("input offset advanced", input_offset, 6);
        failures += expect_result("source description preserved",
            raw_syscall6(SYS_lseek, source, 0, SEEK_CUR, 0, 0, 0), 0);
        bytes_zero(buffer, sizeof(buffer));
        failures += expect_result("read file splice payload",
            raw_syscall6(SYS_read, descriptors[0], (long)buffer,
                         4, 0, 0, 0), 4);
        failures += expect_true("file splice payload",
                                bytes_equal(buffer, "2345", 4));
        failures += expect_result("pipe output offset rejected",
            raw_syscall6(SYS_splice, source, 0, descriptors[1],
                         (long)&output_offset, 1, 0), -ESPIPE);
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    } else {
        failures += expect_true("create file pipe", 0);
    }

    descriptors[0] = descriptors[1] = -1;
    if (target >= 0 && raw_syscall6(SYS_pipe2, (long)descriptors,
                                    0, 0, 0, 0, 0) == 0) {
        failures += expect_result("write pipe payload",
            raw_syscall6(SYS_write, descriptors[1], (long)pipe_data,
                         4, 0, 0, 0), 4);
        output_offset = 2;
        failures += expect_result("pipe to file",
            raw_syscall6(SYS_splice, descriptors[0], 0, target,
                         (long)&output_offset, 4, 0), 4);
        failures += expect_result("output offset advanced", output_offset, 6);
        failures += expect_result("target description preserved",
            raw_syscall6(SYS_lseek, target, 0, SEEK_CUR, 0, 0, 0), 0);
        bytes_zero(buffer, sizeof(buffer));
        failures += expect_result("read target",
            raw_syscall6(SYS_read, target, (long)buffer, 8, 0, 0, 0), 8);
        failures += expect_true("pipe splice payload",
                                bytes_equal(buffer, "--ABCD--", 8));
        failures += expect_result("pipe input offset rejected",
            raw_syscall6(SYS_splice, descriptors[0], (long)&input_offset,
                         target, 0, 1, 0), -ESPIPE);
        failures += expect_result("wrong input pipe end",
            raw_syscall6(SYS_splice, descriptors[1], 0,
                         target, 0, 1, 0), -EBADF);
        failures += expect_result("wrong output pipe end",
            raw_syscall6(SYS_splice, source, 0,
                         descriptors[0], 0, 1, 0), -EBADF);
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    } else {
        failures += expect_true("create output pipe", 0);
    }

    descriptors[0] = descriptors[1] = -1;
    if (target >= 0 && raw_syscall6(SYS_pipe2, (long)descriptors,
                                    0, 0, 0, 0, 0) == 0) {
        failures += expect_result("nonblocking empty pipe",
            raw_syscall6(SYS_splice, descriptors[0], 0, target, 0,
                         1, SPLICE_F_NONBLOCK), -EAGAIN);
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    }

    descriptors[0] = descriptors[1] = -1;
    {
        long wait_target = create_file(wait_path);
        if (wait_target >= 0 &&
            raw_syscall6(SYS_pipe2, (long)descriptors,
                         0, 0, 0, 0, 0) == 0) {
            long child = create_child();
            if (child == 0) {
                struct linux_timespec delay = {0, 20000000};
                (void)raw_syscall6(SYS_close, descriptors[0],
                                   0, 0, 0, 0, 0);
                (void)raw_syscall6(SYS_nanosleep, (long)&delay,
                                   0, 0, 0, 0, 0);
                result = raw_syscall6(SYS_write, descriptors[1],
                                      (long)wait_data, 4, 0, 0, 0);
                raw_syscall6(SYS_exit, result == 4 ? 0 : 1,
                             0, 0, 0, 0, 0);
                __builtin_unreachable();
            }
            (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
            failures += expect_result("blocking splice wakeup",
                raw_syscall6(SYS_splice, descriptors[0], 0,
                             wait_target, 0, 4, 0), 4);
            if (child > 0) {
                int status = 0;
                failures += expect_result("wait writer",
                    raw_syscall6(SYS_wait4, child, (long)&status,
                                 0, 0, 0, 0), child);
                failures += expect_result("writer status", status, 0);
            } else {
                failures += expect_true("create writer", 0);
            }
            (void)raw_syscall6(SYS_lseek, wait_target, 0,
                               SEEK_SET, 0, 0, 0);
            bytes_zero(buffer, sizeof(buffer));
            failures += expect_result("read wake payload",
                raw_syscall6(SYS_read, wait_target, (long)buffer,
                             4, 0, 0, 0), 4);
            failures += expect_true("blocking splice payload",
                                    bytes_equal(buffer, wait_data, 4));
            (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
            (void)raw_syscall6(SYS_close, wait_target, 0, 0, 0, 0, 0);
        } else {
            failures += expect_true("create blocking splice state", 0);
        }
    }

    if (source >= 0) (void)raw_syscall6(SYS_close, source, 0, 0, 0, 0, 0);
    if (target >= 0) (void)raw_syscall6(SYS_close, target, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)source_path,
                       0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)target_path,
                       0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)wait_path,
                       0, 0, 0, 0);
    if (!failures) print_text("SPLICE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
