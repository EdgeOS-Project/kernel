/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS sendfile Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_nanosleep 35
#define SYS_sendfile 40
#define SYS_socketpair 53
#define SYS_fork 57
#define SYS_ftruncate 77
#define SYS_wait4 61
#define SYS_fcntl 72
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_pipe2 293
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_ftruncate 46
#define SYS_openat 56
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_lseek 62
#define SYS_read 63
#define SYS_write 64
#define SYS_sendfile 71
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_socketpair 199
#define SYS_munmap 215
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_wait4 260
#define SYS_fcntl 25
#else
#error "sendfile_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR 0x0002
#define O_CREAT 0x0040
#define O_TRUNC 0x0200
#define O_APPEND 0x0400
#define O_NONBLOCK 0x0800
#define O_DIRECTORY 0x10000
#define F_SETFL 4
#define SEEK_SET 0
#define SEEK_CUR 1
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define AF_UNIX 1
#define SOCK_STREAM 1
#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define SIGCHLD 17
#define PAGE_SIZE 4096

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

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[32];
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
    (void)raw_syscall6(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned long)position),
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
        print_text(" byte=");
        print_number((long)index);
        print_text(" actual=");
        print_number((unsigned char)actual[index]);
        print_text(" expected=");
        print_number((unsigned char)expected[index]);
        print_text("\n");
        return 1;
    }
    return 0;
}

static void zero_bytes(void *memory, unsigned long length) {
    unsigned char *bytes = memory;
    while (length--) *bytes++ = 0;
}

static long open_file(const char *path, long flags) {
    return raw_syscall6(SYS_openat, AT_FDCWD, (long)path, flags, 0600, 0, 0);
}

static long send_file(long output, long input, int64_t *offset,
                      uint64_t count) {
    return raw_syscall6(SYS_sendfile, output, input, (long)offset,
                        (long)count, 0, 0);
}

static __attribute__((noinline, returns_twice)) long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int reset_file(long descriptor) {
    if (raw_syscall6(SYS_ftruncate, descriptor, 0, 0, 0, 0, 0) < 0)
        return -1;
    return raw_syscall6(SYS_lseek, descriptor, 0, SEEK_SET, 0, 0, 0) < 0 ?
           -1 : 0;
}

static int read_at_start(long descriptor, char *buffer,
                         unsigned long length) {
    if (raw_syscall6(SYS_lseek, descriptor, 0, SEEK_SET, 0, 0, 0) < 0)
        return -1;
    return (int)raw_syscall6(SYS_read, descriptor, (long)buffer,
                             (long)length, 0, 0, 0);
}

static int test_regular_copy(long input, long output) {
    char observed[8];
    int64_t offset;
    int failures = 0;

    zero_bytes(observed, sizeof(observed));
    if (reset_file(output) < 0) return 1;
    (void)raw_syscall6(SYS_lseek, input, 1, SEEK_SET, 0, 0, 0);
    failures += expect_result("implicit copy",
        send_file(output, input, 0, 5), 5);
    failures += expect_result("implicit input position",
        raw_syscall6(SYS_lseek, input, 0, SEEK_CUR, 0, 0, 0), 6);
    failures += expect_result("implicit output position",
        raw_syscall6(SYS_lseek, output, 0, SEEK_CUR, 0, 0, 0), 5);
    failures += expect_result("implicit readback",
        read_at_start(output, observed, 5), 5);
    failures += expect_bytes("implicit bytes", observed, "bcdef", 5);

    zero_bytes(observed, sizeof(observed));
    if (reset_file(output) < 0) return failures + 1;
    (void)raw_syscall6(SYS_lseek, input, 7, SEEK_SET, 0, 0, 0);
    offset = 2;
    failures += expect_result("explicit copy",
        send_file(output, input, &offset, 4), 4);
    failures += expect_result("explicit offset", offset, 6);
    failures += expect_result("explicit input position unchanged",
        raw_syscall6(SYS_lseek, input, 0, SEEK_CUR, 0, 0, 0), 7);
    failures += expect_result("explicit readback",
        read_at_start(output, observed, 4), 4);
    failures += expect_bytes("explicit bytes", observed, "cdef", 4);
    return failures;
}

static int test_endpoint_copy(long input) {
    char observed[8];
    int descriptors[2];
    int64_t offset;
    int failures = 0;

    descriptors[0] = -1;
    descriptors[1] = -1;
    failures += expect_result("pipe create",
        raw_syscall6(SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (descriptors[0] >= 0 && descriptors[1] >= 0) {
        long transferred;
        zero_bytes(observed, sizeof(observed));
        offset = 3;
        transferred = send_file(descriptors[1], input, &offset, 4);
        failures += expect_result("pipe output", transferred, 4);
        failures += expect_result("pipe offset", offset, 7);
        if (transferred == 4) {
            failures += expect_result("pipe read",
                raw_syscall6(SYS_read, descriptors[0], (long)observed,
                             4, 0, 0, 0), 4);
            failures += expect_bytes("pipe bytes", observed, "defg", 4);
        }
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    }

    descriptors[0] = -1;
    descriptors[1] = -1;
    failures += expect_result("socketpair create",
        raw_syscall6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0,
                     (long)descriptors, 0, 0), 0);
    if (descriptors[0] >= 0 && descriptors[1] >= 0) {
        long transferred;
        zero_bytes(observed, sizeof(observed));
        offset = 4;
        transferred = send_file(descriptors[0], input, &offset, 4);
        failures += expect_result("socket output", transferred, 4);
        failures += expect_result("socket offset", offset, 8);
        if (transferred == 4) {
            failures += expect_result("socket read",
                raw_syscall6(SYS_read, descriptors[1], (long)observed,
                             4, 0, 0, 0), 4);
            failures += expect_bytes("socket bytes", observed, "efgh", 4);
        }
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    }
    return failures;
}

static int test_pipe_backpressure(long input) {
    static char fill[4096];
    int descriptors[2] = {-1, -1};
    int64_t offset = 0;
    long child;
    long transferred;
    int status = 0;
    int failures = 0;

    for (unsigned long index = 0; index < sizeof(fill); ++index)
        fill[index] = (char)index;
    failures += expect_result("backpressure pipe create",
        raw_syscall6(SYS_pipe2, (long)descriptors, O_NONBLOCK,
                     0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    for (;;) {
        long written = raw_syscall6(SYS_write, descriptors[1],
                                    (long)fill, sizeof(fill), 0, 0, 0);
        if (written == -EAGAIN) break;
        if (written <= 0) {
            failures += expect_result("fill nonblocking pipe", written,
                                      -EAGAIN);
            goto close_pipe;
        }
    }
    transferred = send_file(descriptors[1], input, &offset, 1);
    failures += expect_result("full nonblocking pipe", transferred,
                              -EAGAIN);
    failures += expect_result("nonblocking offset unchanged", offset, 0);
    failures += expect_result("clear pipe nonblocking",
        raw_syscall6(SYS_fcntl, descriptors[1], F_SETFL, 0, 0, 0, 0), 0);

    child = create_child();
    if (child == 0) {
        static const struct linux_timespec delay = {0, 50000000};
        (void)raw_syscall6(SYS_nanosleep, (long)&delay, 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_read, descriptors[0], (long)fill,
                           sizeof(fill), 0, 0, 0);
        raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (child < 0) {
        failures += expect_result("backpressure child", child, 0);
        goto close_pipe;
    }
    offset = 0;
    failures += expect_result("full blocking pipe resumes",
        send_file(descriptors[1], input, &offset, 1), 1);
    failures += expect_result("blocking offset", offset, 1);
    failures += expect_result("backpressure wait",
        raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0), child);
    failures += expect_result("backpressure child status", status, 0);

close_pipe:
    (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    return failures;
}

static int test_socket_backpressure(long input) {
    static char fill[4096];
    int descriptors[2] = {-1, -1};
    int64_t offset = 0;
    long child;
    long transferred;
    int status = 0;
    int failures = 0;

    for (unsigned long index = 0; index < sizeof(fill); ++index)
        fill[index] = (char)index;
    failures += expect_result("backpressure socketpair create",
        raw_syscall6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0,
                     (long)descriptors, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    failures += expect_result("set socket nonblocking",
        raw_syscall6(SYS_fcntl, descriptors[0], F_SETFL, O_NONBLOCK,
                     0, 0, 0), 0);
    for (;;) {
        long written = raw_syscall6(SYS_write, descriptors[0],
                                    (long)fill, sizeof(fill), 0, 0, 0);
        if (written == -EAGAIN) break;
        if (written <= 0) {
            failures += expect_result("fill nonblocking socket", written,
                                      -EAGAIN);
            goto close_socket;
        }
    }
    transferred = send_file(descriptors[0], input, &offset, 1);
    failures += expect_result("full nonblocking socket", transferred,
                              -EAGAIN);
    failures += expect_result("socket nonblocking offset unchanged",
                              offset, 0);
    failures += expect_result("clear socket nonblocking",
        raw_syscall6(SYS_fcntl, descriptors[0], F_SETFL, 0,
                     0, 0, 0), 0);

    child = create_child();
    if (child == 0) {
        static const struct linux_timespec delay = {0, 50000000};
        (void)raw_syscall6(SYS_nanosleep, (long)&delay, 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_fcntl, descriptors[1], F_SETFL,
                           O_NONBLOCK, 0, 0, 0);
        while (raw_syscall6(SYS_read, descriptors[1], (long)fill,
                            sizeof(fill), 0, 0, 0) > 0) {
        }
        raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (child < 0) {
        failures += expect_result("socket backpressure child", child, 0);
        goto close_socket;
    }
    offset = 0;
    failures += expect_result("full blocking socket resumes",
        send_file(descriptors[0], input, &offset, 1), 1);
    failures += expect_result("blocking socket offset", offset, 1);
    failures += expect_result("socket backpressure wait",
        raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0), child);
    failures += expect_result("socket backpressure child status", status, 0);

close_socket:
    (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    return failures;
}

static int test_errors(long input, long output) {
    const char *append_path = "/tmp/edgeos-sendfile-append";
    int64_t offset = 0;
    long append;
    long readonly;
    long writeonly;
    long directory;
    int pipe_fds[2] = {-1, -1};
    int failures = 0;

    failures += expect_result("offset fault before descriptors",
        send_file(-1, -1, (int64_t *)1, 0), -EFAULT);
    failures += expect_result("bad output descriptor at zero count",
        send_file(-1, input, 0, 0), -EBADF);
    failures += expect_result("bad input descriptor at zero count",
        send_file(output, -1, 0, 0), -EBADF);
    failures += expect_result("bad offset pointer at zero count",
        send_file(output, input, (int64_t *)1, 0), -EFAULT);
    offset = -1;
    failures += expect_result("negative offset at zero count",
        send_file(output, input, &offset, 0), -EINVAL);

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)append_path,
                       0, 0, 0, 0);
    append = open_file(append_path, O_CREAT | O_TRUNC | O_WRONLY | O_APPEND);
    failures += expect_result("append output",
        send_file(append, input, 0, 1), -EINVAL);
    if (append >= 0)
        (void)raw_syscall6(SYS_close, append, 0, 0, 0, 0, 0);

    readonly = open_file(append_path, O_RDONLY);
    failures += expect_result("read-only output",
        send_file(readonly, input, 0, 1), -EBADF);
    if (readonly >= 0)
        (void)raw_syscall6(SYS_close, readonly, 0, 0, 0, 0, 0);

    writeonly = open_file(append_path, O_WRONLY);
    failures += expect_result("write-only input",
        send_file(output, writeonly, 0, 1), -EBADF);
    if (writeonly >= 0)
        (void)raw_syscall6(SYS_close, writeonly, 0, 0, 0, 0, 0);

    directory = open_file("/tmp", O_RDONLY | O_DIRECTORY);
    failures += expect_result("directory input",
        send_file(output, directory, 0, 1), -EINVAL);
    if (directory >= 0)
        (void)raw_syscall6(SYS_close, directory, 0, 0, 0, 0, 0);

    failures += expect_result("pipe create for input",
        raw_syscall6(SYS_pipe2, (long)pipe_fds, 0, 0, 0, 0, 0), 0);
    if (pipe_fds[0] >= 0 && pipe_fds[1] >= 0) {
        failures += expect_result("pipe input",
            send_file(output, pipe_fds[0], 0, 1), -EINVAL);
        (void)raw_syscall6(SYS_close, pipe_fds[0], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, pipe_fds[1], 0, 0, 0, 0, 0);
    }
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)append_path,
                       0, 0, 0, 0);
    return failures;
}

static int test_copyback_fault(long input, long output) {
    long page;
    int64_t *offset;
    int failures = 0;

    page = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page < 0) return expect_result("copyback mmap", page, 0);
    offset = (int64_t *)(uintptr_t)page;
    *offset = 1;
    failures += expect_result("copyback mprotect",
        raw_syscall6(SYS_mprotect, page, PAGE_SIZE, PROT_READ,
                     0, 0, 0), 0);
    if (reset_file(output) < 0) ++failures;
    failures += expect_result("offset copyback fault",
        send_file(output, input, offset, 2), -EFAULT);
    failures += expect_result("copyback transfer visible",
        raw_syscall6(SYS_lseek, output, 0, SEEK_CUR, 0, 0, 0), 2);
    (void)raw_syscall6(SYS_munmap, page, PAGE_SIZE, 0, 0, 0, 0);
    return failures;
}

static int run_tests(void) {
    static const char payload[] = "abcdefghijklmnop";
    const char *input_path = "/tmp/edgeos-sendfile-input";
    const char *output_path = "/tmp/edgeos-sendfile-output";
    long input;
    long output;
    int failures = 0;

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)input_path,
                       0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)output_path,
                       0, 0, 0, 0);
    input = open_file(input_path, O_CREAT | O_TRUNC | O_RDWR);
    output = open_file(output_path, O_CREAT | O_TRUNC | O_RDWR);
    if (input < 0 || output < 0) {
        print_text("FAIL setup\n");
        return 1;
    }
    failures += expect_result("write input",
        raw_syscall6(SYS_write, input, (long)payload,
                     (long)(sizeof(payload) - 1u), 0, 0, 0),
        (long)(sizeof(payload) - 1u));

    failures += test_regular_copy(input, output);
    failures += test_endpoint_copy(input);
    failures += test_pipe_backpressure(input);
    failures += test_socket_backpressure(input);
    failures += test_errors(input, output);
    failures += test_copyback_fault(input, output);

    (void)raw_syscall6(SYS_close, input, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, output, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)input_path,
                       0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)output_path,
                       0, 0, 0, 0);
    if (!failures) print_text("SENDFILE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
