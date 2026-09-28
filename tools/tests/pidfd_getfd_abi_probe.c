/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS pidfd_getfd Linux ABI regression test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_fcntl 72
#define SYS_setresuid 117
#define SYS_setresgid 119
#define SYS_prctl 157
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_lseek 62
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_kill 129
#define SYS_setresuid 147
#define SYS_setresgid 149
#define SYS_prctl 167
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "pidfd_getfd_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_pidfd_open 434
#define SYS_pidfd_getfd 438

#define AT_FDCWD (-100)
#define O_RDWR 0x0002
#define O_CREAT 0x0040
#define O_TRUNC 0x0200
#define F_GETFD 1
#define FD_CLOEXEC 1
#define SEEK_SET 0
#define SIGKILL 9
#define SIGCHLD 17
#define PR_SET_DUMPABLE 4
#define EBADF 9
#define EPERM 1
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

static long raw_syscall5(long number, long a0, long a1, long a2,
                         long a3, long a4) {
    return raw_syscall6(number, a0, a1, a2, a3, a4, 0);
}

static long raw_syscall4(long number, long a0, long a1, long a2, long a3) {
    return raw_syscall6(number, a0, a1, a2, a3, 0, 0);
}

static long raw_syscall3(long number, long a0, long a1, long a2) {
    return raw_syscall6(number, a0, a1, a2, 0, 0, 0);
}

static long raw_syscall2(long number, long a0, long a1) {
    return raw_syscall6(number, a0, a1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long a0) {
    return raw_syscall6(number, a0, 0, 0, 0, 0, 0);
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text, (long)string_length(text));
}

static void print_number(long value) {
    char buffer[32];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    (void)raw_syscall3(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned long)position));
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

static int expect_nonnegative(const char *name, long actual) {
    if (actual >= 0) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int test_child_access(int target_fd, int nondumpable) {
    int32_t pipe_descriptors[2] = {-1, -1};
    int32_t status = 0;
    char ready = 0;
    long child;
    long pidfd;
    long duplicate;
    int failures = 0;

    failures += expect_result("pipe2",
        raw_syscall2(SYS_pipe2, (long)pipe_descriptors, 0), 0);
    if (failures) return failures;
    child = create_child();
    failures += expect_nonnegative("create_child", child);
    if (child < 0) return failures;
    if (child == 0) {
        (void)raw_syscall1(SYS_close, pipe_descriptors[0]);
        ready = (!nondumpable ||
                 raw_syscall5(SYS_prctl, PR_SET_DUMPABLE,
                              0, 0, 0, 0) == 0) ? 'R' : 'E';
        if (raw_syscall3(SYS_write, pipe_descriptors[1],
                         (long)&ready, 1) != 1)
            (void)raw_syscall1(SYS_exit, 2);
        for (;;) {}
    }

    (void)raw_syscall1(SYS_close, pipe_descriptors[1]);
    failures += expect_result("child_ready",
        raw_syscall3(SYS_read, pipe_descriptors[0], (long)&ready, 1), 1);
    failures += expect_result("child_setup", ready, 'R');
    pidfd = raw_syscall2(SYS_pidfd_open, child, 0);
    failures += expect_nonnegative("child_pidfd", pidfd);
    duplicate = pidfd < 0 ? pidfd :
        raw_syscall3(SYS_pidfd_getfd, pidfd, target_fd, 0);
    if (nondumpable)
        failures += expect_result("nondumpable_denied", duplicate, -EPERM);
    else
        failures += expect_nonnegative("child_getfd", duplicate);
    if (duplicate >= 0) (void)raw_syscall1(SYS_close, duplicate);
    if (pidfd >= 0) (void)raw_syscall1(SYS_close, pidfd);
    failures += expect_result("kill_child",
        raw_syscall2(SYS_kill, child, SIGKILL), 0);
    failures += expect_result("wait_child",
        raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
    (void)raw_syscall1(SYS_close, pipe_descriptors[0]);
    return failures;
}

static int run_tests(void) {
    static const char path[] = "/tmp/edgeos-pidfd-getfd-abi";
    static const char contents[] = "abcdef";
    char byte = 0;
    long descriptor;
    long pidfd;
    long duplicate;
    int failures = 0;

    descriptor = raw_syscall4(SYS_openat, AT_FDCWD, (long)path,
                              O_RDWR | O_CREAT | O_TRUNC, 0600);
    failures += expect_nonnegative("open_target", descriptor);
    if (descriptor < 0) return failures;
    failures += expect_result("unlink_target",
        raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)path, 0), 0);
    failures += expect_result("write_target",
        raw_syscall3(SYS_write, descriptor, (long)contents,
                     (long)(sizeof(contents) - 1)),
        (long)(sizeof(contents) - 1));
    failures += expect_result("seek_target",
        raw_syscall3(SYS_lseek, descriptor, 0, SEEK_SET), 0);

    pidfd = raw_syscall2(SYS_pidfd_open, raw_syscall6(SYS_getpid, 0, 0, 0,
                                                      0, 0, 0), 0);
    failures += expect_nonnegative("self_pidfd", pidfd);
    if (pidfd >= 0) {
        failures += expect_result("invalid_flags",
            raw_syscall3(SYS_pidfd_getfd, pidfd, descriptor, 1), -EINVAL);
        failures += expect_result("invalid_target_fd",
            raw_syscall3(SYS_pidfd_getfd, pidfd, -1, 0), -EBADF);
        duplicate = raw_syscall3(SYS_pidfd_getfd, pidfd, descriptor, 0);
        failures += expect_nonnegative("self_getfd", duplicate);
        if (duplicate >= 0) {
            failures += expect_result("cloexec",
                raw_syscall3(SYS_fcntl, duplicate, F_GETFD, 0), FD_CLOEXEC);
            failures += expect_result("read_duplicate",
                raw_syscall3(SYS_read, duplicate, (long)&byte, 1), 1);
            failures += expect_result("duplicate_byte", byte, 'a');
            failures += expect_result("read_shared_offset",
                raw_syscall3(SYS_read, descriptor, (long)&byte, 1), 1);
            failures += expect_result("shared_offset_byte", byte, 'b');
            (void)raw_syscall1(SYS_close, duplicate);
        }
        (void)raw_syscall1(SYS_close, pidfd);
    }
    failures += expect_result("invalid_pidfd",
        raw_syscall3(SYS_pidfd_getfd, -1, descriptor, 0), -EBADF);

    failures += expect_result("drop_gid",
        raw_syscall3(SYS_setresgid, 65534, 65534, 65534), 0);
    failures += expect_result("drop_uid",
        raw_syscall3(SYS_setresuid, 65534, 65534, 65534), 0);
    failures += expect_result("restore_dumpable",
        raw_syscall5(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0), 0);
    failures += test_child_access((int)descriptor, 0);
    failures += test_child_access((int)descriptor, 1);
    (void)raw_syscall1(SYS_close, descriptor);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_tests();
    if (!failures)
        print_text("PIDFD_GETFD_ABI_PROBE_PASS failures: 0\n");
    else {
        print_text("PIDFD_GETFD_ABI_PROBE_FAIL failures: ");
        print_number(failures);
        print_text("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
