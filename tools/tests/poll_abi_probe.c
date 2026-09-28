/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding raw Linux poll and ppoll ABI probe.  It intentionally avoids
 * libc so the same executable shape can run against native Linux and EdgeOS.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_poll 7
#define SYS_exit 60
#define SYS_ppoll 271
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_exit 93
#define SYS_ppoll 73
#else
#error "poll_abi_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22

#define POLLIN 0x0001
#define POLLNVAL 0x0020

struct linux_pollfd {
    int32_t fd;
    int16_t events;
    int16_t revents;
};

struct linux_timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

_Static_assert(sizeof(struct linux_pollfd) == 8,
               "Linux pollfd ABI size");
_Static_assert(sizeof(struct linux_timespec64) == 16,
               "Linux timespec ABI size");

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

static long raw_syscall5(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4) {
    return raw_syscall6(number, argument0, argument1, argument2, argument3,
                        argument4, 0);
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

static int run_probe(void) {
    static struct linux_pollfd many_pollfds[1024];
    struct linux_timespec64 zero_timeout = {0, 0};
    struct linux_timespec64 invalid_timeout = {0, 1000000000};
    struct linux_timespec64 expiring_timeout = {0, 2000000};
    struct linux_pollfd pollfd;
    uint64_t signal_mask = 0;
    int descriptors[2] = {-1, -1};
    char byte = 'P';
    long result;
    int failures = 0;

#if defined(__x86_64__)
    result = raw_syscall3(SYS_poll, 0, 0, 0);
    failures += expect_result("poll_null_zero", result, 0);
    result = raw_syscall3(SYS_poll, 1, 0, 0);
    failures += expect_result("poll_ignored_pointer_zero", result, 0);
    result = raw_syscall3(SYS_poll, 0, 1, 0);
    failures += expect_result("poll_null_one", result, -EFAULT);
#endif

    result = raw_syscall5(SYS_ppoll, 0, 0, (long)&zero_timeout, 0, 0);
    failures += expect_result("ppoll_null_zero", result, 0);
    result = raw_syscall5(SYS_ppoll, 1, 0, (long)&zero_timeout, 0, 0);
    failures += expect_result("ppoll_ignored_pointer_zero", result, 0);
    result = raw_syscall5(SYS_ppoll, 0, 1, (long)&zero_timeout, 0, 0);
    failures += expect_result("ppoll_null_one", result, -EFAULT);

    for (unsigned int index = 0;
         index < sizeof(many_pollfds) / sizeof(many_pollfds[0]); ++index) {
        many_pollfds[index].fd = -1;
        many_pollfds[index].events = POLLIN;
        many_pollfds[index].revents = POLLNVAL;
    }
    result = raw_syscall5(SYS_ppoll, (long)many_pollfds,
                          sizeof(many_pollfds) / sizeof(many_pollfds[0]),
                          (long)&zero_timeout, 0, 0);
    failures += expect_result("ppoll_1024_descriptors", result, 0);
    failures += expect_result("ppoll_1024_last_revents",
                              many_pollfds[1023].revents, 0);

    pollfd.fd = 123456;
    pollfd.events = POLLIN;
    pollfd.revents = 0;
    result = raw_syscall5(SYS_ppoll, (long)&pollfd, 1,
                          (long)&zero_timeout, 0, 0);
    failures += expect_result("ppoll_invalid_fd_count", result, 1);
    failures += expect_result("ppoll_invalid_fd_revents",
                              pollfd.revents, POLLNVAL);

    pollfd.fd = -1;
    pollfd.events = POLLIN;
    pollfd.revents = POLLNVAL;
    result = raw_syscall5(SYS_ppoll, (long)&pollfd, 1,
                          (long)&zero_timeout, 0, 0);
    failures += expect_result("ppoll_negative_fd_count", result, 0);
    failures += expect_result("ppoll_negative_fd_revents", pollfd.revents, 0);

    result = raw_syscall2(SYS_pipe2, (long)descriptors, 0);
    failures += expect_result("pipe2", result, 0);
    if (result == 0) {
        pollfd.fd = descriptors[0];
        pollfd.events = POLLIN;
        pollfd.revents = 0;
        result = raw_syscall5(SYS_ppoll, (long)&pollfd, 1,
                              (long)&zero_timeout, 0, 0);
        failures += expect_result("pipe_empty", result, 0);
        failures += expect_result("pipe_empty_revents", pollfd.revents, 0);
        result = raw_syscall3(SYS_write, descriptors[1], (long)&byte, 1);
        failures += expect_result("pipe_write", result, 1);
        result = raw_syscall5(SYS_ppoll, (long)&pollfd, 1,
                              (long)&zero_timeout, 0, 0);
        failures += expect_result("pipe_ready", result, 1);
        failures += expect_result("pipe_ready_revents",
                                  pollfd.revents & POLLIN, POLLIN);
        result = raw_syscall3(SYS_read, descriptors[0], (long)&byte, 1);
        failures += expect_result("pipe_read", result, 1);
    }

    result = raw_syscall5(SYS_ppoll, 0, 0,
                          (long)&invalid_timeout, 0, 0);
    failures += expect_result("ppoll_invalid_timeout", result, -EINVAL);
    result = raw_syscall5(SYS_ppoll, 0, 0,
                          (long)&zero_timeout, (long)&signal_mask, 16);
    failures += expect_result("ppoll_sigset_size", result, -EINVAL);
    result = raw_syscall5(SYS_ppoll, 0, 0,
                          (long)&zero_timeout, 1, 8);
    failures += expect_result("ppoll_bad_sigmask", result, -EFAULT);

    result = raw_syscall5(SYS_ppoll, 0, 0, 1,
                          (long)&signal_mask, 16);
    failures += expect_result("ppoll_timeout_precedes_sigset_size",
                              result, -EFAULT);
    result = raw_syscall5(SYS_ppoll, 0, 0,
                          (long)&invalid_timeout, 1, 8);
    failures += expect_result("ppoll_invalid_timeout_precedes_sigmask",
                              result, -EINVAL);

    result = raw_syscall5(SYS_ppoll, 0, 0,
                          (long)&expiring_timeout, 0, 0);
    failures += expect_result("ppoll_expiring_timeout", result, 0);
    failures += expect_result("ppoll_timeout_after_seconds",
                              expiring_timeout.seconds, 0);
    failures += expect_result("ppoll_timeout_after_nanoseconds",
                              expiring_timeout.nanoseconds, 0);

    if (descriptors[0] >= 0)
        (void)raw_syscall1(SYS_close, descriptors[0]);
    if (descriptors[1] >= 0)
        (void)raw_syscall1(SYS_close, descriptors[1]);
    putstr("POLL_ABI_PROBE_");
    putstr(failures ? "FAIL failures:" : "PASS failures:");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int result = run_probe();
    (void)raw_syscall1(SYS_exit, result);
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
