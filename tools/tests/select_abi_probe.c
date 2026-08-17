/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding raw Linux select and pselect6 ABI probe.  It validates fd-set
 * copy rules, readiness, nested signal-mask arguments, timeout writeback, and
 * observable argument-error ordering without depending on libc wrappers.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_select 23
#define SYS_exit 60
#define SYS_pselect6 270
#define SYS_dup3 292
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_dup3 24
#define SYS_pipe2 59
#define SYS_pselect6 72
#define SYS_exit 93
#else
#error "select_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EFAULT 14
#define EINVAL 22

struct linux_timeval64 {
    int64_t seconds;
    int64_t microseconds;
};

struct linux_timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_pselect_sigset {
    uint64_t mask;
    uint64_t size;
};

_Static_assert(sizeof(struct linux_timeval64) == 16,
               "Linux timeval ABI size");
_Static_assert(sizeof(struct linux_timespec64) == 16,
               "Linux timespec ABI size");
_Static_assert(sizeof(struct linux_pselect_sigset) == 16,
               "Linux pselect signal argument ABI size");

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

static void fdset_zero(uint64_t *set) {
    for (unsigned int index = 0; index < 16; ++index) set[index] = 0;
}

static void fdset_set(uint64_t *set, unsigned int descriptor) {
    set[descriptor / 64u] |= 1ULL << (descriptor % 64u);
}

static int fdset_test(const uint64_t *set, unsigned int descriptor) {
    return (set[descriptor / 64u] & (1ULL << (descriptor % 64u))) != 0;
}

static long raw_pselect(long count, uint64_t *read_set,
                        uint64_t *write_set, uint64_t *except_set,
                        struct linux_timespec64 *timeout,
                        struct linux_pselect_sigset *signal_argument) {
    return raw_syscall6(SYS_pselect6, count, (long)read_set,
                        (long)write_set, (long)except_set, (long)timeout,
                        (long)signal_argument);
}

static int run_probe(void) {
    struct linux_timespec64 zero_timeout = {0, 0};
    struct linux_timespec64 invalid_timeout = {0, 1000000000};
    struct linux_timespec64 expiring_timeout = {0, 2000000};
    struct linux_pselect_sigset signal_argument;
    struct linux_timeval64 zero_timeval = {0, 0};
    struct linux_timeval64 normalized_timeval = {0, 1000000};
    struct linux_timeval64 invalid_timeval = {0, -1};
    struct linux_timeval64 expiring_timeval = {0, 2000};
    static uint64_t read_set[16];
    static uint64_t write_set[16];
    uint64_t signal_mask = 0;
    int descriptors[2] = {-1, -1};
    char byte = 'S';
    long result;
    int failures = 0;

    result = raw_pselect(0, (uint64_t *)1, (uint64_t *)1,
                         (uint64_t *)1, &zero_timeout, 0);
    failures += expect_result("pselect_ignored_sets_zero", result, 0);
    result = raw_pselect(-1, 0, 0, 0, &zero_timeout, 0);
    failures += expect_result("pselect_negative_count", result, -EINVAL);
    result = raw_pselect(0, 0, 0, 0, &invalid_timeout, 0);
    failures += expect_result("pselect_invalid_timeout", result, -EINVAL);

    signal_argument.mask = 0;
    signal_argument.size = 0;
    result = raw_pselect(0, 0, 0, 0, &zero_timeout, &signal_argument);
    failures += expect_result("pselect_null_mask_ignores_size", result, 0);
    signal_argument.mask = (uint64_t)&signal_mask;
    signal_argument.size = 16;
    result = raw_pselect(0, 0, 0, 0, &zero_timeout, &signal_argument);
    failures += expect_result("pselect_sigset_size", result, -EINVAL);
    signal_argument.mask = 1;
    signal_argument.size = 8;
    result = raw_pselect(0, 0, 0, 0, &zero_timeout, &signal_argument);
    failures += expect_result("pselect_bad_sigmask", result, -EFAULT);

    result = raw_pselect(0, 0, 0, 0, (struct linux_timespec64 *)1,
                         (struct linux_pselect_sigset *)1);
    failures += expect_result("pselect_bad_timeout_and_signal_argument",
                              result, -EFAULT);
    result = raw_pselect(0, 0, 0, 0, &invalid_timeout,
                         (struct linux_pselect_sigset *)1);
    failures += expect_result("pselect_signal_argument_precedes_timeout",
                              result, -EFAULT);
    signal_argument.mask = 1;
    signal_argument.size = 8;
    result = raw_pselect(0, 0, 0, 0, &invalid_timeout,
                         &signal_argument);
    failures += expect_result("pselect_timeout_precedes_sigmask_copy",
                              result, -EINVAL);
    signal_argument.mask = (uint64_t)&signal_mask;
    signal_argument.size = 16;
    result = raw_pselect(0, 0, 0, 0, &invalid_timeout,
                         &signal_argument);
    failures += expect_result("pselect_sigset_size_precedes_timeout",
                              result, -EINVAL);

    fdset_zero(read_set);
    result = raw_pselect(1024, read_set, 0, 0, &zero_timeout, 0);
    failures += expect_result("pselect_1024_descriptors", result, 0);
    fdset_zero(read_set);
    fdset_set(read_set, 100);
    result = raw_pselect(101, read_set, 0, 0, &zero_timeout, 0);
    /*
     * Linux scans only the allocated fdtable. A process inherited from a
     * manager that previously used descriptor 100 observes EBADF here, while
     * a fresh 64-entry table ignores the bit. Both paths preserve the input
     * set because either the descriptor is outside the table or the syscall
     * fails before copying results.
     */
    if (result != 0 && result != -EBADF)
        failures += expect_result("pselect_high_fdtable_state", result, 0);
    failures += expect_result("pselect_preserves_high_fd_on_no_result",
                              fdset_test(read_set, 100), 1);
    result = raw_syscall3(SYS_dup3, 1, 100, 0);
    failures += expect_result("dup3_expands_fdtable", result, 100);
    if (result == 100) {
        result = raw_syscall1(SYS_close, 100);
        failures += expect_result("close_expanded_fd", result, 0);
        fdset_zero(read_set);
        fdset_set(read_set, 100);
        result = raw_pselect(101, read_set, 0, 0, &zero_timeout, 0);
        failures += expect_result("pselect_closed_allocated_fd",
                                  result, -EBADF);
        failures += expect_result("pselect_error_preserves_fdset",
                                  fdset_test(read_set, 100), 1);
    }
    result = raw_syscall2(SYS_pipe2, (long)descriptors, 0);
    failures += expect_result("pipe2", result, 0);
    if (result == 0) {
        fdset_zero(read_set);
        fdset_set(read_set, (unsigned int)descriptors[0]);
        result = raw_pselect(descriptors[0] + 1, read_set, 0, 0,
                             &zero_timeout, 0);
        failures += expect_result("pipe_empty", result, 0);
        failures += expect_result("pipe_empty_set",
                                  fdset_test(read_set, descriptors[0]), 0);
        result = raw_syscall3(SYS_write, descriptors[1], (long)&byte, 1);
        failures += expect_result("pipe_write", result, 1);
        fdset_zero(read_set);
        fdset_set(read_set, (unsigned int)descriptors[0]);
        result = raw_pselect(descriptors[0] + 1, read_set, 0, 0,
                             &zero_timeout, 0);
        failures += expect_result("pipe_ready", result, 1);
        failures += expect_result("pipe_ready_set",
                                  fdset_test(read_set, descriptors[0]), 1);
        result = raw_syscall3(SYS_read, descriptors[0], (long)&byte, 1);
        failures += expect_result("pipe_read", result, 1);
        result = raw_syscall1(SYS_close, descriptors[0]);
        failures += expect_result("pipe_read_close", result, 0);
        fdset_zero(read_set);
        fdset_set(read_set, (unsigned int)descriptors[0]);
        result = raw_pselect(descriptors[0] + 1, read_set, 0, 0,
                             &zero_timeout, 0);
        failures += expect_result("pselect_closed_descriptor", result,
                                  -EBADF);
        descriptors[0] = -1;
    }

    result = raw_pselect(0, 0, 0, 0, &expiring_timeout, 0);
    failures += expect_result("pselect_expiring_timeout", result, 0);
    failures += expect_result("pselect_timeout_after_seconds",
                              expiring_timeout.seconds, 0);
    failures += expect_result("pselect_timeout_after_nanoseconds",
                              expiring_timeout.nanoseconds, 0);

#if defined(__x86_64__)
    result = raw_syscall6(SYS_select, 0, 1, 1, 1,
                          (long)&zero_timeval, 0);
    failures += expect_result("select_ignored_sets_zero", result, 0);
    result = raw_syscall6(SYS_select, -1, 0, 0, 0,
                          (long)&zero_timeval, 0);
    failures += expect_result("select_negative_count", result, -EINVAL);
    result = raw_syscall6(SYS_select, 0, 0, 0, 0,
                          (long)&invalid_timeval, 0);
    failures += expect_result("select_invalid_timeout", result, -EINVAL);
    result = raw_syscall6(SYS_select, 0, 0, 0, 0,
                          (long)&normalized_timeval, 0);
    failures += expect_result("select_normalized_timeout", result, 0);
    failures += expect_result("select_normalized_timeout_seconds",
                              normalized_timeval.seconds, 0);
    failures += expect_result("select_normalized_timeout_microseconds",
                              normalized_timeval.microseconds, 0);
    result = raw_syscall6(SYS_select, 0, 0, 0, 0,
                          (long)&expiring_timeval, 0);
    failures += expect_result("select_expiring_timeout", result, 0);
    failures += expect_result("select_timeout_after_seconds",
                              expiring_timeval.seconds, 0);
    failures += expect_result("select_timeout_after_microseconds",
                              expiring_timeval.microseconds, 0);
#endif

    if (descriptors[0] >= 0)
        (void)raw_syscall1(SYS_close, descriptors[0]);
    if (descriptors[1] >= 0)
        (void)raw_syscall1(SYS_close, descriptors[1]);
    putstr("SELECT_ABI_PROBE_");
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
