/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS interval-timer Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_nanosleep 35
#define SYS_getitimer 36
#define SYS_setitimer 38
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_getitimer 102
#define SYS_setitimer 103
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mprotect 226
#else
#error "itimer_abi_probe requires a Linux 64-bit architecture"
#endif

#define ITIMER_REAL 0
#define EFAULT 14
#define EINVAL 22

struct linux_timeval {
    int64_t seconds;
    int64_t microseconds;
};

struct linux_itimerval {
    struct linux_timeval interval;
    struct linux_timeval value;
};

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

static long get_timer(long which, struct linux_itimerval *value) {
    return raw_syscall6(SYS_getitimer, which, (long)value, 0, 0, 0, 0);
}

static long set_timer(long which, const struct linux_itimerval *value,
                      struct linux_itimerval *previous) {
    return raw_syscall6(SYS_setitimer, which, (long)value, (long)previous,
                        0, 0, 0);
}

static uint64_t timeval_microseconds(const struct linux_timeval *value) {
    return (uint64_t)value->seconds * 1000000u +
           (uint64_t)value->microseconds;
}

static int timer_is_zero(const struct linux_itimerval *value) {
    return value->interval.seconds == 0 &&
           value->interval.microseconds == 0 &&
           value->value.seconds == 0 && value->value.microseconds == 0;
}

static struct linux_itimerval zero_timer;
static struct linux_itimerval active_timer = {
    {0, 200000},
    {0, 500000},
};
static struct linux_itimerval fault_timer = {
    {0, 0},
    {0, 400000},
};
static struct linux_itimerval invalid_timer = {
    {0, 1000000},
    {0, 0},
};
static struct linux_itimerval observed;
static struct linux_itimerval previous;
static struct linux_itimerval later;
static const struct linux_timespec delay = {0, 20000000};

static int run_tests(void) {
    uint64_t first_remaining;
    uint64_t later_remaining;
    int failures = 0;

    failures += expect_result("initial disarm",
                              set_timer(ITIMER_REAL, &zero_timer, 0), 0);
    failures += expect_result("get initial",
                              get_timer(ITIMER_REAL, &observed), 0);
    failures += expect_true("initial state zero", timer_is_zero(&observed));
    failures += expect_result("get null output",
                              get_timer(ITIMER_REAL, 0), -EFAULT);
    failures += expect_result("get invalid selector",
                              get_timer(3, &observed), -EINVAL);
    failures += expect_result("invalid selector before get pointer",
                              get_timer(3, 0), -EINVAL);
    failures += expect_result("set invalid selector",
                              set_timer(3, &zero_timer, 0), -EINVAL);
    failures += expect_result("invalid selector before set pointer",
                              set_timer(3,
                                        (const struct linux_itimerval *)1, 0),
                              -EFAULT);
    failures += expect_result("set bad input",
                              set_timer(ITIMER_REAL,
                                        (const struct linux_itimerval *)1, 0),
                              -EFAULT);
    failures += expect_result("set invalid timeval",
                              set_timer(ITIMER_REAL, &invalid_timer, 0),
                              -EINVAL);

    failures += expect_result("arm timer",
                              set_timer(ITIMER_REAL, &active_timer,
                                        &previous), 0);
    failures += expect_true("arm previous zero", timer_is_zero(&previous));
    failures += expect_result("get armed timer",
                              get_timer(ITIMER_REAL, &observed), 0);
    first_remaining = timeval_microseconds(&observed.value);
    failures += expect_true("armed interval preserved",
        timeval_microseconds(&observed.interval) == 200000u);
    failures += expect_true("armed remaining bounded",
        first_remaining > 0 && first_remaining <= 500000u);

    (void)raw_syscall6(SYS_nanosleep, (long)&delay, 0, 0, 0, 0, 0);
    failures += expect_result("get later timer",
                              get_timer(ITIMER_REAL, &later), 0);
    later_remaining = timeval_microseconds(&later.value);
    failures += expect_true("remaining decreases",
        later_remaining > 0 && later_remaining < first_remaining);

    failures += expect_result("null replacement disarms",
                              set_timer(ITIMER_REAL, 0, &previous), 0);
    failures += expect_true("null replacement reports old timer",
        timeval_microseconds(&previous.interval) == 200000u &&
        timeval_microseconds(&previous.value) > 0);
    failures += expect_result("get disarmed timer",
                              get_timer(ITIMER_REAL, &observed), 0);
    failures += expect_true("null replacement state zero",
                            timer_is_zero(&observed));

    failures += expect_result("faulted old output",
        set_timer(ITIMER_REAL, &fault_timer,
                  (struct linux_itimerval *)1), -EFAULT);
    failures += expect_result("get after old output fault",
                              get_timer(ITIMER_REAL, &observed), 0);
    failures += expect_true("timer changed before old output fault",
        timeval_microseconds(&observed.value) > 0 &&
        timeval_microseconds(&observed.value) <= 400000u);
    failures += expect_result("final disarm",
                              set_timer(ITIMER_REAL, &zero_timer, 0), 0);

    if (!failures) print_text("ITIMER_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
