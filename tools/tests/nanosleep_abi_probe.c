/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux sleep syscall ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigreturn 15
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_clock_gettime 228
#define SYS_clock_nanosleep 230
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_clock_gettime 113
#define SYS_clock_nanosleep 115
#define SYS_kill 129
#define SYS_rt_sigaction 134
#define SYS_rt_sigreturn 139
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "nanosleep_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINTR 4
#define EFAULT 14
#define EINVAL 22
#define EOPNOTSUPP 95

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_BOOTTIME 7
#define TIMER_ABSTIME 1
#define SIGUSR2 12
#define SIGCHLD 17
#define SA_RESTORER UINT64_C(0x04000000)

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

static volatile uint64_t signal_count;

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

__attribute__((naked, noreturn)) static void signal_restorer(void) {
#if defined(__x86_64__)
    __asm__ volatile("mov $15, %rax\n\tsyscall");
#else
    __asm__ volatile("mov x8, #139\n\tsvc #0");
#endif
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
static void signal_handler(int signal_number) {
    if (signal_number == SIGUSR2) ++signal_count;
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

static long get_time(long clock_id, struct linux_timespec *value) {
    return raw_syscall6(SYS_clock_gettime, clock_id, (long)value,
                        0, 0, 0, 0);
}

static long sleep_relative(const struct linux_timespec *request,
                           struct linux_timespec *remaining) {
    return raw_syscall6(SYS_nanosleep, (long)request, (long)remaining,
                        0, 0, 0, 0);
}

static long sleep_clock(long clock_id, long flags,
                        const struct linux_timespec *request,
                        struct linux_timespec *remaining) {
    return raw_syscall6(SYS_clock_nanosleep, clock_id, flags,
                        (long)request, (long)remaining, 0, 0);
}

static void signal_sender(long parent) {
    const struct linux_timespec delay = {0, 20000000};
    (void)sleep_relative(&delay, 0);
    (void)raw_syscall6(SYS_kill, parent, SIGUSR2, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) {}
}

static long spawn_signal_sender(long parent) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) signal_sender(parent);
    return child;
}

static int reap_signal_sender(long child) {
    int status = -1;
    long result;
    if (child <= 0) return 1;
    result = raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0);
    return result == child && status == 0 ? 0 : 1;
}

static uint64_t timespec_nanoseconds(const struct linux_timespec *value) {
    return (uint64_t)value->seconds * UINT64_C(1000000000) +
           (uint64_t)value->nanoseconds;
}

static const struct linux_timespec zero_time = {0, 0};
static const struct linux_timespec one_nanosecond = {0, 1};
static const struct linux_timespec two_milliseconds = {0, 2000000};
static const struct linux_timespec invalid_nanoseconds = {0, 1000000000};
static const struct linux_timespec negative_seconds = {-1, 0};
static const struct linux_timespec negative_nanoseconds = {0, -1};

static int run_tests(void) {
    struct linux_signal_action action;
    struct linux_signal_action old_action;
    struct linux_timespec before;
    struct linux_timespec after;
    struct linux_timespec absolute;
    struct linux_timespec remainder = {123, 456};
    uint64_t elapsed;
    long parent;
    long child;
    int failures = 0;

    failures += expect_result("nanosleep null request",
        sleep_relative(0, 0), -EFAULT);
    failures += expect_result("nanosleep invalid nanoseconds",
        sleep_relative(&invalid_nanoseconds, 0), -EINVAL);
    failures += expect_result("nanosleep negative seconds",
        sleep_relative(&negative_seconds, 0), -EINVAL);
    failures += expect_result("nanosleep negative nanoseconds",
        sleep_relative(&negative_nanoseconds, 0), -EINVAL);
    failures += expect_result("nanosleep zero",
        sleep_relative(&zero_time, &remainder), 0);
    failures += expect_true("nanosleep zero leaves remainder",
        remainder.seconds == 123 && remainder.nanoseconds == 456);

    failures += expect_result("clock nanosleep invalid flags",
        sleep_clock(CLOCK_MONOTONIC, 2, &zero_time, 0), 0);
    failures += expect_result("clock nanosleep invalid clock",
        sleep_clock(123, 0, &zero_time, 0), -EINVAL);
    failures += expect_result("clock nanosleep raw unsupported",
        sleep_clock(CLOCK_MONOTONIC_RAW, 0, &zero_time, 0),
        -EOPNOTSUPP);
    failures += expect_result("clock nanosleep coarse unsupported",
        sleep_clock(CLOCK_REALTIME_COARSE, 0, &zero_time, 0),
        -EOPNOTSUPP);
    failures += expect_result("clock nanosleep null request",
        sleep_clock(CLOCK_MONOTONIC, 0, 0, 0), -EFAULT);
    failures += expect_result("clock nanosleep boottime zero",
        sleep_clock(CLOCK_BOOTTIME, 0, &zero_time, 0), 0);

    failures += expect_result("clock get realtime",
        get_time(CLOCK_REALTIME, &absolute), 0);
    if (absolute.seconds > 0) --absolute.seconds;
    remainder.seconds = 321;
    remainder.nanoseconds = 654;
    failures += expect_result("clock absolute past",
        sleep_clock(CLOCK_REALTIME, TIMER_ABSTIME, &absolute,
                    &remainder), 0);
    failures += expect_true("clock absolute ignores remainder",
        remainder.seconds == 321 && remainder.nanoseconds == 654);
    failures += expect_result("clock absolute ignores bad remainder",
        sleep_clock(CLOCK_REALTIME, TIMER_ABSTIME, &absolute,
                    (struct linux_timespec *)1), 0);

    failures += expect_result("clock before tiny sleep",
        get_time(CLOCK_MONOTONIC, &before), 0);
    failures += expect_result("nanosleep one nanosecond",
        sleep_relative(&one_nanosecond, 0), 0);
    failures += expect_result("clock after tiny sleep",
        get_time(CLOCK_MONOTONIC, &after), 0);
    elapsed = timespec_nanoseconds(&after) - timespec_nanoseconds(&before);
    failures += expect_true("nanosleep advances monotonic time",
        elapsed > 0);

    failures += expect_result("clock before relative sleep",
        get_time(CLOCK_MONOTONIC, &before), 0);
    failures += expect_result("clock relative sleep",
        sleep_clock(CLOCK_MONOTONIC, 0, &two_milliseconds, 0), 0);
    failures += expect_result("clock after relative sleep",
        get_time(CLOCK_MONOTONIC, &after), 0);
    elapsed = timespec_nanoseconds(&after) - timespec_nanoseconds(&before);
    failures += expect_true("clock relative deadline honored",
        elapsed >= 2000000u);

    failures += expect_result("clock get monotonic absolute",
        get_time(CLOCK_MONOTONIC, &absolute), 0);
    absolute.nanoseconds += 2000000;
    if (absolute.nanoseconds >= 1000000000) {
        absolute.nanoseconds -= 1000000000;
        ++absolute.seconds;
    }
    failures += expect_result("clock before absolute sleep",
        get_time(CLOCK_MONOTONIC, &before), 0);
    failures += expect_result("clock absolute future",
        sleep_clock(CLOCK_MONOTONIC, TIMER_ABSTIME, &absolute,
                    (struct linux_timespec *)1), 0);
    failures += expect_result("clock after absolute sleep",
        get_time(CLOCK_MONOTONIC, &after), 0);
    failures += expect_true("clock absolute deadline honored",
        timespec_nanoseconds(&after) >= timespec_nanoseconds(&absolute));

    action.handler = (uint64_t)(uintptr_t)signal_handler;
    action.flags = SA_RESTORER;
    action.restorer = (uint64_t)(uintptr_t)signal_restorer;
    action.mask = 0;
    failures += expect_result("install signal handler",
        raw_syscall6(SYS_rt_sigaction, SIGUSR2, (long)&action,
                     (long)&old_action, 8, 0, 0), 0);
    parent = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);

    signal_count = 0;
    remainder.seconds = 123;
    remainder.nanoseconds = 456;
    child = spawn_signal_sender(parent);
    failures += expect_true("spawn relative signal sender", child > 0);
    failures += expect_result("relative sleep interrupted",
        sleep_relative(&(const struct linux_timespec){0, 200000000},
                       &remainder), -EINTR);
    failures += expect_true("relative signal delivered", signal_count == 1);
    elapsed = timespec_nanoseconds(&remainder);
    failures += expect_true("relative remainder written",
        elapsed > 0 && elapsed < 200000000u);
    failures += expect_true("reap relative signal sender",
        reap_signal_sender(child) == 0);

    signal_count = 0;
    child = spawn_signal_sender(parent);
    failures += expect_true("spawn fault signal sender", child > 0);
    failures += expect_result("interrupted remainder fault",
        sleep_relative(&(const struct linux_timespec){0, 200000000},
                       (struct linux_timespec *)1), -EFAULT);
    failures += expect_true("fault signal delivered", signal_count == 1);
    failures += expect_true("reap fault signal sender",
        reap_signal_sender(child) == 0);

    failures += expect_result("get interrupted absolute deadline",
        get_time(CLOCK_MONOTONIC, &absolute), 0);
    absolute.nanoseconds += 200000000;
    if (absolute.nanoseconds >= 1000000000) {
        absolute.nanoseconds -= 1000000000;
        ++absolute.seconds;
    }
    signal_count = 0;
    remainder.seconds = 321;
    remainder.nanoseconds = 654;
    child = spawn_signal_sender(parent);
    failures += expect_true("spawn absolute signal sender", child > 0);
    failures += expect_result("absolute sleep interrupted",
        sleep_clock(CLOCK_MONOTONIC, TIMER_ABSTIME, &absolute,
                    &remainder), -EINTR);
    failures += expect_true("absolute signal delivered", signal_count == 1);
    failures += expect_true("absolute interruption leaves remainder",
        remainder.seconds == 321 && remainder.nanoseconds == 654);
    failures += expect_true("reap absolute signal sender",
        reap_signal_sender(child) == 0);
    failures += expect_result("restore signal handler",
        raw_syscall6(SYS_rt_sigaction, SIGUSR2, (long)&old_action,
                     0, 8, 0, 0), 0);

    if (!failures) print_text("NANOSLEEP_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
