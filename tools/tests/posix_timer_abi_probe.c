/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS POSIX timer Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigreturn 15
#define SYS_nanosleep 35
#define SYS_exit 60
#define SYS_gettid 186
#define SYS_timer_create 222
#define SYS_timer_settime 223
#define SYS_timer_gettime 224
#define SYS_timer_getoverrun 225
#define SYS_timer_delete 226
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_timer_create 107
#define SYS_timer_gettime 108
#define SYS_timer_getoverrun 109
#define SYS_timer_settime 110
#define SYS_timer_delete 111
#define SYS_rt_sigaction 134
#define SYS_rt_sigreturn 139
#define SYS_gettid 178
#else
#error "posix_timer_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINTR 4
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define TIMER_ABSTIME 1

#define SIGUSR2 12
#define SIGEV_SIGNAL 0
#define SIGEV_NONE 1
#define SIGEV_THREAD 2
#define SIGEV_THREAD_ID 4
#define SA_RESTORER UINT64_C(0x04000000)

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_itimerspec {
    struct linux_timespec interval;
    struct linux_timespec value;
};

struct linux_sigevent {
    uint64_t value;
    int32_t signal_number;
    int32_t notify;
    union {
        int32_t thread_id;
        uint8_t padding[48];
    } fields;
};

struct linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

_Static_assert(sizeof(struct linux_sigevent) == 64,
               "Linux 64-bit sigevent layout");
_Static_assert(sizeof(struct linux_itimerspec) == 32,
               "Linux 64-bit itimerspec layout");

static volatile uint64_t signal_count;

void *memset(void *destination, int value, unsigned long length) {
    uint8_t *bytes = (uint8_t *)destination;
    for (unsigned long index = 0; index < length; ++index)
        bytes[index] = (uint8_t)value;
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

static long timer_create_raw(long clock_id,
                             const struct linux_sigevent *event,
                             int32_t *timer_id) {
    return raw_syscall6(SYS_timer_create, clock_id, (long)event,
                        (long)timer_id, 0, 0, 0);
}

static long timer_settime_raw(int32_t timer_id, long flags,
                              const struct linux_itimerspec *replacement,
                              struct linux_itimerspec *previous) {
    return raw_syscall6(SYS_timer_settime, timer_id, flags,
                        (long)replacement, (long)previous, 0, 0);
}

static long timer_gettime_raw(int32_t timer_id,
                              struct linux_itimerspec *current) {
    return raw_syscall6(SYS_timer_gettime, timer_id, (long)current,
                        0, 0, 0, 0);
}

static long timer_getoverrun_raw(int32_t timer_id) {
    return raw_syscall6(SYS_timer_getoverrun, timer_id, 0, 0, 0, 0, 0);
}

static long timer_delete_raw(int32_t timer_id) {
    return raw_syscall6(SYS_timer_delete, timer_id, 0, 0, 0, 0, 0);
}

static uint64_t timespec_microseconds(const struct linux_timespec *value) {
    return (uint64_t)value->seconds * 1000000u +
           (uint64_t)value->nanoseconds / 1000u;
}

static int itimerspec_zero(const struct linux_itimerspec *value) {
    return value->interval.seconds == 0 &&
           value->interval.nanoseconds == 0 &&
           value->value.seconds == 0 && value->value.nanoseconds == 0;
}

static void sleep_milliseconds(uint64_t milliseconds) {
    struct linux_timespec delay;
    delay.seconds = (int64_t)(milliseconds / 1000u);
    delay.nanoseconds = (int64_t)((milliseconds % 1000u) * 1000000u);
    (void)raw_syscall6(SYS_nanosleep, (long)&delay, 0, 0, 0, 0, 0);
}

static const struct linux_itimerspec zero_timer = {
    {0, 0}, {0, 0}
};
static const struct linux_itimerspec one_shot_timer = {
    {0, 0}, {0, 50000000}
};
static const struct linux_itimerspec signal_timer = {
    {0, 0}, {0, 20000000}
};
static const struct linux_itimerspec periodic_timer = {
    {0, 30000000}, {0, 20000000}
};
static const struct linux_itimerspec invalid_timer = {
    {0, 1000000000}, {0, 0}
};

static int test_none_timer(void) {
    struct linux_sigevent event = {0};
    struct linux_itimerspec current;
    struct linux_itimerspec previous;
    int32_t timer_id = -1;
    uint64_t remaining;
    int failures = 0;

    event.notify = SIGEV_NONE;
    failures += expect_result("create invalid clock",
        timer_create_raw(123, &event, &timer_id), -EINVAL);
    failures += expect_result("invalid clock precedes id fault",
        timer_create_raw(123, &event, 0), -EINVAL);
    failures += expect_result("create null id",
        timer_create_raw(CLOCK_MONOTONIC, &event, 0), -EFAULT);
    failures += expect_result("create none timer",
        timer_create_raw(CLOCK_MONOTONIC, &event, &timer_id), 0);
    failures += expect_true("created timer id", timer_id >= 0);
    failures += expect_result("get initial timer",
        timer_gettime_raw(timer_id, &current), 0);
    failures += expect_true("initial timer zero", itimerspec_zero(&current));
    failures += expect_result("get null output",
        timer_gettime_raw(timer_id, 0), -EFAULT);
    failures += expect_result("get invalid id",
        timer_gettime_raw(-1, &current), -EINVAL);
    failures += expect_result("initial overrun",
        timer_getoverrun_raw(timer_id), 0);
    failures += expect_result("set invalid flags",
        timer_settime_raw(timer_id, 2, &zero_timer, 0), 0);
    failures += expect_result("set null replacement",
        timer_settime_raw(timer_id, 0, 0, 0), -EINVAL);
    failures += expect_result("set invalid timespec",
        timer_settime_raw(timer_id, 0, &invalid_timer, 0), -EINVAL);

    failures += expect_result("arm one shot",
        timer_settime_raw(timer_id, 0, &one_shot_timer, &previous), 0);
    failures += expect_true("arm old timer zero",
                            itimerspec_zero(&previous));
    failures += expect_result("get armed timer",
        timer_gettime_raw(timer_id, &current), 0);
    remaining = timespec_microseconds(&current.value);
    failures += expect_true("one shot remaining bounded",
        remaining > 0 && remaining <= 50000u);
    sleep_milliseconds(60);
    failures += expect_result("get expired timer",
        timer_gettime_raw(timer_id, &current), 0);
    failures += expect_true("one shot expires", itimerspec_zero(&current));

    failures += expect_result("arm periodic timer",
        timer_settime_raw(timer_id, 0, &periodic_timer, 0), 0);
    sleep_milliseconds(25);
    failures += expect_result("get periodic timer",
        timer_gettime_raw(timer_id, &current), 0);
    failures += expect_true("periodic interval preserved",
        timespec_microseconds(&current.interval) == 30000u);
    remaining = timespec_microseconds(&current.value);
    failures += expect_true("periodic timer rearmed",
        remaining > 0 && remaining <= 30000u);

    failures += expect_result("disarm periodic timer",
        timer_settime_raw(timer_id, 0, &zero_timer, &previous), 0);
    failures += expect_true("disarm reports interval",
        timespec_microseconds(&previous.interval) == 30000u);
    failures += expect_result("fault old output after apply",
        timer_settime_raw(timer_id, 0, &one_shot_timer,
                          (struct linux_itimerspec *)1), -EFAULT);
    failures += expect_result("get after old output fault",
        timer_gettime_raw(timer_id, &current), 0);
    failures += expect_true("old output fault keeps new timer",
        timespec_microseconds(&current.value) > 0);

    failures += expect_result("delete timer", timer_delete_raw(timer_id), 0);
    failures += expect_result("get deleted timer",
        timer_gettime_raw(timer_id, &current), -EINVAL);
    failures += expect_result("delete invalid timer",
        timer_delete_raw(timer_id), -EINVAL);
    return failures;
}

static int test_signal_timer(void) {
    struct linux_signal_action action;
    struct linux_signal_action old_action;
    struct linux_sigevent event = {0};
    struct linux_timespec remaining;
    const struct linux_timespec long_sleep = {0, 200000000};
    int32_t timer_id = -1;
    long thread_id;
    int failures = 0;

    action.handler = (uint64_t)(uintptr_t)signal_handler;
    action.flags = SA_RESTORER;
    action.restorer = (uint64_t)(uintptr_t)signal_restorer;
    action.mask = 0;
    failures += expect_result("install timer signal handler",
        raw_syscall6(SYS_rt_sigaction, SIGUSR2, (long)&action,
                     (long)&old_action, 8, 0, 0), 0);

    event.notify = SIGEV_THREAD;
    event.signal_number = SIGUSR2;
    failures += expect_result("create raw sigev thread",
        timer_create_raw(CLOCK_MONOTONIC, &event, &timer_id), 0);
    signal_count = 0;
    failures += expect_result("arm raw sigev thread",
        timer_settime_raw(timer_id, 0, &signal_timer, 0), 0);
    sleep_milliseconds(30);
    failures += expect_true("raw sigev thread delivers signal",
                            signal_count == 1);
    failures += expect_result("delete raw sigev thread",
        timer_delete_raw(timer_id), 0);
    event.notify = SIGEV_THREAD_ID;
    event.fields.thread_id = -1;
    failures += expect_result("reject invalid thread target",
        timer_create_raw(CLOCK_MONOTONIC, &event, &timer_id), -EINVAL);
    thread_id = raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    event.fields.thread_id = (int32_t)thread_id;
    failures += expect_result("create thread timer",
        timer_create_raw(CLOCK_MONOTONIC, &event, &timer_id), 0);
    signal_count = 0;
    failures += expect_result("arm signal timer",
        timer_settime_raw(timer_id, 0, &signal_timer, 0), 0);
    failures += expect_result("timer interrupts sleep",
        raw_syscall6(SYS_nanosleep, (long)&long_sleep, (long)&remaining,
                     0, 0, 0, 0), -EINTR);
    failures += expect_true("timer signal delivered", signal_count == 1);
    failures += expect_true("interrupted sleep remainder",
        timespec_microseconds(&remaining) > 0 &&
        timespec_microseconds(&remaining) < 200000u);
    failures += expect_result("signal timer overrun",
        timer_getoverrun_raw(timer_id), 0);
    failures += expect_result("delete signal timer",
        timer_delete_raw(timer_id), 0);
    failures += expect_result("restore timer signal handler",
        raw_syscall6(SYS_rt_sigaction, SIGUSR2, (long)&old_action,
                     0, 8, 0, 0), 0);
    return failures;
}

static int seed_process_exit_cleanup(void) {
    struct linux_sigevent event = {0};
    int32_t timer_id = -1;
    event.notify = SIGEV_NONE;
    /* Repeated probe execution verifies that exit releases this live timer. */
    return expect_result("create exit cleanup timer",
        timer_create_raw(CLOCK_MONOTONIC, &event, &timer_id), 0);
}

static int run_tests(void) {
    int failures = test_none_timer();
    failures += test_signal_timer();
    failures += seed_process_exit_cleanup();
    if (!failures) print_text("POSIX_TIMER_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
