/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 64-bit time ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_time_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_SYS_close 3
#define X32_SYS_nanosleep 35
#define X32_SYS_gettimeofday 96
#define X32_SYS_times 100
#define X32_SYS_time 201
#define X32_SYS_clock_gettime 228
#define X32_SYS_clock_getres 229
#define X32_SYS_clock_nanosleep 230
#define X32_SYS_timerfd_create 283
#define X32_SYS_timerfd_settime 286
#define X32_SYS_timerfd_gettime 287
#define CLOCK_MONOTONIC 1
#define TFD_CLOEXEC 02000000

struct timeval64 {
    int64_t seconds;
    int64_t microseconds;
};

struct timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

struct itimerspec64 {
    struct timespec64 interval;
    struct timespec64 value;
};

struct tms64 {
    int64_t user;
    int64_t system;
    int64_t children_user;
    int64_t children_system;
};

static struct timeval64 wall_time;
static struct timespec64 monotonic_time;
static struct timespec64 resolution;
static struct timespec64 zero_sleep;
static struct itimerspec64 timerfd_value;
static struct tms64 process_times;
static int64_t stored_time;

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
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
}

static long x32_syscall6(long number, long a0, long a1, long a2,
                          long a3, long a4, long a5) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, a3, a4, a5);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static int expect_nonnegative(const char *name, long value) {
    if (value >= 0) return 0;
    return expect_result(name, value, 0);
}

START_ATTRIBUTES void _start(void) {
    long result;
    long descriptor;
    int failures = 0;

    failures += expect_result(
        "gettimeofday", x32_syscall6(
            X32_SYS_gettimeofday, (long)&wall_time, 0, 0, 0, 0, 0), 0);
    failures += expect_nonnegative("wall-seconds", wall_time.seconds);

    result = x32_syscall6(X32_SYS_time, (long)&stored_time, 0, 0, 0, 0, 0);
    failures += expect_nonnegative("time", result);
    failures += expect_result("time-store", stored_time, result);

    failures += expect_result(
        "clock-gettime", x32_syscall6(
            X32_SYS_clock_gettime, CLOCK_MONOTONIC,
            (long)&monotonic_time, 0, 0, 0, 0), 0);
    failures += expect_nonnegative("monotonic-seconds", monotonic_time.seconds);
    failures += expect_result(
        "clock-getres", x32_syscall6(
            X32_SYS_clock_getres, CLOCK_MONOTONIC,
            (long)&resolution, 0, 0, 0, 0), 0);
    failures += expect_nonnegative("resolution-nanoseconds",
                                   resolution.nanoseconds);
    failures += expect_result(
        "nanosleep", x32_syscall6(
            X32_SYS_nanosleep, (long)&zero_sleep, 0, 0, 0, 0, 0), 0);
    failures += expect_result(
        "clock-nanosleep", x32_syscall6(
            X32_SYS_clock_nanosleep, CLOCK_MONOTONIC, 0,
            (long)&zero_sleep, 0, 0, 0), 0);

    failures += expect_nonnegative(
        "times", x32_syscall6(
            X32_SYS_times, (long)&process_times, 0, 0, 0, 0, 0));

    descriptor = x32_syscall6(
        X32_SYS_timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC,
        0, 0, 0, 0);
    failures += expect_nonnegative("timerfd-create", descriptor);
    if (descriptor >= 0) {
        failures += expect_result(
            "timerfd-settime", x32_syscall6(
                X32_SYS_timerfd_settime, descriptor, 0,
                (long)&timerfd_value, 0, 0, 0), 0);
        failures += expect_result(
            "timerfd-gettime", x32_syscall6(
                X32_SYS_timerfd_gettime, descriptor,
                (long)&timerfd_value, 0, 0, 0, 0), 0);
        failures += expect_result(
            "timerfd-close", x32_syscall6(
                X32_SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    if (failures) {
        print_text("X32_TIME_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_TIME_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
