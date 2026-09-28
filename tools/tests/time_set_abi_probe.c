/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux wall-clock mutation ABI test. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_clock_gettime 228
#define SYS_clock_settime 227
#define SYS_exit 60
#define SYS_gettimeofday 96
#define SYS_settimeofday 164
#define SYS_write 1
#elif defined(__aarch64__)
#define SYS_clock_gettime 113
#define SYS_clock_settime 112
#define SYS_exit 93
#define SYS_gettimeofday 169
#define SYS_settimeofday 170
#define SYS_write 64
#else
#error "time_set_abi_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_timeval {
    int64_t seconds;
    int64_t microseconds;
};

struct linux_timezone {
    int32_t minutes_west;
    int32_t dst_time;
};

static long raw_syscall3(long number, long a0, long a1, long a2) {
#if defined(__x86_64__)
    long result;
    __asm__ volatile("syscall" : "=a"(result) :
                     "a"(number), "D"(a0), "S"(a1), "d"(a2) :
                     "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) :
                     "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text, (long)text_length(text));
}

static int expect(long actual, long expected) {
    return actual == expected ? 0 : 1;
}

static int run_probe(void) {
    struct linux_timeval before;
    struct linux_timespec realtime;
    struct linux_timespec invalid = {0, 1000000000};
    struct linux_timezone utc = {0, 0};
    int failures = 0;

    failures += expect(raw_syscall3(SYS_gettimeofday, (long)&before, 0, 0), 0);
    failures += expect(raw_syscall3(SYS_settimeofday, 0, (long)&utc, 0), 0);
    failures += expect(raw_syscall3(SYS_settimeofday, 1, 0, 0), -EFAULT);
    failures += expect(raw_syscall3(SYS_clock_gettime, CLOCK_REALTIME,
                                    (long)&realtime, 0), 0);
    failures += expect(raw_syscall3(SYS_clock_settime, CLOCK_MONOTONIC,
                                    (long)&realtime, 0), -EINVAL);
    failures += expect(raw_syscall3(SYS_clock_settime, CLOCK_REALTIME,
                                    (long)&invalid, 0), -EINVAL);
    failures += expect(raw_syscall3(SYS_clock_settime, CLOCK_REALTIME,
                                    (long)&realtime, 0), 0);
    failures += expect(raw_syscall3(SYS_settimeofday, (long)&before, 0, 0), 0);
    if (!failures) print_text("TIME_SET_ABI_PROBE_PASS failures=0\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall3(SYS_exit, run_probe(), 0, 0);
    for (;;) {}
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("andq $-16, %rsp\ncall probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
