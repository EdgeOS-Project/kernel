/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for getrusage(2) and times(2).
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_getrusage 98
#define SYS_times 100
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_getrusage 165
#define SYS_times 153
#else
#error "process_accounting_runtime_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22

#define RUSAGE_CHILDREN (-1)
#define RUSAGE_SELF 0
#define RUSAGE_THREAD 1

typedef struct linux_timeval64 {
    int64_t tv_sec;
    int64_t tv_usec;
} linux_timeval64_t;

typedef struct linux_rusage64 {
    linux_timeval64_t user_time;
    linux_timeval64_t system_time;
    int64_t counters[14];
} linux_rusage64_t;

typedef struct linux_tms64 {
    int64_t user_ticks;
    int64_t system_ticks;
    int64_t children_user_ticks;
    int64_t children_system_ticks;
} linux_tms64_t;

_Static_assert(sizeof(linux_rusage64_t) == 144,
               "Linux 64-bit rusage layout");
_Static_assert(sizeof(linux_tms64_t) == 32,
               "Linux 64-bit tms layout");

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    long result;
#if defined(__x86_64__)
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall3(number, argument0, argument1, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall3(number, argument0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text, (long)text_length(text));
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

static void bytes_fill(void *pointer, uint8_t value, uint64_t length) {
    uint8_t *bytes = (uint8_t *)pointer;
    for (uint64_t index = 0; index < length; ++index) bytes[index] = value;
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

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    putstr(name);
    putstr(": false\n");
    return 1;
}

static int timeval_valid(const linux_timeval64_t *value) {
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
           value->tv_usec < 1000000;
}

static int test_getrusage_selector(int selector, const char *name) {
    linux_rusage64_t usage;
    long result;

    bytes_fill(&usage, 0xa5u, sizeof(usage));
    result = raw_syscall2(SYS_getrusage, selector, (long)&usage);
    return expect_result(name, result, 0) +
           expect_true("getrusage_timeval_layout",
                       timeval_valid(&usage.user_time) &&
                       timeval_valid(&usage.system_time));
}

static int run_probe(void) {
    linux_tms64_t first;
    linux_tms64_t second;
    long first_elapsed;
    long second_elapsed;
    int failures = 0;

    failures += test_getrusage_selector(RUSAGE_SELF, "getrusage_self");
    failures += test_getrusage_selector(RUSAGE_THREAD, "getrusage_thread");
    failures += test_getrusage_selector(RUSAGE_CHILDREN,
                                        "getrusage_children");
    failures += expect_result("getrusage_invalid_selector",
        raw_syscall2(SYS_getrusage, 2, (long)&first), -EINVAL);
    failures += expect_result("getrusage_null_output",
        raw_syscall2(SYS_getrusage, RUSAGE_SELF, 0), -EFAULT);

    bytes_fill(&first, 0xa5u, sizeof(first));
    bytes_fill(&second, 0x5au, sizeof(second));
    first_elapsed = raw_syscall1(SYS_times, (long)&first);
    second_elapsed = raw_syscall1(SYS_times, (long)&second);
    failures += expect_true("times_elapsed_monotonic",
                            first_elapsed >= 0 &&
                            second_elapsed >= first_elapsed);
    failures += expect_true("times_fields_nonnegative",
        first.user_ticks >= 0 && first.system_ticks >= 0 &&
        first.children_user_ticks >= 0 &&
        first.children_system_ticks >= 0);

    putstr(failures ?
        "PROCESS_ACCOUNTING_RUNTIME_PROBE_FAIL failures: " :
        "PROCESS_ACCOUNTING_RUNTIME_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall1(SYS_exit, run_probe());
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
