/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux syslog ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigreturn 15
#define SYS_setitimer 38
#define SYS_exit 60
#define SYS_syslog 103
#define SYS_setuid 105
#elif defined(__aarch64__)
#define ENTRY_ALIGNMENT
#define SYS_write 64
#define SYS_exit 93
#define SYS_setitimer 103
#define SYS_syslog 116
#define SYS_rt_sigaction 134
#define SYS_rt_sigreturn 139
#define SYS_setuid 146
#else
#error "syslog_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINTR 4
#define EPERM 1
#define EFAULT 14
#define EINVAL 22

#define SIGALRM 14
#define SA_RESTORER UINT64_C(0x04000000)

#define SYSLOG_CLOSE 0
#define SYSLOG_OPEN 1
#define SYSLOG_READ 2
#define SYSLOG_READ_ALL 3
#define SYSLOG_READ_CLEAR 4
#define SYSLOG_CLEAR 5
#define SYSLOG_CONSOLE_OFF 6
#define SYSLOG_CONSOLE_ON 7
#define SYSLOG_CONSOLE_LEVEL 8
#define SYSLOG_SIZE_UNREAD 9
#define SYSLOG_SIZE_BUFFER 10

struct linux_timeval {
    int64_t seconds;
    int64_t microseconds;
};

struct linux_itimerval {
    struct linux_timeval interval;
    struct linux_timeval value;
};

struct linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

static char log_buffer[65536];
#ifndef SYSLOG_ABI_NATIVE_SAFE
static volatile uint64_t signal_count;
#endif

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

#ifndef SYSLOG_ABI_NATIVE_SAFE
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
    if (signal_number == SIGALRM) ++signal_count;
}
#endif

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

static long syslog_raw(long action, void *buffer, long length) {
    return raw_syscall6(SYS_syslog, action, (long)buffer, length,
                        0, 0, 0);
}

static int test_common_commands(void) {
    long buffer_size;
    int failures = 0;
    failures += expect_result("close", syslog_raw(SYSLOG_CLOSE, 0, 0), 0);
    failures += expect_result("open", syslog_raw(SYSLOG_OPEN, 0, 0), 0);
    failures += expect_result("read all null zero",
        syslog_raw(SYSLOG_READ_ALL, 0, 0), -EINVAL);
    failures += expect_result("read all valid zero",
        syslog_raw(SYSLOG_READ_ALL, log_buffer, 0), 0);
    failures += expect_result("read all null one",
        syslog_raw(SYSLOG_READ_ALL, 0, 1), -EINVAL);
    failures += expect_result("read all negative length",
        syslog_raw(SYSLOG_READ_ALL, log_buffer, -1), -EINVAL);
    buffer_size = syslog_raw(SYSLOG_SIZE_BUFFER, 0, 0);
    failures += expect_true("positive log buffer size", buffer_size > 0);
    failures += expect_result("console level zero",
        syslog_raw(SYSLOG_CONSOLE_LEVEL, 0, 0), -EINVAL);
    failures += expect_result("console level nine",
        syslog_raw(SYSLOG_CONSOLE_LEVEL, 0, 9), -EINVAL);
    failures += expect_result("console level four",
        syslog_raw(SYSLOG_CONSOLE_LEVEL, 0, 4), 0);
    failures += expect_result("console off",
        syslog_raw(SYSLOG_CONSOLE_OFF, 0, 0), 0);
    failures += expect_result("console on",
        syslog_raw(SYSLOG_CONSOLE_ON, 0, 0), 0);
    failures += expect_result("restore console level",
        syslog_raw(SYSLOG_CONSOLE_LEVEL, 0, 7), 0);
    failures += expect_result("invalid command",
        syslog_raw(11, 0, 0), -EINVAL);
    return failures;
}

#ifndef SYSLOG_ABI_NATIVE_SAFE
static int test_guest_ring_and_wait(void) {
    struct linux_signal_action action;
    struct linux_signal_action previous_action;
    const struct linux_itimerval timer = {
        {0, 0}, {0, 20000}
    };
    long unread_before;
    long snapshot;
    long consumed;
    int failures = 0;

    snapshot = syslog_raw(SYSLOG_READ_ALL, log_buffer,
                          (long)sizeof(log_buffer));
    failures += expect_true("boot log snapshot available", snapshot > 0);
    failures += expect_result("bad snapshot pointer",
        syslog_raw(SYSLOG_READ_ALL, (void *)1,
                   (long)sizeof(log_buffer)), -EFAULT);
    unread_before = syslog_raw(SYSLOG_SIZE_UNREAD, 0, 0);
    failures += expect_true("unread boot log available", unread_before > 0);
    failures += expect_true("read clear returns data",
        syslog_raw(SYSLOG_READ_CLEAR, log_buffer,
                   (long)sizeof(log_buffer)) > 0);
    failures += expect_result("clear marker hides snapshot",
        syslog_raw(SYSLOG_READ_ALL, log_buffer,
                   (long)sizeof(log_buffer)), 0);
    failures += expect_true("clear preserves consuming stream",
        syslog_raw(SYSLOG_SIZE_UNREAD, 0, 0) > 0);

    consumed = syslog_raw(SYSLOG_READ, log_buffer,
                          (long)sizeof(log_buffer));
    failures += expect_true("consuming read returns data", consumed > 0);
    while (syslog_raw(SYSLOG_SIZE_UNREAD, 0, 0) > 0) {
        consumed = syslog_raw(SYSLOG_READ, log_buffer,
                              (long)sizeof(log_buffer));
        if (consumed <= 0) {
            failures += expect_true("drain consuming stream", 0);
            break;
        }
    }
    failures += expect_result("read null zero",
        syslog_raw(SYSLOG_READ, 0, 0), -EINVAL);
    failures += expect_result("read valid zero",
        syslog_raw(SYSLOG_READ, log_buffer, 0), 0);

    action.handler = (uint64_t)(uintptr_t)signal_handler;
    action.flags = SA_RESTORER;
    action.restorer = (uint64_t)(uintptr_t)signal_restorer;
    action.mask = 0;
    failures += expect_result("install alarm handler",
        raw_syscall6(SYS_rt_sigaction, SIGALRM, (long)&action,
                     (long)&previous_action, 8, 0, 0), 0);
    signal_count = 0;
    failures += expect_result("arm alarm",
        raw_syscall6(SYS_setitimer, 0, (long)&timer, 0, 0, 0, 0), 0);
    failures += expect_result("signal interrupts empty read",
        syslog_raw(SYSLOG_READ, log_buffer, 1), -EINTR);
    failures += expect_true("alarm handler ran", signal_count == 1);
    failures += expect_result("restore alarm handler",
        raw_syscall6(SYS_rt_sigaction, SIGALRM,
                     (long)&previous_action, 0, 8, 0, 0), 0);
    return failures;
}
#endif

static int test_unprivileged_denial(void) {
    int failures = 0;
    failures += expect_result("drop uid",
        raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0), 0);
    failures += expect_true("unprivileged buffer size visible",
        syslog_raw(SYSLOG_SIZE_BUFFER, 0, 0) > 0);
    failures += expect_result("unprivileged consuming read denied",
        syslog_raw(SYSLOG_READ, log_buffer, 1), -EPERM);
    return failures;
}

static int run_tests(void) {
    int failures = test_common_commands();
#ifndef SYSLOG_ABI_NATIVE_SAFE
    failures += test_guest_ring_and_wait();
#else
    failures += expect_true("native read all succeeds",
        syslog_raw(SYSLOG_READ_ALL, log_buffer,
                   (long)sizeof(log_buffer)) >= 0);
#endif
    failures += test_unprivileged_denial();
    if (!failures) print_text("SYSLOG_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) ENTRY_ALIGNMENT void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
