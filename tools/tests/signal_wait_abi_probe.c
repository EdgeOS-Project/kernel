/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for blocking signal waits and mask restoration.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_rt_sigtimedwait 128
#define SYS_rt_sigsuspend 130
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_kill 129
#define SYS_rt_sigsuspend 133
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigtimedwait 137
#define SYS_rt_sigreturn 139
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "signal_wait_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINTR 4
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define SIGUSR1 10
#define SIGUSR2 12
#define SIGCHLD 17
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#define SA_RESTORER UINT64_C(0x04000000)

struct linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_siginfo {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint32_t padding;
    int32_t sender_pid;
    uint32_t sender_uid;
    uint8_t payload[104];
};

static volatile uint64_t handled_usr2;

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(a0), "S"(a1), "d"(a2), "r"(r10),
          "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    result = x0;
#endif
    return result;
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

__attribute__((naked, noreturn)) static void signal_restorer(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("mov $15, %rax\n\tsyscall");
#else
    __asm__ __volatile__("mov x8, #139\n\tsvc #0");
#endif
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
static void handle_usr2(int signal) {
    if (signal == SIGUSR2) ++handled_usr2;
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

static void child_send_after_delay(long parent, int signal) {
    struct linux_timespec delay = {0, 50000000};
    (void)raw_syscall2(SYS_nanosleep, (long)&delay, 0);
    (void)raw_syscall2(SYS_kill, parent, signal);
    (void)raw_syscall1(SYS_exit, 0);
    for (;;) {}
}

static long spawn_signal_sender(long parent, int signal) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) child_send_after_delay(parent, signal);
    return child;
}

static int reap_sender(long child) {
    int status = -1;
    long result;
    if (child <= 0) return 1;
    result = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    return result == child && status == 0 ? 0 : 1;
}

static int test_signal_wait(void) {
    const uint64_t usr1_bit = UINT64_C(1) << (SIGUSR1 - 1);
    const uint64_t usr2_bit = UINT64_C(1) << (SIGUSR2 - 1);
    const uint64_t blocked = usr1_bit | usr2_bit;
    const uint64_t suspend_mask = usr1_bit;
    struct linux_signal_action old_action;
    struct linux_signal_action action;
    struct linux_timespec zero_timeout = {0, 0};
    struct linux_timespec wait_timeout = {2, 0};
    struct linux_timespec invalid_timeout = {0, 1000000000};
    struct linux_siginfo information;
    uint64_t old_mask = 0;
    uint64_t observed_mask = 0;
    long parent = raw_syscall1(SYS_getpid, 0);
    long child;
    int failures = 0;

    action.handler = (uint64_t)(uintptr_t)handle_usr2;
    action.flags = SA_RESTORER;
    action.restorer = (uint64_t)(uintptr_t)signal_restorer;
    action.mask = 0;
    failures += expect_result("install_usr2_handler",
        raw_syscall4(SYS_rt_sigaction, SIGUSR2, (long)&action,
                     (long)&old_action, 8), 0);
    failures += expect_result("block_wait_signals",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&blocked,
                     (long)&old_mask, 8), 0);

    failures += expect_result("timedwait_null_set",
        raw_syscall4(SYS_rt_sigtimedwait, 0, 0,
                     (long)&zero_timeout, 8), -EFAULT);
    failures += expect_result("timedwait_bad_size",
        raw_syscall4(SYS_rt_sigtimedwait, (long)&usr1_bit, 0,
                     (long)&zero_timeout, 16), -EINVAL);
    failures += expect_result("timedwait_invalid_timeout",
        raw_syscall4(SYS_rt_sigtimedwait, (long)&usr1_bit, 0,
                     (long)&invalid_timeout, 8), -EINVAL);
    failures += expect_result("timedwait_zero_timeout",
        raw_syscall4(SYS_rt_sigtimedwait, (long)&usr1_bit, 0,
                     (long)&zero_timeout, 8), -EAGAIN);

    child = spawn_signal_sender(parent, SIGUSR1);
    failures += expect_result("spawn_timedwait_sender", child > 0, 1);
    failures += expect_result("blocking_timedwait",
        raw_syscall4(SYS_rt_sigtimedwait, (long)&usr1_bit,
                     (long)&information, (long)&wait_timeout, 8), SIGUSR1);
    failures += expect_result("blocking_timedwait_signo",
                              information.signal_number, SIGUSR1);
    failures += reap_sender(child);

    child = spawn_signal_sender(parent, SIGUSR2);
    failures += expect_result("spawn_suspend_sender", child > 0, 1);
    failures += expect_result("sigsuspend_result",
        raw_syscall2(SYS_rt_sigsuspend, (long)&suspend_mask, 8), -EINTR);
    failures += expect_result("sigsuspend_handler", (long)handled_usr2, 1);
    failures += expect_result("query_restored_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, 0,
                     (long)&observed_mask, 8), 0);
    failures += expect_result("sigsuspend_restored_mask",
                              (long)(observed_mask & blocked), (long)blocked);
    failures += reap_sender(child);

    failures += expect_result("queue_immediate_suspend_signal",
        raw_syscall2(SYS_kill, parent, SIGUSR2), 0);
    failures += expect_result("immediate_sigsuspend_result",
        raw_syscall2(SYS_rt_sigsuspend, (long)&suspend_mask, 8), -EINTR);
    failures += expect_result("immediate_sigsuspend_handler",
                              (long)handled_usr2, 2);
    observed_mask = 0;
    failures += expect_result("query_immediate_restored_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, 0,
                     (long)&observed_mask, 8), 0);
    failures += expect_result("immediate_sigsuspend_restored_mask",
                              (long)(observed_mask & blocked), (long)blocked);

    failures += expect_result("unblock_interrupt_signal",
        raw_syscall4(SYS_rt_sigprocmask, SIG_UNBLOCK, (long)&usr2_bit,
                     0, 8), 0);
    child = spawn_signal_sender(parent, SIGUSR2);
    failures += expect_result("spawn_interrupt_sender", child > 0, 1);
    failures += expect_result("timedwait_interrupted",
        raw_syscall4(SYS_rt_sigtimedwait, (long)&usr1_bit, 0,
                     (long)&wait_timeout, 8), -EINTR);
    failures += expect_result("timedwait_interrupt_handler",
                              (long)handled_usr2, 3);
    failures += reap_sender(child);

    failures += expect_result("restore_signal_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask,
                     0, 8), 0);
    failures += expect_result("restore_usr2_handler",
        raw_syscall4(SYS_rt_sigaction, SIGUSR2, (long)&old_action,
                     0, 8), 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = test_signal_wait();
    if (!failures)
        putstr("SIGNAL_WAIT_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNAL_WAIT_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
