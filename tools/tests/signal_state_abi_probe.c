/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for signal actions, masks, and pending state.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_getpid 39
#define SYS_kill 62
#define SYS_getuid 102
#define SYS_rt_sigpending 127
#define SYS_rt_sigtimedwait 128
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_kill 129
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigpending 136
#define SYS_rt_sigtimedwait 137
#define SYS_getpid 172
#define SYS_getuid 174
#else
#error "signal_state_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22
#define SIGHUP 1
#define SIGKILL 9
#define SIGSTOP 19
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define SI_USER 0

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
    int32_t signo;
    int32_t error;
    int32_t code;
    uint32_t padding;
    int32_t pid;
    uint32_t uid;
    uint8_t rest[104];
};

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

static int test_signal_state(void) {
    const uint64_t hup_bit = UINT64_C(1) << (SIGHUP - 1);
    const uint64_t kill_bit = UINT64_C(1) << (SIGKILL - 1);
    const uint64_t stop_bit = UINT64_C(1) << (SIGSTOP - 1);
    struct linux_signal_action old_action;
    struct linux_signal_action action;
    struct linux_signal_action observed;
    struct linux_timespec timeout = {1, 0};
    struct linux_siginfo information;
    uint64_t old_mask = 0;
    uint64_t requested_mask = hup_bit | kill_bit | stop_bit;
    uint64_t observed_mask = 0;
    uint64_t pending = 0;
    long pid = raw_syscall1(SYS_getpid, 0);
    long uid = raw_syscall1(SYS_getuid, 0);
    int failures = 0;

    failures += expect_result("sigaction_get_old",
        raw_syscall4(SYS_rt_sigaction, SIGHUP, 0, (long)&old_action, 8), 0);
    action.handler = UINT64_C(0x12345000);
    action.flags = 0;
    action.restorer = 0;
    action.mask = requested_mask;
    failures += expect_result("sigaction_reject_sigkill",
        raw_syscall4(SYS_rt_sigaction, SIGKILL, (long)&action, 0, 8),
        -EINVAL);
    failures += expect_result("sigaction_set_hup",
        raw_syscall4(SYS_rt_sigaction, SIGHUP, (long)&action, 0, 8), 0);
    failures += expect_result("sigaction_get_hup",
        raw_syscall4(SYS_rt_sigaction, SIGHUP, 0, (long)&observed, 8), 0);
    failures += expect_result("sigaction_handler",
        (long)observed.handler, (long)action.handler);
    failures += expect_result("sigaction_mask",
        (long)observed.mask, (long)hup_bit);

    failures += expect_result("sigprocmask_get_old",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, 0,
                     (long)&old_mask, 8), 0);
    failures += expect_result("sigprocmask_block",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK,
                     (long)&requested_mask, 0, 8), 0);
    failures += expect_result("sigprocmask_query",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, 0,
                     (long)&observed_mask, 8), 0);
    failures += expect_result("sigprocmask_sanitized",
        (long)(observed_mask & requested_mask), (long)hup_bit);

    failures += expect_result("kill_hup",
        raw_syscall2(SYS_kill, pid, SIGHUP), 0);
    failures += expect_result("sigpending_hup",
        raw_syscall2(SYS_rt_sigpending, (long)&pending, 8), 0);
    failures += expect_result("sigpending_hup_bit",
        (long)(pending & hup_bit), (long)hup_bit);
    failures += expect_result("sigtimedwait_hup",
        raw_syscall4(SYS_rt_sigtimedwait, (long)&hup_bit,
                     (long)&information, (long)&timeout, 8), SIGHUP);
    failures += expect_result("sigtimedwait_signo", information.signo, SIGHUP);
    failures += expect_result("sigtimedwait_code", information.code, SI_USER);
    failures += expect_result("sigtimedwait_pid", information.pid, pid);
    failures += expect_result("sigtimedwait_uid", information.uid, uid);
    pending = UINT64_MAX;
    failures += expect_result("sigpending_after_wait",
        raw_syscall2(SYS_rt_sigpending, (long)&pending, 8), 0);
    failures += expect_result("sigpending_hup_cleared",
        (long)(pending & hup_bit), 0);

    failures += expect_result("sigprocmask_restore",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK,
                     (long)&old_mask, 0, 8), 0);
    failures += expect_result("sigaction_restore",
        raw_syscall4(SYS_rt_sigaction, SIGHUP,
                     (long)&old_action, 0, 8), 0);
    failures += expect_result("sigaction_bad_size",
        raw_syscall4(SYS_rt_sigaction, SIGHUP, 0, 0, 16), -EINVAL);
    failures += expect_result("sigprocmask_bad_size",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, 0, 0, 16), -EINVAL);
    failures += expect_result("sigpending_bad_size",
        raw_syscall2(SYS_rt_sigpending, (long)&pending, 16), -EINVAL);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = test_signal_state();
    if (!failures)
        putstr("SIGNAL_STATE_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNAL_STATE_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
