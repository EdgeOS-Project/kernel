/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for kill, tkill, and tgkill.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigtimedwait 128
#define SYS_getpid 39
#define SYS_getuid 102
#define SYS_getpgid 121
#define SYS_setpgid 109
#define SYS_gettid 186
#define SYS_kill 62
#define SYS_tkill 200
#define SYS_tgkill 234
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigtimedwait 137
#define SYS_getpid 172
#define SYS_getuid 174
#define SYS_getpgid 155
#define SYS_setpgid 154
#define SYS_gettid 178
#define SYS_kill 129
#define SYS_tkill 130
#define SYS_tgkill 131
#define SYS_exit 93
#else
#error "signal_targeting_abi_probe requires a Linux 64-bit architecture"
#endif

#define ESRCH 3
#define EINVAL 22
#define SIGUSR1 10
#define SIGUSR2 12
#define SIGRT_TEST 35
#define SIG_BLOCK 0
#define SI_USER 0
#define SI_TKILL (-6)

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

static int wait_for_signal(uint64_t mask, int signal, int code,
                           int pid, uint32_t uid) {
    struct linux_timespec timeout = {1, 0};
    struct linux_siginfo information;
    long result = raw_syscall4(
        SYS_rt_sigtimedwait, (long)&mask, (long)&information,
        (long)&timeout, sizeof(mask));
    int failures = 0;
    failures += expect_result("signal_wait_result", result, signal);
    if (result != signal) return failures;
    failures += expect_result("signal_wait_signo", information.signo, signal);
    failures += expect_result("signal_wait_code", information.code, code);
    failures += expect_result("signal_wait_pid", information.pid, pid);
    failures += expect_result("signal_wait_uid", information.uid, uid);
    return failures;
}

static int test_signal_targeting(void) {
    uint64_t blocked = (1ULL << (SIGUSR1 - 1)) |
                       (1ULL << (SIGUSR2 - 1)) |
                       (1ULL << (SIGRT_TEST - 1));
    long pid = raw_syscall1(SYS_getpid, 0);
    long tid = raw_syscall1(SYS_gettid, 0);
    long uid = raw_syscall1(SYS_getuid, 0);
    long pgrp;
    int failures = 0;

    failures += expect_result("setpgid_self",
        raw_syscall2(SYS_setpgid, 0, 0), 0);
    pgrp = raw_syscall1(SYS_getpgid, 0);
    failures += expect_result("sigprocmask_block",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&blocked, 0,
                     sizeof(blocked)), 0);
    failures += expect_result("kill_self_probe",
        raw_syscall2(SYS_kill, pid, 0), 0);
    failures += expect_result("kill_group_probe",
        raw_syscall2(SYS_kill, 0, 0), 0);
    failures += expect_result("kill_named_group_probe",
        raw_syscall2(SYS_kill, -pgrp, 0), 0);
    failures += expect_result("kill_missing",
        raw_syscall2(SYS_kill, 0x7fffffff, 0), -ESRCH);
    failures += expect_result("kill_minimum_pid",
        raw_syscall2(SYS_kill, INT32_MIN, 0), -ESRCH);
    failures += expect_result("kill_invalid_signal",
        raw_syscall2(SYS_kill, pid, 65), -EINVAL);
    failures += expect_result("tkill_invalid_tid",
        raw_syscall2(SYS_tkill, 0, 0), -EINVAL);
    failures += expect_result("tgkill_invalid_tgid",
        raw_syscall3(SYS_tgkill, 0, tid, 0), -EINVAL);
    failures += expect_result("tgkill_wrong_group",
        raw_syscall3(SYS_tgkill, pid + 1, tid, 0), -ESRCH);
    failures += expect_result("tkill_self_probe",
        raw_syscall2(SYS_tkill, tid, 0), 0);
    failures += expect_result("tgkill_self_probe",
        raw_syscall3(SYS_tgkill, pid, tid, 0), 0);

    failures += expect_result("kill_self_delivery",
        raw_syscall2(SYS_kill, pid, SIGUSR1), 0);
    failures += wait_for_signal(
        1ULL << (SIGUSR1 - 1), SIGUSR1, SI_USER, (int)pid, (uint32_t)uid);
    failures += expect_result("tkill_self_delivery",
        raw_syscall2(SYS_tkill, tid, SIGUSR2), 0);
    failures += wait_for_signal(
        1ULL << (SIGUSR2 - 1), SIGUSR2, SI_TKILL, (int)pid,
        (uint32_t)uid);
    failures += expect_result("tgkill_self_delivery",
        raw_syscall3(SYS_tgkill, pid, tid, SIGUSR1), 0);
    failures += wait_for_signal(
        1ULL << (SIGUSR1 - 1), SIGUSR1, SI_TKILL, (int)pid,
        (uint32_t)uid);

    failures += expect_result("kill_mixed_delivery",
        raw_syscall2(SYS_kill, pid, SIGUSR1), 0);
    failures += expect_result("tkill_mixed_delivery",
        raw_syscall2(SYS_tkill, tid, SIGUSR1), 0);
    failures += wait_for_signal(
        1ULL << (SIGUSR1 - 1), SIGUSR1, SI_TKILL, (int)pid,
        (uint32_t)uid);
    failures += wait_for_signal(
        1ULL << (SIGUSR1 - 1), SIGUSR1, SI_USER, (int)pid,
        (uint32_t)uid);

    failures += expect_result("tkill_realtime_first",
        raw_syscall2(SYS_tkill, tid, SIGRT_TEST), 0);
    failures += expect_result("tkill_realtime_second",
        raw_syscall2(SYS_tkill, tid, SIGRT_TEST), 0);
    failures += wait_for_signal(
        1ULL << (SIGRT_TEST - 1), SIGRT_TEST, SI_TKILL, (int)pid,
        (uint32_t)uid);
    failures += wait_for_signal(
        1ULL << (SIGRT_TEST - 1), SIGRT_TEST, SI_TKILL, (int)pid,
        (uint32_t)uid);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = test_signal_targeting();
    if (!failures)
        putstr("SIGNAL_TARGETING_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNAL_TARGETING_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
