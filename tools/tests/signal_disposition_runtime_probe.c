/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS freestanding Linux signal-disposition runtime test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_sched_yield 24
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_rt_sigpending 127
#define SYS_waitid 247
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_waitid 95
#define SYS_sched_yield 124
#define SYS_kill 129
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigpending 136
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "signal_disposition_runtime_probe requires a Linux 64-bit architecture"
#endif

#define ECHILD 10
#define SIGUSR1 10
#define SIGCHLD 17
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define SIG_DFL 0u
#define SIG_IGN 1u
#define SA_NOCLDWAIT 0x00000002u
#define P_PID 1
#define WNOHANG 0x00000001u
#define WEXITED 0x00000004u
#define WNOWAIT 0x01000000u
#define YIELD_LIMIT 200000u

struct linux_signal_action {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

struct linux_siginfo_child {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint32_t padding;
    int32_t pid;
    uint32_t uid;
    int32_t status;
    uint32_t child_padding;
    int64_t user_time;
    int64_t system_time;
    uint8_t reserved[80];
};

_Static_assert(sizeof(struct linux_signal_action) == 32,
               "Linux signal action layout mismatch");
_Static_assert(sizeof(struct linux_siginfo_child) == 128,
               "Linux siginfo layout mismatch");

static long raw_syscall6(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4,
                         long argument5) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = argument3;
    register long r8 __asm__("r8") = argument4;
    register long r9 __asm__("r9") = argument5;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    register long x4 __asm__("x4") = argument4;
    register long x5 __asm__("x5") = argument5;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall5(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, argument4, 0);
}

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, 0, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall6(number, argument0, argument1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
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

static void clear_bytes(void *destination, unsigned long size) {
    uint8_t *bytes = destination;
    while (size) bytes[--size] = 0;
}

static __attribute__((noreturn)) void child_exit(int status) {
    (void)raw_syscall1(SYS_exit, status);
    for (;;) {}
}

static long spawn_child(int status) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) child_exit(status);
    return child;
}

static int test_pending_discard(void) {
    const uint64_t signal_bit = UINT64_C(1) << (SIGUSR1 - 1);
    struct linux_signal_action old_action;
    struct linux_signal_action ignored_action;
    uint64_t old_mask = 0;
    uint64_t pending = 0;
    long pid = raw_syscall1(SYS_getpid, 0);
    int failures = 0;

    clear_bytes(&ignored_action, sizeof(ignored_action));
    ignored_action.handler = SIG_IGN;
    failures += expect_result(
        "discard_save_action",
        raw_syscall4(SYS_rt_sigaction, SIGUSR1, 0, (long)&old_action, 8), 0);
    failures += expect_result(
        "discard_block",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&signal_bit,
                     (long)&old_mask, 8), 0);
    failures += expect_result(
        "discard_queue", raw_syscall2(SYS_kill, pid, SIGUSR1), 0);
    failures += expect_result(
        "discard_pending_before",
        raw_syscall2(SYS_rt_sigpending, (long)&pending, 8), 0);
    failures += expect_result(
        "discard_pending_before_bit", (long)(pending & signal_bit),
        (long)signal_bit);
    failures += expect_result(
        "discard_install_ignore",
        raw_syscall4(SYS_rt_sigaction, SIGUSR1, (long)&ignored_action, 0, 8),
        0);
    pending = UINT64_MAX;
    failures += expect_result(
        "discard_pending_after",
        raw_syscall2(SYS_rt_sigpending, (long)&pending, 8), 0);
    failures += expect_result(
        "discard_pending_after_bit", (long)(pending & signal_bit), 0);
    failures += expect_result(
        "discard_restore_action",
        raw_syscall4(SYS_rt_sigaction, SIGUSR1, (long)&old_action, 0, 8), 0);
    failures += expect_result(
        "discard_restore_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask, 0, 8),
        0);
    return failures;
}

static int test_existing_zombie_preserved(void) {
    const uint64_t signal_bit = UINT64_C(1) << (SIGCHLD - 1);
    struct linux_signal_action old_action;
    struct linux_signal_action default_action;
    struct linux_signal_action ignored_action;
    struct linux_siginfo_child information;
    uint64_t old_mask = 0;
    uint64_t pending = 0;
    int status = 0;
    long child;
    int failures = 0;

    clear_bytes(&default_action, sizeof(default_action));
    clear_bytes(&ignored_action, sizeof(ignored_action));
    ignored_action.handler = SIG_IGN;
    failures += expect_result(
        "zombie_save_action",
        raw_syscall4(SYS_rt_sigaction, SIGCHLD, 0, (long)&old_action, 8), 0);
    failures += expect_result(
        "zombie_default_action",
        raw_syscall4(SYS_rt_sigaction, SIGCHLD, (long)&default_action, 0, 8),
        0);
    failures += expect_result(
        "zombie_block",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&signal_bit,
                     (long)&old_mask, 8), 0);
    child = spawn_child(31);
    failures += expect_result("zombie_spawn", child > 0, 1);
    clear_bytes(&information, sizeof(information));
    if (child > 0) {
        failures += expect_result(
            "zombie_wait_peek",
            raw_syscall5(SYS_waitid, P_PID, child, (long)&information,
                         WEXITED | WNOWAIT, 0), 0);
        failures += expect_result(
            "zombie_wait_peek_pid", information.pid, child);
    }
    failures += expect_result(
        "zombie_pending",
        raw_syscall2(SYS_rt_sigpending, (long)&pending, 8), 0);
    failures += expect_result(
        "zombie_pending_bit", (long)(pending & signal_bit), (long)signal_bit);
    failures += expect_result(
        "zombie_install_ignore",
        raw_syscall4(SYS_rt_sigaction, SIGCHLD, (long)&ignored_action, 0, 8),
        0);
    if (child > 0)
        failures += expect_result(
            "zombie_preserved",
            raw_syscall4(SYS_wait4, child, (long)&status, WNOHANG, 0),
            child);
        failures += expect_result(
            "zombie_status", status, 31 << 8);
    pending = UINT64_MAX;
    failures += expect_result(
        "zombie_pending_after",
        raw_syscall2(SYS_rt_sigpending, (long)&pending, 8), 0);
    failures += expect_result(
        "zombie_pending_after_bit", (long)(pending & signal_bit), 0);
    failures += expect_result(
        "zombie_restore_action",
        raw_syscall4(SYS_rt_sigaction, SIGCHLD, (long)&old_action, 0, 8), 0);
    failures += expect_result(
        "zombie_restore_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask, 0, 8),
        0);
    return failures;
}

static int test_no_child_wait(void) {
    struct linux_signal_action old_action;
    struct linux_signal_action no_wait_action;
    int status = 0;
    long result = 0;
    long child;
    uint32_t attempt;
    int failures = 0;

    clear_bytes(&no_wait_action, sizeof(no_wait_action));
    no_wait_action.handler = SIG_DFL;
    no_wait_action.flags = SA_NOCLDWAIT;
    failures += expect_result(
        "nocldwait_save_action",
        raw_syscall4(SYS_rt_sigaction, SIGCHLD, 0, (long)&old_action, 8), 0);
    failures += expect_result(
        "nocldwait_install",
        raw_syscall4(SYS_rt_sigaction, SIGCHLD, (long)&no_wait_action, 0, 8),
        0);
    child = spawn_child(32);
    failures += expect_result("nocldwait_spawn", child > 0, 1);
    if (child > 0) {
        for (attempt = 0; attempt < YIELD_LIMIT; ++attempt) {
            result = raw_syscall4(
                SYS_wait4, child, (long)&status, WNOHANG, 0);
            if (result == -ECHILD) break;
            if (result != 0) break;
            (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
        }
        failures += expect_result("nocldwait_reaped", result, -ECHILD);
    }
    failures += expect_result(
        "nocldwait_restore_action",
        raw_syscall4(SYS_rt_sigaction, SIGCHLD, (long)&old_action, 0, 8), 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = 0;
    failures += test_pending_discard();
    failures += test_existing_zombie_preserved();
    failures += test_no_child_wait();
    if (!failures)
        putstr("SIGNAL_DISPOSITION_RUNTIME_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNAL_DISPOSITION_RUNTIME_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
