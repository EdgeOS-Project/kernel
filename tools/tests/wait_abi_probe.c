/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux wait4()/waitid() ABI test shared by both 64-bit ports.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_exit_group 231
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_waitid 247
#define SYS_pipe2 293
#define SYS_pidfd_open 434
#elif defined(__aarch64__)
#define SYS_pipe2 59
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_waitid 95
#define SYS_exit 93
#define SYS_exit_group 94
#define SYS_nanosleep 101
#define SYS_kill 129
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_pidfd_open 434
#else
#error "wait_abi_probe requires a Linux 64-bit architecture"
#endif

#define ECHILD 10
#define ESRCH 3
#define SIGKILL 9
#define SIGSTOP 19
#define SIGCONT 18
#define SIGCHLD 17
#define CLD_EXITED 1
#define CLD_KILLED 2
#define CLD_STOPPED 5
#define CLD_CONTINUED 6
#define P_PIDFD 3
#define P_PID 1
#define WNOHANG 0x00000001
#define WSTOPPED 0x00000002
#define WEXITED 0x00000004
#define WCONTINUED 0x00000008
#define WNOWAIT 0x01000000

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_timeval {
    int64_t seconds;
    int64_t microseconds;
};

struct linux_rusage64 {
    struct linux_timeval user_time;
    struct linux_timeval system_time;
    int64_t values[14];
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

_Static_assert(sizeof(struct linux_rusage64) == 144,
               "Linux rusage layout mismatch");
_Static_assert(sizeof(struct linux_siginfo_child) == 128,
               "Linux siginfo layout mismatch");

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

static long raw_syscall5(long number, long a0, long a1, long a2,
                         long a3, long a4) {
    return raw_syscall6(number, a0, a1, a2, a3, a4, 0);
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

static void bytes_fill(void *destination, uint8_t value, unsigned long size) {
    uint8_t *bytes = destination;
    while (size--) *bytes++ = value;
}

static void child_exit_after_accounting(int status) {
    struct linux_timespec delay = {0, 50000000};
    volatile uint64_t value = 1;
    for (uint64_t iteration = 0; iteration < UINT64_C(50000000);
         ++iteration)
        value = value * UINT64_C(6364136223846793005) + iteration;
    if (!value) (void)raw_syscall1(SYS_getpid, 0);
    (void)raw_syscall2(SYS_nanosleep, (long)&delay, 0);
    (void)raw_syscall1(SYS_exit, status);
    for (;;) {}
}

static long spawn_accounting_child(int status) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) child_exit_after_accounting(status);
    return child;
}

static long spawn_paused_child(void) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) {
        struct linux_timespec delay = {60, 0};
        (void)raw_syscall2(SYS_nanosleep, (long)&delay, 0);
        (void)raw_syscall1(SYS_exit, 99);
        for (;;) {}
    }
    return child;
}

static int test_kill_blocked_wait(void) {
    struct linux_timespec settle = {0, 20000000};
    struct linux_timespec poll_delay = {0, 10000000};
    int pipe_fds[2] = {-1, -1};
    int target_status = -1;
    int failures = 0;
    long target;
    long sleeper = -1;
    long waited = 0;

    failures += expect_result("blocked_wait_pipe",
        raw_syscall2(SYS_pipe2, (long)pipe_fds, 0), 0);
    if (failures) return failures;

    target = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!target) {
        int ignored_status = 0;
        long child = spawn_paused_child();
        (void)raw_syscall3(SYS_write, pipe_fds[1],
                           (long)&child, sizeof(child));
        (void)raw_syscall4(SYS_wait4, child, (long)&ignored_status, 0, 0);
        (void)raw_syscall1(SYS_exit, 98);
        for (;;) {}
    }
    failures += expect_result("spawn_blocked_wait_target", target > 0, 1);
    if (target <= 0) return failures;
    failures += expect_result("blocked_wait_ready",
        raw_syscall3(SYS_read, pipe_fds[0], (long)&sleeper,
                     sizeof(sleeper)), sizeof(sleeper));
    (void)raw_syscall2(SYS_nanosleep, (long)&settle, 0);
    failures += expect_result("kill_blocked_wait_target",
        raw_syscall2(SYS_kill, target, SIGKILL), 0);

    for (int attempt = 0; attempt < 200; ++attempt) {
        waited = raw_syscall4(SYS_wait4, target, (long)&target_status,
                              WNOHANG, 0);
        if (waited != 0) break;
        (void)raw_syscall2(SYS_nanosleep, (long)&poll_delay, 0);
    }
    failures += expect_result("reap_blocked_wait_target", waited, target);
    if (waited == target)
        failures += expect_result("blocked_wait_target_status",
                                  target_status, SIGKILL);
    if (sleeper > 0) (void)raw_syscall2(SYS_kill, sleeper, SIGKILL);
    return failures;
}

static int test_exit_wait(void) {
    struct linux_siginfo_child information;
    struct linux_rusage64 usage;
    long child = spawn_accounting_child(33);
    int status = -1;
    int failures = 0;

    failures += expect_result("spawn_exit_child", child > 0, 1);
    bytes_fill(&information, 0x5a, sizeof(information));
    failures += expect_result("waitid_nohang",
        raw_syscall5(SYS_waitid, P_PID, child, (long)&information,
                     WEXITED | WNOHANG, 0), 0);
    /*
     * POSIX.1-2008 TC1 requires si_pid and si_signo to be zero when WNOHANG
     * finds no waitable child.  Reserved siginfo_t storage is not observable
     * ABI and Linux does not promise to overwrite every byte in that case.
     */
    failures += expect_result("waitid_nohang_zero_signo",
                              information.signal_number, 0);
    failures += expect_result("waitid_nohang_zero_pid", information.pid, 0);
    bytes_fill(&usage, 0, sizeof(usage));
    failures += expect_result("wait4_exit",
        raw_syscall4(SYS_wait4, child, (long)&status, 0, (long)&usage),
        child);
    failures += expect_result("wait4_exit_status", status, 33 << 8);
    failures += expect_result("wait4_rusage_nonzero",
        usage.user_time.seconds || usage.user_time.microseconds ||
        usage.system_time.seconds || usage.system_time.microseconds, 1);
    failures += expect_result("wait4_after_reap",
        raw_syscall4(SYS_wait4, child, (long)&status, WNOHANG, 0), -ECHILD);
    return failures;
}

static int test_exit_group_reap_stress(void) {
    int failures = 0;

    /*
     * Desktop session scripts create many short-lived helpers which terminate
     * through exit_group().  Reaping must commit atomically from userspace's
     * perspective: an internal cleanup marker must never remain visible as a
     * live child and leave a later wait4(-1) asleep forever.
     */
    for (int iteration = 0; iteration < 64; ++iteration) {
        int status = -1;
        long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);

        if (!child) {
            (void)raw_syscall1(SYS_exit_group, iteration & 0xff);
            for (;;) {}
        }
        failures += expect_result("spawn_exit_group_child", child > 0, 1);
        if (child <= 0) return failures;
        failures += expect_result("reap_exit_group_child",
            raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
        failures += expect_result("exit_group_child_status",
                                  status, (iteration & 0xff) << 8);
        failures += expect_result("exit_group_child_gone",
            raw_syscall4(SYS_wait4, child, (long)&status, WNOHANG, 0),
            -ECHILD);
    }
    return failures;
}

static int test_signal_wnowait(void) {
    struct linux_siginfo_child information;
    struct linux_rusage64 usage;
    long child = spawn_paused_child();
    int status = -1;
    int failures = 0;

    failures += expect_result("spawn_kill_child", child > 0, 1);
    failures += expect_result("kill_child",
                              raw_syscall2(SYS_kill, child, SIGKILL), 0);
    bytes_fill(&information, 0, sizeof(information));
    bytes_fill(&usage, 0, sizeof(usage));
    failures += expect_result("waitid_killed_wnowait",
        raw_syscall5(SYS_waitid, P_PID, child, (long)&information,
                     WEXITED | WNOWAIT, (long)&usage), 0);
    failures += expect_result("waitid_killed_signo",
                              information.signal_number, SIGCHLD);
    failures += expect_result("waitid_killed_code", information.code,
                              CLD_KILLED);
    failures += expect_result("waitid_killed_pid", information.pid, child);
    failures += expect_result("waitid_killed_status", information.status,
                              SIGKILL);
    failures += expect_result("wait4_reap_killed",
        raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
    failures += expect_result("wait4_killed_status", status, SIGKILL);
    return failures;
}

static int test_stop_continue(void) {
    struct linux_siginfo_child information;
    long child = spawn_paused_child();
    int status = -1;
    int failures = 0;

    failures += expect_result("spawn_stop_child", child > 0, 1);
    failures += expect_result("stop_child",
                              raw_syscall2(SYS_kill, child, SIGSTOP), 0);
    bytes_fill(&information, 0, sizeof(information));
    failures += expect_result("waitid_stopped",
        raw_syscall5(SYS_waitid, P_PID, child, (long)&information,
                     WSTOPPED, 0), 0);
    failures += expect_result("waitid_stopped_code", information.code,
                              CLD_STOPPED);
    failures += expect_result("waitid_stopped_status", information.status,
                              SIGSTOP);
    failures += expect_result("continue_child",
                              raw_syscall2(SYS_kill, child, SIGCONT), 0);
    bytes_fill(&information, 0, sizeof(information));
    failures += expect_result("waitid_continued",
        raw_syscall5(SYS_waitid, P_PID, child, (long)&information,
                     WCONTINUED, 0), 0);
    failures += expect_result("waitid_continued_code", information.code,
                              CLD_CONTINUED);
    failures += expect_result("waitid_continued_status", information.status,
                              SIGCONT);
    failures += expect_result("kill_stopped_child",
                              raw_syscall2(SYS_kill, child, SIGKILL), 0);
    failures += expect_result("reap_stopped_child",
        raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
    return failures;
}

static int test_selector_policy(void) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    int status = -1;
    int failures = 0;

    if (!child) {
        (void)raw_syscall1(SYS_exit, 41);
        for (;;) {}
    }
    failures += expect_result("spawn_process_group_child", child > 0, 1);
    failures += expect_result("wait4_current_process_group",
        raw_syscall4(SYS_wait4, 0, (long)&status, 0, 0), child);
    failures += expect_result("wait4_current_process_group_status",
                              status, 41 << 8);
    failures += expect_result("wait4_int32_min_selector",
        raw_syscall4(SYS_wait4, INT32_MIN, (long)&status, WNOHANG, 0),
        -ESRCH);
    return failures;
}

static int test_pidfd_exit_wait(void) {
    int failures = 0;

    /*
     * Repeat short-lived children so an exit racing the waiter's transition
     * into sleep cannot hide behind a single favorable scheduling order.
     */
    for (int iteration = 0; iteration < 16; ++iteration) {
        struct linux_siginfo_child information;
        long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        long pidfd;

        if (!child) {
            (void)raw_syscall1(SYS_exit, iteration + 1);
            for (;;) {}
        }
        failures += expect_result("spawn_pidfd_child", child > 0, 1);
        if (child <= 0) return failures;
        pidfd = raw_syscall2(SYS_pidfd_open, child, 0);
        failures += expect_result("pidfd_open_child", pidfd >= 0, 1);
        if (pidfd < 0) {
            int status = 0;
            (void)raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
            return failures;
        }
        bytes_fill(&information, 0, sizeof(information));
        failures += expect_result("waitid_pidfd_exit",
            raw_syscall5(SYS_waitid, P_PIDFD, pidfd, (long)&information,
                         WEXITED, 0), 0);
        failures += expect_result("waitid_pidfd_signo",
                                  information.signal_number, SIGCHLD);
        failures += expect_result("waitid_pidfd_code",
                                  information.code, CLD_EXITED);
        failures += expect_result("waitid_pidfd_pid",
                                  information.pid, child);
        failures += expect_result("waitid_pidfd_status",
                                  information.status, iteration + 1);
        failures += expect_result("close_pidfd",
                                  raw_syscall1(SYS_close, pidfd), 0);
    }
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = 0;
    putstr("WAIT_ABI_STAGE exit\n");
    failures += test_exit_wait();
    putstr("WAIT_ABI_STAGE exit-group-stress\n");
    failures += test_exit_group_reap_stress();
    putstr("WAIT_ABI_STAGE signal\n");
    failures += test_signal_wnowait();
    putstr("WAIT_ABI_STAGE stop-continue\n");
    failures += test_stop_continue();
    putstr("WAIT_ABI_STAGE kill-blocked-wait\n");
    failures += test_kill_blocked_wait();
    putstr("WAIT_ABI_STAGE selectors\n");
    failures += test_selector_policy();
    putstr("WAIT_ABI_STAGE pidfd-exit\n");
    failures += test_pidfd_exit_wait();
    if (!failures)
        putstr("WAIT_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("WAIT_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
