/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for temporary signal masks used by wait
 * syscalls.  The handler must observe the temporary mask, while sigreturn
 * restores the mask that was active before entering the wait.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn 15
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_pselect6 270
#define SYS_ppoll 271
#define SYS_epoll_pwait 281
#define SYS_epoll_create1 291
#elif defined(__aarch64__)
#define SYS_epoll_create1 20
#define SYS_epoll_pwait 22
#define SYS_close 57
#define SYS_write 64
#define SYS_pselect6 72
#define SYS_ppoll 73
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_kill 129
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigreturn 139
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "signal_wait_mask_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINTR 4
#define SIGUSR1 10
#define SIGUSR2 12
#define SIGTERM 15
#define SIGCHLD 17
#define SIG_BLOCK 0
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

struct linux_pselect_sigmask {
    uint64_t mask;
    uint64_t size;
};

struct linux_epoll_event {
    uint32_t events;
    uint64_t data;
} __attribute__((packed));

static volatile uint64_t handler_mask;
static volatile long handler_mask_result;
static volatile uint32_t handler_count;

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
    uint64_t observed = 0;
    if (signal != SIGUSR2) return;
    handler_mask_result = raw_syscall4(
        SYS_rt_sigprocmask, SIG_BLOCK, 0, (long)&observed, 8);
    handler_mask = observed;
    ++handler_count;
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

static void child_send_after_delay(long parent) {
    struct linux_timespec delay = {0, 50000000};
    (void)raw_syscall2(SYS_nanosleep, (long)&delay, 0);
    (void)raw_syscall2(SYS_kill, parent, SIGUSR2);
    (void)raw_syscall1(SYS_exit, 0);
    for (;;) {}
}

static long spawn_signal_sender(long parent) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) child_send_after_delay(parent);
    return child;
}

static int reap_sender(long child) {
    int status = -1;
    long result;
    if (child <= 0) return 1;
    result = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    return result == child && status == 0 ? 0 : 1;
}

static int verify_wait_result(const char *result_name, long result,
                              long child, uint64_t original_mask,
                              uint64_t temporary_mask,
                              uint32_t expected_handler_count) {
    const uint64_t usr1_bit = UINT64_C(1) << (SIGUSR1 - 1);
    const uint64_t usr2_bit = UINT64_C(1) << (SIGUSR2 - 1);
    uint64_t after_mask = 0;
    int failures = 0;
    failures += expect_result(result_name, result, -EINTR);
    failures += expect_result("handler_count", handler_count,
                              expected_handler_count);
    failures += expect_result("handler_mask_query", handler_mask_result, 0);
    failures += expect_result("handler_kept_temporary_mask",
                              (handler_mask & temporary_mask) != 0, 1);
    failures += expect_result("handler_did_not_restore_original_early",
                              (handler_mask & usr1_bit) != 0, 0);
    failures += expect_result("handler_blocks_current_signal",
                              (handler_mask & usr2_bit) != 0, 1);
    failures += expect_result("query_restored_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, 0,
                     (long)&after_mask, 8), 0);
    failures += expect_result("restored_original_mask",
                              (long)(after_mask & original_mask),
                              (long)original_mask);
    failures += expect_result("removed_temporary_mask",
                              (after_mask & temporary_mask) != 0, 0);
    failures += reap_sender(child);
    return failures;
}

static int test_wait_masks(void) {
    const uint64_t usr1_bit = UINT64_C(1) << (SIGUSR1 - 1);
    const uint64_t usr2_bit = UINT64_C(1) << (SIGUSR2 - 1);
    const uint64_t original_mask = usr1_bit | usr2_bit;
    const uint64_t temporary_mask = UINT64_C(1) << (SIGTERM - 1);
    struct linux_signal_action old_action;
    struct linux_signal_action action;
    struct linux_timespec timeout;
    struct linux_pselect_sigmask pselect_mask;
    struct linux_epoll_event event;
    uint64_t old_mask = 0;
    long parent = raw_syscall1(SYS_getpid, 0);
    long child;
    long result;
    long epoll_descriptor;
    int failures = 0;

    action.handler = (uint64_t)(uintptr_t)handle_usr2;
    action.flags = SA_RESTORER;
    action.restorer = (uint64_t)(uintptr_t)signal_restorer;
    action.mask = 0;
    failures += expect_result("install_handler",
        raw_syscall4(SYS_rt_sigaction, SIGUSR2, (long)&action,
                     (long)&old_action, 8), 0);
    failures += expect_result("block_original_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&original_mask,
                     (long)&old_mask, 8), 0);

    handler_mask_result = -1;
    child = spawn_signal_sender(parent);
    failures += expect_result("spawn_ppoll_sender", child > 0, 1);
    timeout.seconds = 2;
    timeout.nanoseconds = 0;
    result = raw_syscall6(SYS_ppoll, 0, 0, (long)&timeout,
                          (long)&temporary_mask, 8, 0);
    failures += verify_wait_result("ppoll_result", result, child,
                                   original_mask, temporary_mask, 1);

    handler_mask_result = -1;
    child = spawn_signal_sender(parent);
    failures += expect_result("spawn_pselect_sender", child > 0, 1);
    timeout.seconds = 2;
    timeout.nanoseconds = 0;
    pselect_mask.mask = (uint64_t)(uintptr_t)&temporary_mask;
    pselect_mask.size = 8;
    result = raw_syscall6(SYS_pselect6, 0, 0, 0, 0, (long)&timeout,
                          (long)&pselect_mask);
    failures += verify_wait_result("pselect_result", result, child,
                                   original_mask, temporary_mask, 2);

    epoll_descriptor = raw_syscall1(SYS_epoll_create1, 0);
    failures += expect_result("epoll_create1", epoll_descriptor >= 0, 1);
    if (epoll_descriptor >= 0) {
        handler_mask_result = -1;
        child = spawn_signal_sender(parent);
        failures += expect_result("spawn_epoll_sender", child > 0, 1);
        result = raw_syscall6(SYS_epoll_pwait, epoll_descriptor,
                              (long)&event, 1, 2000,
                              (long)&temporary_mask, 8);
        failures += verify_wait_result("epoll_pwait_result", result, child,
                                       original_mask, temporary_mask, 3);
        failures += expect_result("close_epoll",
                                  raw_syscall1(SYS_close, epoll_descriptor), 0);
    }

    failures += expect_result("restore_original_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask,
                     0, 8), 0);
    failures += expect_result("restore_handler",
        raw_syscall4(SYS_rt_sigaction, SIGUSR2, (long)&old_action,
                     0, 8), 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = test_wait_masks();
    if (!failures)
        putstr("SIGNAL_WAIT_MASK_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNAL_WAIT_MASK_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
