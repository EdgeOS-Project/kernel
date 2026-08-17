/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for pidfd creation and signal delivery.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_rt_sigprocmask 14
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_wait4 61
#define SYS_exit 60
#define SYS_getuid 102
#define SYS_rt_sigtimedwait 128
#define SYS_gettid 186
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigtimedwait 137
#define SYS_getpid 172
#define SYS_getuid 174
#define SYS_gettid 178
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_nanosleep 101
#else
#error "pidfd_signal_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_pidfd_send_signal 424
#define SYS_pidfd_open 434
#if defined(__x86_64__)
#define SYS_ppoll 271
#else
#define SYS_ppoll 73
#endif

#define EBADF 9
#define EFAULT 14
#define ESRCH 3
#define EINVAL 22
#define EPERM 1
#define SIGUSR1 10
#define SIGCHLD 17
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define SI_QUEUE (-1)
#define PIDFD_THREAD 0x80
#define PIDFD_NONBLOCK 0x800
#define PIDFD_SIGNAL_THREAD (1u << 0)
#define PIDFD_SIGNAL_THREAD_GROUP (1u << 1)
#define PIDFD_SIGNAL_PROCESS_GROUP (1u << 2)
#define POLLIN 0x0001

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_pollfd {
    int32_t descriptor;
    int16_t events;
    int16_t returned_events;
};

struct linux_siginfo {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint32_t padding;
    int32_t sender_pid;
    uint32_t sender_uid;
    uint64_t value;
    uint8_t rest[96];
};

_Static_assert(sizeof(struct linux_siginfo) == 128,
               "Linux siginfo probe layout");

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

static long raw_syscall5(long number, long a0, long a1, long a2,
                         long a3, long a4) {
    return raw_syscall6(number, a0, a1, a2, a3, a4, 0);
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

static int expect_nonnegative(const char *name, long value) {
    if (value >= 0) return 0;
    putstr(name);
    putstr(": result=");
    putdec(value);
    putstr(" expected nonnegative\n");
    return 1;
}

static void clear_bytes(void *destination, unsigned long length) {
    uint8_t *bytes = destination;
    while (length) bytes[--length] = 0;
}

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int test_pidfd_exit_readiness(void) {
    struct linux_timespec child_delay = {0, 50000000};
    struct linux_timespec poll_timeout = {1, 0};
    struct linux_pollfd descriptor;
    int32_t status = -1;
    long child = create_child();
    long pidfd;
    int failures = 0;

    if (child < 0) return expect_nonnegative("create_child", child);
    if (child == 0) {
        (void)raw_syscall2(SYS_nanosleep, (long)&child_delay, 0);
        (void)raw_syscall1(SYS_exit, 0);
        for (;;) {}
    }
    pidfd = raw_syscall2(SYS_pidfd_open, child, 0);
    failures += expect_nonnegative("open_child", pidfd);
    if (pidfd >= 0) {
        descriptor.descriptor = (int32_t)pidfd;
        descriptor.events = POLLIN;
        descriptor.returned_events = 0;
        failures += expect_result("poll_child_exit",
            raw_syscall5(SYS_ppoll, (long)&descriptor, 1,
                         (long)&poll_timeout, 0, 8), 1);
        failures += expect_result("pidfd_exit_readable",
            descriptor.returned_events & POLLIN, POLLIN);
    }
    failures += expect_result("reap_child",
        raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
    failures += expect_result("child_status", status, 0);
    if (pidfd >= 0)
        failures += expect_result("close_child_pidfd",
            raw_syscall1(SYS_close, pidfd), 0);
    return failures;
}

static int test_pidfd_zombie_open(void) {
    struct linux_timespec parent_delay = {0, 50000000};
    struct linux_timespec poll_timeout = {0, 0};
    struct linux_pollfd descriptor;
    int32_t status = -1;
    long child = create_child();
    long pidfd;
    int failures = 0;

    if (child < 0) return expect_nonnegative("create_zombie", child);
    if (child == 0) {
        (void)raw_syscall1(SYS_exit, 0);
        for (;;) {}
    }
    (void)raw_syscall2(SYS_nanosleep, (long)&parent_delay, 0);
    pidfd = raw_syscall2(SYS_pidfd_open, child, 0);
    failures += expect_nonnegative("open_zombie", pidfd);
    if (pidfd >= 0) {
        descriptor.descriptor = (int32_t)pidfd;
        descriptor.events = POLLIN;
        descriptor.returned_events = 0;
        failures += expect_result("poll_zombie",
            raw_syscall5(SYS_ppoll, (long)&descriptor, 1,
                         (long)&poll_timeout, 0, 8), 1);
        failures += expect_result("zombie_pidfd_readable",
            descriptor.returned_events & POLLIN, POLLIN);
    }
    failures += expect_result("reap_zombie",
        raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
    failures += expect_result("zombie_status", status, 0);
    if (pidfd >= 0)
        failures += expect_result("close_zombie_pidfd",
            raw_syscall1(SYS_close, pidfd), 0);
    return failures;
}

static int test_pidfd_signals(void) {
    const uint64_t signal_bit = UINT64_C(1) << (SIGUSR1 - 1);
    const uint64_t queued_value = UINT64_C(0x5049444644515545);
    struct linux_timespec timeout = {1, 0};
    struct linux_siginfo information;
    struct linux_siginfo observed;
    uint64_t old_mask = 0;
    long pid = raw_syscall1(SYS_getpid, 0);
    long tid = raw_syscall1(SYS_gettid, 0);
    long uid = raw_syscall1(SYS_getuid, 0);
    long process_pidfd;
    long thread_pidfd;
    long nonblocking_pidfd;
    int failures = 0;

    failures += expect_result("open_zero_pid",
        raw_syscall2(SYS_pidfd_open, 0, 0), -EINVAL);
    failures += expect_result("open_missing_pid",
        raw_syscall2(SYS_pidfd_open, 0x7fffffff, 0), -ESRCH);
    failures += expect_result("open_bad_flags",
        raw_syscall2(SYS_pidfd_open, pid, 1), -EINVAL);

    process_pidfd = raw_syscall2(SYS_pidfd_open, pid, 0);
    failures += expect_nonnegative("open_process", process_pidfd);
    nonblocking_pidfd = raw_syscall2(
        SYS_pidfd_open, pid, PIDFD_NONBLOCK);
    failures += expect_nonnegative("open_nonblocking", nonblocking_pidfd);
    thread_pidfd = raw_syscall2(SYS_pidfd_open, tid, PIDFD_THREAD);
    failures += expect_nonnegative("open_thread", thread_pidfd);

    if (process_pidfd >= 0) {
        failures += expect_result("liveness_default",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, 0, 0, 0), 0);
        failures += expect_result("liveness_thread",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, 0, 0,
                         PIDFD_SIGNAL_THREAD), 0);
        failures += expect_result("liveness_thread_group",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, 0, 0,
                         PIDFD_SIGNAL_THREAD_GROUP), 0);
        failures += expect_result("liveness_process_group",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, 0, 0,
                         PIDFD_SIGNAL_PROCESS_GROUP), 0);
        failures += expect_result("combined_scopes",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, 0, 0,
                         PIDFD_SIGNAL_THREAD |
                         PIDFD_SIGNAL_THREAD_GROUP), -EINVAL);
        failures += expect_result("unknown_scope",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, 0, 0,
                         0x80000000u), -EINVAL);
    }
    failures += expect_result("non_pidfd",
        raw_syscall4(SYS_pidfd_send_signal, 1, 0, 0, 0), -EBADF);

    failures += expect_result("block_signal",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&signal_bit,
                     (long)&old_mask, 8), 0);
    clear_bytes(&information, sizeof(information));
    information.signal_number = SIGUSR1 + 1;
    information.code = SI_QUEUE;
    information.sender_pid = (int32_t)pid;
    information.sender_uid = (uint32_t)uid;
    information.value = queued_value;
    if (process_pidfd >= 0) {
        failures += expect_result("mismatched_siginfo",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, SIGUSR1,
                         (long)&information, 0), -EINVAL);
        information.signal_number = SIGUSR1;
        failures += expect_result("queue_siginfo",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, SIGUSR1,
                         (long)&information, 0), 0);
        clear_bytes(&observed, sizeof(observed));
        failures += expect_result("wait_siginfo",
            raw_syscall4(SYS_rt_sigtimedwait, (long)&signal_bit,
                         (long)&observed, (long)&timeout, 8), SIGUSR1);
        failures += expect_result("queued_code", observed.code, SI_QUEUE);
        failures += expect_result("queued_pid", observed.sender_pid, pid);
        failures += expect_result("queued_uid", observed.sender_uid, uid);
        failures += expect_result("queued_value", (long)observed.value,
                                  (long)queued_value);
        information.signal_number = 0;
        information.code = 0;
        failures += expect_result("group_rejects_kernel_code",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, 0,
                         (long)&information,
                         PIDFD_SIGNAL_PROCESS_GROUP), -EPERM);
        failures += expect_result("bad_siginfo_address",
            raw_syscall4(SYS_pidfd_send_signal, process_pidfd, SIGUSR1,
                         1, 0), -EFAULT);
    }
    if (thread_pidfd >= 0) {
        failures += expect_result("thread_pidfd_liveness",
            raw_syscall4(SYS_pidfd_send_signal, thread_pidfd, 0, 0, 0), 0);
        failures += expect_result("thread_to_group_override",
            raw_syscall4(SYS_pidfd_send_signal, thread_pidfd, 0, 0,
                         PIDFD_SIGNAL_THREAD_GROUP), 0);
    }

    failures += expect_result("restore_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask,
                     0, 8), 0);
    if (process_pidfd >= 0)
        failures += expect_result("close_process",
            raw_syscall1(SYS_close, process_pidfd), 0);
    if (thread_pidfd >= 0)
        failures += expect_result("close_thread",
            raw_syscall1(SYS_close, thread_pidfd), 0);
    if (nonblocking_pidfd >= 0)
        failures += expect_result("close_nonblocking",
            raw_syscall1(SYS_close, nonblocking_pidfd), 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = test_pidfd_signals();
    failures += test_pidfd_exit_readiness();
    failures += test_pidfd_zombie_open();
    if (!failures)
        putstr("PIDFD_SIGNAL_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("PIDFD_SIGNAL_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
