/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding cross-architecture runtime validation for Linux signalfd4.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_rt_sigprocmask 14
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_kill 62
#define SYS_fcntl 72
#define SYS_getuid 102
#define SYS_signalfd4 289
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_kill 129
#define SYS_rt_sigprocmask 135
#define SYS_getpid 172
#define SYS_getuid 174
#define SYS_signalfd4 74
#else
#error "signalfd_runtime_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define SIGUSR1 10
#define SIGUSR2 12
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define F_GETFD 1
#define F_GETFL 3
#define FD_CLOEXEC 1
#define O_NONBLOCK 0x800
#define O_CLOEXEC 0x80000

struct linux_signalfd_siginfo {
    uint32_t signal_number;
    int32_t error;
    int32_t code;
    uint32_t pid;
    uint32_t uid;
    int32_t descriptor;
    uint32_t thread_id;
    uint32_t band;
    uint32_t overrun;
    uint32_t trap_number;
    int32_t status;
    int32_t integer;
    uint64_t pointer;
    uint64_t user_time;
    uint64_t system_time;
    uint64_t address;
    uint16_t address_lsb;
    uint16_t padding_1;
    int32_t syscall_number;
    uint64_t call_address;
    uint32_t architecture;
    uint8_t padding[28];
};

_Static_assert(sizeof(struct linux_signalfd_siginfo) == 128,
               "Linux signalfd_siginfo size");

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

static long create_signalfd(long descriptor, const uint64_t *mask,
                            long mask_size, long flags) {
    return raw_syscall4(
        SYS_signalfd4, descriptor, (long)mask, mask_size, flags);
}

static int send_signal(long pid, long signal) {
    return (int)raw_syscall2(SYS_kill, pid, signal);
}

static int run_tests(void) {
    const uint64_t usr1 = UINT64_C(1) << (SIGUSR1 - 1);
    const uint64_t usr2 = UINT64_C(1) << (SIGUSR2 - 1);
    const uint64_t both = usr1 | usr2;
    struct linux_signalfd_siginfo records[2];
    uint64_t old_mask = 0;
    long pid = raw_syscall1(SYS_getpid, 0);
    long uid = raw_syscall1(SYS_getuid, 0);
    long descriptor;
    long result;
    int failures = 0;

    failures += expect_result("block_signals",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&both,
                     (long)&old_mask, 8), 0);
    failures += expect_result("null_mask",
        create_signalfd(-1, 0, 8, 0), -EFAULT);
    failures += expect_result("bad_mask_size",
        create_signalfd(-1, &both, 16, 0), -EINVAL);
    failures += expect_result("bad_flags",
        create_signalfd(-1, &both, 8, 0x40000000), -EINVAL);
    failures += expect_result("bad_descriptor",
        create_signalfd(-2, &both, 8, 0), -EBADF);

    descriptor = create_signalfd(
        -1, &both, 8, O_NONBLOCK | O_CLOEXEC);
    failures += expect_result("create", descriptor >= 0, 1);
    if (descriptor < 0) goto restore_mask;
    failures += expect_result("nonblock",
        raw_syscall3(SYS_fcntl, descriptor, F_GETFL, 0) & O_NONBLOCK,
        O_NONBLOCK);
    failures += expect_result("cloexec",
        raw_syscall3(SYS_fcntl, descriptor, F_GETFD, 0) & FD_CLOEXEC,
        FD_CLOEXEC);
    failures += expect_result("empty_read",
        raw_syscall3(SYS_read, descriptor, (long)records,
                     sizeof(records[0])), -EAGAIN);
    failures += expect_result("short_read",
        raw_syscall3(SYS_read, descriptor, (long)records,
                     sizeof(records[0]) - 1u), -EINVAL);

    failures += expect_result("send_usr1", send_signal(pid, SIGUSR1), 0);
    result = raw_syscall3(
        SYS_read, descriptor, (long)records, sizeof(records[0]));
    failures += expect_result("basic_read", result, sizeof(records[0]));
    failures += expect_result("basic_signo", records[0].signal_number,
                              SIGUSR1);
    failures += expect_result("basic_code", records[0].code, 0);
    failures += expect_result("basic_pid", records[0].pid, pid);
    failures += expect_result("basic_uid", records[0].uid, uid);

    failures += expect_result("send_usr1_first", send_signal(pid, SIGUSR1), 0);
    failures += expect_result("send_usr1_coalesce", send_signal(pid, SIGUSR1), 0);
    result = raw_syscall3(
        SYS_read, descriptor, (long)records, sizeof(records));
    failures += expect_result("coalesced_read", result, sizeof(records[0]));
    failures += expect_result("coalesced_signo", records[0].signal_number,
                              SIGUSR1);
    failures += expect_result("coalesced_empty",
        raw_syscall3(SYS_read, descriptor, (long)records,
                     sizeof(records[0])), -EAGAIN);

    failures += expect_result("send_usr2_order", send_signal(pid, SIGUSR2), 0);
    failures += expect_result("send_usr1_order", send_signal(pid, SIGUSR1), 0);
    result = raw_syscall3(
        SYS_read, descriptor, (long)records, sizeof(records));
    failures += expect_result("ordered_read", result, sizeof(records));
    failures += expect_result("ordered_first", records[0].signal_number,
                              SIGUSR1);
    failures += expect_result("ordered_second", records[1].signal_number,
                              SIGUSR2);

    failures += expect_result("update_mask",
        create_signalfd(descriptor, &usr2, 8, 0), descriptor);
    failures += expect_result("update_keeps_nonblock",
        raw_syscall3(SYS_fcntl, descriptor, F_GETFL, 0) & O_NONBLOCK,
        O_NONBLOCK);
    failures += expect_result("update_keeps_cloexec",
        raw_syscall3(SYS_fcntl, descriptor, F_GETFD, 0) & FD_CLOEXEC,
        FD_CLOEXEC);
    failures += expect_result("send_masked_usr1", send_signal(pid, SIGUSR1), 0);
    failures += expect_result("send_selected_usr2", send_signal(pid, SIGUSR2), 0);
    result = raw_syscall3(
        SYS_read, descriptor, (long)records, sizeof(records[0]));
    failures += expect_result("updated_read", result, sizeof(records[0]));
    failures += expect_result("updated_signo", records[0].signal_number,
                              SIGUSR2);
    failures += expect_result("updated_empty",
        raw_syscall3(SYS_read, descriptor, (long)records,
                     sizeof(records[0])), -EAGAIN);
    failures += expect_result("restore_descriptor_mask",
        create_signalfd(descriptor, &both, 8, 0), descriptor);
    result = raw_syscall3(
        SYS_read, descriptor, (long)records, sizeof(records[0]));
    failures += expect_result("drain_usr1", result, sizeof(records[0]));
    failures += expect_result("drain_usr1_signo", records[0].signal_number,
                              SIGUSR1);
    failures += expect_result("close", raw_syscall1(SYS_close, descriptor), 0);

restore_mask:
    failures += expect_result("restore_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask,
                     0, 8), 0);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    if (!failures)
        putstr("SIGNALFD_RUNTIME_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNALFD_RUNTIME_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) { }
}
