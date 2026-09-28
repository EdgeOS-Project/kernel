/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for queued process and thread signals.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_rt_sigprocmask 14
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_getuid 102
#define SYS_rt_sigtimedwait 128
#define SYS_rt_sigqueueinfo 129
#define SYS_gettid 186
#define SYS_rt_tgsigqueueinfo 297
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_rt_sigprocmask 135
#define SYS_rt_sigtimedwait 137
#define SYS_rt_sigqueueinfo 138
#define SYS_getpid 172
#define SYS_getuid 174
#define SYS_gettid 178
#define SYS_rt_tgsigqueueinfo 240
#else
#error "signal_queue_abi_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22
#define SIGUSR1 10
#define SIGUSR2 12
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define SI_QUEUE (-1)
#define SI_TKILL (-6)

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

static long raw_syscall3(long number, long a0, long a1, long a2) {
    return raw_syscall6(number, a0, a1, a2, 0, 0, 0);
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

static void clear_bytes(void *destination, unsigned long length) {
    uint8_t *bytes = destination;
    while (length) bytes[--length] = 0;
}

static int wait_for_signal(uint64_t mask, struct linux_siginfo *information) {
    struct linux_timespec timeout = {1, 0};
    clear_bytes(information, sizeof(*information));
    return (int)raw_syscall4(
        SYS_rt_sigtimedwait, (long)&mask, (long)information,
        (long)&timeout, 8);
}

static int test_signal_queue(void) {
    const uint64_t usr1_bit = UINT64_C(1) << (SIGUSR1 - 1);
    const uint64_t usr2_bit = UINT64_C(1) << (SIGUSR2 - 1);
    const uint64_t blocked = usr1_bit | usr2_bit;
    const uint64_t process_value = UINT64_C(0x1122334455667788);
    const uint64_t thread_value = UINT64_C(0x8877665544332211);
    struct linux_siginfo information;
    struct linux_siginfo observed;
    uint64_t old_mask = 0;
    long pid = raw_syscall1(SYS_getpid, 0);
    long tid = raw_syscall1(SYS_gettid, 0);
    long uid = raw_syscall1(SYS_getuid, 0);
    int failures = 0;

    failures += expect_result("block_signals",
        raw_syscall4(SYS_rt_sigprocmask, SIG_BLOCK, (long)&blocked,
                     (long)&old_mask, 8), 0);

    clear_bytes(&information, sizeof(information));
    information.signal_number = 63;
    information.code = SI_QUEUE;
    information.sender_pid = (int32_t)pid;
    information.sender_uid = (uint32_t)uid;
    information.value = process_value;
    failures += expect_result("queue_process",
        raw_syscall3(SYS_rt_sigqueueinfo, pid, SIGUSR1,
                     (long)&information), 0);
    failures += expect_result("wait_process",
        wait_for_signal(usr1_bit, &observed), SIGUSR1);
    failures += expect_result("process_signo", observed.signal_number, SIGUSR1);
    failures += expect_result("process_code", observed.code, SI_QUEUE);
    failures += expect_result("process_pid", observed.sender_pid, pid);
    failures += expect_result("process_uid", observed.sender_uid, uid);
    failures += expect_result("process_value", (long)observed.value,
                              (long)process_value);

    clear_bytes(&information, sizeof(information));
    information.signal_number = 63;
    information.code = SI_TKILL;
    information.sender_pid = (int32_t)pid;
    information.sender_uid = (uint32_t)uid;
    information.value = thread_value;
    failures += expect_result("queue_thread",
        raw_syscall4(SYS_rt_tgsigqueueinfo, pid, tid, SIGUSR2,
                     (long)&information), 0);
    failures += expect_result("wait_thread",
        wait_for_signal(usr2_bit, &observed), SIGUSR2);
    failures += expect_result("thread_signo", observed.signal_number, SIGUSR2);
    failures += expect_result("thread_code", observed.code, SI_TKILL);
    failures += expect_result("thread_pid", observed.sender_pid, pid);
    failures += expect_result("thread_uid", observed.sender_uid, uid);
    failures += expect_result("thread_value", (long)observed.value,
                              (long)thread_value);

    failures += expect_result("queue_null_info",
        raw_syscall3(SYS_rt_sigqueueinfo, pid, SIGUSR1, 0), -EFAULT);
    failures += expect_result("queue_bad_signal",
        raw_syscall3(SYS_rt_sigqueueinfo, pid, 65,
                     (long)&information), -EINVAL);
    failures += expect_result("thread_bad_tgid",
        raw_syscall4(SYS_rt_tgsigqueueinfo, 0, tid, SIGUSR2,
                     (long)&information), -EINVAL);
    failures += expect_result("queue_signal_zero",
        raw_syscall3(SYS_rt_sigqueueinfo, pid, 0,
                     (long)&information), 0);

    failures += expect_result("restore_mask",
        raw_syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask,
                     0, 8), 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = test_signal_queue();
    if (!failures)
        putstr("SIGNAL_QUEUE_ABI_PROBE_PASS failures: 0\n");
    else {
        putstr("SIGNAL_QUEUE_ABI_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
