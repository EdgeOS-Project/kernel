/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 signal-set and siginfo compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_signal_info_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define X32_SYS_rt_sigprocmask 14
#define X32_SYS_close 3
#define X32_SYS_getpid 39
#define X32_SYS_getuid 102
#define X32_SYS_gettid 186
#define X32_SYS_rt_sigpending 522
#define X32_SYS_rt_sigtimedwait 523
#define X32_SYS_rt_sigqueueinfo 524
#define X32_SYS_rt_tgsigqueueinfo 536
#define X32_SYS_pidfd_send_signal 424
#define X32_SYS_pidfd_open 434
#define EINVAL 22
#define SIGUSR1 10
#define SIGUSR2 12
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define SI_QUEUE (-1)

struct compat_siginfo {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint8_t payload[116];
} __attribute__((aligned(8)));

struct timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

static uint64_t blocked_mask;
static uint64_t old_mask;
static uint64_t pending_mask;
static struct compat_siginfo queued_information;
static struct compat_siginfo received_information;
static struct timespec64 zero_timeout;

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
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
}

static long x32_syscall6(long number, long a0, long a1, long a2,
                          long a3, long a4, long a5) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, a3, a4, a5);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static void write_u32(void *base, uint32_t offset, uint32_t value) {
    uint8_t *bytes = (uint8_t *)base;
    bytes[offset + 0u] = (uint8_t)value;
    bytes[offset + 1u] = (uint8_t)(value >> 8);
    bytes[offset + 2u] = (uint8_t)(value >> 16);
    bytes[offset + 3u] = (uint8_t)(value >> 24);
}

static uint32_t read_u32(const void *base, uint32_t offset) {
    const uint8_t *bytes = (const uint8_t *)base;
    return (uint32_t)bytes[offset + 0u] |
           ((uint32_t)bytes[offset + 1u] << 8) |
           ((uint32_t)bytes[offset + 2u] << 16) |
           ((uint32_t)bytes[offset + 3u] << 24);
}

static int queue_and_wait(long pid, long tid, int signal,
                          uint32_t value, int thread_directed) {
    uint64_t mask = UINT64_C(1) << (signal - 1);
    long result;
    int failures = 0;

    for (uint32_t index = 0; index < sizeof(queued_information); ++index)
        ((uint8_t *)&queued_information)[index] = 0;
    for (uint32_t index = 0; index < sizeof(received_information); ++index)
        ((uint8_t *)&received_information)[index] = 0xa5;
    queued_information.signal_number = signal;
    queued_information.code = SI_QUEUE;
    write_u32(&queued_information, 12u, (uint32_t)pid);
    write_u32(&queued_information, 16u, (uint32_t)x32_syscall6(
        X32_SYS_getuid, 0, 0, 0, 0, 0, 0));
    write_u32(&queued_information, 20u, value);

    if (thread_directed) {
        result = x32_syscall6(
            X32_SYS_rt_tgsigqueueinfo, pid, tid, signal,
            (long)&queued_information, 0, 0);
    } else {
        result = x32_syscall6(
            X32_SYS_rt_sigqueueinfo, pid, signal,
            (long)&queued_information, 0, 0, 0);
    }
    failures += expect_result(
        thread_directed ? "queue-thread" : "queue-process", result, 0);
    pending_mask = 0;
    failures += expect_result(
        "query-pending", x32_syscall6(
            X32_SYS_rt_sigpending, (long)&pending_mask, 8, 0, 0, 0, 0), 0);
    failures += expect_result("pending-signal", pending_mask & mask, mask);
    failures += expect_result(
        thread_directed ? "wait-thread" : "wait-process",
        x32_syscall6(X32_SYS_rt_sigtimedwait, (long)&mask,
                    (long)&received_information, (long)&zero_timeout,
                    8, 0, 0),
        signal);
    failures += expect_result("info-signal",
                              received_information.signal_number, signal);
    failures += expect_result("info-error", received_information.error, 0);
    failures += expect_result("info-code", received_information.code,
                              SI_QUEUE);
    failures += expect_result("info-pid", read_u32(&received_information, 12u),
                              (uint32_t)pid);
    failures += expect_result("info-value",
                              read_u32(&received_information, 20u), value);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    long pid = x32_syscall6(X32_SYS_getpid, 0, 0, 0, 0, 0, 0);
    long tid = x32_syscall6(X32_SYS_gettid, 0, 0, 0, 0, 0, 0);
    long pidfd;
    int failures = 0;

    blocked_mask = (UINT64_C(1) << (SIGUSR1 - 1)) |
                   (UINT64_C(1) << (SIGUSR2 - 1));
    failures += expect_result(
        "block-signals", x32_syscall6(
            X32_SYS_rt_sigprocmask, SIG_BLOCK, (long)&blocked_mask,
            (long)&old_mask, 8, 0, 0), 0);
    failures += expect_result("initial-mask", old_mask, 0);
    failures += expect_result(
        "invalid-mask-size", x32_syscall6(
            X32_SYS_rt_sigprocmask, SIG_BLOCK, (long)&blocked_mask,
            0, 4, 0, 0), -EINVAL);
    failures += expect_result(
        "initial-pending", x32_syscall6(
            X32_SYS_rt_sigpending, (long)&pending_mask, 8, 0, 0, 0, 0), 0);
    failures += expect_result("initial-pending-mask", pending_mask, 0);

    failures += queue_and_wait(
        pid, tid, SIGUSR1, UINT32_C(0x89abcdef), 0);
    failures += queue_and_wait(
        pid, tid, SIGUSR2, UINT32_C(0x12345678), 1);

    pidfd = x32_syscall6(X32_SYS_pidfd_open, pid, 0, 0, 0, 0, 0);
    if (pidfd < 0) {
        failures += expect_result("pidfd-open", pidfd, 0);
    } else {
        uint64_t mask = UINT64_C(1) << (SIGUSR1 - 1);

        for (uint32_t index = 0; index < sizeof(queued_information); ++index)
            ((uint8_t *)&queued_information)[index] = 0;
        for (uint32_t index = 0; index < sizeof(received_information); ++index)
            ((uint8_t *)&received_information)[index] = 0xa5;
        queued_information.signal_number = SIGUSR1;
        queued_information.code = SI_QUEUE;
        write_u32(&queued_information, 12u, (uint32_t)pid);
        write_u32(&queued_information, 16u, (uint32_t)x32_syscall6(
            X32_SYS_getuid, 0, 0, 0, 0, 0, 0));
        write_u32(&queued_information, 20u, UINT32_C(0x76543210));
        failures += expect_result(
            "pidfd-send", x32_syscall6(
                X32_SYS_pidfd_send_signal, pidfd, SIGUSR1,
                (long)&queued_information, 0, 0, 0), 0);
        failures += expect_result(
            "pidfd-wait", x32_syscall6(
                X32_SYS_rt_sigtimedwait, (long)&mask,
                (long)&received_information, (long)&zero_timeout,
                8, 0, 0), SIGUSR1);
        failures += expect_result(
            "pidfd-info-value", read_u32(&received_information, 20u),
            UINT32_C(0x76543210));
        failures += expect_result(
            "pidfd-close", x32_syscall6(
                X32_SYS_close, pidfd, 0, 0, 0, 0, 0), 0);
    }

    failures += expect_result(
        "restore-mask", x32_syscall6(
            X32_SYS_rt_sigprocmask, SIG_SETMASK, (long)&old_mask,
            0, 8, 0, 0), 0);

    if (failures) {
        print_text("X32_SIGNAL_INFO_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_SIGNAL_INFO_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
