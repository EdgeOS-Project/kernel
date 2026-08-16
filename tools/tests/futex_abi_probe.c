/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS freestanding Linux futex ABI parity regression test. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_futex 202
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_futex 98
#else
#error "futex_abi_probe requires a supported 64-bit Linux ABI"
#endif

#define SYS_futex_waitv 449
#define SYS_futex_wake 454
#define SYS_futex_wait 455
#define SYS_futex_requeue 456

#define EAGAIN 11
#define EFAULT 14
#define EINVAL 22
#define ENOSYS 38
#define ETIMEDOUT 110

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define FUTEX_WAIT 0u
#define FUTEX_WAKE 1u
#define FUTEX_FD 2u
#define FUTEX_WAKE_OP 5u
#define FUTEX_WAIT_BITSET 9u
#define FUTEX_WAKE_BITSET 10u
#define FUTEX_CLOCK_REALTIME 256u
#define FUTEX_32 2u
#define FUTEX_BITSET_MATCH_ANY UINT32_MAX
#define FUTEX_WAITV_MAX 128u

struct linux_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct futex_waitv_abi {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t reserved;
};

static uint32_t words[2] __attribute__((aligned(8))) = {7u, 0u};

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

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
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
    putstr(name);
    putstr(" result=");
    putdec(actual);
    if (actual == expected) {
        putstr(" PASS\n");
        return 0;
    }
    putstr(" expected=");
    putdec(expected);
    putstr(" FAIL\n");
    return 1;
}

static long classic_futex(void *address, uint32_t operation, uint64_t value,
                          const struct linux_timespec *timeout,
                          void *second_address, uint32_t value3) {
    return raw_syscall6(SYS_futex, (long)address, operation, (long)value,
                        (long)timeout, (long)second_address, value3);
}

static int test_classic_futex(void) {
    struct linux_timespec invalid = {0, 1000000000LL};
    struct linux_timespec expired = {0, 0};
    uint32_t shift_31_set_equal = (8u << 28) | (31u << 12);
    int failures = 0;

    failures += expect_result("classic_misaligned",
        classic_futex((char *)&words[0] + 1, FUTEX_WAKE, 1, 0, 0, 0),
        -EINVAL);
    failures += expect_result("classic_inaccessible",
        classic_futex(0, FUTEX_WAKE, 1, 0, 0, 0), -EFAULT);
    failures += expect_result("classic_unsupported",
        classic_futex(&words[0], FUTEX_FD, 0, 0, 0, 0), -ENOSYS);
    failures += expect_result("classic_wait_mismatch",
        classic_futex(&words[0], FUTEX_WAIT, 0, 0, 0, 0), -EAGAIN);
    failures += expect_result("classic_wait_zero_bitset",
        classic_futex(&words[0], FUTEX_WAIT_BITSET, 7, 0, 0, 0), -EINVAL);
    failures += expect_result("classic_wake_zero_bitset",
        classic_futex(&words[0], FUTEX_WAKE_BITSET, 1, 0, 0, 0), -EINVAL);
    failures += expect_result("classic_wake_max_count",
        classic_futex(&words[0], FUTEX_WAKE, UINT32_MAX, 0, 0, 0), 0);
    words[1] = 0;
    failures += expect_result("classic_wake_op_shift31",
        classic_futex(&words[0], FUTEX_WAKE_OP, 0, 0, &words[1],
                      shift_31_set_equal), 0);
    failures += expect_result("classic_wake_op_shift31_value",
        words[1], UINT32_C(0x80000000));
    words[0] = 0;
    failures += expect_result("classic_invalid_timeout",
        classic_futex(&words[0], FUTEX_WAIT, 0, &invalid, 0, 0), -EINVAL);
    failures += expect_result("classic_expired_timeout",
        classic_futex(&words[0], FUTEX_WAIT_BITSET, 0, &expired, 0,
                      FUTEX_BITSET_MATCH_ANY), -ETIMEDOUT);
    failures += expect_result("classic_realtime_wait",
        classic_futex(&words[0], FUTEX_WAIT | FUTEX_CLOCK_REALTIME,
                      1, 0, 0, 0), -ENOSYS);
    words[0] = 7;
    words[1] = 0;
    return failures;
}

static long wait_vector(struct futex_waitv_abi *waiters, uint32_t count,
                        uint32_t flags,
                        const struct linux_timespec *timeout,
                        int clock_id) {
    return raw_syscall6(SYS_futex_waitv, (long)waiters, count, flags,
                        (long)timeout, clock_id, 0);
}

static int test_wait_vector(void) {
    struct futex_waitv_abi waiter = {
        0, (uint64_t)(uintptr_t)&words[0], FUTEX_32, 0
    };
    int failures = 0;

    failures += expect_result("waitv_top_flags",
        wait_vector(&waiter, 1, 1, 0, CLOCK_MONOTONIC), -EINVAL);
    failures += expect_result("waitv_zero_count",
        wait_vector(&waiter, 0, 0, 0, CLOCK_MONOTONIC), -EINVAL);
    failures += expect_result("waitv_large_count",
        wait_vector(&waiter, FUTEX_WAITV_MAX + 1u, 0, 0,
                    CLOCK_MONOTONIC), -EINVAL);
    failures += expect_result("waitv_null_vector",
        wait_vector(0, 1, 0, 0, CLOCK_MONOTONIC), -EINVAL);
    failures += expect_result("waitv_clock_without_timeout",
        wait_vector(&waiter, 1, 0, 0, -1), -EAGAIN);
    waiter.reserved = 1;
    failures += expect_result("waitv_reserved",
        wait_vector(&waiter, 1, 0, 0, CLOCK_MONOTONIC), -EINVAL);
    waiter.reserved = 0;
    waiter.flags = 0;
    failures += expect_result("waitv_missing_size",
        wait_vector(&waiter, 1, 0, 0, CLOCK_MONOTONIC), -EINVAL);
    waiter.flags = FUTEX_32 | 0x400u;
    failures += expect_result("waitv_unknown_flags",
        wait_vector(&waiter, 1, 0, 0, CLOCK_MONOTONIC), -EINVAL);
    waiter.flags = FUTEX_32;
    waiter.val = UINT64_C(0x100000000);
    failures += expect_result("waitv_value_width",
        wait_vector(&waiter, 1, 0, 0, CLOCK_MONOTONIC), -EINVAL);
    waiter.val = 0;
    waiter.uaddr = (uint64_t)(uintptr_t)((char *)&words[0] + 1);
    failures += expect_result("waitv_misaligned",
        wait_vector(&waiter, 1, 0, 0, CLOCK_MONOTONIC), -EINVAL);
    waiter.uaddr = (uint64_t)(uintptr_t)&words[0];
    failures += expect_result("waitv_mismatch",
        wait_vector(&waiter, 1, 0, 0, CLOCK_MONOTONIC), -EAGAIN);
    return failures;
}

static int test_split_futex(void) {
    struct futex_waitv_abi requeue[2] = {
        {7, (uint64_t)(uintptr_t)&words[0], FUTEX_32, 0},
        {0, (uint64_t)(uintptr_t)&words[1], FUTEX_32, 0},
    };
    int failures = 0;

    failures += expect_result("split_wake_empty",
        raw_syscall6(SYS_futex_wake, (long)&words[0],
                     FUTEX_BITSET_MATCH_ANY, 1, FUTEX_32, 0, 0), 0);
    failures += expect_result("split_wake_misaligned",
        raw_syscall6(SYS_futex_wake, (long)((char *)&words[0] + 1),
                     FUTEX_BITSET_MATCH_ANY, 1, FUTEX_32, 0, 0), -EINVAL);
    failures += expect_result("split_wake_zero_mask",
        raw_syscall6(SYS_futex_wake, (long)&words[0], 0, 1,
                     FUTEX_32, 0, 0), -EINVAL);
    failures += expect_result("split_wake_missing_size",
        raw_syscall6(SYS_futex_wake, (long)&words[0],
                     FUTEX_BITSET_MATCH_ANY, 1, 0, 0, 0), -EINVAL);
    failures += expect_result("split_wait_mismatch",
        raw_syscall6(SYS_futex_wait, (long)&words[0], 0,
                     FUTEX_BITSET_MATCH_ANY, FUTEX_32, 0,
                     CLOCK_MONOTONIC), -EAGAIN);
    failures += expect_result("split_wait_zero_mask",
        raw_syscall6(SYS_futex_wait, (long)&words[0], 7, 0,
                     FUTEX_32, 0, CLOCK_MONOTONIC), -EINVAL);
    failures += expect_result("split_clock_without_timeout",
        raw_syscall6(SYS_futex_wait, (long)&words[0], 0,
                     FUTEX_BITSET_MATCH_ANY, FUTEX_32, 0, -1), -EAGAIN);
    failures += expect_result("split_requeue_top_flags",
        raw_syscall6(SYS_futex_requeue, (long)requeue, 1,
                     0, 0, 0, 0), -EINVAL);
    requeue[0].reserved = 1;
    failures += expect_result("split_requeue_reserved",
        raw_syscall6(SYS_futex_requeue, (long)requeue, 0,
                     0, 0, 0, 0), -EINVAL);
    requeue[0].reserved = 0;
    requeue[0].val = 0;
    failures += expect_result("split_requeue_mismatch",
        raw_syscall6(SYS_futex_requeue, (long)requeue, 0,
                     0, 0, 0, 0), -EAGAIN);
    requeue[0].val = 7;
    failures += expect_result("split_requeue_empty",
        raw_syscall6(SYS_futex_requeue, (long)requeue, 0,
                     0, 1, 0, 0), 0);
    return failures;
}

static int run_probe(void) {
    int failures = 0;
    failures += test_classic_futex();
    failures += test_wait_vector();
    failures += test_split_futex();
    putstr(failures ? "FUTEX_ABI_PROBE_FAIL failures=" :
                      "FUTEX_ABI_PROBE_PASS failures=");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    long status = run_probe();
    (void)raw_syscall6(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {}
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ __volatile__(
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
