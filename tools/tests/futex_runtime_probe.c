/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS freestanding Linux futex runtime parity test.
 * Copyright (c) EdgeOS Contributors.
 *
 * The validation probe covers argument policy.  This probe creates a second
 * task sharing the caller's address space and verifies the queueing, wakeup,
 * vector-index, and requeue state transitions used by real thread libraries.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_sched_yield 24
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_futex 202
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_sched_yield 124
#define SYS_kill 129
#define SYS_futex 98
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "futex_runtime_probe requires a supported 64-bit Linux ABI"
#endif

#define SYS_futex_waitv 449
#define SYS_futex_wake 454
#define SYS_futex_wait 455
#define SYS_futex_requeue 456

#define SIGKILL 9
#define SIGCHLD 17
#define CLONE_VM 0x00000100u
#define FUTEX_WAIT_PRIVATE 128u
#define FUTEX_WAKE_PRIVATE 129u
#define FUTEX_32 2u
#define FUTEX_PRIVATE_FLAG 128u
#define FUTEX_BITSET_MATCH_ANY UINT32_MAX

#define CHILD_CLASSIC 1u
#define CHILD_WAIT_VECTOR 2u
#define CHILD_SPLIT 3u
#define CHILD_REQUEUE 4u
#define SCHEDULE_LIMIT 200000u

struct futex_waitv_abi {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t reserved;
};

static uint8_t child_stack[16384] __attribute__((aligned(16)));
static volatile uint32_t source_word;
static volatile uint32_t destination_word;
static volatile uint32_t child_mode;
static volatile uint32_t child_phase;
static volatile int64_t child_result;

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

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, 0, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
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

static __attribute__((noreturn)) void exit_now(int status) {
    (void)raw_syscall1(SYS_exit, status);
    for (;;) {}
}

static uint32_t load_phase(void) {
    return __atomic_load_n(&child_phase, __ATOMIC_ACQUIRE);
}

static void store_phase(uint32_t phase) {
    __atomic_store_n(&child_phase, phase, __ATOMIC_RELEASE);
}

static __attribute__((noreturn, noinline, used))
void runtime_child_entry(void) {
    struct futex_waitv_abi waiters[2];
    long result;

    waiters[0].val = 0;
    waiters[0].uaddr = (uint64_t)(uintptr_t)&source_word;
    waiters[0].flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
    waiters[0].reserved = 0;
    waiters[1].val = 0;
    waiters[1].uaddr = (uint64_t)(uintptr_t)&destination_word;
    waiters[1].flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
    waiters[1].reserved = 0;

    store_phase(1);
    switch (__atomic_load_n(&child_mode, __ATOMIC_ACQUIRE)) {
    case CHILD_CLASSIC:
        result = raw_syscall6(SYS_futex, (long)&source_word,
                              FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
        break;
    case CHILD_WAIT_VECTOR:
        result = raw_syscall6(SYS_futex_waitv, (long)waiters, 2, 0, 0, 1, 0);
        break;
    case CHILD_SPLIT:
    case CHILD_REQUEUE:
        result = raw_syscall6(SYS_futex_wait, (long)&source_word, 0,
                              FUTEX_BITSET_MATCH_ANY,
                              FUTEX_32 | FUTEX_PRIVATE_FLAG, 0, 1);
        break;
    default:
        result = -1;
        break;
    }
    __atomic_store_n(&child_result, result, __ATOMIC_RELEASE);
    store_phase(2);
    exit_now(0);
}

#if defined(__x86_64__)
static __attribute__((naked, noinline)) long
spawn_runtime_child(uint64_t flags __attribute__((unused)),
                    uint64_t stack __attribute__((unused))) {
    __asm__ __volatile__(
        "xor %edx, %edx\n"
        "xor %r10d, %r10d\n"
        "xor %r8d, %r8d\n"
        "mov $56, %rax\n"
        "syscall\n"
        "test %rax, %rax\n"
        "jnz 1f\n"
        "xor %ebp, %ebp\n"
        "call runtime_child_entry\n"
        "ud2\n"
        "1: ret\n");
}
#else
static __attribute__((noinline)) long
spawn_runtime_child(uint64_t flags, uint64_t stack) {
    register uint64_t x0 __asm__("x0") = flags;
    register uint64_t x1 __asm__("x1") = stack;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    register uint64_t x4 __asm__("x4") = 0;
    register uint64_t x8 __asm__("x8") = SYS_clone;
    __asm__ __volatile__(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "mov x29, xzr\n"
        "bl runtime_child_entry\n"
        "brk #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x29", "x30", "memory", "cc");
    return (long)x0;
}
#endif

static int wait_for_phase(uint32_t expected) {
    for (uint32_t iteration = 0; iteration < SCHEDULE_LIMIT; ++iteration) {
        if (load_phase() >= expected) return 0;
        (void)raw_syscall1(SYS_sched_yield, 0);
    }
    return -1;
}

static long wake_until_queued(uint32_t mode) {
    volatile uint32_t *address = mode == CHILD_WAIT_VECTOR ?
        &destination_word : &source_word;
    for (uint32_t iteration = 0; iteration < SCHEDULE_LIMIT; ++iteration) {
        long result;
        if (mode == CHILD_CLASSIC) {
            result = raw_syscall6(SYS_futex, (long)address,
                                  FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
        } else {
            result = raw_syscall6(SYS_futex_wake, (long)address,
                                  FUTEX_BITSET_MATCH_ANY, 1,
                                  FUTEX_32 | FUTEX_PRIVATE_FLAG, 0, 0);
        }
        if (result != 0) return result;
        if (load_phase() >= 2) return 0;
        (void)raw_syscall1(SYS_sched_yield, 0);
    }
    return 0;
}

static int finish_child(const char *name, long child, int failed) {
    int status = -1;
    long waited;
    if (failed) (void)raw_syscall1(SYS_kill, child);
    waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    putstr(name);
    putstr(" child_result=");
    putdec((long)__atomic_load_n(&child_result, __ATOMIC_ACQUIRE));
    putstr(" wait_result=");
    putdec(waited);
    putstr(" status=");
    putdec(status);
    putstr(failed || waited != child || status != 0 ? " FAIL\n" : " PASS\n");
    return failed || waited != child || status != 0;
}

static int run_wake_case(uint32_t mode, const char *name,
                         long expected_child_result) {
    uint64_t stack_top = (uint64_t)(uintptr_t)
        &child_stack[sizeof(child_stack)];
    long child;
    long wake_result;
    int failed = 0;

    source_word = 0;
    destination_word = 0;
    child_result = -999;
    child_phase = 0;
    __atomic_store_n(&child_mode, mode, __ATOMIC_RELEASE);
    child = spawn_runtime_child(CLONE_VM | SIGCHLD, stack_top);
    if (child < 0) {
        putstr(name);
        putstr(" clone_result=");
        putdec(child);
        putstr(" FAIL\n");
        return 1;
    }
    if (wait_for_phase(1) < 0) failed = 1;
    wake_result = wake_until_queued(mode);
    if (wake_result != 1) failed = 1;
    if (wait_for_phase(2) < 0) failed = 1;
    if (__atomic_load_n(&child_result, __ATOMIC_ACQUIRE) !=
        expected_child_result)
        failed = 1;
    return finish_child(name, child, failed);
}

static int run_requeue_case(void) {
    struct futex_waitv_abi futexes[2];
    uint64_t stack_top = (uint64_t)(uintptr_t)
        &child_stack[sizeof(child_stack)];
    long child;
    long requeue_result = 0;
    long wake_result = 0;
    int failed = 0;

    source_word = 0;
    destination_word = 0;
    child_result = -999;
    child_phase = 0;
    __atomic_store_n(&child_mode, CHILD_REQUEUE, __ATOMIC_RELEASE);
    futexes[0].val = 0;
    futexes[0].uaddr = (uint64_t)(uintptr_t)&source_word;
    futexes[0].flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
    futexes[0].reserved = 0;
    futexes[1].val = 0;
    futexes[1].uaddr = (uint64_t)(uintptr_t)&destination_word;
    futexes[1].flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
    futexes[1].reserved = 0;

    child = spawn_runtime_child(CLONE_VM | SIGCHLD, stack_top);
    if (child < 0) {
        putstr("futex2_requeue clone_result=");
        putdec(child);
        putstr(" FAIL\n");
        return 1;
    }
    if (wait_for_phase(1) < 0) failed = 1;
    for (uint32_t iteration = 0;
         !failed && iteration < SCHEDULE_LIMIT; ++iteration) {
        requeue_result = raw_syscall4(
            SYS_futex_requeue, (long)futexes, 0, 0, 1);
        if (requeue_result != 0) break;
        (void)raw_syscall1(SYS_sched_yield, 0);
    }
    if (requeue_result != 1) failed = 1;
    if (!failed) {
        for (uint32_t iteration = 0; iteration < SCHEDULE_LIMIT; ++iteration) {
            wake_result = raw_syscall6(
                SYS_futex_wake, (long)&destination_word,
                FUTEX_BITSET_MATCH_ANY, 1,
                FUTEX_32 | FUTEX_PRIVATE_FLAG, 0, 0);
            if (wake_result != 0) break;
            (void)raw_syscall1(SYS_sched_yield, 0);
        }
    }
    if (wake_result != 1 || wait_for_phase(2) < 0 ||
        __atomic_load_n(&child_result, __ATOMIC_ACQUIRE) != 0)
        failed = 1;
    return finish_child("futex2_requeue", child, failed);
}

static int run_probe(void) {
    int failures = 0;
    failures += run_wake_case(CHILD_CLASSIC, "classic_private_wait_wake", 0);
    failures += run_wake_case(CHILD_WAIT_VECTOR, "waitv_private_index", 1);
    failures += run_wake_case(CHILD_SPLIT, "futex2_private_wait_wake", 0);
    failures += run_requeue_case();
    putstr(failures ? "FUTEX_RUNTIME_PROBE_FAIL failures=" :
                      "FUTEX_RUNTIME_PROBE_PASS failures=");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int status = run_probe();
    exit_now(status);
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
