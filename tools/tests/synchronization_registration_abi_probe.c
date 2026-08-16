/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for robust lists, rseq, and membarrier.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_membarrier 324
#define SYS_rseq 334
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_set_robust_list 99
#define SYS_get_robust_list 100
#define SYS_membarrier 283
#define SYS_rseq 293
#else
#error "synchronization_registration_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define ESRCH 3
#define EFAULT 14
#define EBUSY 16
#define EINVAL 22

#define RSEQ_FLAG_UNREGISTER 1
#define RSEQ_SIGNATURE 0x53053053u
#define ROBUST_LIST_HEAD_SIZE 24u

#define MEMBARRIER_CMD_QUERY 0u
#define MEMBARRIER_CMD_GLOBAL (1u << 0)
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED (1u << 1)
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED (1u << 2)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED (1u << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED (1u << 4)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1u << 5)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1u << 6)
#define MEMBARRIER_CMD_GET_REGISTRATIONS (1u << 9)
#define MEMBARRIER_CMD_FLAG_CPU 1u

struct linux_rseq {
    uint32_t cpu_id_start;
    uint32_t cpu_id;
    uint64_t rseq_cs;
    uint32_t flags;
    uint32_t node_id;
    uint32_t mm_cid;
    uint32_t reserved;
} __attribute__((aligned(32)));

static struct linux_rseq rseq_area __attribute__((aligned(32)));
static uint8_t misaligned_rseq_storage[sizeof(struct linux_rseq) + 1u];

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = argument3;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall4(number, argument0, argument1, argument2, 0);
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall4(number, argument0, argument1, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall4(number, argument0, 0, 0, 0);
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

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    putstr(name);
    putstr(": false\n");
    return 1;
}

static void bytes_zero(void *pointer, uint64_t length) {
    uint8_t *bytes = (uint8_t *)pointer;
    for (uint64_t index = 0; index < length; ++index) bytes[index] = 0;
}

static long set_robust_list(uint64_t head, uint64_t length) {
    return raw_syscall2(SYS_set_robust_list, (long)head, (long)length);
}

static long get_robust_list(int32_t pid, uint64_t *head, uint64_t *length) {
    return raw_syscall3(SYS_get_robust_list, pid, (long)head, (long)length);
}

static long membarrier(uint32_t command, uint32_t flags, int32_t cpu_id) {
    return raw_syscall3(SYS_membarrier, command, flags, cpu_id);
}

static long rseq_call(struct linux_rseq *area, uint32_t length,
                      uint32_t flags, uint32_t signature) {
    return raw_syscall4(SYS_rseq, (long)area, length, flags, signature);
}

static int test_robust_list(void) {
    int failures = 0;
    uint64_t head = UINT64_MAX;
    uint64_t length = 0;

    failures += expect_result("robust_get_default",
        get_robust_list(0, &head, &length), 0);
    failures += expect_result("robust_default_head", (long)head, 0);
    failures += expect_result("robust_default_length", (long)length,
                              ROBUST_LIST_HEAD_SIZE);
    failures += expect_result("robust_set_unmapped_head",
        set_robust_list(1u, ROBUST_LIST_HEAD_SIZE), 0);
    head = 0;
    length = 0;
    failures += expect_result("robust_get_registered",
        get_robust_list(0, &head, &length), 0);
    failures += expect_result("robust_registered_head", (long)head, 1);
    failures += expect_result("robust_registered_length", (long)length,
                              ROBUST_LIST_HEAD_SIZE);
    failures += expect_result("robust_wrong_length",
        set_robust_list(0, ROBUST_LIST_HEAD_SIZE - 1u), -EINVAL);
    failures += expect_result("robust_missing_pid",
        get_robust_list(0x7fffffff, &head, &length), -ESRCH);
    failures += expect_result("robust_null_head_output",
        get_robust_list(0, 0, &length), -EFAULT);
    failures += expect_result("robust_reset",
        set_robust_list(0, ROBUST_LIST_HEAD_SIZE), 0);
    return failures;
}

static int test_rseq(void) {
    int failures = 0;
    struct linux_rseq *misaligned = (struct linux_rseq *)(
        (uintptr_t)misaligned_rseq_storage + 1u);

    bytes_zero(&rseq_area, sizeof(rseq_area));
    failures += expect_result("rseq_wrong_length",
        rseq_call(&rseq_area, sizeof(rseq_area) - 1u, 0, RSEQ_SIGNATURE),
        -EINVAL);
    failures += expect_result("rseq_misaligned",
        rseq_call(misaligned, sizeof(*misaligned), 0, RSEQ_SIGNATURE),
        -EINVAL);
    failures += expect_result("rseq_register",
        rseq_call(&rseq_area, sizeof(rseq_area), 0, RSEQ_SIGNATURE), 0);
    failures += expect_true("rseq_cpu_initialized",
        rseq_area.cpu_id != UINT32_MAX);
    failures += expect_result("rseq_duplicate",
        rseq_call(&rseq_area, sizeof(rseq_area), 0, RSEQ_SIGNATURE), -EBUSY);
    failures += expect_result("rseq_unregister_wrong_signature",
        rseq_call(&rseq_area, sizeof(rseq_area), RSEQ_FLAG_UNREGISTER,
                  RSEQ_SIGNATURE + 1u), -EPERM);
    failures += expect_result("rseq_unregister",
        rseq_call(&rseq_area, sizeof(rseq_area), RSEQ_FLAG_UNREGISTER,
                  RSEQ_SIGNATURE), 0);
    failures += expect_result("rseq_unregistered_cpu",
                              rseq_area.cpu_id, UINT32_MAX);
    failures += expect_result("rseq_unregister_twice",
        rseq_call(&rseq_area, sizeof(rseq_area), RSEQ_FLAG_UNREGISTER,
                  RSEQ_SIGNATURE), -EINVAL);
    return failures;
}

static int test_membarrier(void) {
    int failures = 0;
    long supported = membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    long registrations;

    failures += expect_true("membarrier_query", supported >= 0);
    if (supported < 0) return failures;
    failures += expect_true("membarrier_global_supported",
        (supported & MEMBARRIER_CMD_GLOBAL) != 0);
    failures += expect_result("membarrier_query_cpu_ignored",
        membarrier(MEMBARRIER_CMD_QUERY, 0, 7), supported);
    failures += expect_result("membarrier_query_bad_flags",
        membarrier(MEMBARRIER_CMD_QUERY, MEMBARRIER_CMD_FLAG_CPU, 0),
        -EINVAL);
    failures += expect_result("membarrier_combined_command",
        membarrier(MEMBARRIER_CMD_GLOBAL |
                   MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 0), -EINVAL);
    failures += expect_result("membarrier_unknown_command",
        membarrier(1u << 30, 0, 0), -EINVAL);
    failures += expect_result("membarrier_global",
        membarrier(MEMBARRIER_CMD_GLOBAL, 0, 7), 0);

    registrations = membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0);
    failures += expect_true("membarrier_get_registrations",
                            registrations >= 0);
    if (supported & MEMBARRIER_CMD_GLOBAL_EXPEDITED)
        failures += expect_result("membarrier_global_expedited_unregistered",
            membarrier(MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 0), 0);
    if (supported & MEMBARRIER_CMD_PRIVATE_EXPEDITED) {
        failures += expect_result("membarrier_private_before_register",
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0), -EPERM);
        failures += expect_result("membarrier_register_private",
            membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 5), 0);
        registrations = membarrier(
            MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0);
        failures += expect_true("membarrier_private_registration_visible",
            (registrations &
             MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED) != 0);
        failures += expect_result("membarrier_private",
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0), 0);
    }
    if (supported & MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE) {
        failures += expect_result("membarrier_sync_before_register",
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0),
            -EPERM);
        failures += expect_result("membarrier_register_sync",
            membarrier(
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
                0, 0), 0);
        failures += expect_result("membarrier_sync_core",
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0),
            0);
    }
    failures += expect_result("membarrier_registration_bad_flags",
        membarrier(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
                   MEMBARRIER_CMD_FLAG_CPU, 0), -EINVAL);
    return failures;
}

static int run_probe(void) {
    int failures = 0;
    failures += test_robust_list();
    failures += test_rseq();
    failures += test_membarrier();
    putstr(failures ?
        "SYNCHRONIZATION_REGISTRATION_ABI_PROBE_FAIL failures: " :
        "SYNCHRONIZATION_REGISTRATION_ABI_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall1(SYS_exit, run_probe());
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
