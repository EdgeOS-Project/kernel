/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux scheduler ABI probe shared by x86_64 and AArch64.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_sched_yield 24
#define SYS_exit 60
#define SYS_sched_setparam 142
#define SYS_sched_getparam 143
#define SYS_sched_setscheduler 144
#define SYS_sched_getscheduler 145
#define SYS_sched_setaffinity 203
#define SYS_sched_getaffinity 204
#define SYS_sched_setattr 314
#define SYS_sched_getattr 315
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_sched_setparam 118
#define SYS_sched_setscheduler 119
#define SYS_sched_getscheduler 120
#define SYS_sched_getparam 121
#define SYS_sched_setaffinity 122
#define SYS_sched_getaffinity 123
#define SYS_sched_yield 124
#define SYS_sched_setattr 274
#define SYS_sched_getattr 275
#else
#error "scheduler_runtime_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22

#define SCHED_OTHER 0
#define SCHED_BATCH 3

typedef struct linux_sched_param {
    int32_t priority;
} linux_sched_param_t;

typedef struct linux_sched_attr {
    uint32_t size;
    uint32_t policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime;
    uint64_t deadline;
    uint64_t period;
    uint32_t util_min;
    uint32_t util_max;
} linux_sched_attr_t;

_Static_assert(sizeof(linux_sched_param_t) == 4,
               "Linux scheduler parameter layout");
_Static_assert(sizeof(linux_sched_attr_t) == 56,
               "Linux scheduler attribute version one layout");

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = (unsigned char *)destination;
    while (length--) *bytes++ = (unsigned char)value;
    return destination;
}

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
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
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

static int run_probe(void) {
    linux_sched_param_t parameter = {0};
    linux_sched_attr_t attribute = {0};
    uint64_t affinity = 0;
    uint64_t selected;
    int failures = 0;

    putstr("scheduler_probe: affinity\n");
    failures += expect_result("sched_getaffinity",
        raw_syscall3(SYS_sched_getaffinity, 0, sizeof(affinity),
                     (long)&affinity), sizeof(affinity));
    putstr("scheduler_probe: affinity-read\n");
    failures += expect_true("sched_getaffinity_nonzero", affinity != 0);
    selected = affinity & (~affinity + 1u);
    failures += expect_result("sched_setaffinity",
        raw_syscall3(SYS_sched_setaffinity, 0, sizeof(selected),
                     (long)&selected), 0);
    putstr("scheduler_probe: affinity-set\n");
    affinity = 0;
    failures += expect_result("sched_getaffinity_after_set",
        raw_syscall3(SYS_sched_getaffinity, 0, sizeof(affinity),
                     (long)&affinity), sizeof(affinity));
    putstr("scheduler_probe: affinity-reread\n");
    failures += expect_true("sched_affinity_persists",
                            affinity == selected);
    affinity = 0;
    failures += expect_result("sched_setaffinity_zero",
        raw_syscall3(SYS_sched_setaffinity, 0, sizeof(affinity),
                     (long)&affinity), -EINVAL);
    failures += expect_result("sched_getaffinity_null",
        raw_syscall3(SYS_sched_getaffinity, 0, sizeof(affinity), 0),
        -EFAULT);

    putstr("scheduler_probe: parameters\n");
    failures += expect_result("sched_getparam",
        raw_syscall2(SYS_sched_getparam, 0, (long)&parameter), 0);
    failures += expect_true("sched_getparam_priority",
                            parameter.priority == 0);
    failures += expect_result("sched_setparam",
        raw_syscall2(SYS_sched_setparam, 0, (long)&parameter), 0);
    failures += expect_result("sched_setscheduler_batch",
        raw_syscall3(SYS_sched_setscheduler, 0, SCHED_BATCH,
                     (long)&parameter), 0);
    failures += expect_result("sched_getscheduler_batch",
        raw_syscall1(SYS_sched_getscheduler, 0), SCHED_BATCH);
    failures += expect_result("sched_setscheduler_other",
        raw_syscall3(SYS_sched_setscheduler, 0, SCHED_OTHER,
                     (long)&parameter), 0);
    failures += expect_result("sched_getscheduler_other",
        raw_syscall1(SYS_sched_getscheduler, 0), SCHED_OTHER);
    failures += expect_result("sched_getparam_null",
        raw_syscall2(SYS_sched_getparam, 0, 0), -EINVAL);

    putstr("scheduler_probe: attributes\n");
    attribute.size = sizeof(attribute);
    failures += expect_result("sched_getattr",
        raw_syscall5(SYS_sched_getattr, 0, (long)&attribute,
                     sizeof(attribute), 0, 0), 0);
    failures += expect_true("sched_getattr_state",
        attribute.size >= sizeof(attribute) &&
        attribute.policy == SCHED_OTHER && attribute.priority == 0);
    attribute.nice = attribute.nice < 19 ? attribute.nice + 1 : 19;
    failures += expect_result("sched_setattr_nice",
        raw_syscall3(SYS_sched_setattr, 0, (long)&attribute, 0), 0);
    {
        linux_sched_attr_t observed = {0};
        observed.size = sizeof(observed);
        failures += expect_result("sched_getattr_after_set",
            raw_syscall5(SYS_sched_getattr, 0, (long)&observed,
                         sizeof(observed), 0, 0), 0);
        failures += expect_true("sched_setattr_nice_persists",
                                observed.nice == attribute.nice);
    }
    putstr("scheduler_probe: yield\n");
    failures += expect_result("sched_yield",
                              raw_syscall1(SYS_sched_yield, 0), 0);

    putstr(failures ?
        "SCHEDULER_RUNTIME_PROBE_FAIL failures: " :
        "SCHEDULER_RUNTIME_PROBE_PASS failures: ");
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
