/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for getrlimit(2), setrlimit(2), and
 * prlimit64(2).  This intentionally avoids libc so the same executable model
 * can validate musl guests and a native Linux reference system.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_getrlimit 97
#define SYS_setrlimit 160
#define SYS_prlimit64 302
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_getrlimit 163
#define SYS_setrlimit 164
#define SYS_prlimit64 261
#else
#error "resource_limit_runtime_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22
#define ESRCH 3

#define RLIMIT_STACK 3
#define RLIMIT_NOFILE 7

typedef struct linux_rlimit64 {
    uint64_t current;
    uint64_t maximum;
} linux_rlimit64_t;

_Static_assert(sizeof(linux_rlimit64_t) == 16,
               "Linux 64-bit rlimit layout");

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
    (void)raw_syscall4(SYS_write, 1, (long)text,
                       (long)text_length(text), 0);
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
    (void)raw_syscall4(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned)position), 0);
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

static int limits_equal(const linux_rlimit64_t *left,
                        const linux_rlimit64_t *right) {
    return left->current == right->current &&
           left->maximum == right->maximum;
}

static uint64_t lower_soft_limit(uint64_t value) {
    if (value == UINT64_MAX || value > 65536u) return 65536u;
    return value > 1u ? value - 1u : value;
}

static int run_probe(void) {
    linux_rlimit64_t nofile;
    linux_rlimit64_t nofile_prlimit;
    linux_rlimit64_t stack;
    linux_rlimit64_t replacement;
    linux_rlimit64_t after;
    int failures = 0;

    failures += expect_result("getrlimit_nofile",
        raw_syscall2(SYS_getrlimit, RLIMIT_NOFILE, (long)&nofile), 0);
    failures += expect_true("nofile_order",
        nofile.current <= nofile.maximum && nofile.maximum != 0);
    failures += expect_result("prlimit64_nofile",
        raw_syscall4(SYS_prlimit64, 0, RLIMIT_NOFILE, 0,
                     (long)&nofile_prlimit), 0);
    failures += expect_true("getrlimit_prlimit_match",
                            limits_equal(&nofile, &nofile_prlimit));

    failures += expect_result("getrlimit_invalid_resource",
        raw_syscall2(SYS_getrlimit, 16, (long)&nofile), -EINVAL);
    failures += expect_result("getrlimit_null_output",
        raw_syscall2(SYS_getrlimit, RLIMIT_NOFILE, 0), -EFAULT);
    failures += expect_result("prlimit64_negative_pid",
        raw_syscall4(SYS_prlimit64, -1, RLIMIT_NOFILE, 0,
                     (long)&nofile), -ESRCH);

    failures += expect_result("getrlimit_stack",
        raw_syscall2(SYS_getrlimit, RLIMIT_STACK, (long)&stack), 0);
    replacement = stack;
    replacement.current = lower_soft_limit(stack.current);
    failures += expect_result("setrlimit_stack",
        raw_syscall2(SYS_setrlimit, RLIMIT_STACK, (long)&replacement), 0);
    failures += expect_result("getrlimit_stack_after_set",
        raw_syscall2(SYS_getrlimit, RLIMIT_STACK, (long)&after), 0);
    failures += expect_true("setrlimit_persists",
                            limits_equal(&replacement, &after));

    replacement.current = lower_soft_limit(after.current);
    failures += expect_result("prlimit64_copyout_fault",
        raw_syscall4(SYS_prlimit64, 0, RLIMIT_STACK,
                     (long)&replacement, 1), -EFAULT);
    failures += expect_result("getrlimit_after_copyout_fault",
        raw_syscall2(SYS_getrlimit, RLIMIT_STACK, (long)&after), 0);
    failures += expect_true("prlimit64_update_precedes_copyout",
                            limits_equal(&replacement, &after));

    putstr(failures ?
        "RESOURCE_LIMIT_RUNTIME_PROBE_FAIL failures: " :
        "RESOURCE_LIMIT_RUNTIME_PROBE_PASS failures: ");
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
