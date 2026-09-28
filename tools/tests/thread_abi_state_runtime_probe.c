/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ABI probe for per-thread personality and clear-TID state.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_personality 135
#define SYS_gettid 186
#define SYS_set_tid_address 218
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_personality 92
#define SYS_set_tid_address 96
#define SYS_gettid 178
#define SYS_exit 93
#else
#error "thread_abi_state_runtime_probe requires a Linux 64-bit architecture"
#endif

#define PERSONALITY_QUERY UINT32_MAX
#define PERSONALITY_UNAME26 0x00020000u

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    long result;
#if defined(__x86_64__)
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall3(number, argument0, 0, 0);
}

static long raw_syscall0(long number) {
    return raw_syscall3(number, 0, 0, 0);
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

static int test_personality(void) {
    long original = raw_syscall1(SYS_personality, PERSONALITY_QUERY);
    uint32_t changed;
    int failures = 0;

    if (original < 0) {
        failures += expect_result("personality_query", original, 0);
        return failures;
    }
    changed = (uint32_t)original ^ PERSONALITY_UNAME26;
    failures += expect_result("personality_set",
        raw_syscall1(SYS_personality, changed), original);
    failures += expect_result("personality_query_changed",
        raw_syscall1(SYS_personality, PERSONALITY_QUERY), changed);
    failures += expect_result("personality_restore",
        raw_syscall1(SYS_personality, original), changed);
    failures += expect_result("personality_query_restored",
        raw_syscall1(SYS_personality, PERSONALITY_QUERY), original);
    return failures;
}

static int test_set_tid_address(void) {
    static uint32_t clear_tid_word = UINT32_MAX;
    long tid = raw_syscall0(SYS_gettid);
    int failures = 0;

    failures += expect_result("set_tid_address",
        raw_syscall1(SYS_set_tid_address, (long)&clear_tid_word), tid);
    failures += expect_result("clear_tid_address",
        raw_syscall1(SYS_set_tid_address, 0), tid);
    return failures;
}

void _start(void) {
    int failures = 0;

    failures += test_personality();
    failures += test_set_tid_address();
    if (!failures)
        putstr("THREAD_ABI_STATE_RUNTIME_PROBE_PASS failures: 0\n");
    else {
        putstr("THREAD_ABI_STATE_RUNTIME_PROBE_FAIL failures: ");
        putdec(failures);
        putstr("\n");
    }
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
