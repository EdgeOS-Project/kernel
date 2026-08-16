/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux ptrace ABI test shared by both 64-bit ports.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_ptrace 101
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_ptrace 117
#define SYS_kill 129
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "ptrace_abi_probe requires a Linux 64-bit architecture"
#endif

#define PTRACE_TRACEME 0
#define PTRACE_PEEKDATA 2
#define PTRACE_POKEDATA 5
#define PTRACE_CONT 7
#define PTRACE_KILL 8
#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207

#define SIGTRAP 5
#define SIGKILL 9
#define SIGCHLD 17
#define SIGSTOP 19

struct linux_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

static volatile uint64_t g_trace_word = UINT64_C(0x11223344556677);

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
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void puthex(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char buffer[18];
    int index;

    buffer[0] = '0';
    buffer[1] = 'x';
    for (index = 0; index < 16; ++index)
        buffer[index + 2] =
            digits[(value >> ((15 - index) * 4)) & 0xfu];
    (void)raw_syscall6(SYS_write, 1, (long)buffer, sizeof(buffer), 0, 0, 0);
}

static int expect_value(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": actual=");
    puthex((uint64_t)actual);
    putstr(" expected=");
    puthex((uint64_t)expected);
    putstr("\n");
    return 1;
}

static int wait_for_pid(long pid, int *status) {
    long result = raw_syscall4(SYS_wait4, pid, (long)status, 0, 0);
    return result == pid ? 0 : 1;
}

static int status_is_stopped(int status, int signal) {
    return (status & 0xff) == 0x7f &&
           ((status >> 8) & 0xff) == signal;
}

static int status_is_exit(int status, int code) {
    return (status & 0x7f) == 0 &&
           ((status >> 8) & 0xff) == code;
}

static int status_is_signal(int status, int signal) {
    return (status & 0x7f) == signal;
}

static void paused_child(void) {
    struct linux_timespec delay = {60, 0};
    for (;;) (void)raw_syscall2(SYS_nanosleep, (long)&delay, 0);
}

static long spawn_paused_child(void) {
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) {
        paused_child();
        (void)raw_syscall1(SYS_exit, 99);
        for (;;) {}
    }
    return child;
}

static int test_traceme_memory_and_resume(void) {
    static const uint64_t replacement = UINT64_C(0x77665544332211);
    uint64_t peeked = 0;
    int status = 0;
    int failures = 0;
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);

    if (!child) {
        long result = raw_syscall4(
            SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
        if (result < 0)
            (void)raw_syscall1(SYS_exit, 20);
        (void)raw_syscall2(
            SYS_kill, raw_syscall1(SYS_getpid, 0), SIGSTOP);
        (void)raw_syscall1(
            SYS_exit, g_trace_word == replacement ? 0 : 21);
        for (;;) {}
    }
    failures += expect_value("traceme child", child > 0, 1);
    failures += expect_value("traceme wait", wait_for_pid(child, &status), 0);
    failures += expect_value(
        "traceme stop", status_is_stopped(status, SIGSTOP), 1);
    failures += expect_value(
        "peek data result",
        raw_syscall4(SYS_ptrace, PTRACE_PEEKDATA, child,
                     (long)&g_trace_word, (long)&peeked),
        0);
    failures += expect_value(
        "peek data value", (long)peeked, (long)g_trace_word);
    failures += expect_value(
        "poke data",
        raw_syscall4(SYS_ptrace, PTRACE_POKEDATA, child,
                     (long)&g_trace_word, (long)replacement),
        0);
    failures += expect_value(
        "continue",
        raw_syscall4(SYS_ptrace, PTRACE_CONT, child, 0, 0), 0);
    failures += expect_value("continue wait", wait_for_pid(child, &status), 0);
    failures += expect_value("continue exit", status_is_exit(status, 0), 1);
    return failures;
}

static int test_attach_and_detach(void) {
    int status = 0;
    int failures = 0;
    long child = spawn_paused_child();

    failures += expect_value("attach child", child > 0, 1);
    failures += expect_value(
        "attach", raw_syscall4(SYS_ptrace, PTRACE_ATTACH, child, 0, 0), 0);
    failures += expect_value("attach wait", wait_for_pid(child, &status), 0);
    failures += expect_value(
        "attach stop", status_is_stopped(status, SIGSTOP), 1);
    failures += expect_value(
        "detach", raw_syscall4(SYS_ptrace, PTRACE_DETACH, child, 0, 0), 0);
    failures += expect_value(
        "detach kill", raw_syscall2(SYS_kill, child, SIGKILL), 0);
    failures += expect_value("detach reap", wait_for_pid(child, &status), 0);
    failures += expect_value(
        "detach signal", status_is_signal(status, SIGKILL), 1);
    return failures;
}

static int test_seize_interrupt_and_kill(void) {
    int status = 0;
    int failures = 0;
    long child = spawn_paused_child();

    failures += expect_value("seize child", child > 0, 1);
    failures += expect_value(
        "seize", raw_syscall4(SYS_ptrace, PTRACE_SEIZE, child, 0, 0), 0);
    failures += expect_value(
        "interrupt",
        raw_syscall4(SYS_ptrace, PTRACE_INTERRUPT, child, 0, 0), 0);
    failures += expect_value("interrupt wait", wait_for_pid(child, &status), 0);
    failures += expect_value(
        "interrupt stop", status_is_stopped(status, SIGTRAP), 1);
    failures += expect_value(
        "ptrace kill",
        raw_syscall4(SYS_ptrace, PTRACE_KILL, child, 0, 0), 0);
    failures += expect_value("ptrace kill reap", wait_for_pid(child, &status), 0);
    failures += expect_value(
        "ptrace kill signal", status_is_signal(status, SIGKILL), 1);
    return failures;
}

__attribute__((noreturn)) void _start(void) {
    int failures = 0;

    putstr("PTRACE_ABI_STAGE traceme-memory-resume\n");
    failures += test_traceme_memory_and_resume();
    putstr("PTRACE_ABI_STAGE attach-detach\n");
    failures += test_attach_and_detach();
    putstr("PTRACE_ABI_STAGE seize-interrupt-kill\n");
    failures += test_seize_interrupt_and_kill();
    if (failures)
        putstr("PTRACE_ABI_PROBE_FAIL\n");
    else
        putstr("PTRACE_ABI_PROBE_PASS\n");
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) {}
}
