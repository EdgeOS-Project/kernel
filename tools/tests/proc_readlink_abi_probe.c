/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS freestanding Linux procfs readlink ABI probe.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_readlinkat 267
#define SYS_exit 60
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_write 64
#define SYS_readlinkat 78
#define SYS_exit 93
#else
#error "proc_readlink_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define EFAULT 14
#define EINVAL 22
#define ENOENT 2

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
    (void)raw_syscall3(
        SYS_write, 1, (long)text, (long)text_length(text));
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
    do {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude && position);
    (void)raw_syscall3(
        SYS_write, 1, (long)&buffer[position],
        (long)(sizeof(buffer) - (unsigned)position));
}

static long call_readlink(const char *path, char *target,
                          unsigned long capacity) {
    return raw_syscall6(
        SYS_readlinkat, AT_FDCWD, (long)path, (long)target,
        (long)capacity, 0, 0);
}

static int text_has_prefix(const char *text, long length,
                           const char *prefix) {
    long index = 0;
    if (length < 0) return 0;
    while (prefix[index]) {
        if (index >= length || text[index] != prefix[index]) return 0;
        ++index;
    }
    return 1;
}

static int text_has_component(const char *text, long length,
                              const char *component) {
    long start;
    for (start = 0; start < length; ++start) {
        long index = 0;
        while (component[index] && start + index < length &&
               text[start + index] == component[index])
            ++index;
        if (!component[index]) return 1;
    }
    return 0;
}

static int decimal_text(const char *text, long length) {
    if (length <= 0) return 0;
    for (long index = 0; index < length; ++index)
        if (text[index] < '0' || text[index] > '9') return 0;
    return 1;
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

static int descriptor_path(char *path, unsigned long capacity,
                           const char *prefix, int descriptor) {
    char reversed[16];
    unsigned long position = 0;
    unsigned long digits = 0;
    unsigned int value = (unsigned int)descriptor;

    while (prefix[position]) {
        if (position + 1u >= capacity) return -1;
        path[position] = prefix[position];
        ++position;
    }
    do {
        reversed[digits++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && digits < sizeof(reversed));
    while (digits) {
        if (position + 1u >= capacity) return -1;
        path[position++] = reversed[--digits];
    }
    path[position] = 0;
    return 0;
}

static int run_probe(void) {
    char target[128];
    char path[64];
    int descriptors[2] = {-1, -1};
    long result;
    int failures = 0;

    result = call_readlink("/proc/self", target, sizeof(target));
    if (!decimal_text(target, result)) {
        putstr("proc_self_alias\n");
        ++failures;
    }
    result = call_readlink("/proc/thread-self", target, sizeof(target));
    if (!text_has_component(target, result, "/task/")) {
        putstr("proc_thread_self_alias\n");
        ++failures;
    }
    result = call_readlink("/proc/self/exe", target, sizeof(target));
    if (result <= 0 || target[0] != '/') {
        putstr("proc_self_exe\n");
        ++failures;
    }
    result = call_readlink("/proc/self/cwd", target, sizeof(target));
    if (result <= 0 || target[0] != '/') {
        putstr("proc_self_cwd\n");
        ++failures;
    }
    result = call_readlink("/proc/self/root", target, sizeof(target));
    if (result != 1 || target[0] != '/') {
        putstr("proc_self_root\n");
        ++failures;
    }
    result = call_readlink("/proc/self/exe", target, 4);
    failures += expect_result("proc_self_exe_truncated", result, 4);

    failures += expect_result(
        "pipe2", raw_syscall2(SYS_pipe2, (long)descriptors, 0), 0);
    if (descriptors[0] >= 0 &&
        descriptor_path(path, sizeof(path), "/proc/self/fd/",
                        descriptors[0]) == 0) {
        result = call_readlink(path, target, sizeof(target));
        if (!text_has_prefix(target, result, "pipe:[") ||
            result < 2 || target[result - 1] != ']') {
            putstr("proc_pipe_target\n");
            ++failures;
        }
    } else {
        putstr("proc_pipe_path\n");
        ++failures;
    }
    if (descriptors[0] >= 0 &&
        descriptor_path(path, sizeof(path), "/dev/fd/",
                        descriptors[0]) == 0) {
        result = call_readlink(path, target, sizeof(target));
        if (!text_has_prefix(target, result, "pipe:[")) {
            putstr("dev_fd_pipe_target\n");
            ++failures;
        }
    }

    failures += expect_result(
        "missing_descriptor",
        call_readlink("/proc/self/fd/999999", target, sizeof(target)),
        -ENOENT);
    failures += expect_result(
        "regular_file", call_readlink("/dev/null", target,
                                      sizeof(target)), -EINVAL);
    failures += expect_result(
        "zero_capacity", call_readlink("/proc/self", target, 0),
        -EINVAL);
    failures += expect_result(
        "null_target", call_readlink("/proc/self", 0, 1), -EFAULT);

    if (descriptors[0] >= 0)
        (void)raw_syscall1(SYS_close, descriptors[0]);
    if (descriptors[1] >= 0)
        (void)raw_syscall1(SYS_close, descriptors[1]);
    putstr(failures ? "PROC_READLINK_ABI_FAIL failures: " :
                      "PROC_READLINK_ABI_PASS failures: ");
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
