/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux namespace syscall ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_access 21
#define SYS_uname 63
#define SYS_exit 60
#define SYS_setuid 105
#define SYS_sethostname 170
#define SYS_openat 257
#define SYS_unshare 272
#define SYS_setns 308
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_close 57
#define SYS_faccessat 48
#define SYS_openat 56
#define SYS_exit 93
#define SYS_unshare 97
#define SYS_setuid 146
#define SYS_uname 160
#define SYS_sethostname 161
#define SYS_setns 268
#else
#error "namespace_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EPERM 1
#define EINVAL 22

#define AT_FDCWD -100
#define O_RDONLY 0
#define O_CLOEXEC 0x80000
#define F_OK 0

#define CLONE_FS 0x00000200u
#define CLONE_FILES 0x00000400u
#define CLONE_NEWUTS 0x04000000u
#define CLONE_NEWNET 0x40000000u

struct utsname_buffer {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
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
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static int text_equal(const char *left, const char *right) {
    unsigned long index = 0;
    while (left[index] && left[index] == right[index]) ++index;
    return left[index] == right[index];
}

static void bytes_zero(void *destination, unsigned long size) {
    unsigned char *bytes = destination;
    while (size) bytes[--size] = 0;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char digits[24];
    unsigned long magnitude;
    int position = (int)sizeof(digits);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&digits[position],
                       (long)(sizeof(digits) - (unsigned long)position),
                       0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static long open_path(const char *path) {
    return raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                        O_RDONLY | O_CLOEXEC, 0, 0, 0);
}

static long access_path(const char *path) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_access, (long)path, F_OK, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_faccessat, AT_FDCWD, (long)path, F_OK,
                        0, 0, 0);
#endif
}

static int run_tests(void) {
    static const char namespace_path[] = "/proc/self/ns/uts";
    static const char regular_path[] = "/dev/null";
    static const char new_hostname[] = "edgeos-ns-probe";
    struct utsname_buffer original_name;
    struct utsname_buffer current_name;
    long namespace_fd;
    long regular_fd;
    int failures = 0;

    bytes_zero(&original_name, sizeof(original_name));
    failures += expect_result("uname original",
        raw_syscall6(SYS_uname, (long)&original_name, 0, 0, 0, 0, 0), 0);
    failures += expect_result("unshare zero",
        raw_syscall6(SYS_unshare, 0, 0, 0, 0, 0, 0), 0);
    failures += expect_result("unshare fs",
        raw_syscall6(SYS_unshare, CLONE_FS, 0, 0, 0, 0, 0), 0);
    failures += expect_result("unshare files",
        raw_syscall6(SYS_unshare, CLONE_FILES, 0, 0, 0, 0, 0), 0);
    failures += expect_result("unshare invalid flag",
        raw_syscall6(SYS_unshare, (long)(1ull << 63), 0, 0, 0, 0, 0),
        -EINVAL);
    failures += expect_result("setns invalid descriptor",
        raw_syscall6(SYS_setns, -1, 0, 0, 0, 0, 0), -EBADF);
    failures += expect_result("access namespace descriptor path",
        access_path(namespace_path), 0);

    regular_fd = open_path(regular_path);
    failures += expect_true("open regular descriptor", regular_fd >= 0);
    if (regular_fd >= 0) {
        failures += expect_result("setns regular descriptor",
            raw_syscall6(SYS_setns, regular_fd, 0, 0, 0, 0, 0), -EINVAL);
        (void)raw_syscall6(SYS_close, regular_fd, 0, 0, 0, 0, 0);
    }

    namespace_fd = open_path(namespace_path);
    failures += expect_true("open namespace descriptor", namespace_fd >= 0);
    if (namespace_fd >= 0) {
        failures += expect_result("setns type mismatch",
            raw_syscall6(SYS_setns, namespace_fd, CLONE_NEWNET,
                         0, 0, 0, 0), -EINVAL);
        failures += expect_result("unshare uts",
            raw_syscall6(SYS_unshare, CLONE_NEWUTS, 0, 0, 0, 0, 0), 0);
        failures += expect_result("set hostname",
            raw_syscall6(SYS_sethostname, (long)new_hostname,
                         sizeof(new_hostname) - 1u, 0, 0, 0, 0), 0);
        bytes_zero(&current_name, sizeof(current_name));
        failures += expect_result("uname isolated",
            raw_syscall6(SYS_uname, (long)&current_name, 0, 0, 0, 0, 0), 0);
        failures += expect_true("isolated hostname",
                                text_equal(current_name.nodename,
                                           new_hostname));
        failures += expect_result("setns restore",
            raw_syscall6(SYS_setns, namespace_fd, CLONE_NEWUTS,
                         0, 0, 0, 0), 0);
        bytes_zero(&current_name, sizeof(current_name));
        failures += expect_result("uname restored",
            raw_syscall6(SYS_uname, (long)&current_name, 0, 0, 0, 0, 0), 0);
        failures += expect_true("restored hostname",
                                text_equal(current_name.nodename,
                                           original_name.nodename));
    }

    failures += expect_result("drop privilege",
        raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0), 0);
    if (namespace_fd >= 0) {
        failures += expect_result("setns requires capability",
            raw_syscall6(SYS_setns, namespace_fd, CLONE_NEWUTS,
                         0, 0, 0, 0), -EPERM);
        (void)raw_syscall6(SYS_close, namespace_fd, 0, 0, 0, 0, 0);
    }
    failures += expect_result("unshare requires capability",
        raw_syscall6(SYS_unshare, CLONE_NEWUTS, 0, 0, 0, 0, 0), -EPERM);

    if (!failures) print_text("NAMESPACE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
