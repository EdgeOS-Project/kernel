/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux memfd_create ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_fcntl 72
#define SYS_ftruncate 77
#define SYS_exit 60
#define SYS_memfd_create 319
#define SYS_statx 332
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_ftruncate 46
#define SYS_close 57
#define SYS_lseek 62
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_memfd_create 279
#define SYS_statx 291
#else
#error "memfd_create_abi_probe requires a Linux 64-bit architecture"
#endif

#define EFAULT 14
#define EINVAL 22
#define EPERM 1

#define MFD_CLOEXEC 0x0001u
#define MFD_ALLOW_SEALING 0x0002u
#define MFD_HUGE_2MB (21u << 26)

#define F_GETFD 1
#define F_GETFL 3
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define FD_CLOEXEC 1
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define O_ACCMODE 3
#define O_RDWR 2
#define SEEK_SET 0
#define AT_EMPTY_PATH 0x1000
#define STATX_MODE 0x00000002u
#define S_IFMT 0170000u
#define S_IFREG 0100000u

struct probe_statx {
    uint32_t mask;
    uint32_t block_size;
    uint64_t attributes;
    uint32_t link_count;
    uint32_t uid;
    uint32_t gid;
    uint16_t mode;
    uint16_t spare;
    uint8_t remainder[224];
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

static int run_tests(void) {
    static const char ordinary_name[] = "edgeos-memfd-create";
    char maximum_name[250];
    char oversized_name[251];
    char readback[3];
    struct probe_statx metadata;
    long descriptor;
    long flags;
    int failures = 0;

    for (int index = 0; index < 249; ++index)
        maximum_name[index] = (char)('a' + index % 26);
    maximum_name[249] = 0;
    for (int index = 0; index < 250; ++index)
        oversized_name[index] = (char)('a' + index % 26);
    oversized_name[250] = 0;
    readback[0] = 0;
    readback[1] = 0;
    readback[2] = 0;

    failures += expect_result("null name",
        raw_syscall6(SYS_memfd_create, 0, 0, 0, 0, 0, 0), -EFAULT);
    failures += expect_result("oversized name",
        raw_syscall6(SYS_memfd_create, (long)oversized_name, 0,
                     0, 0, 0, 0), -EINVAL);
    failures += expect_result("unknown flag",
        raw_syscall6(SYS_memfd_create, (long)ordinary_name, 0x20,
                     0, 0, 0, 0), -EINVAL);
    failures += expect_result("huge selector without hugetlb",
        raw_syscall6(SYS_memfd_create, (long)ordinary_name, MFD_HUGE_2MB,
                     0, 0, 0, 0), -EINVAL);

    descriptor = raw_syscall6(SYS_memfd_create, (long)ordinary_name, 0,
                              0, 0, 0, 0);
    failures += expect_true("ordinary descriptor", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect_result("ordinary descriptor flags",
            raw_syscall6(SYS_fcntl, descriptor, F_GETFD, 0,
                         0, 0, 0), 0);
        flags = raw_syscall6(SYS_fcntl, descriptor, F_GETFL, 0,
                             0, 0, 0);
        failures += expect_true("ordinary read-write mode",
                                flags >= 0 && (flags & O_ACCMODE) == O_RDWR);
        failures += expect_result("ordinary statx",
            raw_syscall6(SYS_statx, descriptor, (long)"", AT_EMPTY_PATH,
                         STATX_MODE, (long)&metadata, 0), 0);
        failures += expect_true("ordinary regular mode",
            (metadata.mask & STATX_MODE) &&
            (metadata.mode & S_IFMT) == S_IFREG &&
            (metadata.mode & 0777u) == 0777u);
        failures += expect_result("ordinary initial seal",
            raw_syscall6(SYS_fcntl, descriptor, F_GET_SEALS, 0,
                         0, 0, 0), F_SEAL_SEAL);
        failures += expect_result("sealed object rejects seals",
            raw_syscall6(SYS_fcntl, descriptor, F_ADD_SEALS,
                         F_SEAL_SHRINK, 0, 0, 0), -EPERM);
        failures += expect_result("ordinary write",
            raw_syscall6(SYS_write, descriptor, (long)"abc", 3,
                         0, 0, 0), 3);
        failures += expect_result("ordinary rewind",
            raw_syscall6(SYS_lseek, descriptor, 0, SEEK_SET,
                         0, 0, 0), 0);
        failures += expect_result("ordinary read",
            raw_syscall6(SYS_read, descriptor, (long)readback, 3,
                         0, 0, 0), 3);
        failures += expect_true("ordinary contents",
            readback[0] == 'a' && readback[1] == 'b' &&
            readback[2] == 'c');
        failures += expect_result("ordinary close",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    descriptor = raw_syscall6(
        SYS_memfd_create, (long)ordinary_name,
        MFD_CLOEXEC | MFD_ALLOW_SEALING, 0, 0, 0, 0);
    failures += expect_true("sealable descriptor", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect_result("close-on-exec descriptor flag",
            raw_syscall6(SYS_fcntl, descriptor, F_GETFD, 0,
                         0, 0, 0), FD_CLOEXEC);
        failures += expect_result("sealable initial state",
            raw_syscall6(SYS_fcntl, descriptor, F_GET_SEALS, 0,
                         0, 0, 0), 0);
        failures += expect_result("add size seals",
            raw_syscall6(SYS_fcntl, descriptor, F_ADD_SEALS,
                         F_SEAL_SHRINK | F_SEAL_GROW, 0, 0, 0), 0);
        failures += expect_result("read size seals",
            raw_syscall6(SYS_fcntl, descriptor, F_GET_SEALS, 0,
                         0, 0, 0), F_SEAL_SHRINK | F_SEAL_GROW);
        failures += expect_result("grow seal enforcement",
            raw_syscall6(SYS_ftruncate, descriptor, 4096,
                         0, 0, 0, 0), -EPERM);
        failures += expect_result("sealable close",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    descriptor = raw_syscall6(SYS_memfd_create, (long)maximum_name, 0,
                              0, 0, 0, 0);
    failures += expect_true("maximum name descriptor", descriptor >= 0);
    if (descriptor >= 0)
        failures += expect_result("maximum name close",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);

    if (!failures) print_text("MEMFD_CREATE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
