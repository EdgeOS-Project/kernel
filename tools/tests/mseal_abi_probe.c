/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux mseal ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_mremap 25
#define SYS_madvise 28
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_mount 165
#define SYS_openat 257
#elif defined(__aarch64__)
#define SYS_mount 40
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_clone 220
#define SYS_munmap 215
#define SYS_mremap 216
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_madvise 233
#define SYS_wait4 260
#else
#error "mseal_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_mseal 462
#define EINVAL 22
#define ENOMEM 12
#define EPERM 1
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MREMAP_MAYMOVE 1
#define MADV_DONTNEED 4
#define SIGCHLD 17
#define PAGE_SIZE 4096u
#define AT_FDCWD -100

static char smaps_buffer[32768];

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

static int buffer_contains(const char *buffer, unsigned long length,
                           const char *needle) {
    unsigned long needle_length = string_length(needle);

    if (!needle_length || needle_length > length) return 0;
    for (unsigned long offset = 0;
         offset + needle_length <= length; ++offset) {
        unsigned long index = 0;
        while (index < needle_length &&
               buffer[offset + index] == needle[index])
            ++index;
        if (index == needle_length) return 1;
    }
    return 0;
}

static int test_smaps_seal_flag(void) {
    static const char proc[] = "proc";
    static const char proc_path[] = "/proc";
    static const char smaps_path[] = "/proc/self/smaps";
    unsigned long total = 0;
    long descriptor;

    (void)raw_syscall6(SYS_mount, (long)proc, (long)proc_path,
                       (long)proc, 0, 0, 0);
    descriptor = raw_syscall6(SYS_openat, AT_FDCWD,
                              (long)smaps_path, 0, 0, 0, 0);
    if (descriptor < 0) return expect_true("smaps open", 0);
    while (total < sizeof(smaps_buffer)) {
        long count = raw_syscall6(
            SYS_read, descriptor, (long)&smaps_buffer[total],
            (long)(sizeof(smaps_buffer) - total), 0, 0, 0);
        if (count < 0) {
            (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
            return expect_true("smaps read", 0);
        }
        if (!count) break;
        total += (unsigned long)count;
    }
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return expect_true(
        "smaps seal flag",
        buffer_contains(smaps_buffer, total, "VmFlags:") &&
        buffer_contains(smaps_buffer, total, " sl"));
}

static long map_anonymous_protection(long address, long length, long flags,
                                     long protection) {
    return raw_syscall6(SYS_mmap, address, length,
                        protection,
                        MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
}

static long map_anonymous(long address, long length, long flags) {
    return map_anonymous_protection(
        address, length, flags, PROT_READ | PROT_WRITE);
}

static int test_fork_inheritance(long mapping) {
    int status = -1;
    long child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);

    if (child < 0)
        return expect_true("clone", 0);
    if (child == 0) {
        long result = raw_syscall6(SYS_mprotect, mapping, PAGE_SIZE,
                                   PROT_READ, 0, 0, 0);
        raw_syscall6(SYS_exit, result == -EPERM ? 0 : 1,
                     0, 0, 0, 0, 0);
        for (;;) { }
    }
    if (raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child)
        return expect_true("wait child", 0);
    return expect_result("fork inheritance", status, 0);
}

static int run_tests(void) {
    long mapping;
    long hole_mapping;
    long read_only_mapping;
    int failures = 0;

    failures += expect_result(
        "zero length", raw_syscall6(SYS_mseal, 0, 0, 0, 0, 0, 0), 0);
    failures += expect_result(
        "unknown flags", raw_syscall6(SYS_mseal, 0, 0, 1, 0, 0, 0),
        -EINVAL);

    mapping = map_anonymous(0, PAGE_SIZE * 4u, 0);
    failures += expect_true("mapping", mapping > 0);
    if (mapping <= 0) return failures;
    failures += expect_result(
        "unaligned start",
        raw_syscall6(SYS_mseal, mapping + 1u, PAGE_SIZE, 0, 0, 0, 0),
        -EINVAL);

    failures += expect_result(
        "make hole",
        raw_syscall6(SYS_munmap, mapping + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result(
        "range with hole",
        raw_syscall6(SYS_mseal, mapping, PAGE_SIZE * 3u,
                     0, 0, 0, 0), -ENOMEM);
    hole_mapping = map_anonymous(mapping + PAGE_SIZE, PAGE_SIZE, MAP_FIXED);
    failures += expect_result("refill hole", hole_mapping,
                              mapping + PAGE_SIZE);

    failures += expect_result(
        "seal rounded range",
        raw_syscall6(SYS_mseal, mapping, PAGE_SIZE + 1u,
                     0, 0, 0, 0), 0);
    failures += expect_result(
        "repeat seal",
        raw_syscall6(SYS_mseal, mapping, PAGE_SIZE * 2u,
                     0, 0, 0, 0), 0);
    failures += expect_result(
        "sealed mprotect",
        raw_syscall6(SYS_mprotect, mapping, PAGE_SIZE,
                     PROT_READ, 0, 0, 0), -EPERM);
    failures += expect_result(
        "sealed munmap",
        raw_syscall6(SYS_munmap, mapping + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), -EPERM);
    failures += expect_result(
        "sealed mremap",
        raw_syscall6(SYS_mremap, mapping, PAGE_SIZE,
                     PAGE_SIZE * 2u, MREMAP_MAYMOVE, 0, 0), -EPERM);
    failures += expect_result(
        "fixed replacement",
        map_anonymous(mapping, PAGE_SIZE, MAP_FIXED), -EPERM);
    failures += expect_result(
        "writable sealed discard",
        raw_syscall6(SYS_madvise, mapping, PAGE_SIZE,
                     MADV_DONTNEED, 0, 0, 0), 0);
    failures += test_fork_inheritance(mapping);
    failures += expect_result(
        "unsealed neighbor",
        raw_syscall6(SYS_munmap, mapping + PAGE_SIZE * 2u,
                     PAGE_SIZE * 2u, 0, 0, 0, 0), 0);

    read_only_mapping = map_anonymous_protection(
        0, PAGE_SIZE, 0, PROT_READ);
    failures += expect_true("read-only mapping", read_only_mapping > 0);
    if (read_only_mapping > 0) {
        failures += expect_result(
            "seal read-only mapping",
            raw_syscall6(SYS_mseal, read_only_mapping, PAGE_SIZE,
                         0, 0, 0, 0), 0);
        failures += expect_result(
            "read-only sealed discard",
            raw_syscall6(SYS_madvise, read_only_mapping, PAGE_SIZE,
                         MADV_DONTNEED, 0, 0, 0), -EPERM);
    }
    failures += test_smaps_seal_flag();
    return failures;
}

void _start(void) {
    int failures = run_tests();
    if (!failures)
        print_text("PASS mseal ABI\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
