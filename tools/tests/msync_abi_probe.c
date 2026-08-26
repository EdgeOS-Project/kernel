/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux msync ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_pread64 17
#define SYS_pwrite64 18
#define SYS_msync 26
#define SYS_fsync 74
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_ftruncate 77
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_renameat 264
#define SYS_fallocate 285
#define SYS_memfd_create 319
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_renameat 38
#define SYS_ftruncate 46
#define SYS_fallocate 47
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_pread64 67
#define SYS_pwrite64 68
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mprotect 226
#define SYS_msync 227
#define SYS_fsync 82
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_memfd_create 279
#else
#error "msync_abi_probe requires a Linux 64-bit architecture"
#endif

#define EINVAL 22
#define ENOMEM 12
#define EOPNOTSUPP 95

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PAGE_SIZE 4096u
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define SIGCHLD 17

#define MS_ASYNC 1
#define MS_INVALIDATE 2
#define MS_SYNC 4
#define FALLOC_FL_ZERO_RANGE 0x10

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
    static const char name[] = "edgeos-msync-probe";
    static const char regular_name[] = "/edgeos-msync-regular";
    static const char rename_source[] = "/edgeos-msync-rename-source";
    static const char rename_target[] = "/edgeos-msync-rename-target";
    volatile uint8_t *mapping;
    volatile uint8_t *shared;
    uint8_t readback[2];
    uint8_t direct_write[2];
    long mapped;
    long shared_mapped;
    long descriptor;
    int failures = 0;

    readback[0] = 0;
    readback[1] = 0;
    direct_write[0] = 0x66u;
    direct_write[1] = 0x99u;

    failures += expect_result("zero length",
        raw_syscall6(SYS_msync, PAGE_SIZE, 0, 0, 0, 0, 0), 0);
    failures += expect_result("unaligned zero length",
        raw_syscall6(SYS_msync, PAGE_SIZE + 1u, 0, 0, 0, 0, 0),
        -EINVAL);
    failures += expect_result("invalid flags",
        raw_syscall6(SYS_msync, PAGE_SIZE, 0, 8, 0, 0, 0), -EINVAL);
    failures += expect_result("conflicting modes",
        raw_syscall6(SYS_msync, PAGE_SIZE, 0,
                     MS_ASYNC | MS_SYNC, 0, 0, 0), -EINVAL);
    failures += expect_result("overflow range",
        raw_syscall6(SYS_msync, -PAGE_SIZE, PAGE_SIZE * 2u,
                     MS_SYNC, 0, 0, 0), -ENOMEM);
    failures += expect_result("unmapped range",
        raw_syscall6(SYS_msync, PAGE_SIZE, PAGE_SIZE,
                     MS_SYNC, 0, 0, 0), -ENOMEM);

    mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE * 3u,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("anonymous mapping", mapped > 0);
    if (mapped <= 0) return failures;
    mapping = (volatile uint8_t *)(uintptr_t)mapped;
    mapping[0] = 0x11u;
    mapping[PAGE_SIZE * 2u] = 0x22u;
    failures += expect_result("flags zero",
        raw_syscall6(SYS_msync, mapped, PAGE_SIZE, 0, 0, 0, 0), 0);
    failures += expect_result("async",
        raw_syscall6(SYS_msync, mapped, PAGE_SIZE,
                     MS_ASYNC, 0, 0, 0), 0);
    failures += expect_result("sync invalidate",
        raw_syscall6(SYS_msync, mapped, PAGE_SIZE,
                     MS_SYNC | MS_INVALIDATE, 0, 0, 0), 0);
    failures += expect_result("remove middle page",
        raw_syscall6(SYS_munmap, mapped + PAGE_SIZE, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("range with hole",
        raw_syscall6(SYS_msync, mapped, PAGE_SIZE * 3u,
                     MS_SYNC, 0, 0, 0), -ENOMEM);

    descriptor = raw_syscall6(SYS_memfd_create, (long)name, 0,
                              0, 0, 0, 0);
    failures += expect_true("memfd create", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect_result("memfd truncate",
            raw_syscall6(SYS_ftruncate, descriptor, PAGE_SIZE,
                         0, 0, 0, 0), 0);
        shared_mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
                                     PROT_READ | PROT_WRITE, MAP_SHARED,
                                     descriptor, 0);
        failures += expect_true("shared mapping", shared_mapped > 0);
        if (shared_mapped > 0) {
            shared = (volatile uint8_t *)(uintptr_t)shared_mapped;
            shared[37] = 0x5au;
            shared[38] = 0xa5u;
            failures += expect_result("shared sync",
                raw_syscall6(SYS_msync, shared_mapped, PAGE_SIZE,
                             MS_SYNC, 0, 0, 0), 0);
            failures += expect_result("shared pread",
                raw_syscall6(SYS_pread64, descriptor, (long)readback,
                             sizeof(readback), 37, 0, 0),
                (long)sizeof(readback));
            failures += expect_true("shared data visible",
                readback[0] == 0x5au && readback[1] == 0xa5u);
            failures += expect_result("shared unmap",
                raw_syscall6(SYS_munmap, shared_mapped, PAGE_SIZE,
                             0, 0, 0, 0), 0);
        }
        failures += expect_result("memfd close",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    }

    descriptor = raw_syscall6(SYS_openat, AT_FDCWD, (long)regular_name,
                              O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
    failures += expect_true("regular create", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect_result("regular truncate",
            raw_syscall6(SYS_ftruncate, descriptor, PAGE_SIZE,
                         0, 0, 0, 0), 0);
        shared_mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
                                     PROT_READ | PROT_WRITE, MAP_SHARED,
                                     descriptor, 0);
        failures += expect_true("regular shared mapping", shared_mapped > 0);
        if (shared_mapped > 0) {
            long child;
            int child_status = 0;
            shared = (volatile uint8_t *)(uintptr_t)shared_mapped;
            shared[91] = 0x3cu;
            shared[92] = 0xc3u;
            failures += expect_result("regular immediate pread",
                raw_syscall6(SYS_pread64, descriptor, (long)readback,
                             sizeof(readback), 91, 0, 0),
                (long)sizeof(readback));
            failures += expect_true("regular immediate map-to-read coherence",
                readback[0] == 0x3cu && readback[1] == 0xc3u);
            shared[201] = 0x2au;
            shared[202] = 0xa2u;
            failures += expect_result("regular mapped fallocate",
                raw_syscall6(SYS_fallocate, descriptor, 0,
                             0, PAGE_SIZE * 2u, 0, 0), 0);
            failures += expect_result("regular post-fallocate pread",
                raw_syscall6(SYS_pread64, descriptor, (long)readback,
                             sizeof(readback), 201, 0, 0),
                (long)sizeof(readback));
            failures += expect_true("regular fallocate preserves map cache",
                readback[0] == 0x2au && readback[1] == 0xa2u);
            {
                long zero_result = raw_syscall6(
                    SYS_fallocate, descriptor, FALLOC_FL_ZERO_RANGE,
                    192, 32, 0, 0);

                failures += expect_true(
                    "regular mapped zero range",
                    zero_result == 0 || zero_result == -EOPNOTSUPP);
                if (zero_result == 0)
                    failures += expect_true("regular zero range updates map",
                        shared[201] == 0 && shared[202] == 0);
            }
            failures += expect_result("regular mapped fsync",
                raw_syscall6(SYS_fsync, descriptor, 0, 0, 0, 0, 0), 0);
            failures += expect_result("regular post-fsync pread",
                raw_syscall6(SYS_pread64, descriptor, (long)readback,
                             sizeof(readback), 91, 0, 0),
                (long)sizeof(readback));
            failures += expect_true("regular post-fsync data visible",
                readback[0] == 0x3cu && readback[1] == 0xc3u);
            failures += expect_result("regular pwrite",
                raw_syscall6(SYS_pwrite64, descriptor, (long)direct_write,
                             sizeof(direct_write), 151, 0, 0),
                (long)sizeof(direct_write));
            failures += expect_true("regular write-to-map coherence",
                shared[151] == 0x66u && shared[152] == 0x99u);
            failures += expect_result("regular protect read",
                raw_syscall6(SYS_mprotect, shared_mapped, PAGE_SIZE,
                             PROT_READ, 0, 0, 0), 0);
            failures += expect_result("regular protect restore write",
                raw_syscall6(SYS_mprotect, shared_mapped, PAGE_SIZE,
                             PROT_READ | PROT_WRITE, 0, 0, 0), 0);
            child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
            failures += expect_true("regular shared clone", child >= 0);
            if (child == 0) {
                shared[123] = 0x7du;
                raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
                for (;;) {}
            }
            if (child > 0) {
                failures += expect_result("regular shared wait",
                    raw_syscall6(SYS_wait4, child, (long)&child_status,
                                 0, 0, 0, 0), child);
                failures += expect_result("regular shared child status",
                                          child_status, 0);
                failures += expect_true("regular shared fork visibility",
                                        shared[123] == 0x7du);
            }
            failures += expect_result("regular shared sync",
                raw_syscall6(SYS_msync, shared_mapped, PAGE_SIZE,
                             MS_SYNC, 0, 0, 0), 0);
            failures += expect_result("regular shared pread",
                raw_syscall6(SYS_pread64, descriptor, (long)readback,
                             sizeof(readback), 91, 0, 0),
                (long)sizeof(readback));
            failures += expect_true("regular shared data visible",
                readback[0] == 0x3cu && readback[1] == 0xc3u);
            failures += expect_result("regular shared unmap",
                raw_syscall6(SYS_munmap, shared_mapped, PAGE_SIZE,
                             0, 0, 0, 0), 0);
        }
        failures += expect_result("regular close",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
        failures += expect_result("regular unlink",
            raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)regular_name,
                         0, 0, 0, 0), 0);
    }

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)rename_source,
                       0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)rename_target,
                       0, 0, 0, 0);
    descriptor = raw_syscall6(SYS_openat, AT_FDCWD, (long)rename_source,
                              O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
    failures += expect_true("rename source create", descriptor >= 0);
    if (descriptor >= 0) {
        failures += expect_result("rename source truncate",
            raw_syscall6(SYS_ftruncate, descriptor, PAGE_SIZE,
                         0, 0, 0, 0), 0);
        shared_mapped = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
                                     PROT_READ | PROT_WRITE, MAP_SHARED,
                                     descriptor, 0);
        failures += expect_true("rename shared mapping", shared_mapped > 0);
        if (shared_mapped > 0) {
            long read_descriptor;
            shared = (volatile uint8_t *)(uintptr_t)shared_mapped;
            shared[307] = 0x4du;
            shared[308] = 0xd4u;
            failures += expect_result("rename while mapped",
                raw_syscall6(SYS_renameat, AT_FDCWD, (long)rename_source,
                             AT_FDCWD, (long)rename_target, 0, 0), 0);
            failures += expect_result("renamed shared sync",
                raw_syscall6(SYS_msync, shared_mapped, PAGE_SIZE,
                             MS_SYNC | MS_INVALIDATE, 0, 0, 0), 0);
            failures += expect_result("renamed shared unmap",
                raw_syscall6(SYS_munmap, shared_mapped, PAGE_SIZE,
                             0, 0, 0, 0), 0);
            read_descriptor = raw_syscall6(
                SYS_openat, AT_FDCWD, (long)rename_target, O_RDWR, 0, 0, 0);
            failures += expect_true("renamed target open",
                                    read_descriptor >= 0);
            if (read_descriptor >= 0) {
                /*
                 * Keep the inode open while unlinking its last pathname.  The
                 * subsequent pread must come from persisted filesystem data,
                 * not merely from the pathname-indexed mmap cache.
                 */
                failures += expect_result("renamed target unlink",
                    raw_syscall6(SYS_unlinkat, AT_FDCWD,
                                 (long)rename_target, 0, 0, 0, 0), 0);
                readback[0] = 0;
                readback[1] = 0;
                failures += expect_result("renamed target pread",
                    raw_syscall6(SYS_pread64, read_descriptor,
                                 (long)readback, sizeof(readback),
                                 307, 0, 0), (long)sizeof(readback));
                failures += expect_true("rename-before-msync persistence",
                    readback[0] == 0x4du && readback[1] == 0xd4u);
                failures += expect_result("renamed target close",
                    raw_syscall6(SYS_close, read_descriptor,
                                 0, 0, 0, 0, 0), 0);
            }
        }
        failures += expect_result("rename source close",
            raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
        (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)rename_target,
                           0, 0, 0, 0);
    }

    failures += expect_result("unmap first page",
        raw_syscall6(SYS_munmap, mapped, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    failures += expect_result("unmap final page",
        raw_syscall6(SYS_munmap, mapped + PAGE_SIZE * 2u, PAGE_SIZE,
                     0, 0, 0, 0), 0);
    if (!failures) print_text("MSYNC_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

__attribute__((noreturn)) void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
