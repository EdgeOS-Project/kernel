/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS process_madvise Linux ABI regression test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_setresuid 117
#define SYS_setresgid 119
#define SYS_prctl 157
#define SYS_getpid 39
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_kill 129
#define SYS_setresuid 147
#define SYS_setresgid 149
#define SYS_prctl 167
#define SYS_getpid 172
#define SYS_munmap 215
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_wait4 260
#define SYS_pipe2 59
#else
#error "process_madvise_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_pidfd_open 434
#define SYS_process_madvise 440

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define MADV_COLLAPSE 25
#define SIGKILL 9
#define SIGCHLD 17
#define PR_SET_DUMPABLE 4
#define EBADF 9
#define EFAULT 14
#define ENOMEM 12
#define EPERM 1
#define EINVAL 22
#define PAGE_SIZE 4096

struct test_iovec {
    uint64_t base;
    uint64_t length;
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

static long call_process_madvise(long pidfd, struct test_iovec *vectors,
                                 long count, long advice, long flags) {
    return raw_syscall6(SYS_process_madvise, pidfd, (long)vectors,
                        count, advice, flags, 0);
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
    char buffer[32];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned long)position),
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

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static long map_page(void) {
    return raw_syscall6(SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static int test_self_advice(void) {
    struct test_iovec vectors[2];
    unsigned char *page;
    long mapping = map_page();
    long pidfd;
    int failures = 0;

    if (mapping < 0) return expect_result("mmap", mapping, 0);
    page = (unsigned char *)(uintptr_t)mapping;
    for (int index = 0; index < PAGE_SIZE; ++index) page[index] = 0xa5;
    pidfd = raw_syscall6(SYS_pidfd_open,
        raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0), 0, 0, 0, 0, 0);
    if (pidfd < 0) return expect_result("pidfd_open", pidfd, 0);
    vectors[0].base = (uint64_t)mapping;
    vectors[0].length = PAGE_SIZE;

    failures += expect_result("invalid_flags",
        call_process_madvise(pidfd, vectors, 1, MADV_WILLNEED, 1),
        -EINVAL);
    failures += expect_result("invalid_pidfd",
        call_process_madvise(-1, vectors, 1, MADV_WILLNEED, 0), -EBADF);
    failures += expect_result("too_many_vectors",
        call_process_madvise(pidfd, vectors, 1025, MADV_WILLNEED, 0),
        -EINVAL);
    failures += expect_result("null_vector",
        call_process_madvise(pidfd, 0, 1, MADV_WILLNEED, 0), -EFAULT);
    failures += expect_result("empty_vector",
        call_process_madvise(pidfd, 0, 0, MADV_WILLNEED, 0), 0);
    failures += expect_result("willneed",
        call_process_madvise(pidfd, vectors, 1, MADV_WILLNEED, 0),
        PAGE_SIZE);
    failures += expect_result("collapse_unsupported",
        call_process_madvise(pidfd, vectors, 1, MADV_COLLAPSE, 0),
        -EINVAL);
    failures += expect_result("unknown_advice",
        call_process_madvise(pidfd, vectors, 1, 999, 0), -EINVAL);

    vectors[0].length = INT64_MAX;
    vectors[1].base = (uint64_t)mapping;
    vectors[1].length = 1;
    failures += expect_result("length_overflow",
        call_process_madvise(pidfd, vectors, 2, MADV_WILLNEED, 0),
        -EINVAL);

    vectors[0].base = (uint64_t)mapping;
    vectors[0].length = PAGE_SIZE;
    vectors[1].base = 0x1000;
    vectors[1].length = PAGE_SIZE;
    failures += expect_result("prevalidate_all_ranges",
        call_process_madvise(pidfd, vectors, 2, MADV_DONTNEED, 0),
        -ENOMEM);
    failures += expect_result("prevalidation_preserves_first_range",
        page[0], 0xa5);

    failures += expect_result("dontneed",
        call_process_madvise(pidfd, vectors, 1, MADV_DONTNEED, 0),
        PAGE_SIZE);
    failures += expect_result("dontneed_zero_start", page[0], 0);
    failures += expect_result("dontneed_zero_end", page[PAGE_SIZE - 1], 0);
    (void)raw_syscall6(SYS_munmap, mapping, PAGE_SIZE, 0, 0, 0, 0);
    return failures;
}

static int test_cross_process_permission(void) {
    int descriptors[2] = {-1, -1};
    struct test_iovec vector;
    uint64_t address = 0;
    int status = 0;
    long child;
    long pidfd;
    int failures = 0;

    failures += expect_result("pipe2",
        raw_syscall6(SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (failures) return failures;
    child = create_child();
    if (child < 0) return expect_result("create_child", child, 0);
    if (child == 0) {
        long mapping;
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        if (raw_syscall6(SYS_setresgid, 65534, 65534, 65534, 0, 0, 0) < 0 ||
            raw_syscall6(SYS_setresuid, 65534, 65534, 65534, 0, 0, 0) < 0 ||
            raw_syscall6(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0, 0) < 0)
            raw_syscall6(SYS_exit, 2, 0, 0, 0, 0, 0);
        mapping = map_page();
        if (mapping < 0 || raw_syscall6(SYS_write, descriptors[1],
                (long)&mapping, sizeof(mapping), 0, 0, 0) != sizeof(mapping))
            raw_syscall6(SYS_exit, 3, 0, 0, 0, 0, 0);
        for (;;) {}
    }

    (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    failures += expect_result("read_child_address",
        raw_syscall6(SYS_read, descriptors[0], (long)&address,
                     sizeof(address), 0, 0, 0), sizeof(address));
    pidfd = raw_syscall6(SYS_pidfd_open, child, 0, 0, 0, 0, 0);
    if (pidfd < 0) failures += expect_result("child_pidfd", pidfd, 0);
    failures += expect_result("drop_gid",
        raw_syscall6(SYS_setresgid, 65534, 65534, 65534, 0, 0, 0), 0);
    failures += expect_result("drop_uid",
        raw_syscall6(SYS_setresuid, 65534, 65534, 65534, 0, 0, 0), 0);
    failures += expect_result("restore_dumpable",
        raw_syscall6(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0, 0), 0);
    vector.base = address;
    vector.length = PAGE_SIZE;
    if (pidfd >= 0)
        failures += expect_result("cross_process_requires_cap_sys_nice",
            call_process_madvise(pidfd, &vector, 1,
                                 MADV_WILLNEED, 0), -EPERM);
    failures += expect_result("kill_child",
        raw_syscall6(SYS_kill, child, SIGKILL, 0, 0, 0, 0), 0);
    failures += expect_result("wait_child",
        raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0), child);
    return failures;
}

void _start(void) {
    int failures = test_self_advice();
    failures += test_cross_process_permission();
    if (!failures) print_text("PROCESS_MADVISE_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
