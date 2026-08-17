/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS process_vm_readv/process_vm_writev Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_setresuid 117
#define SYS_setresgid 119
#define SYS_prctl 157
#define SYS_pipe2 293
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
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
#define SYS_process_vm_readv 270
#define SYS_process_vm_writev 271
#else
#error "process_vm_abi_probe requires a Linux 64-bit architecture"
#endif

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define SIGKILL 9
#define SIGCHLD 17
#define PR_SET_DUMPABLE 4
#define EPERM 1
#define ESRCH 3
#define EFAULT 14
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

static long process_vm_read(long pid, struct test_iovec *local,
                            long local_count, struct test_iovec *remote,
                            long remote_count, long flags) {
    return raw_syscall6(SYS_process_vm_readv, pid, (long)local,
                        local_count, (long)remote, remote_count, flags);
}

static long process_vm_write(long pid, struct test_iovec *local,
                             long local_count, struct test_iovec *remote,
                             long remote_count, long flags) {
    return raw_syscall6(SYS_process_vm_writev, pid, (long)local,
                        local_count, (long)remote, remote_count, flags);
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

static int bytes_equal(const unsigned char *left,
                       const unsigned char *right, unsigned long size) {
    for (unsigned long index = 0; index < size; ++index)
        if (left[index] != right[index]) return 0;
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

static int test_self(void) {
    unsigned char source[16];
    unsigned char destination[16];
    unsigned char written[16];
    struct test_iovec local[2];
    struct test_iovec remote[2];
    long pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    int failures = 0;

    for (int index = 0; index < 16; ++index) {
        source[index] = (unsigned char)(0x20 + index);
        destination[index] = 0;
        written[index] = 0;
    }
    local[0].base = (uint64_t)(uintptr_t)destination;
    local[0].length = 5;
    local[1].base = (uint64_t)(uintptr_t)(destination + 5);
    local[1].length = 11;
    remote[0].base = (uint64_t)(uintptr_t)source;
    remote[0].length = 9;
    remote[1].base = (uint64_t)(uintptr_t)(source + 9);
    remote[1].length = 7;

    failures += expect_result("zero_local_count",
        process_vm_read(-1, 0, 0, remote, 2, 0), 0);
    failures += expect_result("zero_remote_count",
        process_vm_read(-1, local, 2, 0, 0, 0), 0);
    failures += expect_result("invalid_flags",
        process_vm_read(pid, local, 2, remote, 2, 1), -EINVAL);
    failures += expect_result("too_many_local_vectors",
        process_vm_read(pid, local, 1025, remote, 2, 0), -EINVAL);
    failures += expect_result("too_many_remote_vectors",
        process_vm_read(pid, local, 2, remote, 1025, 0), -EINVAL);
    failures += expect_result("self_read_split_vectors",
        process_vm_read(pid, local, 2, remote, 2, 0), 16);
    failures += expect_result("self_read_content",
        bytes_equal(destination, source, sizeof(source)), 1);

    local[0].base = (uint64_t)(uintptr_t)source;
    local[0].length = 6;
    local[1].base = (uint64_t)(uintptr_t)(source + 6);
    local[1].length = 10;
    remote[0].base = (uint64_t)(uintptr_t)written;
    remote[0].length = 4;
    remote[1].base = (uint64_t)(uintptr_t)(written + 4);
    remote[1].length = 12;
    failures += expect_result("self_write_split_vectors",
        process_vm_write(pid, local, 2, remote, 2, 0), 16);
    failures += expect_result("self_write_content",
        bytes_equal(written, source, sizeof(source)), 1);

    local[0].base = 0x1000;
    local[0].length = 1;
    remote[0].base = (uint64_t)(uintptr_t)source;
    remote[0].length = 1;
    failures += expect_result("invalid_local_range",
        process_vm_read(pid, local, 1, remote, 1, 0), -EFAULT);

    local[0].base = (uint64_t)(uintptr_t)destination;
    local[0].length = 0;
    remote[0].base = (uint64_t)(uintptr_t)source;
    remote[0].length = 0;
    failures += expect_result("zero_lengths_before_pid_lookup",
        process_vm_read(-1, local, 1, remote, 1, 0), 0);

    local[0].length = INT64_MAX;
    local[1].base = (uint64_t)(uintptr_t)destination;
    local[1].length = 1;
    remote[0].length = 1;
    failures += expect_result("local_length_overflow",
        process_vm_read(pid, local, 2, remote, 1, 0), -EFAULT);
    local[0].base = (uint64_t)(uintptr_t)destination;
    local[0].length = 1;
    remote[0].length = INT64_MAX;
    remote[1].base = (uint64_t)(uintptr_t)source;
    remote[1].length = 1;
    failures += expect_result("remote_length_overflow",
        process_vm_read(pid, local, 1, remote, 2, 0), 1);
    failures += expect_result("missing_pid",
        process_vm_read(0x7fffffff, local, 1, remote, 1, 0), -ESRCH);
    return failures;
}

static int test_cross_process_transfer(void) {
    int ready[2] = {-1, -1};
    unsigned char observed[32];
    unsigned char replacement[32];
    unsigned char verify[32];
    struct test_iovec local[2];
    struct test_iovec remote[2];
    uint64_t address = 0;
    int status = 0;
    long child;
    int failures = 0;

    failures += expect_result("cross_pipe",
        raw_syscall6(SYS_pipe2, (long)ready, 0, 0, 0, 0, 0), 0);
    if (failures) return failures;
    child = create_child();
    if (child < 0) return expect_result("cross_child", child, 0);
    if (child == 0) {
        long mapping = map_page();
        unsigned char *page = (unsigned char *)(uintptr_t)mapping;
        (void)raw_syscall6(SYS_close, ready[0], 0, 0, 0, 0, 0);
        if (mapping < 0) raw_syscall6(SYS_exit, 2, 0, 0, 0, 0, 0);
        for (int index = 0; index < PAGE_SIZE; ++index)
            page[index] = (unsigned char)(0x40 + (index & 15));
        if (raw_syscall6(SYS_write, ready[1], (long)&mapping,
                         sizeof(mapping), 0, 0, 0) != sizeof(mapping))
            raw_syscall6(SYS_exit, 3, 0, 0, 0, 0, 0);
        for (;;) {}
    }

    (void)raw_syscall6(SYS_close, ready[1], 0, 0, 0, 0, 0);
    failures += expect_result("cross_address",
        raw_syscall6(SYS_read, ready[0], (long)&address,
                     sizeof(address), 0, 0, 0), sizeof(address));
    for (int index = 0; index < 32; ++index) {
        observed[index] = 0;
        replacement[index] = (unsigned char)(0x80 + index);
        verify[index] = 0;
    }
    local[0].base = (uint64_t)(uintptr_t)observed;
    local[0].length = 13;
    local[1].base = (uint64_t)(uintptr_t)(observed + 13);
    local[1].length = 19;
    remote[0].base = address;
    remote[0].length = 7;
    remote[1].base = address + 7;
    remote[1].length = 25;
    failures += expect_result("cross_read",
        process_vm_read(child, local, 2, remote, 2, 0), 32);
    failures += expect_result("cross_read_content", observed[0], 0x40);
    failures += expect_result("cross_read_tail", observed[31], 0x4f);

    local[0].base = (uint64_t)(uintptr_t)replacement;
    local[0].length = 32;
    remote[0].base = address;
    remote[0].length = 32;
    failures += expect_result("cross_write",
        process_vm_write(child, local, 1, remote, 1, 0), 32);
    local[0].base = (uint64_t)(uintptr_t)verify;
    failures += expect_result("cross_write_readback",
        process_vm_read(child, local, 1, remote, 1, 0), 32);
    failures += expect_result("cross_write_content",
        bytes_equal(verify, replacement, 32), 1);

    local[0].base = (uint64_t)(uintptr_t)observed;
    local[0].length = 16;
    remote[0].base = address;
    remote[0].length = 8;
    remote[1].base = 0x1000;
    remote[1].length = 8;
    failures += expect_result("partial_remote_fault",
        process_vm_read(child, local, 1, remote, 2, 0), 8);

    for (int index = 0; index < 8; ++index)
        observed[index] = (unsigned char)(0x10 + index);
    local[0].base = (uint64_t)(uintptr_t)observed;
    local[0].length = 8;
    local[1].base = 0x1000;
    local[1].length = 8;
    remote[0].base = address;
    remote[0].length = 8;
    remote[1].base = address + 8;
    remote[1].length = 8;
    failures += expect_result("local_fault_returns_partial",
        process_vm_write(child, local, 2, remote, 2, 0), 8);
    local[0].base = (uint64_t)(uintptr_t)verify;
    local[0].length = 16;
    failures += expect_result("local_fault_readback",
        process_vm_read(child, local, 1, remote, 2, 0), 16);
    failures += expect_result("local_fault_commits_prefix",
        bytes_equal(verify, observed, 8), 1);
    failures += expect_result("local_fault_preserves_suffix",
        bytes_equal(verify + 8, replacement + 8, 8), 1);

    failures += expect_result("cross_kill",
        raw_syscall6(SYS_kill, child, SIGKILL, 0, 0, 0, 0), 0);
    failures += expect_result("cross_wait",
        raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0), child);
    return failures;
}

static int test_permission_denial(void) {
    int ready[2] = {-1, -1};
    struct test_iovec local;
    struct test_iovec remote;
    uint64_t address = 0;
    uint64_t value = 0;
    int status = 0;
    long child;
    int failures = 0;

    failures += expect_result("permission_pipe",
        raw_syscall6(SYS_pipe2, (long)ready, 0, 0, 0, 0, 0), 0);
    if (failures) return failures;
    child = create_child();
    if (child < 0) return expect_result("permission_child", child, 0);
    if (child == 0) {
        long mapping;
        (void)raw_syscall6(SYS_close, ready[0], 0, 0, 0, 0, 0);
        if (raw_syscall6(SYS_setresgid, 65534, 65534, 65534, 0, 0, 0) < 0 ||
            raw_syscall6(SYS_setresuid, 65534, 65534, 65534, 0, 0, 0) < 0 ||
            raw_syscall6(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0, 0) < 0)
            raw_syscall6(SYS_exit, 2, 0, 0, 0, 0, 0);
        mapping = map_page();
        if (mapping < 0 || raw_syscall6(SYS_write, ready[1],
                (long)&mapping, sizeof(mapping), 0, 0, 0) != sizeof(mapping))
            raw_syscall6(SYS_exit, 3, 0, 0, 0, 0, 0);
        for (;;) {}
    }

    (void)raw_syscall6(SYS_close, ready[1], 0, 0, 0, 0, 0);
    failures += expect_result("permission_address",
        raw_syscall6(SYS_read, ready[0], (long)&address,
                     sizeof(address), 0, 0, 0), sizeof(address));
    failures += expect_result("permission_drop_gid",
        raw_syscall6(SYS_setresgid, 65534, 65534, 65534, 0, 0, 0), 0);
    failures += expect_result("permission_drop_uid",
        raw_syscall6(SYS_setresuid, 65534, 65534, 65534, 0, 0, 0), 0);
    failures += expect_result("permission_restore_dumpable",
        raw_syscall6(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0, 0), 0);
    local.base = (uint64_t)(uintptr_t)&value;
    local.length = sizeof(value);
    remote.base = address;
    remote.length = sizeof(value);
    failures += expect_result("permission_denied",
        process_vm_read(child, &local, 1, &remote, 1, 0), -EPERM);
    failures += expect_result("permission_kill",
        raw_syscall6(SYS_kill, child, SIGKILL, 0, 0, 0, 0), 0);
    failures += expect_result("permission_wait",
        raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0), child);
    return failures;
}

void _start(void) {
    int failures = test_self();
    failures += test_cross_process_transfer();
    failures += test_permission_denial();
    if (!failures) print_text("PROCESS_VM_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
