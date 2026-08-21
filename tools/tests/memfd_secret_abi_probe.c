/* SPDX-License-Identifier: MPL-2.0 */
/* Linux memfd_secret ABI probe for 64-bit architectures. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_fstat 5
#define SYS_lseek 8
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_pread64 17
#define SYS_pwrite64 18
#define SYS_getpid 39
#define SYS_fcntl 72
#define SYS_ftruncate 77
#define SYS_exit 60
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311
#define STAT_MODE_OFFSET 24
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_fstat 80
#define SYS_lseek 62
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_pread64 67
#define SYS_pwrite64 68
#define SYS_getpid 172
#define SYS_fcntl 25
#define SYS_ftruncate 46
#define SYS_exit 93
#define SYS_process_vm_readv 270
#define SYS_process_vm_writev 271
#define STAT_MODE_OFFSET 16
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "memfd_secret_abi_probe requires a Linux 64-bit architecture"
#endif
#define SYS_memfd_secret 447

#define EFAULT 14
#define EINVAL 22
#define ESPIPE 29

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02

#define F_GETFD 1
#define F_GETFL 3
#define FD_CLOEXEC 1
#define O_ACCMODE 3
#define O_RDWR 2
#define O_CLOEXEC 02000000
#define SEEK_SET 0
#define S_IFMT 0170000u
#define S_IFREG 0100000u

struct probe_iovec {
    void *base;
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
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
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

static int test_descriptor(unsigned int flags, int expected_fd_flags) {
    uint64_t metadata[18] = {0};
    char byte = 0;
    long descriptor;
    long mapping;
    long status_flags;
    int failures = 0;

    descriptor = raw_syscall6(SYS_memfd_secret, flags, 0, 0, 0, 0, 0);
    failures += expect_true("descriptor", descriptor >= 0);
    if (descriptor < 0) return failures;

    failures += expect_result(
        "descriptor flags",
        raw_syscall6(SYS_fcntl, descriptor, F_GETFD, 0, 0, 0, 0),
        expected_fd_flags);
    status_flags = raw_syscall6(
        SYS_fcntl, descriptor, F_GETFL, 0, 0, 0, 0);
    failures += expect_true(
        "read-write status", status_flags >= 0 &&
        (status_flags & O_ACCMODE) == O_RDWR);
    failures += expect_result(
        "metadata",
        raw_syscall6(SYS_fstat, descriptor, (long)&metadata,
                     0, 0, 0, 0), 0);
    failures += expect_true(
        "regular file mode",
        (*(uint32_t *)((uint8_t *)metadata + STAT_MODE_OFFSET) & S_IFMT) ==
            S_IFREG);
    failures += expect_result(
        "read rejected",
        raw_syscall6(SYS_read, descriptor, (long)&byte, 1, 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "write rejected",
        raw_syscall6(SYS_write, descriptor, (long)&byte, 1, 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "pread rejected",
        raw_syscall6(SYS_pread64, descriptor, (long)&byte, 1, 0, 0, 0),
        -ESPIPE);
    failures += expect_result(
        "pwrite rejected",
        raw_syscall6(SYS_pwrite64, descriptor, (long)&byte, 1, 0, 0, 0),
        -ESPIPE);
    failures += expect_result(
        "seek rejected",
        raw_syscall6(SYS_lseek, descriptor, 0, SEEK_SET, 0, 0, 0),
        -ESPIPE);
    failures += expect_result(
        "initial truncate",
        raw_syscall6(SYS_ftruncate, descriptor, 4096, 0, 0, 0, 0), 0);
    failures += expect_result(
        "second truncate rejected",
        raw_syscall6(SYS_ftruncate, descriptor, 8192, 0, 0, 0, 0),
        -EINVAL);
    failures += expect_result(
        "private mapping rejected",
        raw_syscall6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE, descriptor, 0), -EINVAL);
    mapping = raw_syscall6(
        SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, 0);
    failures += expect_true("shared mapping", mapping > 0);
    if (mapping > 0) {
        struct probe_iovec local;
        struct probe_iovec remote;
        volatile char *memory = (volatile char *)(uintptr_t)mapping;

        memory[0] = 's';
        memory[4095] = 'm';
        failures += expect_true(
            "shared mapping contents",
            memory[0] == 's' && memory[4095] == 'm');
        local.base = &byte;
        local.length = 1;
        remote.base = (void *)(uintptr_t)mapping;
        remote.length = 1;
        failures += expect_result(
            "process vm read rejected",
            raw_syscall6(SYS_process_vm_readv,
                         raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0),
                         (long)&local, 1, (long)&remote, 1, 0),
            -EFAULT);
        failures += expect_result(
            "process vm write rejected",
            raw_syscall6(SYS_process_vm_writev,
                         raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0),
                         (long)&local, 1, (long)&remote, 1, 0),
            -EFAULT);
        failures += expect_result(
            "unmap", raw_syscall6(
                SYS_munmap, mapping, 4096, 0, 0, 0, 0), 0);
    }
    failures += expect_result(
        "close", raw_syscall6(
            SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
    return failures;
}

static int run_tests(void) {
    int failures = 0;

    failures += expect_result(
        "unknown flag",
        raw_syscall6(SYS_memfd_secret, 2, 0, 0, 0, 0, 0), -EINVAL);
    failures += test_descriptor(0, 0);
    failures += test_descriptor(O_CLOEXEC, FD_CLOEXEC);
    if (!failures) print_text("MEMFD_SECRET_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

START_ATTRIBUTES void _start(void) {
    raw_syscall6(SYS_exit, run_tests(), 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
