/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 scalar and descriptor-only syscall ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_scalar_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))

#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_close 3
#define SYS_write 1
#define SYS_sched_yield 24
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_getuid 102
#define SYS_getgid 104
#define SYS_gettid 186
#define SYS_timerfd_create 283
#define SYS_eventfd2 290
#define SYS_epoll_create1 291
#define SYS_pidfd_open 434

#define EBADF 9
#define EFAULT 14
#define ENOSYS 38
#define CLOCK_MONOTONIC 1
#define O_CLOEXEC 02000000

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
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
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;

    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        X32_SYSCALL_BIT | 1u, 1, (long)text, (long)text_length(text),
        0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(
        X32_SYSCALL_BIT | 1u, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static long x32_syscall(long number, long a0, long a1) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number), a0, a1,
        0, 0, 0, 0);
}

static int expect_descriptor(const char *name, long descriptor) {
    int failures = 0;

    if (descriptor < 0) {
        print_text("FAIL ");
        print_text(name);
        print_text(" actual=");
        print_number(descriptor);
        print_text("\n");
        return 1;
    }
    failures += expect_result(
        "close-descriptor", x32_syscall(SYS_close, descriptor, 0), 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    static const char pointer_marker = '\n';
    long native_pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    long native_tid = raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    int failures = 0;

    failures += expect_result(
        "getpid", x32_syscall(SYS_getpid, 0, 0), native_pid);
    failures += expect_result(
        "gettid", x32_syscall(SYS_gettid, 0, 0), native_tid);
    failures += expect_result(
        "getuid", x32_syscall(SYS_getuid, 0, 0),
        raw_syscall6(SYS_getuid, 0, 0, 0, 0, 0, 0));
    failures += expect_result(
        "getgid", x32_syscall(SYS_getgid, 0, 0),
        raw_syscall6(SYS_getgid, 0, 0, 0, 0, 0, 0));
    failures += expect_result(
        "sched-yield", x32_syscall(SYS_sched_yield, 0, 0), 0);
    failures += expect_result(
        "close-invalid", x32_syscall(SYS_close, -1, 0), -EBADF);
    failures += expect_result(
        "pointer-high-bits",
        raw_syscall6(
            X32_SYSCALL_BIT | SYS_write, 1,
            (long)((uintptr_t)&pointer_marker | UINT64_C(0x100000000)),
            1, 0, 0, 0),
        -EFAULT);
    failures += expect_descriptor(
        "eventfd2", x32_syscall(SYS_eventfd2, 0, O_CLOEXEC));
    failures += expect_descriptor(
        "epoll-create1", x32_syscall(SYS_epoll_create1, O_CLOEXEC, 0));
    failures += expect_descriptor(
        "timerfd-create", x32_syscall(
            SYS_timerfd_create, CLOCK_MONOTONIC, O_CLOEXEC));
    failures += expect_descriptor(
        "pidfd-open", x32_syscall(SYS_pidfd_open, native_pid, 0));
    failures += expect_result(
        "unassigned", x32_syscall(511, 0, 0), -ENOSYS);

    if (failures) {
        print_text("X32_SCALAR_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_SCALAR_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
