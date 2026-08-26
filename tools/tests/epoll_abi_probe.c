/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding raw Linux epoll ABI and readiness probe.  The x86_64 UAPI
 * packs epoll_data_t at byte four, while AArch64 uses the naturally aligned
 * asm-generic record.  Keeping both definitions here makes layout drift fail
 * as observable event-data corruption rather than relying on static routing.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_epoll_create 213
#define SYS_epoll_wait 232
#define SYS_epoll_ctl 233
#define SYS_epoll_pwait 281
#define SYS_epoll_create1 291
#define SYS_pipe2 293
#define SYS_openat 257
#define SYS_mount 165
#define SYS_epoll_pwait2 441
struct linux_epoll_event {
    uint32_t events;
    uint64_t data;
} __attribute__((packed));
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_openat 56
#define SYS_mount 40
#define SYS_exit 93
#define SYS_epoll_create1 20
#define SYS_epoll_ctl 21
#define SYS_epoll_pwait 22
#define SYS_epoll_pwait2 441
struct linux_epoll_event {
    uint32_t events;
    uint64_t data;
};
#else
#error "epoll_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EEXIST 17
#define EFAULT 14
#define EINVAL 22
#define ENOENT 2

#define O_CLOEXEC 0x00080000u
#define EPOLLIN 0x00000001u
#define EPOLLPRI 0x00000002u
#define EPOLLONESHOT 0x40000000u
#define EPOLLET 0x80000000u
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#define AT_FDCWD -100
#define O_RDONLY 0

struct linux_timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

_Static_assert(sizeof(struct linux_epoll_event) ==
#if defined(__x86_64__)
               12,
#else
               16,
#endif
               "Linux epoll_event ABI size");

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

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2, argument3,
                        0, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
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
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
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
    if (!magnitude) {
        putstr("0");
        return;
    }
    while (magnitude && position) {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    }
    (void)raw_syscall3(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned)position));
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

static int run_probe(void) {
    static const uint64_t initial_data = 0x1122334455667788ULL;
    static const uint64_t modified_data = 0x8877665544332211ULL;
    struct linux_timespec64 zero_timeout = {0, 0};
    struct linux_timespec64 short_timeout = {0, 1000000};
    struct linux_timespec64 invalid_timeout = {0, 1000000000};
    struct linux_epoll_event requested;
    struct linux_epoll_event returned;
    uint64_t signal_mask = 0;
    int descriptors[2] = {-1, -1};
    int nested_descriptors[2] = {-1, -1};
    char byte = 'E';
    long epoll_descriptor;
    long proc_swaps_descriptor;
    long result;
    int failures = 0;

    /* Linux oracle initramfs images do not mount procfs automatically. */
    (void)raw_syscall6(SYS_mount, (long)"proc", (long)"/proc",
                       (long)"proc", 0, 0, 0);

    result = raw_syscall1(SYS_epoll_create1, 1);
    failures += expect_result("create1_invalid_flags", result, -EINVAL);
    epoll_descriptor = raw_syscall1(SYS_epoll_create1, O_CLOEXEC);
    if (epoll_descriptor < 0) {
        failures += expect_result("create1", epoll_descriptor, 0);
        return failures;
    }
#if defined(__x86_64__)
    result = raw_syscall1(SYS_epoll_create, 0);
    failures += expect_result("create_zero", result, -EINVAL);
    result = raw_syscall1(SYS_epoll_create, 1);
    if (result < 0) {
        failures += expect_result("create_legacy", result, 0);
    } else {
        (void)raw_syscall1(SYS_close, result);
    }
#endif

    result = raw_syscall3(SYS_pipe2, (long)descriptors, 0, 0);
    failures += expect_result("pipe2", result, 0);
    if (result < 0) return failures;

    proc_swaps_descriptor = raw_syscall4(SYS_openat, AT_FDCWD,
                                         (long)"/proc/swaps", O_RDONLY, 0);
    if (proc_swaps_descriptor < 0) {
        failures += expect_result("open_proc_swaps", proc_swaps_descriptor, 0);
    } else {
        requested.events = EPOLLPRI;
        requested.data = 0x5357415053ULL;
        result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD,
                              proc_swaps_descriptor, (long)&requested);
        failures += expect_result("ctl_add_proc_swaps_pri", result, 0);
        returned.events = 0;
        returned.data = 0;
        result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                              (long)&returned, 1, (long)&zero_timeout, 0, 0);
        failures += expect_result("proc_swaps_no_spurious_pri", result, 0);
        result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_DEL,
                              proc_swaps_descriptor, 0);
        failures += expect_result("ctl_del_proc_swaps", result, 0);
        (void)raw_syscall1(SYS_close, proc_swaps_descriptor);
    }

    requested.events = EPOLLIN | EPOLLONESHOT;
    requested.data = initial_data;
    result = raw_syscall4(SYS_epoll_ctl, -1, EPOLL_CTL_ADD,
                          -1, 0);
    failures += expect_result("ctl_copy_precedes_fd", result, -EFAULT);
    result = raw_syscall4(SYS_epoll_ctl, -1, EPOLL_CTL_ADD,
                          descriptors[0], (long)&requested);
    failures += expect_result("ctl_bad_epoll", result, -EBADF);
    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD,
                          -1, (long)&requested);
    failures += expect_result("ctl_bad_target", result, -EBADF);
    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD,
                          descriptors[0], 0);
    failures += expect_result("ctl_null_event", result, -EFAULT);
    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD,
                          descriptors[0], (long)&requested);
    failures += expect_result("ctl_add", result, 0);
    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_ADD,
                          descriptors[0], (long)&requested);
    failures += expect_result("ctl_duplicate", result, -EEXIST);

    result = raw_syscall3(SYS_write, descriptors[1], (long)&byte, 1);
    failures += expect_result("pipe_write", result, 1);
    returned.events = 0;
    returned.data = 0;
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          (long)&returned, 1, (long)&zero_timeout, 0, 0);
    failures += expect_result("pwait2_ready", result, 1);
    if (result == 1) {
        if (!(returned.events & EPOLLIN)) {
            putstr("pwait2_missing_epollin\n");
            ++failures;
        }
        if (returned.data != initial_data) {
            putstr("pwait2_data_layout_mismatch\n");
            ++failures;
        }
    }
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          (long)&returned, 1, (long)&zero_timeout, 0, 0);
    failures += expect_result("oneshot_disabled", result, 0);

    requested.events = EPOLLIN;
    requested.data = modified_data;
    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_MOD,
                          descriptors[0], (long)&requested);
    failures += expect_result("ctl_mod", result, 0);
    returned.events = 0;
    returned.data = 0;
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          (long)&returned, 1, (long)&zero_timeout, 0, 0);
    failures += expect_result("mod_rearm", result, 1);
    if (result == 1 && returned.data != modified_data) {
        putstr("mod_data_layout_mismatch\n");
        ++failures;
    }
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          0, 1, (long)&zero_timeout, 0, 0);
    failures += expect_result("pwait2_null_events_ready", result, -EFAULT);

    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_DEL,
                          descriptors[0], 0);
    failures += expect_result("ctl_del_null", result, 0);
    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, EPOLL_CTL_DEL,
                          descriptors[0], 0);
    failures += expect_result("ctl_del_missing", result, -ENOENT);
    result = raw_syscall4(SYS_epoll_ctl, epoll_descriptor, 99,
                          descriptors[0], (long)&requested);
    failures += expect_result("ctl_invalid_operation", result, -EINVAL);

    result = raw_syscall6(SYS_epoll_pwait, epoll_descriptor,
                          (long)&returned, 1, 0, (long)&signal_mask, 16);
    failures += expect_result("pwait_sigset_size", result, -EINVAL);
    result = raw_syscall6(SYS_epoll_pwait, -1,
                          (long)&returned, 1, 0, (long)&signal_mask, 16);
    failures += expect_result("pwait_mask_precedes_fd", result, -EINVAL);
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          (long)&returned, 1, (long)&invalid_timeout, 0, 0);
    failures += expect_result("pwait2_invalid_timeout", result, -EINVAL);
    result = raw_syscall6(SYS_epoll_pwait2, -1,
                          (long)&returned, 1, (long)&invalid_timeout, 0, 0);
    failures += expect_result("pwait2_timeout_precedes_fd", result, -EINVAL);
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          0, 1, (long)&zero_timeout, 0, 0);
    failures += expect_result("pwait2_null_events_empty", result, 0);
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          (long)&returned, 0, (long)&zero_timeout, 0, 0);
    failures += expect_result("pwait2_zero_maxevents", result, -EINVAL);
#if defined(__x86_64__)
    result = raw_syscall4(SYS_epoll_wait, -1, (long)&returned, 0, 0);
    failures += expect_result("wait_fd_precedes_maxevents", result, -EBADF);
#endif
    result = raw_syscall6(SYS_epoll_pwait2, epoll_descriptor,
                          (long)&returned, 1, (long)&short_timeout, 0, 0);
    failures += expect_result("pwait2_timeout", result, 0);

    {
        long inner_epoll = raw_syscall1(SYS_epoll_create1, 0);
        long outer_epoll = raw_syscall1(SYS_epoll_create1, 0);
        failures += expect_result("nested_inner_create",
                                  inner_epoll < 0 ? inner_epoll : 0, 0);
        failures += expect_result("nested_outer_create",
                                  outer_epoll < 0 ? outer_epoll : 0, 0);
        result = raw_syscall3(SYS_pipe2, (long)nested_descriptors, 0, 0);
        failures += expect_result("nested_pipe2", result, 0);
        if (inner_epoll >= 0 && outer_epoll >= 0 && result == 0) {
            requested.events = EPOLLIN | EPOLLET;
            requested.data = 0x494e4e4552ULL;
            result = raw_syscall4(SYS_epoll_ctl, inner_epoll,
                                  EPOLL_CTL_ADD, nested_descriptors[0],
                                  (long)&requested);
            failures += expect_result("nested_ctl_inner", result, 0);
            requested.events = EPOLLIN;
            requested.data = 0x4f55544552ULL;
            result = raw_syscall4(SYS_epoll_ctl, outer_epoll,
                                  EPOLL_CTL_ADD, inner_epoll,
                                  (long)&requested);
            failures += expect_result("nested_ctl_outer", result, 0);
            result = raw_syscall3(SYS_write, nested_descriptors[1],
                                  (long)&byte, 1);
            failures += expect_result("nested_pipe_write", result, 1);
            result = raw_syscall6(SYS_epoll_pwait2, outer_epoll,
                                  (long)&returned, 1,
                                  (long)&zero_timeout, 0, 0);
            failures += expect_result("nested_outer_ready", result, 1);
            result = raw_syscall6(SYS_epoll_pwait2, inner_epoll,
                                  (long)&returned, 1,
                                  (long)&zero_timeout, 0, 0);
            failures += expect_result("nested_inner_consume", result, 1);
            result = raw_syscall6(SYS_epoll_pwait2, outer_epoll,
                                  (long)&returned, 1,
                                  (long)&zero_timeout, 0, 0);
            failures += expect_result("nested_outer_no_stale_edge", result,
                                      0);
        }
        if (nested_descriptors[0] >= 0)
            (void)raw_syscall1(SYS_close, nested_descriptors[0]);
        if (nested_descriptors[1] >= 0)
            (void)raw_syscall1(SYS_close, nested_descriptors[1]);
        if (inner_epoll >= 0) (void)raw_syscall1(SYS_close, inner_epoll);
        if (outer_epoll >= 0) (void)raw_syscall1(SYS_close, outer_epoll);
    }

    (void)raw_syscall1(SYS_close, descriptors[0]);
    (void)raw_syscall1(SYS_close, descriptors[1]);
    (void)raw_syscall1(SYS_close, epoll_descriptor);
    putstr("EPOLL_ABI_PROBE_");
    putstr(failures ? "FAIL failures:" : "PASS failures:");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int result = run_probe();
    (void)raw_syscall1(SYS_exit, result);
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
