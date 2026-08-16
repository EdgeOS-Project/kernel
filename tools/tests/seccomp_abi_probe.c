/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux seccomp ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_setuid 105
#define SYS_getppid 110
#define SYS_prctl 157
#define SYS_seccomp 317
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_setuid 146
#define SYS_prctl 167
#define SYS_getppid 173
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_seccomp 277
#define ENTRY_ALIGNMENT
#else
#error "seccomp_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define EACCES 13
#define EFAULT 14
#define EINVAL 22
#define EOPNOTSUPP 95

#define SIGCHLD 17
#define PR_SET_SECCOMP 22
#define PR_SET_NO_NEW_PRIVS 38
#define SECCOMP_MODE_FILTER 2

#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_GET_NOTIF_SIZES 3

#define SECCOMP_FILTER_FLAG_LOG (1u << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1u << 2)
#define SECCOMP_FILTER_FLAG_TSYNC (1u << 0)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1u << 4)

#define SECCOMP_RET_ERRNO 0x00050000u
#define SECCOMP_RET_LOG 0x7ffc0000u
#define SECCOMP_RET_ALLOW 0x7fff0000u

#define BPF_LD 0x00u
#define BPF_W 0x00u
#define BPF_ABS 0x20u
#define BPF_JMP 0x05u
#define BPF_JEQ 0x10u
#define BPF_K 0x00u
#define BPF_RET 0x06u

struct linux_sock_filter {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t value;
};

struct linux_sock_fprog {
    uint16_t length;
    uint16_t padding[3];
    uint64_t filter;
};

struct linux_seccomp_notif_sizes {
    uint16_t seccomp_notif;
    uint16_t seccomp_notif_resp;
    uint16_t seccomp_data;
};

_Static_assert(sizeof(struct linux_sock_filter) == 8,
               "Linux sock_filter ABI size");
_Static_assert(sizeof(struct linux_sock_fprog) == 16,
               "Linux sock_fprog ABI size");
_Static_assert(sizeof(struct linux_seccomp_notif_sizes) == 6,
               "Linux seccomp_notif_sizes ABI size");

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

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static long seccomp_call(uint32_t operation, uint32_t flags,
                         const void *argument) {
    return raw_syscall6(SYS_seccomp, operation, flags,
                        (long)argument, 0, 0, 0);
}

static int run_filtered_child(void) {
    struct linux_sock_filter instructions[] = {
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, 0},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_getppid},
        {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM},
        {BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW},
    };
    struct linux_sock_fprog program = {
        .length = (uint16_t)(sizeof(instructions) / sizeof(instructions[0])),
        .padding = {0, 0, 0},
        .filter = (uint64_t)(uintptr_t)instructions,
    };
    struct linux_sock_fprog empty_program = {
        .length = 0,
        .padding = {0, 0, 0},
        .filter = (uint64_t)(uintptr_t)instructions,
    };
    long grandchild;
    int grandchild_status = 0;
    int failures = 0;

    failures += expect_result("drop privilege",
        raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0), 0);
    failures += expect_result("filter requires privilege or no-new-privs",
        seccomp_call(SECCOMP_SET_MODE_FILTER, 0, &program), -EACCES);
    failures += expect_result("set no-new-privs",
        raw_syscall6(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0), 0);
    failures += expect_result("null filter program",
        seccomp_call(SECCOMP_SET_MODE_FILTER, 0, 0), -EFAULT);
    failures += expect_result("invalid filter pointer",
        seccomp_call(SECCOMP_SET_MODE_FILTER, 0, (const void *)1), -EFAULT);
    failures += expect_result("empty filter program",
        seccomp_call(SECCOMP_SET_MODE_FILTER, 0, &empty_program), -EINVAL);
    failures += expect_result("install errno filter",
        seccomp_call(SECCOMP_SET_MODE_FILTER, 0, &program), 0);
    failures += expect_result("filter errno action",
        raw_syscall6(SYS_getppid, 0, 0, 0, 0, 0, 0), -EPERM);
    failures += expect_result("stack log filter",
        seccomp_call(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG,
                     &program), 0);
    failures += expect_result("stack speculative-allow filter",
        seccomp_call(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_SPEC_ALLOW,
                     &program), 0);
    failures += expect_result("stack thread-synchronized filter",
        seccomp_call(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
                     &program), 0);
    failures += expect_result("stack filter through prctl",
        raw_syscall6(SYS_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                     (long)&program, 0, 0, 0), 0);
    failures += expect_result("stacked filters preserve strictest action",
        raw_syscall6(SYS_getppid, 0, 0, 0, 0, 0, 0), -EPERM);

    grandchild = create_child();
    failures += expect_true("fork after filter", grandchild >= 0);
    if (grandchild == 0) {
        int inherited_failures = expect_result("inherited filter action",
            raw_syscall6(SYS_getppid, 0, 0, 0, 0, 0, 0), -EPERM);
        raw_syscall6(SYS_exit, inherited_failures ? 1 : 0, 0, 0, 0, 0, 0);
        for (;;) { }
    }
    if (grandchild > 0) {
        failures += expect_result("wait filtered grandchild", raw_syscall6(
            SYS_wait4, grandchild, (long)&grandchild_status, 0, 0, 0, 0),
            grandchild);
        failures += expect_result("filtered grandchild status",
                                   grandchild_status, 0);
    }
    return failures;
}

static int run_tests(void) {
    struct linux_seccomp_notif_sizes sizes = {0, 0, 0};
    uint32_t action;
    long child;
    int child_status = 0;
    int failures = 0;

    failures += expect_result("unknown operation",
        seccomp_call(0xffffffffu, 0, 0), -EINVAL);
    failures += expect_result("strict rejects flags",
        seccomp_call(SECCOMP_SET_MODE_STRICT, 1, 0), -EINVAL);
    failures += expect_result("strict rejects argument",
        seccomp_call(SECCOMP_SET_MODE_STRICT, 0, &sizes), -EINVAL);
    failures += expect_result("filter rejects unknown flags",
        seccomp_call(SECCOMP_SET_MODE_FILTER, 0x80000000u, &sizes), -EINVAL);
    failures += expect_result("tsync-esrch requires tsync",
        seccomp_call(SECCOMP_SET_MODE_FILTER,
                     SECCOMP_FILTER_FLAG_TSYNC_ESRCH, &sizes), -EINVAL);

    action = SECCOMP_RET_ALLOW;
    failures += expect_result("allow action available",
        seccomp_call(SECCOMP_GET_ACTION_AVAIL, 0, &action), 0);
    action = SECCOMP_RET_LOG;
    failures += expect_result("log action available",
        seccomp_call(SECCOMP_GET_ACTION_AVAIL, 0, &action), 0);
    action = 0x12340000u;
    failures += expect_result("unknown action unavailable",
        seccomp_call(SECCOMP_GET_ACTION_AVAIL, 0, &action), -EOPNOTSUPP);
    failures += expect_result("action discovery rejects flags",
        seccomp_call(SECCOMP_GET_ACTION_AVAIL, 1, &action), -EINVAL);
    failures += expect_result("action discovery null pointer",
        seccomp_call(SECCOMP_GET_ACTION_AVAIL, 0, 0), -EFAULT);

    failures += expect_result("notification sizes",
        seccomp_call(SECCOMP_GET_NOTIF_SIZES, 0, &sizes), 0);
    failures += expect_true("notification layout sizes",
        sizes.seccomp_notif == 80 && sizes.seccomp_notif_resp == 24 &&
        sizes.seccomp_data == 64);
    failures += expect_result("notification sizes reject flags",
        seccomp_call(SECCOMP_GET_NOTIF_SIZES, 1, &sizes), -EINVAL);
    failures += expect_result("notification sizes null pointer",
        seccomp_call(SECCOMP_GET_NOTIF_SIZES, 0, 0), -EFAULT);

    child = create_child();
    failures += expect_true("fork seccomp child", child >= 0);
    if (child == 0) {
        int child_failures = run_filtered_child();
        raw_syscall6(SYS_exit, child_failures ? 1 : 0, 0, 0, 0, 0, 0);
        for (;;) { }
    }
    if (child > 0) {
        failures += expect_result("wait seccomp child", raw_syscall6(
            SYS_wait4, child, (long)&child_status, 0, 0, 0, 0), child);
        failures += expect_result("seccomp child status", child_status, 0);
    }
    return failures;
}

ENTRY_ALIGNMENT void _start(void) {
    int failures = run_tests();
    if (failures) {
        print_text("seccomp-abi: FAIL count=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("seccomp-abi: PASS\n");
    }
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
