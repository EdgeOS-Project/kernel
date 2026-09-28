/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux module syscall validation-order probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_capget 125
#define SYS_init_module 175
#define SYS_delete_module 176
#define SYS_finit_module 313
#define START_ATTRIBUTES __attribute__((naked, noreturn))
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_capget 90
#define SYS_init_module 105
#define SYS_delete_module 106
#define SYS_finit_module 273
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "module_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define EBADF 9
#define EFAULT 14
#define EINVAL 22
#define LINUX_CAPABILITY_VERSION_3 UINT32_C(0x20080522)
#define LINUX_CAP_SYS_MODULE 16u

struct linux_capability_header {
    uint32_t version;
    int32_t pid;
};

struct linux_capability_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
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
    char output[24];
    unsigned long magnitude;
    int position = (int)sizeof(output);

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&output[position],
                       (long)(sizeof(output) - (unsigned long)position),
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

static int has_module_capability(void) {
    struct linux_capability_header header = {
        .version = LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct linux_capability_data data[2] = {{0}};
    long result = raw_syscall6(SYS_capget, (long)&header, (long)data,
                               0, 0, 0, 0);

    if (result != 0) return 0;
    return (data[LINUX_CAP_SYS_MODULE / 32u].effective &
            (UINT32_C(1) << (LINUX_CAP_SYS_MODULE % 32u))) != 0;
}

static int run_probe(void) {
    static const char empty[] = "";
    int privileged = has_module_capability();
    int failures = 0;

    failures += expect_result(
        "init bad image",
        raw_syscall6(SYS_init_module, 1, 64, (long)empty, 0, 0, 0),
        privileged ? -EFAULT : -EPERM);
    failures += expect_result(
        "delete bad name",
        raw_syscall6(SYS_delete_module, 1, 0, 0, 0, 0, 0),
        privileged ? -EFAULT : -EPERM);
    failures += expect_result(
        "finit bad descriptor",
        raw_syscall6(SYS_finit_module, -1, (long)empty, 0, 0, 0, 0),
        privileged ? -EBADF : -EPERM);
    failures += expect_result(
        "finit bad flags",
        raw_syscall6(SYS_finit_module, -1, (long)empty,
                     UINT32_C(0x80000000), 0, 0, 0),
        privileged ? -EINVAL : -EPERM);

    print_text(failures ? "MODULE_ABI_PROBE_FAIL\n" :
                          "MODULE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall6(SYS_exit, run_probe(), 0, 0, 0, 0, 0);
    for (;;) {}
}

#if defined(__x86_64__)
START_ATTRIBUTES void _start(void) {
    __asm__ volatile("andq $-16, %rsp\ncall probe_entry");
}
#else
START_ATTRIBUTES void _start(void) {
    probe_entry();
}
#endif
