/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux ABI probe for optional native syscall backends. */

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "native_optional_syscalls_abi_probe requires x86_64 or AArch64"
#endif

#if defined(__x86_64__)
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#define SYS_write 1
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_setuid 105
#define SYS_kexec_load 246
#define SYS_kexec_file_load 320
#define SYS_uretprobe 335
#define SYS_uprobe 336
#define SYS_map_shadow_stack 453
#else
#define ENTRY_ALIGNMENT
#define SYS_write 64
#define SYS_exit 93
#define SYS_setuid 146
#define SYS_wait4 260
#define SYS_clone 220
#define SYS_kexec_load 104
#define SYS_kexec_file_load 294
#define SYS_map_shadow_stack 453
#endif

#define EPERM 1
#define ENXIO 6
#define EFAULT 14
#define EINVAL 22
#define ENOSYS 38
#define ENOTSUP 95
#define EADDRNOTAVAIL 99

#define KEXEC_ARCH_X86_64 (62UL << 16)
#define KEXEC_ARCH_AARCH64 (183UL << 16)

struct kexec_segment {
    unsigned long buffer;
    unsigned long buffer_size;
    unsigned long memory;
    unsigned long memory_size;
};

static unsigned char kexec_payload[4096]
    __attribute__((aligned(4096)));

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
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = number;

    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                       "r"(x8)
                     : "cc", "memory");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(
        SYS_write, 1, (long)&buffer[position],
        (long)(sizeof(buffer) - (unsigned long)position), 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" result=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_one_of(const char *name, long actual,
                         long first, long second) {
    if (actual == first || actual == second) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" result=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static int test_kexec_permissions(void) {
    int status = -1;
    long child = raw_syscall6(SYS_clone, 17, 0, 0, 0, 0, 0);

    if (child < 0) return expect_result("fork", child, 0);
    if (child == 0) {
        int failures = 0;
        long architecture =
#if defined(__x86_64__)
            KEXEC_ARCH_X86_64;
#else
            KEXEC_ARCH_AARCH64;
#endif

        failures += expect_result(
            "setuid", raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0), 0);
        failures += expect_result(
            "kexec_load permission",
            raw_syscall6(SYS_kexec_load, 0, 0, 0, architecture, 0, 0),
            -EPERM);
        failures += expect_one_of(
            "kexec_file_load permission",
            raw_syscall6(SYS_kexec_file_load, -1, -1, 0, 0, 0, 0),
            -EPERM, -ENOSYS);
        (void)raw_syscall6(
            SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (raw_syscall6(
            SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child)
        return expect_result("wait4", -1, 0);
    return expect_result("kexec permission child", status, 0);
}

#if defined(__x86_64__)
static int test_uretprobe_direct_entry(void) {
    int status = -1;
    long child = raw_syscall6(SYS_clone, 17, 0, 0, 0, 0, 0);

    if (child < 0) return expect_result("uretprobe fork", child, 0);
    if (child == 0) {
        (void)raw_syscall6(SYS_uretprobe, 0, 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_exit, 99, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (raw_syscall6(
            SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child)
        return expect_result("uretprobe wait4", -1, 0);
    if ((status & 0x7f) == 4) return 0;
    print_text("FAIL uretprobe direct signal status=");
    print_number(status);
    print_text("\n");
    return 1;
}
#endif

static int test_optional_calls(void) {
    int failures = 0;
    struct kexec_segment segment = {
        .buffer = (unsigned long)kexec_payload,
        .buffer_size = sizeof(kexec_payload),
        .memory = 0x02000000,
        .memory_size = sizeof(kexec_payload),
    };
    long architecture =
#if defined(__x86_64__)
        KEXEC_ARCH_X86_64;
#else
        KEXEC_ARCH_AARCH64;
#endif

    failures += expect_result(
        "kexec_load invalid flags",
        raw_syscall6(SYS_kexec_load, 0, 0, 0, architecture | 0x10,
                     0, 0),
        -EINVAL);
    failures += expect_result(
        "kexec_load invalid architecture",
        raw_syscall6(SYS_kexec_load, 0, 0, 0, 1UL << 16, 0, 0),
        -EINVAL);
    failures += expect_result(
        "kexec_load segment limit",
        raw_syscall6(SYS_kexec_load, 0, 17, 0, architecture, 0, 0),
        -EINVAL);
    failures += expect_result(
        "kexec_load segment fault",
        raw_syscall6(SYS_kexec_load, 0, 1, 0, architecture, 0, 0),
        -EFAULT);
    failures += expect_one_of(
        "kexec_load backend",
        raw_syscall6(SYS_kexec_load, 0, 0, 0, architecture, 0, 0),
        0, -ENOTSUP);
    failures += expect_result(
        "kexec_load stage",
        raw_syscall6(SYS_kexec_load, segment.memory, 1,
                     (long)&segment, architecture, 0, 0),
        0);
    failures += expect_result(
        "kexec_load unload",
        raw_syscall6(SYS_kexec_load, 0, 0, 0, architecture, 0, 0),
        0);
    failures += expect_result(
        "kexec_load crash reservation",
        raw_syscall6(SYS_kexec_load, segment.memory, 1,
                     (long)&segment, architecture | 1, 0, 0),
        -EADDRNOTAVAIL);
    failures += expect_one_of(
        "kexec_file_load invalid flags",
        raw_syscall6(SYS_kexec_file_load, -1, -1, 0, 0, 0x40, 0),
        -EINVAL, -ENOSYS);

    /* Unsupported hardware and a disabled backend are distinct Linux states. */
    failures += expect_one_of(
        "map_shadow_stack availability",
        raw_syscall6(SYS_map_shadow_stack, 0, 0, 0, 0, 0, 0),
        -ENOTSUP, -ENOSYS);
#if defined(__x86_64__)
    failures += expect_result(
        "uprobe direct entry",
        raw_syscall6(SYS_uprobe, 0, 0, 0, 0, 0, 0),
        -ENXIO);
    failures += test_uretprobe_direct_entry();
#endif
    return failures;
}

__attribute__((noreturn)) ENTRY_ALIGNMENT void _start(void) {
    int failures = 0;

    failures += test_kexec_permissions();
    failures += test_optional_calls();
    print_text(failures ? "NATIVE_OPTIONAL_SYSCALLS_ABI_PROBE_FAIL\n" :
                          "NATIVE_OPTIONAL_SYSCALLS_ABI_PROBE_PASS\n");
    (void)raw_syscall6(
        SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
