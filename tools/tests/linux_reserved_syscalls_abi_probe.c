/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux ABI probe for architecture-reserved syscall slots. */

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#else
#error "linux_reserved_syscalls_abi_probe requires x86_64 or AArch64"
#endif

#define ENOSYS 38

struct reserved_syscall {
    long number;
    const char *name;
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

static int run_tests(void) {
    static const struct reserved_syscall syscalls[] = {
#if defined(__x86_64__)
        { 134, "uselib" },
        { 156, "_sysctl" },
        { 174, "create_module" },
        { 177, "get_kernel_syms" },
        { 178, "query_module" },
        { 180, "nfsservctl" },
        { 181, "getpmsg" },
        { 182, "putpmsg" },
        { 183, "afs_syscall" },
        { 184, "tuxcall" },
        { 185, "security" },
        { 205, "set_thread_area" },
        { 211, "get_thread_area" },
        { 212, "lookup_dcookie" },
        { 214, "epoll_ctl_old" },
        { 215, "epoll_wait_old" },
        { 236, "vserver" },
#else
        { 18, "lookup_dcookie" },
        { 42, "nfsservctl" },
#endif
    };
    unsigned long index;
    int failures = 0;

    for (index = 0; index < sizeof(syscalls) / sizeof(syscalls[0]); ++index) {
        long result = raw_syscall6(syscalls[index].number, 0, 0, 0, 0, 0, 0);
        if (result == -ENOSYS) continue;
        print_text("FAIL ");
        print_text(syscalls[index].name);
        print_text("\n");
        ++failures;
    }
    return failures;
}

__attribute__((noreturn)) void _start(void) {
    int failures = run_tests();
    print_text(failures ? "LINUX_RESERVED_SYSCALLS_ABI_PROBE_FAIL\n" :
                          "LINUX_RESERVED_SYSCALLS_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
