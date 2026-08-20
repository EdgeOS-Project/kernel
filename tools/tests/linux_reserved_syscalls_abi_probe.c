/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux ABI probe for reserved x86_64 syscall slots. */

#if !defined(__x86_64__)
#error "linux_reserved_syscalls_abi_probe requires the Linux x86_64 ABI"
#endif

#define SYS_write 1
#define SYS_exit 60
#define ENOSYS 38

struct reserved_syscall {
    long number;
    const char *name;
};

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
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int run_tests(void) {
    static const struct reserved_syscall syscalls[] = {
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
        { 214, "epoll_ctl_old" },
        { 215, "epoll_wait_old" },
        { 236, "vserver" },
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
