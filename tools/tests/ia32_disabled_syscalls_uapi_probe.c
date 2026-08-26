/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 probe for system calls disabled by configuration. */

#define SYS_exit 1
#define SYS_write 4
#define ENOSYS 38

struct disabled_syscall {
    long number;
    const char *name;
};

__attribute__((naked)) static long raw_call6(
        long number, long a0, long a1, long a2,
        long a3, long a4, long a5) {
    __asm__ volatile(
        "pushl %ebp\n"
        "pushl %edi\n"
        "pushl %esi\n"
        "pushl %ebx\n"
        "movl 20(%esp), %eax\n"
        "movl 24(%esp), %ebx\n"
        "movl 28(%esp), %ecx\n"
        "movl 32(%esp), %edx\n"
        "movl 36(%esp), %esi\n"
        "movl 40(%esp), %edi\n"
        "movl 44(%esp), %ebp\n"
        "int $0x80\n"
        "popl %ebx\n"
        "popl %esi\n"
        "popl %edi\n"
        "popl %ebp\n"
        "ret\n");
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    raw_call6(SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

__attribute__((noreturn)) void _start(void) {
    static const struct disabled_syscall syscalls[] = {
        { 86, "uselib" },
        { 127, "create_module" },
        { 130, "get_kernel_syms" },
        { 137, "afs_syscall" },
        { 149, "_sysctl" },
        { 167, "query_module" },
        { 169, "nfsservctl" },
        { 188, "getpmsg" },
        { 189, "putpmsg" },
        { 253, "lookup_dcookie" },
        { 273, "vserver" },
        { 453, "map_shadow_stack" },
    };
    unsigned long index;
    int failures = 0;

    for (index = 0; index < sizeof(syscalls) / sizeof(syscalls[0]); ++index) {
        long result = raw_call6(
            syscalls[index].number, 0, 0, 0, 0, 0, 0);
        if (result == -ENOSYS) continue;
        print_text("FAIL ");
        print_text(syscalls[index].name);
        print_text("\n");
        ++failures;
    }
    print_text(failures ? "IA32_DISABLED_SYSCALLS_UAPI_PROBE_FAIL\n" :
                          "IA32_DISABLED_SYSCALLS_UAPI_PROBE_PASS\n");
    raw_call6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
