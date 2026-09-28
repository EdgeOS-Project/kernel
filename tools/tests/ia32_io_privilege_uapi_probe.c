/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 probe for I/O privilege system calls. */

#define SYS_exit 1
#define SYS_write 4
#define SYS_setuid32 213
#define SYS_ioperm 101
#define SYS_iopl 110
#define EPERM 1
#define EINVAL 22

__attribute__((naked)) static long raw_call3(
        long number, long first, long second, long third) {
    __asm__ volatile(
        "pushl %ebx\n"
        "movl 8(%esp), %eax\n"
        "movl 12(%esp), %ebx\n"
        "movl 16(%esp), %ecx\n"
        "movl 20(%esp), %edx\n"
        "int $0x80\n"
        "popl %ebx\n"
        "ret\n");
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_call3(SYS_write, 1, (long)text, text_length(text));
}

static int expect(const char *name, long result, long expected) {
    if (result == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

__attribute__((noreturn)) void _start(void) {
    int failures = 0;

    failures += expect("iopl invalid level", raw_call3(SYS_iopl, 4, 0, 0),
                       -EINVAL);
    failures += expect("ioperm invalid range",
                       raw_call3(SYS_ioperm, 65536, 1, 1), -EINVAL);
    failures += expect("iopl clear", raw_call3(SYS_iopl, 0, 0, 0), 0);
    failures += expect("setuid32", raw_call3(SYS_setuid32, 65534, 0, 0), 0);
    failures += expect("iopl permission", raw_call3(SYS_iopl, 3, 0, 0),
                       -EPERM);
    failures += expect("ioperm permission",
                       raw_call3(SYS_ioperm, 0, 1, 1), -EPERM);
    print_text(failures ? "IA32_IO_PRIVILEGE_UAPI_PROBE_FAIL\n" :
                          "IA32_IO_PRIVILEGE_UAPI_PROBE_PASS\n");
    (void)raw_call3(SYS_exit, failures ? 1 : 0, 0, 0);
    __builtin_unreachable();
}
