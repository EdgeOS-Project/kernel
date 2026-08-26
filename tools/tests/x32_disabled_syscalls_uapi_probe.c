/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux x32 probe for reserved common syscall slots. */

#include <stdint.h>

#define X32_SYSCALL_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_exit 60
#define ENOSYS 38

struct disabled_syscall {
    long number;
    const char *name;
};

static long raw_syscall6(long number, long first, long second, long third,
                         long fourth, long fifth, long sixth) {
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    register long r9 __asm__("r9") = sixth;
    long result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(X32_SYSCALL_BIT | SYS_write, 1, (long)text,
                       text_length(text), 0, 0, 0);
}

__attribute__((noreturn, force_align_arg_pointer)) void _start(void) {
    static const struct disabled_syscall syscalls[] = {
        { 181, "getpmsg" },
        { 182, "putpmsg" },
        { 183, "afs_syscall" },
        { 184, "tuxcall" },
        { 185, "security" },
        { 212, "lookup_dcookie" },
    };
    uint32_t index;
    int failures = 0;

    for (index = 0; index < sizeof(syscalls) / sizeof(syscalls[0]); ++index) {
        long result = raw_syscall6(X32_SYSCALL_BIT | syscalls[index].number,
                                   0, 0, 0, 0, 0, 0);
        if (result == -ENOSYS) continue;
        print_text("FAIL ");
        print_text(syscalls[index].name);
        print_text("\n");
        ++failures;
    }
    print_text(failures ? "X32_DISABLED_SYSCALLS_UAPI_PROBE_FAIL\n" :
                          "X32_DISABLED_SYSCALLS_UAPI_PROBE_PASS\n");
    (void)raw_syscall6(X32_SYSCALL_BIT | SYS_exit, failures ? 1 : 0,
                       0, 0, 0, 0, 0);
    __builtin_unreachable();
}
