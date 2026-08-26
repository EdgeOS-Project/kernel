/* SPDX-License-Identifier: MPL-2.0 */
/* Shebang interpreter used by the freestanding exec ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_exit 93
#else
#error "exec_script_helper requires a Linux 64-bit architecture"
#endif

static int text_equal(const char *left, const char *right) {
    if (!left || !right) return 0;
    while (*left && *right) {
        if (*left++ != *right++) return 0;
    }
    return *left == *right;
}

__attribute__((noreturn)) static void exit_now(int status) {
#if defined(__x86_64__)
    __asm__ __volatile__("syscall"
                         :
                         : "a"(SYS_exit), "D"(status)
                         : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = SYS_exit;
    register long x0 __asm__("x0") = status;
    __asm__ __volatile__("svc #0"
                         : "+r"(x0)
                         : "r"(x8)
                         : "memory", "cc");
#endif
    __builtin_unreachable();
}

__attribute__((noreturn, used)) void probe_entry(uintptr_t *initial_stack) {
    static const char expected[] = "/tmp/edgeos-exec-script-alias";
    unsigned long argument_count = initial_stack ? initial_stack[0] : 0;
    char **arguments = initial_stack ? (char **)&initial_stack[1] : 0;

    exit_now(argument_count >= 2 && arguments &&
                     text_equal(arguments[1], expected)
                 ? 0
                 : 1);
}

#if defined(__x86_64__)
__asm__(".global _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "mov %rsp, %rdi\n"
        "and $-16, %rsp\n"
        "call probe_entry\n");
#else
__asm__(".global _start\n"
        ".type _start,%function\n"
        "_start:\n"
        "mov x0, sp\n"
        "bl probe_entry\n");
#endif
