/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal successful exec target used by freestanding ABI probes. */

#if defined(__x86_64__)
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_exit 93
#else
#error "exec_true_helper requires a Linux 64-bit architecture"
#endif

__attribute__((noreturn)) void _start(void) {
#if defined(__x86_64__)
    __asm__ __volatile__("syscall"
                         :
                         : "a"(SYS_exit), "D"(0)
                         : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = SYS_exit;
    register long x0 __asm__("x0") = 0;
    __asm__ __volatile__("svc #0"
                         : "+r"(x0)
                         : "r"(x8)
                         : "memory", "cc");
#endif
    __builtin_unreachable();
}
