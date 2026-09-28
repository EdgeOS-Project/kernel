/* SPDX-License-Identifier: MPL-2.0 */
/* Exec target used by the freestanding process session ABI probe. */

#if defined(__x86_64__)
#define SYS_sched_yield 24
#elif defined(__aarch64__)
#define SYS_sched_yield 124
#else
#error "process_session_exec_helper requires a Linux 64-bit architecture"
#endif

static long raw_sched_yield(void) {
#if defined(__x86_64__)
    long result;
    __asm__ __volatile__("syscall"
                         : "=a"(result)
                         : "a"(SYS_sched_yield)
                         : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = SYS_sched_yield;
    register long x0 __asm__("x0") = 0;
    __asm__ __volatile__("svc #0"
                         : "+r"(x0)
                         : "r"(x8)
                         : "memory", "cc");
    return x0;
#endif
}

__attribute__((noreturn)) void _start(void) {
    for (;;) (void)raw_sched_yield();
}
