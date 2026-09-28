/* SPDX-License-Identifier: MPL-2.0 */
/* Pin a freestanding CPU worker for scheduler runtime tests. */
#include <stdint.h>

#if defined(__x86_64__)
#define EDGE_SYS_SCHED_SETAFFINITY 203L
#define EDGE_SYS_EXIT 60L

static long raw_syscall1(long number, long argument) {
    register long result __asm__("rax") = number;

    __asm__ volatile("syscall"
                     : "+a"(result)
                     : "D"(argument)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw_sched_setaffinity(uint64_t *mask) {
    register long result __asm__("rax") = EDGE_SYS_SCHED_SETAFFINITY;

    __asm__ volatile("syscall"
                     : "+a"(result)
                     : "D"(0L), "S"(8L), "d"(mask)
                     : "rcx", "r11", "memory");
    return result;
}
#elif defined(__aarch64__)
#define EDGE_SYS_SCHED_SETAFFINITY 122L
#define EDGE_SYS_EXIT 93L

static long raw_syscall1(long number, long argument) {
    register long x0 __asm__("x0") = argument;
    register long x8 __asm__("x8") = number;

    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8)
                     : "memory");
    return x0;
}

static long raw_sched_setaffinity(uint64_t *mask) {
    register long x0 __asm__("x0") = 0L;
    register long x1 __asm__("x1") = 8L;
    register long x2 __asm__("x2") = (long)mask;
    register long x8 __asm__("x8") = EDGE_SYS_SCHED_SETAFFINITY;

    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8)
                     : "memory");
    return x0;
}
#else
#error "scheduler_affinity_busy requires x86_64 or AArch64"
#endif

static uint32_t parse_cpu(const char *text) {
    uint32_t cpu = 0u;

    if (!text || !*text) return 0u;
    while (*text >= '0' && *text <= '9') {
        uint32_t digit = (uint32_t)(*text++ - '0');

        if (cpu > 6u || (cpu == 6u && digit > 3u)) return 0u;
        cpu = cpu * 10u + digit;
    }
    return *text ? 0u : cpu;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(
        uintptr_t *initial_stack) {
    uint32_t cpu = 0u;
    uint64_t mask;

    if (initial_stack && initial_stack[0] > 1u) {
        const char *const *arguments =
            (const char *const *)(uintptr_t)&initial_stack[1];

        cpu = parse_cpu(arguments[1]);
    }
    mask = UINT64_C(1) << cpu;

    if (raw_sched_setaffinity(&mask) < 0)
        raw_syscall1(EDGE_SYS_EXIT, 1L);
    for (;;) __asm__ volatile("" ::: "memory");
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "movq %rsp, %rdi\n"
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "mov x0, sp\n"
        "b probe_entry\n");
}
#endif
