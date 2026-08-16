/* SPDX-License-Identifier: MPL-2.0 */
/* Minimal Linux init that starts the loop runtime test on either architecture. */

typedef unsigned long edge_word_t;

static char shell_path[] = "/bin/sh";
static char script_path[] = "/root/loop_device_runtime_test.sh";
static char failure_message[] = "LOOP_RUNTIME_INIT_EXEC_FAILED\n";
static char *const shell_arguments[] = {
    shell_path,
    script_path,
    (char *)0,
};
static char *const empty_environment[] = {
    (char *)0,
};

static long edge_linux_syscall3(edge_word_t number, edge_word_t first,
                                edge_word_t second, edge_word_t third) {
#if defined(__aarch64__)
    register edge_word_t x0 __asm__("x0") = first;
    register edge_word_t x1 __asm__("x1") = second;
    register edge_word_t x2 __asm__("x2") = third;
    register edge_word_t x8 __asm__("x8") = number;

    __asm__ __volatile__("svc #0"
                         : "+r"(x0)
                         : "r"(x1), "r"(x2), "r"(x8)
                         : "memory");
    return (long)x0;
#elif defined(__x86_64__)
    register edge_word_t rax __asm__("rax") = number;
    register edge_word_t rdi __asm__("rdi") = first;
    register edge_word_t rsi __asm__("rsi") = second;
    register edge_word_t rdx __asm__("rdx") = third;

    __asm__ __volatile__("syscall"
                         : "+a"(rax)
                         : "D"(rdi), "S"(rsi), "d"(rdx)
                         : "rcx", "r11", "memory");
    return (long)rax;
#else
#error "The loop runtime init supports only AArch64 and x86_64"
#endif
}

__attribute__((noreturn)) void _start(void) {
#if defined(__aarch64__)
    const edge_word_t execve_number = 221u;
    const edge_word_t write_number = 64u;
#else
    const edge_word_t execve_number = 59u;
    const edge_word_t write_number = 1u;
#endif

    (void)edge_linux_syscall3(
        execve_number, (edge_word_t)shell_path,
        (edge_word_t)shell_arguments, (edge_word_t)empty_environment);
    (void)edge_linux_syscall3(
        write_number, 2u, (edge_word_t)failure_message,
        sizeof(failure_message) - 1u);
    for (;;) {
#if defined(__aarch64__)
        __asm__ __volatile__("wfe");
#else
        __asm__ __volatile__("pause");
#endif
    }
}
