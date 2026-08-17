/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux exit and exit_group ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define SYS_exit 60
#define SYS_exit_group 231
#elif defined(__aarch64__)
#define SYS_exit 93
#define SYS_exit_group 94
#else
#error "exit_abi_probe requires a Linux 64-bit architecture"
#endif

static long raw_syscall1(long number, long argument) {
#if defined(__x86_64__)
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(argument)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8)
                     : "memory", "cc");
    return x0;
#endif
}

static int wait_for_exit(pid_t child, int expected) {
    int status = 0;
    pid_t result;

    do {
        result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    if (result != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != expected) {
        fprintf(stderr,
                "unexpected child status: pid=%ld result=%ld status=0x%x\n",
                (long)child, (long)result, status);
        return -1;
    }
    return 0;
}

static int check_exit(long syscall_number, int code) {
    pid_t child = fork();

    if (child < 0) {
        perror("fork");
        return -1;
    }
    if (child == 0) {
        (void)raw_syscall1(syscall_number, code);
        _exit(127);
    }
    return wait_for_exit(child, code & 0xff);
}

int main(void) {
    if (check_exit(SYS_exit, 0x15a) < 0) return 1;
    if (check_exit(SYS_exit_group, 0x2a5) < 0) return 2;
    puts("EXIT_ABI_PROBE_PASS");
    return 0;
}
