/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t got_sigint;
static volatile sig_atomic_t saw_linux_stack_alignment;

static void sigint_handler(int signo) {
    uintptr_t rsp;

    __asm__ __volatile__("mov %%rsp,%0" : "=r"(rsp));
    got_sigint = signo == SIGINT;
    /*
     * Linux/x86-64 signal handlers enter as normal ABI callees with a restorer
     * return address at %rsp.  Therefore %rsp must be 8 mod 16 and (%rsp + 8)
     * must be 16-byte aligned for compiler-generated aligned stack accesses.
     */
    saw_linux_stack_alignment = ((rsp & 15u) == 8u);
}

int main(void) {
    struct sigaction sa;

    setvbuf(stdout, NULL, _IONBF, 0);

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigint_handler;
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        printf("sigalign_sigaction_errno:%d\n", errno);
        return 1;
    }

    if (raise(SIGINT) < 0) {
        printf("sigalign_raise_errno:%d\n", errno);
        return 1;
    }

    printf("sigalign_got:%d aligned:%d\n",
           (int)got_sigint, (int)saw_linux_stack_alignment);
    if (!got_sigint || !saw_linux_stack_alignment) return 1;

    printf("SIGNAL_STACK_ALIGNMENT_PROBE_PASS\n");
    return 0;
}
