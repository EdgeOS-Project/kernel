/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Validate Linux x86_64 signal-frame restoration for processor-supported
 * MXCSR features.  DAZ is the useful regression bit because older fixed-mask
 * validators incorrectly reject it even when MXCSR_MASK advertises support.
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__x86_64__)
int main(void) {
    puts("SIGNAL_FPSTATE_ABI_PROBE_SKIP non-x86_64");
    return 0;
}
#else

#define X86_MXCSR_DAZ (UINT32_C(1) << 6)

static volatile sig_atomic_t signal_seen;

static void signal_handler(int signal_number) {
    signal_seen = signal_number == SIGUSR1;
}

static uint32_t read_mxcsr(void) {
    uint32_t value;
    __asm__ __volatile__("stmxcsr %0" : "=m"(value));
    return value;
}

static void write_mxcsr(uint32_t value) {
    __asm__ __volatile__("ldmxcsr %0" :: "m"(value));
}

static uint32_t read_supported_mxcsr_mask(void) {
    uint8_t state[512] __attribute__((aligned(16)));
    uint32_t mask;

    memset(state, 0, sizeof(state));
    __asm__ __volatile__("fxsave %0" : "=m"(state));
    memcpy(&mask, state + 28, sizeof(mask));
    return mask ? mask : UINT32_C(0x0000ffbf);
}

int main(void) {
    struct sigaction action;
    uint32_t original_mxcsr;
    uint32_t requested_mxcsr;
    uint32_t restored_mxcsr;
    uint32_t supported_mask;

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = signal_handler;
    if (sigaction(SIGUSR1, &action, NULL) < 0) {
        perror("sigaction");
        return 1;
    }

    supported_mask = read_supported_mxcsr_mask();
    original_mxcsr = read_mxcsr();
    if ((supported_mask & X86_MXCSR_DAZ) == 0) {
        printf("SIGNAL_FPSTATE_ABI_PROBE_SKIP mxcsr_mask=0x%08x\n",
               supported_mask);
        return 0;
    }

    requested_mxcsr = original_mxcsr | X86_MXCSR_DAZ;
    write_mxcsr(requested_mxcsr);
    if (raise(SIGUSR1) < 0) {
        perror("raise");
        write_mxcsr(original_mxcsr);
        return 1;
    }
    restored_mxcsr = read_mxcsr();
    write_mxcsr(original_mxcsr);

    printf("signal_seen:%d mxcsr_mask:0x%08x requested:0x%08x restored:0x%08x\n",
           (int)signal_seen, supported_mask, requested_mxcsr, restored_mxcsr);
    if (!signal_seen || restored_mxcsr != requested_mxcsr) {
        puts("SIGNAL_FPSTATE_ABI_PROBE_FAIL");
        return 1;
    }
    puts("SIGNAL_FPSTATE_ABI_PROBE_PASS");
    return 0;
}

#endif
