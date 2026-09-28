/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 SVC ABI entry.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux AArch64 passes the syscall number in x8 and arguments in x0..x5.
 * Keep the low-level trap path independent of the higher-level process and
 * file-descriptor implementation so it can be shared once that subsystem is
 * converted from x86 trap frames.
 */

#include <stdint.h>
#include "arch/arm64/syscall.h"
#include "kernel/runtime.h"
#ifdef CONFIG_BSD_DRIVER_BRIDGE
#include "compat/freebsd/edgeos/kthread.h"
#endif

#define EDGEOS_LINUX_ENOSYS 38

static edgeos_arm64_syscall_handler_t g_syscall_handler;

void edgeos_arm64_syscall_register(edgeos_arm64_syscall_handler_t handler) {
    g_syscall_handler = handler;
}

void edgeos_arm64_syscall_dispatch(edgeos_arm64_exception_frame_t *frame) {
    uint64_t number;
    int64_t result;
    if (!frame) return;
    if (!g_syscall_handler) {
        frame->x[0] = (uint64_t)-EDGEOS_LINUX_ENOSYS;
        return;
    }
    number = frame->x[8];
    result = g_syscall_handler(number, frame->x[0], frame->x[1],
                               frame->x[2], frame->x[3], frame->x[4],
                               frame->x[5], frame);
    frame->x[0] = (uint64_t)result;
}

int edgeos_arm64_syscall_selftest(void) {
    register uint64_t nr __asm__("x8") = 0xffffu;
    register uint64_t result __asm__("x0") = 0;
    __asm__ __volatile__("svc #0" : "+r"(result) : "r"(nr) : "memory");
    return result == (uint64_t)-EDGEOS_LINUX_ENOSYS ? 0 : -1;
}
