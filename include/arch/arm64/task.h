/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 task-context ABI.
 * Copyright (c) EdgeOS Contributors.
 *
 * AArch64 scheduling state is intentionally kept separate from x86_64's
 * CR3/FXSAVE context.  Linux AArch64 user TLS is TPIDR_EL0 and exceptions
 * return through ELR_EL1/SPSR_EL1, not an x86 IRET frame.
 */
#ifndef EDGEOS_ARCH_ARM64_TASK_H
#define EDGEOS_ARCH_ARM64_TASK_H

#include <stdint.h>
#include <stddef.h>

typedef struct edgeos_arm64_cpu_context {
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;
    uint64_t x29;
    uint64_t x30;
    uint64_t sp;
    uint64_t pc;
} edgeos_arm64_cpu_context_t;

_Static_assert(offsetof(edgeos_arm64_cpu_context_t, x19) == 0, "switch.S x19 offset");
_Static_assert(offsetof(edgeos_arm64_cpu_context_t, x29) == 80, "switch.S x29 offset");
_Static_assert(offsetof(edgeos_arm64_cpu_context_t, x30) == 88, "switch.S x30 offset");
_Static_assert(offsetof(edgeos_arm64_cpu_context_t, sp) == 96, "switch.S sp offset");
_Static_assert(offsetof(edgeos_arm64_cpu_context_t, pc) == 104, "switch.S pc offset");

typedef struct edgeos_arm64_trap_frame {
    uint64_t x[31];
    uint64_t esr;
    uint64_t far;
    uint64_t elr;
    uint64_t spsr;
    uint64_t sp_el0;
} edgeos_arm64_trap_frame_t;

void edgeos_arm64_context_switch(edgeos_arm64_cpu_context_t *prev,
                                 const edgeos_arm64_cpu_context_t *next);
int edgeos_arm64_context_selftest(void);

#endif
