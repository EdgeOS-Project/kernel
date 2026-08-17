/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_X86_64_SYSCALL_H
#define EDGEOS_ARCH_X86_64_SYSCALL_H

#include <stdint.h>

#include "arch/x86_64/interrupt.h"

/*
 * x86-64 entry state is addressed through the kernel GS base while executing
 * in ring 0.  The assembly offsets are part of the architecture ABI; keep the
 * layout checks in syscall.c synchronized with syscall.asm.
 */
typedef struct edgeos_x86_64_syscall_cpu {
    uint64_t kernel_rsp;
    uint64_t user_rsp;
    uint64_t fs_base;
    uint64_t fs_base_valid;
    uint64_t user_gs_base;
    uint64_t user_gs_base_valid;
    uint64_t logical_id;
} edgeos_x86_64_syscall_cpu_t;

void edgeos_x86_64_syscall_init(void);
void edgeos_x86_64_syscall_init_cpu(uint32_t logical_id);
int edgeos_x86_64_syscall_identity_ready(void);
uint32_t edgeos_x86_64_syscall_cpu_id(void);
void edgeos_x86_64_syscall_set_kernel_rsp(uint64_t rsp);
void edgeos_x86_64_set_fs_base(uint64_t base);
void edgeos_x86_64_set_user_gs_base(uint64_t base);
int edgeos_x86_64_deliver_signal_on_user_return(
    edgeos_x86_64_interrupt_frame_t *frame);

#endif /* EDGEOS_ARCH_X86_64_SYSCALL_H */
