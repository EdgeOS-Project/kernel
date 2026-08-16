/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 SVC dispatch interface. */
#ifndef EDGEOS_ARCH_ARM64_SYSCALL_H
#define EDGEOS_ARCH_ARM64_SYSCALL_H

#include "arch/arm64/interrupt.h"

typedef int64_t (*edgeos_arm64_syscall_handler_t)(uint64_t nr,
                                                   uint64_t a0, uint64_t a1,
                                                   uint64_t a2, uint64_t a3,
                                                   uint64_t a4, uint64_t a5,
                                                   edgeos_arm64_exception_frame_t *frame);

void edgeos_arm64_syscall_register(edgeos_arm64_syscall_handler_t handler);
void edgeos_arm64_syscall_dispatch(edgeos_arm64_exception_frame_t *frame);
int edgeos_arm64_syscall_selftest(void);

#endif
