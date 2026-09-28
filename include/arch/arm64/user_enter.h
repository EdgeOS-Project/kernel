/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 EL0 entry interface. */
#ifndef EDGEOS_ARCH_ARM64_USER_ENTER_H
#define EDGEOS_ARCH_ARM64_USER_ENTER_H

#include <stdint.h>
#include "arch/arm64/interrupt.h"

__attribute__((noreturn)) void edgeos_arm64_enter_user(uint64_t ttbr0,
                                                       uint64_t entry,
                                                       uint64_t stack_pointer,
                                                       uint64_t kernel_stack_pointer);
__attribute__((noreturn)) void edgeos_arm64_resume_user(uint64_t ttbr0,
                                                         const edgeos_arm64_exception_frame_t *frame,
                                                         uint64_t kernel_stack_pointer);

#endif
