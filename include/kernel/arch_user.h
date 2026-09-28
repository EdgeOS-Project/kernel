/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_ARCH_USER_H
#define EDGEOS_KERNEL_ARCH_USER_H

#include <stdint.h>

#include "arch/user.h"
typedef int64_t (*arch_syscall_handler_t)(uint64_t nr,
                                          uint64_t a0, uint64_t a1,
                                          uint64_t a2, uint64_t a3,
                                          uint64_t a4, uint64_t a5,
                                          arch_user_frame_t *frame);

uint16_t arch_user_elf_machine(void);
void arch_syscall_register(arch_syscall_handler_t handler);
__attribute__((noreturn)) void arch_user_enter(uint64_t address_space,
                                               uint64_t entry,
                                               uint64_t stack_pointer,
                                               uint64_t kernel_stack_pointer);
__attribute__((noreturn)) void arch_user_resume(uint64_t address_space,
                                                const arch_user_frame_t *frame,
                                                uint64_t kernel_stack_pointer);

#endif
