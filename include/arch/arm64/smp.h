/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 SMP bring-up interface. */
#ifndef EDGEOS_ARCH_ARM64_SMP_H
#define EDGEOS_ARCH_ARM64_SMP_H

#include <stdint.h>

#include "arch/arm64/bootinfo.h"

int edgeos_arm64_smp_discover(const edgeos_arm64_bootinfo_t *bootinfo);
int edgeos_arm64_smp_start_secondary_cpus(void);
uint32_t edgeos_arm64_smp_current_cpu(void);
uint64_t edgeos_arm64_smp_current_hardware_id(void);
void edgeos_arm64_smp_idle_prepare(void);
void edgeos_arm64_smp_idle_irq_window(void);
void edgeos_arm64_scheduler_secondary_prepare(uint32_t logical_id,
                                              uint64_t stack_top);
void edgeos_arm64_scheduler_secondary_enter(uint32_t logical_id)
    __attribute__((noreturn));
void edgeos_arm64_kernel_execution_enter(void);
void edgeos_arm64_kernel_execution_enter_from_user(void);
int edgeos_arm64_kernel_execution_try_enter(void);
int edgeos_arm64_kernel_execution_waiting(void);
void edgeos_arm64_kernel_execution_exit(void);
void edgeos_arm64_secondary_main(uint64_t logical_id);

#endif
