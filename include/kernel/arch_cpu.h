/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_ARCH_CPU_H
#define EDGEOS_KERNEL_ARCH_CPU_H

#include <stdint.h>

uint64_t arch_cpu_current_task(void);
void arch_cpu_set_current_task(uint64_t task);
uint64_t arch_cpu_user_tls(void);
void arch_cpu_set_user_tls(uint64_t tls);
void arch_cpu_save_user_fp(void *state);
void arch_cpu_restore_user_fp(const void *state);
void arch_cpu_set_user_single_step(int enabled);
uint64_t arch_cpu_stack_pointer(void);
typedef __attribute__((noreturn)) void (*arch_cpu_stack_entry_t)(
    uint32_t argument);
__attribute__((noreturn)) void arch_cpu_call_on_stack(
    uint64_t stack_pointer, arch_cpu_stack_entry_t entry,
    uint32_t argument);
uint64_t arch_cpu_cycle_counter(void);
uint64_t arch_cpu_user_stack_top(void);
uint64_t arch_cpu_user_vdso_base(void);
uint64_t arch_cpu_user_hwcap(void);
uint64_t arch_cpu_user_hwcap2(void);
int arch_cpu_proc_info(char *buffer, uint32_t capacity);
int arch_cpu_proc_ioports(char *buffer, uint32_t capacity);
void arch_cpu_relax(void);
void arch_cpu_wait_event(void);
void arch_cpu_idle(void);
void arch_cpu_idle_irq_window(void);
void arch_cpu_memory_barrier(void);
void arch_cpu_sync_barrier(void);
void arch_cpu_sync_instruction_stream(void);
void arch_cpu_clean_data_range(const void *address, uint64_t length);
void arch_cpu_invalidate_data_range(const void *address, uint64_t length);
__attribute__((noreturn)) void arch_cpu_power_control(int reboot);

#endif
