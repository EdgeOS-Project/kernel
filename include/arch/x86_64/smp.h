/* SPDX-License-Identifier: MPL-2.0 */

#ifndef EDGEOS_ARCH_X86_64_SMP_H
#define EDGEOS_ARCH_X86_64_SMP_H

#include <stdint.h>

void x86_smp_discover(void);
uint32_t x86_smp_current_cpu_id(void);
uint32_t x86_smp_start_secondaries(void);
int arch_smp_send_reschedule(uint32_t logical_id);
uint32_t arch_smp_current_cpu(void);
int arch_smp_calls_available(void);
int arch_smp_send_call(uint32_t logical_id);
void arch_smp_execute_call(uint32_t flags);
void arch_smp_call_relax(void);

#endif
