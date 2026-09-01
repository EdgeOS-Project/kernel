/* SPDX-License-Identifier: MPL-2.0 */
/* Shared CPU runtime services for imported BSD drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_CPU_H
#define EDGEOS_COMPAT_FREEBSD_CPU_H

#include <stdint.h>

int bsd_cpu_runtime_initialize(void);
int bsd_cpu_runtime_refresh_topology(void);
int bsd_cpu_idle(int64_t predicted_idle_time);

#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
int bsd_x86_msr_fault_recover(uint64_t *instruction_pointer);
int bsd_x86_nmi_dispatch(const void *native_frame);
#endif

#endif
