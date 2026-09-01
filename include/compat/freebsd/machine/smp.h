/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS machine SMP compatibility interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef _MACHINE_SMP_H_
#define _MACHINE_SMP_H_

#include <machine/pcpu.h>
#include <kernel/smp.h>
#if defined(__x86_64__)
#include <x86/apicvar.h>
#endif

#define NOCPU (-1)
#define IPI_AST 0

static inline void
ipi_cpu(unsigned int cpu, int ipi)
{
    (void)ipi;
#if defined(__x86_64__)
    (void)edge_smp_vmm_kick(cpu);
#else
    (void)edge_smp_reschedule(cpu);
#endif
}

#endif
