/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS per-CPU compatibility state for imported FreeBSD drivers.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef _SYS_PCPU_H_
#define _SYS_PCPU_H_

#include <sys/types.h>
#include "kthread.h"
#include "../edgeos/kthread.h"

struct _device;
typedef struct _device *device_t;

/*
 * Driver-facing CPU devices only require the stable logical CPU identifier.
 * Additional FreeBSD scheduler-private fields belong in the bridge rather
 * than in unmodified driver sources and can be added as their consumers are
 * integrated.
 */
struct pcpu {
    unsigned int pc_cpuid;
    unsigned int pc_acpi_id;
    unsigned int pc_small_core;
    int pc_domain;
    uint64_t pc_clock;
    device_t pc_device;
};

struct pcpu *pcpu_find(unsigned int cpu);
unsigned int bsd_pcpu_current_small_core(void);

static inline unsigned int
bsd_pcpu_current_cpuid(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (thread && thread->td_bound_cpu >= 0)
        return (unsigned int)thread->td_bound_cpu;
    return bsd_kthread_current_cpu_id();
}

#define PCPU_GET(member) bsd_pcpu_current_##member()

#endif
