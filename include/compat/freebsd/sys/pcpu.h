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
#if defined(__x86_64__)
#include <machine/segments.h>
#include <machine/pcb.h>
#include <arch/x86_64/gdt.h>
#endif

struct _device;
typedef struct _device *device_t;
struct pmap;

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
#if defined(__x86_64__)
    struct pcb pc_pcb_storage;
    void *pc_tssp;
    uint64_t *pc_gdt;
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
    struct pmap *pc_curvmpmap;
    struct thread *pc_fpcurthread;
#endif
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

static inline struct pcpu *
get_pcpu(void)
{
    return pcpu_find(bsd_pcpu_current_cpuid());
}

#if defined(__x86_64__)
static inline struct system_segment_descriptor *
bsd_pcpu_current_tss(void)
{
    return (struct system_segment_descriptor *)
        gdt_current_tss_descriptor();
}

static inline void *
bsd_pcpu_current_tssp(void)
{
    struct pcpu *pcpu = get_pcpu();

    if (!pcpu)
        return 0;
    if (!pcpu->pc_tssp)
        pcpu->pc_tssp = gdt_current_tss();
    return pcpu->pc_tssp;
}

static inline struct pcb *
bsd_pcpu_current_curpcb(void)
{
    struct pcpu *pcpu = get_pcpu();

    return pcpu ? &pcpu->pc_pcb_storage : 0;
}

#ifndef curpcb
#define curpcb bsd_pcpu_current_curpcb()
#endif
#endif

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
#define PCPU_GET(member) (get_pcpu()->pc_##member)
#define PCPU_SET(member, value) (get_pcpu()->pc_##member = (value))
#define DPCPU_DEFINE_STATIC(type, name) \
    static type edge_bsd_dpcpu_##name[MAXCPU]
#define DPCPU_GET(name) \
    (edge_bsd_dpcpu_##name[bsd_pcpu_current_cpuid()])
#define DPCPU_SET(name, value) \
    (edge_bsd_dpcpu_##name[bsd_pcpu_current_cpuid()] = (value))
#else
#define PCPU_GET(member) bsd_pcpu_current_##member()
#endif
#define PCPU_PTR(member) (&get_pcpu()->pc_##member)

#endif
