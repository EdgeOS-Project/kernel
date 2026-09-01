/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _SYS_SMP_H_
#define _SYS_SMP_H_

#include "cpuset.h"
#include "pcpu.h"
#ifdef BSD_BRIDGE_HOST_TEST
#include <limits.h>
#else
#include <sys/limits.h>
#endif

extern int mp_ncpus;
extern int mp_ncores;
extern int mp_maxid;
extern int smp_threads_per_core;
extern int smp_started;
extern cpuset_t all_cpus;
extern cpuset_t cpuset_domain[1];
extern cpuset_t hlt_cpus_mask;

struct _device;
struct resource;
int intr_bind_irq(struct _device *device, struct resource *resource, int cpu);

static inline int
bsd_cpu_next(int cpu)
{
    int count = mp_ncpus > 0 ? mp_ncpus : 1;

    return (cpu + 1) % count;
}

#define CPU_FIRST() 0
#define CPU_NEXT(cpu) bsd_cpu_next((cpu))
#define CPU_FOREACH(cpu) \
    for ((cpu) = 0; (cpu) < mp_ncpus; ++(cpu))
#define CPU_ABSENT(cpu) \
    ((cpu) < 0 || (cpu) >= mp_ncpus || !CPU_ISSET((cpu), &all_cpus))

typedef void (*smp_rendezvous_func_t)(void *);

#ifndef BSD_BRIDGE_HOST_TEST
void bsd_smp_rendezvous_cpus(cpuset_t cpus,
    smp_rendezvous_func_t setup, smp_rendezvous_func_t action,
    smp_rendezvous_func_t teardown, void *argument);
#endif

static inline void
smp_no_rendezvous_barrier(void *argument)
{
    (void)argument;
}

static inline void
smp_rendezvous_cpu(unsigned int cpu, smp_rendezvous_func_t setup,
    smp_rendezvous_func_t action, smp_rendezvous_func_t teardown,
    void *argument)
{
    if (cpu >= (unsigned int)mp_ncpus)
        return;
#ifndef BSD_BRIDGE_HOST_TEST
    cpuset_t cpus;

    CPU_SETOF(cpu, &cpus);
    bsd_smp_rendezvous_cpus(cpus, setup, action, teardown, argument);
#else
    if (setup)
        setup(argument);
    if (action)
        action(argument);
    if (teardown)
        teardown(argument);
#endif
}

static inline void
smp_rendezvous_cpus(cpuset_t cpus, smp_rendezvous_func_t setup,
    smp_rendezvous_func_t action, smp_rendezvous_func_t teardown,
    void *argument)
{
#ifndef BSD_BRIDGE_HOST_TEST
    bsd_smp_rendezvous_cpus(cpus, setup, action, teardown, argument);
#else
    cpuset_t active;

    CPU_AND(&active, &cpus, &all_cpus);
    if (CPU_EMPTY(&active))
        return;
    if (setup)
        setup(argument);
    if (action)
        action(argument);
    if (teardown)
        teardown(argument);
#endif
}

static inline void
smp_rendezvous(smp_rendezvous_func_t setup,
    smp_rendezvous_func_t action, smp_rendezvous_func_t teardown,
    void *argument)
{
    smp_rendezvous_cpus(all_cpus, setup, action, teardown, argument);
}

#endif
