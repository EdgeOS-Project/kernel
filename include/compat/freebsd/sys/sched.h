/* SPDX-License-Identifier: BSD-2-Clause */
/* Scheduler topology helpers exposed to imported BSD drivers. */

#ifndef _SYS_SCHED_H_
#define _SYS_SCHED_H_

#include <machine/smp.h>
#include "kthread.h"
#include "../edgeos/kthread.h"
#include "../edgeos/sync.h"

#define SCHEDULER_STOPPED() 0
#define PRI_MIN 0
#define SRQ_BORING 0
#define SW_VOL 0x0001
#define SWT_RELINQUISH 0x0002

static inline void
thread_lock(struct thread *thread)
{
    while (__atomic_test_and_set(&thread->td_lock, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
        __asm__ __volatile__("yield");
#endif
    }
}

static inline void
thread_unlock(struct thread *thread)
{
    __atomic_clear(&thread->td_lock, __ATOMIC_RELEASE);
}

static inline void
sched_prio(struct thread *thread, int priority)
{
    thread->td_priority = priority;
}

static inline void
sched_add(struct thread *thread, int flags)
{
    (void)flags;
    thread_unlock(thread);
    (void)kthread_resume(thread);
}

static inline void
sched_bind(struct thread *thread, int cpu)
{
    if (!thread || cpu < 0)
        return;
    thread->td_saved_cpu = (int)bsd_kthread_current_cpu_id();
    thread->td_bound_cpu = cpu;
    thread->td_oncpu = cpu;
    thread->td_affinity_mask = UINT64_C(1) << (unsigned int)cpu;
}

static inline int
sched_is_bound(struct thread *thread)
{
    return thread && thread->td_bound_cpu >= 0;
}

static inline void
sched_unbind(struct thread *thread)
{
    if (!thread)
        return;
    thread->td_bound_cpu = -1;
    thread->td_affinity_mask = UINT64_MAX;
}

static inline void
sched_pin(void)
{
    struct thread *thread = bsd_kthread_current_public();

    if (!thread)
        return;
    if (thread->td_pinned++ == 0) {
        thread->td_pin_saved_bound_cpu = thread->td_bound_cpu;
        thread->td_bound_cpu = (int)bsd_kthread_current_cpu_id();
        thread->td_affinity_mask = UINT64_C(1) <<
            (unsigned int)thread->td_bound_cpu;
    }
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
}

static inline void
sched_unpin(void)
{
    struct thread *thread = bsd_kthread_current_public();

    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    if (!thread || thread->td_pinned == 0)
        return;
    if (--thread->td_pinned == 0) {
        thread->td_bound_cpu = thread->td_pin_saved_bound_cpu;
        thread->td_affinity_mask = thread->td_bound_cpu >= 0 ?
            UINT64_C(1) << (unsigned int)thread->td_bound_cpu : UINT64_MAX;
        thread->td_pin_saved_bound_cpu = -1;
    }
}

static inline int
sched_find_l2_neighbor(int cpu)
{
    (void)cpu;
    return -1;
}

static inline void
sched_relinquish(struct thread *thread)
{
    (void)thread;
    bsd_sync_yield_current();
}

static inline void
mi_switch(int flags)
{
    struct thread *thread = bsd_kthread_current_public();

    (void)flags;
    thread_unlock(thread);
    bsd_sync_yield_current();
}

#endif
