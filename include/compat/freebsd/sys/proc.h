/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal process declarations required by imported driver frameworks. */

#ifndef _SYS_PROC_H_
#define _SYS_PROC_H_

#include "condvar.h"
#include "kthread.h"
#include "mutex.h"
#include "signalvar.h"
#include "sx.h"

#define curthread bsd_kthread_current_public()
#define curproc bsd_curproc()
#define PRI_USER (-2)
#define PRI_UNCHANGED (-1)

/*
 * FreeBSD reserves PID_MAX + 1 as the internal "no process" sentinel.
 * Keep this distinct from Linux-visible PID allocation policy; imported
 * drivers use it only inside the BSD compatibility domain.
 */
#define PID_MAX 99999
#define NO_PID (PID_MAX + 1)
#define THREAD0_TID NO_PID
#define P2_HWT 0x00000001u

struct proc *bsd_curproc(void);
struct proc *pfind(int pid);
void bsd_proc_lock(struct proc *process);
void bsd_proc_unlock(struct proc *process);
int bsd_proc_lock_owned(const struct proc *process);
void crhold(struct ucred *credential);
void crfree(struct ucred *credential);
int groupmember(uint32_t group, const struct ucred *credential);
int securelevel_gt(struct ucred *credential, int level);

#define PROC_LOCK(process) bsd_proc_lock((process))
#define PROC_UNLOCK(process) bsd_proc_unlock((process))
#define PROC_LOCK_ASSERT(process, state) do { \
    (void)(state); \
    if (!bsd_proc_lock_owned((process))) \
        __builtin_trap(); \
} while (0)
#define FOREACH_THREAD_IN_PROC(process, thread) \
    for ((thread) = (process)->p_edgeos_thread; (thread) != 0; \
        (thread) = (thread)->td_proc_next)

#define THREAD_NO_SLEEPING() do { \
	curthread->td_no_sleeping++; \
} while (0)
#define THREAD_SLEEPING_OK() do { \
	if (curthread->td_no_sleeping > 0) \
		curthread->td_no_sleeping--; \
} while (0)
#define THREAD_CAN_SLEEP() (curthread->td_no_sleeping == 0)

static inline void
kern_yield(int priority)
{
	(void)priority;
	bsd_sync_yield_current();
}

#endif
