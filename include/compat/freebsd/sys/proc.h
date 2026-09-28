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
#ifndef THREAD0_TID
#define THREAD0_TID NO_PID
#endif
#define P2_HWT 0x00000001u

/* FreeBSD AST index used by the VMM run loop for process suspension. */
#define TDA_SUSPEND 17
#ifndef TDAI
#define TDAI(ast) (1u << (ast))
#endif
#ifndef td_ast_pending
#define td_ast_pending(thread, ast) \
    (((thread)->td_ast & (int)TDAI(ast)) != 0)
#endif

static inline int
thread_check_susp(struct thread *thread, bool sleep)
{
    /* EdgeOS does not currently issue FreeBSD process-suspend ASTs. */
    (void)thread;
    (void)sleep;
    return 0;
}

struct proc *bsd_curproc(void);
struct proc *pfind(int pid);
struct thread *tdfind(int tid, int pid);
struct proc *bsd_proc_first(void);
struct proc *bsd_proc_next(struct proc *process);
void thread_reap_barrier(void);
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
#define FOREACH_PROC_IN_SYSTEM(process) \
    for ((process) = bsd_proc_first(); (process) != 0; \
        (process) = bsd_proc_next((process)))

extern struct sx allproc_lock;

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

static inline void
maybe_yield(void)
{
	bsd_sync_yield_current();
}

#endif
