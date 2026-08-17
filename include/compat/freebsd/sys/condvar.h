/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS condition-variable compatibility for FreeBSD driver sources. */

#ifndef _SYS_CONDVAR_H_
#define _SYS_CONDVAR_H_

#include <sys/errno.h>
#include "../edgeos/kthread.h"
#include "../edgeos/sync.h"
#include "kthread.h"
#include "mutex.h"

struct cv {
    bsd_condition_t edgeos_condition;
    const char *cv_description;
};

static inline void
cv_init(struct cv *condition, const char *description)
{
    condition->cv_description = description;
    (void)bsd_condition_init(&condition->edgeos_condition, description);
}

static inline void
cv_destroy(struct cv *condition)
{
    (void)bsd_condition_destroy(&condition->edgeos_condition);
}

static inline void
cv_wait(struct cv *condition, struct mtx *mutex)
{
    (void)bsd_kthread_sleep(condition, mutex, 0, 0);
}

static inline void
cv_wait_unlock(struct cv *condition, struct mtx *mutex)
{
    (void)bsd_kthread_sleep(condition, mutex, 0x200, 0);
}

static inline int
bsd_cv_signal_pending(void)
{
    struct thread *thread = bsd_kthread_current_public();

    return thread && thread->td_proc &&
        thread->td_proc->p_pending_signals != 0;
}

static inline int
cv_wait_sig(struct cv *condition, struct mtx *mutex)
{
    int error;

    if (bsd_cv_signal_pending())
        return EINTR;
    error = bsd_kthread_sleep(condition, mutex, 0, 0);
    return error == 0 && bsd_cv_signal_pending() ? EINTR : error;
}

static inline int
cv_timedwait(struct cv *condition, struct mtx *mutex, int timeout_ticks)
{
    return bsd_kthread_sleep(condition, mutex, 0, timeout_ticks);
}

static inline int
cv_timedwait_sig(struct cv *condition, struct mtx *mutex,
    int timeout_ticks)
{
    int error;

    if (bsd_cv_signal_pending())
        return EINTR;
    error = bsd_kthread_sleep(condition, mutex, 0, timeout_ticks);
    return error == 0 && bsd_cv_signal_pending() ? EINTR : error;
}

static inline void
cv_signal(struct cv *condition)
{
    bsd_kthread_wakeup(condition, 1);
}

static inline void
cv_broadcast(struct cv *condition)
{
    bsd_kthread_wakeup(condition, 0);
}

static inline const char *
cv_wmesg(const struct cv *condition)
{
    return condition->cv_description;
}

#endif
