/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD reader-mostly lock API backed by the shared EdgeOS RW lock. */

#ifndef _SYS_RMLOCK_H_
#define _SYS_RMLOCK_H_

#include "kernel.h"
#include "rwlock.h"

#define RM_NOWITNESS 0x00000001
#define RM_RECURSE 0x00000002
#define RM_SLEEPABLE 0x00000004
#define RM_NEW 0x00000008
#define RM_DUPOK 0x00000010

struct rm_priotracker {
    int read_locked;
};

struct rmlock {
    struct rwlock edgeos_lock;
};

static inline void
rm_init_flags(struct rmlock *lock, const char *name, int options)
{
    rw_init_flags(&lock->edgeos_lock, name,
        (options & RM_RECURSE) ? RW_RECURSE : 0);
}

static inline void
rm_init(struct rmlock *lock, const char *name)
{
    rm_init_flags(lock, name, 0);
}

static inline void
rm_destroy(struct rmlock *lock)
{
    rw_destroy(&lock->edgeos_lock);
}

static inline int
rm_wowned(const struct rmlock *lock)
{
    return rw_wowned(&lock->edgeos_lock);
}

static inline void
_rm_wlock(struct rmlock *lock)
{
    rw_wlock(&lock->edgeos_lock);
}

static inline void
_rm_wunlock(struct rmlock *lock)
{
    rw_wunlock(&lock->edgeos_lock);
}

static inline int
_rm_rlock(struct rmlock *lock, struct rm_priotracker *tracker, int trylock)
{
    int acquired;

    acquired = trylock ? rw_try_rlock(&lock->edgeos_lock) : 1;
    if (!trylock)
        rw_rlock(&lock->edgeos_lock);
    if (tracker)
        tracker->read_locked = acquired;
    return acquired;
}

static inline void
_rm_runlock(struct rmlock *lock, struct rm_priotracker *tracker)
{
    if (!tracker || tracker->read_locked) {
        rw_runlock(&lock->edgeos_lock);
        if (tracker)
            tracker->read_locked = 0;
    }
}

#define rm_wlock(lock) _rm_wlock((lock))
#define rm_wunlock(lock) _rm_wunlock((lock))
#define rm_rlock(lock, tracker) \
    ((void)_rm_rlock((lock), (tracker), 0))
#define rm_try_rlock(lock, tracker) \
    _rm_rlock((lock), (tracker), 1)
#define rm_runlock(lock, tracker) _rm_runlock((lock), (tracker))

struct rm_args {
    struct rmlock *lock;
    const char *description;
    int flags;
};

static inline void
rm_sysinit(const void *argument)
{
    const struct rm_args *args = argument;

    rm_init_flags(args->lock, args->description, args->flags);
}

static inline void
rm_sysuninit(const void *argument)
{
    rm_destroy((struct rmlock *)(uintptr_t)argument);
}

#define RM_SYSINIT_FLAGS(name, lock_value, description_value, flags_value) \
    static const struct rm_args name##_args = {                           \
        (lock_value), (description_value), (flags_value),                 \
    };                                                                    \
    C_SYSINIT(name##_rm_sysinit, SI_SUB_LOCK, SI_ORDER_MIDDLE,            \
        rm_sysinit, &name##_args);                                         \
    C_SYSUNINIT(name##_rm_sysuninit, SI_SUB_LOCK, SI_ORDER_MIDDLE,        \
        rm_sysuninit, (lock_value))

#define RM_SYSINIT(name, lock_value, description_value) \
    RM_SYSINIT_FLAGS(name, lock_value, description_value, 0)

#endif
