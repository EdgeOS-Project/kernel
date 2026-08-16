/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD reader/writer lock API backed by the shared EdgeOS runtime. */

#ifndef _SYS_RWLOCK_H_
#define _SYS_RWLOCK_H_

#include "_rwlock.h"
#include "../edgeos/sleep.h"
#include "kernel.h"
#include "lock.h"

#define RW_RECURSE BSD_RWLOCK_RECURSE
#define RW_DUPOK 0
#define RW_NOPROFILE 0
#define RW_NOWITNESS 0

#define RA_UNLOCKED 0
#define RA_LOCKED 1
#define RA_RLOCKED 2
#define RA_WLOCKED 4
#define RA_RECURSED 8
#define RA_NOTRECURSED 16

static inline void
bsd_rw_lock_object_lock(void *data)
{
    struct rwlock *lock = data;

    bsd_rwlock_write_lock(&lock->edgeos_lock);
}

static inline int
bsd_rw_lock_object_trylock(void *data)
{
    struct rwlock *lock = data;

    return bsd_rwlock_try_write_lock(&lock->edgeos_lock);
}

static inline void
bsd_rw_lock_object_unlock(void *data)
{
    struct rwlock *lock = data;

    bsd_rwlock_write_unlock(&lock->edgeos_lock);
}

static inline int
bsd_rw_lock_object_owned(void *data)
{
    struct rwlock *lock = data;

    return bsd_rwlock_write_owned(&lock->edgeos_lock);
}

static inline void
rw_init_flags(struct rwlock *lock, const char *name, int options)
{
    lock->lock_object.lo_data = lock;
    lock->lock_object.lo_name = name;
    lock->lock_object.lo_lock = bsd_rw_lock_object_lock;
    lock->lock_object.lo_trylock = bsd_rw_lock_object_trylock;
    lock->lock_object.lo_unlock = bsd_rw_lock_object_unlock;
    lock->lock_object.lo_owned = bsd_rw_lock_object_owned;
    lock->lock_object.lo_flags = 0;
    (void)bsd_rwlock_init(&lock->edgeos_lock, name,
        (uint32_t)options & RW_RECURSE);
}

static inline void
rw_init(struct rwlock *lock, const char *name)
{
    rw_init_flags(lock, name, 0);
}

static inline void
rw_destroy(struct rwlock *lock)
{
    (void)bsd_rwlock_destroy(&lock->edgeos_lock);
}

static inline int
rw_initialized(const struct rwlock *lock)
{
    return lock && lock->edgeos_lock.initialized;
}

static inline void
rw_rlock(struct rwlock *lock)
{
    bsd_rwlock_read_lock(&lock->edgeos_lock);
}

static inline int
rw_try_rlock(struct rwlock *lock)
{
    return bsd_rwlock_try_read_lock(&lock->edgeos_lock);
}

static inline void
rw_runlock(struct rwlock *lock)
{
    bsd_rwlock_read_unlock(&lock->edgeos_lock);
}

static inline void
rw_wlock(struct rwlock *lock)
{
    bsd_rwlock_write_lock(&lock->edgeos_lock);
}

static inline int
rw_try_wlock(struct rwlock *lock)
{
    return bsd_rwlock_try_write_lock(&lock->edgeos_lock);
}

static inline void
rw_wunlock(struct rwlock *lock)
{
    bsd_rwlock_write_unlock(&lock->edgeos_lock);
}

static inline int
rw_wowned(const struct rwlock *lock)
{
    return bsd_rwlock_write_owned(&lock->edgeos_lock);
}

static inline void
rw_unlock(struct rwlock *lock)
{
    if (rw_wowned(lock))
        rw_wunlock(lock);
    else
        rw_runlock(lock);
}

static inline int
rw_try_upgrade(struct rwlock *lock)
{
    return bsd_rwlock_try_upgrade(&lock->edgeos_lock);
}

static inline void
rw_downgrade(struct rwlock *lock)
{
    bsd_rwlock_downgrade(&lock->edgeos_lock);
}

static inline int
rw_sleep(const void *channel, struct rwlock *lock, int priority,
    const char *wait_message, int timeout_ticks)
{
    return bsd_rw_sleep(channel, &lock->edgeos_lock, priority,
        wait_message, timeout_ticks);
}

static inline void
rw_assert(const struct rwlock *lock, int assertion)
{
    int write_owned = rw_wowned(lock);
    int read_locked = bsd_rwlock_read_locked(&lock->edgeos_lock);
    int valid = 0;

    switch (assertion) {
    case RA_UNLOCKED:
        valid = !write_owned && !read_locked;
        break;
    case RA_LOCKED:
        valid = write_owned || read_locked;
        break;
    case RA_RLOCKED:
        valid = read_locked;
        break;
    case RA_WLOCKED:
        valid = write_owned;
        break;
    case RA_RECURSED:
        valid = write_owned && lock->edgeos_lock.writer_recursion != 0;
        break;
    case RA_NOTRECURSED:
        valid = write_owned && lock->edgeos_lock.writer_recursion == 0;
        break;
    default:
        break;
    }
    if (!valid)
        __builtin_trap();
}

struct bsd_rw_sysinit_args {
    struct rwlock *lock;
    const char *description;
    int options;
};

static inline void
bsd_rw_sysinit(const void *argument)
{
    const struct bsd_rw_sysinit_args *args = argument;

    rw_init_flags(args->lock, args->description, args->options);
}

static inline void
bsd_rw_sysuninit(const void *argument)
{
    rw_destroy((struct rwlock *)(uintptr_t)argument);
}

#define RW_SYSINIT_FLAGS(name, lock_value, description_value, options_value) \
    static const struct bsd_rw_sysinit_args name##_args = {                 \
        (lock_value), (description_value), (options_value),                 \
    };                                                                      \
    C_SYSINIT(name##_rw_sysinit, SI_SUB_LOCK, SI_ORDER_MIDDLE,              \
        bsd_rw_sysinit, &name##_args);                                       \
    C_SYSUNINIT(name##_rw_sysuninit, SI_SUB_LOCK, SI_ORDER_MIDDLE,          \
        bsd_rw_sysuninit, (lock_value))

#define RW_SYSINIT(name, lock_value, description_value) \
    RW_SYSINIT_FLAGS(name, lock_value, description_value, 0)

#endif
