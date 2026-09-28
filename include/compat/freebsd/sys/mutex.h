/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS mutex compatibility for unmodified FreeBSD driver sources. */

#ifndef _SYS_MUTEX_H_
#define _SYS_MUTEX_H_

#include "_mutex.h"
#include "../edgeos/sleep.h"
#include "lock.h"
#include "kernel.h"

#define MTX_DEF BSD_MUTEX_DEF
#define MTX_SPIN BSD_MUTEX_SPIN
#define MTX_RECURSE BSD_MUTEX_RECURSE
#define MTX_NOWITNESS 0x00000008u
#define MTX_QUIET LOP_QUIET
#define MTX_DUPOK LOP_DUPOK
#define MTX_NOPROFILE 0x00000020u
#define MTX_NEW 0x00000040u
#define MTX_NETWORK_LOCK "network driver"

extern struct mtx Giant;

#define DROP_GIANT() \
    int _giant_lock_count = 0; \
    while (mtx_owned(&Giant)) { \
        mtx_unlock(&Giant); \
        ++_giant_lock_count; \
    }
#define PICKUP_GIANT() \
    while (_giant_lock_count-- > 0) \
        mtx_lock(&Giant)

struct mtx_pool;
extern struct mtx_pool *mtxpool_sleep;
struct mtx *mtx_pool_find(struct mtx_pool *pool, void *pointer);

#define GIANT_REQUIRED ((void)0)

static inline void
bsd_mtx_lock_object_lock(void *data)
{
    struct mtx *mutex = data;

    bsd_mutex_lock(&mutex->edgeos_mutex);
}

static inline int
bsd_mtx_lock_object_trylock(void *data)
{
    struct mtx *mutex = data;

    return bsd_mutex_trylock(&mutex->edgeos_mutex);
}

static inline void
bsd_mtx_lock_object_unlock(void *data)
{
    struct mtx *mutex = data;

    bsd_mutex_unlock(&mutex->edgeos_mutex);
}

static inline int
bsd_mtx_lock_object_owned(void *data)
{
    struct mtx *mutex = data;

    return bsd_mutex_owned(&mutex->edgeos_mutex);
}

static inline void
mtx_init(struct mtx *mutex, const char *name, const char *type, int options)
{
    (void)type;
    mutex->lock_object.lo_data = mutex;
    mutex->lock_object.lo_name = name;
    mutex->lock_object.lo_lock = bsd_mtx_lock_object_lock;
    mutex->lock_object.lo_trylock = bsd_mtx_lock_object_trylock;
    mutex->lock_object.lo_unlock = bsd_mtx_lock_object_unlock;
    mutex->lock_object.lo_owned = bsd_mtx_lock_object_owned;
    mutex->lock_object.lo_flags =
        (options & MTX_SPIN) != 0 ? BSD_LOCK_OBJECT_SPIN : 0;
    (void)bsd_mutex_init(&mutex->edgeos_mutex, name,
        (uint32_t)options & (MTX_SPIN | MTX_RECURSE));
}

static inline void
mtx_destroy(struct mtx *mutex)
{
    (void)bsd_mutex_destroy(&mutex->edgeos_mutex);
}

static inline int
mtx_initialized(const struct mtx *mutex)
{
    return mutex && mutex->edgeos_mutex.initialized;
}

static inline void
mtx_lock(struct mtx *mutex)
{
    bsd_mutex_lock(&mutex->edgeos_mutex);
}

static inline void
mtx_lock_flags(struct mtx *mutex, int options)
{
    (void)options;
    mtx_lock(mutex);
}

static inline void
mtx_lock_spin(struct mtx *mutex)
{
    bsd_mutex_lock(&mutex->edgeos_mutex);
}

static inline int
mtx_trylock(struct mtx *mutex)
{
    return bsd_mutex_trylock(&mutex->edgeos_mutex);
}

static inline int
mtx_trylock_spin(struct mtx *mutex)
{
    return bsd_mutex_trylock(&mutex->edgeos_mutex);
}

static inline void
mtx_unlock(struct mtx *mutex)
{
    bsd_mutex_unlock(&mutex->edgeos_mutex);
}

static inline void
mtx_unlock_spin(struct mtx *mutex)
{
    bsd_mutex_unlock(&mutex->edgeos_mutex);
}

static inline int
mtx_owned(const struct mtx *mutex)
{
    return bsd_mutex_owned(&mutex->edgeos_mutex);
}

static inline int
mtx_recursed(const struct mtx *mutex)
{
    return bsd_mutex_recursed(&mutex->edgeos_mutex);
}

static inline const char *
mtx_name(const struct mtx *mutex)
{
    return mutex->edgeos_mutex.name;
}

static inline void
mtx_assert(const struct mtx *mutex, int assertion)
{
    (void)bsd_mutex_assert(&mutex->edgeos_mutex, assertion);
}

static inline int
mtx_sleep(const void *channel, struct mtx *mutex, int priority,
    const char *wait_message, int timeout_ticks)
{
    return bsd_msleep(channel, mutex, priority, wait_message,
        timeout_ticks);
}

struct bsd_mtx_sysinit_args {
    struct mtx *mutex;
    const char *description;
    int options;
};

static inline void
bsd_mtx_sysinit(const void *argument)
{
    const struct bsd_mtx_sysinit_args *args = argument;

    mtx_init(args->mutex, args->description, 0, args->options);
}

static inline void
bsd_mtx_sysuninit(const void *argument)
{
    mtx_destroy((struct mtx *)(uintptr_t)argument);
}

#define MTX_SYSINIT(name, mutex_value, description_value, options_value)  \
    static const struct bsd_mtx_sysinit_args name##_args = {             \
        (mutex_value), (description_value), (options_value),             \
    };                                                                    \
    C_SYSINIT(name##_mtx_sysinit, SI_SUB_LOCK, SI_ORDER_MIDDLE,          \
        bsd_mtx_sysinit, &name##_args);                                   \
    C_SYSUNINIT(name##_mtx_sysuninit, SI_SUB_LOCK, SI_ORDER_MIDDLE,      \
        bsd_mtx_sysuninit, (mutex_value))

#endif
