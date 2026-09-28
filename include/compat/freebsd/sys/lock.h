/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS compatibility definitions for unmodified FreeBSD driver sources. */

#ifndef _SYS_LOCK_H_
#define _SYS_LOCK_H_

#include "_lock.h"
#include "../edgeos/sleep.h"
#include "../edgeos/sync.h"

#define MA_OWNED 1
#define MA_NOTOWNED 2
#define MA_RECURSED 4
#define MA_NOTRECURSED 8

#define LA_UNLOCKED 0x00000000
#define LA_LOCKED 0x00000001
#define LA_SLOCKED 0x00000002
#define LA_XLOCKED 0x00000004
#define LA_RECURSED 0x00000008
#define LA_NOTRECURSED 0x00000010

#define LOP_QUIET 0x00000002
#define LOP_DUPOK 0x00000010

#define SA_LOCKED LA_LOCKED
#define SA_SLOCKED LA_SLOCKED
#define SA_XLOCKED LA_XLOCKED
#define SA_UNLOCKED LA_UNLOCKED
#define SA_RECURSED LA_RECURSED
#define SA_NOTRECURSED LA_NOTRECURSED

#define SX_LOCKED LA_LOCKED
#define SX_SLOCKED LA_SLOCKED
#define SX_XLOCKED LA_XLOCKED
#define SX_UNLOCKED LA_UNLOCKED
#define SX_RECURSED LA_RECURSED
#define SX_NOTRECURSED LA_NOTRECURSED

#define SX_DUPOK 0x01
#define SX_NOPROFILE 0x02
#define SX_NOWITNESS 0x04
#define SX_QUIET 0x08
#define SX_RECURSE 0x20
#define SX_NEW 0x40

#define WARN_GIANTOK 0x01
#define WARN_SLEEPOK 0x04
#define WITNESS_WARN(flags, lock, format, ...) ((void)0)

void spinlock_enter(void);
void spinlock_exit(void);

#ifndef _SYS__SX_H_
#define _SYS__SX_H_
struct sx {
    struct lock_object lock_object;
    bsd_rwlock_t edgeos_lock;
};
#endif

#define sx_lock edgeos_lock.writer
#define SX_OWNER(value) ((uintptr_t)(value))

static inline struct thread *
sx_xholder(const struct sx *lock)
{
    return (struct thread *)(uintptr_t)__atomic_load_n(
        &lock->edgeos_lock.writer, __ATOMIC_ACQUIRE);
}

static inline void
bsd_sx_lock_object_lock(void *data)
{
    struct sx *lock = data;

    bsd_rwlock_write_lock(&lock->edgeos_lock);
}

static inline int
bsd_sx_lock_object_trylock(void *data)
{
    struct sx *lock = data;

    return bsd_rwlock_try_write_lock(&lock->edgeos_lock);
}

static inline void
bsd_sx_lock_object_unlock(void *data)
{
    struct sx *lock = data;

    bsd_rwlock_write_unlock(&lock->edgeos_lock);
}

static inline int
bsd_sx_lock_object_owned(void *data)
{
    struct sx *lock = data;

    return bsd_rwlock_write_owned(&lock->edgeos_lock);
}

static inline void
sx_init_flags(struct sx *lock, const char *description, int options)
{
    lock->lock_object.lo_data = lock;
    lock->lock_object.lo_name = description;
    lock->lock_object.lo_lock = bsd_sx_lock_object_lock;
    lock->lock_object.lo_trylock = bsd_sx_lock_object_trylock;
    lock->lock_object.lo_unlock = bsd_sx_lock_object_unlock;
    lock->lock_object.lo_owned = bsd_sx_lock_object_owned;
    lock->lock_object.lo_flags = 0;
    (void)bsd_rwlock_init(&lock->edgeos_lock, description,
        (options & SX_RECURSE) != 0 ? BSD_RWLOCK_RECURSE : 0);
}

static inline void
sx_init(struct sx *lock, const char *description)
{
    sx_init_flags(lock, description, 0);
}

static inline void
sx_destroy(struct sx *lock)
{
    (void)bsd_rwlock_destroy(&lock->edgeos_lock);
}

static inline int
sx_initialized(const struct sx *lock)
{
    return lock && lock->edgeos_lock.initialized;
}

static inline void
sx_xlock(struct sx *lock)
{
    bsd_rwlock_write_lock(&lock->edgeos_lock);
}

static inline int
sx_xlock_sig(struct sx *lock)
{
    bsd_rwlock_write_lock(&lock->edgeos_lock);
    return 0;
}

static inline int
sx_try_xlock(struct sx *lock)
{
    return bsd_rwlock_try_write_lock(&lock->edgeos_lock);
}

static inline void
sx_xunlock(struct sx *lock)
{
    bsd_rwlock_write_unlock(&lock->edgeos_lock);
}

static inline void
sx_slock(struct sx *lock)
{
    bsd_rwlock_read_lock(&lock->edgeos_lock);
}

static inline int
sx_slock_sig(struct sx *lock)
{
    bsd_rwlock_read_lock(&lock->edgeos_lock);
    return 0;
}

static inline int
sx_try_slock(struct sx *lock)
{
    return bsd_rwlock_try_read_lock(&lock->edgeos_lock);
}

static inline void
sx_sunlock(struct sx *lock)
{
    bsd_rwlock_read_unlock(&lock->edgeos_lock);
}

static inline int
sx_try_upgrade(struct sx *lock)
{
    return bsd_rwlock_try_upgrade(&lock->edgeos_lock);
}

static inline void
sx_downgrade(struct sx *lock)
{
    bsd_rwlock_downgrade(&lock->edgeos_lock);
}

static inline int
sx_xlocked(const struct sx *lock)
{
    return bsd_rwlock_write_owned(&lock->edgeos_lock);
}

static inline int
sx_has_waiters(const struct sx *lock)
{
    return lock->edgeos_lock.reader_wait_head != 0 ||
        lock->edgeos_lock.writer_wait_head != 0;
}

static inline void
sx_unlock(struct sx *lock)
{
    if (sx_xlocked(lock))
        sx_xunlock(lock);
    else
        sx_sunlock(lock);
}

static inline int
sx_sleep(const void *channel, struct sx *lock, int priority,
    const char *wait_message, int timeout_ticks)
{
    return bsd_rw_sleep(channel, &lock->edgeos_lock, priority,
        wait_message, timeout_ticks);
}

static inline void
sx_assert(const struct sx *lock, int assertion)
{
    int exclusive = bsd_rwlock_write_owned(&lock->edgeos_lock);
    int shared = bsd_rwlock_read_locked(&lock->edgeos_lock);
    int valid = 0;

    switch (assertion) {
    case SA_UNLOCKED:
        valid = !exclusive && !shared;
        break;
    case SA_LOCKED:
        valid = exclusive || shared;
        break;
    case SA_SLOCKED:
        valid = shared;
        break;
    case SA_XLOCKED:
        valid = exclusive;
        break;
    case SA_RECURSED:
        valid = exclusive && lock->edgeos_lock.writer_recursion != 0;
        break;
    case SA_NOTRECURSED:
        valid = (exclusive || shared) &&
            lock->edgeos_lock.writer_recursion == 0;
        break;
    default:
        break;
    }
    if (!valid)
        __builtin_trap();
}

#endif
