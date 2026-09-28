/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS BSD Driver Bridge synchronization interface. */

#ifndef EDGEOS_COMPAT_FREEBSD_SYNC_H
#define EDGEOS_COMPAT_FREEBSD_SYNC_H

#include <stdint.h>

#define BSD_MUTEX_DEF 0x00000000u
#define BSD_MUTEX_SPIN 0x00000001u
#define BSD_MUTEX_RECURSE 0x00000004u

#define BSD_MUTEX_ASSERT_OWNED 1
#define BSD_MUTEX_ASSERT_NOTOWNED 2
#define BSD_MUTEX_ASSERT_RECURSED 4
#define BSD_MUTEX_ASSERT_NOTRECURSED 8

#define BSD_RWLOCK_RECURSE 0x00000001u

typedef void *(*bsd_sync_current_thread_fn)(void *context);
typedef int (*bsd_sync_can_block_fn)(void *thread, void *context);
typedef void (*bsd_sync_prepare_block_fn)(void *thread, void *context);
typedef void (*bsd_sync_block_current_fn)(void *thread, void *context);
typedef void (*bsd_sync_wake_thread_fn)(void *thread, void *context);
typedef void (*bsd_sync_yield_fn)(void *context);
typedef void (*bsd_sync_fatal_fn)(const char *message, void *context);

typedef struct {
    bsd_sync_current_thread_fn current_thread;
    bsd_sync_can_block_fn can_block;
    bsd_sync_prepare_block_fn prepare_block;
    bsd_sync_block_current_fn block_current;
    bsd_sync_wake_thread_fn wake_thread;
    bsd_sync_yield_fn yield_thread;
    bsd_sync_fatal_fn fatal;
    void *context;
} bsd_sync_ops_t;

typedef struct {
    volatile uint32_t guard;
    uintptr_t owner;
    void *wait_head;
    void *wait_tail;
    const char *name;
    uint64_t spin_interrupt_state;
    uint32_t recursion;
    uint32_t flags;
    uint8_t initialized;
} bsd_mutex_t;

typedef struct {
    volatile uint32_t guard;
    void *wait_head;
    void *wait_tail;
    const char *description;
    uint8_t initialized;
} bsd_condition_t;

typedef struct {
    volatile uint32_t guard;
    uintptr_t writer;
    uintptr_t writer_grant;
    void *reader_wait_head;
    void *reader_wait_tail;
    void *writer_wait_head;
    void *writer_wait_tail;
    const char *name;
    uint32_t readers;
    uint32_t writer_recursion;
    uint32_t waiting_writers;
    uint32_t flags;
    uint8_t initialized;
} bsd_rwlock_t;

int bsd_sync_initialize(const bsd_sync_ops_t *ops);
int bsd_sync_is_initialized(void);
void bsd_sync_yield_current(void);

int bsd_mutex_init(bsd_mutex_t *mutex, const char *name, uint32_t flags);
int bsd_mutex_destroy(bsd_mutex_t *mutex);
void bsd_mutex_lock(bsd_mutex_t *mutex);
int bsd_mutex_trylock(bsd_mutex_t *mutex);
void bsd_mutex_unlock(bsd_mutex_t *mutex);
int bsd_mutex_owned(const bsd_mutex_t *mutex);
int bsd_mutex_recursed(const bsd_mutex_t *mutex);
int bsd_mutex_assert(const bsd_mutex_t *mutex, int assertion);

int bsd_condition_init(bsd_condition_t *condition, const char *description);
int bsd_condition_destroy(bsd_condition_t *condition);
void bsd_condition_wait(bsd_condition_t *condition, bsd_mutex_t *mutex);
void bsd_condition_signal(bsd_condition_t *condition);
void bsd_condition_broadcast(bsd_condition_t *condition);

int bsd_rwlock_init(bsd_rwlock_t *lock, const char *name, uint32_t flags);
int bsd_rwlock_destroy(bsd_rwlock_t *lock);
void bsd_rwlock_read_lock(bsd_rwlock_t *lock);
int bsd_rwlock_try_read_lock(bsd_rwlock_t *lock);
void bsd_rwlock_read_unlock(bsd_rwlock_t *lock);
void bsd_rwlock_write_lock(bsd_rwlock_t *lock);
int bsd_rwlock_try_write_lock(bsd_rwlock_t *lock);
void bsd_rwlock_write_unlock(bsd_rwlock_t *lock);
int bsd_rwlock_write_owned(const bsd_rwlock_t *lock);
int bsd_rwlock_read_locked(const bsd_rwlock_t *lock);
int bsd_rwlock_try_upgrade(bsd_rwlock_t *lock);
void bsd_rwlock_downgrade(bsd_rwlock_t *lock);

#endif
