/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD Driver Bridge synchronization backend. */

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/sync.h"
#include <sys/condvar.h>
#include <sys/rwlock.h>

#define WORKER_COUNT 8
#define WORKER_ITERATIONS 20000

_Static_assert(MTX_DUPOK == LOP_DUPOK,
    "mutex duplicate-acquire option must match the lock option ABI");

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t condition;
    int prepared;
    int wake_pending;
} test_thread_t;

typedef struct {
    bsd_mutex_t mutex;
    uint64_t counter;
} counter_context_t;

typedef struct {
    bsd_mutex_t mutex;
    bsd_condition_t condition;
    volatile int waiting;
    int ready;
    int observed;
} condition_context_t;

typedef struct {
    bsd_rwlock_t lock;
    volatile uint32_t active_readers;
    volatile uint32_t maximum_readers;
    volatile uint32_t writer_active;
    volatile uint32_t violation;
    uint64_t writes;
} rwlock_context_t;

static _Thread_local test_thread_t *g_current_thread;

void
bsd_kthread_wakeup(const void *channel, int one)
{
    (void)channel;
    (void)one;
}

static void test_thread_init(test_thread_t *thread) {
    memset(thread, 0, sizeof(*thread));
    assert(pthread_mutex_init(&thread->lock, 0) == 0);
    assert(pthread_cond_init(&thread->condition, 0) == 0);
}

static void test_thread_destroy(test_thread_t *thread) {
    assert(pthread_cond_destroy(&thread->condition) == 0);
    assert(pthread_mutex_destroy(&thread->lock) == 0);
}

static void *test_current_thread(void *context) {
    (void)context;
    return g_current_thread;
}

static int test_can_block(void *thread, void *context) {
    (void)context;
    return thread != 0;
}

static void test_prepare_block(void *opaque_thread, void *context) {
    test_thread_t *thread = opaque_thread;
    (void)context;
    assert(pthread_mutex_lock(&thread->lock) == 0);
    thread->prepared = 1;
    assert(pthread_mutex_unlock(&thread->lock) == 0);
}

static void test_block_current(void *opaque_thread, void *context) {
    test_thread_t *thread = opaque_thread;
    (void)context;
    assert(pthread_mutex_lock(&thread->lock) == 0);
    assert(thread->prepared);
    while (!thread->wake_pending)
        assert(pthread_cond_wait(&thread->condition, &thread->lock) == 0);
    thread->wake_pending = 0;
    thread->prepared = 0;
    assert(pthread_mutex_unlock(&thread->lock) == 0);
}

static void test_wake_thread(void *opaque_thread, void *context) {
    test_thread_t *thread = opaque_thread;
    (void)context;
    assert(pthread_mutex_lock(&thread->lock) == 0);
    thread->wake_pending = 1;
    assert(pthread_cond_signal(&thread->condition) == 0);
    assert(pthread_mutex_unlock(&thread->lock) == 0);
}

static void test_yield(void *context) {
    (void)context;
    sched_yield();
}

static void test_fatal(const char *message, void *context) {
    (void)context;
    fprintf(stderr, "unexpected bridge fatal error: %s\n", message);
    abort();
}

static void *counter_worker(void *opaque_context) {
    counter_context_t *context = opaque_context;
    test_thread_t thread;
    test_thread_init(&thread);
    g_current_thread = &thread;
    for (uint32_t iteration = 0; iteration < WORKER_ITERATIONS; ++iteration) {
        bsd_mutex_lock(&context->mutex);
        context->counter++;
        bsd_mutex_unlock(&context->mutex);
    }
    g_current_thread = 0;
    test_thread_destroy(&thread);
    return 0;
}

static void test_mutex_contention(void) {
    counter_context_t context;
    pthread_t workers[WORKER_COUNT];
    memset(&context, 0, sizeof(context));
    assert(bsd_mutex_init(&context.mutex, "counter", BSD_MUTEX_DEF) == 0);
    for (uint32_t index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_create(&workers[index], 0, counter_worker, &context) == 0);
    for (uint32_t index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_join(workers[index], 0) == 0);
    assert(context.counter == (uint64_t)WORKER_COUNT * WORKER_ITERATIONS);
    assert(bsd_mutex_destroy(&context.mutex) == 0);
}

static void test_recursive_and_spin_mutex(void) {
    bsd_mutex_t non_recursive;
    bsd_mutex_t recursive;
    bsd_mutex_t spin;

    assert(bsd_mutex_init(
        &non_recursive, "non-recursive", BSD_MUTEX_DEF) == 0);
    bsd_mutex_lock(&non_recursive);
    assert(!bsd_mutex_trylock(&non_recursive));
    assert(bsd_mutex_owned(&non_recursive));
    bsd_mutex_unlock(&non_recursive);
    assert(bsd_mutex_destroy(&non_recursive) == 0);

    assert(bsd_mutex_init(&recursive, "recursive", BSD_MUTEX_RECURSE) == 0);
    bsd_mutex_lock(&recursive);
    bsd_mutex_lock(&recursive);
    assert(bsd_mutex_owned(&recursive));
    assert(bsd_mutex_recursed(&recursive));
    assert(bsd_mutex_assert(&recursive, BSD_MUTEX_ASSERT_RECURSED) == 0);
    bsd_mutex_unlock(&recursive);
    assert(!bsd_mutex_recursed(&recursive));
    bsd_mutex_unlock(&recursive);
    assert(bsd_mutex_destroy(&recursive) == 0);

    assert(bsd_mutex_init(&spin, "spin", BSD_MUTEX_SPIN) == 0);
    assert(bsd_mutex_trylock(&spin));
    assert(bsd_mutex_owned(&spin));
    bsd_mutex_unlock(&spin);
    assert(bsd_mutex_destroy(&spin) == 0);
}

static void *condition_waiter(void *opaque_context) {
    condition_context_t *context = opaque_context;
    test_thread_t thread;
    test_thread_init(&thread);
    g_current_thread = &thread;

    bsd_mutex_lock(&context->mutex);
    __atomic_add_fetch(&context->waiting, 1, __ATOMIC_RELEASE);
    while (!context->ready)
        bsd_condition_wait(&context->condition, &context->mutex);
    context->observed++;
    bsd_mutex_unlock(&context->mutex);

    g_current_thread = 0;
    test_thread_destroy(&thread);
    return 0;
}

static void test_condition_signal(void) {
    condition_context_t context;
    pthread_t waiter;
    memset(&context, 0, sizeof(context));
    assert(bsd_mutex_init(&context.mutex, "condition", BSD_MUTEX_DEF) == 0);
    assert(bsd_condition_init(&context.condition, "ready") == 0);
    assert(pthread_create(&waiter, 0, condition_waiter, &context) == 0);
    while (!__atomic_load_n(&context.waiting, __ATOMIC_ACQUIRE))
        sched_yield();

    bsd_mutex_lock(&context.mutex);
    context.ready = 1;
    bsd_condition_signal(&context.condition);
    bsd_mutex_unlock(&context.mutex);

    assert(pthread_join(waiter, 0) == 0);
    assert(context.observed);
    assert(bsd_condition_destroy(&context.condition) == 0);
    assert(bsd_mutex_destroy(&context.mutex) == 0);
}

static void test_condition_broadcast(void) {
    condition_context_t context;
    pthread_t waiters[WORKER_COUNT];
    memset(&context, 0, sizeof(context));
    assert(bsd_mutex_init(&context.mutex, "broadcast", BSD_MUTEX_DEF) == 0);
    assert(bsd_condition_init(&context.condition, "broadcast-ready") == 0);
    for (uint32_t index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_create(&waiters[index], 0, condition_waiter, &context) == 0);
    while (__atomic_load_n(&context.waiting, __ATOMIC_ACQUIRE) != WORKER_COUNT)
        sched_yield();

    bsd_mutex_lock(&context.mutex);
    context.ready = 1;
    bsd_condition_broadcast(&context.condition);
    bsd_mutex_unlock(&context.mutex);

    for (uint32_t index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_join(waiters[index], 0) == 0);
    assert(context.observed == WORKER_COUNT);
    assert(bsd_condition_destroy(&context.condition) == 0);
    assert(bsd_mutex_destroy(&context.mutex) == 0);
}

static void *rwlock_reader(void *opaque_context) {
    rwlock_context_t *context = opaque_context;
    test_thread_t thread;

    test_thread_init(&thread);
    g_current_thread = &thread;
    for (uint32_t iteration = 0; iteration < WORKER_ITERATIONS; ++iteration) {
        uint32_t readers;
        uint32_t maximum;

        bsd_rwlock_read_lock(&context->lock);
        readers = __atomic_add_fetch(
            &context->active_readers, 1, __ATOMIC_SEQ_CST);
        maximum = __atomic_load_n(
            &context->maximum_readers, __ATOMIC_RELAXED);
        while (maximum < readers &&
               !__atomic_compare_exchange_n(
                   &context->maximum_readers, &maximum, readers, 0,
                   __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        }
        if (__atomic_load_n(&context->writer_active, __ATOMIC_SEQ_CST))
            __atomic_store_n(&context->violation, 1, __ATOMIC_RELAXED);
        if ((iteration & 31u) == 0)
            sched_yield();
        __atomic_sub_fetch(
            &context->active_readers, 1, __ATOMIC_SEQ_CST);
        bsd_rwlock_read_unlock(&context->lock);
    }
    g_current_thread = 0;
    test_thread_destroy(&thread);
    return 0;
}

static void *rwlock_writer(void *opaque_context) {
    rwlock_context_t *context = opaque_context;
    test_thread_t thread;

    test_thread_init(&thread);
    g_current_thread = &thread;
    for (uint32_t iteration = 0;
         iteration < WORKER_ITERATIONS / 4u; ++iteration) {
        bsd_rwlock_write_lock(&context->lock);
        if (__atomic_exchange_n(
                &context->writer_active, 1, __ATOMIC_SEQ_CST) ||
            __atomic_load_n(
                &context->active_readers, __ATOMIC_SEQ_CST))
            __atomic_store_n(&context->violation, 1, __ATOMIC_RELAXED);
        context->writes++;
        if ((iteration & 31u) == 0)
            sched_yield();
        __atomic_store_n(
            &context->writer_active, 0, __ATOMIC_SEQ_CST);
        bsd_rwlock_write_unlock(&context->lock);
    }
    g_current_thread = 0;
    test_thread_destroy(&thread);
    return 0;
}

static void test_rwlock_contention(void) {
    rwlock_context_t context;
    pthread_t readers[WORKER_COUNT];
    pthread_t writer;

    memset(&context, 0, sizeof(context));
    assert(bsd_rwlock_init(&context.lock, "shared-state", 0) == 0);
    for (uint32_t index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_create(
            &readers[index], 0, rwlock_reader, &context) == 0);
    assert(pthread_create(&writer, 0, rwlock_writer, &context) == 0);
    for (uint32_t index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_join(readers[index], 0) == 0);
    assert(pthread_join(writer, 0) == 0);
    assert(!context.violation);
    assert(context.maximum_readers > 1);
    assert(context.writes == WORKER_ITERATIONS / 4u);
    assert(bsd_rwlock_destroy(&context.lock) == 0);
}

static void test_freebsd_header_wrappers(void) {
    struct mtx mutex;
    struct cv condition;
    struct rwlock lock;

    mtx_init(&mutex, "wrapper", 0, MTX_RECURSE | MTX_NOWITNESS);
    cv_init(&condition, "wrapper-cv");
    mtx_lock(&mutex);
    assert(mtx_owned(&mutex));
    assert(mtx_trylock(&mutex));
    assert(mtx_recursed(&mutex));
    mtx_unlock(&mutex);
    mtx_unlock(&mutex);
    cv_signal(&condition);
    cv_destroy(&condition);
    mtx_destroy(&mutex);

    rw_init_flags(&lock, "wrapper-rw", RW_RECURSE);
    rw_rlock(&lock);
    assert(bsd_rwlock_read_locked(&lock.edgeos_lock));
    assert(rw_try_upgrade(&lock));
    assert(rw_wowned(&lock));
    rw_wlock(&lock);
    rw_wunlock(&lock);
    rw_downgrade(&lock);
    rw_runlock(&lock);
    assert(rw_try_wlock(&lock));
    rw_wunlock(&lock);
    rw_destroy(&lock);
}

int main(void) {
    bsd_sync_ops_t ops;
    test_thread_t main_thread;

    test_thread_init(&main_thread);
    g_current_thread = &main_thread;
    memset(&ops, 0, sizeof(ops));
    ops.current_thread = test_current_thread;
    ops.can_block = test_can_block;
    ops.prepare_block = test_prepare_block;
    ops.block_current = test_block_current;
    ops.wake_thread = test_wake_thread;
    ops.yield_thread = test_yield;
    ops.fatal = test_fatal;
    assert(bsd_sync_initialize(&ops) == 0);

    test_mutex_contention();
    test_recursive_and_spin_mutex();
    test_condition_signal();
    test_condition_broadcast();
    test_rwlock_contention();
    test_freebsd_header_wrappers();

    g_current_thread = 0;
    test_thread_destroy(&main_thread);
    printf("bsd_bridge_sync_unit: PASS\n");
    return 0;
}
