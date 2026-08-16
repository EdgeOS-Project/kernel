/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD Driver Bridge atomic contract. */

#ifdef BSD_BRIDGE_TARGET_COMPILE

#include <machine/atomic.h>
#include <sys/refcount.h>

int
bsd_bridge_atomic_compile_probe(volatile u_int *value32,
    volatile u_long *value_long, volatile uint64_t *value64,
    volatile uintptr_t *value_ptr)
{
    u_int expected = atomic_load_int(value32);
    volatile u_int references;

    atomic_add_int(value32, 1);
    atomic_store_rel_long(value_long,
        atomic_load_acq_long(value_long) + 1);
    atomic_store_rel_64(value64, atomic_load_acq_64(value64) + 1);
    atomic_store_rel_ptr(value_ptr, atomic_load_acq_ptr(value_ptr) + 1);
    refcount_init(&references, 1);
    (void)refcount_acquire(&references);
    (void)refcount_release(&references);
#if defined(__aarch64__) || defined(_M_ARM64)
    dmb(ish);
    dsb(sy);
    isb();
#endif
    return atomic_fcmpset_int(value32, &expected, expected + 1);
}

#else

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "include/compat/freebsd/machine/atomic.h"

#ifndef __result_use_check
#define __result_use_check __attribute__((__warn_unused_result__))
#endif
#ifndef __predict_true
#define __predict_true(expression) __builtin_expect((expression), 1)
#endif
#ifndef __predict_false
#define __predict_false(expression) __builtin_expect((expression), 0)
#endif

#include "include/compat/freebsd/sys/refcount.h"

#define WORKER_COUNT 8
#define WORKER_ITERATIONS 50000

static volatile u_int shared_counter;

static void *
increment_worker(void *context)
{
    u_int iteration;

    (void)context;
    for (iteration = 0; iteration < WORKER_ITERATIONS; ++iteration)
        (void)atomic_fetchadd_int(&shared_counter, 1);
    return 0;
}

static void
test_parallel_fetch_add(void)
{
    pthread_t workers[WORKER_COUNT];
    int index;

    shared_counter = 0;
    for (index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_create(&workers[index], 0, increment_worker, 0) == 0);
    for (index = 0; index < WORKER_COUNT; ++index)
        assert(pthread_join(workers[index], 0) == 0);
    assert(shared_counter == WORKER_COUNT * WORKER_ITERATIONS);
}

static void
test_integer_operations(void)
{
    volatile u_int value = 0;
    u_int expected;

    atomic_add_int(&value, 7);
    atomic_subtract_int(&value, 2);
    assert(value == 5);

    atomic_set_int(&value, 0x10);
    assert(value == 0x15);
    atomic_clear_int(&value, 0x5);
    assert(value == 0x10);

    assert(atomic_cmpset_int(&value, 0x10, 0x20));
    assert(value == 0x20);
    assert(!atomic_cmpset_int(&value, 0x10, 0x30));
    assert(value == 0x20);

    expected = 0x10;
    assert(!atomic_fcmpset_int(&value, &expected, 0x30));
    assert(expected == 0x20);
    assert(atomic_fcmpset_int(&value, &expected, 0x30));
    assert(value == 0x30);

    assert(atomic_swap_int(&value, 0x40) == 0x30);
    assert(atomic_readandclear_int(&value) == 0x40);
    assert(value == 0);

    assert(!atomic_testandset_int(&value, 3));
    assert(atomic_testandset_int(&value, 3));
    assert(atomic_testandclear_int(&value, 3));
    assert(!atomic_testandclear_int(&value, 3));
    assert(!atomic_testandset_32(&value, 7));
    assert(atomic_testandset_32(&value, 7));
    assert(atomic_testandclear_32(&value, 7));
    assert(!atomic_testandclear_32(&value, 7));
}

static void
test_width_aliases(void)
{
    volatile uint16_t value16 = 0;
    volatile uint64_t value64 = 9;

    atomic_store_rel_16(&value16, 0x1234);
    assert(atomic_load_acq_16(&value16) == 0x1234);
    assert(atomic_fetchadd_64(&value64, 7) == 9);
    assert(value64 == 16);

    atomic_thread_fence_acq();
    atomic_thread_fence_rel();
    atomic_thread_fence_acq_rel();
    atomic_thread_fence_seq_cst();
    mb();
    rmb();
    wmb();
}

static void
test_reference_counts(void)
{
    volatile u_int references;

    refcount_init(&references, 1);
    assert(refcount_load(&references) == 1);
    assert(refcount_acquire(&references) == 1);
    assert(refcount_acquiren(&references, 2) == 2);
    assert(refcount_load(&references) == 4);
    assert(refcount_release_if_gt(&references, 2));
    assert(refcount_release_if_not_last(&references));
    assert(!refcount_release_if_last(&references));
    assert(!refcount_release(&references));
    assert(refcount_release_if_last(&references));
    assert(refcount_load(&references) == 0);
    assert(!refcount_acquire_if_not_zero(&references));

    refcount_init(&references, 2);
    assert(refcount_acquire_checked(&references));
    assert(refcount_acquire_if_gt(&references, 2));
    assert(!refcount_release_if_gt(&references, 4));
    assert(refcount_releasen(&references, 4));

    atomic_store_int(&references, REFCOUNT_SATURATION_VALUE);
    assert(refcount_acquire(&references) == REFCOUNT_SATURATION_VALUE);
    assert(refcount_load(&references) == REFCOUNT_SATURATION_VALUE);
    assert(!refcount_release(&references));
    assert(refcount_load(&references) == REFCOUNT_SATURATION_VALUE);
}

int
main(void)
{
    test_parallel_fetch_add();
    test_integer_operations();
    test_width_aliases();
    test_reference_counts();
    return 0;
}

#endif
