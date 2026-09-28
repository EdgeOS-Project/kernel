/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stddef.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/epoch.h>

struct epoch_test_context {
    struct epoch_context callback_context;
    struct epoch_context chained_context;
    epoch_t epoch;
    volatile uint32_t reader_entered;
    volatile uint32_t reader_release;
    volatile uint32_t callback_count;
};

static void
epoch_test_chained_callback(epoch_context_t context)
{
    struct epoch_test_context *test =
        (struct epoch_test_context *)((char *)(void *)context -
            offsetof(struct epoch_test_context, chained_context));

    __atomic_add_fetch(&test->callback_count, 1u, __ATOMIC_RELEASE);
}

static void
epoch_test_callback(epoch_context_t context)
{
    struct epoch_test_context *test =
        (struct epoch_test_context *)(void *)context;

    __atomic_add_fetch(&test->callback_count, 1u, __ATOMIC_RELEASE);
    epoch_call(test->epoch, epoch_test_chained_callback,
        &test->chained_context);
}

static void *
epoch_test_reader(void *opaque)
{
    struct epoch_test_context *test = opaque;
    struct epoch_tracker tracker = {0};

    epoch_enter_preempt(global_epoch_preempt, &tracker);
    __atomic_store_n(&test->reader_entered, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&test->reader_release, __ATOMIC_ACQUIRE))
        sched_yield();
    epoch_exit_preempt(global_epoch_preempt, &tracker);
    return 0;
}

int
main(void)
{
    struct epoch_test_context test = {0};
    epoch_t allocated;
    pthread_t reader;

    test.epoch = global_epoch_preempt;
    assert(pthread_create(&reader, 0, epoch_test_reader, &test) == 0);
    while (!__atomic_load_n(&test.reader_entered, __ATOMIC_ACQUIRE))
        sched_yield();
    epoch_call(global_epoch_preempt, epoch_test_callback,
        &test.callback_context);
    assert(__atomic_load_n(&test.callback_count, __ATOMIC_ACQUIRE) == 0);
    __atomic_store_n(&test.reader_release, 1u, __ATOMIC_RELEASE);
    assert(pthread_join(reader, 0) == 0);
    epoch_drain_callbacks(global_epoch_preempt);
    assert(__atomic_load_n(&test.callback_count, __ATOMIC_ACQUIRE) == 2);

    allocated = epoch_alloc("test", EPOCH_PREEMPT);
    assert(allocated != 0);
    epoch_free(allocated);
    allocated = epoch_alloc("test-reuse", EPOCH_PREEMPT);
    assert(allocated != 0);
    epoch_free(allocated);

    puts("bsd_bridge_epoch_unit: PASS");
    return 0;
}
