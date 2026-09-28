/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for the BSD Driver Bridge taskqueue runtime. */

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "compat/freebsd/sys/callout.h"
#include "compat/freebsd/sys/cpuset.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/taskqueue.h"

#define TEST_PAGE_SIZE 4096u

static int g_order[8];
static uint32_t g_order_count;
static volatile uint32_t g_async_count;
static volatile uint32_t g_timeout_count;
static uint32_t g_notify_count;
static volatile uint64_t g_worker_affinity;
static _Thread_local uint8_t g_thread_token;

uint64_t
boottime_monotonic_us(void)
{
    struct timespec now;

    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * UINT64_C(1000000) +
        (uint64_t)now.tv_nsec / 1000u;
}

static void *
test_current_thread(void *context)
{
    void *worker = bsd_kthread_current_token();

    (void)context;
    return worker ? worker : &g_thread_token;
}

static int
test_cannot_block(void *thread, void *context)
{
    (void)thread;
    (void)context;
    return 0;
}

static void
test_noop_thread(void *thread, void *context)
{
    (void)thread;
    (void)context;
}

static void
test_yield(void *context)
{
    (void)context;
    sched_yield();
}

static void
test_fatal(const char *message, void *context)
{
    (void)context;
    fprintf(stderr, "unexpected bridge fatal error: %s\n", message);
    abort();
}

static void *
allocate_pages(uint64_t pages, void *context)
{
    void *memory = 0;

    (void)context;
    if (pages > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)pages * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0, (size_t)pages * TEST_PAGE_SIZE);
    return memory;
}

static void
release_pages(void *base, uint64_t pages, void *context)
{
    (void)pages;
    (void)context;
    free(base);
}

static void
notify_queue(void *context)
{
    uint32_t *count = context;

    ++*count;
}

static void
record_task(void *context, int pending)
{
    int value = *(int *)context;

    assert(g_order_count < sizeof(g_order) / sizeof(g_order[0]));
    g_order[g_order_count++] = value * 10 + pending;
}

static void
async_task(void *context, int pending)
{
    (void)context;
    __atomic_fetch_add(&g_async_count, (uint32_t)pending, __ATOMIC_RELEASE);
}

static void
timeout_task(void *context, int pending)
{
    (void)context;
    __atomic_fetch_add(&g_timeout_count, (uint32_t)pending,
        __ATOMIC_RELEASE);
}

static void
affinity_task(void *context, int pending)
{
    struct thread *thread = bsd_kthread_current_public();

    (void)context;
    assert(thread != 0);
    __atomic_store_n(&g_worker_affinity, thread->td_affinity_mask,
        __ATOMIC_RELEASE);
    __atomic_fetch_add(&g_async_count, (uint32_t)pending, __ATOMIC_RELEASE);
}

static void
wait_async(uint32_t expected)
{
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 1000000L };

    for (uint32_t attempt = 0; attempt < 5000u; ++attempt) {
        if (__atomic_load_n(&g_async_count, __ATOMIC_ACQUIRE) == expected)
            return;
        (void)nanosleep(&delay, 0);
    }
    assert(!"taskqueue worker timed out");
}

static void *
initialize_global_queue(void *context)
{
    (void)context;
    return (void *)(intptr_t)bsd_taskqueue_runtime_initialize();
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = allocate_pages,
        .release_pages = release_pages,
    };
    bsd_sync_ops_t sync_ops = {
        .current_thread = test_current_thread,
        .can_block = test_cannot_block,
        .prepare_block = test_noop_thread,
        .block_current = test_noop_thread,
        .wake_thread = test_noop_thread,
        .yield_thread = test_yield,
        .fatal = test_fatal,
    };
    struct taskqueue *manual;
    struct taskqueue *blocked;
    struct taskqueue *threaded;
    struct taskqueue *affined;
    struct task low;
    struct task high;
    struct task canceled;
    struct task asynchronous;
    struct task affinity;
    struct task global;
    struct task bus;
    struct timeout_task delayed;
    struct timeout_task tick_delayed;
    unsigned int canceled_pending = 0;
    int timeout_result;
    int low_value = 1;
    int high_value = 2;
    int canceled_value = 3;
    pthread_t initializers[8];
    cpuset_t mask;

    assert(bsd_allocator_initialize(&allocator) == 0);
    assert(bsd_kthread_runtime_initialize() == 0);
    assert(bsd_sync_initialize(&sync_ops) == 0);

    manual = taskqueue_create("manual", 0, notify_queue, &g_notify_count);
    assert(manual != 0);
    TASK_INIT(&low, 1, record_task, &low_value);
    TASK_INIT(&high, 9, record_task, &high_value);
    TASK_INIT(&canceled, 5, record_task, &canceled_value);
    assert(taskqueue_enqueue(manual, &low) == 0);
    assert(taskqueue_enqueue(manual, &high) == 0);
    assert(taskqueue_enqueue(manual, &low) == 0);
    assert(taskqueue_enqueue(manual, &canceled) == 0);
    assert(taskqueue_cancel(manual, &canceled, &canceled_pending) == 0);
    assert(canceled_pending == 1);
    assert(g_notify_count == 3);
    taskqueue_run(manual);
    assert(g_order_count == 2);
    assert(g_order[0] == 21);
    assert(g_order[1] == 12);
    taskqueue_free(manual);

    blocked = taskqueue_create("blocked", 0, 0, 0);
    assert(blocked != 0);
    TASK_INIT(&canceled, 0, record_task, &canceled_value);
    taskqueue_block(blocked);
    assert(taskqueue_enqueue(blocked, &canceled) == 0);
    taskqueue_free(blocked);
    assert(g_order_count == 3);
    assert(g_order[2] == 31);

    threaded = taskqueue_create(
        "threaded", 0, taskqueue_thread_enqueue, &threaded);
    assert(threaded != 0);
    assert(taskqueue_start_threads(
        &threaded, 1, 0, "threaded-unit") == 0);
    TASK_INIT(&asynchronous, 0, async_task, 0);
    assert(taskqueue_enqueue(threaded, &asynchronous) == 0);
    assert(taskqueue_enqueue(threaded, &asynchronous) == 0);
    wait_async(2);
    taskqueue_drain(threaded, &asynchronous);
    taskqueue_free(threaded);

    affined = taskqueue_create(
        "affined", 0, taskqueue_thread_enqueue, &affined);
    assert(affined != 0);
    CPU_SETOF(0, &mask);
    assert(taskqueue_start_threads_cpuset(
        &affined, 1, 7, &mask, "affined-unit") == 0);
    TASK_INIT(&affinity, 0, affinity_task, 0);
    assert(taskqueue_enqueue(affined, &affinity) == 0);
    wait_async(3);
    assert(__atomic_load_n(&g_worker_affinity, __ATOMIC_ACQUIRE) ==
        UINT64_C(1));
    taskqueue_drain(affined, &affinity);
    taskqueue_free(affined);

    for (size_t index = 0;
        index < sizeof(initializers) / sizeof(initializers[0]); ++index)
        assert(pthread_create(&initializers[index], 0,
            initialize_global_queue, 0) == 0);
    for (size_t index = 0;
        index < sizeof(initializers) / sizeof(initializers[0]); ++index) {
        void *result = 0;

        assert(pthread_join(initializers[index], &result) == 0);
        assert((intptr_t)result == 0);
    }
    assert(bsd_taskqueue_runtime_is_initialized());
    assert(taskqueue_bus != 0);
    assert(taskqueue_bus != taskqueue_thread);
    TASK_INIT(&global, 0, async_task, 0);
    assert(taskqueue_enqueue(taskqueue_thread, &global) == 0);
    wait_async(4);
    taskqueue_drain(taskqueue_thread, &global);
    TASK_INIT(&bus, 0, async_task, 0);
    assert(taskqueue_enqueue(taskqueue_bus, &bus) == 0);
    wait_async(5);
    taskqueue_drain(taskqueue_bus, &bus);

    TIMEOUT_TASK_INIT(taskqueue_bus, &delayed, 0, timeout_task, 0);
    timeout_result = taskqueue_enqueue_timeout_sbt(taskqueue_bus, &delayed,
        SBT_1MS * 100, 0, C_PREL(2));
    assert(timeout_result == 0);
    assert(taskqueue_enqueue_timeout_sbt(taskqueue_bus, &delayed,
        -SBT_1MS, 0, C_PREL(2)) == 1);
    {
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };
        unsigned int pending = 0;

        assert(nanosleep(&delay, 0) == 0);
        assert(__atomic_load_n(&g_timeout_count, __ATOMIC_ACQUIRE) == 0);
        assert(taskqueue_cancel_timeout(
            taskqueue_bus, &delayed, &pending) == 0);
        assert(pending == 1);
    }
    assert(taskqueue_enqueue_timeout_sbt(taskqueue_bus, &delayed,
        INT64_MIN, 0, C_PREL(2)) == 0);
    {
        unsigned int pending = 0;

        assert(taskqueue_cancel_timeout(
            taskqueue_bus, &delayed, &pending) == 0);
        assert(pending == 1);
    }

    TIMEOUT_TASK_INIT(taskqueue_bus, &tick_delayed, 0, timeout_task, 0);
    assert(taskqueue_enqueue_timeout(
        taskqueue_bus, &tick_delayed, -2) == 0);
    taskqueue_drain_timeout(taskqueue_bus, &tick_delayed);

    printf("bsd_bridge_taskqueue_unit: PASS\n");
    return 0;
}
