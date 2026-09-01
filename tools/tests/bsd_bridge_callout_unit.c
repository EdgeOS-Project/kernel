/* SPDX-License-Identifier: MPL-2.0 */
/* Host behavior tests for the BSD Driver Bridge timer-callout runtime. */

#include <assert.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "compat/freebsd/edgeos/callout.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/sys/callout.h"
#include "compat/freebsd/sys/mutex.h"

typedef struct {
    struct callout callout;
    volatile uint32_t count;
} reschedule_context_t;

typedef struct {
    struct callout callout;
    uint32_t depth;
    uint32_t maximum_depth;
    uint32_t count;
} direct_reschedule_context_t;

static _Thread_local uint8_t g_thread_token;
static volatile uint32_t g_callback_count;
static volatile uint32_t g_mutex_callback_count;
static volatile uint32_t g_direct_callback_count;
static volatile uint32_t g_slow_started;
static volatile uint32_t g_slow_finished;

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

static void
sleep_milliseconds(uint32_t milliseconds)
{
    struct timespec delay = {
        .tv_sec = (time_t)(milliseconds / 1000u),
        .tv_nsec = (long)(milliseconds % 1000u) * 1000000L,
    };

    while (nanosleep(&delay, &delay) != 0) {
    }
}

static void
wait_for_value(volatile uint32_t *value, uint32_t expected)
{
    for (uint32_t attempt = 0; attempt < 5000u; ++attempt) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) == expected)
            return;
        sleep_milliseconds(1);
    }
    assert(!"callout callback timed out");
}

static void
count_callback(void *context)
{
    volatile uint32_t *count = context;

    __atomic_add_fetch(count, 1, __ATOMIC_RELEASE);
}

static void
mutex_callback(void *context)
{
    struct mtx *mutex = context;

    assert(mtx_owned(mutex));
    __atomic_add_fetch(&g_mutex_callback_count, 1, __ATOMIC_RELEASE);
}

static void
reschedule_callback(void *context)
{
    reschedule_context_t *reschedule = context;
    uint32_t count =
        __atomic_add_fetch(&reschedule->count, 1, __ATOMIC_RELEASE);

    if (count == 1)
        assert(callout_schedule(&reschedule->callout, 2) == 0);
}

static void
direct_reschedule_callback(void *context)
{
    direct_reschedule_context_t *reschedule = context;

    reschedule->depth++;
    if (reschedule->depth > reschedule->maximum_depth)
        reschedule->maximum_depth = reschedule->depth;
    reschedule->count++;
    if (reschedule->count == 1) {
        assert(callout_reset_sbt(&reschedule->callout, 0, 0,
            direct_reschedule_callback, reschedule, C_DIRECT_EXEC) == 0);
        bsd_callout_process_timer_tick();
    }
    reschedule->depth--;
}

static void
slow_callback(void *context)
{
    (void)context;
    __atomic_store_n(&g_slow_started, 1, __ATOMIC_RELEASE);
    sleep_milliseconds(30);
    __atomic_store_n(&g_slow_finished, 1, __ATOMIC_RELEASE);
}

int
main(void)
{
    bsd_sync_ops_t sync_ops = {
        .current_thread = test_current_thread,
        .can_block = test_cannot_block,
        .prepare_block = test_noop_thread,
        .block_current = test_noop_thread,
        .wake_thread = test_noop_thread,
        .yield_thread = test_yield,
        .fatal = test_fatal,
    };
    struct callout basic;
    struct callout canceled;
    struct callout locked;
    struct callout blocked;
    struct callout direct;
    struct callout invalid_direct;
    struct callout slow;
    struct mtx mutex;
    struct mtx spin_mutex;
    direct_reschedule_context_t direct_reschedule = {0};
    reschedule_context_t reschedule = {0};
    sbintime_t absolute;
    sbintime_t effective_precision;
    sbintime_t now;
    uint64_t drain_start;

    assert(bsd_kthread_runtime_initialize() == 0);
    assert(bsd_sync_initialize(&sync_ops) == 0);
    assert(bsd_callout_runtime_initialize() == 0);
    assert(bsd_callout_runtime_is_initialized());

    callout_init(&basic, 1);
    assert(callout_reset(&basic, 3, count_callback,
        (void *)&g_callback_count) == 0);
    assert(callout_active(&basic));
    assert(callout_pending(&basic));
    wait_for_value(&g_callback_count, 1);
    assert(!callout_pending(&basic));
    callout_deactivate(&basic);
    assert(!callout_active(&basic));

    callout_init(&canceled, 1);
    assert(callout_reset(&canceled, 100, count_callback,
        (void *)&g_callback_count) == 0);
    assert(callout_reset(&canceled, 3, count_callback,
        (void *)&g_callback_count) == 1);
    wait_for_value(&g_callback_count, 2);
    callout_deactivate(&canceled);
    assert(callout_reset(&canceled, 50, count_callback,
        (void *)&g_callback_count) == 0);
    assert(callout_stop(&canceled) == 1);
    sleep_milliseconds(60);
    assert(__atomic_load_n(
        &g_callback_count, __ATOMIC_ACQUIRE) == 2);

    callout_init(&reschedule.callout, 1);
    assert(callout_reset(&reschedule.callout, 2,
        reschedule_callback, &reschedule) == 0);
    wait_for_value(&reschedule.count, 2);
    callout_deactivate(&reschedule.callout);

    mtx_init(&mutex, "callout-unit", 0, MTX_DEF);
    callout_init_mtx(&locked, &mutex, 0);
    assert(callout_reset(&locked, 2, mutex_callback, &mutex) == 0);
    wait_for_value(&g_mutex_callback_count, 1);
    assert(!mtx_owned(&mutex));
    callout_deactivate(&locked);

    callout_init_mtx(&blocked, &mutex, 0);
    mtx_lock(&mutex);
    assert(callout_reset(&blocked, 2, count_callback,
        (void *)&g_callback_count) == 0);
    sleep_milliseconds(5);
    assert(callout_stop(&blocked) == 1);
    mtx_unlock(&mutex);
    sleep_milliseconds(10);
    assert(__atomic_load_n(
        &g_callback_count, __ATOMIC_ACQUIRE) == 2);

    callout_init(&direct, 1);
    assert(callout_reset_sbt(&direct, SBT_1MS, 0,
        count_callback, (void *)&g_direct_callback_count,
        C_DIRECT_EXEC) == 0);
    sleep_milliseconds(5);
    assert(__atomic_load_n(
        &g_direct_callback_count, __ATOMIC_ACQUIRE) == 0);
    bsd_callout_process_timer_tick();
    assert(__atomic_load_n(
        &g_direct_callback_count, __ATOMIC_ACQUIRE) == 1);
    callout_deactivate(&direct);

    callout_init(&direct_reschedule.callout, 1);
    assert(callout_reset_sbt(&direct_reschedule.callout, 0, 0,
        direct_reschedule_callback, &direct_reschedule,
        C_DIRECT_EXEC) == 0);
    bsd_callout_process_timer_tick();
    assert(direct_reschedule.maximum_depth == 1);
    assert(direct_reschedule.count >= 1 && direct_reschedule.count <= 2);
    if (callout_pending(&direct_reschedule.callout))
        bsd_callout_process_timer_tick();
    assert(direct_reschedule.count == 2);
    assert(direct_reschedule.maximum_depth == 1);
    callout_deactivate(&direct_reschedule.callout);

    callout_init_mtx(&invalid_direct, &mutex, 0);
    assert(callout_reset_sbt(&invalid_direct, SBT_1MS, 0,
        count_callback, (void *)&g_direct_callback_count,
        C_DIRECT_EXEC) == 22);

    mtx_init(&spin_mutex, "callout-direct", 0, MTX_SPIN);
    callout_init_mtx(&direct, &spin_mutex, 0);
    assert(callout_reset_sbt(&direct, 0, 0, mutex_callback,
        &spin_mutex, C_DIRECT_EXEC | C_ABSOLUTE) == 0);
    bsd_callout_process_timer_tick();
    assert(__atomic_load_n(
        &g_mutex_callback_count, __ATOMIC_ACQUIRE) == 2);
    callout_deactivate(&direct);
    mtx_destroy(&spin_mutex);

    callout_init(&slow, 1);
    assert(callout_reset(&slow, 1, slow_callback, 0) == 0);
    wait_for_value(&g_slow_started, 1);
    drain_start = boottime_monotonic_us();
    assert(callout_drain(&slow) == 0);
    assert(__atomic_load_n(&g_slow_finished, __ATOMIC_ACQUIRE));
    assert(boottime_monotonic_us() - drain_start >= 10000u);

    now = (sbintime_t)(boottime_monotonic_us() / UINT64_C(1000000))
        * SBT_1S;
    callout_when(now + SBT_1MS, SBT_1US, C_ABSOLUTE,
        &absolute, &effective_precision);
    assert(absolute == now + SBT_1MS);
    assert(effective_precision == SBT_1US);

    mtx_destroy(&mutex);
    printf("bsd_bridge_callout_unit: PASS\n");
    return 0;
}
