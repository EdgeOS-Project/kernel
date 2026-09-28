/* SPDX-License-Identifier: MPL-2.0 */
/* Host runtime tests for BSD Driver Bridge kernel workers and sleep queues. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/mutex.h"
#include "compat/freebsd/sys/pcpu.h"
#include "compat/freebsd/sys/sched.h"
#include "compat/freebsd/sys/unistd.h"

static uint8_t g_wait_channel;
static volatile uint32_t g_wait_stage;
static volatile uint32_t g_timeout_result;
static volatile uint32_t g_sbt_timeout_result;
static volatile uint32_t g_sbt_mutex_stage;
static volatile uint32_t g_sbt_mutex_result;
static volatile uint32_t g_suspend_stage;
static volatile uint32_t g_suspend_stop;
static volatile uint32_t g_stubborn_stage;
static volatile uint32_t g_generation_stage;
static uint64_t g_generation;
static struct mtx g_sbt_mutex;
static int g_main_thread_token;

static void *
test_current_thread(void *context)
{
    void *thread = bsd_kthread_current_token();

    (void)context;
    return thread ? thread : &g_main_thread_token;
}

static int
test_can_block(void *thread, void *context)
{
    (void)context;
    return bsd_kthread_token_valid(thread);
}

static void
test_thread_noop(void *thread, void *context)
{
    (void)thread;
    (void)context;
}

static void
test_yield(void *context)
{
    (void)context;
}

static void
wait_until(volatile uint32_t *value, uint32_t expected)
{
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 1000000L };

    for (uint32_t attempt = 0; attempt < 5000u; ++attempt) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) == expected)
            return;
        (void)nanosleep(&delay, 0);
    }
    assert(!"worker completion timed out");
}

static void
wait_worker(void *argument)
{
    struct thread *thread;

    (void)argument;
    assert(bsd_kthread_token_valid(bsd_kthread_current_token()));
    thread = bsd_kthread_current_public();
    assert(thread != 0);
    assert(thread->td_bound_cpu == -1);
    assert(thread->td_saved_cpu == -1);
    assert(thread->td_pin_saved_bound_cpu == -1);
    assert(thread->td_pinned == 0);
    assert(thread->td_affinity_mask == UINT64_MAX);
    assert(PCPU_GET(cpuid) == 0);
    sched_bind(thread, 0);
    assert(thread->td_bound_cpu == 0);
    assert(thread->td_saved_cpu == 0);
    assert(thread->td_affinity_mask == UINT64_C(1));
    assert(PCPU_GET(cpuid) == 0);
    sched_unbind(thread);
    assert(thread->td_bound_cpu == -1);
    assert(thread->td_affinity_mask == UINT64_MAX);
    assert(PCPU_GET(cpuid) == 0);
    sched_pin();
    assert(thread->td_pinned == 1);
    assert(thread->td_pin_saved_bound_cpu == -1);
    assert(thread->td_bound_cpu == 0);
    assert(thread->td_affinity_mask == UINT64_C(1));
    sched_pin();
    assert(thread->td_pinned == 2);
    sched_unpin();
    assert(thread->td_pinned == 1);
    assert(thread->td_bound_cpu == 0);
    sched_unpin();
    assert(thread->td_pinned == 0);
    assert(thread->td_pin_saved_bound_cpu == -1);
    assert(thread->td_bound_cpu == -1);
    assert(thread->td_affinity_mask == UINT64_MAX);
    __atomic_store_n(&g_wait_stage, 1, __ATOMIC_RELEASE);
    assert(bsd_msleep(&g_wait_channel, 0, 0, "unitwait", 0) == 0);
    __atomic_store_n(&g_wait_stage, 2, __ATOMIC_RELEASE);
}

static void
timeout_worker(void *argument)
{
    (void)argument;
    g_timeout_result =
        (uint32_t)bsd_pause("unittime", 2);
}

static void
sbt_timeout_worker(void *argument)
{
    (void)argument;
    g_sbt_timeout_result = (uint32_t)bsd_tsleep_sbt(
        &g_wait_channel, 0, "unitsbt", INT64_C(1) << 22, 0, 0);
}

static void
sbt_mutex_worker(void *argument)
{
    (void)argument;
    mtx_lock(&g_sbt_mutex);
    __atomic_store_n(&g_sbt_mutex_stage, 1, __ATOMIC_RELEASE);
    g_sbt_mutex_result = (uint32_t)bsd_msleep_sbt(
        &g_wait_channel, &g_sbt_mutex, 0, "unitsbtmtx",
        INT64_C(1) << 22, 0, 0);
    assert(mtx_owned(&g_sbt_mutex));
    mtx_unlock(&g_sbt_mutex);
    __atomic_store_n(&g_sbt_mutex_stage, 2, __ATOMIC_RELEASE);
}

static void
suspend_worker(void *argument)
{
    (void)argument;
    __atomic_store_n(&g_suspend_stage, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&g_suspend_stop, __ATOMIC_ACQUIRE)) {
        kthread_suspend_check();
        (void)bsd_pause("unitsusp", 1);
    }
    __atomic_store_n(&g_suspend_stage, 2, __ATOMIC_RELEASE);
}

static void
stubborn_worker(void *argument)
{
    (void)argument;
    __atomic_store_n(&g_stubborn_stage, 1, __ATOMIC_RELEASE);
    bsd_delay(200000);
    __atomic_store_n(&g_stubborn_stage, 2, __ATOMIC_RELEASE);
}

static void
generation_worker(void *argument)
{
    (void)argument;
    __atomic_store_n(&g_generation_stage, 1, __ATOMIC_RELEASE);
    assert(bsd_kthread_sleep_generation(
        &g_wait_channel, g_generation, 0) == 0);
    __atomic_store_n(&g_generation_stage, 2, __ATOMIC_RELEASE);
}

int
main(void)
{
    bsd_sync_ops_t sync = {
        .current_thread = test_current_thread,
        .can_block = test_can_block,
        .prepare_block = test_thread_noop,
        .block_current = test_thread_noop,
        .wake_thread = test_thread_noop,
        .yield_thread = test_yield,
    };
    struct thread *wait_thread = 0;
    struct thread *timeout_thread = 0;
    struct thread *sbt_timeout_thread = 0;
    struct thread *sbt_mutex_thread = 0;
    struct thread *suspend_thread = 0;
    struct thread *stubborn_thread = 0;
    struct thread *generation_thread = 0;

    assert(bsd_kthread_runtime_initialize() == 0);
    assert(bsd_kthread_runtime_is_initialized());
    assert(bsd_sync_initialize(&sync) == 0);
    mtx_init(&g_sbt_mutex, "sbt-mutex", 0, MTX_DEF);
    g_generation = bsd_kthread_wakeup_generation(&g_wait_channel);
    assert(g_generation != 0);
    bsd_wakeup_one(&g_wait_channel);
    assert(bsd_kthread_sleep_generation(
        &g_wait_channel, g_generation, 0) == 0);
    g_generation = bsd_kthread_wakeup_generation(&g_wait_channel);
    assert(kthread_add(generation_worker, 0, 0, &generation_thread,
        0, 0, "generation-worker") == 0);
    wait_until(&g_generation_stage, 1);
    bsd_wakeup_one(&g_wait_channel);
    wait_until(&g_generation_stage, 2);
    assert(bsd_kthread_join(generation_thread) == 0);

    assert(kthread_add(wait_worker, 0, 0, &wait_thread,
        RFHIGHPID, 0, "wait-worker") == 0);
    assert(wait_thread != 0);
    assert(wait_thread->td_tid > PID_MAX);
    assert(wait_thread->td_tid == THREAD0_TID + wait_thread->td_proc->p_pid);
    wait_until(&g_wait_stage, 1);
    bsd_wakeup_one(&g_wait_channel);
    wait_until(&g_wait_stage, 2);
    assert(bsd_kthread_join(wait_thread) == 0);
    assert(bsd_kthread_join(wait_thread) == 22);

    assert(kthread_add(timeout_worker, 0, 0, &timeout_thread,
        0, 0, "timeout-worker") == 0);
    assert(timeout_thread != 0);
    wait_until(&g_timeout_result, 35);
    assert(bsd_kthread_join(timeout_thread) == 0);

    assert(kthread_add(sbt_timeout_worker, 0, 0, &sbt_timeout_thread,
        0, 0, "sbt-timeout-worker") == 0);
    wait_until(&g_sbt_timeout_result, 35);
    assert(bsd_kthread_join(sbt_timeout_thread) == 0);
    assert(bsd_tsleep_sbt(&g_wait_channel, 0, "expired",
        1, 0, 0x0200) == 11);

    assert(kthread_add(sbt_mutex_worker, 0, 0, &sbt_mutex_thread,
        0, 0, "sbt-mutex-worker") == 0);
    wait_until(&g_sbt_mutex_stage, 2);
    assert(g_sbt_mutex_result == 35);
    assert(bsd_kthread_join(sbt_mutex_thread) == 0);

    assert(kthread_add(suspend_worker, 0, 0, &suspend_thread,
        0, 0, "suspend-worker") == 0);
    wait_until(&g_suspend_stage, 1);
    assert(kthread_suspend(suspend_thread, 1000) == 0);
    assert(kthread_resume(suspend_thread) == 0);
    __atomic_store_n(&g_suspend_stop, 1, __ATOMIC_RELEASE);
    bsd_wakeup(suspend_thread);
    wait_until(&g_suspend_stage, 2);
    assert(bsd_kthread_join(suspend_thread) == 0);

    assert(kthread_add(stubborn_worker, 0, 0, &stubborn_thread,
        0, 0, "stubborn-worker") == 0);
    wait_until(&g_stubborn_stage, 1);
    assert(kthread_suspend(stubborn_thread, 50) == 35);
    wait_until(&g_stubborn_stage, 2);
    assert(bsd_kthread_join(stubborn_thread) == 0);

    mtx_destroy(&g_sbt_mutex);
    printf("bsd_bridge_kthread_unit: PASS\n");
    return 0;
}
