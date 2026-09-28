/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD delay and sleep-channel services on the shared worker runtime. */

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/sync.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/mutex.h"
#include "sys/boottime.h"
#include <sys/sleepqueue.h>

struct sbuf;

#define BSD_SLEEP_C_ABSOLUTE 0x0200
#define BSD_SLEEP_EINTR 4
#define BSD_SLEEP_EWOULDBLOCK 11
#define BSD_SLEEP_SBT_ONE_SECOND (INT64_C(1) << 32)

#ifdef BSD_BRIDGE_HOST_TEST
#include <time.h>
#else
#include "kernel/arch_cpu.h"
#include "kernel/signal_runtime.h"
#endif

static uint64_t
bsd_sleep_monotonic_us(void)
{
#ifdef BSD_BRIDGE_HOST_TEST
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000) +
        (uint64_t)now.tv_nsec / UINT64_C(1000);
#else
    return boottime_monotonic_us();
#endif
}

void
bsd_delay(unsigned int microseconds)
{
#ifdef BSD_BRIDGE_HOST_TEST
    struct timespec duration = {
        .tv_sec = (time_t)(microseconds / 1000000u),
        .tv_nsec = (long)(microseconds % 1000000u) * 1000L,
    };

    while (nanosleep(&duration, &duration) != 0) {
    }
#else
    uint64_t start = boottime_monotonic_us();

    while (boottime_monotonic_us() - start < microseconds)
        arch_cpu_relax();
#endif
}

int
bsd_pause(const char *wait_message, int timeout_ticks)
{
    static uint8_t pause_channel;
    const void *channel = bsd_kthread_current_token();

    (void)wait_message;
    if (!channel)
        channel = &pause_channel;
    return bsd_kthread_sleep(channel, 0, 0, timeout_ticks);
}

int
bsd_pause_sig(const char *wait_message, int timeout_ticks)
{
    int result;

#ifndef BSD_BRIDGE_HOST_TEST
    if (kernel_current_signal_wake_pending())
        return BSD_SLEEP_EINTR;
#endif
    result = bsd_pause(wait_message, timeout_ticks);
#ifndef BSD_BRIDGE_HOST_TEST
    if (kernel_current_signal_wake_pending())
        return BSD_SLEEP_EINTR;
#endif
    return result;
}

int
bsd_pause_sbt(const char *wait_message, int64_t sleep_time,
    int64_t precision, int flags)
{
    static uint8_t pause_channel;
    const void *channel = bsd_kthread_current_token();

    if (!channel)
        channel = &pause_channel;
    return bsd_tsleep_sbt(channel, 0, wait_message, sleep_time,
        precision, flags);
}

int
bsd_msleep(const void *channel, struct mtx *mutex, int priority,
    const char *wait_message, int timeout_ticks)
{
    (void)wait_message;
    return bsd_kthread_sleep(
        channel, mutex, priority, timeout_ticks);
}

static int
bsd_sbt_to_ticks(int64_t sleep_time)
{
    uint64_t whole_seconds;
    uint64_t fraction;
    uint64_t ticks;

    if (sleep_time <= 0)
        return 0;
    whole_seconds = (uint64_t)sleep_time >> 32;
    fraction = (uint32_t)sleep_time;
    if (whole_seconds > (uint64_t)INT32_MAX / (unsigned int)hz)
        return INT32_MAX;
    ticks = whole_seconds * (unsigned int)hz;
    ticks += (fraction * (unsigned int)hz +
        (uint64_t)UINT32_MAX) >> 32;
    if (ticks == 0)
        ticks = 1;
    return ticks > INT32_MAX ? INT32_MAX : (int)ticks;
}

#define BSD_SLEEPQ_CONTEXT_COUNT 64u

struct bsd_sleepq_context {
    void *thread;
    const void *channel;
    uint64_t generation;
    int timeout_ticks;
};

static volatile unsigned int g_sleepq_guard;
static struct bsd_sleepq_context
    g_sleepq_contexts[BSD_SLEEPQ_CONTEXT_COUNT];

static void
sleepq_guard_lock(void)
{
    while (__atomic_exchange_n(&g_sleepq_guard, 1u,
        __ATOMIC_ACQUIRE) != 0)
        bsd_sync_yield_current();
}

static void
sleepq_guard_unlock(void)
{
    __atomic_store_n(&g_sleepq_guard, 0u, __ATOMIC_RELEASE);
}

static struct bsd_sleepq_context *
sleepq_current_context(int create)
{
    void *thread = bsd_kthread_current_token();
    struct bsd_sleepq_context *available = 0;
    struct bsd_sleepq_context *result = 0;

    if (!thread)
        return 0;
    sleepq_guard_lock();
    for (unsigned int index = 0; index < BSD_SLEEPQ_CONTEXT_COUNT; ++index) {
        if (g_sleepq_contexts[index].thread == thread) {
            result = &g_sleepq_contexts[index];
            break;
        }
        if (!available && !g_sleepq_contexts[index].thread)
            available = &g_sleepq_contexts[index];
    }
    if (!result && create && available) {
        available->thread = thread;
        result = available;
    }
    sleepq_guard_unlock();
    return result;
}

static void
sleepq_context_clear(struct bsd_sleepq_context *context)
{
    if (!context)
        return;
    sleepq_guard_lock();
    context->thread = 0;
    context->channel = 0;
    context->generation = 0;
    context->timeout_ticks = 0;
    sleepq_guard_unlock();
}

void
init_sleepqueues(void)
{
    bsd_memset(g_sleepq_contexts, 0, sizeof(g_sleepq_contexts));
}

void
sleepq_lock(const void *channel)
{
    struct bsd_sleepq_context *context = sleepq_current_context(1);

    if (!context)
        return;
    context->channel = channel;
    context->generation = bsd_kthread_wakeup_generation(channel);
    context->timeout_ticks = 0;
}

void
sleepq_release(const void *channel)
{
    struct bsd_sleepq_context *context = sleepq_current_context(0);

    if (context && context->channel == channel)
        sleepq_context_clear(context);
}

void
sleepq_add(const void *channel, struct lock_object *lock,
    const char *message, int flags, int queue)
{
    struct bsd_sleepq_context *context = sleepq_current_context(1);

    (void)lock;
    (void)message;
    (void)flags;
    (void)queue;
    if (!context)
        return;
    if (context->channel != channel) {
        context->channel = channel;
        context->generation = bsd_kthread_wakeup_generation(channel);
    }
}

void
sleepq_set_timeout_sbt(const void *channel, sbintime_t sleep_time,
    sbintime_t precision, int flags)
{
    struct bsd_sleepq_context *context = sleepq_current_context(1);

    (void)precision;
    (void)flags;
    if (!context)
        return;
    context->channel = channel;
    context->timeout_ticks = bsd_sbt_to_ticks(sleep_time);
}

static int
sleepq_wait_common(const void *channel, int timed)
{
    struct bsd_sleepq_context *context = sleepq_current_context(0);
    uint64_t generation = context && context->channel == channel ?
        context->generation : bsd_kthread_wakeup_generation(channel);
    int timeout_ticks = timed && context && context->channel == channel ?
        context->timeout_ticks : 0;
    int result;

    sleepq_context_clear(context);
    result = bsd_kthread_sleep_generation(channel, generation, timeout_ticks);
    return result;
}

void
sleepq_wait(const void *channel, int priority)
{
    (void)priority;
    (void)sleepq_wait_common(channel, 0);
}

int
sleepq_wait_sig(const void *channel, int priority)
{
    (void)priority;
    return sleepq_wait_common(channel, 0);
}

int
sleepq_timedwait(const void *channel, int priority)
{
    (void)priority;
    return sleepq_wait_common(channel, 1);
}

int
sleepq_timedwait_sig(const void *channel, int priority)
{
    (void)priority;
    return sleepq_wait_common(channel, 1);
}

void
sleepq_signal(const void *channel, int flags, int priority, int queue)
{
    (void)flags;
    (void)priority;
    (void)queue;
    bsd_kthread_wakeup(channel, 1);
}

void
sleepq_broadcast(const void *channel, int flags, int priority, int queue)
{
    (void)flags;
    (void)priority;
    (void)queue;
    bsd_kthread_wakeup(channel, 0);
}

int
bsd_msleep_sbt(const void *channel, struct mtx *mutex, int priority,
    const char *wait_message, int64_t sleep_time, int64_t precision,
    int flags)
{
    int timeout_ticks;

    (void)precision;
    if ((flags & BSD_SLEEP_C_ABSOLUTE) != 0 && sleep_time != 0) {
        uint64_t microseconds = bsd_sleep_monotonic_us();
        uint64_t seconds = microseconds / UINT64_C(1000000);
        uint64_t remainder = microseconds % UINT64_C(1000000);
        uint64_t current;

        if (seconds > (uint64_t)INT64_MAX >> 32)
            current = (uint64_t)INT64_MAX;
        else
            current = (seconds << 32) +
                (remainder * (uint64_t)BSD_SLEEP_SBT_ONE_SECOND) /
                UINT64_C(1000000);

        if (sleep_time <= 0 || (uint64_t)sleep_time <= current)
            return BSD_SLEEP_EWOULDBLOCK;
        sleep_time -= (int64_t)current;
    }
    timeout_ticks = bsd_sbt_to_ticks(sleep_time);
    return bsd_msleep(channel, mutex, priority, wait_message, timeout_ticks);
}

int
bsd_tsleep_sbt(const void *channel, int priority,
    const char *wait_message, int64_t sleep_time, int64_t precision,
    int flags)
{
    return bsd_msleep_sbt(channel, 0, priority, wait_message, sleep_time,
        precision, flags);
}

int
bsd_rw_sleep(const void *channel, void *opaque_lock, int priority,
    const char *wait_message, int timeout_ticks)
{
    bsd_rwlock_t *lock = opaque_lock;
    uint64_t generation;
    int result;

    (void)priority;
    (void)wait_message;
    if (!channel || !lock || !bsd_rwlock_write_owned(lock))
        return 22;
    generation = bsd_kthread_wakeup_generation(channel);
    bsd_rwlock_write_unlock(lock);
    result = bsd_kthread_sleep_generation(
        channel, generation, timeout_ticks);
    bsd_rwlock_write_lock(lock);
    return result;
}

void
bsd_wakeup(const void *channel)
{
    bsd_kthread_wakeup(channel, 0);
}

void
bsd_wakeup_one(const void *channel)
{
    bsd_kthread_wakeup(channel, 1);
}

int
sleepq_sbuf_print_stacks(struct sbuf *buffer, const void *channel, int queue,
    int *stack_count)
{
    (void)buffer;
    (void)channel;
    (void)queue;
    if (stack_count != 0)
        *stack_count = 0;
    return 0;
}
