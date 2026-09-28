/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral process interval-timer policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include "kernel/itimer_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
#include "sys/boottime.h"

#define KERNEL_ITIMER_SIGALRM 14u

typedef struct kernel_itimer_real {
    int32_t owner_tgid;
    uint64_t deadline_us;
    uint64_t interval_us;
} kernel_itimer_real_t;

static const kernel_itimer_backend_ops_t *g_backend_ops;
static void *g_backend_context;
static kernel_itimer_real_t g_real_timers[EDGE_RUNTIME_MAX_TASKS];
static uint32_t g_real_timer_high_water;

int kernel_itimer_backend_register(
    const kernel_itimer_backend_ops_t *ops, void *context) {
    if (!ops || !ops->current_thread_group || !ops->send_signal)
        return -EDGE_LINUX_EINVAL;
    g_backend_ops = ops;
    g_backend_context = context;
    return 0;
}

static kernel_itimer_real_t *real_timer_lookup(int32_t tgid) {
    uint32_t index;
    for (index = 0; index < g_real_timer_high_water; ++index) {
        if (g_real_timers[index].owner_tgid == tgid)
            return &g_real_timers[index];
    }
    return 0;
}

static kernel_itimer_real_t *real_timer_allocate(int32_t tgid) {
    kernel_itimer_real_t *timer = real_timer_lookup(tgid);
    uint32_t index;
    if (timer) return timer;
    for (index = 0; index < g_real_timer_high_water; ++index) {
        if (!g_real_timers[index].owner_tgid) {
            timer = &g_real_timers[index];
            break;
        }
    }
    if (!timer && g_real_timer_high_water < EDGE_RUNTIME_MAX_TASKS)
        timer = &g_real_timers[g_real_timer_high_water++];
    if (!timer) return 0;
    timer->owner_tgid = tgid;
    timer->deadline_us = 0;
    timer->interval_us = 0;
    return timer;
}

static int current_thread_group(int32_t *tgid) {
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    return g_backend_ops->current_thread_group(
        g_backend_context, tgid);
}

static void real_timer_snapshot(const kernel_itimer_real_t *timer,
                                linux_itimerval64_t *value,
                                uint64_t now) {
    uint64_t remaining = 0;
    uint64_t interval = timer ? timer->interval_us : 0;
    if (timer && timer->deadline_us > now)
        remaining = timer->deadline_us - now;
    value->it_interval.tv_sec = (int64_t)(interval / 1000000u);
    value->it_interval.tv_usec = (int64_t)(interval % 1000000u);
    value->it_value.tv_sec = (int64_t)(remaining / 1000000u);
    value->it_value.tv_usec = (int64_t)(remaining % 1000000u);
}

void kernel_itimer_real_poll(void) {
    uint64_t now;
    uint32_t index;
    if (!g_backend_ops) return;
    now = boottime_monotonic_us();
    for (index = 0; index < g_real_timer_high_water; ++index) {
        kernel_itimer_real_t *timer = &g_real_timers[index];
        uint64_t elapsed;
        uint64_t periods;
        if (!timer->owner_tgid || !timer->deadline_us ||
            now < timer->deadline_us)
            continue;
        (void)g_backend_ops->send_signal(
            g_backend_context, timer->owner_tgid,
            KERNEL_ITIMER_SIGALRM);
        if (!timer->interval_us) {
            timer->deadline_us = 0;
            continue;
        }
        elapsed = now - timer->deadline_us;
        periods = elapsed / timer->interval_us + 1u;
        if (periods >
            (UINT64_MAX - timer->deadline_us) / timer->interval_us)
            timer->deadline_us = UINT64_MAX;
        else
            timer->deadline_us += periods * timer->interval_us;
    }
}

int kernel_itimer_real_get(linux_itimerval64_t *value) {
    kernel_itimer_real_t *timer;
    int32_t tgid;
    int status;
    uint64_t now;
    if (!value) return -EDGE_LINUX_EINVAL;
    status = current_thread_group(&tgid);
    if (status < 0) return status;
    kernel_itimer_real_poll();
    timer = real_timer_lookup(tgid);
    now = boottime_monotonic_us();
    real_timer_snapshot(timer, value, now);
    return 0;
}

int kernel_itimer_real_exchange(const linux_itimerval64_t *replacement,
                                linux_itimerval64_t *previous) {
    kernel_itimer_real_t *timer;
    int32_t tgid;
    int status;
    uint64_t initial;
    uint64_t interval;
    uint64_t now;
    if (!replacement || !previous)
        return -EDGE_LINUX_EINVAL;
    status = current_thread_group(&tgid);
    if (status < 0) return status;
    kernel_itimer_real_poll();
    timer = real_timer_lookup(tgid);
    now = boottime_monotonic_us();
    real_timer_snapshot(timer, previous, now);
    initial = (uint64_t)replacement->it_value.tv_sec * 1000000u +
              (uint64_t)replacement->it_value.tv_usec;
    interval = (uint64_t)replacement->it_interval.tv_sec * 1000000u +
               (uint64_t)replacement->it_interval.tv_usec;
    if (!timer && (initial || interval))
        timer = real_timer_allocate(tgid);
    if (!timer) return 0;
    timer->interval_us = interval;
    timer->deadline_us = initial ?
        (initial > UINT64_MAX - now ? UINT64_MAX : now + initial) : 0;
    return 0;
}

void kernel_itimer_real_delete_process(int32_t process_id) {
    kernel_itimer_real_t *timer;
    if (process_id <= 0) return;
    timer = real_timer_lookup(process_id);
    if (!timer) return;
    timer->owner_tgid = 0;
    timer->deadline_us = 0;
    timer->interval_us = 0;
    while (g_real_timer_high_water &&
           !g_real_timers[g_real_timer_high_water - 1u].owner_tgid)
        --g_real_timer_high_water;
}
