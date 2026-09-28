/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral POSIX timer policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include "kernel/linux_errno.h"
#include "kernel/linux_time.h"
#include "kernel/posix_timer_runtime.h"
#include "kernel/signal_queue.h"
#include "kernel/signal_runtime.h"
#include "sys/boottime.h"

#define KERNEL_POSIX_TIMER_MAX 256u
#define KERNEL_POSIX_TIMER_SIGNAL_INFO_SIZE 128u
#define KERNEL_POSIX_TIMER_RETRY_US 1000u

typedef struct kernel_posix_timer {
    uint8_t used;
    uint8_t clock_id;
    uint8_t notify;
    uint8_t signal_queued;
    int32_t user_id;
    int32_t owner_tgid;
    int32_t target_tid;
    int32_t signal;
    int32_t current_overrun;
    int32_t last_overrun;
    uint64_t signal_value;
    uint64_t next_expiry_us;
    uint64_t interval_us;
} kernel_posix_timer_t;

static const kernel_posix_timer_backend_ops_t *g_backend_ops;
static void *g_backend_context;
static kernel_posix_timer_t g_timers[KERNEL_POSIX_TIMER_MAX];
static int32_t g_next_timer_id = 1;

static void bytes_zero(void *buffer, uint32_t length) {
    uint8_t *bytes = buffer;
    while (length--) *bytes++ = 0;
}

int kernel_posix_timer_backend_register(
    const kernel_posix_timer_backend_ops_t *ops, void *context) {
    if (!ops || !ops->current_identity || !ops->thread_group_for_tid ||
        !ops->enqueue_signal)
        return -EDGE_LINUX_EINVAL;
    g_backend_ops = ops;
    g_backend_context = context;
    return 0;
}

static uint64_t posix_timer_now(uint8_t clock_id) {
    return clock_id == LINUX_CLOCK_REALTIME ||
           clock_id == LINUX_CLOCK_REALTIME_ALARM ?
        boottime_realtime_us() : boottime_monotonic_us();
}

static int current_identity(int32_t *tid, int32_t *tgid) {
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    return g_backend_ops->current_identity(
        g_backend_context, tid, tgid);
}

static kernel_posix_timer_t *timer_lookup(int32_t owner_tgid,
                                          int32_t timer_id) {
    uint32_t index;
    for (index = 0; index < KERNEL_POSIX_TIMER_MAX; ++index) {
        kernel_posix_timer_t *timer = &g_timers[index];
        if (timer->used && timer->user_id == timer_id &&
            timer->owner_tgid == owner_tgid)
            return timer;
    }
    return 0;
}

static kernel_posix_timer_t *current_timer(int32_t timer_id) {
    int32_t tid;
    int32_t tgid;
    if (current_identity(&tid, &tgid) < 0) return 0;
    (void)tid;
    return timer_lookup(tgid, timer_id);
}

static int32_t allocate_timer_id(void) {
    int32_t candidate;
    uint32_t attempt;
    for (attempt = 0; attempt < KERNEL_POSIX_TIMER_MAX + 1u; ++attempt) {
        uint32_t index;
        int collision = 0;
        candidate = g_next_timer_id++;
        if (g_next_timer_id <= 0) g_next_timer_id = 1;
        if (candidate <= 0) continue;
        for (index = 0; index < KERNEL_POSIX_TIMER_MAX; ++index) {
            if (g_timers[index].used &&
                g_timers[index].user_id == candidate) {
                collision = 1;
                break;
            }
        }
        if (!collision) return candidate;
    }
    return -1;
}

static void timer_snapshot(const kernel_posix_timer_t *timer,
                           kernel_posix_timer_state_t *state) {
    uint64_t now;
    bytes_zero(state, sizeof(*state));
    state->interval_microseconds = timer->interval_us;
    state->last_overrun = timer->last_overrun;
    if (!timer->next_expiry_us) return;
    now = posix_timer_now(timer->clock_id);
    state->remaining_microseconds = timer->next_expiry_us > now ?
        timer->next_expiry_us - now : 1u;
}

int kernel_posix_timer_create(
    const kernel_posix_timer_create_request_t *request,
    int32_t *timer_id) {
    kernel_posix_timer_t *timer = 0;
    int32_t tid;
    int32_t tgid;
    int32_t allocated_id;
    uint32_t index;

    if (!request || !timer_id ||
        current_identity(&tid, &tgid) < 0)
        return -EDGE_LINUX_EINVAL;
    (void)tid;
    if (request->notify == KERNEL_POSIX_TIMER_SIGEV_THREAD_ID) {
        int32_t target_tgid;
        if (request->target_tid <= 0 ||
            g_backend_ops->thread_group_for_tid(
                g_backend_context, request->target_tid,
                &target_tgid) < 0 ||
            target_tgid != tgid)
            return -EDGE_LINUX_EINVAL;
    }
    for (index = 0; index < KERNEL_POSIX_TIMER_MAX; ++index) {
        if (!g_timers[index].used) {
            timer = &g_timers[index];
            break;
        }
    }
    if (!timer) return -EDGE_LINUX_EAGAIN;
    allocated_id = allocate_timer_id();
    if (allocated_id <= 0) return -EDGE_LINUX_EAGAIN;

    bytes_zero(timer, sizeof(*timer));
    timer->used = 1;
    timer->clock_id = (uint8_t)request->clock_id;
    timer->notify = (uint8_t)request->notify;
    timer->user_id = allocated_id;
    timer->owner_tgid = tgid;
    timer->target_tid = request->target_tid;
    timer->signal = request->signal_number;
    timer->signal_value = request->default_event ?
        (uint32_t)allocated_id : request->signal_value;
    *timer_id = allocated_id;
    return 0;
}

int kernel_posix_timer_get(int32_t timer_id,
                           kernel_posix_timer_state_t *state) {
    kernel_posix_timer_t *timer = current_timer(timer_id);
    if (!timer || !state) return -EDGE_LINUX_EINVAL;
    kernel_posix_timer_poll();
    timer_snapshot(timer, state);
    return 0;
}

int kernel_posix_timer_set(int32_t timer_id,
                           uint64_t initial_microseconds,
                           uint64_t interval_microseconds,
                           int absolute,
                           kernel_posix_timer_state_t *previous) {
    kernel_posix_timer_t *timer = current_timer(timer_id);
    uint64_t now;
    if (!timer) return -EDGE_LINUX_EINVAL;
    kernel_posix_timer_poll();
    if (previous) timer_snapshot(timer, previous);
    timer->interval_us = interval_microseconds;
    timer->current_overrun = 0;
    timer->last_overrun = 0;
    if (!initial_microseconds) {
        timer->next_expiry_us = 0;
        return 0;
    }
    now = posix_timer_now(timer->clock_id);
    timer->next_expiry_us = absolute ? initial_microseconds :
        (initial_microseconds > UINT64_MAX - now ?
         UINT64_MAX : now + initial_microseconds);
    return 0;
}

int kernel_posix_timer_get_overrun(int32_t timer_id) {
    kernel_posix_timer_t *timer = current_timer(timer_id);
    return timer ? timer->last_overrun : -EDGE_LINUX_EINVAL;
}

int kernel_posix_timer_delete(int32_t timer_id) {
    kernel_posix_timer_t *timer = current_timer(timer_id);
    if (!timer) return -EDGE_LINUX_EINVAL;
    bytes_zero(timer, sizeof(*timer));
    return 0;
}

void kernel_posix_timer_delete_process(int32_t process_id) {
    uint32_t index;
    if (process_id <= 0) return;
    for (index = 0; index < KERNEL_POSIX_TIMER_MAX; ++index) {
        if (g_timers[index].used &&
            g_timers[index].owner_tgid == process_id)
            bytes_zero(&g_timers[index], sizeof(g_timers[index]));
    }
}

void kernel_posix_timer_signal_consumed(int32_t timer_id, int32_t overrun) {
    uint32_t index;
    for (index = 0; index < KERNEL_POSIX_TIMER_MAX; ++index) {
        kernel_posix_timer_t *timer = &g_timers[index];
        if (!timer->used || timer->user_id != timer_id) continue;
        timer->last_overrun = overrun;
        timer->current_overrun = 0;
        timer->signal_queued = 0;
        return;
    }
}

void kernel_posix_timer_poll(void) {
    uint32_t index;
    if (!g_backend_ops) return;
    for (index = 0; index < KERNEL_POSIX_TIMER_MAX; ++index) {
        kernel_posix_timer_t *timer = &g_timers[index];
        uint64_t now;
        uint64_t expirations;
        uint64_t elapsed;
        if (!timer->used || !timer->next_expiry_us) continue;
        now = posix_timer_now(timer->clock_id);
        if (now < timer->next_expiry_us) continue;
        elapsed = now - timer->next_expiry_us;
        expirations = timer->interval_us ?
            1u + elapsed / timer->interval_us : 1u;
        if (timer->interval_us) {
            if (expirations >
                (UINT64_MAX - timer->next_expiry_us) / timer->interval_us)
                timer->next_expiry_us = UINT64_MAX;
            else
                timer->next_expiry_us +=
                    expirations * timer->interval_us;
        } else {
            timer->next_expiry_us = 0;
        }
        if (timer->notify == KERNEL_POSIX_TIMER_SIGEV_NONE) continue;
        if (timer->signal_queued) {
            uint64_t total =
                (uint64_t)(uint32_t)timer->current_overrun + expirations;
            timer->current_overrun = total > INT32_MAX ?
                INT32_MAX : (int32_t)total;
            (void)kernel_signal_queue_update_timer_overrun(
                timer->user_id, timer->current_overrun);
            continue;
        }
        {
            uint8_t information[KERNEL_POSIX_TIMER_SIGNAL_INFO_SIZE];
            int directed =
                timer->notify == KERNEL_POSIX_TIMER_SIGEV_THREAD_ID;
            int32_t target = directed ?
                timer->target_tid : timer->owner_tgid;
            int result;
            timer->current_overrun =
                expirations > (uint64_t)INT32_MAX + 1u ?
                INT32_MAX : (int32_t)(expirations - 1u);
            kernel_signal_info_build_timer(
                information, (uint32_t)timer->signal, timer->user_id,
                timer->current_overrun, timer->signal_value);
            result = g_backend_ops->enqueue_signal(
                g_backend_context, target, (uint32_t)timer->signal,
                directed, information);
            if (result < 0) {
                if (!timer->next_expiry_us)
                    timer->next_expiry_us =
                        now + KERNEL_POSIX_TIMER_RETRY_US;
                continue;
            }
            timer->signal_queued = 1;
        }
    }
}
