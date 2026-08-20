/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Architecture-independent Linux timerfd state and expiration semantics.
 * Descriptor tables and task wake queues remain runtime-specific mechanisms.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
#include "kernel/timerfd.h"
#include "kernel/timerfd_runtime.h"
#include "string.h"
#include "sys/boottime.h"

typedef struct kernel_timerfd_object {
    uint8_t used;
    uint8_t cancel_on_set;
    uint8_t canceled;
    uint8_t deadline_is_monotonic;
    int32_t clock_id;
    uint32_t references;
    uint64_t next_expiry_us;
    uint64_t interval_us;
    uint64_t expirations;
    uint64_t readiness_sequence;
} kernel_timerfd_object_t;

static kernel_timerfd_object_t
    g_timerfds[EDGE_RUNTIME_MAX_TIMERFDS];
static volatile uint32_t g_timerfd_lock;

static void kernel_timerfd_lock(void) {
    while (__sync_lock_test_and_set(&g_timerfd_lock, 1u)) { }
}

static void kernel_timerfd_unlock(void) {
    __sync_lock_release(&g_timerfd_lock);
}

static void kernel_timerfd_sequence_advance(
    kernel_timerfd_object_t *timer) {
    if (!timer) return;
    ++timer->readiness_sequence;
    if (!timer->readiness_sequence) timer->readiness_sequence = 1u;
}

int kernel_timerfd_clock_supported(int32_t clock_id) {
    return clock_id == LINUX_CLOCK_REALTIME ||
           clock_id == LINUX_CLOCK_MONOTONIC ||
           clock_id == LINUX_CLOCK_BOOTTIME ||
           clock_id == LINUX_CLOCK_REALTIME_ALARM ||
           clock_id == LINUX_CLOCK_BOOTTIME_ALARM;
}

static uint64_t kernel_timerfd_clock_now_us(int32_t clock_id) {
    if (clock_id == LINUX_CLOCK_REALTIME ||
        clock_id == LINUX_CLOCK_REALTIME_ALARM)
        return boottime_realtime_us();
    return boottime_monotonic_us();
}

static uint64_t kernel_timerfd_now_us(
    const kernel_timerfd_object_t *timer) {
    if (timer && timer->deadline_is_monotonic)
        return boottime_monotonic_us();
    return timer ? kernel_timerfd_clock_now_us(timer->clock_id) : 0;
}

static kernel_timerfd_object_t *kernel_timerfd_lookup_locked(int timer_id) {
    if (timer_id < 0 || timer_id >= EDGE_RUNTIME_MAX_TIMERFDS ||
        !g_timerfds[timer_id].used)
        return 0;
    return &g_timerfds[timer_id];
}

static int kernel_timerfd_timespec_to_us(
    const linux_timespec64_t *value, uint64_t *usec,
    int saturate_overflow) {
    uint64_t seconds;
    uint64_t subsecond;
    if (!value || !usec || value->tv_sec < 0 || value->tv_nsec < 0 ||
        value->tv_nsec >= 1000000000LL)
        return -EDGE_LINUX_EINVAL;
    seconds = (uint64_t)value->tv_sec;
    subsecond = ((uint64_t)value->tv_nsec + 999u) / 1000u;
    if (seconds > (UINT64_MAX - subsecond) / 1000000u) {
        if (!saturate_overflow) return -EDGE_LINUX_EINVAL;
        *usec = UINT64_MAX;
        return 0;
    }
    *usec = seconds * 1000000u + subsecond;
    return 0;
}

static void kernel_timerfd_us_to_timespec(
    uint64_t usec, linux_timespec64_t *value) {
    if (!value) return;
    value->tv_sec = (int64_t)(usec / 1000000u);
    value->tv_nsec = (int64_t)((usec % 1000000u) * 1000u);
}

static int kernel_timerfd_update_locked(kernel_timerfd_object_t *timer) {
    uint64_t count;
    uint64_t elapsed;
    uint64_t now;
    uint64_t previous_expirations;
    if (!timer || !timer->next_expiry_us || timer->canceled) return 0;
    now = kernel_timerfd_now_us(timer);
    if (now < timer->next_expiry_us) return 0;
    previous_expirations = timer->expirations;
    elapsed = now - timer->next_expiry_us;
    count = timer->interval_us ? 1u + elapsed / timer->interval_us : 1u;
    if (timer->expirations > UINT64_MAX - count)
        timer->expirations = UINT64_MAX;
    else
        timer->expirations += count;
    if (!timer->interval_us) {
        timer->next_expiry_us = 0;
    } else if (count >
               (UINT64_MAX - timer->next_expiry_us) / timer->interval_us) {
        timer->next_expiry_us = UINT64_MAX;
    } else {
        timer->next_expiry_us += count * timer->interval_us;
    }
    if (timer->expirations != previous_expirations)
        kernel_timerfd_sequence_advance(timer);
    return 1;
}

static void kernel_timerfd_current_locked(
    kernel_timerfd_object_t *timer, linux_itimerspec64_t *current) {
    uint64_t remaining = 0;
    uint64_t now;
    memset(current, 0, sizeof(*current));
    kernel_timerfd_update_locked(timer);
    now = kernel_timerfd_now_us(timer);
    if (timer->next_expiry_us > now)
        remaining = timer->next_expiry_us - now;
    kernel_timerfd_us_to_timespec(timer->interval_us,
                                  &current->it_interval);
    kernel_timerfd_us_to_timespec(remaining, &current->it_value);
}

int kernel_timerfd_create(int32_t clock_id) {
    int result = -EDGE_LINUX_ENFILE;
    if (!kernel_timerfd_clock_supported(clock_id))
        return -EDGE_LINUX_EINVAL;
    kernel_timerfd_lock();
    for (int timer_id = 0; timer_id < EDGE_RUNTIME_MAX_TIMERFDS;
         ++timer_id) {
        kernel_timerfd_object_t *timer = &g_timerfds[timer_id];
        if (timer->used) continue;
        memset(timer, 0, sizeof(*timer));
        timer->used = 1;
        timer->clock_id = clock_id;
        timer->references = 1u;
        timer->readiness_sequence = 1u;
        result = timer_id;
        break;
    }
    kernel_timerfd_unlock();
    return result;
}

int kernel_timerfd_retain(int timer_id) {
    kernel_timerfd_object_t *timer;
    int result = 0;
    kernel_timerfd_lock();
    timer = kernel_timerfd_lookup_locked(timer_id);
    if (!timer) result = -EDGE_LINUX_EBADF;
    else if (timer->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else ++timer->references;
    kernel_timerfd_unlock();
    return result;
}

void kernel_timerfd_release(int timer_id) {
    kernel_timerfd_object_t *timer;
    kernel_timerfd_lock();
    timer = kernel_timerfd_lookup_locked(timer_id);
    if (timer && timer->references && --timer->references == 0u)
        memset(timer, 0, sizeof(*timer));
    kernel_timerfd_unlock();
}

int kernel_timerfd_query(int timer_id, kernel_timerfd_state_t *state) {
    kernel_timerfd_object_t *timer;
    int result = 0;
    if (!state) return -EDGE_LINUX_EINVAL;
    kernel_timerfd_lock();
    timer = kernel_timerfd_lookup_locked(timer_id);
    if (!timer) {
        result = -EDGE_LINUX_EBADF;
    } else {
        kernel_timerfd_update_locked(timer);
        state->clock_id = timer->clock_id;
        state->references = timer->references;
        state->next_expiry_us = timer->next_expiry_us;
        state->interval_us = timer->interval_us;
        state->expirations = timer->expirations;
        state->readiness_sequence = timer->readiness_sequence;
        state->cancel_on_set = timer->cancel_on_set;
        state->canceled = timer->canceled;
        state->deadline_is_monotonic = timer->deadline_is_monotonic;
    }
    kernel_timerfd_unlock();
    return result;
}

int kernel_timerfd_gettime(int timer_id, linux_itimerspec64_t *current) {
    kernel_timerfd_object_t *timer;
    int result = 0;
    if (!current) return -EDGE_LINUX_EINVAL;
    kernel_timerfd_lock();
    timer = kernel_timerfd_lookup_locked(timer_id);
    if (!timer) result = -EDGE_LINUX_EBADF;
    else kernel_timerfd_current_locked(timer, current);
    kernel_timerfd_unlock();
    return result;
}

int kernel_timerfd_settime(int timer_id, uint32_t flags,
                           const linux_itimerspec64_t *replacement,
                           linux_itimerspec64_t *previous) {
    kernel_timerfd_object_t *timer;
    uint64_t first;
    uint64_t interval;
    uint64_t now;
    uint64_t next_expiry = 0;
    uint64_t old_expirations;
    uint64_t sequence_before_replacement;
    uint8_t old_canceled;
    int result;
    if (!replacement) return -EDGE_LINUX_EFAULT;
    if (flags & ~(KERNEL_TIMERFD_TIMER_ABSTIME |
                  KERNEL_TIMERFD_TIMER_CANCEL_ON_SET))
        return -EDGE_LINUX_EINVAL;
    result = kernel_timerfd_timespec_to_us(
        &replacement->it_value, &first,
        (flags & KERNEL_TIMERFD_TIMER_ABSTIME) != 0);
    if (result < 0) return result;
    result = kernel_timerfd_timespec_to_us(&replacement->it_interval,
                                           &interval, 0);
    if (result < 0) return result;

    kernel_timerfd_lock();
    timer = kernel_timerfd_lookup_locked(timer_id);
    if (!timer) {
        result = -EDGE_LINUX_EBADF;
    } else {
        if (first && !(flags & KERNEL_TIMERFD_TIMER_ABSTIME)) {
            now = boottime_monotonic_us();
            if (first > UINT64_MAX - now)
                result = -EDGE_LINUX_EINVAL;
            else
                next_expiry = now + first;
        } else {
            next_expiry = first;
        }
        if (!result) {
            kernel_timerfd_update_locked(timer);
            if (previous) kernel_timerfd_current_locked(timer, previous);
            old_expirations = timer->expirations;
            old_canceled = timer->canceled;
            sequence_before_replacement = timer->readiness_sequence;
            timer->interval_us = interval;
            timer->expirations = 0;
            timer->canceled = 0;
            timer->deadline_is_monotonic =
                first && !(flags & KERNEL_TIMERFD_TIMER_ABSTIME);
            timer->cancel_on_set =
                (flags & KERNEL_TIMERFD_TIMER_ABSTIME) &&
                (flags & KERNEL_TIMERFD_TIMER_CANCEL_ON_SET) &&
                (timer->clock_id == LINUX_CLOCK_REALTIME ||
                 timer->clock_id == LINUX_CLOCK_REALTIME_ALARM);
            timer->next_expiry_us = next_expiry;
            kernel_timerfd_update_locked(timer);
            if (timer->readiness_sequence == sequence_before_replacement &&
                (timer->expirations != old_expirations ||
                 timer->canceled != old_canceled))
                kernel_timerfd_sequence_advance(timer);
        }
    }
    kernel_timerfd_unlock();
    return result;
}

int kernel_timerfd_update(int timer_id) {
    kernel_timerfd_object_t *timer;
    int result;
    kernel_timerfd_lock();
    timer = kernel_timerfd_lookup_locked(timer_id);
    result = timer ? kernel_timerfd_update_locked(timer) :
                     -EDGE_LINUX_EBADF;
    kernel_timerfd_unlock();
    return result;
}

int kernel_timerfd_read(int timer_id,
                        kernel_timerfd_copy_value_fn copy_value,
                        void *copy_context, uint64_t *expirations) {
    kernel_timerfd_object_t *timer;
    uint64_t value = 0;
    int result = 0;
    kernel_timerfd_lock();
    timer = kernel_timerfd_lookup_locked(timer_id);
    if (!timer) {
        result = -EDGE_LINUX_EBADF;
    } else {
        kernel_timerfd_update_locked(timer);
        if (timer->canceled) {
            timer->canceled = 0;
            result = -EDGE_LINUX_ECANCELED;
        } else if (!timer->expirations) {
            result = -EDGE_LINUX_EAGAIN;
        } else {
            value = timer->expirations;
            timer->expirations = 0;
            if (expirations) *expirations = value;
        }
    }
    kernel_timerfd_unlock();
    /* Linux commits the expiration read before copy_to_user can fail. */
    if (!result && copy_value && copy_value(copy_context, value) < 0)
        result = -EDGE_LINUX_EFAULT;
    return result;
}

int kernel_timerfd_monotonic_deadline(
        const kernel_timerfd_state_t *state, uint64_t *deadline_us) {
    uint64_t clock_now;
    uint64_t monotonic_now;
    uint64_t remaining;

    if (!state || !deadline_us) return -EDGE_LINUX_EINVAL;
    *deadline_us = 0;
    if (!state->next_expiry_us) return 0;

    monotonic_now = boottime_monotonic_us();
    if (state->deadline_is_monotonic) {
        clock_now = monotonic_now;
    } else {
        switch (state->clock_id) {
            case LINUX_CLOCK_REALTIME:
            case LINUX_CLOCK_REALTIME_ALARM:
                clock_now = boottime_realtime_us();
                break;
            case LINUX_CLOCK_MONOTONIC:
            case LINUX_CLOCK_BOOTTIME:
            case LINUX_CLOCK_BOOTTIME_ALARM:
                clock_now = monotonic_now;
                break;
            default:
                return -EDGE_LINUX_EINVAL;
        }
    }
    if (state->next_expiry_us <= clock_now) {
        *deadline_us = monotonic_now ? monotonic_now : 1u;
        return 0;
    }
    remaining = state->next_expiry_us - clock_now;
    *deadline_us = remaining > UINT64_MAX - monotonic_now ?
                   UINT64_MAX : monotonic_now + remaining;
    return 0;
}

void kernel_timerfd_realtime_change_begin(void) {
    kernel_timerfd_lock();
}

static void kernel_timerfd_realtime_change_notify(int cancel_absolute) {
    uint8_t notify[EDGE_RUNTIME_MAX_TIMERFDS] = {0};

    for (int timer_id = 0; timer_id < EDGE_RUNTIME_MAX_TIMERFDS;
         ++timer_id) {
        kernel_timerfd_object_t *timer = &g_timerfds[timer_id];
        if (!timer->used ||
            (timer->clock_id != LINUX_CLOCK_REALTIME &&
             timer->clock_id != LINUX_CLOCK_REALTIME_ALARM) ||
            timer->deadline_is_monotonic ||
            !timer->next_expiry_us)
            continue;
        notify[timer_id] = 1;
        if (cancel_absolute && timer->cancel_on_set) {
            timer->next_expiry_us = 0;
            timer->expirations = 0;
            timer->canceled = 1;
            kernel_timerfd_sequence_advance(timer);
        }
    }
    kernel_timerfd_unlock();

    /*
     * Notifications run without the timerfd lock because backends query the
     * object and may enter scheduler paths.  Non-canceling realtime timers
     * also need this wakeup so blocked waits recompute absolute deadlines.
     */
    for (int timer_id = 0; timer_id < EDGE_RUNTIME_MAX_TIMERFDS;
         ++timer_id) {
        if (notify[timer_id]) kernel_timerfd_state_changed(timer_id);
    }
}

void kernel_timerfd_realtime_change_complete(void) {
    kernel_timerfd_realtime_change_notify(1);
}

void kernel_timerfd_realtime_rate_change(void) {
    kernel_timerfd_lock();
    kernel_timerfd_realtime_change_notify(0);
}
