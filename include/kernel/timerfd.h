/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_TIMERFD_H
#define EDGEOS_KERNEL_TIMERFD_H

#include <stdint.h>

#include "kernel/linux_time.h"

#define KERNEL_TIMERFD_TIMER_ABSTIME      0x00000001u
#define KERNEL_TIMERFD_TIMER_CANCEL_ON_SET 0x00000002u

typedef struct kernel_timerfd_state {
    int32_t clock_id;
    uint32_t references;
    uint64_t next_expiry_us;
    uint64_t interval_us;
    uint64_t expirations;
    uint64_t readiness_sequence;
    uint8_t cancel_on_set;
    uint8_t canceled;
    uint8_t deadline_is_monotonic;
} kernel_timerfd_state_t;

typedef int (*kernel_timerfd_copy_value_fn)(void *context, uint64_t value);

int kernel_timerfd_clock_supported(int32_t clock_id);
int kernel_timerfd_create(int32_t clock_id);
int kernel_timerfd_retain(int timer_id);
void kernel_timerfd_release(int timer_id);
int kernel_timerfd_query(int timer_id, kernel_timerfd_state_t *state);
int kernel_timerfd_gettime(int timer_id, linux_itimerspec64_t *current);
int kernel_timerfd_settime(int timer_id, uint32_t flags,
                           const linux_itimerspec64_t *replacement,
                           linux_itimerspec64_t *previous);
int kernel_timerfd_update(int timer_id);
int kernel_timerfd_read(int timer_id,
                        kernel_timerfd_copy_value_fn copy_value,
                        void *copy_context, uint64_t *expirations);
int kernel_timerfd_monotonic_deadline(
    const kernel_timerfd_state_t *state, uint64_t *deadline_us);
void kernel_timerfd_realtime_change_begin(void);
void kernel_timerfd_realtime_change_complete(void);

#endif
