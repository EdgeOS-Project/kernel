/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_TIMERFD_RUNTIME_H
#define EDGEOS_KERNEL_TIMERFD_RUNTIME_H

#include <stdint.h>

#define KERNEL_TIMERFD_NONBLOCK 0x00000800u
#define KERNEL_TIMERFD_CLOEXEC  0x00080000u

int kernel_timerfd_create_descriptor(int32_t clock_id, uint32_t flags);
int kernel_timerfd_descriptor_id(int32_t descriptor);
void kernel_timerfd_state_changed(int timer_id);

/* Kernel diagnostic metadata, not a userspace timerfd layout. */
typedef struct kernel_timerfd_probe_state {
    uint64_t generation;
    uint64_t arm_id;
    uint64_t deadline_us;
    int32_t clock_id;
    uint32_t flags;
} kernel_timerfd_probe_state_t;

#define KERNEL_TIMERFD_PROBE_ARM 3u
#define KERNEL_TIMERFD_PROBE_READY 4u
#define KERNEL_TIMERFD_PROBE_READ 5u
int kernel_timerfd_probe_snapshot(int timer_id, kernel_timerfd_probe_state_t *state);

/* Optional observers never change timer state or supply readiness. The ready
 * hook reports first observation of expiry, which can follow a deadline wake. */
void kernel_timerfd_probe_notify(uint32_t kind, int timer_id,
    const kernel_timerfd_probe_state_t *state, int64_t value) __attribute__((weak));
void kernel_wait_probe_timer_source(int32_t tid, int timer_id,
    uint64_t planned_deadline_us) __attribute__((weak));

typedef void (*kernel_timerfd_probe_observer_t)(uint32_t kind, int timer_id,
    const kernel_timerfd_probe_state_t *state, int64_t value);
typedef void (*kernel_wait_probe_observer_t)(int32_t tid, int timer_id,
    const kernel_timerfd_probe_state_t *state, uint64_t planned_deadline_us);
void kernel_timerfd_probe_set_observer(kernel_timerfd_probe_observer_t observer);
void kernel_wait_probe_set_observer(kernel_wait_probe_observer_t observer);

#endif
