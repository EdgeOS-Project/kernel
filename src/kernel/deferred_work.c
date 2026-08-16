/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-independent deferred-work cadence.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/deferred_work.h"

static volatile uint32_t g_deferred_work_requested;
static volatile uint32_t g_deferred_work_tick_count;
static volatile uint32_t g_display_work_requested;
static volatile uint32_t g_input_work_requested;

void kernel_deferred_work_request(void) {
    __atomic_store_n(&g_deferred_work_requested, 1u, __ATOMIC_RELEASE);
}

int kernel_deferred_work_pending(void) {
    return __atomic_load_n(&g_deferred_work_requested,
                           __ATOMIC_ACQUIRE) != 0u;
}

int kernel_deferred_work_take(void) {
    return __atomic_exchange_n(&g_deferred_work_requested, 0u,
                               __ATOMIC_ACQ_REL) != 0u;
}

int kernel_deferred_work_tick(uint32_t interval_ticks) {
    uint32_t current;
    uint32_t next;
    int due;

    if (!interval_ticks) interval_ticks = 1u;
    current = __atomic_load_n(&g_deferred_work_tick_count,
                              __ATOMIC_RELAXED);
    for (;;) {
        due = current >= interval_ticks - 1u;
        next = due ? 0u : current + 1u;
        if (__atomic_compare_exchange_n(&g_deferred_work_tick_count,
                                        &current, next, 0,
                                        __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            break;
    }
    if (due) kernel_deferred_work_request();
    return due;
}

void kernel_display_work_request(void) {
    __atomic_store_n(&g_display_work_requested, 1u, __ATOMIC_RELEASE);
}

int kernel_display_work_pending(void) {
    return __atomic_load_n(&g_display_work_requested,
                           __ATOMIC_ACQUIRE) != 0u;
}

int kernel_display_work_take(void) {
    return __atomic_exchange_n(&g_display_work_requested, 0u,
                               __ATOMIC_ACQ_REL) != 0u;
}

void kernel_input_work_request(void) {
    __atomic_store_n(&g_input_work_requested, 1u, __ATOMIC_RELEASE);
}

int kernel_input_work_pending(void) {
    return __atomic_load_n(&g_input_work_requested,
                           __ATOMIC_ACQUIRE) != 0u;
}

int kernel_input_work_take(void) {
    return __atomic_exchange_n(&g_input_work_requested, 0u,
                               __ATOMIC_ACQ_REL) != 0u;
}

int kernel_deferred_work_service_pending(uint32_t cpu_id) {
    return kernel_input_work_pending() ||
           kernel_display_work_pending() ||
           (cpu_id == 0u && kernel_deferred_work_pending());
}

uint32_t kernel_deferred_work_take_ready(void) {
    uint32_t ready = 0u;

    if (kernel_input_work_take())
        ready |= KERNEL_DEFERRED_WORK_INPUT;
    if (kernel_display_work_take())
        ready |= KERNEL_DEFERRED_WORK_DISPLAY;
    if (kernel_deferred_work_take())
        ready |= KERNEL_DEFERRED_WORK_GENERAL;
    return ready;
}
