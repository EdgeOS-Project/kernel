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
static volatile uint64_t g_display_work_deadline_us;
static volatile uint32_t g_input_work_requested;

__attribute__((weak)) void kernel_arch_display_deadline_request(
    uint64_t deadline_us) {
    (void)deadline_us;
}

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

void kernel_display_deadline_request(uint64_t deadline_us) {
    uint64_t current;

    if (!deadline_us) return;
    current = __atomic_load_n(&g_display_work_deadline_us,
                              __ATOMIC_ACQUIRE);
    while ((!current || deadline_us < current) &&
           !__atomic_compare_exchange_n(
               &g_display_work_deadline_us, &current, deadline_us, 0,
               __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    }
    if (!current || deadline_us < current)
        kernel_arch_display_deadline_request(deadline_us);
}

uint64_t kernel_display_deadline(void) {
    return __atomic_load_n(&g_display_work_deadline_us,
                           __ATOMIC_ACQUIRE);
}

int kernel_display_deadline_poll(uint64_t now_us) {
    uint64_t deadline = __atomic_load_n(
        &g_display_work_deadline_us, __ATOMIC_ACQUIRE);

    while (deadline && now_us >= deadline) {
        if (__atomic_compare_exchange_n(
                &g_display_work_deadline_us, &deadline, 0u, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            kernel_display_work_request();
            return 1;
        }
    }
    return 0;
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
