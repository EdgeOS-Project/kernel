/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral boot and realtime clock policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/boottime_arch.h"
#include "kernel/linux_vdso.h"
#include "kernel/timerfd.h"
#include "sys/boottime.h"

#ifdef CONFIG_BSD_DRIVER_BRIDGE
void bsd_compat_time_tick(uint64_t monotonic_microseconds);
#endif

enum {
    BOOTTIME_UNINITIALIZED = 0,
    BOOTTIME_INITIALIZING = 1,
    BOOTTIME_READY = 2,
};

static volatile uint32_t g_boottime_state;
static volatile uint64_t g_realtime_base_us;
static volatile uint64_t g_last_monotonic_us;

static void boottime_publish_vdso(void) {
    uint64_t cycle_last = 0;
    uint64_t monotonic_base_us = 0;
    uint64_t frequency = 0;

    kernel_arch_boottime_vdso_snapshot(
        &cycle_last, &monotonic_base_us, &frequency);
    linux_vdso_time_update(
        cycle_last, monotonic_base_us,
        __atomic_load_n(&g_realtime_base_us, __ATOMIC_ACQUIRE), frequency);
}

static uint64_t boottime_saturating_add(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

void boottime_init(void) {
    uint32_t expected = BOOTTIME_UNINITIALIZED;

    if (__atomic_compare_exchange_n(
            &g_boottime_state, &expected, BOOTTIME_INITIALIZING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        uint64_t realtime_base = kernel_arch_boottime_initialize();

        __atomic_store_n(&g_realtime_base_us, realtime_base,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&g_last_monotonic_us, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&g_boottime_state, BOOTTIME_READY,
                         __ATOMIC_RELEASE);
        boottime_publish_vdso();
        return;
    }

    while (__atomic_load_n(&g_boottime_state, __ATOMIC_ACQUIRE) !=
           BOOTTIME_READY) {
        __asm__ __volatile__("" ::: "memory");
    }
}

static void boottime_ensure_initialized(void) {
    if (__atomic_load_n(&g_boottime_state, __ATOMIC_ACQUIRE) !=
        BOOTTIME_READY)
        boottime_init();
}

void boottime_timer_tick(uint32_t hz) {
    boottime_ensure_initialized();
    kernel_arch_boottime_timer_tick(hz);
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    bsd_compat_time_tick(boottime_monotonic_us());
#endif
}

int boottime_refine_tsc(uint64_t hz) {
    uint64_t floor_us = boottime_monotonic_us();
    int result = kernel_arch_boottime_refine(hz, floor_us);

    if (result == 0) boottime_publish_vdso();
    return result;
}

uint64_t boottime_clocksource_hz(void) {
    boottime_ensure_initialized();
    return kernel_arch_boottime_source_hz();
}

const char *boottime_clocksource_name(void) {
    boottime_ensure_initialized();
    return kernel_arch_boottime_source_name();
}

uint64_t boottime_monotonic_us(void) {
    uint64_t previous;
    uint64_t current;

    boottime_ensure_initialized();
    current = kernel_arch_boottime_monotonic_us();
    previous = __atomic_load_n(&g_last_monotonic_us, __ATOMIC_ACQUIRE);
    for (;;) {
        if (current <= previous) return previous;
        if (__atomic_compare_exchange_n(
                &g_last_monotonic_us, &previous, current, 0,
                __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
            return current;
    }
}

uint64_t boottime_realtime_us(void) {
    uint64_t realtime_base;
    uint64_t monotonic;

    monotonic = boottime_monotonic_us();
    realtime_base = __atomic_load_n(&g_realtime_base_us, __ATOMIC_ACQUIRE);
    return boottime_saturating_add(realtime_base, monotonic);
}

int boottime_set_realtime_us(uint64_t realtime_us) {
    uint64_t monotonic = boottime_monotonic_us();

    if (realtime_us < monotonic) return -1;
    /*
     * Serialize the visible clock step with realtime timerfd arming.  This
     * prevents a CANCEL_ON_SET timer armed after the step from being canceled
     * as though it had existed before the step.
     */
    kernel_timerfd_realtime_change_begin();
    __atomic_store_n(&g_realtime_base_us, realtime_us - monotonic,
                     __ATOMIC_RELEASE);
    boottime_publish_vdso();
    kernel_timerfd_realtime_change_complete();
    return 0;
}

uint32_t boottime_now_us(void) {
    return (uint32_t)boottime_monotonic_us();
}
