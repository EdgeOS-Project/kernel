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
#include "sys/spinlock.h"

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
static volatile uint32_t g_realtime_sequence;
static volatile uint64_t g_discipline_anchor_us;
static volatile int64_t g_frequency_scaled_ppm;
static volatile int64_t g_pending_adjustment_us;
static spinlock_t g_realtime_write_lock;

#define BOOTTIME_SCALED_PPM_DENOMINATOR 65536000000ll
#define BOOTTIME_SLEW_DIVISOR 2000u

static uint64_t boottime_saturating_add(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static uint64_t boottime_negative_magnitude(int64_t value) {
    return (uint64_t)(-(value + 1)) + 1u;
}

static int64_t boottime_frequency_correction(
    uint64_t elapsed_us, int64_t scaled_ppm) {
    int64_t seconds = (int64_t)(elapsed_us / 1000000u);
    int64_t remainder = (int64_t)(elapsed_us % 1000000u);
    int64_t whole = (seconds * scaled_ppm) / 65536ll;
    int64_t fraction =
        (remainder * scaled_ppm) / BOOTTIME_SCALED_PPM_DENOMINATOR;
    return whole + fraction;
}

static int64_t boottime_slew_correction(
    uint64_t elapsed_us, int64_t pending_adjustment_us) {
    int64_t limit;

    if (!pending_adjustment_us) return 0;
    limit = (int64_t)(elapsed_us / BOOTTIME_SLEW_DIVISOR);
    if (!limit && elapsed_us) limit = 1;
    if (pending_adjustment_us > 0)
        return pending_adjustment_us < limit ?
            pending_adjustment_us : limit;
    return boottime_negative_magnitude(pending_adjustment_us) <
            (uint64_t)limit ?
        pending_adjustment_us : -limit;
}

static uint64_t boottime_apply_signed(uint64_t value, int64_t adjustment) {
    if (adjustment >= 0)
        return boottime_saturating_add(value, (uint64_t)adjustment);
    return boottime_negative_magnitude(adjustment) < value ?
        value - boottime_negative_magnitude(adjustment) : 0;
}

static void boottime_publish_vdso(void) {
    uint64_t cycle_last = 0;
    uint64_t monotonic_base_us = 0;
    uint64_t frequency = 0;

    kernel_arch_boottime_vdso_snapshot(
        &cycle_last, &monotonic_base_us, &frequency);
    linux_vdso_time_update(
        cycle_last, monotonic_base_us,
        __atomic_load_n(&g_realtime_base_us, __ATOMIC_ACQUIRE), frequency,
        __atomic_load_n(&g_discipline_anchor_us, __ATOMIC_ACQUIRE),
        __atomic_load_n(&g_frequency_scaled_ppm, __ATOMIC_ACQUIRE),
        __atomic_load_n(&g_pending_adjustment_us, __ATOMIC_ACQUIRE));
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
        __atomic_store_n(&g_discipline_anchor_us, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&g_frequency_scaled_ppm, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&g_pending_adjustment_us, 0, __ATOMIC_RELEASE);
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
    uint64_t anchor;
    int64_t frequency;
    int64_t pending;
    int64_t correction;
    uint32_t before;
    uint32_t after;

    monotonic = boottime_monotonic_us();
    do {
        before = __atomic_load_n(&g_realtime_sequence, __ATOMIC_ACQUIRE);
        if (before & 1u) continue;
        realtime_base =
            __atomic_load_n(&g_realtime_base_us, __ATOMIC_RELAXED);
        anchor = __atomic_load_n(
            &g_discipline_anchor_us, __ATOMIC_RELAXED);
        frequency = __atomic_load_n(
            &g_frequency_scaled_ppm, __ATOMIC_RELAXED);
        pending = __atomic_load_n(
            &g_pending_adjustment_us, __ATOMIC_RELAXED);
        after = __atomic_load_n(&g_realtime_sequence, __ATOMIC_ACQUIRE);
    } while (before != after || (after & 1u));
    correction = boottime_frequency_correction(
        monotonic > anchor ? monotonic - anchor : 0, frequency);
    correction += boottime_slew_correction(
        monotonic > anchor ? monotonic - anchor : 0, pending);
    return boottime_apply_signed(
        boottime_saturating_add(realtime_base, monotonic), correction);
}

static void boottime_realtime_write_begin(void) {
    uint32_t sequence =
        __atomic_load_n(&g_realtime_sequence, __ATOMIC_RELAXED) & ~1u;
    __atomic_store_n(
        &g_realtime_sequence, sequence + 1u, __ATOMIC_RELEASE);
}

static void boottime_realtime_write_end(void) {
    uint32_t sequence =
        __atomic_load_n(&g_realtime_sequence, __ATOMIC_RELAXED) | 1u;
    __atomic_store_n(
        &g_realtime_sequence, sequence + 1u, __ATOMIC_RELEASE);
}

static void boottime_collapse_discipline_locked(uint64_t monotonic) {
    uint64_t anchor = g_discipline_anchor_us;
    uint64_t elapsed = monotonic > anchor ? monotonic - anchor : 0;
    int64_t frequency = g_frequency_scaled_ppm;
    int64_t pending = g_pending_adjustment_us;
    int64_t frequency_correction =
        boottime_frequency_correction(elapsed, frequency);
    int64_t slew_correction = boottime_slew_correction(elapsed, pending);
    uint64_t realtime = boottime_apply_signed(
        boottime_saturating_add(g_realtime_base_us, monotonic),
        frequency_correction + slew_correction);

    g_realtime_base_us = realtime > monotonic ? realtime - monotonic : 0;
    g_discipline_anchor_us = monotonic;
    g_pending_adjustment_us = pending - slew_correction;
}

int boottime_set_realtime_us(uint64_t realtime_us) {
    uint64_t monotonic = boottime_monotonic_us();
    uint64_t lock_flags;

    if (realtime_us < monotonic) return -1;
    /*
     * Serialize the visible clock step with realtime timerfd arming.  This
     * prevents a CANCEL_ON_SET timer armed after the step from being canceled
     * as though it had existed before the step.
     */
    kernel_timerfd_realtime_change_begin();
    lock_flags = spin_lock_irqsave(&g_realtime_write_lock);
    boottime_realtime_write_begin();
    g_realtime_base_us = realtime_us - monotonic;
    g_discipline_anchor_us = monotonic;
    g_pending_adjustment_us = 0;
    boottime_realtime_write_end();
    spin_unlock_irqrestore(&g_realtime_write_lock, lock_flags);
    boottime_publish_vdso();
    kernel_timerfd_realtime_change_complete();
    return 0;
}

int boottime_adjust_realtime_us(int64_t adjustment_us, int immediate) {
    uint64_t monotonic = boottime_monotonic_us();
    uint64_t lock_flags;
    uint64_t current;

    if (immediate) kernel_timerfd_realtime_change_begin();
    lock_flags = spin_lock_irqsave(&g_realtime_write_lock);
    boottime_realtime_write_begin();
    boottime_collapse_discipline_locked(monotonic);
    if (immediate) {
        current = boottime_saturating_add(g_realtime_base_us, monotonic);
        current = boottime_apply_signed(current, adjustment_us);
        if (current < monotonic) {
            boottime_realtime_write_end();
            spin_unlock_irqrestore(&g_realtime_write_lock, lock_flags);
            if (immediate) kernel_timerfd_realtime_change_complete();
            return -1;
        }
        g_realtime_base_us = current - monotonic;
    } else if ((adjustment_us > 0 &&
                g_pending_adjustment_us > INT64_MAX - adjustment_us) ||
               (adjustment_us < 0 &&
                g_pending_adjustment_us < INT64_MIN - adjustment_us)) {
        boottime_realtime_write_end();
        spin_unlock_irqrestore(&g_realtime_write_lock, lock_flags);
        if (immediate) kernel_timerfd_realtime_change_complete();
        return -1;
    } else {
        g_pending_adjustment_us += adjustment_us;
    }
    boottime_realtime_write_end();
    spin_unlock_irqrestore(&g_realtime_write_lock, lock_flags);
    boottime_publish_vdso();
    if (immediate)
        kernel_timerfd_realtime_change_complete();
    else
        kernel_timerfd_realtime_rate_change();
    return 0;
}

int boottime_set_pending_adjustment_us(int64_t adjustment_us) {
    uint64_t monotonic = boottime_monotonic_us();
    uint64_t lock_flags;

    lock_flags = spin_lock_irqsave(&g_realtime_write_lock);
    boottime_realtime_write_begin();
    boottime_collapse_discipline_locked(monotonic);
    g_pending_adjustment_us = adjustment_us;
    boottime_realtime_write_end();
    spin_unlock_irqrestore(&g_realtime_write_lock, lock_flags);
    boottime_publish_vdso();
    kernel_timerfd_realtime_rate_change();
    return 0;
}

int boottime_set_frequency_scaled_ppm(int64_t frequency_scaled_ppm) {
    uint64_t monotonic = boottime_monotonic_us();
    uint64_t lock_flags = spin_lock_irqsave(&g_realtime_write_lock);

    boottime_realtime_write_begin();
    boottime_collapse_discipline_locked(monotonic);
    g_frequency_scaled_ppm = frequency_scaled_ppm;
    boottime_realtime_write_end();
    spin_unlock_irqrestore(&g_realtime_write_lock, lock_flags);
    boottime_publish_vdso();
    kernel_timerfd_realtime_rate_change();
    return 0;
}

int64_t boottime_frequency_scaled_ppm(void) {
    return __atomic_load_n(&g_frequency_scaled_ppm, __ATOMIC_ACQUIRE);
}

int64_t boottime_pending_adjustment_us(void) {
    uint64_t monotonic = boottime_monotonic_us();
    uint64_t anchor;
    int64_t pending;
    uint32_t before;
    uint32_t after;

    do {
        before = __atomic_load_n(&g_realtime_sequence, __ATOMIC_ACQUIRE);
        if (before & 1u) continue;
        anchor = g_discipline_anchor_us;
        pending = g_pending_adjustment_us;
        after = __atomic_load_n(&g_realtime_sequence, __ATOMIC_ACQUIRE);
    } while (before != after || (after & 1u));
    return pending - boottime_slew_correction(
        monotonic > anchor ? monotonic - anchor : 0, pending);
}

uint32_t boottime_now_us(void) {
    return (uint32_t)boottime_monotonic_us();
}
