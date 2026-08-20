/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for realtime frequency and slew discipline. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "sys/boottime.h"

static uint64_t g_monotonic_us = 1000000u;
static uint64_t g_vdso_anchor_us;
static int64_t g_vdso_frequency_scaled_ppm;
static int64_t g_vdso_pending_adjustment_us;
static unsigned int g_clock_steps;
static unsigned int g_rate_changes;

uint64_t kernel_arch_boottime_initialize(void) { return 5000000u; }
uint64_t kernel_arch_boottime_monotonic_us(void) { return g_monotonic_us; }
void kernel_arch_boottime_timer_tick(uint32_t hz) { (void)hz; }
int kernel_arch_boottime_refine(uint64_t hz, uint64_t floor_us) {
    (void)hz;
    (void)floor_us;
    return 0;
}
uint64_t kernel_arch_boottime_source_hz(void) { return 1000000u; }
const char *kernel_arch_boottime_source_name(void) { return "test"; }
void kernel_arch_boottime_vdso_snapshot(
    uint64_t *cycle_last, uint64_t *monotonic_base_us,
    uint64_t *frequency) {
    *cycle_last = g_monotonic_us;
    *monotonic_base_us = g_monotonic_us;
    *frequency = 1000000u;
}
void linux_vdso_time_update(
    uint64_t cycle_last, uint64_t monotonic_base_us,
    uint64_t realtime_offset_us, uint64_t frequency,
    uint64_t discipline_anchor_us, int64_t frequency_scaled_ppm,
    int64_t pending_adjustment_us) {
    (void)cycle_last;
    (void)monotonic_base_us;
    (void)realtime_offset_us;
    (void)frequency;
    g_vdso_anchor_us = discipline_anchor_us;
    g_vdso_frequency_scaled_ppm = frequency_scaled_ppm;
    g_vdso_pending_adjustment_us = pending_adjustment_us;
}
void kernel_timerfd_realtime_change_begin(void) { ++g_clock_steps; }
void kernel_timerfd_realtime_change_complete(void) { ++g_clock_steps; }
void kernel_timerfd_realtime_rate_change(void) { ++g_rate_changes; }

int main(void) {
    uint64_t before;

    boottime_init();
    assert(boottime_realtime_us() == 6000000u);
    assert(boottime_set_frequency_scaled_ppm(32768000ll) == 0);
    assert(g_vdso_frequency_scaled_ppm == 32768000ll);
    assert(g_vdso_anchor_us == 1000000u);

    g_monotonic_us = 3000000u;
    assert(boottime_realtime_us() == 8001000u);
    assert(boottime_set_frequency_scaled_ppm(0) == 0);
    before = boottime_realtime_us();
    assert(before == 8001000u);

    assert(boottime_adjust_realtime_us(1000, 0) == 0);
    assert(g_clock_steps == 0);
    assert(g_rate_changes == 3);
    assert(g_vdso_pending_adjustment_us == 1000);
    g_monotonic_us = 4000000u;
    assert(boottime_realtime_us() == before + 1000000u + 500u);
    assert(boottime_pending_adjustment_us() == 500);
    g_monotonic_us = 5000000u;
    assert(boottime_realtime_us() == before + 2000000u + 1000u);
    assert(boottime_pending_adjustment_us() == 0);

    assert(boottime_set_pending_adjustment_us(4000) == 0);
    assert(g_clock_steps == 0);
    assert(boottime_pending_adjustment_us() == 4000);
    assert(boottime_set_pending_adjustment_us(-3000) == 0);
    assert(boottime_pending_adjustment_us() == -3000);

    before = boottime_realtime_us();
    assert(boottime_adjust_realtime_us(-2000, 1) == 0);
    assert(g_clock_steps == 2);
    assert(boottime_realtime_us() == before - 2000u);
    puts("boottime_discipline_unit: PASS");
    return 0;
}
