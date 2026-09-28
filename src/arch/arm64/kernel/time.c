/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 architectural counter and PL031 realtime clock backend. */

#include <stdint.h>

#include "kernel/boottime_arch.h"
#include "serial_console.h"

static uint64_t counter_base;
static uint64_t counter_frequency;

static uint64_t counter_now(void) {
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

uint64_t kernel_arch_boottime_initialize(void) {
    volatile uint32_t *pl031_data = (volatile uint32_t *)(uintptr_t)0x09010000ULL;
    serial_console_write_raw('V');
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(counter_frequency));
    serial_console_write_raw('W');
    counter_base = counter_now();
    serial_console_write_raw('X');
    uint64_t realtime_base = (uint64_t)*pl031_data * 1000000ULL;
    serial_console_write_raw('Y');
    return realtime_base;
}

uint64_t kernel_arch_boottime_monotonic_us(void) {
    uint64_t delta;
    if (!counter_frequency) return 0;
    delta = counter_now() - counter_base;
    return (delta / counter_frequency) * 1000000ULL +
           ((delta % counter_frequency) * 1000000ULL) / counter_frequency;
}

void kernel_arch_boottime_timer_tick(uint32_t hz) {
    (void)hz;
}

int kernel_arch_boottime_refine(uint64_t hz,
                                uint64_t monotonic_floor_us) {
    /* CNTFRQ_EL0 is the fixed frequency source for the architected counter. */
    (void)hz;
    (void)monotonic_floor_us;
    return -1;
}

uint64_t kernel_arch_boottime_source_hz(void) {
    return counter_frequency;
}

const char *kernel_arch_boottime_source_name(void) {
    return "arm-architected-counter";
}

void kernel_arch_boottime_vdso_snapshot(uint64_t *cycle_last,
                                        uint64_t *monotonic_base_us,
                                        uint64_t *frequency) {
    if (cycle_last) *cycle_last = counter_base;
    if (monotonic_base_us) *monotonic_base_us = 0;
    if (frequency) *frequency = counter_frequency;
}
