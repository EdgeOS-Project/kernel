/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral memory-management event accounting. */

#include <stdint.h>

#include "mm/statistics.h"
#include "string.h"

static edge_mm_statistics_snapshot_t g_mm_statistics;
static edge_mm_pressure_state_t g_mm_pressure;
static volatile uint32_t g_mm_pressure_lock;

static const uint32_t g_pressure_windows[3] = { 10u, 60u, 300u };

static void statistics_add(uint64_t *counter, uint64_t value) {
    uint64_t previous;
    uint64_t next;

    do {
        previous = __atomic_load_n(counter, __ATOMIC_RELAXED);
        next = previous > UINT64_MAX - value ? UINT64_MAX : previous + value;
    } while (!__atomic_compare_exchange_n(
        counter, &previous, next, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
}

void edge_mm_statistics_note_fault(int major) {
    statistics_add(major ? &g_mm_statistics.major_faults :
                           &g_mm_statistics.minor_faults,
                   1u);
}

void edge_mm_statistics_note_reclaim(uint64_t scanned_pages,
                                     uint64_t reclaimed_pages) {
    statistics_add(&g_mm_statistics.scanned_pages, scanned_pages);
    statistics_add(&g_mm_statistics.reclaimed_pages, reclaimed_pages);
}

void edge_mm_statistics_note_swap_in(uint64_t pages) {
    statistics_add(&g_mm_statistics.swap_in_pages, pages);
}

void edge_mm_statistics_note_swap_out(uint64_t pages) {
    statistics_add(&g_mm_statistics.swap_out_pages, pages);
}

static uint64_t pressure_add_saturating(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static void pressure_decay_average(uint32_t *average, uint32_t window,
                                   uint64_t elapsed_seconds) {
    if (!average || !window || !elapsed_seconds) return;
    if (elapsed_seconds >= (uint64_t)window * 8u) {
        *average = 0;
        return;
    }
    while (elapsed_seconds--)
        *average = (uint32_t)(
            ((uint64_t)*average * (window - 1u)) / window);
}

static uint32_t pressure_contribution(uint64_t stall_us,
                                      uint32_t window) {
    uint64_t denominator = (uint64_t)window * 1000000u;
    uint64_t contribution;

    if (!stall_us || !window) return 0;
    contribution = stall_us > UINT64_MAX / 10000u ? 10000u :
        (stall_us * 10000u) / denominator;
    return contribution > 10000u ? 10000u : (uint32_t)contribution;
}

static void pressure_decay_state(edge_mm_pressure_state_t *state,
                                 uint64_t now_us) {
    uint64_t elapsed_seconds;

    if (!state || !state->last_update_us ||
        now_us <= state->last_update_us)
        return;
    elapsed_seconds = (now_us - state->last_update_us) / 1000000u;
    if (!elapsed_seconds) return;
    for (uint32_t index = 0; index < 3u; ++index) {
        pressure_decay_average(&state->some_average[index],
                               g_pressure_windows[index], elapsed_seconds);
        pressure_decay_average(&state->full_average[index],
                               g_pressure_windows[index], elapsed_seconds);
    }
    state->last_update_us += elapsed_seconds * 1000000u;
}

void edge_mm_pressure_record(edge_mm_pressure_state_t *state,
                             uint64_t now_us, uint64_t some_stall_us,
                             uint64_t full_stall_us) {
    if (!state || (!some_stall_us && !full_stall_us)) return;
    pressure_decay_state(state, now_us);
    for (uint32_t index = 0; index < 3u; ++index) {
        uint32_t some_contribution;
        uint32_t full_contribution;
        uint64_t next;

        some_contribution = pressure_contribution(
            some_stall_us, g_pressure_windows[index]);
        full_contribution = pressure_contribution(
            full_stall_us, g_pressure_windows[index]);
        next = (uint64_t)state->some_average[index] + some_contribution;
        state->some_average[index] = next > 10000u ? 10000u :
                                     (uint32_t)next;
        next = (uint64_t)state->full_average[index] + full_contribution;
        state->full_average[index] = next > 10000u ? 10000u :
                                     (uint32_t)next;
    }
    state->some_total_us = pressure_add_saturating(
        state->some_total_us, some_stall_us);
    state->full_total_us = pressure_add_saturating(
        state->full_total_us, full_stall_us);
    if (!state->last_update_us) state->last_update_us = now_us;
}

void edge_mm_pressure_snapshot_at(edge_mm_pressure_state_t *state,
                                  uint64_t now_us,
                                  edge_mm_pressure_snapshot_t *snapshot) {
    pressure_decay_state(state, now_us);
    edge_mm_pressure_snapshot(state, snapshot);
}

void edge_mm_pressure_snapshot(const edge_mm_pressure_state_t *state,
                               edge_mm_pressure_snapshot_t *snapshot) {
    if (!snapshot) return;
    memset(snapshot, 0, sizeof(*snapshot));
    if (!state) return;
    snapshot->some_total_us = state->some_total_us;
    snapshot->full_total_us = state->full_total_us;
    for (uint32_t index = 0; index < 3u; ++index) {
        snapshot->some_average[index] = state->some_average[index];
        snapshot->full_average[index] = state->full_average[index];
    }
}

void edge_mm_statistics_note_pressure(uint64_t now_us,
                                      uint64_t some_stall_us,
                                      uint64_t full_stall_us) {
    while (__sync_lock_test_and_set(&g_mm_pressure_lock, 1u)) { }
    edge_mm_pressure_record(&g_mm_pressure, now_us,
                            some_stall_us, full_stall_us);
    __sync_lock_release(&g_mm_pressure_lock);
}

void edge_mm_statistics_pressure_snapshot(
    uint64_t now_us, edge_mm_pressure_snapshot_t *snapshot) {
    if (!snapshot) return;
    while (__sync_lock_test_and_set(&g_mm_pressure_lock, 1u)) { }
    edge_mm_pressure_snapshot_at(&g_mm_pressure, now_us, snapshot);
    __sync_lock_release(&g_mm_pressure_lock);
}

void edge_mm_statistics_snapshot(edge_mm_statistics_snapshot_t *snapshot) {
    edge_mm_pressure_snapshot_t pressure;

    if (!snapshot) return;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->minor_faults = __atomic_load_n(
        &g_mm_statistics.minor_faults, __ATOMIC_RELAXED);
    snapshot->major_faults = __atomic_load_n(
        &g_mm_statistics.major_faults, __ATOMIC_RELAXED);
    snapshot->reclaimed_pages = __atomic_load_n(
        &g_mm_statistics.reclaimed_pages, __ATOMIC_RELAXED);
    snapshot->scanned_pages = __atomic_load_n(
        &g_mm_statistics.scanned_pages, __ATOMIC_RELAXED);
    snapshot->swap_in_pages = __atomic_load_n(
        &g_mm_statistics.swap_in_pages, __ATOMIC_RELAXED);
    snapshot->swap_out_pages = __atomic_load_n(
        &g_mm_statistics.swap_out_pages, __ATOMIC_RELAXED);
    while (__sync_lock_test_and_set(&g_mm_pressure_lock, 1u)) { }
    edge_mm_pressure_snapshot(&g_mm_pressure, &pressure);
    __sync_lock_release(&g_mm_pressure_lock);
    snapshot->pressure_some_total_us = pressure.some_total_us;
    snapshot->pressure_full_total_us = pressure.full_total_us;
    snapshot->pressure_some_avg10 = pressure.some_average[0];
    snapshot->pressure_some_avg60 = pressure.some_average[1];
    snapshot->pressure_some_avg300 = pressure.some_average[2];
    snapshot->pressure_full_avg10 = pressure.full_average[0];
    snapshot->pressure_full_avg60 = pressure.full_average[1];
    snapshot->pressure_full_avg300 = pressure.full_average[2];
}
