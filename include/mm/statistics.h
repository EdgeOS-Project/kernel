/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral memory-management event accounting. */
#ifndef EDGEOS_MM_STATISTICS_H
#define EDGEOS_MM_STATISTICS_H

#include <stdint.h>

typedef struct edge_mm_statistics_snapshot {
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t reclaimed_pages;
    uint64_t scanned_pages;
    uint64_t swap_in_pages;
    uint64_t swap_out_pages;
    uint64_t pressure_some_total_us;
    uint64_t pressure_full_total_us;
    uint32_t pressure_some_avg10;
    uint32_t pressure_some_avg60;
    uint32_t pressure_some_avg300;
    uint32_t pressure_full_avg10;
    uint32_t pressure_full_avg60;
    uint32_t pressure_full_avg300;
} edge_mm_statistics_snapshot_t;

typedef struct edge_mm_pressure_state {
    uint64_t some_total_us;
    uint64_t full_total_us;
    uint64_t last_update_us;
    uint32_t some_average[3];
    uint32_t full_average[3];
} edge_mm_pressure_state_t;

typedef struct edge_mm_pressure_snapshot {
    uint64_t some_total_us;
    uint64_t full_total_us;
    uint32_t some_average[3];
    uint32_t full_average[3];
} edge_mm_pressure_snapshot_t;

void edge_mm_statistics_note_fault(int major);
void edge_mm_statistics_note_reclaim(uint64_t scanned_pages,
                                     uint64_t reclaimed_pages);
void edge_mm_statistics_note_swap_in(uint64_t pages);
void edge_mm_statistics_note_swap_out(uint64_t pages);
void edge_mm_statistics_note_pressure(uint64_t now_us,
                                      uint64_t some_stall_us,
                                      uint64_t full_stall_us);
void edge_mm_statistics_snapshot(edge_mm_statistics_snapshot_t *snapshot);
void edge_mm_pressure_record(edge_mm_pressure_state_t *state,
                             uint64_t now_us, uint64_t some_stall_us,
                             uint64_t full_stall_us);
void edge_mm_pressure_snapshot(const edge_mm_pressure_state_t *state,
                               edge_mm_pressure_snapshot_t *snapshot);
void edge_mm_pressure_snapshot_at(edge_mm_pressure_state_t *state,
                                  uint64_t now_us,
                                  edge_mm_pressure_snapshot_t *snapshot);
void edge_mm_statistics_pressure_snapshot(
    uint64_t now_us, edge_mm_pressure_snapshot_t *snapshot);

#endif
