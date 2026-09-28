/* SPDX-License-Identifier: MPL-2.0 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/proc_memory.h"

static int failures;

static void expect_contains(const char *name, const char *text,
                            const char *needle) {
    if (strstr(text, needle)) return;
    fprintf(stderr, "FAIL: %s missing '%s'\n", name, needle);
    ++failures;
}

int main(void) {
    edge_page_allocator_snapshot_t snapshot = {0};
    edge_mm_statistics_snapshot_t statistics = {0};
    char buffer[16384];
    int length;
    edge_mm_statistics_snapshot_t recorded = {0};
    edge_mm_pressure_snapshot_t pressure = {
        .some_total_us = 12345u,
        .full_total_us = 99u,
        .some_average = { 123u, 45u, 6u },
        .full_average = { 1u, 0u, 0u },
    };
    edge_mm_pressure_state_t pressure_state = {0};

    snapshot.managed_pages[EDGE_PAGE_ZONE_NORMAL] = 1024u;
    snapshot.free_pages[EDGE_PAGE_ZONE_NORMAL] = 512u;
    snapshot.watermark_min[EDGE_PAGE_ZONE_NORMAL] = 10u;
    snapshot.watermark_low[EDGE_PAGE_ZONE_NORMAL] = 20u;
    snapshot.watermark_high[EDGE_PAGE_ZONE_NORMAL] = 30u;
    snapshot.free_blocks[EDGE_PAGE_ZONE_NORMAL]
                        [EDGE_PAGE_MIGRATE_UNMOVABLE][0] = 3u;
    snapshot.free_blocks[EDGE_PAGE_ZONE_NORMAL]
                        [EDGE_PAGE_MIGRATE_MOVABLE][0] = 1u;
    snapshot.free_blocks[EDGE_PAGE_ZONE_NORMAL]
                        [EDGE_PAGE_MIGRATE_CMA][1] = 2u;
    snapshot.allocated_pages = 100u;
    snapshot.freed_pages = 80u;
    snapshot.allocation_failures = 2u;
    snapshot.buddy_exact = 1u;
    statistics.minor_faults = 17u;
    statistics.major_faults = 3u;
    statistics.scanned_pages = 11u;
    statistics.reclaimed_pages = 7u;
    statistics.swap_in_pages = 5u;
    statistics.swap_out_pages = 4u;

    length = kernel_proc_vmstat_render(
        buffer, sizeof(buffer), &snapshot, &statistics, 9u, 4u);
    if (length < 0) return 1;
    expect_contains("vmstat free", buffer, "nr_free_pages 512\n");
    expect_contains("vmstat file", buffer, "nr_file_pages 9\n");
    expect_contains("vmstat alloc", buffer, "pgalloc_normal 100\n");
    expect_contains("vmstat free events", buffer, "pgfree 80\n");
    expect_contains("vmstat stalls", buffer, "allocstall_normal 2\n");
    expect_contains("vmstat faults", buffer, "pgfault 20\n");
    expect_contains("vmstat major faults", buffer, "pgmajfault 3\n");
    expect_contains("vmstat swap in", buffer, "pswpin 5\n");

    length = kernel_proc_memory_pressure_render(
        buffer, sizeof(buffer), &pressure);
    if (length < 0) return 1;
    expect_contains("pressure some", buffer,
                    "some avg10=1.23 avg60=0.45 avg300=0.06 total=12345\n");
    expect_contains("pressure full", buffer,
                    "full avg10=0.01 avg60=0.00 avg300=0.00 total=99\n");

    edge_mm_pressure_record(
        &pressure_state, 1000000u, 100000u, 25000u);
    edge_mm_pressure_snapshot(&pressure_state, &pressure);
    if (pressure.some_total_us != 100000u ||
        pressure.full_total_us != 25000u ||
        pressure.some_average[0] != 100u ||
        pressure.full_average[0] != 25u) {
        fprintf(stderr, "FAIL: pressure accounting\n");
        ++failures;
    }
    edge_mm_pressure_record(
        &pressure_state, 11000000u, 100000u, 0u);
    edge_mm_pressure_snapshot(&pressure_state, &pressure);
    if (pressure.some_total_us != 200000u ||
        pressure.full_total_us != 25000u ||
        pressure.some_average[0] != 132u ||
        pressure.full_average[0] != 6u) {
        fprintf(stderr, "FAIL: pressure decay\n");
        ++failures;
    }
    edge_mm_pressure_snapshot_at(
        &pressure_state, 91000000u, &pressure);
    if (pressure.some_average[0] != 0u ||
        pressure.full_average[0] != 0u ||
        pressure.some_total_us != 200000u ||
        pressure.full_total_us != 25000u) {
        fprintf(stderr, "FAIL: pressure idle decay\n");
        ++failures;
    }

    length = kernel_proc_zoneinfo_render(
        buffer, sizeof(buffer), &snapshot);
    if (length < 0) return 1;
    expect_contains("zone name", buffer, "Node 0, zone Normal\n");
    expect_contains("zone managed", buffer, "managed  1024\n");

    length = kernel_proc_buddyinfo_render(
        buffer, sizeof(buffer), &snapshot);
    if (length < 0) return 1;
    expect_contains("buddy aggregation", buffer,
                    "Node 0, zone Normal 4 2 ");

    length = kernel_proc_pagetypeinfo_render(
        buffer, sizeof(buffer), &snapshot);
    if (length < 0) return 1;
    expect_contains("pagetype movable", buffer,
                    "Node 0, zone Normal, type Movable 1 ");
    expect_contains("pagetype CMA", buffer,
                    "Node 0, zone Normal, type CMA 0 2 ");

    snapshot.buddy_exact = 0u;
    length = kernel_proc_buddyinfo_render(
        buffer, sizeof(buffer), &snapshot);
    if (length != 0 || buffer[0] != 0) {
        fprintf(stderr, "FAIL: inexact buddy topology must stay empty\n");
        ++failures;
    }

    edge_mm_statistics_note_fault(0);
    edge_mm_statistics_note_fault(1);
    edge_mm_statistics_note_reclaim(9u, 6u);
    edge_mm_statistics_note_swap_in(2u);
    edge_mm_statistics_note_swap_out(3u);
    edge_mm_statistics_note_pressure(1000000u, 20000u, 5000u);
    edge_mm_statistics_snapshot(&recorded);
    if (recorded.minor_faults != 1u || recorded.major_faults != 1u ||
        recorded.scanned_pages != 9u || recorded.reclaimed_pages != 6u ||
        recorded.swap_in_pages != 2u || recorded.swap_out_pages != 3u ||
        recorded.pressure_some_total_us != 20000u ||
        recorded.pressure_full_total_us != 5000u) {
        fprintf(stderr, "FAIL: shared MM event accounting\n");
        ++failures;
    }

    if (failures) return 1;
    puts("proc_memory_unit: PASS");
    return 0;
}
