/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux-compatible /proc/meminfo rendering shared by every architecture.
 */

#include <stdint.h>
#include "kernel/proc_memory.h"

static int memory_append(char *buffer, uint32_t capacity, uint32_t *length,
                         const char *text) {
    if (!buffer || !length || !text) return -1;
    while (*text) {
        if (*length + 1u >= capacity) return -1;
        buffer[(*length)++] = *text++;
    }
    buffer[*length] = 0;
    return 0;
}

static int memory_append_u64(char *buffer, uint32_t capacity,
                             uint32_t *length, uint64_t value) {
    char reversed[24];
    uint32_t count = 0;

    if (!value) reversed[count++] = '0';
    while (value && count < sizeof(reversed)) {
        reversed[count++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (count) {
        char byte[2] = { reversed[--count], 0 };
        if (memory_append(buffer, capacity, length, byte) < 0) return -1;
    }
    return 0;
}

static int memory_append_kb(char *buffer, uint32_t capacity,
                            uint32_t *length, const char *label,
                            uint64_t bytes) {
    if (memory_append(buffer, capacity, length, label) < 0 ||
        memory_append_u64(buffer, capacity, length, bytes / 1024u) < 0 ||
        memory_append(buffer, capacity, length, " kB\n") < 0)
        return -1;
    return 0;
}

static int memory_append_value(char *buffer, uint32_t capacity,
                               uint32_t *length, const char *label,
                               uint64_t value) {
    if (memory_append(buffer, capacity, length, label) < 0 ||
        memory_append_u64(buffer, capacity, length, value) < 0 ||
        memory_append(buffer, capacity, length, "\n") < 0)
        return -1;
    return 0;
}

static int memory_append_pressure_average(char *buffer, uint32_t capacity,
                                          uint32_t *length,
                                          uint32_t hundredths) {
    if (hundredths > 10000u) hundredths = 10000u;
    if (memory_append_u64(
            buffer, capacity, length, hundredths / 100u) < 0 ||
        memory_append(buffer, capacity, length, ".") < 0 ||
        (hundredths % 100u < 10u &&
         memory_append(buffer, capacity, length, "0") < 0) ||
        memory_append_u64(
            buffer, capacity, length, hundredths % 100u) < 0)
        return -1;
    return 0;
}

static int memory_append_pressure_line(
    char *buffer, uint32_t capacity, uint32_t *length,
    const char *kind, const uint32_t average[3], uint64_t total_us) {
    if (memory_append(buffer, capacity, length, kind) < 0 ||
        memory_append(buffer, capacity, length, " avg10=") < 0 ||
        memory_append_pressure_average(
            buffer, capacity, length, average[0]) < 0 ||
        memory_append(buffer, capacity, length, " avg60=") < 0 ||
        memory_append_pressure_average(
            buffer, capacity, length, average[1]) < 0 ||
        memory_append(buffer, capacity, length, " avg300=") < 0 ||
        memory_append_pressure_average(
            buffer, capacity, length, average[2]) < 0 ||
        memory_append(buffer, capacity, length, " total=") < 0 ||
        memory_append_u64(buffer, capacity, length, total_us) < 0 ||
        memory_append(buffer, capacity, length, "\n") < 0)
        return -1;
    return 0;
}

static const char *memory_zone_name(uint32_t zone) {
    static const char *const names[EDGE_PAGE_ZONE_COUNT] = {
        "DMA", "DMA32", "Normal"
    };
    return zone < EDGE_PAGE_ZONE_COUNT ? names[zone] : "Unknown";
}

static const char *memory_migrate_name(uint32_t migrate) {
    static const char *const names[EDGE_PAGE_MIGRATE_COUNT] = {
        "Unmovable", "Movable", "Reclaimable", "CMA"
    };
    return migrate < EDGE_PAGE_MIGRATE_COUNT ? names[migrate] : "Unknown";
}

int kernel_proc_memory_render(char *buffer, uint32_t capacity,
                              const kernel_proc_memory_snapshot_t *snapshot) {
    uint32_t length = 0;
    uint64_t slab_bytes;

    if (!buffer || !snapshot || capacity < 2u) return -1;
    slab_bytes = snapshot->slab_reclaimable_bytes +
                 snapshot->slab_unreclaimable_bytes;

    /*
     * These fields are the Linux userspace contract consumed by GLib, XFCE,
     * procps, system monitors, and memory-pressure policy.  Values represent
     * tracked kernel resources; EdgeOS currently has no separate block-buffer
     * cache or slab allocator, so those classes remain zero until such an
     * allocator owns real pages.
     */
    if (memory_append_kb(buffer, capacity, &length,
                         "MemTotal:       ", snapshot->total_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "MemFree:        ", snapshot->free_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "MemAvailable:   ", snapshot->available_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "Buffers:        ", snapshot->buffer_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "Cached:         ", snapshot->cache_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "Shmem:          ", snapshot->shared_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "Slab:           ", slab_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "SReclaimable:   ", snapshot->slab_reclaimable_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "SUnreclaim:     ", snapshot->slab_unreclaimable_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "SwapTotal:      ", snapshot->swap_total_bytes) < 0 ||
        memory_append_kb(buffer, capacity, &length,
                         "SwapFree:       ", snapshot->swap_free_bytes) < 0)
        return -1;
    return (int)length;
}

int kernel_proc_memory_pressure_render(
    char *buffer, uint32_t capacity,
    const edge_mm_pressure_snapshot_t *pressure) {
    uint32_t length = 0;

    if (!buffer || !pressure || capacity < 2u) return -1;
    buffer[0] = 0;
    if (memory_append_pressure_line(
            buffer, capacity, &length, "some", pressure->some_average,
            pressure->some_total_us) < 0 ||
        memory_append_pressure_line(
            buffer, capacity, &length, "full", pressure->full_average,
            pressure->full_total_us) < 0)
        return -1;
    return (int)length;
}

int kernel_proc_vmstat_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot,
    const edge_mm_statistics_snapshot_t *statistics,
    uint64_t file_pages, uint64_t shared_pages) {
    uint32_t length = 0;
    uint64_t free_pages = 0;
    uint64_t fault_pages;

    if (!buffer || !snapshot || !statistics || capacity < 2u) return -1;
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone)
        free_pages += snapshot->free_pages[zone];
    fault_pages = statistics->minor_faults >
                  UINT64_MAX - statistics->major_faults ? UINT64_MAX :
                  statistics->minor_faults + statistics->major_faults;
    if (memory_append_value(buffer, capacity, &length,
                            "nr_free_pages ", free_pages) < 0 ||
        memory_append_value(buffer, capacity, &length,
                            "nr_file_pages ", file_pages) < 0 ||
        memory_append_value(buffer, capacity, &length,
                            "nr_shmem ", shared_pages) < 0 ||
        memory_append_value(buffer, capacity, &length,
                            "nr_slab_reclaimable ", 0) < 0 ||
        memory_append_value(buffer, capacity, &length,
                            "nr_slab_unreclaimable ", 0) < 0 ||
        memory_append_value(buffer, capacity, &length,
                            "pgalloc_normal ",
                            snapshot->allocated_pages) < 0 ||
        memory_append_value(buffer, capacity, &length,
                            "pgfree ", snapshot->freed_pages) < 0 ||
        memory_append_value(buffer, capacity, &length,
                            "allocstall_normal ",
                            snapshot->allocation_failures) < 0 ||
        memory_append_value(buffer, capacity, &length, "pgscan_direct ",
                            statistics->scanned_pages) < 0 ||
        memory_append_value(buffer, capacity, &length, "pgsteal_direct ",
                            statistics->reclaimed_pages) < 0 ||
        memory_append_value(buffer, capacity, &length, "pgfault ",
                            fault_pages) < 0 ||
        memory_append_value(buffer, capacity, &length, "pgmajfault ",
                            statistics->major_faults) < 0 ||
        memory_append_value(buffer, capacity, &length, "pswpin ",
                            statistics->swap_in_pages) < 0 ||
        memory_append_value(buffer, capacity, &length, "pswpout ",
                            statistics->swap_out_pages) < 0)
        return -1;
    return (int)length;
}

int kernel_proc_zoneinfo_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot) {
    uint32_t length = 0;

    if (!buffer || !snapshot || capacity < 2u) return -1;
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone) {
        if (!snapshot->managed_pages[zone]) continue;
        if (memory_append(buffer, capacity, &length, "Node 0, zone ") < 0 ||
            memory_append(buffer, capacity, &length,
                          memory_zone_name(zone)) < 0 ||
            memory_append(buffer, capacity, &length, "\n") < 0 ||
            memory_append_value(buffer, capacity, &length,
                                "  pages free     ",
                                snapshot->free_pages[zone]) < 0 ||
            memory_append_value(buffer, capacity, &length,
                                "        min      ",
                                snapshot->watermark_min[zone]) < 0 ||
            memory_append_value(buffer, capacity, &length,
                                "        low      ",
                                snapshot->watermark_low[zone]) < 0 ||
            memory_append_value(buffer, capacity, &length,
                                "        high     ",
                                snapshot->watermark_high[zone]) < 0 ||
            memory_append_value(buffer, capacity, &length,
                                "        managed  ",
                                snapshot->managed_pages[zone]) < 0)
            return -1;
    }
    return (int)length;
}

int kernel_proc_buddyinfo_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot) {
    uint32_t length = 0;

    if (!buffer || !snapshot || capacity < 2u) return -1;
    if (!snapshot->buddy_exact) {
        buffer[0] = 0;
        return 0;
    }
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone) {
        if (!snapshot->managed_pages[zone]) continue;
        if (memory_append(buffer, capacity, &length,
                          "Node 0, zone ") < 0 ||
            memory_append(buffer, capacity, &length,
                          memory_zone_name(zone)) < 0)
            return -1;
        for (uint32_t order = 0;
             order <= EDGE_PAGE_ALLOCATOR_ORDER_MAX; ++order) {
            uint64_t blocks = 0;
            for (uint32_t migrate = 0;
                 migrate < EDGE_PAGE_MIGRATE_COUNT; ++migrate)
                blocks += snapshot->free_blocks[zone][migrate][order];
            if (memory_append(buffer, capacity, &length, " ") < 0 ||
                memory_append_u64(buffer, capacity, &length, blocks) < 0)
                return -1;
        }
        if (memory_append(buffer, capacity, &length, "\n") < 0) return -1;
    }
    return (int)length;
}

int kernel_proc_pagetypeinfo_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot) {
    uint32_t length = 0;

    if (!buffer || !snapshot || capacity < 2u) return -1;
    if (!snapshot->buddy_exact) {
        buffer[0] = 0;
        return 0;
    }
    if (memory_append(buffer, capacity, &length,
                      "Page block order: 0\nPages per block: 1\n") < 0)
        return -1;
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone) {
        if (!snapshot->managed_pages[zone]) continue;
        for (uint32_t migrate = 0;
             migrate < EDGE_PAGE_MIGRATE_COUNT; ++migrate) {
            if (memory_append(buffer, capacity, &length,
                              "Node 0, zone ") < 0 ||
                memory_append(buffer, capacity, &length,
                              memory_zone_name(zone)) < 0 ||
                memory_append(buffer, capacity, &length, ", type ") < 0 ||
                memory_append(buffer, capacity, &length,
                              memory_migrate_name(migrate)) < 0)
                return -1;
            for (uint32_t order = 0;
                 order <= EDGE_PAGE_ALLOCATOR_ORDER_MAX; ++order) {
                if (memory_append(buffer, capacity, &length, " ") < 0 ||
                    memory_append_u64(
                        buffer, capacity, &length,
                        snapshot->free_blocks[zone][migrate][order]) < 0)
                    return -1;
            }
            if (memory_append(buffer, capacity, &length, "\n") < 0)
                return -1;
        }
    }
    return (int)length;
}
