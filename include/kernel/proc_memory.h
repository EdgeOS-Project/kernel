/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Architecture-neutral Linux /proc/meminfo formatting.
 */
#ifndef EDGEOS_KERNEL_PROC_MEMORY_H
#define EDGEOS_KERNEL_PROC_MEMORY_H

#include <stdint.h>
#include "mm/page_allocator.h"
#include "mm/statistics.h"

typedef struct kernel_proc_memory_snapshot {
    uint64_t total_bytes;
    uint64_t free_bytes;
    uint64_t available_bytes;
    uint64_t buffer_bytes;
    uint64_t cache_bytes;
    uint64_t shared_bytes;
    uint64_t slab_reclaimable_bytes;
    uint64_t slab_unreclaimable_bytes;
    uint64_t swap_total_bytes;
    uint64_t swap_free_bytes;
} kernel_proc_memory_snapshot_t;

int kernel_proc_memory_render(char *buffer, uint32_t capacity,
                              const kernel_proc_memory_snapshot_t *snapshot);
int kernel_proc_memory_pressure_render(
    char *buffer, uint32_t capacity,
    const edge_mm_pressure_snapshot_t *pressure);
int kernel_proc_vmstat_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot,
    const edge_mm_statistics_snapshot_t *statistics,
    uint64_t file_pages, uint64_t shared_pages);
int kernel_proc_zoneinfo_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot);
int kernel_proc_buddyinfo_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot);
int kernel_proc_pagetypeinfo_render(
    char *buffer, uint32_t capacity,
    const edge_page_allocator_snapshot_t *snapshot);

#endif
