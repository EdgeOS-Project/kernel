/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral physical page allocator.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_MM_PAGE_ALLOCATOR_H
#define EDGEOS_MM_PAGE_ALLOCATOR_H

#include <stdint.h>

#define EDGE_PAGE_SIZE             4096u
#define EDGE_PAGE_ALLOCATOR_ORDER_MAX 24u
#define EDGE_PAGE_INDEX_NONE       UINT32_MAX
#define EDGE_PAGE_CGROUP_NONE      UINT16_MAX
#define EDGE_PAGE_CPU_MAX          256u
#define EDGE_PAGE_CPU_CACHE_CAPACITY 32u

typedef enum edge_page_zone {
    EDGE_PAGE_ZONE_DMA = 0,
    EDGE_PAGE_ZONE_DMA32,
    EDGE_PAGE_ZONE_NORMAL,
    EDGE_PAGE_ZONE_COUNT,
} edge_page_zone_t;

typedef enum edge_page_pressure {
    EDGE_PAGE_PRESSURE_NONE = 0,
    EDGE_PAGE_PRESSURE_LOW,
    EDGE_PAGE_PRESSURE_MINIMUM,
} edge_page_pressure_t;

typedef enum edge_page_migrate_type {
    EDGE_PAGE_MIGRATE_UNMOVABLE = 0,
    EDGE_PAGE_MIGRATE_MOVABLE,
    EDGE_PAGE_MIGRATE_RECLAIMABLE,
    EDGE_PAGE_MIGRATE_CMA,
    EDGE_PAGE_MIGRATE_COUNT,
} edge_page_migrate_type_t;

typedef uint32_t (*edge_page_reclaim_callback_t)(
    void *context, uint32_t target_pages,
    edge_page_pressure_t pressure);

typedef struct edge_page_metadata {
    uint32_t next;
    uint32_t previous;
    uint32_t references;
    uint32_t mappings;
    uint32_t compound_head;
    uint16_t cgroup_owner;
    uint8_t order;
    uint8_t zone;
    uint8_t node;
    uint8_t migrate_type;
    uint8_t flags;
    uint8_t reserved[3];
} edge_page_metadata_t;

typedef struct edge_page_allocator_snapshot {
    uint32_t managed_pages[EDGE_PAGE_ZONE_COUNT];
    uint32_t free_pages[EDGE_PAGE_ZONE_COUNT];
    uint32_t watermark_min[EDGE_PAGE_ZONE_COUNT];
    uint32_t watermark_low[EDGE_PAGE_ZONE_COUNT];
    uint32_t watermark_high[EDGE_PAGE_ZONE_COUNT];
    uint32_t free_blocks[EDGE_PAGE_ZONE_COUNT][EDGE_PAGE_MIGRATE_COUNT]
                        [EDGE_PAGE_ALLOCATOR_ORDER_MAX + 1u];
    uint64_t allocated_pages;
    uint64_t freed_pages;
    uint64_t allocation_failures;
    uint8_t buddy_exact;
} edge_page_allocator_snapshot_t;

typedef struct edge_page_allocator {
    uint64_t base;
    uint32_t page_count;
    uint32_t free_pages;
    edge_page_metadata_t *pages;
    uint32_t free_head[EDGE_PAGE_ZONE_COUNT][EDGE_PAGE_MIGRATE_COUNT]
                      [EDGE_PAGE_ALLOCATOR_ORDER_MAX + 1u];
    uint32_t free_count[EDGE_PAGE_ZONE_COUNT][EDGE_PAGE_MIGRATE_COUNT]
                       [EDGE_PAGE_ALLOCATOR_ORDER_MAX + 1u];
    uint32_t managed_zone_pages[EDGE_PAGE_ZONE_COUNT];
    uint32_t free_zone_pages[EDGE_PAGE_ZONE_COUNT];
    uint32_t watermark_min[EDGE_PAGE_ZONE_COUNT];
    uint32_t watermark_low[EDGE_PAGE_ZONE_COUNT];
    uint32_t watermark_high[EDGE_PAGE_ZONE_COUNT];
    uint32_t cpu_cache[EDGE_PAGE_CPU_MAX][EDGE_PAGE_ZONE_COUNT]
                      [EDGE_PAGE_CPU_CACHE_CAPACITY];
    uint8_t cpu_cache_count[EDGE_PAGE_CPU_MAX][EDGE_PAGE_ZONE_COUNT];
    uint64_t allocated_pages;
    uint64_t freed_pages;
    uint64_t allocation_failures;
    edge_page_reclaim_callback_t reclaim;
    void *reclaim_context;
    volatile uint32_t lock;
    uint8_t reclaim_active;
    uint8_t initialized;
} edge_page_allocator_t;

uint64_t edge_page_allocator_metadata_bytes(uint64_t page_count);
int edge_page_allocator_initialize(edge_page_allocator_t *allocator,
                                   void *metadata, uint64_t metadata_bytes,
                                   uint64_t base, uint32_t page_count,
                                   uint32_t reserved_prefix_pages);
int edge_page_allocator_add_range(edge_page_allocator_t *allocator,
                                  uint64_t physical, uint32_t page_count,
                                  uint8_t numa_node);
uint64_t edge_page_allocator_allocate(edge_page_allocator_t *allocator,
                                      uint32_t page_count,
                                      edge_page_zone_t highest_zone);
uint64_t edge_page_allocator_allocate_typed(
    edge_page_allocator_t *allocator, uint32_t page_count,
    edge_page_zone_t highest_zone, uint8_t numa_node,
    edge_page_migrate_type_t migrate_type, int allow_node_fallback);
uint64_t edge_page_allocator_allocate_cma(
    edge_page_allocator_t *allocator, uint32_t page_count,
    edge_page_zone_t highest_zone, uint8_t numa_node,
    int allow_node_fallback);
uint64_t edge_page_allocator_allocate_local(
    edge_page_allocator_t *allocator, uint32_t cpu_id,
    edge_page_zone_t highest_zone);
int edge_page_allocator_retain(edge_page_allocator_t *allocator,
                               uint64_t physical);
int edge_page_allocator_recover(edge_page_allocator_t *allocator,
                                uint64_t physical);
int edge_page_allocator_release(edge_page_allocator_t *allocator,
                                uint64_t physical);
int edge_page_allocator_release_local(edge_page_allocator_t *allocator,
                                      uint64_t physical,
                                      uint32_t cpu_id);
uint32_t edge_page_allocator_references(
    const edge_page_allocator_t *allocator, uint64_t physical);
int edge_page_allocator_mapping_acquire(
    edge_page_allocator_t *allocator, uint64_t physical,
    uint16_t cgroup_owner, uint32_t *previous_mappings);
int edge_page_allocator_mapping_release(
    edge_page_allocator_t *allocator, uint64_t physical,
    uint16_t *released_cgroup_owner, uint32_t *remaining_mappings);
uint32_t edge_page_allocator_mappings(
    const edge_page_allocator_t *allocator, uint64_t physical);
int edge_page_allocator_mapping_owner(
    const edge_page_allocator_t *allocator, uint64_t physical,
    uint16_t *cgroup_owner_out);
uint64_t edge_page_allocator_free_bytes(
    const edge_page_allocator_t *allocator);
uint32_t edge_page_allocator_referenced_pages(
    const edge_page_allocator_t *allocator, uint64_t *reference_total);
edge_page_pressure_t edge_page_allocator_zone_pressure(
    const edge_page_allocator_t *allocator, edge_page_zone_t zone);
uint32_t edge_page_allocator_drain_cpu(
    edge_page_allocator_t *allocator, uint32_t cpu_id);
int edge_page_allocator_snapshot(
    const edge_page_allocator_t *allocator,
    edge_page_allocator_snapshot_t *snapshot);
void edge_page_allocator_set_reclaim(
    edge_page_allocator_t *allocator,
    edge_page_reclaim_callback_t reclaim, void *context);
int edge_page_allocator_set_migrate_type(
    edge_page_allocator_t *allocator, uint64_t physical,
    uint32_t page_count, edge_page_migrate_type_t migrate_type);
int edge_page_allocator_contains(const edge_page_allocator_t *allocator,
                                 uint64_t physical, uint32_t *index_out);

#endif
