/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral zone-aware buddy page allocator.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "mm/page_allocator.h"
#include "string.h"

#define EDGE_PAGE_FLAG_FREE          0x01u
#define EDGE_PAGE_FLAG_RESERVED      0x02u
#define EDGE_PAGE_FLAG_COMPOUND_HEAD 0x04u
#define EDGE_PAGE_FLAG_COMPOUND_TAIL 0x08u
#define EDGE_DMA_LIMIT          0x01000000ull
#define EDGE_DMA32_LIMIT        0x100000000ull

static void edge_page_lock(edge_page_allocator_t *allocator) {
    while (__atomic_exchange_n(&allocator->lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&allocator->lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void edge_page_unlock(edge_page_allocator_t *allocator) {
    __atomic_store_n(&allocator->lock, 0u, __ATOMIC_RELEASE);
}

static edge_page_zone_t edge_page_zone_for_physical(uint64_t physical) {
    if (physical < EDGE_DMA_LIMIT) return EDGE_PAGE_ZONE_DMA;
    if (physical < EDGE_DMA32_LIMIT) return EDGE_PAGE_ZONE_DMA32;
    return EDGE_PAGE_ZONE_NORMAL;
}

static void edge_page_update_watermarks_locked(
    edge_page_allocator_t *allocator, edge_page_zone_t zone) {
    uint32_t managed = allocator->managed_zone_pages[zone];
    uint32_t minimum;

    if (!managed) {
        allocator->watermark_min[zone] = 0;
        allocator->watermark_low[zone] = 0;
        allocator->watermark_high[zone] = 0;
        return;
    }
    minimum = managed / 100u;
    if (minimum < 16u) minimum = managed < 16u ? managed : 16u;
    if (minimum > 4096u) minimum = 4096u;
    allocator->watermark_min[zone] = minimum;
    allocator->watermark_low[zone] =
        minimum > UINT32_MAX / 2u ? UINT32_MAX : minimum * 2u;
    allocator->watermark_high[zone] =
        minimum > UINT32_MAX / 3u ? UINT32_MAX : minimum * 3u;
    if (allocator->watermark_low[zone] > managed)
        allocator->watermark_low[zone] = managed;
    if (allocator->watermark_high[zone] > managed)
        allocator->watermark_high[zone] = managed;
}

int edge_page_allocator_contains(const edge_page_allocator_t *allocator,
                                 uint64_t physical, uint32_t *index_out) {
    uint64_t offset;

    if (!allocator || !allocator->initialized ||
        physical < allocator->base ||
        (physical & (EDGE_PAGE_SIZE - 1u)))
        return 0;
    offset = physical - allocator->base;
    if (offset / EDGE_PAGE_SIZE >= allocator->page_count) return 0;
    if (index_out) *index_out = (uint32_t)(offset / EDGE_PAGE_SIZE);
    return 1;
}

uint64_t edge_page_allocator_metadata_bytes(uint64_t page_count) {
    if (!page_count ||
        page_count > UINT64_MAX / sizeof(edge_page_metadata_t))
        return 0;
    return page_count * sizeof(edge_page_metadata_t);
}

static void edge_page_list_remove(edge_page_allocator_t *allocator,
                                  uint32_t index) {
    edge_page_metadata_t *page = &allocator->pages[index];
    uint32_t zone = page->zone;
    uint32_t migrate_type = page->migrate_type;
    uint32_t order = page->order;

    if (!(page->flags & EDGE_PAGE_FLAG_FREE) ||
        zone >= EDGE_PAGE_ZONE_COUNT ||
        migrate_type >= EDGE_PAGE_MIGRATE_COUNT ||
        order > EDGE_PAGE_ALLOCATOR_ORDER_MAX)
        return;
    if (page->previous != EDGE_PAGE_INDEX_NONE)
        allocator->pages[page->previous].next = page->next;
    else
        allocator->free_head[zone][migrate_type][order] = page->next;
    if (page->next != EDGE_PAGE_INDEX_NONE)
        allocator->pages[page->next].previous = page->previous;
    if (allocator->free_count[zone][migrate_type][order])
        --allocator->free_count[zone][migrate_type][order];
    page->next = EDGE_PAGE_INDEX_NONE;
    page->previous = EDGE_PAGE_INDEX_NONE;
    page->flags &= (uint8_t)~EDGE_PAGE_FLAG_FREE;
}

static void edge_page_list_insert(edge_page_allocator_t *allocator,
                                  uint32_t index, uint32_t order) {
    edge_page_metadata_t *page = &allocator->pages[index];
    uint32_t zone = page->zone;
    uint32_t migrate_type = page->migrate_type;
    uint32_t head;

    if (migrate_type >= EDGE_PAGE_MIGRATE_COUNT)
        migrate_type = EDGE_PAGE_MIGRATE_UNMOVABLE;
    page->migrate_type = (uint8_t)migrate_type;
    head = allocator->free_head[zone][migrate_type][order];

    page->order = (uint8_t)order;
    page->flags = EDGE_PAGE_FLAG_FREE;
    page->references = 0;
    page->mappings = 0;
    page->compound_head = EDGE_PAGE_INDEX_NONE;
    page->cgroup_owner = EDGE_PAGE_CGROUP_NONE;
    page->previous = EDGE_PAGE_INDEX_NONE;
    page->next = head;
    if (head != EDGE_PAGE_INDEX_NONE)
        allocator->pages[head].previous = index;
    allocator->free_head[zone][migrate_type][order] = index;
    ++allocator->free_count[zone][migrate_type][order];
}

static void edge_page_free_block_locked(edge_page_allocator_t *allocator,
                                        uint32_t index, uint32_t order) {
    edge_page_zone_t zone = (edge_page_zone_t)allocator->pages[index].zone;

    while (order < EDGE_PAGE_ALLOCATOR_ORDER_MAX) {
        uint32_t buddy = index ^ (1u << order);
        edge_page_metadata_t *buddy_page;

        if (buddy >= allocator->page_count) break;
        buddy_page = &allocator->pages[buddy];
        if (buddy_page->zone != zone ||
            buddy_page->node != allocator->pages[index].node ||
            buddy_page->migrate_type !=
                allocator->pages[index].migrate_type ||
            !(buddy_page->flags & EDGE_PAGE_FLAG_FREE) ||
            buddy_page->order != order)
            break;
        edge_page_list_remove(allocator, buddy);
        if (buddy < index) index = buddy;
        ++order;
    }
    edge_page_list_insert(allocator, index, order);
}

static uint32_t edge_page_largest_range_order(
    const edge_page_allocator_t *allocator, uint32_t index,
    uint32_t remaining) {
    uint32_t order = 0;
    edge_page_zone_t zone =
        (edge_page_zone_t)allocator->pages[index].zone;

    while (order < EDGE_PAGE_ALLOCATOR_ORDER_MAX) {
        uint32_t next_order = order + 1u;
        uint32_t pages = 1u << next_order;
        if (pages > remaining || (index & (pages - 1u)) ||
            index + pages > allocator->page_count ||
            allocator->pages[index + pages - 1u].zone != zone ||
            allocator->pages[index + pages - 1u].node !=
                allocator->pages[index].node ||
            allocator->pages[index + pages - 1u].migrate_type !=
                allocator->pages[index].migrate_type)
            break;
        order = next_order;
    }
    return order;
}

int edge_page_allocator_initialize(edge_page_allocator_t *allocator,
                                   void *metadata, uint64_t metadata_bytes,
                                   uint64_t base, uint32_t page_count,
                                   uint32_t reserved_prefix_pages) {
    uint64_t required = edge_page_allocator_metadata_bytes(page_count);
    uint32_t index;

    if (!allocator || !metadata || !required || metadata_bytes < required ||
        (base & (EDGE_PAGE_SIZE - 1u)) ||
        reserved_prefix_pages > page_count)
        return -1;
    memset(allocator, 0, sizeof(*allocator));
    allocator->base = base;
    allocator->page_count = page_count;
    allocator->pages = (edge_page_metadata_t *)metadata;
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone)
        for (uint32_t migrate_type = 0;
             migrate_type < EDGE_PAGE_MIGRATE_COUNT; ++migrate_type)
            for (uint32_t order = 0;
                 order <= EDGE_PAGE_ALLOCATOR_ORDER_MAX; ++order)
                allocator->free_head[zone][migrate_type][order] =
                    EDGE_PAGE_INDEX_NONE;
    for (index = 0; index < page_count; ++index) {
        edge_page_metadata_t *page = &allocator->pages[index];
        uint64_t physical = base + (uint64_t)index * EDGE_PAGE_SIZE;
        *page = (edge_page_metadata_t){0};
        page->next = EDGE_PAGE_INDEX_NONE;
        page->previous = EDGE_PAGE_INDEX_NONE;
        page->cgroup_owner = EDGE_PAGE_CGROUP_NONE;
        page->compound_head = EDGE_PAGE_INDEX_NONE;
        page->migrate_type = EDGE_PAGE_MIGRATE_UNMOVABLE;
        page->zone = (uint8_t)edge_page_zone_for_physical(physical);
        page->flags = EDGE_PAGE_FLAG_RESERVED;
    }
    allocator->initialized = 1u;
    if (reserved_prefix_pages < page_count &&
        edge_page_allocator_add_range(
            allocator,
            base + (uint64_t)reserved_prefix_pages * EDGE_PAGE_SIZE,
            page_count - reserved_prefix_pages, 0u) < 0)
        return -1;
    return 0;
}

int edge_page_allocator_add_range(edge_page_allocator_t *allocator,
                                  uint64_t physical, uint32_t page_count,
                                  uint8_t numa_node) {
    uint32_t index;
    uint32_t end;
    uint32_t cursor;

    if (!allocator || !allocator->initialized || !page_count ||
        !edge_page_allocator_contains(allocator, physical, &index) ||
        page_count > allocator->page_count - index)
        return -1;
    end = index + page_count;
    edge_page_lock(allocator);
    for (cursor = index; cursor < end; ++cursor)
        if (allocator->pages[cursor].flags != EDGE_PAGE_FLAG_RESERVED) {
            edge_page_unlock(allocator);
            return -1;
        }
    for (cursor = index; cursor < end; ++cursor) {
        allocator->pages[cursor].flags = 0;
        allocator->pages[cursor].node = numa_node;
    }
    cursor = index;
    while (cursor < end) {
        uint32_t order = edge_page_largest_range_order(
            allocator, cursor, end - cursor);
        edge_page_zone_t zone =
            (edge_page_zone_t)allocator->pages[cursor].zone;
        uint32_t block_pages = 1u << order;
        edge_page_list_insert(allocator, cursor, order);
        allocator->free_pages += block_pages;
        allocator->free_zone_pages[zone] += block_pages;
        allocator->managed_zone_pages[zone] += block_pages;
        cursor += block_pages;
    }
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone)
        edge_page_update_watermarks_locked(
            allocator, (edge_page_zone_t)zone);
    edge_page_unlock(allocator);
    return 0;
}

static uint32_t edge_page_find_free_block_locked(
    const edge_page_allocator_t *allocator, edge_page_zone_t zone,
    edge_page_migrate_type_t migrate_type, uint32_t order,
    uint8_t numa_node, int exact_node) {
    uint32_t index;

    index = allocator->free_head[zone][migrate_type][order];
    while (index != EDGE_PAGE_INDEX_NONE) {
        const edge_page_metadata_t *page = &allocator->pages[index];
        if (!exact_node || page->node == numa_node) return index;
        index = page->next;
    }
    return EDGE_PAGE_INDEX_NONE;
}

static int edge_page_allocate_order_locked(
    edge_page_allocator_t *allocator, uint32_t requested_order,
    edge_page_zone_t highest_zone, uint8_t numa_node,
    edge_page_migrate_type_t migrate_type, int allow_node_fallback,
    uint32_t *index_out) {
    edge_page_migrate_type_t fallback[EDGE_PAGE_MIGRATE_COUNT];
    uint32_t fallback_count = 0;
    int zone;

    if (requested_order > EDGE_PAGE_ALLOCATOR_ORDER_MAX ||
        highest_zone >= EDGE_PAGE_ZONE_COUNT ||
        migrate_type >= EDGE_PAGE_MIGRATE_COUNT || !index_out)
        return -1;

    fallback[fallback_count++] = migrate_type;
    if (migrate_type != EDGE_PAGE_MIGRATE_CMA) {
        for (uint32_t type = 0; type < EDGE_PAGE_MIGRATE_COUNT; ++type) {
            if (type == (uint32_t)migrate_type ||
                type == (uint32_t)EDGE_PAGE_MIGRATE_CMA)
                continue;
            fallback[fallback_count++] = (edge_page_migrate_type_t)type;
        }
    }

    for (uint32_t node_pass = 0;
         node_pass < (allow_node_fallback ? 2u : 1u); ++node_pass) {
        int exact_node = node_pass == 0u;
        for (zone = (int)highest_zone; zone >= EDGE_PAGE_ZONE_DMA; --zone) {
            for (uint32_t type_index = 0;
                 type_index < fallback_count; ++type_index) {
                edge_page_migrate_type_t source_type =
                    fallback[type_index];
                for (uint32_t order = requested_order;
                     order <= EDGE_PAGE_ALLOCATOR_ORDER_MAX; ++order) {
                    uint32_t index = edge_page_find_free_block_locked(
                        allocator, (edge_page_zone_t)zone, source_type,
                        order, numa_node, exact_node);
                    if (index == EDGE_PAGE_INDEX_NONE) continue;
                    edge_page_list_remove(allocator, index);
                    while (order > requested_order) {
                        uint32_t buddy;
                        --order;
                        buddy = index + (1u << order);
                        edge_page_list_insert(allocator, buddy, order);
                    }
                    for (uint32_t offset = 0;
                         offset < (1u << requested_order); ++offset) {
                        edge_page_metadata_t *page =
                            &allocator->pages[index + offset];
                        page->flags = 0;
                        page->order = 0;
                        page->references = 1u;
                        page->mappings = 0;
                        page->compound_head = EDGE_PAGE_INDEX_NONE;
                        page->cgroup_owner = EDGE_PAGE_CGROUP_NONE;
                        page->migrate_type = (uint8_t)migrate_type;
                        page->next = EDGE_PAGE_INDEX_NONE;
                        page->previous = EDGE_PAGE_INDEX_NONE;
                    }
                    allocator->free_pages -= 1u << requested_order;
                    *index_out = index;
                    return 0;
                }
            }
        }
    }
    return -1;
}

static uint32_t edge_page_drain_cpu_locked(
    edge_page_allocator_t *allocator, uint32_t cpu_id) {
    uint32_t drained = 0;

    if (cpu_id >= EDGE_PAGE_CPU_MAX) return 0;
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone) {
        uint8_t *count = &allocator->cpu_cache_count[cpu_id][zone];
        while (*count) {
            uint32_t index = allocator->cpu_cache[cpu_id][zone][--*count];
            edge_page_free_block_locked(allocator, index, 0u);
            ++drained;
        }
    }
    return drained;
}

static uint32_t edge_page_drain_all_locked(
    edge_page_allocator_t *allocator) {
    uint32_t drained = 0;

    for (uint32_t cpu = 0; cpu < EDGE_PAGE_CPU_MAX; ++cpu)
        drained += edge_page_drain_cpu_locked(allocator, cpu);
    return drained;
}

uint64_t edge_page_allocator_allocate(edge_page_allocator_t *allocator,
                                      uint32_t page_count,
                                      edge_page_zone_t highest_zone) {
    return edge_page_allocator_allocate_typed(
        allocator, page_count, highest_zone, 0u,
        EDGE_PAGE_MIGRATE_UNMOVABLE, 1);
}

uint64_t edge_page_allocator_allocate_typed(
    edge_page_allocator_t *allocator, uint32_t page_count,
    edge_page_zone_t highest_zone, uint8_t numa_node,
    edge_page_migrate_type_t migrate_type, int allow_node_fallback) {
    uint32_t allocation_pages = 1u;
    uint32_t order = 0;
    uint32_t index;

    if (!allocator || !allocator->initialized || !page_count ||
        highest_zone >= EDGE_PAGE_ZONE_COUNT ||
        migrate_type >= EDGE_PAGE_MIGRATE_COUNT)
        return 0;
    while (allocation_pages < page_count) {
        if (order >= EDGE_PAGE_ALLOCATOR_ORDER_MAX) return 0;
        allocation_pages <<= 1;
        ++order;
    }
    edge_page_lock(allocator);
    if (edge_page_allocate_order_locked(
            allocator, order, highest_zone, numa_node, migrate_type,
            allow_node_fallback, &index) < 0) {
        if (!edge_page_drain_all_locked(allocator) ||
            edge_page_allocate_order_locked(
                allocator, order, highest_zone, numa_node, migrate_type,
                allow_node_fallback, &index) < 0) {
            edge_page_reclaim_callback_t reclaim = allocator->reclaim;
            void *reclaim_context = allocator->reclaim_context;
            uint32_t reclaimed = 0;

            if (reclaim && !allocator->reclaim_active) {
                allocator->reclaim_active = 1u;
                edge_page_unlock(allocator);
                reclaimed = reclaim(
                    reclaim_context, allocation_pages,
                    EDGE_PAGE_PRESSURE_MINIMUM);
                edge_page_lock(allocator);
                allocator->reclaim_active = 0u;
            }
            if (reclaimed)
                (void)edge_page_drain_all_locked(allocator);
            if (!reclaimed ||
                edge_page_allocate_order_locked(
                    allocator, order, highest_zone, numa_node,
                    migrate_type, allow_node_fallback, &index) < 0) {
                ++allocator->allocation_failures;
                edge_page_unlock(allocator);
                return 0;
            }
        }
    }
    allocator->free_zone_pages[allocator->pages[index].zone] -=
        allocation_pages;
    for (uint32_t offset = page_count; offset < allocation_pages; ++offset) {
        edge_page_metadata_t *page = &allocator->pages[index + offset];
        page->references = 0;
        edge_page_free_block_locked(allocator, index + offset, 0u);
        ++allocator->free_pages;
        ++allocator->free_zone_pages[page->zone];
    }
    if (page_count > 1u) {
        allocator->pages[index].flags |= EDGE_PAGE_FLAG_COMPOUND_HEAD;
        allocator->pages[index].compound_head = index;
        for (uint32_t offset = 1; offset < page_count; ++offset) {
            allocator->pages[index + offset].flags |=
                EDGE_PAGE_FLAG_COMPOUND_TAIL;
            allocator->pages[index + offset].compound_head = index;
        }
    }
    allocator->allocated_pages += page_count;
    edge_page_unlock(allocator);
    return allocator->base + (uint64_t)index * EDGE_PAGE_SIZE;
}

uint64_t edge_page_allocator_allocate_cma(
    edge_page_allocator_t *allocator, uint32_t page_count,
    edge_page_zone_t highest_zone, uint8_t numa_node,
    int allow_node_fallback) {
    return edge_page_allocator_allocate_typed(
        allocator, page_count, highest_zone, numa_node,
        EDGE_PAGE_MIGRATE_CMA, allow_node_fallback);
}

uint64_t edge_page_allocator_allocate_local(
    edge_page_allocator_t *allocator, uint32_t cpu_id,
    edge_page_zone_t highest_zone) {
    uint32_t index = EDGE_PAGE_INDEX_NONE;
    int from_cpu_cache = 0;

    if (!allocator || !allocator->initialized ||
        cpu_id >= EDGE_PAGE_CPU_MAX || highest_zone >= EDGE_PAGE_ZONE_COUNT)
        return edge_page_allocator_allocate(allocator, 1u, highest_zone);
    edge_page_lock(allocator);
    for (int zone = (int)highest_zone; zone >= EDGE_PAGE_ZONE_DMA; --zone) {
        uint8_t *count = &allocator->cpu_cache_count[cpu_id][zone];
        if (!*count) continue;
        index = allocator->cpu_cache[cpu_id][zone][--*count];
        from_cpu_cache = 1;
        break;
    }
    if (index == EDGE_PAGE_INDEX_NONE &&
        edge_page_allocate_order_locked(
            allocator, 0u, highest_zone, 0u,
            EDGE_PAGE_MIGRATE_UNMOVABLE, 1, &index) < 0) {
        if (!edge_page_drain_all_locked(allocator) ||
            edge_page_allocate_order_locked(
                allocator, 0u, highest_zone, 0u,
                EDGE_PAGE_MIGRATE_UNMOVABLE, 1, &index) < 0) {
            edge_page_reclaim_callback_t reclaim = allocator->reclaim;
            void *reclaim_context = allocator->reclaim_context;
            uint32_t reclaimed = 0;

            if (reclaim && !allocator->reclaim_active) {
                allocator->reclaim_active = 1u;
                edge_page_unlock(allocator);
                reclaimed = reclaim(
                    reclaim_context, 1u,
                    EDGE_PAGE_PRESSURE_MINIMUM);
                edge_page_lock(allocator);
                allocator->reclaim_active = 0u;
            }
            if (reclaimed)
                (void)edge_page_drain_all_locked(allocator);
            if (!reclaimed ||
                edge_page_allocate_order_locked(
                    allocator, 0u, highest_zone, 0u,
                    EDGE_PAGE_MIGRATE_UNMOVABLE, 1, &index) < 0) {
                ++allocator->allocation_failures;
                edge_page_unlock(allocator);
                return 0;
            }
        }
    }
    if (from_cpu_cache) --allocator->free_pages;
    --allocator->free_zone_pages[allocator->pages[index].zone];
    allocator->pages[index].flags = 0;
    allocator->pages[index].references = 1u;
    allocator->pages[index].mappings = 0;
    allocator->pages[index].compound_head = EDGE_PAGE_INDEX_NONE;
    allocator->pages[index].cgroup_owner = EDGE_PAGE_CGROUP_NONE;
    allocator->pages[index].migrate_type = EDGE_PAGE_MIGRATE_UNMOVABLE;
    ++allocator->allocated_pages;
    edge_page_unlock(allocator);
    return allocator->base + (uint64_t)index * EDGE_PAGE_SIZE;
}

static int edge_page_claim_locked(edge_page_allocator_t *allocator,
                                  uint32_t target) {
    edge_page_metadata_t *target_page = &allocator->pages[target];

    if (target_page->flags & EDGE_PAGE_FLAG_RESERVED) return -1;
    if (target_page->references) {
        if (target_page->references == UINT32_MAX) return -1;
        ++target_page->references;
        return 0;
    }
    for (uint32_t cpu = 0; cpu < EDGE_PAGE_CPU_MAX; ++cpu) {
        uint8_t *count = &allocator->cpu_cache_count[cpu][target_page->zone];
        for (uint32_t slot = 0; slot < *count; ++slot) {
            if (allocator->cpu_cache[cpu][target_page->zone][slot] != target)
                continue;
            allocator->cpu_cache[cpu][target_page->zone][slot] =
                allocator->cpu_cache[cpu][target_page->zone][--*count];
            target_page->flags = 0;
            target_page->order = 0;
            target_page->references = 1u;
            target_page->mappings = 0;
            target_page->compound_head = EDGE_PAGE_INDEX_NONE;
            target_page->cgroup_owner = EDGE_PAGE_CGROUP_NONE;
            --allocator->free_pages;
            --allocator->free_zone_pages[target_page->zone];
            return 0;
        }
    }
    for (uint32_t order = 0;
         order <= EDGE_PAGE_ALLOCATOR_ORDER_MAX; ++order) {
        uint32_t mask = (1u << order) - 1u;
        uint32_t block = target & ~mask;
        edge_page_metadata_t *head;

        if (block >= allocator->page_count) continue;
        head = &allocator->pages[block];
        if (!(head->flags & EDGE_PAGE_FLAG_FREE) || head->order != order)
            continue;
        edge_page_list_remove(allocator, block);
        while (order) {
            uint32_t half;
            --order;
            half = 1u << order;
            if (target < block + half) {
                edge_page_list_insert(allocator, block + half, order);
            } else {
                edge_page_list_insert(allocator, block, order);
                block += half;
            }
        }
        target_page->flags = 0;
        target_page->order = 0;
        target_page->references = 1u;
        target_page->mappings = 0;
        target_page->compound_head = EDGE_PAGE_INDEX_NONE;
        target_page->cgroup_owner = EDGE_PAGE_CGROUP_NONE;
        --allocator->free_pages;
        --allocator->free_zone_pages[target_page->zone];
        return 0;
    }
    return -1;
}

int edge_page_allocator_retain(edge_page_allocator_t *allocator,
                               uint64_t physical) {
    uint32_t index;
    int result = -1;

    if (!edge_page_allocator_contains(allocator, physical, &index)) return -1;
    edge_page_lock(allocator);
    if (!(allocator->pages[index].flags &
          (EDGE_PAGE_FLAG_FREE | EDGE_PAGE_FLAG_RESERVED)) &&
        allocator->pages[index].references &&
        allocator->pages[index].references != UINT32_MAX) {
        ++allocator->pages[index].references;
        result = 0;
    }
    edge_page_unlock(allocator);
    return result;
}

int edge_page_allocator_recover(edge_page_allocator_t *allocator,
                                uint64_t physical) {
    uint32_t index;
    int result;
    int newly_allocated;

    if (!edge_page_allocator_contains(allocator, physical, &index)) return -1;
    edge_page_lock(allocator);
    newly_allocated = allocator->pages[index].references == 0u;
    result = edge_page_claim_locked(allocator, index);
    if (result == 0 && newly_allocated) ++allocator->allocated_pages;
    else if (result < 0) ++allocator->allocation_failures;
    edge_page_unlock(allocator);
    return result;
}

int edge_page_allocator_release(edge_page_allocator_t *allocator,
                                uint64_t physical) {
    uint32_t index;
    edge_page_metadata_t *page;
    int freed = 0;

    if (!edge_page_allocator_contains(allocator, physical, &index)) return -1;
    edge_page_lock(allocator);
    page = &allocator->pages[index];
    if ((page->flags & (EDGE_PAGE_FLAG_FREE | EDGE_PAGE_FLAG_RESERVED)) ||
        !page->references) {
        edge_page_unlock(allocator);
        return -1;
    }
    --page->references;
    if (!page->references) {
        if (page->mappings) {
            ++page->references;
            edge_page_unlock(allocator);
            return -1;
        }
        edge_page_free_block_locked(allocator, index, 0u);
        ++allocator->free_pages;
        ++allocator->free_zone_pages[page->zone];
        ++allocator->freed_pages;
        freed = 1;
    }
    edge_page_unlock(allocator);
    return freed;
}

int edge_page_allocator_release_local(edge_page_allocator_t *allocator,
                                      uint64_t physical,
                                      uint32_t cpu_id) {
    uint32_t index;
    edge_page_metadata_t *page;
    uint8_t *count;

    if (cpu_id >= EDGE_PAGE_CPU_MAX ||
        !edge_page_allocator_contains(allocator, physical, &index))
        return edge_page_allocator_release(allocator, physical);
    edge_page_lock(allocator);
    page = &allocator->pages[index];
    if ((page->flags & (EDGE_PAGE_FLAG_FREE | EDGE_PAGE_FLAG_RESERVED)) ||
        !page->references) {
        edge_page_unlock(allocator);
        return -1;
    }
    --page->references;
    if (page->references) {
        edge_page_unlock(allocator);
        return 0;
    }
    if (page->mappings) {
        ++page->references;
        edge_page_unlock(allocator);
        return -1;
    }
    page->flags = 0;
    page->compound_head = EDGE_PAGE_INDEX_NONE;
    count = &allocator->cpu_cache_count[cpu_id][page->zone];
    if (page->migrate_type == EDGE_PAGE_MIGRATE_UNMOVABLE &&
        *count < EDGE_PAGE_CPU_CACHE_CAPACITY) {
        allocator->cpu_cache[cpu_id][page->zone][(*count)++] = index;
    } else {
        edge_page_free_block_locked(allocator, index, 0u);
    }
    ++allocator->free_pages;
    ++allocator->free_zone_pages[page->zone];
    ++allocator->freed_pages;
    edge_page_unlock(allocator);
    return 1;
}

uint32_t edge_page_allocator_references(
    const edge_page_allocator_t *allocator, uint64_t physical) {
    edge_page_allocator_t *mutable_allocator =
        (edge_page_allocator_t *)(uintptr_t)allocator;
    uint32_t index;
    uint32_t references;

    if (!edge_page_allocator_contains(allocator, physical, &index)) return 0;
    edge_page_lock(mutable_allocator);
    references = allocator->pages[index].references;
    edge_page_unlock(mutable_allocator);
    return references;
}

int edge_page_allocator_mapping_acquire(
    edge_page_allocator_t *allocator, uint64_t physical,
    uint16_t cgroup_owner, uint32_t *previous_mappings) {
    uint32_t index;
    edge_page_metadata_t *page;

    if (!edge_page_allocator_contains(allocator, physical, &index)) return -1;
    edge_page_lock(allocator);
    page = &allocator->pages[index];
    if ((page->flags & (EDGE_PAGE_FLAG_FREE | EDGE_PAGE_FLAG_RESERVED)) ||
        !page->references || page->mappings == UINT32_MAX) {
        edge_page_unlock(allocator);
        return -1;
    }
    if (previous_mappings) *previous_mappings = page->mappings;
    if (!page->mappings) page->cgroup_owner = cgroup_owner;
    ++page->mappings;
    edge_page_unlock(allocator);
    return 0;
}

int edge_page_allocator_mapping_release(
    edge_page_allocator_t *allocator, uint64_t physical,
    uint16_t *released_cgroup_owner, uint32_t *remaining_mappings) {
    uint32_t index;
    edge_page_metadata_t *page;

    if (!edge_page_allocator_contains(allocator, physical, &index)) return -1;
    edge_page_lock(allocator);
    page = &allocator->pages[index];
    if (!page->mappings) {
        edge_page_unlock(allocator);
        return -1;
    }
    --page->mappings;
    if (remaining_mappings) *remaining_mappings = page->mappings;
    if (!page->mappings) {
        if (released_cgroup_owner)
            *released_cgroup_owner = page->cgroup_owner;
        page->cgroup_owner = EDGE_PAGE_CGROUP_NONE;
    } else if (released_cgroup_owner) {
        *released_cgroup_owner = EDGE_PAGE_CGROUP_NONE;
    }
    edge_page_unlock(allocator);
    return 0;
}

uint32_t edge_page_allocator_mappings(
    const edge_page_allocator_t *allocator, uint64_t physical) {
    edge_page_allocator_t *mutable_allocator =
        (edge_page_allocator_t *)(uintptr_t)allocator;
    uint32_t index;
    uint32_t mappings;

    if (!edge_page_allocator_contains(allocator, physical, &index)) return 0;
    edge_page_lock(mutable_allocator);
    mappings = allocator->pages[index].mappings;
    edge_page_unlock(mutable_allocator);
    return mappings;
}

int edge_page_allocator_mapping_owner(
    const edge_page_allocator_t *allocator, uint64_t physical,
    uint16_t *cgroup_owner_out) {
    edge_page_allocator_t *mutable_allocator =
        (edge_page_allocator_t *)(uintptr_t)allocator;
    uint32_t index;
    uint16_t owner;

    if (!cgroup_owner_out ||
        !edge_page_allocator_contains(allocator, physical, &index))
        return -1;
    edge_page_lock(mutable_allocator);
    if (!allocator->pages[index].mappings ||
        allocator->pages[index].cgroup_owner == EDGE_PAGE_CGROUP_NONE) {
        edge_page_unlock(mutable_allocator);
        return -1;
    }
    owner = allocator->pages[index].cgroup_owner;
    edge_page_unlock(mutable_allocator);
    *cgroup_owner_out = owner;
    return 0;
}

uint64_t edge_page_allocator_free_bytes(
    const edge_page_allocator_t *allocator) {
    edge_page_allocator_t *mutable_allocator =
        (edge_page_allocator_t *)(uintptr_t)allocator;
    uint64_t bytes;

    if (!allocator || !allocator->initialized) return 0;
    edge_page_lock(mutable_allocator);
    bytes = (uint64_t)allocator->free_pages * EDGE_PAGE_SIZE;
    edge_page_unlock(mutable_allocator);
    return bytes;
}

uint32_t edge_page_allocator_referenced_pages(
    const edge_page_allocator_t *allocator, uint64_t *reference_total) {
    edge_page_allocator_t *mutable_allocator =
        (edge_page_allocator_t *)(uintptr_t)allocator;
    uint64_t references = 0;
    uint32_t pages = 0;

    if (reference_total) *reference_total = 0;
    if (!allocator || !allocator->initialized) return 0;
    edge_page_lock(mutable_allocator);
    for (uint32_t index = 0; index < allocator->page_count; ++index) {
        uint32_t count = allocator->pages[index].references;
        if (!count) continue;
        ++pages;
        references += count;
    }
    edge_page_unlock(mutable_allocator);
    if (reference_total) *reference_total = references;
    return pages;
}

edge_page_pressure_t edge_page_allocator_zone_pressure(
    const edge_page_allocator_t *allocator, edge_page_zone_t zone) {
    edge_page_allocator_t *mutable_allocator =
        (edge_page_allocator_t *)(uintptr_t)allocator;
    edge_page_pressure_t pressure = EDGE_PAGE_PRESSURE_NONE;
    uint32_t free_pages;

    if (!allocator || !allocator->initialized ||
        zone >= EDGE_PAGE_ZONE_COUNT)
        return EDGE_PAGE_PRESSURE_MINIMUM;
    edge_page_lock(mutable_allocator);
    free_pages = allocator->free_zone_pages[zone];
    if (free_pages <= allocator->watermark_min[zone])
        pressure = EDGE_PAGE_PRESSURE_MINIMUM;
    else if (free_pages <= allocator->watermark_low[zone])
        pressure = EDGE_PAGE_PRESSURE_LOW;
    edge_page_unlock(mutable_allocator);
    return pressure;
}

uint32_t edge_page_allocator_drain_cpu(
    edge_page_allocator_t *allocator, uint32_t cpu_id) {
    uint32_t drained;

    if (!allocator || !allocator->initialized || cpu_id >= EDGE_PAGE_CPU_MAX)
        return 0;
    edge_page_lock(allocator);
    drained = edge_page_drain_cpu_locked(allocator, cpu_id);
    edge_page_unlock(allocator);
    return drained;
}

int edge_page_allocator_snapshot(
    const edge_page_allocator_t *allocator,
    edge_page_allocator_snapshot_t *snapshot) {
    edge_page_allocator_t *mutable_allocator =
        (edge_page_allocator_t *)(uintptr_t)allocator;

    if (!allocator || !allocator->initialized || !snapshot) return -1;
    edge_page_lock(mutable_allocator);
    memset(snapshot, 0, sizeof(*snapshot));
    for (uint32_t zone = 0; zone < EDGE_PAGE_ZONE_COUNT; ++zone) {
        snapshot->managed_pages[zone] =
            allocator->managed_zone_pages[zone];
        snapshot->free_pages[zone] = allocator->free_zone_pages[zone];
        snapshot->watermark_min[zone] = allocator->watermark_min[zone];
        snapshot->watermark_low[zone] = allocator->watermark_low[zone];
        snapshot->watermark_high[zone] = allocator->watermark_high[zone];
        for (uint32_t migrate = 0;
             migrate < EDGE_PAGE_MIGRATE_COUNT; ++migrate)
            for (uint32_t order = 0;
                 order <= EDGE_PAGE_ALLOCATOR_ORDER_MAX; ++order)
                snapshot->free_blocks[zone][migrate][order] =
                    allocator->free_count[zone][migrate][order];
    }
    snapshot->allocated_pages = allocator->allocated_pages;
    snapshot->freed_pages = allocator->freed_pages;
    snapshot->allocation_failures = allocator->allocation_failures;
    snapshot->buddy_exact = 1u;
    edge_page_unlock(mutable_allocator);
    return 0;
}

void edge_page_allocator_set_reclaim(
    edge_page_allocator_t *allocator,
    edge_page_reclaim_callback_t reclaim, void *context) {
    if (!allocator) return;
    edge_page_lock(allocator);
    allocator->reclaim = reclaim;
    allocator->reclaim_context = context;
    edge_page_unlock(allocator);
}

int edge_page_allocator_set_migrate_type(
    edge_page_allocator_t *allocator, uint64_t physical,
    uint32_t page_count, edge_page_migrate_type_t migrate_type) {
    uint32_t first;
    uint32_t claimed = 0;

    if (!allocator || !allocator->initialized || !page_count ||
        migrate_type >= EDGE_PAGE_MIGRATE_COUNT ||
        !edge_page_allocator_contains(allocator, physical, &first) ||
        page_count > allocator->page_count - first)
        return -1;

    edge_page_lock(allocator);
    (void)edge_page_drain_all_locked(allocator);
    for (uint32_t offset = 0; offset < page_count; ++offset) {
        edge_page_metadata_t *page = &allocator->pages[first + offset];
        if ((page->flags & EDGE_PAGE_FLAG_RESERVED) ||
            page->references || page->mappings) {
            edge_page_unlock(allocator);
            return -1;
        }
    }
    for (uint32_t offset = 0; offset < page_count; ++offset) {
        edge_page_metadata_t *page = &allocator->pages[first + offset];
        page->reserved[0] = page->migrate_type;
    }

    for (; claimed < page_count; ++claimed) {
        if (edge_page_claim_locked(allocator, first + claimed) < 0)
            break;
    }
    if (claimed != page_count) {
        for (uint32_t offset = 0; offset < claimed; ++offset) {
            edge_page_metadata_t *page = &allocator->pages[first + offset];
            page->migrate_type = page->reserved[0];
            page->reserved[0] = 0;
            page->references = 0;
            edge_page_free_block_locked(allocator, first + offset, 0u);
            ++allocator->free_pages;
            ++allocator->free_zone_pages[page->zone];
        }
        for (uint32_t offset = claimed; offset < page_count; ++offset)
            allocator->pages[first + offset].reserved[0] = 0;
        edge_page_unlock(allocator);
        return -1;
    }

    for (uint32_t offset = 0; offset < page_count; ++offset) {
        edge_page_metadata_t *page = &allocator->pages[first + offset];
        page->migrate_type = (uint8_t)migrate_type;
        page->reserved[0] = 0;
        page->references = 0;
        page->flags = 0;
        edge_page_free_block_locked(allocator, first + offset, 0u);
        ++allocator->free_pages;
        ++allocator->free_zone_pages[page->zone];
    }
    edge_page_unlock(allocator);
    return 0;
}
