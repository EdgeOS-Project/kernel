/* SPDX-License-Identifier: MPL-2.0 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mm/page_allocator.h"

static int failures;

typedef struct reclaim_test_context {
    edge_page_allocator_t *allocator;
    uint64_t page;
    uint32_t calls;
} reclaim_test_context_t;

static uint32_t reclaim_one_page(void *opaque, uint32_t target_pages,
                                 edge_page_pressure_t pressure) {
    reclaim_test_context_t *context =
        (reclaim_test_context_t *)opaque;
    if (!context || !context->allocator || !context->page ||
        !target_pages || pressure != EDGE_PAGE_PRESSURE_MINIMUM)
        return 0;
    ++context->calls;
    if (edge_page_allocator_release_local(
            context->allocator, context->page, 2u) != 1)
        return 0;
    context->page = 0;
    return 1u;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
}

int main(void) {
    enum { PAGE_COUNT = 4096, RESERVED_PAGES = 17 };
    edge_page_allocator_t allocator;
    uint64_t metadata_bytes =
        edge_page_allocator_metadata_bytes(PAGE_COUNT);
    void *metadata = calloc(1, (size_t)metadata_bytes);
    uint64_t first;
    uint64_t run;
    uint64_t cma_base;
    uint64_t cma_run;
    uint64_t movable;
    uint64_t recovered;
    uint16_t owner = EDGE_PAGE_CGROUP_NONE;
    uint16_t observed_owner = EDGE_PAGE_CGROUP_NONE;
    uint32_t previous = UINT32_MAX;
    uint32_t remaining = UINT32_MAX;
    uint64_t local_pages[40];
    edge_page_allocator_t sparse_allocator;
    void *sparse_metadata = calloc(1, (size_t)metadata_bytes);
    edge_page_allocator_t isolated_allocator;
    void *isolated_metadata = calloc(1, (size_t)metadata_bytes);
    edge_page_allocator_t pressure_allocator;
    uint64_t pressure_metadata_bytes =
        edge_page_allocator_metadata_bytes(8u);
    void *pressure_metadata = calloc(
        1, (size_t)pressure_metadata_bytes);
    uint64_t pressure_pages[8] = {0};
    reclaim_test_context_t reclaim_context = {0};

    expect_true("metadata allocated", metadata != 0);
    if (!metadata) return 1;
    expect_true("allocator initialized",
                edge_page_allocator_initialize(
                    &allocator, metadata, metadata_bytes,
                    0x100000000ull, PAGE_COUNT, RESERVED_PAGES) == 0);
    expect_true("reserved prefix excluded",
                edge_page_allocator_free_bytes(&allocator) ==
                    (uint64_t)(PAGE_COUNT - RESERVED_PAGES) * EDGE_PAGE_SIZE);

    first = edge_page_allocator_allocate(
        &allocator, 1u, EDGE_PAGE_ZONE_NORMAL);
    expect_true("single page allocated", first != 0);
    expect_true("single page reference",
                edge_page_allocator_references(&allocator, first) == 1u);
    expect_true("retain page",
                edge_page_allocator_retain(&allocator, first) == 0 &&
                edge_page_allocator_references(&allocator, first) == 2u);
    expect_true("release retained page",
                edge_page_allocator_release(&allocator, first) == 0 &&
                edge_page_allocator_references(&allocator, first) == 1u);

    expect_true("first mapping",
                edge_page_allocator_mapping_acquire(
                    &allocator, first, 7u, &previous) == 0 &&
                previous == 0u);
    expect_true("shared mapping",
                edge_page_allocator_mapping_acquire(
                    &allocator, first, 9u, &previous) == 0 &&
                previous == 1u &&
                edge_page_allocator_mappings(&allocator, first) == 2u);
    expect_true("first mapping owns shared page",
                edge_page_allocator_mapping_owner(
                    &allocator, first, &observed_owner) == 0 &&
                observed_owner == 7u);
    expect_true("mapping owner retained",
                edge_page_allocator_mapping_release(
                    &allocator, first, &owner, &remaining) == 0 &&
                remaining == 1u && owner == EDGE_PAGE_CGROUP_NONE);
    expect_true("last mapping returns owner",
                edge_page_allocator_mapping_release(
                    &allocator, first, &owner, &remaining) == 0 &&
                remaining == 0u && owner == 7u);
    expect_true("unmapped page has no owner",
                edge_page_allocator_mapping_owner(
                    &allocator, first, &observed_owner) < 0);
    expect_true("single page freed",
                edge_page_allocator_release(&allocator, first) == 1);

    run = edge_page_allocator_allocate(
        &allocator, 37u, EDGE_PAGE_ZONE_NORMAL);
    expect_true("exact contiguous run allocated", run != 0);
    expect_true("compound head recorded",
                allocator.pages[(run - allocator.base) / EDGE_PAGE_SIZE]
                        .compound_head ==
                    (run - allocator.base) / EDGE_PAGE_SIZE);
    for (uint32_t index = 0; index < 37u; ++index)
        expect_true("contiguous page referenced",
                    edge_page_allocator_references(
                        &allocator,
                        run + (uint64_t)index * EDGE_PAGE_SIZE) == 1u);
    for (uint32_t index = 0; index < 37u; ++index)
        expect_true("contiguous page released",
                    edge_page_allocator_release(
                        &allocator,
                        run + (uint64_t)index * EDGE_PAGE_SIZE) == 1);
    expect_true("buddy coalescing restores capacity",
                edge_page_allocator_free_bytes(&allocator) ==
                    (uint64_t)(PAGE_COUNT - RESERVED_PAGES) * EDGE_PAGE_SIZE);

    cma_base = allocator.base + 2048u * EDGE_PAGE_SIZE;
    expect_true("free range converted to CMA",
                edge_page_allocator_set_migrate_type(
                    &allocator, cma_base, 128u,
                    EDGE_PAGE_MIGRATE_CMA) == 0);
    cma_run = edge_page_allocator_allocate_cma(
        &allocator, 37u, EDGE_PAGE_ZONE_NORMAL, 0u, 0);
    expect_true("exact CMA run allocated", cma_run != 0);
    for (uint32_t index = 0; index < 37u; ++index) {
        uint32_t page_index = (uint32_t)(
            (cma_run - allocator.base) / EDGE_PAGE_SIZE) + index;
        expect_true("CMA allocation remains isolated",
                    allocator.pages[page_index].migrate_type ==
                        EDGE_PAGE_MIGRATE_CMA);
        expect_true("CMA page released",
                    edge_page_allocator_release(
                        &allocator,
                        cma_run + (uint64_t)index * EDGE_PAGE_SIZE) == 1);
    }
    expect_true("CMA release restores capacity",
                edge_page_allocator_free_bytes(&allocator) ==
                    (uint64_t)(PAGE_COUNT - RESERVED_PAGES) * EDGE_PAGE_SIZE);

    movable = edge_page_allocator_allocate_typed(
        &allocator, 1u, EDGE_PAGE_ZONE_NORMAL, 0u,
        EDGE_PAGE_MIGRATE_MOVABLE, 0);
    expect_true("movable allocation succeeds", movable != 0);
    expect_true("movable allocation classified",
                allocator.pages[(movable - allocator.base) / EDGE_PAGE_SIZE]
                        .migrate_type == EDGE_PAGE_MIGRATE_MOVABLE);
    expect_true("movable page bypasses unmovable CPU cache",
                edge_page_allocator_release_local(
                    &allocator, movable, 2u) == 1);

    for (uint32_t index = 0; index < 40u; ++index) {
        local_pages[index] = edge_page_allocator_allocate_local(
            &allocator, 2u, EDGE_PAGE_ZONE_NORMAL);
        expect_true("local page allocated", local_pages[index] != 0);
    }
    for (uint32_t index = 0; index < 40u; ++index)
        expect_true("local page released",
                    edge_page_allocator_release_local(
                        &allocator, local_pages[index], 2u) == 1);
    expect_true("local cache keeps free accounting",
                edge_page_allocator_free_bytes(&allocator) ==
                    (uint64_t)(PAGE_COUNT - RESERVED_PAGES) * EDGE_PAGE_SIZE);
    expect_true("local cache drains into buddy",
                edge_page_allocator_drain_cpu(&allocator, 2u) ==
                    EDGE_PAGE_CPU_CACHE_CAPACITY);
    expect_true("healthy zone above low watermark",
                edge_page_allocator_zone_pressure(
                    &allocator, EDGE_PAGE_ZONE_NORMAL) ==
                    EDGE_PAGE_PRESSURE_NONE);

    recovered = 0x100000000ull +
        (uint64_t)(RESERVED_PAGES + 123u) * EDGE_PAGE_SIZE;
    expect_true("recover a specific free page",
                edge_page_allocator_recover(&allocator, recovered) == 0 &&
                edge_page_allocator_references(&allocator, recovered) == 1u);
    expect_true("recover retains live page",
                edge_page_allocator_recover(&allocator, recovered) == 0 &&
                edge_page_allocator_references(&allocator, recovered) == 2u);
    expect_true("recover release one reference",
                edge_page_allocator_release(&allocator, recovered) == 0);
    expect_true("recover release final reference",
                edge_page_allocator_release(&allocator, recovered) == 1);
    expect_true("reserved page cannot recover",
                edge_page_allocator_recover(
                    &allocator, 0x100000000ull) < 0);
    expect_true("double free rejected",
                edge_page_allocator_release(&allocator, recovered) < 0);

    expect_true("sparse allocator initialized reserved",
                sparse_metadata != 0 &&
                edge_page_allocator_initialize(
                    &sparse_allocator, sparse_metadata, metadata_bytes,
                    0x200000000ull, PAGE_COUNT, PAGE_COUNT) == 0 &&
                edge_page_allocator_free_bytes(&sparse_allocator) == 0u);
    expect_true("sparse range added",
                edge_page_allocator_add_range(
                    &sparse_allocator,
                    0x200000000ull + 100u * EDGE_PAGE_SIZE,
                    300u, 3u) == 0 &&
                edge_page_allocator_free_bytes(&sparse_allocator) ==
                    300u * EDGE_PAGE_SIZE);
    expect_true("overlapping sparse range rejected",
                edge_page_allocator_add_range(
                    &sparse_allocator,
                    0x200000000ull + 200u * EDGE_PAGE_SIZE,
                    10u, 3u) < 0);

    expect_true("isolated allocator initialized",
                isolated_metadata != 0 &&
                edge_page_allocator_initialize(
                    &isolated_allocator, isolated_metadata, metadata_bytes,
                    0x300000000ull, PAGE_COUNT, PAGE_COUNT) == 0);
    expect_true("node-local range added",
                edge_page_allocator_add_range(
                    &isolated_allocator, 0x300000000ull,
                    64u, 4u) == 0);
    expect_true("node-local allocation does not silently fall back",
                edge_page_allocator_allocate_typed(
                    &isolated_allocator, 1u, EDGE_PAGE_ZONE_NORMAL, 3u,
                    EDGE_PAGE_MIGRATE_UNMOVABLE, 0) == 0);
    first = edge_page_allocator_allocate_typed(
        &isolated_allocator, 1u, EDGE_PAGE_ZONE_NORMAL, 3u,
        EDGE_PAGE_MIGRATE_UNMOVABLE, 1);
    expect_true("node allocation may explicitly fall back", first != 0);
    expect_true("fallback preserves source NUMA node",
                isolated_allocator.pages[
                    (first - isolated_allocator.base) / EDGE_PAGE_SIZE]
                        .node == 4u);
    expect_true("node fallback page released",
                edge_page_allocator_release(
                    &isolated_allocator, first) == 1);
    expect_true("CMA-only range prepared",
                edge_page_allocator_set_migrate_type(
                    &isolated_allocator, 0x300000000ull,
                    64u, EDGE_PAGE_MIGRATE_CMA) == 0);
    expect_true("ordinary allocation cannot consume CMA reserve",
                edge_page_allocator_allocate(
                    &isolated_allocator, 1u,
                    EDGE_PAGE_ZONE_NORMAL) == 0);
    first = edge_page_allocator_allocate_cma(
        &isolated_allocator, 1u, EDGE_PAGE_ZONE_NORMAL, 4u, 0);
    expect_true("CMA allocation consumes CMA reserve", first != 0);
    expect_true("CMA reserve page released",
                edge_page_allocator_release(
                    &isolated_allocator, first) == 1);

    expect_true("pressure allocator initialized",
                pressure_metadata != 0 &&
                edge_page_allocator_initialize(
                    &pressure_allocator, pressure_metadata,
                    pressure_metadata_bytes, 0x400000000ull,
                    8u, 0u) == 0);
    for (uint32_t index = 0; index < 8u; ++index) {
        pressure_pages[index] = edge_page_allocator_allocate(
            &pressure_allocator, 1u, EDGE_PAGE_ZONE_NORMAL);
        expect_true("pressure page allocated",
                    pressure_pages[index] != 0);
    }
    reclaim_context.allocator = &pressure_allocator;
    reclaim_context.page = pressure_pages[0];
    edge_page_allocator_set_reclaim(
        &pressure_allocator, reclaim_one_page, &reclaim_context);
    first = edge_page_allocator_allocate_local(
        &pressure_allocator, 2u, EDGE_PAGE_ZONE_NORMAL);
    expect_true("local allocation drains reclaimed CPU cache",
                first == pressure_pages[0] &&
                reclaim_context.calls == 1u);
    for (uint32_t index = 1; index < 8u; ++index)
        (void)edge_page_allocator_release(
            &pressure_allocator, pressure_pages[index]);
    (void)edge_page_allocator_release(&pressure_allocator, first);

    free(metadata);
    free(sparse_metadata);
    free(isolated_metadata);
    free(pressure_metadata);
    if (failures) return 1;
    puts("page_allocator_unit: PASS");
    return 0;
}
