/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD Driver Bridge allocator. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"

#define TEST_PAGE_SIZE 4096u

typedef struct {
    uint64_t allocation_calls;
    uint64_t release_calls;
    uint64_t allocated_pages;
    uint64_t released_pages;
    int fail_next_allocation;
    int wait_calls;
} test_backend_t;

static void *test_allocate_pages(uint64_t pages, void *context) {
    test_backend_t *backend = context;
    void *memory = 0;
    backend->allocation_calls++;
    if (backend->fail_next_allocation) {
        backend->fail_next_allocation = 0;
        return 0;
    }
    if (pages > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
                       (size_t)pages * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0xa5, (size_t)pages * TEST_PAGE_SIZE);
    backend->allocated_pages += pages;
    return memory;
}

static void test_release_pages(void *base, uint64_t pages, void *context) {
    test_backend_t *backend = context;
    backend->release_calls++;
    backend->released_pages += pages;
    free(base);
}

static int test_wait_for_memory(void *context) {
    test_backend_t *backend = context;
    backend->wait_calls++;
    return 1;
}

static void test_basic_allocation(test_backend_t *backend) {
    bsd_allocator_stats_t stats;
    void *minimum = bsd_kmalloc(0, BSD_M_NOWAIT);
    uint8_t *first = bsd_kmalloc(31, BSD_M_NOWAIT | BSD_M_ZERO);
    uint8_t *second = bsd_kmalloc(1000, BSD_M_NOWAIT);

    assert(minimum != 0);
    assert(first != 0);
    assert(second != 0);
    assert(((uintptr_t)first & 15u) == 0);
    assert(((uintptr_t)second & 15u) == 0);
    for (size_t index = 0; index < 31; ++index) assert(first[index] == 0);
    assert(bsd_kmalloc_usable_size(first) >= 31);
    assert(bsd_kmalloc_usable_size(second) >= 1000);

    memset(first, 0x5a, 31);
    bsd_allocator_get_stats(&stats);
    assert(stats.bytes_in_use == 1032);
    assert(stats.allocation_count == 3);
    assert(stats.active_arenas == 1);

    bsd_kfree(minimum);
    bsd_kfree(first);
    bsd_kfree(second);
    bsd_allocator_get_stats(&stats);
    assert(stats.bytes_in_use == 0);
    assert(stats.free_count == 3);
    assert(stats.active_arenas == 0);
    assert(backend->release_calls == 1);
}

static void test_split_and_coalesce(test_backend_t *backend) {
    void *allocations[128];
    uint64_t releases_before = backend->release_calls;

    for (size_t index = 0; index < 128; ++index) {
        allocations[index] = bsd_kmalloc(128 + index, BSD_M_NOWAIT);
        assert(allocations[index] != 0);
    }
    for (size_t index = 0; index < 128; index += 2)
        bsd_kfree(allocations[index]);
    for (size_t index = 1; index < 128; index += 2)
        bsd_kfree(allocations[index]);
    assert(backend->release_calls > releases_before);
}

static void test_reallocation(void) {
    uint8_t *allocation = bsd_kmalloc(64, BSD_M_NOWAIT);
    assert(allocation != 0);
    for (size_t index = 0; index < 64; ++index)
        allocation[index] = (uint8_t)index;

    allocation = bsd_krealloc(allocation, 4096, BSD_M_NOWAIT | BSD_M_ZERO);
    assert(allocation != 0);
    for (size_t index = 0; index < 64; ++index)
        assert(allocation[index] == (uint8_t)index);
    for (size_t index = 64; index < 4096; ++index)
        assert(allocation[index] == 0);

    allocation = bsd_krealloc(allocation, 32, BSD_M_NOWAIT);
    assert(allocation != 0);
    for (size_t index = 0; index < 32; ++index)
        assert(allocation[index] == (uint8_t)index);
    bsd_kfree(allocation);
}

static void test_large_and_overflow_allocations(test_backend_t *backend) {
    bsd_allocator_stats_t stats;
    void *waited;
    void *large = bsd_kmalloc(256 * 1024, BSD_M_NOWAIT);
    assert(large != 0);
    assert(bsd_kmalloc_usable_size(large) >= 256 * 1024);
    bsd_kfree(large);

    assert(bsd_kmallocarray(SIZE_MAX, 2, BSD_M_NOWAIT) == 0);
    backend->fail_next_allocation = 1;
    waited = bsd_kmalloc(64, BSD_M_WAITOK);
    assert(waited != 0);
    assert(backend->wait_calls == 1);

    bsd_allocator_get_stats(&stats);
    assert(stats.failed_allocation_count >= 1);
    bsd_kfree(waited);
}

int main(void) {
    test_backend_t backend;
    bsd_allocator_ops_t ops;
    bsd_allocator_stats_t stats;

    memset(&backend, 0, sizeof(backend));
    memset(&ops, 0, sizeof(ops));
    ops.allocate_pages = test_allocate_pages;
    ops.release_pages = test_release_pages;
    ops.wait_for_memory = test_wait_for_memory;
    ops.context = &backend;

    assert(bsd_allocator_initialize(&ops) == 0);
    assert(bsd_allocator_is_initialized());
    test_basic_allocation(&backend);
    test_split_and_coalesce(&backend);
    test_reallocation();
    test_large_and_overflow_allocations(&backend);

    bsd_allocator_get_stats(&stats);
    assert(stats.bytes_in_use == 0);
    assert(stats.active_arenas == 0);
    assert(backend.allocated_pages == backend.released_pages);
    bsd_kfree(0);
    printf("bsd_bridge_allocator_unit: PASS\n");
    return 0;
}
