/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise real SquashFS allocation and cache code with immediate page reuse. */
#define EDGEOS_SQFS_HOST_TEST 1
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/fs/squashfs/squashfs_port.c"
#include "../../src/fs/squashfs/upstream/cache.c"

#define TEST_PAGES 32u
static _Alignas(4096) uint8_t arena[TEST_PAGES][4096];
static uint8_t allocated[TEST_PAGES];
static uint32_t allocation_calls;
static uint32_t free_calls;
static uint32_t replacement_pages;
static uint32_t disposed;

void *arch_vm_alloc_pages(uint64_t count) {
    ++allocation_calls;
    if (!count || count > TEST_PAGES) return NULL;
    for (uint32_t start = 0; start <= TEST_PAGES - count; ++start) {
        uint32_t offset;
        for (offset = 0; offset < count; ++offset)
            if (allocated[start + offset]) break;
        if (offset != count) continue;
        for (offset = 0; offset < count; ++offset)
            allocated[start + offset] = 1;
        return arena[start];
    }
    return NULL;
}

void arch_vm_free_page(void *page) {
    uintptr_t offset = (uintptr_t)page - (uintptr_t)arena;
    assert(offset < sizeof(arena) && offset % 4096u == 0);
    uint32_t index = (uint32_t)(offset / 4096u);
    assert(allocated[index]);
    allocated[index] = 0;
    ++free_calls;
    /* Model another CPU replacing the header before the free call returns. */
    memset(page, 0xa5, 4096u);
    ((edge_sqfs_allocation_t *)page)->pages = replacement_pages;
}

int64_t block_read_bytes(block_device_t *device, uint64_t offset,
                         void *buffer, uint32_t count) {
    (void)device;
    (void)offset;
    (void)buffer;
    (void)count;
    return -1;
}

static void assert_no_leaks(void) {
    for (uint32_t index = 0; index < TEST_PAGES; ++index)
        assert(!allocated[index]);
}

static void test_release(uint32_t poison, size_t bytes, uint32_t pages) {
    void *pointer = edge_sqfs_alloc(bytes);
    assert(pointer);
    replacement_pages = poison;
    free_calls = 0;
    edge_sqfs_free(pointer);
    assert(free_calls == pages);
    assert_no_leaks();
}

static void dispose_entry(void *entry) {
    assert(*(uint64_t *)entry == 0x12345678u);
    ++disposed;
}

static void test_cache_retry(void) {
    sqfs_cache cache = NULL;
    assert(sqfs_cache_init(&cache, sizeof(uint64_t), 1,
                           dispose_entry) == SQFS_OK);
    /* Zero is a legal cache key, including in a newly zeroed cache. */
    uint64_t *entry = sqfs_cache_get(&cache, 0);
    assert(!sqfs_cache_entry_valid(&cache, entry));
    sqfs_cache_put(&cache, entry);
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        entry = sqfs_cache_get(&cache, 0x4283);
        assert(!sqfs_cache_entry_valid(&cache, entry));
        /* A failed I/O or decode must leave a retryable miss. */
        sqfs_cache_put(&cache, entry);
    }
    entry = sqfs_cache_get(&cache, 0x4283);
    *entry = 0x12345678u;
    sqfs_cache_entry_mark_valid(&cache, entry);
    sqfs_cache_put(&cache, entry);
    assert(sqfs_cache_get(&cache, 0x4283) == entry);
    assert(sqfs_cache_entry_valid(&cache, entry));
    assert(*entry == 0x12345678u && disposed == 0);
    sqfs_cache_put(&cache, entry);
    entry = sqfs_cache_get(&cache, 17);
    assert(disposed == 1 && !sqfs_cache_entry_valid(&cache, entry));
    sqfs_cache_put(&cache, entry);
    entry = sqfs_cache_get(&cache, 17);
    assert(!sqfs_cache_entry_valid(&cache, entry));
    *entry = 0x12345678u;
    sqfs_cache_entry_mark_valid(&cache, entry);
    sqfs_cache_put(&cache, entry);
    sqfs_cache_destroy(&cache);
    assert(!cache && disposed == 2);
    assert_no_leaks();
}

int main(void) {
    test_release(0, 8192u, 3);
    test_release(1, 8192u, 3);
    test_release(UINT32_MAX, 8192u, 3);
    test_release(UINT32_MAX, 1u, 1);
    test_release(0, 4096u - sizeof(edge_sqfs_allocation_t), 1);
    test_release(0, 4096u - sizeof(edge_sqfs_allocation_t) + 1u, 2);
    uint32_t before = allocation_calls;
    assert(!edge_sqfs_alloc(SIZE_MAX));
    assert(!edge_sqfs_alloc(UINT32_MAX));
    assert(!edge_sqfs_calloc(SIZE_MAX, 2));
    assert(allocation_calls == before);
    test_cache_retry();
    puts("squashfs_cache_regression_unit: PASS");
    return 0;
}
