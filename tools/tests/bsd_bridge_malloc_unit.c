/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the EdgeOS BSD Driver Bridge malloc-type adapter. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/malloc.h"

#define TEST_PAGE_SIZE 4096U

MALLOC_DEFINE(M_TEST, "test", "BSD bridge unit-test allocations");

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / TEST_PAGE_SIZE)
        return 0;
    if (posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)page_count * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0xa5, (size_t)page_count * TEST_PAGE_SIZE);
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static void
test_malloc_contract(void)
{
    uint8_t *allocation;
    size_t accounted_size;

    allocation = bsd_malloc(257, M_TEST, M_NOWAIT | M_ZERO);
    assert(allocation != 0);
    accounted_size = M_TEST->bytes_allocated;
    assert(accounted_size >= 257);
    assert(M_TEST->allocation_count == 1);
    for (size_t index = 0; index < 257; ++index)
        assert(allocation[index] == 0);

    memset(allocation, 0x5a, 257);
    allocation = bsd_realloc(allocation, 1024, M_TEST, M_WAITOK);
    assert(allocation != 0);
    for (size_t index = 0; index < 257; ++index)
        assert(allocation[index] == 0x5a);
    assert(M_TEST->allocation_count == 2);
    assert(M_TEST->free_count == 1);

    bsd_free(allocation, M_TEST);
    assert(M_TEST->free_count == 2);
    assert(M_TEST->bytes_allocated == M_TEST->bytes_freed);
}

static void
test_array_overflow(void)
{
    assert(bsd_mallocarray(SIZE_MAX, 2, M_TEST, M_NOWAIT) == 0);
    assert(bsd_reallocarray(0, SIZE_MAX, 2, M_TEST, M_NOWAIT) == 0);
}

static void
test_aligned_allocation(void)
{
    uint8_t *allocation;

    allocation = bsd_malloc_aligned(130, 256, M_TEST, M_WAITOK | M_ZERO);
    assert(allocation != 0);
    assert(((uintptr_t)allocation & 255U) == 0);
    for (size_t index = 0; index < 130; ++index)
        assert(allocation[index] == 0);
    for (size_t index = 0; index < 130; ++index)
        allocation[index] = (uint8_t)index;
    allocation = bsd_realloc(allocation, 512, M_TEST, M_WAITOK);
    assert(allocation != 0);
    assert(((uintptr_t)allocation & 255U) == 0);
    for (size_t index = 0; index < 130; ++index)
        assert(allocation[index] == (uint8_t)index);
    bsd_free(allocation, M_TEST);
    assert(bsd_malloc_aligned(32, 3, M_TEST, M_NOWAIT) == 0);
}

int
main(void)
{
    bsd_allocator_ops_t ops = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };

    assert(bsd_allocator_initialize(&ops) == 0);
    test_malloc_contract();
    test_array_overflow();
    test_aligned_allocation();
    return 0;
}
