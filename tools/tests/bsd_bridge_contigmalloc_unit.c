/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for shared BSD contiguous allocations. */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/vm/vm_extern.h"

static void *
test_allocate_pages(uint64_t page_count, void *context)
{
    void *memory = 0;

    (void)context;
    if (page_count > SIZE_MAX / 4096U ||
        posix_memalign(&memory, 4096U,
        (size_t)page_count * 4096U) != 0)
        return 0;
    return memory;
}

static void
test_release_pages(void *base, uint64_t page_count, void *context)
{
    (void)page_count;
    (void)context;
    free(base);
}

static int
test_physical_address(const void *pointer, uint64_t *physical_address,
    void *context)
{
    (void)context;
    *physical_address = (uint64_t)(uintptr_t)pointer;
    return 0;
}

static void *
test_dma_allocate_pages(uint64_t page_count, uint32_t flags, void *context)
{
    (void)flags;
    return test_allocate_pages(page_count, context);
}

int
main(void)
{
    bsd_allocator_ops_t allocator_operations = {
        .allocate_pages = test_allocate_pages,
        .release_pages = test_release_pages,
    };
    bsd_bus_dma_ops_t dma_operations = {
        .allocate_pages = test_dma_allocate_pages,
        .release_pages = test_release_pages,
        .physical_address = test_physical_address,
    };
    uint8_t *allocation;
    uint8_t *software_allocation;
    uint64_t physical;

    assert(bsd_allocator_initialize(&allocator_operations) == 0);
    assert(bsd_bus_dma_initialize(&dma_operations) == 0);
    allocation = bsd_contigmalloc(8192, M_DEVBUF, M_WAITOK | M_ZERO,
        0, UINT64_MAX, 4096, 0);
    assert(allocation != 0);
    assert(((uintptr_t)allocation & 4095U) == 0);
    for (size_t index = 0; index < 8192; ++index)
        assert(allocation[index] == 0);
    bsd_contigfree(allocation, 8192, M_DEVBUF);
    assert(bsd_contigmalloc(4096, M_DEVBUF, M_NOWAIT,
        0, UINT64_MAX, 3, 0) == 0);
    assert(bsd_contigmalloc(8192, M_DEVBUF, M_NOWAIT,
        0, UINT64_MAX, 4096, 4096) == 0);
    software_allocation = bsd_contigmalloc(8192, M_DEVBUF,
        M_NOWAIT | M_ZERO, 0x1000, 0xfffff, 4096, 0);
    assert(software_allocation != 0);
    assert(bsd_bus_dma_physical_address(
        software_allocation, &physical) == 0);
    assert(physical >= 0x1000 && physical + 8191 <= 0xfffff);
    assert(bsd_bus_dma_physical_address(
        software_allocation + 4096, &physical) == 0);
    assert(physical >= 0x2000 && physical + 4095 <= 0xfffff);
    bsd_contigfree(software_allocation, 8192, M_DEVBUF);
    allocation = kmem_alloc_contig(4096, M_WAITOK | M_ZERO, 0,
        UINT64_MAX, 4096, 0, VM_MEMATTR_DEFAULT);
    assert(allocation != 0);
    assert(((uintptr_t)allocation & 4095U) == 0);
    for (size_t index = 0; index < 4096; ++index)
        assert(allocation[index] == 0);
    kmem_free(allocation, 4096);
    return 0;
}
