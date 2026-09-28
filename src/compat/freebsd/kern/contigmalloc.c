/* SPDX-License-Identifier: MPL-2.0 */
/* Physically contiguous allocation adapter for imported BSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/sys/domainset.h"
#include "compat/freebsd/vm/vm_extern.h"

#define BSD_CONTIG_PAGE_SIZE 4096U
#define BSD_CONTIG_SOFTWARE_WINDOW_LIMIT UINT64_C(0x100000)
#define BSD_CONTIG_SOFTWARE_ALLOCATION_MAX 32U

typedef struct {
    uint8_t *allocation;
    size_t size;
    uint64_t physical_start;
    uint8_t active;
} bsd_contig_software_allocation_t;

static bsd_contig_software_allocation_t
    g_contig_software_allocations[BSD_CONTIG_SOFTWARE_ALLOCATION_MAX];
static volatile uint32_t g_contig_software_guard;

static void
contig_registry_lock(void)
{
    while (__atomic_test_and_set(
        &g_contig_software_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
contig_registry_unlock(void)
{
    __atomic_clear(&g_contig_software_guard, __ATOMIC_RELEASE);
}

static uint64_t
contig_align_up(uint64_t value, uint64_t alignment)
{
    uint64_t mask = alignment - 1;

    if (value > UINT64_MAX - mask)
        return UINT64_MAX;
    return (value + mask) & ~mask;
}

static int
contig_ranges_overlap(uint64_t left_start, uint64_t left_size,
    uint64_t right_start, uint64_t right_size)
{
    return left_start < right_start + right_size &&
        right_start < left_start + left_size;
}

static int
contig_software_register(void *allocation, size_t size, uint64_t low,
    uint64_t high, uint64_t alignment, uint64_t boundary)
{
    bsd_contig_software_allocation_t *available = 0;
    uint64_t candidate;

    if (!allocation || size == 0 ||
        high > BSD_CONTIG_SOFTWARE_WINDOW_LIMIT)
        return -1;
    if (bsd_bus_dma_register_physical_override(
        bsd_contigmalloc_physical_address) != 0)
        return -1;
    if (low < BSD_CONTIG_PAGE_SIZE)
        low = BSD_CONTIG_PAGE_SIZE;
    candidate = contig_align_up(low, alignment);

    contig_registry_lock();
    for (uint32_t index = 0;
         index < BSD_CONTIG_SOFTWARE_ALLOCATION_MAX; ++index) {
        if (!g_contig_software_allocations[index].active && !available)
            available = &g_contig_software_allocations[index];
    }
    while (available && candidate != UINT64_MAX &&
        candidate <= high && size - 1 <= high - candidate) {
        uint64_t candidate_end = candidate + size - 1;
        uint64_t next_candidate = 0;
        int conflict = 0;

        if (boundary != 0 &&
            candidate / boundary != candidate_end / boundary) {
            candidate = contig_align_up(
                candidate + boundary, boundary);
            continue;
        }
        for (uint32_t index = 0;
             index < BSD_CONTIG_SOFTWARE_ALLOCATION_MAX; ++index) {
            bsd_contig_software_allocation_t *entry =
                &g_contig_software_allocations[index];

            if (!entry->active ||
                !contig_ranges_overlap(candidate, size,
                    entry->physical_start, entry->size))
                continue;
            conflict = 1;
            next_candidate = entry->physical_start + entry->size;
            break;
        }
        if (!conflict) {
            available->allocation = allocation;
            available->size = size;
            available->physical_start = candidate;
            available->active = 1;
            contig_registry_unlock();
            return 0;
        }
        candidate = contig_align_up(next_candidate, alignment);
    }
    contig_registry_unlock();
    return -1;
}

static int
contig_software_unregister(void *allocation)
{
    int removed = 0;

    contig_registry_lock();
    for (uint32_t index = 0;
         index < BSD_CONTIG_SOFTWARE_ALLOCATION_MAX; ++index) {
        bsd_contig_software_allocation_t *entry =
            &g_contig_software_allocations[index];

        if (!entry->active || entry->allocation != allocation)
            continue;
        entry->active = 0;
        entry->allocation = 0;
        entry->size = 0;
        entry->physical_start = 0;
        removed = 1;
        break;
    }
    contig_registry_unlock();
    return removed;
}

int
bsd_contigmalloc_physical_address(const void *pointer,
    uint64_t *physical_address)
{
    uintptr_t value;
    int found = -1;

    if (!pointer || !physical_address)
        return -1;
    value = (uintptr_t)pointer;
    contig_registry_lock();
    for (uint32_t index = 0;
         index < BSD_CONTIG_SOFTWARE_ALLOCATION_MAX; ++index) {
        bsd_contig_software_allocation_t *entry =
            &g_contig_software_allocations[index];
        uintptr_t start;

        if (!entry->active)
            continue;
        start = (uintptr_t)entry->allocation;
        if (value < start || value - start >= entry->size)
            continue;
        *physical_address = entry->physical_start + (value - start);
        found = 0;
        break;
    }
    contig_registry_unlock();
    return found;
}

static int
contig_power_of_two(uint64_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

static int
contig_physical_range(void *allocation, size_t size,
    uint64_t *start_out, uint64_t *end_out)
{
    uint8_t *bytes = allocation;
    uint64_t start;

    if (!allocation || size == 0 ||
        bsd_bus_dma_physical_address(allocation, &start) != 0 ||
        start > UINT64_MAX - (size - 1))
        return -1;
    for (size_t offset = 0; offset < size;) {
        uint64_t physical;
        size_t step = BSD_CONTIG_PAGE_SIZE -
            (((uintptr_t)bytes + offset) & (BSD_CONTIG_PAGE_SIZE - 1));

        if (bsd_bus_dma_physical_address(bytes + offset, &physical) != 0 ||
            physical != start + offset)
            return -1;
        if (step > size - offset)
            step = size - offset;
        offset += step;
    }
    *start_out = start;
    *end_out = start + size - 1;
    return 0;
}

void *
bsd_contigmalloc(unsigned long size, struct malloc_type *type,
    int flags, uint64_t low, uint64_t high, unsigned long alignment,
    uint64_t boundary)
{
    uint64_t physical_start;
    uint64_t physical_end;
    void *allocation;

    if (size == 0 || low > high ||
        (alignment != 0 && !contig_power_of_two(alignment)) ||
        (boundary != 0 && !contig_power_of_two(boundary)))
        return 0;
    if (alignment < BSD_CONTIG_PAGE_SIZE)
        alignment = BSD_CONTIG_PAGE_SIZE;
    allocation = bsd_malloc_aligned(size, alignment, type, flags);
    if (!allocation)
        return 0;
    if (contig_physical_range(allocation, size, &physical_start,
        &physical_end) != 0) {
        bsd_free(allocation, type);
        return 0;
    }
    if (physical_start < low || physical_end > high ||
        (boundary != 0 &&
        (physical_start / boundary != physical_end / boundary))) {
        if (contig_software_register(allocation, size, low, high,
            alignment, boundary) != 0) {
            bsd_free(allocation, type);
            return 0;
        }
    }
    return allocation;
}

void *
bsd_contigmalloc_domainset(unsigned long size, struct malloc_type *type,
    struct domainset *policy, int flags, uint64_t low, uint64_t high,
    unsigned long alignment, uint64_t boundary)
{
    if (!policy || policy->preferred_domain != 0)
        return 0;
    return bsd_contigmalloc(size, type, flags, low, high, alignment,
        boundary);
}

void
bsd_contigfree(void *allocation, unsigned long size,
    struct malloc_type *type)
{
    (void)size;
    (void)contig_software_unregister(allocation);
    bsd_free(allocation, type);
}

void *
kmem_alloc_contig(vm_size_t size, int flags, vm_paddr_t low,
    vm_paddr_t high, unsigned long alignment, vm_paddr_t boundary,
    vm_memattr_t memattr)
{
    (void)memattr;
    return bsd_contigmalloc(size, M_DEVBUF, flags, low, high, alignment,
        boundary);
}

void *
kmem_alloc_contig_domainset(struct domainset *policy, vm_size_t size,
    int flags, vm_paddr_t low, vm_paddr_t high,
    unsigned long alignment, vm_paddr_t boundary,
    vm_memattr_t memattr)
{
    if (!policy || policy->preferred_domain != 0)
        return 0;
    return kmem_alloc_contig(size, flags, low, high, alignment,
        boundary, memattr);
}

void *
kmem_alloc_attr_domainset(struct domainset *policy, vm_size_t size,
    int flags, vm_paddr_t low, vm_paddr_t high, vm_memattr_t memattr)
{
    if (!policy || policy->preferred_domain != 0)
        return 0;
    return kmem_alloc_contig(size, flags, low, high,
        BSD_CONTIG_PAGE_SIZE, 0,
        memattr);
}

void *
kmem_alloc_attr(vm_size_t size, int flags, vm_paddr_t low,
    vm_paddr_t high, vm_memattr_t memattr)
{
    return kmem_alloc_attr_domainset(DOMAINSET_PREF(0), size, flags,
        low, high, memattr);
}

void
kmem_free(void *address, vm_size_t size)
{
    bsd_contigfree(address, size, M_DEVBUF);
}
