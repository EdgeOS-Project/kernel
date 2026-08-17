/* SPDX-License-Identifier: MPL-2.0 */
/* Kernel virtual-memory adapter for imported FreeBSD drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/edgeos/vm_page.h"
#include "compat/freebsd/sys/malloc.h"
#include "compat/freebsd/vm/pmap.h"
#include "compat/freebsd/vm/vm_extern.h"
#include "compat/freebsd/vm/vm_page.h"

typedef struct bsd_kva_allocation {
    struct bsd_kva_allocation *next;
    uint8_t *base;
    vm_size_t size;
    vm_page_t *pages;
    uint32_t page_count;
    vm_paddr_t device_physical_address;
    vm_size_t device_mapping_size;
} bsd_kva_allocation_t;

static bsd_kva_allocation_t *g_kva_allocations;
static volatile uint32_t g_kva_guard;

static void
kva_registry_lock(void)
{
    while (__atomic_test_and_set(&g_kva_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
kva_registry_unlock(void)
{
    __atomic_clear(&g_kva_guard, __ATOMIC_RELEASE);
}

static bsd_kva_allocation_t *
kva_find_locked(const void *address, vm_size_t size, uint32_t *first_page)
{
    uintptr_t value = (uintptr_t)address;

    for (bsd_kva_allocation_t *entry = g_kva_allocations;
         entry; entry = entry->next) {
        uintptr_t base = (uintptr_t)entry->base;
        vm_size_t offset;

        if (value < base)
            continue;
        offset = (vm_size_t)(value - base);
        if ((offset & (PAGE_SIZE - 1u)) != 0 ||
            offset > entry->size || size > entry->size - offset)
            continue;
        if (first_page)
            *first_page = (uint32_t)(offset / PAGE_SIZE);
        return entry;
    }
    return 0;
}

void *
kva_alloc(vm_size_t size)
{
    bsd_kva_allocation_t *entry;
    uint32_t page_count;
    void *base;

    if (size == 0 || (size & (PAGE_SIZE - 1u)) != 0 ||
        size / PAGE_SIZE > UINT32_MAX)
        return 0;
    page_count = (uint32_t)(size / PAGE_SIZE);
    entry = bsd_malloc(sizeof(*entry), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!entry)
        return 0;
    entry->pages = bsd_mallocarray(page_count, sizeof(*entry->pages),
        M_DEVBUF, M_WAITOK | M_ZERO);
    if (!entry->pages) {
        bsd_free(entry, M_DEVBUF);
        return 0;
    }
    base = bsd_malloc_aligned((size_t)size, PAGE_SIZE, M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!base) {
        bsd_free(entry->pages, M_DEVBUF);
        bsd_free(entry, M_DEVBUF);
        return 0;
    }
    entry->base = base;
    entry->size = size;
    entry->page_count = page_count;
    kva_registry_lock();
    entry->next = g_kva_allocations;
    g_kva_allocations = entry;
    kva_registry_unlock();
    return base;
}

void *
kmem_malloc(vm_size_t size, int flags)
{
    vm_size_t rounded;

    (void)flags;
    if (size == 0 || size > UINT64_MAX - (PAGE_SIZE - 1u))
        return 0;
    rounded = (size + PAGE_SIZE - 1u) & ~(vm_size_t)(PAGE_SIZE - 1u);
    return kva_alloc(rounded);
}

void
pmap_qenter(void *address, vm_page_t *pages, int count)
{
    bsd_kva_allocation_t *entry;
    uint32_t first;
    vm_size_t size;

    if (!address || !pages || count <= 0 ||
        (uint32_t)count > UINT32_MAX / PAGE_SIZE)
        return;
    size = (vm_size_t)(uint32_t)count * PAGE_SIZE;
    kva_registry_lock();
    entry = kva_find_locked(address, size, &first);
    if (!entry || first > entry->page_count ||
        (uint32_t)count > entry->page_count - first)
        goto out;
    for (int index = 0; index < count; ++index) {
        vm_page_t page = pages[index];
        uint64_t physical;
        uint8_t *allocation =
            entry->base + ((vm_size_t)first + (uint32_t)index) * PAGE_SIZE;

        if (!page || entry->pages[first + (uint32_t)index] ||
            (page->edgeos_flags & EDGEOS_VM_PAGE_KVA_BINDING) != 0 ||
            bsd_bus_dma_physical_address(allocation, &physical) != 0 ||
            (physical & (PAGE_SIZE - 1u)) != 0)
            goto out;
    }
    for (int index = 0; index < count; ++index) {
        vm_page_t page = pages[index];
        uint32_t slot = first + (uint32_t)index;
        uint8_t *allocation =
            entry->base + (vm_size_t)slot * PAGE_SIZE;
        uint64_t physical;

        if (bsd_bus_dma_physical_address(allocation, &physical) != 0 ||
            bsd_vm_page_bind(page, allocation, physical) != 0)
            goto out;
        entry->pages[slot] = page;
    }
out:
    kva_registry_unlock();
}

void
pmap_qremove(void *address, int count)
{
    bsd_kva_allocation_t *entry;
    uint32_t first;
    vm_size_t size;

    if (!address || count <= 0 ||
        (uint32_t)count > UINT32_MAX / PAGE_SIZE)
        return;
    size = (vm_size_t)(uint32_t)count * PAGE_SIZE;
    kva_registry_lock();
    entry = kva_find_locked(address, size, &first);
    if (!entry || first > entry->page_count ||
        (uint32_t)count > entry->page_count - first)
        goto out;
    for (int index = 0; index < count; ++index) {
        uint32_t slot = first + (uint32_t)index;
        uint8_t *allocation =
            entry->base + (vm_size_t)slot * PAGE_SIZE;

        bsd_vm_page_unbind(entry->pages[slot], allocation);
        entry->pages[slot] = 0;
    }
out:
    kva_registry_unlock();
}

void
pmap_kenter_device(vm_offset_t address, vm_size_t size,
    vm_paddr_t physical_address)
{
    bsd_kva_allocation_t *entry;
    uint32_t first;

    if (address == 0 || size == 0 ||
        (address & (PAGE_SIZE - 1u)) != 0 ||
        (size & (PAGE_SIZE - 1u)) != 0 ||
        (physical_address & (PAGE_SIZE - 1u)) != 0 ||
        physical_address > UINT64_MAX - (size - 1u))
        bsd_panic("pmap_kenter_device: invalid mapping");
    kva_registry_lock();
    entry = kva_find_locked((void *)(uintptr_t)address, size, &first);
    if (!entry || first != 0 || size != entry->size ||
        entry->device_mapping_size != 0) {
        kva_registry_unlock();
        bsd_panic("pmap_kenter_device: unknown KVA allocation");
    }
    entry->device_physical_address = physical_address;
    entry->device_mapping_size = size;
    kva_registry_unlock();
}

void
pmap_kremove_device(vm_offset_t address, vm_size_t size)
{
    bsd_kva_allocation_t *entry;
    uint32_t first;

    if (address == 0 || size == 0 ||
        (address & (PAGE_SIZE - 1u)) != 0 ||
        (size & (PAGE_SIZE - 1u)) != 0)
        bsd_panic("pmap_kremove_device: invalid mapping");
    kva_registry_lock();
    entry = kva_find_locked((void *)(uintptr_t)address, size, &first);
    if (!entry || first != 0 || size != entry->device_mapping_size) {
        kva_registry_unlock();
        bsd_panic("pmap_kremove_device: mapping not found");
    }
    entry->device_physical_address = 0;
    entry->device_mapping_size = 0;
    kva_registry_unlock();
}

int
bsd_pmap_kva_extract(vm_offset_t address, vm_paddr_t *physical_address)
{
    bsd_kva_allocation_t *entry;
    uintptr_t offset;

    if (!address || !physical_address)
        return -1;
    kva_registry_lock();
    entry = kva_find_locked((void *)(uintptr_t)
        (address & ~(vm_offset_t)(PAGE_SIZE - 1u)), PAGE_SIZE, 0);
    if (!entry || entry->device_mapping_size == 0) {
        kva_registry_unlock();
        return -1;
    }
    offset = address - (vm_offset_t)(uintptr_t)entry->base;
    if (offset >= entry->device_mapping_size) {
        kva_registry_unlock();
        return -1;
    }
    *physical_address = entry->device_physical_address + offset;
    kva_registry_unlock();
    return 0;
}

int
bsd_pmap_sync_device_mapping(void *address, vm_size_t size, int to_device)
{
    bsd_kva_allocation_t *entry;
    uint32_t first;
    uintptr_t offset;
    void *device_address = 0;

    if (!address || size == 0)
        return -1;
    kva_registry_lock();
    entry = kva_find_locked(address, size, &first);
    if (!entry || entry->device_mapping_size == 0) {
        kva_registry_unlock();
        return 0;
    }
    offset = (uintptr_t)address - (uintptr_t)entry->base;
    if (offset > entry->device_mapping_size ||
        size > entry->device_mapping_size - offset ||
        bsd_bus_dma_virtual_address(entry->device_physical_address + offset,
            (size_t)size, &device_address) != 0 || !device_address) {
        kva_registry_unlock();
        return -1;
    }
    if (to_device)
        bsd_memcpy(device_address, address, (size_t)size);
    else
        bsd_memcpy(address, device_address, (size_t)size);
    kva_registry_unlock();
    return 0;
}

void
kva_free(void *address, vm_size_t size)
{
    bsd_kva_allocation_t **link;
    bsd_kva_allocation_t *entry = 0;

    if (!address || size == 0)
        return;
    kva_registry_lock();
    for (link = &g_kva_allocations; *link; link = &(*link)->next) {
        if ((*link)->base != address || (*link)->size != size)
            continue;
        entry = *link;
        *link = entry->next;
        break;
    }
    if (entry) {
        if (entry->device_mapping_size != 0) {
            kva_registry_unlock();
            bsd_panic("kva_free: device mapping is still active");
        }
        for (uint32_t index = 0; index < entry->page_count; ++index) {
            bsd_vm_page_unbind(entry->pages[index],
                entry->base + (vm_size_t)index * PAGE_SIZE);
            entry->pages[index] = 0;
        }
    }
    kva_registry_unlock();
    if (!entry)
        return;
    bsd_free(entry->base, M_DEVBUF);
    bsd_free(entry->pages, M_DEVBUF);
    bsd_free(entry, M_DEVBUF);
}
