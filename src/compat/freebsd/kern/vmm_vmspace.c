/* SPDX-License-Identifier: MPL-2.0 */
/* Guest address-space lifetime adapter for the imported FreeBSD VMM. */

#include <stdint.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/vm/pmap.h"
#include "compat/freebsd/vm/vm_extern.h"
#include "compat/freebsd/vm/vm_object.h"
#include "compat/freebsd/vm/vm_pageout.h"
#include "compat/freebsd/vm/vm_param.h"

struct bsd_vm_map_entry {
    struct bsd_vm_map_entry *next;
    vm_object_t object;
    vm_ooffset_t offset;
    vm_offset_t start;
    vm_offset_t end;
    vm_prot_t protection;
    uint8_t wired;
};

void
vm_map_lock(vm_map_t map)
{
    if (!map)
        return;
    while (__atomic_exchange_n(&map->lock, 1u, __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&map->lock, __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

void
vm_map_unlock(vm_map_t map)
{
    if (map)
        __atomic_store_n(&map->lock, 0u, __ATOMIC_RELEASE);
}

static struct bsd_vm_map_entry *
vm_map_entry_find(vm_map_t map, vm_offset_t address)
{
    struct bsd_vm_map_entry *entry;

    for (entry = map->edgeos_entries; entry; entry = entry->next) {
        if (address >= entry->start && address < entry->end)
            return entry;
        if (address < entry->start)
            break;
    }
    return 0;
}

int
vm_map_insert(vm_map_t map, vm_object_t object, vm_ooffset_t offset,
    vm_offset_t start, vm_offset_t end, vm_prot_t protection,
    vm_prot_t maximum_protection, int flags)
{
    struct bsd_vm_map_entry **link;
    struct bsd_vm_map_entry *entry;

    if (!map || !object || start >= end || start < map->edgeos_min ||
        end > map->edgeos_max || ((start | end | offset) &
        (PAGE_SIZE - 1u)) != 0 || (protection & ~VM_PROT_ALL) != 0 ||
        maximum_protection != protection || flags != 0 ||
        offset > IDX_TO_OFF(object->size) ||
        end - start > IDX_TO_OFF(object->size) - offset)
        return KERN_INVALID_ARGUMENT;
    for (link = &map->edgeos_entries; *link; link = &(*link)->next) {
        if (end <= (*link)->start)
            break;
        if (start < (*link)->end)
            return KERN_NO_SPACE;
    }
    entry = bsd_kmalloc(sizeof(*entry), BSD_M_WAITOK | BSD_M_ZERO);
    if (!entry)
        return KERN_RESOURCE_SHORTAGE;
    entry->object = object;
    entry->offset = offset;
    entry->start = start;
    entry->end = end;
    entry->protection = protection;
    entry->next = *link;
    *link = entry;
    return KERN_SUCCESS;
}

static vm_page_t
vm_map_entry_page(struct bsd_vm_map_entry *entry, vm_offset_t address,
    int allocation_flags)
{
    const vm_ooffset_t offset = entry->offset + address - entry->start;
    vm_page_t page;

    if (entry->object->type == OBJT_SG) {
        vm_paddr_t physical_address;

        if (vm_object_pager_physical_address(entry->object, offset,
            &physical_address) != 0)
            return 0;
        page = vm_page_getfake(physical_address &
            ~(vm_paddr_t)(PAGE_SIZE - 1u), entry->object->memattr);
        if (!page)
            return 0;
        page->edgeos_page = vm_page_direct_map(page);
        if ((allocation_flags & VM_ALLOC_WIRED) != 0)
            page->ref_count = 1;
        return page;
    }
    page = vm_page_grab(entry->object, OFF_TO_IDX(offset),
        allocation_flags);
    if (page)
        page->a.act_count = (uint8_t)entry->object->memattr;
    return page;
}

int
vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
    vm_offset_t address;
    int result = KERN_SUCCESS;

    if (!map || start >= end || (flags & ~VM_MAP_WIRE_USER) != 0)
        return KERN_INVALID_ARGUMENT;
    vm_map_lock(map);
    for (address = start; address < end; address += PAGE_SIZE) {
        struct bsd_vm_map_entry *entry = vm_map_entry_find(map, address);
        vm_page_t page;
        int error;

        if (!entry || address + PAGE_SIZE > entry->end) {
            result = KERN_INVALID_ADDRESS;
            break;
        }
        page = vm_map_entry_page(entry, address, VM_ALLOC_WAITOK);
        if (!page) {
            result = KERN_RESOURCE_SHORTAGE;
            break;
        }
        error = pmap_enter(map->pmap, address, page, entry->protection,
            PMAP_ENTER_WIRED, 0);
        if ((page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) != 0)
            vm_page_putfake(page);
        if (error != 0) {
            result = error == 12 ? KERN_RESOURCE_SHORTAGE :
                KERN_INVALID_ARGUMENT;
            break;
        }
        entry->wired = 1;
    }
    if (result != KERN_SUCCESS)
        pmap_remove(map->pmap, start, address);
    vm_map_unlock(map);
    return result;
}

int
vm_fault(vm_map_t map, vm_offset_t address, vm_prot_t protection,
    int fault_flags, vm_page_t *result_page)
{
    struct bsd_vm_map_entry *entry;
    vm_page_t page;
    int error;

    if (!map || fault_flags != VM_FAULT_NORMAL ||
        (protection & ~VM_PROT_ALL) != 0 || protection == VM_PROT_NONE)
        return KERN_INVALID_ARGUMENT;
    address &= ~(vm_offset_t)(PAGE_SIZE - 1u);
    vm_map_lock(map);
    entry = vm_map_entry_find(map, address);
    if (!entry) {
        vm_map_unlock(map);
        return KERN_INVALID_ADDRESS;
    }
    if ((protection & ~entry->protection) != 0) {
        vm_map_unlock(map);
        return KERN_PROTECTION_FAILURE;
    }
    page = vm_map_entry_page(entry, address, VM_ALLOC_WAITOK);
    if (!page) {
        vm_map_unlock(map);
        return KERN_RESOURCE_SHORTAGE;
    }
    error = pmap_enter(map->pmap, address, page, entry->protection,
        entry->wired ? PMAP_ENTER_WIRED : 0, 0);
    if (error == 0 && result_page)
        *result_page = page;
    if ((page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) != 0 && !result_page)
        vm_page_putfake(page);
    vm_map_unlock(map);
    if (error == 0)
        return KERN_SUCCESS;
    return error == 12 ? KERN_RESOURCE_SHORTAGE : KERN_FAILURE;
}

int
vm_map_remove(vm_map_t map, vm_offset_t start, vm_offset_t end)
{
    struct bsd_vm_map_entry **link;

    if (!map || start >= end)
        return KERN_INVALID_ARGUMENT;
    vm_map_lock(map);
    for (struct bsd_vm_map_entry *entry = map->edgeos_entries; entry;
         entry = entry->next) {
        if (entry->end <= start || entry->start >= end)
            continue;
        if (entry->start < start || entry->end > end) {
            vm_map_unlock(map);
            return KERN_INVALID_ARGUMENT;
        }
    }
    link = &map->edgeos_entries;
    while (*link) {
        struct bsd_vm_map_entry *entry = *link;

        if (entry->end <= start || entry->start >= end) {
            link = &entry->next;
            continue;
        }
        *link = entry->next;
        pmap_remove(map->pmap, entry->start, entry->end);
        vm_object_deallocate(entry->object);
        bsd_kfree(entry);
    }
    vm_map_unlock(map);
    return KERN_SUCCESS;
}

int
vm_fault_quick_hold_pages(vm_map_t map, vm_offset_t address,
    vm_size_t length, vm_prot_t protection, vm_page_t *pages,
    int maximum_pages)
{
    vm_offset_t first;
    vm_offset_t last;
    int count = 0;

    if (!map || !pages || maximum_pages <= 0 || length == 0 ||
        address > UINTPTR_MAX - length ||
        (protection & ~VM_PROT_ALL) != 0)
        return 0;
#ifndef BSD_BRIDGE_HOST_TEST
    if (!map->edgeos_entries && map->edgeos_address_space != 0) {
        int page_count;

        if (vm_fault_hold_pages(map, address, length, protection, pages,
            maximum_pages, &page_count) != 0)
            return -1;
        return page_count;
    }
#endif
    first = address & ~(vm_offset_t)(PAGE_SIZE - 1u);
    last = (address + length - 1u) & ~(vm_offset_t)(PAGE_SIZE - 1u);
    if ((last - first) / PAGE_SIZE >= (vm_size_t)maximum_pages)
        return 0;
    vm_map_lock(map);
    for (vm_offset_t current = first;; current += PAGE_SIZE) {
        struct bsd_vm_map_entry *entry = vm_map_entry_find(map, current);
        vm_page_t page;

        if (!entry || (protection & ~entry->protection) != 0)
            break;
        page = vm_map_entry_page(entry, current,
            VM_ALLOC_WAITOK | VM_ALLOC_WIRED);
        if (!page)
            break;
        pages[count++] = page;
        if (current == last)
            break;
    }
    vm_map_unlock(map);
    if (count == (int)((last - first) / PAGE_SIZE + 1u))
        return count;
    while (count > 0) {
        vm_page_t page = pages[--count];

        (void)vm_page_unwire_noq(page);
        if ((page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) != 0)
            vm_page_putfake(page);
    }
    return 0;
}

int
vm_mmap_to_errno(int result)
{
    switch (result) {
    case KERN_SUCCESS:
        return 0;
    case KERN_INVALID_ADDRESS:
    case KERN_NO_SPACE:
    case KERN_RESOURCE_SHORTAGE:
        return 12;
    case KERN_PROTECTION_FAILURE:
        return 13;
    default:
        return 22;
    }
}

struct vmspace *
vmspace_alloc(vm_offset_t min, vm_offset_t max, pmap_pinit_t pinit)
{
    struct vmspace *vmspace;

    if (!pinit || min >= max)
        return 0;
    vmspace = bsd_kmalloc(sizeof(*vmspace), BSD_M_WAITOK | BSD_M_ZERO);
    if (!vmspace)
        return 0;
    if (!pinit(&vmspace->vm_pmap)) {
        bsd_kfree(vmspace);
        return 0;
    }
    vmspace->vm_map.edgeos_address_space = vmspace->vm_pmap.pm_cr3;
    vmspace->vm_map.edgeos_min = min;
    vmspace->vm_map.edgeos_max = max;
    vmspace->vm_map.pmap = &vmspace->vm_pmap;
    return vmspace;
}

void
vmspace_free(struct vmspace *vmspace)
{
    if (!vmspace)
        return;
    (void)vm_map_remove(&vmspace->vm_map, vmspace->vm_map.edgeos_min,
        vmspace->vm_map.edgeos_max);
    pmap_release(&vmspace->vm_pmap);
    bsd_kfree(vmspace);
}

long
vmspace_resident_count(struct vmspace *vmspace)
{
    struct bsd_vm_map_entry *entry;
    long count = 0;

    if (!vmspace)
        return 0;
    vm_map_lock(&vmspace->vm_map);
    for (entry = vmspace->vm_map.edgeos_entries; entry;
         entry = entry->next)
        count += (long)((entry->end - entry->start) / PAGE_SIZE);
    vm_map_unlock(&vmspace->vm_map);
    return count;
}
