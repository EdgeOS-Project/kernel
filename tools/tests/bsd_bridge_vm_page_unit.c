/* SPDX-License-Identifier: MPL-2.0 */
/* Host tests for the FreeBSD no-object VM-page adapter. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/vm_page.h"
#include "compat/freebsd/sys/sglist.h"
#include "compat/freebsd/vm/vm_object.h"
#include "compat/freebsd/vm/vm_page.h"
#include "compat/freebsd/vm/vm_pageout.h"
#include "compat/freebsd/vm/vm_pager.h"
#include "compat/freebsd/vm/vm_param.h"
#include "compat/freebsd/vm/vm_radix.h"
#include "compat/freebsd/vm/pmap.h"
#include "compat/freebsd/vm/vm_extern.h"

#define TEST_PAGE_SIZE 4096u

static uint32_t g_page_allocations;
static uint32_t g_page_releases;
static uint32_t g_sglist_releases;

int
pmap_enter(pmap_t pmap, vm_offset_t virtual_address, vm_page_t page,
    vm_prot_t protection, unsigned int flags, int8_t page_size_index)
{
    (void)pmap;
    (void)virtual_address;
    (void)page;
    (void)protection;
    (void)flags;
    (void)page_size_index;
    return 0;
}

void
pmap_remove(pmap_t pmap, vm_offset_t start, vm_offset_t end)
{
    (void)pmap;
    (void)start;
    (void)end;
}

int
bsd_bus_dma_virtual_address(uint64_t physical_address, size_t length,
    void **virtual_address)
{
    if (!physical_address || !length || !virtual_address)
        return -1;
    *virtual_address = (void *)(uintptr_t)physical_address;
    return 0;
}

static void *
allocator_pages(uint64_t pages, void *context)
{
    void *memory = 0;

    (void)context;
    if (pages > SIZE_MAX / TEST_PAGE_SIZE ||
        posix_memalign(&memory, TEST_PAGE_SIZE,
        (size_t)pages * TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0xa5, (size_t)pages * TEST_PAGE_SIZE);
    return memory;
}

static void
allocator_release(void *base, uint64_t pages, void *context)
{
    (void)pages;
    (void)context;
    free(base);
}

static void *
page_allocate(void)
{
    void *memory = 0;

    if (posix_memalign(&memory, TEST_PAGE_SIZE, TEST_PAGE_SIZE) != 0)
        return 0;
    memset(memory, 0xa5, TEST_PAGE_SIZE);
    ++g_page_allocations;
    return memory;
}

static void
page_release(void *page)
{
    ++g_page_releases;
    free(page);
}

static int
page_physical(const void *page, uint64_t *physical)
{
    if (!page || !physical)
        return -1;
    *physical = (uint64_t)(uintptr_t)page;
    return 0;
}

void
sglist_free(struct sglist *segments)
{
    assert(segments != 0);
    assert(segments->sg_refs == 1);
    g_sglist_releases++;
    free(segments);
}

static void
test_sg_pager(void)
{
    struct sglist *segments;
    struct sglist_seg *storage;
    vm_object_t object;
    vm_paddr_t physical = 0;

    segments = calloc(1, sizeof(*segments) +
        2u * sizeof(struct sglist_seg));
    assert(segments != 0);
    storage = (struct sglist_seg *)(void *)(segments + 1);
    sglist_init(segments, 2, storage);
    segments->sg_nseg = 2;
    segments->sg_segs[0].ss_paddr = 0x100000u;
    segments->sg_segs[0].ss_len = TEST_PAGE_SIZE;
    segments->sg_segs[1].ss_paddr = 0x300000u;
    segments->sg_segs[1].ss_len = 2u * TEST_PAGE_SIZE;

    object = vm_pager_allocate(OBJT_SG, segments,
        3u * TEST_PAGE_SIZE, VM_PROT_ALL, 0, 0);
    assert(object != 0);
    assert(object->type == OBJT_SG);
    assert(object->size == 3);
    assert(vm_object_pager_physical_address(object, 0, &physical) == 0);
    assert(physical == 0x100000u);
    assert(vm_object_pager_physical_address(object,
        TEST_PAGE_SIZE - 1u, &physical) == 0);
    assert(physical == 0x100fffu);
    assert(vm_object_pager_physical_address(object,
        TEST_PAGE_SIZE, &physical) == 0);
    assert(physical == 0x300000u);
    assert(vm_object_pager_physical_address(object,
        3u * TEST_PAGE_SIZE - 1u, &physical) == 0);
    assert(physical == 0x301fffu);
    assert(vm_object_pager_physical_address(object,
        3u * TEST_PAGE_SIZE, &physical) == 22);
    vm_object_reference(object);
    vm_object_deallocate(object);
    assert(g_sglist_releases == 0);
    vm_pager_deallocate(object);
    assert(g_sglist_releases == 1);
}

static int
test_rvi_pinit(pmap_t pmap)
{
    return pmap_pinit_type(pmap, PT_RVI, PMAP_PDE_SUPERPAGE);
}

static void
test_guest_vmspace(void)
{
    struct pmap pmap;
    struct vmspace *vmspace;
    vm_object_t object;
    vm_page_t held_page = 0;

    memset(&pmap, 0, sizeof(pmap));
    assert(pmap_pinit_type(&pmap, PT_EPT,
        PMAP_PDE_SUPERPAGE | PMAP_SUPPORTS_EXEC_ONLY) == 1);
    assert(pmap.pm_type == PT_EPT);
    assert(pmap.pm_cr3 != 0);
    assert((pmap.pm_cr3 & (TEST_PAGE_SIZE - 1u)) == 0);
    assert(pmap.edgeos_root_page != 0);
    for (uint32_t index = 0; index < TEST_PAGE_SIZE; ++index)
        assert(((uint8_t *)pmap.edgeos_root_page->edgeos_page)[index] == 0);
    pmap_release(&pmap);
    assert(pmap.pm_cr3 == 0);
    assert(pmap.edgeos_root_page == 0);

    vmspace = vmspace_alloc(0, 1ull << 40, test_rvi_pinit);
    assert(vmspace != 0);
    assert(vmspace_pmap(vmspace)->pm_type == PT_RVI);
    assert(vm_map_min(&vmspace->vm_map) == 0);
    assert(vm_map_max(&vmspace->vm_map) == (1ull << 40));
    assert(vm_map_pmap(&vmspace->vm_map) == vmspace_pmap(vmspace));
    assert(vmspace->vm_map.edgeos_address_space ==
        vmspace_pmap(vmspace)->pm_cr3);

    object = vm_object_allocate(OBJT_SWAP, 2);
    assert(object != 0);
    vm_map_lock(&vmspace->vm_map);
    assert(vm_map_insert(&vmspace->vm_map, object, 0, 0x2000,
        0x4000, VM_PROT_RW, VM_PROT_RW, 0) == KERN_SUCCESS);
    vm_map_unlock(&vmspace->vm_map);
    assert(vm_map_wire(&vmspace->vm_map, 0x2000, 0x4000,
        VM_MAP_WIRE_USER | VM_MAP_WIRE_NOHOLES) == KERN_SUCCESS);
    assert(vm_fault_quick_hold_pages(&vmspace->vm_map, 0x2000,
        TEST_PAGE_SIZE, VM_PROT_READ, &held_page, 1) == 1);
    assert(held_page != 0);
    assert(vm_page_unwire(held_page, PQ_ACTIVE));
    vmspace_free(vmspace);
}

int
main(void)
{
    bsd_allocator_ops_t allocator = {
        .allocate_pages = allocator_pages,
        .release_pages = allocator_release,
    };
    struct pctrie_iter iterator;
    vm_object_t object;
    vm_page_t page;
    vm_page_t page_one;
    vm_page_t page_three;
    void *replacement = 0;

    assert(bsd_allocator_initialize(&allocator) == 0);
    bsd_vm_page_test_backend(
        page_allocate, page_release, page_physical);

    page = vm_page_alloc_noobj(VM_ALLOC_NODUMP | VM_ALLOC_ZERO);
    assert(page != 0);
    assert(page->a.queue == PQ_NONE);
    assert(page->edgeos_page != 0);
    assert(VM_PAGE_TO_PHYS(page) ==
        (uint64_t)(uintptr_t)page->edgeos_page);
    for (uint32_t index = 0; index < TEST_PAGE_SIZE; ++index)
        assert(((uint8_t *)page->edgeos_page)[index] == 0);
    vm_page_free(page);

    page = vm_page_alloc_noobj(
        VM_ALLOC_WIRED | VM_ALLOC_WAITOK | VM_ALLOC_ZERO);
    assert(page != 0);
    assert(VPRC_WIRE_COUNT(page->ref_count) == 1);
    vm_page_wire(page);
    assert(VPRC_WIRE_COUNT(page->ref_count) == 2);
    assert(vm_page_unwire_noq(page) == false);
    assert(VPRC_WIRE_COUNT(page->ref_count) == 1);
    assert(posix_memalign(&replacement, TEST_PAGE_SIZE,
        TEST_PAGE_SIZE) == 0);
    memset(replacement, 0, TEST_PAGE_SIZE);
    assert(bsd_vm_page_bind(page, replacement,
        (uint64_t)(uintptr_t)replacement) == 0);
    assert(page->edgeos_page == replacement);
    assert(g_page_releases == 2);
    bsd_vm_page_unbind(page, replacement);
    assert(page->edgeos_page == 0);
    assert(vm_page_unwire_noq(page) == true);
    vm_page_free(page);
    free(replacement);

    assert(vm_page_alloc_noobj(
        VM_ALLOC_NOWAIT | VM_ALLOC_WAITOK) == 0);
    assert(vm_page_alloc_noobj(0x40000000) == 0);
    assert(vm_object_allocate(0, 4) == 0);
    assert(vm_object_allocate(OBJT_SWAP, 0) == 0);

    test_sg_pager();
    test_guest_vmspace();

    object = vm_object_allocate(OBJT_SWAP, 4);
    assert(object != 0);
    VM_OBJECT_WLOCK(object);
    assert(vm_object_wowned(object));
    page_three = vm_page_grab(object, 3,
        VM_ALLOC_NOBUSY | VM_ALLOC_WIRED | VM_ALLOC_ZERO);
    page_one = vm_page_grab(object, 1,
        VM_ALLOC_NOBUSY | VM_ALLOC_WIRED | VM_ALLOC_ZERO);
    assert(page_three != 0);
    assert(page_one != 0);
    assert(page_one->pindex == 1);
    assert(page_three->pindex == 3);
    assert(page_one->valid == VM_PAGE_BITS_ALL);
    assert(page_three->valid == VM_PAGE_BITS_ALL);
    assert(TAILQ_FIRST(&object->pages) == page_one);
    assert(TAILQ_NEXT(page_one, object_link) == page_three);
    vm_page_iter_init(&iterator, object);
    assert(vm_radix_iter_lookup(&iterator, 1) == page_one);
    assert(vm_radix_iter_lookup(&iterator, 2) == 0);
    assert(vm_radix_iter_lookup(&iterator, 3) == page_three);
    assert(vm_page_grab(object, 4, VM_ALLOC_WIRED) == 0);
    assert(vm_page_grab(object, 1, VM_ALLOC_WIRED) == page_one);
    assert(VPRC_WIRE_COUNT(page_one->ref_count) == 2);
    assert(vm_page_unwire(page_one, PQ_INACTIVE) == false);
    assert(vm_page_unwire(page_one, PQ_INACTIVE) == true);
    assert(page_one->a.queue == PQ_INACTIVE);
    VM_OBJECT_WUNLOCK(object);
    assert(!vm_object_wowned(object));
    vm_object_deallocate(object);

    assert(bsd_vm_page_runtime_initialize() == 0);
    assert(bogus_page != 0);
    assert(VM_PAGE_TO_PHYS(bogus_page) != 0);
    assert(vm_page_wired(bogus_page));
    assert(bsd_vm_page_runtime_initialize() == 0);
    vm_page_free(bogus_page);
    bogus_page = 0;

    assert(g_page_allocations == 9);
    assert(g_page_releases == 9);
    printf("bsd_bridge_vm_page_unit: PASS\n");
    return 0;
}
