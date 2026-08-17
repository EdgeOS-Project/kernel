/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS physical-page adapter for FreeBSD no-object VM pages. */

#include <limits.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/edgeos/vm_page.h"
#include "compat/freebsd/sys/kthread.h"
#include "compat/freebsd/sys/domainset.h"
typedef unsigned int u_int;
typedef unsigned long u_long;
#include <sys/vmmeter.h>
#include "compat/freebsd/vm/vm_page.h"
#include "compat/freebsd/vm/vm_object.h"
#include "compat/freebsd/vm/vm_pager.h"
#include "compat/freebsd/vm/vm_extern.h"
#include "compat/freebsd/vm/pmap.h"
#include "compat/freebsd/sys/sglist.h"

#ifndef BSD_BRIDGE_HOST_TEST
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/process_runtime.h"
#include "mm/arch_vm.h"
#endif

#define BSD_VM_PAGE_ALLOWED_FLAGS \
    (VM_ALLOC_CLASS_MASK | VM_ALLOC_NOWAIT | VM_ALLOC_WAITOK | \
     VM_ALLOC_WIRED | VM_ALLOC_ZERO | VM_ALLOC_NOBUSY | VM_ALLOC_NODUMP | \
     VM_ALLOC_NOCREAT | VM_ALLOC_WAITFAIL)

void
pmap_allow_2m_x_ept_recalculate(void)
{
    /* EdgeOS does not expose nested EPT mappings to imported drivers. */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

vm_page_t bogus_page;
struct pmap edgeos_kernel_pmap;
struct vmmeter vm_cnt = {
    .v_page_size = 4096u,
};
u_long vm_user_wire_count;

struct bsd_pmap_mapping {
    struct bsd_pmap_mapping *next;
    vm_offset_t virtual_address;
    vm_paddr_t physical_address;
    vm_page_t page;
    vm_prot_t protection;
    uint8_t wired;
};

#ifndef BSD_BRIDGE_HOST_TEST
struct bsd_vm_page_run {
    void *allocation;
    vm_page_t descriptors;
    uint32_t count;
    volatile uint32_t references;
    volatile uint32_t bindings;
};
#endif

static SLIST_HEAD(, vm_page) g_physical_pages =
    SLIST_HEAD_INITIALIZER(g_physical_pages);
static volatile uint32_t g_physical_pages_guard;
static TAILQ_HEAD(, vm_object) g_device_pager_objects =
    TAILQ_HEAD_INITIALIZER(g_device_pager_objects);
static volatile uint32_t g_device_pager_guard;

static void
physical_pages_lock(void)
{
    while (__atomic_exchange_n(&g_physical_pages_guard, 1u,
        __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&g_physical_pages_guard,
            __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

static void
physical_pages_unlock(void)
{
    __atomic_store_n(&g_physical_pages_guard, 0u, __ATOMIC_RELEASE);
}

static void
device_pager_lock(void)
{
    while (__atomic_exchange_n(&g_device_pager_guard, 1u,
        __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&g_device_pager_guard,
            __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

static void
device_pager_unlock(void)
{
    __atomic_store_n(&g_device_pager_guard, 0u, __ATOMIC_RELEASE);
}

static void
physical_pages_insert(vm_page_t page)
{
    physical_pages_lock();
    SLIST_INSERT_HEAD(&g_physical_pages, page, physical_link);
    physical_pages_unlock();
}

static void
physical_pages_remove(vm_page_t page)
{
    vm_page_t *link;

    physical_pages_lock();
    for (link = &SLIST_FIRST(&g_physical_pages); *link;
        link = &SLIST_NEXT(*link, physical_link)) {
        if (*link != page)
            continue;
        *link = SLIST_NEXT(page, physical_link);
        break;
    }
    physical_pages_unlock();
}

#ifdef BSD_BRIDGE_HOST_TEST
static void *(*g_test_page_allocate)(void);
static void (*g_test_page_release)(void *);
static int (*g_test_page_physical)(const void *, uint64_t *);

void
bsd_vm_page_test_backend(void *(*allocate_page)(void),
    void (*release_page)(void *),
    int (*physical_address)(const void *, uint64_t *))
{
    g_test_page_allocate = allocate_page;
    g_test_page_release = release_page;
    g_test_page_physical = physical_address;
}
#endif

int
bsd_vm_page_runtime_initialize(void)
{
    vm_page_t expected = 0;
    vm_page_t page;

    if (__atomic_load_n(&bogus_page, __ATOMIC_ACQUIRE))
        return 0;
    page = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO |
        VM_ALLOC_WAITOK);
    if (!page)
        return 12;
    if (!__atomic_compare_exchange_n(&bogus_page, &expected, page, 0,
        __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
        vm_page_free(page);
    return 0;
}

vm_page_t
vm_page_alloc_noobj(int flags)
{
    vm_page_t descriptor;
    void *page;
    uint64_t physical;
    uint32_t allocation_flags;

    if ((flags & ~BSD_VM_PAGE_ALLOWED_FLAGS) != 0 ||
        ((flags & VM_ALLOC_NOWAIT) != 0 &&
        (flags & VM_ALLOC_WAITOK) != 0))
        return 0;
    allocation_flags = (flags & (VM_ALLOC_WAITOK | VM_ALLOC_WAITFAIL)) != 0 ?
        BSD_M_WAITOK : BSD_M_NOWAIT;
    descriptor = bsd_kmalloc(sizeof(*descriptor),
        allocation_flags | BSD_M_ZERO);
    if (!descriptor)
        return 0;
#ifdef BSD_BRIDGE_HOST_TEST
    page = g_test_page_allocate ? g_test_page_allocate() : 0;
#else
    page = arch_vm_alloc_page();
#endif
    if (!page)
        goto fail_descriptor;
#ifdef BSD_BRIDGE_HOST_TEST
    if (!g_test_page_physical ||
        g_test_page_physical(page, &physical) != 0)
        goto fail_page;
#else
    if (bsd_bus_dma_physical_address(page, &physical) != 0)
        goto fail_page;
#endif
    if ((physical & (PAGE_SIZE - 1u)) != 0)
        goto fail_page;
    if ((flags & VM_ALLOC_ZERO) != 0)
        bsd_memset(page, 0, PAGE_SIZE);
    descriptor->a.queue = PQ_NONE;
    descriptor->phys_addr = physical;
    descriptor->flags = (flags & VM_ALLOC_ZERO) != 0 ? PG_ZERO : 0;
    descriptor->edgeos_page = page;
    descriptor->edgeos_flags = (uint32_t)flags |
        EDGEOS_VM_PAGE_OWNS_ALLOCATION;
    descriptor->ref_count = (flags & VM_ALLOC_WIRED) != 0 ? 1u : 0u;
    physical_pages_insert(descriptor);
    return descriptor;

fail_page:
#ifdef BSD_BRIDGE_HOST_TEST
    if (g_test_page_release)
        g_test_page_release(page);
#else
    arch_vm_free_page(page);
#endif
fail_descriptor:
    bsd_kfree(descriptor);
    return 0;
}

vm_page_t
vm_page_alloc_noobj_contig(int flags, unsigned long count,
    vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
    vm_paddr_t boundary, vm_memattr_t memory_attribute)
{
    if (count == 0 || count > INT32_MAX)
        return 0;
    return vm_page_alloc_contig(0, 0, flags, (int)count, low, high,
        alignment, boundary, memory_attribute);
}

static void
vm_page_object_insert(vm_object_t object, vm_page_t page,
    vm_pindex_t index)
{
    vm_page_t cursor;

    page->object = object;
    page->pindex = index;
    TAILQ_FOREACH(cursor, &object->pages, object_link) {
        if (cursor->pindex > index) {
            TAILQ_INSERT_BEFORE(cursor, page, object_link);
            __atomic_add_fetch(&object->resident_page_count, 1u,
                __ATOMIC_RELAXED);
            return;
        }
    }
    TAILQ_INSERT_TAIL(&object->pages, page, object_link);
    __atomic_add_fetch(&object->resident_page_count, 1u,
        __ATOMIC_RELAXED);
}

int
vm_page_insert(vm_page_t page, vm_object_t object, vm_pindex_t index)
{
    if (!page || !object || page->object ||
        (object->type != OBJT_PHYS && index >= object->size) ||
        vm_page_lookup(object, index))
        return 1;
    vm_page_object_insert(object, page, index);
    return 0;
}

static void
vm_page_object_remove(vm_object_t object, vm_page_t page)
{
    if (!object || !page || page->object != object)
        return;
    TAILQ_REMOVE(&object->pages, page, object_link);
    page->object = 0;
    if (__atomic_fetch_sub(&object->resident_page_count, 1u,
        __ATOMIC_RELAXED) == 0)
        bsd_bridge_panic_stop();
}

vm_page_t
vm_page_alloc_contig(vm_object_t object, vm_pindex_t index, int flags,
    int count, vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
    vm_paddr_t boundary, vm_memattr_t memory_attribute)
{
    vm_page_t page;
    vm_paddr_t physical;

    (void)memory_attribute;
    if (count <= 0 || low > high ||
        (alignment != 0 && (alignment & (alignment - 1u)) != 0) ||
        (boundary != 0 && (boundary & (boundary - 1u)) != 0))
        return 0;
    if (count == 1) {
        page = vm_page_alloc_noobj(flags);
        if (!page)
            return 0;
        physical = VM_PAGE_TO_PHYS(page);
        if (physical < low || physical > high ||
            (alignment != 0 && (physical & (alignment - 1u)) != 0) ||
            !vm_addr_bound_ok(physical, PAGE_SIZE, boundary)) {
            vm_page_free(page);
            return 0;
        }
        if (object && object->type != OBJT_PHYS && index >= object->size) {
            vm_page_free(page);
            return 0;
        }
        if (object && index >= object->size)
            object->size = index + 1u;
        if (object)
            vm_page_object_insert(object, page, index);
        return page;
    }
#ifdef BSD_BRIDGE_HOST_TEST
    return 0;
#else
    {
        struct bsd_vm_page_run *run = 0;
        vm_page_t descriptors = 0;
        void *allocation = 0;
        uint64_t physical_start;
        int allocation_flags;
        int initialized = 0;

        if ((uint64_t)count > SIZE_MAX / sizeof(*descriptors) ||
            (uint64_t)count > ULONG_MAX / PAGE_SIZE ||
            (object && object->type != OBJT_PHYS &&
            (index >= object->size ||
            (vm_pindex_t)count > object->size - index)))
            return 0;
        allocation_flags = (flags &
            (VM_ALLOC_WAITOK | VM_ALLOC_WAITFAIL)) != 0 ?
            M_WAITOK : M_NOWAIT;
        if ((flags & VM_ALLOC_ZERO) != 0)
            allocation_flags |= M_ZERO;
        allocation = bsd_contigmalloc(
            (unsigned long)count * PAGE_SIZE, M_DEVBUF,
            allocation_flags, low, high,
            alignment < PAGE_SIZE ? PAGE_SIZE : alignment, boundary);
        if (!allocation || bsd_contigmalloc_physical_address(allocation,
            &physical_start) != 0)
            goto fail;
        descriptors = bsd_kmallocarray((size_t)count,
            sizeof(*descriptors),
            (flags & (VM_ALLOC_WAITOK | VM_ALLOC_WAITFAIL)) != 0 ?
            BSD_M_WAITOK | BSD_M_ZERO : BSD_M_NOWAIT | BSD_M_ZERO);
        run = bsd_kmalloc(sizeof(*run),
            (flags & (VM_ALLOC_WAITOK | VM_ALLOC_WAITFAIL)) != 0 ?
            BSD_M_WAITOK | BSD_M_ZERO : BSD_M_NOWAIT | BSD_M_ZERO);
        if (!descriptors || !run)
            goto fail;
        run->allocation = allocation;
        run->descriptors = descriptors;
        run->count = (uint32_t)count;
        run->references = (uint32_t)count;
        for (int page_index = 0; page_index < count; ++page_index) {
            uint64_t page_physical;

            page = &descriptors[page_index];
            if (bsd_contigmalloc_physical_address(
                (uint8_t *)allocation +
                (size_t)page_index * PAGE_SIZE,
                &page_physical) != 0 || page_physical !=
                physical_start + (uint64_t)page_index * PAGE_SIZE)
                goto fail;
            page->a.queue = PQ_NONE;
            page->phys_addr = page_physical;
            page->flags = (flags & VM_ALLOC_ZERO) != 0 ? PG_ZERO : 0;
            page->edgeos_page = (uint8_t *)allocation +
                (size_t)page_index * PAGE_SIZE;
            page->edgeos_run = run;
            page->edgeos_flags = (uint32_t)flags |
                EDGEOS_VM_PAGE_OWNS_ALLOCATION;
            page->ref_count = (flags & VM_ALLOC_WIRED) != 0 ? 1u : 0u;
            page->valid = (flags & VM_ALLOC_ZERO) != 0 ?
                VM_PAGE_BITS_ALL : 0;
            if (object)
                vm_page_object_insert(object, page,
                    index + (vm_pindex_t)page_index);
            physical_pages_insert(page);
            ++initialized;
        }
        if (object && object->type == OBJT_PHYS &&
            index + (vm_pindex_t)count > object->size)
            object->size = index + (vm_pindex_t)count;
        return descriptors;

fail:
        while (initialized > 0) {
            page = &descriptors[--initialized];
            physical_pages_remove(page);
            vm_page_object_remove(object, page);
        }
        if (run)
            bsd_kfree(run);
        if (descriptors)
            bsd_kfree(descriptors);
        if (allocation)
            bsd_contigfree(allocation,
                (unsigned long)count * PAGE_SIZE, M_DEVBUF);
        return 0;
    }
#endif
}

int
vm_page_reclaim_contig(int flags, unsigned long count,
    vm_paddr_t low, vm_paddr_t high, unsigned long alignment,
    vm_paddr_t boundary)
{
#ifdef BSD_BRIDGE_HOST_TEST
    void **pages;
    uint64_t first = 0;
    unsigned long allocated = 0;
    int contiguous = 1;
    int result = 12;
#else
    void *reservation;
    unsigned long size;
#endif

    if (count == 0 || count > ULONG_MAX / PAGE_SIZE || low > high ||
        (alignment != 0 && (alignment & (alignment - 1u)) != 0) ||
        (boundary != 0 && (boundary & (boundary - 1u)) != 0))
        return 34;
#ifdef BSD_BRIDGE_HOST_TEST
    if (!g_test_page_allocate || !g_test_page_release ||
        !g_test_page_physical)
        return 12;
    (void)flags;
    pages = bsd_kmallocarray(count, sizeof(*pages),
        BSD_M_WAITOK | BSD_M_ZERO);
    if (!pages)
        return 12;
    for (; allocated < count; ++allocated) {
        uint64_t physical;

        pages[allocated] = g_test_page_allocate();
        if (!pages[allocated])
            break;
        if (g_test_page_physical(pages[allocated], &physical) != 0) {
            contiguous = 0;
            ++allocated;
            break;
        }
        if (allocated == 0)
            first = physical;
        if (physical != first + allocated * PAGE_SIZE) {
            contiguous = 0;
            ++allocated;
            break;
        }
    }
    if (contiguous && allocated == count && first >= low &&
        first <= high && count * PAGE_SIZE - 1u <= high - first &&
        (alignment == 0 || (first & (alignment - 1u)) == 0) &&
        vm_addr_bound_ok(first, count * PAGE_SIZE, boundary))
        result = 0;
    while (allocated > 0)
        g_test_page_release(pages[--allocated]);
    bsd_kfree(pages);
    return result;
#else
    size = count * PAGE_SIZE;
    reservation = bsd_contigmalloc(size, M_DEVBUF,
        (flags & VM_ALLOC_ZERO) != 0 ? M_WAITOK | M_ZERO : M_WAITOK,
        low, high, alignment < PAGE_SIZE ? PAGE_SIZE : alignment,
        boundary);
    if (!reservation)
        return 12;
    bsd_contigfree(reservation, size, M_DEVBUF);
    return 0;
#endif
}

void
vm_wait(vm_object_t object)
{
    (void)object;
    (void)bsd_allocator_wait_for_memory();
}

vm_page_t
PHYS_TO_VM_PAGE(vm_paddr_t physical_address)
{
    vm_page_t page;

    if ((physical_address & (PAGE_SIZE - 1u)) != 0)
        return 0;
    physical_pages_lock();
    SLIST_FOREACH(page, &g_physical_pages, physical_link) {
        if (page->phys_addr == physical_address)
            break;
    }
    physical_pages_unlock();
    return page;
}

void
vm_page_initfake(vm_page_t page, vm_paddr_t physical_address,
    vm_memattr_t memory_attribute)
{
    if (!page)
        return;
    bsd_memset(page, 0, sizeof(*page));
    page->a.queue = PQ_NONE;
    page->phys_addr = physical_address;
    page->edgeos_flags = EDGEOS_VM_PAGE_FAKE;
    page->a.act_count = (uint8_t)memory_attribute;
}

void
vm_page_updatefake(vm_page_t page, vm_paddr_t physical_address,
    vm_memattr_t memory_attribute)
{
    if (!page || (page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) == 0)
        return;
    page->phys_addr = physical_address;
    page->edgeos_page = 0;
    page->a.act_count = (uint8_t)memory_attribute;
}

static void *
vm_page_direct_mapping(vm_page_t page)
{
    void *mapping = 0;

    if (!page)
        return 0;
    if (page->edgeos_page)
        return page->edgeos_page;
    if (bsd_bus_dma_virtual_address(page->phys_addr, PAGE_SIZE,
        &mapping) != 0)
        return 0;
    return mapping;
}

void
pmap_copy_pages(vm_page_t source_pages[], vm_offset_t source_offset,
    vm_page_t destination_pages[], vm_offset_t destination_offset,
    int transfer_size)
{
    size_t source_index = source_offset / PAGE_SIZE;
    size_t destination_index = destination_offset / PAGE_SIZE;
    size_t source_page_offset = source_offset & (PAGE_SIZE - 1u);
    size_t destination_page_offset =
        destination_offset & (PAGE_SIZE - 1u);

    if (!source_pages || !destination_pages || transfer_size < 0)
        return;
    while (transfer_size > 0) {
        void *source = vm_page_direct_mapping(source_pages[source_index]);
        void *destination =
            vm_page_direct_mapping(destination_pages[destination_index]);
        size_t portion = PAGE_SIZE - source_page_offset;
        size_t destination_available = PAGE_SIZE - destination_page_offset;

        if (!source || !destination)
            bsd_panic("pmap_copy_pages: physical page is not mapped");
        if (portion > destination_available)
            portion = destination_available;
        if (portion > (size_t)transfer_size)
            portion = (size_t)transfer_size;
        bsd_memcpy((uint8_t *)destination + destination_page_offset,
            (const uint8_t *)source + source_page_offset, portion);
        transfer_size -= (int)portion;
        source_page_offset += portion;
        destination_page_offset += portion;
        if (source_page_offset == PAGE_SIZE) {
            source_page_offset = 0;
            ++source_index;
        }
        if (destination_page_offset == PAGE_SIZE) {
            destination_page_offset = 0;
            ++destination_index;
        }
    }
}

int
pmap_large_map(vm_paddr_t physical_address, vm_size_t size,
    void **mapping, vm_memattr_t memory_attribute)
{
    if (!mapping || size == 0 ||
        physical_address > UINT64_MAX - (size - 1u) ||
        memory_attribute != VM_MEMATTR_WRITE_BACK)
        return 22;
    *mapping = 0;
    if (bsd_bus_dma_virtual_address(physical_address, size, mapping) != 0 ||
        !*mapping)
        return 6;
    return 0;
}

void
pmap_large_map_wb(void *mapping, vm_size_t size)
{
    uintptr_t start = (uintptr_t)mapping;

    if (!mapping || size == 0 || start > UINTPTR_MAX - size)
        return;
    pmap_force_invalidate_cache_range(start, start + size);
}

void
pmap_large_unmap(void *mapping, vm_size_t size)
{
    /* Bus DMA exposes a stable direct mapping with no per-call lifetime. */
    (void)mapping;
    (void)size;
}

void
pmap_flush_cache_phys_range(vm_paddr_t start, vm_paddr_t end,
    vm_memattr_t memory_attribute)
{
    void *mapping = 0;

    (void)memory_attribute;
    if (start >= end)
        return;
    if (end - start <= SIZE_MAX &&
        bsd_bus_dma_virtual_address(start, (size_t)(end - start),
        &mapping) == 0 && mapping) {
        pmap_force_invalidate_cache_range((uintptr_t)mapping,
            (uintptr_t)mapping + (size_t)(end - start));
        return;
    }
    pmap_invalidate_cache();
}

vm_page_t
vm_page_getfake(vm_paddr_t physical_address,
    vm_memattr_t memory_attribute)
{
    vm_page_t page;

    page = bsd_kmalloc(sizeof(*page), BSD_M_WAITOK | BSD_M_ZERO);
    if (page)
        vm_page_initfake(page, physical_address, memory_attribute);
    return page;
}

void
vm_page_putfake(vm_page_t page)
{
    if (!page || (page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) == 0)
        return;
    bsd_kfree(page);
}

int
bsd_vm_page_bind(vm_page_t page, void *allocation,
    uint64_t physical_address)
{
    void *previous;

    if (!page || !allocation ||
        ((uintptr_t)allocation & (PAGE_SIZE - 1u)) != 0 ||
        (physical_address & (PAGE_SIZE - 1u)) != 0)
        return -1;
    previous = page->edgeos_page;
    if (previous == allocation && page->phys_addr == physical_address)
        return 0;
    if ((page->edgeos_flags & EDGEOS_VM_PAGE_KVA_BINDING) != 0)
        return -1;
    physical_pages_remove(page);
#ifndef BSD_BRIDGE_HOST_TEST
    if (page->edgeos_run) {
        struct bsd_vm_page_run *run = page->edgeos_run;

        page->edgeos_page = allocation;
        page->phys_addr = physical_address;
        page->edgeos_flags &= ~EDGEOS_VM_PAGE_OWNS_ALLOCATION;
        page->edgeos_flags |= EDGEOS_VM_PAGE_KVA_BINDING;
        physical_pages_insert(page);
        if (__atomic_add_fetch(&run->bindings, 1u, __ATOMIC_ACQ_REL) ==
            run->count && run->allocation) {
            void *run_allocation = run->allocation;

            run->allocation = 0;
            bsd_contigfree(run_allocation,
                (unsigned long)run->count * PAGE_SIZE, M_DEVBUF);
        }
        return 0;
    }
#endif
#ifdef BSD_BRIDGE_HOST_TEST
    if (previous && (page->edgeos_flags &
        EDGEOS_VM_PAGE_OWNS_ALLOCATION) != 0 && g_test_page_release)
        g_test_page_release(previous);
#else
    if (previous && (page->edgeos_flags &
        EDGEOS_VM_PAGE_OWNS_ALLOCATION) != 0)
        arch_vm_free_page(previous);
#endif
    page->edgeos_page = allocation;
    page->phys_addr = physical_address;
    page->edgeos_flags &= ~EDGEOS_VM_PAGE_OWNS_ALLOCATION;
    page->edgeos_flags |= EDGEOS_VM_PAGE_KVA_BINDING;
    return 0;
}

void
bsd_vm_page_unbind(vm_page_t page, const void *allocation)
{
    if (!page || page->edgeos_page != allocation ||
        (page->edgeos_flags & EDGEOS_VM_PAGE_KVA_BINDING) == 0)
        return;
    physical_pages_remove(page);
    page->edgeos_page = 0;
    page->phys_addr = 0;
    page->edgeos_flags &= ~EDGEOS_VM_PAGE_KVA_BINDING;
}

void
vm_page_wire(vm_page_t page)
{
    uint32_t old;
    uint32_t replacement;

    if (!page)
        return;
    old = __atomic_load_n(&page->ref_count, __ATOMIC_ACQUIRE);
    for (;;) {
        if ((old & VPRC_BLOCKED) != 0 ||
            VPRC_WIRE_COUNT(old) == VPRC_WIRE_COUNT_MAX)
            return;
        replacement = old + 1u;
        if (__atomic_compare_exchange_n(&page->ref_count, &old,
            replacement, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return;
    }
}

bool
vm_page_unwire_noq(vm_page_t page)
{
    uint32_t old;
    uint32_t replacement;

    if (!page)
        return false;
    old = __atomic_load_n(&page->ref_count, __ATOMIC_ACQUIRE);
    for (;;) {
        if (VPRC_WIRE_COUNT(old) == 0)
            return false;
        replacement = old - 1u;
        if (__atomic_compare_exchange_n(&page->ref_count, &old,
            replacement, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return VPRC_WIRE_COUNT(old) == 1u;
    }
}

void
vm_page_free(vm_page_t page)
{
    void *allocation;

    if (!page)
        return;
    if ((page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) != 0) {
        vm_page_putfake(page);
        return;
    }
    if (page->object)
        vm_page_object_remove(page->object, page);
    physical_pages_remove(page);
#ifndef BSD_BRIDGE_HOST_TEST
    if (page->edgeos_run) {
        struct bsd_vm_page_run *run = page->edgeos_run;

        page->edgeos_page = 0;
        page->phys_addr = 0;
        page->edgeos_run = 0;
        if (__atomic_sub_fetch(&run->references, 1u,
            __ATOMIC_ACQ_REL) == 0) {
            if (run->allocation)
                bsd_contigfree(run->allocation,
                    (unsigned long)run->count * PAGE_SIZE, M_DEVBUF);
            bsd_kfree(run->descriptors);
            bsd_kfree(run);
        }
        return;
    }
#endif
    allocation = page->edgeos_page;
    page->edgeos_page = 0;
    page->phys_addr = 0;
#ifdef BSD_BRIDGE_HOST_TEST
    if (allocation &&
        (page->edgeos_flags & EDGEOS_VM_PAGE_OWNS_ALLOCATION) != 0 &&
        g_test_page_release)
        g_test_page_release(allocation);
#else
    if (allocation &&
        (page->edgeos_flags & EDGEOS_VM_PAGE_OWNS_ALLOCATION) != 0)
        arch_vm_free_page(allocation);
#endif
    bsd_kfree(page);
}

void
vm_object_wlock(vm_object_t object)
{
    if (!object)
        return;
    while (__atomic_exchange_n(&object->lock, 1u, __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&object->lock, __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

void
vm_object_wunlock(vm_object_t object)
{
    int destroy;

    if (!object)
        return;
    destroy = object->edgeos_destroy_on_unlock != 0;
    object->edgeos_destroy_on_unlock = 0;
    __atomic_store_n(&object->lock, 0u, __ATOMIC_RELEASE);
    if (destroy)
        vm_object_deallocate(object);
}

int
vm_object_wowned(vm_object_t object)
{
    return object && __atomic_load_n(&object->lock, __ATOMIC_RELAXED) != 0;
}

vm_object_t
vm_object_allocate(int type, vm_pindex_t size)
{
    vm_object_t object;

    if ((type != OBJT_SWAP && type != OBJT_PHYS && type != OBJT_SG &&
        type != OBJT_DEVICE && type != OBJT_MGTDEVICE) ||
        size == 0)
        return 0;
    object = bsd_kmalloc(sizeof(*object), BSD_M_WAITOK | BSD_M_ZERO);
    if (!object)
        return 0;
    TAILQ_INIT(&object->pages);
    object->size = size;
    object->references = 1;
    object->type = type;
    object->domain.dr_policy = DOMAINSET_PREF(0);
    return object;
}

void
vm_object_reference(vm_object_t object)
{
    if (object)
        __atomic_add_fetch(&object->references, 1u, __ATOMIC_ACQ_REL);
}

vm_object_t
vm_pager_allocate(objtype_t type, void *handle, vm_ooffset_t size,
    vm_prot_t protection, vm_ooffset_t offset, struct ucred *credential)
{
    vm_pindex_t pages;

    (void)protection;
    (void)credential;
    if ((type != OBJT_PHYS && type != OBJT_SG) || size == 0 ||
        (type == OBJT_SG && !handle) ||
        (offset & (PAGE_SIZE - 1u)) != 0 ||
        size > UINT64_MAX - (PAGE_SIZE - 1u) - offset)
        return 0;
    pages = OFF_TO_IDX(offset + size + PAGE_SIZE - 1u);
    if (pages == 0)
        pages = 1;
    {
        vm_object_t object = vm_object_allocate(type, pages);

        if (object)
            object->handle = handle;
        return object;
    }
}

vm_object_t
cdev_pager_lookup(void *handle)
{
    vm_object_t object;

    if (!handle)
        return 0;
    device_pager_lock();
    TAILQ_FOREACH(object, &g_device_pager_objects, pager_link) {
        if (object->un_pager.devp.handle == handle) {
            vm_object_reference(object);
            device_pager_unlock();
            return object;
        }
    }
    device_pager_unlock();
    return 0;
}

vm_object_t
cdev_pager_allocate(void *handle, objtype_t type,
    const struct cdev_pager_ops *operations, vm_ooffset_t size,
    vm_prot_t protection, vm_ooffset_t offset,
    struct ucred *credential)
{
    vm_object_t object;
    vm_object_t existing;
    vm_pindex_t pages;
    unsigned short color = 0;

    if (!handle || !operations ||
        (type != OBJT_DEVICE && type != OBJT_MGTDEVICE) || size == 0 ||
        (offset & (PAGE_SIZE - 1u)) != 0 ||
        size > UINT64_MAX - (PAGE_SIZE - 1u) - offset ||
        (type == OBJT_DEVICE && operations->cdev_pg_populate))
        return 0;
    pages = OFF_TO_IDX(offset + size + PAGE_SIZE - 1u);
    if (pages == 0)
        return 0;

    existing = cdev_pager_lookup(handle);
    if (existing) {
        if (existing->type != type ||
            existing->un_pager.devp.ops != operations) {
            vm_object_deallocate(existing);
            return 0;
        }
        VM_OBJECT_WLOCK(existing);
        if (pages > existing->size)
            existing->size = pages;
        VM_OBJECT_WUNLOCK(existing);
        return existing;
    }

    object = vm_object_allocate(type, pages);
    if (!object)
        return 0;
    object->handle = handle;
    object->un_pager.devp.handle = handle;
    object->un_pager.devp.ops = operations;
    if (operations->cdev_pg_ctor && operations->cdev_pg_ctor(handle,
        size, protection, offset, credential, &color) != 0) {
        vm_object_deallocate(object);
        return 0;
    }

    device_pager_lock();
    TAILQ_FOREACH(existing, &g_device_pager_objects, pager_link) {
        if (existing->un_pager.devp.handle != handle)
            continue;
        vm_object_reference(existing);
        device_pager_unlock();
        if (operations->cdev_pg_dtor)
            operations->cdev_pg_dtor(handle);
        object->un_pager.devp.ops = 0;
        object->un_pager.devp.handle = 0;
        vm_object_deallocate(object);
        if (existing->type != type ||
            existing->un_pager.devp.ops != operations) {
            vm_object_deallocate(existing);
            return 0;
        }
        VM_OBJECT_WLOCK(existing);
        if (pages > existing->size)
            existing->size = pages;
        VM_OBJECT_WUNLOCK(existing);
        return existing;
    }
    TAILQ_INSERT_TAIL(&g_device_pager_objects, object, pager_link);
    object->pager_registered = 1;
    device_pager_unlock();
    return object;
}

void
cdev_pager_free_page(vm_object_t object, vm_page_t page)
{
    if (!object || !page || page->object != object ||
        (object->type != OBJT_DEVICE && object->type != OBJT_MGTDEVICE))
        return;
    vm_page_object_remove(object, page);
}

int
vm_object_pager_physical_address(vm_object_t object,
    vm_ooffset_t offset, vm_paddr_t *physical_address)
{
    struct sglist *segments;

    if (!object || !physical_address || offset >= IDX_TO_OFF(object->size) ||
        object->type != OBJT_SG || !object->handle)
        return 22;
    segments = object->handle;
    for (unsigned int index = 0; index < segments->sg_nseg; ++index) {
        const struct sglist_seg *segment = &segments->sg_segs[index];

        if (offset < segment->ss_len) {
            if (segment->ss_paddr > UINT64_MAX - offset)
                return 22;
            *physical_address = segment->ss_paddr + offset;
            return 0;
        }
        offset -= segment->ss_len;
    }
    return 22;
}

void
vm_pager_deallocate(vm_object_t object)
{
    const struct cdev_pager_ops *operations;
    void *handle;

    if (!object)
        return;
    if (object->type != OBJT_DEVICE && object->type != OBJT_MGTDEVICE) {
        vm_object_deallocate(object);
        return;
    }
    operations = object->un_pager.devp.ops;
    handle = object->un_pager.devp.handle;
    VM_OBJECT_WUNLOCK(object);
    if (operations && operations->cdev_pg_dtor)
        operations->cdev_pg_dtor(handle);
    device_pager_lock();
    if (object->pager_registered) {
        TAILQ_REMOVE(&g_device_pager_objects, object, pager_link);
        object->pager_registered = 0;
    }
    device_pager_unlock();
    VM_OBJECT_WLOCK(object);
    object->handle = 0;
    object->un_pager.devp.handle = 0;
    object->un_pager.devp.ops = 0;
    object->type = OBJT_DEAD;
    object->edgeos_destroy_on_unlock = 1;
}

void
vm_object_deallocate(vm_object_t object)
{
    vm_page_t page;

    if (!object || __atomic_fetch_sub(&object->references, 1u,
        __ATOMIC_ACQ_REL) != 1u)
        return;
    for (;;) {
        vm_object_wlock(object);
        page = TAILQ_FIRST(&object->pages);
        if (page) {
            vm_page_object_remove(object, page);
        }
        vm_object_wunlock(object);
        if (!page)
            break;
        vm_page_free(page);
    }
    if (object->pager_registered) {
        device_pager_lock();
        if (object->pager_registered) {
            TAILQ_REMOVE(&g_device_pager_objects, object, pager_link);
            object->pager_registered = 0;
        }
        device_pager_unlock();
    }
    if ((object->type == OBJT_DEVICE || object->type == OBJT_MGTDEVICE) &&
        object->un_pager.devp.ops &&
        object->un_pager.devp.ops->cdev_pg_dtor)
        object->un_pager.devp.ops->cdev_pg_dtor(
            object->un_pager.devp.handle);
    if (object->type == OBJT_SG && object->handle)
        sglist_free(object->handle);
    bsd_kfree(object);
}

vm_page_t
vm_page_lookup(vm_object_t object, vm_pindex_t index)
{
    vm_page_t page;

    if (!object)
        return 0;
    TAILQ_FOREACH(page, &object->pages, object_link) {
        if (page->pindex == index)
            return page;
        if (page->pindex > index)
            break;
    }
    return 0;
}

vm_page_t
vm_page_grab(vm_object_t object, vm_pindex_t index, int flags)
{
    vm_page_t page;
    vm_page_t cursor;
    int allocation_flags;

    if (!object || (object->type != OBJT_PHYS && index >= object->size))
        return 0;
    page = vm_page_lookup(object, index);
    if (page) {
        if ((flags & VM_ALLOC_WIRED) != 0)
            vm_page_wire(page);
        if ((flags & VM_ALLOC_ZERO) != 0 &&
            page->valid != VM_PAGE_BITS_ALL) {
            bsd_memset(page->edgeos_page, 0, PAGE_SIZE);
            page->valid = VM_PAGE_BITS_ALL;
        }
        return page;
    }
    if ((flags & VM_ALLOC_NOCREAT) != 0)
        return 0;
    allocation_flags = flags;
    if ((allocation_flags & (VM_ALLOC_NOWAIT | VM_ALLOC_WAITOK)) == 0)
        allocation_flags |= VM_ALLOC_WAITOK;
    page = vm_page_alloc_noobj(allocation_flags);
    if (!page)
        return 0;
    if (object->type == OBJT_PHYS && index >= object->size)
        object->size = index + 1u;
    page->valid = (flags & VM_ALLOC_ZERO) != 0 ? VM_PAGE_BITS_ALL : 0;
    (void)cursor;
    vm_page_object_insert(object, page, index);
    return page;
}

bool
vm_page_unwire(vm_page_t page, uint8_t queue)
{
    bool unwired;

    unwired = vm_page_unwire_noq(page);
    if (page && unwired)
        page->a.queue = queue;
    return unwired;
}

bool
vm_page_wired(vm_page_t page)
{
    return page && VPRC_WIRE_COUNT(__atomic_load_n(&page->ref_count,
        __ATOMIC_ACQUIRE)) != 0;
}

void
vm_page_xunbusy(vm_page_t page)
{
    if (page)
        __atomic_store_n(&page->busy_lock, 0u, __ATOMIC_RELEASE);
}

bool
vm_page_busy_acquire(vm_page_t page, int allocation_flags)
{
    if (!page)
        return false;
    for (;;) {
        uint32_t expected = 0;

        if (__atomic_compare_exchange_n(&page->busy_lock, &expected, 1u,
            0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return true;
        if ((allocation_flags & (VM_ALLOC_NOWAIT | VM_ALLOC_WAITFAIL)) != 0)
            return false;
        __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

void
vm_page_remove_xbusy(vm_page_t page)
{
    if (!page || !page->object)
        return;
    vm_page_object_remove(page->object, page);
}

int
vm_page_free_pages_toq(struct spglist *pages, bool update_wire_count)
{
    vm_page_t page;
    int count = 0;

    if (!pages)
        return 0;
    while ((page = SLIST_FIRST(pages)) != 0) {
        SLIST_REMOVE_HEAD(pages, plinks.s.ss);
        if (update_wire_count && vm_page_wired(page))
            (void)vm_page_unwire_noq(page);
        vm_page_free(page);
        ++count;
    }
    return count;
}

void
pmap_zero_page(vm_page_t page)
{
    if (!page || !page->edgeos_page)
        return;
    bsd_memset(page->edgeos_page, 0, PAGE_SIZE);
    page->flags |= PG_ZERO;
    page->valid = VM_PAGE_BITS_ALL;
}

#ifndef BSD_BRIDGE_HOST_TEST
int vm_ndomains = 1;

struct proc *
bsd_curproc(void)
{
    struct thread *thread = bsd_kthread_current_public();
    kernel_proc_task_view_t view;
    kernel_process_task_handle_t task;
    uint64_t address_space = 0;
    uint64_t flags;

    if (!thread || !thread->td_proc)
        return 0;
    flags = arch_process_task_lock();
    task = arch_process_current_task_locked();
    if (task && arch_process_task_view_locked(task, &view) == 0)
        address_space = view.memory_context_id;
    arch_process_task_unlock(flags);
    thread->td_proc->p_vmspace = &thread->td_proc->p_edgeos_vmspace;
    thread->td_proc->p_vmspace->vm_map.edgeos_address_space =
        address_space;
    thread->td_proc->p_vmspace->vm_pmap.edgeos_address_space =
        address_space;
    return thread->td_proc;
}

#if defined(__x86_64__)
void
smp_targeted_tlb_shootdown_native(pmap_t pmap, vm_offset_t start,
    vm_offset_t end, smp_invl_local_cb_t local_callback,
    enum invl_op_codes operation)
{
    (void)operation;
    if (local_callback)
        local_callback(pmap, start, end);
}

smp_targeted_tlb_shootdown_t smp_targeted_tlb_shootdown =
    smp_targeted_tlb_shootdown_native;
#endif

vm_paddr_t
pmap_extract(pmap_t pmap, vm_offset_t virtual_address)
{
    struct bsd_pmap_mapping *mapping;
    uint64_t physical_address;

    if (!pmap)
        return 0;
    if (pmap == kernel_pmap)
        return bsd_pmap_kextract((uintptr_t)virtual_address);
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        if ((virtual_address & ~(vm_offset_t)(PAGE_SIZE - 1u)) !=
            mapping->virtual_address)
            continue;
        physical_address = mapping->physical_address |
            (virtual_address & (PAGE_SIZE - 1u));
        pmap_unlock(pmap);
        return physical_address;
    }
    pmap_unlock(pmap);
    if (!pmap->edgeos_address_space ||
        arch_vm_translate(pmap->edgeos_address_space,
        (uint64_t)virtual_address, &physical_address, 0) != 0)
        return 0;
    return physical_address;
}

int
pmap_pinit(pmap_t pmap)
{
    if (!pmap)
        return 12;
    pmap->edgeos_address_space = 0;
    pmap->lock = 0;
    pmap->edgeos_mappings = 0;
    return 0;
}

int
pmap_enter(pmap_t pmap, vm_offset_t virtual_address, vm_page_t page,
    vm_prot_t protection, unsigned int flags, int8_t page_size_index)
{
    struct bsd_pmap_mapping *mapping;
    vm_offset_t page_address;
    unsigned int allowed_flags = VM_PROT_ALL | PMAP_ENTER_NOSLEEP |
        PMAP_ENTER_WIRED | PMAP_ENTER_UNPROTECTED;

    if (!pmap || !page || page_size_index != 0 ||
        (protection & ~VM_PROT_ALL) != 0 ||
        (flags & ~allowed_flags) != 0)
        return 22;
    page_address = virtual_address & ~(vm_offset_t)(PAGE_SIZE - 1u);
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        if (mapping->virtual_address == page_address)
            break;
    }
    if (!mapping) {
        mapping = bsd_malloc(sizeof(*mapping), M_DEVBUF,
            M_NOWAIT | M_ZERO);
        if (!mapping) {
            pmap_unlock(pmap);
            return 12;
        }
        mapping->virtual_address = page_address;
        mapping->next = pmap->edgeos_mappings;
        pmap->edgeos_mappings = mapping;
    } else if (mapping->wired && mapping->page) {
        (void)vm_page_unwire_noq(mapping->page);
    }
    mapping->physical_address = VM_PAGE_TO_PHYS(page) &
        ~(vm_paddr_t)(PAGE_SIZE - 1u);
    mapping->page = page;
    mapping->protection = protection;
    mapping->wired = (flags & PMAP_ENTER_WIRED) != 0;
    if (mapping->wired)
        vm_page_wire(page);
    pmap_unlock(pmap);
    return 0;
}

void
pmap_remove(pmap_t pmap, vm_offset_t start, vm_offset_t end)
{
    struct bsd_pmap_mapping **link;

    if (!pmap || start >= end)
        return;
    start &= ~(vm_offset_t)(PAGE_SIZE - 1u);
    if (end > UINTPTR_MAX - (PAGE_SIZE - 1u))
        end = UINTPTR_MAX & ~(vm_offset_t)(PAGE_SIZE - 1u);
    else
        end = (end + PAGE_SIZE - 1u) &
            ~(vm_offset_t)(PAGE_SIZE - 1u);
    pmap_lock(pmap);
    for (link = &pmap->edgeos_mappings; *link;) {
        struct bsd_pmap_mapping *mapping = *link;

        if (mapping->virtual_address < start ||
            mapping->virtual_address >= end) {
            link = &mapping->next;
            continue;
        }
        *link = mapping->next;
        if (mapping->wired && mapping->page)
            (void)vm_page_unwire_noq(mapping->page);
        bsd_free(mapping, M_DEVBUF);
    }
    pmap_unlock(pmap);
}

void
pmap_release(pmap_t pmap)
{
    struct bsd_pmap_mapping *mapping;

    if (!pmap)
        return;
    pmap_lock(pmap);
    mapping = pmap->edgeos_mappings;
    pmap->edgeos_mappings = 0;
    pmap->edgeos_address_space = 0;
    while (mapping) {
        struct bsd_pmap_mapping *next = mapping->next;

        if (mapping->wired && mapping->page)
            (void)vm_page_unwire_noq(mapping->page);
        bsd_free(mapping, M_DEVBUF);
        mapping = next;
    }
    pmap_unlock(pmap);
}

static void
vm_page_release_descriptors(vm_page_t *pages, int page_count)
{
    for (int index = 0; index < page_count; ++index) {
        if (pages[index]) {
            vm_page_free(pages[index]);
            pages[index] = 0;
        }
    }
}

int
vm_fault_hold_pages(vm_map_t map, vm_offset_t address, vm_size_t length,
    vm_prot_t protection, vm_page_t *pages, int maximum_pages,
    int *page_count)
{
    uint64_t first;
    uint64_t last;
    uint64_t current;
    uint32_t required = 0;
    int held = 0;

    if (page_count)
        *page_count = 0;
    if (!map || !map->edgeos_address_space || !pages || !page_count ||
        maximum_pages <= 0 || length == 0 ||
        address > UINTPTR_MAX - length)
        return EDGE_LINUX_EFAULT;
    if ((protection & ~(VM_PROT_READ | VM_PROT_WRITE |
        VM_PROT_EXECUTE)) != 0)
        return EDGE_LINUX_EINVAL;
    if ((protection & VM_PROT_READ) != 0)
        required |= ARCH_VM_PROT_READ;
    if ((protection & VM_PROT_WRITE) != 0)
        required |= ARCH_VM_PROT_WRITE;
    if ((protection & VM_PROT_EXECUTE) != 0)
        required |= ARCH_VM_PROT_EXEC;
    first = (uint64_t)address & ~(uint64_t)(PAGE_SIZE - 1u);
    last = ((uint64_t)address + (uint64_t)length - 1u) &
        ~(uint64_t)(PAGE_SIZE - 1u);
    if ((last - first) / PAGE_SIZE >= (uint64_t)maximum_pages)
        return EDGE_LINUX_EFAULT;

    for (current = first;; current += PAGE_SIZE) {
        vm_page_t descriptor;
        uint64_t physical;
        uint32_t actual;

        if (kernel_mm_resolve_user_page(
            map->edgeos_address_space, current, required) <= 0 ||
            arch_vm_user_page_protection(map->edgeos_address_space,
                current, &actual) != 0 ||
            (actual & required) != required ||
            arch_vm_translate(map->edgeos_address_space, current,
                &physical, 0) != 0)
            goto fault;
        descriptor = bsd_kmalloc(sizeof(*descriptor),
            BSD_M_WAITOK | BSD_M_ZERO);
        if (!descriptor)
            goto no_memory;
        descriptor->a.queue = PQ_NONE;
        descriptor->phys_addr = physical & ~(uint64_t)(PAGE_SIZE - 1u);
        descriptor->edgeos_page =
            (void *)(uintptr_t)descriptor->phys_addr;
        descriptor->edgeos_flags = EDGEOS_VM_PAGE_USER_HOLD;
        pages[held++] = descriptor;
        if (current == last)
            break;
    }
    *page_count = held;
    return 0;

no_memory:
    vm_page_release_descriptors(pages, held);
    return EDGE_LINUX_ENOMEM;
fault:
    vm_page_release_descriptors(pages, held);
    return EDGE_LINUX_EFAULT;
}

void
vm_page_unhold_pages(vm_page_t *pages, int page_count)
{
    if (!pages || page_count <= 0)
        return;
    vm_page_release_descriptors(pages, page_count);
}
#endif
