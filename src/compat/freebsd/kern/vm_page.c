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
#include "compat/freebsd/sys/systm.h"
typedef unsigned int u_int;
typedef unsigned long u_long;
#include <sys/vmmeter.h>
#include "compat/freebsd/vm/vm_page.h"
#include "compat/freebsd/vm/vm_object.h"
#include "compat/freebsd/vm/vm_pager.h"
#include "compat/freebsd/vm/vm_param.h"
#include "compat/freebsd/vm/vm_extern.h"
#include "compat/freebsd/vm/pmap.h"
#include "compat/freebsd/vm/vm_phys.h"
#include "compat/freebsd/sys/sglist.h"

#if (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)
#include <machine/armreg.h>
#endif

#ifndef BSD_BRIDGE_HOST_TEST
#include "kernel/linux_errno.h"
#include "kernel/mm_runtime.h"
#include "kernel/proc_maps.h"
#include "kernel/process_runtime.h"
#include "mm/arch_vm.h"
#endif

#define BSD_VM_PAGE_ALLOWED_FLAGS \
    (VM_ALLOC_CLASS_MASK | VM_ALLOC_NOWAIT | VM_ALLOC_WAITOK | \
     VM_ALLOC_WIRED | VM_ALLOC_ZERO | VM_ALLOC_NOBUSY | VM_ALLOC_NODUMP | \
     VM_ALLOC_NOCREAT | VM_ALLOC_WAITFAIL | VM_ALLOC_NORECLAIM)

void
pmap_allow_2m_x_ept_recalculate(void)
{
    /* EdgeOS does not expose nested EPT mappings to imported drivers. */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

vm_page_t bogus_page;
struct pmap edgeos_kernel_pmap;
static struct vm_object edgeos_kernel_object_storage;
vm_object_t kernel_object = &edgeos_kernel_object_storage;
struct vmmeter vm_cnt = {
    .v_page_size = 4096u,
};
u_long vm_user_wire_count;

int
vm_fault_disable_pagefaults(void)
{
    struct thread *thread = bsd_kthread_current_public();
    int saved_flags;

    if (!thread)
        return 0;
    saved_flags = (int)thread->td_pflags;
    thread->td_pflags |= TDP_NOFAULTING;
    return saved_flags;
}

void
vm_fault_enable_pagefaults(int saved_flags)
{
    struct thread *thread = bsd_kthread_current_public();

    if (!thread)
        return;
    thread->td_pflags = (thread->td_pflags & ~TDP_NOFAULTING) |
        ((uint32_t)saved_flags & TDP_NOFAULTING);
}

struct bsd_pmap_mapping {
    struct bsd_pmap_mapping *next;
    vm_offset_t virtual_address;
    vm_paddr_t physical_address;
    vm_page_t page;
    vm_prot_t protection;
    uint8_t wired;
    uint8_t dirty_tracked;
    uint8_t dirty;
    uint8_t dirty_write_protected;
};

#ifndef BSD_BRIDGE_HOST_TEST
#define BSD_PMAP_MAPPING_CHUNK_CAPACITY 4096u

struct bsd_pmap_mapping_chunk {
    struct bsd_pmap_mapping_chunk *next;
    struct bsd_pmap_mapping mappings[BSD_PMAP_MAPPING_CHUNK_CAPACITY];
};

static struct bsd_pmap_mapping *
pmap_mapping_alloc_locked(pmap_t pmap)
{
    struct bsd_pmap_mapping_chunk *chunk;
    struct bsd_pmap_mapping *mapping;

    if (!pmap->edgeos_mapping_free) {
        chunk = bsd_kmalloc(sizeof(*chunk), BSD_M_NOWAIT | BSD_M_ZERO);
        if (!chunk)
            return 0;
        chunk->next = pmap->edgeos_mapping_chunks;
        pmap->edgeos_mapping_chunks = chunk;
        for (unsigned int index = 0;
             index < BSD_PMAP_MAPPING_CHUNK_CAPACITY; ++index) {
            chunk->mappings[index].next = pmap->edgeos_mapping_free;
            pmap->edgeos_mapping_free = &chunk->mappings[index];
        }
    }
    mapping = pmap->edgeos_mapping_free;
    pmap->edgeos_mapping_free = mapping->next;
    __builtin_memset(mapping, 0, sizeof(*mapping));
    return mapping;
}

static void
pmap_mapping_free_locked(pmap_t pmap, struct bsd_pmap_mapping *mapping)
{
    __builtin_memset(mapping, 0, sizeof(*mapping));
    mapping->next = pmap->edgeos_mapping_free;
    pmap->edgeos_mapping_free = mapping;
}
#endif

struct bsd_pmap_table_page {
    struct bsd_pmap_table_page *next;
    vm_page_t page;
};

#ifdef BSD_BRIDGE_HOST_TEST
int
pmap_pinit(pmap_t pmap)
{
    return pmap_pinit_type(pmap, PT_X86, 0);
}

int
pmap_pinit_type(pmap_t pmap, enum pmap_type type, int flags)
{
    const int allowed_flags = PMAP_NESTED_IPIMASK |
        PMAP_PDE_SUPERPAGE | PMAP_EMULATE_AD_BITS |
        PMAP_SUPPORTS_EXEC_ONLY;
    vm_page_t root_page;

    if (!pmap || type < PT_X86 || type > PT_RVI ||
        (flags & ~allowed_flags) != 0)
        return 0;
    root_page = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO |
        VM_ALLOC_WAITOK);
    if (!root_page)
        return 0;
    pmap->pm_cr3 = VM_PAGE_TO_PHYS(root_page);
    pmap->lock = 0;
    pmap->edgeos_mappings = 0;
    pmap->edgeos_mapping_tail = 0;
    pmap->edgeos_mapping_free = 0;
    pmap->edgeos_mapping_chunks = 0;
    pmap->edgeos_table_pages = 0;
    pmap->edgeos_root_page = root_page;
    pmap->pm_pmltop = vm_page_direct_map(root_page);
    smr_init(&pmap->edgeos_eptsmr);
    pmap->pm_eptsmr = &pmap->edgeos_eptsmr;
    CPU_ZERO(&pmap->pm_active);
    pmap->pm_eptgen = 0;
    pmap->pm_type = type;
    pmap->pm_flags = (uint32_t)flags;
    return 1;
}

#endif

#ifndef BSD_BRIDGE_HOST_TEST

#define EDGEOS_PMAP_ENTRY_ADDRESS 0x000ffffffffff000ull
#define EDGEOS_RVI_PRESENT 0x001ull
#define EDGEOS_RVI_WRITE 0x002ull
#define EDGEOS_RVI_USER 0x004ull
#define EDGEOS_RVI_NO_EXECUTE (1ull << 63)
#define EDGEOS_EPT_READ 0x001ull
#define EDGEOS_EPT_WRITE 0x002ull
#define EDGEOS_EPT_EXECUTE 0x004ull
#define EDGEOS_EPT_MEMORY_WB (6ull << 3)
#define EDGEOS_ARM64_TABLE UINT64_C(0x003)
#define EDGEOS_ARM64_PAGE UINT64_C(0x003)
#define EDGEOS_ARM64_AF (UINT64_C(1) << 10)
#define EDGEOS_ARM64_S2_READ (UINT64_C(1) << 6)
#define EDGEOS_ARM64_S2_WRITE (UINT64_C(1) << 7)
#define EDGEOS_ARM64_S2_MEMORY_WB (UINT64_C(0xf) << 2)
#define EDGEOS_ARM64_S2_XN_ALL (UINT64_C(2) << 53)

static vm_page_t
pmap_nested_table_alloc(pmap_t pmap)
{
    struct bsd_pmap_table_page *table_page;
    vm_page_t page;

    page = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO |
        VM_ALLOC_NOWAIT);
    if (!page)
        return 0;
    table_page = bsd_kmalloc(sizeof(*table_page),
        BSD_M_NOWAIT | BSD_M_ZERO);
    if (!table_page) {
        vm_page_free(page);
        return 0;
    }
    table_page->page = page;
    table_page->next = pmap->edgeos_table_pages;
    pmap->edgeos_table_pages = table_page;
    return page;
}

static uint64_t
pmap_nested_nonleaf_flags(const pmap_t pmap)
{
    if (pmap->pm_type == PT_ARM64_STAGE2)
        return EDGEOS_ARM64_TABLE;
    if (pmap->pm_type == PT_EPT)
        return EDGEOS_EPT_READ | EDGEOS_EPT_WRITE | EDGEOS_EPT_EXECUTE;
    return EDGEOS_RVI_PRESENT | EDGEOS_RVI_WRITE | EDGEOS_RVI_USER;
}

static uint64_t
pmap_nested_leaf_flags(const pmap_t pmap, vm_prot_t protection)
{
    uint64_t flags;

    if (pmap->pm_type == PT_ARM64_STAGE2) {
        flags = EDGEOS_ARM64_PAGE | EDGEOS_ARM64_AF |
            EDGEOS_ARM64_S2_MEMORY_WB;
        if ((protection & VM_PROT_READ) != 0)
            flags |= EDGEOS_ARM64_S2_READ;
        if ((protection & VM_PROT_WRITE) != 0)
            flags |= EDGEOS_ARM64_S2_WRITE;
        if ((protection & VM_PROT_EXECUTE) == 0)
            flags |= EDGEOS_ARM64_S2_XN_ALL;
        return flags;
    }
    if (pmap->pm_type == PT_EPT) {
        flags = EDGEOS_EPT_MEMORY_WB;
        if ((protection & VM_PROT_READ) != 0)
            flags |= EDGEOS_EPT_READ;
        if ((protection & VM_PROT_WRITE) != 0)
            flags |= EDGEOS_EPT_WRITE;
        if ((protection & VM_PROT_EXECUTE) != 0)
            flags |= EDGEOS_EPT_EXECUTE;
        return flags;
    }
    flags = EDGEOS_RVI_PRESENT | EDGEOS_RVI_USER;
    if ((protection & VM_PROT_WRITE) != 0)
        flags |= EDGEOS_RVI_WRITE;
    if ((protection & VM_PROT_EXECUTE) == 0)
        flags |= EDGEOS_RVI_NO_EXECUTE;
    return flags;
}

static int
pmap_nested_enter_locked(pmap_t pmap, vm_offset_t virtual_address,
    vm_page_t page, vm_prot_t protection)
{
    static const unsigned int shifts[] = {39u, 30u, 21u};
    unsigned int first_level;
    unsigned int table_levels;
    uint64_t *table;

    if (pmap->pm_type != PT_EPT && pmap->pm_type != PT_RVI &&
        pmap->pm_type != PT_ARM64_STAGE2)
        return 0;
    table_levels = pmap->pm_type == PT_ARM64_STAGE2 ?
        (unsigned int)pmap->pm_levels : 4u;
    if (table_levels < 2u || table_levels > 4u)
        return 22;
    first_level = 4u - table_levels;
    table = vm_page_direct_map(pmap->edgeos_root_page);
    if (!table)
        return 12;
    for (unsigned int level = first_level; level < 3u; ++level) {
        const unsigned int index =
            ((uint64_t)virtual_address >> shifts[level]) & 0x1ffu;
        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_ACQUIRE);
        vm_page_t child_page;

        if ((entry & 0x3u) == 0) {
            child_page = pmap_nested_table_alloc(pmap);
            if (!child_page)
                return 12;
            entry = (VM_PAGE_TO_PHYS(child_page) &
                EDGEOS_PMAP_ENTRY_ADDRESS) |
                pmap_nested_nonleaf_flags(pmap);
            __atomic_store_n(&table[index], entry, __ATOMIC_RELEASE);
        } else {
            child_page = PHYS_TO_VM_PAGE(entry &
                EDGEOS_PMAP_ENTRY_ADDRESS);
            if (!child_page)
                return 14;
        }
        table = vm_page_direct_map(child_page);
        if (!table)
            return 14;
    }
    {
        uint64_t flags = pmap_nested_leaf_flags(pmap, protection);

        if (pmap->pm_type == PT_EPT &&
            page->a.act_count == VM_MEMATTR_UNCACHEABLE)
            flags &= ~EDGEOS_EPT_MEMORY_WB;
        if (pmap->pm_type == PT_ARM64_STAGE2 &&
            page->a.act_count == VM_MEMATTR_UNCACHEABLE)
            flags &= ~EDGEOS_ARM64_S2_MEMORY_WB;
        __atomic_store_n(&table[((uint64_t)virtual_address >> PAGE_SHIFT) &
            0x1ffu], (VM_PAGE_TO_PHYS(page) &
            EDGEOS_PMAP_ENTRY_ADDRESS) | flags, __ATOMIC_RELEASE);
    }
    return 0;
}

static void
pmap_nested_remove_locked(pmap_t pmap, vm_offset_t virtual_address)
{
    static const unsigned int shifts[] = {39u, 30u, 21u};
    unsigned int first_level;
    uint64_t *table;

    if ((pmap->pm_type != PT_EPT && pmap->pm_type != PT_RVI &&
        pmap->pm_type != PT_ARM64_STAGE2) ||
        !pmap->edgeos_root_page)
        return;
    first_level = pmap->pm_type == PT_ARM64_STAGE2 ?
        4u - (unsigned int)pmap->pm_levels : 0u;
    table = vm_page_direct_map(pmap->edgeos_root_page);
    for (unsigned int level = first_level; table && level < 3u; ++level) {
        uint64_t entry = __atomic_load_n(
            &table[((uint64_t)virtual_address >> shifts[level]) & 0x1ffu],
            __ATOMIC_ACQUIRE);
        vm_page_t child_page;

        if ((entry & 0x7u) == 0)
            return;
        child_page = PHYS_TO_VM_PAGE(entry & EDGEOS_PMAP_ENTRY_ADDRESS);
        if (!child_page)
            return;
        table = vm_page_direct_map(child_page);
    }
    if (table)
        __atomic_store_n(&table[((uint64_t)virtual_address >> PAGE_SHIFT) &
            0x1ffu], 0, __ATOMIC_RELEASE);
}

static uint64_t *
pmap_nested_leaf_locked(pmap_t pmap, vm_offset_t virtual_address)
{
    static const unsigned int shifts[] = {39u, 30u, 21u};
    uint64_t *table;

    if ((pmap->pm_type != PT_EPT && pmap->pm_type != PT_RVI) ||
        !pmap->edgeos_root_page)
        return 0;
    table = vm_page_direct_map(pmap->edgeos_root_page);
    for (unsigned int level = 0; table && level < 3u; ++level) {
        uint64_t entry = __atomic_load_n(
            &table[((uint64_t)virtual_address >> shifts[level]) & 0x1ffu],
            __ATOMIC_ACQUIRE);
        vm_page_t child_page;

        if ((entry & 0x7u) == 0)
            return 0;
        child_page = PHYS_TO_VM_PAGE(entry & EDGEOS_PMAP_ENTRY_ADDRESS);
        if (!child_page)
            return 0;
        table = vm_page_direct_map(child_page);
    }
    return table ? &table[((uint64_t)virtual_address >> PAGE_SHIFT) &
        0x1ffu] : 0;
}

#endif

#ifdef BSD_BRIDGE_HOST_TEST

void
pmap_release(pmap_t pmap)
{
    struct bsd_pmap_mapping *mapping;
    vm_page_t root_page;

    if (!pmap)
        return;
#if (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)
    if (pmap->pm_stage == PM_STAGE2 && pmap_stage2_invalidate_all)
        pmap_stage2_invalidate_all(pmap_to_ttbr0(pmap));
#endif
    edgeos_smr_write_enter(pmap->pm_eptsmr);
    pmap_lock(pmap);
    mapping = pmap->edgeos_mappings;
    pmap->edgeos_mappings = 0;
    root_page = pmap->edgeos_root_page;
    pmap->edgeos_root_page = 0;
    pmap->pm_pmltop = 0;
    pmap->edgeos_address_space = 0;
    while (mapping) {
        struct bsd_pmap_mapping *next = mapping->next;

        if (mapping->wired && mapping->page)
            (void)vm_page_unwire_noq(mapping->page);
        bsd_kfree(mapping);
        mapping = next;
    }
    pmap_unlock(pmap);
    if (root_page)
        vm_page_free(root_page);
#if (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)
    pmap_stage2_vmid_free(pmap->pm_vmid);
    pmap->pm_vmid = 0;
    pmap->pm_stage = PM_INVALID;
#endif
    edgeos_smr_write_exit(pmap->pm_eptsmr);
}
#endif

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
static volatile unsigned long g_physical_page_count;
struct bsd_fictitious_page {
    struct vm_page page;
    SLIST_ENTRY(bsd_fictitious_page) range_link;
};

struct bsd_fictitious_range {
    vm_paddr_t start;
    vm_paddr_t end;
    vm_memattr_t memory_attribute;
    SLIST_HEAD(, bsd_fictitious_page) pages;
    SLIST_ENTRY(bsd_fictitious_range) range_link;
};

static SLIST_HEAD(, bsd_fictitious_range) g_fictitious_ranges =
    SLIST_HEAD_INITIALIZER(g_fictitious_ranges);
static volatile uint32_t g_fictitious_ranges_guard;
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
fictitious_ranges_lock(void)
{
    while (__atomic_exchange_n(&g_fictitious_ranges_guard, 1u,
        __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&g_fictitious_ranges_guard,
            __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

static void
fictitious_ranges_unlock(void)
{
    __atomic_store_n(&g_fictitious_ranges_guard, 0u, __ATOMIC_RELEASE);
}

static vm_page_t
physical_page_lookup_locked(vm_paddr_t physical_address)
{
    vm_page_t page;

    SLIST_FOREACH(page, &g_physical_pages, physical_link) {
        if (page->phys_addr == physical_address)
            return page;
    }
    return 0;
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
    (void)__atomic_add_fetch(&g_physical_page_count, 1ul,
        __ATOMIC_RELAXED);
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
        (void)__atomic_sub_fetch(&g_physical_page_count, 1ul,
            __ATOMIC_RELAXED);
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

static void vm_page_object_remove(vm_object_t object, vm_page_t page);

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

void
vm_page_remove(vm_page_t page)
{
    if (page && page->object)
        vm_page_object_remove(page->object, page);
}

void
vm_page_replace(vm_page_t page, vm_object_t object, vm_pindex_t index,
    vm_page_t old_page)
{
    if (!page || !object)
        return;
    if (old_page && old_page->object == object)
        vm_page_remove(old_page);
    (void)vm_page_insert(page, object, index);
    if (old_page && old_page != page)
        vm_page_free(old_page);
}

unsigned int
vm_free_count(void)
{
    unsigned long allocated = __atomic_load_n(&g_physical_page_count,
        __ATOMIC_RELAXED);

    return physmem > allocated ? (unsigned int)(physmem - allocated) : 0;
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
    page = physical_page_lookup_locked(physical_address);
    physical_pages_unlock();
    if (page)
        return page;
    return vm_phys_fictitious_to_vm_page(physical_address);
}

int
vm_phys_fictitious_reg_range(vm_paddr_t start, vm_paddr_t end,
    vm_memattr_t memory_attribute)
{
    struct bsd_fictitious_range *range;
    struct bsd_fictitious_range *existing;

    if (start == 0 || start >= end ||
        (start & (PAGE_SIZE - 1u)) != 0 ||
        (end & (PAGE_SIZE - 1u)) != 0)
        return 22;
    range = bsd_kmalloc(sizeof(*range), BSD_M_WAITOK | BSD_M_ZERO);
    if (!range)
        return 12;
    range->start = start;
    range->end = end;
    range->memory_attribute = memory_attribute;
    SLIST_INIT(&range->pages);
    fictitious_ranges_lock();
    SLIST_FOREACH(existing, &g_fictitious_ranges, range_link) {
        if (start < existing->end && existing->start < end) {
            fictitious_ranges_unlock();
            bsd_kfree(range);
            return 17;
        }
    }
    SLIST_INSERT_HEAD(&g_fictitious_ranges, range, range_link);
    fictitious_ranges_unlock();
    return 0;
}

void
vm_phys_fictitious_unreg_range(vm_paddr_t start, vm_paddr_t end)
{
    struct bsd_fictitious_range **link;
    struct bsd_fictitious_range *range = 0;
    struct bsd_fictitious_page *page;

    fictitious_ranges_lock();
    for (link = &SLIST_FIRST(&g_fictitious_ranges); *link;
        link = &SLIST_NEXT(*link, range_link)) {
        if ((*link)->start != start || (*link)->end != end)
            continue;
        range = *link;
        *link = SLIST_NEXT(range, range_link);
        break;
    }
    if (!range) {
        fictitious_ranges_unlock();
        return;
    }
    while ((page = SLIST_FIRST(&range->pages)) != 0) {
        SLIST_REMOVE_HEAD(&range->pages, range_link);
        physical_pages_remove(&page->page);
        bsd_kfree(page);
    }
    fictitious_ranges_unlock();
    bsd_kfree(range);
}

vm_page_t
vm_phys_fictitious_to_vm_page(vm_paddr_t physical_address)
{
    struct bsd_fictitious_range *range;
    struct bsd_fictitious_page *candidate;
    struct bsd_fictitious_page *page;
    vm_memattr_t memory_attribute = VM_MEMATTR_DEFAULT;
    int found = 0;

    if ((physical_address & (PAGE_SIZE - 1u)) != 0)
        return 0;
    fictitious_ranges_lock();
    SLIST_FOREACH(range, &g_fictitious_ranges, range_link) {
        if (physical_address >= range->start &&
            physical_address < range->end) {
            memory_attribute = range->memory_attribute;
            found = 1;
            break;
        }
    }
    fictitious_ranges_unlock();
    if (!found)
        return 0;
    candidate = bsd_kmalloc(sizeof(*candidate),
        BSD_M_WAITOK | BSD_M_ZERO);
    if (!candidate)
        return 0;
    vm_page_initfake(&candidate->page, physical_address,
        memory_attribute);
    candidate->page.edgeos_flags |= EDGEOS_VM_PAGE_FICTITIOUS;

    fictitious_ranges_lock();
    SLIST_FOREACH(range, &g_fictitious_ranges, range_link) {
        if (physical_address < range->start ||
            physical_address >= range->end)
            continue;
        SLIST_FOREACH(page, &range->pages, range_link) {
            if (page->page.phys_addr == physical_address) {
                fictitious_ranges_unlock();
                bsd_kfree(candidate);
                return &page->page;
            }
        }
        physical_pages_lock();
        {
            vm_page_t existing =
                physical_page_lookup_locked(physical_address);

            if (existing) {
                physical_pages_unlock();
                fictitious_ranges_unlock();
                bsd_kfree(candidate);
                return existing;
            }
        }
        SLIST_INSERT_HEAD(&range->pages, candidate, range_link);
        SLIST_INSERT_HEAD(&g_physical_pages, &candidate->page,
            physical_link);
        (void)__atomic_add_fetch(&g_physical_page_count, 1ul,
            __ATOMIC_RELAXED);
        physical_pages_unlock();
        fictitious_ranges_unlock();
        return &candidate->page;
    }
    fictitious_ranges_unlock();
    bsd_kfree(candidate);
    return 0;
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

void *
vm_page_direct_map(vm_page_t page)
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
pmap_copy_page(vm_page_t source, vm_page_t destination)
{
    vm_page_t source_pages[1] = { source };
    vm_page_t destination_pages[1] = { destination };

    pmap_copy_pages(source_pages, 0, destination_pages, 0, PAGE_SIZE);
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
        void *source = vm_page_direct_map(source_pages[source_index]);
        void *destination =
            vm_page_direct_map(destination_pages[destination_index]);
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
    if (!page || (page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) == 0 ||
        (page->edgeos_flags & EDGEOS_VM_PAGE_FICTITIOUS) != 0)
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
vm_page_free_zero(vm_page_t page)
{
    vm_page_free(page);
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
    object->memattr = VM_MEMATTR_DEFAULT;
    object->domain.dr_policy = DOMAINSET_PREF(0);
    return object;
}

void
vm_object_reference(vm_object_t object)
{
    if (object)
        __atomic_add_fetch(&object->references, 1u, __ATOMIC_ACQ_REL);
}

int
vm_object_set_memattr(vm_object_t object, vm_memattr_t memattr)
{
    if (!object || memattr < VM_MEMATTR_UNCACHEABLE ||
        memattr >= VM_MEMATTR_END)
        return KERN_INVALID_ARGUMENT;
    object->memattr = memattr;
    return KERN_SUCCESS;
}

vm_object_t
vm_pager_allocate(objtype_t type, void *handle, vm_ooffset_t size,
    vm_prot_t protection, vm_ooffset_t offset, struct ucred *credential)
{
    vm_pindex_t pages;

    (void)protection;
    (void)credential;
    if ((type != OBJT_SWAP && type != OBJT_PHYS && type != OBJT_SG) ||
        size == 0 ||
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

void
cdev_mgtdev_pager_free_pages(vm_object_t object)
{
    vm_page_t page;
    vm_page_t next;

    if (!object || object->type != OBJT_MGTDEVICE)
        return;
    VM_OBJECT_WLOCK(object);
    for (page = TAILQ_FIRST(&object->pages); page; page = next) {
        next = TAILQ_NEXT(page, object_link);
        pmap_remove_all(page);
        vm_page_remove(page);
    }
    VM_OBJECT_WUNLOCK(object);
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

int
vm_page_grab_valid(vm_page_t *result, vm_object_t object,
    vm_pindex_t index, int flags)
{
    vm_page_t page;

    if (!result)
        return VM_PAGER_BAD;
    *result = 0;
    page = vm_page_grab(object, index, flags);
    if (!page)
        return VM_PAGER_FAIL;
    if (page->valid != VM_PAGE_BITS_ALL)
        pmap_zero_page(page);
    *result = page;
    return VM_PAGER_OK;
}

void
vm_object_page_remove(vm_object_t object, vm_pindex_t start,
    vm_pindex_t end, int flags)
{
    vm_page_t page;
    vm_page_t next;

    if (!object || end < start)
        return;
    for (page = TAILQ_FIRST(&object->pages); page; page = next) {
        next = TAILQ_NEXT(page, object_link);
        if (page->pindex < start)
            continue;
        if (page->pindex >= end)
            break;
        if ((flags & OBJPR_CLEANONLY) != 0 && page->dirty != 0)
            continue;
        if (vm_page_wired(page))
            continue;
        vm_page_free(page);
    }
}

bool
vm_page_unwire(vm_page_t page, uint8_t queue)
{
    bool unwired;
    bool fake;

    fake = page && (page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) != 0;
    unwired = vm_page_unwire_noq(page);
    if (page && unwired && !fake)
        page->a.queue = queue;
    if (unwired && fake)
        vm_page_putfake(page);
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
    kernel_proc_vma_accounting_t accounting;
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
    thread->td_proc->p_vmspace->vm_map.size = 0;
    if (address_space != 0 &&
        kernel_proc_vma_account(view.tgid > 0 ? view.tgid : view.tid,
            &accounting) == 0)
        thread->td_proc->p_vmspace->vm_map.size =
            accounting.virtual_size_bytes;
    thread->td_proc->p_vmspace->vm_map.pmap =
        &thread->td_proc->p_vmspace->vm_pmap;
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

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
void (*pmap_clean_stage2_tlbi)(void);
void (*pmap_stage2_invalidate_range)(uint64_t, vm_offset_t, vm_offset_t,
    bool);
void (*pmap_stage2_invalidate_all)(uint64_t);

static volatile uint32_t g_stage2_vmid_lock;
static uint64_t g_stage2_vmids[4] = { UINT64_C(1), 0, 0, 0 };

static void
pmap_stage2_vmid_lock(void)
{
    while (__atomic_exchange_n(&g_stage2_vmid_lock, 1u,
        __ATOMIC_ACQUIRE) != 0) {
        while (__atomic_load_n(&g_stage2_vmid_lock, __ATOMIC_RELAXED) != 0)
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

static void
pmap_stage2_vmid_unlock(void)
{
    __atomic_store_n(&g_stage2_vmid_lock, 0u, __ATOMIC_RELEASE);
}

static uint16_t
pmap_stage2_vmid_alloc(void)
{
    uint16_t vmid = 0;

    pmap_stage2_vmid_lock();
    for (unsigned int word = 0; word < 4u && vmid == 0; ++word) {
        uint64_t free_bits = ~g_stage2_vmids[word];

        if (free_bits != 0) {
            unsigned int bit = (unsigned int)__builtin_ctzll(free_bits);

            g_stage2_vmids[word] |= UINT64_C(1) << bit;
            vmid = (uint16_t)(word * 64u + bit);
        }
    }
    pmap_stage2_vmid_unlock();
    return vmid;
}

static void
pmap_stage2_vmid_free(uint16_t vmid)
{
    if (vmid == 0)
        return;
    pmap_stage2_vmid_lock();
    g_stage2_vmids[vmid / 64u] &= ~(UINT64_C(1) << (vmid % 64u));
    pmap_stage2_vmid_unlock();
}

int
pmap_pinit_stage(pmap_t pmap, enum pmap_stage stage, int levels)
{
    vm_page_t root_page;
    uint16_t vmid = 0;

    if (!pmap || (stage != PM_STAGE1 && stage != PM_STAGE2) ||
        levels < 2 || levels > 4)
        return 0;
    if (stage == PM_STAGE2) {
        vmid = pmap_stage2_vmid_alloc();
        if (vmid == 0)
            return 0;
    }
    root_page = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO |
        VM_ALLOC_WAITOK);
    if (!root_page) {
        pmap_stage2_vmid_free(vmid);
        return 0;
    }
    pmap->pm_cr3 = VM_PAGE_TO_PHYS(root_page);
    pmap->lock = 0;
    pmap->edgeos_mappings = 0;
    pmap->edgeos_mapping_tail = 0;
    pmap->edgeos_mapping_free = 0;
    pmap->edgeos_mapping_chunks = 0;
    pmap->edgeos_table_pages = 0;
    pmap->edgeos_root_page = root_page;
    pmap->pm_pmltop = vm_page_direct_map(root_page);
    smr_init(&pmap->edgeos_eptsmr);
    pmap->pm_eptsmr = &pmap->edgeos_eptsmr;
    CPU_ZERO(&pmap->pm_active);
    pmap->pm_eptgen = 0;
    pmap->pm_type = stage == PM_STAGE2 ?
        PT_ARM64_STAGE2 : PT_ARM64_STAGE1;
    pmap->pm_flags = 0;
    pmap->pm_vmid = vmid;
    pmap->pm_stage = (uint8_t)stage;
    pmap->pm_levels = (uint8_t)levels;
    pmap->pm_ttbr = VM_PAGE_TO_PHYS(root_page);
    return pmap->pm_pmltop != 0;
}

bool
pmap_vs_enabled(void)
{
    /* EdgeOS deliberately uses the universally available 8-bit VMID form. */
    return false;
}

void
pmap_remove_pages(pmap_t pmap)
{
    if (pmap)
        pmap_remove(pmap, 0, UINTPTR_MAX);
}

void
pmap_activate_vm(pmap_t pmap)
{
    if (pmap && pmap->pm_stage == PM_STAGE2)
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

uint64_t
pmap_to_ttbr0(pmap_t pmap)
{
    if (!pmap)
        return 0;
    return pmap->pm_ttbr | ((uint64_t)pmap->pm_vmid << 48);
}

int
pmap_fault(pmap_t pmap, uint64_t esr, uint64_t fault_address)
{
    struct bsd_pmap_mapping *mapping;
    uint64_t *table;
    unsigned int first_level;
    int dirty_write = 0;

    (void)esr;
    if (!pmap || pmap->pm_stage != PM_STAGE2 ||
        pmap->pm_levels < 2 || pmap->pm_levels > 4)
        return KERN_FAILURE;
    table = vm_page_direct_map(pmap->edgeos_root_page);
    first_level = 4u - (unsigned int)pmap->pm_levels;
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        if (mapping->virtual_address ==
            (fault_address & ~(vm_offset_t)(PAGE_SIZE - 1u)))
            break;
    }
    if (mapping && mapping->dirty_tracked &&
        (mapping->protection & VM_PROT_WRITE) != 0 &&
        ESR_ELx_EXCEPTION(esr) == EXCP_DATA_ABORT_L &&
        (esr & ISS_DATA_WnR) != 0) {
        mapping->dirty = 1;
        mapping->dirty_write_protected = 0;
        dirty_write = 1;
    }
    for (unsigned int level = first_level; table && level < 3u; ++level) {
        static const unsigned int shifts[] = {39u, 30u, 21u};
        uint64_t entry = table[(fault_address >> shifts[level]) & 0x1ffu];
        vm_page_t child;

        if ((entry & 0x3u) == 0) {
            table = 0;
            break;
        }
        child = PHYS_TO_VM_PAGE(entry & EDGEOS_PMAP_ENTRY_ADDRESS);
        table = child ? vm_page_direct_map(child) : 0;
    }
    if (table) {
        uint64_t *entry = &table[(fault_address >> PAGE_SHIFT) & 0x1ffu];

        if (*entry != 0) {
            uint64_t flags = EDGEOS_ARM64_AF | EDGEOS_ARM64_PAGE;

            if (dirty_write)
                flags |= EDGEOS_ARM64_S2_WRITE;
            __atomic_fetch_or(entry, flags, __ATOMIC_RELEASE);
            __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
            pmap_unlock(pmap);
            if (pmap_stage2_invalidate_range)
                pmap_stage2_invalidate_range(pmap_to_ttbr0(pmap),
                    fault_address & ~(vm_offset_t)(PAGE_SIZE - 1u),
                    (fault_address & ~(vm_offset_t)(PAGE_SIZE - 1u)) +
                        PAGE_SIZE,
                    true);
            return KERN_SUCCESS;
        }
    }
    pmap_unlock(pmap);
    return KERN_FAILURE;
}
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
    if (pmap->pm_type != PT_X86 || !pmap->edgeos_address_space ||
        arch_vm_translate(pmap->edgeos_address_space,
        (uint64_t)virtual_address, &physical_address, 0) != 0)
        return 0;
    return physical_address;
}

vm_page_t
pmap_extract_and_hold(pmap_t pmap, vm_offset_t virtual_address,
    vm_prot_t protection)
{
    vm_page_t page;
    vm_paddr_t physical_address;

    (void)protection;
    physical_address = pmap_extract(pmap, virtual_address) &
        ~(vm_paddr_t)(PAGE_SIZE - 1u);
    if (physical_address == 0)
        return 0;
    page = PHYS_TO_VM_PAGE(physical_address);
    if (page) {
        vm_page_wire(page);
        return page;
    }
    page = bsd_kmalloc(sizeof(*page), BSD_M_NOWAIT | BSD_M_ZERO);
    if (!page)
        return 0;
    page->a.queue = PQ_NONE;
    page->oflags = VPO_UNMANAGED;
    page->phys_addr = physical_address;
    page->edgeos_page = PHYS_TO_DMAP(physical_address);
    page->edgeos_flags = EDGEOS_VM_PAGE_USER_HOLD;
    page->ref_count = 1;
    return page;
}

static bool
pmap_has_page(pmap_t pmap, vm_page_t page)
{
    struct bsd_pmap_mapping *mapping;
    vm_paddr_t physical_address;

    if (!pmap || !page)
        return false;
    physical_address = VM_PAGE_TO_PHYS(page) &
        ~(vm_paddr_t)(PAGE_SIZE - 1u);
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        if (mapping->physical_address == physical_address) {
            pmap_unlock(pmap);
            return true;
        }
    }
    pmap_unlock(pmap);
    return false;
}

bool
pmap_page_is_mapped(vm_page_t page)
{
    struct thread *thread;

    if (pmap_has_page(kernel_pmap, page))
        return true;
    thread = bsd_kthread_current_public();
    return thread && thread->td_proc && thread->td_proc->p_vmspace &&
        pmap_has_page(&thread->td_proc->p_vmspace->vm_pmap, page);
}

void
pmap_remove_all(vm_page_t page)
{
    struct thread *thread;
    struct pmap *pmap;
    struct bsd_pmap_mapping **link;
    vm_paddr_t physical_address;

    if (!page)
        return;
    physical_address = VM_PAGE_TO_PHYS(page) &
        ~(vm_paddr_t)(PAGE_SIZE - 1u);
    thread = bsd_kthread_current_public();
    for (int pass = 0; pass < 2; ++pass) {
        pmap = pass == 0 ? kernel_pmap :
            (thread && thread->td_proc && thread->td_proc->p_vmspace ?
            &thread->td_proc->p_vmspace->vm_pmap : 0);
        if (!pmap)
            continue;
        pmap_lock(pmap);
        for (link = &pmap->edgeos_mappings; *link;) {
            struct bsd_pmap_mapping *mapping = *link;

            if (mapping->physical_address != physical_address) {
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
}

int
pmap_pinit(pmap_t pmap)
{
    return pmap_pinit_type(pmap, PT_X86, 0);
}

int
pmap_pinit_type(pmap_t pmap, enum pmap_type type, int flags)
{
    const int allowed_flags = PMAP_NESTED_IPIMASK |
        PMAP_PDE_SUPERPAGE | PMAP_EMULATE_AD_BITS |
        PMAP_SUPPORTS_EXEC_ONLY;
    vm_page_t root_page;

    if (!pmap || type < PT_X86 || type > PT_RVI ||
        (flags & ~allowed_flags) != 0)
        return 0;
    root_page = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO |
        VM_ALLOC_WAITOK);
    if (!root_page)
        return 0;
    pmap->pm_cr3 = VM_PAGE_TO_PHYS(root_page);
    pmap->lock = 0;
    pmap->edgeos_mappings = 0;
    pmap->edgeos_mapping_tail = 0;
    pmap->edgeos_mapping_free = 0;
    pmap->edgeos_mapping_chunks = 0;
    pmap->edgeos_table_pages = 0;
    pmap->edgeos_root_page = root_page;
    pmap->pm_pmltop = vm_page_direct_map(root_page);
    smr_init(&pmap->edgeos_eptsmr);
    pmap->pm_eptsmr = &pmap->edgeos_eptsmr;
    CPU_ZERO(&pmap->pm_active);
    pmap->pm_eptgen = 0;
    pmap->pm_type = type;
    pmap->pm_flags = (uint32_t)flags;
    return 1;
}

int
pmap_enter(pmap_t pmap, vm_offset_t virtual_address, vm_page_t page,
    vm_prot_t protection, unsigned int flags, int8_t page_size_index)
{
    struct bsd_pmap_mapping **link;
    struct bsd_pmap_mapping *mapping;
    vm_offset_t page_address;
    int error;
    int new_mapping = 0;
    unsigned int allowed_flags = VM_PROT_ALL | PMAP_ENTER_NOSLEEP |
        PMAP_ENTER_WIRED | PMAP_ENTER_UNPROTECTED;

    if (!pmap || !page || page_size_index != 0 ||
        (protection & ~VM_PROT_ALL) != 0 ||
        (flags & ~allowed_flags) != 0)
        return 22;
    page_address = virtual_address & ~(vm_offset_t)(PAGE_SIZE - 1u);
    edgeos_smr_write_enter(pmap->pm_eptsmr);
    pmap_lock(pmap);
    mapping = pmap->edgeos_mapping_tail;
    link = 0;
    if (mapping && mapping->virtual_address < page_address &&
        (!mapping->next ||
         mapping->next->virtual_address >= page_address)) {
        link = &mapping->next;
        mapping = *link;
    } else if (!mapping || mapping->virtual_address != page_address) {
        link = &pmap->edgeos_mappings;
        while (*link && (*link)->virtual_address < page_address)
            link = &(*link)->next;
        mapping = *link;
    }
    if (mapping && mapping->virtual_address != page_address)
        mapping = 0;
    if (!mapping) {
        mapping = pmap_mapping_alloc_locked(pmap);
        if (!mapping) {
            pmap_unlock(pmap);
            edgeos_smr_write_exit(pmap->pm_eptsmr);
            return 12;
        }
        mapping->virtual_address = page_address;
        if (!link)
            link = &pmap->edgeos_mappings;
        mapping->next = *link;
        *link = mapping;
        new_mapping = 1;
    } else if (mapping->wired && mapping->page) {
        (void)vm_page_unwire_noq(mapping->page);
    }
    pmap->edgeos_mapping_tail = mapping;
    error = pmap_nested_enter_locked(pmap, page_address, page, protection);
    if (error != 0) {
        if (new_mapping) {
            if (pmap->edgeos_mappings == mapping) {
                pmap->edgeos_mappings = mapping->next;
            } else {
                struct bsd_pmap_mapping *previous =
                    pmap->edgeos_mappings;

                while (previous && previous->next != mapping)
                    previous = previous->next;
                if (previous)
                    previous->next = mapping->next;
            }
            if (pmap->edgeos_mapping_tail == mapping) {
                pmap->edgeos_mapping_tail = pmap->edgeos_mappings;
                while (pmap->edgeos_mapping_tail &&
                    pmap->edgeos_mapping_tail->next)
                    pmap->edgeos_mapping_tail =
                        pmap->edgeos_mapping_tail->next;
            }
            pmap_mapping_free_locked(pmap, mapping);
        }
        pmap_unlock(pmap);
        edgeos_smr_write_exit(pmap->pm_eptsmr);
        return error;
    }
    mapping->physical_address = VM_PAGE_TO_PHYS(page) &
        ~(vm_paddr_t)(PAGE_SIZE - 1u);
    mapping->page = (page->edgeos_flags & EDGEOS_VM_PAGE_FAKE) != 0 ?
        0 : page;
    mapping->protection = protection;
    mapping->wired = mapping->page &&
        (flags & PMAP_ENTER_WIRED) != 0;
    if (mapping->wired)
        vm_page_wire(page);
    __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    edgeos_smr_write_exit(pmap->pm_eptsmr);
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
    if (pmap->pm_stage == PM_STAGE2 && pmap_stage2_invalidate_range)
        pmap_stage2_invalidate_range(pmap_to_ttbr0(pmap), page_address,
            page_address + PAGE_SIZE, true);
#endif
    return 0;
}

int
pmap_emulate_accessed_dirty(pmap_t pmap, vm_offset_t address,
    int fault_type)
{
    (void)address;
    (void)fault_type;
    if (!pmap || (pmap->pm_flags & PMAP_EMULATE_AD_BITS) == 0)
        return -1;
    /* EdgeOS nested mappings currently use hardware-managed A/D state. */
    return -1;
}

long
pmap_wired_count(pmap_t pmap)
{
    struct bsd_pmap_mapping *mapping;
    long count = 0;

    if (!pmap)
        return 0;
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        if (mapping->wired)
            ++count;
    }
    pmap_unlock(pmap);
    return count;
}

int
edgeos_pmap_get_dirty(pmap_t pmap, vm_offset_t start,
    uint32_t page_count, uint64_t *bitmap, uint32_t bitmap_words,
    int clear)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    uint64_t dirty_flag;
    int cleared = 0;

    if (!pmap || !bitmap || page_count == 0 ||
        bitmap_words < (page_count + 63u) / 64u ||
        (pmap->pm_type != PT_EPT && pmap->pm_type != PT_RVI))
        return 22;
    for (uint32_t word = 0; word < bitmap_words; ++word)
        bitmap[word] = 0;
    dirty_flag = pmap->pm_type == PT_EPT ? UINT64_C(1) << 9 : PG_M;
    edgeos_smr_write_enter(pmap->pm_eptsmr);
    pmap_lock(pmap);
    for (uint32_t page = 0; page < page_count; ++page) {
        uint64_t *entry = pmap_nested_leaf_locked(
            pmap, start + (uint64_t)page * PAGE_SIZE);
        uint64_t previous;

        if (!entry)
            continue;
        previous = clear ?
            __atomic_fetch_and(entry, ~dirty_flag, __ATOMIC_ACQ_REL) :
            __atomic_load_n(entry, __ATOMIC_ACQUIRE);
        if ((previous & dirty_flag) == 0)
            continue;
        bitmap[page / 64u] |= UINT64_C(1) << (page % 64u);
        cleared |= clear != 0;
    }
    if (cleared)
        __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    edgeos_smr_write_exit(pmap->pm_eptsmr);
    return 0;
#elif (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)
    struct bsd_pmap_mapping *mapping;
    int cleared = 0;

    if (!pmap || !bitmap || page_count == 0 ||
        bitmap_words < (page_count + 63u) / 64u ||
        pmap->pm_type != PT_ARM64_STAGE2)
        return 22;
    for (uint32_t word = 0; word < bitmap_words; ++word)
        bitmap[word] = 0;
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        vm_offset_t address = mapping->virtual_address;
        uint64_t offset;
        uint32_t page;
        uint64_t *entry;

        if (address < start)
            continue;
        offset = address - start;
        if ((offset & (PAGE_SIZE - 1u)) != 0 ||
            offset / PAGE_SIZE >= page_count)
            continue;
        page = (uint32_t)(offset / PAGE_SIZE);
        if (!mapping || !mapping->dirty_tracked || !mapping->dirty)
            continue;
        bitmap[page / 64u] |= UINT64_C(1) << (page % 64u);
        if (!clear)
            continue;
        entry = pmap_nested_leaf_locked(pmap, address);
        if (!mapping->dirty_write_protected && entry) {
            __atomic_fetch_and(entry, ~EDGEOS_ARM64_S2_WRITE,
                __ATOMIC_ACQ_REL);
            mapping->dirty_write_protected = 1;
        } else {
            mapping->dirty = 0;
        }
        cleared = 1;
    }
    if (cleared)
        __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    if (cleared && pmap_stage2_invalidate_range)
        pmap_stage2_invalidate_range(pmap_to_ttbr0(pmap), start,
            start + (uint64_t)page_count * PAGE_SIZE, true);
    return 0;
#else
    (void)pmap;
    (void)start;
    (void)page_count;
    (void)bitmap;
    (void)bitmap_words;
    (void)clear;
    return 95;
#endif
}

int
edgeos_pmap_clear_dirty(pmap_t pmap, vm_offset_t start,
    uint32_t page_count, const uint64_t *bitmap, uint32_t bitmap_words)
{
#if defined(__x86_64__) && !defined(BSD_BRIDGE_HOST_TEST)
    uint64_t dirty_flag;
    int cleared = 0;

    if (!pmap || !bitmap || page_count == 0 ||
        bitmap_words < (page_count + 63u) / 64u ||
        (pmap->pm_type != PT_EPT && pmap->pm_type != PT_RVI))
        return 22;
    dirty_flag = pmap->pm_type == PT_EPT ? UINT64_C(1) << 9 : PG_M;
    edgeos_smr_write_enter(pmap->pm_eptsmr);
    pmap_lock(pmap);
    for (uint32_t page = 0; page < page_count; ++page) {
        uint64_t *entry;
        uint64_t previous;

        if ((bitmap[page / 64u] &
             (UINT64_C(1) << (page % 64u))) == 0)
            continue;
        entry = pmap_nested_leaf_locked(
            pmap, start + (uint64_t)page * PAGE_SIZE);
        if (!entry)
            continue;
        previous = __atomic_fetch_and(entry, ~dirty_flag, __ATOMIC_ACQ_REL);
        cleared |= (previous & dirty_flag) != 0;
    }
    if (cleared)
        __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    edgeos_smr_write_exit(pmap->pm_eptsmr);
    return 0;
#elif (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)
    struct bsd_pmap_mapping *mapping;
    int cleared = 0;

    if (!pmap || !bitmap || page_count == 0 ||
        bitmap_words < (page_count + 63u) / 64u ||
        pmap->pm_type != PT_ARM64_STAGE2)
        return 22;
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        vm_offset_t address = mapping->virtual_address;
        uint64_t offset;
        uint32_t page;
        uint64_t *entry;

        if (address < start)
            continue;
        offset = address - start;
        if ((offset & (PAGE_SIZE - 1u)) != 0 ||
            offset / PAGE_SIZE >= page_count)
            continue;
        page = (uint32_t)(offset / PAGE_SIZE);
        if ((bitmap[page / 64u] &
             (UINT64_C(1) << (page % 64u))) == 0)
            continue;
        if (!mapping || !mapping->dirty_tracked)
            continue;
        entry = pmap_nested_leaf_locked(pmap, address);
        if (!mapping->dirty_write_protected && entry) {
            __atomic_fetch_and(entry, ~EDGEOS_ARM64_S2_WRITE,
                __ATOMIC_ACQ_REL);
            mapping->dirty_write_protected = 1;
        } else {
            mapping->dirty = 0;
        }
        cleared = 1;
    }
    if (cleared)
        __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    if (cleared && pmap_stage2_invalidate_range)
        pmap_stage2_invalidate_range(pmap_to_ttbr0(pmap), start,
            start + (uint64_t)page_count * PAGE_SIZE, true);
    return 0;
#else
    (void)pmap;
    (void)start;
    (void)page_count;
    (void)bitmap;
    (void)bitmap_words;
    return 95;
#endif
}

int
edgeos_pmap_enable_dirty_tracking(pmap_t pmap, vm_offset_t start,
    uint32_t page_count)
{
#if (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)
    struct bsd_pmap_mapping *mapping;
    uint32_t tracked = 0;

    if (!pmap || page_count == 0 || pmap->pm_type != PT_ARM64_STAGE2)
        return 22;
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        vm_offset_t address = mapping->virtual_address;
        uint64_t offset;
        uint64_t *entry;

        if (address < start)
            continue;
        offset = address - start;
        if ((offset & (PAGE_SIZE - 1u)) != 0 ||
            offset / PAGE_SIZE >= page_count)
            continue;
        mapping->dirty_tracked = 1;
        mapping->dirty = 0;
        mapping->dirty_write_protected = 1;
        entry = pmap_nested_leaf_locked(pmap, address);
        if (entry && (mapping->protection & VM_PROT_WRITE) != 0)
            __atomic_fetch_and(entry, ~EDGEOS_ARM64_S2_WRITE,
                __ATOMIC_ACQ_REL);
        ++tracked;
    }
    if (tracked != page_count) {
        pmap_unlock(pmap);
        return 22;
    }
    __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    if (pmap_stage2_invalidate_range)
        pmap_stage2_invalidate_range(pmap_to_ttbr0(pmap), start,
            start + (uint64_t)page_count * PAGE_SIZE, true);
    return 0;
#else
    (void)pmap;
    (void)start;
    (void)page_count;
    return 95;
#endif
}

int
edgeos_pmap_disable_dirty_tracking(pmap_t pmap, vm_offset_t start,
    uint32_t page_count)
{
#if (defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)) && \
    !defined(BSD_BRIDGE_HOST_TEST)
    struct bsd_pmap_mapping *mapping;
    uint32_t updated = 0;

    if (!pmap || page_count == 0 || pmap->pm_type != PT_ARM64_STAGE2)
        return 22;
    pmap_lock(pmap);
    for (mapping = pmap->edgeos_mappings; mapping;
         mapping = mapping->next) {
        vm_offset_t address = mapping->virtual_address;
        uint64_t offset;
        uint64_t *entry;

        if (address < start)
            continue;
        offset = address - start;
        if ((offset & (PAGE_SIZE - 1u)) != 0 ||
            offset / PAGE_SIZE >= page_count)
            continue;
        mapping->dirty_tracked = 0;
        mapping->dirty = 0;
        mapping->dirty_write_protected = 0;
        entry = pmap_nested_leaf_locked(pmap, address);
        if (entry && (mapping->protection & VM_PROT_WRITE) != 0)
            __atomic_fetch_or(entry, EDGEOS_ARM64_S2_WRITE,
                __ATOMIC_ACQ_REL);
        ++updated;
    }
    if (updated != page_count) {
        pmap_unlock(pmap);
        return 22;
    }
    __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    if (pmap_stage2_invalidate_range)
        pmap_stage2_invalidate_range(pmap_to_ttbr0(pmap), start,
            start + (uint64_t)page_count * PAGE_SIZE, true);
    return 0;
#else
    (void)pmap;
    (void)start;
    (void)page_count;
    return 95;
#endif
}

void
pmap_remove(pmap_t pmap, vm_offset_t start, vm_offset_t end)
{
    struct bsd_pmap_mapping **link;
    int invalidate_all;

    if (!pmap || start >= end)
        return;
    invalidate_all = start == 0 && end == UINTPTR_MAX;
    start &= ~(vm_offset_t)(PAGE_SIZE - 1u);
    if (end > UINTPTR_MAX - (PAGE_SIZE - 1u))
        end = UINTPTR_MAX & ~(vm_offset_t)(PAGE_SIZE - 1u);
    else
        end = (end + PAGE_SIZE - 1u) &
            ~(vm_offset_t)(PAGE_SIZE - 1u);
    edgeos_smr_write_enter(pmap->pm_eptsmr);
    pmap_lock(pmap);
    for (link = &pmap->edgeos_mappings; *link;) {
        struct bsd_pmap_mapping *mapping = *link;

        if (mapping->virtual_address < start ||
            mapping->virtual_address >= end) {
            link = &mapping->next;
            continue;
        }
        *link = mapping->next;
        pmap_nested_remove_locked(pmap, mapping->virtual_address);
        if (mapping->wired && mapping->page)
            (void)vm_page_unwire_noq(mapping->page);
        pmap_mapping_free_locked(pmap, mapping);
    }
    pmap->edgeos_mapping_tail = pmap->edgeos_mappings;
    while (pmap->edgeos_mapping_tail &&
        pmap->edgeos_mapping_tail->next)
        pmap->edgeos_mapping_tail = pmap->edgeos_mapping_tail->next;
    __atomic_fetch_add(&pmap->pm_eptgen, 1, __ATOMIC_RELEASE);
    pmap_unlock(pmap);
    edgeos_smr_write_exit(pmap->pm_eptsmr);
#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
    if (pmap->pm_stage == PM_STAGE2) {
        if (invalidate_all && pmap_stage2_invalidate_all)
            pmap_stage2_invalidate_all(pmap_to_ttbr0(pmap));
        else if (pmap_stage2_invalidate_range)
            pmap_stage2_invalidate_range(pmap_to_ttbr0(pmap), start, end,
                true);
    }
#endif
}

void
pmap_release(pmap_t pmap)
{
    struct bsd_pmap_mapping *mapping;
    struct bsd_pmap_mapping_chunk *mapping_chunk;
    struct bsd_pmap_table_page *table_page;
    vm_page_t root_page;

    if (!pmap)
        return;
    edgeos_smr_write_enter(pmap->pm_eptsmr);
    pmap_lock(pmap);
    mapping = pmap->edgeos_mappings;
    pmap->edgeos_mappings = 0;
    pmap->edgeos_mapping_tail = 0;
    pmap->edgeos_mapping_free = 0;
    mapping_chunk = pmap->edgeos_mapping_chunks;
    pmap->edgeos_mapping_chunks = 0;
    root_page = pmap->edgeos_root_page;
    pmap->edgeos_root_page = 0;
    pmap->pm_pmltop = 0;
    table_page = pmap->edgeos_table_pages;
    pmap->edgeos_table_pages = 0;
    pmap->edgeos_address_space = 0;
    while (mapping) {
        struct bsd_pmap_mapping *next = mapping->next;

        if (mapping->wired && mapping->page)
            (void)vm_page_unwire_noq(mapping->page);
        mapping = next;
    }
    pmap_unlock(pmap);
    while (mapping_chunk) {
        struct bsd_pmap_mapping_chunk *next = mapping_chunk->next;

        bsd_kfree(mapping_chunk);
        mapping_chunk = next;
    }
    while (table_page) {
        struct bsd_pmap_table_page *next = table_page->next;

        vm_page_free(table_page->page);
        bsd_kfree(table_page);
        table_page = next;
    }
    if (root_page)
        vm_page_free(root_page);
    edgeos_smr_write_exit(pmap->pm_eptsmr);
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

int
vm_mmap_object(vm_map_t map, vm_offset_t *address, vm_size_t size,
    vm_prot_t protection, vm_prot_t maximum_protection, int flags,
    vm_object_t object, vm_ooffset_t offset, int write_counted,
    struct thread *thread)
{
    vm_offset_t mapped = 0;
    uint32_t arch_protection = 0;

    (void)flags;
    (void)write_counted;
    (void)thread;
    if (!map || !map->edgeos_address_space || !address || !*address ||
        !object || size == 0 || (offset & (PAGE_SIZE - 1u)) != 0 ||
        (protection & ~maximum_protection) != 0 ||
        *address > UINTPTR_MAX - size)
        return 22;
    if ((protection & VM_PROT_READ) != 0)
        arch_protection |= ARCH_VM_PROT_READ;
    if ((protection & VM_PROT_WRITE) != 0)
        arch_protection |= ARCH_VM_PROT_WRITE;
    if ((protection & VM_PROT_EXECUTE) != 0)
        arch_protection |= ARCH_VM_PROT_EXEC;
    for (mapped = 0; mapped < size; mapped += PAGE_SIZE) {
        vm_ooffset_t object_offset = offset + mapped;
        vm_page_t page = vm_page_lookup(object,
            OFF_TO_IDX(object_offset));
        vm_paddr_t physical_address;

        if (page) {
            physical_address = VM_PAGE_TO_PHYS(page);
        } else if (vm_object_pager_physical_address(object,
            object_offset, &physical_address) != 0) {
            goto fail;
        }
        if (arch_vm_map_user_page(map->edgeos_address_space,
            *address + mapped, physical_address, arch_protection) != 0)
            goto fail;
    }
    vm_object_reference(object);
    return 0;

fail:
    if (mapped != 0)
        (void)arch_vm_unmap_user_range(map->edgeos_address_space,
            *address, mapped);
    return 14;
}

int
vm_map_find(vm_map_t map, vm_object_t object, vm_ooffset_t offset,
    vm_offset_t *address, vm_size_t size, vm_offset_t maximum_address,
    int find_space, vm_prot_t protection, vm_prot_t maximum_protection,
    int inheritance)
{
    kernel_mm_map_request_t request;
    int64_t mapped_address;
    int result;

    (void)maximum_address;
    (void)find_space;
    if (!map || !map->edgeos_address_space || !address || !object ||
        size == 0 || inheritance != MAP_INHERIT_SHARE ||
        map->edgeos_address_space != arch_mm_current_address_space())
        return KERN_INVALID_ARGUMENT;

    request.address = *address;
    request.length = size;
    request.protection = 0;
    if ((protection & VM_PROT_READ) != 0)
        request.protection |= KERNEL_MM_PROT_READ;
    if ((protection & VM_PROT_WRITE) != 0)
        request.protection |= KERNEL_MM_PROT_WRITE;
    if ((protection & VM_PROT_EXECUTE) != 0)
        request.protection |= KERNEL_MM_PROT_EXEC;
    request.flags = KERNEL_MM_MAP_SHARED | KERNEL_MM_MAP_ANONYMOUS;
    request.descriptor = -1;
    request.reserved = 0;
    request.offset = 0;
    mapped_address = kernel_mm_map(&request);
    if (mapped_address < 0)
        return mapped_address == -EDGE_LINUX_ENOMEM ?
            KERN_NO_SPACE : KERN_FAILURE;

    *address = (vm_offset_t)mapped_address;
    result = vm_mmap_object(map, address, size, protection,
        maximum_protection, 0, object, offset, 0, curthread);
    if (result != 0) {
        (void)kernel_mm_unmap_range(*address, size);
        *address = 0;
        return result == 14 ? KERN_INVALID_ADDRESS :
            KERN_INVALID_ARGUMENT;
    }
    map->size += size;
    return KERN_SUCCESS;
}

void
vm_page_unhold_pages(vm_page_t *pages, int page_count)
{
    if (!pages || page_count <= 0)
        return;
    vm_page_release_descriptors(pages, page_count);
}
#endif
