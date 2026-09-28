/* SPDX-License-Identifier: MPL-2.0 */
/* Shared bus-DMA implementation for BSD drivers on EdgeOS. */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>
#include "compat/freebsd/edgeos/allocator.h"
#include "compat/freebsd/edgeos/bus_dma.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/iommu/iommu.h"
#include "compat/freebsd/machine/bus.h"
#include "compat/freebsd/sys/bio.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/vm/vm.h"
#ifdef BSD_BRIDGE_HOST_TEST
typedef unsigned int u_int;
#endif
#include "sys/memdesc.h"
#include "compat/freebsd/sys/mutex.h"
#include "compat/freebsd/sys/uio.h"
#include "compat/freebsd/vm/pmap.h"
#include "compat/freebsd/vm/vm_page.h"
#include "x86/include/busdma_impl.h"

#ifndef BSD_BRIDGE_HOST_TEST
#include "kernel/arch_cpu.h"
#include "mm/arch_vm.h"
#include "sys/mmio.h"
#endif

#define BSD_BUS_DMA_PAGE_SIZE 4096ULL

struct bus_dma_tag {
    bus_dma_tag_t parent;
    bus_size_t alignment;
    bus_addr_t boundary;
    bus_addr_t lowaddr;
    bus_addr_t highaddr;
    bus_size_t maxsize;
    bus_size_t max_segment_size;
    int nsegments;
    int flags;
    int domain;
    bus_dma_lock_t *lock_function;
    void *lock_argument;
    void *iommu;
    void *iommu_domain;
    uint32_t map_count;
    uint32_t child_count;
};

struct bus_dmamap {
    bus_dma_tag_t tag;
    void *buffer;
    bus_size_t length;
    int segment_count;
    void *allocation_base;
    uint64_t allocation_pages;
    void *owned_buffer;
    int buffer_kind;
    bus_dma_segment_t segments[];
};

static bsd_bus_dma_ops_t g_bus_dma_ops;
static uint8_t g_bus_dma_init_state;
static bsd_bus_dma_physical_override_fn g_bus_dma_physical_override;

#ifndef BSD_BRIDGE_HOST_TEST
static void *
default_allocate_pages(uint64_t page_count, uint32_t flags, void *context)
{
    (void)flags;
    (void)context;
    return arch_vm_alloc_pages(page_count);
}

static void
default_release_pages(void *base, uint64_t page_count, void *context)
{
    uint8_t *page = base;

    (void)context;
    for (uint64_t index = 0; index < page_count; ++index)
        arch_vm_free_page(page + index * BSD_BUS_DMA_PAGE_SIZE);
}

static int
default_physical_address(const void *pointer, uint64_t *physical_address,
    void *context)
{
    uintptr_t value = (uintptr_t)pointer;

    (void)context;
    if (!pointer || !physical_address)
        return -1;
    if (value >= EDGE_MMIO_LOW_ALIAS_BASE &&
        value < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE)
        value -= EDGE_MMIO_LOW_ALIAS_BASE;
    *physical_address = value;
    return 0;
}

static int
default_virtual_address(uint64_t physical_address, size_t length,
    void **virtual_address, void *context)
{
    (void)context;
    if (!virtual_address || length == 0 ||
        physical_address > UINTPTR_MAX ||
        length - 1 > UINTPTR_MAX - (uintptr_t)physical_address)
        return -1;
#if defined(__x86_64__)
    if (!edge_mmio_phys_range_mapped(physical_address, length))
        return -1;
    *virtual_address = (void *)edge_mmio_low_alias(physical_address);
#else
    *virtual_address = (void *)(uintptr_t)physical_address;
#endif
    return 0;
}

static void
default_sync(void *buffer, size_t length, int operation, void *context)
{
    (void)buffer;
    (void)length;
    (void)operation;
    (void)context;
    arch_cpu_memory_barrier();
}
#endif

static int
power_of_two(bus_size_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

static bus_size_t
maximum(bus_size_t left, bus_size_t right)
{
    return left > right ? left : right;
}

static bus_size_t
minimum(bus_size_t left, bus_size_t right)
{
    return left < right ? left : right;
}

static int
range_overflows(bus_addr_t address, bus_size_t length)
{
    return length == 0 || address > UINT64_MAX - (length - 1);
}

static int
range_is_accessible(bus_dma_tag_t tag, bus_addr_t address,
    bus_size_t length)
{
    bus_addr_t end;

    if (!tag || range_overflows(address, length))
        return 0;
    end = address + length - 1;
    if (address <= tag->highaddr && end > tag->lowaddr)
        return 0;
    return 1;
}

static int
tag_is_idle(bus_dma_tag_t tag)
{
    return __atomic_load_n(&tag->map_count, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&tag->child_count, __ATOMIC_ACQUIRE) == 0;
}

int
bsd_bus_dma_ensure_initialized(void)
{
    uint8_t state =
        __atomic_load_n(&g_bus_dma_init_state, __ATOMIC_ACQUIRE);

    if (state == 2)
        return 0;
    if (state == 1) {
        do {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
            state = __atomic_load_n(
                &g_bus_dma_init_state, __ATOMIC_ACQUIRE);
        } while (state == 1);
        return state == 2 ? 0 : -1;
    }
#ifdef BSD_BRIDGE_HOST_TEST
    return -1;
#else
    bsd_bus_dma_ops_t ops = {
        .allocate_pages = default_allocate_pages,
        .release_pages = default_release_pages,
        .physical_address = default_physical_address,
        .virtual_address = default_virtual_address,
        .sync = default_sync,
    };
    if (bsd_bus_dma_initialize(&ops) == 0)
        return 0;
    while (__atomic_load_n(
        &g_bus_dma_init_state, __ATOMIC_ACQUIRE) == 1) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
    return bsd_bus_dma_is_initialized() ? 0 : -1;
#endif
}

int
bsd_bus_dma_initialize(const bsd_bus_dma_ops_t *ops)
{
    uint8_t expected = 0;

    if (!ops || !ops->allocate_pages || !ops->release_pages ||
        !ops->physical_address)
        return -1;
    if (!__atomic_compare_exchange_n(&g_bus_dma_init_state, &expected, 1, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -1;
    g_bus_dma_ops = *ops;
    __atomic_store_n(&g_bus_dma_init_state, 2, __ATOMIC_RELEASE);
    return 0;
}

int
bsd_bus_dma_is_initialized(void)
{
    return __atomic_load_n(&g_bus_dma_init_state, __ATOMIC_ACQUIRE) == 2;
}

int
bsd_bus_dma_physical_address(const void *pointer,
    uint64_t *physical_address)
{
    bsd_bus_dma_physical_override_fn override;

    if (!pointer || !physical_address ||
        bsd_bus_dma_ensure_initialized() != 0)
        return -1;
    override = __atomic_load_n(
        &g_bus_dma_physical_override, __ATOMIC_ACQUIRE);
    if (override && override(pointer, physical_address) == 0)
        return 0;
    return g_bus_dma_ops.physical_address(pointer, physical_address,
        g_bus_dma_ops.context);
}

int
bsd_bus_dma_virtual_address(uint64_t physical_address, size_t length,
    void **virtual_address)
{
    if (!virtual_address || length == 0 ||
        bsd_bus_dma_ensure_initialized() != 0 ||
        !g_bus_dma_ops.virtual_address)
        return -1;
    *virtual_address = 0;
    return g_bus_dma_ops.virtual_address(physical_address, length,
        virtual_address, g_bus_dma_ops.context);
}

int
bsd_bus_dma_register_physical_override(
    bsd_bus_dma_physical_override_fn function)
{
    bsd_bus_dma_physical_override_fn expected = 0;

    if (!function)
        return -1;
    if (__atomic_compare_exchange_n(&g_bus_dma_physical_override,
        &expected, function, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0;
    return expected == function ? 0 : -1;
}

uint64_t
bsd_pmap_kextract(uintptr_t virtual_value)
{
    uint64_t physical_address;

#ifndef BSD_BRIDGE_HOST_TEST
    if (bsd_pmap_kva_extract((vm_offset_t)virtual_value,
        &physical_address) == 0)
        return physical_address;
#endif
    if (bsd_bus_dma_physical_address(
        (const void *)(uintptr_t)virtual_value, &physical_address) != 0)
        return 0;
    return physical_address;
}

void *
bsd_pmap_phys_to_dmap(vm_paddr_t physical_address)
{
    void *virtual_address = 0;

    if (bsd_bus_dma_virtual_address(physical_address, 1,
        &virtual_address) != 0)
        return 0;
    return virtual_address;
}

int
bus_dma_tag_create(bus_dma_tag_t parent, bus_size_t alignment,
    bus_addr_t boundary, bus_addr_t lowaddr, bus_addr_t highaddr,
    bus_dma_filter_t *filter, void *filter_argument, bus_size_t maxsize,
    int nsegments, bus_size_t max_segment_size, int flags,
    bus_dma_lock_t *lock_function, void *lock_argument,
    bus_dma_tag_t *result)
{
    bus_dma_tag_t tag;

    if (result)
        *result = 0;
    if (bsd_bus_dma_ensure_initialized() != 0 || !result || filter ||
        filter_argument ||
        maxsize == 0 || max_segment_size == 0)
        return 22;
    if (alignment == 0)
        alignment = 1;
    if (!power_of_two(alignment) ||
        (boundary != 0 && !power_of_two(boundary)))
        return 22;

    tag = bsd_malloc(sizeof(*tag), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!tag)
        return 12;
    tag->parent = parent;
    tag->alignment = alignment;
    tag->boundary = boundary;
    tag->lowaddr = lowaddr;
    tag->highaddr = highaddr;
    tag->maxsize = maxsize;
    tag->nsegments = nsegments;
    tag->max_segment_size = max_segment_size;
    tag->flags = flags;
    tag->lock_function = lock_function;
    tag->lock_argument = lock_argument;

    if (parent) {
        if (tag->boundary == 0 ||
            (parent->boundary != 0 && parent->boundary < tag->boundary))
            tag->boundary = parent->boundary;
        tag->lowaddr = minimum(tag->lowaddr, parent->lowaddr);
        tag->highaddr = maximum(tag->highaddr, parent->highaddr);
        tag->domain = parent->domain;
        tag->iommu = parent->iommu;
        tag->iommu_domain = parent->iommu_domain;
    }
    if (tag->boundary != 0 &&
        tag->max_segment_size > tag->boundary)
        tag->max_segment_size = tag->boundary;
    if (tag->maxsize == 0 || tag->max_segment_size == 0) {
        bsd_free(tag, M_DEVBUF);
        return 22;
    }
    if (parent)
        __atomic_add_fetch(&parent->child_count, 1, __ATOMIC_ACQ_REL);
    *result = tag;
    return 0;
}

int
bus_dma_tag_destroy(bus_dma_tag_t tag)
{
    bus_dma_tag_t parent;

    if (!tag)
        return 22;
    if (!tag_is_idle(tag))
        return 16;
    parent = tag->parent;
    bsd_free(tag, M_DEVBUF);
    if (parent)
        __atomic_sub_fetch(&parent->child_count, 1, __ATOMIC_ACQ_REL);
    return 0;
}

void
bus_dma_template_init(bus_dma_template_t *template, bus_dma_tag_t parent)
{
    if (!template)
        return;
    template->parent = parent;
    template->alignment = 1;
    template->boundary = 0;
    template->lowaddr = BUS_SPACE_MAXADDR;
    template->highaddr = BUS_SPACE_MAXADDR;
    template->maxsize = BUS_SPACE_MAXSIZE;
    template->nsegments = BUS_SPACE_UNRESTRICTED;
    template->maxsegsize = BUS_SPACE_MAXSIZE;
    template->flags = 0;
    template->lockfunc = 0;
    template->lockfuncarg = 0;
    template->name = 0;
}

int
bus_dma_template_tag(bus_dma_template_t *template, bus_dma_tag_t *result)
{
    if (!template || !result)
        return 22;
    return bus_dma_tag_create(template->parent, template->alignment,
        template->boundary, template->lowaddr, template->highaddr, 0, 0,
        template->maxsize, template->nsegments, template->maxsegsize,
        template->flags, template->lockfunc, template->lockfuncarg, result);
}

void
bus_dma_template_clone(bus_dma_template_t *template, bus_dma_tag_t tag)
{
    if (!template || !tag)
        return;
    template->parent = tag->parent;
    template->alignment = tag->alignment;
    template->boundary = tag->boundary;
    template->lowaddr = tag->lowaddr;
    template->highaddr = tag->highaddr;
    template->maxsize = tag->maxsize;
    template->nsegments = tag->nsegments;
    template->maxsegsize = tag->max_segment_size;
    template->flags = tag->flags;
    template->lockfunc = tag->lock_function;
    template->lockfuncarg = tag->lock_argument;
    template->name = 0;
}

void
bus_dma_template_fill(bus_dma_template_t *template,
    bus_dma_param_t *parameters, unsigned int count)
{
    if (!template || (!parameters && count != 0))
        return;
    while (count != 0) {
        bus_dma_param_t *parameter = &parameters[--count];

        switch (parameter->key) {
        case BD_PARAM_PARENT:
            template->parent = parameter->ptr;
            break;
        case BD_PARAM_ALIGNMENT:
            template->alignment = parameter->num;
            break;
        case BD_PARAM_BOUNDARY:
            template->boundary = parameter->num;
            break;
        case BD_PARAM_LOWADDR:
            template->lowaddr = parameter->pa;
            break;
        case BD_PARAM_HIGHADDR:
            template->highaddr = parameter->pa;
            break;
        case BD_PARAM_MAXSIZE:
            template->maxsize = parameter->num;
            break;
        case BD_PARAM_NSEGMENTS:
            template->nsegments = (int)parameter->num;
            break;
        case BD_PARAM_MAXSEGSIZE:
            template->maxsegsize = parameter->num;
            break;
        case BD_PARAM_FLAGS:
            template->flags = (int)parameter->num;
            break;
        case BD_PARAM_LOCKFUNC:
            template->lockfunc =
                (bus_dma_lock_t *)(uintptr_t)parameter->ptr;
            break;
        case BD_PARAM_LOCKFUNCARG:
            template->lockfuncarg = parameter->ptr;
            break;
        case BD_PARAM_NAME:
            template->name = parameter->ptr;
            break;
        case BD_PARAM_INVALID:
        default:
            break;
        }
    }
}

int
bus_dma_tag_set_domain(bus_dma_tag_t tag, int domain)
{
    if (!tag || domain < 0)
        return 22;
    if (__atomic_load_n(&tag->map_count, __ATOMIC_ACQUIRE) != 0)
        return 16;
    tag->domain = domain;
    return 0;
}

int
bus_dma_tag_set_iommu(bus_dma_tag_t tag, void *iommu, void *domain)
{
    if (!tag || (!iommu != !domain))
        return 22;
    if (__atomic_load_n(&tag->map_count, __ATOMIC_ACQUIRE) != 0)
        return 16;
    if (iommu)
        return 95;
    tag->iommu = 0;
    tag->iommu_domain = 0;
    return 0;
}

bool
bus_dma_id_mapped(bus_dma_tag_t tag, bus_addr_t physical_address,
    bus_size_t length)
{
    bus_addr_t end;

    if (!tag || tag->iommu || tag->iommu_domain || length == 0 ||
        length > tag->maxsize || length > tag->max_segment_size ||
        tag->nsegments < 1 ||
        (physical_address & (tag->alignment - 1)) != 0 ||
        !range_is_accessible(tag, physical_address, length))
        return false;
    end = physical_address + length - 1;
    if (tag->boundary != 0 &&
        physical_address / tag->boundary != end / tag->boundary)
        return false;
    return true;
}

__attribute__((weak)) bool
bus_dma_iommu_set_buswide(device_t device)
{
    /*
     * Match FreeBSD's non-IOMMU busdma contract. EdgeOS currently uses
     * direct DMA mappings, so there is no translation context to widen.
     */
    (void)device;
    return false;
}

__attribute__((weak)) int
bus_dma_iommu_load_ident(bus_dma_tag_t tag, bus_dmamap_t map,
    vm_paddr_t start, vm_size_t length, int flags)
{
    /*
     * The direct-DMA backend already presents an identity address space.
     * This is the same contract used by FreeBSD's non-IOMMU busdma path:
     * no translation entry is necessary, but invalid requests still fail
     * at the bridge boundary.
     */
    if (!tag || !map || map->tag != tag || length == 0 ||
        (start & (BSD_BUS_DMA_PAGE_SIZE - 1)) != 0 ||
        (length & (BSD_BUS_DMA_PAGE_SIZE - 1)) != 0 ||
        start > UINT64_MAX - length ||
        (flags & ~(BUS_DMA_NOWAIT | BUS_DMA_NOWRITE)) != 0)
        return 22;
    if (tag->iommu || tag->iommu_domain)
        return 95;
    return 0;
}

int
common_bus_dma_tag_create(struct bus_dma_tag_common *parent,
    bus_size_t alignment, bus_addr_t boundary, bus_addr_t lowaddr,
    bus_addr_t highaddr, bus_size_t maxsize, int nsegments,
    bus_size_t maxsegsz, int flags, bus_dma_lock_t *lockfunc,
    void *lockfuncarg, size_t size, void **result)
{
    struct bus_dma_tag_common *tag;

    if (!result || size < sizeof(*tag) || alignment == 0 ||
        nsegments <= 0 || maxsize == 0 || maxsegsz == 0)
        return 22;
    *result = 0;
    if (boundary != 0 && maxsegsz > boundary)
        maxsegsz = boundary;
    tag = bsd_malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!tag)
        return 12;
    tag->impl = parent ? parent->impl : 0;
    tag->alignment = alignment;
    tag->boundary = boundary;
    tag->lowaddr = lowaddr | (BSD_BUS_DMA_PAGE_SIZE - 1);
    tag->highaddr = highaddr | (BSD_BUS_DMA_PAGE_SIZE - 1);
    tag->maxsize = maxsize;
    tag->nsegments = (unsigned int)nsegments;
    tag->maxsegsz = maxsegsz;
    tag->flags = flags;
    tag->lockfunc = lockfunc ? lockfunc : _busdma_dflt_lock;
    tag->lockfuncarg = lockfunc ? lockfuncarg : 0;
    if (parent) {
        if (tag->lowaddr > parent->lowaddr)
            tag->lowaddr = parent->lowaddr;
        if (tag->highaddr < parent->highaddr)
            tag->highaddr = parent->highaddr;
        if (tag->boundary == 0 ||
            (parent->boundary != 0 && parent->boundary < tag->boundary))
            tag->boundary = parent->boundary;
        tag->domain = parent->domain;
    }
    *result = tag;
    return 0;
}

int
bus_dmamap_create(bus_dma_tag_t tag, int flags, bus_dmamap_t *result)
{
    size_t size;
    bus_dmamap_t map;

    (void)flags;
    if (!tag || !result || tag->nsegments <= 0 ||
        (size_t)tag->nsegments >
            (SIZE_MAX - sizeof(*map)) / sizeof(bus_dma_segment_t))
        return 22;
    size = sizeof(*map) +
        (size_t)tag->nsegments * sizeof(bus_dma_segment_t);
    map = bsd_malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!map)
        return 12;
    map->tag = tag;
    __atomic_add_fetch(&tag->map_count, 1, __ATOMIC_ACQ_REL);
    *result = map;
    return 0;
}

int
bus_dmamap_destroy(bus_dma_tag_t tag, bus_dmamap_t map)
{
    if (!tag || !map || map->tag != tag)
        return 22;
    if (map->allocation_base || map->buffer)
        return 16;
    bsd_free(map, M_DEVBUF);
    __atomic_sub_fetch(&tag->map_count, 1, __ATOMIC_ACQ_REL);
    return 0;
}

int
bus_dmamem_alloc(bus_dma_tag_t tag, void **virtual_address, int flags,
    bus_dmamap_t *result)
{
    bus_dmamap_t map;
    uint64_t allocation_bytes;
    uint64_t allocation_pages;
    uint64_t allocation_size;
    uint64_t base_physical;
    uint64_t aligned_physical;
    uintptr_t offset;
    void *base;
    int error;

    if (!tag || !virtual_address || !result ||
        tag->maxsize > UINT64_MAX - (tag->alignment - 1))
        return 22;
    error = bus_dmamap_create(tag, flags, &map);
    if (error != 0)
        return error;

    allocation_bytes = tag->maxsize + tag->alignment - 1;
    if (allocation_bytes >
        UINT64_MAX - (BSD_BUS_DMA_PAGE_SIZE - 1)) {
        (void)bus_dmamap_destroy(tag, map);
        return 22;
    }
    allocation_pages = (allocation_bytes + BSD_BUS_DMA_PAGE_SIZE - 1) /
        BSD_BUS_DMA_PAGE_SIZE;
    if (allocation_pages > UINT64_MAX / BSD_BUS_DMA_PAGE_SIZE) {
        (void)bus_dmamap_destroy(tag, map);
        return 22;
    }
    allocation_size = allocation_pages * BSD_BUS_DMA_PAGE_SIZE;
    base = g_bus_dma_ops.allocate_pages(allocation_pages, (uint32_t)flags,
        g_bus_dma_ops.context);
    if (!base) {
        (void)bus_dmamap_destroy(tag, map);
        return 12;
    }
    if (g_bus_dma_ops.physical_address(base, &base_physical,
        g_bus_dma_ops.context) != 0) {
        g_bus_dma_ops.release_pages(base, allocation_pages,
            g_bus_dma_ops.context);
        (void)bus_dmamap_destroy(tag, map);
        return 22;
    }
    if (base_physical > UINT64_MAX - (tag->alignment - 1)) {
        g_bus_dma_ops.release_pages(base, allocation_pages,
            g_bus_dma_ops.context);
        (void)bus_dmamap_destroy(tag, map);
        return 27;
    }
    aligned_physical = (base_physical + tag->alignment - 1) &
        ~(tag->alignment - 1);
    offset = (uintptr_t)(aligned_physical - base_physical);
    if (tag->maxsize > allocation_size ||
        offset > allocation_size - tag->maxsize ||
        (uintptr_t)base > UINTPTR_MAX - offset ||
        !range_is_accessible(tag, aligned_physical, tag->maxsize) ||
        (tag->boundary != 0 &&
         aligned_physical / tag->boundary !=
         (aligned_physical + tag->maxsize - 1) / tag->boundary)) {
        g_bus_dma_ops.release_pages(base, allocation_pages,
            g_bus_dma_ops.context);
        (void)bus_dmamap_destroy(tag, map);
        return 27;
    }

    map->allocation_base = base;
    map->allocation_pages = allocation_pages;
    map->owned_buffer = (uint8_t *)base + offset;
    if ((flags & BUS_DMA_ZERO) != 0)
        bsd_memset(map->owned_buffer, 0, tag->maxsize);
    *virtual_address = map->owned_buffer;
    *result = map;
    return 0;
}

void
bus_dmamem_free(bus_dma_tag_t tag, void *virtual_address, bus_dmamap_t map)
{
    if (!tag || !map || map->tag != tag ||
        map->owned_buffer != virtual_address || !map->allocation_base ||
        map->buffer)
        return;
    g_bus_dma_ops.release_pages(map->allocation_base, map->allocation_pages,
        g_bus_dma_ops.context);
    map->allocation_base = 0;
    map->allocation_pages = 0;
    map->owned_buffer = 0;
    map->buffer = 0;
    map->length = 0;
    map->segment_count = 0;
    (void)bus_dmamap_destroy(tag, map);
}

static int
append_segment(bus_dma_tag_t tag, bus_dmamap_t map, bus_addr_t physical,
    bus_size_t length)
{
    bus_dma_segment_t *segment;
    bus_addr_t end;

    if (!range_is_accessible(tag, physical, length) ||
        (physical & (tag->alignment - 1)) != 0)
        return 27;
    end = physical + length - 1;
    if (map->segment_count != 0) {
        segment = &map->segments[map->segment_count - 1];
        if (!range_overflows(segment->ds_addr, segment->ds_len) &&
            segment->ds_addr + segment->ds_len == physical &&
            segment->ds_len <= tag->max_segment_size &&
            length <= tag->max_segment_size - segment->ds_len &&
            (tag->boundary == 0 ||
             segment->ds_addr / tag->boundary ==
             end / tag->boundary)) {
            segment->ds_len += length;
            return 0;
        }
    }
    if (map->segment_count >= tag->nsegments)
        return 27;
    segment = &map->segments[map->segment_count++];
    segment->ds_addr = physical;
    segment->ds_len = length;
    return 0;
}

int
bus_dmamap_load(bus_dma_tag_t tag, bus_dmamap_t map, void *buffer,
    bus_size_t length, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags)
{
    bus_size_t offset = 0;
    int error = 0;
    int load_started = 0;

    (void)flags;
    if (!tag || !map || map->tag != tag || !buffer || length == 0 ||
        length > tag->maxsize) {
        error = 22;
        goto complete;
    }
    if (map->buffer) {
        error = 16;
        goto complete;
    }

    map->buffer = buffer;
    map->buffer_kind = 1;
    map->length = length;
    map->segment_count = 0;
    load_started = 1;
    while (offset < length) {
        uint64_t physical;
        bus_size_t page_remaining;
        bus_size_t chunk;

        if ((uintptr_t)buffer > UINTPTR_MAX - offset ||
            g_bus_dma_ops.physical_address(
            (uint8_t *)buffer + offset, &physical,
            g_bus_dma_ops.context) != 0) {
            error = 22;
            break;
        }
        page_remaining =
            BSD_BUS_DMA_PAGE_SIZE - (physical & (BSD_BUS_DMA_PAGE_SIZE - 1));
        chunk = minimum(length - offset, page_remaining);
        chunk = minimum(chunk, tag->max_segment_size);
        if (tag->boundary != 0) {
            bus_size_t boundary_remaining =
                tag->boundary - (physical & (tag->boundary - 1));
            chunk = minimum(chunk, boundary_remaining);
        }
        error = append_segment(tag, map, physical, chunk);
        if (error != 0)
            break;
        offset += chunk;
    }

complete:
    if (error != 0 && load_started) {
        map->buffer = 0;
        map->buffer_kind = 0;
        map->length = 0;
        map->segment_count = 0;
    }
    if (callback)
        callback(callback_argument, map ? map->segments : 0,
            error == 0 ? map->segment_count : 0, error);
    return error;
}

int
bus_dmamap_load_bio(bus_dma_tag_t tag, bus_dmamap_t map, struct bio *bio,
    bus_dmamap_callback_t *callback, void *callback_argument, int flags)
{
    struct memdesc memory;

    if (!bio || bio->bio_bcount <= 0) {
        if (callback)
            callback(callback_argument, 0, 0, 22);
        return 22;
    }
    memory = memdesc_bio(bio);
    return bus_dmamap_load_mem(tag, map, &memory, callback,
        callback_argument, flags);
}

struct bus_dmamap_uio_callback {
    bus_dmamap_callback2_t *function;
    void *argument;
    bus_size_t length;
};

static void
bus_dmamap_uio_complete(void *argument, bus_dma_segment_t *segments,
    int segment_count, int error)
{
    struct bus_dmamap_uio_callback *completion = argument;

    if (completion->function)
        completion->function(completion->argument, segments, segment_count,
            error == 0 ? completion->length : 0, error);
}

int
bus_dmamap_load_uio(bus_dma_tag_t tag, bus_dmamap_t map, struct uio *uio,
    bus_dmamap_callback2_t *callback, void *callback_argument, int flags)
{
    struct bus_dmamap_uio_callback completion = {
        .function = callback,
        .argument = callback_argument,
        .length = uio && uio->uio_resid > 0 ?
            (bus_size_t)uio->uio_resid : 0,
    };
    struct memdesc memory;

    if (!uio) {
        bus_dmamap_uio_complete(&completion, 0, 0, 22);
        return 22;
    }
    memory = memdesc_uio(uio);
    return bus_dmamap_load_mem(tag, map, &memory,
        bus_dmamap_uio_complete, &completion, flags);
}

static int
append_physical_range(bus_dma_tag_t tag, bus_dmamap_t map,
    bus_addr_t physical, bus_size_t length)
{
    while (length != 0) {
        bus_size_t chunk = length;

        if (chunk > tag->max_segment_size)
            chunk = tag->max_segment_size;
        if (tag->boundary != 0) {
            bus_size_t remaining =
                tag->boundary - (physical & (tag->boundary - 1));

            if (chunk > remaining)
                chunk = remaining;
        }
        if (append_segment(tag, map, physical, chunk) != 0)
            return 27;
        physical += chunk;
        length -= chunk;
    }
    return 0;
}

int
_bus_dmamap_load_phys(bus_dma_tag_t tag, bus_dmamap_t map,
    bus_addr_t physical_address, bus_size_t length, int flags,
    bus_dma_segment_t *segments, int *segment_index)
{
    int error;
    int output_index;

    (void)flags;
    if (!tag || !map || map->tag != tag || length == 0 ||
        length > tag->maxsize || !segment_index || map->buffer)
        return 22;
    output_index = *segment_index;
    if (output_index < -1 || output_index >= tag->nsegments)
        return 22;

    map->buffer = map;
    map->buffer_kind = 3;
    map->length = length;
    map->segment_count = 0;
    error = append_physical_range(tag, map, physical_address, length);
    if (!error && output_index + map->segment_count >= tag->nsegments)
        error = 27;
    if (error) {
        map->buffer = 0;
        map->buffer_kind = 0;
        map->length = 0;
        map->segment_count = 0;
        return error;
    }

    if (!segments)
        segments = map->segments;
    if (segments != map->segments) {
        for (int index = 0; index < map->segment_count; ++index)
            segments[output_index + index + 1] = map->segments[index];
    }
    *segment_index = output_index + map->segment_count;
    return 0;
}

static int
append_virtual_range(bus_dma_tag_t tag, bus_dmamap_t map,
    const void *buffer, bus_size_t length)
{
    bus_size_t offset = 0;

    while (offset < length) {
        uint64_t physical;
        bus_size_t chunk;

        if ((uintptr_t)buffer > UINTPTR_MAX - offset ||
            g_bus_dma_ops.physical_address(
                (const uint8_t *)buffer + offset, &physical,
                g_bus_dma_ops.context) != 0)
            return 22;
        chunk = BSD_BUS_DMA_PAGE_SIZE -
            (physical & (BSD_BUS_DMA_PAGE_SIZE - 1u));
        if (chunk > length - offset)
            chunk = length - offset;
        if (append_physical_range(tag, map, physical, chunk) != 0)
            return 27;
        offset += chunk;
    }
    return 0;
}

struct memdesc
memdesc_bio(struct bio *bio)
{
    if ((bio->bio_flags & BIO_VLIST) != 0)
        return memdesc_vlist((struct bus_dma_segment *)bio->bio_data,
            bio->bio_ma_n);
    if ((bio->bio_flags & BIO_UNMAPPED) != 0)
        return memdesc_vmpages(bio->bio_ma, (size_t)bio->bio_bcount,
            (u_int)bio->bio_ma_offset);
    return memdesc_vaddr(bio->bio_data, (size_t)bio->bio_bcount);
}

int
bus_dmamap_load_mem(bus_dma_tag_t tag, bus_dmamap_t map,
    struct memdesc *memory, bus_dmamap_callback_t *callback,
    void *callback_argument, int flags)
{
    bus_size_t total = 0;
    int error = 0;

    (void)flags;
    if (!tag || !map || map->tag != tag || !memory || map->buffer) {
        error = 22;
        goto complete;
    }
    map->buffer = map;
    map->buffer_kind = 3;
    map->segment_count = 0;
    switch (memory->md_type) {
    case MEMDESC_VADDR:
        total = memory->md_len;
        if (!memory->u.md_vaddr || total == 0)
            error = 22;
        else
            error = append_virtual_range(
                tag, map, memory->u.md_vaddr, total);
        break;
    case MEMDESC_PADDR:
        total = memory->md_len;
        if (total == 0)
            error = 22;
        else
            error = append_physical_range(
                tag, map, memory->u.md_paddr, total);
        break;
    case MEMDESC_VLIST:
    case MEMDESC_PLIST:
        if (!memory->u.md_list || memory->md_nseg <= 0) {
            error = 22;
            break;
        }
        for (int index = 0; index < memory->md_nseg && !error; ++index) {
            bus_dma_segment_t *segment = &memory->u.md_list[index];

            if (segment->ds_len == 0 ||
                segment->ds_len > tag->maxsize ||
                total > tag->maxsize - segment->ds_len) {
                error = 27;
                break;
            }
            if (memory->md_type == MEMDESC_PLIST)
                error = append_physical_range(tag, map,
                    segment->ds_addr, segment->ds_len);
            else
                error = append_virtual_range(tag, map,
                    (const void *)(uintptr_t)segment->ds_addr,
                    segment->ds_len);
            total += segment->ds_len;
        }
        break;
    case MEMDESC_UIO:
        if (!memory->u.md_uio || memory->u.md_uio->uio_resid <= 0) {
            error = 22;
            break;
        }
        total = 0;
        for (int index = 0;
            index < memory->u.md_uio->uio_iovcnt && !error &&
            total < (bus_size_t)memory->u.md_uio->uio_resid; ++index) {
            struct iovec *vector = &memory->u.md_uio->uio_iov[index];
            bus_size_t length = vector->iov_len;

            if (length == 0)
                continue;
            if (length >
                (bus_size_t)memory->u.md_uio->uio_resid - total)
                length = (bus_size_t)memory->u.md_uio->uio_resid - total;
            if (!vector->iov_base || total > tag->maxsize - length) {
                error = 27;
                break;
            }
            error = append_virtual_range(
                tag, map, vector->iov_base, length);
            total += length;
        }
        break;
    case MEMDESC_MBUF: {
        struct mbuf *mbuf = memory->u.md_mbuf;

        if (!mbuf) {
            error = 22;
            break;
        }
        for (; mbuf && !error; mbuf = mbuf->m_next) {
            if (mbuf->m_len < 0 || (!mbuf->m_data && mbuf->m_len != 0) ||
                total > tag->maxsize - (bus_size_t)mbuf->m_len) {
                error = 27;
                break;
            }
            if (mbuf->m_len != 0)
                error = append_virtual_range(tag, map, mbuf->m_data,
                    (bus_size_t)mbuf->m_len);
            total += (bus_size_t)mbuf->m_len;
        }
        break;
    }
    case MEMDESC_VMPAGES: {
        bus_size_t remaining = memory->md_len;
        bus_size_t offset = memory->md_offset;
        int index = 0;

        total = memory->md_len;
        if (!memory->u.md_ma || remaining == 0 ||
            offset >= BSD_BUS_DMA_PAGE_SIZE) {
            error = 22;
            break;
        }
        while (remaining != 0) {
            vm_page_t page = memory->u.md_ma[index++];
            bus_size_t chunk = BSD_BUS_DMA_PAGE_SIZE - offset;

            if (!page) {
                error = 22;
                break;
            }
            if (chunk > remaining)
                chunk = remaining;
            error = append_physical_range(tag, map,
                VM_PAGE_TO_PHYS(page) + offset, chunk);
            if (error)
                break;
            remaining -= chunk;
            offset = 0;
        }
        break;
    }
    default:
        error = 22;
        break;
    }
    if (!error && (total == 0 || total > tag->maxsize))
        error = 27;
    if (!error)
        map->length = total;

complete:
    if (error && map) {
        map->buffer = 0;
        map->buffer_kind = 0;
        map->length = 0;
        map->segment_count = 0;
    }
    if (callback)
        callback(callback_argument, map ? map->segments : 0,
            error == 0 ? map->segment_count : 0, error);
    return error;
}

int
bus_dmamap_load_mbuf(bus_dma_tag_t tag, bus_dmamap_t map,
    struct mbuf *mbuf, bus_dmamap_callback2_t *callback,
    void *callback_argument, int flags)
{
    int segment_count = 0;
    int error;

    if (!callback)
        return 22;
    if (!map || !mbuf || (mbuf->m_flags & M_PKTHDR) == 0) {
        callback(callback_argument, 0, 0, 0, 22);
        return 22;
    }
    error = bus_dmamap_load_mbuf_sg(tag, map, mbuf, map->segments,
        &segment_count, flags | BUS_DMA_NOWAIT);
    callback(callback_argument, error ? 0 : map->segments,
        error ? 0 : segment_count,
        error ? 0 : (bus_size_t)mbuf->m_pkthdr.len, error);
    return error;
}

int
bus_dmamap_load_mbuf_sg(bus_dma_tag_t tag, bus_dmamap_t map,
    struct mbuf *mbuf, bus_dma_segment_t *segments, int *segment_count,
    int flags)
{
    struct mbuf *current;
    bus_size_t total = 0;
    int error = 0;

    (void)flags;
    if (segment_count)
        *segment_count = 0;
    if (!tag || !map || map->tag != tag || !mbuf || !segments ||
        !segment_count || map->buffer)
        return 22;
    map->buffer = mbuf;
    map->buffer_kind = 2;
    map->segment_count = 0;
    for (current = mbuf; current; current = current->m_next) {
        bus_size_t offset = 0;

        if (current->m_len < 0 || (!current->m_data &&
            current->m_len != 0)) {
            error = 22;
            break;
        }
        if ((bus_size_t)current->m_len > tag->maxsize - total) {
            error = 27;
            break;
        }
        while (offset < (bus_size_t)current->m_len) {
            uint64_t physical;
            bus_size_t page_remaining;
            bus_size_t chunk;

            if ((uintptr_t)current->m_data > UINTPTR_MAX - offset ||
                g_bus_dma_ops.physical_address(
                current->m_data + offset, &physical,
                g_bus_dma_ops.context) != 0) {
                error = 22;
                break;
            }
            page_remaining = BSD_BUS_DMA_PAGE_SIZE -
                (physical & (BSD_BUS_DMA_PAGE_SIZE - 1));
            chunk = minimum((bus_size_t)current->m_len - offset,
                page_remaining);
            chunk = minimum(chunk, tag->max_segment_size);
            if (tag->boundary != 0) {
                bus_size_t boundary_remaining = tag->boundary -
                    (physical & (tag->boundary - 1));
                chunk = minimum(chunk, boundary_remaining);
            }
            error = append_segment(tag, map, physical, chunk);
            if (error != 0)
                break;
            offset += chunk;
        }
        if (error != 0)
            break;
        total += (bus_size_t)current->m_len;
    }
    if (error == 0 && total == 0)
        error = 22;
    if (error != 0) {
        map->buffer = 0;
        map->buffer_kind = 0;
        map->length = 0;
        map->segment_count = 0;
        return error;
    }
    map->length = total;
    for (int index = 0; index < map->segment_count; ++index)
        segments[index] = map->segments[index];
    *segment_count = map->segment_count;
    return 0;
}

void
bus_dmamap_sync(bus_dma_tag_t tag, bus_dmamap_t map,
    bus_dmasync_op_t operation)
{
    if (!tag || !map || map->tag != tag || !map->buffer)
        return;
    if (map->buffer_kind == 3) {
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    } else if (g_bus_dma_ops.sync && map->buffer_kind == 2) {
        struct mbuf *mbuf = map->buffer;

        for (; mbuf; mbuf = mbuf->m_next) {
            if (mbuf->m_len > 0)
                g_bus_dma_ops.sync(mbuf->m_data,
                    (size_t)mbuf->m_len, operation,
                    g_bus_dma_ops.context);
        }
    } else if (g_bus_dma_ops.sync) {
        g_bus_dma_ops.sync(map->buffer, map->length, operation,
            g_bus_dma_ops.context);
    } else {
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    }
}

void
bus_dmamap_unload(bus_dma_tag_t tag, bus_dmamap_t map)
{
    if (!tag || !map || map->tag != tag)
        return;
    map->buffer = 0;
    map->buffer_kind = 0;
    map->length = 0;
    map->segment_count = 0;
}

void
busdma_lock_mutex(void *argument, bus_dma_lock_op_t operation)
{
    struct mtx *mutex = argument;

    if (operation == BUS_DMA_LOCK)
        mtx_lock(mutex);
    else
        mtx_unlock(mutex);
}

void
_busdma_dflt_lock(void *argument, bus_dma_lock_op_t operation)
{
    (void)argument;
    (void)operation;
}
