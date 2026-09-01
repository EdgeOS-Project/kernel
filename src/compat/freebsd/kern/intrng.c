/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS interrupt-domain runtime for imported BSD platform drivers.
 *
 * The public contract follows FreeBSD INTRNG, while resource ownership,
 * deferred execution, and architecture delivery remain shared EdgeOS
 * services.  Interrupt-controller drivers therefore retain their mapping,
 * masking, acknowledgement, and trigger-mode logic without gaining a second
 * architecture-specific implementation.
 */

#include <stdint.h>

#ifndef INTRNG
#define INTRNG 1
#endif

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cpuset.h>
#include <sys/intr.h>
#include <sys/interrupt.h>
#include <sys/kthread.h>
#include <sys/rman.h>
#include <sys/stdarg.h>
#include <sys/systm.h>

#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "msi_if.h"
#include "pic_if.h"

#define BSD_INTRNG_EINVAL 22
#define BSD_INTRNG_EBUSY 16
#define BSD_INTRNG_ENOMEM 12
#define BSD_INTRNG_ENOENT 2
#define BSD_INTRNG_ENXIO 6
#define BSD_INTRNG_ESRCH 3
#define BSD_INTRNG_ENOTSUP 45
#define BSD_INTRNG_SYNTHETIC_FIRST UINT32_C(0x80000000)
#define BSD_INTRNG_SYNTHETIC_LAST UINT32_C(0xfffffffe)

struct intr_pic_child_record {
    struct intr_pic_child_record *next;
    struct intr_pic *child_pic;
    intr_child_irq_filter_t *filter;
    void *argument;
    uintptr_t start;
    uintptr_t length;
};

struct intr_pic {
    struct intr_pic *next;
    device_t device;
    intptr_t xref;
    struct intr_pic_child_record *children;
    uint8_t is_msi;
};

struct bsd_intrng_handler {
    struct bsd_intrng_handler *next;
    struct bsd_intrng_source *source;
    struct bsd_intrng_map *map;
    device_t device;
    struct resource *resource;
    driver_filter_t *filter;
    driver_intr_t *handler;
    void *argument;
    int flags;
    volatile unsigned int active;
    volatile uint8_t pending;
    volatile uint8_t removing;
    uint8_t suspended;
    char description[64];
};

struct bsd_intrng_source {
    struct bsd_intrng_source *next;
    struct intr_irqsrc *isrc;
    struct bsd_intrng_handler *handlers;
    struct taskqueue *thread_queue;
    struct task deferred_task;
    unsigned int threaded_handlers;
    unsigned int suspended_handlers;
    uint8_t thread_armed;
};

struct bsd_intrng_map {
    struct bsd_intrng_map *next;
    device_t device;
    intptr_t xref;
    struct intr_map_data *data;
    struct intr_irqsrc *isrc;
    struct resource *active_resource;
    u_int id;
    unsigned int handlers;
    volatile unsigned int operations;
    uint8_t removing;
    uint8_t activating;
    uint8_t deactivating;
};

struct bsd_intrng_root {
    device_t device;
    intr_irq_filter_t *filter;
    void *argument;
};

static struct intr_pic *g_intrng_pics;
static struct bsd_intrng_source *g_intrng_sources;
static struct bsd_intrng_map *g_intrng_maps;
static struct bsd_intrng_root g_intrng_roots[4];
static volatile unsigned int g_intrng_guard;
static u_int g_intrng_next_map = BSD_INTRNG_SYNTHETIC_FIRST;
static u_int g_intrng_next_source;

u_int intr_nirq = 65536;

static void
intrng_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void
intrng_lock(void)
{
    while (__atomic_test_and_set(&g_intrng_guard, __ATOMIC_ACQUIRE))
        intrng_relax();
}

static void
intrng_unlock(void)
{
    __atomic_clear(&g_intrng_guard, __ATOMIC_RELEASE);
}

static struct intr_pic *
intrng_pic_lookup_locked(device_t device, intptr_t xref)
{
    struct intr_pic *pic;

    for (pic = g_intrng_pics; pic; pic = pic->next) {
        if (!device) {
            if (xref != 0 && pic->xref == xref)
                return pic;
        } else if ((xref == 0 || pic->xref == 0) &&
            pic->device == device) {
            return pic;
        } else if (pic->device == device && pic->xref == xref) {
            return pic;
        }
    }
    return 0;
}

static struct bsd_intrng_source *
intrng_source_lookup_locked(const struct intr_irqsrc *isrc)
{
    struct bsd_intrng_source *source;

    for (source = g_intrng_sources; source; source = source->next) {
        if (source->isrc == isrc)
            return source;
    }
    return 0;
}

static struct bsd_intrng_map *
intrng_map_lookup_locked(u_int id)
{
    struct bsd_intrng_map *map;

    for (map = g_intrng_maps; map; map = map->next) {
        if (map->id == id)
            return map;
    }
    return 0;
}

static struct bsd_intrng_map *
intrng_map_acquire(u_int id)
{
    struct bsd_intrng_map *map;

    intrng_lock();
    map = intrng_map_lookup_locked(id);
    if (map && !map->removing)
        __atomic_add_fetch(&map->operations, 1, __ATOMIC_ACQ_REL);
    else
        map = 0;
    intrng_unlock();
    return map;
}

static void
intrng_map_release(struct bsd_intrng_map *map)
{
    __atomic_sub_fetch(&map->operations, 1, __ATOMIC_ACQ_REL);
}

static struct intr_map_data *
intrng_copy_map_data(const struct intr_map_data *data)
{
    struct intr_map_data *copy;

    if (!data || data->len < sizeof(*data))
        return 0;
    copy = bsd_malloc(data->len, M_DEVBUF, M_WAITOK | M_ZERO);
    if (copy)
        memcpy(copy, data, data->len);
    return copy;
}

static int
intrng_resolve_map(struct bsd_intrng_map *map,
    struct intr_map_data *data, struct intr_irqsrc **isrc_out)
{
    struct intr_pic *pic;

    intrng_lock();
    pic = intrng_pic_lookup_locked(map->device, map->xref);
    intrng_unlock();
    if (!pic)
        return BSD_INTRNG_ESRCH;
    if (!data || !isrc_out)
        return BSD_INTRNG_EINVAL;
    if (data->type == INTR_MAP_DATA_MSI) {
        struct intr_map_data_msi *msi =
            (struct intr_map_data_msi *)data;

        if (!pic->is_msi || !msi->isrc)
            return BSD_INTRNG_EINVAL;
        *isrc_out = msi->isrc;
        return 0;
    }
    if (pic->is_msi)
        return BSD_INTRNG_EINVAL;
    return PIC_MAP_INTR(pic->device, data, isrc_out);
}

int
bsd_intrng_resource_is_mapped(const struct resource *resource)
{
    struct bsd_intrng_map *map;
    rman_res_t start;
    int found;

    if (!resource || rman_get_type(resource) != SYS_RES_IRQ ||
        rman_get_start(resource) != rman_get_end(resource))
        return 0;
    start = rman_get_start(resource);
    if (start < BSD_INTRNG_SYNTHETIC_FIRST ||
        start > BSD_INTRNG_SYNTHETIC_LAST)
        return 0;
    intrng_lock();
    map = intrng_map_lookup_locked((u_int)start);
    found = map && !map->removing;
    intrng_unlock();
    return found;
}

struct intr_map_data *
intr_alloc_map_data(enum intr_map_data_type type, size_t length, int flags)
{
    struct intr_map_data *data;

    if (length < sizeof(*data))
        return 0;
    data = bsd_malloc(length, M_DEVBUF, flags);
    if (!data)
        return 0;
    data->type = type;
    data->len = length;
    return data;
}

void
intr_free_intr_map_data(struct intr_map_data *data)
{
    if (data)
        bsd_free(data, M_DEVBUF);
}

u_int
intr_map_irq(device_t device, intptr_t xref, struct intr_map_data *data)
{
    struct bsd_intrng_map *map;
    u_int candidate;

    if (!device || !data || data->len < sizeof(*data))
        return INTR_IRQ_INVALID;
    map = bsd_malloc(sizeof(*map), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!map)
        return INTR_IRQ_INVALID;
    map->device = device;
    map->xref = xref;
    map->data = data;

    intrng_lock();
    candidate = g_intrng_next_map;
    do {
        if (!intrng_map_lookup_locked(candidate))
            break;
        candidate = candidate == BSD_INTRNG_SYNTHETIC_LAST ?
            BSD_INTRNG_SYNTHETIC_FIRST : candidate + 1;
    } while (candidate != g_intrng_next_map);
    if (intrng_map_lookup_locked(candidate)) {
        intrng_unlock();
        bsd_free(map, M_DEVBUF);
        panic("BSD interrupt mapping space exhausted");
    }
    map->id = candidate;
    map->next = g_intrng_maps;
    g_intrng_maps = map;
    g_intrng_next_map = candidate == BSD_INTRNG_SYNTHETIC_LAST ?
        BSD_INTRNG_SYNTHETIC_FIRST : candidate + 1;
    intrng_unlock();
    return candidate;
}

void
intr_unmap_irq(u_int id)
{
    struct bsd_intrng_map **cursor;
    struct bsd_intrng_map *map;

    intrng_lock();
    map = intrng_map_lookup_locked(id);
    if (!map) {
        intrng_unlock();
        panic("Attempt to unmap invalid interrupt resource %u", id);
    }
    if (map->handlers != 0 || map->active_resource) {
        intrng_unlock();
        panic("Attempt to unmap active interrupt resource %u", id);
    }
    map->removing = 1;
    intrng_unlock();
    while (__atomic_load_n(&map->operations, __ATOMIC_ACQUIRE) != 0)
        intrng_relax();

    intrng_lock();
    for (cursor = &g_intrng_maps; *cursor; cursor = &(*cursor)->next) {
        if (*cursor == map) {
            *cursor = map->next;
            break;
        }
    }
    intrng_unlock();
    intr_free_intr_map_data(map->data);
    bsd_free(map, M_DEVBUF);
}

u_int
intr_map_clone_irq(u_int old_id)
{
    struct bsd_intrng_map *map;
    struct intr_map_data *copy;
    device_t device;
    intptr_t xref;

    map = intrng_map_acquire(old_id);
    if (!map)
        return INTR_IRQ_INVALID;
    copy = intrng_copy_map_data(map->data);
    device = map->device;
    xref = map->xref;
    intrng_map_release(map);
    if (!copy)
        return INTR_IRQ_INVALID;
    return intr_map_irq(device, xref, copy);
}

int
intr_isrc_register(struct intr_irqsrc *isrc, device_t device, u_int flags,
    const char *format, ...)
{
    struct bsd_intrng_source *source;
    va_list arguments;

    if (!isrc || !device || !format)
        return BSD_INTRNG_EINVAL;
    source = bsd_malloc(sizeof(*source), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!source)
        return BSD_INTRNG_ENOMEM;
    memset(isrc, 0, sizeof(*isrc));
    isrc->isrc_dev = device;
    isrc->isrc_flags = flags;
    CPU_ZERO(&isrc->isrc_cpu);
    isrc->isrc_count = bsd_malloc(2 * sizeof(*isrc->isrc_count),
        M_DEVBUF, M_WAITOK | M_ZERO);
    if (!isrc->isrc_count) {
        bsd_free(source, M_DEVBUF);
        return BSD_INTRNG_ENOMEM;
    }
    va_start(arguments, format);
    vsnprintf(isrc->isrc_name, sizeof(isrc->isrc_name), format, arguments);
    va_end(arguments);

    intrng_lock();
    if (intrng_source_lookup_locked(isrc)) {
        intrng_unlock();
        bsd_free(isrc->isrc_count, M_DEVBUF);
        isrc->isrc_count = 0;
        bsd_free(source, M_DEVBUF);
        return BSD_INTRNG_EBUSY;
    }
    isrc->isrc_irq = g_intrng_next_source++;
    isrc->isrc_index = isrc->isrc_irq * 2;
    source->isrc = isrc;
    source->next = g_intrng_sources;
    g_intrng_sources = source;
    intrng_unlock();
    return 0;
}

int
intr_isrc_deregister(struct intr_irqsrc *isrc)
{
    struct bsd_intrng_source **cursor;
    struct bsd_intrng_source *source;
    struct bsd_intrng_map *map;

    if (!isrc)
        return BSD_INTRNG_EINVAL;
    intrng_lock();
    source = intrng_source_lookup_locked(isrc);
    if (!source) {
        intrng_unlock();
        return BSD_INTRNG_ENOENT;
    }
    if (source->handlers || source->thread_armed) {
        intrng_unlock();
        return BSD_INTRNG_EBUSY;
    }
    for (map = g_intrng_maps; map; map = map->next) {
        if (map->isrc == isrc) {
            intrng_unlock();
            return BSD_INTRNG_EBUSY;
        }
    }
    for (cursor = &g_intrng_sources; *cursor;
        cursor = &(*cursor)->next) {
        if (*cursor == source) {
            *cursor = source->next;
            break;
        }
    }
    intrng_unlock();
    bsd_free(isrc->isrc_count, M_DEVBUF);
    memset(isrc, 0, sizeof(*isrc));
    isrc->isrc_irq = INTR_IRQ_INVALID;
    bsd_free(source, M_DEVBUF);
    return 0;
}

struct intr_pic *
intr_pic_register(device_t device, intptr_t xref)
{
    struct intr_pic *pic;

    if (!device)
        return 0;
    intrng_lock();
    pic = intrng_pic_lookup_locked(device, xref);
    intrng_unlock();
    if (pic)
        return pic->is_msi ? 0 : pic;
    pic = bsd_malloc(sizeof(*pic), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!pic)
        return 0;
    pic->device = device;
    pic->xref = xref;
    intrng_lock();
    if (intrng_pic_lookup_locked(device, xref)) {
        struct intr_pic *existing =
            intrng_pic_lookup_locked(device, xref);

        intrng_unlock();
        bsd_free(pic, M_DEVBUF);
        return existing->is_msi ? 0 : existing;
    }
    pic->next = g_intrng_pics;
    g_intrng_pics = pic;
    intrng_unlock();
    return pic;
}

int
intr_msi_register(device_t device, intptr_t xref)
{
    struct intr_pic *existing;
    struct intr_pic *pic;

    if (!device)
        return BSD_INTRNG_EINVAL;
    intrng_lock();
    existing = intrng_pic_lookup_locked(device, xref);
    intrng_unlock();
    if (existing)
        return existing->is_msi ? 0 : BSD_INTRNG_EBUSY;
    pic = bsd_malloc(sizeof(*pic), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!pic)
        return BSD_INTRNG_ENOMEM;
    pic->device = device;
    pic->xref = xref;
    pic->is_msi = 1;
    intrng_lock();
    existing = intrng_pic_lookup_locked(device, xref);
    if (existing) {
        intrng_unlock();
        bsd_free(pic, M_DEVBUF);
        return existing->is_msi ? 0 : BSD_INTRNG_EBUSY;
    }
    pic->next = g_intrng_pics;
    g_intrng_pics = pic;
    intrng_unlock();
    return 0;
}

static struct intr_pic *
intrng_msi_pic_lookup(intptr_t xref)
{
    struct intr_pic *pic;

    intrng_lock();
    for (pic = g_intrng_pics; pic; pic = pic->next) {
        if (pic->is_msi && pic->xref == xref)
            break;
    }
    intrng_unlock();
    return pic;
}

static int
intrng_msi_source_for_irq(struct intr_pic *pic, int irq,
    struct intr_irqsrc **source_out)
{
    struct bsd_intrng_map *map;
    struct intr_map_data_msi *msi;
    int error = 0;

    if (!pic || !source_out || irq == (int)INTR_IRQ_INVALID)
        return BSD_INTRNG_EINVAL;
    map = intrng_map_acquire((u_int)irq);
    if (!map)
        return BSD_INTRNG_EINVAL;
    if (map->device != pic->device || map->xref != pic->xref ||
        !map->data || map->data->type != INTR_MAP_DATA_MSI ||
        map->data->len < sizeof(*msi)) {
        error = BSD_INTRNG_EINVAL;
    } else {
        msi = (struct intr_map_data_msi *)map->data;
        if (!msi->isrc)
            error = BSD_INTRNG_EINVAL;
        else
            *source_out = msi->isrc;
    }
    intrng_map_release(map);
    return error;
}

int
intr_alloc_msi(device_t pci, device_t child, intptr_t xref, int count,
    int maxcount, int *irqs)
{
    struct iommu_domain *domain = 0;
    struct intr_irqsrc **sources;
    struct intr_pic *pic;
    device_t controller = 0;
    int error;
    int mapped = 0;

    (void)pci;
    if (!irqs || count <= 0 || maxcount < count)
        return BSD_INTRNG_EINVAL;
    pic = intrng_msi_pic_lookup(xref);
    if (!pic)
        return BSD_INTRNG_ESRCH;
    for (int index = 0; index < count; ++index)
        irqs[index] = (int)INTR_IRQ_INVALID;
    error = MSI_IOMMU_INIT(pic->device, child, &domain);
    if (error)
        return error;
    sources = bsd_malloc(sizeof(*sources) * (size_t)count, M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!sources) {
        MSI_IOMMU_DEINIT(pic->device, child);
        return BSD_INTRNG_ENOMEM;
    }
    error = MSI_ALLOC_MSI(pic->device, child, count, maxcount,
        &controller, sources);
    if (error)
        goto out;
    for (int index = 0; index < count; ++index) {
        struct intr_map_data_msi *msi;
        u_int irq;

        if (!sources[index]) {
            error = BSD_INTRNG_EINVAL;
            break;
        }
        sources[index]->isrc_iommu = domain;
        msi = (struct intr_map_data_msi *)intr_alloc_map_data(
            INTR_MAP_DATA_MSI, sizeof(*msi), M_WAITOK | M_ZERO);
        if (!msi) {
            error = BSD_INTRNG_ENOMEM;
            break;
        }
        msi->isrc = sources[index];
        irq = intr_map_irq(pic->device, xref,
            (struct intr_map_data *)msi);
        if (irq == INTR_IRQ_INVALID) {
            intr_free_intr_map_data((struct intr_map_data *)msi);
            error = BSD_INTRNG_ENOMEM;
            break;
        }
        irqs[index] = (int)irq;
        mapped++;
    }
    if (!error)
        goto out_success;
    for (int index = 0; index < mapped; ++index)
        intr_unmap_irq((u_int)irqs[index]);
    for (int index = 0; index < count; ++index) {
        if (sources[index])
            sources[index]->isrc_iommu = 0;
        irqs[index] = (int)INTR_IRQ_INVALID;
    }
    (void)MSI_RELEASE_MSI(pic->device, child, count, sources);
out:
    MSI_IOMMU_DEINIT(pic->device, child);
    bsd_free(sources, M_DEVBUF);
    return error;
out_success:
    bsd_free(sources, M_DEVBUF);
    return 0;
}

int
intr_release_msi(device_t pci, device_t child, intptr_t xref, int count,
    int *irqs)
{
    struct intr_irqsrc **sources;
    struct intr_pic *pic;
    int error = 0;

    (void)pci;
    if (!irqs || count <= 0)
        return BSD_INTRNG_EINVAL;
    pic = intrng_msi_pic_lookup(xref);
    if (!pic)
        return BSD_INTRNG_ESRCH;
    sources = bsd_malloc(sizeof(*sources) * (size_t)count, M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!sources)
        return BSD_INTRNG_ENOMEM;
    for (int index = 0; index < count; ++index) {
        error = intrng_msi_source_for_irq(pic, irqs[index],
            &sources[index]);
        if (error)
            break;
    }
    if (error) {
        bsd_free(sources, M_DEVBUF);
        return error;
    }
    MSI_IOMMU_DEINIT(pic->device, child);
    error = MSI_RELEASE_MSI(pic->device, child, count, sources);
    for (int index = 0; index < count; ++index) {
        sources[index]->isrc_iommu = 0;
        intr_unmap_irq((u_int)irqs[index]);
        irqs[index] = (int)INTR_IRQ_INVALID;
    }
    bsd_free(sources, M_DEVBUF);
    return error;
}

int
intr_alloc_msix(device_t pci, device_t child, intptr_t xref, int *irq)
{
    struct iommu_domain *domain = 0;
    struct intr_map_data_msi *msi;
    struct intr_irqsrc *source = 0;
    struct intr_pic *pic;
    device_t controller = 0;
    u_int mapped_irq;
    int error;

    (void)pci;
    if (!irq)
        return BSD_INTRNG_EINVAL;
    *irq = (int)INTR_IRQ_INVALID;
    pic = intrng_msi_pic_lookup(xref);
    if (!pic)
        return BSD_INTRNG_ESRCH;
    error = MSI_IOMMU_INIT(pic->device, child, &domain);
    if (error)
        return error;
    error = MSI_ALLOC_MSIX(pic->device, child, &controller, &source);
    if (error)
        goto out;
    if (!source) {
        error = BSD_INTRNG_EINVAL;
        goto release;
    }
    source->isrc_iommu = domain;
    msi = (struct intr_map_data_msi *)intr_alloc_map_data(
        INTR_MAP_DATA_MSI, sizeof(*msi), M_WAITOK | M_ZERO);
    if (!msi) {
        error = BSD_INTRNG_ENOMEM;
        goto release;
    }
    msi->isrc = source;
    mapped_irq = intr_map_irq(pic->device, xref,
        (struct intr_map_data *)msi);
    if (mapped_irq == INTR_IRQ_INVALID) {
        intr_free_intr_map_data((struct intr_map_data *)msi);
        error = BSD_INTRNG_ENOMEM;
        goto release;
    }
    *irq = (int)mapped_irq;
    return 0;
release:
    if (source) {
        source->isrc_iommu = 0;
        (void)MSI_RELEASE_MSIX(pic->device, child, source);
    }
out:
    MSI_IOMMU_DEINIT(pic->device, child);
    return error;
}

int
intr_release_msix(device_t pci, device_t child, intptr_t xref, int irq)
{
    struct intr_irqsrc *source = 0;
    struct intr_pic *pic;
    int error;

    (void)pci;
    pic = intrng_msi_pic_lookup(xref);
    if (!pic)
        return BSD_INTRNG_ESRCH;
    error = intrng_msi_source_for_irq(pic, irq, &source);
    if (error)
        return error;
    MSI_IOMMU_DEINIT(pic->device, child);
    error = MSI_RELEASE_MSIX(pic->device, child, source);
    source->isrc_iommu = 0;
    intr_unmap_irq((u_int)irq);
    return error;
}

int
intr_map_msi(device_t pci, device_t child, intptr_t xref, int irq,
    uint64_t *address, uint32_t *data)
{
    struct intr_irqsrc *source = 0;
    struct intr_pic *pic;
    int error;

    (void)pci;
    if (!address || !data)
        return BSD_INTRNG_EINVAL;
    pic = intrng_msi_pic_lookup(xref);
    if (!pic)
        return BSD_INTRNG_ESRCH;
    error = intrng_msi_source_for_irq(pic, irq, &source);
    if (error)
        return error;
    return MSI_MAP_MSI(pic->device, child, source, address, data);
}

int
intr_pic_deregister(device_t device, intptr_t xref)
{
    struct intr_pic **cursor;
    struct intr_pic *pic;
    struct bsd_intrng_map *map;
    uint32_t root_number;

    intrng_lock();
    pic = intrng_pic_lookup_locked(device, xref);
    if (!pic) {
        intrng_unlock();
        return BSD_INTRNG_ENOENT;
    }
    if (pic->children) {
        intrng_unlock();
        return BSD_INTRNG_EBUSY;
    }
    for (root_number = 0; root_number < nitems(g_intrng_roots);
        ++root_number) {
        if (g_intrng_roots[root_number].device == device) {
            intrng_unlock();
            return BSD_INTRNG_EBUSY;
        }
    }
    for (map = g_intrng_maps; map; map = map->next) {
        if (map->device == device &&
            (xref == 0 || map->xref == xref || map->xref == 0)) {
            intrng_unlock();
            return BSD_INTRNG_EBUSY;
        }
    }
    for (cursor = &g_intrng_pics; *cursor; cursor = &(*cursor)->next) {
        if (*cursor == pic) {
            *cursor = pic->next;
            break;
        }
    }
    intrng_unlock();
    bsd_free(pic, M_DEVBUF);
    return 0;
}

int
intr_pic_add_handler(device_t parent, struct intr_pic *child_pic,
    intr_child_irq_filter_t *filter, void *argument, uintptr_t start,
    uintptr_t length)
{
    struct intr_pic_child_record *child;
    struct intr_pic *parent_pic;
    struct intr_pic_child_record *cursor;

    if (!parent || !child_pic || !filter || length == 0 ||
        start > UINTPTR_MAX - length)
        return BSD_INTRNG_EINVAL;
    child = bsd_malloc(sizeof(*child), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!child)
        return BSD_INTRNG_ENOMEM;
    intrng_lock();
    parent_pic = intrng_pic_lookup_locked(parent, 0);
    if (!parent_pic) {
        intrng_unlock();
        bsd_free(child, M_DEVBUF);
        return BSD_INTRNG_ENXIO;
    }
    for (cursor = parent_pic->children; cursor; cursor = cursor->next) {
        if (cursor->child_pic == child_pic ||
            (start < cursor->start + cursor->length &&
            cursor->start < start + length)) {
            intrng_unlock();
            bsd_free(child, M_DEVBUF);
            return BSD_INTRNG_EBUSY;
        }
    }
    child->child_pic = child_pic;
    child->filter = filter;
    child->argument = argument;
    child->start = start;
    child->length = length;
    child->next = parent_pic->children;
    parent_pic->children = child;
    intrng_unlock();
    return 0;
}

int
intr_child_irq_handler(struct intr_pic *parent, uintptr_t irq)
{
    struct intr_pic_child_record *child;
    intr_child_irq_filter_t *filter = 0;
    void *argument = 0;

    if (!parent)
        return FILTER_STRAY;
    intrng_lock();
    for (child = parent->children; child; child = child->next) {
        if (irq >= child->start && irq - child->start < child->length) {
            filter = child->filter;
            argument = child->argument;
            break;
        }
    }
    intrng_unlock();
    return filter ? filter(argument, irq) : FILTER_STRAY;
}

int
intr_pic_claim_root(device_t device, intptr_t xref,
    intr_irq_filter_t *filter, void *argument, uint32_t root_number)
{
    struct intr_pic *pic;

    if (!device || !filter || root_number >= nitems(g_intrng_roots))
        return BSD_INTRNG_EINVAL;
    intrng_lock();
    pic = intrng_pic_lookup_locked(device, xref);
    if (!pic) {
        intrng_unlock();
        return BSD_INTRNG_ENOENT;
    }
    if (g_intrng_roots[root_number].device) {
        intrng_unlock();
        return BSD_INTRNG_EBUSY;
    }
    g_intrng_roots[root_number].device = device;
    g_intrng_roots[root_number].filter = filter;
    g_intrng_roots[root_number].argument = argument;
    intrng_unlock();
    return 0;
}

device_t
intr_irq_root_device(uint32_t root_number)
{
    device_t device;

    if (root_number >= nitems(g_intrng_roots))
        return 0;
    intrng_lock();
    device = g_intrng_roots[root_number].device;
    intrng_unlock();
    return device;
}

void
intr_irq_handler(struct trapframe *frame, uint32_t root_number)
{
    intr_irq_filter_t *filter;
    struct thread *thread;
    struct trapframe *previous_frame;
    void *argument;

    if (root_number >= nitems(g_intrng_roots))
        panic("Invalid interrupt root %u", root_number);
    intrng_lock();
    filter = g_intrng_roots[root_number].filter;
    argument = g_intrng_roots[root_number].argument;
    intrng_unlock();
    if (!filter)
        panic("Interrupt root %u is not registered", root_number);

    bsd_kthread_critical_enter();
    thread = curthread;
    previous_frame = thread ? thread->td_intr_frame : 0;
    if (thread)
        thread->td_intr_frame = frame;
    (void)filter(argument);
    if (thread)
        thread->td_intr_frame = previous_frame;
    bsd_kthread_critical_exit();
}

static void
intrng_deferred_task(void *context, int pending_count)
{
    struct bsd_intrng_source *source = context;

    (void)pending_count;
    for (;;) {
        struct bsd_intrng_handler *handler = 0;
        int have_pending = 0;

        intrng_lock();
        for (handler = source->handlers; handler;
            handler = handler->next) {
            if (__atomic_exchange_n(&handler->pending, 0,
                __ATOMIC_ACQ_REL)) {
                have_pending = 1;
                break;
            }
        }
        intrng_unlock();
        if (have_pending) {
            if (!__atomic_load_n(&handler->removing,
                __ATOMIC_ACQUIRE) && !handler->suspended &&
                handler->handler)
                handler->handler(handler->argument);
            __atomic_sub_fetch(&handler->active, 1,
                __ATOMIC_ACQ_REL);
            continue;
        }

        PIC_POST_ITHREAD(source->isrc->isrc_dev, source->isrc);
        intrng_lock();
        for (handler = source->handlers; handler;
            handler = handler->next) {
            if (__atomic_load_n(&handler->pending, __ATOMIC_ACQUIRE)) {
                have_pending = 1;
                break;
            }
        }
        if (!have_pending)
            source->thread_armed = 0;
        intrng_unlock();
        if (!have_pending)
            return;
        PIC_PRE_ITHREAD(source->isrc->isrc_dev, source->isrc);
    }
}

int
intr_activate_irq(device_t device, struct resource *resource)
{
    struct bsd_intrng_map *map;
    struct intr_map_data *data;
    struct intr_irqsrc *isrc;
    u_int id;
    int error;

    (void)device;
    if (!resource || rman_get_start(resource) != rman_get_end(resource))
        return BSD_INTRNG_EINVAL;
    id = (u_int)rman_get_start(resource);
    map = intrng_map_acquire(id);
    if (!map)
        return BSD_INTRNG_ENOENT;
    intrng_lock();
    if (map->active_resource) {
        error = map->active_resource == resource ? 0 : BSD_INTRNG_EBUSY;
        intrng_unlock();
        intrng_map_release(map);
        return error;
    }
    if (map->activating || map->deactivating) {
        intrng_unlock();
        intrng_map_release(map);
        return BSD_INTRNG_EBUSY;
    }
    map->activating = 1;
    intrng_unlock();
    data = intrng_copy_map_data(map->data);
    if (!data) {
        intrng_lock();
        map->activating = 0;
        intrng_unlock();
        intrng_map_release(map);
        return BSD_INTRNG_ENOMEM;
    }
    error = intrng_resolve_map(map, data, &isrc);
    if (error == 0)
        error = PIC_ACTIVATE_INTR(isrc->isrc_dev, isrc, resource, data);
    if (error != 0) {
        bsd_free(data, M_DEVBUF);
        intrng_lock();
        map->activating = 0;
        intrng_unlock();
        intrng_map_release(map);
        return error;
    }
    intrng_lock();
    map->isrc = isrc;
    map->active_resource = resource;
    map->activating = 0;
    intrng_unlock();
    rman_set_virtual(resource, data);
    intrng_map_release(map);
    return 0;
}

int
intr_deactivate_irq(device_t device, struct resource *resource)
{
    struct bsd_intrng_map *map;
    struct intr_map_data *data;
    struct intr_irqsrc *isrc;
    u_int id;
    int error;

    (void)device;
    if (!resource || rman_get_start(resource) != rman_get_end(resource))
        return BSD_INTRNG_EINVAL;
    id = (u_int)rman_get_start(resource);
    map = intrng_map_acquire(id);
    if (!map)
        return BSD_INTRNG_ENOENT;
    intrng_lock();
    if (map->active_resource != resource || map->handlers != 0 ||
        map->activating || map->deactivating) {
        error = map->handlers != 0 || map->activating || map->deactivating ?
            BSD_INTRNG_EBUSY : BSD_INTRNG_EINVAL;
        intrng_unlock();
        intrng_map_release(map);
        return error;
    }
    map->deactivating = 1;
    isrc = map->isrc;
    data = rman_get_virtual(resource);
    intrng_unlock();
    error = PIC_DEACTIVATE_INTR(isrc->isrc_dev, isrc, resource, data);
    if (error == 0) {
        intrng_lock();
        map->active_resource = 0;
        map->isrc = 0;
        map->deactivating = 0;
        intrng_unlock();
        rman_set_virtual(resource, 0);
        bsd_free(data, M_DEVBUF);
    } else {
        intrng_lock();
        map->deactivating = 0;
        intrng_unlock();
    }
    intrng_map_release(map);
    return error;
}

int
intr_setup_irq(device_t device, struct resource *resource,
    driver_filter_t filter, driver_intr_t handler, void *argument,
    int flags, void **cookie_out)
{
    struct bsd_intrng_handler *record;
    struct bsd_intrng_source *source;
    struct bsd_intrng_map *map;
    struct intr_irqsrc *isrc;
    struct taskqueue *new_queue = 0;
    struct taskqueue *redundant_queue = 0;
    u_int id;
    int enable;
    int error;

    if (!device || !resource || !cookie_out || (!filter && !handler) ||
        rman_get_start(resource) != rman_get_end(resource))
        return BSD_INTRNG_EINVAL;
    id = (u_int)rman_get_start(resource);
    map = intrng_map_acquire(id);
    if (!map)
        return BSD_INTRNG_ENOENT;
    intrng_lock();
    if (map->active_resource != resource || !map->isrc) {
        intrng_unlock();
        intrng_map_release(map);
        return BSD_INTRNG_EINVAL;
    }
    isrc = map->isrc;
    source = intrng_source_lookup_locked(isrc);
    intrng_unlock();
    if (!source) {
        intrng_map_release(map);
        return BSD_INTRNG_ENOENT;
    }
    record = bsd_malloc(sizeof(*record), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!record) {
        intrng_map_release(map);
        return BSD_INTRNG_ENOMEM;
    }
    if (handler) {
        int need_queue;

        intrng_lock();
        need_queue = source->thread_queue == 0;
        intrng_unlock();
        if (need_queue) {
            if (!bsd_taskqueue_runtime_is_initialized()) {
                bsd_free(record, M_DEVBUF);
                intrng_map_release(map);
                return BSD_INTRNG_ENOTSUP;
            }
            new_queue = bsd_taskqueue_worker_create("intr_domain");
            if (!new_queue) {
                bsd_free(record, M_DEVBUF);
                intrng_map_release(map);
                return BSD_INTRNG_ENOMEM;
            }
        }
    }
    record->source = source;
    record->map = map;
    record->device = device;
    record->resource = resource;
    record->filter = filter;
    record->handler = handler;
    record->argument = argument;
    record->flags = flags;
    (void)bsd_strlcpy(record->description, device_get_nameunit(device),
        sizeof(record->description));

    error = PIC_SETUP_INTR(isrc->isrc_dev, isrc, resource,
        rman_get_virtual(resource));
    if (error != 0)
        goto fail;
    if (!rman_claim_irq_cookie(resource, 0, record)) {
        (void)PIC_TEARDOWN_INTR(isrc->isrc_dev, isrc, resource,
            rman_get_virtual(resource));
        error = BSD_INTRNG_EBUSY;
        goto fail;
    }

    intrng_lock();
    if (new_queue && !source->thread_queue) {
        source->thread_queue = new_queue;
        bsd_taskqueue_task_init(&source->deferred_task, 0,
            intrng_deferred_task, source);
        new_queue = 0;
    } else if (new_queue) {
        redundant_queue = new_queue;
        new_queue = 0;
    }
    record->next = source->handlers;
    source->handlers = record;
    if (handler) {
        source->threaded_handlers++;
        if (!source->thread_queue) {
            intrng_unlock();
            panic("Interrupt domain lost its worker queue");
        }
    }
    map->handlers++;
    enable = isrc->isrc_handlers == 0;
    isrc->isrc_handlers++;
    intrng_unlock();
    if (redundant_queue)
        bsd_taskqueue_worker_destroy(redundant_queue);
    if (enable)
        PIC_ENABLE_INTR(isrc->isrc_dev, isrc);
    *cookie_out = record;
    intrng_map_release(map);
    return 0;

fail:
    if (new_queue)
        bsd_taskqueue_worker_destroy(new_queue);
    bsd_free(record, M_DEVBUF);
    intrng_map_release(map);
    return error;
}

int
intr_teardown_irq(device_t device, struct resource *resource, void *cookie)
{
    struct bsd_intrng_handler *record = cookie;
    struct bsd_intrng_handler **cursor;
    struct bsd_intrng_source *source;
    struct bsd_intrng_map *map;
    struct taskqueue *destroy_queue = 0;
    struct intr_irqsrc *isrc;
    int disable;
    int error;

    if (!record || record->device != device ||
        record->resource != resource ||
        rman_get_irq_cookie(resource) != record)
        return BSD_INTRNG_EINVAL;
    source = record->source;
    map = record->map;
    isrc = source->isrc;
    if (__atomic_exchange_n(&record->removing, 1, __ATOMIC_ACQ_REL))
        return BSD_INTRNG_EBUSY;
    if (source->thread_queue)
        bsd_taskqueue_worker_drain(source->thread_queue,
            &source->deferred_task);
    while (__atomic_load_n(&record->active, __ATOMIC_ACQUIRE) != 0)
        intrng_relax();
    if (!rman_claim_irq_cookie(resource, record, 0)) {
        __atomic_store_n(&record->removing, 0, __ATOMIC_RELEASE);
        return BSD_INTRNG_EBUSY;
    }

    intrng_lock();
    for (cursor = &source->handlers; *cursor;
        cursor = &(*cursor)->next) {
        if (*cursor == record) {
            *cursor = record->next;
            break;
        }
    }
    if (record->suspended)
        source->suspended_handlers--;
    if (record->handler)
        source->threaded_handlers--;
    map->handlers--;
    isrc->isrc_handlers--;
    disable = isrc->isrc_handlers == 0;
    if (source->threaded_handlers == 0 && source->thread_queue) {
        destroy_queue = source->thread_queue;
        source->thread_queue = 0;
    }
    intrng_unlock();
    if (disable)
        PIC_DISABLE_INTR(isrc->isrc_dev, isrc);
    error = PIC_TEARDOWN_INTR(isrc->isrc_dev, isrc, resource,
        rman_get_virtual(resource));
    if (destroy_queue)
        bsd_taskqueue_worker_destroy(destroy_queue);
    bsd_free(record, M_DEVBUF);
    return error;
}

int
bsd_intrng_drain_irq(unsigned int irq)
{
    struct bsd_intrng_handler *record;
    struct bsd_intrng_source *source;
    struct bsd_intrng_map *map;
    int active;

    map = intrng_map_acquire((u_int)irq);
    if (!map)
        return 0;
    for (;;) {
        active = 0;
        intrng_lock();
        source = map->isrc ? intrng_source_lookup_locked(map->isrc) : 0;
        if (source) {
            for (record = source->handlers; record;
                record = record->next) {
                if (__atomic_load_n(&record->active,
                    __ATOMIC_ACQUIRE) != 0) {
                    active = 1;
                    break;
                }
            }
        }
        intrng_unlock();
        if (!active)
            break;
        intrng_relax();
    }
    intrng_map_release(map);
    return 1;
}

int
intr_describe_irq(device_t device, struct resource *resource, void *cookie,
    const char *description)
{
    struct bsd_intrng_handler *record = cookie;

    if (!record || record->device != device ||
        record->resource != resource || !description ||
        rman_get_irq_cookie(resource) != record)
        return BSD_INTRNG_EINVAL;
    (void)bsd_strlcpy(record->description, description,
        sizeof(record->description));
    return 0;
}

int
intr_isrc_dispatch(struct intr_irqsrc *isrc, struct trapframe *frame)
{
    struct bsd_intrng_handler *record;
    struct bsd_intrng_handler *head;
    struct bsd_intrng_source *source;
    int handled = 0;
    int start_worker = 0;

    (void)frame;
    if (!isrc)
        return BSD_INTRNG_EINVAL;
    intrng_lock();
    source = intrng_source_lookup_locked(isrc);
    if (!source) {
        intrng_unlock();
        return BSD_INTRNG_ENOENT;
    }
    head = source->handlers;
    for (record = head; record; record = record->next)
        __atomic_add_fetch(&record->active, 1, __ATOMIC_ACQ_REL);
    if (isrc->isrc_count)
        isrc->isrc_count[0]++;
    intrng_unlock();

    for (record = head; record;) {
        struct bsd_intrng_handler *next = record->next;
        int filter_result = FILTER_STRAY;

        if (!__atomic_load_n(&record->removing, __ATOMIC_ACQUIRE) &&
            !record->suspended) {
            filter_result = record->filter ?
                record->filter(record->argument) :
                FILTER_SCHEDULE_THREAD;
            if ((filter_result & FILTER_HANDLED) != 0)
                handled = 1;
            if ((filter_result & FILTER_SCHEDULE_THREAD) != 0 &&
                record->handler) {
                handled = 1;
                if (!__atomic_exchange_n(&record->pending, 1,
                    __ATOMIC_ACQ_REL))
                    __atomic_add_fetch(&record->active, 1,
                        __ATOMIC_ACQ_REL);
                intrng_lock();
                if (!source->thread_armed) {
                    source->thread_armed = 1;
                    start_worker = 1;
                }
                intrng_unlock();
            }
        }
        __atomic_sub_fetch(&record->active, 1, __ATOMIC_ACQ_REL);
        record = next;
    }
    if (start_worker) {
        int error;

        PIC_PRE_ITHREAD(isrc->isrc_dev, isrc);
        error = bsd_taskqueue_worker_schedule(source->thread_queue,
            &source->deferred_task);
        if (error != 0) {
            intrng_lock();
            source->thread_armed = 0;
            for (record = source->handlers; record;
                record = record->next) {
                if (__atomic_exchange_n(&record->pending, 0,
                    __ATOMIC_ACQ_REL))
                    __atomic_sub_fetch(&record->active, 1,
                        __ATOMIC_ACQ_REL);
            }
            intrng_unlock();
            PIC_POST_ITHREAD(isrc->isrc_dev, isrc);
            handled = 0;
        }
    } else if (handled && !source->thread_armed) {
        PIC_POST_FILTER(isrc->isrc_dev, isrc);
    }
    if (!handled && isrc->isrc_count)
        isrc->isrc_count[1]++;
    return handled ? 0 : BSD_INTRNG_EINVAL;
}

bool
intr_is_per_cpu(struct resource *resource)
{
    struct bsd_intrng_map *map;
    bool result = false;

    if (!resource)
        return false;
    map = intrng_map_acquire((u_int)rman_get_start(resource));
    if (map) {
        result = map->isrc &&
            (map->isrc->isrc_flags & INTR_ISRCF_PPI) != 0;
        intrng_map_release(map);
    }
    return result;
}

int
bsd_intrng_suspend_irq(device_t device, struct resource *resource)
{
    struct bsd_intrng_handler *record = rman_get_irq_cookie(resource);
    struct bsd_intrng_source *source;
    int disable = 0;

    if (!record || record->device != device || record->resource != resource)
        return BSD_INTRNG_EINVAL;
    source = record->source;
    intrng_lock();
    if (!record->suspended) {
        record->suspended = 1;
        source->suspended_handlers++;
        disable = source->suspended_handlers ==
            source->isrc->isrc_handlers;
    }
    intrng_unlock();
    if (disable)
        PIC_DISABLE_INTR(source->isrc->isrc_dev, source->isrc);
    return 0;
}

int
bsd_intrng_resume_irq(device_t device, struct resource *resource)
{
    struct bsd_intrng_handler *record = rman_get_irq_cookie(resource);
    struct bsd_intrng_source *source;
    int enable = 0;

    if (!record || record->device != device || record->resource != resource)
        return BSD_INTRNG_EINVAL;
    source = record->source;
    intrng_lock();
    if (record->suspended) {
        enable = source->suspended_handlers ==
            source->isrc->isrc_handlers;
        record->suspended = 0;
        source->suspended_handlers--;
    }
    intrng_unlock();
    if (enable)
        PIC_ENABLE_INTR(source->isrc->isrc_dev, source->isrc);
    return 0;
}

int
intr_setaffinity(int id, int which, const cpuset_t *mask)
{
    struct bsd_intrng_map *map;
    cpuset_t active;
    int error;

    if (which != CPU_WHICH_IRQ || id < 0 || !mask)
        return BSD_INTRNG_EINVAL;
    CPU_AND(&active, mask, cpuset_root);
    if (CPU_EMPTY(&active))
        return BSD_INTRNG_EINVAL;
    map = intrng_map_acquire((u_int)id);
    if (!map || !map->isrc) {
        if (map)
            intrng_map_release(map);
        return BSD_INTRNG_ENOENT;
    }
    CPU_COPY(&active, &map->isrc->isrc_cpu);
    map->isrc->isrc_flags |= INTR_ISRCF_BOUND;
    error = PIC_BIND_INTR(map->isrc->isrc_dev, map->isrc);
    if (error != 0)
        map->isrc->isrc_flags &= ~INTR_ISRCF_BOUND;
    intrng_map_release(map);
    return error;
}

u_int
intr_irq_next_cpu(u_int current_cpu, cpuset_t *cpu_mask)
{
    u_int next;

    if (!cpu_mask || CPU_EMPTY(cpu_mask))
        return current_cpu;
    for (next = current_cpu + 1; next < CPU_SETSIZE; ++next) {
        if (CPU_ISSET(next, cpu_mask))
            return next;
    }
    for (next = 0; next <= current_cpu && next < CPU_SETSIZE; ++next) {
        if (CPU_ISSET(next, cpu_mask))
            return next;
    }
    return (u_int)(CPU_FFS(cpu_mask) - 1);
}

#ifdef SMP
bool
intr_isrc_init_on_cpu(struct intr_irqsrc *isrc, u_int cpu)
{
    if (!isrc || isrc->isrc_handlers == 0 || cpu >= CPU_SETSIZE)
        return false;
    if ((isrc->isrc_flags & (INTR_ISRCF_PPI | INTR_ISRCF_IPI)) == 0)
        return false;
    if ((isrc->isrc_flags & INTR_ISRCF_BOUND) != 0)
        return CPU_ISSET(cpu, &isrc->isrc_cpu);
    CPU_SET(cpu, &isrc->isrc_cpu);
    return true;
}

int
intr_bind_irq(device_t device, struct resource *resource, int cpu)
{
    struct bsd_intrng_map *map;
    int error;

    (void)device;
    if (!resource || cpu < 0 || cpu >= CPU_SETSIZE)
        return BSD_INTRNG_EINVAL;
    map = intrng_map_acquire((u_int)rman_get_start(resource));
    if (!map || !map->isrc) {
        if (map)
            intrng_map_release(map);
        return BSD_INTRNG_ENOENT;
    }
    CPU_SETOF((u_int)cpu, &map->isrc->isrc_cpu);
    map->isrc->isrc_flags |= INTR_ISRCF_BOUND;
    error = PIC_BIND_INTR(map->isrc->isrc_dev, map->isrc);
    if (error != 0) {
        CPU_ZERO(&map->isrc->isrc_cpu);
        map->isrc->isrc_flags &= ~INTR_ISRCF_BOUND;
    }
    intrng_map_release(map);
    return error;
}

void
intr_pic_init_secondary(void)
{
    uint32_t index;

    for (index = 0; index < nitems(g_intrng_roots); ++index) {
        if (g_intrng_roots[index].device)
            PIC_INIT_SECONDARY(g_intrng_roots[index].device, index);
    }
}
#endif
