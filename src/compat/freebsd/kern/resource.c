/* SPDX-License-Identifier: MPL-2.0 */
/* Shared newbus resource registry for BSD drivers on EdgeOS. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/bus_space.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/resource.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/machine/resource.h"
#include "compat/freebsd/machine/vm.h"
#include "compat/freebsd/sys/rman.h"

/*
 * This translation unit implements the canonical resource functions.
 * Disable FreeBSD's source-compatibility overload macros around their
 * definitions while preserving those macros for imported drivers.
 */
#undef bus_alloc_resource
#undef bus_adjust_resource
#undef bus_activate_resource
#undef bus_deactivate_resource
#undef bus_map_resource
#undef bus_unmap_resource
#undef bus_release_resource

#define BSD_RESOURCE_ENOENT 2
#define BSD_RESOURCE_ENOMEM 12
#define BSD_RESOURCE_EBUSY 16
#define BSD_RESOURCE_EEXIST 17
#define BSD_RESOURCE_EINVAL 22
#define BSD_RESOURCE_ENXIO 6

struct resource_i {
    struct resource_i *next;
    struct resource_i *rman_next;
    struct rman *manager;
    struct resource public;
    device_t device;
    rman_res_t registered_start;
    rman_res_t registered_count;
    rman_res_t start;
    rman_res_t count;
    unsigned int flags;
    int type;
    int rid;
    uint8_t allocated;
    uint8_t mapped;
    unsigned int map_inflight;
    void *irq_cookie;
    bsd_resource_interrupt_source_ops_t interrupt_source;
    uint32_t interrupt_flags;
    uint8_t interrupt_enabled;
    struct resource_mapping_i *mappings;
};

struct resource_mapping_i {
    struct resource_mapping_i *next;
    struct resource_map public;
};

static volatile unsigned int g_resource_guard;
static struct resource_i *g_resources;

static void
resource_guard_lock(void)
{
    while (__atomic_test_and_set(&g_resource_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

static void
resource_guard_unlock(void)
{
    __atomic_clear(&g_resource_guard, __ATOMIC_RELEASE);
}

static struct resource_i *
resource_entry(const struct resource *resource)
{
    return resource ? resource->__r_i : 0;
}

#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
static int
resource_uses_intrng(const struct resource *resource)
{
    return bsd_intrng_resource_is_mapped(resource);
}
#endif

int
rman_init(struct rman *manager)
{
    if (!manager || manager->rm_start > manager->rm_end ||
        (manager->rm_type != RMAN_ARRAY &&
        manager->rm_type != RMAN_GAUGE))
        return BSD_RESOURCE_EINVAL;
    manager->rm_private = 0;
    return 0;
}

int
rman_fini(struct rman *manager)
{
    if (!manager)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    if (manager->rm_private) {
        resource_guard_unlock();
        return BSD_RESOURCE_EBUSY;
    }
    manager->rm_type = RMAN_UNINIT;
    resource_guard_unlock();
    return 0;
}

int
rman_manage_region(struct rman *manager, rman_res_t start, rman_res_t end)
{
    if (!manager || manager->rm_type == RMAN_UNINIT ||
        start > end || start < manager->rm_start || end > manager->rm_end)
        return BSD_RESOURCE_EINVAL;
    manager->rm_start = start;
    manager->rm_end = end;
    return 0;
}

static rman_res_t
rman_region_end(const struct resource_i *entry)
{
    return entry->start + entry->count - 1;
}

static int
rman_align_start(rman_res_t start, unsigned int flags,
    rman_res_t *aligned)
{
    unsigned int shift = RF_ALIGNMENT(flags);
    rman_res_t mask;

    if (!aligned || shift >= sizeof(rman_res_t) * 8u)
        return BSD_RESOURCE_EINVAL;
    mask = shift == 0 ? 0 : ((rman_res_t)1u << shift) - 1u;
    if (start > RM_MAX_END - mask)
        return BSD_RESOURCE_EINVAL;
    *aligned = (start + mask) & ~mask;
    return 0;
}

int
rman_first_free_region(struct rman *manager, rman_res_t *start,
    rman_res_t *end)
{
    rman_res_t cursor;

    if (!manager || !start || !end || manager->rm_type == RMAN_UNINIT)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    cursor = manager->rm_start;
    for (;;) {
        struct resource_i *entry;
        rman_res_t nearest = manager->rm_end;
        int has_nearest = 0;
        int advanced = 0;

        for (entry = manager->rm_private; entry;
             entry = entry->rman_next) {
            rman_res_t entry_end = rman_region_end(entry);

            if (entry_end < cursor)
                continue;
            if (entry->start <= cursor) {
                if (entry_end == RM_MAX_END) {
                    resource_guard_unlock();
                    return BSD_RESOURCE_ENOENT;
                }
                cursor = entry_end + 1u;
                advanced = 1;
                break;
            }
            if (!has_nearest || entry->start < nearest) {
                nearest = entry->start;
                has_nearest = 1;
            }
        }
        if (advanced) {
            if (cursor > manager->rm_end) {
                resource_guard_unlock();
                return BSD_RESOURCE_ENOENT;
            }
            continue;
        }
        *start = cursor;
        *end = has_nearest ? nearest - 1u : manager->rm_end;
        resource_guard_unlock();
        return 0;
    }
}

int
rman_last_free_region(struct rman *manager, rman_res_t *start,
    rman_res_t *end)
{
    rman_res_t cursor;

    if (!manager || !start || !end || manager->rm_type == RMAN_UNINIT)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    cursor = manager->rm_end;
    for (;;) {
        struct resource_i *entry;
        rman_res_t nearest = manager->rm_start;
        int has_nearest = 0;
        int advanced = 0;

        for (entry = manager->rm_private; entry;
             entry = entry->rman_next) {
            rman_res_t entry_end = rman_region_end(entry);

            if (entry->start > cursor)
                continue;
            if (entry_end >= cursor) {
                if (entry->start == 0) {
                    resource_guard_unlock();
                    return BSD_RESOURCE_ENOENT;
                }
                cursor = entry->start - 1u;
                advanced = 1;
                break;
            }
            if (!has_nearest || entry_end > nearest) {
                nearest = entry_end;
                has_nearest = 1;
            }
        }
        if (advanced) {
            if (cursor < manager->rm_start) {
                resource_guard_unlock();
                return BSD_RESOURCE_ENOENT;
            }
            continue;
        }
        *start = has_nearest ? nearest + 1u : manager->rm_start;
        *end = cursor;
        resource_guard_unlock();
        return 0;
    }
}

struct resource *
rman_reserve_resource(struct rman *manager, rman_res_t start,
    rman_res_t end, rman_res_t count, unsigned int flags, device_t device)
{
    struct resource_i *entry;
    struct resource_i *current;
    rman_res_t candidate;
    rman_res_t requested_end;

    if (!manager || manager->rm_type == RMAN_UNINIT || count == 0 ||
        start > end)
        return 0;
    if (start < manager->rm_start)
        start = manager->rm_start;
    if (end > manager->rm_end)
        end = manager->rm_end;
    if (start > end || count > end - start + 1 ||
        rman_align_start(start, flags, &candidate) != 0)
        return 0;
    entry = bsd_malloc(sizeof(*entry), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!entry)
        return 0;
    entry->public.__r_i = entry;
    entry->manager = manager;
    entry->device = device;
    entry->registered_start = candidate;
    entry->registered_count = count;
    entry->start = candidate;
    entry->count = count;
    entry->flags = (flags | RF_ALLOCATED) &
        (RF_ALLOCATED | RF_ACTIVE | RF_SHAREABLE | RF_PREFETCHABLE |
        RF_UNMAPPED);
    entry->type = SYS_RES_MEMORY;
    entry->rid = -1;
    entry->allocated = 1;

    resource_guard_lock();
    for (;;) {
        int collision = 0;

        if (candidate > end || count > end - candidate + 1)
            break;
        requested_end = candidate + count - 1u;
        for (current = manager->rm_private; current;
             current = current->rman_next) {
            rman_res_t current_end = rman_region_end(current);

            if (candidate > current_end ||
                requested_end < current->start)
                continue;
            if ((entry->flags & current->flags & RF_SHAREABLE) != 0 &&
                candidate == current->start &&
                requested_end == current_end) {
                collision = 0;
                goto found;
            }
            if (current_end == RM_MAX_END ||
                rman_align_start(current_end + 1u, flags,
                &candidate) != 0) {
                collision = 1;
                candidate = RM_MAX_END;
                break;
            }
            collision = 1;
            break;
        }
        if (!collision)
            goto found;
    }
    resource_guard_unlock();
    bsd_free(entry, M_DEVBUF);
    return 0;

found:
    entry->registered_start = candidate;
    entry->start = candidate;
    entry->rman_next = manager->rm_private;
    manager->rm_private = entry;
    resource_guard_unlock();
    return &entry->public;
}

int
rman_adjust_resource(struct resource *resource, rman_res_t start,
    rman_res_t end)
{
    struct resource_i *entry = resource_entry(resource);
    struct resource_i *other;

    if (!entry || !entry->manager || start > end ||
        start < entry->manager->rm_start || end > entry->manager->rm_end ||
        (entry->flags & (RF_SHAREABLE | RF_ACTIVE)) != 0 ||
        end < entry->start || rman_region_end(entry) < start)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    if (entry->mappings || entry->map_inflight) {
        resource_guard_unlock();
        return BSD_RESOURCE_EBUSY;
    }
    for (other = entry->manager->rm_private; other;
         other = other->rman_next) {
        if (other == entry)
            continue;
        if (start <= rman_region_end(other) && end >= other->start) {
            resource_guard_unlock();
            return BSD_RESOURCE_EBUSY;
        }
    }
    entry->start = start;
    entry->count = end - start + 1u;
    entry->registered_start = start;
    entry->registered_count = entry->count;
    resource_guard_unlock();
    return 0;
}

int
rman_is_region_manager(const struct resource *resource,
    const struct rman *manager)
{
    const struct resource_i *entry = resource_entry(resource);

    return entry && entry->manager == manager;
}

uint32_t
rman_make_alignment_flags(uint32_t size)
{
    if (size == 0)
        return 0;
    return RF_ALIGNMENT_LOG2(bsd_flsl((long)size - 1));
}

int
rman_release_resource(struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    struct resource_i **cursor;

    if (!entry || !entry->manager)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    for (cursor = (struct resource_i **)&entry->manager->rm_private;
         *cursor && *cursor != entry; cursor = &(*cursor)->rman_next)
        ;
    if (*cursor != entry) {
        resource_guard_unlock();
        return BSD_RESOURCE_ENOENT;
    }
    *cursor = entry->rman_next;
    resource_guard_unlock();
    bsd_free(entry, M_DEVBUF);
    return 0;
}

struct rman *
bsd_resource_get_manager(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);

    return entry ? entry->manager : 0;
}

static int
resource_mapping_matches(const struct resource_mapping_i *entry,
    const struct resource_map *mapping)
{
    return entry->public.r_bustag == mapping->r_bustag &&
        entry->public.r_bushandle == mapping->r_bushandle &&
        entry->public.r_size == mapping->r_size &&
        entry->public.r_vaddr == mapping->r_vaddr;
}

static bus_space_tag_t
resource_default_tag(int type)
{
    if (type == SYS_RES_MEMORY)
        return bsd_bus_space_memory_tag();
    if (type == SYS_RES_IOPORT)
        return bsd_bus_space_io_tag();
    return 0;
}

static struct resource_i *
resource_find(device_t device, int type, int rid)
{
    struct resource_i *entry;

    for (entry = g_resources; entry; entry = entry->next) {
        if (entry->device == device && entry->type == type &&
            entry->rid == rid)
            return entry;
    }
    return 0;
}

int
bsd_device_add_resource(device_t device, int type, int rid,
    rman_res_t start, rman_res_t count, unsigned int flags,
    bus_space_tag_t tag)
{
    struct resource_i *entry;

    if (!device || rid < 0 || count == 0 ||
        start > UINT64_MAX - (count - 1))
        return BSD_RESOURCE_EINVAL;
    if ((type == SYS_RES_MEMORY || type == SYS_RES_IOPORT) && !tag)
        tag = resource_default_tag(type);
    if ((type == SYS_RES_MEMORY || type == SYS_RES_IOPORT) && !tag)
        return BSD_RESOURCE_EINVAL;

    entry = bsd_malloc(sizeof(*entry), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!entry)
        return BSD_RESOURCE_ENOMEM;
    entry->public.__r_i = entry;
    entry->public.r_bustag = tag;
    entry->device = device;
    entry->registered_start = start;
    entry->registered_count = count;
    entry->start = start;
    entry->count = count;
    entry->flags = flags &
        (RF_SHAREABLE | RF_PREFETCHABLE | RF_UNMAPPED);
    entry->type = type;
    entry->rid = rid;

    resource_guard_lock();
    if (resource_find(device, type, rid)) {
        resource_guard_unlock();
        bsd_free(entry, M_DEVBUF);
        return BSD_RESOURCE_EEXIST;
    }
    entry->next = g_resources;
    g_resources = entry;
    resource_guard_unlock();
    return 0;
}

int
bsd_resource_set_interrupt_source(device_t device, int rid,
    const bsd_resource_interrupt_source_ops_t *operations)
{
    struct resource_i *entry;

    if (!device || rid < 0 || !operations || !operations->enable ||
        !operations->disable)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    entry = resource_find(device, SYS_RES_IRQ, rid);
    if (!entry || entry->allocated || entry->interrupt_enabled) {
        resource_guard_unlock();
        return entry ? BSD_RESOURCE_EBUSY : BSD_RESOURCE_ENOENT;
    }
    entry->interrupt_source = *operations;
    entry->interrupt_flags = operations->interrupt_flags;
    resource_guard_unlock();
    return 0;
}

int
bsd_resource_set_interrupt_flags(device_t device, int rid,
    uint32_t interrupt_flags)
{
    struct resource_i *entry;

    if (!device || rid < 0)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    entry = resource_find(device, SYS_RES_IRQ, rid);
    if (!entry || entry->allocated) {
        resource_guard_unlock();
        return entry ? BSD_RESOURCE_EBUSY : BSD_RESOURCE_ENOENT;
    }
    entry->interrupt_flags = interrupt_flags;
    resource_guard_unlock();
    return 0;
}

uint32_t
bsd_resource_get_interrupt_flags(const struct resource *resource)
{
    const struct resource_i *entry = resource_entry(resource);

    return entry && entry->type == SYS_RES_IRQ ?
        entry->interrupt_flags : 0;
}

int
bsd_resource_is_allocated(device_t device, int type, int rid)
{
    struct resource_i *entry;
    int allocated;

    resource_guard_lock();
    entry = resource_find(device, type, rid);
    allocated = entry && entry->allocated;
    resource_guard_unlock();
    return allocated;
}

int
bsd_resource_enable_interrupt(struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    int result;

    if (!entry || entry->type != SYS_RES_IRQ || !entry->allocated ||
        (entry->flags & RF_ACTIVE) == 0)
        return BSD_RESOURCE_EINVAL;
    if (!entry->interrupt_source.enable)
        return 0;
    resource_guard_lock();
    if (entry->interrupt_enabled == 1) {
        resource_guard_unlock();
        return 0;
    }
    if (entry->interrupt_enabled != 0) {
        resource_guard_unlock();
        return BSD_RESOURCE_EBUSY;
    }
    entry->interrupt_enabled = 2;
    resource_guard_unlock();
    result = entry->interrupt_source.enable(
        entry->interrupt_source.context);
    resource_guard_lock();
    entry->interrupt_enabled = result == 0 ? 1 : 0;
    resource_guard_unlock();
    return result;
}

int
bsd_resource_disable_interrupt(struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    int result;

    if (!entry || entry->type != SYS_RES_IRQ)
        return BSD_RESOURCE_EINVAL;
    if (!entry->interrupt_source.disable)
        return 0;
    resource_guard_lock();
    if (entry->interrupt_enabled == 0) {
        resource_guard_unlock();
        return 0;
    }
    if (entry->interrupt_enabled != 1) {
        resource_guard_unlock();
        return BSD_RESOURCE_EBUSY;
    }
    entry->interrupt_enabled = 2;
    resource_guard_unlock();
    result = entry->interrupt_source.disable(
        entry->interrupt_source.context);
    resource_guard_lock();
    entry->interrupt_enabled = result == 0 ? 0 : 1;
    resource_guard_unlock();
    return result;
}

int
rman_activate_resource(struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    int result;

    if (!entry)
        return BSD_RESOURCE_EINVAL;
    if ((entry->flags & RF_ACTIVE) != 0)
        return 0;
    if ((entry->type == SYS_RES_MEMORY ||
         entry->type == SYS_RES_IOPORT) &&
        (entry->flags & RF_UNMAPPED) == 0) {
        result = bus_space_map(resource->r_bustag, entry->start,
            entry->count, (entry->flags & RF_PREFETCHABLE) ?
            BUS_SPACE_MAP_PREFETCHABLE : 0, &resource->r_bushandle);
        if (result != 0)
            return result;
        entry->mapped = 1;
        resource->r_virtual = bus_space_vaddr(
            resource->r_bustag, resource->r_bushandle);
    } else {
        resource->r_bushandle = (bus_space_handle_t)entry->start;
        resource->r_virtual = bus_space_vaddr(
            resource->r_bustag, resource->r_bushandle);
    }
    entry->flags |= RF_ACTIVE;
    return 0;
}

int
rman_deactivate_resource(struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);

    if (!entry)
        return BSD_RESOURCE_EINVAL;
    if ((entry->flags & RF_ACTIVE) == 0)
        return 0;
    if (entry->mapped) {
        bus_space_unmap(resource->r_bustag, resource->r_bushandle,
            entry->count);
        entry->mapped = 0;
    }
    resource->r_bushandle = 0;
    resource->r_virtual = 0;
    entry->flags &= ~RF_ACTIVE;
    return 0;
}

struct resource *
bus_alloc_resource(device_t device, int type, int rid, rman_res_t start,
    rman_res_t end, rman_res_t count, unsigned int flags)
{
    struct resource_i *entry;
    if (!device)
        return 0;
    resource_guard_lock();
    entry = resource_find(device, type, rid);
    if (!entry) {
        resource_guard_unlock();
#if !defined(BSD_BRIDGE_HOST_TEST) && defined(EDGEOS_BSD_BRIDGE)
        return bsd_bus_alloc_resource_from_parent(device, type, rid,
            start, end, count, flags);
#endif
        return 0;
    }
    if (entry->allocated ||
        (!RMAN_IS_DEFAULT_RANGE(start, end) &&
         (entry->registered_start < start ||
          entry->registered_start + entry->registered_count - 1 > end)) ||
        (count > 1 && count > entry->registered_count)) {
        resource_guard_unlock();
        return 0;
    }
    entry->start = entry->registered_start;
    entry->count = entry->registered_count;
    entry->allocated = 1;
    entry->flags |= RF_ALLOCATED | (flags &
        (RF_SHAREABLE | RF_PREFETCHABLE | RF_UNMAPPED));
    resource_guard_unlock();
    if ((flags & RF_ACTIVE) != 0 &&
        bus_activate_resource(device, &entry->public) != 0) {
        resource_guard_lock();
        entry->allocated = 0;
        entry->flags &= ~RF_ALLOCATED;
        resource_guard_unlock();
        return 0;
    }
    return &entry->public;
}

int
bus_alloc_resources(device_t device, struct resource_spec *specifications,
    struct resource **resources)
{
    int index;

    if (!device || !specifications || !resources)
        return BSD_RESOURCE_EINVAL;
    for (index = 0; specifications[index].type != -1; ++index)
        resources[index] = 0;
    for (index = 0; specifications[index].type != -1; ++index) {
        resources[index] = bus_alloc_resource(
            device, specifications[index].type, specifications[index].rid,
            0, RM_MAX_END, 1, (unsigned int)specifications[index].flags);
        if (!resources[index] &&
            (specifications[index].flags & RF_OPTIONAL) == 0) {
            bus_release_resources(device, specifications, resources);
            return BSD_RESOURCE_ENXIO;
        }
    }
    return 0;
}

void
bus_release_resources(device_t device,
    const struct resource_spec *specifications, struct resource **resources)
{
    int index;

    if (!device || !specifications || !resources)
        return;
    for (index = 0; specifications[index].type != -1; ++index) {
        if (resources[index]) {
            (void)bus_release_resource(device, resources[index]);
            resources[index] = 0;
        }
    }
}

int
bus_adjust_resource(device_t device, struct resource *resource,
    rman_res_t start, rman_res_t end)
{
    struct resource_i *entry = resource_entry(resource);
    rman_res_t registered_end;

    if (!entry || entry->device != device || !entry->allocated ||
        end < start || end - start == UINT64_MAX)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    registered_end =
        entry->registered_start + entry->registered_count - 1;
    if (start < entry->registered_start || end > registered_end) {
        resource_guard_unlock();
        return BSD_RESOURCE_EINVAL;
    }
    if ((entry->flags & RF_ACTIVE) != 0 || entry->mapped ||
        entry->map_inflight != 0 || entry->interrupt_enabled != 0 ||
        entry->mappings ||
        __atomic_load_n(&entry->irq_cookie, __ATOMIC_ACQUIRE)) {
        resource_guard_unlock();
        return BSD_RESOURCE_EBUSY;
    }
    entry->start = start;
    entry->count = end - start + 1;
    resource_guard_unlock();
    return 0;
}

int
bus_adjust_resource_old(device_t device, int type,
    struct resource *resource, rman_res_t start, rman_res_t end)
{
    if (rman_get_type(resource) != type)
        return BSD_RESOURCE_EINVAL;
    return bus_adjust_resource(device, resource, start, end);
}

int
bus_activate_resource(device_t device, struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    int result;

    if (!entry || entry->device != device || !entry->allocated)
        return BSD_RESOURCE_EINVAL;
    result = rman_activate_resource(resource);
#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
    if (result == 0 && resource_uses_intrng(resource)) {
        result = intr_activate_irq(device, resource);
        if (result != 0)
            (void)rman_deactivate_resource(resource);
    }
#endif
    return result;
}

int
bus_activate_resource_old(device_t device, int type, int rid,
    struct resource *resource)
{
    (void)type;
    (void)rid;
    return bus_activate_resource(device, resource);
}

int
bus_deactivate_resource(device_t device, struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    int result;

    if (!entry || entry->device != device || !entry->allocated)
        return BSD_RESOURCE_EINVAL;
#if !defined(BSD_BRIDGE_HOST_TEST) || \
    defined(BSD_BRIDGE_INTRNG_HOST_TEST)
    if (resource_uses_intrng(resource)) {
        result = intr_deactivate_irq(device, resource);
        if (result != 0)
            return result;
    }
#else
    (void)result;
#endif
    return rman_deactivate_resource(resource);
}

int
bus_deactivate_resource_old(device_t device, int type, int rid,
    struct resource *resource)
{
    (void)type;
    (void)rid;
    return bus_deactivate_resource(device, resource);
}

void
resource_init_map_request_impl(struct resource_map_request *request,
    size_t size)
{
    if (!request || size < sizeof(request->size))
        return;
    bsd_memset(request, 0, size);
    request->size = size;
    request->memattr = VM_MEMATTR_DEVICE;
}

int
resource_validate_map_request(struct resource *resource,
    struct resource_map_request *input, struct resource_map_request *output,
    rman_res_t *start, rman_res_t *length)
{
    struct resource_i *entry = resource_entry(resource);
    size_t copy_size;
    rman_res_t requested_length;

    if (!entry || !output || !start || !length ||
        output->size != sizeof(*output))
        return BSD_RESOURCE_EINVAL;
    if (input) {
        if (input->size < sizeof(input->size))
            return BSD_RESOURCE_EINVAL;
        copy_size = input->size < output->size ?
            input->size : output->size;
        bsd_memcpy(output, input, copy_size);
    }
    if (output->offset >= entry->count)
        return BSD_RESOURCE_EINVAL;
    requested_length = output->length != 0 ?
        output->length : entry->count;
    if (requested_length == 0 ||
        requested_length > entry->count - output->offset)
        return BSD_RESOURCE_EINVAL;
    if (entry->start > UINT64_MAX - output->offset)
        return BSD_RESOURCE_EINVAL;
    *start = entry->start + output->offset;
    *length = requested_length;
    return 0;
}

int
bus_map_resource(device_t device, struct resource *resource,
    struct resource_map_request *request, struct resource_map *mapping)
{
    struct resource_i *entry = resource_entry(resource);
    struct resource_mapping_i *record;
    struct resource_map_request validated;
    rman_res_t start;
    rman_res_t length;
    int flags;
    int result;

    if (!entry || entry->device != device || !mapping ||
        (entry->type != SYS_RES_MEMORY && entry->type != SYS_RES_IOPORT))
        return BSD_RESOURCE_EINVAL;
    resource_init_map_request_impl(&validated, sizeof(validated));
    result = resource_validate_map_request(resource, request, &validated,
        &start, &length);
    if (result != 0)
        return result;
    if (length > (rman_res_t)(bus_size_t)-1)
        return BSD_RESOURCE_EINVAL;

    record = bsd_malloc(sizeof(*record), M_DEVBUF, M_WAITOK | M_ZERO);
    if (!record)
        return BSD_RESOURCE_ENOMEM;

    resource_guard_lock();
    if (!entry->allocated || (entry->flags & RF_ACTIVE) == 0) {
        resource_guard_unlock();
        bsd_free(record, M_DEVBUF);
        return BSD_RESOURCE_EINVAL;
    }
    entry->map_inflight++;
    resource_guard_unlock();

    flags = (entry->flags & RF_PREFETCHABLE) ?
        BUS_SPACE_MAP_PREFETCHABLE : 0;
    result = bsd_bus_space_map_attr(resource->r_bustag, start,
        (bus_size_t)length, flags, validated.memattr,
        &record->public.r_bushandle);
    if (result != 0) {
        resource_guard_lock();
        entry->map_inflight--;
        resource_guard_unlock();
        bsd_free(record, M_DEVBUF);
        return result;
    }
    record->public.r_bustag = resource->r_bustag;
    record->public.r_size = (bus_size_t)length;
    record->public.r_vaddr = bus_space_vaddr(record->public.r_bustag,
        record->public.r_bushandle);

    resource_guard_lock();
    entry->map_inflight--;
    if (!entry->allocated || (entry->flags & RF_ACTIVE) == 0) {
        resource_guard_unlock();
        bus_space_unmap(record->public.r_bustag,
            record->public.r_bushandle, record->public.r_size);
        bsd_free(record, M_DEVBUF);
        return BSD_RESOURCE_EBUSY;
    }
    record->next = entry->mappings;
    entry->mappings = record;
    *mapping = record->public;
    resource_guard_unlock();
    return 0;
}

int
bus_map_resource_old(device_t device, int type, struct resource *resource,
    struct resource_map_request *request, struct resource_map *mapping)
{
    if (rman_get_type(resource) != type)
        return BSD_RESOURCE_EINVAL;
    return bus_map_resource(device, resource, request, mapping);
}

int
bus_unmap_resource(device_t device, struct resource *resource,
    struct resource_map *mapping)
{
    struct resource_i *entry = resource_entry(resource);
    struct resource_mapping_i **cursor;
    struct resource_mapping_i *removed = 0;

    if (!entry || entry->device != device || !mapping)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    for (cursor = &entry->mappings; *cursor; cursor = &(*cursor)->next) {
        if (resource_mapping_matches(*cursor, mapping)) {
            removed = *cursor;
            *cursor = removed->next;
            break;
        }
    }
    resource_guard_unlock();
    if (!removed)
        return BSD_RESOURCE_EINVAL;
    bus_space_unmap(removed->public.r_bustag,
        removed->public.r_bushandle, removed->public.r_size);
    bsd_memset(mapping, 0, sizeof(*mapping));
    bsd_free(removed, M_DEVBUF);
    return 0;
}

int
bus_unmap_resource_old(device_t device, int type,
    struct resource *resource, struct resource_map *mapping)
{
    if (rman_get_type(resource) != type)
        return BSD_RESOURCE_EINVAL;
    return bus_unmap_resource(device, resource, mapping);
}

int
bus_release_resource(device_t device, struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    if (!entry || entry->device != device || !entry->allocated)
        return BSD_RESOURCE_EINVAL;
#if !defined(BSD_BRIDGE_HOST_TEST) && defined(EDGEOS_BSD_BRIDGE)
    if (entry->manager)
        return bsd_bus_release_resource_to_parent(device, resource);
#endif
    resource_guard_lock();
    if (entry->mappings || entry->map_inflight ||
        entry->interrupt_enabled ||
        __atomic_load_n(&entry->irq_cookie, __ATOMIC_ACQUIRE)) {
        resource_guard_unlock();
        return BSD_RESOURCE_EBUSY;
    }
    resource_guard_unlock();
    if (bus_deactivate_resource(device, resource) != 0)
        return BSD_RESOURCE_EBUSY;
    resource_guard_lock();
    entry->allocated = 0;
    entry->start = entry->registered_start;
    entry->count = entry->registered_count;
    entry->flags &= ~RF_ALLOCATED;
    resource_guard_unlock();
    return 0;
}

int
bus_release_resource_old(device_t device, int type, int rid,
    struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);

    if (rman_get_type(resource) != type ||
        ((!entry || !entry->manager) && rman_get_rid(resource) != rid))
        return BSD_RESOURCE_EINVAL;
    return bus_release_resource(device, resource);
}

int
bus_free_resource(device_t device, int type, struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);

    if (!entry || entry->type != type)
        return BSD_RESOURCE_EINVAL;
    return bus_release_resource(device, resource);
}

int
bus_set_resource(device_t device, int type, int rid, rman_res_t start,
    rman_res_t count)
{
    struct resource_i *entry;

    if (!device || rid < 0 || count == 0 ||
        start > UINT64_MAX - (count - 1))
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    entry = resource_find(device, type, rid);
    if (entry) {
        if (entry->allocated || entry->mapped ||
            entry->map_inflight || entry->interrupt_enabled ||
            entry->mappings ||
            __atomic_load_n(&entry->irq_cookie, __ATOMIC_ACQUIRE)) {
            resource_guard_unlock();
            return BSD_RESOURCE_EBUSY;
        }
        entry->registered_start = start;
        entry->registered_count = count;
        entry->start = start;
        entry->count = count;
        resource_guard_unlock();
        return 0;
    }
    resource_guard_unlock();
    return bsd_device_add_resource(device, type, rid, start, count, 0, 0);
}

int
bus_get_resource(device_t device, int type, int rid, rman_res_t *start,
    rman_res_t *count)
{
    struct resource_i *entry;

    if (!device)
        return BSD_RESOURCE_EINVAL;
    resource_guard_lock();
    entry = resource_find(device, type, rid);
    if (entry) {
        if (start)
            *start = entry->registered_start;
        if (count)
            *count = entry->registered_count;
    }
    resource_guard_unlock();
    return entry ? 0 : BSD_RESOURCE_ENOENT;
}

rman_res_t
bus_get_resource_start(device_t device, int type, int rid)
{
    rman_res_t start = 0;
    rman_res_t count;

    (void)bus_get_resource(device, type, rid, &start, &count);
    return start;
}

rman_res_t
bus_get_resource_count(device_t device, int type, int rid)
{
    rman_res_t start;
    rman_res_t count = 0;

    (void)bus_get_resource(device, type, rid, &start, &count);
    return count;
}

void
bus_delete_resource(device_t device, int type, int rid)
{
    struct resource_i **cursor;
    struct resource_i *removed = 0;

    resource_guard_lock();
    for (cursor = &g_resources; *cursor; cursor = &(*cursor)->next) {
        if ((*cursor)->device == device && (*cursor)->type == type &&
            (*cursor)->rid == rid && !(*cursor)->allocated) {
            removed = *cursor;
            *cursor = removed->next;
            break;
        }
    }
    resource_guard_unlock();
    if (removed)
        bsd_free(removed, M_DEVBUF);
}

void
bsd_resource_release_device(device_t device)
{
    struct resource_i **cursor;

    if (!device)
        return;
    for (;;) {
        struct resource_i *removed = 0;

        resource_guard_lock();
        for (cursor = &g_resources; *cursor; cursor = &(*cursor)->next) {
            if ((*cursor)->device == device) {
                removed = *cursor;
                *cursor = removed->next;
                break;
            }
        }
        resource_guard_unlock();
        if (!removed)
            return;
        (void)bsd_resource_disable_interrupt(&removed->public);
        while (removed->mappings) {
            struct resource_mapping_i *mapping = removed->mappings;

            removed->mappings = mapping->next;
            bus_space_unmap(mapping->public.r_bustag,
                mapping->public.r_bushandle, mapping->public.r_size);
            bsd_free(mapping, M_DEVBUF);
        }
        (void)rman_deactivate_resource(&removed->public);
        bsd_free(removed, M_DEVBUF);
    }
}

rman_res_t
rman_get_start(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? entry->start : 0;
}

rman_res_t
rman_get_end(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? entry->start + entry->count - 1 : 0;
}

rman_res_t
rman_get_size(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? entry->count : 0;
}

unsigned int
rman_get_flags(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? entry->flags : 0;
}

int
rman_get_rid(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? entry->rid : -1;
}

int
rman_get_type(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? entry->type : -1;
}

device_t
rman_get_device(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? entry->device : 0;
}

void *
rman_get_virtual(const struct resource *resource)
{
    return resource && (rman_get_flags(resource) & RF_ACTIVE) ?
        resource->r_virtual : 0;
}

bus_space_tag_t
rman_get_bustag(const struct resource *resource)
{
    return resource ? resource->r_bustag : 0;
}

bus_space_handle_t
rman_get_bushandle(const struct resource *resource)
{
    return resource ? resource->r_bushandle : 0;
}

void *
rman_get_irq_cookie(const struct resource *resource)
{
    struct resource_i *entry = resource_entry(resource);
    return entry ? __atomic_load_n(&entry->irq_cookie,
        __ATOMIC_ACQUIRE) : 0;
}

int
rman_claim_irq_cookie(struct resource *resource, void *expected,
    void *replacement)
{
    struct resource_i *entry = resource_entry(resource);

    if (!entry)
        return 0;
    return __atomic_compare_exchange_n(&entry->irq_cookie, &expected,
        replacement, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

void
rman_set_device(struct resource *resource, device_t device)
{
    struct resource_i *entry = resource_entry(resource);
    if (entry)
        entry->device = device;
}

void
rman_set_rid(struct resource *resource, int rid)
{
    struct resource_i *entry = resource_entry(resource);
    if (entry)
        entry->rid = rid;
}

void
rman_set_type(struct resource *resource, int type)
{
    struct resource_i *entry = resource_entry(resource);
    if (entry)
        entry->type = type;
}

void
rman_set_bustag(struct resource *resource, bus_space_tag_t tag)
{
    if (resource)
        resource->r_bustag = tag;
}

void
rman_set_bushandle(struct resource *resource, bus_space_handle_t handle)
{
    if (resource)
        resource->r_bushandle = handle;
}

void
rman_set_virtual(struct resource *resource, void *virtual_address)
{
    if (resource)
        resource->r_virtual = virtual_address;
}

void
rman_set_mapping(struct resource *resource, struct resource_map *mapping)
{
    if (!resource || !mapping ||
        rman_get_size(resource) != mapping->r_size)
        return;
    rman_set_bustag(resource, mapping->r_bustag);
    rman_set_bushandle(resource, mapping->r_bushandle);
    rman_set_virtual(resource, mapping->r_vaddr);
}

void
rman_get_mapping(const struct resource *resource,
    struct resource_map *mapping)
{
    if (!mapping)
        return;
    if (!resource) {
        bsd_memset(mapping, 0, sizeof(*mapping));
        return;
    }
    mapping->r_bustag = rman_get_bustag(resource);
    mapping->r_bushandle = rman_get_bushandle(resource);
    mapping->r_size = (bus_size_t)rman_get_size(resource);
    mapping->r_vaddr = rman_get_virtual(resource);
}

void
rman_set_irq_cookie(struct resource *resource, void *cookie)
{
    struct resource_i *entry = resource_entry(resource);
    if (entry)
        __atomic_store_n(&entry->irq_cookie, cookie, __ATOMIC_RELEASE);
}
