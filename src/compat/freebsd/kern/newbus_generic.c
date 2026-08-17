/* SPDX-License-Identifier: MPL-2.0 */
/* Shared default newbus methods for imported FreeBSD drivers. */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpuset.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <machine/resource.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/kernel.h"

#define BSD_NEWBUS_ENOENT 2
#define BSD_NEWBUS_ENOMEM 12
#define BSD_NEWBUS_EBUSY 16
#define BSD_NEWBUS_EINVAL 22
#define BSD_NEWBUS_ENODEV 19

int bsd_device_add_resource(device_t device, int type, int rid,
    rman_res_t start, rman_res_t count, unsigned int flags,
    bus_space_tag_t tag);

static int
device_has_methods(device_t device)
{
    return device && ((kobj_t)device)->ops;
}

bool
bsd_device_implements_method(device_t device,
    struct kobjop_desc *descriptor)
{
    kobj_method_t **cache_entry;
    kobj_method_t *method;

    if (!device_has_methods(device) || !descriptor)
        return 0;
    cache_entry = &((kobj_t)device)->ops->cache[
        descriptor->id & (KOBJ_CACHE_SIZE - 1)];
    method = *cache_entry;
    if (method->desc != descriptor) {
        method = kobj_lookup_method(
            ((kobj_t)device)->ops->cls, cache_entry, descriptor);
    }
    return method && method->func != descriptor->deflt.func;
}

struct resource *
bsd_bus_alloc_resource_from_parent(device_t child, int type, int rid,
    uint64_t start, uint64_t end, uint64_t count, unsigned int flags)
{
    device_t parent = device_get_parent(child);

    if (!parent ||
        !bsd_device_implements_method(parent, &bus_alloc_resource_desc))
        return 0;
    return BUS_ALLOC_RESOURCE(parent, child, type, rid, start, end,
        count, flags);
}

int
bsd_bus_release_resource_to_parent(device_t child,
    struct resource *resource)
{
    device_t parent = device_get_parent(child);

    if (!parent ||
        !bsd_device_implements_method(parent, &bus_release_resource_desc))
        return BSD_NEWBUS_ENODEV;
    return BUS_RELEASE_RESOURCE(parent, child, resource);
}

int
bsd_bus_setup_intr_from_parent(device_t child, struct resource *resource,
    int flags, driver_filter_t *filter, driver_intr_t *handler,
    void *argument, void **cookie)
{
    device_t parent = device_get_parent(child);

    if (!parent ||
        !bsd_device_implements_method(parent, &bus_setup_intr_desc))
        return BSD_NEWBUS_ENODEV;
    return BUS_SETUP_INTR(parent, child, resource, flags, filter, handler,
        argument, cookie);
}

int
bsd_bus_teardown_intr_to_parent(device_t child,
    struct resource *resource, void *cookie)
{
    device_t parent = device_get_parent(child);

    if (!parent ||
        !bsd_device_implements_method(parent, &bus_teardown_intr_desc))
        return BSD_NEWBUS_ENODEV;
    return BUS_TEARDOWN_INTR(parent, child, resource, cookie);
}

int
bus_generic_print_child(device_t bus, device_t child)
{
    const char *description = device_get_desc(child);

    (void)bus;
    if (device_is_quiet(child))
        return 0;
    return device_printf(child, "%s\n",
        description ? description : "attached");
}

int
bus_generic_read_ivar(device_t bus, device_t child, int index,
    uintptr_t *result)
{
    (void)bus;
    (void)child;
    (void)index;
    (void)result;
    return BSD_NEWBUS_ENOENT;
}

int
bus_generic_write_ivar(device_t bus, device_t child, int index,
    uintptr_t value)
{
    (void)bus;
    (void)child;
    (void)index;
    (void)value;
    return BSD_NEWBUS_ENOENT;
}

int
bus_print_child_header(device_t bus, device_t child)
{
    const char *description;

    (void)bus;
    if (!child)
        return 0;
    description = device_get_desc(child);
    if (description)
        return device_printf(child, "<%s>", description);
    return bsd_printf("%s", device_get_nameunit(child));
}

int
bus_print_child_footer(device_t bus, device_t child)
{
    (void)child;
    return bus ? bsd_printf(" on %s\n", device_get_nameunit(bus)) : 0;
}

int
bus_print_child_domain(device_t bus, device_t child)
{
    int domain;

    if (!device_has_methods(bus) ||
        BUS_GET_DOMAIN(bus, child, &domain) != 0)
        return 0;
    return bsd_printf(" numa-domain %d", domain);
}

void
bus_attach_children(device_t bus)
{
    device_t *children;
    int count;

    if (!bus || device_get_children(bus, &children, &count) != 0)
        return;
    for (int index = 0; index < count; ++index) {
        if (device_get_state(children[index]) != DS_ATTACHED)
            (void)device_probe_and_attach(children[index]);
    }
    if (children)
        bsd_free(children, M_TEMP);
}

void
bus_identify_children(device_t bus)
{
    bsd_device_identify_children(bus);
}

void
bus_delayed_attach_children(device_t bus)
{
    if (bus)
        config_intrhook_oneshot((ich_func_t)bus_attach_children, bus);
}

int
bus_generic_attach(device_t bus)
{
    bus_attach_children(bus);
    return 0;
}

void
bus_enumerate_hinted_children(device_t bus)
{
    const char *bus_names[2];

    if (!bus || !device_has_methods(bus))
        return;
    bus_names[0] = device_get_nameunit(bus);
    bus_names[1] = device_get_name(bus);
    for (unsigned int name_index = 0; name_index < 2; ++name_index) {
        const char *child_name;
        int child_unit;
        int anchor = 0;

        if (!bus_names[name_index] ||
            (name_index == 1 && bus_names[0] &&
             bsd_strcmp(bus_names[0], bus_names[1]) == 0))
            continue;
        while (resource_find_match(&anchor, &child_name, &child_unit,
            "at", bus_names[name_index]) == 0)
            BUS_HINTED_CHILD(bus, child_name, child_unit);
    }
}

void
bus_generic_driver_added(device_t bus, driver_t *driver)
{
    device_t *children;
    int count;

    if (!bus || !driver)
        return;
    if (driver->ops)
        DEVICE_IDENTIFY(driver, bus);
    if (device_get_children(bus, &children, &count) != 0)
        return;
    for (int index = 0; index < count; ++index) {
        if (device_get_state(children[index]) == DS_NOTPRESENT)
            (void)device_probe_and_attach(children[index]);
    }
    if (children)
        bsd_free(children, M_TEMP);
}

void
bus_generic_new_pass(device_t bus)
{
    device_t *children;
    int count;

    if (!bus || device_get_children(bus, &children, &count) != 0)
        return;
    for (int index = 0; index < count; ++index) {
        device_t child = children[index];

        if (device_is_attached(child) && device_has_methods(child))
            BUS_NEW_PASS(child);
        else if (device_get_state(child) == DS_NOTPRESENT)
            (void)device_probe_and_attach(child);
    }
    if (children)
        bsd_free(children, M_TEMP);
}

int
bus_generic_translate_resource(device_t bus, int type, rman_res_t start,
    rman_res_t *translated)
{
    device_t parent;

    if (!bus || !translated)
        return BSD_NEWBUS_EINVAL;
    parent = device_get_parent(bus);
    if (device_has_methods(parent))
        return BUS_TRANSLATE_RESOURCE(parent, type, start, translated);
    *translated = start;
    return 0;
}

int
bus_generic_setup_intr(device_t bus, device_t child,
    struct resource *interrupt, int flags, driver_filter_t *filter,
    driver_intr_t *handler, void *argument, void **cookie)
{
    device_t parent = device_get_parent(bus);

    if (bsd_device_implements_method(parent, &bus_setup_intr_desc)) {
        return BUS_SETUP_INTR(parent, child, interrupt, flags,
            filter, handler, argument, cookie);
    }
#ifdef BSD_BRIDGE_HOST_TEST
    return bus_setup_intr(
#else
    return bsd_interrupt_setup_direct(
#endif
        child, interrupt, flags, filter, handler, argument, cookie);
}

struct resource *
bus_generic_alloc_resource(device_t bus, device_t child, int type,
    int rid, rman_res_t start, rman_res_t end, rman_res_t count,
    u_int flags)
{
    device_t parent = device_get_parent(bus);

    if (bsd_device_implements_method(parent, &bus_alloc_resource_desc)) {
        return BUS_ALLOC_RESOURCE(parent, child, type, rid,
            start, end, count, flags);
    }
    return bus_alloc_resource(
        child, type, rid, start, end, count, flags);
}

int
bus_generic_release_resource(device_t bus, device_t child,
    struct resource *resource)
{
    device_t parent = device_get_parent(bus);

    if (bsd_device_implements_method(parent, &bus_release_resource_desc))
        return BUS_RELEASE_RESOURCE(parent, child, resource);
    return bus_release_resource(child, resource);
}

int
bus_generic_activate_resource(device_t bus, device_t child,
    struct resource *resource)
{
    device_t parent = device_get_parent(bus);

    if (bsd_device_implements_method(parent, &bus_activate_resource_desc))
        return BUS_ACTIVATE_RESOURCE(parent, child, resource);
    return bus_activate_resource(child, resource);
}

int
bus_generic_deactivate_resource(device_t bus, device_t child,
    struct resource *resource)
{
    device_t parent = device_get_parent(bus);

    if (bsd_device_implements_method(parent, &bus_deactivate_resource_desc))
        return BUS_DEACTIVATE_RESOURCE(parent, child, resource);
    return bus_deactivate_resource(child, resource);
}

int
bus_generic_adjust_resource(device_t bus, device_t child,
    struct resource *resource, rman_res_t start, rman_res_t end)
{
    device_t parent = device_get_parent(bus);

    if (bsd_device_implements_method(parent, &bus_adjust_resource_desc)) {
        return BUS_ADJUST_RESOURCE(
            parent, child, resource, start, end);
    }
    return bus_adjust_resource(child, resource, start, end);
}

int
bus_generic_map_resource(device_t bus, device_t child,
    struct resource *resource, struct resource_map_request *request,
    struct resource_map *mapping)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_MAP_RESOURCE(parent, child, resource, request, mapping);
    return bus_map_resource(child, resource, request, mapping);
}

int
bus_generic_unmap_resource(device_t bus, device_t child,
    struct resource *resource, struct resource_map *mapping)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_UNMAP_RESOURCE(parent, child, resource, mapping);
    return bus_unmap_resource(child, resource, mapping);
}

int
bus_generic_bind_intr(device_t bus, device_t child,
    struct resource *resource, int cpu)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_BIND_INTR(parent, child, resource, cpu);
    return BSD_NEWBUS_EINVAL;
}

int
bus_bind_intr(device_t device, struct resource *resource, int cpu)
{
    device_t parent;

    if (!device || !resource || cpu < 0)
        return BSD_NEWBUS_EINVAL;
    parent = device_get_parent(device);
    if (!device_has_methods(parent))
        return BSD_NEWBUS_EINVAL;
    return BUS_BIND_INTR(parent, device, resource, cpu);
}

int
intr_bind_irq(device_t device, struct resource *resource, int cpu)
{
    return bus_bind_intr(device, resource, cpu);
}

int
bus_describe_intr(device_t device, struct resource *resource,
    void *cookie, const char *format, ...)
{
    char description[64];
    device_t parent;
    va_list arguments;

    if (!device || !resource || !format)
        return BSD_NEWBUS_EINVAL;
    parent = device_get_parent(device);
    if (!device_has_methods(parent))
        return 0;
    va_start(arguments, format);
    (void)bsd_vsnprintf(
        description, sizeof(description), format, arguments);
    va_end(arguments);
    return BUS_DESCRIBE_INTR(
        parent, device, resource, cookie, description);
}

int
bus_get_cpus(device_t device, enum cpu_sets operation, size_t set_size,
    cpuset_t *set)
{
    device_t parent;
    int error;

    if (!device || !set || set_size < sizeof(*set) ||
        (operation != LOCAL_CPUS && operation != INTR_CPUS))
        return BSD_NEWBUS_EINVAL;
    parent = device_get_parent(device);
    if (device_has_methods(parent)) {
        error = BUS_GET_CPUS(
            parent, device, operation, set_size, set);
        if (error == 0 && !CPU_EMPTY(set))
            return 0;
    }
    CPU_COPY(&all_cpus, set);
    return CPU_EMPTY(set) ? BSD_NEWBUS_EINVAL : 0;
}

int
bus_generic_config_intr(device_t bus, int interrupt,
    enum intr_trigger trigger, enum intr_polarity polarity)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_CONFIG_INTR(parent, interrupt, trigger, polarity);
    return BSD_NEWBUS_EINVAL;
}

int
bus_generic_describe_intr(device_t bus, device_t child,
    struct resource *resource, void *cookie, const char *description)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent)) {
        return BUS_DESCRIBE_INTR(parent, child, resource, cookie,
            description);
    }
    return 0;
}

int
bus_generic_get_cpus(device_t bus, device_t child, enum cpu_sets operation,
    size_t set_size, struct _cpuset *set)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_GET_CPUS(parent, child, operation, set_size, set);
    return BSD_NEWBUS_EINVAL;
}

bus_dma_tag_t
bus_generic_get_dma_tag(device_t bus, device_t child)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_GET_DMA_TAG(parent, child);
    return bus_get_dma_tag(child);
}

bus_space_tag_t
bus_generic_get_bus_tag(device_t bus, device_t child)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_GET_BUS_TAG(parent, child);
    (void)child;
    return 0;
}

int
bus_generic_child_present(device_t bus, device_t child)
{
    device_t parent = device_get_parent(bus);

    if (device_has_methods(parent))
        return BUS_CHILD_PRESENT(parent, bus);
    return device_is_alive(child) ? -1 : 0;
}

int
bus_generic_get_domain(device_t bus, device_t child, int *domain)
{
    device_t parent = device_get_parent(bus);

    if (!domain)
        return BSD_NEWBUS_EINVAL;
    if (device_has_methods(parent))
        return BUS_GET_DOMAIN(parent, child, domain);
    return BSD_NEWBUS_ENOENT;
}

ssize_t
bsd_bus_get_property(device_t parent, device_t child,
    const char *name, void *value, size_t size, device_property_type_t type)
{
    if (device_has_methods(parent))
        return BUS_GET_PROPERTY(parent, child, name, value, size, type);
    return -1;
}

ssize_t
bus_generic_get_property(device_t bus, device_t child,
    const char *name, void *value, size_t size, device_property_type_t type)
{
    device_t parent = device_get_parent(bus);

    return bsd_bus_get_property(parent, child, name, value, size, type);
}

void
resource_list_init(struct resource_list *list)
{
    if (list)
        STAILQ_INIT(list);
}

struct resource_list_entry *
resource_list_find(struct resource_list *list, int type, int rid)
{
    struct resource_list_entry *entry;

    if (!list)
        return 0;
    STAILQ_FOREACH(entry, list, link) {
        if (entry->type == type && entry->rid == rid)
            return entry;
    }
    return 0;
}

struct resource_list_entry *
resource_list_add(struct resource_list *list, int type, int rid,
    rman_res_t start, rman_res_t end, rman_res_t count)
{
    struct resource_list_entry *entry;

    if (!list || rid < 0 || count == 0 || end < start)
        return 0;
    entry = resource_list_find(list, type, rid);
    if (!entry) {
        entry = bsd_malloc(
            sizeof(*entry), M_DEVBUF, M_WAITOK | M_ZERO);
        if (!entry)
            return 0;
        entry->type = type;
        entry->rid = rid;
        STAILQ_INSERT_TAIL(list, entry, link);
    } else if (entry->res) {
        bsd_bridge_panic_stop();
    }
    entry->start = start;
    entry->end = end;
    entry->count = count;
    return entry;
}

int
resource_list_add_next(struct resource_list *list, int type,
    rman_res_t start, rman_res_t end, rman_res_t count)
{
    int rid = 0;

    if (!list)
        return -1;
    while (resource_list_find(list, type, rid))
        rid++;
    return resource_list_add(
        list, type, rid, start, end, count) ? rid : -1;
}

int
resource_list_busy(struct resource_list *list, int type, int rid)
{
    struct resource_list_entry *entry =
        resource_list_find(list, type, rid);

    if (!entry || !entry->res)
        return 0;
    return (entry->flags &
        (RLE_RESERVED | RLE_ALLOCATED)) != RLE_RESERVED;
}

int
resource_list_reserved(struct resource_list *list, int type, int rid)
{
    struct resource_list_entry *entry =
        resource_list_find(list, type, rid);

    return entry && (entry->flags & RLE_RESERVED) != 0;
}

void
resource_list_delete(struct resource_list *list, int type, int rid)
{
    struct resource_list_entry *entry =
        resource_list_find(list, type, rid);

    if (!entry)
        return;
    if (entry->res)
        bsd_bridge_panic_stop();
    STAILQ_REMOVE(list, entry, resource_list_entry, link);
    bsd_free(entry, M_DEVBUF);
}

static struct resource *
resource_list_allocate_direct(struct resource_list_entry *entry,
    device_t child, int type, int rid, rman_res_t start, rman_res_t end,
    rman_res_t count, u_int flags)
{
    rman_res_t registered_start;
    rman_res_t registered_count;

    if (bus_get_resource(child, type, rid,
        &registered_start, &registered_count) != 0) {
        if (bsd_device_add_resource(child, type, rid, start, count,
            entry->flags & RLE_PREFETCH ? RF_PREFETCHABLE : 0, 0) != 0)
            return 0;
    }
    return bus_alloc_resource(
        child, type, rid, start, end, count, flags);
}

struct resource *
resource_list_alloc(struct resource_list *list, device_t bus,
    device_t child, int type, int rid, rman_res_t start, rman_res_t end,
    rman_res_t count, u_int flags)
{
    struct resource_list_entry *entry;
    device_t parent;
    int passthrough;

    if (!list || !bus || !child || count == 0)
        return 0;
    passthrough = device_get_parent(child) != bus;
    parent = device_get_parent(bus);
    if (passthrough &&
        bsd_device_implements_method(parent, &bus_alloc_resource_desc)) {
        return BUS_ALLOC_RESOURCE(parent, child, type, rid,
            start, end, count, flags);
    }

    entry = resource_list_find(list, type, rid);
    if (!entry)
        return 0;
    if (entry->res) {
        if ((entry->flags & RLE_RESERVED) == 0 ||
            (entry->flags & RLE_ALLOCATED) != 0)
            return 0;
        if ((flags & RF_ACTIVE) &&
            bus_activate_resource(child, entry->res) != 0)
            return 0;
        entry->flags |= RLE_ALLOCATED;
        return entry->res;
    }
    if (RMAN_IS_DEFAULT_RANGE(start, end)) {
        start = entry->start;
        if (count < entry->count)
            count = entry->count;
        end = entry->end;
        if (start > RM_MAX_END - (count - 1))
            return 0;
        if (end < start + count - 1)
            end = start + count - 1;
    }
    entry->res = resource_list_allocate_direct(
        entry, child, type, rid, start, end, count, flags);
    if (entry->res) {
        entry->start = rman_get_start(entry->res);
        entry->end = rman_get_end(entry->res);
        entry->count = rman_get_size(entry->res);
    }
    return entry->res;
}

int
resource_list_release(struct resource_list *list, device_t bus,
    device_t child, struct resource *resource)
{
    struct resource_list_entry *entry;
    device_t parent;
    int result;

    if (!list || !bus || !child || !resource)
        return BSD_NEWBUS_EINVAL;
    parent = device_get_parent(bus);
    if (device_get_parent(child) != bus &&
        bsd_device_implements_method(parent, &bus_release_resource_desc))
        return BUS_RELEASE_RESOURCE(parent, child, resource);

    entry = resource_list_find(
        list, rman_get_type(resource), rman_get_rid(resource));
    if (!entry || entry->res != resource)
        return BSD_NEWBUS_EINVAL;
    if ((entry->flags & RLE_RESERVED) != 0) {
        if ((entry->flags & RLE_ALLOCATED) == 0)
            return BSD_NEWBUS_EINVAL;
        if ((rman_get_flags(resource) & RF_ACTIVE) != 0) {
            result = bus_deactivate_resource(child, resource);
            if (result)
                return result;
        }
        entry->flags &= ~RLE_ALLOCATED;
        return 0;
    }
    result = bus_release_resource(child, resource);
    if (result == 0)
        entry->res = 0;
    return result;
}

int
resource_list_release_active(struct resource_list *list,
    device_t bus, device_t child, int type)
{
    struct resource_list_entry *entry;
    int busy = 0;

    if (!list)
        return BSD_NEWBUS_EINVAL;
    STAILQ_FOREACH(entry, list, link) {
        if (entry->type != type || !entry->res ||
            (entry->flags &
            (RLE_RESERVED | RLE_ALLOCATED)) == RLE_RESERVED)
            continue;
        busy = BSD_NEWBUS_EBUSY;
        (void)resource_list_release(
            list, bus, child, entry->res);
    }
    return busy;
}

struct resource *
resource_list_reserve(struct resource_list *list, device_t bus,
    device_t child, int type, int rid, rman_res_t start, rman_res_t end,
    rman_res_t count, u_int flags)
{
    struct resource *resource;
    struct resource_list_entry *entry;

    if (!list || !bus || !child ||
        device_get_parent(child) != bus || (flags & RF_ACTIVE))
        return 0;
    resource = resource_list_alloc(
        list, bus, child, type, rid, start, end, count, flags);
    if (!resource)
        return 0;
    entry = resource_list_find(list, type, rid);
    entry->flags |= RLE_RESERVED;
    return resource;
}

int
resource_list_unreserve(struct resource_list *list, device_t bus,
    device_t child, int type, int rid)
{
    struct resource_list_entry *entry;
    int result;

    if (!list || !bus || !child ||
        device_get_parent(child) != bus)
        return BSD_NEWBUS_EINVAL;
    entry = resource_list_find(list, type, rid);
    if (!entry || (entry->flags & RLE_RESERVED) == 0)
        return BSD_NEWBUS_EINVAL;
    if ((entry->flags & RLE_ALLOCATED) != 0)
        return BSD_NEWBUS_EBUSY;
    entry->flags &= ~RLE_RESERVED;
    result = bus_release_resource(child, entry->res);
    if (result == 0)
        entry->res = 0;
    return result;
}

int
resource_list_print_type(struct resource_list *list,
    const char *name, int type, const char *format)
{
    struct resource_list_entry *entry;
    int printed = 0;
    int result = 0;

    if (!list || !name || !format)
        return 0;
    STAILQ_FOREACH(entry, list, link) {
        if (entry->type != type)
            continue;
        if (printed++ == 0)
            result += bsd_printf(" %s ", name);
        else
            result += bsd_printf(",");
        result += bsd_printf(format, entry->start);
        if (entry->count > 1) {
            result += bsd_printf("-");
            result += bsd_printf(
                format, entry->start + entry->count - 1);
        }
    }
    return result;
}

void
resource_list_purge(struct resource_list *list)
{
    struct resource_list_entry *entry;

    if (!list)
        return;
    while ((entry = STAILQ_FIRST(list)) != 0) {
        if (entry->res) {
            (void)bus_release_resource(
                rman_get_device(entry->res), entry->res);
        }
        STAILQ_REMOVE_HEAD(list, link);
        bsd_free(entry, M_DEVBUF);
    }
}

void
resource_list_free(struct resource_list *list)
{
    struct resource_list_entry *entry;

    if (!list)
        return;
    while ((entry = STAILQ_FIRST(list)) != 0) {
        if (entry->res)
            bsd_bridge_panic_stop();
        STAILQ_REMOVE_HEAD(list, link);
        bsd_free(entry, M_DEVBUF);
    }
}

int
bus_generic_rl_get_resource(device_t bus, device_t child,
    int type, int rid, rman_res_t *start, rman_res_t *count)
{
    struct resource_list *list =
        BUS_GET_RESOURCE_LIST(bus, child);
    struct resource_list_entry *entry;

    if (!list)
        return BSD_NEWBUS_EINVAL;
    entry = resource_list_find(list, type, rid);
    if (!entry)
        return BSD_NEWBUS_ENOENT;
    if (start)
        *start = entry->start;
    if (count)
        *count = entry->count;
    return 0;
}

int
bus_generic_rl_set_resource(device_t bus, device_t child,
    int type, int rid, rman_res_t start, rman_res_t count)
{
    struct resource_list *list =
        BUS_GET_RESOURCE_LIST(bus, child);

    if (!list || count == 0 ||
        start > (rman_res_t)-1 - (count - 1))
        return BSD_NEWBUS_EINVAL;
    return resource_list_add(list, type, rid, start,
        start + count - 1, count) ? 0 : BSD_NEWBUS_ENOMEM;
}

void
bus_generic_rl_delete_resource(device_t bus, device_t child,
    int type, int rid)
{
    struct resource_list *list =
        BUS_GET_RESOURCE_LIST(bus, child);

    if (list)
        resource_list_delete(list, type, rid);
}

struct resource *
bus_generic_rl_alloc_resource(device_t bus, device_t child,
    int type, int rid, rman_res_t start, rman_res_t end,
    rman_res_t count, u_int flags)
{
    struct resource_list *list;
    device_t parent = device_get_parent(bus);

    if (device_get_parent(child) != bus &&
        bsd_device_implements_method(parent, &bus_alloc_resource_desc)) {
        return BUS_ALLOC_RESOURCE(parent, child, type, rid,
            start, end, count, flags);
    }
    list = BUS_GET_RESOURCE_LIST(bus, child);
    return list ? resource_list_alloc(list, bus, child,
        type, rid, start, end, count, flags) : 0;
}

int
bus_generic_rl_release_resource(device_t bus, device_t child,
    struct resource *resource)
{
    struct resource_list *list;
    device_t parent = device_get_parent(bus);

    if (device_get_parent(child) != bus &&
        bsd_device_implements_method(parent, &bus_release_resource_desc))
        return BUS_RELEASE_RESOURCE(parent, child, resource);
    list = BUS_GET_RESOURCE_LIST(bus, child);
    return list ? resource_list_release(
        list, bus, child, resource) : BSD_NEWBUS_EINVAL;
}

int
bus_generic_child_pnpinfo(device_t bus, device_t child, struct sbuf *buffer)
{
    (void)bus;
    (void)child;
    (void)buffer;
    return 0;
}

int
bus_generic_child_location(device_t bus, device_t child,
    struct sbuf *buffer)
{
    (void)bus;
    (void)child;
    (void)buffer;
    return 0;
}

int
bus_generic_get_device_path(device_t bus, device_t child,
    const char *locator, struct sbuf *buffer)
{
    device_t parent;
    int result = 0;

    if (!bus || !child || !locator || !buffer)
        return BSD_NEWBUS_EINVAL;
    parent = device_get_parent(bus);
    if (device_has_methods(parent) &&
        bsd_strcmp(locator, BUS_LOCATOR_ACPI) != 0)
        result = BUS_GET_DEVICE_PATH(parent, bus, locator, buffer);
    if (result == 0 &&
        bsd_strcmp(locator, BUS_LOCATOR_FREEBSD) == 0)
        result = sbuf_printf(buffer, "/%s", device_get_nameunit(child));
    return result;
}

int
bus_null_rescan(device_t bus)
{
    (void)bus;
    return BSD_NEWBUS_ENODEV;
}
