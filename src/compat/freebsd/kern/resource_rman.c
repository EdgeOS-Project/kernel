/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD generic rman forwarding on the shared EdgeOS resource runtime. */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include "compat/freebsd/edgeos/resource.h"
#include "bus_if.h"

#define BSD_RESOURCE_EINVAL 22

struct resource *
bus_generic_rman_alloc_resource(device_t device, device_t child, int type,
    int rid, rman_res_t start, rman_res_t end, rman_res_t count,
    unsigned int flags)
{
    struct rman *manager;
    struct resource *resource;

    if (!device || !child || !((kobj_t)device)->ops)
        return 0;
    manager = BUS_GET_RMAN(device, type, flags);
    if (!manager)
        return 0;
    resource = rman_reserve_resource(manager, start, end, count,
        flags & ~RF_ACTIVE, child);
    if (!resource)
        return 0;
    rman_set_rid(resource, rid);
    rman_set_type(resource, type);
    if ((flags & RF_ACTIVE) != 0 &&
        bus_activate_resource(child, resource) != 0) {
        (void)rman_release_resource(resource);
        return 0;
    }
    return resource;
}

int
bus_generic_rman_adjust_resource(device_t device, device_t child,
    struct resource *resource, rman_res_t start, rman_res_t end)
{
    struct rman *manager;

    if (!device || !child || !resource || !((kobj_t)device)->ops)
        return BSD_RESOURCE_EINVAL;
    manager = BUS_GET_RMAN(device, rman_get_type(resource),
        rman_get_flags(resource));
    if (!manager || bsd_resource_get_manager(resource) != manager)
        return BSD_RESOURCE_EINVAL;
    return bus_adjust_resource(child, resource, start, end);
}

int
bus_generic_rman_release_resource(device_t device, device_t child,
    struct resource *resource)
{
    struct rman *manager;
    int error;

    if (!device || !child || !resource || !((kobj_t)device)->ops)
        return BSD_RESOURCE_EINVAL;
    manager = BUS_GET_RMAN(device, rman_get_type(resource),
        rman_get_flags(resource));
    if (!manager || bsd_resource_get_manager(resource) != manager)
        return BSD_RESOURCE_EINVAL;
    if ((rman_get_flags(resource) & RF_ACTIVE) != 0) {
        error = bus_deactivate_resource(child, resource);
        if (error)
            return error;
    }
    return rman_release_resource(resource);
}

int
bus_generic_rman_activate_resource(device_t device, device_t child,
    struct resource *resource)
{
    struct rman *manager;

    if (!device || !child || !resource || !((kobj_t)device)->ops)
        return BSD_RESOURCE_EINVAL;
    manager = BUS_GET_RMAN(device, rman_get_type(resource),
        rman_get_flags(resource));
    if (!manager || bsd_resource_get_manager(resource) != manager)
        return BSD_RESOURCE_EINVAL;
    return bus_activate_resource(child, resource);
}

int
bus_generic_rman_deactivate_resource(device_t device, device_t child,
    struct resource *resource)
{
    struct rman *manager;

    if (!device || !child || !resource || !((kobj_t)device)->ops)
        return BSD_RESOURCE_EINVAL;
    manager = BUS_GET_RMAN(device, rman_get_type(resource),
        rman_get_flags(resource));
    if (!manager || bsd_resource_get_manager(resource) != manager)
        return BSD_RESOURCE_EINVAL;
    return bus_deactivate_resource(child, resource);
}
