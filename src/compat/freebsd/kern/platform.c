/* SPDX-License-Identifier: MPL-2.0 */
/* Shared platform-device adapter for imported BSD newbus drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/platform.h"
#include "compat/freebsd/machine/resource.h"

#define BSD_PLATFORM_ENXIO 6
#define BSD_PLATFORM_EINVAL 22

int
bsd_platform_add_bus(device_t parent, const char *name, int unit,
    device_t *result)
{
    device_t child;

    if (result)
        *result = 0;
    if (!parent || !name || name[0] == '\0')
        return BSD_PLATFORM_EINVAL;
    child = device_add_child(parent, name, unit);
    if (!child)
        return BSD_PLATFORM_ENXIO;
    if (result)
        *result = child;
    return 0;
}

static int
platform_description_valid(const bsd_platform_device_t *description)
{
    if (!description ||
        (!description->name && !description->driver &&
         !description->firmware) ||
        (!description->resources && description->resource_count != 0))
        return 0;
    for (size_t index = 0; index < description->resource_count; ++index) {
        const bsd_platform_resource_t *resource =
            &description->resources[index];

        if (resource->rid < 0 || resource->count == 0 ||
            resource->start > UINT64_MAX - (resource->count - 1))
            return 0;
        if ((resource->interrupt_source ||
             resource->interrupt_flags != 0) &&
            resource->type != SYS_RES_IRQ)
            return 0;
    }
    return 1;
}

int
bsd_platform_remove_device(device_t parent, device_t device)
{
    int error;

    if (!parent || !device || device_get_parent(device) != parent)
        return BSD_PLATFORM_EINVAL;
    error = device_delete_children(device);
    if (error)
        return error;
    return device_delete_child(parent, device);
}

int
bsd_platform_register_device(device_t parent,
    const bsd_platform_device_t *description, device_t *result)
{
    device_t child;
    int error;

    if (result)
        *result = 0;
    if (!parent || !platform_description_valid(description))
        return BSD_PLATFORM_EINVAL;

    child = device_add_child_ordered(parent, description->order,
        description->name, description->unit);
    if (!child)
        return BSD_PLATFORM_ENXIO;

    if (description->driver) {
        error = device_set_driver(child, description->driver);
        if (error)
            goto fail;
    }
    if (description->firmware) {
        error = bsd_firmware_bind(child, description->firmware);
        if (error)
            goto fail;
    }
    for (size_t index = 0; index < description->resource_count; ++index) {
        const bsd_platform_resource_t *resource =
            &description->resources[index];

        error = bsd_device_add_resource(child, resource->type,
            resource->rid, resource->start, resource->count,
            resource->flags, resource->tag);
        if (error)
            goto fail;
        if (resource->interrupt_source) {
            error = bsd_resource_set_interrupt_source(child,
                resource->rid, resource->interrupt_source);
            if (error)
                goto fail;
        }
        if (resource->interrupt_flags != 0) {
            error = bsd_resource_set_interrupt_flags(child,
                resource->rid, resource->interrupt_flags);
            if (error)
                goto fail;
        }
    }

    if (result)
        *result = child;
    return 0;

fail:
    (void)bsd_platform_remove_device(parent, child);
    return error;
}

int
bsd_platform_attach_device(device_t device)
{
    if (!device || !device_get_parent(device))
        return BSD_PLATFORM_EINVAL;
    return device_probe_and_attach(device);
}

int
bsd_platform_add_device(device_t parent,
    const bsd_platform_device_t *description, device_t *result)
{
    device_t child = 0;
    int error;

    if (result)
        *result = 0;
    error = bsd_platform_register_device(parent, description, &child);
    if (error)
        return error;
    error = bsd_platform_attach_device(child);
    if (error) {
        (void)bsd_platform_remove_device(parent, child);
        return error;
    }
    if (result)
        *result = child;
    return 0;
}
