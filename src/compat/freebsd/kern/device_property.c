/* SPDX-License-Identifier: MPL-2.0 */
/* Shared firmware property access for FreeBSD-compatible devices. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/bus.h>

#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/systm.h"

static size_t
property_copy_size(ssize_t property_size, size_t capacity)
{
    size_t available;

    if (property_size <= 0)
        return 0;
    available = (size_t)property_size;
    return available < capacity ? available : capacity;
}

static ssize_t
device_get_fdt_property(device_t device, const char *name, void *value,
    size_t size, device_property_type_t type)
{
    phandle_t node = bsd_firmware_fdt_node(device);
    ssize_t result;

    if (node == (phandle_t)-1)
        return -1;
    if (!value || size == 0)
        return OF_getproplen(node, name);

    switch (type) {
    case DEVICE_PROP_ANY:
    case DEVICE_PROP_BUFFER:
        return OF_getprop(node, name, value, size);
    case DEVICE_PROP_UINT32:
        return OF_getencprop(node, name, value, size);
    case DEVICE_PROP_UINT64: {
        uint32_t *cells = value;
        size_t converted;

        result = OF_getencprop(node, name, cells, size);
        if (result <= 0)
            return result;
        converted = property_copy_size(result, size);
        for (size_t offset = 0;
            offset + sizeof(uint64_t) <= converted;
            offset += sizeof(uint64_t)) {
            size_t index = offset / sizeof(uint32_t);
            uint64_t host_value =
                ((uint64_t)cells[index] << 32) | cells[index + 1];

            bsd_memcpy((uint8_t *)value + offset, &host_value,
                sizeof(host_value));
        }
        return result;
    }
    case DEVICE_PROP_HANDLE: {
        phandle_t xref;

        if (size < sizeof(phandle_t))
            return -1;
        result = OF_getencprop(node, name, &xref, sizeof(xref));
        if (result <= 0)
            return result;
        node = OF_node_from_xref(xref);
        bsd_memcpy(value, &node, sizeof(node));
        return result;
    }
    default:
        return -1;
    }
}

ssize_t
device_get_property(device_t device, const char *name, void *value,
    size_t size, device_property_type_t type)
{
    device_t parent;
    ssize_t result;

    if (!device || !name || (!value && size != 0))
        return -1;
    switch (type) {
    case DEVICE_PROP_ANY:
    case DEVICE_PROP_BUFFER:
    case DEVICE_PROP_HANDLE:
        break;
    case DEVICE_PROP_UINT32:
        if (size % sizeof(uint32_t) != 0)
            return -1;
        break;
    case DEVICE_PROP_UINT64:
        if (size % sizeof(uint64_t) != 0)
            return -1;
        break;
    default:
        return -1;
    }

    result = device_get_fdt_property(device, name, value, size, type);
    if (result >= 0 || bsd_firmware_fdt_node(device) != (phandle_t)-1)
        return result;

    parent = device_get_parent(device);
    return bsd_bus_get_property(parent, device, name, value, size, type);
}

bool
device_has_property(device_t device, const char *name)
{
    return device_get_property(device, name, 0, 0,
        DEVICE_PROP_ANY) >= 0;
}
