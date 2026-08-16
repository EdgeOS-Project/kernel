/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Shared Device Tree inventory for imported BSD platform drivers.
 *
 * Enumeration records firmware metadata and decoded resources without
 * probing drivers. A device becomes BSD-owned only through an explicit claim.
 */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/fdt_inventory.h"
#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/platform.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/ofw/ofw_bus_subr.h"
#include "compat/freebsd/machine/resource.h"

#define BSD_FDT_INVENTORY_ENOENT 2
#define BSD_FDT_INVENTORY_ENXIO 6
#define BSD_FDT_INVENTORY_ENOMEM 12
#define BSD_FDT_INVENTORY_EBUSY 16
#define BSD_FDT_INVENTORY_EINVAL 22

static device_t g_inventory_root;
static device_t g_inventory_bus;
static phandle_t g_inventory_root_node;
static bsd_fdt_inventory_status_t g_inventory_status;

static int
fdt_compatible_list(phandle_t node, const char ***result,
    size_t *count)
{
    const char *property;
    const char **items;
    size_t offset = 0;
    size_t item_count = 0;
    int length;

    if (!result || !count)
        return BSD_FDT_INVENTORY_EINVAL;
    *result = 0;
    *count = 0;
    property = bsd_ofw_fdt_get_property(node, "compatible", &length);
    if (!property)
        return BSD_FDT_INVENTORY_ENOENT;
    if (length <= 0)
        return BSD_FDT_INVENTORY_EINVAL;
    while (offset < (size_t)length) {
        size_t item_length = bsd_strnlen(
            property + offset, (size_t)length - offset);

        if (item_length == 0 ||
            item_length == (size_t)length - offset)
            return BSD_FDT_INVENTORY_EINVAL;
        ++item_count;
        offset += item_length + 1;
    }
    if (item_count > SIZE_MAX / sizeof(*items))
        return BSD_FDT_INVENTORY_EINVAL;
    items = bsd_malloc(item_count * sizeof(*items), M_DEVBUF,
        M_WAITOK);
    if (!items)
        return BSD_FDT_INVENTORY_ENOMEM;
    offset = 0;
    for (size_t index = 0; index < item_count; ++index) {
        size_t item_length = bsd_strlen(property + offset);

        items[index] = property + offset;
        offset += item_length + 1;
    }
    *result = items;
    *count = item_count;
    return 0;
}

static int
fdt_node_resources(phandle_t node, bsd_platform_resource_t **result,
    size_t *count, bsd_fdt_inventory_status_t *status)
{
    bsd_platform_resource_t *resources;
    size_t register_count = 0;
    size_t interrupt_count = 0;
    size_t capacity;
    size_t used = 0;
    int error;

    if (!result || !count || !status)
        return BSD_FDT_INVENTORY_EINVAL;
    *result = 0;
    *count = 0;
    error = bsd_ofw_fdt_get_reg_count(node, &register_count);
    if (error == BSD_FDT_INVENTORY_ENOENT)
        register_count = 0;
    else if (error != 0) {
        register_count = 0;
        ++status->unresolved_resources;
    }
    error = bsd_ofw_fdt_get_interrupt_count(node, &interrupt_count);
    if (error == BSD_FDT_INVENTORY_ENOENT)
        interrupt_count = 0;
    else if (error != 0) {
        interrupt_count = 0;
        ++status->unresolved_resources;
    }
    if (register_count > SIZE_MAX - interrupt_count ||
        register_count + interrupt_count >
            SIZE_MAX / sizeof(*resources))
        return BSD_FDT_INVENTORY_EINVAL;
    capacity = register_count + interrupt_count;
    if (capacity == 0)
        return 0;
    resources = bsd_malloc(capacity * sizeof(*resources), M_DEVBUF,
        M_WAITOK | M_ZERO);
    if (!resources)
        return BSD_FDT_INVENTORY_ENOMEM;

    for (size_t index = 0; index < register_count; ++index) {
        uint64_t address;
        uint64_t size;

        if (index > INT32_MAX ||
            bsd_ofw_fdt_get_reg(node, (unsigned int)index,
                &address, &size) != 0 ||
            size == 0) {
            ++status->unresolved_resources;
            continue;
        }
        resources[used++] = (bsd_platform_resource_t) {
            .type = SYS_RES_MEMORY,
            .rid = (int)index,
            .start = address,
            .count = size,
        };
        ++status->memory_resources;
    }
    for (size_t index = 0; index < interrupt_count; ++index) {
        uint32_t interrupt;
        uint32_t flags;

        if (index > INT32_MAX ||
            bsd_ofw_fdt_get_interrupt(node, (unsigned int)index,
                &interrupt, &flags) != 0) {
            ++status->unresolved_resources;
            continue;
        }
        resources[used++] = (bsd_platform_resource_t) {
            .type = SYS_RES_IRQ,
            .rid = (int)index,
            .start = interrupt,
            .count = 1,
            .interrupt_flags = flags,
        };
        ++status->interrupt_resources;
    }
    if (used == 0) {
        bsd_free(resources, M_DEVBUF);
        return 0;
    }
    *result = resources;
    *count = used;
    return 0;
}

static int
fdt_register_device(device_t parent, phandle_t node, int enabled,
    int bus, device_t *result, bsd_fdt_inventory_status_t *status)
{
    const char **compatible = 0;
    size_t compatible_count = 0;
    bsd_platform_resource_t *resources = 0;
    size_t resource_count = 0;
    bsd_firmware_description_t firmware;
    bsd_platform_device_t description;
    device_t device = 0;
    int error;

    error = fdt_compatible_list(node, &compatible, &compatible_count);
    if (error)
        return error;
    error = fdt_node_resources(node, &resources, &resource_count, status);
    if (error)
        goto out;
    firmware = (bsd_firmware_description_t) {
        .kind = BSD_FIRMWARE_FDT,
        .enabled = enabled,
        .compatible = compatible,
        .compatible_count = compatible_count,
        .node = node,
    };
    description = (bsd_platform_device_t) {
        .name = bus ? "simplebus" : 0,
        .unit = DEVICE_UNIT_ANY,
        .resources = resources,
        .resource_count = resource_count,
        .firmware = &firmware,
    };
    error = bsd_platform_register_device(parent, &description, &device);
    if (error)
        goto out;
    error = OF_device_register_xref(OF_xref_from_node(node), device);
    if (error) {
        (void)bsd_platform_remove_device(parent, device);
        device = 0;
        goto out;
    }
    if (!enabled)
        device_disable(device);
    ++status->devices_registered;
    if (bus)
        ++status->buses_registered;
    if (!enabled)
        ++status->disabled_nodes;
    if (result)
        *result = device;
out:
    if (resources)
        bsd_free(resources, M_DEVBUF);
    if (compatible)
        bsd_free((void *)compatible, M_DEVBUF);
    return error;
}

static void
fdt_unregister_xrefs(device_t device)
{
    device_t *children = 0;
    int count = 0;
    phandle_t node;

    if (!device)
        return;
    if (device_get_children(device, &children, &count) == 0) {
        for (int index = 0; index < count; ++index)
            fdt_unregister_xrefs(children[index]);
    }
    if (children)
        bsd_free(children, M_TEMP);
    node = bsd_firmware_fdt_node(device);
    if (node != (phandle_t)-1)
        OF_device_unregister_xref(OF_xref_from_node(node), device);
}

static int
fdt_detach_tree(device_t device)
{
    device_t *children = 0;
    int count = 0;
    int error;

    if (!device)
        return 0;
    error = device_get_children(device, &children, &count);
    if (error)
        return error;
    for (int index = count - 1; index >= 0; --index) {
        error = fdt_detach_tree(children[index]);
        if (error)
            break;
    }
    if (children)
        bsd_free(children, M_TEMP);
    if (error)
        return error;
    return device_detach(device);
}

static int
fdt_register_children(device_t parent, phandle_t node,
    int parent_enabled, bsd_fdt_inventory_status_t *status)
{
    for (phandle_t child = OF_child(node);
         child != 0; child = OF_peer(child)) {
        device_t device = 0;
        int enabled;
        int bus;
        int error;

        ++status->nodes_seen;
        enabled = parent_enabled && ofw_bus_node_status_okay(child);
        bus = ofw_bus_node_is_compatible(child, "simple-bus");
        error = fdt_register_device(parent, child, enabled, bus,
            &device, status);
        if (error == BSD_FDT_INVENTORY_ENOENT) {
            ++status->unsupported_nodes;
            continue;
        }
        if (error)
            return error;
        if (bus) {
            error = fdt_register_children(device, child, enabled,
                status);
            if (error)
                return error;
        }
    }
    return 0;
}

static int
fdt_inventory_contains(device_t device)
{
    for (device_t current = device; current;
         current = device_get_parent(current)) {
        if (current == g_inventory_bus)
            return 1;
    }
    return 0;
}

int
bsd_fdt_inventory_register(device_t root,
    bsd_fdt_inventory_status_t *status)
{
    phandle_t root_node;
    device_t bus = 0;
    int error;

    if (status)
        *status = (bsd_fdt_inventory_status_t){0};
    if (!root || !bsd_ofw_fdt_available())
        return BSD_FDT_INVENTORY_EINVAL;
    if (g_inventory_bus)
        return g_inventory_root == root ?
            BSD_FDT_INVENTORY_EBUSY : BSD_FDT_INVENTORY_EINVAL;
    root_node = OF_peer(0);
    if (root_node == 0)
        return BSD_FDT_INVENTORY_ENXIO;
    error = bsd_platform_add_bus(root, "ofwbus", DEVICE_UNIT_ANY, &bus);
    if (error)
        return error;
    error = OF_device_register_xref(OF_xref_from_node(root_node), bus);
    if (error)
        goto fail;

    g_inventory_status = (bsd_fdt_inventory_status_t) {
        .bus = bus,
        .nodes_seen = 1,
        .buses_registered = 1,
    };
    error = fdt_register_children(bus, root_node, 1,
        &g_inventory_status);
    if (error)
        goto fail;
    g_inventory_root = root;
    g_inventory_bus = bus;
    g_inventory_root_node = root_node;
    if (status)
        *status = g_inventory_status;
    return 0;

fail:
    OF_device_unregister_xref(OF_xref_from_node(root_node), bus);
    fdt_unregister_xrefs(bus);
    (void)bsd_platform_remove_device(root, bus);
    g_inventory_status = (bsd_fdt_inventory_status_t){0};
    return error;
}

int
bsd_fdt_inventory_unregister(device_t root)
{
    device_t bus = g_inventory_bus;
    int error;

    if (!root || root != g_inventory_root || !bus)
        return BSD_FDT_INVENTORY_EINVAL;
    error = fdt_detach_tree(bus);
    if (error)
        return error;
    OF_device_unregister_xref(OF_xref_from_node(
        g_inventory_root_node), bus);
    fdt_unregister_xrefs(bus);
    error = bsd_platform_remove_device(root, bus);
    if (error)
        return error;
    g_inventory_root = 0;
    g_inventory_bus = 0;
    g_inventory_root_node = 0;
    g_inventory_status = (bsd_fdt_inventory_status_t){0};
    return 0;
}

void
bsd_fdt_inventory_get_status(bsd_fdt_inventory_status_t *status)
{
    if (status)
        *status = g_inventory_status;
}

device_t
bsd_fdt_inventory_find(phandle_t node)
{
    device_t device;

    if (!bsd_ofw_fdt_node_valid(node))
        return 0;
    device = OF_device_from_xref(OF_xref_from_node(node));
    return fdt_inventory_contains(device) ? device : 0;
}

int
bsd_fdt_inventory_claim(phandle_t node, driver_t *driver,
    device_t *result)
{
    device_t device = bsd_fdt_inventory_find(node);
    int error;

    if (result)
        *result = 0;
    if (!device || device == g_inventory_bus)
        return BSD_FDT_INVENTORY_ENOENT;
    if (device_has_children(device) || device_is_attached(device))
        return BSD_FDT_INVENTORY_EBUSY;
    if (!device_is_enabled(device))
        return BSD_FDT_INVENTORY_ENXIO;
    if (driver) {
        error = device_set_driver(device, driver);
        if (error)
            return error;
    }
    error = bsd_platform_attach_device(device);
    if (error) {
        (void)device_set_driver(device, 0);
        return error;
    }
    if (result)
        *result = device;
    return 0;
}

int
bsd_fdt_inventory_release(phandle_t node)
{
    device_t device = bsd_fdt_inventory_find(node);

    if (!device)
        return BSD_FDT_INVENTORY_ENOENT;
    if (!device_is_attached(device))
        return BSD_FDT_INVENTORY_EINVAL;
    return device_detach(device);
}
