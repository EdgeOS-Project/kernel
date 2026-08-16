/* SPDX-License-Identifier: MPL-2.0 */
/* Device-facing OFW helpers backed by immutable firmware metadata. */

#include <stddef.h>

#include <sys/bus.h>

#include "compat/freebsd/edgeos/firmware.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/ofw/ofw_bus_subr.h"
#include "compat/freebsd/machine/resource.h"
#include "compat/freebsd/sys/sbuf.h"

#define BSD_OFW_BUS_ENOENT 2
#define BSD_OFW_BUS_ENOMEM 12
#define BSD_OFW_BUS_EINVAL 22
#define BSD_OFW_BUS_ERANGE 34
#define BSD_OFW_BUS_MAX_INTERRUPT_CELLS 16

static int ofw_bus_string_equal(const char *left, const char *right);

static void
ofw_bus_release_property(char **property)
{
    if (property && *property) {
        OF_prop_free(*property);
        *property = 0;
    }
}

int
ofw_bus_gen_setup_devinfo(struct ofw_bus_devinfo *devinfo,
    phandle_t node)
{
    if (!devinfo || node == 0 || node == (phandle_t)-1)
        return BSD_OFW_BUS_EINVAL;
    bsd_memset(devinfo, 0, sizeof(*devinfo));
    if (OF_getprop_alloc(
        node, "name", (void **)&devinfo->obd_name) < 0)
        return BSD_OFW_BUS_EINVAL;
    (void)OF_getprop_alloc(
        node, "compatible", (void **)&devinfo->obd_compat);
    (void)OF_getprop_alloc(
        node, "device_type", (void **)&devinfo->obd_type);
    (void)OF_getprop_alloc(
        node, "model", (void **)&devinfo->obd_model);
    (void)OF_getprop_alloc(
        node, "status", (void **)&devinfo->obd_status);
    devinfo->obd_node = node;
    return 0;
}

void
ofw_bus_gen_destroy_devinfo(struct ofw_bus_devinfo *devinfo)
{
    if (!devinfo)
        return;
    ofw_bus_release_property(&devinfo->obd_compat);
    ofw_bus_release_property(&devinfo->obd_model);
    ofw_bus_release_property(&devinfo->obd_name);
    ofw_bus_release_property(&devinfo->obd_type);
    ofw_bus_release_property(&devinfo->obd_status);
    devinfo->obd_node = 0;
}

static const struct ofw_bus_devinfo *
ofw_bus_gen_devinfo(device_t bus, device_t device)
{
    if (!bus || !device)
        return 0;
    return OFW_BUS_GET_DEVINFO(bus, device);
}

const char *
ofw_bus_gen_get_compat(device_t bus, device_t device)
{
    const struct ofw_bus_devinfo *devinfo =
        ofw_bus_gen_devinfo(bus, device);

    return devinfo ? devinfo->obd_compat : 0;
}

const char *
ofw_bus_gen_get_model(device_t bus, device_t device)
{
    const struct ofw_bus_devinfo *devinfo =
        ofw_bus_gen_devinfo(bus, device);

    return devinfo ? devinfo->obd_model : 0;
}

const char *
ofw_bus_gen_get_name(device_t bus, device_t device)
{
    const struct ofw_bus_devinfo *devinfo =
        ofw_bus_gen_devinfo(bus, device);

    return devinfo ? devinfo->obd_name : 0;
}

phandle_t
ofw_bus_gen_get_node(device_t bus, device_t device)
{
    const struct ofw_bus_devinfo *devinfo =
        ofw_bus_gen_devinfo(bus, device);

    return devinfo ? devinfo->obd_node : (phandle_t)-1;
}

const char *
ofw_bus_gen_get_type(device_t bus, device_t device)
{
    const struct ofw_bus_devinfo *devinfo =
        ofw_bus_gen_devinfo(bus, device);

    return devinfo ? devinfo->obd_type : 0;
}

int
ofw_bus_gen_child_pnpinfo(device_t bus, device_t child,
    struct sbuf *buffer)
{
    const struct ofw_bus_devinfo *devinfo =
        ofw_bus_gen_devinfo(bus, child);

    if (!buffer || !devinfo ||
        (devinfo->obd_status &&
        !ofw_bus_string_equal(devinfo->obd_status, "okay") &&
        !ofw_bus_string_equal(devinfo->obd_status, "ok")))
        return 0;
    if (devinfo->obd_name)
        (void)sbuf_printf(buffer, "name=%s ", devinfo->obd_name);
    if (devinfo->obd_compat)
        (void)sbuf_printf(
            buffer, "compat=%s ", devinfo->obd_compat);
    return 0;
}

int
ofw_bus_gen_get_device_path(device_t bus, device_t child,
    const char *locator, struct sbuf *buffer)
{
    int error;

    error = bus_generic_get_device_path(bus, child, locator, buffer);
    if (error == 0 && locator &&
        bsd_strcmp(locator, BUS_LOCATOR_OFW) == 0)
        error = sbuf_printf(buffer, "/%s", ofw_bus_get_name(child));
    return error;
}

int
ofw_bus_reg_to_rl(device_t device, phandle_t node,
    pcell_t address_cells, pcell_t size_cells,
    struct resource_list *resources)
{
    pcell_t *registers = 0;
    ssize_t cell_count;
    size_t tuple_cells;
    int rid = 0;

    if (!device || !resources || address_cells == 0 ||
        address_cells > 2 || size_cells == 0 || size_cells > 2)
        return BSD_OFW_BUS_EINVAL;
    tuple_cells = (size_t)address_cells + (size_t)size_cells;
    cell_count = OF_getencprop_alloc_multi(
        node, "reg", sizeof(*registers), (void **)&registers);
    if (cell_count < 0)
        return 0;
    if ((size_t)cell_count % tuple_cells != 0) {
        OF_prop_free(registers);
        return BSD_OFW_BUS_EINVAL;
    }
    for (size_t offset = 0; offset < (size_t)cell_count;
        offset += tuple_cells) {
        uint64_t start = 0;
        uint64_t size = 0;

        for (size_t index = 0; index < address_cells; ++index)
            start = (start << 32) | registers[offset + index];
        for (size_t index = 0; index < size_cells; ++index)
            size = (size << 32) |
                registers[offset + address_cells + index];
        if (size != 0 && !resource_list_add(resources,
            SYS_RES_MEMORY, rid++, start, start + size - 1, size)) {
            OF_prop_free(registers);
            return BSD_OFW_BUS_ENOMEM;
        }
    }
    OF_prop_free(registers);
    return 0;
}

static int
ofw_bus_decode_interrupt(device_t device, phandle_t provider,
    int cell_count, pcell_t *cells)
{
    if (!device || provider == 0 || !cells || cell_count < 1 ||
        cell_count > BSD_OFW_BUS_MAX_INTERRUPT_CELLS)
        return -BSD_OFW_BUS_EINVAL;
    if (cell_count == 3 &&
        (ofw_bus_node_is_compatible(
            OF_node_from_xref(provider), "arm,gic-v3") ||
        ofw_bus_node_is_compatible(
            OF_node_from_xref(provider), "arm,gic-400"))) {
        if (cells[0] == 0 && cells[1] <= 987)
            return (int)cells[1] + 32;
        if (cells[0] == 1 && cells[1] <= 15)
            return (int)cells[1] + 16;
        return -BSD_OFW_BUS_ERANGE;
    }
    return ofw_bus_map_intr(device, provider, cell_count, cells);
}

static int
ofw_bus_add_interrupt(struct resource_list *resources, int rid,
    int interrupt)
{
    if (interrupt < 0)
        return -interrupt;
    return resource_list_add(resources, SYS_RES_IRQ, rid,
        (rman_res_t)interrupt, (rman_res_t)interrupt, 1) ?
        0 : BSD_OFW_BUS_ENOMEM;
}

static int
ofw_bus_standard_interrupts_to_rl(device_t device, phandle_t node,
    struct resource_list *resources, int *added)
{
    size_t count = 0;
    int error = bsd_ofw_fdt_get_interrupt_count(node, &count);

    if (error != 0)
        return error;
    if (count > (size_t)INT32_MAX)
        return BSD_OFW_BUS_ERANGE;
    for (size_t index = 0; index < count; ++index) {
        uint32_t interrupt;
        uint32_t flags;

        error = bsd_ofw_fdt_get_interrupt(
            node, (unsigned int)index, &interrupt, &flags);
        (void)flags;
        if (error != 0)
            return error;
        error = ofw_bus_add_interrupt(
            resources, *added, (int)interrupt);
        if (error != 0)
            return error;
        ++*added;
    }
    (void)device;
    return 0;
}

static int
ofw_bus_extended_interrupts_to_rl(device_t device, phandle_t node,
    struct resource_list *resources, int *added)
{
    pcell_t *list = 0;
    ssize_t byte_count = OF_getencprop_alloc(
        node, "interrupts-extended", (void **)&list);
    size_t count;
    size_t cursor = 0;
    int error = 0;

    if (byte_count < 0)
        return BSD_OFW_BUS_ENOENT;
    if ((size_t)byte_count % sizeof(*list) != 0) {
        OF_prop_free(list);
        return BSD_OFW_BUS_EINVAL;
    }
    count = (size_t)byte_count / sizeof(*list);
    while (cursor < count) {
        phandle_t provider = list[cursor++];
        phandle_t provider_node = OF_node_from_xref(provider);
        pcell_t cell_count;
        int interrupt;

        if (provider == 0 || provider_node == 0 ||
            OF_getencprop(provider_node, "#interrupt-cells",
            &cell_count, sizeof(cell_count)) !=
            (ssize_t)sizeof(cell_count) ||
            cell_count == 0 ||
            cell_count > BSD_OFW_BUS_MAX_INTERRUPT_CELLS ||
            cell_count > count - cursor) {
            error = BSD_OFW_BUS_EINVAL;
            break;
        }
        interrupt = ofw_bus_decode_interrupt(device, provider,
            (int)cell_count, &list[cursor]);
        cursor += cell_count;
        error = ofw_bus_add_interrupt(
            resources, *added, interrupt);
        if (error != 0)
            break;
        ++*added;
    }
    OF_prop_free(list);
    return error;
}

int
ofw_bus_intr_to_rl(device_t device, phandle_t node,
    struct resource_list *resources, int *resource_count)
{
    int added = 0;
    int error;

    if (resource_count)
        *resource_count = 0;
    if (!device || !resources || node == 0 ||
        node == (phandle_t)-1)
        return BSD_OFW_BUS_EINVAL;
    if (OF_hasprop(node, "interrupts")) {
        error = ofw_bus_standard_interrupts_to_rl(
            device, node, resources, &added);
    } else if (OF_hasprop(node, "interrupts-extended")) {
        error = ofw_bus_extended_interrupts_to_rl(
            device, node, resources, &added);
    } else {
        error = 0;
    }
    if (error != 0) {
        while (added > 0)
            resource_list_delete(
                resources, SYS_RES_IRQ, --added);
        return error;
    }
    if (resource_count)
        *resource_count = added;
    return 0;
}

static unsigned char
ofw_bus_ascii_lower(unsigned char value)
{
    return value >= 'A' && value <= 'Z' ?
        (unsigned char)(value + ('a' - 'A')) : value;
}

static int
ofw_bus_string_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *right) {
        if (ofw_bus_ascii_lower((unsigned char)*left) !=
            ofw_bus_ascii_lower((unsigned char)*right))
            return 0;
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

static const char *
ofw_bus_string_property(device_t device, const char *property)
{
    phandle_t node = ofw_bus_get_node(device);
    int length;
    const char *value;

    if (node == (phandle_t)-1)
        return 0;
    value = bsd_ofw_fdt_get_property(node, property, &length);
    return value && length > 0 && value[length - 1] == '\0' ?
        value : 0;
}

const char *
ofw_bus_get_compat(device_t device)
{
    const char *compatible = ofw_bus_string_property(
        device, "compatible");

    return compatible ? compatible :
        bsd_firmware_fdt_first_compatible(device);
}

const char *
ofw_bus_get_model(device_t device)
{
    return ofw_bus_string_property(device, "model");
}

const char *
ofw_bus_get_name(device_t device)
{
    phandle_t node = ofw_bus_get_node(device);
    const char *name;

    if (node != (phandle_t)-1 &&
        (name = bsd_ofw_fdt_get_name(node, 0)) != 0)
        return name;
    return device_get_name(device);
}

const char *
ofw_bus_get_type(device_t device)
{
    return ofw_bus_string_property(device, "device_type");
}

const char *
ofw_bus_get_status(device_t device)
{
    const char *status = ofw_bus_string_property(device, "status");

    if (status)
        return status;
    return bsd_firmware_status_okay(device) ? "okay" : "disabled";
}

int
ofw_bus_is_compatible_strict(device_t device, const char *compatible)
{
    const char *first = ofw_bus_get_compat(device);
    size_t length;

    if (!first || !compatible)
        return 0;
    length = bsd_strlen(compatible);
    return bsd_strlen(first) == length &&
        ofw_bus_string_equal(first, compatible);
}

const struct ofw_compat_data *
ofw_bus_search_compatible(device_t device,
    const struct ofw_compat_data *table)
{
    if (!table)
        return 0;
    while (table->ocd_str) {
        if (ofw_bus_is_compatible(device, table->ocd_str))
            break;
        ++table;
    }
    return table;
}

int
ofw_bus_has_prop(device_t device, const char *property)
{
    phandle_t node = ofw_bus_get_node(device);

    return node != (phandle_t)-1 && OF_hasprop(node, property);
}

device_t
ofw_bus_find_child_device_by_phandle(device_t bus, phandle_t node)
{
    device_t *children = 0;
    device_t result = 0;
    int count = 0;

    if (!bus || node == (phandle_t)-1 ||
        device_get_children(bus, &children, &count) != 0)
        return 0;
    for (int index = 0; index < count; ++index) {
        if (ofw_bus_get_node(children[index]) == node) {
            result = children[index];
            break;
        }
    }
    bsd_free(children, M_TEMP);
    return result;
}
