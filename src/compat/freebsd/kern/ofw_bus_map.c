/* SPDX-License-Identifier: MPL-2.0 */
/* Shared Open Firmware interrupt and requester mapping helpers. */

#include <stddef.h>

#include "compat/freebsd/edgeos/ofw.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/dev/ofw/ofw_bus_subr.h"

#define BSD_OFW_BUS_ENOENT 2
#define BSD_OFW_BUS_EINVAL 22
#define BSD_OFW_BUS_MAX_MAP_KEY_BYTES 256

void
ofw_bus_setup_iinfo(phandle_t node, struct ofw_bus_iinfo *info,
    int interrupt_cell_size)
{
    pcell_t address_cells = 2;
    ssize_t map_size;
    ssize_t mask_size;

    if (!info)
        return;
    bsd_memset(info, 0, sizeof(*info));
    if (OF_getencprop(node, "#address-cells", &address_cells,
        sizeof(address_cells)) < 0)
        address_cells = 2;
    if (address_cells > INT32_MAX / sizeof(pcell_t) ||
        interrupt_cell_size < 0)
        bsd_panic("ofw_bus_setup_iinfo: invalid map key size");
    info->opi_addrc = address_cells * sizeof(pcell_t);
    map_size = OF_getencprop_alloc(node, "interrupt-map",
        (void **)&info->opi_imap);
    if (map_size <= 0)
        return;
    if (map_size > INT32_MAX)
        bsd_panic("ofw_bus_setup_iinfo: interrupt-map is too large");
    info->opi_imapsz = (int)map_size;
    mask_size = OF_getencprop_alloc(node, "interrupt-map-mask",
        (void **)&info->opi_imapmsk);
    if (mask_size >= 0 &&
        mask_size != (ssize_t)info->opi_addrc + interrupt_cell_size)
        bsd_panic("ofw_bus_setup_iinfo: invalid interrupt-map-mask size");
}

void
ofw_bus_destroy_iinfo(struct ofw_bus_iinfo *info)
{
    if (!info)
        return;
    OF_prop_free(info->opi_imapmsk);
    OF_prop_free(info->opi_imap);
    bsd_memset(info, 0, sizeof(*info));
}

int
ofw_bus_lookup_imap(phandle_t node, struct ofw_bus_iinfo *info,
    void *registers, int register_size, void *interrupt,
    int interrupt_size, void *result, int result_size,
    phandle_t *interrupt_parent)
{
    uint8_t mask_buffer[BSD_OFW_BUS_MAX_MAP_KEY_BYTES];

    if (!info || info->opi_imapsz <= 0)
        return 0;
    if (!registers || !interrupt || !result || register_size < 0 ||
        interrupt_size < 0 || result_size < 0 ||
        register_size < (int)info->opi_addrc ||
        (size_t)info->opi_addrc + (size_t)interrupt_size >
            sizeof(mask_buffer))
        return 0;
    if (node != (phandle_t)-1 &&
        OF_getencprop(node, "reg", registers, register_size) <
            register_size)
        return 0;
    return ofw_bus_search_intrmap(interrupt, interrupt_size, registers,
        info->opi_addrc, info->opi_imap, info->opi_imapsz,
        info->opi_imapmsk, mask_buffer, result, result_size,
        interrupt_parent);
}

int
ofw_bus_search_intrmap(void *interrupt, int interrupt_size,
    void *registers, int physical_size, void *map, int map_size,
    void *mask, void *mask_buffer, void *result, int result_size,
    phandle_t *interrupt_parent)
{
    uint8_t *key = mask_buffer;
    uint8_t *map_cursor = map;
    const uint8_t *interrupt_bytes = interrupt;
    const uint8_t *register_bytes = registers;
    const uint8_t *mask_bytes = mask;
    int remaining = map_size;

    if (!interrupt || !registers || !map || !mask_buffer || !result ||
        interrupt_size < 0 || physical_size < 0 || map_size < 0 ||
        result_size < 0)
        return 0;
    if ((size_t)physical_size + (size_t)interrupt_size >
        BSD_OFW_BUS_MAX_MAP_KEY_BYTES)
        return 0;
    for (int index = 0; index < physical_size; ++index)
        key[index] = mask_bytes ?
            register_bytes[index] & mask_bytes[index] :
            register_bytes[index];
    for (int index = 0; index < interrupt_size; ++index)
        key[physical_size + index] = mask_bytes ?
            interrupt_bytes[index] & mask_bytes[physical_size + index] :
            interrupt_bytes[index];

    while (remaining > 0) {
        phandle_t parent;
        pcell_t parent_address_cells = 0;
        pcell_t parent_interrupt_cells = 1;
        int parent_address_size;
        int parent_interrupt_size;
        int stride;

        if (remaining < physical_size + interrupt_size +
            (int)sizeof(parent))
            return 0;
        bsd_memcpy(&parent,
            map_cursor + physical_size + interrupt_size, sizeof(parent));
        (void)OF_getencprop(OF_node_from_xref(parent), "#address-cells",
            &parent_address_cells, sizeof(parent_address_cells));
        if (OF_searchencprop(OF_node_from_xref(parent),
            "#interrupt-cells", &parent_interrupt_cells,
            sizeof(parent_interrupt_cells)) < 0)
            parent_interrupt_cells = 1;
        if (parent_address_cells > INT32_MAX / sizeof(pcell_t) ||
            parent_interrupt_cells > INT32_MAX / sizeof(pcell_t))
            return 0;
        parent_address_size = parent_address_cells * sizeof(pcell_t);
        parent_interrupt_size = parent_interrupt_cells * sizeof(pcell_t);
        if (physical_size > INT32_MAX - interrupt_size -
            (int)sizeof(parent) || parent_address_size > INT32_MAX -
            physical_size - interrupt_size - (int)sizeof(parent) ||
            parent_interrupt_size > INT32_MAX - physical_size -
            interrupt_size - (int)sizeof(parent) - parent_address_size)
            return 0;
        stride = physical_size + interrupt_size + sizeof(parent) +
            parent_address_size + parent_interrupt_size;
        if (stride <= 0 || remaining < stride)
            return 0;
        if (bsd_memcmp(key, map_cursor,
            physical_size + interrupt_size) == 0) {
            int copy_size = result_size < parent_interrupt_size ?
                result_size : parent_interrupt_size;

            bsd_memcpy(result, map_cursor + physical_size + interrupt_size +
                sizeof(parent) + parent_address_size, copy_size);
            if (interrupt_parent)
                *interrupt_parent = parent;
            return parent_interrupt_cells;
        }
        map_cursor += stride;
        remaining -= stride;
    }
    return 0;
}

static int
ofw_bus_map_requester(phandle_t node, const char *map_property,
    const char *mask_property, uint16_t requester_id,
    phandle_t *mapped_parent, uint32_t *mapped_requester_id,
    int pass_through_when_absent)
{
    pcell_t *map = 0;
    pcell_t mask = UINT32_MAX;
    uint32_t masked_requester;
    ssize_t cell_count;

    cell_count = OF_getencprop_alloc_multi(node, map_property,
        sizeof(*map), (void **)&map);
    if (cell_count < 0) {
        if (!pass_through_when_absent)
            return BSD_OFW_BUS_ENOENT;
        if (mapped_parent) {
            *mapped_parent = 0;
            (void)OF_getencprop(node, "msi-parent", mapped_parent,
                sizeof(*mapped_parent));
        }
        if (mapped_requester_id)
            *mapped_requester_id = requester_id;
        return 0;
    }
    if (cell_count == 0 || (cell_count % 4) != 0) {
        OF_prop_free(map);
        return BSD_OFW_BUS_EINVAL;
    }
    (void)OF_getencprop(node, mask_property, &mask, sizeof(mask));
    masked_requester = requester_id & mask;
    for (ssize_t index = 0; index < cell_count; index += 4) {
        uint32_t requester_base = map[index];
        uint32_t mapped_base = map[index + 2];
        uint32_t requester_count = map[index + 3];

        if (masked_requester < requester_base || requester_count == 0 ||
            masked_requester - requester_base >= requester_count)
            continue;
        if (mapped_parent)
            *mapped_parent = map[index + 1];
        if (mapped_requester_id)
            *mapped_requester_id = masked_requester - requester_base +
                mapped_base;
        OF_prop_free(map);
        return 0;
    }
    OF_prop_free(map);
    return BSD_OFW_BUS_ENOENT;
}

int
ofw_bus_msimap(phandle_t node, uint16_t requester_id,
    phandle_t *msi_parent, uint32_t *msi_requester_id)
{
    return ofw_bus_map_requester(node, "msi-map", "msi-map-mask",
        requester_id, msi_parent, msi_requester_id, 1);
}

int
ofw_bus_iommu_map(phandle_t node, uint16_t requester_id,
    phandle_t *iommu_parent, uint32_t *iommu_requester_id)
{
    return ofw_bus_map_requester(node, "iommu-map", "iommu-map-mask",
        requester_id, iommu_parent, iommu_requester_id, 0);
}
