/* SPDX-License-Identifier: MPL-2.0 */
/* Shared OFW bus helpers for imported BSD attachment frontends. */

#ifndef EDGEOS_COMPAT_FREEBSD_OFW_BUS_SUBR_H
#define EDGEOS_COMPAT_FREEBSD_OFW_BUS_SUBR_H

#include "../../sys/module.h"

#include "ofw_bus.h"

struct resource_list;
struct sbuf;

struct ofw_bus_iinfo {
    uint8_t *opi_imap;
    uint8_t *opi_imapmsk;
    int opi_imapsz;
    pcell_t opi_addrc;
};

#ifdef INTRNG
#include <sys/intr.h>

struct intr_map_data_fdt {
    struct intr_map_data hdr;
    phandle_t iparent;
    u_int ncells;
    pcell_t cells[];
};
#endif

struct ofw_compat_data {
    const char *ocd_str;
    uintptr_t ocd_data;
};

#define FDTCOMPAT_PNP_DESCR "Z:compat;P:#;"
#define FDTCOMPAT_PNP_INFO(table, bus_name)                              \
    MODULE_PNP_INFO(FDTCOMPAT_PNP_DESCR, bus_name, table, table,        \
        sizeof(table) / sizeof((table)[0]))
#define OFWBUS_PNP_INFO(table) FDTCOMPAT_PNP_INFO(table, ofwbus)
#define SIMPLEBUS_PNP_INFO(table) FDTCOMPAT_PNP_INFO(table, simplebus)

int ofw_bus_gen_setup_devinfo(struct ofw_bus_devinfo *devinfo,
    phandle_t node);
void ofw_bus_gen_destroy_devinfo(struct ofw_bus_devinfo *devinfo);
const char *ofw_bus_gen_get_compat(device_t bus, device_t device);
const char *ofw_bus_gen_get_model(device_t bus, device_t device);
const char *ofw_bus_gen_get_name(device_t bus, device_t device);
phandle_t ofw_bus_gen_get_node(device_t bus, device_t device);
const char *ofw_bus_gen_get_type(device_t bus, device_t device);
int ofw_bus_gen_child_pnpinfo(device_t bus, device_t child,
    struct sbuf *buffer);
int ofw_bus_gen_get_device_path(device_t bus, device_t child,
    const char *locator, struct sbuf *buffer);
int ofw_bus_reg_to_rl(device_t device, phandle_t node,
    pcell_t address_cells, pcell_t size_cells,
    struct resource_list *resources);
int ofw_bus_intr_to_rl(device_t device, phandle_t node,
    struct resource_list *resources, int *resource_count);
void ofw_bus_setup_iinfo(phandle_t node, struct ofw_bus_iinfo *info,
    int interrupt_cell_size);
void ofw_bus_destroy_iinfo(struct ofw_bus_iinfo *info);
int ofw_bus_lookup_imap(phandle_t node, struct ofw_bus_iinfo *info,
    void *registers, int register_size, void *interrupt, int interrupt_size,
    void *result, int result_size, phandle_t *interrupt_parent);
int ofw_bus_search_intrmap(void *interrupt, int interrupt_size,
    void *registers, int physical_size, void *map, int map_size,
    void *mask, void *mask_buffer, void *result, int result_size,
    phandle_t *interrupt_parent);
int ofw_bus_msimap(phandle_t node, uint16_t requester_id,
    phandle_t *msi_parent, uint32_t *msi_requester_id);
int ofw_bus_iommu_map(phandle_t node, uint16_t requester_id,
    phandle_t *iommu_parent, uint32_t *iommu_requester_id);

const char *ofw_bus_get_status(device_t device);
int ofw_bus_node_status_okay(phandle_t node);
int ofw_bus_is_compatible_strict(device_t device,
    const char *compatible);
int ofw_bus_node_is_compatible(phandle_t node,
    const char *compatible);
bool ofw_bus_is_machine_compatible(const char *compatible);
const struct ofw_compat_data *ofw_bus_search_compatible(device_t device,
    const struct ofw_compat_data *table);
int ofw_bus_has_prop(device_t device, const char *property);
phandle_t ofw_bus_find_compatible(phandle_t node,
    const char *compatible);
phandle_t ofw_bus_find_child(phandle_t node, const char *name);
int ofw_bus_find_string_index(phandle_t node, const char *list_name,
    const char *name, int *index);
int ofw_bus_parse_xref_list_alloc(phandle_t node, const char *list_name,
    const char *cells_name, int index, phandle_t *producer,
    int *cell_count, pcell_t **cells);
int ofw_bus_parse_xref_list_get_length(phandle_t node,
    const char *list_name, const char *cells_name, int *count);
int ofw_bus_string_list_to_array(phandle_t node,
    const char *list_name, const char ***array);
device_t ofw_bus_find_child_device_by_phandle(device_t bus,
    phandle_t node);

#endif
