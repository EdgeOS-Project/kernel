/* SPDX-License-Identifier: MPL-2.0 */
/* Non-attaching Device Tree inventory for controlled BSD driver ownership. */

#ifndef EDGEOS_COMPAT_FREEBSD_FDT_INVENTORY_H
#define EDGEOS_COMPAT_FREEBSD_FDT_INVENTORY_H

#include <stddef.h>

#include "newbus.h"
#include "../dev/ofw/openfirm.h"

typedef struct bsd_fdt_inventory_status {
    device_t bus;
    size_t nodes_seen;
    size_t devices_registered;
    size_t buses_registered;
    size_t disabled_nodes;
    size_t unsupported_nodes;
    size_t memory_resources;
    size_t interrupt_resources;
    size_t unresolved_resources;
} bsd_fdt_inventory_status_t;

int bsd_fdt_inventory_register(device_t root,
    bsd_fdt_inventory_status_t *status);
int bsd_fdt_inventory_unregister(device_t root);
void bsd_fdt_inventory_get_status(
    bsd_fdt_inventory_status_t *status);
device_t bsd_fdt_inventory_find(phandle_t node);
int bsd_fdt_inventory_claim(phandle_t node, driver_t *driver,
    device_t *result);
int bsd_fdt_inventory_release(phandle_t node);

#endif
