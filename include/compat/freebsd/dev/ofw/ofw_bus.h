/* SPDX-License-Identifier: MPL-2.0 */
/* OFW attachment helpers backed by the EdgeOS firmware bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_OFW_BUS_H
#define EDGEOS_COMPAT_FREEBSD_OFW_BUS_H

#ifdef BSD_BRIDGE_HOST_TEST
#include "../../edgeos/newbus.h"
#else
#include <sys/bus.h>
#endif

#include "openfirm.h"
#include "ofw_bus_if.h"

const char *ofw_bus_get_compat(device_t device);
const char *ofw_bus_get_model(device_t device);
const char *ofw_bus_get_name(device_t device);
phandle_t ofw_bus_get_node(device_t device);
const char *ofw_bus_get_type(device_t device);

int ofw_bus_status_okay(device_t device);
int ofw_bus_is_compatible(device_t device, const char *compatible);

static __inline int
ofw_bus_map_intr(device_t device, phandle_t parent, int cell_count,
    pcell_t *cells)
{
    return OFW_BUS_MAP_INTR(
        device, device, parent, cell_count, cells);
}

#endif
