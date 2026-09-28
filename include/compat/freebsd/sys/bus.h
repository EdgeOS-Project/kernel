/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS newbus include-order adapter for unmodified FreeBSD drivers.
 *
 * FreeBSD's normal kernel include graph makes moduledata_t and the module
 * declaration macros visible before sys/bus.h expands DRIVER_MODULE().
 * Imported drivers do not all include sys/module.h explicitly, so establish
 * that invariant here and then expose the complete upstream newbus header.
 */

#ifndef EDGEOS_COMPAT_FREEBSD_SYS_BUS_H
#define EDGEOS_COMPAT_FREEBSD_SYS_BUS_H

#include "module.h"
#include_next <sys/bus.h>

ssize_t bsd_bus_get_property(device_t parent, device_t child,
    const char *name, void *value, size_t size,
    device_property_type_t type);

#endif
