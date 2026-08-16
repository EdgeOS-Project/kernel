/* SPDX-License-Identifier: MPL-2.0 */
/* Platform-device handoff contract for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_PLATFORM_H
#define EDGEOS_COMPAT_FREEBSD_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#ifdef _SYS_BUS_H_
#ifndef BSD_RESOURCE_INTERRUPT_SOURCE_OPS_DEFINED
#define BSD_RESOURCE_INTERRUPT_SOURCE_OPS_DEFINED
typedef struct {
    int (*enable)(void *context);
    int (*disable)(void *context);
    void *context;
    uint32_t interrupt_flags;
} bsd_resource_interrupt_source_ops_t;
#endif
#else
#include "newbus.h"
#include "resource.h"
#endif

#include "firmware.h"

typedef struct bsd_platform_resource {
    int type;
    int rid;
    uint64_t start;
    uint64_t count;
    unsigned int flags;
    bus_space_tag_t tag;
    const bsd_resource_interrupt_source_ops_t *interrupt_source;
    uint32_t interrupt_flags;
} bsd_platform_resource_t;

typedef struct bsd_platform_device {
    const char *name;
    int unit;
    unsigned int order;
    driver_t *driver;
    const bsd_platform_resource_t *resources;
    size_t resource_count;
    const bsd_firmware_description_t *firmware;
} bsd_platform_device_t;

int bsd_platform_add_bus(device_t parent, const char *name, int unit,
    device_t *result);
int bsd_platform_register_device(device_t parent,
    const bsd_platform_device_t *description, device_t *result);
int bsd_platform_attach_device(device_t device);
int bsd_platform_add_device(device_t parent,
    const bsd_platform_device_t *description, device_t *result);
int bsd_platform_remove_device(device_t parent, device_t device);

#endif
