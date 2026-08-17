/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS handoff adapter for the unmodified FreeBSD VirtIO MMIO frontend. */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>

#include "compat/freebsd/edgeos/platform.h"
#include "compat/freebsd/edgeos/virtio_mmio.h"
#include "compat/freebsd/machine/resource.h"

#define BSD_VIRTIO_MMIO_EINVAL 22

int
bsd_virtio_mmio_attach(device_t parent,
    const bsd_virtio_mmio_description_t *description, device_t *result)
{
    static const char *const compatible[] = {
        "virtio,mmio",
    };
    bsd_firmware_description_t firmware = {
        .kind = BSD_FIRMWARE_FDT,
        .enabled = 1,
        .compatible = compatible,
        .compatible_count = sizeof(compatible) / sizeof(compatible[0]),
    };
    bsd_platform_resource_t resources[2];
    bsd_platform_device_t device;
    device_t bus = 0;
    int error;

    if (result)
        *result = 0;
    if (!parent || !description || !result || description->size == 0 ||
        description->unit > (uint32_t)INT32_MAX)
        return BSD_VIRTIO_MMIO_EINVAL;

    resources[0] = (bsd_platform_resource_t) {
        .type = SYS_RES_MEMORY,
        .rid = 0,
        .start = description->base,
        .count = description->size,
    };
    resources[1] = (bsd_platform_resource_t) {
        .type = SYS_RES_IRQ,
        .rid = 0,
        .start = description->interrupt,
        .count = 1,
        .interrupt_source = description->interrupt_source,
        .interrupt_flags = description->interrupt_flags,
    };
    device = (bsd_platform_device_t) {
        .name = "virtio_mmio",
        .unit = (int)description->unit,
        .resources = resources,
        .resource_count = sizeof(resources) / sizeof(resources[0]),
        .firmware = &firmware,
    };
    error = bsd_platform_add_bus(parent, "simplebus",
        DEVICE_UNIT_ANY, &bus);
    if (error)
        return error;
    error = bsd_platform_add_device(bus, &device, result);
    if (error)
        (void)bsd_platform_remove_device(parent, bus);
    return error;
}

int
bsd_virtio_mmio_detach(device_t parent, device_t device)
{
    device_t bus;

    if (!parent || !device)
        return BSD_VIRTIO_MMIO_EINVAL;
    bus = device_get_parent(device);
    if (!bus || device_get_parent(bus) != parent ||
        !device_get_name(bus) ||
        strcmp(device_get_name(bus), "simplebus") != 0)
        return BSD_VIRTIO_MMIO_EINVAL;
    return bsd_platform_remove_device(parent, bus);
}
