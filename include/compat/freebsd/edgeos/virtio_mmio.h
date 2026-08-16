/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS platform frontend for the unmodified FreeBSD VirtIO MMIO driver. */

#ifndef EDGEOS_COMPAT_FREEBSD_VIRTIO_MMIO_H
#define EDGEOS_COMPAT_FREEBSD_VIRTIO_MMIO_H

#include <stdint.h>

#include "platform.h"

typedef struct bsd_virtio_mmio_description {
    uint64_t base;
    uint64_t size;
    uint32_t interrupt;
    uint32_t interrupt_flags;
    uint32_t unit;
    const bsd_resource_interrupt_source_ops_t *interrupt_source;
} bsd_virtio_mmio_description_t;

int bsd_virtio_mmio_attach(device_t parent,
    const bsd_virtio_mmio_description_t *description, device_t *result);
int bsd_virtio_mmio_detach(device_t parent, device_t device);

#endif
