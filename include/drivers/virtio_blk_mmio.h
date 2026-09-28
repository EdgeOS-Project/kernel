/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 virtio-mmio block transport. */

#ifndef EDGEOS_DRIVERS_VIRTIO_BLK_MMIO_H
#define EDGEOS_DRIVERS_VIRTIO_BLK_MMIO_H

#include "arch/arm64/bootinfo.h"

int edgeos_arm64_virtio_blk_init(const edgeos_arm64_bootinfo_t *bootinfo);
int edgeos_arm64_virtio_blk_enable_interrupts(void);

#endif
