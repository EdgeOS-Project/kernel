/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_VIRTIO_SOUND_MMIO_H
#define EDGEOS_VIRTIO_SOUND_MMIO_H

#include "arch/arm64/bootinfo.h"

int edgeos_arm64_virtio_sound_init(const edgeos_arm64_bootinfo_t *bootinfo);

#endif
