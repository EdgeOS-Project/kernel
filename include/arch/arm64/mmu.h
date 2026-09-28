/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS ARM64 MMU interface. */
#ifndef EDGEOS_ARCH_ARM64_MMU_H
#define EDGEOS_ARCH_ARM64_MMU_H

#include "arch/arm64/bootinfo.h"

/* Installs the EL1 kernel translation regime from the UEFI memory map. */
int edgeos_arm64_mmu_init(const edgeos_arm64_bootinfo_t *bootinfo);

/* Extends the identity map for a firmware-described device resource. */
int edgeos_arm64_mmu_map_device_range(uint64_t start, uint64_t size);

#endif
