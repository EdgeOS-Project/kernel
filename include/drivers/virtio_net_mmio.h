/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_ARM64_VIRTIO_NET_H
#define EDGEOS_ARCH_ARM64_VIRTIO_NET_H

#include "arch/arm64/bootinfo.h"

int edgeos_arm64_virtio_net_init(const edgeos_arm64_bootinfo_t *bootinfo);
int edgeos_arm64_virtio_net_enable_interrupts(void);
int edgeos_arm64_virtio_net_stop(void);
int edgeos_arm64_virtio_net_resume(void);
int edgeos_arm64_virtio_mmio_aperture(const edgeos_arm64_bootinfo_t *bootinfo,
                                      uint64_t *base_out);
int edgeos_arm64_virtio_mmio_find(const edgeos_arm64_bootinfo_t *bootinfo,
                                  uint32_t device_id, uint64_t *base_out);
int edgeos_arm64_virtio_mmio_find_nth(const edgeos_arm64_bootinfo_t *bootinfo,
                                      uint32_t device_id, uint32_t match_index,
                                      uint64_t *base_out);
int edgeos_arm64_virtio_mmio_find_nth_irq(
    const edgeos_arm64_bootinfo_t *bootinfo, uint32_t device_id,
    uint32_t match_index, uint64_t *base_out, uint32_t *interrupt_out,
    uint32_t *interrupt_flags_out);
int edgeos_arm64_virtio_mmio_describe_nth(
    const edgeos_arm64_bootinfo_t *bootinfo, uint32_t device_id,
    uint32_t match_index, uint64_t *base_out, uint64_t *size_out,
    uint32_t *interrupt_out, uint32_t *interrupt_flags_out);

#endif
