/* SPDX-License-Identifier: MPL-2.0 */
/* Supervisor aliases keep device registers independent of low user mappings. */
#ifndef EDGEOS_ARCH_ARM64_MMIO_H
#define EDGEOS_ARCH_ARM64_MMIO_H
#include <stdint.h>
#include "sys/mmio.h"

static inline int edgeos_arm64_mmio_alias_overlaps(uint64_t start,
                                                  uint64_t length) {
    uint64_t end = start + length;
    if (!length) return 0;
    if (end < start) return 1;
    return (start < EDGE_MMIO_LOW_ALIAS_BASE + EDGE_MMIO_LOW_ALIAS_SIZE &&
            end > EDGE_MMIO_LOW_ALIAS_BASE) ||
           (start < EDGE_MMIO_UNCACHED_ALIAS_BASE + EDGE_MMIO_UNCACHED_ALIAS_SIZE &&
            end > EDGE_MMIO_UNCACHED_ALIAS_BASE);
}

#if defined(__aarch64__) && !defined(BSD_BRIDGE_HOST_TEST) && !defined(EDGEOS_HOST_TEST)
uintptr_t edgeos_arm64_mmio_alias(uint64_t physical);
#else
static inline uintptr_t edgeos_arm64_mmio_alias(uint64_t physical) {
    return (uintptr_t)physical;
}
#endif
#endif
