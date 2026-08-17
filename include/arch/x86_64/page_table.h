/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARCH_X86_64_PAGE_TABLE_H
#define EDGEOS_ARCH_X86_64_PAGE_TABLE_H

#include <stdint.h>

#include "sys/mmio.h"

/*
 * Hardware page-table entries contain physical addresses.  Kernel walkers
 * must use the low-physical direct-map alias because reclaimable page-table
 * pages can live above the legacy identity-mapped region.
 */
static inline void *x86_page_table_alias(uint64_t entry) {
    uint64_t physical = entry & 0x000ffffffffff000ULL;

    if (physical >= EDGE_MMIO_LOW_ALIAS_SIZE) return 0;
    return (void *)(uintptr_t)edge_mmio_low_alias(physical);
}

#endif
