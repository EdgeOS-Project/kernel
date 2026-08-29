/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Kernel MMIO virtual address layout for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_SYS_MMIO_H
#define EDGEOS_SYS_MMIO_H

#include <stdint.h>

/*
 * EdgeOS preserves broad supervisor identity mappings for simple device BAR
 * access, but Linux-compatible userspace also owns selected low virtual ranges
 * for mmap(2).  q35 firmware commonly places PCIe ECAM at 0xb0000000, which is
 * inside the low userspace sparse-mmap window.  Kernel drivers must therefore
 * use this supervisor-only alias for low PCI/MMIO physical addresses instead
 * of dereferencing the raw physical address after a user task CR3 is active.
 */
#define EDGE_MMIO_LOW_ALIAS_PML4_INDEX 0x71u
#define EDGE_MMIO_LOW_ALIAS_BASE ((uint64_t)EDGE_MMIO_LOW_ALIAS_PML4_INDEX << 39)
/*
 * Cover the first 1 TiB of physical address space.  QEMU's q35 layout can put
 * 64-bit modern virtio BARs at 768 GiB when the guest has 4 GiB of RAM.  The
 * second PML4 slot keeps those resources available through the same linear,
 * supervisor-only alias after a userspace CR3 replaces the raw high identity
 * map with Linux mmap page tables.
 */
#define EDGE_MMIO_LOW_ALIAS_SIZE (1024ULL * 1024ULL * 1024ULL * 1024ULL)
#define EDGE_MMIO_LOW_ALIAS_PML4_COUNT \
    (EDGE_MMIO_LOW_ALIAS_SIZE / (512ULL * 1024ULL * 1024ULL * 1024ULL))

/*
 * QEMU/OVMF may allocate the 64-bit PCI resource aperture at 56 TiB.  x86-64
 * installs this 512 GiB physical window as a supervisor-only identity mapping
 * in both the boot and process page tables.  It is deliberately separate from
 * the low linear alias because extending that alias to 56 TiB would consume a
 * large page-table root in every address space for no additional coverage.
 */
#define EDGE_PCI_MMIO_HIGH_PML4_INDEX 0x70u
#define EDGE_PCI_MMIO_HIGH_BASE ((uint64_t)EDGE_PCI_MMIO_HIGH_PML4_INDEX << 39)
#define EDGE_PCI_MMIO_HIGH_SIZE (512ULL * 1024ULL * 1024ULL * 1024ULL)

/*
 * SeaBIOS on the i440FX machine places 64-bit PCI BARs in the 14 TiB
 * aperture.  That physical range overlaps the user sparse-mmap virtual
 * window, so expose it through a separate supervisor-only alias instead of
 * installing an identity mapping.
 */
#define EDGE_PCI_MMIO_I440FX_PHYS_BASE 0x00000E0000000000ULL
#define EDGE_PCI_MMIO_I440FX_SIZE (512ULL * 1024ULL * 1024ULL * 1024ULL)
#define EDGE_PCI_MMIO_I440FX_ALIAS_PML4_INDEX 0x73u
#define EDGE_PCI_MMIO_I440FX_ALIAS_BASE \
    ((uint64_t)EDGE_PCI_MMIO_I440FX_ALIAS_PML4_INDEX << 39)

static inline uintptr_t edge_mmio_low_alias(uint64_t phys) {
    if (phys < EDGE_MMIO_LOW_ALIAS_SIZE) {
        return (uintptr_t)(EDGE_MMIO_LOW_ALIAS_BASE + phys);
    }
    if (phys >= EDGE_PCI_MMIO_I440FX_PHYS_BASE &&
        phys < EDGE_PCI_MMIO_I440FX_PHYS_BASE +
            EDGE_PCI_MMIO_I440FX_SIZE) {
        return (uintptr_t)(EDGE_PCI_MMIO_I440FX_ALIAS_BASE +
            (phys - EDGE_PCI_MMIO_I440FX_PHYS_BASE));
    }
    return (uintptr_t)phys;
}

static inline int edge_mmio_phys_range_mapped(uint64_t phys, uint64_t size) {
    uint64_t end;
    if (size == 0 || phys > UINT64_MAX - (size - 1ULL)) return 0;
    end = phys + size - 1ULL;
    if (end < EDGE_MMIO_LOW_ALIAS_SIZE) return 1;
    if (phys >= EDGE_PCI_MMIO_HIGH_BASE &&
        end < EDGE_PCI_MMIO_HIGH_BASE + EDGE_PCI_MMIO_HIGH_SIZE) {
        return 1;
    }
    if (phys >= EDGE_PCI_MMIO_I440FX_PHYS_BASE &&
        end < EDGE_PCI_MMIO_I440FX_PHYS_BASE +
            EDGE_PCI_MMIO_I440FX_SIZE) {
        return 1;
    }
    return 0;
}

#endif
