/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS Intel integrated graphics probe.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This is original EdgeOS code.  It deliberately stops at real PCI/MMIO
 * discovery until EdgeOS has the GEM/TTM, display pipe, interrupt, and
 * modesetting infrastructure needed for a full Linux-compatible i915-style
 * driver.  Red flag: do not expose acceleration or DRM success from this file.
 */

#include "drivers/intel_graphics.h"
#include "drivers/pci.h"
#include "stdio.h"
#include "sys/mmio.h"

#include <stdint.h>

#define PCI_VENDOR_INTEL 0x8086u
#define PCI_COMMAND_MEM  0x0002u
#define PCI_COMMAND_BUSM 0x0004u

#define GEN_GMCH_CTRL          0x50u
#define GEN_GMCH_GMS_MASK      0x00F0u
#define GEN_GMCH_GMS_SHIFT     4u

#define INTEL_DISPLAY_MMIO_MIN 0x100000u

static uint64_t pci_mmio_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t index) {
    uint8_t off;
    uint32_t lo;

    if (index >= 6u) return 0;
    off = (uint8_t)(0x10u + index * 4u);
    lo = pci_cfg_read32(bus, slot, func, off);
    if ((lo & 1u) || (lo & ~0xFu) == 0) return 0;
    if (((lo >> 1) & 0x3u) == 0x2u && index < 5u) {
        uint32_t hi = pci_cfg_read32(bus, slot, func, (uint8_t)(off + 4u));
        return ((uint64_t)hi << 32) | (uint64_t)(lo & ~0xFu);
    }
    return (uint64_t)(lo & ~0xFu);
}

static int is_intel_display_class(uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t cls = pci_cfg_read32(bus, slot, func, 0x08);
    uint8_t class_code = (uint8_t)(cls >> 24);
    uint8_t subclass = (uint8_t)(cls >> 16);
    return class_code == 0x03u && (subclass == 0x00u || subclass == 0x02u);
}

int intel_graphics_probe_init(int framebuffer_already_active) {
    for (uint32_t bus32 = 0; bus32 < 256u; ++bus32) {
        uint8_t bus = (uint8_t)bus32;
        for (uint8_t slot = 0; slot < 32u; ++slot) {
            for (uint8_t func = 0; func < 8u; ++func) {
                uint16_t vendor = pci_cfg_read16(bus, slot, func, 0x00);
                uint16_t device;
                uint16_t cmd;
                uint16_t gmch;
                uint64_t mmio_phys;
                volatile uint8_t *mmio;
                uint32_t devid_reg;
                uint8_t hdr;

                if (vendor == PCI_VENDOR_INVALID) continue;
                if (vendor != PCI_VENDOR_INTEL || !is_intel_display_class(bus, slot, func)) {
                    if (func == 0) {
                        hdr = pci_header_type(bus, slot, func);
                        if ((hdr & 0x80u) == 0) break;
                    }
                    continue;
                }

                device = pci_cfg_read16(bus, slot, func, 0x02);
                mmio_phys = pci_mmio_bar(bus, slot, func, 0);
                if (!mmio_phys) {
                    printf("[drm] i915: Intel GPU %04x at %u:%u.%u has no MMIO BAR0\n",
                           device, bus, slot, func);
                    return -1;
                }

                cmd = pci_cfg_read16(bus, slot, func, 0x04);
                pci_cfg_write16(bus, slot, func, (uint8_t)0x04, (uint16_t)(cmd | PCI_COMMAND_MEM | PCI_COMMAND_BUSM));

                /*
                 * BAR sizing is not available without destructive PCI probing.
                 * The first MiB is enough for the common display identity and
                 * control register aperture used by Gen graphics families.
                 */
                if ((mmio_phys & 0xFFFu) != 0) {
                    printf("[drm] i915: unaligned MMIO BAR0=0x%llx device=%04x\n",
                           (unsigned long long)mmio_phys, device);
                    return -1;
                }
                (void)INTEL_DISPLAY_MMIO_MIN;
                mmio = (volatile uint8_t *)edge_mmio_low_alias(mmio_phys);
                devid_reg = *(volatile uint32_t *)(mmio + 0x2u);
                gmch = pci_cfg_read16(bus, slot, func, GEN_GMCH_CTRL);

                printf("[drm] i915: partial Intel graphics probe device=%04x bus=%u dev=%u fn=%u mmio=0x%llx fb_active=%d stolen_mem_code=%u devid_reg=0x%x\n",
                       device, bus, slot, func, (unsigned long long)mmio_phys,
                       framebuffer_already_active ? 1 : 0,
                       (uint32_t)((gmch & GEN_GMCH_GMS_MASK) >> GEN_GMCH_GMS_SHIFT),
                       devid_reg);
                return 0;
            }
        }
    }
    printf("[drm] i915: no Intel integrated graphics PCI device found\n");
    return -1;
}
