/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS Bochs/QEMU BGA framebuffer driver.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This is original EdgeOS code based on the public Bochs VBE Dispi register
 * interface.  It is intentionally small: use the bootloader/GOP framebuffer
 * when firmware already provided one, and use BGA only as a real linear
 * framebuffer fallback.  Red flags:
 * - Do not expose BGA as supported unless the Dispi ID register answers.
 * - Do not mode-set over an existing boot framebuffer; that can blank QEMU
 *   while GRUB-provided fbcon is already working.
 * - Keep Linux userspace ABI on /dev/fb0 tied to fb.c; this driver only
 *   installs the underlying scanout memory.
 */

#include "drivers/bga.h"
#include "drivers/pci.h"
#include "fb.h"
#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "sys/mmio.h"

#include <stdint.h>

#define BGA_VENDOR_BOCHS_QEMU 0x1234u
#define BGA_DEVICE_VGA       0x1111u

#define BGA_INDEX_PORT 0x01CEu
#define BGA_DATA_PORT  0x01CFu

#define BGA_IDX_ID          0x00u
#define BGA_IDX_XRES        0x01u
#define BGA_IDX_YRES        0x02u
#define BGA_IDX_BPP         0x03u
#define BGA_IDX_ENABLE      0x04u
#define BGA_IDX_VIRT_WIDTH  0x06u
#define BGA_IDX_VIRT_HEIGHT 0x07u
#define BGA_IDX_X_OFFSET    0x08u
#define BGA_IDX_Y_OFFSET    0x09u

#define BGA_ID_MIN 0xB0C0u
#define BGA_ID_MAX 0xB0C5u
#define BGA_ENABLE 0x0001u
#define BGA_LFB    0x0040u

#define BGA_DEFAULT_WIDTH  1024u
#define BGA_DEFAULT_HEIGHT 768u
#define BGA_DEFAULT_BPP    32u

static int g_bga_available;
static uint64_t g_bga_lfb_phys;

static uint16_t bga_read(uint16_t index) {
    outports(BGA_INDEX_PORT, index);
    return inports(BGA_DATA_PORT);
}

static void bga_write(uint16_t index, uint16_t value) {
    outports(BGA_INDEX_PORT, index);
    outports(BGA_DATA_PORT, value);
}

static int bga_find_pci(uint8_t *bus_out, uint8_t *slot_out, uint8_t *func_out, uint32_t *bar0_out) {
    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint8_t slot = 0; slot < 32u; ++slot) {
            for (uint8_t func = 0; func < 8u; ++func) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, slot, func, 0x00);
                uint16_t device;
                uint8_t hdr;
                if (vendor == PCI_VENDOR_INVALID) continue;
                device = pci_cfg_read16((uint8_t)bus, slot, func, 0x02);
                if (vendor == BGA_VENDOR_BOCHS_QEMU && device == BGA_DEVICE_VGA) {
                    if (bus_out) *bus_out = (uint8_t)bus;
                    if (slot_out) *slot_out = slot;
                    if (func_out) *func_out = func;
                    if (bar0_out) *bar0_out = pci_read_bar((uint8_t)bus, slot, func, 0);
                    return 0;
                }
                if (func == 0) {
                    hdr = pci_header_type((uint8_t)bus, slot, func);
                    if ((hdr & 0x80u) == 0) break;
                }
            }
        }
    }
    return -1;
}

int bga_available(void) {
    return g_bga_available;
}

int bga_init(int framebuffer_already_active) {
    uint8_t bus = 0, slot = 0, func = 0;
    uint32_t bar0 = 0;
    uint16_t id;
    uint64_t lfb;

    if (bga_find_pci(&bus, &slot, &func, &bar0) < 0) return -1;
    id = bga_read(BGA_IDX_ID);
    if (id < BGA_ID_MIN || id > BGA_ID_MAX) {
        printf("[bga] PCI device present but Dispi ID invalid: 0x%x\n", id);
        return -1;
    }

    g_bga_available = 1;
    if ((bar0 & 0x1u) != 0 || (bar0 & ~0x0fu) == 0) {
        printf("[bga] detected %02x:%02x.%u id=0x%x without usable LFB BAR0=0x%x\n",
               (uint32_t)bus, (uint32_t)slot, (uint32_t)func, id, bar0);
        return framebuffer_already_active ? 0 : -1;
    }
    lfb = (uint64_t)(bar0 & ~0x0fu);
    g_bga_lfb_phys = lfb;

    if (framebuffer_already_active) {
        printf("[bga] detected %02x:%02x.%u id=0x%x lfb=0x%llx, keeping boot framebuffer\n",
               (uint32_t)bus, (uint32_t)slot, (uint32_t)func, id,
               (unsigned long long)lfb);
        return 0;
    }

    bga_write(BGA_IDX_ENABLE, 0);
    bga_write(BGA_IDX_XRES, BGA_DEFAULT_WIDTH);
    bga_write(BGA_IDX_YRES, BGA_DEFAULT_HEIGHT);
    bga_write(BGA_IDX_BPP, BGA_DEFAULT_BPP);
    bga_write(BGA_IDX_VIRT_WIDTH, BGA_DEFAULT_WIDTH);
    bga_write(BGA_IDX_VIRT_HEIGHT, BGA_DEFAULT_HEIGHT);
    bga_write(BGA_IDX_X_OFFSET, 0);
    bga_write(BGA_IDX_Y_OFFSET, 0);
    bga_write(BGA_IDX_ENABLE, BGA_ENABLE | BGA_LFB);

    fb_install_physical(lfb, (uint8_t *)edge_mmio_low_alias(lfb),
                        BGA_DEFAULT_WIDTH, BGA_DEFAULT_HEIGHT,
                        BGA_DEFAULT_WIDTH * 4u, BGA_DEFAULT_BPP,
                        16, 8, 0, 0x00FF0000u, 0x0000FF00u, 0x000000FFu);
    printf("[bga] installed framebuffer %ux%ux%u lfb=0x%llx\n",
           BGA_DEFAULT_WIDTH, BGA_DEFAULT_HEIGHT, BGA_DEFAULT_BPP,
           (unsigned long long)g_bga_lfb_phys);
    return 0;
}
