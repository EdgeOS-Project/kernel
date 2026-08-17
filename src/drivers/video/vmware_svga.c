/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS VMware SVGA framebuffer driver.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * VMware SVGA II PCI register interface support.
 *
 * It only installs a linear true-color framebuffer; accelerated
 * FIFO commands and DRM ioctls are separate Linux ABI work and must not be
 * faked here.
 */

#include "drivers/vmware_svga.h"
#include "drivers/pci.h"
#include "fb.h"
#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "sys/mmio.h"

#include <stdint.h>

#define VMWARE_VENDOR_ID 0x15ADu
#define VMWARE_SVGA2_DEVICE_ID 0x0405u

#define PCI_COMMAND_IO     0x0001u
#define PCI_COMMAND_MEM    0x0002u

#define SVGA_INDEX_PORT    0x0u
#define SVGA_VALUE_PORT    0x1u

#define SVGA_ID_INVALID    0xFFFFFFFFu
#define SVGA_ID_0          0x90000000u
#define SVGA_ID_1          0x90000001u
#define SVGA_ID_2          0x90000002u

#define SVGA_REG_ID              0u
#define SVGA_REG_ENABLE          1u
#define SVGA_REG_WIDTH           2u
#define SVGA_REG_HEIGHT          3u
#define SVGA_REG_MAX_WIDTH       4u
#define SVGA_REG_MAX_HEIGHT      5u
#define SVGA_REG_DEPTH           6u
#define SVGA_REG_BITS_PER_PIXEL  7u
#define SVGA_REG_RED_MASK        9u
#define SVGA_REG_GREEN_MASK      10u
#define SVGA_REG_BLUE_MASK       11u
#define SVGA_REG_BYTES_PER_LINE  12u
#define SVGA_REG_FB_START        13u
#define SVGA_REG_FB_SIZE         16u
#define SVGA_REG_MEM_START       18u
#define SVGA_REG_MEM_SIZE        19u
#define SVGA_REG_CONFIG_DONE     20u
#define SVGA_REG_SYNC            21u
#define SVGA_REG_BUSY            22u
#define SVGA_REG_GUEST_ID        23u
#define SVGA_REG_PITCHLOCK       32u

#define SVGA_DEFAULT_WIDTH  1024u
#define SVGA_DEFAULT_HEIGHT 768u
#define SVGA_DEFAULT_BPP    32u

static int g_svga_available;

static uint32_t svga_read(uint16_t io_base, uint32_t index) {
    outportl((uint16_t)(io_base + SVGA_INDEX_PORT), index);
    return inportl((uint16_t)(io_base + SVGA_VALUE_PORT));
}

static void svga_write(uint16_t io_base, uint32_t index, uint32_t value) {
    outportl((uint16_t)(io_base + SVGA_INDEX_PORT), index);
    outportl((uint16_t)(io_base + SVGA_VALUE_PORT), value);
}

static int svga_find_pci(uint8_t *bus_out, uint8_t *slot_out, uint8_t *func_out,
                         uint32_t *io_bar_out, uint32_t *fb_bar_out) {
    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint8_t slot = 0; slot < 32u; ++slot) {
            for (uint8_t func = 0; func < 8u; ++func) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, slot, func, 0x00);
                uint16_t device;
                uint8_t hdr;
                if (vendor == PCI_VENDOR_INVALID) continue;
                device = pci_cfg_read16((uint8_t)bus, slot, func, 0x02);
                if (vendor == VMWARE_VENDOR_ID && device == VMWARE_SVGA2_DEVICE_ID) {
                    if (bus_out) *bus_out = (uint8_t)bus;
                    if (slot_out) *slot_out = slot;
                    if (func_out) *func_out = func;
                    if (io_bar_out) *io_bar_out = pci_read_bar((uint8_t)bus, slot, func, 0);
                    if (fb_bar_out) *fb_bar_out = pci_read_bar((uint8_t)bus, slot, func, 1);
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

static uint32_t svga_negotiate_id(uint16_t io_base) {
    svga_write(io_base, SVGA_REG_ID, SVGA_ID_2);
    if (svga_read(io_base, SVGA_REG_ID) == SVGA_ID_2) return SVGA_ID_2;
    svga_write(io_base, SVGA_REG_ID, SVGA_ID_1);
    if (svga_read(io_base, SVGA_REG_ID) == SVGA_ID_1) return SVGA_ID_1;
    svga_write(io_base, SVGA_REG_ID, SVGA_ID_0);
    if (svga_read(io_base, SVGA_REG_ID) == SVGA_ID_0) return SVGA_ID_0;
    return SVGA_ID_INVALID;
}

static int svga_wait_not_busy(uint16_t io_base) {
    /*
     * A framebuffer driver must never leave early boot stuck in an
     * unbounded device wait.  If the controller is broken, misconfigured,
     * or emulated differently than expected, fail the SVGA install path and
     * keep the already available boot console behavior intact.
     */
    for (uint32_t i = 0; i < 10000000u; ++i) {
        if (!svga_read(io_base, SVGA_REG_BUSY)) return 0;
    }
    return -1;
}

int vmware_svga_available(void) {
    return g_svga_available;
}

int vmware_svga_init(int framebuffer_already_active) {
    uint8_t bus = 0, slot = 0, func = 0;
    uint32_t io_bar = 0, fb_bar = 0;
    uint16_t io_base;
    uint32_t id;
    uint32_t max_w, max_h;
    uint32_t width = SVGA_DEFAULT_WIDTH;
    uint32_t height = SVGA_DEFAULT_HEIGHT;
    uint32_t fb_phys;
    uint32_t pitch;
    uint16_t cmd;

    if (svga_find_pci(&bus, &slot, &func, &io_bar, &fb_bar) < 0) return -1;
    if ((io_bar & 0x1u) == 0 || (io_bar & ~0x3u) == 0) {
        printf("[vmw-svga] invalid IO BAR0=0x%x\n", io_bar);
        return -1;
    }
    io_base = (uint16_t)(io_bar & ~0x3u);

    /*
     * Firmware is not required to leave VGA-compatible PCI devices with BAR
     * decoding enabled.  Enable only the resources this driver actually uses
     * before touching the SVGA register port or framebuffer BAR.
     */
    cmd = pci_cfg_read16(bus, slot, func, 0x04);
    cmd |= PCI_COMMAND_IO | PCI_COMMAND_MEM;
    pci_cfg_write16(bus, slot, func, 0x04, cmd);

    id = svga_negotiate_id(io_base);
    if (id == SVGA_ID_INVALID) {
        printf("[vmw-svga] PCI device present but SVGA ID negotiation failed io=0x%x cmd=0x%x\n",
               (uint32_t)io_base, (uint32_t)cmd);
        return -1;
    }

    g_svga_available = 1;
    fb_phys = (fb_bar & 0x1u) ? 0 : (fb_bar & ~0x0fu);
    if (!fb_phys) fb_phys = svga_read(io_base, SVGA_REG_FB_START);

    max_w = svga_read(io_base, SVGA_REG_MAX_WIDTH);
    max_h = svga_read(io_base, SVGA_REG_MAX_HEIGHT);
    if (max_w && width > max_w) width = max_w;
    if (max_h && height > max_h) height = max_h;

    if (framebuffer_already_active) {
        printf("[vmw-svga] detected %02x:%02x.%u id=0x%x io=0x%x fb=0x%x, keeping boot framebuffer\n",
               (uint32_t)bus, (uint32_t)slot, (uint32_t)func, id,
               (uint32_t)io_base, fb_phys);
        return 0;
    }

    if (!fb_phys) return -1;
    svga_write(io_base, SVGA_REG_ENABLE, 0);
    svga_write(io_base, SVGA_REG_GUEST_ID, 0x500Au); /* Linux guest family ID used only for host policy. */
    svga_write(io_base, SVGA_REG_WIDTH, width);
    svga_write(io_base, SVGA_REG_HEIGHT, height);
    svga_write(io_base, SVGA_REG_BITS_PER_PIXEL, SVGA_DEFAULT_BPP);
    svga_write(io_base, SVGA_REG_DEPTH, SVGA_DEFAULT_BPP);
    svga_write(io_base, SVGA_REG_PITCHLOCK, width * 4u);
    svga_write(io_base, SVGA_REG_ENABLE, 1);
    svga_write(io_base, SVGA_REG_CONFIG_DONE, 1);
    svga_write(io_base, SVGA_REG_SYNC, 1);
    if (svga_wait_not_busy(io_base) < 0) {
        printf("[vmw-svga] sync timeout; framebuffer not installed\n");
        return -1;
    }

    pitch = svga_read(io_base, SVGA_REG_BYTES_PER_LINE);
    if (!pitch) pitch = width * 4u;
    fb_install_physical(fb_phys, (uint8_t *)edge_mmio_low_alias(fb_phys),
                        width, height, pitch, SVGA_DEFAULT_BPP,
                        16, 8, 0, 0x00FF0000u, 0x0000FF00u, 0x000000FFu);
    printf("[vmw-svga] installed framebuffer %ux%ux%u pitch=%u io=0x%x fb=0x%x id=0x%x\n",
           width, height, SVGA_DEFAULT_BPP, pitch, (uint32_t)io_base, fb_phys, id);
    return 0;
}
