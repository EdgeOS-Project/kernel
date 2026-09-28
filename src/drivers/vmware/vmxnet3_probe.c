/*-
 * Copyright (c) 2013 Tsubai Masanari
 * Copyright (c) 2013 Bryan Venteicher <bryanv@FreeBSD.org>
 * Copyright (c) 2018 Patrick Kelsey
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */
/*
 * BSD-derived vmxnet3 PCI/MMIO probe based on FreeBSD
 * sys/dev/vmware/vmxnet3.  This is not a data-plane driver yet; it performs
 * real device identification, command-register reset/disable, MAC readout,
 * and interrupt masking so vmxnet3 hardware is visible without creating a fake
 * Linux netdevice.
 */

#include "drivers/vmxnet3.h"

#include "drivers/pci.h"
#include "stdio.h"
#include "sys/mmio.h"

#include <stdint.h>

#define VMXNET3_VENDOR_VMWARE 0x15ADu
#define VMXNET3_DEVICE_ID     0x07B0u

#define VMXNET3_BAR0_IMASK(irq) (0x000u + (irq) * 8u)
#define VMXNET3_BAR1_VRRS      0x000u
#define VMXNET3_BAR1_UVRS      0x008u
#define VMXNET3_BAR1_CMD       0x020u
#define VMXNET3_BAR1_MACL      0x028u
#define VMXNET3_BAR1_MACH      0x030u
#define VMXNET3_BAR1_INTR      0x038u
#define VMXNET3_BAR1_EVENT     0x040u
#define VMXNET3_CMD_DISABLE    0xCAFE0001u
#define VMXNET3_CMD_RESET      0xCAFE0002u
#define VMXNET3_CMD_GET_MACL   0xF00D0003u
#define VMXNET3_CMD_GET_MACH   0xF00D0004u
#define VMXNET3_REV1_MAGIC     0xBABEFEE1u
#define VMXNET3_UPT1_MAGIC     0x1u

static int g_vmxnet3_count;

static uint32_t vmx_rd32(volatile uint8_t *mmio, uint32_t reg) {
    return *(volatile uint32_t *)(mmio + reg);
}

static void vmx_wr32(volatile uint8_t *mmio, uint32_t reg, uint32_t val) {
    *(volatile uint32_t *)(mmio + reg) = val;
}

static uint64_t vmx_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t index) {
    uint8_t off = (uint8_t)(0x10u + index * 4u);
    uint32_t bar = pci_cfg_read32(bus, slot, func, off);
    if ((bar & 1u) || (bar & ~0xFu) == 0) return 0;
    if (((bar >> 1) & 0x3u) == 0x2u && off <= 0x20) {
        uint32_t hi = pci_cfg_read32(bus, slot, func, (uint8_t)(off + 4));
        return ((uint64_t)hi << 32) | (uint64_t)(bar & ~0xFu);
    }
    return (uint64_t)(bar & ~0xFu);
}

void vmxnet3_probe_init(void) {
    g_vmxnet3_count = 0;
    for (uint8_t bus = 0; bus < 255; ++bus) {
        for (uint8_t slot = 0; slot < 32; ++slot) {
            for (uint8_t func = 0; func < 8; ++func) {
                uint16_t ven = pci_cfg_read16(bus, slot, func, 0x00);
                uint16_t did;
                uint64_t bar0;
                uint64_t bar1;
                volatile uint8_t *mmio0;
                volatile uint8_t *mmio1;
                uint16_t cmd;
                uint32_t macl;
                uint32_t mach;
                if (ven == PCI_VENDOR_INVALID) {
                    if (func == 0) break;
                    continue;
                }
                did = pci_cfg_read16(bus, slot, func, 0x02);
                if (ven != VMXNET3_VENDOR_VMWARE || did != VMXNET3_DEVICE_ID) continue;
                bar0 = vmx_bar(bus, slot, func, 0);
                bar1 = vmx_bar(bus, slot, func, 1);
                if (!bar0 || !bar1) {
                    printf("[net] vmxnet3: %u:%u.%u missing MMIO BARs bar0=0x%x bar1=0x%x\n",
                           (uint32_t)bus, (uint32_t)slot, (uint32_t)func,
                           (uint32_t)bar0, (uint32_t)bar1);
                    continue;
                }
                cmd = pci_cfg_read16(bus, slot, func, 0x04);
                pci_cfg_write16(bus, slot, func, 0x04, (uint16_t)(cmd | 0x0006u));
                mmio0 = (volatile uint8_t *)edge_mmio_low_alias(bar0);
                mmio1 = (volatile uint8_t *)edge_mmio_low_alias(bar1);
                for (uint32_t irq = 0; irq < 25; ++irq) vmx_wr32(mmio0, VMXNET3_BAR0_IMASK(irq), 1);
                vmx_wr32(mmio1, VMXNET3_BAR1_VRRS, VMXNET3_REV1_MAGIC);
                vmx_wr32(mmio1, VMXNET3_BAR1_UVRS, VMXNET3_UPT1_MAGIC);
                vmx_wr32(mmio1, VMXNET3_BAR1_CMD, VMXNET3_CMD_RESET);
                vmx_wr32(mmio1, VMXNET3_BAR1_CMD, VMXNET3_CMD_DISABLE);
                vmx_wr32(mmio1, VMXNET3_BAR1_INTR, 0xFFFFFFFFu);
                vmx_wr32(mmio1, VMXNET3_BAR1_EVENT, 0xFFFFFFFFu);
                vmx_wr32(mmio1, VMXNET3_BAR1_CMD, VMXNET3_CMD_GET_MACL);
                macl = vmx_rd32(mmio1, VMXNET3_BAR1_MACL);
                vmx_wr32(mmio1, VMXNET3_BAR1_CMD, VMXNET3_CMD_GET_MACH);
                mach = vmx_rd32(mmio1, VMXNET3_BAR1_MACH);
                printf("[net] vmxnet3: partial probe bus=%u dev=%u fn=%u mac=%x:%x:%x:%x:%x:%x bar0=0x%x bar1=0x%x\n",
                       (uint32_t)bus, (uint32_t)slot, (uint32_t)func,
                       macl & 0xffu, (macl >> 8) & 0xffu, (macl >> 16) & 0xffu,
                       (macl >> 24) & 0xffu, mach & 0xffu, (mach >> 8) & 0xffu,
                       (uint32_t)bar0, (uint32_t)bar1);
                g_vmxnet3_count++;
            }
        }
    }
    if (g_vmxnet3_count == 0) printf("[net] vmxnet3: no VMware VMXNET3 PCI device found\n");
}

int vmxnet3_probe_count(void) {
    return g_vmxnet3_count;
}
