/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Register definitions and controller sequencing in this file are derived from
 * FreeBSD sys/dev/usb/controller/ohcireg.h and OHCI controller behavior.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/ohci.h"
#include "drivers/pci.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#define PCI_COMMAND_REG 0x04u
#define PCI_COMMAND_MEM 0x0002u
#define PCI_COMMAND_BUSMASTER 0x0004u

#define OHCI_REVISION 0x00u
#define OHCI_CONTROL 0x04u
#define OHCI_COMMAND_STATUS 0x08u
#define OHCI_INTERRUPT_STATUS 0x0cu
#define OHCI_INTERRUPT_ENABLE 0x10u
#define OHCI_INTERRUPT_DISABLE 0x14u
#define OHCI_HCCA 0x18u
#define OHCI_CONTROL_HEAD_ED 0x20u
#define OHCI_BULK_HEAD_ED 0x28u
#define OHCI_FM_INTERVAL 0x34u
#define OHCI_PERIODIC_START 0x40u
#define OHCI_LS_THRESHOLD 0x44u
#define OHCI_RH_DESCRIPTOR_A 0x48u
#define OHCI_RH_STATUS 0x50u
#define OHCI_RH_PORT_STATUS(n) (0x54u + (4u * (uint32_t)(n)))

#define OHCI_HCFS_RESET       0x00000000u
#define OHCI_HCFS_OPERATIONAL 0x00000080u
#define OHCI_IR               0x00000100u
#define OHCI_HCR              0x00000001u
#define OHCI_OCR              0x00000008u
#define OHCI_MIE              0x80000000u
#define OHCI_ALL_INTRS        0xc000007fu
#define OHCI_GET_NDP(s)       ((s) & 0xffu)
#define OHCI_LPSC             0x00010000u
#define OHCI_PRS              0x00000010u
#define OHCI_PPS              0x00000100u
#define OHCI_CCS              0x00000001u
#define OHCI_PES              0x00000002u
#define OHCI_CSC              0x00010000u
#define OHCI_PESC             0x00020000u
#define OHCI_PRSC             0x00100000u

static inline uint32_t ohci_rd32(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint32_t *)(base + off);
}

static inline void ohci_wr32(volatile uint8_t *base, uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(base + off) = v;
}

static int ohci_wait(volatile uint8_t *base, uint32_t off, uint32_t mask,
                     uint32_t value, uint32_t spins) {
    for (uint32_t i = 0; i < spins; ++i) {
        if ((ohci_rd32(base, off) & mask) == value) return 0;
    }
    return -1;
}

static uint64_t ohci_bar_phys(uint32_t bar0) {
    if (bar0 == 0 || bar0 == 0xffffffffu || (bar0 & 1u)) return 0;
    return (uint64_t)(bar0 & ~0x0fu);
}

static void ohci_power_ports(ohci_controller_t *oc) {
    ohci_wr32(oc->regs, OHCI_RH_STATUS, OHCI_LPSC);
    for (uint8_t p = 0; p < oc->n_ports; ++p) {
        uint32_t ps = ohci_rd32(oc->regs, OHCI_RH_PORT_STATUS(p));
        ohci_wr32(oc->regs, OHCI_RH_PORT_STATUS(p), OHCI_PPS | OHCI_CSC | OHCI_PESC | OHCI_PRSC);
        if (ps & OHCI_CCS) {
            ohci_wr32(oc->regs, OHCI_RH_PORT_STATUS(p), OHCI_PRS);
            (void)ohci_wait(oc->regs, OHCI_RH_PORT_STATUS(p), OHCI_PRS, 0, 800000u);
            ps = ohci_rd32(oc->regs, OHCI_RH_PORT_STATUS(p));
            if (ps & OHCI_PRSC) ohci_wr32(oc->regs, OHCI_RH_PORT_STATUS(p), OHCI_PRSC);
            if ((ps & OHCI_PES) == 0) {
                printf("[usb][ohci] port %u connected but not enabled status=0x%x\n",
                       (uint32_t)(p + 1u), ps);
            }
        }
    }
}

int ohci_init_controller(ohci_controller_t *oc,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint8_t irq_line) {
    uint64_t phys;
    uint32_t ctl, fmi, desc_a;

    if (!oc) return -1;
    memset(oc, 0, sizeof(*oc));
    phys = ohci_bar_phys(bar0);
    if (!phys) return -1;
    oc->regs = (volatile uint8_t *)edge_mmio_low_alias(phys);
    oc->revision = (uint8_t)(ohci_rd32(oc->regs, OHCI_REVISION) & 0xffu);

    pci_cfg_write16(bus, dev, fn, PCI_COMMAND_REG,
                    (uint16_t)(pci_cfg_read16(bus, dev, fn, PCI_COMMAND_REG) |
                               PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER));

    ctl = ohci_rd32(oc->regs, OHCI_CONTROL);
    if (ctl & OHCI_IR) {
        ohci_wr32(oc->regs, OHCI_COMMAND_STATUS, OHCI_OCR);
        (void)ohci_wait(oc->regs, OHCI_CONTROL, OHCI_IR, 0, 2000000u);
    }
    ohci_wr32(oc->regs, OHCI_INTERRUPT_DISABLE, OHCI_MIE | OHCI_ALL_INTRS);
    ohci_wr32(oc->regs, OHCI_COMMAND_STATUS, OHCI_HCR);
    if (ohci_wait(oc->regs, OHCI_COMMAND_STATUS, OHCI_HCR, 0, 2000000u) < 0) return -1;

    if (usb_dma_alloc_zero(256u, 256u, &oc->hcca) < 0) return -1;
    ohci_wr32(oc->regs, OHCI_HCCA, oc->hcca.paddr);
    ohci_wr32(oc->regs, OHCI_CONTROL_HEAD_ED, 0u);
    ohci_wr32(oc->regs, OHCI_BULK_HEAD_ED, 0u);
    fmi = ohci_rd32(oc->regs, OHCI_FM_INTERVAL);
    if ((fmi & 0x3fffu) == 0) fmi = 0x2edfU;
    ohci_wr32(oc->regs, OHCI_FM_INTERVAL, fmi);
    ohci_wr32(oc->regs, OHCI_PERIODIC_START, (fmi & 0x3fffu) * 9u / 10u);
    ohci_wr32(oc->regs, OHCI_LS_THRESHOLD, 0x0628u);
    ohci_wr32(oc->regs, OHCI_INTERRUPT_STATUS, OHCI_ALL_INTRS);
    ohci_wr32(oc->regs, OHCI_CONTROL, OHCI_HCFS_OPERATIONAL);

    desc_a = ohci_rd32(oc->regs, OHCI_RH_DESCRIPTOR_A);
    oc->n_ports = (uint8_t)OHCI_GET_NDP(desc_a);
    if (oc->n_ports == 0 || oc->n_ports > 15u) oc->n_ports = 2;
    ohci_power_ports(oc);

    oc->used = 1;
    oc->running = 1;
    oc->bus = bus;
    oc->dev = dev;
    oc->fn = fn;
    oc->irq_line = irq_line;
    oc->vendor = vendor;
    oc->device = device;
    oc->mmio_phys = phys;
    printf("[usb][ohci] initialized %u:%u.%u mmio=0x%x ports=%u rev=0x%x\n",
           (uint32_t)bus, (uint32_t)dev, (uint32_t)fn,
           (uint32_t)phys, (uint32_t)oc->n_ports, (uint32_t)oc->revision);
    return 0;
}

void ohci_poll_controller(ohci_controller_t *oc) {
    uint32_t st;
    if (!oc || !oc->running) return;
    st = ohci_rd32(oc->regs, OHCI_INTERRUPT_STATUS);
    if (st & OHCI_ALL_INTRS) ohci_wr32(oc->regs, OHCI_INTERRUPT_STATUS, st & OHCI_ALL_INTRS);
}

void ohci_debug_dump(const ohci_controller_t *oc) {
    if (!oc || !oc->used) return;
    printf("[usb][ohci] %u:%u.%u ports=%u running=%d\n",
           (uint32_t)oc->bus, (uint32_t)oc->dev, (uint32_t)oc->fn,
           (uint32_t)oc->n_ports, oc->running);
}
