/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Register definitions and controller sequencing in this file are derived from
 * FreeBSD sys/dev/usb/controller/ehcireg.h and EHCI controller behavior.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#include "drivers/ehci.h"
#include "drivers/pci.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"

#define PCI_COMMAND_REG 0x04u
#define PCI_COMMAND_MEM 0x0002u
#define PCI_COMMAND_BUSMASTER 0x0004u

#define EHCI_CAPLEN_HCIVERSION 0x00u
#define EHCI_HCSPARAMS        0x04u
#define EHCI_HCCPARAMS        0x08u
#define EHCI_HCSP_PORTROUTE   0x0cu
#define EHCI_HCC_EECP(x)      (((x) >> 8) & 0xffu)
#define EHCI_HCS_N_PORTS(x)   ((x) & 0x0fu)

#define EHCI_EC_LEGSUP 0x01u
#define EHCI_EECP_ID(x) ((x) & 0xffu)
#define EHCI_EECP_NEXT(x) (((x) >> 8) & 0xffu)
#define EHCI_LEGSUP_BIOS_SEM 0x02u
#define EHCI_LEGSUP_OS_SEM   0x03u

#define EHCI_USBCMD 0x00u
#define EHCI_USBSTS 0x04u
#define EHCI_USBINTR 0x08u
#define EHCI_FRINDEX 0x0cu
#define EHCI_CTRLDSSEGMENT 0x10u
#define EHCI_PERIODICLISTBASE 0x14u
#define EHCI_ASYNCLISTADDR 0x18u
#define EHCI_CONFIGFLAG 0x40u
#define EHCI_PORTSC(n) (0x40u + (4u * (uint32_t)(n)))

#define EHCI_CMD_RS      0x00000001u
#define EHCI_CMD_HCRESET 0x00000002u
#define EHCI_CMD_PSE     0x00000010u
#define EHCI_CMD_ASE     0x00000020u
#define EHCI_CMD_ITC_1   0x00010000u
#define EHCI_STS_HCH     0x00001000u
#define EHCI_STS_INTRS   0x0000003fu
#define EHCI_CONF_CF     0x00000001u

#define EHCI_PS_PO    0x00002000u
#define EHCI_PS_PP    0x00001000u
#define EHCI_PS_PR    0x00000100u
#define EHCI_PS_PE    0x00000004u
#define EHCI_PS_CS    0x00000001u
#define EHCI_PS_CLEAR 0x0000002au

typedef struct __attribute__((packed, aligned(128))) {
    uint32_t horiz;
    uint32_t ep_char;
    uint32_t ep_cap;
    uint32_t cur_qtd;
    uint32_t next_qtd;
    uint32_t alt_next_qtd;
    uint32_t token;
    uint32_t buf[5];
    uint32_t buf_hi[5];
} ehci_qh_t;

static inline uint32_t ehci_rd32(volatile uint8_t *base, uint32_t off) {
    return *(volatile uint32_t *)(base + off);
}

static inline void ehci_wr32(volatile uint8_t *base, uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(base + off) = v;
}

static int ehci_wait(volatile uint8_t *base, uint32_t off, uint32_t mask,
                     uint32_t value, uint32_t spins) {
    for (uint32_t i = 0; i < spins; ++i) {
        if ((ehci_rd32(base, off) & mask) == value) return 0;
    }
    return -1;
}

static uint64_t ehci_bar_phys(uint32_t bar0) {
    if (bar0 == 0 || bar0 == 0xffffffffu || (bar0 & 1u)) return 0;
    return (uint64_t)(bar0 & ~0x0fu);
}

static void ehci_legacy_handoff(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t eecp) {
    uint8_t off = eecp;
    for (uint32_t guard = 0; guard < 16u && off >= 0x40u; ++guard) {
        uint32_t cap = pci_cfg_read32(bus, dev, fn, off);
        if (EHCI_EECP_ID(cap) == EHCI_EC_LEGSUP) {
            pci_cfg_write8(bus, dev, fn, (uint8_t)(off + EHCI_LEGSUP_OS_SEM), 1u);
            for (uint32_t i = 0; i < 200000u; ++i) {
                uint8_t bios = pci_cfg_read8(bus, dev, fn, (uint8_t)(off + EHCI_LEGSUP_BIOS_SEM));
                if (bios == 0) break;
            }
            pci_cfg_write32(bus, dev, fn, (uint8_t)(off + 4u), 0u);
            printf("[usb][ehci] BIOS ownership handoff at cap=0x%x\n", (uint32_t)off);
            return;
        }
        off = (uint8_t)EHCI_EECP_NEXT(cap);
    }
}

static void ehci_power_ports(ehci_controller_t *ec) {
    for (uint8_t p = 0; p < ec->n_ports; ++p) {
        uint32_t ps = ehci_rd32(ec->op, EHCI_PORTSC(p));
        if (ps & EHCI_PS_CLEAR) ehci_wr32(ec->op, EHCI_PORTSC(p), ps);
        ps = ehci_rd32(ec->op, EHCI_PORTSC(p));
        ehci_wr32(ec->op, EHCI_PORTSC(p), (ps & ~EHCI_PS_CLEAR) | EHCI_PS_PP);
        ps = ehci_rd32(ec->op, EHCI_PORTSC(p));
        if (ps & EHCI_PS_CS) {
            ehci_wr32(ec->op, EHCI_PORTSC(p), (ps & ~EHCI_PS_CLEAR) | EHCI_PS_PP | EHCI_PS_PR);
            (void)ehci_wait(ec->op, EHCI_PORTSC(p), EHCI_PS_PR, 0, 800000u);
            ps = ehci_rd32(ec->op, EHCI_PORTSC(p));
            if ((ps & EHCI_PS_PE) == 0) {
                ehci_wr32(ec->op, EHCI_PORTSC(p), (ps & ~EHCI_PS_CLEAR) | EHCI_PS_PO | EHCI_PS_PP);
            }
        }
    }
}

int ehci_init_controller(ehci_controller_t *ec,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint8_t irq_line) {
    uint64_t phys;
    uint32_t capver, hcs, hcc, cmd;
    ehci_qh_t *qh;

    if (!ec) return -1;
    memset(ec, 0, sizeof(*ec));
    phys = ehci_bar_phys(bar0);
    if (!phys) return -1;

    ec->cap = (volatile uint8_t *)edge_mmio_low_alias(phys);
    capver = ehci_rd32(ec->cap, EHCI_CAPLEN_HCIVERSION);
    ec->cap_len = (uint8_t)(capver & 0xffu);
    ec->hci_version = (uint16_t)((capver >> 16) & 0xffffu);
    if (ec->cap_len < 0x20u || ec->hci_version < 0x0100u) return -1;
    ec->op = ec->cap + ec->cap_len;
    hcs = ehci_rd32(ec->cap, EHCI_HCSPARAMS);
    hcc = ehci_rd32(ec->cap, EHCI_HCCPARAMS);
    ec->n_ports = (uint8_t)EHCI_HCS_N_PORTS(hcs);
    if (ec->n_ports == 0 || ec->n_ports > 15u) return -1;
    ec->eecp = (uint8_t)EHCI_HCC_EECP(hcc);
    if (ec->eecp >= 0x40u) ehci_legacy_handoff(bus, dev, fn, ec->eecp);

    pci_cfg_write16(bus, dev, fn, PCI_COMMAND_REG,
                    (uint16_t)(pci_cfg_read16(bus, dev, fn, PCI_COMMAND_REG) |
                               PCI_COMMAND_MEM | PCI_COMMAND_BUSMASTER));

    cmd = ehci_rd32(ec->op, EHCI_USBCMD);
    ehci_wr32(ec->op, EHCI_USBCMD, cmd & ~EHCI_CMD_RS);
    (void)ehci_wait(ec->op, EHCI_USBSTS, EHCI_STS_HCH, EHCI_STS_HCH, 1000000u);
    ehci_wr32(ec->op, EHCI_USBCMD, EHCI_CMD_HCRESET);
    if (ehci_wait(ec->op, EHCI_USBCMD, EHCI_CMD_HCRESET, 0, 2000000u) < 0) return -1;

    if (usb_dma_alloc_zero(4096u, 4096u, &ec->periodic) < 0) return -1;
    if (usb_dma_alloc_zero(128u, 128u, &ec->async_qh) < 0) return -1;
    for (uint32_t i = 0; i < 1024u; ++i) ((uint32_t *)ec->periodic.vaddr)[i] = 1u;
    qh = (ehci_qh_t *)ec->async_qh.vaddr;
    qh->horiz = (ec->async_qh.paddr & ~0x1fu) | 0x2u;
    qh->ep_char = (1u << 15); /* Head of reclamation list. */
    qh->next_qtd = 1u;
    qh->alt_next_qtd = 1u;
    qh->token = 0x40u;

    ehci_wr32(ec->op, EHCI_CTRLDSSEGMENT, 0u);
    ehci_wr32(ec->op, EHCI_PERIODICLISTBASE, ec->periodic.paddr);
    ehci_wr32(ec->op, EHCI_ASYNCLISTADDR, ec->async_qh.paddr);
    ehci_wr32(ec->op, EHCI_USBINTR, 0u);
    ehci_wr32(ec->op, EHCI_USBSTS, EHCI_STS_INTRS);
    ehci_wr32(ec->op, EHCI_FRINDEX, 0u);
    ehci_wr32(ec->op, EHCI_CONFIGFLAG, EHCI_CONF_CF);
    ehci_wr32(ec->op, EHCI_USBCMD, EHCI_CMD_ITC_1 | EHCI_CMD_PSE | EHCI_CMD_ASE | EHCI_CMD_RS);
    if (ehci_wait(ec->op, EHCI_USBSTS, EHCI_STS_HCH, 0, 2000000u) < 0) return -1;
    ehci_power_ports(ec);

    ec->used = 1;
    ec->running = 1;
    ec->bus = bus;
    ec->dev = dev;
    ec->fn = fn;
    ec->irq_line = irq_line;
    ec->vendor = vendor;
    ec->device = device;
    ec->mmio_phys = phys;
    printf("[usb][ehci] initialized %u:%u.%u mmio=0x%x ports=%u version=0x%x\n",
           (uint32_t)bus, (uint32_t)dev, (uint32_t)fn,
           (uint32_t)phys, (uint32_t)ec->n_ports, (uint32_t)ec->hci_version);
    return 0;
}

void ehci_poll_controller(ehci_controller_t *ec) {
    uint32_t st;
    if (!ec || !ec->running) return;
    st = ehci_rd32(ec->op, EHCI_USBSTS);
    if (st & EHCI_STS_INTRS) ehci_wr32(ec->op, EHCI_USBSTS, st & EHCI_STS_INTRS);
}

void ehci_debug_dump(const ehci_controller_t *ec) {
    if (!ec || !ec->used) return;
    printf("[usb][ehci] %u:%u.%u ports=%u running=%d\n",
           (uint32_t)ec->bus, (uint32_t)ec->dev, (uint32_t)ec->fn,
           (uint32_t)ec->n_ports, ec->running);
}
