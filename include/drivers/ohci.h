/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This file contains BSD-derived OHCI register definitions from
 * FreeBSD sys/dev/usb/controller/ohcireg.h.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_OHCI_H
#define EDGEOS_DRIVERS_OHCI_H

#include <stdint.h>
#include "drivers/usb_dma.h"

typedef struct {
    int used;
    uint8_t bus, dev, fn;
    uint8_t irq_line;
    uint16_t vendor, device;
    uint64_t mmio_phys;
    volatile uint8_t *regs;
    uint8_t n_ports;
    uint8_t revision;
    usb_dma_block_t hcca;
    int running;
} ohci_controller_t;

int ohci_init_controller(ohci_controller_t *oc,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint8_t irq_line);
void ohci_poll_controller(ohci_controller_t *oc);
void ohci_debug_dump(const ohci_controller_t *oc);

#endif
