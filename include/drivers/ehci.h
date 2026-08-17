/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This file contains BSD-derived EHCI register definitions from
 * FreeBSD sys/dev/usb/controller/ehcireg.h.
 *
 * Modifications for EdgeOS.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_EHCI_H
#define EDGEOS_DRIVERS_EHCI_H

#include <stdint.h>
#include "drivers/usb_dma.h"

typedef struct {
    int used;
    uint8_t bus, dev, fn;
    uint8_t irq_line;
    uint16_t vendor, device;
    uint64_t mmio_phys;
    volatile uint8_t *cap;
    volatile uint8_t *op;
    uint8_t cap_len;
    uint8_t n_ports;
    uint8_t eecp;
    uint16_t hci_version;
    usb_dma_block_t periodic;
    usb_dma_block_t async_qh;
    int running;
} ehci_controller_t;

int ehci_init_controller(ehci_controller_t *ec,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint8_t irq_line);
void ehci_poll_controller(ehci_controller_t *ec);
void ehci_debug_dump(const ehci_controller_t *ec);

#endif
