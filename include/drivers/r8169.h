/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Realtek RTL8111/RTL8168/RTL8125 Ethernet driver interface.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_R8169_H
#define EDGEOS_DRIVERS_R8169_H

#include <stdint.h>

typedef void (*r8169_rx_frame_cb_t)(const uint8_t *frame, uint32_t len);

int r8169_init(void);
int r8169_is_ready(void);
void r8169_poll(void);
int r8169_get_mac(uint8_t mac_out[6]);
int r8169_send_frame_raw(const void *frame, uint16_t len);
void r8169_set_rx_frame_callback(r8169_rx_frame_cb_t cb);
int r8169_get_pci_location(uint8_t *bus, uint8_t *slot,
                           uint8_t *function);
int r8169_stop(void);
int r8169_resume(void);

#endif
