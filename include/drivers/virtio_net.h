/* SPDX-License-Identifier: MPL-2.0 */
/* Copyright (c) EdgeOS Contributors. */

#ifndef DRIVERS_VIRTIO_NET_H
#define DRIVERS_VIRTIO_NET_H

#include <stdint.h>

#define EDGE_VIRTIO_NET_ETHERNET_MIN_FRAME_SIZE 60u

typedef void (*virtio_net_rx_frame_cb_t)(const uint8_t *frame, uint32_t len);

int virtio_net_init(void);
int virtio_net_is_ready(void);
void virtio_net_poll(void);
int virtio_net_get_mac(uint8_t mac_out[6]);
int virtio_net_send_frame_raw(const void *frame, uint16_t len);
void virtio_net_set_rx_frame_callback(virtio_net_rx_frame_cb_t cb);
int virtio_net_get_pci_location(uint8_t *bus, uint8_t *slot,
                                uint8_t *function);
int virtio_net_stop(void);
int virtio_net_resume(void);

#endif
