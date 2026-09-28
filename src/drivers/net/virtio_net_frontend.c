/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Compatibility front end for the current netdev API when only virtio-net is
 * compiled.  The public names are historical; this file intentionally contains
 * no e1000 hardware driver logic.
 */

#include "drivers/e1000.h"
#include "drivers/virtio_net.h"

#include "stdio.h"

#include <stdint.h>

static e1000_rx_frame_cb_t g_rx_frame_cb;

void e1000_init(void) {
    if (virtio_net_init() == 0) {
        virtio_net_set_rx_frame_callback(g_rx_frame_cb);
        printf("[net] virtio-net: using primary NIC backend\n");
    } else {
        printf("[net] virtio-net: not found\n");
    }
}

int e1000_is_ready(void) {
    return virtio_net_is_ready();
}

void e1000_poll(void) {
    if (virtio_net_is_ready()) virtio_net_poll();
}

int e1000_get_mac(uint8_t mac_out[6]) {
    return virtio_net_get_mac(mac_out);
}

int e1000_send_frame_raw(const void *frame, uint16_t len) {
    return virtio_net_send_frame_raw(frame, len);
}

void e1000_set_rx_frame_callback(e1000_rx_frame_cb_t cb) {
    g_rx_frame_cb = cb;
    if (virtio_net_is_ready()) virtio_net_set_rx_frame_callback(cb);
}

int e1000_get_pci_location(uint8_t *bus, uint8_t *slot,
                           uint8_t *function) {
    return virtio_net_get_pci_location(bus, slot, function);
}

int e1000_stop(void) {
    return virtio_net_stop();
}

int e1000_resume(void) {
    return virtio_net_resume();
}

int e1000_send_icmp_echo(uint32_t dst_ip_be, const uint8_t *icmp_payload, uint16_t icmp_len) {
    (void)dst_ip_be;
    (void)icmp_payload;
    (void)icmp_len;
    return -1;
}

int e1000_recv_icmp_reply_for_id(uint16_t id_be, uint8_t *ip_packet_out, uint32_t *ip_packet_len, uint32_t *src_ip_be) {
    (void)id_be;
    (void)ip_packet_out;
    (void)ip_packet_len;
    (void)src_ip_be;
    return 0;
}
