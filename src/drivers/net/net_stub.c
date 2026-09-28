/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Empty network-device front end used when CONFIG_NET is enabled without any
 * compiled NIC backend.  Keeping these symbols present lets the Linux ABI
 * socket layer initialize normally while reporting that no carrier exists.
 */

#include "drivers/e1000.h"

#include <stdint.h>

void e1000_init(void) {
}

int e1000_is_ready(void) {
    return 0;
}

void e1000_poll(void) {
}

int e1000_get_mac(uint8_t mac_out[6]) {
    (void)mac_out;
    return -1;
}

int e1000_send_frame_raw(const void *frame, uint16_t len) {
    (void)frame;
    (void)len;
    return -1;
}

void e1000_set_rx_frame_callback(e1000_rx_frame_cb_t cb) {
    (void)cb;
}

int e1000_get_pci_location(uint8_t *bus, uint8_t *slot,
                           uint8_t *function) {
    (void)bus;
    (void)slot;
    (void)function;
    return -1;
}

int e1000_stop(void) {
    return 0;
}

int e1000_resume(void) {
    return -1;
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
