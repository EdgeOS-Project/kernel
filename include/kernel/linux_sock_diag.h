/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux socket diagnostics policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_SOCK_DIAG_H
#define EDGEOS_KERNEL_LINUX_SOCK_DIAG_H

#include <stdint.h>

#define EDGE_LINUX_NETLINK_SOCK_DIAG 4u
#define EDGE_LINUX_SOCK_DIAG_BY_FAMILY 20u

#define EDGE_LINUX_TCP_ESTABLISHED 1u
#define EDGE_LINUX_TCP_SYN_SENT 2u
#define EDGE_LINUX_TCP_SYN_RECV 3u
#define EDGE_LINUX_TCP_FIN_WAIT1 4u
#define EDGE_LINUX_TCP_FIN_WAIT2 5u
#define EDGE_LINUX_TCP_TIME_WAIT 6u
#define EDGE_LINUX_TCP_CLOSE 7u
#define EDGE_LINUX_TCP_CLOSE_WAIT 8u
#define EDGE_LINUX_TCP_LAST_ACK 9u
#define EDGE_LINUX_TCP_LISTEN 10u
#define EDGE_LINUX_TCP_CLOSING 11u

typedef struct edge_linux_sock_diag_snapshot {
    uint8_t family;
    uint8_t protocol;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmits;
    uint8_t reserved[3];
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t source_address[16];
    uint8_t destination_address[16];
    uint32_t interface_index;
    uint32_t cookie[2];
    uint32_t expires_ms;
    uint32_t receive_queue;
    uint32_t write_queue;
    uint32_t user_id;
    uint32_t inode;
} edge_linux_sock_diag_snapshot_t;

typedef int (*edge_linux_sock_diag_snapshot_fn)(
    void *context, uint32_t network_namespace, uint32_t ordinal,
    edge_linux_sock_diag_snapshot_t *snapshot);

/* Converts an lwIP tcp_state value into the Linux TCP state ABI. */
uint8_t edge_linux_sock_diag_state_from_lwip(uint8_t state);

/*
 * Encodes one Linux inet_diag dump using architecture-owned live socket
 * snapshots. Unsupported optional extensions are omitted rather than
 * synthesized.
 */
int edge_linux_sock_diag_respond(
    uint32_t network_namespace, uint32_t port_id,
    const void *request, uint32_t request_length,
    edge_linux_sock_diag_snapshot_fn snapshot_at, void *snapshot_context,
    uint32_t snapshot_limit, void *response, uint32_t response_capacity,
    uint32_t *response_length);

#endif
