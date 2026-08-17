/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux socket diagnostics policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_sock_diag.h"

#define EDGE_AF_INET 2u
#define EDGE_AF_INET6 10u
#define EDGE_IPPROTO_TCP 6u
#define EDGE_IPPROTO_UDP 17u
#define EDGE_NLMSG_DONE 3u
#define EDGE_NLM_F_MULTI 2u
#define EDGE_INET_DIAG_NOCOOKIE 0xffffffffu

typedef struct edge_sock_diag_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} edge_sock_diag_nlmsghdr_t;

typedef struct edge_inet_diag_sockid {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t source[4];
    uint32_t destination[4];
    uint32_t interface_index;
    uint32_t cookie[2];
} edge_inet_diag_sockid_t;

typedef struct edge_inet_diag_request_v2 {
    uint8_t family;
    uint8_t protocol;
    uint8_t extensions;
    uint8_t padding;
    uint32_t states;
    edge_inet_diag_sockid_t id;
} edge_inet_diag_request_v2_t;

typedef struct edge_inet_diag_message {
    uint8_t family;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmits;
    edge_inet_diag_sockid_t id;
    uint32_t expires_ms;
    uint32_t receive_queue;
    uint32_t write_queue;
    uint32_t user_id;
    uint32_t inode;
} edge_inet_diag_message_t;

static uint32_t edge_sock_diag_align(uint32_t value) {
    return (value + 3u) & ~3u;
}

static int edge_sock_diag_all_zero(const uint32_t *words,
                                   uint32_t word_count) {
    uint32_t index;

    for (index = 0; index < word_count; ++index)
        if (words[index] != 0u) return 0;
    return 1;
}

static int edge_sock_diag_address_matches(
    uint8_t family, const uint32_t requested[4],
    const uint8_t actual[16]) {
    uint32_t bytes = family == EDGE_AF_INET ? 4u : 16u;

    if (edge_sock_diag_all_zero(requested, bytes / 4u)) return 1;
    return memcmp(requested, actual, bytes) == 0;
}

static int edge_sock_diag_matches(
    const edge_inet_diag_request_v2_t *request,
    const edge_linux_sock_diag_snapshot_t *snapshot) {
    if (snapshot->family != request->family ||
        snapshot->protocol != request->protocol)
        return 0;
    if (snapshot->state >= 32u ||
        !(request->states & (1u << snapshot->state)))
        return 0;
    if (request->id.source_port != 0u &&
        request->id.source_port != snapshot->source_port)
        return 0;
    if (request->id.destination_port != 0u &&
        request->id.destination_port != snapshot->destination_port)
        return 0;
    if (request->id.interface_index != 0u &&
        request->id.interface_index != snapshot->interface_index)
        return 0;
    if (!edge_sock_diag_address_matches(
            request->family, request->id.source,
            snapshot->source_address) ||
        !edge_sock_diag_address_matches(
            request->family, request->id.destination,
            snapshot->destination_address))
        return 0;
    if (!((request->id.cookie[0] == 0u &&
           request->id.cookie[1] == 0u) ||
          (request->id.cookie[0] == EDGE_INET_DIAG_NOCOOKIE &&
           request->id.cookie[1] == EDGE_INET_DIAG_NOCOOKIE)) &&
        (request->id.cookie[0] != snapshot->cookie[0] ||
         request->id.cookie[1] != snapshot->cookie[1]))
        return 0;
    return 1;
}

uint8_t edge_linux_sock_diag_state_from_lwip(uint8_t state) {
    static const uint8_t linux_states[] = {
        EDGE_LINUX_TCP_CLOSE,
        EDGE_LINUX_TCP_LISTEN,
        EDGE_LINUX_TCP_SYN_SENT,
        EDGE_LINUX_TCP_SYN_RECV,
        EDGE_LINUX_TCP_ESTABLISHED,
        EDGE_LINUX_TCP_FIN_WAIT1,
        EDGE_LINUX_TCP_FIN_WAIT2,
        EDGE_LINUX_TCP_CLOSE_WAIT,
        EDGE_LINUX_TCP_CLOSING,
        EDGE_LINUX_TCP_LAST_ACK,
        EDGE_LINUX_TCP_TIME_WAIT,
    };

    if (state >= sizeof(linux_states)) return EDGE_LINUX_TCP_CLOSE;
    return linux_states[state];
}

int edge_linux_sock_diag_respond(
    uint32_t network_namespace, uint32_t port_id,
    const void *request_data,
    uint32_t request_length,
    edge_linux_sock_diag_snapshot_fn snapshot_at, void *snapshot_context,
    uint32_t snapshot_limit, void *response_data, uint32_t response_capacity,
    uint32_t *response_length) {
    edge_sock_diag_nlmsghdr_t request_header;
    edge_inet_diag_request_v2_t request;
    uint8_t *response = (uint8_t *)response_data;
    uint32_t offset = 0;
    uint32_t ordinal;

    if (!response_length) return -EDGE_LINUX_EINVAL;
    *response_length = 0;
    if (!request_data || !snapshot_at || !response_data ||
        request_length < sizeof(request_header) + sizeof(request))
        return -EDGE_LINUX_EINVAL;
    memcpy(&request_header, request_data, sizeof(request_header));
    if (request_header.length < sizeof(request_header) + sizeof(request) ||
        request_header.length > request_length ||
        request_header.type != EDGE_LINUX_SOCK_DIAG_BY_FAMILY)
        return -EDGE_LINUX_EINVAL;
    memcpy(&request, (const uint8_t *)request_data + sizeof(request_header),
           sizeof(request));
    if (request.family != EDGE_AF_INET && request.family != EDGE_AF_INET6)
        return -EDGE_LINUX_EAFNOSUPPORT;
    if (request.protocol != EDGE_IPPROTO_TCP &&
        request.protocol != EDGE_IPPROTO_UDP)
        return -EDGE_LINUX_EPROTONOSUPPORT;

    for (ordinal = 0; ordinal < snapshot_limit; ++ordinal) {
        edge_linux_sock_diag_snapshot_t snapshot;
        edge_sock_diag_nlmsghdr_t output_header;
        edge_inet_diag_message_t message;
        uint32_t message_length =
            (uint32_t)(sizeof(output_header) + sizeof(message));
        uint32_t padded_length = edge_sock_diag_align(message_length);
        int available;

        memset(&snapshot, 0, sizeof(snapshot));
        available = snapshot_at(
            snapshot_context, network_namespace, ordinal, &snapshot);
        if (available < 0) return available;
        if (!available || !edge_sock_diag_matches(&request, &snapshot))
            continue;
        if (offset > response_capacity ||
            padded_length > response_capacity - offset)
            return -EDGE_LINUX_ENOBUFS;
        memset(&output_header, 0, sizeof(output_header));
        output_header.length = message_length;
        output_header.type = EDGE_LINUX_SOCK_DIAG_BY_FAMILY;
        output_header.flags = EDGE_NLM_F_MULTI;
        output_header.sequence = request_header.sequence;
        output_header.port_id = port_id;
        memset(&message, 0, sizeof(message));
        message.family = snapshot.family;
        message.state = snapshot.state;
        message.timer = snapshot.timer;
        message.retransmits = snapshot.retransmits;
        message.id.source_port = snapshot.source_port;
        message.id.destination_port = snapshot.destination_port;
        memcpy(message.id.source, snapshot.source_address,
               sizeof(message.id.source));
        memcpy(message.id.destination, snapshot.destination_address,
               sizeof(message.id.destination));
        message.id.interface_index = snapshot.interface_index;
        message.id.cookie[0] = snapshot.cookie[0];
        message.id.cookie[1] = snapshot.cookie[1];
        message.expires_ms = snapshot.expires_ms;
        message.receive_queue = snapshot.receive_queue;
        message.write_queue = snapshot.write_queue;
        message.user_id = snapshot.user_id;
        message.inode = snapshot.inode;
        memcpy(response + offset, &output_header, sizeof(output_header));
        memcpy(response + offset + sizeof(output_header),
               &message, sizeof(message));
        if (padded_length > message_length)
            memset(response + offset + message_length, 0,
                   padded_length - message_length);
        offset += padded_length;
    }
    {
        struct {
            edge_sock_diag_nlmsghdr_t header;
            int32_t status;
        } done;

        if (offset > response_capacity ||
            sizeof(done) > response_capacity - offset)
            return -EDGE_LINUX_ENOBUFS;
        memset(&done, 0, sizeof(done));
        done.header.length = sizeof(done);
        done.header.type = EDGE_NLMSG_DONE;
        done.header.flags = EDGE_NLM_F_MULTI;
        done.header.sequence = request_header.sequence;
        done.header.port_id = port_id;
        memcpy(response + offset, &done, sizeof(done));
        offset += sizeof(done);
    }
    *response_length = offset;
    return 0;
}
