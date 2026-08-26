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
#define EDGE_NLA_F_NESTED 0x8000u
#define EDGE_NLA_TYPE_MASK 0x3fffu
#define EDGE_INET_DIAG_REQ_SK_BPF_STORAGES 2u
#define EDGE_INET_DIAG_SK_BPF_STORAGES 20u
#define EDGE_SK_DIAG_BPF_STORAGE_REQ_MAP_FD 1u
#define EDGE_SK_DIAG_BPF_STORAGE 1u
#define EDGE_SK_DIAG_BPF_STORAGE_PAD 1u
#define EDGE_SK_DIAG_BPF_STORAGE_MAP_ID 2u
#define EDGE_SK_DIAG_BPF_STORAGE_MAP_VALUE 3u

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

typedef struct edge_sock_diag_nlattr {
    uint16_t length;
    uint16_t type;
} edge_sock_diag_nlattr_t;

typedef struct edge_sock_diag_bpf_query {
    edge_linux_sock_diag_bpf_map_t maps[EDGE_RUNTIME_MAX_BPF_OBJECTS];
    uint32_t map_count;
    uint8_t requested;
} edge_sock_diag_bpf_query_t;

static uint32_t edge_sock_diag_align(uint32_t value) {
    return (value + 3u) & ~3u;
}

static void edge_sock_diag_bpf_query_release(
    edge_sock_diag_bpf_query_t *query,
    const edge_linux_sock_diag_bpf_ops_t *ops) {
    uint32_t index;

    if (!query || !ops || !ops->release) return;
    for (index = 0; index < query->map_count; ++index)
        ops->release(ops->context, &query->maps[index]);
    query->map_count = 0u;
}

static int edge_sock_diag_bpf_query_add(
    edge_sock_diag_bpf_query_t *query,
    const edge_linux_sock_diag_bpf_ops_t *ops,
    const edge_linux_sock_diag_bpf_map_t *map) {
    uint32_t index;

    if (!query || !ops || !map) return -EDGE_LINUX_EINVAL;
    for (index = 0; index < query->map_count; ++index) {
        if (query->maps[index].object_id == map->object_id) {
            if (ops->release) ops->release(ops->context, map);
            return -EDGE_LINUX_EEXIST;
        }
    }
    if (query->map_count >= EDGE_RUNTIME_MAX_BPF_OBJECTS) {
        if (ops->release) ops->release(ops->context, map);
        return -EDGE_LINUX_E2BIG;
    }
    if (map->value_size > 0xffffu - 4u) {
        if (ops->release) ops->release(ops->context, map);
        return -EDGE_LINUX_E2BIG;
    }
    query->maps[query->map_count++] = *map;
    return 0;
}

static int edge_sock_diag_bpf_query_prepare(
    const uint8_t *request_data, uint32_t request_length,
    uint32_t attributes_offset, int bpf_capable,
    const edge_linux_sock_diag_bpf_ops_t *ops,
    edge_sock_diag_bpf_query_t *query) {
    const edge_sock_diag_nlattr_t *storage_attribute = 0;
    edge_sock_diag_nlattr_t attribute;
    uint32_t storage_length = 0u;
    uint32_t offset = attributes_offset;
    int status;

    if (!query) return -EDGE_LINUX_EINVAL;
    memset(query, 0, sizeof(*query));
    while (offset < request_length) {
        uint32_t padded;

        if (request_length - offset < sizeof(attribute))
            return -EDGE_LINUX_EINVAL;
        memcpy(&attribute, request_data + offset, sizeof(attribute));
        if (attribute.length < sizeof(attribute) ||
            attribute.length > request_length - offset)
            return -EDGE_LINUX_EINVAL;
        padded = edge_sock_diag_align(attribute.length);
        if (padded > request_length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((attribute.type & EDGE_NLA_TYPE_MASK) ==
            EDGE_INET_DIAG_REQ_SK_BPF_STORAGES) {
            storage_attribute =
                (const edge_sock_diag_nlattr_t *)(request_data + offset);
            storage_length = attribute.length;
        }
        offset += padded;
    }
    if (!storage_attribute) return 0;
    query->requested = 1u;
    if (!bpf_capable) return -EDGE_LINUX_EPERM;
    if (!ops || !ops->map_from_descriptor || !ops->next_map ||
        !ops->lookup || !ops->exists || !ops->release)
        return -EDGE_LINUX_EOPNOTSUPP;

    offset = sizeof(*storage_attribute);
    while (offset < storage_length) {
        int32_t descriptor;
        edge_linux_sock_diag_bpf_map_t map;
        uint32_t padded;

        if (storage_length - offset < sizeof(attribute)) {
            status = -EDGE_LINUX_EINVAL;
            goto error;
        }
        memcpy(&attribute,
               (const uint8_t *)storage_attribute + offset,
               sizeof(attribute));
        if (attribute.length < sizeof(attribute) ||
            attribute.length > storage_length - offset) {
            status = -EDGE_LINUX_EINVAL;
            goto error;
        }
        padded = edge_sock_diag_align(attribute.length);
        if (padded > storage_length - offset) {
            status = -EDGE_LINUX_EINVAL;
            goto error;
        }
        if ((attribute.type & EDGE_NLA_TYPE_MASK) ==
            EDGE_SK_DIAG_BPF_STORAGE_REQ_MAP_FD) {
            if (attribute.length != sizeof(attribute) +
                                    sizeof(descriptor)) {
                status = -EDGE_LINUX_EINVAL;
                goto error;
            }
            memcpy(&descriptor,
                   (const uint8_t *)storage_attribute + offset +
                       sizeof(attribute),
                   sizeof(descriptor));
            memset(&map, 0, sizeof(map));
            map.object_id = -1;
            status = ops->map_from_descriptor(
                ops->context, descriptor, &map);
            if (status < 0) goto error;
            status = edge_sock_diag_bpf_query_add(query, ops, &map);
            if (status < 0) goto error;
        }
        offset += padded;
    }
    if (query->map_count == 0u) {
        uint32_t cursor = 0u;

        for (;;) {
            edge_linux_sock_diag_bpf_map_t map;

            memset(&map, 0, sizeof(map));
            map.object_id = -1;
            status = ops->next_map(ops->context, &cursor, &map);
            if (status == -EDGE_LINUX_ENOENT) break;
            if (status < 0) goto error;
            status = edge_sock_diag_bpf_query_add(query, ops, &map);
            if (status < 0) goto error;
        }
    }
    return 0;

error:
    edge_sock_diag_bpf_query_release(query, ops);
    return status;
}

static int edge_sock_diag_append_bpf_storage(
    const edge_sock_diag_bpf_query_t *query,
    const edge_linux_sock_diag_bpf_ops_t *ops,
    const edge_linux_sock_diag_snapshot_t *snapshot,
    uint8_t *response, uint32_t response_capacity,
    uint32_t *offset) {
    uint32_t outer_start;
    uint32_t position;
    uint32_t index;
    uint32_t written = 0u;

    if (!query || !query->requested || query->map_count == 0u) return 0;
    if (!ops || !snapshot || !response || !offset)
        return -EDGE_LINUX_EINVAL;
    outer_start = *offset;
    if (outer_start > response_capacity ||
        sizeof(edge_sock_diag_nlattr_t) > response_capacity - outer_start)
        return -EDGE_LINUX_ENOBUFS;
    position = outer_start + sizeof(edge_sock_diag_nlattr_t);

    for (index = 0; index < query->map_count; ++index) {
        const edge_linux_sock_diag_bpf_map_t *map = &query->maps[index];
        edge_sock_diag_nlattr_t attribute;
        uint32_t storage_start;
        uint32_t value_start;
        uint32_t value_total;
        uint32_t item_start = position;
        int status;

        status = ops->exists(
            ops->context, map, snapshot->socket_identity);
        if (status == -EDGE_LINUX_ENOENT) continue;
        if (status < 0) return status;
        storage_start = position;
        if (position > response_capacity ||
            sizeof(attribute) + 2u * sizeof(uint32_t) >
                response_capacity - position)
            return -EDGE_LINUX_ENOBUFS;
        position += sizeof(attribute);
        attribute.length = sizeof(attribute) + sizeof(uint32_t);
        attribute.type = EDGE_SK_DIAG_BPF_STORAGE_MAP_ID;
        memcpy(response + position, &attribute, sizeof(attribute));
        memcpy(response + position + sizeof(attribute),
               &map->user_id, sizeof(map->user_id));
        position += edge_sock_diag_align(attribute.length);
        if (((uintptr_t)(response + position + sizeof(attribute)) & 7u) != 0u) {
            if (position > response_capacity ||
                sizeof(attribute) > response_capacity - position)
                return -EDGE_LINUX_ENOBUFS;
            attribute.length = sizeof(attribute);
            attribute.type = EDGE_SK_DIAG_BPF_STORAGE_PAD;
            memcpy(response + position, &attribute, sizeof(attribute));
            position += sizeof(attribute);
        }
        value_start = position;
        value_total = edge_sock_diag_align(
            (uint32_t)sizeof(attribute) + map->value_size);
        if (position > response_capacity ||
            value_total > response_capacity - position)
            return -EDGE_LINUX_ENOBUFS;
        attribute.length = (uint16_t)(sizeof(attribute) + map->value_size);
        attribute.type = EDGE_SK_DIAG_BPF_STORAGE_MAP_VALUE;
        memcpy(response + position, &attribute, sizeof(attribute));
        status = ops->lookup(
            ops->context, map, snapshot->socket_identity,
            response + position + sizeof(attribute));
        if (status == -EDGE_LINUX_ENOENT) {
            position = item_start;
            continue;
        }
        if (status < 0) return status;
        if (value_total > attribute.length)
            memset(response + value_start + attribute.length, 0,
                   value_total - attribute.length);
        position += value_total;
        attribute.length = (uint16_t)(position - storage_start);
        attribute.type = EDGE_SK_DIAG_BPF_STORAGE | EDGE_NLA_F_NESTED;
        memcpy(response + storage_start, &attribute, sizeof(attribute));
        ++written;
    }
    if (written == 0u) return 0;
    {
        edge_sock_diag_nlattr_t outer;

        outer.length = (uint16_t)(position - outer_start);
        outer.type = EDGE_INET_DIAG_SK_BPF_STORAGES | EDGE_NLA_F_NESTED;
        memcpy(response + outer_start, &outer, sizeof(outer));
    }
    *offset = position;
    return 0;
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

int edge_linux_sock_diag_respond_with_bpf_storage(
    uint32_t network_namespace, uint32_t port_id,
    const void *request_data,
    uint32_t request_length,
    edge_linux_sock_diag_snapshot_fn snapshot_at, void *snapshot_context,
    uint32_t snapshot_limit, void *response_data, uint32_t response_capacity,
    uint32_t *response_length, int bpf_capable,
    const edge_linux_sock_diag_bpf_ops_t *bpf_ops) {
    edge_sock_diag_nlmsghdr_t request_header;
    edge_inet_diag_request_v2_t request;
    edge_sock_diag_bpf_query_t bpf_query;
    uint8_t *response = (uint8_t *)response_data;
    uint32_t offset = 0;
    uint32_t ordinal;
    int result;

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
    result = edge_sock_diag_bpf_query_prepare(
        (const uint8_t *)request_data, request_header.length,
        (uint32_t)(sizeof(request_header) + sizeof(request)),
        bpf_capable, bpf_ops, &bpf_query);
    if (result < 0) return result;

    for (ordinal = 0; ordinal < snapshot_limit; ++ordinal) {
        edge_linux_sock_diag_snapshot_t snapshot;
        edge_sock_diag_nlmsghdr_t output_header;
        edge_inet_diag_message_t message;
        uint32_t message_start = offset;
        uint32_t base_length =
            (uint32_t)(sizeof(output_header) + sizeof(message));
        uint32_t message_end;
        uint32_t padded_length;
        int available;

        memset(&snapshot, 0, sizeof(snapshot));
        available = snapshot_at(
            snapshot_context, network_namespace, ordinal, &snapshot);
        if (available < 0) {
            result = available;
            goto out_release;
        }
        if (!available || !edge_sock_diag_matches(&request, &snapshot))
            continue;
        if (offset > response_capacity ||
            base_length > response_capacity - offset) {
            result = -EDGE_LINUX_ENOBUFS;
            goto out_release;
        }
        memset(&output_header, 0, sizeof(output_header));
        output_header.length = base_length;
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
        message_end = offset + base_length;
        result = edge_sock_diag_append_bpf_storage(
            &bpf_query, bpf_ops, &snapshot,
            response, response_capacity, &message_end);
        if (result < 0) goto out_release;
        output_header.length = message_end - message_start;
        memcpy(response + message_start, &output_header,
               sizeof(output_header));
        padded_length = edge_sock_diag_align(output_header.length);
        if (message_start > response_capacity ||
            padded_length > response_capacity - message_start) {
            result = -EDGE_LINUX_ENOBUFS;
            goto out_release;
        }
        if (padded_length > output_header.length)
            memset(response + message_start + output_header.length, 0,
                   padded_length - output_header.length);
        offset = message_start + padded_length;
    }
    {
        struct {
            edge_sock_diag_nlmsghdr_t header;
            int32_t status;
        } done;

        if (offset > response_capacity ||
            sizeof(done) > response_capacity - offset) {
            result = -EDGE_LINUX_ENOBUFS;
            goto out_release;
        }
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
    result = 0;
out_release:
    edge_sock_diag_bpf_query_release(&bpf_query, bpf_ops);
    return result;
}

int edge_linux_sock_diag_respond(
    uint32_t network_namespace, uint32_t port_id,
    const void *request_data, uint32_t request_length,
    edge_linux_sock_diag_snapshot_fn snapshot_at, void *snapshot_context,
    uint32_t snapshot_limit, void *response_data, uint32_t response_capacity,
    uint32_t *response_length) {
    return edge_linux_sock_diag_respond_with_bpf_storage(
        network_namespace, port_id, request_data, request_length,
        snapshot_at, snapshot_context, snapshot_limit,
        response_data, response_capacity, response_length, 0, 0);
}
