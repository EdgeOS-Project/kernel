/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Netlink delivery policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/socket_runtime.h"

static int netlink_payload_validate(const void *payload, uint32_t length) {
    if (!payload && length) return -EDGE_LINUX_EFAULT;
    if (length > arch_socket_netlink_payload_capacity())
        return -EDGE_LINUX_EMSGSIZE;
    return 0;
}

static int netlink_endpoint_view(
    uint32_t index, kernel_socket_netlink_endpoint_t *endpoint) {
    if (!endpoint) return -EDGE_LINUX_EFAULT;
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->identity = -1;
    return arch_socket_netlink_endpoint_view(index, endpoint);
}

static int netlink_broadcast(
    uint32_t network_namespace, int namespace_scoped,
    uint32_t protocol, uint32_t destination_groups,
    uint16_t message_type, int kernel_originated,
    const void *payload, uint32_t length) {
    kernel_socket_netlink_source_t source;
    uint32_t endpoint_count;
    int delivered = 0;
    int congested = 0;
    int status;

    status = netlink_payload_validate(payload, length);
    if (status < 0) return status;
    memset(&source, 0, sizeof(source));
    source.groups = destination_groups;
    source.network_namespace = network_namespace;
    source.message_type = message_type;
    source.kernel_originated = kernel_originated ? 1u : 0u;
    source.endpoint_identity = -1;
    endpoint_count = arch_socket_netlink_endpoint_count();
    for (uint32_t index = 0; index < endpoint_count; ++index) {
        kernel_socket_netlink_endpoint_t endpoint;

        if (netlink_endpoint_view(index, &endpoint) < 0 ||
            !endpoint.active ||
            endpoint.protocol != protocol ||
            (namespace_scoped &&
             endpoint.network_namespace != network_namespace) ||
            (destination_groups &&
             !(endpoint.groups & destination_groups)))
            continue;
        if (arch_socket_netlink_enqueue(
                index, payload, length, &source) < 0) {
            congested = 1;
            continue;
        }
        ++delivered;
    }
    if (!delivered && congested) return -EDGE_LINUX_ENOBUFS;
    return 0;
}

int kernel_socket_broadcast_netlink_datagram(
    uint32_t protocol, uint32_t destination_groups,
    const void *payload, uint32_t length) {
    return netlink_broadcast(
        0u, 0, protocol, destination_groups, 0u, 0,
        payload, length);
}

int kernel_socket_broadcast_netlink_event(
    uint32_t network_namespace, uint32_t protocol,
    uint32_t destination_groups, uint16_t message_type,
    const void *payload, uint32_t length) {
    return netlink_broadcast(
        network_namespace, 1, protocol, destination_groups,
        message_type, 1, payload, length);
}

int kernel_socket_netlink_deliver_datagram(
    int32_t descriptor, uint32_t protocol, uint32_t destination_port,
    uint32_t destination_groups, const void *payload, uint32_t length) {
    kernel_socket_netlink_source_t source;
    uint32_t endpoint_count;
    int delivered = 0;
    int congested = 0;
    int status;

    memset(&source, 0, sizeof(source));
    source.endpoint_identity = -1;
    status = arch_socket_netlink_sender_inspect(
        descriptor, protocol, &source);
    if (status < 0) return status;
    status = netlink_payload_validate(payload, length);
    if (status < 0) return status;
    status = arch_socket_netlink_sender_bind(&source);
    if (status < 0) return status;
    source.groups = destination_groups;

    endpoint_count = arch_socket_netlink_endpoint_count();
    for (uint32_t index = 0; index < endpoint_count; ++index) {
        kernel_socket_netlink_endpoint_t endpoint;
        int port_match;
        int group_match;

        if (netlink_endpoint_view(index, &endpoint) < 0 ||
            !endpoint.active || endpoint.protocol != protocol)
            continue;
        if (endpoint.network_namespace != source.network_namespace)
            continue;
        port_match = destination_port &&
            endpoint.port_id == destination_port;
        group_match = destination_groups &&
            (endpoint.groups & destination_groups);
        if (!port_match && !group_match) continue;
        if (group_match &&
            endpoint.identity == source.endpoint_identity &&
            !port_match)
            continue;
        if (arch_socket_netlink_enqueue(
                index, payload, length, &source) < 0) {
            congested = 1;
            continue;
        }
        ++delivered;
    }
    if (delivered) return 0;
    if (congested) return -EDGE_LINUX_ENOBUFS;
    return destination_port ?
        -EDGE_LINUX_ECONNREFUSED : -EDGE_LINUX_ESRCH;
}
