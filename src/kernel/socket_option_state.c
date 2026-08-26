/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent socket option state policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/socket_runtime.h"
#include "kernel/linux_errno.h"

#include <string.h>

void kernel_socket_option_state_initialize(
    kernel_socket_option_state_t *state, uint32_t buffer_capacity) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->send_buffer = buffer_capacity;
    state->receive_buffer = buffer_capacity;
    state->send_low_water = 1;
    state->receive_low_water = 1;
    state->ip_ttl = 64;
    state->ip_multicast_ttl = 1;
    state->ip_multicast_loop = 1;
    state->ip_mtu_discover = 1;
    state->ipv6_multicast_hops = 1;
    state->ipv6_multicast_loop = 1;
    state->tcp_keep_idle = 7200;
    state->tcp_keep_interval = 75;
    state->tcp_keep_count = 9;
}

int kernel_socket_icmp6_filter_allows(
    const kernel_socket_option_state_t *state, uint8_t type) {
    uint32_t word;
    uint32_t mask;

    if (!state) return 0;
    word = (uint32_t)type >> 5;
    mask = 1u << ((uint32_t)type & 31u);
    return (state->icmp6_filter[word] & mask) == 0u;
}

static kernel_socket_timestamp_mode_t kernel_socket_timestamp_mode(
    kernel_socket_option_id_t option) {
    switch (option) {
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_OLD:
        return KERNEL_SOCKET_TIMESTAMP_US_OLD;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_NEW:
        return KERNEL_SOCKET_TIMESTAMP_US_NEW;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_OLD:
        return KERNEL_SOCKET_TIMESTAMP_NS_OLD;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_NEW:
        return KERNEL_SOCKET_TIMESTAMP_NS_NEW;
    default:
        return KERNEL_SOCKET_TIMESTAMP_DISABLED;
    }
}

int kernel_socket_option_state_set_integer(
    kernel_socket_option_state_t *state, kernel_socket_option_id_t option,
    int64_t value, uint32_t *effects) {
    uint32_t selected_effects = KERNEL_SOCKET_OPTION_EFFECT_NONE;
    kernel_socket_timestamp_mode_t timestamp_mode;

    if (!state) return -EDGE_LINUX_EINVAL;
    switch (option) {
    case KERNEL_SOCKET_OPTION_PASS_CREDENTIALS:
        state->pass_credentials = value != 0;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_PASS_CREDENTIALS;
        break;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_OLD:
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_NEW:
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_OLD:
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_NEW:
        timestamp_mode = kernel_socket_timestamp_mode(option);
        if (value)
            state->timestamp_mode = timestamp_mode;
        else if (state->timestamp_mode == timestamp_mode)
            state->timestamp_mode = KERNEL_SOCKET_TIMESTAMP_DISABLED;
        break;
    case KERNEL_SOCKET_OPTION_REUSE_ADDRESS:
        state->reuse_address = value != 0;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_REUSE_PORT:
        state->reuse_port = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_BROADCAST:
        state->broadcast = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_KEEPALIVE:
        state->keepalive = value != 0;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_OOB_INLINE:
        state->oob_inline = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_NO_CHECK:
        state->no_check = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_LINGER_ENABLED:
        state->linger_enabled = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_LINGER_SECONDS:
        state->linger_seconds = (int32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_PRIORITY:
        state->priority = (int32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_MARK:
        state->mark = (uint32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_SEND_BUFFER:
        state->send_buffer = (uint32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_RECEIVE_BUFFER:
        state->receive_buffer = (uint32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_SEND_LOW_WATER:
        state->send_low_water = (uint32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_RECEIVE_LOW_WATER:
        state->receive_low_water = (uint32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_IP_TOS:
        state->ip_tos = (uint8_t)value;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_IP_TTL:
        state->ip_ttl = (uint8_t)value;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_TTL:
        state->ip_multicast_ttl = (uint8_t)value;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_LOOP:
        state->ip_multicast_loop = value != 0;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_IP_PACKET_INFO:
        state->ip_packet_info = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IP_RECEIVE_ERROR:
        state->ip_receive_error = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IP_RECEIVE_TTL:
        state->ip_receive_ttl = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IP_FREEBIND:
        state->ip_freebind = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IP_MTU_DISCOVER:
        state->ip_mtu_discover = (int32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_ONLY:
        state->ipv6_only = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_MULTICAST_HOPS:
        state->ipv6_multicast_hops = (int32_t)value;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_MULTICAST_LOOP:
        state->ipv6_multicast_loop = value != 0;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_ERROR:
        state->ipv6_receive_error = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_PACKET_INFO:
        state->ipv6_receive_packet_info = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_HOP_LIMIT:
        state->ipv6_receive_hop_limit = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_TRAFFIC_CLASS:
        state->ipv6_receive_traffic_class = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_CHECKSUM:
        state->ipv6_checksum = (int32_t)value;
        break;
    case KERNEL_SOCKET_OPTION_TCP_NODELAY:
        state->tcp_nodelay = value != 0;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_TCP_KEEP_IDLE:
        state->tcp_keep_idle = (int32_t)value;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_TCP_KEEP_INTERVAL:
        state->tcp_keep_interval = (int32_t)value;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_TCP_KEEP_COUNT:
        state->tcp_keep_count = (int32_t)value;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_RECEIVE_TIMEOUT_US:
        state->receive_timeout_us = (uint64_t)value;
        break;
    case KERNEL_SOCKET_OPTION_SEND_TIMEOUT_US:
        state->send_timeout_us = (uint64_t)value;
        break;
    case KERNEL_SOCKET_OPTION_IP_HEADER_INCLUDED:
        state->ip_header_included = value != 0;
        selected_effects |= KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT;
        break;
    case KERNEL_SOCKET_OPTION_NETLINK_PACKET_INFO:
        state->netlink_packet_info = value != 0;
        break;
    case KERNEL_SOCKET_OPTION_FILTER_LOCKED:
        if (state->filter_locked && !value)
            return -EDGE_LINUX_EPERM;
        state->filter_locked = value != 0;
        break;
    default:
        return -EDGE_LINUX_EINVAL;
    }
    if (effects) *effects = selected_effects;
    return 0;
}

int kernel_socket_option_state_get_integer(
    const kernel_socket_option_state_t *state,
    kernel_socket_option_id_t option, int64_t *value) {
    if (!state || !value) return -EDGE_LINUX_EINVAL;
    switch (option) {
    case KERNEL_SOCKET_OPTION_PASS_CREDENTIALS:
        *value = state->pass_credentials;
        break;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_OLD:
        *value = state->timestamp_mode == KERNEL_SOCKET_TIMESTAMP_US_OLD;
        break;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_US_NEW:
        *value = state->timestamp_mode == KERNEL_SOCKET_TIMESTAMP_US_NEW;
        break;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_OLD:
        *value = state->timestamp_mode == KERNEL_SOCKET_TIMESTAMP_NS_OLD;
        break;
    case KERNEL_SOCKET_OPTION_TIMESTAMP_NS_NEW:
        *value = state->timestamp_mode == KERNEL_SOCKET_TIMESTAMP_NS_NEW;
        break;
    case KERNEL_SOCKET_OPTION_REUSE_ADDRESS:
        *value = state->reuse_address;
        break;
    case KERNEL_SOCKET_OPTION_REUSE_PORT:
        *value = state->reuse_port;
        break;
    case KERNEL_SOCKET_OPTION_BROADCAST:
        *value = state->broadcast;
        break;
    case KERNEL_SOCKET_OPTION_KEEPALIVE:
        *value = state->keepalive;
        break;
    case KERNEL_SOCKET_OPTION_OOB_INLINE:
        *value = state->oob_inline;
        break;
    case KERNEL_SOCKET_OPTION_NO_CHECK:
        *value = state->no_check;
        break;
    case KERNEL_SOCKET_OPTION_LINGER_ENABLED:
        *value = state->linger_enabled;
        break;
    case KERNEL_SOCKET_OPTION_LINGER_SECONDS:
        *value = state->linger_seconds;
        break;
    case KERNEL_SOCKET_OPTION_PRIORITY:
        *value = state->priority;
        break;
    case KERNEL_SOCKET_OPTION_MARK:
        *value = state->mark;
        break;
    case KERNEL_SOCKET_OPTION_SEND_BUFFER:
        *value = state->send_buffer;
        break;
    case KERNEL_SOCKET_OPTION_RECEIVE_BUFFER:
        *value = state->receive_buffer;
        break;
    case KERNEL_SOCKET_OPTION_SEND_LOW_WATER:
        *value = state->send_low_water;
        break;
    case KERNEL_SOCKET_OPTION_RECEIVE_LOW_WATER:
        *value = state->receive_low_water;
        break;
    case KERNEL_SOCKET_OPTION_IP_TOS:
        *value = state->ip_tos;
        break;
    case KERNEL_SOCKET_OPTION_IP_TTL:
        *value = state->ip_ttl;
        break;
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_TTL:
        *value = state->ip_multicast_ttl;
        break;
    case KERNEL_SOCKET_OPTION_IP_MULTICAST_LOOP:
        *value = state->ip_multicast_loop;
        break;
    case KERNEL_SOCKET_OPTION_IP_PACKET_INFO:
        *value = state->ip_packet_info;
        break;
    case KERNEL_SOCKET_OPTION_IP_RECEIVE_ERROR:
        *value = state->ip_receive_error;
        break;
    case KERNEL_SOCKET_OPTION_IP_RECEIVE_TTL:
        *value = state->ip_receive_ttl;
        break;
    case KERNEL_SOCKET_OPTION_IP_FREEBIND:
        *value = state->ip_freebind;
        break;
    case KERNEL_SOCKET_OPTION_IP_MTU_DISCOVER:
        *value = state->ip_mtu_discover;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_ONLY:
        *value = state->ipv6_only;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_MULTICAST_HOPS:
        *value = state->ipv6_multicast_hops;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_MULTICAST_LOOP:
        *value = state->ipv6_multicast_loop;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_ERROR:
        *value = state->ipv6_receive_error;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_PACKET_INFO:
        *value = state->ipv6_receive_packet_info;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_HOP_LIMIT:
        *value = state->ipv6_receive_hop_limit;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_RECEIVE_TRAFFIC_CLASS:
        *value = state->ipv6_receive_traffic_class;
        break;
    case KERNEL_SOCKET_OPTION_IPV6_CHECKSUM:
        *value = state->ipv6_checksum;
        break;
    case KERNEL_SOCKET_OPTION_TCP_NODELAY:
        *value = state->tcp_nodelay;
        break;
    case KERNEL_SOCKET_OPTION_TCP_KEEP_IDLE:
        *value = state->tcp_keep_idle;
        break;
    case KERNEL_SOCKET_OPTION_TCP_KEEP_INTERVAL:
        *value = state->tcp_keep_interval;
        break;
    case KERNEL_SOCKET_OPTION_TCP_KEEP_COUNT:
        *value = state->tcp_keep_count;
        break;
    case KERNEL_SOCKET_OPTION_RECEIVE_TIMEOUT_US:
        *value = (int64_t)state->receive_timeout_us;
        break;
    case KERNEL_SOCKET_OPTION_SEND_TIMEOUT_US:
        *value = (int64_t)state->send_timeout_us;
        break;
    case KERNEL_SOCKET_OPTION_IP_HEADER_INCLUDED:
        *value = state->ip_header_included;
        break;
    case KERNEL_SOCKET_OPTION_NETLINK_PACKET_INFO:
        *value = state->netlink_packet_info;
        break;
    case KERNEL_SOCKET_OPTION_FILTER_LOCKED:
        *value = state->filter_locked;
        break;
    default:
        return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

int kernel_socket_bound_device_parse(
    const char *name, uint32_t length, int32_t *interface_index) {
    if (!name || !interface_index) return -EDGE_LINUX_EINVAL;
    if (!length || !name[0])
        *interface_index = 0;
    else if (strcmp(name, "lo") == 0)
        *interface_index = 1;
    else if (strcmp(name, "eth0") == 0)
        *interface_index = 2;
    else
        return -EDGE_LINUX_ENODEV;
    return 0;
}

int kernel_socket_bound_device_format(
    int32_t interface_index, char *name, uint32_t capacity,
    uint32_t *length) {
    const char *source = "";
    uint32_t required = 0;

    if (!name || !length) return -EDGE_LINUX_EINVAL;
    if (interface_index == 1)
        source = "lo";
    else if (interface_index == 2)
        source = "eth0";
    if (interface_index == 1 || interface_index == 2)
        required = (uint32_t)strlen(source) + 1u;
    if (capacity < required) return -EDGE_LINUX_EINVAL;
    if (required) memcpy(name, source, required);
    *length = required;
    return 0;
}

int kernel_socket_error_take(int32_t *stored_error, int32_t *error) {
    if (!stored_error || !error) return -EDGE_LINUX_EINVAL;
    *error = *stored_error;
    *stored_error = 0;
    return 0;
}

int32_t kernel_socket_mtu_normalize(uint32_t transport_mtu) {
    return transport_mtu ? (int32_t)transport_mtu : 1500;
}

int kernel_socket_udp_local_refusal_policy(
    int connected, uint16_t destination_port,
    int destination_is_loopback, int destination_is_bound) {
    return connected && destination_port && destination_is_loopback &&
           !destination_is_bound;
}

int kernel_socket_udp_local_delivery_match(
    uint32_t sender_namespace, uint32_t receiver_namespace,
    uint16_t destination_port, uint16_t receiver_port,
    const uint8_t *destination_address,
    const uint8_t *receiver_address, uint32_t address_length,
    int receiver_address_is_any) {
    if (sender_namespace != receiver_namespace || !destination_port ||
        destination_port != receiver_port || !destination_address ||
        !receiver_address || (address_length != 4u && address_length != 16u))
        return 0;
    return receiver_address_is_any ||
        memcmp(destination_address, receiver_address, address_length) == 0;
}
