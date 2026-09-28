/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux ethtool Netlink policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_ethtool.h"
#include "net/network_core.h"

#define EDGE_NLMSG_DONE 3u
#define EDGE_NLM_F_MULTI 2u
#define EDGE_NLM_F_DUMP 0x300u
#define EDGE_NLA_F_NESTED 0x8000u

#define EDGE_ETHTOOL_A_HEADER 1u
#define EDGE_ETHTOOL_A_STATS_HEADER 2u
#define EDGE_ETHTOOL_A_STATS_GROUPS 3u
#define EDGE_ETHTOOL_A_STATS_GRP 4u
#define EDGE_ETHTOOL_A_STATS_SRC 5u
#define EDGE_ETHTOOL_A_HEADER_DEV_INDEX 1u
#define EDGE_ETHTOOL_A_HEADER_DEV_NAME 2u
#define EDGE_ETHTOOL_A_HEADER_FLAGS 3u

#define EDGE_ETHTOOL_A_BITSET_NOMASK 1u
#define EDGE_ETHTOOL_A_BITSET_SIZE 2u
#define EDGE_ETHTOOL_A_BITSET_BITS 3u
#define EDGE_ETHTOOL_A_BITSET_VALUE 4u
#define EDGE_ETHTOOL_A_BITSET_MASK 5u
#define EDGE_ETHTOOL_A_BITSET_BITS_BIT 1u
#define EDGE_ETHTOOL_A_BITSET_BIT_INDEX 1u
#define EDGE_ETHTOOL_A_BITSET_BIT_NAME 2u
#define EDGE_ETHTOOL_A_BITSET_BIT_VALUE 3u

#define EDGE_ETHTOOL_A_STATS_GRP_ID 2u
#define EDGE_ETHTOOL_A_STATS_GRP_SS_ID 3u
#define EDGE_ETHTOOL_A_STATS_GRP_STAT 4u
#define EDGE_ETHTOOL_STATS_GROUP_COUNT 5u
#define EDGE_ETHTOOL_STATS_ETH_MAC 1u
#define EDGE_ETH_SS_STATS_ETH_PHY 17u
#define EDGE_ETH_SS_STATS_ETH_MAC 18u
#define EDGE_ETH_SS_STATS_ETH_CTRL 19u
#define EDGE_ETH_SS_STATS_RMON 20u
#define EDGE_ETH_SS_STATS_PHY 21u
#define EDGE_ETHTOOL_A_STATS_ETH_MAC_TX_PACKETS 0u
#define EDGE_ETHTOOL_A_STATS_ETH_MAC_RX_PACKETS 3u
#define EDGE_ETHTOOL_A_STATS_ETH_MAC_TX_BYTES 6u
#define EDGE_ETHTOOL_A_STATS_ETH_MAC_RX_BYTES 12u
#define EDGE_ETHTOOL_MAC_STATS_SRC_AGGREGATE 0u

#define EDGE_ETHTOOL_A_LINKINFO_PORT 2u
#define EDGE_ETHTOOL_A_LINKMODES_SPEED 5u
#define EDGE_ETHTOOL_A_LINKMODES_DUPLEX 6u
#define EDGE_ETHTOOL_A_LINKSTATE_LINK 2u
#define EDGE_ETHTOOL_A_CHANNELS_COMBINED_MAX 5u
#define EDGE_ETHTOOL_A_CHANNELS_COMBINED_COUNT 9u
#define EDGE_ETHTOOL_PORT_OTHER 0xffu
#define EDGE_ETHTOOL_SPEED_UNKNOWN 0xffffffffu
#define EDGE_ETHTOOL_DUPLEX_UNKNOWN 0xffu

typedef struct edge_ethtool_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} edge_ethtool_nlmsghdr_t;

typedef struct edge_ethtool_genl_header {
    uint8_t command;
    uint8_t version;
    uint16_t reserved;
} edge_ethtool_genl_header_t;

typedef struct edge_ethtool_attribute {
    uint16_t length;
    uint16_t type;
} edge_ethtool_attribute_t;

typedef struct edge_ethtool_selector {
    int index_seen;
    int name_seen;
    int32_t index;
    char name[EDGE_NET_DEVICE_NAME_MAX];
    uint32_t stats_groups;
} edge_ethtool_selector_t;

static const char *const g_edge_ethtool_stats_group_names[] = {
    "eth-phy", "eth-mac", "eth-ctrl", "rmon", "phydev"
};

static uint32_t edge_ethtool_align(uint32_t value) {
    return (value + 3u) & ~3u;
}

static int edge_ethtool_append_attribute(
    uint8_t *buffer, uint32_t capacity, uint32_t *offset, uint16_t type,
    const void *payload, uint16_t payload_length) {
    edge_ethtool_attribute_t attribute;
    uint32_t length = (uint32_t)sizeof(attribute) + payload_length;
    uint32_t padded_length = edge_ethtool_align(length);

    if (*offset > capacity || padded_length > capacity - *offset)
        return -EDGE_LINUX_ENOBUFS;
    attribute.length = (uint16_t)length;
    attribute.type = type;
    memcpy(buffer + *offset, &attribute, sizeof(attribute));
    if (payload_length)
        memcpy(buffer + *offset + sizeof(attribute), payload,
               payload_length);
    if (padded_length > length)
        memset(buffer + *offset + length, 0, padded_length - length);
    *offset += padded_length;
    return 0;
}

static int edge_ethtool_begin_nested(
    uint8_t *buffer, uint32_t capacity, uint32_t *offset,
    uint32_t *nested_offset) {
    edge_ethtool_attribute_t attribute;

    if (!nested_offset || *offset > capacity ||
        sizeof(attribute) > capacity - *offset)
        return -EDGE_LINUX_ENOBUFS;
    *nested_offset = *offset;
    memset(&attribute, 0, sizeof(attribute));
    memcpy(buffer + *offset, &attribute, sizeof(attribute));
    *offset += sizeof(attribute);
    return 0;
}

static void edge_ethtool_end_nested(
    uint8_t *buffer, uint32_t offset, uint32_t nested_offset,
    uint16_t type) {
    edge_ethtool_attribute_t attribute;

    attribute.length = (uint16_t)(offset - nested_offset);
    attribute.type = (uint16_t)(type | EDGE_NLA_F_NESTED);
    memcpy(buffer + nested_offset, &attribute, sizeof(attribute));
}

static int edge_ethtool_parse_header(
    const uint8_t *request, uint32_t request_length, uint32_t offset,
    uint16_t header_type, edge_ethtool_selector_t *selector,
    int *header_seen) {
    while (offset < request_length) {
        edge_ethtool_attribute_t outer;
        uint32_t outer_end;
        uint32_t inner_offset;

        if (request_length - offset < sizeof(outer))
            return -EDGE_LINUX_EINVAL;
        memcpy(&outer, request + offset, sizeof(outer));
        if (outer.length < sizeof(outer) ||
            outer.length > request_length - offset ||
            edge_ethtool_align(outer.length) > request_length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((outer.type & 0x3fffu) != header_type) {
            offset += edge_ethtool_align(outer.length);
            continue;
        }
        *header_seen = 1;
        outer_end = offset + outer.length;
        inner_offset = offset + sizeof(outer);
        while (inner_offset < outer_end) {
            edge_ethtool_attribute_t attribute;
            uint32_t payload_length;

            if (outer_end - inner_offset < sizeof(attribute))
                return -EDGE_LINUX_EINVAL;
            memcpy(&attribute, request + inner_offset, sizeof(attribute));
            if (attribute.length < sizeof(attribute) ||
                attribute.length > outer_end - inner_offset ||
                edge_ethtool_align(attribute.length) >
                    outer_end - inner_offset)
                return -EDGE_LINUX_EINVAL;
            payload_length = attribute.length - sizeof(attribute);
            if (attribute.type == EDGE_ETHTOOL_A_HEADER_DEV_INDEX) {
                if (payload_length != sizeof(selector->index))
                    return -EDGE_LINUX_EINVAL;
                memcpy(&selector->index,
                       request + inner_offset + sizeof(attribute),
                       sizeof(selector->index));
                if (selector->index <= 0) return -EDGE_LINUX_EINVAL;
                selector->index_seen = 1;
            } else if (attribute.type == EDGE_ETHTOOL_A_HEADER_DEV_NAME) {
                const uint8_t *name =
                    request + inner_offset + sizeof(attribute);
                if (payload_length < 2u ||
                    payload_length > sizeof(selector->name) ||
                    name[payload_length - 1u] != 0u)
                    return -EDGE_LINUX_EINVAL;
                memcpy(selector->name, name, payload_length);
                selector->name_seen = 1;
            } else if (attribute.type == EDGE_ETHTOOL_A_HEADER_FLAGS) {
                uint32_t flags;
                if (payload_length != sizeof(flags))
                    return -EDGE_LINUX_EINVAL;
                memcpy(&flags, request + inner_offset + sizeof(attribute),
                       sizeof(flags));
                if (flags & ~7u) return -EDGE_LINUX_EINVAL;
            }
            inner_offset += edge_ethtool_align(attribute.length);
        }
        offset += edge_ethtool_align(outer.length);
    }
    return 0;
}

static int edge_ethtool_stats_group_from_name(
    const uint8_t *name, uint32_t length, uint32_t *group) {
    uint32_t index;

    if (!name || !length || name[length - 1u] != 0u || !group)
        return -EDGE_LINUX_EINVAL;
    for (index = 0; index < EDGE_ETHTOOL_STATS_GROUP_COUNT; ++index) {
        uint32_t expected_length =
            (uint32_t)strlen(g_edge_ethtool_stats_group_names[index]) + 1u;
        if (length == expected_length &&
            memcmp(name, g_edge_ethtool_stats_group_names[index],
                   length) == 0) {
            *group = index;
            return 0;
        }
    }
    return -EDGE_LINUX_EOPNOTSUPP;
}

static int edge_ethtool_parse_stats_verbose_bits(
    const uint8_t *request, uint32_t bits_offset, uint32_t bits_end,
    int no_mask, uint32_t *groups) {
    while (bits_offset < bits_end) {
        edge_ethtool_attribute_t bit;
        uint32_t bit_end;
        uint32_t offset;
        uint32_t group = UINT32_MAX;
        uint32_t name_group = UINT32_MAX;
        int index_seen = 0;
        int name_seen = 0;
        int value_seen = 0;

        if (bits_end - bits_offset < sizeof(bit))
            return -EDGE_LINUX_EINVAL;
        memcpy(&bit, request + bits_offset, sizeof(bit));
        if ((bit.type & 0x3fffu) != EDGE_ETHTOOL_A_BITSET_BITS_BIT ||
            bit.length < sizeof(bit) || bit.length > bits_end - bits_offset ||
            edge_ethtool_align(bit.length) > bits_end - bits_offset)
            return -EDGE_LINUX_EINVAL;
        bit_end = bits_offset + bit.length;
        offset = bits_offset + sizeof(bit);
        while (offset < bit_end) {
            edge_ethtool_attribute_t attribute;
            uint32_t payload_length;
            uint16_t type;

            if (bit_end - offset < sizeof(attribute))
                return -EDGE_LINUX_EINVAL;
            memcpy(&attribute, request + offset, sizeof(attribute));
            if (attribute.length < sizeof(attribute) ||
                attribute.length > bit_end - offset ||
                edge_ethtool_align(attribute.length) > bit_end - offset)
                return -EDGE_LINUX_EINVAL;
            payload_length = attribute.length - sizeof(attribute);
            type = attribute.type & 0x3fffu;
            if (type == EDGE_ETHTOOL_A_BITSET_BIT_INDEX) {
                if (payload_length != sizeof(group))
                    return -EDGE_LINUX_EINVAL;
                memcpy(&group, request + offset + sizeof(attribute),
                       sizeof(group));
                if (group >= EDGE_ETHTOOL_STATS_GROUP_COUNT)
                    return -EDGE_LINUX_EOPNOTSUPP;
                index_seen = 1;
            } else if (type == EDGE_ETHTOOL_A_BITSET_BIT_NAME) {
                int result = edge_ethtool_stats_group_from_name(
                    request + offset + sizeof(attribute), payload_length,
                    &name_group);
                if (result < 0) return result;
                name_seen = 1;
            } else if (type == EDGE_ETHTOOL_A_BITSET_BIT_VALUE) {
                if (payload_length != 0u) return -EDGE_LINUX_EINVAL;
                value_seen = 1;
            }
            offset += edge_ethtool_align(attribute.length);
        }
        if (!index_seen && !name_seen) return -EDGE_LINUX_EINVAL;
        if (index_seen && name_seen && group != name_group)
            return -EDGE_LINUX_EINVAL;
        if (!index_seen) group = name_group;
        if (no_mask || value_seen)
            *groups |= 1u << group;
        else
            *groups &= ~(1u << group);
        bits_offset += edge_ethtool_align(bit.length);
    }
    return 0;
}

static int edge_ethtool_parse_stats_groups(
    const uint8_t *request, uint32_t request_length, uint32_t offset,
    uint32_t *groups) {
    int groups_seen = 0;

    if (!groups) return -EDGE_LINUX_EINVAL;
    *groups = 0u;
    while (offset < request_length) {
        edge_ethtool_attribute_t outer;
        uint32_t outer_end;
        uint32_t inner_offset;
        uint32_t bits_offset = 0u;
        uint32_t bits_end = 0u;
        uint32_t bitset_size = 0u;
        uint32_t value = 0u;
        uint32_t mask = 0u;
        int no_mask = 0;
        int size_seen = 0;
        int value_seen = 0;
        int mask_seen = 0;

        if (request_length - offset < sizeof(outer))
            return -EDGE_LINUX_EINVAL;
        memcpy(&outer, request + offset, sizeof(outer));
        if (outer.length < sizeof(outer) ||
            outer.length > request_length - offset ||
            edge_ethtool_align(outer.length) > request_length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((outer.type & 0x3fffu) != EDGE_ETHTOOL_A_STATS_GROUPS) {
            offset += edge_ethtool_align(outer.length);
            continue;
        }
        if (groups_seen++) return -EDGE_LINUX_EINVAL;
        outer_end = offset + outer.length;
        inner_offset = offset + sizeof(outer);
        while (inner_offset < outer_end) {
            edge_ethtool_attribute_t attribute;
            uint32_t payload_length;
            uint16_t type;

            if (outer_end - inner_offset < sizeof(attribute))
                return -EDGE_LINUX_EINVAL;
            memcpy(&attribute, request + inner_offset, sizeof(attribute));
            if (attribute.length < sizeof(attribute) ||
                attribute.length > outer_end - inner_offset ||
                edge_ethtool_align(attribute.length) >
                    outer_end - inner_offset)
                return -EDGE_LINUX_EINVAL;
            payload_length = attribute.length - sizeof(attribute);
            type = attribute.type & 0x3fffu;
            if (type == EDGE_ETHTOOL_A_BITSET_NOMASK) {
                if (payload_length != 0u) return -EDGE_LINUX_EINVAL;
                no_mask = 1;
            } else if (type == EDGE_ETHTOOL_A_BITSET_SIZE) {
                if (payload_length != sizeof(bitset_size))
                    return -EDGE_LINUX_EINVAL;
                memcpy(&bitset_size,
                       request + inner_offset + sizeof(attribute),
                       sizeof(bitset_size));
                size_seen = 1;
            } else if (type == EDGE_ETHTOOL_A_BITSET_BITS) {
                bits_offset = inner_offset + sizeof(attribute);
                bits_end = inner_offset + attribute.length;
            } else if (type == EDGE_ETHTOOL_A_BITSET_VALUE ||
                       type == EDGE_ETHTOOL_A_BITSET_MASK) {
                if (payload_length != sizeof(value))
                    return -EDGE_LINUX_EINVAL;
                if (type == EDGE_ETHTOOL_A_BITSET_VALUE) {
                    memcpy(&value,
                           request + inner_offset + sizeof(attribute),
                           sizeof(value));
                    value_seen = 1;
                } else {
                    memcpy(&mask,
                           request + inner_offset + sizeof(attribute),
                           sizeof(mask));
                    mask_seen = 1;
                }
            }
            inner_offset += edge_ethtool_align(attribute.length);
        }
        if (bits_offset) {
            int result;
            if (value_seen || mask_seen) return -EDGE_LINUX_EINVAL;
            result = edge_ethtool_parse_stats_verbose_bits(
                request, bits_offset, bits_end, no_mask, groups);
            if (result < 0) return result;
        } else {
            uint32_t valid_mask =
                (1u << EDGE_ETHTOOL_STATS_GROUP_COUNT) - 1u;
            uint32_t size_mask;
            uint32_t effective_mask;
            if (!size_seen || !value_seen || !bitset_size ||
                bitset_size > 32u || (!no_mask && !mask_seen) ||
                (no_mask && mask_seen))
                return -EDGE_LINUX_EINVAL;
            size_mask = bitset_size == 32u ? UINT32_MAX :
                        (1u << bitset_size) - 1u;
            effective_mask = (no_mask ? size_mask : mask) & size_mask;
            if (effective_mask & ~valid_mask)
                return -EDGE_LINUX_EOPNOTSUPP;
            *groups = value & effective_mask & valid_mask;
        }
        offset += edge_ethtool_align(outer.length);
    }
    if (!groups_seen || !*groups) return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_ethtool_select_device(
    uint32_t network_namespace, const edge_ethtool_selector_t *selector,
    edge_net_device_snapshot_t *snapshot) {
    int32_t ifindex = selector->index;
    int result;

    if (selector->name_seen) {
        result = edge_net_device_find(
            network_namespace, selector->name, &ifindex);
        if (result != EDGE_NET_OK) return -EDGE_LINUX_ENODEV;
        if (selector->index_seen && ifindex != selector->index)
            return -EDGE_LINUX_ENODEV;
    }
    result = edge_net_route_interface_snapshot(
        ifindex, network_namespace, snapshot);
    if (result != EDGE_NET_OK) return -EDGE_LINUX_ENODEV;
    return 0;
}

static int edge_ethtool_append_header(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    const edge_net_device_snapshot_t *snapshot, uint16_t header_type) {
    edge_ethtool_attribute_t header;
    uint32_t header_offset = *offset;
    uint32_t ifindex = (uint32_t)snapshot->configuration.ifindex;
    uint16_t name_length = 0;
    int result;

    while (name_length < sizeof(snapshot->configuration.name) &&
           snapshot->configuration.name[name_length])
        ++name_length;
    if (name_length == sizeof(snapshot->configuration.name))
        return -EDGE_LINUX_EINVAL;
    ++name_length;
    if (header_offset > capacity || sizeof(header) > capacity - header_offset)
        return -EDGE_LINUX_ENOBUFS;
    memset(&header, 0, sizeof(header));
    memcpy(response + header_offset, &header, sizeof(header));
    *offset += sizeof(header);
    result = edge_ethtool_append_attribute(
        response, capacity, offset, EDGE_ETHTOOL_A_HEADER_DEV_INDEX,
        &ifindex, sizeof(ifindex));
    if (result < 0) return result;
    result = edge_ethtool_append_attribute(
        response, capacity, offset, EDGE_ETHTOOL_A_HEADER_DEV_NAME,
        snapshot->configuration.name, name_length);
    if (result < 0) return result;
    header.length = (uint16_t)(*offset - header_offset);
    header.type = (uint16_t)(header_type | EDGE_NLA_F_NESTED);
    memcpy(response + header_offset, &header, sizeof(header));
    return 0;
}

static int edge_ethtool_append_stat(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    uint16_t statistic, uint64_t value) {
    uint32_t nested_offset;
    int result;

    result = edge_ethtool_begin_nested(
        response, capacity, offset, &nested_offset);
    if (result < 0) return result;
    result = edge_ethtool_append_attribute(
        response, capacity, offset, statistic, &value, sizeof(value));
    if (result < 0) return result;
    edge_ethtool_end_nested(
        response, *offset, nested_offset, EDGE_ETHTOOL_A_STATS_GRP_STAT);
    return 0;
}

static uint32_t edge_ethtool_stats_string_set(uint32_t group) {
    static const uint32_t string_sets[EDGE_ETHTOOL_STATS_GROUP_COUNT] = {
        EDGE_ETH_SS_STATS_ETH_PHY,
        EDGE_ETH_SS_STATS_ETH_MAC,
        EDGE_ETH_SS_STATS_ETH_CTRL,
        EDGE_ETH_SS_STATS_RMON,
        EDGE_ETH_SS_STATS_PHY
    };

    return group < EDGE_ETHTOOL_STATS_GROUP_COUNT ? string_sets[group] : 0u;
}

static int edge_ethtool_append_stats(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    const edge_net_device_snapshot_t *snapshot, uint32_t groups) {
    uint32_t source = EDGE_ETHTOOL_MAC_STATS_SRC_AGGREGATE;
    int result;

    result = edge_ethtool_append_attribute(
        response, capacity, offset, EDGE_ETHTOOL_A_STATS_SRC,
        &source, sizeof(source));
    if (result < 0) return result;
    for (uint32_t group = 0; group < EDGE_ETHTOOL_STATS_GROUP_COUNT;
         ++group) {
        uint32_t nested_offset;
        uint32_t string_set;

        if (!(groups & (1u << group))) continue;
        result = edge_ethtool_begin_nested(
            response, capacity, offset, &nested_offset);
        if (result < 0) return result;
        string_set = edge_ethtool_stats_string_set(group);
        result = edge_ethtool_append_attribute(
            response, capacity, offset, EDGE_ETHTOOL_A_STATS_GRP_ID,
            &group, sizeof(group));
        if (result >= 0)
            result = edge_ethtool_append_attribute(
                response, capacity, offset, EDGE_ETHTOOL_A_STATS_GRP_SS_ID,
                &string_set, sizeof(string_set));
        if (result < 0) return result;
        if (group == EDGE_ETHTOOL_STATS_ETH_MAC) {
            result = edge_ethtool_append_stat(
                response, capacity, offset,
                EDGE_ETHTOOL_A_STATS_ETH_MAC_TX_PACKETS,
                snapshot->tx_packets);
            if (result >= 0)
                result = edge_ethtool_append_stat(
                    response, capacity, offset,
                    EDGE_ETHTOOL_A_STATS_ETH_MAC_RX_PACKETS,
                    snapshot->rx_packets);
            if (result >= 0)
                result = edge_ethtool_append_stat(
                    response, capacity, offset,
                    EDGE_ETHTOOL_A_STATS_ETH_MAC_TX_BYTES,
                    snapshot->tx_bytes);
            if (result >= 0)
                result = edge_ethtool_append_stat(
                    response, capacity, offset,
                    EDGE_ETHTOOL_A_STATS_ETH_MAC_RX_BYTES,
                    snapshot->rx_bytes);
            if (result < 0) return result;
        }
        edge_ethtool_end_nested(
            response, *offset, nested_offset, EDGE_ETHTOOL_A_STATS_GRP);
    }
    return 0;
}

static int edge_ethtool_append_reply(
    uint32_t port_id, const edge_ethtool_nlmsghdr_t *request,
    const edge_ethtool_genl_header_t *generic,
    const edge_net_device_snapshot_t *snapshot,
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    uint32_t stats_groups, int dump) {
    edge_ethtool_nlmsghdr_t header;
    edge_ethtool_genl_header_t reply;
    uint32_t message_offset = *offset;
    int result;

    if (message_offset > capacity ||
        sizeof(header) + sizeof(reply) > capacity - message_offset)
        return -EDGE_LINUX_ENOBUFS;
    memset(&header, 0, sizeof(header));
    header.type = EDGE_LINUX_GENL_ID_ETHTOOL;
    header.flags = dump ? EDGE_NLM_F_MULTI : 0u;
    header.sequence = request->sequence;
    header.port_id = port_id;
    memcpy(response + *offset, &header, sizeof(header));
    *offset += sizeof(header);
    memset(&reply, 0, sizeof(reply));
    reply.command = generic->command;
    reply.version = EDGE_LINUX_GENL_ETHTOOL_VERSION;
    memcpy(response + *offset, &reply, sizeof(reply));
    *offset += sizeof(reply);

    result = edge_ethtool_append_header(
        response, capacity, offset, snapshot,
        generic->command == EDGE_LINUX_ETHTOOL_MSG_STATS_GET ?
        EDGE_ETHTOOL_A_STATS_HEADER : EDGE_ETHTOOL_A_HEADER);
    if (result < 0) return result;
    if (generic->command == EDGE_LINUX_ETHTOOL_MSG_LINKINFO_GET) {
        uint8_t port = EDGE_ETHTOOL_PORT_OTHER;
        result = edge_ethtool_append_attribute(
            response, capacity, offset, EDGE_ETHTOOL_A_LINKINFO_PORT,
            &port, sizeof(port));
    } else if (generic->command == EDGE_LINUX_ETHTOOL_MSG_LINKMODES_GET) {
        uint32_t speed = EDGE_ETHTOOL_SPEED_UNKNOWN;
        uint8_t duplex = EDGE_ETHTOOL_DUPLEX_UNKNOWN;
        result = edge_ethtool_append_attribute(
            response, capacity, offset, EDGE_ETHTOOL_A_LINKMODES_SPEED,
            &speed, sizeof(speed));
        if (result >= 0)
            result = edge_ethtool_append_attribute(
                response, capacity, offset, EDGE_ETHTOOL_A_LINKMODES_DUPLEX,
                &duplex, sizeof(duplex));
    } else if (generic->command == EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET) {
        uint8_t link = snapshot->configuration.carrier ? 1u : 0u;
        result = edge_ethtool_append_attribute(
            response, capacity, offset, EDGE_ETHTOOL_A_LINKSTATE_LINK,
            &link, sizeof(link));
    } else if (generic->command == EDGE_LINUX_ETHTOOL_MSG_CHANNELS_GET) {
        uint32_t channels = 1u;
        result = edge_ethtool_append_attribute(
            response, capacity, offset, EDGE_ETHTOOL_A_CHANNELS_COMBINED_MAX,
            &channels, sizeof(channels));
        if (result >= 0)
            result = edge_ethtool_append_attribute(
                response, capacity, offset,
                EDGE_ETHTOOL_A_CHANNELS_COMBINED_COUNT,
                &channels, sizeof(channels));
    } else {
        result = edge_ethtool_append_stats(
            response, capacity, offset, snapshot, stats_groups);
    }
    if (result < 0) return result;
    header.length = *offset - message_offset;
    memcpy(response + message_offset, &header, sizeof(header));
    return 0;
}

int edge_linux_ethtool_respond(
    uint32_t network_namespace, uint32_t port_id,
    const void *request_data, uint32_t request_length,
    void *response_data, uint32_t response_capacity,
    uint32_t *response_length) {
    edge_ethtool_nlmsghdr_t request;
    edge_ethtool_genl_header_t generic;
    edge_ethtool_selector_t selector;
    const uint8_t *request_bytes = (const uint8_t *)request_data;
    uint8_t *response = (uint8_t *)response_data;
    uint32_t offset = 0;
    int header_seen = 0;
    int dump;
    int result;

    if (!response_length) return -EDGE_LINUX_EINVAL;
    *response_length = 0;
    if (!request_data || !response_data ||
        request_length < sizeof(request) + sizeof(generic))
        return -EDGE_LINUX_EINVAL;
    memcpy(&request, request_data, sizeof(request));
    if (request.length < sizeof(request) + sizeof(generic) ||
        request.length > request_length ||
        request.type != EDGE_LINUX_GENL_ID_ETHTOOL)
        return -EDGE_LINUX_EINVAL;
    memcpy(&generic, request_bytes + sizeof(request), sizeof(generic));
    if (generic.command != EDGE_LINUX_ETHTOOL_MSG_LINKINFO_GET &&
        generic.command != EDGE_LINUX_ETHTOOL_MSG_LINKMODES_GET &&
        generic.command != EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET &&
        generic.command != EDGE_LINUX_ETHTOOL_MSG_CHANNELS_GET &&
        generic.command != EDGE_LINUX_ETHTOOL_MSG_STATS_GET)
        return -EDGE_LINUX_EOPNOTSUPP;
    dump = (request.flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP;
    memset(&selector, 0, sizeof(selector));
    result = edge_ethtool_parse_header(
        request_bytes, request.length, sizeof(request) + sizeof(generic),
        generic.command == EDGE_LINUX_ETHTOOL_MSG_STATS_GET ?
        EDGE_ETHTOOL_A_STATS_HEADER : EDGE_ETHTOOL_A_HEADER,
        &selector, &header_seen);
    if (result < 0) return result;
    if (generic.command == EDGE_LINUX_ETHTOOL_MSG_STATS_GET) {
        result = edge_ethtool_parse_stats_groups(
            request_bytes, request.length,
            sizeof(request) + sizeof(generic), &selector.stats_groups);
        if (result < 0) return result;
    }
    if (!dump && (!header_seen ||
                  (!selector.index_seen && !selector.name_seen)))
        return -EDGE_LINUX_EINVAL;

    if (selector.index_seen || selector.name_seen) {
        edge_net_device_snapshot_t snapshot;
        result = edge_ethtool_select_device(
            network_namespace, &selector, &snapshot);
        if (result < 0) return result;
        result = edge_ethtool_append_reply(
            port_id, &request, &generic, &snapshot,
            response, response_capacity, &offset,
            selector.stats_groups, dump);
        if (result < 0) return result;
    } else {
        uint32_t ordinal;
        for (ordinal = 0; ordinal < EDGE_NET_DEVICE_MAX; ++ordinal) {
            edge_net_device_snapshot_t snapshot;
            result = edge_net_device_snapshot_at(
                network_namespace, ordinal, &snapshot);
            if (result == EDGE_NET_NOT_FOUND) break;
            if (result != EDGE_NET_OK) return -EDGE_LINUX_EIO;
            result = edge_ethtool_append_reply(
                port_id, &request, &generic, &snapshot,
                response, response_capacity, &offset,
                selector.stats_groups, 1);
            if (result < 0) return result;
        }
    }
    if (dump) {
        struct {
            edge_ethtool_nlmsghdr_t header;
            int32_t status;
        } done;
        if (offset > response_capacity ||
            sizeof(done) > response_capacity - offset)
            return -EDGE_LINUX_ENOBUFS;
        memset(&done, 0, sizeof(done));
        done.header.length = sizeof(done);
        done.header.type = EDGE_NLMSG_DONE;
        done.header.flags = EDGE_NLM_F_MULTI;
        done.header.sequence = request.sequence;
        done.header.port_id = port_id;
        memcpy(response + offset, &done, sizeof(done));
        offset += sizeof(done);
    }
    *response_length = offset;
    return 0;
}
