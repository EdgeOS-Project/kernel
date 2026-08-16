/* SPDX-License-Identifier: MPL-2.0 */
/* Unit coverage for the shared Linux netfilter netlink response policy. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_netlink.h"
#include "kernel/linux_tun.h"
#include "kernel/namespace_runtime.h"
#include "net/network_core.h"

#define TEST_AF_INET 2u
#define TEST_AF_BRIDGE 7u
#define TEST_AF_INET6 10u
#define TEST_IPPROTO_UDP 17u

typedef struct test_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} test_nlmsghdr_t;

typedef struct test_nfgenmsg {
    uint8_t family;
    uint8_t version;
    uint16_t resource_id;
} test_nfgenmsg_t;

typedef struct test_nlattr {
    uint16_t length;
    uint16_t type;
} test_nlattr_t;

typedef struct test_ifinfomsg {
    uint8_t family;
    uint8_t pad;
    uint16_t type;
    int32_t index;
    uint32_t flags;
    uint32_t change;
} test_ifinfomsg_t;

typedef struct test_bridge_vlan_info {
    uint16_t flags;
    uint16_t vlan_id;
} test_bridge_vlan_info_t;

typedef struct test_bridge_port_message {
    uint8_t family;
    uint8_t padding[3];
    uint32_t ifindex;
} test_bridge_port_message_t;

typedef union test_mdb_address {
    uint32_t ipv4;
    uint8_t ipv6[16];
    uint8_t hardware_address[6];
} test_mdb_address_t;

typedef struct test_mdb_entry {
    uint32_t ifindex;
    uint8_t state;
    uint8_t flags;
    uint16_t vlan_id;
    test_mdb_address_t address;
    uint16_t protocol;
} test_mdb_entry_t;

typedef struct test_ifaddrmsg {
    uint8_t family;
    uint8_t prefix_length;
    uint8_t flags;
    uint8_t scope;
    uint32_t index;
} test_ifaddrmsg_t;

typedef struct test_rtmsg {
    uint8_t family;
    uint8_t destination_length;
    uint8_t source_length;
    uint8_t tos;
    uint8_t table;
    uint8_t protocol;
    uint8_t scope;
    uint8_t type;
    uint32_t flags;
} test_rtmsg_t;

typedef struct test_rulemsg {
    uint8_t family;
    uint8_t destination_length;
    uint8_t source_length;
    uint8_t tos;
    uint8_t table;
    uint8_t reserved1;
    uint8_t reserved2;
    uint8_t action;
    uint32_t flags;
} test_rulemsg_t;

typedef struct test_nhmsg {
    uint8_t family;
    uint8_t scope;
    uint8_t protocol;
    uint8_t reserved;
    uint32_t flags;
} test_nhmsg_t;

typedef struct test_nexthop_group {
    uint32_t id;
    uint8_t weight;
    uint8_t reserved1;
    uint16_t reserved2;
} test_nexthop_group_t;

typedef struct test_rtnexthop {
    uint16_t length;
    uint8_t flags;
    uint8_t hops;
    int32_t output_ifindex;
} test_rtnexthop_t;

typedef struct test_ndmsg {
    uint8_t family;
    uint8_t pad1;
    uint16_t pad2;
    int32_t index;
    uint16_t state;
    uint8_t flags;
    uint8_t type;
} test_ndmsg_t;

typedef struct test_tcmsg {
    uint8_t family;
    uint8_t pad1;
    uint16_t pad2;
    int32_t index;
    uint32_t handle;
    uint32_t parent;
    uint32_t info;
} test_tcmsg_t;

typedef struct test_tc_fifo_options {
    uint32_t limit;
} test_tc_fifo_options_t;

typedef struct test_tc_stats {
    uint64_t bytes;
    uint32_t packets;
    uint32_t drops;
    uint32_t overlimits;
    uint32_t bytes_per_second;
    uint32_t packets_per_second;
    uint32_t queue_length;
    uint32_t backlog;
} test_tc_stats_t;

static uint32_t observed_bridge_ipv4;
static uint8_t observed_bridge_prefix;
static int observed_bridge_active = -1;
static int32_t observed_bridge_ifindex;
static uint32_t observed_bridge_namespace;
static uint8_t observed_ipv6_address[16];
static uint8_t observed_ipv6_prefix;
static int observed_ipv6_active = -1;
static uint32_t observed_ipv6_interface_removals;
static int32_t observed_ipv6_ifindex;
static uint32_t observed_ipv6_namespace;
static uint32_t observed_ipv6_flags;
static uint8_t observed_ipv6_router[16];
static int observed_ipv6_router_active = -1;
static uint32_t observed_ipv4_neighbor_address;
static int32_t observed_ipv4_neighbor_ifindex;
static uint32_t observed_ipv4_neighbor_namespace;
static uint8_t observed_ipv4_neighbor_hardware_address[6];
static uint16_t observed_ipv4_neighbor_state;
static uint8_t observed_ipv4_neighbor_flags;
static int observed_ipv4_neighbor_active = -1;
static uint32_t transmitted_packets;
static uint32_t tun_received_packets;
static uint8_t tun_received_payload[128];
static uint32_t tun_received_length;

typedef struct test_tun_ifreq {
    char name[16];
    uint16_t flags;
    uint8_t padding[22];
} test_tun_ifreq_t;

static int tun_copy_from_user(
    void *context, void *destination, uint64_t source, uint32_t length) {
    (void)context;
    memcpy(destination, (const void *)(uintptr_t)source, length);
    return 0;
}

static int tun_copy_to_user(
    void *context, uint64_t destination, const void *source,
    uint32_t length) {
    (void)context;
    memcpy((void *)(uintptr_t)destination, source, length);
    return 0;
}

static void receive_tun_packet(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    (void)ifindex;
    (void)network_namespace;
    assert(context == &tun_received_packets);
    assert(packet->total_length <= sizeof(tun_received_payload));
    assert(edge_net_packet_linearize(
               packet, tun_received_payload,
               sizeof(tun_received_payload)) ==
           (int)packet->total_length);
    tun_received_length = packet->total_length;
    ++tun_received_packets;
}

static void count_transmitted_packet(
    int32_t ifindex, uint32_t network_namespace,
    edge_net_packet_t *packet, void *context) {
    (void)ifindex;
    (void)network_namespace;
    (void)packet;
    (void)context;
    ++transmitted_packets;
}

static const uint8_t test_ipv6_address[16] = {
    0x20u, 0x01u, 0x0du, 0xb8u, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x15u
};
static const uint8_t test_ipv6_router[16] = {
    0xfeu, 0x80u, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 2u
};
static const uint8_t test_ipv4_neighbor_hardware_address[6] = {
    0x52u, 0x54u, 0, 0x65u, 0x43u, 0x21u
};
static const uint32_t test_ipv4_neighbor_address = 0x02007f0au;

static int test_ipv4_neighbor_at(
    uint32_t network_namespace, int ordinal,
    edge_linux_rtnetlink_ipv4_neighbor_t *neighbor) {
    if (network_namespace != 37u || ordinal != 0 || !neighbor) return -1;
    memset(neighbor, 0, sizeof(*neighbor));
    neighbor->address = test_ipv4_neighbor_address;
    neighbor->ifindex = 44;
    memcpy(neighbor->hardware_address,
           test_ipv4_neighbor_hardware_address,
           sizeof(neighbor->hardware_address));
    neighbor->state = 0x80u;
    return 0;
}

static int test_ipv4_configure_neighbor(
    uint32_t network_namespace, int32_t ifindex, uint32_t address,
    const uint8_t hardware_address[6], uint16_t state,
    uint8_t flags, int active) {
    observed_ipv4_neighbor_namespace = network_namespace;
    observed_ipv4_neighbor_ifindex = ifindex;
    observed_ipv4_neighbor_address = address;
    memset(observed_ipv4_neighbor_hardware_address, 0,
           sizeof(observed_ipv4_neighbor_hardware_address));
    if (hardware_address)
        memcpy(observed_ipv4_neighbor_hardware_address, hardware_address,
               sizeof(observed_ipv4_neighbor_hardware_address));
    observed_ipv4_neighbor_state = state;
    observed_ipv4_neighbor_flags = flags;
    observed_ipv4_neighbor_active = active;
    return 0;
}

static const edge_linux_rtnetlink_ipv4_provider_t test_ipv4_provider = {
    .neighbor_at = test_ipv4_neighbor_at,
    .configure_neighbor = test_ipv4_configure_neighbor,
};

static int test_ipv6_address_at(
    int ordinal, edge_linux_rtnetlink_ipv6_address_t *address) {
    if (ordinal != 0 || !address) return -1;
    memset(address, 0, sizeof(*address));
    memcpy(address->address, test_ipv6_address, sizeof(address->address));
    address->prefix_length = 64u;
    address->flags = 0x80u;
    address->valid_lifetime = UINT32_MAX;
    address->preferred_lifetime = UINT32_MAX;
    return 0;
}

static int test_ipv6_configure_address(
    uint32_t network_namespace, int32_t ifindex,
    const uint8_t address[16], uint8_t prefix_length,
    uint32_t flags, uint32_t valid_lifetime,
    uint32_t preferred_lifetime, int active) {
    (void)valid_lifetime;
    (void)preferred_lifetime;
    observed_ipv6_namespace = network_namespace;
    observed_ipv6_ifindex = ifindex;
    observed_ipv6_flags = flags;
    memcpy(observed_ipv6_address, address, sizeof(observed_ipv6_address));
    observed_ipv6_prefix = prefix_length;
    observed_ipv6_active = active;
    return 0;
}

static int test_ipv6_router_at(
    int ordinal, edge_linux_rtnetlink_ipv6_router_t *router) {
    if (ordinal != 0 || !router) return -1;
    memset(router, 0, sizeof(*router));
    memcpy(router->address, test_ipv6_router, sizeof(router->address));
    router->lifetime = 1800u;
    return 0;
}

static void test_ipv6_remove_interface(
    uint32_t network_namespace, int32_t ifindex) {
    (void)network_namespace;
    (void)ifindex;
    ++observed_ipv6_interface_removals;
}

static int test_ipv6_configure_router(
    const uint8_t address[16], int active) {
    memcpy(observed_ipv6_router, address, sizeof(observed_ipv6_router));
    observed_ipv6_router_active = active;
    return 0;
}

static int test_ipv6_neighbor_at(
    int ordinal, edge_linux_rtnetlink_ipv6_neighbor_t *neighbor) {
    static const uint8_t hardware_address[6] = {
        0x52u, 0x54u, 0, 0x12u, 0x34u, 0x56u
    };

    if (ordinal != 0 || !neighbor) return -1;
    memset(neighbor, 0, sizeof(*neighbor));
    memcpy(neighbor->address, test_ipv6_router, sizeof(neighbor->address));
    memcpy(neighbor->hardware_address, hardware_address,
           sizeof(neighbor->hardware_address));
    neighbor->state = 0x02u;
    neighbor->is_router = 1u;
    return 0;
}

static const edge_linux_rtnetlink_ipv6_provider_t test_ipv6_provider = {
    .address_at = test_ipv6_address_at,
    .configure_address = test_ipv6_configure_address,
    .remove_interface = test_ipv6_remove_interface,
    .router_at = test_ipv6_router_at,
    .configure_default_router = test_ipv6_configure_router,
    .neighbor_at = test_ipv6_neighbor_at,
};

int kernel_namespace_descriptor_get(
    int32_t descriptor, kernel_namespace_descriptor_t *information) {
    if (!information) return -EDGE_LINUX_EFAULT;
    if (descriptor != 99) return -EDGE_LINUX_ENOTTY;
    information->kind = EDGE_NAMESPACE_NET;
    information->id = 37u;
    return 0;
}

static int observe_bridge_ipv4(
    int32_t ifindex, uint32_t network_namespace,
    uint32_t address, uint8_t prefix_length, int active) {
    observed_bridge_ifindex = ifindex;
    observed_bridge_namespace = network_namespace;
    observed_bridge_ipv4 = address;
    observed_bridge_prefix = prefix_length;
    observed_bridge_active = active;
    return 0;
}

static uint32_t align4(uint32_t value) {
    return (value + 3u) & ~3u;
}

static uint32_t host_to_be32(uint32_t value) {
    return ((value & 0x000000ffu) << 24u) |
           ((value & 0x0000ff00u) << 8u) |
           ((value & 0x00ff0000u) >> 8u) |
           ((value & 0xff000000u) >> 24u);
}

static uint64_t host_to_be64(uint64_t value) {
    return ((uint64_t)host_to_be32((uint32_t)value) << 32u) |
           host_to_be32((uint32_t)(value >> 32u));
}

static uint32_t begin_message(
    uint8_t *buffer, uint32_t offset, uint16_t type, uint16_t flags,
    uint32_t sequence, uint8_t family) {
    test_nlmsghdr_t header;
    test_nfgenmsg_t family_message;

    memset(&header, 0, sizeof(header));
    memset(&family_message, 0, sizeof(family_message));
    header.type = type;
    header.flags = flags;
    header.sequence = sequence;
    family_message.family = family;
    memcpy(buffer + offset, &header, sizeof(header));
    memcpy(buffer + offset + sizeof(header), &family_message,
           sizeof(family_message));
    return offset + sizeof(header) + sizeof(family_message);
}

static uint32_t put_attribute(
    uint8_t *buffer, uint32_t offset, uint16_t type,
    const void *data, uint16_t length) {
    test_nlattr_t attribute;
    uint32_t start = offset;

    attribute.length = (uint16_t)(sizeof(attribute) + length);
    attribute.type = type;
    memcpy(buffer + offset, &attribute, sizeof(attribute));
    memcpy(buffer + offset + sizeof(attribute), data, length);
    offset = start + align4(attribute.length);
    memset(buffer + start + attribute.length, 0,
           offset - start - attribute.length);
    return offset;
}

static uint32_t finish_message(
    uint8_t *buffer, uint32_t start, uint32_t offset);

static const uint8_t *find_route_attribute(
    const uint8_t *message, uint32_t message_length,
    uint32_t payload_length, uint16_t wanted, uint32_t *length_out) {
    uint32_t offset = sizeof(test_nlmsghdr_t) + payload_length;

    while (offset + sizeof(test_nlattr_t) <= message_length) {
        const test_nlattr_t *attribute =
            (const test_nlattr_t *)(message + offset);
        if (attribute->length < sizeof(*attribute) ||
            offset + attribute->length > message_length)
            return NULL;
        if ((attribute->type & 0x3fffu) == wanted) {
            if (length_out)
                *length_out = attribute->length - sizeof(*attribute);
            return message + offset + sizeof(*attribute);
        }
        offset += align4(attribute->length);
    }
    return NULL;
}

static const uint8_t *find_nested_attribute(
    const uint8_t *attributes, uint32_t attributes_length,
    uint16_t wanted, uint32_t *length_out) {
    uint32_t offset = 0u;

    while (offset + sizeof(test_nlattr_t) <= attributes_length) {
        const test_nlattr_t *attribute =
            (const test_nlattr_t *)(attributes + offset);

        if (attribute->length < sizeof(*attribute) ||
            offset + attribute->length > attributes_length)
            return NULL;
        if ((attribute->type & 0x3fffu) == wanted) {
            if (length_out)
                *length_out = attribute->length - sizeof(*attribute);
            return attributes + offset + sizeof(*attribute);
        }
        offset += align4(attribute->length);
    }
    return NULL;
}

static uint32_t put_be32_attribute(
    uint8_t *buffer, uint32_t offset, uint16_t type, uint32_t value) {
    uint32_t encoded = host_to_be32(value);

    return put_attribute(buffer, offset, type, &encoded, sizeof(encoded));
}

static uint32_t append_route_nexthop(
    uint8_t *buffer, uint32_t offset, int32_t output_ifindex,
    uint8_t flags, uint8_t hops, const uint8_t *gateway,
    uint32_t gateway_length) {
    test_rtnexthop_t nexthop;
    uint32_t start = offset;

    memset(&nexthop, 0, sizeof(nexthop));
    nexthop.length = sizeof(nexthop);
    nexthop.flags = flags;
    nexthop.hops = hops;
    nexthop.output_ifindex = output_ifindex;
    memcpy(buffer + offset, &nexthop, sizeof(nexthop));
    offset += sizeof(nexthop);
    if (gateway && gateway_length)
        offset = put_attribute(
            buffer, offset, 5u, gateway, (uint16_t)gateway_length);
    ((test_rtnexthop_t *)(buffer + start))->length =
        (uint16_t)(offset - start);
    return offset;
}

static uint32_t append_nexthop_object(
    uint8_t *buffer, uint16_t type, uint32_t id,
    int32_t output_ifindex, const uint8_t gateway[4]) {
    test_nlmsghdr_t header;
    test_nhmsg_t message;
    uint32_t offset;

    memset(buffer, 0, 256);
    memset(&header, 0, sizeof(header));
    memset(&message, 0, sizeof(message));
    header.type = type;
    header.flags = type == 104u ? 0x605u : 0x5u;
    header.sequence = 301u + id;
    message.family = TEST_AF_INET;
    message.protocol = 4u;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &message, sizeof(message));
    offset = sizeof(header) + sizeof(message);
    offset = put_attribute(buffer, offset, 1u, &id, sizeof(id));
    if (type == 104u) {
        offset = put_attribute(
            buffer, offset, 5u,
            &output_ifindex, sizeof(output_ifindex));
        if (gateway)
            offset = put_attribute(
                buffer, offset, 6u, gateway, 4u);
    }
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_nexthop_group(
    uint8_t *buffer, uint32_t id,
    const test_nexthop_group_t *members, uint32_t member_count) {
    test_nlmsghdr_t header;
    test_nhmsg_t message;
    uint32_t offset;

    memset(buffer, 0, 256);
    memset(&header, 0, sizeof(header));
    memset(&message, 0, sizeof(message));
    header.type = 104u;
    header.flags = 0x605u;
    header.sequence = 401u + id;
    message.family = TEST_AF_INET;
    message.protocol = 4u;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &message, sizeof(message));
    offset = sizeof(header) + sizeof(message);
    offset = put_attribute(buffer, offset, 1u, &id, sizeof(id));
    offset = put_attribute(
        buffer, offset, 2u, members,
        (uint16_t)(member_count * sizeof(members[0])));
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_route_nexthop_id(
    uint8_t *buffer, uint16_t type, const uint8_t destination[4],
    uint8_t prefix_length, uint32_t table, uint32_t nexthop_id) {
    test_nlmsghdr_t header;
    test_rtmsg_t route;
    uint32_t offset;

    memset(buffer, 0, 256);
    memset(&header, 0, sizeof(header));
    memset(&route, 0, sizeof(route));
    header.type = type;
    header.flags = type == 24u ? 0x605u : 0x5u;
    header.sequence = 501u;
    route.family = TEST_AF_INET;
    route.destination_length = prefix_length;
    route.table = table <= 255u ? (uint8_t)table : 0u;
    route.protocol = 4u;
    route.type = 1u;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &route, sizeof(route));
    offset = sizeof(header) + sizeof(route);
    offset = put_attribute(buffer, offset, 1u, destination, 4u);
    offset = put_attribute(
        buffer, offset, 15u, &table, sizeof(table));
    offset = put_attribute(
        buffer, offset, 30u, &nexthop_id, sizeof(nexthop_id));
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_expression(
    uint8_t *expressions, uint32_t offset, const char *name,
    const uint8_t *data, uint16_t data_length) {
    uint8_t expression[256];
    uint32_t length = 0;

    length = put_attribute(
        expression, length, 1u, name, (uint16_t)strlen(name) + 1u);
    length = put_attribute(
        expression, length, (uint16_t)(2u | 0x8000u),
        data, data_length);
    return put_attribute(
        expressions, offset, (uint16_t)(1u | 0x8000u),
        expression, (uint16_t)length);
}

static uint32_t append_payload_expression(
    uint8_t *expressions, uint32_t offset, uint32_t base,
    uint32_t payload_offset, uint32_t payload_length) {
    uint8_t data[64];
    uint32_t length = 0;

    length = put_be32_attribute(data, length, 1u, 1u);
    length = put_be32_attribute(data, length, 2u, base);
    length = put_be32_attribute(data, length, 3u, payload_offset);
    length = put_be32_attribute(data, length, 4u, payload_length);
    return append_expression(
        expressions, offset, "payload", data, (uint16_t)length);
}

static uint32_t append_compare_expression(
    uint8_t *expressions, uint32_t offset,
    const void *value, uint16_t value_length) {
    uint8_t comparison[32];
    uint8_t data[96];
    uint32_t comparison_length = 0;
    uint32_t data_length = 0;

    comparison_length = put_attribute(
        comparison, comparison_length, 1u, value, value_length);
    data_length = put_be32_attribute(data, data_length, 1u, 1u);
    data_length = put_be32_attribute(data, data_length, 2u, 0u);
    data_length = put_attribute(
        data, data_length, (uint16_t)(3u | 0x8000u),
        comparison, (uint16_t)comparison_length);
    return append_expression(
        expressions, offset, "cmp", data, (uint16_t)data_length);
}

static uint32_t append_nat_target_expression(
    uint8_t *expressions, uint32_t offset, const char *name,
    const uint8_t address[4], uint16_t port, uint32_t flags) {
    uint8_t info[44];
    uint8_t data[96];
    uint32_t range_count = 1u;
    uint32_t data_length = 0;
    uint32_t info_length;
    uint32_t revision;
    uint16_t encoded_port = (uint16_t)((port << 8u) | (port >> 8u));

    memset(info, 0, sizeof(info));
    if (strcmp(name, "DNAT") == 0 || strcmp(name, "SNAT") == 0) {
        revision = 2u;
        info_length = 44u;
        memcpy(info, &flags, sizeof(flags));
        memcpy(info + 4u, address, 4u);
        memcpy(info + 20u, address, 4u);
        memcpy(info + 36u, &encoded_port, sizeof(encoded_port));
        memcpy(info + 38u, &encoded_port, sizeof(encoded_port));
    } else {
        revision = 0u;
        info_length = 24u;
        memcpy(info, &range_count, sizeof(range_count));
        memcpy(info + 4u, &flags, sizeof(flags));
        memcpy(info + 8u, address, 4u);
        memcpy(info + 12u, address, 4u);
        memcpy(info + 16u, &encoded_port, sizeof(encoded_port));
        memcpy(info + 18u, &encoded_port, sizeof(encoded_port));
    }
    data_length = put_attribute(
        data, data_length, 1u, name, (uint16_t)strlen(name) + 1u);
    data_length = put_be32_attribute(
        data, data_length, 2u, revision);
    data_length = put_attribute(
        data, data_length, 3u, info, (uint16_t)info_length);
    return append_expression(
        expressions, offset, "target", data, (uint16_t)data_length);
}

static uint32_t finish_message(
    uint8_t *buffer, uint32_t start, uint32_t offset) {
    test_nlmsghdr_t *header = (test_nlmsghdr_t *)(buffer + start);

    header->length = offset - start;
    return offset;
}

static uint32_t append_batch_begin(
    uint8_t *buffer, uint32_t offset, uint32_t generation) {
    uint32_t start = offset;
    uint32_t encoded = host_to_be32(generation);

    offset = begin_message(buffer, offset, 0x10u, 1u, 1u, 0u);
    offset = put_attribute(buffer, offset, 1u, &encoded, sizeof(encoded));
    return finish_message(buffer, start, offset);
}

static uint32_t append_table(
    uint8_t *buffer, uint32_t offset, uint16_t operation,
    uint16_t flags, const char *name, uint32_t sequence) {
    uint32_t start = offset;

    offset = begin_message(
        buffer, offset, (uint16_t)((10u << 8u) | operation),
        flags, sequence, 2u);
    offset = put_attribute(
        buffer, offset, 1u, name, (uint16_t)strlen(name) + 1u);
    return finish_message(buffer, start, offset);
}

static uint32_t append_chain(
    uint8_t *buffer, uint32_t offset, uint16_t operation,
    uint16_t flags, const char *table, const char *name,
    uint32_t sequence) {
    uint32_t start = offset;

    offset = begin_message(
        buffer, offset, (uint16_t)((10u << 8u) | operation),
        flags, sequence, 2u);
    offset = put_attribute(
        buffer, offset, 1u, table, (uint16_t)strlen(table) + 1u);
    offset = put_attribute(
        buffer, offset, 3u, name, (uint16_t)strlen(name) + 1u);
    return finish_message(buffer, start, offset);
}

static uint32_t append_base_chain(
    uint8_t *buffer, uint32_t offset, const char *table,
    const char *name, uint32_t hook_number, int32_t priority,
    uint32_t policy, uint32_t sequence) {
    uint8_t hook[32];
    uint32_t hook_length = 0u;
    uint32_t start = offset;

    hook_length = put_be32_attribute(
        hook, hook_length, 1u, hook_number);
    hook_length = put_be32_attribute(
        hook, hook_length, 2u, (uint32_t)priority);
    offset = begin_message(
        buffer, offset, (uint16_t)((10u << 8u) | 3u),
        1u, sequence, TEST_AF_INET);
    offset = put_attribute(
        buffer, offset, 1u, table, (uint16_t)strlen(table) + 1u);
    offset = put_attribute(
        buffer, offset, 3u, name, (uint16_t)strlen(name) + 1u);
    offset = put_attribute(
        buffer, offset, 7u, "filter", sizeof("filter"));
    offset = put_attribute(
        buffer, offset, (uint16_t)(4u | 0x8000u),
        hook, (uint16_t)hook_length);
    offset = put_be32_attribute(buffer, offset, 5u, policy);
    return finish_message(buffer, start, offset);
}

static uint32_t append_verdict_rule(
    uint8_t *buffer, uint32_t offset, const char *table,
    const char *chain, uint32_t verdict, uint32_t sequence) {
    uint8_t verdict_data[16];
    uint8_t immediate[32];
    uint8_t data[64];
    uint8_t expressions[128];
    uint32_t verdict_length = 0u;
    uint32_t immediate_length = 0u;
    uint32_t data_length = 0u;
    uint32_t expressions_length = 0u;
    uint32_t start = offset;

    verdict_length = put_be32_attribute(
        verdict_data, verdict_length, 1u, verdict);
    immediate_length = put_attribute(
        immediate, immediate_length, (uint16_t)(2u | 0x8000u),
        verdict_data, (uint16_t)verdict_length);
    data_length = put_be32_attribute(data, data_length, 1u, 0u);
    data_length = put_attribute(
        data, data_length, (uint16_t)(2u | 0x8000u),
        immediate, (uint16_t)immediate_length);
    expressions_length = append_expression(
        expressions, expressions_length, "immediate",
        data, (uint16_t)data_length);
    offset = begin_message(
        buffer, offset, (uint16_t)((10u << 8u) | 6u),
        1u, sequence, TEST_AF_INET);
    offset = put_attribute(
        buffer, offset, 1u, table, (uint16_t)strlen(table) + 1u);
    offset = put_attribute(
        buffer, offset, 2u, chain, (uint16_t)strlen(chain) + 1u);
    offset = put_attribute(
        buffer, offset, (uint16_t)(4u | 0x8000u),
        expressions, (uint16_t)expressions_length);
    return finish_message(buffer, start, offset);
}

static uint32_t append_rule(
    uint8_t *buffer, uint32_t offset, uint16_t operation,
    uint16_t flags, const char *table, const char *chain,
    uint64_t handle, uint32_t sequence) {
    uint32_t start = offset;
    uint64_t encoded_handle = host_to_be64(handle);

    offset = begin_message(
        buffer, offset, (uint16_t)((10u << 8u) | operation),
        flags, sequence, 2u);
    offset = put_attribute(
        buffer, offset, 1u, table, (uint16_t)strlen(table) + 1u);
    offset = put_attribute(
        buffer, offset, 2u, chain, (uint16_t)strlen(chain) + 1u);
    if (handle)
        offset = put_attribute(
            buffer, offset, 3u, &encoded_handle, sizeof(encoded_handle));
    return finish_message(buffer, start, offset);
}

static uint32_t append_nat_rule(
    uint8_t *buffer, uint32_t offset, const char *table,
    const char *chain, int destination, uint32_t sequence) {
    static const uint8_t resolver_address[4] = {127u, 0u, 0u, 11u};
    uint8_t expressions[512];
    uint32_t expressions_length = 0;
    uint32_t start = offset;
    uint16_t match_port = destination ? 53u : 49153u;
    uint16_t encoded_match_port =
        (uint16_t)((match_port << 8u) | (match_port >> 8u));

    expressions_length = append_payload_expression(
        expressions, expressions_length, 1u,
        destination ? 16u : 12u, 4u);
    expressions_length = append_compare_expression(
        expressions, expressions_length,
        resolver_address, sizeof(resolver_address));
    expressions_length = append_payload_expression(
        expressions, expressions_length, 2u,
        destination ? 2u : 0u, 2u);
    expressions_length = append_compare_expression(
        expressions, expressions_length,
        &encoded_match_port, sizeof(encoded_match_port));
    expressions_length = append_nat_target_expression(
        expressions, expressions_length,
        destination ? "DNAT" : "SNAT", resolver_address,
        destination ? 49153u : 53u,
        destination ? 3u : 2u);

    offset = begin_message(
        buffer, offset, (uint16_t)((10u << 8u) | 6u),
        0x0c01u, sequence, 2u);
    offset = put_attribute(
        buffer, offset, 1u, table, (uint16_t)strlen(table) + 1u);
    offset = put_attribute(
        buffer, offset, 2u, chain, (uint16_t)strlen(chain) + 1u);
    offset = put_attribute(
        buffer, offset, (uint16_t)(4u | 0x8000u),
        expressions, (uint16_t)expressions_length);
    return finish_message(buffer, start, offset);
}

static uint32_t append_simple_nat_target_rule(
    uint8_t *buffer, uint32_t offset, const char *table,
    const char *chain, const char *target, uint32_t sequence) {
    static const uint8_t empty_address[4] = {0u, 0u, 0u, 0u};
    uint8_t expressions[256];
    uint32_t expressions_length = 0;
    uint32_t start = offset;

    expressions_length = append_nat_target_expression(
        expressions, expressions_length, target,
        empty_address, 0u, 0u);
    offset = begin_message(
        buffer, offset, (uint16_t)((10u << 8u) | 6u),
        0x0c01u, sequence, 2u);
    offset = put_attribute(
        buffer, offset, 1u, table, (uint16_t)strlen(table) + 1u);
    offset = put_attribute(
        buffer, offset, 2u, chain, (uint16_t)strlen(chain) + 1u);
    offset = put_attribute(
        buffer, offset, (uint16_t)(4u | 0x8000u),
        expressions, (uint16_t)expressions_length);
    return finish_message(buffer, start, offset);
}

static uint64_t response_rule_handle(
    const uint8_t *response, uint32_t response_length) {
    const test_nlmsghdr_t *header = (const test_nlmsghdr_t *)response;
    uint32_t offset = sizeof(*header) + sizeof(test_nfgenmsg_t);

    assert(header->length <= response_length);
    while (offset < header->length) {
        const test_nlattr_t *attribute =
            (const test_nlattr_t *)(response + offset);

        assert(attribute->length >= sizeof(*attribute));
        assert(attribute->length <= header->length - offset);
        if ((attribute->type & 0x3fffu) == 3u) {
            uint64_t encoded;

            assert(attribute->length == sizeof(*attribute) + sizeof(encoded));
            memcpy(&encoded, response + offset + sizeof(*attribute),
                   sizeof(encoded));
            return host_to_be64(encoded);
        }
        offset += align4(attribute->length);
    }
    assert(!"rule handle missing");
    return 0;
}

static uint32_t response_u32_attribute(
    const uint8_t *response, uint32_t response_length,
    uint32_t body_length, uint16_t wanted) {
    const test_nlmsghdr_t *header = (const test_nlmsghdr_t *)response;
    uint32_t offset = sizeof(*header) + body_length;

    assert(header->length <= response_length);
    while (offset < header->length) {
        const test_nlattr_t *attribute =
            (const test_nlattr_t *)(response + offset);

        assert(attribute->length >= sizeof(*attribute));
        assert(attribute->length <= header->length - offset);
        if ((attribute->type & 0x3fffu) == wanted) {
            uint32_t value;

            assert(attribute->length == sizeof(*attribute) + sizeof(value));
            memcpy(&value, response + offset + sizeof(*attribute),
                   sizeof(value));
            return value;
        }
        offset += align4(attribute->length);
    }
    assert(!"u32 attribute missing");
    return 0;
}

static uint32_t append_batch_end(uint8_t *buffer, uint32_t offset) {
    uint32_t start = offset;

    offset = begin_message(buffer, offset, 0x11u, 1u, 4u, 0u);
    return finish_message(buffer, start, offset);
}

static uint32_t append_bridge_link(
    uint8_t *buffer, uint16_t type, int32_t index,
    uint32_t flags, uint32_t change) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    uint8_t linkinfo[32];
    uint32_t linkinfo_length = 0;
    uint32_t offset;

    memset(buffer, 0, 128);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    header.type = type;
    header.flags = 0x605u;
    header.sequence = 90u;
    info.index = index;
    info.flags = flags;
    info.change = change;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    if (!index) {
        offset = put_attribute(
            buffer, offset, 3u, "docker0", sizeof("docker0"));
        linkinfo_length = put_attribute(
            linkinfo, 0, 1u, "bridge", (uint16_t)strlen("bridge"));
        offset = put_attribute(
            buffer, offset, 18u, linkinfo,
            (uint16_t)linkinfo_length);
    }
    ((test_nlmsghdr_t *)buffer)->length = offset;
    return offset;
}

static uint32_t append_bridge_port_controls(
    uint8_t *buffer, int32_t index, uint8_t state, uint8_t hairpin,
    uint8_t learning, uint8_t unicast_flood, uint8_t multicast_flood,
    uint8_t broadcast_flood, uint8_t isolated) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    uint8_t info_data[64];
    uint8_t linkinfo[96];
    uint32_t info_data_length = 0u;
    uint32_t linkinfo_length = 0u;
    uint32_t offset;

    memset(buffer, 0, 128);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    memset(info_data, 0, sizeof(info_data));
    memset(linkinfo, 0, sizeof(linkinfo));
    header.type = 19u;
    header.flags = 0x5u;
    header.sequence = 204u;
    info.index = index;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    info_data_length = put_attribute(
        info_data, info_data_length, 1u, &state, sizeof(state));
    info_data_length = put_attribute(
        info_data, info_data_length, 4u, &hairpin, sizeof(hairpin));
    info_data_length = put_attribute(
        info_data, info_data_length, 8u, &learning, sizeof(learning));
    info_data_length = put_attribute(
        info_data, info_data_length, 9u, &unicast_flood,
        sizeof(unicast_flood));
    info_data_length = put_attribute(
        info_data, info_data_length, 27u, &multicast_flood,
        sizeof(multicast_flood));
    info_data_length = put_attribute(
        info_data, info_data_length, 30u, &broadcast_flood,
        sizeof(broadcast_flood));
    info_data_length = put_attribute(
        info_data, info_data_length, 33u, &isolated, sizeof(isolated));
    linkinfo_length = put_attribute(
        linkinfo, linkinfo_length, 1u,
        "bridge_slave", sizeof("bridge_slave"));
    linkinfo_length = put_attribute(
        linkinfo, linkinfo_length, 2u,
        info_data, (uint16_t)info_data_length);
    offset = put_attribute(
        buffer, offset, 18u, linkinfo, (uint16_t)linkinfo_length);
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_bridge_vlan_filtering(
    uint8_t *buffer, int32_t index, uint8_t enabled) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    uint8_t info_data[16];
    uint8_t linkinfo[48];
    uint32_t info_data_length = 0u;
    uint32_t linkinfo_length = 0u;
    uint32_t offset;

    memset(buffer, 0, 128);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    memset(info_data, 0, sizeof(info_data));
    memset(linkinfo, 0, sizeof(linkinfo));
    header.type = 19u;
    header.flags = 0x5u;
    header.sequence = 206u;
    info.index = index;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    info_data_length = put_attribute(
        info_data, info_data_length, 7u, &enabled, sizeof(enabled));
    linkinfo_length = put_attribute(
        linkinfo, linkinfo_length, 1u, "bridge", sizeof("bridge"));
    linkinfo_length = put_attribute(
        linkinfo, linkinfo_length, 2u,
        info_data, (uint16_t)info_data_length);
    offset = put_attribute(
        buffer, offset, 18u, linkinfo, (uint16_t)linkinfo_length);
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_bridge_vlan(
    uint8_t *buffer, uint16_t message_type, int32_t index,
    uint16_t vlan_id, uint16_t flags) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    test_bridge_vlan_info_t vlan;
    uint8_t address_family[16];
    uint32_t address_family_length = 0u;
    uint32_t offset;

    memset(buffer, 0, 128);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    memset(&vlan, 0, sizeof(vlan));
    memset(address_family, 0, sizeof(address_family));
    header.type = message_type;
    header.flags = 0x5u;
    header.sequence = 207u;
    info.family = TEST_AF_BRIDGE;
    info.index = index;
    vlan.flags = flags;
    vlan.vlan_id = vlan_id;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    address_family_length = put_attribute(
        address_family, address_family_length, 2u,
        &vlan, sizeof(vlan));
    offset = put_attribute(
        buffer, offset, (uint16_t)(26u | 0x8000u),
        address_family, (uint16_t)address_family_length);
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_bridge_mdb(
    uint8_t *buffer, uint16_t message_type, int32_t bridge_ifindex,
    int32_t port_ifindex, const uint8_t group[4], uint16_t vlan_id) {
    test_nlmsghdr_t header;
    test_bridge_port_message_t message;
    test_mdb_entry_t entry;
    uint8_t *protocol;
    uint32_t offset;

    memset(buffer, 0, 128);
    memset(&header, 0, sizeof(header));
    memset(&message, 0, sizeof(message));
    memset(&entry, 0, sizeof(entry));
    header.type = message_type;
    header.flags = message_type == 84u ? 0x605u : 0x5u;
    header.sequence = 208u;
    message.family = TEST_AF_BRIDGE;
    message.ifindex = (uint32_t)bridge_ifindex;
    entry.ifindex = (uint32_t)port_ifindex;
    entry.state = 1u;
    entry.vlan_id = vlan_id;
    memcpy(&entry.address.ipv4, group, 4u);
    protocol = (uint8_t *)&entry.protocol;
    protocol[0] = 0x08u;
    protocol[1] = 0x00u;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &message, sizeof(message));
    offset = sizeof(header) + sizeof(message);
    offset = put_attribute(
        buffer, offset, 1u, &entry, sizeof(entry));
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_veth_link(
    uint8_t *buffer, uint16_t type, int32_t index, const char *name,
    const char *peer_name) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    test_nlattr_t peer_attribute;
    uint8_t info_data[128];
    uint8_t linkinfo[192];
    uint32_t info_data_length;
    uint32_t linkinfo_length;
    uint32_t offset;

    memset(buffer, 0, 256);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    memset(info_data, 0, sizeof(info_data));
    memset(linkinfo, 0, sizeof(linkinfo));
    header.type = type;
    header.flags = 0x605u;
    header.sequence = 92u;
    info.index = index;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    if (!index) {
        offset = put_attribute(
            buffer, offset, 3u, name, (uint16_t)strlen(name) + 1u);
        memset(&peer_attribute, 0, sizeof(peer_attribute));
        peer_attribute.type = 1u;
        memcpy(info_data, &peer_attribute, sizeof(peer_attribute));
        memset(info_data + sizeof(peer_attribute), 0, sizeof(info));
        info_data_length = sizeof(peer_attribute) + sizeof(info);
        info_data_length = put_attribute(
            info_data, info_data_length, 3u, peer_name,
            (uint16_t)strlen(peer_name) + 1u);
        ((test_nlattr_t *)info_data)->length =
            (uint16_t)info_data_length;
        linkinfo_length = put_attribute(
            linkinfo, 0, 1u, "veth", sizeof("veth"));
        linkinfo_length = put_attribute(
            linkinfo, linkinfo_length, 2u, info_data,
            (uint16_t)info_data_length);
        offset = put_attribute(
            buffer, offset, 18u, linkinfo,
            (uint16_t)linkinfo_length);
    }
    ((test_nlmsghdr_t *)buffer)->length = offset;
    return offset;
}

static uint32_t append_qdisc(
    uint8_t *buffer, uint16_t type, int32_t ifindex,
    uint32_t handle, const char *kind, uint32_t limit) {
    test_nlmsghdr_t header;
    test_tcmsg_t message;
    test_tc_fifo_options_t options;
    uint32_t offset;

    memset(buffer, 0, 256);
    memset(&header, 0, sizeof(header));
    memset(&message, 0, sizeof(message));
    header.type = type;
    header.flags = type == 36u ? 0x605u : 0x5u;
    header.sequence = 212u;
    message.index = ifindex;
    message.handle = handle;
    message.parent = UINT32_MAX;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &message, sizeof(message));
    offset = sizeof(header) + sizeof(message);
    if (type == 36u) {
        options.limit = limit;
        offset = put_attribute(
            buffer, offset, 1u, kind,
            (uint16_t)strlen(kind) + 1u);
        offset = put_attribute(
            buffer, offset, 2u, &options, sizeof(options));
    }
    return finish_message(buffer, 0u, offset);
}

static uint32_t append_virtual_link(
    uint8_t *buffer, uint16_t type, int32_t index,
    const char *name, const char *kind, int32_t lower_index,
    uint16_t vlan_id, uint16_t vlan_protocol) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    uint8_t info_data[32];
    uint8_t linkinfo[96];
    uint8_t protocol[2];
    uint32_t info_data_length = 0u;
    uint32_t linkinfo_length;
    uint32_t offset;

    memset(buffer, 0, 256);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    memset(info_data, 0, sizeof(info_data));
    memset(linkinfo, 0, sizeof(linkinfo));
    header.type = type;
    header.flags = 0x605u;
    header.sequence = 209u;
    info.index = index;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    if (!index) {
        offset = put_attribute(
            buffer, offset, 3u, name, (uint16_t)strlen(name) + 1u);
        if (lower_index > 0)
            offset = put_attribute(
                buffer, offset, 5u, &lower_index, sizeof(lower_index));
        linkinfo_length = put_attribute(
            linkinfo, 0u, 1u, kind, (uint16_t)strlen(kind) + 1u);
        if (strcmp(kind, "vlan") == 0) {
            protocol[0] = (uint8_t)(vlan_protocol >> 8u);
            protocol[1] = (uint8_t)vlan_protocol;
            info_data_length = put_attribute(
                info_data, info_data_length, 1u,
                &vlan_id, sizeof(vlan_id));
            info_data_length = put_attribute(
                info_data, info_data_length, 5u,
                protocol, sizeof(protocol));
            linkinfo_length = put_attribute(
                linkinfo, linkinfo_length, 2u,
                info_data, (uint16_t)info_data_length);
        } else if (strcmp(kind, "macvlan") == 0) {
            uint32_t mode = vlan_id;
            uint32_t flags = vlan_protocol;

            info_data_length = put_attribute(
                info_data, info_data_length, 1u,
                &mode, sizeof(mode));
            info_data_length = put_attribute(
                info_data, info_data_length, 2u,
                &flags, sizeof(flags));
            linkinfo_length = put_attribute(
                linkinfo, linkinfo_length, 2u,
                info_data, (uint16_t)info_data_length);
        } else if (strcmp(kind, "ipvlan") == 0) {
            uint16_t mode = vlan_id;
            uint16_t flags = vlan_protocol;

            info_data_length = put_attribute(
                info_data, info_data_length, 1u,
                &mode, sizeof(mode));
            info_data_length = put_attribute(
                info_data, info_data_length, 2u,
                &flags, sizeof(flags));
            linkinfo_length = put_attribute(
                linkinfo, linkinfo_length, 2u,
                info_data, (uint16_t)info_data_length);
        } else if (strcmp(kind, "bond") == 0) {
            uint8_t mode = (uint8_t)vlan_id;
            uint8_t hash_policy = (uint8_t)vlan_protocol;

            info_data_length = put_attribute(
                info_data, info_data_length, 1u,
                &mode, sizeof(mode));
            info_data_length = put_attribute(
                info_data, info_data_length, 14u,
                &hash_policy, sizeof(hash_policy));
            linkinfo_length = put_attribute(
                linkinfo, linkinfo_length, 2u,
                info_data, (uint16_t)info_data_length);
        } else if (strcmp(kind, "vrf") == 0) {
            uint32_t routing_table = vlan_id;

            info_data_length = put_attribute(
                info_data, info_data_length, 1u,
                &routing_table, sizeof(routing_table));
            linkinfo_length = put_attribute(
                linkinfo, linkinfo_length, 2u,
                info_data, (uint16_t)info_data_length);
        }
        offset = put_attribute(
            buffer, offset, 18u, linkinfo,
            (uint16_t)linkinfo_length);
    }
    ((test_nlmsghdr_t *)buffer)->length = offset;
    return offset;
}

static uint32_t append_link_namespace(
    uint8_t *buffer, int32_t index, uint32_t descriptor) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    uint32_t offset;

    memset(buffer, 0, 128);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    header.type = 16u;
    header.flags = 0x405u;
    header.sequence = 96u;
    info.index = index;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    offset = put_attribute(
        buffer, offset, 28u, &descriptor, sizeof(descriptor));
    ((test_nlmsghdr_t *)buffer)->length = offset;
    return offset;
}

static uint32_t append_getlink_name(
    uint8_t *buffer, const char *name, uint32_t sequence) {
    test_nlmsghdr_t header;
    test_ifinfomsg_t info;
    uint32_t offset;

    memset(buffer, 0, 256);
    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    header.type = 18u;
    header.sequence = sequence;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &info, sizeof(info));
    offset = sizeof(header) + sizeof(info);
    offset = put_attribute(
        buffer, offset, 3u, name, (uint16_t)strlen(name) + 1u);
    ((test_nlmsghdr_t *)buffer)->length = offset;
    return offset;
}

int kernel_socket_netlink_deliver_datagram(
    int32_t descriptor, uint32_t protocol, uint32_t destination_port,
    uint32_t destination_groups, const void *payload, uint32_t length) {
    (void)descriptor;
    (void)protocol;
    (void)destination_port;
    (void)destination_groups;
    (void)payload;
    (void)length;
    return 0;
}

static uint32_t g_netlink_event_count;
static uint32_t g_netlink_event_namespace;
static uint32_t g_netlink_event_protocol;
static uint32_t g_netlink_event_groups;
static uint16_t g_netlink_event_type;
static uint32_t g_netlink_event_length;

int kernel_socket_broadcast_netlink_event(
    uint32_t network_namespace, uint32_t protocol,
    uint32_t destination_groups, uint16_t message_type,
    const void *payload, uint32_t length) {
    assert(payload || !length);
    ++g_netlink_event_count;
    g_netlink_event_namespace = network_namespace;
    g_netlink_event_protocol = protocol;
    g_netlink_event_groups = destination_groups;
    g_netlink_event_type = message_type;
    g_netlink_event_length = length;
    return 0;
}

int main(void) {
    struct {
        test_nlmsghdr_t header;
        test_nfgenmsg_t family;
    } request;
    uint8_t response[4096];
    uint8_t batch[2048];
    test_nlmsghdr_t reply;
    test_nlattr_t attribute;
    uint32_t response_length = 0;
    uint32_t generation = 1;
    uint32_t batch_length;
    uint64_t rule_handle;
    uint8_t route_request[256];
    test_ifinfomsg_t link_info;
    uint32_t route_length;
    uint32_t route_offset;
    uint32_t route_matches;
    int route_handled;
    uint8_t highest_revision;

    assert(edge_linux_netfilter_extension_revision(
        "DNAT", 1, 2u, &highest_revision) == 0);
    assert(highest_revision == 2u);
    assert(edge_linux_netfilter_extension_revision(
        "conntrack", 0, 3u, &highest_revision) == 0);
    assert(highest_revision == 3u);
    assert(edge_linux_netfilter_extension_revision(
        "conntrack", 0, 4u, &highest_revision) ==
        -EDGE_LINUX_EPROTONOSUPPORT);
    assert(edge_linux_netfilter_extension_revision(
        "unknown", 0, 0u, &highest_revision) ==
        -EDGE_LINUX_ENOENT);

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 16u;
    request.header.flags = 1u;
    request.header.sequence = 73u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    assert(response_length == sizeof(reply) + sizeof(test_nfgenmsg_t) +
                                  sizeof(attribute) + sizeof(generation));
    memcpy(&reply, response, sizeof(reply));
    assert(reply.length == response_length);
    assert(reply.type == ((10u << 8u) | 15u));
    assert(reply.sequence == 73u);
    assert(reply.port_id == 492u);
    memcpy(&attribute, response + sizeof(reply) + sizeof(test_nfgenmsg_t),
           sizeof(attribute));
    assert(attribute.length == sizeof(attribute) + sizeof(generation));
    assert(attribute.type == 1u);
    memcpy(&generation,
           response + sizeof(reply) + sizeof(test_nfgenmsg_t) +
               sizeof(attribute),
           sizeof(generation));
    assert(generation == 0u);

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (1u << 8u) | 1u;
    request.header.flags = 0x301u;
    request.header.sequence = 81u;
    request.family.family = 2u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    assert(response_length == sizeof(reply));
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == 3u);
    assert(reply.flags == 2u);
    assert(reply.sequence == 81u);
    assert(reply.port_id == 492u);

    memset(batch, 0, sizeof(batch));
    batch_length = begin_message(
        batch, 0, (uint16_t)(11u << 8u), 5u, 72u, 2u);
    batch_length = put_attribute(
        batch, batch_length, 1u,
        "MASQUERADE", sizeof("MASQUERADE"));
    generation = host_to_be32(0u);
    batch_length = put_attribute(
        batch, batch_length, 2u, &generation, sizeof(generation));
    generation = host_to_be32(1u);
    batch_length = put_attribute(
        batch, batch_length, 3u, &generation, sizeof(generation));
    batch_length = finish_message(batch, 0, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == (11u << 8u));
    assert(reply.sequence == 72u);

    generation = host_to_be32(1u);
    memcpy(batch + sizeof(test_nlmsghdr_t) + sizeof(test_nfgenmsg_t) +
               align4(sizeof(test_nlattr_t) + sizeof("MASQUERADE")) +
               sizeof(test_nlattr_t),
           &generation, sizeof(generation));
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == -EDGE_LINUX_EPROTONOSUPPORT);

    memset(batch, 0, sizeof(batch));
    batch_length = begin_message(
        batch, 0, (uint16_t)(11u << 8u), 5u, 80u, 2u);
    batch_length = put_attribute(
        batch, batch_length, 1u, "conntrack", sizeof("conntrack"));
    generation = host_to_be32(0u);
    batch_length = put_attribute(
        batch, batch_length, 2u, &generation, sizeof(generation));
    batch_length = put_attribute(
        batch, batch_length, 3u, &generation, sizeof(generation));
    batch_length = finish_message(batch, 0, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == -EDGE_LINUX_EPROTONOSUPPORT);

    generation = host_to_be32(1u);
    memcpy(batch + sizeof(test_nlmsghdr_t) + sizeof(test_nfgenmsg_t) +
               align4(sizeof(test_nlattr_t) + sizeof("conntrack")) +
               sizeof(test_nlattr_t),
           &generation, sizeof(generation));
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == (11u << 8u));
    assert(reply.sequence == 80u);

    memset(batch, 0, sizeof(batch));
    batch_length = begin_message(
        batch, 0, (uint16_t)(11u << 8u), 5u, 79u, 2u);
    batch_length = put_attribute(
        batch, batch_length, 1u, "addrtype", sizeof("addrtype"));
    generation = host_to_be32(0u);
    batch_length = put_attribute(
        batch, batch_length, 2u, &generation, sizeof(generation));
    batch_length = put_attribute(
        batch, batch_length, 3u, &generation, sizeof(generation));
    batch_length = finish_message(batch, 0, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == (11u << 8u));
    assert(reply.sequence == 79u);
    memcpy(&generation,
           response + sizeof(test_nlmsghdr_t) +
               sizeof(test_nfgenmsg_t) +
               align4(sizeof(test_nlattr_t) + sizeof("addrtype")) +
               sizeof(test_nlattr_t),
           sizeof(generation));
    assert(host_to_be32(generation) == 1u);

    generation = host_to_be32(1u);
    memcpy(batch + sizeof(test_nlmsghdr_t) + sizeof(test_nfgenmsg_t) +
               align4(sizeof(test_nlattr_t) + sizeof("addrtype")) +
               sizeof(test_nlattr_t),
           &generation, sizeof(generation));
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == (11u << 8u));
    assert(reply.sequence == 79u);

    memset(batch, 0, sizeof(batch));
    batch_length = begin_message(
        batch, 0, (uint16_t)(11u << 8u), 5u, 82u, 2u);
    batch_length = put_attribute(
        batch, batch_length, 1u, "tcp", sizeof("tcp"));
    generation = host_to_be32(0u);
    batch_length = put_attribute(
        batch, batch_length, 2u, &generation, sizeof(generation));
    batch_length = put_attribute(
        batch, batch_length, 3u, &generation, sizeof(generation));
    batch_length = finish_message(batch, 0, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == (11u << 8u));
    assert(reply.sequence == 82u);

    memset(batch, 0, sizeof(batch));
    batch_length = begin_message(
        batch, 0, (uint16_t)(11u << 8u), 5u, 83u, 2u);
    batch_length = put_attribute(
        batch, batch_length, 1u, "DNAT", sizeof("DNAT"));
    generation = host_to_be32(0u);
    batch_length = put_attribute(
        batch, batch_length, 2u, &generation, sizeof(generation));
    generation = host_to_be32(1u);
    batch_length = put_attribute(
        batch, batch_length, 3u, &generation, sizeof(generation));
    batch_length = finish_message(batch, 0, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == (11u << 8u));
    assert(reply.sequence == 83u);

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 1u;
    request.header.flags = 0x301u;
    request.header.sequence = 74u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    assert(response_length == sizeof(reply));
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == 3u);
    assert(reply.sequence == 74u);

    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, 0u);
    batch_length = append_table(
        batch, batch_length, 0u, 0x401u, "nat", 2u);
    batch_length = append_chain(
        batch, batch_length, 3u, 0x201u,
        "nat", "EDGEOSTEST", 3u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    assert(response_length == 0u);

    memset(batch, 0, sizeof(batch));
    batch_length = append_chain(
        batch, 0, 4u, 5u, "nat", "EDGEOSTEST", 72u);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == ((10u << 8u) | 3u));
    memcpy(&reply, response + align4(reply.length), sizeof(reply));
    assert(reply.type == 2u);
    assert(reply.sequence == 72u);
    {
        int32_t acknowledgement_error;

        memcpy(&acknowledgement_error,
               response + align4(
                   ((test_nlmsghdr_t *)response)->length) + sizeof(reply),
               sizeof(acknowledgement_error));
        assert(acknowledgement_error == 0);
    }

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 16u;
    request.header.sequence = 75u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    memcpy(&generation,
           response + sizeof(reply) + sizeof(test_nfgenmsg_t) +
               sizeof(attribute),
           sizeof(generation));
    assert(generation == host_to_be32(1u));

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 1u;
    request.header.flags = 0x301u;
    request.header.sequence = 76u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == ((10u << 8u) | 0u));
    memcpy(&reply, response + align4(reply.length), sizeof(reply));
    assert(reply.type == 3u);

    request.header.type = (10u << 8u) | 4u;
    request.header.sequence = 77u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == ((10u << 8u) | 3u));
    memcpy(&reply, response + align4(reply.length), sizeof(reply));
    assert(reply.type == 3u);

    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, 1u);
    batch_length = append_rule(
        batch, batch_length, 6u, 0x0c01u,
        "nat", "EDGEOSTEST", 0, 2u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 7u;
    request.header.flags = 0x301u;
    request.header.sequence = 78u;
    request.family.family = 2u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == ((10u << 8u) | 6u));
    rule_handle = response_rule_handle(response, response_length);
    assert(rule_handle != 0);

    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, 2u);
    batch_length = append_table(
        batch, batch_length, 0u, 0x401u, "nat", 2u);
    batch_length = append_chain(
        batch, batch_length, 3u, 0x201u,
        "nat", "EDGEOSTEST", 3u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == -EDGE_LINUX_EEXIST);

    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, 0u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == -EDGE_LINUX_EAGAIN);

    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, 2u);
    batch_length = append_rule(
        batch, batch_length, 8u, 1u,
        "nat", "EDGEOSTEST", rule_handle, 2u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);

    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, 3u);
    batch_length = append_chain(
        batch, batch_length, 5u, 1u,
        "nat", "EDGEOSTEST", 2u);
    batch_length = append_table(
        batch, batch_length, 2u, 1u, "nat", 3u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond(
        492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 1u;
    request.header.flags = 0x301u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    assert(response_length == sizeof(reply));
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == 3u);

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 16u;
    request.header.sequence = 96u;
    assert(edge_linux_netfilter_respond_in_namespace(
        41u, 492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    memcpy(&generation,
           response + sizeof(reply) + sizeof(test_nfgenmsg_t) +
               sizeof(attribute),
           sizeof(generation));
    generation = host_to_be32(generation);

    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, generation);
    batch_length = append_table(
        batch, batch_length, 0u, 0x401u, "dnsnat", 97u);
    batch_length = append_chain(
        batch, batch_length, 3u, 0x201u,
        "dnsnat", "OUTPUT", 98u);
    batch_length = append_nat_rule(
        batch, batch_length, "dnsnat", "OUTPUT", 1, 99u);
    batch_length = append_nat_rule(
        batch, batch_length, "dnsnat", "OUTPUT", 0, 100u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond_in_namespace(
        41u, 492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    {
        edge_linux_netfilter_tuple_t tuple;
        edge_linux_conntrack_snapshot_t connection;
        static const uint8_t resolver_address[4] = {127u, 0u, 0u, 11u};
        static const uint8_t container_address[4] = {172u, 30u, 88u, 3u};

        memset(&tuple, 0, sizeof(tuple));
        tuple.network_namespace = 41u;
        tuple.family = TEST_AF_INET;
        tuple.protocol = TEST_IPPROTO_UDP;
        memcpy(tuple.source_address,
               container_address, sizeof(container_address));
        memcpy(tuple.destination_address,
               resolver_address, sizeof(resolver_address));
        tuple.source_port = 40000u;
        tuple.destination_port = 53u;
        assert(edge_linux_netfilter_translate_local(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) == 1);
        assert(tuple.destination_port == 49153u);
        assert(edge_linux_conntrack_snapshot(
            41u, 0u, &connection) == 0);
        assert(connection.original.destination_port == 53u);
        assert(connection.translated.destination_port == 49153u);
        assert(edge_linux_netfilter_translate_local(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) == 0);
        assert(memcmp(tuple.source_address,
                      container_address, sizeof(container_address)) == 0);

        tuple.network_namespace = 42u;
        tuple.destination_port = 53u;
        assert(edge_linux_netfilter_translate_local(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) == 0);
        assert(tuple.destination_port == 53u);

        memset(&tuple, 0, sizeof(tuple));
        tuple.network_namespace = 41u;
        tuple.family = TEST_AF_INET;
        tuple.protocol = TEST_IPPROTO_UDP;
        memcpy(tuple.source_address,
               resolver_address, sizeof(resolver_address));
        tuple.source_port = 49153u;
        tuple.destination_port = 40000u;
        assert(edge_linux_netfilter_translate_local(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) == 1);
        assert(tuple.source_port == 53u);

        memset(&request, 0, sizeof(request));
        request.header.length = sizeof(request);
        request.header.type = (1u << 8u) | 1u;
        request.header.flags = 0x301u;
        request.header.sequence = 101u;
        request.family.family = 2u;
        assert(edge_linux_netfilter_respond_in_namespace(
            41u, 492u, &request, sizeof(request),
            response, sizeof(response), &response_length) == 0);
        assert(response_length > sizeof(reply));
        memcpy(&reply, response, sizeof(reply));
        assert(reply.type == (1u << 8u));
        assert(reply.sequence == 101u);
    }

    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = (10u << 8u) | 16u;
    assert(edge_linux_netfilter_respond_in_namespace(
        44u, 492u, &request, sizeof(request), response, sizeof(response),
        &response_length) == 0);
    memcpy(&generation,
           response + sizeof(reply) + sizeof(test_nfgenmsg_t) +
               sizeof(attribute),
           sizeof(generation));
    generation = host_to_be32(generation);
    memset(batch, 0, sizeof(batch));
    batch_length = append_batch_begin(batch, 0, generation);
    batch_length = append_table(
        batch, batch_length, 0u, 0x401u, "container_nat", 102u);
    batch_length = append_base_chain(
        batch, batch_length, "container_nat", "POSTROUTING",
        4u, 100, 1u, 103u);
    batch_length = append_simple_nat_target_rule(
        batch, batch_length, "container_nat", "POSTROUTING",
        "MASQUERADE", 104u);
    batch_length = append_batch_end(batch, batch_length);
    assert(edge_linux_netfilter_respond_in_namespace(
        44u, 492u, batch, batch_length, response, sizeof(response),
        &response_length) == 0);
    {
        edge_linux_netfilter_tuple_t tuple;
        edge_linux_conntrack_snapshot_t connection;
        static const uint8_t private_address[4] = {172u, 17u, 0u, 2u};
        static const uint8_t public_address[4] = {10u, 0u, 2u, 15u};
        static const uint8_t remote_address[4] = {8u, 8u, 8u, 8u};
        uint32_t masquerade_address;

        memcpy(&masquerade_address, public_address,
               sizeof(masquerade_address));
        edge_linux_netfilter_set_ipv4_masquerade_address(
            masquerade_address);
        memset(&tuple, 0, sizeof(tuple));
        tuple.network_namespace = 44u;
        tuple.family = TEST_AF_INET;
        tuple.protocol = TEST_IPPROTO_UDP;
        memcpy(tuple.source_address, private_address,
               sizeof(private_address));
        memcpy(tuple.destination_address, remote_address,
               sizeof(remote_address));
        tuple.source_port = 42000u;
        tuple.destination_port = 53u;
        assert(edge_linux_netfilter_translate_local(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) == 1);
        assert(memcmp(tuple.source_address, public_address,
                      sizeof(public_address)) == 0);
        assert(edge_linux_conntrack_snapshot(
            44u, 0u, &connection) == 0);
        assert(memcmp(connection.original.source_address,
                      private_address, sizeof(private_address)) == 0);
        assert(memcmp(connection.translated.source_address,
                      public_address, sizeof(public_address)) == 0);

        memset(&tuple, 0, sizeof(tuple));
        tuple.network_namespace = 44u;
        tuple.family = TEST_AF_INET;
        tuple.protocol = TEST_IPPROTO_UDP;
        memcpy(tuple.source_address, private_address,
               sizeof(private_address));
        tuple.source_address[3] = 3u;
        memcpy(tuple.destination_address, remote_address,
               sizeof(remote_address));
        tuple.source_port = 42001u;
        tuple.destination_port = 53u;
        assert(edge_linux_netfilter_translate_forward(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) == 1);
        assert(memcmp(tuple.source_address, public_address,
                      sizeof(public_address)) == 0);

        memset(&tuple, 0, sizeof(tuple));
        tuple.network_namespace = 44u;
        tuple.family = TEST_AF_INET;
        tuple.protocol = TEST_IPPROTO_UDP;
        memcpy(tuple.source_address, remote_address,
               sizeof(remote_address));
        memcpy(tuple.destination_address, public_address,
               sizeof(public_address));
        tuple.source_port = 53u;
        tuple.destination_port = 42001u;
        assert(edge_linux_netfilter_translate_forward(
            &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) == 1);
        assert(memcmp(tuple.destination_address, private_address,
                      sizeof(private_address) - 1u) == 0);
        assert(tuple.destination_address[3] == 3u);
    }

    request.header.type = (10u << 8u) | 3u;
    assert(edge_linux_netfilter_respond(
        492u, &request, sizeof(request) - 1u, response, sizeof(response),
        &response_length) == -EDGE_LINUX_EINVAL);

    route_length = append_bridge_link(
        route_request, 16u, 0, 0, 0);
    route_handled = 0;
    assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
    assert(route_handled == 1);
    assert(g_netlink_event_count == 1u);
    assert(g_netlink_event_namespace == 0u);
    assert(g_netlink_event_protocol == 0u);
    assert(g_netlink_event_groups == 1u);
    assert(g_netlink_event_type == 16u);
    assert(g_netlink_event_length == route_length);

    {
        edge_net_device_snapshot_t virtual_snapshot;
        int32_t bridge_ifindex;
        int32_t bond_ifindex;
        int32_t vrf_ifindex;
        int32_t dummy_ifindex;
        int32_t vlan_ifindex;
        int32_t macvlan_ifindex;
        int32_t ipvlan_ifindex;

        assert(edge_net_device_find(
                   0u, "docker0", &bridge_ifindex) == EDGE_NET_OK);
        route_length = append_virtual_link(
            route_request, 16u, 0, "dummy-test", "dummy",
            0, 0u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_device_find(
                   0u, "dummy-test", &dummy_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   dummy_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.configuration.kind ==
               EDGE_NET_DEVICE_DUMMY);
        assert(virtual_snapshot.configuration.carrier == 1u);
        {
            edge_linux_network_interface_snapshot_t interface_snapshot;

            assert(edge_linux_network_interface_by_name(
                       0u, "dummy-test", &interface_snapshot) == 0);
            assert(interface_snapshot.ifindex == dummy_ifindex);
            assert(interface_snapshot.mtu == 1500u);
            assert(interface_snapshot.tx_queue_length == 1000u);
            assert(interface_snapshot.carrier == 1u);
            assert(edge_linux_network_interface_by_index(
                       0u, dummy_ifindex, &interface_snapshot) == 0);
            assert(strcmp(interface_snapshot.name, "dummy-test") == 0);
            assert(edge_linux_network_interface_configure(
                       0u, dummy_ifindex, EDGE_NET_DEVICE_FLAG_UP,
                       EDGE_NET_DEVICE_FLAG_UP, 1400u, 1,
                       2048u, 1) == 0);
            assert(edge_linux_network_interface_configure_ipv4(
                       0u, dummy_ifindex, 0x01020304u, 24u,
                       0x01020301u) == 0);
            assert(edge_linux_network_interface_by_name(
                       0u, "dummy-test", &interface_snapshot) == 0);
            assert(interface_snapshot.flags & EDGE_NET_DEVICE_FLAG_UP);
            assert(interface_snapshot.mtu == 1400u);
            assert(interface_snapshot.tx_queue_length == 2048u);
            assert(interface_snapshot.ipv4_address == 0x01020304u);
            assert(interface_snapshot.ipv4_prefix_length == 24u);
            assert(interface_snapshot.ipv4_gateway == 0x01020301u);
            assert(edge_linux_network_interface_at(
                       0u, 1u, &interface_snapshot) == 0);
            assert(strcmp(interface_snapshot.name, "dummy-test") == 0);
            assert(edge_linux_network_interface_by_name(
                       37u, "dummy-test", &interface_snapshot) ==
                   -EDGE_LINUX_ENODEV);
        }

        route_length = append_virtual_link(
            route_request, 16u, 0, "bond-test", "bond",
            0, EDGE_NET_BOND_MODE_ACTIVE_BACKUP,
            EDGE_NET_BOND_HASH_LAYER23);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_device_find(
                   0u, "bond-test", &bond_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   bond_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.configuration.kind ==
               EDGE_NET_DEVICE_BOND);
        assert(virtual_snapshot.configuration.virtual_mode ==
               EDGE_NET_BOND_MODE_ACTIVE_BACKUP);
        assert(virtual_snapshot.configuration.virtual_flags ==
               EDGE_NET_BOND_HASH_LAYER23);
        route_length = append_bridge_link(
            route_request, 19u, bond_ifindex, 1u, 1u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        route_length = append_virtual_link(
            route_request, 19u, dummy_ifindex, 0, 0, 0, 0u, 0u);
        route_length = put_attribute(
            route_request, route_length, 10u,
            &bond_ifindex, sizeof(bond_ifindex));
        ((test_nlmsghdr_t *)route_request)->length = route_length;
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   dummy_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.master_ifindex == bond_ifindex);
        assert(edge_net_device_snapshot(
                   bond_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.configuration.carrier == 1u);

        route_length = append_virtual_link(
            route_request, 16u, 0, "vlan-test", "vlan",
            bridge_ifindex, 123u, 0x8100u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_device_find(
                   0u, "vlan-test", &vlan_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   vlan_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.configuration.kind ==
               EDGE_NET_DEVICE_VLAN);
        assert(virtual_snapshot.configuration.lower_ifindex ==
               bridge_ifindex);
        assert(virtual_snapshot.configuration.vlan_id == 123u);
        assert(virtual_snapshot.configuration.vlan_protocol == 0x8100u);

        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == -EDGE_LINUX_EEXIST);
        route_length = append_getlink_name(
            route_request, "vlan-test", 210u);
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_links(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        assert(response_u32_attribute(
                   response, route_offset, sizeof(test_ifinfomsg_t),
                   5u) == (uint32_t)bridge_ifindex);

        route_length = append_virtual_link(
            route_request, 16u, 0, "ipvlan-test", "ipvlan",
            bridge_ifindex, EDGE_NET_IPVLAN_MODE_L2,
            EDGE_NET_IPVLAN_FLAG_PRIVATE);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_device_find(
                   0u, "ipvlan-test", &ipvlan_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   ipvlan_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.configuration.kind ==
               EDGE_NET_DEVICE_IPVLAN);
        assert(virtual_snapshot.configuration.lower_ifindex ==
               bridge_ifindex);
        assert(virtual_snapshot.configuration.virtual_mode ==
               EDGE_NET_IPVLAN_MODE_L2);
        assert(virtual_snapshot.configuration.virtual_flags ==
               EDGE_NET_IPVLAN_FLAG_PRIVATE);
        route_length = append_getlink_name(
            route_request, "ipvlan-test", 212u);
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_links(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        assert(response_u32_attribute(
                   response, route_offset, sizeof(test_ifinfomsg_t),
                   5u) == (uint32_t)bridge_ifindex);

        route_length = append_virtual_link(
            route_request, 17u, ipvlan_ifindex, 0, 0, 0, 0u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   ipvlan_ifindex, &virtual_snapshot) ==
               EDGE_NET_NOT_FOUND);

        route_length = append_virtual_link(
            route_request, 16u, 0, "macvlan-test", "macvlan",
            bridge_ifindex, EDGE_NET_MACVLAN_MODE_BRIDGE, 1u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_device_find(
                   0u, "macvlan-test", &macvlan_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   macvlan_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.configuration.kind ==
               EDGE_NET_DEVICE_MACVLAN);
        assert(virtual_snapshot.configuration.lower_ifindex ==
               bridge_ifindex);
        assert(virtual_snapshot.configuration.virtual_mode ==
               EDGE_NET_MACVLAN_MODE_BRIDGE);
        assert(virtual_snapshot.configuration.virtual_flags == 1u);
        route_length = append_getlink_name(
            route_request, "macvlan-test", 211u);
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_links(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        assert(response_u32_attribute(
                   response, route_offset, sizeof(test_ifinfomsg_t),
                   5u) == (uint32_t)bridge_ifindex);

        route_length = append_virtual_link(
            route_request, 17u, macvlan_ifindex, 0, 0, 0, 0u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   macvlan_ifindex, &virtual_snapshot) ==
               EDGE_NET_NOT_FOUND);

        route_length = append_virtual_link(
            route_request, 17u, vlan_ifindex, 0, 0, 0, 0u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   vlan_ifindex, &virtual_snapshot) ==
               EDGE_NET_NOT_FOUND);
        route_length = append_virtual_link(
            route_request, 17u, bond_ifindex, 0, 0, 0, 0u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   bond_ifindex, &virtual_snapshot) ==
               EDGE_NET_NOT_FOUND);
        assert(edge_net_device_snapshot(
                   dummy_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.master_ifindex == 0);

        route_length = append_virtual_link(
            route_request, 16u, 0, "vrf-test", "vrf",
            0, 1001u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_find(
                   0u, "vrf-test", &vrf_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   vrf_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.configuration.kind ==
               EDGE_NET_DEVICE_VRF);
        assert(virtual_snapshot.configuration.routing_table == 1001u);
        route_length = append_virtual_link(
            route_request, 19u, dummy_ifindex, 0, 0, 0, 0u, 0u);
        route_length = put_attribute(
            route_request, route_length, 10u,
            &vrf_ifindex, sizeof(vrf_ifindex));
        ((test_nlmsghdr_t *)route_request)->length = route_length;
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   dummy_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.master_ifindex == vrf_ifindex);
        {
            edge_linux_route_query_t lookup;
            edge_linux_route_result_t resolved;
            uint32_t destination = 0x09020304u;

            memset(&lookup, 0, sizeof(lookup));
            memset(&resolved, 0, sizeof(resolved));
            lookup.family = 2u;
            lookup.output_ifindex = dummy_ifindex;
            memcpy(lookup.destination, &destination,
                   sizeof(destination));
            assert(edge_linux_route_lookup(&lookup, &resolved) == 0);
            assert(resolved.table == 1001u);
            assert(resolved.priority == 1000u);
            assert(resolved.output_ifindex == dummy_ifindex);
        }
        route_length = append_virtual_link(
            route_request, 17u, vrf_ifindex, 0, 0, 0, 0u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   dummy_ifindex, &virtual_snapshot) == EDGE_NET_OK);
        assert(virtual_snapshot.master_ifindex == 0);
        route_length = append_virtual_link(
            route_request, 17u, dummy_ifindex, 0, 0, 0, 0u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(edge_net_device_snapshot(
                   dummy_ifindex, &virtual_snapshot) ==
               EDGE_NET_NOT_FOUND);
    }
    {
        edge_linux_route_query_t lookup;
        edge_linux_route_result_t lookup_result;
        test_ifaddrmsg_t address_query;
        const uint8_t *attribute_data;
        uint32_t attribute_length;
        static const uint8_t loopback_ipv6[16] = {
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
        };

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&address_query, 0, sizeof(address_query));
        reply.type = 22u;
        reply.flags = 0x301u;
        address_query.family = TEST_AF_INET6;
        address_query.index = 1u;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &address_query,
               sizeof(address_query));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(address_query));
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_addresses(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        memcpy(&address_query, response + sizeof(reply),
               sizeof(address_query));
        assert(address_query.family == TEST_AF_INET6);
        assert(address_query.prefix_length == 128u);
        assert(address_query.scope == 254u);
        assert(address_query.index == 1u);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(address_query), 1u,
            &attribute_length);
        assert(attribute_data && attribute_length == 16u);
        assert(memcmp(attribute_data, loopback_ipv6, 16u) == 0);

        memset(&lookup, 0, sizeof(lookup));
        lookup.family = TEST_AF_INET6;
        memcpy(lookup.destination, loopback_ipv6, 16u);
        assert(edge_linux_route_lookup(&lookup, &lookup_result) == 0);
        assert(lookup_result.output_ifindex == 1);
        assert(lookup_result.prefix_length == 128u);
        assert(lookup_result.scope == 254u);
        assert(memcmp(lookup_result.preferred_source,
                      loopback_ipv6, 16u) == 0);

        memset(&lookup, 0, sizeof(lookup));
        lookup.family = TEST_AF_INET;
        lookup.destination[0] = 127u;
        lookup.destination[3] = 9u;
        assert(edge_linux_route_lookup(&lookup, &lookup_result) == 0);
        assert(lookup_result.output_ifindex == 1);
        assert(lookup_result.prefix_length == 8u);
        assert(lookup_result.scope == 254u);
        assert(lookup_result.preferred_source[0] == 127u);
        assert(lookup_result.preferred_source[1] == 0u);
        assert(lookup_result.preferred_source[2] == 0u);
        assert(lookup_result.preferred_source[3] == 1u);
    }

    route_length = append_veth_link(
        route_request, 16u, 0, "veth-host", "veth-peer");
    route_handled = 0;
    assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
    assert(route_handled == 1);

    route_length = append_getlink_name(
        route_request, "veth-host", 93u);
    route_offset = 0;
    route_matches = 0;
    assert(edge_linux_rtnetlink_append_links(
        0u, 492u, route_request, route_length,
        response, sizeof(response), &route_offset, &route_matches) == 0);
    assert(route_matches == 1u);
    memcpy(&link_info, response + sizeof(reply), sizeof(link_info));
    assert(link_info.index >= 4);
    {
        edge_net_device_snapshot_t snapshot;

        assert(edge_net_device_snapshot(link_info.index, &snapshot) ==
               EDGE_NET_OK);
        assert(snapshot.configuration.kind == EDGE_NET_DEVICE_VETH);
        assert(snapshot.peer_ifindex > 0);
    }
    {
        edge_net_qdisc_snapshot_t qdisc_snapshot;
        test_tcmsg_t qdisc_query;
        test_tcmsg_t qdisc_reply;
        test_tc_fifo_options_t qdisc_options;
        const uint8_t *attribute_data;
        const uint8_t *nested_data;
        uint32_t attribute_length;
        uint32_t nested_length;

        route_length = append_qdisc(
            route_request, 36u, link_info.index,
            0x10000u, "pfifo", 8u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_qdisc_snapshot(
                   link_info.index, &qdisc_snapshot) == EDGE_NET_OK);
        assert(qdisc_snapshot.configuration.kind == EDGE_NET_QDISC_PFIFO);
        assert(qdisc_snapshot.configuration.handle == 0x10000u);
        assert(qdisc_snapshot.configuration.limit == 8u);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&qdisc_query, 0, sizeof(qdisc_query));
        reply.type = 38u;
        reply.flags = 0x301u;
        reply.sequence = 213u;
        qdisc_query.index = link_info.index;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &qdisc_query,
               sizeof(qdisc_query));
        route_length = finish_message(
            route_request, 0u,
            sizeof(reply) + sizeof(qdisc_query));
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_qdiscs(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        memcpy(&qdisc_reply, response + sizeof(reply),
               sizeof(qdisc_reply));
        assert(reply.type == 36u && reply.sequence == 213u);
        assert(qdisc_reply.index == link_info.index);
        assert(qdisc_reply.handle == 0x10000u);
        assert(qdisc_reply.parent == UINT32_MAX);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(qdisc_reply), 1u,
            &attribute_length);
        assert(attribute_data && attribute_length == sizeof("pfifo"));
        assert(strcmp((const char *)attribute_data, "pfifo") == 0);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(qdisc_reply), 2u,
            &attribute_length);
        assert(attribute_data &&
               attribute_length == sizeof(qdisc_options));
        memcpy(&qdisc_options, attribute_data, sizeof(qdisc_options));
        assert(qdisc_options.limit == 8u);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(qdisc_reply), 3u,
            &attribute_length);
        assert(attribute_data &&
               attribute_length == sizeof(test_tc_stats_t));
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(qdisc_reply), 7u,
            &attribute_length);
        assert(attribute_data);
        nested_data = find_nested_attribute(
            attribute_data, attribute_length, 1u, &nested_length);
        assert(nested_data && nested_length == 16u);
        nested_data = find_nested_attribute(
            attribute_data, attribute_length, 3u, &nested_length);
        assert(nested_data && nested_length == 20u);

        route_length = append_qdisc(
            route_request, 37u, link_info.index,
            0x10000u, NULL, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_qdisc_snapshot(
                   link_info.index, &qdisc_snapshot) == EDGE_NET_OK);
        assert(qdisc_snapshot.configuration.kind == EDGE_NET_QDISC_NOQUEUE);
    }
    {
        static const uint8_t fdb_hardware_address[6] = {
            0x02u, 0x42u, 0xacu, 0x11u, 0, 2u
        };
        test_nlmsghdr_t route_header;
        test_ifinfomsg_t port_update;
        test_ndmsg_t neighbor;
        edge_net_bridge_fdb_entry_t fdb_entry;
        const uint8_t *attribute_data;
        uint32_t attribute_length;
        int32_t bridge_ifindex;

        assert(edge_net_device_find(
                   0u, "docker0", &bridge_ifindex) == EDGE_NET_OK);
        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&port_update, 0, sizeof(port_update));
        route_header.type = 19u;
        port_update.index = link_info.index;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &port_update,
               sizeof(port_update));
        route_offset = sizeof(route_header) + sizeof(port_update);
        route_offset = put_attribute(
            route_request, route_offset, 10u,
            &bridge_ifindex, sizeof(bridge_ifindex));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        route_length = append_bridge_port_controls(
            route_request, link_info.index, 3u, 1u, 0u, 0u,
            0u, 0u, 1u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        {
            edge_net_device_snapshot_t port_snapshot;

            assert(edge_net_device_snapshot(
                       link_info.index, &port_snapshot) == EDGE_NET_OK);
            assert(port_snapshot.hairpin == 1u);
            assert(port_snapshot.bridge_state == 3u);
            assert(port_snapshot.bridge_learning == 0u);
            assert(port_snapshot.bridge_unicast_flood == 0u);
            assert(port_snapshot.bridge_multicast_flood == 0u);
            assert(port_snapshot.bridge_broadcast_flood == 0u);
            assert(port_snapshot.bridge_isolated == 1u);
        }

        route_length = append_bridge_vlan_filtering(
            route_request, bridge_ifindex, 1u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        {
            edge_net_device_snapshot_t bridge_snapshot;

            assert(edge_net_device_snapshot(
                       bridge_ifindex, &bridge_snapshot) == EDGE_NET_OK);
            assert(bridge_snapshot.bridge_vlan_filtering == 1u);
        }
        route_length = append_bridge_vlan(
            route_request, 17u, link_info.index, 1u, 0u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        route_length = append_bridge_vlan(
            route_request, 19u, link_info.index, 100u, 0x6u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        {
            edge_net_bridge_vlan_entry_t vlan_entry;

            assert(edge_net_bridge_vlan_snapshot(
                       link_info.index, 0u, &vlan_entry) == EDGE_NET_OK);
            assert(vlan_entry.vlan_id == 100u);
            assert(vlan_entry.pvid == 1u);
            assert(vlan_entry.untagged == 1u);
            assert(edge_net_bridge_vlan_snapshot(
                       link_info.index, 1u, &vlan_entry) ==
                   EDGE_NET_NOT_FOUND);
        }

        route_length = append_getlink_name(
            route_request, "veth-host", 205u);
        ((test_ifinfomsg_t *)(route_request +
            sizeof(test_nlmsghdr_t)))->family = TEST_AF_BRIDGE;
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_links(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        {
            test_ifinfomsg_t bridge_query_reply;

            memcpy(&bridge_query_reply,
                   response + sizeof(test_nlmsghdr_t),
                   sizeof(bridge_query_reply));
            assert(bridge_query_reply.family == TEST_AF_BRIDGE);
        }
        attribute_data = find_route_attribute(
            response, route_offset, sizeof(test_ifinfomsg_t),
            12u, &attribute_length);
        assert(attribute_data &&
               attribute_length >= sizeof(test_nlattr_t) + 1u);
        {
            const uint8_t *nested;
            uint32_t nested_length;

            nested = find_nested_attribute(
                attribute_data, attribute_length, 1u, &nested_length);
            assert(nested && nested_length == 1u && nested[0] == 3u);
            nested = find_nested_attribute(
                attribute_data, attribute_length, 4u, &nested_length);
            assert(nested && nested_length == 1u && nested[0] == 1u);
            nested = find_nested_attribute(
                attribute_data, attribute_length, 8u, &nested_length);
            assert(nested && nested_length == 1u && nested[0] == 0u);
            nested = find_nested_attribute(
                attribute_data, attribute_length, 9u, &nested_length);
            assert(nested && nested_length == 1u && nested[0] == 0u);
            nested = find_nested_attribute(
                attribute_data, attribute_length, 27u, &nested_length);
            assert(nested && nested_length == 1u && nested[0] == 0u);
            nested = find_nested_attribute(
                attribute_data, attribute_length, 30u, &nested_length);
            assert(nested && nested_length == 1u && nested[0] == 0u);
            nested = find_nested_attribute(
                attribute_data, attribute_length, 33u, &nested_length);
            assert(nested && nested_length == 1u && nested[0] == 1u);
        }
        attribute_data = find_route_attribute(
            response, route_offset, sizeof(test_ifinfomsg_t),
            26u, &attribute_length);
        assert(attribute_data && attribute_length >=
               sizeof(test_nlattr_t) + sizeof(test_bridge_vlan_info_t));
        {
            const test_nlattr_t *vlan_attribute =
                (const test_nlattr_t *)attribute_data;
            test_bridge_vlan_info_t vlan;

            assert((vlan_attribute->type & 0x3fffu) == 2u);
            memcpy(&vlan, vlan_attribute + 1, sizeof(vlan));
            assert(vlan.vlan_id == 100u);
            assert((vlan.flags & 0x6u) == 0x6u);
        }

        {
            static const uint8_t multicast_group[4] = {
                239u, 1u, 1u, 1u
            };
            edge_net_bridge_mdb_entry_t mdb_entry;
            test_bridge_port_message_t mdb_query;
            test_mdb_entry_t mdb_reply;
            const uint8_t *outer_data;
            const uint8_t *list_data;
            const uint8_t *entry_data;
            uint32_t outer_length;
            uint32_t list_length;
            uint32_t entry_length;

            route_length = append_bridge_mdb(
                route_request, 84u, bridge_ifindex,
                link_info.index, multicast_group, 100u);
            route_handled = 0;
            assert(edge_linux_rtnetlink_apply(
                       0u, route_request, route_length,
                       &route_handled) == 0);
            assert(route_handled == 1);
            assert(edge_net_bridge_mdb_snapshot(
                       bridge_ifindex, 0u, &mdb_entry) == EDGE_NET_OK);
            assert(mdb_entry.port_ifindex == link_info.index);
            assert(mdb_entry.vlan_id == 100u);
            assert(mdb_entry.is_static == 1u);
            assert(memcmp(mdb_entry.group_address,
                          multicast_group, 4u) == 0);

            memset(route_request, 0, sizeof(route_request));
            memset(&reply, 0, sizeof(reply));
            memset(&mdb_query, 0, sizeof(mdb_query));
            reply.type = 86u;
            reply.flags = 0x301u;
            reply.sequence = 209u;
            mdb_query.family = TEST_AF_BRIDGE;
            mdb_query.ifindex = (uint32_t)bridge_ifindex;
            memcpy(route_request, &reply, sizeof(reply));
            memcpy(route_request + sizeof(reply), &mdb_query,
                   sizeof(mdb_query));
            route_length = finish_message(
                route_request, 0u,
                sizeof(reply) + sizeof(mdb_query));
            route_offset = 0u;
            route_matches = 0u;
            assert(edge_linux_rtnetlink_append_mdb(
                       0u, 492u, route_request, route_length,
                       response, sizeof(response), &route_offset,
                       &route_matches) == 0);
            assert(route_matches == 1u);
            memcpy(&reply, response, sizeof(reply));
            assert(reply.type == 84u && reply.sequence == 209u);
            outer_data = find_route_attribute(
                response, reply.length, sizeof(mdb_query), 1u,
                &outer_length);
            assert(outer_data);
            assert(((const test_nlattr_t *)(outer_data -
                    sizeof(test_nlattr_t)))->type == 1u);
            list_data = find_nested_attribute(
                outer_data, outer_length, 1u, &list_length);
            assert(list_data);
            assert(((const test_nlattr_t *)(list_data -
                    sizeof(test_nlattr_t)))->type == 1u);
            entry_data = find_nested_attribute(
                list_data, list_length, 1u, &entry_length);
            assert(entry_data && entry_length == sizeof(mdb_reply));
            memcpy(&mdb_reply, entry_data, sizeof(mdb_reply));
            assert(mdb_reply.ifindex == (uint32_t)link_info.index);
            assert(mdb_reply.vlan_id == 100u);
            assert(mdb_reply.state == 1u);
            assert(memcmp(&mdb_reply.address.ipv4,
                          multicast_group, 4u) == 0);

            route_length = append_bridge_mdb(
                route_request, 85u, bridge_ifindex,
                link_info.index, multicast_group, 100u);
            route_handled = 0;
            assert(edge_linux_rtnetlink_apply(
                       0u, route_request, route_length,
                       &route_handled) == 0);
            assert(route_handled == 1);
            assert(edge_net_bridge_mdb_snapshot(
                       bridge_ifindex, 0u, &mdb_entry) ==
                   EDGE_NET_NOT_FOUND);
        }

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&neighbor, 0, sizeof(neighbor));
        route_header.type = 28u;
        neighbor.family = TEST_AF_BRIDGE;
        neighbor.index = link_info.index;
        neighbor.state = 0x80u;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &neighbor,
               sizeof(neighbor));
        route_offset = sizeof(route_header) + sizeof(neighbor);
        route_offset = put_attribute(
            route_request, route_offset, 2u,
            fdb_hardware_address, sizeof(fdb_hardware_address));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_bridge_fdb_snapshot(
                   bridge_ifindex, 0u, &fdb_entry) == EDGE_NET_OK);
        assert(fdb_entry.port_ifindex == link_info.index);
        assert(fdb_entry.is_static == 1u);

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&neighbor, 0, sizeof(neighbor));
        route_header.type = 30u;
        route_header.flags = 0x301u;
        route_header.sequence = 203u;
        neighbor.family = TEST_AF_BRIDGE;
        neighbor.index = link_info.index;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &neighbor,
               sizeof(neighbor));
        route_length = finish_message(
            route_request, 0, sizeof(route_header) + sizeof(neighbor));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_neighbors(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(neighbor), 2u,
            &attribute_length);
        assert(attribute_data && attribute_length == 6u);
        assert(memcmp(attribute_data, fdb_hardware_address, 6u) == 0);

        ((test_nlmsghdr_t *)route_request)->type = 29u;
        route_offset = sizeof(route_header) + sizeof(neighbor);
        route_offset = put_attribute(
            route_request, route_offset, 2u,
            fdb_hardware_address, sizeof(fdb_hardware_address));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_bridge_fdb_snapshot(
                   bridge_ifindex, 0u, &fdb_entry) == EDGE_NET_NOT_FOUND);
    }

    memset(route_request, 0, sizeof(route_request));
    memset(&reply, 0, sizeof(reply));
    reply.length = (uint32_t)sizeof(reply) + 4u;
    reply.type = 18u;
    reply.flags = 0x301u;
    reply.sequence = 93u;
    memcpy(route_request, &reply, sizeof(reply));
    route_length = reply.length;
    route_offset = 0;
    route_matches = 0;
    assert(edge_linux_rtnetlink_append_links(
        0u, 492u, route_request, route_length,
        response, sizeof(response), &route_offset, &route_matches) == 0);
    assert(route_matches == 3u);

    route_length = append_getlink_name(
        route_request, "veth-peer", 94u);
    route_offset = 0;
    route_matches = 0;
    assert(edge_linux_rtnetlink_append_links(
        0u, 492u, route_request, route_length,
        response, sizeof(response), &route_offset, &route_matches) == 0);
    assert(route_matches == 1u);
    {
        test_ifinfomsg_t peer_info;
        test_nlmsghdr_t route_header;
        test_ifaddrmsg_t peer_address;
        test_rtmsg_t route_query;
        uint32_t peer_ipv4 = 0x020011acu;
        uint32_t gateway_ipv4 = 0x010011acu;

        memcpy(&peer_info, response + sizeof(reply), sizeof(peer_info));
        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&peer_address, 0, sizeof(peer_address));
        route_header.type = 20u;
        route_header.flags = 0x405u;
        peer_address.family = 2u;
        peer_address.prefix_length = 16u;
        peer_address.index = (uint32_t)peer_info.index;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &peer_address,
               sizeof(peer_address));
        route_offset = sizeof(route_header) + sizeof(peer_address);
        route_offset = put_attribute(
            route_request, route_offset, 2u,
            &peer_ipv4, sizeof(peer_ipv4));
        ((test_nlmsghdr_t *)route_request)->length = route_offset;
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                0u, route_request, route_offset, &route_handled) == 0);
        assert(route_handled == 1);

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&route_query, 0, sizeof(route_query));
        route_header.type = 24u;
        route_header.flags = 0x405u;
        route_query.family = 2u;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &route_query,
               sizeof(route_query));
        route_offset = sizeof(route_header) + sizeof(route_query);
        route_offset = put_attribute(
            route_request, route_offset, 4u,
            &peer_info.index, sizeof(peer_info.index));
        route_offset = put_attribute(
            route_request, route_offset, 5u,
            &gateway_ipv4, sizeof(gateway_ipv4));
        ((test_nlmsghdr_t *)route_request)->length = route_offset;
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                0u, route_request, route_offset, &route_handled) == 0);
        assert(route_handled == 1);

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&route_query, 0, sizeof(route_query));
        route_header.type = 26u;
        route_header.flags = 0x301u;
        route_header.sequence = 96u;
        route_query.family = 2u;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &route_query,
               sizeof(route_query));
        route_length = finish_message(
            route_request, 0, sizeof(route_header) + sizeof(route_query));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_route(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 2u);
        memcpy(&reply, response, sizeof(reply));
        assert(reply.type == 24u);
        assert(response_u32_attribute(
            response, reply.length, sizeof(route_query), 1u) ==
            0x000011acu);
        assert(response_u32_attribute(
            response, reply.length, sizeof(route_query), 4u) ==
            (uint32_t)peer_info.index);
        memcpy(&reply, response + align4(reply.length), sizeof(reply));
        assert(reply.type == 24u);
        assert(response_u32_attribute(
            response + align4(((test_nlmsghdr_t *)response)->length),
            reply.length, sizeof(route_query), 5u) == gateway_ipv4);

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&peer_address, 0, sizeof(peer_address));
        route_header.type = 22u;
        route_header.flags = 0x301u;
        route_header.sequence = 94u;
        peer_address.family = 2u;
        peer_address.index = (uint32_t)peer_info.index;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &peer_address,
               sizeof(peer_address));
        route_length = finish_message(
            route_request, 0, sizeof(route_header) + sizeof(peer_address));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_addresses(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        assert(reply.type == 20u);
        assert(response_u32_attribute(
            response, route_offset, sizeof(peer_address), 2u) == peer_ipv4);

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&route_query, 0, sizeof(route_query));
        route_header.type = 26u;
        route_header.sequence = 95u;
        route_query.family = 2u;
        route_query.destination_length = 32u;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &route_query,
               sizeof(route_query));
        route_offset = sizeof(route_header) + sizeof(route_query);
        route_offset = put_attribute(
            route_request, route_offset, 1u,
            &gateway_ipv4, sizeof(gateway_ipv4));
        route_length = finish_message(route_request, 0, route_offset);
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_route(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        assert(reply.type == 24u);
        assert(response_u32_attribute(
            response, route_offset, sizeof(route_query), 4u) ==
            (uint32_t)peer_info.index);
        assert(response_u32_attribute(
            response, route_offset, sizeof(route_query), 7u) == peer_ipv4);
    }

    {
        edge_net_device_snapshot_t bridge_snapshot;
        edge_net_device_snapshot_t host_snapshot;
        edge_net_device_snapshot_t peer_snapshot;
        int32_t bridge_ifindex;
        int32_t host_ifindex;
        int32_t peer_ifindex;

        assert(edge_net_device_find(
                   0u, "docker0", &bridge_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_find(
                   0u, "veth-host", &host_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_find(
                   0u, "veth-peer", &peer_ifindex) == EDGE_NET_OK);

        route_length = append_bridge_link(
            route_request, 19u, host_ifindex, 1u, 1u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        route_length = append_link_namespace(
            route_request, peer_ifindex, 99u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        route_length = append_bridge_link(
            route_request, 19u, peer_ifindex, 1u, 1u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   37u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        assert(edge_net_device_snapshot(
                   bridge_ifindex, &bridge_snapshot) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   host_ifindex, &host_snapshot) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   peer_ifindex, &peer_snapshot) == EDGE_NET_OK);
        assert(host_snapshot.master_ifindex == bridge_ifindex);
        assert(host_snapshot.configuration.flags & EDGE_NET_DEVICE_FLAG_UP);
        assert(peer_snapshot.configuration.flags & EDGE_NET_DEVICE_FLAG_UP);
        assert(host_snapshot.configuration.carrier == 1u);
        assert(peer_snapshot.configuration.carrier == 1u);

        route_length = append_getlink_name(
            route_request, "veth-host", 97u);
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_links(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&link_info, response + sizeof(reply), sizeof(link_info));
        assert((link_info.flags & 0x10041u) == 0x10041u);

        route_length = append_getlink_name(
            route_request, "veth-peer", 98u);
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_links(
                   37u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&link_info, response + sizeof(reply), sizeof(link_info));
        assert((link_info.flags & 0x10041u) == 0x10041u);
    }

    route_length = append_getlink_name(
        route_request, "veth-host", 99u);
    route_offset = 0;
    route_matches = 0;
    assert(edge_linux_rtnetlink_append_links(
               0u, 492u, route_request, route_length,
               response, sizeof(response), &route_offset,
               &route_matches) == 0);
    assert(route_matches == 1u);
    memcpy(&link_info, response + sizeof(reply), sizeof(link_info));

    route_length = append_veth_link(
        route_request, 17u, link_info.index, 0, 0);
    route_handled = 0;
    assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
    assert(route_handled == 1);

    route_length = append_getlink_name(
        route_request, "veth-peer", 94u);
    route_offset = 0;
    route_matches = 0;
    assert(edge_linux_rtnetlink_append_links(
        0u, 492u, route_request, route_length,
        response, sizeof(response), &route_offset, &route_matches) == 0);
    assert(route_matches == 0u);

    edge_linux_rtnetlink_set_ipv4_update_callback(observe_bridge_ipv4);
    memset(route_request, 0, sizeof(route_request));
    route_offset = begin_message(
        route_request, 0, 18u, 0, 91u, 0);
    route_offset += sizeof(test_ifinfomsg_t) - sizeof(test_nfgenmsg_t);
    route_offset = put_attribute(
        route_request, route_offset, 3u,
        "docker0", sizeof("docker0"));
    route_length = finish_message(route_request, 0, route_offset);
    route_offset = 0;
    route_matches = 0;
    assert(edge_linux_rtnetlink_append_links(
        0u, 492u, route_request, route_length,
        response, sizeof(response), &route_offset, &route_matches) == 0);
    assert(route_matches == 1u);
    memcpy(&reply, response, sizeof(reply));
    assert(reply.type == 16u);
    memcpy(&link_info, response + sizeof(reply), sizeof(link_info));
    assert(link_info.index >= 3);
    assert((link_info.flags & 0x1002u) == 0x1002u);
    {
        edge_net_device_snapshot_t snapshot;

        assert(edge_net_device_snapshot(link_info.index, &snapshot) ==
               EDGE_NET_OK);
        assert(snapshot.configuration.kind == EDGE_NET_DEVICE_BRIDGE);
        assert(snapshot.configuration.network_namespace == 0u);
    }

    route_length = append_bridge_link(
        route_request, 19u, link_info.index, 1u, 1u);
    route_handled = 0;
    assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
    assert(route_handled == 1);
    route_length = append_getlink_name(
        route_request, "docker0", 95u);
    route_offset = 0;
    route_matches = 0;
    assert(edge_linux_rtnetlink_append_links(
        0u, 492u, route_request, route_length,
        response, sizeof(response), &route_offset, &route_matches) == 0);
    assert(route_matches == 1u);
    memcpy(&link_info, response + sizeof(reply), sizeof(link_info));
    assert((link_info.flags & 1u) == 1u);

    route_length = append_link_namespace(
        route_request, link_info.index, 99u);
    route_handled = 0;
    assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
    assert(route_handled == 1);
    {
        edge_net_device_snapshot_t snapshot;

        assert(edge_net_device_snapshot(link_info.index, &snapshot) ==
               EDGE_NET_OK);
        assert(snapshot.configuration.network_namespace == 37u);
    }

    memset(route_request, 0, sizeof(route_request));
    memset(&reply, 0, sizeof(reply));
    reply.type = 20u;
    reply.flags = 0x405u;
    memcpy(route_request, &reply, sizeof(reply));
    {
        test_ifaddrmsg_t address;
        uint32_t ipv4 = 0x010011acu;

        memset(&address, 0, sizeof(address));
        address.family = 2u;
        address.prefix_length = 16u;
        address.index = (uint32_t)link_info.index;
        memcpy(route_request + sizeof(reply), &address, sizeof(address));
        route_offset = sizeof(reply) + sizeof(address);
        route_offset = put_attribute(
            route_request, route_offset, 2u, &ipv4, sizeof(ipv4));
        ((test_nlmsghdr_t *)route_request)->length = route_offset;
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                37u, route_request, route_offset, &route_handled) == 0);
        assert(route_handled == 1);
        assert(observed_bridge_ipv4 == ipv4);
        assert(observed_bridge_ifindex == link_info.index);
        assert(observed_bridge_namespace == 37u);
        assert(observed_bridge_prefix == 16u);
        assert(observed_bridge_active == 1);
        assert(edge_linux_rtnetlink_ipv4_is_local(ipv4));
        assert(edge_linux_rtnetlink_ipv4_is_local_in_namespace(
            37u, ipv4));
        assert(!edge_linux_rtnetlink_ipv4_is_local_in_namespace(
            38u, ipv4));
        {
            edge_net_device_snapshot_t snapshot;

            assert(edge_net_device_snapshot(
                       link_info.index, &snapshot) == EDGE_NET_OK);
            assert(snapshot.ipv4_address == ipv4);
            assert(snapshot.ipv4_prefix_length == 16u);
        }
        {
            uint32_t primary = 0;
            uint32_t owner = 0;

            assert(edge_linux_rtnetlink_ipv4_primary(37u, &primary) == 0);
            assert(primary == ipv4);
            assert(edge_linux_rtnetlink_ipv4_owner(ipv4, &owner) == 0);
            assert(owner == 37u);
            assert(edge_linux_rtnetlink_ipv4_primary(38u, &primary) ==
                   -EDGE_LINUX_ENOENT);
        }
    }

    route_length = append_bridge_link(
        route_request, 16u, 0, 0, 0);
    route_handled = 0;
    assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
    assert(route_handled == 1);

    route_length = append_bridge_link(
        route_request, 17u, link_info.index, 0, 0);
    route_handled = 0;
    assert(edge_linux_rtnetlink_apply(
            37u, route_request, route_length, &route_handled) == 0);
    assert(route_handled == 1);
    assert(observed_bridge_ipv4 == 0x010011acu);
    assert(observed_bridge_prefix == 16u);
    assert(observed_bridge_active == 0);
    assert(!edge_linux_rtnetlink_ipv4_is_local(0x010011acu));
    assert(!edge_linux_rtnetlink_ipv4_is_local_in_namespace(
        37u, 0x010011acu));
    {
        edge_net_device_snapshot_t snapshot;

        assert(edge_net_device_snapshot(link_info.index, &snapshot) ==
               EDGE_NET_NOT_FOUND);
    }

    edge_linux_rtnetlink_set_ipv4_provider(&test_ipv4_provider);
    edge_linux_rtnetlink_set_ipv6_provider(&test_ipv6_provider);
    {
        test_ndmsg_t neighbor_query;
        const uint8_t *attribute_data;
        uint32_t attribute_length;

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&neighbor_query, 0, sizeof(neighbor_query));
        reply.type = 30u;
        reply.flags = 0x301u;
        reply.sequence = 199u;
        neighbor_query.family = TEST_AF_INET;
        neighbor_query.index = 44;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &neighbor_query,
               sizeof(neighbor_query));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(neighbor_query));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_neighbors(
                   37u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        memcpy(&neighbor_query, response + sizeof(reply),
               sizeof(neighbor_query));
        assert(neighbor_query.family == TEST_AF_INET);
        assert(neighbor_query.index == 44);
        assert(neighbor_query.state == 0x80u);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(neighbor_query), 1u,
            &attribute_length);
        assert(attribute_data && attribute_length == sizeof(uint32_t));
        assert(memcmp(attribute_data, &test_ipv4_neighbor_address,
                      sizeof(test_ipv4_neighbor_address)) == 0);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(neighbor_query), 2u,
            &attribute_length);
        assert(attribute_data && attribute_length == 6u);
        assert(memcmp(attribute_data, test_ipv4_neighbor_hardware_address,
                      6u) == 0);
    }
    {
        static const uint8_t virtual_ipv6[16] = {
            0xfdu, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x37u
        };
        edge_linux_network_interface_snapshot_t snapshot;
        test_ifaddrmsg_t address_update;
        test_ifaddrmsg_t address_query;
        test_rtmsg_t route_query;
        uint32_t interface_index;
        uint32_t virtual_flags = 0x102u;
        const uint8_t *attribute_data;
        uint32_t attribute_length;

        route_length = append_virtual_link(
            route_request, 16u, 0, "ipv6dummy", "dummy", 0, 0, 0);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   37u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_linux_network_interface_by_name(
                   37u, "ipv6dummy", &snapshot) == 0);
        interface_index = (uint32_t)snapshot.ifindex;

        {
            test_ndmsg_t neighbor_update;

            memset(route_request, 0, sizeof(route_request));
            memset(&reply, 0, sizeof(reply));
            memset(&neighbor_update, 0, sizeof(neighbor_update));
            reply.type = 28u;
            reply.flags = 0x405u;
            neighbor_update.family = TEST_AF_INET;
            neighbor_update.index = (int32_t)interface_index;
            neighbor_update.state = 0x80u;
            memcpy(route_request, &reply, sizeof(reply));
            memcpy(route_request + sizeof(reply), &neighbor_update,
                   sizeof(neighbor_update));
            route_offset = sizeof(reply) + sizeof(neighbor_update);
            route_offset = put_attribute(
                route_request, route_offset, 1u,
                &test_ipv4_neighbor_address,
                sizeof(test_ipv4_neighbor_address));
            route_offset = put_attribute(
                route_request, route_offset, 2u,
                test_ipv4_neighbor_hardware_address,
                sizeof(test_ipv4_neighbor_hardware_address));
            route_length = finish_message(route_request, 0, route_offset);
            observed_ipv4_neighbor_active = -1;
            route_handled = 0;
            assert(edge_linux_rtnetlink_apply(
                       37u, route_request, route_length,
                       &route_handled) == 0);
            assert(route_handled == 1);
            assert(observed_ipv4_neighbor_active == 1);
            assert(observed_ipv4_neighbor_namespace == 37u);
            assert(observed_ipv4_neighbor_ifindex ==
                   (int32_t)interface_index);
            assert(observed_ipv4_neighbor_address ==
                   test_ipv4_neighbor_address);
            assert(observed_ipv4_neighbor_state == 0x80u);
            assert(observed_ipv4_neighbor_flags == 0u);
            assert(memcmp(observed_ipv4_neighbor_hardware_address,
                          test_ipv4_neighbor_hardware_address, 6u) == 0);

            ((test_nlmsghdr_t *)route_request)->type = 29u;
            ((test_nlmsghdr_t *)route_request)->length =
                sizeof(reply) + sizeof(neighbor_update) +
                align4(sizeof(test_nlattr_t) +
                       sizeof(test_ipv4_neighbor_address));
            route_length = ((test_nlmsghdr_t *)route_request)->length;
            observed_ipv4_neighbor_active = -1;
            route_handled = 0;
            assert(edge_linux_rtnetlink_apply(
                       37u, route_request, route_length,
                       &route_handled) == 0);
            assert(route_handled == 1);
            assert(observed_ipv4_neighbor_active == 0);
        }

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&address_update, 0, sizeof(address_update));
        reply.type = 20u;
        reply.flags = 0x405u;
        address_update.family = TEST_AF_INET6;
        address_update.prefix_length = 64u;
        address_update.flags = 0x02u;
        address_update.index = interface_index;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &address_update,
               sizeof(address_update));
        route_offset = sizeof(reply) + sizeof(address_update);
        route_offset = put_attribute(
            route_request, route_offset, 2u,
            virtual_ipv6, sizeof(virtual_ipv6));
        route_offset = put_attribute(
            route_request, route_offset, 8u,
            &virtual_flags, sizeof(virtual_flags));
        route_length = finish_message(route_request, 0, route_offset);
        observed_ipv6_active = -1;
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   37u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(observed_ipv6_active == 1);
        assert(observed_ipv6_namespace == 37u);
        assert(observed_ipv6_ifindex == snapshot.ifindex);
        assert(observed_ipv6_prefix == 64u);
        assert(observed_ipv6_flags == virtual_flags);
        assert(memcmp(observed_ipv6_address, virtual_ipv6, 16u) == 0);
        {
            edge_linux_route_query_t lookup;
            edge_linux_route_result_t lookup_result;

            memset(&lookup, 0, sizeof(lookup));
            lookup.network_namespace = 37u;
            lookup.family = TEST_AF_INET6;
            memcpy(lookup.destination, virtual_ipv6, 16u);
            lookup.destination[15] = 0x99u;
            assert(edge_linux_route_lookup(
                       &lookup, &lookup_result) == 0);
            assert(lookup_result.output_ifindex ==
                   (int32_t)interface_index);
            assert(lookup_result.prefix_length == 64u);
            assert(memcmp(lookup_result.preferred_source,
                          virtual_ipv6, 16u) == 0);
        }

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&address_query, 0, sizeof(address_query));
        reply.type = 22u;
        reply.flags = 0x301u;
        address_query.family = TEST_AF_INET6;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &address_query,
               sizeof(address_query));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(address_query));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_addresses(
                   37u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 2u);
        memcpy(&reply, response, sizeof(reply));
        memcpy(&address_query, response + sizeof(reply),
               sizeof(address_query));
        assert(address_query.index == interface_index);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(address_query), 1u,
            &attribute_length);
        assert(attribute_data && attribute_length == 16u);
        assert(memcmp(attribute_data, virtual_ipv6, 16u) == 0);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(address_query), 8u,
            &attribute_length);
        assert(attribute_data && attribute_length == sizeof(uint32_t));
        memcpy(&observed_ipv6_flags, attribute_data,
               sizeof(observed_ipv6_flags));
        assert(observed_ipv6_flags == virtual_flags);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_query, 0, sizeof(route_query));
        reply.type = 26u;
        reply.flags = 0x301u;
        route_query.family = TEST_AF_INET6;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_query,
               sizeof(route_query));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(route_query));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_route(
                   37u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        assert(response_u32_attribute(
                   response, reply.length, sizeof(route_query), 4u) ==
               interface_index);

        route_length = append_virtual_link(
            route_request, 17u, snapshot.ifindex,
            "ipv6dummy", "dummy", 0, 0, 0);
        observed_ipv6_active = -1;
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   37u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(observed_ipv6_active == 0);
        assert(observed_ipv6_namespace == 37u);
        assert(observed_ipv6_ifindex == snapshot.ifindex);
    }
    {
        test_ifaddrmsg_t address_query;
        const uint8_t *attribute_data;
        uint32_t attribute_length;

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&address_query, 0, sizeof(address_query));
        reply.type = 22u;
        reply.flags = 0x301u;
        reply.sequence = 200u;
        address_query.family = TEST_AF_INET6;
        address_query.index = 2u;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &address_query,
               sizeof(address_query));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(address_query));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_addresses(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        assert(reply.type == 20u);
        memcpy(&address_query, response + sizeof(reply),
               sizeof(address_query));
        assert(address_query.family == TEST_AF_INET6);
        assert(address_query.prefix_length == 64u);
        assert(address_query.index == 2u);
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(address_query), 1u,
            &attribute_length);
        assert(attribute_data && attribute_length == 16u);
        assert(memcmp(attribute_data, test_ipv6_address, 16u) == 0);
    }
    {
        test_rtmsg_t route_query;
        uint32_t first_length;

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_query, 0, sizeof(route_query));
        reply.type = 26u;
        reply.flags = 0x301u;
        reply.sequence = 201u;
        route_query.family = TEST_AF_INET6;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_query,
               sizeof(route_query));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(route_query));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_route(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 2u);
        memcpy(&reply, response, sizeof(reply));
        assert(reply.type == 24u);
        first_length = align4(reply.length);
        memcpy(&reply, response + first_length, sizeof(reply));
        assert(reply.type == 24u);
    }
    {
        test_ndmsg_t neighbor_query;
        const uint8_t *attribute_data;
        uint32_t attribute_length;

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&neighbor_query, 0, sizeof(neighbor_query));
        reply.type = 30u;
        reply.flags = 0x301u;
        reply.sequence = 202u;
        neighbor_query.family = TEST_AF_INET6;
        neighbor_query.index = 2;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &neighbor_query,
               sizeof(neighbor_query));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(neighbor_query));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_neighbors(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(neighbor_query), 1u,
            &attribute_length);
        assert(attribute_data && attribute_length == 16u);
        assert(memcmp(attribute_data, test_ipv6_router, 16u) == 0);
    }
    {
        test_ifaddrmsg_t address_update;

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&address_update, 0, sizeof(address_update));
        reply.type = 20u;
        address_update.family = TEST_AF_INET6;
        address_update.prefix_length = 64u;
        address_update.index = 2u;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &address_update,
               sizeof(address_update));
        route_offset = sizeof(reply) + sizeof(address_update);
        route_offset = put_attribute(
            route_request, route_offset, 2u,
            test_ipv6_address, sizeof(test_ipv6_address));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        assert(observed_ipv6_active == 1);
        assert(observed_ipv6_prefix == 64u);
        assert(memcmp(observed_ipv6_address, test_ipv6_address, 16u) == 0);
    }
    {
        test_rtmsg_t route_update;
        uint32_t interface_index = 2u;

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_update, 0, sizeof(route_update));
        reply.type = 24u;
        route_update.family = TEST_AF_INET6;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_update,
               sizeof(route_update));
        route_offset = sizeof(reply) + sizeof(route_update);
        route_offset = put_attribute(
            route_request, route_offset, 4u,
            &interface_index, sizeof(interface_index));
        route_offset = put_attribute(
            route_request, route_offset, 5u,
            test_ipv6_router, sizeof(test_ipv6_router));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        assert(observed_ipv6_router_active == 1);
        assert(memcmp(observed_ipv6_router, test_ipv6_router, 16u) == 0);
    }
    {
        static const uint8_t route_destination[4] = {
            198u, 51u, 100u, 0u
        };
        static const uint8_t route_gateway[4] = {10u, 0u, 2u, 2u};
        static const uint8_t rule_source[4] = {192u, 0u, 2u, 0u};
        static const uint8_t lookup_source[4] = {192u, 0u, 2u, 44u};
        static const uint8_t lookup_destination[4] = {
            198u, 51u, 100u, 25u
        };
        test_rtmsg_t route_update;
        test_rulemsg_t rule_update;
        edge_linux_route_query_t lookup;
        edge_linux_route_result_t lookup_result;
        const uint8_t *attribute_data;
        uint32_t attribute_length;
        uint32_t table = 100u;
        uint32_t metric = 25u;
        uint32_t priority = 1000u;
        uint32_t mark = 0x42u;
        uint32_t interface_index = 2u;

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_update, 0, sizeof(route_update));
        reply.type = 24u;
        reply.flags = 0x605u;
        route_update.family = TEST_AF_INET;
        route_update.destination_length = 24u;
        route_update.table = (uint8_t)table;
        route_update.protocol = 4u;
        route_update.type = 1u;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_update,
               sizeof(route_update));
        route_offset = sizeof(reply) + sizeof(route_update);
        route_offset = put_attribute(
            route_request, route_offset, 1u,
            route_destination, sizeof(route_destination));
        route_offset = put_attribute(
            route_request, route_offset, 4u,
            &interface_index, sizeof(interface_index));
        route_offset = put_attribute(
            route_request, route_offset, 5u,
            route_gateway, sizeof(route_gateway));
        route_offset = put_attribute(
            route_request, route_offset, 6u, &metric, sizeof(metric));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&rule_update, 0, sizeof(rule_update));
        reply.type = 32u;
        reply.flags = 0x605u;
        rule_update.family = TEST_AF_INET;
        rule_update.source_length = 24u;
        rule_update.table = (uint8_t)table;
        rule_update.action = 1u;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &rule_update,
               sizeof(rule_update));
        route_offset = sizeof(reply) + sizeof(rule_update);
        route_offset = put_attribute(
            route_request, route_offset, 2u,
            rule_source, sizeof(rule_source));
        route_offset = put_attribute(
            route_request, route_offset, 6u,
            &priority, sizeof(priority));
        route_offset = put_attribute(
            route_request, route_offset, 10u, &mark, sizeof(mark));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        memset(&lookup, 0, sizeof(lookup));
        lookup.family = TEST_AF_INET;
        lookup.mark = mark;
        memcpy(lookup.source, lookup_source, sizeof(lookup_source));
        memcpy(lookup.destination, lookup_destination,
               sizeof(lookup_destination));
        assert(edge_linux_route_lookup(&lookup, &lookup_result) == 0);
        assert(lookup_result.table == table);
        assert(lookup_result.priority == priority);
        assert(lookup_result.metric == metric);
        assert(lookup_result.output_ifindex == 2);
        assert(memcmp(lookup_result.gateway, route_gateway,
                      sizeof(route_gateway)) == 0);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_update, 0, sizeof(route_update));
        reply.type = 26u;
        reply.flags = 0x301u;
        route_update.family = TEST_AF_INET;
        route_update.table = (uint8_t)table;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_update,
               sizeof(route_update));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(route_update));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_route(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        attribute_data = find_route_attribute(
            response, reply.length, sizeof(route_update), 15u,
            &attribute_length);
        assert(attribute_data && attribute_length == sizeof(table));
        assert(memcmp(attribute_data, &table, sizeof(table)) == 0);
        assert(response_u32_attribute(
            response, reply.length, sizeof(route_update), 6u) == metric);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&rule_update, 0, sizeof(rule_update));
        reply.type = 34u;
        reply.flags = 0x301u;
        rule_update.family = TEST_AF_INET;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &rule_update,
               sizeof(rule_update));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(rule_update));
        route_offset = 0;
        route_matches = 0;
        assert(edge_linux_rtnetlink_append_rules(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 4u);

        ((test_nlmsghdr_t *)route_request)->type = 33u;
        ((test_nlmsghdr_t *)route_request)->flags = 0x5u;
        rule_update.table = 0u;
        rule_update.action = 0u;
        rule_update.source_length = 0u;
        memcpy(route_request + sizeof(reply), &rule_update,
               sizeof(rule_update));
        route_offset = sizeof(reply) + sizeof(rule_update);
        route_offset = put_attribute(
            route_request, route_offset, 6u,
            &priority, sizeof(priority));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_update, 0, sizeof(route_update));
        reply.type = 25u;
        route_update.family = TEST_AF_INET;
        route_update.destination_length = 24u;
        route_update.table = (uint8_t)table;
        route_update.protocol = 4u;
        route_update.type = 1u;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_update,
               sizeof(route_update));
        route_offset = sizeof(reply) + sizeof(route_update);
        route_offset = put_attribute(
            route_request, route_offset, 1u,
            route_destination, sizeof(route_destination));
        route_offset = put_attribute(
            route_request, route_offset, 4u,
            &interface_index, sizeof(interface_index));
        route_offset = put_attribute(
            route_request, route_offset, 5u,
            route_gateway, sizeof(route_gateway));
        route_offset = put_attribute(
            route_request, route_offset, 6u, &metric, sizeof(metric));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_linux_route_lookup(&lookup, &lookup_result) ==
               -EDGE_LINUX_ENOENT);
    }
    {
        static const uint8_t destination[4] = {203u, 0u, 113u, 0u};
        static const uint8_t first_gateway[4] = {10u, 0u, 2u, 2u};
        static const uint8_t second_gateway[4] = {10u, 0u, 3u, 2u};
        uint8_t multipath[96];
        test_rtmsg_t route_update;
        edge_linux_route_query_t lookup;
        edge_linux_route_result_t lookup_result;
        const uint8_t *dumped_multipath;
        uint32_t dumped_length;
        uint32_t multipath_length = 0u;
        uint32_t table = 101u;
        uint32_t first_selected = 0u;
        uint32_t second_selected = 0u;
        uint32_t flow;

        memset(multipath, 0, sizeof(multipath));
        multipath_length = append_route_nexthop(
            multipath, multipath_length, 2, 0u, 0u,
            first_gateway, sizeof(first_gateway));
        multipath_length = append_route_nexthop(
            multipath, multipath_length, 3, 0u, 2u,
            second_gateway, sizeof(second_gateway));
        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_update, 0, sizeof(route_update));
        reply.type = 24u;
        reply.flags = 0x605u;
        route_update.family = TEST_AF_INET;
        route_update.destination_length = 24u;
        route_update.table = (uint8_t)table;
        route_update.protocol = 4u;
        route_update.type = 1u;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_update,
               sizeof(route_update));
        route_offset = sizeof(reply) + sizeof(route_update);
        route_offset = put_attribute(
            route_request, route_offset, 1u,
            destination, sizeof(destination));
        route_offset = put_attribute(
            route_request, route_offset, 9u,
            multipath, (uint16_t)multipath_length);
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
            0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        {
            static const uint8_t source_prefix[4] = {192u, 0u, 2u, 0u};
            test_rulemsg_t rule_update;
            uint32_t rule_priority = 900u;

            memset(route_request, 0, sizeof(route_request));
            memset(&reply, 0, sizeof(reply));
            memset(&rule_update, 0, sizeof(rule_update));
            reply.type = 32u;
            reply.flags = 0x605u;
            rule_update.family = TEST_AF_INET;
            rule_update.source_length = 24u;
            rule_update.table = (uint8_t)table;
            rule_update.action = 1u;
            memcpy(route_request, &reply, sizeof(reply));
            memcpy(route_request + sizeof(reply), &rule_update,
                   sizeof(rule_update));
            route_offset = sizeof(reply) + sizeof(rule_update);
            route_offset = put_attribute(
                route_request, route_offset, 2u,
                source_prefix, sizeof(source_prefix));
            route_offset = put_attribute(
                route_request, route_offset, 6u,
                &rule_priority, sizeof(rule_priority));
            route_length = finish_message(route_request, 0, route_offset);
            route_handled = 0;
            assert(edge_linux_rtnetlink_apply(
                0u, route_request, route_length, &route_handled) == 0);
            assert(route_handled == 1);
        }

        memset(&lookup, 0, sizeof(lookup));
        lookup.family = TEST_AF_INET;
        lookup.source[0] = 192u;
        lookup.source[1] = 0u;
        lookup.source[2] = 2u;
        memcpy(lookup.destination, destination, sizeof(destination));
        lookup.destination[3] = 25u;
        for (flow = 1u; flow <= 128u; ++flow) {
            lookup.source[3] = (uint8_t)flow;
            assert(edge_linux_route_lookup(&lookup, &lookup_result) == 0);
            if (lookup_result.output_ifindex == 2) {
                ++first_selected;
                assert(memcmp(lookup_result.gateway, first_gateway,
                              sizeof(first_gateway)) == 0);
            } else {
                assert(lookup_result.output_ifindex == 3);
                ++second_selected;
                assert(memcmp(lookup_result.gateway, second_gateway,
                              sizeof(second_gateway)) == 0);
            }
        }
        assert(first_selected > 0u);
        assert(second_selected > first_selected);
        lookup.output_ifindex = 2;
        assert(edge_linux_route_lookup(&lookup, &lookup_result) == 0);
        assert(lookup_result.output_ifindex == 2);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&route_update, 0, sizeof(route_update));
        reply.type = 26u;
        reply.flags = 0x301u;
        route_update.family = TEST_AF_INET;
        route_update.table = (uint8_t)table;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &route_update,
               sizeof(route_update));
        route_length = finish_message(
            route_request, 0, sizeof(reply) + sizeof(route_update));
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_route(
            0u, 492u, route_request, route_length,
            response, sizeof(response), &route_offset,
            &route_matches) == 0);
        assert(route_matches == 1u);
        memcpy(&reply, response, sizeof(reply));
        dumped_multipath = find_route_attribute(
            response, reply.length, sizeof(route_update), 9u,
            &dumped_length);
        assert(dumped_multipath != NULL);
        assert(dumped_length == multipath_length);
        assert(memcmp(dumped_multipath, multipath,
                      multipath_length) == 0);
    }
    {
        static const uint8_t destination[4] = {198u, 19u, 0u, 0u};
        static const uint8_t first_gateway[4] = {10u, 0u, 2u, 10u};
        static const uint8_t second_gateway[4] = {10u, 0u, 2u, 11u};
        test_nexthop_group_t members[2];
        test_nhmsg_t query_message;
        edge_linux_route_query_t lookup;
        edge_linux_route_result_t lookup_result;
        uint32_t first_selected = 0u;
        uint32_t second_selected = 0u;
        uint32_t flow;

        route_length = append_nexthop_object(
            route_request, 104u, 11u, 2, first_gateway);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        route_length = append_nexthop_object(
            route_request, 104u, 12u, 2, second_gateway);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        memset(members, 0, sizeof(members));
        members[0].id = 11u;
        members[1].id = 12u;
        members[1].weight = 2u;
        route_length = append_nexthop_group(
            route_request, 20u, members, 2u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);

        memset(route_request, 0, sizeof(route_request));
        memset(&reply, 0, sizeof(reply));
        memset(&query_message, 0, sizeof(query_message));
        reply.type = 106u;
        reply.flags = 0x301u;
        query_message.family = TEST_AF_INET;
        memcpy(route_request, &reply, sizeof(reply));
        memcpy(route_request + sizeof(reply), &query_message,
               sizeof(query_message));
        route_length = finish_message(
            route_request, 0,
            sizeof(reply) + sizeof(query_message));
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_nexthops(
                   0u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 3u);
        memcpy(&reply, response, sizeof(reply));
        assert(reply.type == 104u);
        assert(response_u32_attribute(
                   response, reply.length, sizeof(query_message), 1u) ==
               11u);

        route_length = append_route_nexthop_id(
            route_request, 24u, destination, 24u, 254u, 20u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        assert(route_handled == 1);
        memset(&lookup, 0, sizeof(lookup));
        lookup.family = TEST_AF_INET;
        lookup.source[0] = 192u;
        lookup.source[1] = 0u;
        lookup.source[2] = 2u;
        memcpy(lookup.destination, destination, sizeof(destination));
        lookup.destination[3] = 44u;
        for (flow = 1u; flow <= 128u; ++flow) {
            lookup.source[3] = (uint8_t)flow;
            assert(edge_linux_route_lookup(&lookup, &lookup_result) == 0);
            assert(lookup_result.output_ifindex == 2);
            if (memcmp(lookup_result.gateway, first_gateway,
                       sizeof(first_gateway)) == 0)
                ++first_selected;
            else {
                assert(memcmp(lookup_result.gateway, second_gateway,
                              sizeof(second_gateway)) == 0);
                ++second_selected;
            }
        }
        assert(first_selected > 0u);
        assert(second_selected > first_selected);

        route_length = append_nexthop_object(
            route_request, 105u, 11u, 0, NULL);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) ==
               -EDGE_LINUX_EBUSY);
        route_length = append_route_nexthop_id(
            route_request, 25u, destination, 24u, 254u, 20u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        route_length = append_nexthop_object(
            route_request, 105u, 20u, 0, NULL);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        route_length = append_nexthop_object(
            route_request, 105u, 11u, 0, NULL);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
        route_length = append_nexthop_object(
            route_request, 105u, 12u, 0, NULL);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length, &route_handled) == 0);
    }
    {
        edge_net_device_configuration_t device;
        edge_net_packet_segment_t segments[2];
        edge_net_packet_metadata_t metadata;
        edge_net_packet_t packet;
        uint8_t frame[64];
        uint8_t header_copy[20];

        edge_net_core_reset();
        assert(edge_net_namespace_ensure(57u) == EDGE_NET_OK);
        assert(edge_net_namespace_ensure(58u) == EDGE_NET_OK);
        memset(&device, 0, sizeof(device));
        device.ifindex = 200;
        device.network_namespace = 57u;
        device.kind = EDGE_NET_DEVICE_PHYSICAL;
        device.flags = EDGE_NET_DEVICE_FLAG_UP |
            EDGE_NET_DEVICE_FLAG_RUNNING;
        device.mtu = 1500u;
        device.carrier = 1u;
        device.transmit = count_transmitted_packet;
        memcpy(device.name, "edge-drop0", sizeof("edge-drop0"));
        assert(edge_net_device_register(&device) == EDGE_NET_OK);
        device.ifindex = 201;
        device.network_namespace = 58u;
        memcpy(device.name, "edge-pass0", sizeof("edge-pass0"));
        assert(edge_net_device_register(&device) == EDGE_NET_OK);
        assert(edge_linux_netfilter_enable_datapath() == 0);
        assert(edge_linux_netfilter_enable_datapath() == 0);

        memset(&request, 0, sizeof(request));
        request.header.length = sizeof(request);
        request.header.type = (10u << 8u) | 16u;
        assert(edge_linux_netfilter_respond_in_namespace(
            57u, 492u, &request, sizeof(request), response,
            sizeof(response), &response_length) == 0);
        memcpy(&generation,
               response + sizeof(reply) + sizeof(test_nfgenmsg_t) +
                   sizeof(attribute),
               sizeof(generation));
        generation = host_to_be32(generation);
        memset(batch, 0, sizeof(batch));
        batch_length = append_batch_begin(batch, 0u, generation);
        batch_length = append_table(
            batch, batch_length, 0u, 1u,
            "packet_filter", 120u);
        batch_length = append_base_chain(
            batch, batch_length, "packet_filter", "output",
            3u, 0, 1u, 121u);
        batch_length = append_verdict_rule(
            batch, batch_length, "packet_filter", "output",
            0u, 122u);
        batch_length = append_batch_end(batch, batch_length);
        assert(edge_linux_netfilter_respond_in_namespace(
            57u, 492u, batch, batch_length, response,
            sizeof(response), &response_length) == 0);

        memset(frame, 0, sizeof(frame));
        memset(frame, 0xff, 6u);
        frame[12] = 0x08u;
        frame[13] = 0x00u;
        frame[14] = 0x45u;
        frame[23] = TEST_IPPROTO_UDP;
        frame[26] = 192u;
        frame[27] = 0u;
        frame[28] = 2u;
        frame[29] = 10u;
        frame[30] = 198u;
        frame[31] = 51u;
        frame[32] = 100u;
        frame[33] = 20u;
        frame[34] = 0x9cu;
        frame[35] = 0x40u;
        frame[36] = 0x00u;
        frame[37] = 0x35u;
        segments[0].data = frame;
        segments[0].length = 10u;
        segments[1].data = frame + 10u;
        segments[1].length = sizeof(frame) - 10u;
        memset(&metadata, 0, sizeof(metadata));
        assert(edge_net_packet_initialize(
            &packet, segments, 2u, &metadata, NULL, NULL) == EDGE_NET_OK);
        assert(edge_net_packet_read(
            &packet, 10u, header_copy, sizeof(header_copy)) == EDGE_NET_OK);
        assert(memcmp(header_copy, frame + 10u, sizeof(header_copy)) == 0);
        transmitted_packets = 0u;
        assert(edge_net_device_transmit(200, &packet) == EDGE_NET_OK);
        assert(transmitted_packets == 0u);
        assert(edge_net_device_transmit(201, &packet) == EDGE_NET_OK);
        assert(transmitted_packets == 1u);

        memset(&request, 0, sizeof(request));
        request.header.length = sizeof(request);
        request.header.type = (10u << 8u) | 16u;
        assert(edge_linux_netfilter_respond_in_namespace(
            57u, 492u, &request, sizeof(request), response,
            sizeof(response), &response_length) == 0);
        memcpy(&generation,
               response + sizeof(reply) + sizeof(test_nfgenmsg_t) +
                   sizeof(attribute),
               sizeof(generation));
        generation = host_to_be32(generation);
        memset(batch, 0, sizeof(batch));
        batch_length = append_batch_begin(batch, 0u, generation);
        batch_length = append_table(
            batch, batch_length, 2u, 1u,
            "packet_filter", 123u);
        batch_length = append_batch_end(batch, batch_length);
        assert(edge_linux_netfilter_respond_in_namespace(
            57u, 492u, batch, batch_length, response,
            sizeof(response), &response_length) == 0);
        assert(edge_net_device_transmit(200, &packet) == EDGE_NET_OK);
        assert(transmitted_packets == 2u);
        edge_net_packet_release(&packet);
    }
    {
        edge_net_device_snapshot_t host_snapshot;
        edge_net_device_snapshot_t peer_snapshot;
        test_nlmsghdr_t route_header;
        test_rtmsg_t route_entry;
        static const uint8_t route_destination[16] = {
            0xfdu, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0x37u, 0, 0
        };
        int32_t host_ifindex;
        int32_t peer_ifindex;

        route_length = append_veth_link(
            route_request, 16u, 0, "netns-host", "netns-peer");
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_device_find(
                   0u, "netns-host", &host_ifindex) == EDGE_NET_OK);
        assert(edge_net_device_find(
                   0u, "netns-peer", &peer_ifindex) == EDGE_NET_OK);

        route_length = append_link_namespace(
            route_request, peer_ifindex, 99u);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   0u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);
        assert(edge_net_device_snapshot(
                   host_ifindex, &host_snapshot) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(
                   peer_ifindex, &peer_snapshot) == EDGE_NET_OK);
        assert(host_snapshot.configuration.network_namespace == 0u);
        assert(peer_snapshot.configuration.network_namespace == 37u);

        {
            edge_linux_route_query_t lookup;
            edge_linux_route_result_t lookup_result;
            uint32_t address;
            uint32_t gateway;
            static const uint8_t address_bytes[4] = {10u, 77u, 0u, 2u};
            static const uint8_t gateway_bytes[4] = {10u, 77u, 0u, 1u};
            static const uint8_t connected_bytes[4] = {10u, 77u, 0u, 9u};
            static const uint8_t external_bytes[4] = {203u, 0u, 113u, 9u};

            memcpy(&address, address_bytes, sizeof(address));
            memcpy(&gateway, gateway_bytes, sizeof(gateway));
            assert(edge_linux_network_interface_configure_ipv4(
                       37u, peer_ifindex, address, 24u, gateway) == 0);
            memset(&lookup, 0, sizeof(lookup));
            lookup.network_namespace = 37u;
            lookup.family = TEST_AF_INET;
            memcpy(lookup.destination, connected_bytes,
                   sizeof(connected_bytes));
            assert(edge_linux_route_lookup(
                       &lookup, &lookup_result) == 0);
            assert(lookup_result.output_ifindex == peer_ifindex);
            assert(lookup_result.prefix_length == 24u);
            assert(memcmp(lookup_result.preferred_source, address_bytes,
                          sizeof(address_bytes)) == 0);
            memset(&lookup, 0, sizeof(lookup));
            lookup.network_namespace = 37u;
            lookup.family = TEST_AF_INET;
            memcpy(lookup.destination, external_bytes,
                   sizeof(external_bytes));
            assert(edge_linux_route_lookup(
                       &lookup, &lookup_result) == 0);
            assert(lookup_result.output_ifindex == peer_ifindex);
            assert(lookup_result.prefix_length == 0u);
            assert(memcmp(lookup_result.gateway, gateway_bytes,
                          sizeof(gateway_bytes)) == 0);
        }

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&route_entry, 0, sizeof(route_entry));
        route_header.type = 24u;
        route_header.flags = 0x405u;
        route_entry.family = TEST_AF_INET6;
        route_entry.destination_length = 64u;
        route_entry.table = 254u;
        route_entry.type = 1u;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &route_entry,
               sizeof(route_entry));
        route_offset = sizeof(route_header) + sizeof(route_entry);
        route_offset = put_attribute(
            route_request, route_offset, 1u,
            route_destination, sizeof(route_destination));
        route_offset = put_attribute(
            route_request, route_offset, 4u,
            &peer_ifindex, sizeof(peer_ifindex));
        route_length = finish_message(route_request, 0, route_offset);
        route_handled = 0;
        assert(edge_linux_rtnetlink_apply(
                   37u, route_request, route_length,
                   &route_handled) == 0);
        assert(route_handled == 1);

        observed_ipv6_interface_removals = 0u;
        edge_linux_network_namespace_destroy(37u);
        assert(observed_ipv6_interface_removals >= 2u);
        assert(edge_net_device_snapshot(
                   host_ifindex, &host_snapshot) == EDGE_NET_NOT_FOUND);
        assert(edge_net_device_snapshot(
                   peer_ifindex, &peer_snapshot) == EDGE_NET_NOT_FOUND);

        memset(route_request, 0, sizeof(route_request));
        memset(&route_header, 0, sizeof(route_header));
        memset(&route_entry, 0, sizeof(route_entry));
        route_header.type = 26u;
        route_entry.family = TEST_AF_INET6;
        route_entry.destination_length = 64u;
        memcpy(route_request, &route_header, sizeof(route_header));
        memcpy(route_request + sizeof(route_header), &route_entry,
               sizeof(route_entry));
        route_offset = sizeof(route_header) + sizeof(route_entry);
        route_offset = put_attribute(
            route_request, route_offset, 1u,
            route_destination, sizeof(route_destination));
        route_length = finish_message(route_request, 0, route_offset);
        route_offset = 0u;
        route_matches = 0u;
        assert(edge_linux_rtnetlink_append_route(
                   37u, 492u, route_request, route_length,
                   response, sizeof(response), &route_offset,
                   &route_matches) == 0);
        assert(route_matches == 0u);
    }
    {
        test_tun_ifreq_t interface_request;
        edge_net_device_snapshot_t device;
        edge_net_packet_segment_t segment;
        edge_net_packet_metadata_t metadata;
        edge_net_packet_t packet;
        uint8_t ipv4_packet[32];
        uint8_t readback[64];
        uint32_t removals_before_close;
        int32_t ifindex;
        int64_t transferred;

        edge_linux_tun_reset();
        edge_net_core_reset();
        assert(edge_linux_tun_open(7001u) == 0);
        memset(&interface_request, 0, sizeof(interface_request));
        memcpy(interface_request.name, "edge-tun%d", 11u);
        interface_request.flags =
            EDGE_LINUX_IFF_TUN | EDGE_LINUX_IFF_NO_PI;
        assert(edge_linux_tun_ioctl(
                   7001u, 71u, EDGE_LINUX_TUNSETIFF,
                   (uint64_t)(uintptr_t)&interface_request,
                   tun_copy_from_user, tun_copy_to_user, 0) == 0);
        assert(edge_net_device_find(
                   71u, interface_request.name, &ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(ifindex, &device) == EDGE_NET_OK);
        assert(device.configuration.kind == EDGE_NET_DEVICE_TUN);
        assert(edge_net_device_set_link(
                   ifindex,
                   EDGE_NET_DEVICE_FLAG_UP | EDGE_NET_DEVICE_FLAG_RUNNING,
                   EDGE_NET_DEVICE_FLAG_UP | EDGE_NET_DEVICE_FLAG_RUNNING,
                   0u, 0) == EDGE_NET_OK);

        memset(ipv4_packet, 0, sizeof(ipv4_packet));
        ipv4_packet[0] = 0x45u;
        ipv4_packet[2] = 0u;
        ipv4_packet[3] = sizeof(ipv4_packet);
        ipv4_packet[8] = 64u;
        ipv4_packet[9] = 1u;
        segment.data = ipv4_packet;
        segment.length = sizeof(ipv4_packet);
        memset(&metadata, 0, sizeof(metadata));
        metadata.network_namespace = 71u;
        metadata.output_ifindex = ifindex;
        metadata.protocol = 0x0800u;
        assert(edge_net_packet_initialize(
                   &packet, &segment, 1u, &metadata, 0, 0) == EDGE_NET_OK);
        assert(edge_net_device_transmit(ifindex, &packet) == EDGE_NET_OK);
        assert(edge_linux_tun_read_ready(7001u));
        transferred = edge_linux_tun_read(
            7001u, (uint64_t)(uintptr_t)readback, sizeof(readback),
            tun_copy_to_user, 0);
        assert(transferred == (int64_t)sizeof(ipv4_packet));
        assert(memcmp(readback, ipv4_packet, sizeof(ipv4_packet)) == 0);
        assert(!edge_linux_tun_read_ready(7001u));

        tun_received_packets = 0u;
        tun_received_length = 0u;
        assert(edge_net_device_set_receive_callback(
                   ifindex, receive_tun_packet,
                   &tun_received_packets) == EDGE_NET_OK);
        transferred = edge_linux_tun_write(
            7001u, (uint64_t)(uintptr_t)ipv4_packet,
            sizeof(ipv4_packet), tun_copy_from_user, 0);
        assert(transferred == (int64_t)sizeof(ipv4_packet));
        assert(tun_received_packets == 1u);
        assert(tun_received_length == sizeof(ipv4_packet));
        assert(memcmp(tun_received_payload, ipv4_packet,
                      sizeof(ipv4_packet)) == 0);
        removals_before_close = observed_ipv6_interface_removals;
        edge_linux_tun_close(7001u);
        assert(observed_ipv6_interface_removals ==
               removals_before_close + 1u);
        assert(edge_net_device_snapshot(ifindex, &device) ==
               EDGE_NET_NOT_FOUND);

        assert(edge_linux_tun_open(7002u) == 0);
        memset(&interface_request, 0, sizeof(interface_request));
        memcpy(interface_request.name, "edge-tap%d", 11u);
        interface_request.flags =
            EDGE_LINUX_IFF_TAP | EDGE_LINUX_IFF_NO_PI;
        assert(edge_linux_tun_ioctl(
                   7002u, 71u, EDGE_LINUX_TUNSETIFF,
                   (uint64_t)(uintptr_t)&interface_request,
                   tun_copy_from_user, tun_copy_to_user, 0) == 0);
        assert(edge_net_device_find(
                   71u, interface_request.name, &ifindex) == EDGE_NET_OK);
        assert(edge_net_device_snapshot(ifindex, &device) == EDGE_NET_OK);
        assert(device.configuration.kind == EDGE_NET_DEVICE_TAP);
        edge_linux_tun_close(7002u);

        {
            test_tun_ifreq_t first_queue;
            test_tun_ifreq_t second_queue;
            test_tun_ifreq_t queue_request;
            uint32_t requested_ifindex = 77u;
            uint32_t carrier = 0u;
            uint32_t features = 0u;

            assert(edge_linux_tun_open(7003u) == 0);
            assert(edge_linux_tun_open(7004u) == 0);
            assert(edge_linux_tun_ioctl(
                       7003u, 71u, EDGE_LINUX_TUNGETFEATURES,
                       (uint64_t)(uintptr_t)&features,
                       tun_copy_from_user, tun_copy_to_user, 0) == 0);
            assert(features & EDGE_LINUX_IFF_MULTI_QUEUE);
            assert(features & EDGE_LINUX_IFF_NO_CARRIER);
            assert(edge_linux_tun_ioctl(
                       7003u, 71u, EDGE_LINUX_TUNSETIFINDEX,
                       (uint64_t)(uintptr_t)&requested_ifindex,
                       tun_copy_from_user, tun_copy_to_user, 0) == 0);
            memset(&first_queue, 0, sizeof(first_queue));
            memcpy(first_queue.name, "edge-mq0", sizeof("edge-mq0"));
            first_queue.flags = EDGE_LINUX_IFF_TAP |
                EDGE_LINUX_IFF_NO_PI | EDGE_LINUX_IFF_MULTI_QUEUE |
                EDGE_LINUX_IFF_NO_CARRIER;
            assert(edge_linux_tun_ioctl(
                       7003u, 71u, EDGE_LINUX_TUNSETIFF,
                       (uint64_t)(uintptr_t)&first_queue,
                       tun_copy_from_user, tun_copy_to_user, 0) == 0);
            assert(edge_net_device_find(
                       71u, first_queue.name, &ifindex) == EDGE_NET_OK);
            assert(ifindex == (int32_t)requested_ifindex);
            assert(edge_net_device_snapshot(ifindex, &device) == EDGE_NET_OK);
            assert(device.configuration.carrier == 0u);

            memset(&second_queue, 0, sizeof(second_queue));
            memcpy(second_queue.name, "edge-mq0", sizeof("edge-mq0"));
            second_queue.flags = EDGE_LINUX_IFF_TAP |
                EDGE_LINUX_IFF_NO_PI | EDGE_LINUX_IFF_MULTI_QUEUE;
            assert(edge_linux_tun_ioctl(
                       7004u, 71u, EDGE_LINUX_TUNSETIFF,
                       (uint64_t)(uintptr_t)&second_queue,
                       tun_copy_from_user, tun_copy_to_user, 0) == 0);
            carrier = 1u;
            assert(edge_linux_tun_ioctl(
                       7004u, 71u, EDGE_LINUX_TUNSETCARRIER,
                       (uint64_t)(uintptr_t)&carrier,
                       tun_copy_from_user, tun_copy_to_user, 0) == 0);
            assert(edge_net_device_snapshot(ifindex, &device) == EDGE_NET_OK);
            assert(device.configuration.carrier == 1u);
            assert(edge_net_device_set_link(
                       ifindex,
                       EDGE_NET_DEVICE_FLAG_UP |
                           EDGE_NET_DEVICE_FLAG_RUNNING,
                       EDGE_NET_DEVICE_FLAG_UP |
                           EDGE_NET_DEVICE_FLAG_RUNNING,
                       0u, 0) == EDGE_NET_OK);

            memset(ipv4_packet, 0, sizeof(ipv4_packet));
            memset(ipv4_packet, 0xff, 6u);
            ipv4_packet[12] = 0x08u;
            ipv4_packet[13] = 0x00u;
            segment.data = ipv4_packet;
            segment.length = sizeof(ipv4_packet);
            memset(&metadata, 0, sizeof(metadata));
            metadata.network_namespace = 71u;
            metadata.output_ifindex = ifindex;
            metadata.protocol = 0x0800u;
            assert(edge_net_packet_initialize(
                       &packet, &segment, 1u, &metadata, 0, 0) == EDGE_NET_OK);
            assert(edge_net_device_transmit(ifindex, &packet) == EDGE_NET_OK);
            assert(edge_net_device_transmit(ifindex, &packet) == EDGE_NET_OK);
            assert(edge_linux_tun_read_ready(7003u));
            assert(edge_linux_tun_read_ready(7004u));
            assert(edge_linux_tun_read(
                       7003u, (uint64_t)(uintptr_t)readback,
                       sizeof(readback), tun_copy_to_user, 0) ==
                   (int64_t)sizeof(ipv4_packet));
            assert(edge_linux_tun_read(
                       7004u, (uint64_t)(uintptr_t)readback,
                       sizeof(readback), tun_copy_to_user, 0) ==
                   (int64_t)sizeof(ipv4_packet));

            memset(&queue_request, 0, sizeof(queue_request));
            queue_request.flags = EDGE_LINUX_IFF_DETACH_QUEUE;
            assert(edge_linux_tun_ioctl(
                       7003u, 71u, EDGE_LINUX_TUNSETQUEUE,
                       (uint64_t)(uintptr_t)&queue_request,
                       tun_copy_from_user, tun_copy_to_user, 0) == 0);
            assert(!edge_linux_tun_write_ready(7003u));
            assert(edge_net_device_transmit(ifindex, &packet) == EDGE_NET_OK);
            assert(!edge_linux_tun_read_ready(7003u));
            assert(edge_linux_tun_read_ready(7004u));
            assert(edge_linux_tun_read(
                       7004u, (uint64_t)(uintptr_t)readback,
                       sizeof(readback), tun_copy_to_user, 0) ==
                   (int64_t)sizeof(ipv4_packet));
            queue_request.flags = EDGE_LINUX_IFF_ATTACH_QUEUE;
            assert(edge_linux_tun_ioctl(
                       7003u, 71u, EDGE_LINUX_TUNSETQUEUE,
                       (uint64_t)(uintptr_t)&queue_request,
                       tun_copy_from_user, tun_copy_to_user, 0) == 0);
            assert(edge_linux_tun_write_ready(7003u));

            edge_linux_tun_close(7003u);
            assert(edge_net_device_snapshot(ifindex, &device) == EDGE_NET_OK);
            edge_linux_tun_close(7004u);
            assert(edge_net_device_snapshot(ifindex, &device) ==
                   EDGE_NET_NOT_FOUND);
        }
        edge_linux_tun_reset();
    }
    edge_linux_rtnetlink_set_ipv4_provider(NULL);
    edge_linux_rtnetlink_set_ipv6_provider(NULL);

    puts("linux_netlink_netfilter_unit: PASS");
    return 0;
}
