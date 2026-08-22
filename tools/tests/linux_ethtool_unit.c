/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_ethtool.h"
#include "net/network_core.h"

#define NLM_F_REQUEST 1u
#define NLM_F_MULTI 2u
#define NLM_F_DUMP 0x300u
#define NLMSG_DONE 3u
#define NLA_F_NESTED 0x8000u

typedef struct nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} nlmsghdr_t;

typedef struct genlmsghdr {
    uint8_t command;
    uint8_t version;
    uint16_t reserved;
} genlmsghdr_t;

typedef struct nlattr {
    uint16_t length;
    uint16_t type;
} nlattr_t;

static uint32_t align4(uint32_t value) {
    return (value + 3u) & ~3u;
}

static uint32_t append_attribute(
    uint8_t *buffer, uint32_t offset, uint16_t type,
    const void *payload, uint16_t payload_length) {
    nlattr_t attribute;
    uint32_t length = sizeof(attribute) + payload_length;
    uint32_t padded = align4(length);

    attribute.length = (uint16_t)length;
    attribute.type = type;
    memcpy(buffer + offset, &attribute, sizeof(attribute));
    if (payload_length)
        memcpy(buffer + offset + sizeof(attribute), payload, payload_length);
    if (padded > length) memset(buffer + offset + length, 0, padded - length);
    return offset + padded;
}

static uint32_t make_request(
    uint8_t *buffer, uint8_t command, uint16_t flags,
    const char *name, int32_t ifindex) {
    nlmsghdr_t header;
    genlmsghdr_t generic;
    nlattr_t nested;
    uint32_t nested_offset;
    uint32_t offset = sizeof(header) + sizeof(generic);

    memset(buffer, 0, 128u);
    memset(&header, 0, sizeof(header));
    header.type = EDGE_LINUX_GENL_ID_ETHTOOL;
    header.flags = flags;
    header.sequence = 991u;
    generic.command = command;
    generic.version = EDGE_LINUX_GENL_ETHTOOL_VERSION;
    generic.reserved = 0u;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &generic, sizeof(generic));
    nested_offset = offset;
    memset(&nested, 0, sizeof(nested));
    memcpy(buffer + offset, &nested, sizeof(nested));
    offset += sizeof(nested);
    if (name)
        offset = append_attribute(
            buffer, offset, 2u, name, (uint16_t)(strlen(name) + 1u));
    if (ifindex > 0)
        offset = append_attribute(
            buffer, offset, 1u, &ifindex, sizeof(ifindex));
    nested.length = (uint16_t)(offset - nested_offset);
    nested.type = (uint16_t)(1u | NLA_F_NESTED);
    memcpy(buffer + nested_offset, &nested, sizeof(nested));
    header.length = offset;
    memcpy(buffer, &header, sizeof(header));
    return offset;
}

static uint32_t make_stats_request(
    uint8_t *buffer, const char *name, uint32_t groups) {
    nlmsghdr_t header;
    genlmsghdr_t generic;
    nlattr_t nested;
    uint32_t nested_offset;
    uint32_t size = 5u;
    uint32_t offset = sizeof(header) + sizeof(generic);

    memset(buffer, 0, 128u);
    memset(&header, 0, sizeof(header));
    header.type = EDGE_LINUX_GENL_ID_ETHTOOL;
    header.flags = NLM_F_REQUEST;
    header.sequence = 991u;
    generic.command = EDGE_LINUX_ETHTOOL_MSG_STATS_GET;
    generic.version = EDGE_LINUX_GENL_ETHTOOL_VERSION;
    generic.reserved = 0u;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &generic, sizeof(generic));

    nested_offset = offset;
    memset(&nested, 0, sizeof(nested));
    memcpy(buffer + offset, &nested, sizeof(nested));
    offset += sizeof(nested);
    offset = append_attribute(
        buffer, offset, 2u, name, (uint16_t)(strlen(name) + 1u));
    nested.length = (uint16_t)(offset - nested_offset);
    nested.type = (uint16_t)(2u | NLA_F_NESTED);
    memcpy(buffer + nested_offset, &nested, sizeof(nested));

    nested_offset = offset;
    memset(&nested, 0, sizeof(nested));
    memcpy(buffer + offset, &nested, sizeof(nested));
    offset += sizeof(nested);
    offset = append_attribute(buffer, offset, 1u, 0, 0u);
    offset = append_attribute(buffer, offset, 2u, &size, sizeof(size));
    offset = append_attribute(buffer, offset, 4u, &groups, sizeof(groups));
    nested.length = (uint16_t)(offset - nested_offset);
    nested.type = (uint16_t)(3u | NLA_F_NESTED);
    memcpy(buffer + nested_offset, &nested, sizeof(nested));

    header.length = offset;
    memcpy(buffer, &header, sizeof(header));
    return offset;
}

static uint32_t make_stats_verbose_request(
    uint8_t *buffer, const char *device_name, const char *group_name) {
    nlmsghdr_t header;
    genlmsghdr_t generic;
    nlattr_t stats_header;
    nlattr_t stats_groups;
    nlattr_t bits;
    nlattr_t bit;
    uint32_t stats_header_offset;
    uint32_t stats_groups_offset;
    uint32_t bits_offset;
    uint32_t bit_offset;
    uint32_t offset = sizeof(header) + sizeof(generic);

    memset(buffer, 0, 128u);
    memset(&header, 0, sizeof(header));
    header.type = EDGE_LINUX_GENL_ID_ETHTOOL;
    header.flags = NLM_F_REQUEST;
    header.sequence = 991u;
    generic.command = EDGE_LINUX_ETHTOOL_MSG_STATS_GET;
    generic.version = EDGE_LINUX_GENL_ETHTOOL_VERSION;
    generic.reserved = 0u;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &generic, sizeof(generic));
    stats_header_offset = offset;
    memset(&stats_header, 0, sizeof(stats_header));
    memcpy(buffer + offset, &stats_header, sizeof(stats_header));
    offset += sizeof(stats_header);
    offset = append_attribute(
        buffer, offset,
        2u, device_name, (uint16_t)(strlen(device_name) + 1u));
    stats_header.length = (uint16_t)(offset - stats_header_offset);
    stats_header.type = (uint16_t)(2u | NLA_F_NESTED);
    memcpy(buffer + stats_header_offset, &stats_header, sizeof(stats_header));

    stats_groups_offset = offset;
    memset(&stats_groups, 0, sizeof(stats_groups));
    memcpy(buffer + offset, &stats_groups, sizeof(stats_groups));
    offset += sizeof(stats_groups);
    offset = append_attribute(buffer, offset, 1u, 0, 0u);
    bits_offset = offset;
    memset(&bits, 0, sizeof(bits));
    memcpy(buffer + offset, &bits, sizeof(bits));
    offset += sizeof(bits);
    bit_offset = offset;
    memset(&bit, 0, sizeof(bit));
    memcpy(buffer + offset, &bit, sizeof(bit));
    offset += sizeof(bit);
    offset = append_attribute(
        buffer, offset, 2u, group_name,
        (uint16_t)(strlen(group_name) + 1u));
    bit.length = (uint16_t)(offset - bit_offset);
    bit.type = (uint16_t)(1u | NLA_F_NESTED);
    memcpy(buffer + bit_offset, &bit, sizeof(bit));
    bits.length = (uint16_t)(offset - bits_offset);
    bits.type = (uint16_t)(3u | NLA_F_NESTED);
    memcpy(buffer + bits_offset, &bits, sizeof(bits));
    stats_groups.length = (uint16_t)(offset - stats_groups_offset);
    stats_groups.type = (uint16_t)(3u | NLA_F_NESTED);
    memcpy(buffer + stats_groups_offset, &stats_groups, sizeof(stats_groups));

    header.length = offset;
    memcpy(buffer, &header, sizeof(header));
    return offset;
}

static void validate_reply(
    const uint8_t *response, uint32_t response_length, uint8_t command,
    uint16_t flags, const char *expected_name, int32_t expected_index,
    uint8_t expected_value) {
    nlmsghdr_t header;
    genlmsghdr_t generic;
    nlattr_t outer;
    uint32_t inner_offset;
    uint32_t outer_end;
    uint32_t offset;
    int name_seen = 0;
    int index_seen = 0;
    int value_seen = 0;

    assert(response_length >= sizeof(header) + sizeof(generic));
    memcpy(&header, response, sizeof(header));
    assert(header.type == EDGE_LINUX_GENL_ID_ETHTOOL);
    assert(header.flags == flags);
    assert(header.sequence == 991u);
    assert(header.port_id == 8123u);
    memcpy(&generic, response + sizeof(header), sizeof(generic));
    assert(generic.command == command);
    offset = sizeof(header) + sizeof(generic);
    memcpy(&outer, response + offset, sizeof(outer));
    assert((outer.type & 0x3fffu) == 1u);
    assert(outer.type & NLA_F_NESTED);
    outer_end = offset + outer.length;
    inner_offset = offset + sizeof(outer);
    while (inner_offset < outer_end) {
        nlattr_t attribute;
        memcpy(&attribute, response + inner_offset, sizeof(attribute));
        if (attribute.type == 1u) {
            int32_t value;
            memcpy(&value, response + inner_offset + sizeof(attribute),
                   sizeof(value));
            assert(value == expected_index);
            index_seen = 1;
        } else if (attribute.type == 2u) {
            assert(strcmp(
                       (const char *)(response + inner_offset +
                                      sizeof(attribute)),
                       expected_name) == 0);
            name_seen = 1;
        }
        inner_offset += align4(attribute.length);
    }
    offset += align4(outer.length);
    while (offset < header.length) {
        nlattr_t attribute;
        memcpy(&attribute, response + offset, sizeof(attribute));
        if (attribute.type == 2u) {
            assert(response[offset + sizeof(attribute)] == expected_value);
            value_seen = 1;
        }
        offset += align4(attribute.length);
    }
    assert(name_seen && index_seen && value_seen);
}

static void validate_u32_reply_values(
    const uint8_t *response, uint8_t command, uint16_t first_type,
    uint32_t first_value, uint16_t second_type, uint32_t second_value) {
    nlmsghdr_t header;
    nlattr_t attribute;
    uint32_t offset;
    int first_seen = 0;
    int second_seen = 0;

    memcpy(&header, response, sizeof(header));
    offset = sizeof(header) + sizeof(genlmsghdr_t);
    memcpy(&attribute, response + offset, sizeof(attribute));
    offset += align4(attribute.length);
    while (offset < header.length) {
        uint32_t value;
        memcpy(&attribute, response + offset, sizeof(attribute));
        if (attribute.type == first_type) {
            assert(attribute.length == sizeof(attribute) + sizeof(value));
            memcpy(&value, response + offset + sizeof(attribute),
                   sizeof(value));
            assert(value == first_value);
            first_seen = 1;
        } else if (attribute.type == second_type) {
            assert(attribute.length == sizeof(attribute) + sizeof(value));
            memcpy(&value, response + offset + sizeof(attribute),
                   sizeof(value));
            assert(value == second_value);
            second_seen = 1;
        }
        offset += align4(attribute.length);
    }
    assert(command == EDGE_LINUX_ETHTOOL_MSG_CHANNELS_GET);
    assert(first_seen && second_seen);
}

static void validate_linkmodes_reply(const uint8_t *response) {
    nlmsghdr_t header;
    nlattr_t attribute;
    uint32_t offset;
    int speed_seen = 0;
    int duplex_seen = 0;

    memcpy(&header, response, sizeof(header));
    offset = sizeof(header) + sizeof(genlmsghdr_t);
    memcpy(&attribute, response + offset, sizeof(attribute));
    offset += align4(attribute.length);
    while (offset < header.length) {
        memcpy(&attribute, response + offset, sizeof(attribute));
        if (attribute.type == 5u) {
            uint32_t speed;
            memcpy(&speed, response + offset + sizeof(attribute),
                   sizeof(speed));
            assert(speed == 0xffffffffu);
            speed_seen = 1;
        } else if (attribute.type == 6u) {
            assert(response[offset + sizeof(attribute)] == 0xffu);
            duplex_seen = 1;
        }
        offset += align4(attribute.length);
    }
    assert(speed_seen && duplex_seen);
}

static void validate_stats_reply(const uint8_t *response) {
    static const uint16_t expected_types[] = { 0u, 3u, 6u, 12u };
    static const uint64_t expected_values[] = { 1u, 1u, 64u, 64u };
    nlmsghdr_t header;
    genlmsghdr_t generic;
    uint32_t offset;
    uint32_t found = 0u;
    int header_seen = 0;
    int group_seen = 0;
    int source_seen = 0;

    memcpy(&header, response, sizeof(header));
    memcpy(&generic, response + sizeof(header), sizeof(generic));
    assert(generic.command == EDGE_LINUX_ETHTOOL_MSG_STATS_GET);
    offset = sizeof(header) + sizeof(generic);
    while (offset < header.length) {
        nlattr_t attribute;
        uint16_t type;

        memcpy(&attribute, response + offset, sizeof(attribute));
        type = attribute.type & 0x3fffu;
        if (type == 2u && !header_seen) {
            header_seen = 1;
        } else if (type == 5u) {
            uint32_t source;
            memcpy(&source, response + offset + sizeof(attribute),
                   sizeof(source));
            assert(source == 0u);
            source_seen = 1;
        } else if (type == 4u) {
            uint32_t group_offset = offset + sizeof(attribute);
            uint32_t group_end = offset + attribute.length;
            uint32_t group_id = UINT32_MAX;
            uint32_t string_set = UINT32_MAX;

            while (group_offset < group_end) {
                nlattr_t group_attribute;
                uint16_t group_type;

                memcpy(&group_attribute, response + group_offset,
                       sizeof(group_attribute));
                group_type = group_attribute.type & 0x3fffu;
                if (group_type == 2u) {
                    memcpy(&group_id,
                           response + group_offset + sizeof(group_attribute),
                           sizeof(group_id));
                } else if (group_type == 3u) {
                    memcpy(&string_set,
                           response + group_offset + sizeof(group_attribute),
                           sizeof(string_set));
                } else if (group_type == 4u) {
                    nlattr_t value_attribute;
                    uint64_t value;
                    uint32_t index;

                    memcpy(&value_attribute,
                           response + group_offset + sizeof(group_attribute),
                           sizeof(value_attribute));
                    memcpy(&value,
                           response + group_offset +
                               sizeof(group_attribute) +
                               sizeof(value_attribute),
                           sizeof(value));
                    for (index = 0; index < 4u; ++index) {
                        if ((value_attribute.type & 0x3fffu) !=
                            expected_types[index])
                            continue;
                        assert(value == expected_values[index]);
                        found |= 1u << index;
                    }
                }
                group_offset += align4(group_attribute.length);
            }
            assert(group_id == 1u && string_set == 18u);
            group_seen = 1;
        }
        offset += align4(attribute.length);
    }
    assert(header_seen && source_seen && group_seen && found == 0x0fu);
}

int main(void) {
    edge_net_device_configuration_t device;
    uint8_t request[128];
    uint8_t response[1024];
    uint32_t request_length;
    uint32_t response_length = 0;
    nlmsghdr_t first;
    nlmsghdr_t done;
    edge_net_packet_t packet;
    edge_net_packet_segment_t segment;
    uint8_t frame[64];

    edge_net_core_reset();
    memset(&device, 0, sizeof(device));
    device.ifindex = 7;
    device.network_namespace = 42u;
    device.kind = EDGE_NET_DEVICE_PHYSICAL;
    device.flags = EDGE_NET_DEVICE_FLAG_UP | EDGE_NET_DEVICE_FLAG_RUNNING;
    device.mtu = 1500u;
    device.carrier = 1u;
    memcpy(device.name, "edge-test0", sizeof("edge-test0"));
    assert(edge_net_namespace_ensure(42u) == EDGE_NET_OK);
    assert(edge_net_device_register(&device) == EDGE_NET_OK);

    memset(frame, 0, sizeof(frame));
    segment.data = frame;
    segment.length = sizeof(frame);
    assert(edge_net_packet_initialize(
               &packet, &segment, 1u, 0, 0, 0) == EDGE_NET_OK);
    assert(edge_net_device_receive(7, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);
    assert(edge_net_packet_initialize(
               &packet, &segment, 1u, 0, 0, 0) == EDGE_NET_OK);
    assert(edge_net_device_transmit(7, &packet) == EDGE_NET_OK);
    edge_net_packet_release(&packet);

    request_length = make_request(
        request, EDGE_LINUX_ETHTOOL_MSG_LINKINFO_GET,
        NLM_F_REQUEST, "edge-test0", 0);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) == 0);
    validate_reply(
        response, response_length, EDGE_LINUX_ETHTOOL_MSG_LINKINFO_GET,
        0u, "edge-test0", 7, 0xffu);

    request_length = make_request(
        request, EDGE_LINUX_ETHTOOL_MSG_LINKMODES_GET,
        NLM_F_REQUEST, "edge-test0", 0);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) == 0);
    validate_linkmodes_reply(response);

    request_length = make_request(
        request, EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET,
        NLM_F_REQUEST, 0, 7);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) == 0);
    validate_reply(
        response, response_length, EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET,
        0u, "edge-test0", 7, 1u);
    assert(edge_linux_ethtool_respond(
               43u, 8123u, request, request_length,
               response, sizeof(response), &response_length) ==
           -EDGE_LINUX_ENODEV);

    request_length = make_request(
        request, EDGE_LINUX_ETHTOOL_MSG_CHANNELS_GET,
        NLM_F_REQUEST, 0, 7);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) == 0);
    validate_u32_reply_values(
        response, EDGE_LINUX_ETHTOOL_MSG_CHANNELS_GET,
        5u, 1u, 9u, 1u);

    request_length = make_stats_request(
        request, "edge-test0", 1u << 1u);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) == 0);
    validate_stats_reply(response);

    request_length = make_stats_verbose_request(
        request, "edge-test0", "eth-mac");
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) == 0);
    validate_stats_reply(response);

    request_length = make_stats_request(request, "edge-test0", 0u);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) ==
           -EDGE_LINUX_EINVAL);
    request_length = make_stats_request(
        request, "edge-test0", 1u << 5u);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) ==
           -EDGE_LINUX_EINVAL);
    request_length = make_stats_verbose_request(
        request, "edge-test0", "not-a-group");
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) ==
           -EDGE_LINUX_EOPNOTSUPP);

    request_length = make_request(
        request, EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET,
        NLM_F_REQUEST | NLM_F_DUMP, 0, 0);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) == 0);
    memcpy(&first, response, sizeof(first));
    validate_reply(
        response, response_length, EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET,
        NLM_F_MULTI, "edge-test0", 7, 1u);
    memcpy(&done, response + first.length, sizeof(done));
    assert(done.type == NLMSG_DONE && done.flags == NLM_F_MULTI);

    request_length = make_request(request, 99u, NLM_F_REQUEST, 0, 7);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, request_length,
               response, sizeof(response), &response_length) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(edge_linux_ethtool_respond(
               42u, 8123u, request, sizeof(nlmsghdr_t),
               response, sizeof(response), &response_length) ==
           -EDGE_LINUX_EINVAL);

    edge_net_core_reset();
    puts("linux_ethtool_unit: PASS");
    return 0;
}
