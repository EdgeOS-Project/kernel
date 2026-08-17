/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_ethtool.h"
#include "kernel/linux_genetlink.h"

#define NLMSG_DONE 3u
#define NLM_F_REQUEST 1u
#define NLM_F_MULTI 2u
#define NLM_F_DUMP 0x300u
#define CTRL_CMD_NEWFAMILY 1u
#define CTRL_CMD_GETFAMILY 3u
#define CTRL_ATTR_FAMILY_ID 1u
#define CTRL_ATTR_FAMILY_NAME 2u
#define CTRL_ATTR_VERSION 3u
#define CTRL_ATTR_HDRSIZE 4u
#define CTRL_ATTR_MAXATTR 5u
#define CTRL_ATTR_OPS 6u

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

static uint32_t make_request(
    uint8_t *buffer, uint16_t flags, uint16_t attribute_type,
    const void *payload, uint16_t payload_length) {
    nlmsghdr_t header;
    genlmsghdr_t generic;
    nlattr_t attribute;
    uint32_t offset = sizeof(header) + sizeof(generic);

    memset(buffer, 0, 128u);
    memset(&header, 0, sizeof(header));
    header.type = EDGE_LINUX_GENL_ID_CTRL;
    header.flags = flags;
    header.sequence = 0x12345678u;
    memset(&generic, 0, sizeof(generic));
    generic.command = CTRL_CMD_GETFAMILY;
    generic.version = EDGE_LINUX_GENL_CTRL_VERSION;
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &generic, sizeof(generic));
    if (attribute_type != 0u) {
        attribute.length = (uint16_t)(sizeof(attribute) + payload_length);
        attribute.type = attribute_type;
        memcpy(buffer + offset, &attribute, sizeof(attribute));
        memcpy(buffer + offset + sizeof(attribute), payload, payload_length);
        offset += align4(attribute.length);
    }
    header.length = offset;
    memcpy(buffer, &header, sizeof(header));
    return offset;
}

static void validate_family(const uint8_t *response, uint32_t length,
                            uint16_t expected_flags, uint16_t expected_id,
                            const char *expected_name,
                            uint32_t expected_version,
                            uint32_t expected_maxattr) {
    nlmsghdr_t header;
    genlmsghdr_t generic;
    uint32_t offset;
    unsigned seen = 0u;

    assert(length >= sizeof(header) + sizeof(generic));
    memcpy(&header, response, sizeof(header));
    assert(header.length <= length);
    assert(header.type == EDGE_LINUX_GENL_ID_CTRL);
    assert(header.flags == expected_flags);
    assert(header.sequence == 0x12345678u);
    assert(header.port_id == 7123u);
    memcpy(&generic, response + sizeof(header), sizeof(generic));
    assert(generic.command == CTRL_CMD_NEWFAMILY);
    assert(generic.version == EDGE_LINUX_GENL_CTRL_VERSION);

    offset = sizeof(header) + sizeof(generic);
    while (offset < header.length) {
        nlattr_t attribute;
        const uint8_t *payload;
        memcpy(&attribute, response + offset, sizeof(attribute));
        assert(attribute.length >= sizeof(attribute));
        assert(offset + attribute.length <= header.length);
        payload = response + offset + sizeof(attribute);
        switch (attribute.type & 0x3fffu) {
        case CTRL_ATTR_FAMILY_ID: {
            uint16_t value;
            memcpy(&value, payload, sizeof(value));
            assert(value == expected_id);
            seen |= 1u << 0;
            break;
        }
        case CTRL_ATTR_FAMILY_NAME:
            assert(strcmp((const char *)payload, expected_name) == 0);
            seen |= 1u << 1;
            break;
        case CTRL_ATTR_VERSION: {
            uint32_t value;
            memcpy(&value, payload, sizeof(value));
            assert(value == expected_version);
            seen |= 1u << 2;
            break;
        }
        case CTRL_ATTR_HDRSIZE: {
            uint32_t value;
            memcpy(&value, payload, sizeof(value));
            assert(value == 0u);
            seen |= 1u << 3;
            break;
        }
        case CTRL_ATTR_MAXATTR: {
            uint32_t value;
            memcpy(&value, payload, sizeof(value));
            assert(value == expected_maxattr);
            seen |= 1u << 4;
            break;
        }
        case CTRL_ATTR_OPS:
            assert((attribute.type & 0x8000u) != 0u);
            seen |= 1u << 5;
            break;
        default:
            assert(0);
        }
        offset += align4(attribute.length);
    }
    assert(seen == 0x3fu);
}

int main(void) {
    uint8_t request[128];
    uint8_t response[512];
    uint32_t request_length;
    uint32_t response_length = 0;
    static const char controller_name[] = "nlctrl";
    static const char ethtool_name[] = "ethtool";
    static const char unknown_name[] = "not-a-family";
    uint16_t controller_id = EDGE_LINUX_GENL_ID_CTRL;
    nlmsghdr_t done;

    request_length = make_request(
        request, NLM_F_REQUEST, CTRL_ATTR_FAMILY_NAME,
        controller_name, sizeof(controller_name));
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, request_length, response, sizeof(response),
               &response_length) == 0);
    validate_family(
        response, response_length, 0u, EDGE_LINUX_GENL_ID_CTRL,
        controller_name, EDGE_LINUX_GENL_CTRL_VERSION, 10u);

    request_length = make_request(
        request, NLM_F_REQUEST, CTRL_ATTR_FAMILY_ID,
        &controller_id, sizeof(controller_id));
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, request_length, response, sizeof(response),
               &response_length) == 0);
    validate_family(
        response, response_length, 0u, EDGE_LINUX_GENL_ID_CTRL,
        controller_name, EDGE_LINUX_GENL_CTRL_VERSION, 10u);

    request_length = make_request(
        request, NLM_F_REQUEST, CTRL_ATTR_FAMILY_NAME,
        ethtool_name, sizeof(ethtool_name));
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, request_length, response, sizeof(response),
               &response_length) == 0);
    validate_family(
        response, response_length, 0u, EDGE_LINUX_GENL_ID_ETHTOOL,
        ethtool_name, EDGE_LINUX_GENL_ETHTOOL_VERSION, 0u);

    request_length = make_request(
        request, NLM_F_REQUEST | NLM_F_DUMP, 0u, 0, 0u);
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, request_length, response, sizeof(response),
               &response_length) == 0);
    validate_family(
        response, response_length, NLM_F_MULTI, EDGE_LINUX_GENL_ID_CTRL,
        controller_name, EDGE_LINUX_GENL_CTRL_VERSION, 10u);
    {
        uint32_t second_offset = ((const nlmsghdr_t *)response)->length;
        const nlmsghdr_t *second =
            (const nlmsghdr_t *)(response + second_offset);
        validate_family(
            response + second_offset, response_length - second_offset,
            NLM_F_MULTI, EDGE_LINUX_GENL_ID_ETHTOOL,
            ethtool_name, EDGE_LINUX_GENL_ETHTOOL_VERSION, 0u);
        memcpy(&done, response + second_offset + second->length,
               sizeof(done));
    }
    assert(done.type == NLMSG_DONE);
    assert(done.flags == NLM_F_MULTI);
    assert(done.sequence == 0x12345678u);

    request_length = make_request(
        request, NLM_F_REQUEST, CTRL_ATTR_FAMILY_NAME,
        unknown_name, sizeof(unknown_name));
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, request_length, response, sizeof(response),
               &response_length) == -EDGE_LINUX_ENOENT);

    request_length = make_request(request, NLM_F_REQUEST, 0u, 0, 0u);
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, request_length, response, sizeof(response),
               &response_length) == -EDGE_LINUX_EINVAL);
    ((nlattr_t *)(request + sizeof(nlmsghdr_t) + sizeof(genlmsghdr_t)))->length =
        3u;
    ((nlmsghdr_t *)request)->length += sizeof(nlattr_t);
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, ((nlmsghdr_t *)request)->length,
               response, sizeof(response), &response_length) ==
           -EDGE_LINUX_EINVAL);
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, sizeof(nlmsghdr_t), response,
               sizeof(response), &response_length) == -EDGE_LINUX_EINVAL);
    request_length = make_request(
        request, NLM_F_REQUEST, CTRL_ATTR_FAMILY_NAME,
        controller_name, sizeof(controller_name));
    assert(edge_linux_genetlink_respond(
               0u, 7123u, request, request_length, response, 8u,
               &response_length) == -EDGE_LINUX_ENOBUFS);

    puts("linux_genetlink_unit: PASS");
    return 0;
}
