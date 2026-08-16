/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux Generic Netlink policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_ethtool.h"
#include "kernel/linux_genetlink.h"

#define EDGE_NLMSG_DONE 3u
#define EDGE_NLM_F_MULTI 2u
#define EDGE_NLM_F_DUMP 0x300u

#define EDGE_GENL_CTRL_CMD_NEWFAMILY 1u
#define EDGE_GENL_CTRL_CMD_GETFAMILY 3u

#define EDGE_GENL_CTRL_ATTR_FAMILY_ID 1u
#define EDGE_GENL_CTRL_ATTR_FAMILY_NAME 2u
#define EDGE_GENL_CTRL_ATTR_VERSION 3u
#define EDGE_GENL_CTRL_ATTR_HDRSIZE 4u
#define EDGE_GENL_CTRL_ATTR_MAXATTR 5u
#define EDGE_GENL_CTRL_ATTR_OPS 6u
#define EDGE_GENL_CTRL_ATTR_MAX 10u

#define EDGE_GENL_CTRL_ATTR_OP_ID 1u
#define EDGE_GENL_CTRL_ATTR_OP_FLAGS 2u
#define EDGE_GENL_CMD_CAP_DO 2u
#define EDGE_GENL_CMD_CAP_DUMP 4u

#define EDGE_NLA_F_NESTED 0x8000u

typedef struct edge_genl_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} edge_genl_nlmsghdr_t;

typedef struct edge_genl_header {
    uint8_t command;
    uint8_t version;
    uint16_t reserved;
} edge_genl_header_t;

typedef struct edge_genl_attribute {
    uint16_t length;
    uint16_t type;
} edge_genl_attribute_t;

typedef struct edge_genl_family {
    uint16_t id;
    uint8_t version;
    uint32_t maximum_attribute;
    const char *name;
    const uint32_t *operations;
    uint32_t operation_count;
} edge_genl_family_t;

typedef struct edge_genl_family_selector {
    int id_seen;
    int name_seen;
    uint16_t id;
    char name[16];
} edge_genl_family_selector_t;

static const uint32_t edge_genl_controller_operations[] = {
    EDGE_GENL_CTRL_CMD_GETFAMILY,
};

static const uint32_t edge_genl_ethtool_operations[] = {
    EDGE_LINUX_ETHTOOL_MSG_LINKINFO_GET,
    EDGE_LINUX_ETHTOOL_MSG_LINKMODES_GET,
    EDGE_LINUX_ETHTOOL_MSG_LINKSTATE_GET,
    EDGE_LINUX_ETHTOOL_MSG_CHANNELS_GET,
};

static const edge_genl_family_t edge_genl_families[] = {
    {
        EDGE_LINUX_GENL_ID_CTRL,
        EDGE_LINUX_GENL_CTRL_VERSION,
        EDGE_GENL_CTRL_ATTR_MAX,
        "nlctrl",
        edge_genl_controller_operations,
        sizeof(edge_genl_controller_operations) /
            sizeof(edge_genl_controller_operations[0]),
    },
    {
        EDGE_LINUX_GENL_ID_ETHTOOL,
        EDGE_LINUX_GENL_ETHTOOL_VERSION,
        0u,
        "ethtool",
        edge_genl_ethtool_operations,
        sizeof(edge_genl_ethtool_operations) /
            sizeof(edge_genl_ethtool_operations[0]),
    },
};

static uint32_t edge_genl_align(uint32_t value) {
    return (value + 3u) & ~3u;
}

static int edge_genl_append_attribute(
    uint8_t *buffer, uint32_t capacity, uint32_t *offset, uint16_t type,
    const void *payload, uint16_t payload_length) {
    edge_genl_attribute_t attribute;
    uint32_t length = (uint32_t)sizeof(attribute) + payload_length;
    uint32_t padded_length = edge_genl_align(length);

    if (!buffer || !offset || (!payload && payload_length != 0u))
        return -EDGE_LINUX_EINVAL;
    if (*offset > capacity || padded_length > capacity - *offset)
        return -EDGE_LINUX_ENOBUFS;
    attribute.length = (uint16_t)length;
    attribute.type = type;
    memcpy(buffer + *offset, &attribute, sizeof(attribute));
    if (payload_length != 0u)
        memcpy(buffer + *offset + sizeof(attribute), payload,
               payload_length);
    if (padded_length > length)
        memset(buffer + *offset + length, 0, padded_length - length);
    *offset += padded_length;
    return 0;
}

static int edge_genl_append_controller_operations(
    uint8_t *buffer, uint32_t capacity, uint32_t *offset,
    const edge_genl_family_t *family) {
    edge_genl_attribute_t outer;
    uint32_t outer_offset = *offset;
    uint32_t index;

    if (outer_offset > capacity || sizeof(outer) > capacity - outer_offset)
        return -EDGE_LINUX_ENOBUFS;
    memset(&outer, 0, sizeof(outer));
    memcpy(buffer + outer_offset, &outer, sizeof(outer));
    *offset += sizeof(outer);

    for (index = 0; index < family->operation_count; ++index) {
        edge_genl_attribute_t entry;
        uint32_t entry_offset = *offset;
        uint32_t operation_id = family->operations[index];
        uint32_t operation_flags =
            EDGE_GENL_CMD_CAP_DO | EDGE_GENL_CMD_CAP_DUMP;
        int result;

        if (entry_offset > capacity ||
            sizeof(entry) > capacity - entry_offset)
            return -EDGE_LINUX_ENOBUFS;
        memset(&entry, 0, sizeof(entry));
        memcpy(buffer + entry_offset, &entry, sizeof(entry));
        *offset += sizeof(entry);
        result = edge_genl_append_attribute(
            buffer, capacity, offset, EDGE_GENL_CTRL_ATTR_OP_ID,
            &operation_id, sizeof(operation_id));
        if (result < 0) return result;
        result = edge_genl_append_attribute(
            buffer, capacity, offset, EDGE_GENL_CTRL_ATTR_OP_FLAGS,
            &operation_flags, sizeof(operation_flags));
        if (result < 0) return result;
        entry.length = (uint16_t)(*offset - entry_offset);
        entry.type = (uint16_t)((index + 1u) | EDGE_NLA_F_NESTED);
        memcpy(buffer + entry_offset, &entry, sizeof(entry));
    }
    outer.length = (uint16_t)(*offset - outer_offset);
    outer.type = (uint16_t)(EDGE_GENL_CTRL_ATTR_OPS | EDGE_NLA_F_NESTED);
    memcpy(buffer + outer_offset, &outer, sizeof(outer));
    return 0;
}

static int edge_genl_parse_family_selector(
    const uint8_t *request, uint32_t request_length, uint32_t attribute_offset,
    edge_genl_family_selector_t *selector) {

    while (attribute_offset < request_length) {
        edge_genl_attribute_t attribute;
        uint32_t padded_length;

        if (request_length - attribute_offset < sizeof(attribute))
            return -EDGE_LINUX_EINVAL;
        memcpy(&attribute, request + attribute_offset, sizeof(attribute));
        if (attribute.length < sizeof(attribute) ||
            attribute.length > request_length - attribute_offset)
            return -EDGE_LINUX_EINVAL;
        padded_length = edge_genl_align(attribute.length);
        if (padded_length > request_length - attribute_offset)
            return -EDGE_LINUX_EINVAL;

        if (attribute.type == EDGE_GENL_CTRL_ATTR_FAMILY_ID) {
            uint16_t family_id;
            if (attribute.length != sizeof(attribute) + sizeof(family_id))
                return -EDGE_LINUX_EINVAL;
            memcpy(&family_id, request + attribute_offset + sizeof(attribute),
                   sizeof(family_id));
            selector->id_seen = 1;
            selector->id = family_id;
        } else if (attribute.type == EDGE_GENL_CTRL_ATTR_FAMILY_NAME) {
            const uint8_t *name =
                request + attribute_offset + sizeof(attribute);
            uint32_t name_length = attribute.length - sizeof(attribute);
            if (name_length < 2u || name_length > sizeof(selector->name) ||
                name[name_length - 1u] != 0u)
                return -EDGE_LINUX_EINVAL;
            selector->name_seen = 1;
            memcpy(selector->name, name, name_length);
        }
        attribute_offset += padded_length;
    }
    return 0;
}

static int edge_genl_family_matches(
    const edge_genl_family_t *family,
    const edge_genl_family_selector_t *selector) {
    if (selector->id_seen && family->id != selector->id) return 0;
    if (selector->name_seen && strcmp(family->name, selector->name) != 0)
        return 0;
    return 1;
}

static int edge_genl_append_controller_family(
    uint32_t port_id, const edge_genl_nlmsghdr_t *request,
    const edge_genl_family_t *family,
    uint8_t *response, uint32_t capacity, uint32_t *offset, int dump) {
    edge_genl_nlmsghdr_t header;
    edge_genl_header_t generic;
    uint32_t message_offset = *offset;
    uint16_t family_id = family->id;
    uint32_t version = family->version;
    uint32_t header_size = 0u;
    uint32_t maximum_attribute = family->maximum_attribute;
    uint16_t family_name_length = 0;
    int result;

    while (family->name[family_name_length]) ++family_name_length;
    ++family_name_length;

    if (message_offset > capacity ||
        sizeof(header) + sizeof(generic) > capacity - message_offset)
        return -EDGE_LINUX_ENOBUFS;
    memset(&header, 0, sizeof(header));
    header.type = EDGE_LINUX_GENL_ID_CTRL;
    header.flags = dump ? EDGE_NLM_F_MULTI : 0u;
    header.sequence = request->sequence;
    header.port_id = port_id;
    memcpy(response + *offset, &header, sizeof(header));
    *offset += sizeof(header);

    memset(&generic, 0, sizeof(generic));
    generic.command = EDGE_GENL_CTRL_CMD_NEWFAMILY;
    generic.version = EDGE_LINUX_GENL_CTRL_VERSION;
    memcpy(response + *offset, &generic, sizeof(generic));
    *offset += sizeof(generic);

    result = edge_genl_append_attribute(
        response, capacity, offset, EDGE_GENL_CTRL_ATTR_FAMILY_ID,
        &family_id, sizeof(family_id));
    if (result < 0) return result;
    result = edge_genl_append_attribute(
        response, capacity, offset, EDGE_GENL_CTRL_ATTR_FAMILY_NAME,
        family->name, family_name_length);
    if (result < 0) return result;
    result = edge_genl_append_attribute(
        response, capacity, offset, EDGE_GENL_CTRL_ATTR_VERSION,
        &version, sizeof(version));
    if (result < 0) return result;
    result = edge_genl_append_attribute(
        response, capacity, offset, EDGE_GENL_CTRL_ATTR_HDRSIZE,
        &header_size, sizeof(header_size));
    if (result < 0) return result;
    result = edge_genl_append_attribute(
        response, capacity, offset, EDGE_GENL_CTRL_ATTR_MAXATTR,
        &maximum_attribute, sizeof(maximum_attribute));
    if (result < 0) return result;
    result = edge_genl_append_controller_operations(
        response, capacity, offset, family);
    if (result < 0) return result;

    header.length = *offset - message_offset;
    memcpy(response + message_offset, &header, sizeof(header));
    return 0;
}

int edge_linux_genetlink_respond(
    uint32_t network_namespace, uint32_t port_id,
    const void *request_data, uint32_t request_length,
    void *response_data, uint32_t response_capacity,
    uint32_t *response_length) {
    edge_genl_nlmsghdr_t request;
    edge_genl_header_t generic;
    const uint8_t *request_bytes = (const uint8_t *)request_data;
    uint8_t *response = (uint8_t *)response_data;
    uint32_t offset = 0;
    edge_genl_family_selector_t selector;
    uint32_t family_index;
    uint32_t matches = 0;
    int dump;
    int result;

    if (!response_length) return -EDGE_LINUX_EINVAL;
    *response_length = 0;
    if (!request_data || !response_data ||
        request_length < sizeof(request) + sizeof(generic))
        return -EDGE_LINUX_EINVAL;
    memcpy(&request, request_data, sizeof(request));
    if (request.length < sizeof(request) + sizeof(generic) ||
        request.length > request_length)
        return -EDGE_LINUX_EINVAL;
    if (request.type == EDGE_LINUX_GENL_ID_ETHTOOL)
        return edge_linux_ethtool_respond(
            network_namespace, port_id, request_data, request_length,
            response_data, response_capacity, response_length);
    if (request.type != EDGE_LINUX_GENL_ID_CTRL)
        return -EDGE_LINUX_ENOENT;
    memcpy(&generic, request_bytes + sizeof(request), sizeof(generic));
    if (generic.command != EDGE_GENL_CTRL_CMD_GETFAMILY)
        return -EDGE_LINUX_EOPNOTSUPP;
    dump = (request.flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP;
    memset(&selector, 0, sizeof(selector));
    result = edge_genl_parse_family_selector(
        request_bytes, request.length, sizeof(request) + sizeof(generic),
        &selector);
    if (result < 0) return result;
    if (!dump && !selector.id_seen && !selector.name_seen)
        return -EDGE_LINUX_EINVAL;

    for (family_index = 0;
         family_index < sizeof(edge_genl_families) /
             sizeof(edge_genl_families[0]);
         ++family_index) {
        const edge_genl_family_t *family =
            &edge_genl_families[family_index];

        if (!edge_genl_family_matches(family, &selector)) continue;
        result = edge_genl_append_controller_family(
            port_id, &request, family,
            response, response_capacity, &offset, dump);
        if (result < 0) return result;
        ++matches;
    }
    if (!matches && (selector.id_seen || selector.name_seen))
        return -EDGE_LINUX_ENOENT;
    if (dump) {
        struct {
            edge_genl_nlmsghdr_t header;
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
