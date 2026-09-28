/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_FS_EXT4_ACL_H
#define EDGEOS_FS_EXT4_ACL_H

#include <stdint.h>

#define EDGE_EXT4_ACL_INVALID (-1)
#define EDGE_EXT4_ACL_RANGE (-2)
#define EDGE_EXT4_ACL_DISK_VERSION 1u
#define EDGE_EXT4_ACL_XATTR_VERSION 2u

static inline uint16_t edge_ext4_acl_read16(const uint8_t *bytes) {
    return (uint16_t)((uint16_t)bytes[0] | (uint16_t)bytes[1] << 8);
}

static inline uint32_t edge_ext4_acl_read32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static inline void edge_ext4_acl_write16(uint8_t *bytes, uint16_t value) {
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static inline void edge_ext4_acl_write32(uint8_t *bytes, uint32_t value) {
    for (uint32_t index = 0; index < 4u; ++index)
        bytes[index] = (uint8_t)(value >> (index * 8u));
}

/* Source and destination must not overlap. Validate the complete value before
 * publishing any bytes. A NULL destination queries the converted size.
 * A header without entries returns four bytes; callers handle it as no ACL.
 * Accept legacy v2 disk values written by older EdgeOS versions, but emit v1
 * for every new disk value. Namespace ID translation belongs above this codec. */
static inline int edge_ext4_acl_convert(const void *source, uint32_t length,
                                       void *destination, uint32_t capacity,
                                       int to_disk) {
    const uint8_t *input = (const uint8_t *)source;
    uint8_t *output = (uint8_t *)destination;
    uint32_t source_version, cursor = 4u, required = 4u;
    unsigned phase = 0u;
    int named_entries = 0;

    if (!input || length < 4u) return EDGE_EXT4_ACL_INVALID;
    source_version = edge_ext4_acl_read32(input);
    if ((to_disk && source_version != EDGE_EXT4_ACL_XATTR_VERSION) ||
        (!to_disk && source_version != EDGE_EXT4_ACL_DISK_VERSION &&
         source_version != EDGE_EXT4_ACL_XATTR_VERSION))
        return EDGE_EXT4_ACL_INVALID;

    while (cursor < length) {
        uint16_t tag, permissions;
        uint32_t input_size, output_size;
        int named;
        if (length - cursor < 4u) return EDGE_EXT4_ACL_INVALID;
        tag = edge_ext4_acl_read16(input + cursor);
        permissions = edge_ext4_acl_read16(input + cursor + 2u);
        named = tag == 2u || tag == 8u;
        input_size = source_version == EDGE_EXT4_ACL_XATTR_VERSION || named ? 8u : 4u;
        output_size = !to_disk || named ? 8u : 4u;
        if (length - cursor < input_size || (permissions & ~7u) ||
            (named && edge_ext4_acl_read32(input + cursor + 4u) == UINT32_MAX))
            return EDGE_EXT4_ACL_INVALID;
        /* Match the POSIX ACL tag ordering without imposing an additional
         * sorting or uniqueness rule on named user and group identifiers. */
        switch (tag) {
        case 1u:
            if (phase != 0u) return EDGE_EXT4_ACL_INVALID;
            phase = 1u;
            break;
        case 2u:
            if (phase != 1u) return EDGE_EXT4_ACL_INVALID;
            named_entries = 1;
            break;
        case 4u:
            if (phase != 1u) return EDGE_EXT4_ACL_INVALID;
            phase = 2u;
            break;
        case 8u:
            if (phase != 2u) return EDGE_EXT4_ACL_INVALID;
            named_entries = 1;
            break;
        case 16u:
            if (phase != 2u) return EDGE_EXT4_ACL_INVALID;
            phase = 3u;
            break;
        case 32u:
            if (phase != 3u && !(phase == 2u && !named_entries))
                return EDGE_EXT4_ACL_INVALID;
            phase = 4u;
            break;
        default:
            return EDGE_EXT4_ACL_INVALID;
        }
        if (required > INT32_MAX - output_size)
            return EDGE_EXT4_ACL_INVALID;
        required += output_size;
        cursor += input_size;
    }
    if (length != 4u && phase != 4u) return EDGE_EXT4_ACL_INVALID;
    if (!output) return (int)required;
    if (capacity < required) return EDGE_EXT4_ACL_RANGE;

    edge_ext4_acl_write32(output, to_disk ? EDGE_EXT4_ACL_DISK_VERSION :
                                          EDGE_EXT4_ACL_XATTR_VERSION);
    cursor = 4u;
    required = 4u;
    while (cursor < length) {
        uint16_t tag = edge_ext4_acl_read16(input + cursor);
        int named = tag == 2u || tag == 8u;
        edge_ext4_acl_write16(output + required, tag);
        edge_ext4_acl_write16(output + required + 2u,
                             edge_ext4_acl_read16(input + cursor + 2u));
        if (!to_disk || named)
            edge_ext4_acl_write32(output + required + 4u, named ?
                edge_ext4_acl_read32(input + cursor + 4u) : UINT32_MAX);
        cursor += source_version == EDGE_EXT4_ACL_XATTR_VERSION || named ? 8u : 4u;
        required += !to_disk || named ? 8u : 4u;
    }
    return (int)required;
}

static inline int edge_ext4_acl_from_disk(const void *source, uint32_t length,
                                         void *destination, uint32_t capacity) {
    return edge_ext4_acl_convert(source, length, destination, capacity, 0);
}

static inline int edge_ext4_acl_to_disk(const void *source, uint32_t length,
                                       void *destination, uint32_t capacity) {
    return edge_ext4_acl_convert(source, length, destination, capacity, 1);
}

#endif
