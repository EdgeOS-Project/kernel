/*
 * EdgeOS integration configuration for XZ Embedded.
 *
 * XZ Embedded is in the public domain. The decoder sources retain their
 * upstream attribution and public-domain notices.
 */

#ifndef EDGEOS_XZ_CONFIG_H
#define EDGEOS_XZ_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../sqfs_port.h"
#include "xz.h"

#define XZ_DEC_SINGLE 1

#define kmalloc(size, flags) edge_sqfs_alloc(size)
#define kfree(pointer) edge_sqfs_free(pointer)
#define vmalloc(size) edge_sqfs_alloc(size)
#define vfree(pointer) edge_sqfs_free(pointer)

#define memeq(a, b, size) (memcmp((a), (b), (size)) == 0)
#define memzero(buffer, size) memset((buffer), 0, (size))

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#define min_t(type, x, y) min((x), (y))

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

static inline uint32_t get_unaligned_le32(const uint8_t *buffer) {
    return (uint32_t)buffer[0] |
           ((uint32_t)buffer[1] << 8) |
           ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

static inline uint32_t get_unaligned_be32(const uint8_t *buffer) {
    return ((uint32_t)buffer[0] << 24) |
           ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8) |
           (uint32_t)buffer[3];
}

static inline void put_unaligned_le32(uint32_t value, uint8_t *buffer) {
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
    buffer[2] = (uint8_t)(value >> 16);
    buffer[3] = (uint8_t)(value >> 24);
}

static inline void put_unaligned_be32(uint32_t value, uint8_t *buffer) {
    buffer[0] = (uint8_t)(value >> 24);
    buffer[1] = (uint8_t)(value >> 16);
    buffer[2] = (uint8_t)(value >> 8);
    buffer[3] = (uint8_t)value;
}

#define get_le32 get_unaligned_le32

#endif
