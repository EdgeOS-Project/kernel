/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_USER_STRING_COPY_H
#define EDGEOS_KERNEL_USER_STRING_COPY_H
#include <stdint.h>
#include "kernel/linux_errno.h"

#define KERNEL_USER_STRING_CHUNK 128u
#define KERNEL_USER_STRING_PAGE 4096u

typedef int (*kernel_user_string_read_t)(
    void *context, void *destination, uint64_t source, uint64_t length);
typedef struct {
    uint64_t calls;
    uint64_t requested_bytes;
} kernel_user_string_copy_stats_t;

static inline int kernel_user_string_read_chunk(
    kernel_user_string_read_t read, void *context, void *destination,
    uint64_t source, uint32_t length, kernel_user_string_copy_stats_t *stats) {
    ++stats->calls;
    stats->requested_bytes += length;
    return read(context, destination, source, length);
}

/* Copy through the first NUL without crossing a user page in any read.
 * A failed speculative chunk is retried bytewise: a valid terminator before
 * an inaccessible suffix must still succeed, including sub-page limits.
 * Failed or post-NUL chunk bytes are never published to the destination. */
static inline int kernel_user_string_copy(
    kernel_user_string_read_t read, void *context, uint64_t source,
    char *destination, uint32_t capacity, int too_long_error,
    kernel_user_string_copy_stats_t *stats) {
    char buffer[KERNEL_USER_STRING_CHUNK];
    uint32_t index = 0;
    stats->calls = 0;
    stats->requested_bytes = 0;
    if (!source) return -EDGE_LINUX_EFAULT;
    if (!destination || !capacity) return -EDGE_LINUX_EIO;
    if (!read) return -EDGE_LINUX_EFAULT;
    while (index < capacity) {
        uint64_t address;
        uint32_t length, page_left;
        if (source > UINT64_MAX - index) return -EDGE_LINUX_EFAULT;
        address = source + index;
        page_left = KERNEL_USER_STRING_PAGE -
                    (uint32_t)(address & (KERNEL_USER_STRING_PAGE - 1u));
        length = capacity - index;
        if (length > sizeof(buffer)) length = sizeof(buffer);
        if (length > page_left) length = page_left;
        if (kernel_user_string_read_chunk(
                read, context, buffer, address, length, stats) < 0) {
            if (length == 1u) return -EDGE_LINUX_EFAULT;
            for (uint32_t byte = 0; byte < length; ++byte) {
                char value;
                if (kernel_user_string_read_chunk(
                        read, context, &value, address + byte, 1u, stats) < 0)
                    return -EDGE_LINUX_EFAULT;
                destination[index] = value;
                if (!value) return (int)index;
                ++index;
            }
        } else {
            for (uint32_t byte = 0; byte < length; ++byte) {
                destination[index] = buffer[byte];
                if (!buffer[byte]) return (int)index;
                ++index;
            }
        }
    }
    destination[capacity - 1u] = 0;
    return -too_long_error;
}
#endif
