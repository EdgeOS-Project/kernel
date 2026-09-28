/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS architecture-independent VFS readahead implementation.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "vfs/vfs.h"

#define VFS_READAHEAD_WINDOW_MAX (256u * 1024u)

int vfs_read_inode_exact(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint64_t offset, void *buffer, uint32_t length) {
    uint32_t completed = 0;

    if (!sb || !inode || (!buffer && length) || !sb->ops ||
        !sb->ops->read || offset > UINT32_MAX ||
        length > UINT32_MAX - (uint32_t)offset)
        return -1;
    while (completed < length) {
        uint32_t remaining = length - completed;
        int received = sb->ops->read(
            sb, inode, (uint32_t)offset + completed,
            (uint8_t *)buffer + completed, remaining);

        if (received <= 0 || (uint32_t)received > remaining)
            return -1;
        completed += (uint32_t)received;
    }
    return 0;
}

int vfs_readahead_inode(vfs_superblock_t *sb, vfs_inode_t *inode,
                        uint64_t offset, uint64_t length,
                        void *scratch, uint32_t scratch_capacity) {
    uint64_t remaining;
    uint64_t available;
    uint64_t completed = 0;

    if (!sb || !inode || !scratch || !scratch_capacity || !sb->ops ||
        !sb->ops->read || (inode->mode & 0xF000u) != VFS_INODE_FILE)
        return VFS_READAHEAD_ERR_INVALID;
    if (!length || offset >= inode->size) return 0;

    available = (uint64_t)inode->size - offset;
    remaining = length < available ? length : available;
    if (remaining > VFS_READAHEAD_WINDOW_MAX)
        remaining = VFS_READAHEAD_WINDOW_MAX;

    while (remaining) {
        uint32_t chunk = remaining < scratch_capacity ?
                         (uint32_t)remaining : scratch_capacity;
        int received = sb->ops->read(sb, inode, (uint32_t)(offset + completed),
                                     scratch, chunk);
        if (received < 0) return VFS_READAHEAD_ERR_IO;
        if (received == 0) break;
        completed += (uint32_t)received;
        remaining -= (uint32_t)received;
        if ((uint32_t)received < chunk) break;
    }
    return 0;
}
