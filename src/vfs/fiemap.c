/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent file extent dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "vfs/vfs.h"

int vfs_map_extent(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   uint64_t offset, uint64_t length,
                   vfs_extent_t *extent) {
    if (!sb || !inode || !extent || !length ||
        (inode->mode & 0xf000u) != VFS_INODE_FILE)
        return VFS_EXTENT_ERR_INVALID;
    if (offset >= inode->size)
        return VFS_EXTENT_ERR_NO_DATA;
    if (!sb->ops || !sb->ops->map_extent)
        return VFS_EXTENT_ERR_UNSUPPORTED;
    return sb->ops->map_extent(sb, inode, offset, length, extent);
}
