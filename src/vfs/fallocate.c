/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS architecture-independent VFS file allocation dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/page_writeback.h"
#include "vfs/readahead.h"
#include "vfs/vfs.h"

int vfs_fallocate_inode(vfs_superblock_t *sb, vfs_inode_t *inode,
                        uint32_t mode, uint64_t offset, uint64_t length) {
    uint32_t invalidating_modes =
        VFS_FALLOC_FL_PUNCH_HOLE | VFS_FALLOC_FL_ZERO_RANGE |
        VFS_FALLOC_FL_COLLAPSE_RANGE | VFS_FALLOC_FL_INSERT_RANGE;
    uint64_t invalidate_length = length;
    int rc;
    if (!sb || !inode || !length) return VFS_FALLOCATE_ERR_INVALID;
    if ((inode->mode & 0xF000u) != VFS_INODE_FILE)
        return VFS_FALLOCATE_ERR_INVALID;
    if (!sb->ops || !sb->ops->fallocate)
        return VFS_FALLOCATE_ERR_UNSUPPORTED;
    if (mode & (VFS_FALLOC_FL_COLLAPSE_RANGE |
                VFS_FALLOC_FL_INSERT_RANGE))
        invalidate_length = UINT64_MAX - offset;
    if ((mode & invalidating_modes) &&
        vfs_page_writeback_sync_range(
            sb, inode, offset, invalidate_length) < 0)
        return VFS_FALLOCATE_ERR_IO;
    rc = sb->ops->fallocate(sb, inode, mode, offset, length);
    if (rc == 0) {
        if (mode & invalidating_modes)
            vfs_page_writeback_forget_range(
                sb, inode, offset, invalidate_length);
        vfs_readahead_forget_inode(sb, inode);
        vfs_path_cache_invalidate_all();
    }
    return rc;
}
