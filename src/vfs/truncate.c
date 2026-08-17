/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS architecture-independent VFS inode truncation.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/page_writeback.h"
#include "vfs/readahead.h"
#include "vfs/vfs.h"

int vfs_truncate_inode(vfs_superblock_t *sb, vfs_inode_t *inode,
                       uint32_t length) {
    uint32_t old_length;
    uint64_t discard_start;
    if (!sb || !inode || (inode->mode & 0xf000u) != VFS_INODE_FILE)
        return VFS_TRUNCATE_ERR_INVALID;
    if (!sb->ops || !sb->ops->truncate)
        return VFS_TRUNCATE_ERR_UNSUPPORTED;
    old_length = inode->size;
    if (sb->ops->truncate(sb, inode, length) < 0)
        return VFS_TRUNCATE_ERR_IO;
    inode->size = length;
    if (length < old_length) {
        discard_start = ((uint64_t)length +
                         VFS_PAGE_WRITEBACK_PAGE_SIZE - 1u) &
                        ~((uint64_t)VFS_PAGE_WRITEBACK_PAGE_SIZE - 1u);
        vfs_page_writeback_forget_range(
            sb, inode, discard_start, UINT64_MAX - discard_start);
    }
    vfs_readahead_forget_inode(sb, inode);
    /*
     * Linux ftruncate(2) changes inode state but does not imply fsync(2).
     * Forcing a filesystem-wide sync here serialized every browser profile
     * update and could report EIO after the truncate had already succeeded.
     * Synchronous mounts are handled by the filesystem mutation policy;
     * explicit durability remains the job of fsync/fdatasync/sync.
     */
    /* One inode may be reachable through hard links and cached symlink walks. */
    vfs_path_cache_invalidate_all();
    return 0;
}
