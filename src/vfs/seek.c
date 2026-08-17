/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent sparse file seek dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/vfs.h"

int vfs_seek_data_hole(vfs_superblock_t *sb, const vfs_inode_t *inode,
                       uint64_t offset, int seek_hole,
                       uint64_t *result) {
    if (!sb || !inode || !result ||
        (inode->mode & 0xf000u) != VFS_INODE_FILE)
        return VFS_SEEK_DATA_HOLE_ERR_INVALID;
    if (offset >= inode->size)
        return VFS_SEEK_DATA_HOLE_ERR_NO_DATA;
    if (sb->ops && sb->ops->seek_data_hole)
        return sb->ops->seek_data_hole(
            sb, inode, offset, seek_hole != 0, result);

    /*
     * Linux permits filesystems without sparse extent knowledge to report the
     * complete file as data followed by one hole at EOF.
     */
    *result = seek_hole ? inode->size : offset;
    return 0;
}
