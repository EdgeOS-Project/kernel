/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS architecture-independent miscellaneous file attribute dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include "string.h"
#include "vfs/vfs.h"

int vfs_inode_fileattr_get(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           vfs_fileattr_t *attributes) {
    if (!sb || !inode || !attributes) return VFS_FILEATTR_ERR_INVALID;
    if (!sb->ops || !sb->ops->fileattr_get)
        return VFS_FILEATTR_ERR_UNSUPPORTED;
    memset(attributes, 0, sizeof(*attributes));
    return sb->ops->fileattr_get(sb, inode, attributes);
}

int vfs_inode_fileattr_set(vfs_superblock_t *sb, vfs_inode_t *inode,
                           const vfs_fileattr_t *attributes) {
    int result;
    if (!sb || !inode || !attributes ||
        (attributes->xflags & ~((uint64_t)VFS_FILE_XFLAG_ALL)))
        return VFS_FILEATTR_ERR_INVALID;
    if (!sb->ops || !sb->ops->fileattr_set)
        return VFS_FILEATTR_ERR_UNSUPPORTED;
    result = sb->ops->fileattr_set(sb, inode, attributes);
    if (result == 0) vfs_path_cache_invalidate_all();
    return result;
}
