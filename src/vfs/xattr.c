/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS architecture-independent extended attribute dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include "string.h"
#include "vfs/vfs.h"

int vfs_inode_setxattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                       const char *name, const void *value, uint32_t size,
                       uint32_t flags) {
    if (!sb || !inode || !name || !name[0] ||
        (uint32_t)strlen(name) > VFS_XATTR_NAME_MAX ||
        size > VFS_XATTR_VALUE_MAX || (size && !value) ||
        (flags & ~(VFS_XATTR_CREATE | VFS_XATTR_REPLACE)) ||
        flags == (VFS_XATTR_CREATE | VFS_XATTR_REPLACE))
        return VFS_XATTR_ERR_INVALID;
    if (!sb->ops || !sb->ops->setxattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return sb->ops->setxattr(sb, inode, name, value, size, flags);
}

int vfs_inode_getxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                       const char *name, void *value, uint32_t size) {
    if (!sb || !inode || !name || !name[0] ||
        (uint32_t)strlen(name) > VFS_XATTR_NAME_MAX || (size && !value))
        return VFS_XATTR_ERR_INVALID;
    if (!sb->ops || !sb->ops->getxattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return sb->ops->getxattr(sb, inode, name, value, size);
}

int vfs_inode_listxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                        char *list, uint32_t size) {
    if (!sb || !inode || (size && !list)) return VFS_XATTR_ERR_INVALID;
    if (!sb->ops || !sb->ops->listxattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return sb->ops->listxattr(sb, inode, list, size);
}

int vfs_inode_removexattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                          const char *name) {
    if (!sb || !inode || !name || !name[0] ||
        (uint32_t)strlen(name) > VFS_XATTR_NAME_MAX)
        return VFS_XATTR_ERR_INVALID;
    if (!sb->ops || !sb->ops->removexattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return sb->ops->removexattr(sb, inode, name);
}
