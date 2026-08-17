/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS VFS export-handle dispatch.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/vfs.h"

int vfs_encode_file_handle(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           uint32_t *handle_type, void *handle,
                           uint32_t *handle_bytes) {
    if (!sb || !inode || !handle_type || !handle_bytes)
        return VFS_FILE_HANDLE_ERR_INVALID;
    if (!sb->ops || !sb->ops->encode_handle)
        return VFS_FILE_HANDLE_ERR_UNSUPPORTED;
    return sb->ops->encode_handle(sb, inode, handle_type, handle,
                                  handle_bytes);
}

int vfs_decode_file_handle(vfs_superblock_t *sb, uint32_t handle_type,
                           const void *handle, uint32_t handle_bytes,
                           vfs_inode_t *out) {
    if (!sb || !handle || !handle_bytes || !out)
        return VFS_FILE_HANDLE_ERR_INVALID;
    if (!sb->ops || !sb->ops->decode_handle)
        return VFS_FILE_HANDLE_ERR_UNSUPPORTED;
    return sb->ops->decode_handle(sb, handle_type, handle, handle_bytes, out);
}
