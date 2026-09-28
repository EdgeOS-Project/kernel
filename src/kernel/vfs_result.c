/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent VFS result translation.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/linux_errno.h"
#include "kernel/vfs_runtime.h"
#include "vfs/vfs.h"

int kernel_vfs_path_result(int result) {
    switch (result) {
        case 0: return 0;
        case VFS_PATH_ERR_BUSY: return -EDGE_LINUX_EBUSY;
        case VFS_PATH_ERR_NOT_EMPTY: return -EDGE_LINUX_ENOTEMPTY;
        case VFS_PATH_ERR_CROSS_DEVICE: return -EDGE_LINUX_EXDEV;
        case VFS_PATH_ERR_IS_DIRECTORY: return -EDGE_LINUX_EISDIR;
        case VFS_PATH_ERR_NOT_DIRECTORY: return -EDGE_LINUX_ENOTDIR;
        case VFS_PATH_ERR_NOT_FOUND: return -EDGE_LINUX_ENOENT;
        case VFS_PATH_ERR_EXISTS: return -EDGE_LINUX_EEXIST;
        case VFS_PATH_ERR_INVALID: return -EDGE_LINUX_EINVAL;
        case VFS_PATH_ERR_ACCESS: return -EDGE_LINUX_EACCES;
        case VFS_PATH_ERR_NO_SPACE: return -EDGE_LINUX_ENOSPC;
        case VFS_PATH_ERR_READ_ONLY: return -EDGE_LINUX_EROFS;
        case VFS_PATH_ERR_PERMISSION: return -EDGE_LINUX_EPERM;
        case VFS_PATH_ERR_IO:
        default: return -EDGE_LINUX_EIO;
    }
}
