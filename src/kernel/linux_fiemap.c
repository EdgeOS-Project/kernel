/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux FIEMAP implementation.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_fiemap.h"

_Static_assert(sizeof(edge_linux_fiemap_t) == 32u,
               "Linux fiemap header ABI size mismatch");
_Static_assert(sizeof(edge_linux_fiemap_extent_t) == 56u,
               "Linux fiemap extent ABI size mismatch");

static int64_t fiemap_extent_error(int result) {
    switch (result) {
        case VFS_EXTENT_ERR_NO_DATA:
            return 0;
        case VFS_EXTENT_ERR_UNSUPPORTED:
            return -EDGE_LINUX_EOPNOTSUPP;
        case VFS_EXTENT_ERR_INVALID:
            return -EDGE_LINUX_EINVAL;
        case VFS_EXTENT_ERR_IO:
        default:
            return -EDGE_LINUX_EIO;
    }
}

static int fiemap_copy_from_user(const kernel_ioctl_request_t *request,
                                 void *destination, uint64_t source,
                                 uint32_t length) {
    return request && request->copy_from_user && source &&
           request->copy_from_user(request->copy_context, destination,
                                   source, length) == 0 ? 0 : -1;
}

static int fiemap_copy_to_user(const kernel_ioctl_request_t *request,
                               uint64_t destination, const void *source,
                               uint32_t length) {
    return request && request->copy_to_user && destination &&
           request->copy_to_user(request->copy_context, destination,
                                 source, length) == 0 ? 0 : -1;
}

int64_t kernel_linux_fiemap_ioctl(
    vfs_superblock_t *sb, const vfs_inode_t *inode,
    const kernel_ioctl_request_t *request) {
    edge_linux_fiemap_t header;
    uint64_t end;
    uint64_t cursor;
    uint64_t extent_address;
    uint32_t mapped = 0;
    uint32_t supported_flags = EDGE_LINUX_FIEMAP_FLAG_SYNC |
                               EDGE_LINUX_FIEMAP_FLAG_XATTR |
                               EDGE_LINUX_FIEMAP_FLAG_CACHE;

    if (!sb || !inode || !request ||
        request->command != EDGE_LINUX_FS_IOC_FIEMAP ||
        !request->argument)
        return -EDGE_LINUX_EINVAL;
    if (fiemap_copy_from_user(request, &header, request->argument,
                              sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!header.length) return -EDGE_LINUX_EINVAL;
    if (header.flags & ~supported_flags)
        return -EDGE_LINUX_EBADR;
    if (header.flags & EDGE_LINUX_FIEMAP_FLAG_XATTR)
        return -EDGE_LINUX_EOPNOTSUPP;
    if ((inode->mode & 0xf000u) != VFS_INODE_FILE)
        return -EDGE_LINUX_EINVAL;
    if (header.flags & EDGE_LINUX_FIEMAP_FLAG_SYNC) {
        if (vfs_sync_inode(sb, inode, 0) < 0)
            return -EDGE_LINUX_EIO;
    }

    end = header.start + header.length;
    if (end < header.start) end = UINT64_MAX;
    if (end > inode->size) end = inode->size;
    cursor = header.start;
    extent_address = request->argument + sizeof(header);
    if (extent_address < request->argument)
        return -EDGE_LINUX_EFAULT;

    while (cursor < end) {
        vfs_extent_t extent;
        edge_linux_fiemap_extent_t output;
        int result;

        memset(&extent, 0, sizeof(extent));
        result = vfs_map_extent(sb, inode, cursor, end - cursor, &extent);
        if (result == VFS_EXTENT_ERR_NO_DATA) break;
        if (result < 0) return fiemap_extent_error(result);
        if (!extent.length || extent.logical < cursor ||
            extent.logical >= end || extent.length > end - extent.logical)
            return -EDGE_LINUX_EIO;

        memset(&output, 0, sizeof(output));
        output.logical = extent.logical;
        output.physical = extent.physical;
        output.length = extent.length;
        if (extent.flags & VFS_EXTENT_FLAG_LAST)
            output.flags |= EDGE_LINUX_FIEMAP_EXTENT_LAST;
        if (extent.flags & VFS_EXTENT_FLAG_UNWRITTEN)
            output.flags |= EDGE_LINUX_FIEMAP_EXTENT_UNWRITTEN;
        if (extent.flags & VFS_EXTENT_FLAG_UNKNOWN)
            output.flags |= EDGE_LINUX_FIEMAP_EXTENT_UNKNOWN;

        if (mapped < header.extent_count) {
            uint64_t destination = extent_address +
                (uint64_t)mapped * sizeof(output);
            if (destination < extent_address ||
                fiemap_copy_to_user(request, destination, &output,
                                    sizeof(output)) < 0)
                return -EDGE_LINUX_EFAULT;
        }
        if (mapped == UINT32_MAX) return -EDGE_LINUX_EOVERFLOW;
        ++mapped;
        cursor = extent.logical + extent.length;
        if (extent.flags & VFS_EXTENT_FLAG_LAST) break;
        if (header.extent_count && mapped >= header.extent_count) break;
    }

    header.mapped_extents = mapped;
    if (fiemap_copy_to_user(request, request->argument, &header,
                            sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}
