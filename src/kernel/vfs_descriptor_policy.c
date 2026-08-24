/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent VFS descriptor policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/fanotify.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_seek.h"
#include "kernel/mm_runtime.h"
#include "kernel/vfs_runtime.h"
#include "vfs/page_writeback.h"

int kernel_vfs_resolve_fd(int32_t descriptor, kernel_vfs_target_t *target) {
    if (!target || descriptor < 0)
        return -EDGE_LINUX_EBADF;
    memset(target, 0, sizeof(*target));
    return arch_vfs_resolve_fd(descriptor, target);
}

int kernel_vfs_install_inode_descriptor(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint32_t status_flags, uint32_t descriptor_flags,
    int linkable_zero_link_inode) {
    if (!superblock || !inode)
        return -EDGE_LINUX_EINVAL;
    return arch_vfs_install_inode_descriptor(
        superblock, inode, status_flags, descriptor_flags,
        linkable_zero_link_inode);
}

int kernel_vfs_metadata_fd(int32_t descriptor,
                           kernel_file_metadata_t *metadata) {
    if (!metadata || descriptor < 0)
        return -EDGE_LINUX_EBADF;
    return arch_vfs_metadata_fd(descriptor, metadata);
}

int kernel_vfs_sync_descriptor(
    int32_t descriptor, kernel_vfs_sync_operation_t operation) {
    if (descriptor < 0)
        return -EDGE_LINUX_EBADF;
    if (operation != KERNEL_VFS_SYNC_FILE &&
        operation != KERNEL_VFS_SYNC_DATA &&
        operation != KERNEL_VFS_SYNC_FILESYSTEM &&
        operation != KERNEL_VFS_SYNC_RANGE)
        return -EDGE_LINUX_EINVAL;
    return arch_vfs_sync_descriptor(descriptor, operation);
}

int kernel_vfs_sync_descriptor_range(int32_t descriptor, uint64_t offset,
                                     uint64_t length, uint32_t flags) {
    kernel_vfs_descriptor_t description;
    uint16_t kind;
    int result;

    if (descriptor < 0) return -EDGE_LINUX_EBADF;
    result = kernel_vfs_describe_descriptor(descriptor, &description);
    if (result < 0) return result;
    if (flags & ~7u) return -EDGE_LINUX_EINVAL;
    if (offset > INT64_MAX || length > INT64_MAX ||
        (length && offset > (uint64_t)INT64_MAX - length))
        return -EDGE_LINUX_EINVAL;
    if (!description.superblock || !description.inode)
        return description.kind == KERNEL_VFS_DESCRIPTOR_MEMORY ? 0 :
               -EDGE_LINUX_ESPIPE;
    kind = (uint16_t)(description.inode->mode & 0xf000u);
    if (kind != VFS_INODE_FILE && kind != VFS_INODE_DIR &&
        kind != VFS_INODE_BLK)
        return -EDGE_LINUX_ESPIPE;
    if (!flags) return 0;
    if (vfs_page_writeback_sync_range(
            description.superblock, description.inode, offset,
            length ? length : UINT64_MAX) < 0)
        return -EDGE_LINUX_EIO;
    return 0;
}

int kernel_vfs_describe_descriptor(
    int32_t descriptor, kernel_vfs_descriptor_t *description) {
    if (!description || descriptor < 0)
        return -EDGE_LINUX_EBADF;
    memset(description, 0, sizeof(*description));
    return arch_vfs_describe_descriptor(descriptor, description);
}

int kernel_vfs_cachestat(int32_t descriptor, uint64_t offset,
                         uint64_t length,
                         kernel_vfs_cache_stats_t *statistics) {
    kernel_vfs_descriptor_t description;
    int result;

    if (descriptor < 0 || !statistics)
        return -EDGE_LINUX_EBADF;
    memset(statistics, 0, sizeof(*statistics));
    result = kernel_vfs_describe_descriptor(descriptor, &description);
    if (result < 0) return result;
    result = arch_vfs_cachestat(
        descriptor, offset, length, statistics);
    if (result < 0) return result;
    if (description.superblock && description.inode) {
        uint64_t dirty_pages = 0;
        uint64_t writeback_pages = 0;
        uint64_t shadow_evicted_pages = 0;
        uint64_t shadow_recently_evicted_pages = 0;

        vfs_page_writeback_stat_range(
            description.superblock, description.inode,
            offset, length, &dirty_pages, &writeback_pages);
        statistics->dirty_pages += dirty_pages;
        statistics->writeback_pages += writeback_pages;
        kernel_mm_file_cache_shadow_stat_range(
            (uint64_t)(uintptr_t)vfs_superblock_identity(
                description.superblock),
            description.inode->ino, description.inode->generation,
            offset, length, &shadow_evicted_pages,
            &shadow_recently_evicted_pages);
        statistics->evicted_pages += shadow_evicted_pages;
        statistics->recently_evicted_pages +=
            shadow_recently_evicted_pages;
    }
    return 0;
}

int kernel_vfs_fallocate_descriptor(
    int32_t descriptor, uint32_t mode, uint64_t offset, uint64_t length) {
    if (descriptor < 0)
        return -EDGE_LINUX_EBADF;
    return arch_vfs_fallocate_descriptor(
        descriptor, mode, offset, length);
}

int kernel_vfs_fallocate_inode_transaction(
    vfs_superblock_t *superblock, vfs_inode_t *inode, uint32_t mode,
    uint64_t offset, uint64_t length) {
    int result;

    if (!superblock || !inode)
        return -EDGE_LINUX_EINVAL;
    result = arch_vfs_fallocate_prepare(
        superblock, inode, mode, offset, length);
    if (result < 0) return result;
    result = vfs_fallocate_inode(superblock, inode, mode, offset, length);
    if (result == VFS_FALLOCATE_ERR_UNSUPPORTED)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (result == VFS_FALLOCATE_ERR_NOSPC)
        return -EDGE_LINUX_ENOSPC;
    if (result == VFS_FALLOCATE_ERR_INVALID)
        return -EDGE_LINUX_EINVAL;
    if (result < 0)
        return -EDGE_LINUX_EIO;
    arch_vfs_fallocate_commit(
        superblock, inode, mode, offset, length);
    return 0;
}

int kernel_vfs_truncate_descriptor(int32_t descriptor, uint32_t length) {
    kernel_vfs_descriptor_t description;
    int result;

    if (descriptor < 0)
        return -EDGE_LINUX_EBADF;
    result = kernel_vfs_describe_descriptor(descriptor, &description);
    if (result < 0) return result;
    if (description.kind == KERNEL_VFS_DESCRIPTOR_REGULAR &&
        description.path) {
        result = kernel_fanotify_pre_access_permission_check(
            description.path, length, 0u);
        if (result < 0) return result;
    }
    return arch_vfs_truncate_descriptor(descriptor, length);
}

edge_linux_seek_result_t kernel_vfs_seek_descriptor(
    int32_t descriptor, int64_t displacement, uint32_t whence,
    uint64_t *result) {
    if (!result || descriptor < 0)
        return EDGE_LINUX_SEEK_BAD_DESCRIPTOR;
    return arch_vfs_seek_descriptor(
        descriptor, displacement, whence, result);
}
