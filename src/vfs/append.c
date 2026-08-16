/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include "kernel/process_runtime.h"
#include "vfs/vfs.h"

#define VFS_APPEND_LOCK_COUNT 128u

static volatile uint32_t g_append_locks[VFS_APPEND_LOCK_COUNT];

static volatile uint32_t *vfs_append_lock_for(vfs_superblock_t *sb,
                                               uint32_t inode) {
    uintptr_t value = (uintptr_t)vfs_superblock_identity(sb);
    uint32_t hash =
        (uint32_t)(value >> 4) ^ (uint32_t)(value >> 32) ^ inode;

    hash ^= hash >> 16;
    return &g_append_locks[hash % VFS_APPEND_LOCK_COUNT];
}

int vfs_append_write(const char *path, vfs_superblock_t *sb,
                     vfs_inode_t *inode, const void *buffer, uint32_t length,
                     uint32_t *offset_out) {
    volatile uint32_t *lock;
    vfs_inode_t current;
    vfs_superblock_t *current_sb = 0;
    uint32_t offset = 0;
    int result = -1;

    if (offset_out) *offset_out = 0;
    if (!sb || !inode || (!buffer && length) ||
        !sb->ops || !sb->ops->write)
        return -1;

    lock = vfs_append_lock_for(sb, inode->ino);
    while (__sync_lock_test_and_set(lock, 1u)) {
        if (!kernel_runtime_yield())
            __asm__ __volatile__("" ::: "memory");
    }

    current = *inode;
    if (sb->ops->append) {
        result = sb->ops->append(
            sb, &current, buffer, length, &offset);
    } else {
        /*
         * Filesystems without a native append hook can still provide atomic
         * O_APPEND for linked files by resolving the inode under the append
         * lock. Native hooks are required for rename- and unlink-stable
         * append because only the filesystem can reload an inode by number.
         */
        if (path && path[0]) {
            vfs_path_cache_invalidate(path);
            if (vfs_resolve(
                    path, &current, &current_sb, 0, 0) < 0 ||
                !vfs_superblock_same_filesystem(current_sb, sb) ||
                current.ino != inode->ino)
                current = *inode;
        }
        offset = current.size;
        result = sb->ops->write(
            sb, &current, offset, buffer, length);
    }
    if (result >= 0) {
        *inode = current;
        if (offset_out) *offset_out = offset;
        if (path && path[0]) vfs_path_cache_invalidate(path);
    }
    __sync_lock_release(lock);
    return result;
}
