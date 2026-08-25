/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux directory record policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "kernel/directory_runtime.h"
#include "kernel/fanotify.h"
#include "kernel/linux_errno.h"
#include "kernel/vfs_runtime.h"
#include "vfs/vfs.h"

uint8_t kernel_vfs_mode_to_dtype(uint16_t mode) {
    switch (mode & 0xf000u) {
        case VFS_INODE_DIR: return 4u;
        case VFS_INODE_FILE: return 8u;
        case VFS_INODE_LNK: return 10u;
        case VFS_INODE_CHR: return 2u;
        case VFS_INODE_BLK: return 6u;
        case VFS_INODE_FIFO: return 1u;
        case VFS_INODE_SOCK: return 12u;
        default: return 0u;
    }
}

int vfs_readdir_dirent(vfs_superblock_t *sb, vfs_inode_t *dir,
                       uint32_t idx, char *name_out,
                       vfs_inode_t *inode_out) {
    uint32_t inode_number = 0;
    uint16_t mode = 0;
    int result;

    if (!sb || !dir || !name_out || !inode_out || !sb->ops)
        return -1;
    if (sb->ops->readdir_dirent) {
        result = sb->ops->readdir_dirent(
            sb, dir, idx, name_out, &inode_number, &mode);
        if (result < 0) return result;
        memset(inode_out, 0, sizeof(*inode_out));
        inode_out->ino = inode_number;
        inode_out->mode = mode;
        return 0;
    }
    if (!sb->ops->readdir) return -1;
    return sb->ops->readdir(sb, dir, idx, name_out, inode_out);
}

int kernel_vfs_device_directory_uses_backing_readdir(
    const char *path, const vfs_superblock_t *superblock) {
    size_t mount_length;

    if (!path || !superblock || !superblock->ops ||
        !superblock->ops->readdir)
        return 0;
    if (strncmp(path, "/dev", 4u) != 0 ||
        (path[4] != 0 && path[4] != '/'))
        return 0;
    mount_length = strlen(superblock->mountpoint);
    if (mount_length < 4u ||
        strncmp(superblock->mountpoint, "/dev", 4u) != 0 ||
        (superblock->mountpoint[4] != 0 &&
         superblock->mountpoint[4] != '/'))
        return 0;
    return strncmp(path, superblock->mountpoint, mount_length) == 0 &&
           (path[mount_length] == 0 || path[mount_length] == '/');
}

static int kernel_vfs_dirent64_emit(
    const kernel_vfs_getdents_request_t *request, uint64_t *written,
    uint64_t inode, int64_t next_offset, uint8_t type, const char *name) {
    union {
        struct edge_linux_dirent64 alignment;
        uint8_t bytes[offsetof(struct edge_linux_dirent64, d_name) +
                      VFS_NAME_MAX + 8u];
    } record;
    struct edge_linux_dirent64 *directory_entry =
        (struct edge_linux_dirent64 *)(void *)record.bytes;
    uint64_t name_length = 0;
    uint64_t record_length;

    if (!request || !written || !request->copy_to_user || !name)
        return -EDGE_LINUX_EIO;
    while (name_length < VFS_NAME_MAX && name[name_length]) ++name_length;
    if (name_length == VFS_NAME_MAX) return -EDGE_LINUX_ENAMETOOLONG;
    record_length = (offsetof(struct edge_linux_dirent64, d_name) +
                     name_length + 1u + 7u) & ~7ULL;
    if (*written > request->capacity ||
        record_length > request->capacity - *written)
        return *written ? 0 : -EDGE_LINUX_EINVAL;
    if (request->user_buffer > UINT64_MAX - *written)
        return *written ? 0 : -EDGE_LINUX_EFAULT;

    memset(record.bytes, 0, (size_t)record_length);
    directory_entry->d_ino = inode;
    directory_entry->d_off = next_offset;
    directory_entry->d_reclen = (uint16_t)record_length;
    directory_entry->d_type = type;
    memcpy(directory_entry->d_name, name, (size_t)name_length + 1u);
    if (request->copy_to_user(
            request->copy_context, request->user_buffer + *written,
            record.bytes, record_length) < 0)
        return *written ? 0 : -EDGE_LINUX_EFAULT;
    *written += record_length;
    return 1;
}

static int kernel_vfs_dirent_native64_emit(
    const kernel_vfs_getdents_request_t *request, uint64_t *written,
    uint64_t inode, int64_t next_offset, uint8_t type, const char *name) {
    union {
        struct edge_linux_dirent alignment;
        uint8_t bytes[offsetof(struct edge_linux_dirent, d_name) +
                      VFS_NAME_MAX + 9u];
    } record;
    struct edge_linux_dirent *directory_entry =
        (struct edge_linux_dirent *)(void *)record.bytes;
    uint64_t name_length = 0;
    uint64_t record_length;

    if (!request || !written || !request->copy_to_user || !name)
        return -EDGE_LINUX_EIO;
    while (name_length < VFS_NAME_MAX && name[name_length]) ++name_length;
    if (name_length == VFS_NAME_MAX) return -EDGE_LINUX_ENAMETOOLONG;
    record_length = (offsetof(struct edge_linux_dirent, d_name) +
                     name_length + 2u + 7u) & ~7ULL;
    if (*written > request->capacity ||
        record_length > request->capacity - *written)
        return *written ? 0 : -EDGE_LINUX_EINVAL;
    if (request->user_buffer > UINT64_MAX - *written)
        return *written ? 0 : -EDGE_LINUX_EFAULT;

    memset(record.bytes, 0, (size_t)record_length);
    directory_entry->d_ino = inode;
    directory_entry->d_off = next_offset;
    directory_entry->d_reclen = (uint16_t)record_length;
    memcpy(directory_entry->d_name, name, (size_t)name_length + 1u);
    record.bytes[record_length - 1u] = type;
    if (request->copy_to_user(
            request->copy_context, request->user_buffer + *written,
            record.bytes, record_length) < 0)
        return *written ? 0 : -EDGE_LINUX_EFAULT;
    *written += record_length;
    return 1;
}

static int kernel_vfs_dirent_native32_emit(
    const kernel_vfs_getdents_request_t *request, uint64_t *written,
    uint64_t inode, int64_t next_offset, uint8_t type, const char *name) {
    union {
        struct edge_linux_ia32_dirent alignment;
        uint8_t bytes[offsetof(struct edge_linux_ia32_dirent, d_name) +
                      VFS_NAME_MAX + 5u];
    } record;
    struct edge_linux_ia32_dirent *directory_entry =
        (struct edge_linux_ia32_dirent *)(void *)record.bytes;
    uint64_t name_length = 0;
    uint64_t record_length;

    if (!request || !written || !request->copy_to_user || !name)
        return -EDGE_LINUX_EIO;
    if (inode > UINT32_MAX || next_offset < 0 ||
        (uint64_t)next_offset > UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    while (name_length < VFS_NAME_MAX && name[name_length]) ++name_length;
    if (name_length == VFS_NAME_MAX) return -EDGE_LINUX_ENAMETOOLONG;
    record_length = (offsetof(struct edge_linux_ia32_dirent, d_name) +
                     name_length + 2u + 3u) & ~3ULL;
    if (*written > request->capacity ||
        record_length > request->capacity - *written)
        return *written ? 0 : -EDGE_LINUX_EINVAL;
    if (request->user_buffer > UINT64_MAX - *written)
        return *written ? 0 : -EDGE_LINUX_EFAULT;

    memset(record.bytes, 0, (size_t)record_length);
    directory_entry->d_ino = (uint32_t)inode;
    directory_entry->d_off = (uint32_t)next_offset;
    directory_entry->d_reclen = (uint16_t)record_length;
    memcpy(directory_entry->d_name, name, (size_t)name_length + 1u);
    record.bytes[record_length - 1u] = type;
    if (request->copy_to_user(
            request->copy_context, request->user_buffer + *written,
            record.bytes, record_length) < 0)
        return *written ? 0 : -EDGE_LINUX_EFAULT;
    *written += record_length;
    return 1;
}

int kernel_vfs_dirent_emit(
    const kernel_vfs_getdents_request_t *request, uint64_t *written,
    uint64_t inode, int64_t next_offset, uint8_t type, const char *name) {
    if (request && request->format == KERNEL_VFS_DIRENT_NATIVE64)
        return kernel_vfs_dirent_native64_emit(
            request, written, inode, next_offset, type, name);
    if (request && request->format == KERNEL_VFS_DIRENT_NATIVE32)
        return kernel_vfs_dirent_native32_emit(
            request, written, inode, next_offset, type, name);
    return kernel_vfs_dirent64_emit(
        request, written, inode, next_offset, type, name);
}

int64_t kernel_vfs_getdents(
    const kernel_vfs_getdents_request_t *request) {
    kernel_vfs_descriptor_t description;
    kernel_vfs_directory_cursor_t cursor;
    kernel_vfs_directory_entry_t entry;
    uint64_t written = 0;
    int64_t special_result;
    int handled = 0;
    int status;

    if (!request || !request->copy_to_user) return -EDGE_LINUX_EIO;
    status = kernel_vfs_describe_descriptor(
        request->descriptor, &description);
    if (status < 0) return status;
    if (description.kind == KERNEL_VFS_DESCRIPTOR_DIRECTORY &&
        description.path) {
        status = kernel_fanotify_directory_access_permission_check(
            description.path);
        if (status < 0) return status;
    }
    special_result = arch_vfs_special_getdents64(request, &handled);
    if (handled) return special_result;
    if (special_result < 0) return special_result;
    status = arch_vfs_directory_open(request->descriptor, &cursor);
    if (status < 0) return status;

    for (;;) {
        status = arch_vfs_directory_next(&cursor, &entry);
        if (status < 0) {
            arch_vfs_directory_finish(&cursor);
            return written ? (int64_t)written : status;
        }
        if (!status) break;
        status = kernel_vfs_dirent_emit(
            request, &written, entry.inode.ino,
            (int64_t)entry.next_offset,
            kernel_vfs_mode_to_dtype(entry.inode.mode), entry.name);
        if (status < 0) {
            arch_vfs_directory_finish(&cursor);
            return status;
        }
        if (!status) break;
        arch_vfs_directory_commit(&cursor, &entry);
    }
    arch_vfs_directory_finish(&cursor);
    return (int64_t)written;
}
