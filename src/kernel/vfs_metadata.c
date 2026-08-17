/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent VFS metadata policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_syscall.h"
#include "kernel/namespaces.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"
#include "vfs/vfs.h"

static int kernel_vfs_namespace_path_metadata(
    const char *path, const kernel_linux_identity_t *identity,
    kernel_file_metadata_t *metadata) {
    static const char prefix[] = "/proc/";
    static const char separator[] = "ns/";
    const char *cursor;
    uint64_t inode;
    uint32_t pid = 0;
    uint32_t position = 0;

    if (!path || !identity || !metadata) return 0;
    while (prefix[position] && path[position] == prefix[position]) ++position;
    if (prefix[position]) return 0;
    cursor = path + position;
    if (strncmp(cursor, "self", 4u) == 0 && cursor[4] == '/') {
        pid = (uint32_t)identity->global_tgid;
        cursor += 5u;
    } else if (strncmp(cursor, "thread-self", 11u) == 0 &&
               cursor[11] == '/') {
        pid = (uint32_t)identity->global_tid;
        cursor += 12u;
    } else {
        if (*cursor < '0' || *cursor > '9') return 0;
        while (*cursor >= '0' && *cursor <= '9') {
            if (pid > (UINT32_MAX - (uint32_t)(*cursor - '0')) / 10u)
                return 0;
            pid = pid * 10u + (uint32_t)(*cursor++ - '0');
        }
        if (*cursor++ != '/') return 0;
    }
    for (position = 0; separator[position]; ++position)
        if (cursor[position] != separator[position]) return 0;
    cursor += position;
    for (uint32_t kind = 0; kind < EDGE_NAMESPACE_KIND_COUNT; ++kind) {
        const char *name = edge_namespace_name((edge_namespace_kind_t)kind);
        if (!name || strcmp(cursor, name) != 0) continue;
        if (arch_proc_namespace_inode((int32_t)pid, kind, &inode) < 0)
            return -EDGE_LINUX_ENOENT;
        kernel_file_metadata_initialize(
            metadata, (uint16_t)(VFS_INODE_FILE | 0444u), 0);
        metadata->inode = inode;
        return 1;
    }
    return 0;
}

int kernel_vfs_metadata_at(int32_t directory, const char *path, int nofollow,
                           kernel_file_metadata_t *metadata) {
    kernel_vfs_mount_scratch_t scratch;
    kernel_linux_identity_t identity;
    vfs_superblock_t *superblock = 0;
    vfs_inode_t inode;
    int have_inode;
    int handled = 0;
    int status;

    if (!path || !metadata) return -EDGE_LINUX_EFAULT;
    if (!path[0]) return -EDGE_LINUX_ENOENT;
    status = kernel_vfs_current_mount_scratch(&scratch);
    if (status < 0) return status;
    status = kernel_vfs_resolve_at_path(
        directory, path, scratch.workspace, scratch.capacity);
    if (status < 0) return status;
    status = vfs_path_search_check(
        scratch.workspace, scratch.data, scratch.capacity, 0);
    if (status < 0) return status;

    if (!nofollow && kernel_current_linux_identity(&identity) == 0) {
        status = kernel_vfs_namespace_path_metadata(
            scratch.workspace, &identity, metadata);
        if (status < 0) return status;
        if (status > 0) return 0;
        status = edge_linux_current_magic_fd_metadata(
            scratch.workspace, &identity, metadata, &handled);
        if (handled) return status;
    }

    status = arch_vfs_metadata_path_prepare(
        scratch.workspace, nofollow, scratch.target, scratch.capacity);
    if (status < 0) return status;
    have_inode = nofollow ?
        vfs_resolve_nofollow(
            scratch.target, &inode, &superblock) == 0 :
        vfs_resolve(
            scratch.target, &inode, &superblock, 0, 0) == 0;
    status = arch_vfs_special_path_metadata(
        scratch.target, superblock, have_inode ? &inode : 0,
        metadata, &handled);
    if (status < 0 || handled) return status;
    if (!have_inode) return -EDGE_LINUX_ENOENT;

    kernel_file_metadata_from_inode(superblock, &inode, metadata);
    if (nofollow && (inode.mode & 0xf000u) == VFS_INODE_LNK &&
        !metadata->size) {
        status = arch_vfs_readlink_path(
            scratch.target, scratch.data, scratch.capacity);
        if (status >= 0) {
            metadata->size = (uint64_t)status;
            metadata->blocks = (metadata->size + 511u) / 512u;
        }
    }
    return 0;
}
