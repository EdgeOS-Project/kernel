/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent current-task VFS policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stddef.h>
#include <stdint.h>

#include "kernel/fanotify.h"
#include "kernel/fs_context.h"
#include "kernel/inotify.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"
#include "string.h"
#include "vfs/vfs.h"

static int kernel_vfs_context_get(kernel_vfs_current_context_t *context) {
    if (!context || arch_vfs_current_context(context) < 0)
        return -EDGE_LINUX_EIO;
    if (!context->root || !context->cwd || !context->xattr ||
        !context->path_capacity || !context->xattr_capacity ||
        !context->resolve_workspace ||
        !context->resolve_workspace_capacity)
        return -EDGE_LINUX_EIO;
    for (uint32_t index = 0; index < 8u; ++index)
        if (!context->paths[index]) return -EDGE_LINUX_EIO;
    return 0;
}

int kernel_vfs_current_xattr_scratch(kernel_vfs_xattr_scratch_t *scratch) {
    kernel_vfs_current_context_t context;

    if (!scratch || kernel_vfs_context_get(&context) < 0)
        return -EDGE_LINUX_EIO;
    scratch->path = context.paths[0];
    scratch->path_capacity = context.path_capacity;
    scratch->value = context.xattr;
    scratch->value_capacity = context.xattr_capacity;
    return 0;
}

int kernel_vfs_current_mount_scratch(kernel_vfs_mount_scratch_t *scratch) {
    kernel_vfs_current_context_t context;

    if (!scratch || kernel_vfs_context_get(&context) < 0)
        return -EDGE_LINUX_EIO;
    scratch->source = context.paths[0];
    scratch->target = context.paths[1];
    scratch->data = context.paths[2];
    scratch->workspace = context.paths[3];
    scratch->capacity = context.path_capacity;
    return 0;
}

int kernel_vfs_resolve_at_path(int32_t directory, const char *path,
                               char *output, uint32_t capacity) {
    kernel_vfs_current_context_t context;
    kernel_vfs_target_t directory_target;
    char *buffers[3];
    char *cwd;
    char *root;
    char *normalization;
    char *copied_path;
    const char *base;
    uint32_t buffer_count = 0;
    uint32_t length;
    int status;

    if (!path || !output || !capacity ||
        kernel_vfs_context_get(&context) < 0)
        return -EDGE_LINUX_EFAULT;
    for (length = 0; path[length]; ++length) {
        if (length + 1u >= context.xattr_capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
    }
    copied_path = (char *)context.xattr;
    memmove(copied_path, path, length + 1u);
    if (!copied_path[0]) return -EDGE_LINUX_ENOENT;

    for (uint32_t index = 0; index < 4u && buffer_count < 3u; ++index) {
        if (context.paths[index] != output)
            buffers[buffer_count++] = context.paths[index];
    }
    if (buffer_count < 3u || context.path_capacity < capacity)
        return -EDGE_LINUX_EIO;
    cwd = buffers[0];
    root = buffers[1];
    normalization = buffers[2];
    status = kernel_current_fs_snapshot(
        cwd, context.path_capacity, root, context.path_capacity);
    if (status < 0) return status;
    base = cwd;

    if (copied_path[0] != '/' && directory != EDGE_LINUX_AT_FDCWD) {
        status = kernel_vfs_resolve_fd(directory, &directory_target);
        if (status == -EDGE_LINUX_EOPNOTSUPP)
            return -EDGE_LINUX_ENOTDIR;
        if (status < 0) return status;
        if (!directory_target.inode ||
            (directory_target.inode->mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
        if (!directory_target.resolved_path)
            return -EDGE_LINUX_EIO;
        length = (uint32_t)strlen(directory_target.resolved_path);
        if (length >= context.path_capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        memmove(cwd, directory_target.resolved_path, length + 1u);
        base = cwd;
    }

    return kernel_fs_path_resolve(
        root, base, copied_path, normalization, context.path_capacity,
        output, capacity);
}

int kernel_vfs_resolve_current_path(const char *path, char *output,
                                    uint32_t capacity) {
    kernel_vfs_current_context_t context;

    if (!path || !output || kernel_vfs_context_get(&context) < 0)
        return -EDGE_LINUX_EFAULT;
    return kernel_fs_path_resolve(
        context.root[0] ? context.root : "/",
        context.cwd[0] ? context.cwd : "/", path,
        (char *)context.xattr, context.xattr_capacity,
        output, capacity);
}

static int kernel_vfs_path_at_or_below(const char *path,
                                       const char *root) {
    uint32_t length = 0;

    while (root[length] && path[length] == root[length]) ++length;
    if (root[length]) return 0;
    return length == 1u || !path[length] || path[length] == '/';
}

int kernel_vfs_rebase_pivot_path(const char *new_root,
                                 const char *put_old,
                                 const char *path,
                                 char *output,
                                 uint32_t capacity) {
    static const char detached_old_root[] = "/.edgeos-pivot-old";
    const char *prefix;
    const char *suffix;
    uint32_t new_root_length;
    uint32_t length = 0;

    if (!new_root || !put_old || !path || !output || !capacity ||
        new_root[0] != '/' || put_old[0] != '/' || path[0] != '/')
        return -EDGE_LINUX_EINVAL;
    new_root_length = (uint32_t)strlen(new_root);
    if (kernel_vfs_path_at_or_below(path, new_root)) {
        prefix = "/";
        suffix = path + new_root_length;
    } else {
        prefix = strcmp(new_root, put_old) == 0 ?
            detached_old_root : put_old + new_root_length;
        suffix = path;
    }
    while (prefix[length]) {
        if (length + 1u >= capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        output[length] = prefix[length];
        ++length;
    }
    if (length && output[length - 1u] == '/' && suffix[0] == '/')
        ++suffix;
    while (*suffix) {
        if (length + 1u >= capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        output[length++] = *suffix++;
    }
    if (!length) {
        if (capacity < 2u) return -EDGE_LINUX_ENAMETOOLONG;
        output[length++] = '/';
    }
    output[length] = 0;
    return 0;
}

int kernel_vfs_rebase_pivot_fs_location(const char *new_root,
                                        const char *put_old,
                                        const char *path,
                                        char *output,
                                        uint32_t capacity) {
    /*
     * Linux moves fs_struct root and pwd references that identify the old
     * namespace root onto the new root. Directory descriptors remain ordinary
     * path references and continue to identify the moved tree.
     */
    if (!new_root || !put_old || !path || !output || !capacity ||
        new_root[0] != '/' || put_old[0] != '/' || path[0] != '/')
        return -EDGE_LINUX_EINVAL;
    if (strcmp(path, "/") == 0) {
        if (capacity < 2u) return -EDGE_LINUX_ENAMETOOLONG;
        output[0] = '/';
        output[1] = 0;
        return 0;
    }
    return kernel_vfs_rebase_pivot_path(
        new_root, put_old, path, output, capacity);
}

int kernel_vfs_rebase_move_path(const char *source, const char *target,
                                const char *path, char *output,
                                uint32_t capacity) {
    const char *prefix;
    const char *suffix;
    uint32_t source_length;
    uint32_t length = 0;

    if (!source || !target || !path || !output || !capacity ||
        source[0] != '/' || target[0] != '/' || path[0] != '/')
        return -EDGE_LINUX_EINVAL;
    if (kernel_vfs_path_at_or_below(path, source)) {
        source_length = (uint32_t)strlen(source);
        prefix = target;
        suffix = path + source_length;
    } else {
        prefix = path;
        suffix = "";
    }
    while (*prefix) {
        if (length + 1u >= capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        output[length++] = *prefix++;
    }
    if (length && output[length - 1u] == '/' && suffix[0] == '/')
        ++suffix;
    while (*suffix) {
        if (length + 1u >= capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        output[length++] = *suffix++;
    }
    if (!length) {
        if (capacity < 2u) return -EDGE_LINUX_ENAMETOOLONG;
        output[length++] = '/';
    }
    output[length] = 0;
    return 0;
}

int kernel_vfs_resolve_path(const char *path, int nofollow,
                            kernel_vfs_target_t *target) {
    kernel_vfs_current_context_t context;
    char *resolved;
    int status;

    if (!path || !target || kernel_vfs_context_get(&context) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!path[0]) return -EDGE_LINUX_ENOENT;
    resolved = context.paths[1];
    status = kernel_fs_path_resolve(
        context.root[0] ? context.root : "/",
        context.cwd[0] ? context.cwd : "/", path,
        context.paths[2], context.path_capacity,
        resolved, context.path_capacity);
    if (status < 0) return status;
    status = vfs_path_search_check(
        resolved, context.paths[2], context.path_capacity, 0);
    if (status < 0) return status;

    target->inode = &target->inode_storage;
    target->superblock = 0;
    target->resolved_path = resolved;
    target->linkable_zero_link_inode = 0;
    target->path_only = 0;
    if (nofollow ?
            vfs_resolve_nofollow(
                resolved, target->inode, &target->superblock) < 0 :
            vfs_resolve(
                resolved, target->inode, &target->superblock, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    return 0;
}

int kernel_vfs_pivot_root(const char *new_root, const char *put_old) {
    uint32_t namespace_id;

    if (!new_root || !put_old ||
        arch_vfs_current_mount_namespace(&namespace_id) < 0)
        return -EDGE_LINUX_EINVAL;
    if (vfs_pivot_root(new_root, put_old) < 0)
        return -EDGE_LINUX_EINVAL;
    arch_vfs_rebase_mount_namespace_paths(
        namespace_id, new_root, put_old);
    return 0;
}

int kernel_vfs_truncate_result(int result) {
    if (result == VFS_TRUNCATE_ERR_PERMISSION)
        return -EDGE_LINUX_EPERM;
    if (result == VFS_TRUNCATE_ERR_UNSUPPORTED ||
        result == VFS_TRUNCATE_ERR_INVALID)
        return -EDGE_LINUX_EINVAL;
    return result < 0 ? -EDGE_LINUX_EIO : 0;
}

static int kernel_vfs_truncate_resolved(
    kernel_vfs_target_t *target, uint32_t length, const char *path) {
    int result;

    if (!target || !target->superblock || !target->inode)
        return -EDGE_LINUX_EINVAL;
    if (path && (vfs_mount_flags_for_path(path) & VFS_MOUNT_READONLY))
        return -EDGE_LINUX_EROFS;
    if (path && path[0]) {
        result = kernel_fanotify_pre_access_permission_check(
            path, length, 0u);
        if (result < 0) return result;
    }
    result = kernel_vfs_truncate_inode_transaction(
        target->superblock, target->inode, length);
    if (result < 0) return result;
    if (path && path[0])
        arch_vfs_notify_path(path, KERNEL_INOTIFY_MODIFY);
    return 0;
}

int kernel_vfs_truncate_inode_transaction(vfs_superblock_t *superblock,
                                          vfs_inode_t *inode,
                                          uint32_t length) {
    uint32_t old_length;
    int result;

    if (!superblock || !inode)
        return -EDGE_LINUX_EINVAL;
    old_length = inode->size;
    result = arch_vfs_truncate_prepare(
        superblock, inode, old_length, length);
    if (result < 0) return result;
    result = vfs_truncate_inode(superblock, inode, length);
    if (result < 0) return kernel_vfs_truncate_result(result);
    arch_vfs_truncate_commit(
        superblock, inode, old_length, length);
    return 0;
}

int kernel_vfs_truncate_path(const char *path, kernel_vfs_target_t *target,
                             uint32_t length) {
    if (!path) return -EDGE_LINUX_EINVAL;
    return kernel_vfs_truncate_resolved(target, length, path);
}

int kernel_vfs_truncate_target(kernel_vfs_target_t *target, uint32_t length) {
    return kernel_vfs_truncate_resolved(
        target, length, target ? target->resolved_path : 0);
}

void kernel_vfs_notify_create(const char *path, int directory) {
    uint32_t mask = KERNEL_INOTIFY_CREATE;

    if (!path || !path[0]) return;
    if (directory) mask |= KERNEL_INOTIFY_ISDIR;
    arch_vfs_notify_path(path, mask);
}

void kernel_vfs_notify_attrib(const char *path) {
    if (path && path[0])
        arch_vfs_notify_path(path, KERNEL_INOTIFY_ATTRIB);
}

void kernel_vfs_notify_link(const char *source, const char *destination) {
    if (source && source[0])
        arch_vfs_notify_path(source, KERNEL_INOTIFY_ATTRIB);
    if (destination && destination[0])
        arch_vfs_notify_path(destination, KERNEL_INOTIFY_CREATE);
}

void kernel_vfs_notify_remove(const char *path, int directory) {
    uint32_t mask =
        KERNEL_INOTIFY_DELETE | KERNEL_INOTIFY_DELETE_SELF;

    if (!path || !path[0]) return;
    if (directory) mask |= KERNEL_INOTIFY_ISDIR;
    arch_vfs_notify_path(path, mask);
}

void kernel_vfs_notify_rename(const char *old_path, const char *new_path) {
    if (!old_path || !old_path[0] || !new_path || !new_path[0]) return;
    arch_vfs_notify_move(old_path, new_path);
}
