/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux open policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "fs/cgroupfs.h"
#include "kernel/fanotify.h"
#include "kernel/file_metadata.h"
#include "kernel/inotify.h"
#include "kernel/landlock_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"
#include "vfs/mount_namespace.h"
#include "vfs/path_cache.h"
#include "vfs/vfs.h"

static uint32_t g_vfs_tmpfile_sequence = 1u;

static uint64_t kernel_vfs_landlock_open_access(
    const kernel_vfs_open_request_t *request, uint16_t inode_kind) {
    uint64_t access = 0;
    if (!request || (request->flags & KERNEL_VFS_OPEN_PATH)) return 0;
    if (inode_kind == VFS_INODE_DIR) {
        if (request->access_mode == KERNEL_VFS_OPEN_READ_ONLY ||
            request->access_mode == KERNEL_VFS_OPEN_READ_WRITE)
            access |= EDGE_LINUX_LANDLOCK_ACCESS_FS_READ_DIR;
        return access;
    }
    if (request->access_mode == KERNEL_VFS_OPEN_READ_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE)
        access |= EDGE_LINUX_LANDLOCK_ACCESS_FS_READ_FILE;
    if (request->access_mode == KERNEL_VFS_OPEN_WRITE_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE)
        access |= EDGE_LINUX_LANDLOCK_ACCESS_FS_WRITE_FILE;
    if (request->flags & KERNEL_VFS_OPEN_TRUNCATE)
        access |= EDGE_LINUX_LANDLOCK_ACCESS_FS_TRUNCATE;
    return access;
}

int kernel_vfs_open_check_landlock(kernel_vfs_open_request_t *request,
                                    const char *path, uint16_t inode_kind) {
    int status = kernel_landlock_check_path(
        path, kernel_vfs_landlock_open_access(request, inode_kind));
    if (status < 0) return status;
    request->landlock_access = kernel_landlock_check_path(
        path, EDGE_LINUX_LANDLOCK_ACCESS_FS_TRUNCATE) == 0 ?
        EDGE_LINUX_LANDLOCK_ACCESS_FS_TRUNCATE : 0;
    return 0;
}

static int kernel_vfs_cgroup_device_open(
        const kernel_vfs_open_request_t *request,
        const vfs_inode_t *inode, int *checked) {
    kernel_bpf_cgroup_device_context_t context;
    uint32_t cgroup_id;
    uint16_t kind;
    uint32_t access = 0u;

    if (checked) *checked = 0;
    if (!request || !inode ||
        (request->flags & KERNEL_VFS_OPEN_PATH))
        return 0;
    kind = inode->mode & 0xf000u;
    if (kind != VFS_INODE_CHR && kind != VFS_INODE_BLK)
        return 0;
    if (checked) *checked = 1;
    if (request->access_mode == KERNEL_VFS_OPEN_READ_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE)
        access |= KERNEL_BPF_DEVCG_ACC_READ;
    if (request->access_mode == KERNEL_VFS_OPEN_WRITE_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE)
        access |= KERNEL_BPF_DEVCG_ACC_WRITE;
    if (kernel_current_cgroup_id(&cgroup_id) < 0)
        return -EDGE_LINUX_ESRCH;
    memset(&context, 0, sizeof(context));
    context.access_type = (access << 16) |
        (kind == VFS_INODE_CHR ? KERNEL_BPF_DEVCG_DEV_CHAR :
                                KERNEL_BPF_DEVCG_DEV_BLOCK);
    context.major = kernel_file_device_major(inode->rdev);
    context.minor = kernel_file_device_minor(inode->rdev);
    return cgroupfs_bpf_device_allowed(cgroup_id, &context) ?
           0 : -EDGE_LINUX_EPERM;
}

#define EDGE_RESOLVE_NO_XDEV       0x01u
#define EDGE_RESOLVE_NO_MAGICLINKS 0x02u
#define EDGE_RESOLVE_NO_SYMLINKS   0x04u
#define EDGE_RESOLVE_BENEATH       0x08u
#define EDGE_RESOLVE_IN_ROOT       0x10u
#define EDGE_RESOLVE_CACHED        0x20u

static int kernel_vfs_path_pop(char *path) {
    uint32_t length;

    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(path);
    while (length > 1u && path[length - 1u] == '/') --length;
    while (length > 1u && path[length - 1u] != '/') --length;
    if (length > 1u) --length;
    path[length] = 0;
    return 0;
}

static int kernel_vfs_path_append_component(
    char *path, uint32_t capacity, const char *component,
    uint32_t component_length) {
    uint32_t length;

    if (!path || !capacity || !component || !component_length)
        return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(path);
    if (length + (length == 1u ? 0u : 1u) + component_length + 1u >
        capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    if (length != 1u) path[length++] = '/';
    memcpy(path + length, component, component_length);
    path[length + component_length] = 0;
    return 0;
}

static int kernel_vfs_path_is_beneath(const char *root, const char *path) {
    uint32_t length;

    if (!root || !path || root[0] != '/' || path[0] != '/') return 0;
    if (root[1] == 0) return 1;
    length = (uint32_t)strlen(root);
    return strncmp(root, path, length) == 0 &&
           (path[length] == 0 || path[length] == '/');
}

static int kernel_vfs_decimal_component(const char **cursor) {
    const char *position;

    if (!cursor || !*cursor) return 0;
    position = *cursor;
    if (*position < '0' || *position > '9') return 0;
    while (*position >= '0' && *position <= '9') ++position;
    if (*position != '/') return 0;
    *cursor = position + 1;
    return 1;
}

static int kernel_vfs_path_is_proc_magic_link(const char *path) {
    const char *cursor;

    if (!path || strncmp(path, "/proc/", 6u) != 0) return 0;
    cursor = path + 6u;
    if (strncmp(cursor, "self/fd/", 8u) == 0 ||
        strncmp(cursor, "thread-self/fd/", 15u) == 0)
        return 1;
    if (strncmp(cursor, "self/task/", 10u) == 0) {
        cursor += 10u;
        return kernel_vfs_decimal_component(&cursor) &&
               strncmp(cursor, "fd/", 3u) == 0;
    }
    if (!kernel_vfs_decimal_component(&cursor)) return 0;
    if (strncmp(cursor, "fd/", 3u) == 0) return 1;
    if (strncmp(cursor, "task/", 5u) != 0) return 0;
    cursor += 5u;
    return kernel_vfs_decimal_component(&cursor) &&
           strncmp(cursor, "fd/", 3u) == 0;
}

static int kernel_vfs_validate_resolution(
    const kernel_vfs_open_request_t *request, char *base, char *walk,
    char *canonical, uint32_t capacity) {
    kernel_vfs_current_context_t context;
    kernel_vfs_target_t directory_target;
    vfs_inode_t inode;
    vfs_superblock_t *base_superblock = 0;
    vfs_superblock_t *superblock = 0;
    const char *resolution_root;
    const char *cursor;
    uint32_t base_length;
    uint32_t depth = 0;
    int final_symlink = 0;
    int intermediate_symlink = 0;
    uint64_t flags;
    int status;

    if (!request || !base || !walk || !canonical || !capacity)
        return -EDGE_LINUX_EINVAL;
    flags = request->resolve_flags;
    if (!flags) return 0;
    if ((flags & EDGE_RESOLVE_BENEATH) && request->path[0] == '/')
        return -EDGE_LINUX_EXDEV;
    if (arch_vfs_current_context(&context) < 0 || !context.root ||
        !context.cwd)
        return -EDGE_LINUX_EIO;

    if (request->directory != EDGE_LINUX_AT_FDCWD &&
        ((flags & EDGE_RESOLVE_IN_ROOT) || request->path[0] != '/')) {
        status = kernel_vfs_resolve_fd(request->directory, &directory_target);
        if (status < 0) return status;
        if (!directory_target.inode ||
            (directory_target.inode->mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
        if (!directory_target.resolved_path) return -EDGE_LINUX_EIO;
        base_length = (uint32_t)strlen(directory_target.resolved_path);
        if (base_length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
        memcpy(base, directory_target.resolved_path, base_length + 1u);
    } else if ((flags & EDGE_RESOLVE_IN_ROOT) ||
               request->path[0] != '/') {
        base_length = (uint32_t)strlen(context.cwd);
        if (base_length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
        memcpy(base, context.cwd, base_length + 1u);
    } else {
        base_length = (uint32_t)strlen(context.root);
        if (base_length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
        memcpy(base, context.root, base_length + 1u);
    }
    resolution_root = (flags & EDGE_RESOLVE_IN_ROOT) ? base : context.root;
    if (flags & (EDGE_RESOLVE_BENEATH | EDGE_RESOLVE_NO_XDEV |
                 EDGE_RESOLVE_IN_ROOT)) {
        if (vfs_resolve_canonical(
                base, canonical, capacity, &inode, &superblock) == 0) {
            base_length = (uint32_t)strlen(canonical);
            if (base_length >= capacity)
                return -EDGE_LINUX_ENAMETOOLONG;
            memcpy(base, canonical, base_length + 1u);
        }
        if (flags & EDGE_RESOLVE_IN_ROOT) resolution_root = base;
    }
    base_length = (uint32_t)strlen(base);
    if (base_length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(walk, base, base_length + 1u);
    if ((flags & EDGE_RESOLVE_NO_XDEV) &&
        vfs_resolve(base, &inode, &base_superblock, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;

    cursor = request->path;
    while (*cursor == '/') ++cursor;
    while (*cursor) {
        const char *component = cursor;
        uint32_t length = 0;

        while (cursor[length] && cursor[length] != '/') ++length;
        cursor += length;
        while (*cursor == '/') ++cursor;
        if (!length || (length == 1u && component[0] == '.')) continue;
        if (length == 2u && component[0] == '.' && component[1] == '.') {
            if ((flags & EDGE_RESOLVE_BENEATH) && !depth)
                return -EDGE_LINUX_EXDEV;
            if ((flags & EDGE_RESOLVE_IN_ROOT) && !depth)
                continue;
            if (depth) --depth;
            status = kernel_vfs_path_pop(walk);
            if (status < 0) return status;
            continue;
        }
        ++depth;
        status = kernel_vfs_path_append_component(
            walk, capacity, component, length);
        if (status < 0) return status;
        superblock = 0;
        if (flags & EDGE_RESOLVE_CACHED) {
            int negative = 0;
            if (!vfs_resolve_cached(
                    walk, &inode, &superblock, &negative))
                return -EDGE_LINUX_EAGAIN;
            if (negative) return -EDGE_LINUX_ENOENT;
        } else if (vfs_resolve_nofollow(
                       walk, &inode, &superblock) < 0) {
            continue;
        }
        if ((inode.mode & 0xf000u) == VFS_INODE_LNK) {
            if (*cursor) intermediate_symlink = 1;
            else final_symlink = 1;
            if (flags & EDGE_RESOLVE_NO_SYMLINKS)
                return -EDGE_LINUX_ELOOP;
            if (flags & EDGE_RESOLVE_CACHED)
                return -EDGE_LINUX_EAGAIN;
        }
        if ((flags & EDGE_RESOLVE_NO_XDEV) &&
            (!superblock || !base_superblock ||
             superblock->mount_id != base_superblock->mount_id))
            return -EDGE_LINUX_EXDEV;
    }
    if ((flags & EDGE_RESOLVE_NO_MAGICLINKS) &&
        kernel_vfs_path_is_proc_magic_link(walk) &&
        !(final_symlink &&
          (request->flags & KERNEL_VFS_OPEN_PATH) &&
          (request->flags & KERNEL_VFS_OPEN_NOFOLLOW)))
        return -EDGE_LINUX_ELOOP;
    if (final_symlink &&
        (request->flags & KERNEL_VFS_OPEN_NOFOLLOW)) {
        if ((flags & EDGE_RESOLVE_BENEATH) &&
            !kernel_vfs_path_is_beneath(base, walk))
            return -EDGE_LINUX_EXDEV;
        if ((flags & EDGE_RESOLVE_NO_XDEV) &&
            (!superblock || !base_superblock ||
             superblock->mount_id != base_superblock->mount_id))
            return -EDGE_LINUX_EXDEV;
        return 0;
    }
    if (!(flags & EDGE_RESOLVE_CACHED) &&
        (flags & (EDGE_RESOLVE_BENEATH | EDGE_RESOLVE_NO_XDEV |
                  EDGE_RESOLVE_IN_ROOT))) {
        vfs_superblock_t *canonical_superblock = 0;
        const char *checked_path = canonical;
        int missing_final = 0;

        status = vfs_resolve_canonical_rooted(
            walk, resolution_root, canonical, capacity, &inode,
            &canonical_superblock);
        if (status < 0) {
            char final_leaf[VFS_NAME_MAX];
            uint32_t length = (uint32_t)strlen(walk);
            uint32_t leaf_start = length;
            uint32_t leaf_length;
            if ((flags & EDGE_RESOLVE_IN_ROOT) &&
                (intermediate_symlink ||
                 (final_symlink &&
                  !(request->flags & KERNEL_VFS_OPEN_NOFOLLOW))))
                return -EDGE_LINUX_ENOENT;
            if (length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
            while (leaf_start > 0u && walk[leaf_start - 1u] != '/')
                --leaf_start;
            leaf_length = length - leaf_start;
            if (!leaf_length || leaf_length >= sizeof(final_leaf))
                return -EDGE_LINUX_ENOENT;
            memcpy(final_leaf, walk + leaf_start, leaf_length);
            final_leaf[leaf_length] = 0;
            memcpy(canonical, walk, length + 1u);
            if (kernel_vfs_path_pop(canonical) < 0)
                return -EDGE_LINUX_EINVAL;
            status = vfs_resolve_canonical_rooted(
                canonical, resolution_root, walk, capacity, &inode,
                &canonical_superblock);
            checked_path = walk;
            if (status == 0) {
                status = kernel_vfs_path_append_component(
                    walk, capacity, final_leaf, leaf_length);
                if (status < 0) return status;
                missing_final = 1;
            } else {
                return -EDGE_LINUX_ENOENT;
            }
        }
        if (status == 0 && (flags & EDGE_RESOLVE_BENEATH) &&
            !kernel_vfs_path_is_beneath(base, checked_path))
            return -EDGE_LINUX_EXDEV;
        if (status == 0 && (flags & EDGE_RESOLVE_NO_XDEV) &&
            (!canonical_superblock || !base_superblock ||
             canonical_superblock->mount_id != base_superblock->mount_id))
            return -EDGE_LINUX_EXDEV;
        if (status == 0 && (flags & EDGE_RESOLVE_IN_ROOT) &&
            !missing_final &&
            !(request->flags & KERNEL_VFS_OPEN_NOFOLLOW)) {
            uint32_t length = (uint32_t)strlen(canonical);
            if (length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
            memcpy(walk, canonical, length + 1u);
        }
    }
    return 0;
}

static int kernel_vfs_tmpfile_path(
    const char *directory, char *path, uint32_t capacity) {
    static const char prefix[] = ".edgeos-tmp-";
    static const char hexadecimal[] = "0123456789abcdef";
    uint32_t sequence = __atomic_fetch_add(
        &g_vfs_tmpfile_sequence, 1u, __ATOMIC_RELAXED);
    uint32_t directory_length;
    uint32_t length;

    if (!directory || !path || !capacity) return -EDGE_LINUX_EINVAL;
    directory_length = (uint32_t)strlen(directory);
    if (!directory_length) return -EDGE_LINUX_EINVAL;
    length = directory_length;
    if (length + (directory[length - 1u] == '/' ? 0u : 1u) +
        sizeof(prefix) - 1u + 8u + 1u > capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(path, directory, directory_length);
    if (path[length - 1u] != '/') path[length++] = '/';
    memcpy(path + length, prefix, sizeof(prefix) - 1u);
    length += (uint32_t)sizeof(prefix) - 1u;
    for (uint32_t index = 0; index < 8u; ++index)
        path[length + index] =
            hexadecimal[(sequence >> ((7u - index) * 4u)) & 0xfu];
    path[length + 8u] = 0;
    return 0;
}

static uint16_t kernel_vfs_created_mode(uint16_t requested) {
    uint16_t mask = (uint16_t)(kernel_current_umask() & 0777u);
    return (uint16_t)(
        (requested & 07000u) |
        ((requested & 0777u) & (uint16_t)~mask));
}

static int kernel_vfs_split_parent(
    const char *path, char *parent, char *leaf, uint32_t capacity) {
    uint32_t length;
    uint32_t slash;
    uint32_t leaf_length;

    if (!path || path[0] != '/' || !parent || !leaf || capacity < 2u)
        return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(path);
    while (length > 1u && path[length - 1u] == '/') --length;
    slash = length;
    while (slash > 0u && path[slash - 1u] != '/') --slash;
    if (!slash || slash == length) return -EDGE_LINUX_EINVAL;
    leaf_length = length - slash;
    if (leaf_length >= VFS_NAME_MAX || leaf_length >= capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(leaf, path + slash, leaf_length);
    leaf[leaf_length] = 0;
    if (slash <= 1u) {
        parent[0] = '/';
        parent[1] = 0;
        return 0;
    }
    if (slash > capacity) return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(parent, path, slash - 1u);
    parent[slash - 1u] = 0;
    return 0;
}

static int kernel_vfs_create_regular(
    const char *path, uint16_t mode, char *parent_path, char *leaf,
    uint32_t capacity, vfs_inode_t *inode,
    vfs_superblock_t **superblock) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_superblock_t *resolved_superblock = 0;
    int status;

    if (!path || !inode || !superblock)
        return -EDGE_LINUX_EINVAL;
    if (vfs_resolve_nofollow(path, &existing, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    status = kernel_vfs_split_parent(
        path, parent_path, leaf, capacity);
    if (status < 0) return status;
    if (vfs_resolve(
            parent_path, &parent, &resolved_superblock, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    if ((parent.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (vfs_mount_flags_for_path(parent_path) & VFS_MOUNT_READONLY)
        return -EDGE_LINUX_EROFS;
    if (vfs_permission_check(&parent, 3) < 0)
        return -EDGE_LINUX_EACCES;
    if (!resolved_superblock || !resolved_superblock->ops ||
        !resolved_superblock->ops->create)
        return -EDGE_LINUX_EACCES;
    status = resolved_superblock->ops->create(
        resolved_superblock, &parent, leaf,
        (uint16_t)(VFS_INODE_FILE | (mode & 07777u)), inode);
    if (status < 0) return kernel_vfs_path_result(status);
    if (vfs_sync_mutation_if_required(
            resolved_superblock, 1) < 0)
        return -EDGE_LINUX_EIO;
    *superblock = resolved_superblock;
    vfs_path_cache_runtime_invalidate_namespace(
        vfs_mount_namespace_current());
    return 0;
}

static int kernel_vfs_open_resolve(
    const char *path, int nofollow, kernel_vfs_target_t *target) {
    int found;

    if (!path || !target) return -EDGE_LINUX_EFAULT;
    memset(target, 0, sizeof(*target));
    target->inode = &target->inode_storage;
    target->resolved_path = path;
    found = nofollow ?
        vfs_resolve_nofollow(
            path, target->inode, &target->superblock) == 0 :
        vfs_resolve(
            path, target->inode, &target->superblock, 0, 0) == 0;
    return found ? 0 : -EDGE_LINUX_ENOENT;
}

static int64_t kernel_vfs_open_tmpfile(
    const kernel_vfs_open_request_t *request, const char *directory,
    char *staging_path, char *parent_path, char *leaf,
    uint32_t capacity) {
    kernel_vfs_target_t directory_target;
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    uint16_t mode;
    int descriptor;
    int status;
    kernel_vfs_open_request_t tmpfile_request;

    status = kernel_landlock_check_path(
        directory, EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_REG |
                       EDGE_LINUX_LANDLOCK_ACCESS_FS_WRITE_FILE);
    if (status < 0) return status;

    if (request->access_mode == KERNEL_VFS_OPEN_READ_ONLY)
        return -EDGE_LINUX_EINVAL;
    status = kernel_vfs_open_resolve(
        directory, 0, &directory_target);
    if (status < 0 ||
        (directory_target.inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (!directory_target.superblock ||
        !directory_target.superblock->ops ||
        !directory_target.superblock->ops->create ||
        !directory_target.superblock->ops->unlink)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (vfs_mount_flags_for_path(directory) & VFS_MOUNT_READONLY)
        return -EDGE_LINUX_EROFS;
    mode = kernel_vfs_created_mode(request->mode);
    tmpfile_request = *request;
    tmpfile_request.landlock_access =
        EDGE_LINUX_LANDLOCK_ACCESS_FS_TRUNCATE;
    tmpfile_request.linkable_zero_link_inode =
        (request->flags & KERNEL_VFS_OPEN_EXCLUSIVE) == 0;
    for (uint32_t attempt = 0; attempt < 64u; ++attempt) {
        status = kernel_vfs_tmpfile_path(
            directory, staging_path, capacity);
        if (status < 0) return status;
        status = kernel_vfs_create_regular(
            staging_path, mode, parent_path, leaf, capacity,
            &inode, &superblock);
        if (status == -EDGE_LINUX_EEXIST) continue;
        if (status < 0) return status;
        descriptor = arch_vfs_open_install_regular(
            &tmpfile_request, staging_path, &inode, superblock, 1);
        if (descriptor < 0)
            (void)vfs_unlink(staging_path);
        return descriptor;
    }
    return -EDGE_LINUX_EIO;
}

static int kernel_vfs_open_detached_proc_directory(
    const kernel_vfs_open_request_t *request, kernel_vfs_target_t *target,
    char *superblock_path, char *descriptor_path, uint32_t capacity) {
    kernel_vfs_target_t directory;
    vfs_inode_t visible_inode;
    vfs_superblock_t *visible_superblock = 0;
    const char *proc_suffix = 0;
    uint32_t base_length;
    uint32_t path_length;

    if (!request || !target || !superblock_path || !descriptor_path ||
        !capacity || request->directory == EDGE_LINUX_AT_FDCWD ||
        !request->path || request->path[0] == '/' ||
        (request->flags & (KERNEL_VFS_OPEN_CREATE |
                           KERNEL_VFS_OPEN_TMPFILE |
                           KERNEL_VFS_OPEN_NOFOLLOW)))
        return 0;
    if (kernel_vfs_resolve_fd(request->directory, &directory) < 0 ||
        !directory.inode || !directory.superblock ||
        !directory.resolved_path ||
        (directory.inode->mode & 0xf000u) != VFS_INODE_DIR ||
        strcmp(directory.superblock->fs_name, "proc") != 0)
        return 0;
    if (vfs_resolve(directory.resolved_path, &visible_inode,
                    &visible_superblock, 0, 0) == 0 &&
        vfs_inode_same_object(directory.superblock, directory.inode,
                              visible_superblock, &visible_inode))
        return 0;

    for (const char *cursor = directory.resolved_path; *cursor; ++cursor) {
        if (cursor[0] == '/' && cursor[1] == 'p' && cursor[2] == 'r' &&
            cursor[3] == 'o' && cursor[4] == 'c' &&
            (cursor[5] == 0 || cursor[5] == '/'))
            proc_suffix = cursor + 5;
    }
    if (!proc_suffix) return -EDGE_LINUX_ENOENT;
    base_length = (uint32_t)strlen(proc_suffix);
    path_length = (uint32_t)strlen(request->path);
    if (base_length + path_length + 2u > capacity ||
        path_length + 6u > capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    if (base_length) memcpy(superblock_path, proc_suffix, base_length);
    else superblock_path[0] = 0;
    if (!base_length || superblock_path[base_length - 1u] != '/')
        superblock_path[base_length++] = '/';
    memcpy(superblock_path + base_length, request->path, path_length + 1u);
    if (vfs_resolve_superblock_path(
            directory.superblock, superblock_path,
            &target->inode_storage) < 0)
        return -EDGE_LINUX_ENOENT;

    memcpy(descriptor_path, "/proc", 5u);
    memcpy(descriptor_path + 5u, superblock_path,
           strlen(superblock_path) + 1u);
    target->inode = &target->inode_storage;
    target->superblock = directory.superblock;
    target->resolved_path = descriptor_path;
    target->path_only = (request->flags & KERNEL_VFS_OPEN_PATH) != 0;
    return 1;
}

static int kernel_vfs_open_detached_mount_root(
    const kernel_vfs_open_request_t *request, kernel_vfs_target_t *target,
    char *superblock_path, char *descriptor_path, uint32_t capacity) {
    kernel_vfs_target_t directory;
    vfs_inode_t visible_inode;
    vfs_superblock_t *visible_superblock = 0;
    const char *cursor;
    uint32_t path_length;

    if (!request || !target || !superblock_path || !descriptor_path ||
        !capacity || request->directory == EDGE_LINUX_AT_FDCWD ||
        !request->path || request->path[0] == '/' ||
        (request->flags & (KERNEL_VFS_OPEN_CREATE |
                           KERNEL_VFS_OPEN_TMPFILE |
                           KERNEL_VFS_OPEN_NOFOLLOW)))
        return 0;
    if (kernel_vfs_resolve_fd(request->directory, &directory) < 0 ||
        !directory.inode || !directory.superblock ||
        !directory.resolved_path ||
        (directory.inode->mode & 0xf000u) != VFS_INODE_DIR ||
        !vfs_inode_same_object(directory.superblock, directory.inode,
                               directory.superblock,
                               &directory.superblock->root))
        return 0;
    if (vfs_resolve(directory.resolved_path, &visible_inode,
                    &visible_superblock, 0, 0) == 0 &&
        vfs_inode_same_object(directory.superblock, directory.inode,
                              visible_superblock, &visible_inode))
        return 0;

    cursor = request->path;
    while (*cursor) {
        const char *component;
        uint32_t component_length = 0;

        while (*cursor == '/') ++cursor;
        if (!*cursor) break;
        component = cursor;
        while (*cursor && *cursor != '/') {
            ++component_length;
            ++cursor;
        }
        if (component_length == 2u && component[0] == '.' &&
            component[1] == '.')
            return 0;
    }

    path_length = (uint32_t)strlen(request->path);
    if (path_length + 2u > capacity) return -EDGE_LINUX_ENAMETOOLONG;
    superblock_path[0] = '/';
    memcpy(superblock_path + 1u, request->path, path_length + 1u);
    if (vfs_resolve_superblock_path(
            directory.superblock, superblock_path,
            &target->inode_storage) < 0)
        return -EDGE_LINUX_ENOENT;

    path_length = (uint32_t)strlen(directory.resolved_path);
    if (path_length + (path_length > 1u ? 1u : 0u) +
            strlen(request->path) + 1u > capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(descriptor_path, directory.resolved_path, path_length);
    if (path_length > 1u) descriptor_path[path_length++] = '/';
    memcpy(descriptor_path + path_length, request->path,
           strlen(request->path) + 1u);
    target->inode = &target->inode_storage;
    target->superblock = directory.superblock;
    target->resolved_path = descriptor_path;
    target->path_only = (request->flags & KERNEL_VFS_OPEN_PATH) != 0;
    return 1;
}

int64_t kernel_vfs_open_at(const kernel_vfs_open_request_t *request) {
    kernel_vfs_mount_scratch_t scratch;
    kernel_vfs_open_request_t stable_request;
    kernel_vfs_target_t target;
    const char *path;
    int64_t special_result;
    int64_t magic_result;
    int handled = 0;
    int device_checked = 0;
    int created = 0;
    int descriptor;
    int status;

    if (!request) return -EDGE_LINUX_EIO;
    if (!request->path) return -EDGE_LINUX_EFAULT;
    /* A directory descriptor remains usable before its mount is attached.
     * Resolve the self component from its retained inode, not a global path. */
    if (request->directory != EDGE_LINUX_AT_FDCWD &&
        strcmp(request->path, ".") == 0 &&
        !(request->flags & KERNEL_VFS_OPEN_TMPFILE)) {
        status = kernel_vfs_resolve_fd(request->directory, &target);
        if (status < 0) return status;
        if (!target.inode || !target.superblock ||
            (target.inode->mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
        if (target.resolved_path && !target.resolved_path[0]) {
            if ((request->flags & (KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE)) ==
                (KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE))
                return -EDGE_LINUX_EEXIST;
            if (!(request->flags & KERNEL_VFS_OPEN_PATH) &&
                (request->access_mode != KERNEL_VFS_OPEN_READ_ONLY ||
                 (request->flags & KERNEL_VFS_OPEN_CREATE)))
                return -EDGE_LINUX_EISDIR;
            if (vfs_permission_check_with_acl(target.superblock, target.inode,
                    1u | ((request->flags & KERNEL_VFS_OPEN_PATH) ? 0u : 4u)) < 0)
                return -EDGE_LINUX_EACCES;
            return arch_vfs_open_install_regular(request, "", target.inode,
                                                  target.superblock, 0);
        }
    }
    status = kernel_vfs_current_mount_scratch(&scratch);
    if (status < 0) return status;
    {
        uint32_t length = (uint32_t)strlen(request->path);
        if (length >= scratch.capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        memmove(scratch.workspace, request->path, length + 1u);
        stable_request = *request;
        stable_request.path = scratch.workspace;
        request = &stable_request;
    }
    status = kernel_vfs_open_detached_mount_root(
        request, &target, scratch.data, scratch.target, scratch.capacity);
    if (status < 0) return status;
    if (status > 0) {
        path = scratch.target;
        goto target_resolved;
    }
    status = kernel_vfs_open_detached_proc_directory(
        request, &target, scratch.data, scratch.target, scratch.capacity);
    if (status < 0) return status;
    if (status > 0) {
        path = scratch.target;
        goto target_resolved;
    }
    status = kernel_vfs_validate_resolution(
        request, scratch.target, scratch.data, scratch.source,
        scratch.capacity);
    if (status < 0) return status;
    if (request->resolve_flags) {
        uint32_t length = (uint32_t)strlen(scratch.data);
        if (length >= scratch.capacity)
            return -EDGE_LINUX_ENAMETOOLONG;
        memmove(scratch.workspace, scratch.data, length + 1u);
    } else {
        status = kernel_vfs_resolve_at_path(
            request->directory, request->path,
            scratch.workspace, scratch.capacity);
        if (status < 0) return status;
    }
    if (strncmp(scratch.workspace, "/dev/", 5u) == 0) {
        vfs_inode_t early_inode;
        if (vfs_resolve(scratch.workspace, &early_inode, 0, 0, 0) == 0) {
            status = kernel_vfs_cgroup_device_open(
                request, &early_inode, &device_checked);
            if (status < 0) return status;
        }
    }
    magic_result = kernel_vfs_open_magic_fd(
        request, scratch.workspace, &handled);
    if (handled || magic_result < 0) return magic_result;
    special_result = arch_vfs_open_special(
        request, scratch.workspace, &handled);
    if (handled) {
        if (special_result >= 0)
            arch_vfs_notify_path(
                scratch.workspace, KERNEL_INOTIFY_OPEN);
        return special_result;
    }
    if (special_result < 0) return special_result;
    status = vfs_path_search_check(
        scratch.workspace, scratch.data, scratch.capacity, 0);
    if (status < 0) return status;
    path = scratch.workspace;

    if (request->flags & KERNEL_VFS_OPEN_TMPFILE)
        return kernel_vfs_open_tmpfile(
            request, path, scratch.data, scratch.source,
            scratch.target, scratch.capacity);

    status = kernel_vfs_open_resolve(
        path, (request->flags & KERNEL_VFS_OPEN_NOFOLLOW) != 0,
        &target);
    if (status < 0) {
        uint16_t mode;
        if (!(request->flags & KERNEL_VFS_OPEN_CREATE))
            return status;
        {
            vfs_inode_t link;
            if (vfs_resolve_nofollow(path, &link, 0) == 0 &&
                (link.mode & 0xf000u) == VFS_INODE_LNK) {
                kernel_vfs_current_context_t context;
                if (request->flags & KERNEL_VFS_OPEN_EXCLUSIVE)
                    return -EDGE_LINUX_EEXIST;
                if (request->flags & KERNEL_VFS_OPEN_NOFOLLOW)
                    return -EDGE_LINUX_ELOOP;
                if (arch_vfs_current_context(&context) < 0 || !context.root)
                    return -EDGE_LINUX_EIO;
                scratch.source[0] = 0;
                (void)vfs_resolve_canonical_rooted(
                    path, context.root, scratch.source, scratch.capacity,
                    0, 0);
                if (!scratch.source[0]) return -EDGE_LINUX_ENOENT;
                /* Check policy against the destination, not the link name. */
                memmove(scratch.workspace, scratch.source,
                        strlen(scratch.source) + 1u);
                path = scratch.workspace;
                status = vfs_path_search_check(
                    path, scratch.data, scratch.capacity, 0);
                if (status < 0) return status;
            }
        }
        status = kernel_landlock_check_path(
            path, EDGE_LINUX_LANDLOCK_ACCESS_FS_MAKE_REG |
                      kernel_vfs_landlock_open_access(
                          request, VFS_INODE_FILE));
        if (status < 0) return status;
        mode = kernel_vfs_created_mode(request->mode);
        status = kernel_vfs_create_regular(
            path, mode, scratch.source, scratch.data, scratch.capacity,
            &target.inode_storage, &target.superblock);
        if (status < 0) return status;
        target.inode = &target.inode_storage;
        target.resolved_path = path;
        created = 1;
    } else if ((request->flags &
                (KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE)) ==
               (KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE)) {
        return -EDGE_LINUX_EEXIST;
    }

target_resolved:
    if (!target.superblock &&
        !(request->flags & KERNEL_VFS_OPEN_PATH))
        return -EDGE_LINUX_ENOENT;
    if ((target.inode->mode & 0xf000u) == VFS_INODE_LNK &&
        !(request->flags & KERNEL_VFS_OPEN_PATH))
        return -EDGE_LINUX_ELOOP;
    if ((request->flags & KERNEL_VFS_OPEN_DIRECTORY) &&
        (target.inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (!(request->flags & KERNEL_VFS_OPEN_PATH) &&
        (target.inode->mode & 0xf000u) == VFS_INODE_DIR &&
        request->access_mode != KERNEL_VFS_OPEN_READ_ONLY)
        return -EDGE_LINUX_EISDIR;
    if (!device_checked) {
        status = kernel_vfs_cgroup_device_open(
            request, target.inode, &device_checked);
        if (status < 0) return status;
    }
    if (!(request->flags & KERNEL_VFS_OPEN_PATH) &&
        (target.inode->mode & 0xf000u) == VFS_INODE_FILE &&
        request->access_mode != KERNEL_VFS_OPEN_READ_ONLY &&
        target.superblock &&
        (vfs_mount_flags_for_path(path) & VFS_MOUNT_READONLY))
        return -EDGE_LINUX_EROFS;
    if (!(request->flags & KERNEL_VFS_OPEN_PATH) &&
        (target.inode->mode & 0xf000u) == VFS_INODE_FILE &&
        request->access_mode != KERNEL_VFS_OPEN_READ_ONLY) {
        if (target.inode->metadata_flags & VFS_FILE_XFLAG_IMMUTABLE)
            return -EDGE_LINUX_EPERM;
        if ((target.inode->metadata_flags & VFS_FILE_XFLAG_APPEND) &&
            !(request->flags & KERNEL_VFS_OPEN_APPEND))
            return -EDGE_LINUX_EPERM;
    }
    status = kernel_vfs_open_access_mask(request, created);
    if (status && vfs_permission_check_with_acl(
                      target.superblock, target.inode, status) < 0)
        return -EDGE_LINUX_EACCES;
    status = kernel_vfs_open_check_landlock(
        &stable_request, path, target.inode->mode & 0xf000u);
    if (status < 0) return status;
    if (!created && !(request->flags & KERNEL_VFS_OPEN_PATH)) {
        uint64_t fanotify_mask = KERNEL_FAN_OPEN_PERM;
        if ((target.inode->mode & 0xf000u) == VFS_INODE_DIR)
            fanotify_mask |= KERNEL_FAN_ONDIR;
        status = kernel_fanotify_permission_check(path, fanotify_mask);
        if (status < 0) return status;
    }
    if (!created && !(request->flags & KERNEL_VFS_OPEN_PATH) &&
        (request->flags & KERNEL_VFS_OPEN_TRUNCATE) &&
        (target.inode->mode & 0xf000u) == VFS_INODE_FILE) {
        status = kernel_vfs_truncate_target(&target, 0);
        if (status < 0) return status;
    }

    descriptor = arch_vfs_open_install_regular(
        request, path, target.inode, target.superblock, 0);
    if (descriptor < 0) return descriptor;
    if (created) arch_vfs_notify_path(path, KERNEL_INOTIFY_CREATE);
    arch_vfs_notify_path(path, KERNEL_INOTIFY_OPEN);
    return descriptor;
}
