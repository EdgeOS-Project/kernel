/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent mount topology operations.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/vfs.h"

#include "string.h"
#include "vfs/mount_namespace.h"
#include "vfs/path_cache.h"

static volatile unsigned char g_mount_topology_lock;

static void mount_topology_lock(void) {
    while (__atomic_test_and_set(
            &g_mount_topology_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("" ::: "memory");
    }
}

static void mount_topology_unlock(void) {
    __atomic_clear(&g_mount_topology_lock, __ATOMIC_RELEASE);
}

static int mount_path_is_at_or_below(const char *path, const char *root) {
    uint32_t index = 0;
    if (!path || !root || path[0] != '/' || root[0] != '/') return 0;
    while (root[index] && path[index] == root[index]) ++index;
    if (root[index]) return 0;
    if (index == 1u && root[0] == '/') return 1;
    return path[index] == 0 || path[index] == '/';
}

static int mount_has_ancestor(const vfs_mount_table_t *table,
                              const vfs_superblock_t *mount,
                              uint64_t ancestor_id) {
    uint64_t parent_id;
    if (!table || !mount || !ancestor_id) return 0;
    parent_id = mount->parent_mount_id;
    for (int depth = 0; depth < table->mount_count && parent_id; ++depth) {
        const vfs_superblock_t *parent = 0;
        if (parent_id == ancestor_id) return 1;
        for (int index = 0; index < table->mount_count; ++index) {
            const vfs_superblock_t *candidate =
                vfs_mount_table_at_const(table, (uint32_t)index);
            if (!candidate || candidate->mount_id != parent_id) continue;
            parent = candidate;
            break;
        }
        if (!parent || parent->parent_mount_id == parent_id) break;
        parent_id = parent->parent_mount_id;
    }
    return 0;
}

static vfs_superblock_t *find_visible_mount(vfs_mount_table_t *table,
                                            const char *path) {
    vfs_superblock_t *current = 0;
    int current_index = -1;
    if (!table || !path || path[0] != '/') return 0;
    for (int index = 0; index < table->mount_count; ++index) {
        vfs_superblock_t *candidate =
            vfs_mount_table_at(table, (uint32_t)index);
        if (!candidate) continue;
        if (!candidate->parent_mount_id &&
            strcmp(candidate->mountpoint, "/") == 0) {
            current = candidate;
            current_index = index;
        }
    }
    if (!current) return 0;
    for (int depth = 0; depth < table->mount_count; ++depth) {
        int child = -1;
        for (int index = 0; index < table->mount_count; ++index) {
            vfs_superblock_t *candidate =
                vfs_mount_table_at(table, (uint32_t)index);
            uint32_t length;
            if (!candidate || index == current_index ||
                candidate->parent_mount_id != current->mount_id)
                continue;
            length = (uint32_t)strlen(candidate->mountpoint);
            if (strncmp(path, candidate->mountpoint, length) != 0 ||
                !(path[length] == 0 || path[length] == '/' || length == 1u))
                continue;
            child = index;
        }
        if (child < 0) break;
        current = vfs_mount_table_at(table, (uint32_t)child);
        current_index = child;
    }
    return current;
}

uint32_t vfs_mount_flags_for_path(const char *path) {
    vfs_superblock_t *mount = find_visible_mount(
        vfs_mount_namespace_active_table(), path);
    return mount ? mount->mount_flags : 0;
}

static int copy_rebased_mountpoint(char destination[VFS_PATH_MAX],
                                   const char *target, const char *suffix) {
    uint32_t output = 0;
    uint32_t input = 0;
    while (target[output]) {
        if (output + 1u >= VFS_PATH_MAX) return -1;
        destination[output] = target[output];
        ++output;
    }
    if (output && destination[output - 1u] == '/' && suffix[0] == '/')
        ++suffix;
    while (suffix[input]) {
        if (output + 1u >= VFS_PATH_MAX) return -1;
        destination[output++] = suffix[input++];
    }
    destination[output] = 0;
    return 0;
}

static int vfs_move_mount_locked(const char *source, const char *target) {
    vfs_mount_table_t *table = vfs_mount_namespace_active_table();
    vfs_superblock_t *source_mount;
    vfs_superblock_t *target_mount;
    vfs_inode_t source_inode;
    vfs_inode_t target_inode;
    uint64_t new_parent_id;
    uint64_t source_mount_id;
    uint32_t source_length;
    uint32_t workspace_pages = 0;
    char *workspace;
    int source_index = -1;

    if (!table || !source || !target || source[0] != '/' || target[0] != '/' ||
        strcmp(source, "/") == 0 || strcmp(source, target) == 0)
        return VFS_PATH_ERR_INVALID;
    if (vfs_resolve(source, &source_inode, 0, 0, 0) < 0 ||
        vfs_resolve(target, &target_inode, 0, 0, 0) < 0)
        return VFS_PATH_ERR_NOT_FOUND;
    if ((source_inode.mode & 0xf000u) != (target_inode.mode & 0xf000u))
        return ((target_inode.mode & 0xf000u) == VFS_INODE_DIR) ?
            VFS_PATH_ERR_IS_DIRECTORY : VFS_PATH_ERR_NOT_DIRECTORY;

    source_mount = find_visible_mount(table, source);
    target_mount = find_visible_mount(table, target);
    if (!source_mount || strcmp(source_mount->mountpoint, source) != 0 ||
        !source_mount->mount_id || !target_mount)
        return VFS_PATH_ERR_INVALID;
    source_mount_id = source_mount->mount_id;
    for (int index = 0; index < table->mount_count; ++index) {
        if (vfs_mount_table_at(table, (uint32_t)index) == source_mount) {
            source_index = index;
            break;
        }
    }
    if (source_index < 0 ||
        mount_path_is_at_or_below(target, source) ||
        target_mount == source_mount ||
        mount_has_ancestor(table, target_mount, source_mount_id))
        return VFS_PATH_ERR_INVALID;

    /*
     * Mount stacks are siblings in the EdgeOS topology.  Moving onto an
     * occupied mountpoint therefore uses the visible mount's parent, while a
     * path inside a mount attaches below that containing mount.
     */
    new_parent_id = strcmp(target_mount->mountpoint, target) == 0 ?
        target_mount->parent_mount_id : target_mount->mount_id;
    if (!new_parent_id && strcmp(target, "/") != 0)
        new_parent_id = target_mount->mount_id;

    source_length = (uint32_t)strlen(source);
    workspace = vfs_mount_path_workspace_allocate(
        (uint32_t)table->mount_count, &workspace_pages);
    if (!workspace) return VFS_PATH_ERR_IO;
    for (int index = 0; index < table->mount_count; ++index) {
        vfs_superblock_t *mount =
            vfs_mount_table_at(table, (uint32_t)index);
        char *rebased = workspace + (uint64_t)index * VFS_PATH_MAX;
        const char *suffix;
        if (!mount) {
            vfs_mount_path_workspace_release(workspace, workspace_pages);
            return VFS_PATH_ERR_IO;
        }
        if (index != source_index &&
            !mount_has_ancestor(table, mount, source_mount_id)) {
            rebased[0] = 0;
            continue;
        }
        suffix = mount->mountpoint + source_length;
        if (copy_rebased_mountpoint(rebased, target, suffix) < 0) {
            vfs_mount_path_workspace_release(workspace, workspace_pages);
            return VFS_PATH_ERR_INVALID;
        }
    }

    for (int index = 0; index < table->mount_count; ++index) {
        vfs_superblock_t *mount =
            vfs_mount_table_at(table, (uint32_t)index);
        char *rebased = workspace + (uint64_t)index * VFS_PATH_MAX;
        if (!mount || !rebased[0]) continue;
        memcpy(mount->mountpoint, rebased, strlen(rebased) + 1u);
    }
    source_mount = vfs_mount_table_at(table, (uint32_t)source_index);
    if (!source_mount) {
        vfs_mount_path_workspace_release(workspace, workspace_pages);
        return VFS_PATH_ERR_IO;
    }
    source_mount->parent_mount_id = new_parent_id;
    vfs_mount_path_workspace_release(workspace, workspace_pages);
    vfs_path_cache_runtime_invalidate_subtree(source);
    vfs_path_cache_runtime_invalidate_subtree(target);
    vfs_mount_namespace_note_change();
    return 0;
}

int vfs_move_mount(const char *source, const char *target) {
    int result;
    mount_topology_lock();
    result = vfs_move_mount_locked(source, target);
    mount_topology_unlock();
    return result;
}

static int vfs_set_mount_attributes_locked(
    const char *target, uint32_t set_flags, uint32_t clear_flags,
    int recursive) {
    vfs_mount_table_t *table = vfs_mount_namespace_active_table();
    vfs_superblock_t *selected;
    uint64_t selected_id;
    int changed = 0;

    if (!table || !target || target[0] != '/')
        return VFS_PATH_ERR_INVALID;
    selected = find_visible_mount(table, target);
    if (!selected || strcmp(selected->mountpoint, target) != 0 ||
        !selected->mount_id)
        return VFS_PATH_ERR_INVALID;
    selected_id = selected->mount_id;

    for (int index = 0; index < table->mount_count; ++index) {
        vfs_superblock_t *mount =
            vfs_mount_table_at(table, (uint32_t)index);
        uint32_t updated_flags;
        if (!mount) return VFS_PATH_ERR_IO;
        if (mount->mount_id != selected_id &&
            (!recursive ||
             !mount_has_ancestor(table, mount, selected_id)))
            continue;
        updated_flags = (mount->mount_flags & ~clear_flags) | set_flags;
        if (updated_flags == mount->mount_flags) continue;
        mount->mount_flags = updated_flags;
        changed = 1;
    }
    if (changed) vfs_mount_namespace_note_change();
    return 0;
}

int vfs_set_mount_attributes(const char *target, uint32_t set_flags,
                             uint32_t clear_flags, int recursive) {
    int result;
    mount_topology_lock();
    result = vfs_set_mount_attributes_locked(
        target, set_flags, clear_flags, recursive);
    mount_topology_unlock();
    return result;
}
