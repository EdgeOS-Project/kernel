/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent mount topology unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "string.h"
#include "vfs/mount_namespace.h"
#include "vfs/vfs.h"

static vfs_mount_table_t test_table;
static uint32_t namespace_changes;
static char topology_workspace[
    VFS_MOUNT_TABLE_INLINE_CAPACITY * VFS_PATH_MAX];

vfs_superblock_t *vfs_mount_table_at(vfs_mount_table_t *table,
                                     uint32_t index) {
    return table && index < VFS_MOUNT_TABLE_INLINE_CAPACITY ?
        &table->inline_mounts[index] : 0;
}

const vfs_superblock_t *vfs_mount_table_at_const(
    const vfs_mount_table_t *table, uint32_t index) {
    return table && index < VFS_MOUNT_TABLE_INLINE_CAPACITY ?
        &table->inline_mounts[index] : 0;
}

char *vfs_mount_path_workspace_allocate(uint32_t path_count,
                                        uint32_t *page_count_out) {
    if (!page_count_out ||
        path_count > VFS_MOUNT_TABLE_INLINE_CAPACITY)
        return 0;
    *page_count_out = 1u;
    return topology_workspace;
}

void vfs_mount_path_workspace_release(char *workspace,
                                      uint32_t page_count) {
    (void)workspace;
    (void)page_count;
}

vfs_mount_table_t *vfs_mount_namespace_active_table(void) {
    return &test_table;
}

void vfs_mount_namespace_note_change(void) {
    ++namespace_changes;
}

int vfs_resolve(const char *path, vfs_inode_t *out_inode,
                vfs_superblock_t **out_superblock,
                vfs_inode_t *out_parent, char *leaf) {
    (void)path;
    (void)out_superblock;
    (void)out_parent;
    (void)leaf;
    if (out_inode) {
        memset(out_inode, 0, sizeof(*out_inode));
        out_inode->mode = VFS_INODE_DIR | 0755u;
    }
    return 0;
}

void vfs_path_cache_runtime_invalidate_subtree(const char *absolute_root) {
    (void)absolute_root;
}

#include "../../src/vfs/mount_topology.c"

static void initialize_mount(int index, const char *mountpoint,
                             uint64_t mount_id, uint64_t parent_mount_id,
                             uint32_t mount_flags) {
    vfs_superblock_t *mount =
        vfs_mount_table_at(&test_table, (uint32_t)index);
    memset(mount, 0, sizeof(*mount));
    assert((uint32_t)strlen(mountpoint) <
           (uint32_t)sizeof(mount->mountpoint));
    memcpy(mount->mountpoint, mountpoint, strlen(mountpoint) + 1u);
    mount->mount_id = mount_id;
    mount->parent_mount_id = parent_mount_id;
    mount->mount_flags = mount_flags;
}

int main(void) {
    memset(&test_table, 0, sizeof(test_table));
    test_table.mount_count = 4;
    initialize_mount(0, "/", 1, 0, VFS_MOUNT_RELATIME);
    initialize_mount(
        1, "/mnt", 2, 1, VFS_MOUNT_RELATIME | VFS_MOUNT_NOSUID);
    initialize_mount(2, "/mnt/child", 3, 2, VFS_MOUNT_NOEXEC);
    initialize_mount(3, "/other", 4, 1, VFS_MOUNT_READONLY);

    assert(vfs_set_mount_attributes(
               "/mnt", VFS_MOUNT_NODEV, VFS_MOUNT_NOSUID, 0) == 0);
    assert(vfs_mount_table_at(&test_table, 1u)->mount_flags ==
           (VFS_MOUNT_RELATIME | VFS_MOUNT_NODEV));
    assert(vfs_mount_table_at(&test_table, 2u)->mount_flags ==
           VFS_MOUNT_NOEXEC);
    assert(vfs_mount_table_at(&test_table, 3u)->mount_flags ==
           VFS_MOUNT_READONLY);
    assert(namespace_changes == 1);

    assert(vfs_set_mount_attributes(
               "/mnt", VFS_MOUNT_NOSUID,
               VFS_MOUNT_NODEV | VFS_MOUNT_NOEXEC, 1) == 0);
    assert(vfs_mount_table_at(&test_table, 1u)->mount_flags ==
           (VFS_MOUNT_RELATIME | VFS_MOUNT_NOSUID));
    assert(vfs_mount_table_at(&test_table, 2u)->mount_flags ==
           VFS_MOUNT_NOSUID);
    assert(vfs_mount_table_at(&test_table, 3u)->mount_flags ==
           VFS_MOUNT_READONLY);
    assert(namespace_changes == 2);

    assert(vfs_set_mount_attributes("/mnt", 0, 0, 1) == 0);
    assert(namespace_changes == 2);
    assert(vfs_set_mount_attributes("/mnt/not-a-mount", 0, 0, 0) ==
           VFS_PATH_ERR_INVALID);

    /*
     * BusyBox switch_root first moves the API filesystems below the future
     * root and then moves that root onto /.  The complete descendant mount
     * tree must remain visible after both operations; systemd opens these
     * paths through O_PATH directory descriptors immediately after exec.
     */
    memset(&test_table, 0, sizeof(test_table));
    namespace_changes = 0;
    test_table.mount_count = 4;
    initialize_mount(0, "/", 1, 0, VFS_MOUNT_RELATIME);
    initialize_mount(1, "/newroot", 2, 1, VFS_MOUNT_READONLY);
    initialize_mount(2, "/sys", 3, 1, VFS_MOUNT_NODEV);
    initialize_mount(3, "/sys/fs/cgroup", 4, 3, VFS_MOUNT_NOEXEC);

    assert(vfs_move_mount("/sys", "/newroot/sys") == 0);
    assert(vfs_move_mount("/newroot", "/") == 0);

    assert(strcmp(vfs_mount_table_at(&test_table, 1u)->mountpoint, "/") == 0);
    assert(vfs_mount_table_at(&test_table, 1u)->parent_mount_id == 0);
    assert(strcmp(vfs_mount_table_at(&test_table, 2u)->mountpoint, "/sys") == 0);
    assert(vfs_mount_table_at(&test_table, 2u)->parent_mount_id == 2);
    assert(strcmp(vfs_mount_table_at(&test_table, 3u)->mountpoint,
                  "/sys/fs/cgroup") == 0);
    assert(vfs_mount_table_at(&test_table, 3u)->parent_mount_id == 3);
    assert(find_visible_mount(&test_table, "/") ==
           vfs_mount_table_at(&test_table, 1u));
    assert(find_visible_mount(&test_table, "/sys/fs") ==
           vfs_mount_table_at(&test_table, 2u));
    assert(find_visible_mount(&test_table, "/sys/fs/cgroup") ==
           vfs_mount_table_at(&test_table, 3u));
    assert(namespace_changes == 2);

    puts("vfs_mount_topology_unit: PASS");
    return 0;
}
