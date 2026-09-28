/* SPDX-License-Identifier: MPL-2.0 */
/* Shared streaming mount snapshot test. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs/mount_namespace.h"

static vfs_mount_table_t test_table;

vfs_mount_table_t *vfs_mount_namespace_active_table(void) {
    return &test_table;
}

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

static void initialize_mount(uint32_t index, uint64_t id, uint64_t parent,
                             const char *device, const char *mountpoint,
                             const char *filesystem, uint32_t flags) {
    vfs_superblock_t *mount = vfs_mount_table_at(&test_table, index);
    assert(mount != 0);
    memset(mount, 0, sizeof(*mount));
    mount->mount_id = id;
    mount->parent_mount_id = parent;
    mount->mount_flags = flags;
    strcpy(mount->dev_name, device);
    strcpy(mount->mountpoint, mountpoint);
    strcpy(mount->fs_name, filesystem);
}

int main(void) {
    char complete[1024];
    char streamed[1024];
    uint32_t offset = 0;
    int length;

    memset(&test_table, 0, sizeof(test_table));
    test_table.mount_count = 3;
    initialize_mount(0u, 1u, 0u, "/dev/vda", "/", "ext4",
                     VFS_MOUNT_RELATIME);
    initialize_mount(1u, 2u, 1u, "proc", "/proc", "proc",
                     VFS_MOUNT_NOSUID | VFS_MOUNT_NODEV |
                     VFS_MOUNT_NOEXEC);
    initialize_mount(2u, 3u, 1u, "tmp fs", "/run/space here", "tmpfs",
                     VFS_MOUNT_NOSUID);
    test_table.inline_mounts[1].peer_group = 7u;

    length = vfs_mountinfo_snapshot(complete, sizeof(complete));
    assert(length > 0);
    assert(strstr(complete, "shared:7") != 0);
    assert(strstr(complete, "/run/space\\040here") != 0);
    assert(strstr(complete, "tmp\\040fs") != 0);

    while (offset < (uint32_t)length) {
        int copied = vfs_mount_snapshot_read(
            1, offset, streamed + offset, 7u);
        assert(copied > 0 && copied <= 7);
        offset += (uint32_t)copied;
    }
    streamed[offset] = 0;
    assert(offset == (uint32_t)length);
    assert(strcmp(streamed, complete) == 0);
    assert(vfs_mount_snapshot_read(1, offset, streamed, 7u) == 0);
    assert(vfs_mountinfo_snapshot(streamed, 8u) < 0);

    puts("vfs_mount_snapshot_unit: PASS");
    return 0;
}
