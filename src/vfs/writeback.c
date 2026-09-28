/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent VFS durability policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "sys/boottime.h"
#include "vfs/mount_namespace.h"
#include "vfs/page_writeback.h"
#include "vfs/vfs.h"

#define VFS_WRITEBACK_INTERVAL_US 5000000ull

static uint64_t g_writeback_deadline_us;

int vfs_sync_mutation_if_required(vfs_superblock_t *sb,
                                  int directory_mutation) {
    uint32_t required;

    if (!sb || !sb->ops || !sb->ops->sync) return 0;
    required = sb->mount_flags & VFS_MOUNT_SYNCHRONOUS;
    if (directory_mutation)
        required |= sb->mount_flags & VFS_MOUNT_DIRSYNC;
    return required ? sb->ops->sync(sb) : 0;
}

int vfs_sync_all(void) {
    return vfs_filesystem_sync_all();
}

int vfs_sync_inode(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   int data_only) {
    if (!sb || !inode || !sb->ops) return -1;
    if (sb->ops->sync_inode)
        return sb->ops->sync_inode(sb, inode, data_only != 0);
    return sb->ops->sync ? sb->ops->sync(sb) : 0;
}

void vfs_writeback_poll(void) {
    uint64_t now = boottime_monotonic_us();
    uint64_t deadline = __atomic_load_n(&g_writeback_deadline_us,
                                        __ATOMIC_ACQUIRE);
    uint64_t next;

    /*
     * Keep the five-second cadence shared by both architectures.  A shorter
     * syscall-assisted interval makes unrelated desktop and browser work pay
     * filesystem writeback latency.
     */
    if (!deadline) {
        next = now + VFS_WRITEBACK_INTERVAL_US;
        (void)__atomic_compare_exchange_n(&g_writeback_deadline_us,
                                          &deadline, next, 0,
                                          __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE);
        return;
    }
    if (now < deadline) return;
    next = now + VFS_WRITEBACK_INTERVAL_US;
    if (!__atomic_compare_exchange_n(&g_writeback_deadline_us,
                                     &deadline, next, 0,
                                     __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return;

    (void)vfs_page_writeback_run(32u);
    vfs_mount_table_t *table = vfs_mount_namespace_active_table();
    for (int index = 0; index < table->mount_count; ++index) {
        vfs_superblock_t *sb =
            vfs_mount_table_at(table, (uint32_t)index);
        if (!sb) continue;
        if (sb->ops && sb->ops->writeback)
            (void)sb->ops->writeback(sb);
    }
}
