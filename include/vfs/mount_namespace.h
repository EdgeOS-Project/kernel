/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS mount namespace storage.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_VFS_MOUNT_NAMESPACE_H
#define EDGEOS_VFS_MOUNT_NAMESPACE_H

#include <stdint.h>
#include "vfs/vfs.h"

#define VFS_MOUNT_TABLE_INLINE_CAPACITY 4u

typedef struct vfs_mount_chunk vfs_mount_chunk_t;

typedef struct vfs_mount_table {
    vfs_superblock_t inline_mounts[VFS_MOUNT_TABLE_INLINE_CAPACITY];
    vfs_mount_chunk_t *overflow;
    int mount_count;
    uint32_t next_peer_group;
    uint32_t event_generation;
    uint64_t next_mount_id;
    uint32_t references;
} vfs_mount_table_t;

/* Return a stable mount wrapper. Existing entries never move during growth. */
vfs_superblock_t *vfs_mount_table_at(vfs_mount_table_t *table,
                                     uint32_t index);
const vfs_superblock_t *vfs_mount_table_at_const(
    const vfs_mount_table_t *table, uint32_t index);

/* Grow a namespace mount table without imposing a fixed mount-count limit. */
int vfs_mount_table_reserve(vfs_mount_table_t *table,
                            uint32_t required_capacity);

/* Allocate temporary path storage for topology-wide transformations. */
char *vfs_mount_path_workspace_allocate(uint32_t path_count,
                                        uint32_t *page_count_out);
void vfs_mount_path_workspace_release(char *workspace,
                                      uint32_t page_count);

/* Reset the initial namespace during VFS bootstrap. */
void vfs_mount_namespace_bootstrap(void);

/*
 * VFS implementations operate on the table selected for the current CPU.
 * A scheduler must activate a task's namespace before that task can perform
 * filesystem work.
 */
vfs_mount_table_t *vfs_mount_namespace_active_table(void);

#endif
