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
typedef struct vfs_mount_id_cache_entry vfs_mount_id_cache_entry_t;
typedef struct vfs_mount_lookup_cache vfs_mount_lookup_cache_t;

typedef struct vfs_mount_table {
    vfs_superblock_t inline_mounts[VFS_MOUNT_TABLE_INLINE_CAPACITY];
    vfs_mount_chunk_t *overflow;
    vfs_mount_chunk_t *overflow_tail;
    vfs_mount_chunk_t **chunk_index;
    uint32_t chunk_index_count;
    vfs_mount_id_cache_entry_t *mount_id_cache;
    vfs_mount_lookup_cache_t *mount_lookup_cache;
    uint32_t capacity;
    int mount_count;
    uint64_t root_mount_id;
    uint32_t next_peer_group;
    uint32_t event_generation;
    uint64_t next_mount_id;
    uint32_t references;
} vfs_mount_table_t;

typedef struct vfs_mount_table_iterator {
    vfs_mount_table_t *table;
    vfs_mount_chunk_t *chunk;
    uint32_t index;
    uint32_t chunk_index;
} vfs_mount_table_iterator_t;

/* Return a mount wrapper. Growth is stable; removal may compact entries. */
vfs_superblock_t *vfs_mount_table_at(vfs_mount_table_t *table,
                                     uint32_t index);
const vfs_superblock_t *vfs_mount_table_at_const(
    const vfs_mount_table_t *table, uint32_t index);
vfs_superblock_t *vfs_mount_table_find_id(vfs_mount_table_t *table,
                                          uint64_t mount_id);
const vfs_superblock_t *vfs_mount_table_find_id_const(
    const vfs_mount_table_t *table, uint64_t mount_id);
int vfs_mount_table_lookup_cache_get(vfs_mount_table_t *table,
                                     const char *path,
                                     uint32_t *table_index);
void vfs_mount_table_lookup_cache_store(vfs_mount_table_t *table,
                                        const char *path,
                                        uint32_t table_index);
void vfs_mount_table_lookup_cache_invalidate(vfs_mount_table_t *table);
void vfs_mount_table_lookup_cache_invalidate_subtree(
    vfs_mount_table_t *table, const char *path);
void vfs_mount_table_link_latest(vfs_mount_table_t *table,
                                 vfs_superblock_t *mount);
void vfs_mount_table_rebuild_child_links(vfs_mount_table_t *table);

/* Walk a mount table in storage order without repeatedly replaying chunks. */
void vfs_mount_table_iterator_begin(vfs_mount_table_t *table,
                                    vfs_mount_table_iterator_t *iterator);
vfs_superblock_t *vfs_mount_table_iterator_next(
    vfs_mount_table_iterator_t *iterator, uint32_t *index_out);

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
void vfs_mount_namespace_note_path_change(const char *path);

/*
 * VFS implementations operate on the table selected for the current CPU.
 * A scheduler must activate a task's namespace before that task can perform
 * filesystem work.
 */
vfs_mount_table_t *vfs_mount_namespace_active_table(void);
int vfs_mount_namespace_uses_initial_root(void);

#endif
