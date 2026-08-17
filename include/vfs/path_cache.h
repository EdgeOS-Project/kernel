/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent VFS path cache.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_VFS_PATH_CACHE_H
#define EDGEOS_VFS_PATH_CACHE_H

#include <stdint.h>
#include "vfs/vfs.h"

typedef struct vfs_path_cache_result {
    vfs_inode_t inode;
    uint32_t superblock_index;
    uint8_t miss;
} vfs_path_cache_result_t;

typedef struct vfs_path_cache_allocator {
    void *(*allocate_pages)(uint32_t page_count, void *context);
    void (*release_pages)(void *base, uint32_t page_count, void *context);
    void *context;
} vfs_path_cache_allocator_t;

int vfs_path_cache_runtime_set_allocator(
    const vfs_path_cache_allocator_t *allocator);
void vfs_path_cache_runtime_reset(void);
int vfs_path_cache_runtime_lookup(
    const char *absolute_path, uint32_t namespace_id,
    vfs_path_cache_result_t *result);
void vfs_path_cache_runtime_store(
    const char *absolute_path, uint32_t namespace_id, int miss,
    const vfs_inode_t *inode, uint32_t superblock_index);
void vfs_path_cache_runtime_invalidate_absolute(
    const char *absolute_path);
void vfs_path_cache_runtime_invalidate_subtree(
    const char *absolute_root);
uint32_t vfs_path_cache_runtime_reclaim(uint32_t entry_count);
uint32_t vfs_path_cache_runtime_count(void);

#endif
