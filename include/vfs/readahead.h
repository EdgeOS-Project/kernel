/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_VFS_READAHEAD_H
#define EDGEOS_VFS_READAHEAD_H

#include <stdint.h>

#include "vfs/vfs.h"

#define VFS_READAHEAD_PAGE_SIZE 4096u
#define VFS_READAHEAD_MIN_PAGES 16u
#define VFS_READAHEAD_MAX_PAGES 64u

typedef struct {
    void *(*allocate_pages)(uint32_t page_count, void *context);
    void (*release_pages)(void *base, uint32_t page_count, void *context);
    void *context;
} vfs_readahead_allocator_t;

/*
 * Return an adaptive forward window for a file-cache miss.  The state is keyed
 * by filesystem identity and inode generation.  A bounded set of recent
 * sequential streams lets concurrent executable and shared-library faults
 * progress without splitting the inode page cache or allocating per-task
 * state.  Rename and bind mounts therefore retain history while inode reuse
 * starts fresh state.
 */
uint32_t vfs_readahead_plan(vfs_superblock_t *sb,
                            const vfs_inode_t *inode,
                            uint64_t page_offset,
                            uint32_t maximum_pages);

void vfs_readahead_forget_inode(vfs_superblock_t *sb,
                                const vfs_inode_t *inode);
uint32_t vfs_readahead_reclaim(uint32_t state_count);
uint32_t vfs_readahead_state_count(void);

int vfs_readahead_runtime_set_allocator(
    const vfs_readahead_allocator_t *allocator);
void vfs_readahead_runtime_reset(void);

#endif
