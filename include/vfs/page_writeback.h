/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent file page writeback tracking.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef VFS_PAGE_WRITEBACK_H
#define VFS_PAGE_WRITEBACK_H

#include <stdint.h>

#include "vfs/vfs.h"

#define VFS_PAGE_WRITEBACK_PAGE_SIZE 4096u

#define VFS_PAGE_WRITEBACK_COMPLETE 0
#define VFS_PAGE_WRITEBACK_RETAIN   1
#define VFS_PAGE_WRITEBACK_DISCARD  2

#define VFS_PAGE_WRITEBACK_ERR_INVALID (-1)
#define VFS_PAGE_WRITEBACK_ERR_IO      (-2)

typedef int (*vfs_page_writeback_callback_t)(
    uint64_t token, uint32_t dirty_generation, void *context);

typedef struct vfs_page_writeback_allocator {
    void *(*allocate_pages)(uint32_t page_count, void *context);
    void (*release_pages)(void *base, uint32_t page_count,
                          void *context);
    void *context;
} vfs_page_writeback_allocator_t;

int vfs_page_writeback_mark_dirty(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t page_offset, uint64_t token,
    vfs_page_writeback_callback_t callback, void *context);
void vfs_page_writeback_forget_token(
    vfs_page_writeback_callback_t callback, void *context,
    uint64_t token);
void vfs_page_writeback_forget_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length);

uint32_t vfs_page_writeback_run(uint32_t page_budget);
int vfs_page_writeback_sync_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length);
int vfs_page_writeback_sync_inode(
    vfs_superblock_t *superblock, const vfs_inode_t *inode);
int vfs_page_writeback_sync_superblock(vfs_superblock_t *superblock);
int vfs_page_writeback_error(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    int clear_error);
uint32_t vfs_page_writeback_dirty_pages(void);
void vfs_page_writeback_stat_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length,
    uint64_t *dirty_pages, uint64_t *writeback_pages);
int vfs_page_writeback_should_throttle(void);

int vfs_page_writeback_runtime_set_allocator(
    const vfs_page_writeback_allocator_t *allocator);
void vfs_page_writeback_runtime_reset(void);

#endif
