/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-independent Linux quota control service. */

#ifndef EDGEOS_KERNEL_QUOTA_RUNTIME_H
#define EDGEOS_KERNEL_QUOTA_RUNTIME_H

#include <stdint.h>

#include "vfs/vfs.h"

#define KERNEL_QUOTA_USER    0u
#define KERNEL_QUOTA_GROUP   1u
#define KERNEL_QUOTA_PROJECT 2u
#define KERNEL_QUOTA_TYPES   3u

#define KERNEL_QUOTA_FORMAT_VFS_OLD 1u
#define KERNEL_QUOTA_FORMAT_VFS_V0  2u
#define KERNEL_QUOTA_FORMAT_OCFS2   3u
#define KERNEL_QUOTA_FORMAT_VFS_V1  4u
#define KERNEL_QUOTA_FORMAT_SHMEM   5u

#define KERNEL_QUOTA_VALID_BLOCK_LIMITS (1u << 0)
#define KERNEL_QUOTA_VALID_SPACE        (1u << 1)
#define KERNEL_QUOTA_VALID_INODE_LIMITS (1u << 2)
#define KERNEL_QUOTA_VALID_INODES       (1u << 3)
#define KERNEL_QUOTA_VALID_BLOCK_TIME   (1u << 4)
#define KERNEL_QUOTA_VALID_INODE_TIME   (1u << 5)
#define KERNEL_QUOTA_VALID_ALL          0x3fu

#define KERNEL_QUOTA_INFO_BLOCK_GRACE (1u << 0)
#define KERNEL_QUOTA_INFO_INODE_GRACE (1u << 1)
#define KERNEL_QUOTA_INFO_FLAGS       (1u << 2)
#define KERNEL_QUOTA_INFO_ALL         0x7u

typedef struct kernel_quota_block {
    uint64_t block_hard_limit;
    uint64_t block_soft_limit;
    uint64_t current_space;
    uint64_t inode_hard_limit;
    uint64_t inode_soft_limit;
    uint64_t current_inodes;
    uint64_t block_time;
    uint64_t inode_time;
    uint32_t valid;
} kernel_quota_block_t;

typedef struct kernel_quota_next_block {
    uint64_t block_hard_limit;
    uint64_t block_soft_limit;
    uint64_t current_space;
    uint64_t inode_hard_limit;
    uint64_t inode_soft_limit;
    uint64_t current_inodes;
    uint64_t block_time;
    uint64_t inode_time;
    uint32_t valid;
    uint32_t id;
} kernel_quota_next_block_t;

typedef struct kernel_quota_info {
    uint64_t block_grace;
    uint64_t inode_grace;
    uint32_t flags;
    uint32_t valid;
} kernel_quota_info_t;

_Static_assert(sizeof(kernel_quota_block_t) == 72,
               "Linux if_dqblk size mismatch");
_Static_assert(sizeof(kernel_quota_next_block_t) == 72,
               "Linux if_nextdqblk size mismatch");
_Static_assert(sizeof(kernel_quota_info_t) == 24,
               "Linux if_dqinfo size mismatch");

int kernel_quota_enable(vfs_superblock_t *superblock, uint32_t type,
                        uint32_t format);
int kernel_quota_disable(vfs_superblock_t *superblock, uint32_t type);
int kernel_quota_sync(vfs_superblock_t *superblock, uint32_t type);
int kernel_quota_format(vfs_superblock_t *superblock, uint32_t type,
                        uint32_t *format);
int kernel_quota_get_info(vfs_superblock_t *superblock, uint32_t type,
                          kernel_quota_info_t *information);
int kernel_quota_set_info(vfs_superblock_t *superblock, uint32_t type,
                          const kernel_quota_info_t *information);
int kernel_quota_get(vfs_superblock_t *superblock, uint32_t type,
                     uint32_t id, kernel_quota_block_t *quota);
int kernel_quota_get_next(vfs_superblock_t *superblock, uint32_t type,
                          uint32_t id, kernel_quota_next_block_t *quota);
int kernel_quota_set(vfs_superblock_t *superblock, uint32_t type,
                     uint32_t id, const kernel_quota_block_t *quota);

#endif
