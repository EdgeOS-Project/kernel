/* SPDX-License-Identifier: MPL-2.0 */
/* Shared freestanding XFS read-only reader interface. */

#ifndef EDGEOS_XFS_READER_H
#define EDGEOS_XFS_READER_H

#include <stdint.h>

#include "block/block.h"

typedef struct edge_xfs_reader {
    block_device_t *device;
    uint64_t device_bytes;
    uint64_t data_blocks;
    uint64_t root_inode;
    uint64_t free_data_blocks;
    uint64_t inode_count;
    uint32_t block_size;
    uint32_t allocation_group_blocks;
    uint32_t allocation_group_count;
    uint32_t directory_block_size;
    uint32_t feature_ro_compat;
    uint32_t feature_incompat;
    uint16_t inode_size;
    uint16_t inodes_per_block;
    uint8_t block_log;
    uint8_t inode_log;
    uint8_t inodes_per_block_log;
    uint8_t allocation_group_block_log;
    uint8_t directory_block_log;
    uint8_t has_file_type;
} edge_xfs_reader_t;

typedef struct edge_xfs_inode {
    uint64_t number;
    uint64_t disk_offset;
    uint64_t size;
    uint64_t blocks;
    int64_t atime;
    int64_t mtime;
    int64_t ctime;
    uint64_t extent_count;
    uint64_t flags2;
    uint32_t uid;
    uint32_t gid;
    uint32_t link_count;
    uint32_t generation;
    uint16_t mode;
    uint16_t data_fork_size;
    uint16_t core_size;
    uint8_t version;
    uint8_t format;
    uint8_t fork_offset;
} edge_xfs_inode_t;

typedef struct edge_xfs_directory_entry {
    uint64_t inode_number;
    uint8_t file_type;
    char name[256];
} edge_xfs_directory_entry_t;

int edge_xfs_reader_init(edge_xfs_reader_t *reader, block_device_t *device);
int edge_xfs_inode_load(edge_xfs_reader_t *reader, uint64_t inode_number,
                        edge_xfs_inode_t *inode);
int64_t edge_xfs_inode_read(edge_xfs_reader_t *reader,
                            const edge_xfs_inode_t *inode,
                            uint64_t offset, void *buffer, uint32_t length);
int edge_xfs_directory_entry(edge_xfs_reader_t *reader,
                             const edge_xfs_inode_t *directory,
                             uint32_t index,
                             edge_xfs_directory_entry_t *entry);
int edge_xfs_directory_lookup(edge_xfs_reader_t *reader,
                              const edge_xfs_inode_t *directory,
                              const char *name, uint64_t *inode_number);

#endif
