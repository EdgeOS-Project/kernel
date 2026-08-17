/* SPDX-License-Identifier: MPL-2.0 */
/* Shared freestanding Btrfs read-only reader interface. */

#ifndef EDGEOS_BTRFS_READER_H
#define EDGEOS_BTRFS_READER_H

#include <stdint.h>

#include "block/block.h"

#define EDGE_BTRFS_MAX_CHUNKS 64u
#define EDGE_BTRFS_ROOT_INODE 256u

typedef struct edge_btrfs_chunk {
    uint64_t logical;
    uint64_t length;
    uint64_t physical;
    uint64_t type;
} edge_btrfs_chunk_t;

typedef struct edge_btrfs_reader {
    block_device_t *device;
    uint64_t device_bytes;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint64_t root_tree;
    uint64_t chunk_tree;
    uint64_t fs_tree;
    uint64_t incompat_flags;
    uint64_t compat_ro_flags;
    uint32_t sector_size;
    uint32_t node_size;
    uint32_t chunk_count;
    uint8_t root_level;
    uint8_t chunk_level;
    uint8_t fs_level;
    uint8_t reserved;
    edge_btrfs_chunk_t chunks[EDGE_BTRFS_MAX_CHUNKS];
} edge_btrfs_reader_t;

typedef struct edge_btrfs_inode {
    uint64_t number;
    uint64_t generation;
    uint64_t size;
    uint64_t bytes;
    int64_t atime;
    int64_t mtime;
    int64_t ctime;
    uint32_t uid;
    uint32_t gid;
    uint32_t link_count;
    uint32_t mode;
} edge_btrfs_inode_t;

typedef struct edge_btrfs_directory_entry {
    uint64_t inode_number;
    uint8_t file_type;
    char name[256];
} edge_btrfs_directory_entry_t;

int edge_btrfs_reader_init(edge_btrfs_reader_t *reader,
                           block_device_t *device);
int edge_btrfs_inode_load(edge_btrfs_reader_t *reader,
                          uint64_t inode_number,
                          edge_btrfs_inode_t *inode);
int64_t edge_btrfs_inode_read(edge_btrfs_reader_t *reader,
                              const edge_btrfs_inode_t *inode,
                              uint64_t offset, void *buffer,
                              uint32_t length);
int edge_btrfs_directory_entry(edge_btrfs_reader_t *reader,
                               const edge_btrfs_inode_t *directory,
                               uint32_t index,
                               edge_btrfs_directory_entry_t *entry);
int edge_btrfs_directory_lookup(edge_btrfs_reader_t *reader,
                                const edge_btrfs_inode_t *directory,
                                const char *name,
                                uint64_t *inode_number);

#endif
