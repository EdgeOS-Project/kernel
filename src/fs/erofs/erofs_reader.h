/* SPDX-License-Identifier: MPL-2.0 */
/* Shared freestanding EROFS reader interface. */

#ifndef EDGEOS_EROFS_READER_H
#define EDGEOS_EROFS_READER_H

#include <stddef.h>
#include <stdint.h>

#include "block/block.h"

typedef struct edge_erofs_reader {
    block_device_t *device;
    uint64_t device_bytes;
    uint64_t inode_count;
    uint64_t root_nid;
    uint64_t metadata_offset;
    uint64_t xattr_offset;
    uint64_t block_count;
    uint32_t block_size;
    uint32_t directory_block_size;
    uint32_t feature_compat;
    uint32_t feature_incompat;
    uint32_t maximum_pcluster_blocks;
    uint32_t lz4_maximum_distance;
    uint16_t compression_algorithms;
    uint8_t *compressed_workspace;
    uint32_t compressed_workspace_size;
    uint8_t *history_workspace;
    uint32_t history_workspace_size;
} edge_erofs_reader_t;

typedef struct edge_erofs_inode {
    uint64_t nid;
    uint64_t inode_offset;
    uint64_t size;
    uint64_t mtime;
    uint64_t start_block;
    uint32_t inode_number;
    uint32_t uid;
    uint32_t gid;
    uint32_t link_count;
    uint32_t xattr_size;
    uint32_t rdev;
    uint16_t mode;
    uint16_t format;
    uint16_t chunk_format;
    uint8_t inode_size;
    uint8_t data_layout;
} edge_erofs_inode_t;

typedef struct edge_erofs_directory_entry {
    uint64_t nid;
    uint8_t file_type;
    char name[256];
} edge_erofs_directory_entry_t;

int edge_erofs_reader_init(edge_erofs_reader_t *reader,
                           block_device_t *device);
int edge_erofs_reader_set_compression_workspace(
    edge_erofs_reader_t *reader, void *compressed, uint32_t compressed_size,
    void *history, uint32_t history_size);
int edge_erofs_inode_load(edge_erofs_reader_t *reader, uint64_t nid,
                          edge_erofs_inode_t *inode);
int64_t edge_erofs_inode_read(edge_erofs_reader_t *reader,
                              const edge_erofs_inode_t *inode,
                              uint64_t offset, void *buffer,
                              uint32_t length);
int edge_erofs_directory_entry(edge_erofs_reader_t *reader,
                               const edge_erofs_inode_t *directory,
                               uint32_t index,
                               edge_erofs_directory_entry_t *entry);
int edge_erofs_directory_lookup(edge_erofs_reader_t *reader,
                                const edge_erofs_inode_t *directory,
                                const char *name, uint64_t *nid);
int edge_erofs_getxattr(edge_erofs_reader_t *reader,
                        const edge_erofs_inode_t *inode,
                        const char *name, void *value,
                        uint32_t capacity);

#endif
