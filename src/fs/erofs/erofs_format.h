/* SPDX-License-Identifier: MIT */
/*
 * EROFS on-disk definitions used by EdgeOS.
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 * Copyright (C) 2021 Alibaba Cloud
 *
 * Derived from the MIT-licensed Linux UAPI-style erofs_fs.h definition.
 */

#ifndef EDGEOS_EROFS_FORMAT_H
#define EDGEOS_EROFS_FORMAT_H

#include <stdint.h>

#define EDGE_EROFS_SUPER_OFFSET 1024u
#define EDGE_EROFS_MAGIC 0xe0f5e1e2u

#define EDGE_EROFS_FEATURE_COMPAT_SB_CHKSUM 0x00000001u

#define EDGE_EROFS_FEATURE_INCOMPAT_LZ4_0PADDING 0x00000001u
#define EDGE_EROFS_FEATURE_INCOMPAT_COMPR_CFGS 0x00000002u
#define EDGE_EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER 0x00000002u
#define EDGE_EROFS_FEATURE_INCOMPAT_CHUNKED_FILE 0x00000004u
#define EDGE_EROFS_FEATURE_INCOMPAT_DEVICE_TABLE 0x00000008u
#define EDGE_EROFS_FEATURE_INCOMPAT_COMPR_HEAD2 0x00000008u
#define EDGE_EROFS_FEATURE_INCOMPAT_ZTAILPACKING 0x00000010u
#define EDGE_EROFS_FEATURE_INCOMPAT_FRAGMENTS 0x00000020u
#define EDGE_EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES 0x00000040u
#define EDGE_EROFS_FEATURE_INCOMPAT_48BIT 0x00000080u
#define EDGE_EROFS_FEATURE_INCOMPAT_METABOX 0x00000100u

#define EDGE_EROFS_INODE_FLAT_PLAIN 0u
#define EDGE_EROFS_INODE_COMPRESSED_FULL 1u
#define EDGE_EROFS_INODE_FLAT_INLINE 2u
#define EDGE_EROFS_INODE_COMPRESSED_COMPACT 3u
#define EDGE_EROFS_INODE_CHUNK_BASED 4u

#define EDGE_EROFS_INODE_VERSION_MASK 0x01u
#define EDGE_EROFS_INODE_DATALAYOUT_MASK 0x07u
#define EDGE_EROFS_INODE_DATALAYOUT_BIT 1u

#define EDGE_EROFS_CHUNK_FORMAT_BLKBITS_MASK 0x001fu
#define EDGE_EROFS_CHUNK_FORMAT_INDEXES 0x0020u
#define EDGE_EROFS_CHUNK_FORMAT_48BIT 0x0040u
#define EDGE_EROFS_NULL_ADDR32 0xffffffffu

#define EDGE_EROFS_COMPRESSION_LZ4 0u
#define EDGE_EROFS_COMPRESSION_LZ4_MASK 0x0001u

#define EDGE_EROFS_ADVISE_COMPACTED_2B 0x0001u
#define EDGE_EROFS_ADVISE_BIG_PCLUSTER_1 0x0002u
#define EDGE_EROFS_ADVISE_BIG_PCLUSTER_2 0x0004u
#define EDGE_EROFS_ADVISE_INLINE_PCLUSTER 0x0008u
#define EDGE_EROFS_ADVISE_INTERLACED_PCLUSTER 0x0010u
#define EDGE_EROFS_ADVISE_FRAGMENT_PCLUSTER 0x0020u

#define EDGE_EROFS_LCLUSTER_PLAIN 0u
#define EDGE_EROFS_LCLUSTER_HEAD1 1u
#define EDGE_EROFS_LCLUSTER_NONHEAD 2u
#define EDGE_EROFS_LCLUSTER_HEAD2 3u
#define EDGE_EROFS_LCLUSTER_TYPE_MASK 3u
#define EDGE_EROFS_LCLUSTER_PARTIAL_REF 0x8000u
#define EDGE_EROFS_LCLUSTER_HOLE 0x4000u
#define EDGE_EROFS_LCLUSTER_CBLKCNT 0x0800u

#define EDGE_EROFS_XATTR_INDEX_USER 1u
#define EDGE_EROFS_XATTR_INDEX_POSIX_ACL_ACCESS 2u
#define EDGE_EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT 3u
#define EDGE_EROFS_XATTR_INDEX_TRUSTED 4u
#define EDGE_EROFS_XATTR_INDEX_LUSTRE 5u
#define EDGE_EROFS_XATTR_INDEX_SECURITY 6u
#define EDGE_EROFS_XATTR_LONG_PREFIX 0x80u

typedef struct __attribute__((packed)) edge_erofs_super_disk {
    uint32_t magic;
    uint32_t checksum;
    uint32_t feature_compat;
    uint8_t block_bits;
    uint8_t extension_slots;
    uint16_t root_nid_16;
    uint64_t inode_count;
    uint64_t epoch;
    uint32_t fixed_nsec;
    uint32_t blocks_low;
    uint32_t metadata_block;
    uint32_t xattr_block;
    uint8_t uuid[16];
    uint8_t volume_name[16];
    uint32_t feature_incompat;
    uint16_t compression;
    uint16_t extra_devices;
    uint16_t device_slot_offset;
    uint8_t directory_block_bits;
    uint8_t xattr_prefix_count;
    uint32_t xattr_prefix_start;
    uint64_t packed_nid;
    uint8_t xattr_filter_reserved;
    uint8_t inode_share_prefix_id;
    uint8_t reserved[2];
    uint32_t build_time;
    uint64_t root_nid_64;
    uint64_t reserved2;
    uint64_t metabox_nid;
    uint64_t reserved3;
} edge_erofs_super_disk_t;

typedef struct __attribute__((packed)) edge_erofs_inode_compact_disk {
    uint16_t format;
    uint16_t xattr_count;
    uint16_t mode;
    uint16_t link_count;
    uint32_t size;
    uint32_t mtime;
    uint32_t data;
    uint32_t inode_number;
    uint16_t uid;
    uint16_t gid;
    uint32_t reserved;
} edge_erofs_inode_compact_disk_t;

typedef struct __attribute__((packed)) edge_erofs_inode_extended_disk {
    uint16_t format;
    uint16_t xattr_count;
    uint16_t mode;
    uint16_t link_count_low;
    uint64_t size;
    uint32_t data;
    uint32_t inode_number;
    uint32_t uid;
    uint32_t gid;
    uint64_t mtime;
    uint32_t mtime_nsec;
    uint32_t link_count;
    uint8_t reserved[16];
} edge_erofs_inode_extended_disk_t;

typedef struct __attribute__((packed)) edge_erofs_directory_entry_disk {
    uint64_t nid;
    uint16_t name_offset;
    uint8_t file_type;
    uint8_t reserved;
} edge_erofs_directory_entry_disk_t;

typedef struct __attribute__((packed)) edge_erofs_xattr_header_disk {
    uint32_t name_filter;
    uint8_t shared_count;
    uint8_t reserved[7];
} edge_erofs_xattr_header_disk_t;

typedef struct __attribute__((packed)) edge_erofs_xattr_entry_disk {
    uint8_t name_length;
    uint8_t name_index;
    uint16_t value_size;
} edge_erofs_xattr_entry_disk_t;

typedef struct __attribute__((packed)) edge_erofs_chunk_index_disk {
    uint16_t start_block_high;
    uint16_t device_id;
    uint32_t start_block_low;
} edge_erofs_chunk_index_disk_t;

typedef struct __attribute__((packed)) edge_erofs_compression_header_disk {
    uint32_t data_or_fragment;
    uint16_t advise;
    uint8_t algorithms;
    uint8_t cluster_bits;
} edge_erofs_compression_header_disk_t;

typedef struct __attribute__((packed)) edge_erofs_lcluster_index_disk {
    uint16_t advise;
    uint16_t cluster_offset;
    union {
        uint32_t start_block;
        uint16_t delta[2];
    } data;
} edge_erofs_lcluster_index_disk_t;

typedef struct __attribute__((packed)) edge_erofs_lz4_config_disk {
    uint16_t maximum_distance;
    uint16_t maximum_pcluster_blocks;
    uint8_t reserved[10];
} edge_erofs_lz4_config_disk_t;

_Static_assert(sizeof(edge_erofs_super_disk_t) == 144u,
               "EROFS superblock layout must remain stable");
_Static_assert(sizeof(edge_erofs_inode_compact_disk_t) == 32u,
               "EROFS compact inode layout must remain stable");
_Static_assert(sizeof(edge_erofs_inode_extended_disk_t) == 64u,
               "EROFS extended inode layout must remain stable");
_Static_assert(sizeof(edge_erofs_directory_entry_disk_t) == 12u,
               "EROFS directory entry layout must remain stable");
_Static_assert(sizeof(edge_erofs_compression_header_disk_t) == 8u,
               "EROFS compression header layout must remain stable");
_Static_assert(sizeof(edge_erofs_lcluster_index_disk_t) == 8u,
               "EROFS compression index layout must remain stable");
_Static_assert(sizeof(edge_erofs_lz4_config_disk_t) == 14u,
               "EROFS LZ4 configuration layout must remain stable");

#endif
