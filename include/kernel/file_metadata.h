/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent file metadata representation.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_FILE_METADATA_H
#define EDGEOS_KERNEL_FILE_METADATA_H

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "vfs/vfs.h"

#define KERNEL_FILE_METADATA_TYPE        0x00000001u
#define KERNEL_FILE_METADATA_MODE        0x00000002u
#define KERNEL_FILE_METADATA_NLINK       0x00000004u
#define KERNEL_FILE_METADATA_UID         0x00000008u
#define KERNEL_FILE_METADATA_GID         0x00000010u
#define KERNEL_FILE_METADATA_ATIME       0x00000020u
#define KERNEL_FILE_METADATA_MTIME       0x00000040u
#define KERNEL_FILE_METADATA_CTIME       0x00000080u
#define KERNEL_FILE_METADATA_INO         0x00000100u
#define KERNEL_FILE_METADATA_SIZE        0x00000200u
#define KERNEL_FILE_METADATA_BLOCKS      0x00000400u
#define KERNEL_FILE_METADATA_BASIC       0x000007ffu
#define KERNEL_FILE_METADATA_BTIME       0x00000800u
#define KERNEL_FILE_METADATA_MOUNT_ID    0x00001000u
#define KERNEL_FILE_METADATA_DIO_ALIGN   0x00002000u
#define KERNEL_FILE_METADATA_MOUNT_UNIQUE 0x00004000u
#define KERNEL_FILE_METADATA_SUBVOLUME   0x00008000u
#define KERNEL_FILE_METADATA_WRITE_ATOMIC 0x00010000u
#define KERNEL_FILE_METADATA_DIO_READ_ALIGN 0x00020000u

typedef struct kernel_file_timestamp {
    int64_t seconds;
    uint32_t nanoseconds;
} kernel_file_timestamp_t;

typedef struct kernel_file_metadata {
    uint32_t result_mask;
    uint32_t block_size;
    uint64_t attributes;
    uint64_t attributes_mask;
    uint64_t device;
    uint64_t inode;
    uint64_t rdev;
    uint64_t size;
    uint64_t blocks;
    uint64_t mount_id;
    uint64_t subvolume;
    uint32_t links;
    uint32_t uid;
    uint32_t gid;
    uint16_t mode;
    uint32_t direct_io_memory_alignment;
    uint32_t direct_io_offset_alignment;
    uint32_t direct_io_read_offset_alignment;
    uint32_t atomic_write_unit_minimum;
    uint32_t atomic_write_unit_maximum;
    uint32_t atomic_write_segments_maximum;
    uint32_t atomic_write_unit_maximum_optimal;
    kernel_file_timestamp_t access_time;
    kernel_file_timestamp_t birth_time;
    kernel_file_timestamp_t change_time;
    kernel_file_timestamp_t modification_time;
} kernel_file_metadata_t;

uint64_t kernel_file_device_encode(uint32_t major, uint32_t minor);
uint32_t kernel_file_device_major(uint64_t device);
uint32_t kernel_file_device_minor(uint64_t device);

void kernel_file_metadata_initialize(kernel_file_metadata_t *metadata,
                                     uint16_t mode, uint64_t size);
void kernel_file_metadata_from_inode(vfs_superblock_t *superblock,
                                     const vfs_inode_t *inode,
                                     kernel_file_metadata_t *metadata);
void kernel_file_metadata_set_mount_id(kernel_file_metadata_t *metadata,
                                       uint64_t mount_id);
void kernel_file_metadata_to_statx(const kernel_file_metadata_t *metadata,
                                   struct edge_linux_statx *result);

#endif
