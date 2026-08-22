/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent file metadata helpers.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/file_metadata.h"
#include "kernel/vfs_runtime.h"
#include "string.h"

uint64_t kernel_file_device_encode(uint32_t major, uint32_t minor) {
    return ((uint64_t)(minor & 0xffu)) |
           ((uint64_t)(major & 0xfffu) << 8) |
           ((uint64_t)(minor & ~0xffu) << 12) |
           ((uint64_t)(major & ~0xfffu) << 32);
}

uint32_t kernel_file_device_major(uint64_t device) {
    return (uint32_t)(((device >> 8) & 0xfffu) |
                      ((device >> 32) & ~0xfffu));
}

uint32_t kernel_file_device_minor(uint64_t device) {
    return (uint32_t)((device & 0xffu) |
                      ((device >> 12) & ~0xffu));
}

void kernel_file_metadata_initialize(kernel_file_metadata_t *metadata,
                                     uint16_t mode, uint64_t size) {
    if (!metadata) return;
    memset(metadata, 0, sizeof(*metadata));
    metadata->result_mask = KERNEL_FILE_METADATA_BASIC;
    metadata->block_size = 4096u;
    metadata->device = kernel_file_device_encode(0u, 1u);
    metadata->links = 1u;
    metadata->mode = mode;
    metadata->size = size;
    metadata->blocks = (size + 511u) / 512u;
}

void kernel_file_metadata_from_inode(vfs_superblock_t *superblock,
                                     const vfs_inode_t *inode,
                                     kernel_file_metadata_t *metadata) {
    if (!metadata) return;
    kernel_file_metadata_initialize(metadata, 0, 0);
    if (!inode) return;
    metadata->inode = inode->ino;
    metadata->rdev = inode->rdev;
    metadata->size = inode->size;
    metadata->blocks = (metadata->size + 511u) / 512u;
    metadata->links = vfs_inode_link_count(inode);
    metadata->uid = inode->uid;
    metadata->gid = inode->gid;
    metadata->mode = inode->mode;
    metadata->access_time.seconds = inode->atime;
    metadata->modification_time.seconds = inode->mtime;
    metadata->change_time.seconds = inode->ctime;
    metadata->attributes_mask |= EDGE_LINUX_STATX_ATTR_IMMUTABLE |
                                 EDGE_LINUX_STATX_ATTR_APPEND |
                                 EDGE_LINUX_STATX_ATTR_NODUMP |
                                 EDGE_LINUX_STATX_ATTR_MOUNT_ROOT;
    if (inode->metadata_flags & VFS_FILE_XFLAG_IMMUTABLE)
        metadata->attributes |= EDGE_LINUX_STATX_ATTR_IMMUTABLE;
    if (inode->metadata_flags & VFS_FILE_XFLAG_APPEND)
        metadata->attributes |= EDGE_LINUX_STATX_ATTR_APPEND;
    if (inode->metadata_flags & VFS_FILE_XFLAG_NODUMP)
        metadata->attributes |= EDGE_LINUX_STATX_ATTR_NODUMP;
    if (superblock &&
        vfs_inode_same_object(superblock, inode,
                              superblock, &superblock->root))
        metadata->attributes |= EDGE_LINUX_STATX_ATTR_MOUNT_ROOT;
    kernel_file_metadata_set_mount_id(
        metadata, superblock ? superblock->mount_id : 0u);
}

void kernel_file_metadata_set_mount_id(kernel_file_metadata_t *metadata,
                                       uint64_t mount_id) {
    if (!metadata) return;
    metadata->device = kernel_file_device_encode(
        0u, (uint32_t)(mount_id ? mount_id : 1u));
    if (!mount_id) return;
    metadata->mount_id = mount_id;
    metadata->result_mask |= KERNEL_FILE_METADATA_MOUNT_ID;
}

int kernel_file_metadata_from_descriptor(
    const kernel_vfs_descriptor_t *description,
    kernel_file_metadata_t *metadata) {
    kernel_pipe_metadata_t pipe_metadata;
    if (!description || !metadata) return -1;

    if (description->kind == KERNEL_VFS_DESCRIPTOR_SOCKET) {
        kernel_file_metadata_initialize(
            metadata, (uint16_t)(VFS_INODE_SOCK | 0777u), 0);
        metadata->inode = 0xe0000000u +
            (description->identity & 0x0fffffffu);
        return 0;
    }
    if (description->kind == KERNEL_VFS_DESCRIPTOR_PIPE &&
        description->pipe &&
        kernel_pipe_metadata_snapshot(
            description->pipe, &pipe_metadata) == 0) {
        kernel_file_metadata_initialize(
            metadata,
            (uint16_t)(VFS_INODE_FIFO | pipe_metadata.mode), 0);
        metadata->inode = 0xe0000000u +
            (description->identity & 0x0fffffffu);
        metadata->uid = pipe_metadata.uid;
        metadata->gid = pipe_metadata.gid;
        return 0;
    }
    return 1;
}

static void kernel_file_timestamp_to_statx(
    const kernel_file_timestamp_t *source,
    struct edge_linux_statx_timestamp *destination) {
    destination->tv_sec = source->seconds;
    destination->tv_nsec = source->nanoseconds;
    destination->__reserved = 0;
}

void kernel_file_metadata_to_statx(const kernel_file_metadata_t *metadata,
                                   struct edge_linux_statx *result) {
    if (!result) return;
    memset(result, 0, sizeof(*result));
    if (!metadata) return;
    result->stx_mask = metadata->result_mask;
    result->stx_blksize = metadata->block_size;
    result->stx_attributes = metadata->attributes;
    result->stx_nlink = metadata->links;
    result->stx_uid = metadata->uid;
    result->stx_gid = metadata->gid;
    result->stx_mode = metadata->mode;
    result->stx_ino = metadata->inode;
    result->stx_size = metadata->size;
    result->stx_blocks = metadata->blocks;
    result->stx_attributes_mask = metadata->attributes_mask;
    kernel_file_timestamp_to_statx(&metadata->access_time,
                                   &result->stx_atime);
    kernel_file_timestamp_to_statx(&metadata->birth_time,
                                   &result->stx_btime);
    kernel_file_timestamp_to_statx(&metadata->change_time,
                                   &result->stx_ctime);
    kernel_file_timestamp_to_statx(&metadata->modification_time,
                                   &result->stx_mtime);
    result->stx_rdev_major = kernel_file_device_major(metadata->rdev);
    result->stx_rdev_minor = kernel_file_device_minor(metadata->rdev);
    result->stx_dev_major = kernel_file_device_major(metadata->device);
    result->stx_dev_minor = kernel_file_device_minor(metadata->device);
    result->stx_mnt_id = metadata->mount_id;
    result->stx_dio_mem_align = metadata->direct_io_memory_alignment;
    result->stx_dio_offset_align = metadata->direct_io_offset_alignment;
    result->stx_subvol = metadata->subvolume;
    result->stx_atomic_write_unit_min =
        metadata->atomic_write_unit_minimum;
    result->stx_atomic_write_unit_max =
        metadata->atomic_write_unit_maximum;
    result->stx_atomic_write_segments_max =
        metadata->atomic_write_segments_maximum;
    result->stx_dio_read_offset_align =
        metadata->direct_io_read_offset_alignment;
    result->stx_atomic_write_unit_max_opt =
        metadata->atomic_write_unit_maximum_optimal;
}
