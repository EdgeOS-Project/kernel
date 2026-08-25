/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent directory syscall interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_DIRECTORY_RUNTIME_H
#define EDGEOS_KERNEL_DIRECTORY_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "vfs/vfs.h"

typedef enum kernel_vfs_dirent_format {
    KERNEL_VFS_DIRENT64 = 0,
    KERNEL_VFS_DIRENT_NATIVE64 = 1,
    KERNEL_VFS_DIRENT_NATIVE32 = 2,
} kernel_vfs_dirent_format_t;

typedef struct kernel_vfs_getdents_request {
    int32_t descriptor;
    kernel_vfs_dirent_format_t format;
    uint64_t user_buffer;
    uint64_t capacity;
    void *copy_context;
    edge_linux_copy_to_user_fn copy_to_user;
} kernel_vfs_getdents_request_t;

typedef struct kernel_vfs_directory_cursor {
    void *opaque;
    uint64_t offset;
} kernel_vfs_directory_cursor_t;

typedef struct kernel_vfs_directory_entry {
    vfs_inode_t inode;
    uint64_t next_offset;
    char name[VFS_NAME_MAX];
} kernel_vfs_directory_entry_t;

/*
 * Returns one after emitting a record, zero when a partial result should be
 * returned, or a negative Linux errno when no record has been emitted.
 */
int kernel_vfs_dirent_emit(
    const kernel_vfs_getdents_request_t *request, uint64_t *written,
    uint64_t inode, int64_t next_offset, uint8_t type, const char *name);
uint8_t kernel_vfs_mode_to_dtype(uint16_t mode);
int kernel_vfs_device_directory_uses_backing_readdir(
    const char *path, const vfs_superblock_t *superblock);

int64_t kernel_vfs_getdents(
    const kernel_vfs_getdents_request_t *request);
int64_t arch_vfs_special_getdents64(
    const kernel_vfs_getdents_request_t *request, int *handled);
int arch_vfs_directory_open(int32_t descriptor,
                            kernel_vfs_directory_cursor_t *cursor);
int arch_vfs_directory_next(kernel_vfs_directory_cursor_t *cursor,
                            kernel_vfs_directory_entry_t *entry);
void arch_vfs_directory_commit(
    kernel_vfs_directory_cursor_t *cursor,
    const kernel_vfs_directory_entry_t *entry);
void arch_vfs_directory_finish(kernel_vfs_directory_cursor_t *cursor);

#endif
