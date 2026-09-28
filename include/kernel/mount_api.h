/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent descriptor mount API.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_MOUNT_API_H
#define EDGEOS_KERNEL_MOUNT_API_H

#include <stdint.h>

#include "vfs/vfs.h"
#include "kernel/io_runtime.h"

#define KERNEL_MOUNT_API_SET_FLAG         0u
#define KERNEL_MOUNT_API_SET_STRING       1u
#define KERNEL_MOUNT_API_SET_BINARY       2u
#define KERNEL_MOUNT_API_SET_PATH         3u
#define KERNEL_MOUNT_API_SET_PATH_EMPTY   4u
#define KERNEL_MOUNT_API_SET_FD           5u
#define KERNEL_MOUNT_API_CREATE           6u
#define KERNEL_MOUNT_API_RECONFIGURE      7u
#define KERNEL_MOUNT_API_CREATE_EXCLUSIVE 8u

/* The caller supplies one reference; accepted options acquire their own.
 * The final release calls destroy outside the mount-object lock. */
typedef struct kernel_mount_api_file_reference {
    kernel_io_path_snapshot_t snapshot;
    uint32_t references;
    void (*destroy)(struct kernel_mount_api_file_reference *reference);
} kernel_mount_api_file_reference_t;

void kernel_mount_api_file_reference_release(
    kernel_mount_api_file_reference_t *reference);
int kernel_mount_api_context_check(int object_id);
int kernel_mount_api_context_file_option_check(int object_id, const char *key);
int kernel_mount_api_context_configure_file(
    int object_id, const char *key, kernel_mount_api_file_reference_t *reference);

int kernel_mount_api_filesystem_supported(const char *filesystem);
int kernel_mount_api_context_create(const char *filesystem);
int kernel_mount_api_context_pick(const char *path);
int kernel_mount_api_context_pick_object(int object_id);
int kernel_mount_api_context_configure(
    int object_id, uint32_t command, const char *key, const char *value,
    int32_t auxiliary, char *workspace, uint32_t workspace_capacity);
int kernel_mount_api_context_mount(int context_id, uint64_t attributes);
int kernel_mount_api_tree_open(const char *path, int clone, int recursive);
int kernel_mount_api_tree_open_resolved(
    const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, uint32_t propagation,
    int clone, int recursive);
int kernel_mount_api_mount_attach(
    int object_id, char *target, char *workspace,
    uint32_t workspace_capacity);
int kernel_mount_api_mount_attach_resolved(
    int object_id, char *target, const vfs_inode_t *target_inode,
    char *workspace, uint32_t workspace_capacity);
int kernel_mount_api_mount_setattr(
    int object_id, uint64_t attr_set, uint64_t attr_clear,
    uint64_t propagation, int recursive);
/* The caller must hold a mount-object reference while using the root. */
int kernel_mount_api_root(int object_id, vfs_superblock_t **superblock_out,
                           vfs_inode_t *inode_out);
int kernel_mount_api_resolve_relative(
    int object_id, const char *relative_path, int nofollow,
    char *resolved_path, uint32_t resolved_capacity,
    vfs_superblock_t **superblock_out, vfs_inode_t *inode_out);
int kernel_mount_api_resolve(
    int object_id, char *path, uint32_t path_capacity,
    uint64_t *attributes);
int kernel_mount_api_retain(int object_id);
void kernel_mount_api_release(int object_id);

#endif
