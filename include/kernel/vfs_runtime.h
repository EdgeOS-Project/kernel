/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS current-task VFS runtime hooks.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_VFS_RUNTIME_H
#define EDGEOS_KERNEL_VFS_RUNTIME_H

#include <stdint.h>

#include "kernel/file_metadata.h"
#include "kernel/pipe_runtime.h"
#include "vfs/vfs.h"

typedef struct kernel_vfs_target {
    vfs_superblock_t *superblock;
    vfs_inode_t *inode;
    vfs_inode_t inode_storage;
    const char *resolved_path;
    /* O_TMPFILE without O_EXCL may acquire its first name through linkat. */
    int linkable_zero_link_inode;
    int path_only;
} kernel_vfs_target_t;

typedef struct kernel_vfs_xattr_scratch {
    char *path;
    uint32_t path_capacity;
    uint8_t *value;
    uint32_t value_capacity;
} kernel_vfs_xattr_scratch_t;

/*
 * mount(2) must keep source, target, filesystem data, and a normalized path
 * live at the same time.  These buffers belong to the current task so the
 * shared syscall policy never places several PATH_MAX objects on a kernel
 * stack and never aliases the xattr/path-resolution workspace.
 */
typedef struct kernel_vfs_mount_scratch {
    char *source;
    char *target;
    char *data;
    char *workspace;
    uint32_t capacity;
} kernel_vfs_mount_scratch_t;

typedef struct kernel_vfs_current_context {
    const char *root;
    const char *cwd;
    char *paths[8];
    uint32_t path_capacity;
    uint8_t *xattr;
    uint32_t xattr_capacity;
    void *resolve_workspace;
    uint32_t resolve_workspace_capacity;
} kernel_vfs_current_context_t;

typedef enum kernel_vfs_open_flag {
    KERNEL_VFS_OPEN_CREATE = 1u << 0,
    KERNEL_VFS_OPEN_EXCLUSIVE = 1u << 1,
    KERNEL_VFS_OPEN_NO_CONTROLLING_TTY = 1u << 2,
    KERNEL_VFS_OPEN_TRUNCATE = 1u << 3,
    KERNEL_VFS_OPEN_APPEND = 1u << 4,
    KERNEL_VFS_OPEN_NONBLOCK = 1u << 5,
    KERNEL_VFS_OPEN_DIRECTORY = 1u << 6,
    KERNEL_VFS_OPEN_NOFOLLOW = 1u << 7,
    KERNEL_VFS_OPEN_CLOEXEC = 1u << 8,
    KERNEL_VFS_OPEN_PATH = 1u << 9,
    KERNEL_VFS_OPEN_TMPFILE = 1u << 10,
} kernel_vfs_open_flag_t;

typedef enum kernel_vfs_open_access_mode {
    KERNEL_VFS_OPEN_READ_ONLY = 0,
    KERNEL_VFS_OPEN_WRITE_ONLY = 1,
    KERNEL_VFS_OPEN_READ_WRITE = 2,
} kernel_vfs_open_access_mode_t;

typedef struct kernel_vfs_open_request {
    int32_t directory;
    uint32_t linux_flags;
    uint64_t user_path;
    void *user_registers;
    const char *path;
    uint64_t resolve_flags;
    uint32_t flags;
    uint16_t mode;
    uint8_t access_mode;
    uint8_t reserved;
} kernel_vfs_open_request_t;

typedef enum kernel_vfs_sync_operation {
    KERNEL_VFS_SYNC_FILE = 1,
    KERNEL_VFS_SYNC_DATA,
    KERNEL_VFS_SYNC_FILESYSTEM,
    KERNEL_VFS_SYNC_RANGE,
} kernel_vfs_sync_operation_t;

typedef enum kernel_vfs_descriptor_kind {
    KERNEL_VFS_DESCRIPTOR_REGULAR = 1,
    KERNEL_VFS_DESCRIPTOR_MEMORY,
    KERNEL_VFS_DESCRIPTOR_DIRECTORY,
    KERNEL_VFS_DESCRIPTOR_PIPE,
    KERNEL_VFS_DESCRIPTOR_SOCKET,
    KERNEL_VFS_DESCRIPTOR_TERMINAL,
    KERNEL_VFS_DESCRIPTOR_PSEUDO_TERMINAL,
    KERNEL_VFS_DESCRIPTOR_DEVICE,
    KERNEL_VFS_DESCRIPTOR_NAMESPACE,
    KERNEL_VFS_DESCRIPTOR_ANONYMOUS,
    KERNEL_VFS_DESCRIPTOR_OTHER,
} kernel_vfs_descriptor_kind_t;

typedef struct kernel_vfs_descriptor {
    kernel_vfs_descriptor_kind_t kind;
    uint64_t identity;
    int readable;
    int writable;
    uint32_t seals;
    uint64_t size;
    uint64_t maximum_size;
    uint64_t mount_id;
    vfs_superblock_t *superblock;
    vfs_inode_t *inode;
    kernel_pipe_runtime_t *pipe;
    uint8_t *scratch;
    uint32_t scratch_capacity;
} kernel_vfs_descriptor_t;

typedef struct kernel_vfs_cache_stats {
    uint64_t cached_pages;
    uint64_t dirty_pages;
    uint64_t writeback_pages;
    uint64_t evicted_pages;
    uint64_t recently_evicted_pages;
} kernel_vfs_cache_stats_t;

int kernel_file_metadata_from_descriptor(
    const kernel_vfs_descriptor_t *description,
    kernel_file_metadata_t *metadata);

#define KERNEL_VFS_SEAL_SEAL         0x0001u
#define KERNEL_VFS_SEAL_SHRINK       0x0002u
#define KERNEL_VFS_SEAL_GROW         0x0004u
#define KERNEL_VFS_SEAL_WRITE        0x0008u
#define KERNEL_VFS_SEAL_FUTURE_WRITE 0x0010u

int kernel_vfs_current_xattr_scratch(kernel_vfs_xattr_scratch_t *scratch);
int kernel_vfs_current_mount_scratch(kernel_vfs_mount_scratch_t *scratch);
int kernel_vfs_open_access_mask(const kernel_vfs_open_request_t *request,
                                int newly_created);
int64_t kernel_vfs_open_magic_fd(
    const kernel_vfs_open_request_t *request, const char *path,
    int *handled);
/* linux_flags remains available for descriptor status and F_GETFL. */
int64_t kernel_vfs_open_at(const kernel_vfs_open_request_t *request);
int kernel_vfs_resolve_at_path(int32_t directory, const char *path,
                               char *output, uint32_t capacity);
int kernel_vfs_path_result(int result);
int kernel_vfs_resolve_current_path(const char *path, char *output,
                                    uint32_t capacity);
int kernel_vfs_rebase_pivot_path(const char *new_root,
                                 const char *put_old,
                                 const char *path,
                                 char *output,
                                 uint32_t capacity);
int kernel_vfs_rebase_pivot_fs_location(const char *new_root,
                                        const char *put_old,
                                        const char *path,
                                        char *output,
                                        uint32_t capacity);
int kernel_vfs_rebase_move_path(const char *source, const char *target,
                                const char *path, char *output,
                                uint32_t capacity);
int kernel_vfs_pivot_root(const char *new_root, const char *put_old);
int kernel_vfs_resolve_path(const char *path, int nofollow,
                            kernel_vfs_target_t *target);
int kernel_vfs_resolve_fd(int32_t descriptor, kernel_vfs_target_t *target);
int kernel_vfs_install_inode_descriptor(vfs_superblock_t *superblock,
                                        const vfs_inode_t *inode,
                                        uint32_t status_flags,
                                        uint32_t descriptor_flags,
                                        int linkable_zero_link_inode);
int kernel_vfs_truncate_target(kernel_vfs_target_t *target, uint32_t length);
int kernel_vfs_truncate_result(int result);
int kernel_vfs_metadata_at(int32_t directory, const char *path, int nofollow,
                           kernel_file_metadata_t *metadata);
int kernel_vfs_metadata_fd(int32_t descriptor,
                           kernel_file_metadata_t *metadata);
int kernel_vfs_sync_descriptor(int32_t descriptor,
                               kernel_vfs_sync_operation_t operation);
int kernel_vfs_sync_descriptor_range(int32_t descriptor, uint64_t offset,
                                     uint64_t length, uint32_t flags);
int kernel_vfs_describe_descriptor(int32_t descriptor,
                                   kernel_vfs_descriptor_t *description);
int kernel_vfs_cachestat(int32_t descriptor, uint64_t offset,
                         uint64_t length,
                         kernel_vfs_cache_stats_t *statistics);
int kernel_vfs_fallocate_descriptor(int32_t descriptor, uint32_t mode,
                                    uint64_t offset, uint64_t length);
int kernel_vfs_fallocate_inode_transaction(vfs_superblock_t *superblock,
                                           vfs_inode_t *inode,
                                           uint32_t mode, uint64_t offset,
                                           uint64_t length);
int kernel_vfs_truncate_path(const char *path, kernel_vfs_target_t *target,
                             uint32_t length);
int kernel_vfs_truncate_descriptor(int32_t descriptor, uint32_t length);
int kernel_vfs_truncate_inode_transaction(vfs_superblock_t *superblock,
                                          vfs_inode_t *inode,
                                          uint32_t length);
int kernel_vfs_readlink_target(const char *path, char *target,
                               uint32_t capacity);
void kernel_vfs_notify_create(const char *path, int directory);
void kernel_vfs_notify_attrib(const char *path);
void kernel_vfs_notify_link(const char *source, const char *destination);
void kernel_vfs_notify_remove(const char *path, int directory);
void kernel_vfs_notify_rename(const char *old_path, const char *new_path);

/*
 * Architecture adapters expose current-task storage and native notification
 * delivery. Linux-visible validation and path policy stay in common code.
 */
int arch_vfs_current_context(kernel_vfs_current_context_t *context);
int arch_vfs_current_mount_namespace(uint32_t *namespace_id);
int arch_vfs_resolve_fd(int32_t descriptor, kernel_vfs_target_t *target);
int arch_vfs_install_inode_descriptor(vfs_superblock_t *superblock,
                                      const vfs_inode_t *inode,
                                      uint32_t status_flags,
                                      uint32_t descriptor_flags,
                                      int linkable_zero_link_inode);
int arch_vfs_reopen_fifo_descriptor(
    int32_t source, const kernel_vfs_open_request_t *request);
int arch_vfs_metadata_fd(int32_t descriptor,
                         kernel_file_metadata_t *metadata);
int arch_vfs_sync_descriptor(int32_t descriptor,
                             kernel_vfs_sync_operation_t operation);
int arch_vfs_describe_descriptor(int32_t descriptor,
                                 kernel_vfs_descriptor_t *description);
int arch_vfs_cachestat(int32_t descriptor, uint64_t offset,
                       uint64_t length,
                       kernel_vfs_cache_stats_t *statistics);
int arch_vfs_fallocate_descriptor(int32_t descriptor, uint32_t mode,
                                  uint64_t offset, uint64_t length);
int arch_vfs_fallocate_prepare(vfs_superblock_t *superblock,
                               const vfs_inode_t *inode, uint32_t mode,
                               uint64_t offset, uint64_t length);
void arch_vfs_fallocate_commit(vfs_superblock_t *superblock,
                               const vfs_inode_t *inode, uint32_t mode,
                               uint64_t offset, uint64_t length);
int arch_vfs_truncate_descriptor(int32_t descriptor, uint32_t length);
int arch_vfs_truncate_prepare(vfs_superblock_t *superblock,
                              const vfs_inode_t *inode,
                              uint32_t old_length, uint32_t new_length);
void arch_vfs_truncate_commit(vfs_superblock_t *superblock,
                              const vfs_inode_t *inode,
                              uint32_t old_length, uint32_t new_length);
int arch_vfs_readlink_path(const char *path, char *target,
                           uint32_t capacity);
int arch_vfs_metadata_path_prepare(const char *path, int nofollow,
                                   char *output, uint32_t capacity);
int arch_vfs_special_path_metadata(
    const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, kernel_file_metadata_t *metadata,
    int *handled);
int64_t arch_vfs_open_special(
    const kernel_vfs_open_request_t *request, const char *path,
    int *handled);
int arch_vfs_open_install_regular(
    const kernel_vfs_open_request_t *request, const char *path,
    const vfs_inode_t *inode, vfs_superblock_t *superblock,
    int unlink_after_open);
void arch_vfs_rebase_mount_namespace_paths(
    uint32_t namespace_id, const char *new_root, const char *put_old);
void arch_vfs_rebase_mount_move_paths(
    uint32_t namespace_id, const char *source, const char *target);
void arch_vfs_notify_path(const char *path, uint32_t mask);
void arch_vfs_notify_move(const char *old_path, const char *new_path);

#endif
