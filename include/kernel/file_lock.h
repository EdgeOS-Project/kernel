/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux-compatible advisory file locking.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_FILE_LOCK_H
#define EDGEOS_KERNEL_FILE_LOCK_H

#include <stdint.h>

#include "kernel/linux_abi.h"

typedef struct kernel_file_lock_info {
    uint64_t filesystem;
    uint64_t inode;
    uint64_t open_description;
    uint64_t offset;
    uint64_t size;
    uint32_t status_flags;
    uint32_t description_references;
    int32_t process_id;
    int32_t task_id;
} kernel_file_lock_info_t;

enum edge_linux_file_lock_object_class {
    EDGE_FILE_LOCK_OBJECT_TTY = 1,
    EDGE_FILE_LOCK_OBJECT_NULL,
    EDGE_FILE_LOCK_OBJECT_PIPE,
    EDGE_FILE_LOCK_OBJECT_SOCKET,
    EDGE_FILE_LOCK_OBJECT_PTY_MASTER,
    EDGE_FILE_LOCK_OBJECT_PTY_SLAVE,
    EDGE_FILE_LOCK_OBJECT_EVENTFD,
    EDGE_FILE_LOCK_OBJECT_TIMERFD,
    EDGE_FILE_LOCK_OBJECT_SIGNALFD,
    EDGE_FILE_LOCK_OBJECT_EPOLL,
    EDGE_FILE_LOCK_OBJECT_PIDFD,
    EDGE_FILE_LOCK_OBJECT_INOTIFY,
    EDGE_FILE_LOCK_OBJECT_MEMFD,
    EDGE_FILE_LOCK_OBJECT_NAMESPACE,
    EDGE_FILE_LOCK_OBJECT_FBDEV,
    EDGE_FILE_LOCK_OBJECT_INPUT,
    EDGE_FILE_LOCK_OBJECT_ANONYMOUS,
};

/* Construct a stable lock-manager identity for descriptors without a VFS inode. */
void edge_linux_file_lock_pseudo_identity(
    uint32_t object_class, uint64_t object_identity, const char *path,
    uint64_t *filesystem, uint64_t *inode);

/* Descriptor and scheduler mechanisms supplied by each architecture runtime. */
int arch_fd_file_lock_info(int32_t descriptor,
                           kernel_file_lock_info_t *information);
int arch_file_lock_wait_prepare(void *user_registers, int32_t task_id);
int64_t arch_file_lock_wait_park(int32_t task_id);
/* Called with the common lock-manager spinlock held; this must not reenter it. */
void arch_file_lock_wake(int32_t task_id, int64_t result);

int64_t edge_linux_file_lock_fcntl(
    int32_t descriptor, uint32_t command, uint64_t user_lock,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context,
    void *user_registers);
int64_t edge_linux_file_lock_flock(int32_t descriptor, uint32_t operation,
                                   void *user_registers);

void edge_linux_file_lock_descriptor_closed(
    const kernel_file_lock_info_t *information);
void edge_linux_file_lock_task_exit(int32_t task_id);
int edge_linux_file_lock_cancel_wait(int32_t task_id, int64_t result);

#endif
