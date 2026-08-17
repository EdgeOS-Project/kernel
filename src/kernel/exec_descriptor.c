/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent executable descriptor adapter.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "fs/tmpfs.h"
#include "kernel/exec_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/vfs_runtime.h"

static void exec_descriptor_source_clear(
    kernel_exec_descriptor_source_t *source) {
    if (source) memset(source, 0, sizeof(*source));
}

void kernel_exec_descriptor_source_release(
    kernel_exec_descriptor_source_t *source) {
    if (!source || !source->active) return;
    vfs_inode_close(source->superblock, &source->inode);
    exec_descriptor_source_clear(source);
}

int kernel_exec_descriptor_source_acquire(
    int32_t descriptor, kernel_exec_descriptor_source_t *source) {
    kernel_vfs_descriptor_t description;
    kernel_io_file_range_scratch_t scratch;
    vfs_inode_t inode;
    vfs_superblock_t *superblock = 0;
    uint64_t offset = 0;
    int status;

    if (!source || descriptor < 0) return -EDGE_LINUX_EBADF;
    exec_descriptor_source_clear(source);
    status = kernel_vfs_describe_descriptor(descriptor, &description);
    if (status < 0) return status;
    if (description.kind != KERNEL_VFS_DESCRIPTOR_MEMORY)
        return -EDGE_LINUX_EACCES;
    if (description.size > UINT32_MAX)
        return -EDGE_LINUX_EFBIG;
    if (kernel_io_file_range_current_scratch(&scratch) < 0 ||
        !scratch.buffer || !scratch.capacity)
        return -EDGE_LINUX_ENOMEM;
    if (tmpfs_create_anonymous(0777u, 0u, &inode, &superblock) < 0)
        return -EDGE_LINUX_ENOSPC;
    if (vfs_inode_open(superblock, &inode) < 0) {
        tmpfs_release_anonymous(superblock, &inode);
        return -EDGE_LINUX_ENFILE;
    }
    tmpfs_release_anonymous(superblock, &inode);

    source->inode = inode;
    source->superblock = superblock;
    source->active = 1u;
    while (offset < description.size) {
        uint64_t remaining = description.size - offset;
        uint32_t chunk = remaining > scratch.capacity ?
            scratch.capacity : (uint32_t)remaining;
        int64_t read = kernel_io_file_range_read(
            descriptor, offset, scratch.buffer, chunk);
        int written;

        if (read < 0) {
            status = (int)read;
            goto fail;
        }
        if (!read || (uint64_t)read > chunk) {
            status = -EDGE_LINUX_EIO;
            goto fail;
        }
        written = superblock->ops->write(
            superblock, &source->inode, (uint32_t)offset,
            scratch.buffer, (uint32_t)read);
        if (written != read) {
            status = written < 0 ? written : -EDGE_LINUX_EIO;
            goto fail;
        }
        offset += (uint64_t)read;
    }
    if (tmpfs_memfd_add_seals(
            superblock, &source->inode, description.seals) < 0) {
        status = -EDGE_LINUX_EPERM;
        goto fail;
    }
    return 0;

fail:
    kernel_exec_descriptor_source_release(source);
    return status;
}
