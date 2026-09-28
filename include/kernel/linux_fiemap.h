/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-compatible FIEMAP ABI shared by every EdgeOS architecture. */

#ifndef EDGEOS_KERNEL_LINUX_FIEMAP_H
#define EDGEOS_KERNEL_LINUX_FIEMAP_H

#include <stdint.h>

#include "kernel/ioctl_runtime.h"
#include "vfs/vfs.h"

#define EDGE_LINUX_FS_IOC_FIEMAP 0xc020660bu

#define EDGE_LINUX_FIEMAP_FLAG_SYNC  0x00000001u
#define EDGE_LINUX_FIEMAP_FLAG_XATTR 0x00000002u
#define EDGE_LINUX_FIEMAP_FLAG_CACHE 0x00000004u

#define EDGE_LINUX_FIEMAP_EXTENT_LAST      0x00000001u
#define EDGE_LINUX_FIEMAP_EXTENT_UNKNOWN   0x00000002u
#define EDGE_LINUX_FIEMAP_EXTENT_UNWRITTEN 0x00000800u

typedef struct edge_linux_fiemap_extent {
    uint64_t logical;
    uint64_t physical;
    uint64_t length;
    uint64_t reserved64[2];
    uint32_t flags;
    uint32_t reserved[3];
} edge_linux_fiemap_extent_t;

typedef struct edge_linux_fiemap {
    uint64_t start;
    uint64_t length;
    uint32_t flags;
    uint32_t mapped_extents;
    uint32_t extent_count;
    uint32_t reserved;
} edge_linux_fiemap_t;

int64_t kernel_linux_fiemap_ioctl(
    vfs_superblock_t *sb, const vfs_inode_t *inode,
    const kernel_ioctl_request_t *request);

#endif
