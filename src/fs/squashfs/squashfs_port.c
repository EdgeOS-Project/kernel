/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS block I/O and page allocation adapter for SquashFUSE. */

#include <stddef.h>
#include <stdint.h>

#include "mm/arch_vm.h"
#include "string.h"
#include "upstream/fs.h"
#include "upstream/nonstd.h"
#include "upstream/sqfs_port.h"

#define EDGE_SQFS_PAGE_SIZE 4096u
#define EDGE_SQFS_ALLOCATION_MAGIC 0x53514653u

typedef struct edge_sqfs_allocation {
    uint32_t magic;
    uint32_t pages;
} edge_sqfs_allocation_t;

void *edge_sqfs_alloc(size_t size) {
    edge_sqfs_allocation_t *allocation;
    uint64_t required;
    uint32_t pages;

    if (!size) size = 1u;
    required = (uint64_t)sizeof(*allocation) + size;
    if (required > UINT32_MAX) return 0;
    pages = (uint32_t)((required + EDGE_SQFS_PAGE_SIZE - 1u) /
                       EDGE_SQFS_PAGE_SIZE);
    allocation = (edge_sqfs_allocation_t *)arch_vm_alloc_pages(pages);
    if (!allocation) return 0;
    allocation->magic = EDGE_SQFS_ALLOCATION_MAGIC;
    allocation->pages = pages;
    return allocation + 1;
}

void *edge_sqfs_calloc(size_t count, size_t size) {
    void *pointer;
    uint64_t bytes = (uint64_t)count * size;

    if (size && bytes / size != count) return 0;
    if (bytes > UINT32_MAX) return 0;
    pointer = edge_sqfs_alloc((size_t)bytes);
    if (pointer) memset(pointer, 0, (size_t)bytes);
    return pointer;
}

void edge_sqfs_free(void *pointer) {
    edge_sqfs_allocation_t *allocation;

    if (!pointer) return;
    allocation = (edge_sqfs_allocation_t *)pointer - 1;
    if (allocation->magic != EDGE_SQFS_ALLOCATION_MAGIC) return;
    allocation->magic = 0;
    for (uint32_t page = 0; page < allocation->pages; ++page)
        arch_vm_free_page((uint8_t *)allocation +
                          (uint64_t)page * EDGE_SQFS_PAGE_SIZE);
}

ssize_t sqfs_pread(sqfs_fd_t device, void *buffer, size_t count,
                   sqfs_off_t offset) {
    int64_t result;

    if (!device || !buffer || offset < 0 || count > UINT32_MAX)
        return -1;
    result = block_read_bytes(device, (uint64_t)offset, buffer,
                              (uint32_t)count);
    return result < 0 ? -1 : (ssize_t)result;
}

sqfs_mode_t sqfs_mode(int inode_type) {
    switch (inode_type) {
        case SQUASHFS_DIR_TYPE:
        case SQUASHFS_LDIR_TYPE:
            return S_IFDIR;
        case SQUASHFS_REG_TYPE:
        case SQUASHFS_LREG_TYPE:
            return S_IFREG;
        case SQUASHFS_SYMLINK_TYPE:
        case SQUASHFS_LSYMLINK_TYPE:
            return S_IFLNK;
        case SQUASHFS_BLKDEV_TYPE:
        case SQUASHFS_LBLKDEV_TYPE:
            return S_IFBLK;
        case SQUASHFS_CHRDEV_TYPE:
        case SQUASHFS_LCHRDEV_TYPE:
            return S_IFCHR;
        case SQUASHFS_FIFO_TYPE:
        case SQUASHFS_LFIFO_TYPE:
            return S_IFIFO;
        case SQUASHFS_SOCKET_TYPE:
        case SQUASHFS_LSOCKET_TYPE:
            return S_IFSOCK;
        default:
            return 0;
    }
}
