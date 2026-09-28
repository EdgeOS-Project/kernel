#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_fiemap.h"

typedef struct test_buffer {
    edge_linux_fiemap_t header;
    edge_linux_fiemap_extent_t extents[4];
} test_buffer_t;

static int g_sync_calls;

static int copy_from_user(void *context, void *destination,
                          uint64_t source, uint64_t length) {
    (void)context;
    memcpy(destination, (const void *)(uintptr_t)source, length);
    return 0;
}

static int copy_to_user(void *context, uint64_t destination,
                        const void *source, uint64_t length) {
    (void)context;
    memcpy((void *)(uintptr_t)destination, source, length);
    return 0;
}

static int test_sync_inode(vfs_superblock_t *sb,
                           const vfs_inode_t *inode, int data_only) {
    (void)sb;
    (void)inode;
    (void)data_only;
    ++g_sync_calls;
    return 0;
}

int vfs_sync_inode(vfs_superblock_t *sb, const vfs_inode_t *inode,
                   int data_only) {
    return sb && sb->ops && sb->ops->sync_inode ?
        sb->ops->sync_inode(sb, inode, data_only) : 0;
}

static int test_map_extent(vfs_superblock_t *sb,
                           const vfs_inode_t *inode,
                           uint64_t offset, uint64_t length,
                           vfs_extent_t *extent) {
    (void)sb;
    (void)inode;
    (void)length;
    memset(extent, 0, sizeof(*extent));
    if (offset == 0) {
        extent->logical = 0;
        extent->physical = 0x100000;
        extent->length = 4096;
        return 0;
    }
    if (offset <= 32768) {
        extent->logical = 32768;
        extent->physical = 0x200000;
        extent->length = 4096;
        extent->flags = VFS_EXTENT_FLAG_LAST |
                        VFS_EXTENT_FLAG_UNWRITTEN;
        return 0;
    }
    return VFS_EXTENT_ERR_NO_DATA;
}

static kernel_ioctl_request_t request_for(test_buffer_t *buffer) {
    kernel_ioctl_request_t request;
    memset(&request, 0, sizeof(request));
    request.command = EDGE_LINUX_FS_IOC_FIEMAP;
    request.argument = (uint64_t)(uintptr_t)buffer;
    request.copy_from_user = copy_from_user;
    request.copy_to_user = copy_to_user;
    return request;
}

int main(void) {
    filesystem_ops_t operations;
    vfs_superblock_t superblock;
    vfs_inode_t inode;
    kernel_ioctl_request_t request;
    test_buffer_t buffer;

    memset(&operations, 0, sizeof(operations));
    memset(&superblock, 0, sizeof(superblock));
    memset(&inode, 0, sizeof(inode));
    operations.map_extent = test_map_extent;
    operations.sync_inode = test_sync_inode;
    superblock.ops = &operations;
    inode.mode = VFS_INODE_FILE;
    inode.size = 65536;

    memset(&buffer, 0, sizeof(buffer));
    buffer.header.length = UINT64_MAX;
    buffer.header.extent_count = 4;
    buffer.header.flags = EDGE_LINUX_FIEMAP_FLAG_SYNC;
    request = request_for(&buffer);
    assert(kernel_linux_fiemap_ioctl(&superblock, &inode, &request) == 0);
    assert(g_sync_calls == 1);
    assert(buffer.header.mapped_extents == 2);
    assert(buffer.extents[0].logical == 0);
    assert(buffer.extents[0].physical == 0x100000);
    assert(buffer.extents[0].length == 4096);
    assert(buffer.extents[0].flags == 0);
    assert(buffer.extents[1].logical == 32768);
    assert(buffer.extents[1].physical == 0x200000);
    assert(buffer.extents[1].length == 4096);
    assert(buffer.extents[1].flags ==
           (EDGE_LINUX_FIEMAP_EXTENT_LAST |
            EDGE_LINUX_FIEMAP_EXTENT_UNWRITTEN));

    memset(&buffer, 0, sizeof(buffer));
    buffer.header.length = UINT64_MAX;
    buffer.header.extent_count = 1;
    request = request_for(&buffer);
    assert(kernel_linux_fiemap_ioctl(&superblock, &inode, &request) == 0);
    assert(buffer.header.mapped_extents == 1);
    assert(buffer.extents[0].logical == 0);

    memset(&buffer, 0, sizeof(buffer));
    buffer.header.length = UINT64_MAX;
    request = request_for(&buffer);
    assert(kernel_linux_fiemap_ioctl(&superblock, &inode, &request) == 0);
    assert(buffer.header.mapped_extents == 2);

    buffer.header.flags = 0x80000000u;
    assert(kernel_linux_fiemap_ioctl(&superblock, &inode, &request) ==
           -EDGE_LINUX_EBADR);
    buffer.header.flags = EDGE_LINUX_FIEMAP_FLAG_XATTR;
    assert(kernel_linux_fiemap_ioctl(&superblock, &inode, &request) ==
           -EDGE_LINUX_EOPNOTSUPP);

    operations.map_extent = 0;
    buffer.header.flags = 0;
    assert(kernel_linux_fiemap_ioctl(&superblock, &inode, &request) ==
           -EDGE_LINUX_EOPNOTSUPP);
    return 0;
}
