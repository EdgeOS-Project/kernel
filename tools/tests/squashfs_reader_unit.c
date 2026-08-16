/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side reader test against a real SquashFS image. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fs/squashfs/upstream/dir.h"
#include "fs/squashfs/upstream/file.h"
#include "fs/squashfs/upstream/fs.h"
#include "fs/squashfs/upstream/xattr.h"

#undef calloc
#undef free
#undef malloc

void *edge_sqfs_alloc(size_t size) {
    return malloc(size ? size : 1u);
}

void *edge_sqfs_calloc(size_t count, size_t size) {
    return calloc(count ? count : 1u, size ? size : 1u);
}

void edge_sqfs_free(void *pointer) {
    free(pointer);
}

uint64_t block_device_size_bytes(const block_device_t *device) {
    return device ? (uint64_t)device->sector_size * device->sector_count : 0;
}

ssize_t sqfs_pread(sqfs_fd_t device, void *buffer, size_t count,
                   sqfs_off_t offset) {
    FILE *image;

    if (!device || !device->ctx || offset < 0) return -1;
    image = (FILE *)device->ctx;
    if (fseeko(image, (off_t)offset, SEEK_SET) != 0) return -1;
    return (ssize_t)fread(buffer, 1u, count, image);
}

sqfs_mode_t sqfs_mode(int inode_type) {
    switch (inode_type) {
        case SQUASHFS_DIR_TYPE:
        case SQUASHFS_LDIR_TYPE: return S_IFDIR;
        case SQUASHFS_REG_TYPE:
        case SQUASHFS_LREG_TYPE: return S_IFREG;
        case SQUASHFS_SYMLINK_TYPE:
        case SQUASHFS_LSYMLINK_TYPE: return S_IFLNK;
        case SQUASHFS_BLKDEV_TYPE:
        case SQUASHFS_LBLKDEV_TYPE: return S_IFBLK;
        case SQUASHFS_CHRDEV_TYPE:
        case SQUASHFS_LCHRDEV_TYPE: return S_IFCHR;
        case SQUASHFS_FIFO_TYPE:
        case SQUASHFS_LFIFO_TYPE: return S_IFIFO;
        case SQUASHFS_SOCKET_TYPE:
        case SQUASHFS_LSOCKET_TYPE: return S_IFSOCK;
        default: return 0;
    }
}

static void load_path(sqfs *reader, const char *path, sqfs_inode *inode) {
    bool found = false;

    assert(sqfs_inode_get(reader, inode, sqfs_inode_root(reader)) == SQFS_OK);
    assert(sqfs_lookup_path(reader, inode, path, &found) == SQFS_OK);
    assert(found);
}

int main(int argc, char **argv) {
    block_device_t device;
    sqfs reader;
    sqfs_inode inode;
    FILE *image;
    long image_size;
    char buffer[128];
    sqfs_off_t read_size;
    size_t xattr_size;

    assert(argc == 2);
    image = fopen(argv[1], "rb");
    assert(image != NULL);
    assert(fseeko(image, 0, SEEK_END) == 0);
    image_size = ftello(image);
    assert(image_size > 0 && (uint64_t)image_size <= UINT32_MAX);
    memset(&device, 0, sizeof(device));
    device.present = 1;
    device.sector_size = 1u;
    device.sector_count = (uint32_t)image_size;
    device.ctx = image;

    assert(sqfs_init(&reader, &device, 0) == SQFS_OK);
    assert(reader.sb.s_major == 4u && reader.sb.s_minor == 0u);

    load_path(&reader, "marker.txt", &inode);
    read_size = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));
    assert(sqfs_read_range(&reader, &inode, 0, &read_size, buffer) == SQFS_OK);
    assert(read_size == strlen("edgeos-squashfs-runtime\n"));
    assert(memcmp(buffer, "edgeos-squashfs-runtime\n", read_size) == 0);

    xattr_size = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));
    assert(sqfs_xattr_lookup(&reader, &inode, "user.edgeos",
                             buffer, &xattr_size) == SQFS_OK);
    assert(xattr_size == strlen("verified"));
    assert(memcmp(buffer, "verified", xattr_size) == 0);

    load_path(&reader, "marker-link", &inode);
    xattr_size = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));
    assert(sqfs_readlink(&reader, &inode, buffer, &xattr_size) == SQFS_OK);
    assert(strcmp(buffer, "marker.txt") == 0);

    load_path(&reader, "payload/large-zero.bin", &inode);
    read_size = sizeof(buffer);
    memset(buffer, 0xff, sizeof(buffer));
    assert(sqfs_read_range(&reader, &inode, 131000, &read_size, buffer) ==
           SQFS_OK);
    assert(read_size == sizeof(buffer));
    for (size_t index = 0; index < sizeof(buffer); ++index)
        assert(buffer[index] == 0);

    sqfs_destroy(&reader);
    fclose(image);
    puts("squashfs_reader_unit: PASS");
    return 0;
}
