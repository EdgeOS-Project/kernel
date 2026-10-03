/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define STRING_H
#define STDIO_H
#include "../../src/fs/initramfs.c"

static int found;
static int synthetic;
static int removals;
static uint16_t existing_mode;
static vfs_superblock_t existing_superblock;

int vfs_resolve_nofollow(const char *path, vfs_inode_t *inode,
                         vfs_superblock_t **superblock) {
    assert(path);
    if (!found) return -1;
    memset(inode, 0, sizeof(*inode));
    inode->mode = existing_mode;
    *superblock = synthetic ? 0 : &existing_superblock;
    return 0;
}

int vfs_unlink(const char *path) {
    assert(path && !synthetic);
    ++removals;
    return 0;
}

int vfs_rmdir(const char *path) {
    assert(path && !synthetic);
    ++removals;
    return 0;
}

int main(void) {
    assert(initramfs_prepare_destination("/dev/fd", VFS_INODE_LNK, 0) == 0);
    found = synthetic = 1;
    existing_mode = VFS_INODE_DIR | 0555;
    assert(initramfs_prepare_destination("/dev/fd", VFS_INODE_LNK, 0) == 0);
    assert(removals == 0);
    assert(initramfs_prepare_destination("/dev/console", VFS_INODE_CHR, 0) == 0);
    assert(initramfs_prepare_destination("/dev/fd", VFS_INODE_FILE, 0) < 0);
    synthetic = 0;
    existing_mode = VFS_INODE_LNK | 0777;
    assert(initramfs_prepare_destination("/dev/fd", VFS_INODE_LNK, 0) == 0);
    assert(removals == 1);
    existing_mode = VFS_INODE_FILE | 0644;
    assert(initramfs_prepare_destination("/file", VFS_INODE_FILE, 1) == 1);
    assert(removals == 1);
    puts("initramfs_destination_unit: PASS");
    return 0;
}
