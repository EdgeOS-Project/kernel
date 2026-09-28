/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent devpts instance configuration capacity test. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "vfs/vfs.h"

void *arch_vm_alloc_pages(uint64_t page_count) {
    return calloc(page_count, 4096u);
}

void arch_vm_free_page(void *page) {
    free(page);
}

const vfs_superblock_t *vfs_superblock_stable_const(
    const vfs_superblock_t *superblock) {
    return superblock;
}

vfs_superblock_t *vfs_superblock_stable(vfs_superblock_t *superblock) {
    return superblock;
}

const void *vfs_superblock_identity(const vfs_superblock_t *superblock) {
    return superblock;
}

vfs_superblock_t *vfs_superblock_acquire(vfs_superblock_t *superblock) {
    return superblock;
}

void vfs_superblock_release(vfs_superblock_t *superblock) {
    (void)superblock;
}

int tmpfs_mount_type(const char *device, const char *target,
                     const char *filesystem) {
    (void)device;
    (void)target;
    (void)filesystem;
    return -1;
}

int vfs_resolve(const char *path, vfs_inode_t *inode,
                vfs_superblock_t **superblock, vfs_inode_t *parent,
                char *last_component) {
    (void)path;
    (void)inode;
    (void)superblock;
    (void)parent;
    (void)last_component;
    return -1;
}

int vfs_umount(const char *target, int detach) {
    (void)target;
    (void)detach;
    return -1;
}

int vfs_inode_setattr(vfs_superblock_t *superblock, vfs_inode_t *inode,
                      uint16_t mode, uint32_t uid, uint32_t gid,
                      uint32_t valid) {
    (void)superblock;
    (void)inode;
    (void)mode;
    (void)uid;
    (void)gid;
    (void)valid;
    return -1;
}

int vfs_inode_refresh(vfs_superblock_t *superblock, vfs_inode_t *inode) {
    (void)superblock;
    (void)inode;
    return -1;
}

void vfs_path_cache_invalidate_all(void) {
}

#include "../../src/fs/devpts.c"

int main(void) {
    enum { INSTANCE_COUNT = 512 };
    devpts_mount_config_t expected;
    devpts_mount_config_t actual;
    vfs_superblock_t *superblocks =
        calloc(INSTANCE_COUNT, sizeof(*superblocks));

    assert(superblocks != 0);
    memset(&expected, 0, sizeof(expected));
    expected.mode = 0620u;
    expected.ptmx_mode = 0666u;
    expected.gid = 5u;
    expected.max_slaves = 4096u;

    for (uint32_t index = 0; index < INSTANCE_COUNT; ++index) {
        strcpy(superblocks[index].fs_name, "devpts");
        superblocks[index].fs_private = &superblocks[index];
        assert(devpts_config_install(&superblocks[index], &expected) == 0);
    }
    for (uint32_t index = 0; index < INSTANCE_COUNT; ++index) {
        memset(&actual, 0, sizeof(actual));
        assert(devpts_config_for_superblock(
                   &superblocks[index], &actual) == 0);
        assert(actual.mode == expected.mode);
        assert(actual.ptmx_mode == expected.ptmx_mode);
        assert(actual.gid == expected.gid);
        assert(actual.max_slaves == expected.max_slaves);
    }
    for (uint32_t index = 0; index < INSTANCE_COUNT; ++index)
        devpts_filesystem_release(&superblocks[index]);
    for (uint32_t index = 0; index < INSTANCE_COUNT; ++index)
        assert(devpts_config_for_superblock(
                   &superblocks[index], 0) < 0);

    for (uint32_t index = 0; index < INSTANCE_COUNT; ++index)
        assert(devpts_config_install(&superblocks[index], &expected) == 0);

    free(superblocks);
    puts("devpts_config_unit: PASS");
    return 0;
}
