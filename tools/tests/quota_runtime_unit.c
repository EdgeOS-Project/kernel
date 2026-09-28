/* SPDX-License-Identifier: MPL-2.0 */
/* Host unit coverage for the shared Linux quota control service. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/quota_runtime.h"

static int g_sync_count;

const void *vfs_superblock_identity(const vfs_superblock_t *superblock) {
    return superblock ? superblock->fs_private : 0;
}

static int test_sync(vfs_superblock_t *superblock) {
    (void)superblock;
    ++g_sync_count;
    return 0;
}

static int check(int condition, const char *name) {
    if (condition) return 0;
    fprintf(stderr, "FAIL %s\n", name);
    return 1;
}

int main(void) {
    filesystem_ops_t operations;
    filesystem_ops_t coherent_operations;
    vfs_superblock_t first;
    vfs_superblock_t alias;
    vfs_superblock_t coherent;
    kernel_quota_block_t set;
    kernel_quota_block_t get;
    kernel_quota_next_block_t next;
    kernel_quota_info_t information;
    uint32_t identity;
    uint32_t coherent_identity;
    uint32_t format = 0;
    int failures = 0;

    memset(&operations, 0, sizeof(operations));
    operations.sync = test_sync;
    memset(&first, 0, sizeof(first));
    first.ops = &operations;
    first.fs_private = &identity;
    alias = first;

    failures += check(kernel_quota_format(
                          &first, KERNEL_QUOTA_USER, &format) ==
                          -EDGE_LINUX_ESRCH,
                      "disabled format");
    failures += check(kernel_quota_enable(
                          &first, KERNEL_QUOTA_USER,
                          KERNEL_QUOTA_FORMAT_VFS_V1) == 0,
                      "enable user quota");
    failures += check(kernel_quota_enable(
                          &first, KERNEL_QUOTA_USER,
                          KERNEL_QUOTA_FORMAT_VFS_V1) ==
                          -EDGE_LINUX_EBUSY,
                      "duplicate enable");
    failures += check(kernel_quota_format(
                          &alias, KERNEL_QUOTA_USER, &format) == 0 &&
                          format == KERNEL_QUOTA_FORMAT_VFS_V1,
                      "stable filesystem identity");

    memset(&set, 0, sizeof(set));
    set.block_hard_limit = 4096;
    set.block_soft_limit = 3072;
    set.inode_hard_limit = 64;
    set.valid = KERNEL_QUOTA_VALID_BLOCK_LIMITS |
                KERNEL_QUOTA_VALID_INODE_LIMITS;
    failures += check(kernel_quota_set(
                          &first, KERNEL_QUOTA_USER, 1000, &set) == 0,
                      "set limits");
    memset(&set, 0, sizeof(set));
    set.current_space = 8192;
    set.current_inodes = 3;
    set.valid = KERNEL_QUOTA_VALID_SPACE |
                KERNEL_QUOTA_VALID_INODES;
    failures += check(kernel_quota_set(
                          &alias, KERNEL_QUOTA_USER, 1000, &set) == 0,
                      "merge usage");
    memset(&get, 0, sizeof(get));
    failures += check(kernel_quota_get(
                          &first, KERNEL_QUOTA_USER, 1000, &get) == 0 &&
                          get.block_hard_limit == 4096 &&
                          get.inode_hard_limit == 64 &&
                          get.current_space == 8192 &&
                          get.current_inodes == 3,
                      "get merged quota");

    memset(&set, 0, sizeof(set));
    set.block_hard_limit = 16384;
    set.valid = KERNEL_QUOTA_VALID_BLOCK_LIMITS;
    failures += check(kernel_quota_set(
                          &first, KERNEL_QUOTA_USER, 2000, &set) == 0,
                      "set second quota");
    memset(&next, 0, sizeof(next));
    failures += check(kernel_quota_get_next(
                          &first, KERNEL_QUOTA_USER, 1001, &next) == 0 &&
                          next.id == 2000 &&
                          next.block_hard_limit == 16384,
                      "get next quota");

    memset(&information, 0, sizeof(information));
    information.block_grace = 604800;
    information.inode_grace = 86400;
    information.valid = KERNEL_QUOTA_INFO_BLOCK_GRACE |
                        KERNEL_QUOTA_INFO_INODE_GRACE;
    failures += check(kernel_quota_set_info(
                          &first, KERNEL_QUOTA_USER, &information) == 0,
                      "set grace information");
    memset(&information, 0, sizeof(information));
    failures += check(kernel_quota_get_info(
                          &first, KERNEL_QUOTA_USER, &information) == 0 &&
                          information.block_grace == 604800 &&
                          information.inode_grace == 86400,
                      "get grace information");
    failures += check(kernel_quota_sync(
                          &first, KERNEL_QUOTA_USER) == 0 &&
                          g_sync_count == 1,
                      "sync enabled quota");
    memset(&coherent, 0, sizeof(coherent));
    memset(&coherent_operations, 0, sizeof(coherent_operations));
    coherent.ops = &coherent_operations;
    coherent.fs_private = &coherent_identity;
    failures += check(kernel_quota_enable(
                          &coherent, KERNEL_QUOTA_USER,
                          KERNEL_QUOTA_FORMAT_SHMEM) == 0 &&
                          kernel_quota_sync(
                              &coherent, KERNEL_QUOTA_USER) == 0,
                      "sync coherent in-memory quota");
    failures += check(kernel_quota_disable(
                          &first, KERNEL_QUOTA_USER) == 0,
                      "disable quota");
    failures += check(kernel_quota_get(
                          &first, KERNEL_QUOTA_USER, 1000, &get) ==
                          -EDGE_LINUX_ESRCH,
                      "records unavailable after disable");

    if (!failures) puts("QUOTA_RUNTIME_UNIT_PASS");
    return failures ? 1 : 0;
}
