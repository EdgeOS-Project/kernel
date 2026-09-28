/* SPDX-License-Identifier: MPL-2.0 */
/* Unit coverage for architecture-independent file attribute dispatch. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs/vfs.h"

static unsigned int g_get_calls;
static unsigned int g_set_calls;
static unsigned int g_invalidation_calls;
static vfs_fileattr_t g_stored;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

void vfs_path_cache_invalidate_all(void) {
    ++g_invalidation_calls;
}

static int test_get(vfs_superblock_t *superblock,
                    const vfs_inode_t *inode,
                    vfs_fileattr_t *attributes) {
    expect_true("get superblock", superblock != NULL);
    expect_true("get inode", inode != NULL);
    ++g_get_calls;
    *attributes = g_stored;
    return 0;
}

static int test_set(vfs_superblock_t *superblock, vfs_inode_t *inode,
                    const vfs_fileattr_t *attributes) {
    expect_true("set superblock", superblock != NULL);
    expect_true("set inode", inode != NULL);
    ++g_set_calls;
    g_stored = *attributes;
    return 0;
}

int main(void) {
    filesystem_ops_t operations;
    vfs_superblock_t superblock;
    vfs_inode_t inode;
    vfs_fileattr_t attributes;

    memset(&operations, 0, sizeof(operations));
    memset(&superblock, 0, sizeof(superblock));
    memset(&inode, 0, sizeof(inode));
    memset(&attributes, 0, sizeof(attributes));
    superblock.ops = &operations;

    expect_true("get unsupported",
                vfs_inode_fileattr_get(&superblock, &inode, &attributes) ==
                    VFS_FILEATTR_ERR_UNSUPPORTED);
    expect_true("set unsupported",
                vfs_inode_fileattr_set(&superblock, &inode, &attributes) ==
                    VFS_FILEATTR_ERR_UNSUPPORTED);
    expect_true("get null",
                vfs_inode_fileattr_get(NULL, &inode, &attributes) ==
                    VFS_FILEATTR_ERR_INVALID);

    operations.fileattr_get = test_get;
    operations.fileattr_set = test_set;
    g_stored.xflags = VFS_FILE_XFLAG_NODUMP;
    g_stored.projid = 42u;
    memset(&attributes, 0xa5, sizeof(attributes));
    expect_true("get success",
                vfs_inode_fileattr_get(&superblock, &inode, &attributes) == 0);
    expect_true("get dispatch",
                g_get_calls == 1u &&
                attributes.xflags == VFS_FILE_XFLAG_NODUMP &&
                attributes.projid == 42u);

    memset(&attributes, 0, sizeof(attributes));
    attributes.xflags = VFS_FILE_XFLAG_APPEND | VFS_FILE_XFLAG_NOATIME;
    expect_true("set success",
                vfs_inode_fileattr_set(&superblock, &inode, &attributes) == 0);
    expect_true("set dispatch",
                g_set_calls == 1u &&
                g_stored.xflags == attributes.xflags &&
                g_invalidation_calls == 1u);

    attributes.xflags = 1ull << 40;
    expect_true("set unknown flag",
                vfs_inode_fileattr_set(&superblock, &inode, &attributes) ==
                    VFS_FILEATTR_ERR_INVALID);
    expect_true("invalid set not dispatched",
                g_set_calls == 1u && g_invalidation_calls == 1u);

    puts("vfs_fileattr_unit: PASS");
    return 0;
}
