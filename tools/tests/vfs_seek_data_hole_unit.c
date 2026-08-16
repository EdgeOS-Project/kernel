/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side tests for shared sparse file seek dispatch and Linux policy. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/linux_seek.h"
#include "vfs/vfs.h"

static int g_query_result;
static uint64_t g_query_position;
static uint64_t g_query_offset;
static int g_query_hole;

edge_linux_seek_result_t kernel_vfs_seek_descriptor(
    int32_t descriptor, int64_t displacement, uint32_t whence,
    uint64_t *result) {
    (void)descriptor;
    (void)displacement;
    (void)whence;
    (void)result;
    return EDGE_LINUX_SEEK_INTERNAL;
}

static int test_query(vfs_superblock_t *superblock,
                      const vfs_inode_t *inode, uint64_t offset,
                      int seek_hole, uint64_t *result) {
    (void)superblock;
    (void)inode;
    g_query_offset = offset;
    g_query_hole = seek_hole;
    if (!g_query_result) *result = g_query_position;
    return g_query_result;
}

int main(void) {
    filesystem_ops_t operations = {0};
    vfs_superblock_t superblock = {0};
    vfs_inode_t inode = {0};
    edge_linux_seek_state_t state = {0};
    uint64_t result = UINT64_MAX;

    inode.mode = VFS_INODE_FILE | 0644u;
    inode.size = 16384u;
    superblock.ops = &operations;

    assert(vfs_seek_data_hole(
               &superblock, &inode, 1024u, 0, &result) == 0);
    assert(result == 1024u);
    assert(vfs_seek_data_hole(
               &superblock, &inode, 1024u, 1, &result) == 0);
    assert(result == inode.size);
    assert(vfs_seek_data_hole(
               &superblock, &inode, inode.size, 0, &result) ==
           VFS_SEEK_DATA_HOLE_ERR_NO_DATA);

    operations.seek_data_hole = test_query;
    g_query_result = 0;
    g_query_position = 8192u;
    state.end = inode.size;
    state.maximum = INT64_MAX;
    state.capabilities = EDGE_LINUX_SEEK_POSITIONAL |
                         EDGE_LINUX_SEEK_DATA_HOLE;
    assert(edge_linux_seek_resolve_data_hole(
               &superblock, &inode, 4096, EDGE_LINUX_SEEK_DATA,
               &state) == EDGE_LINUX_SEEK_OK);
    assert(g_query_offset == 4096u && !g_query_hole);
    assert(edge_linux_seek_calculate(
               &state, 4096, EDGE_LINUX_SEEK_DATA, &result) ==
           EDGE_LINUX_SEEK_OK);
    assert(result == 8192u);

    state.data_hole_resolved = 0;
    g_query_position = 12288u;
    assert(edge_linux_seek_resolve_data_hole(
               &superblock, &inode, 8192, EDGE_LINUX_SEEK_HOLE,
               &state) == EDGE_LINUX_SEEK_OK);
    assert(g_query_offset == 8192u && g_query_hole);
    assert(edge_linux_seek_calculate(
               &state, 8192, EDGE_LINUX_SEEK_HOLE, &result) ==
           EDGE_LINUX_SEEK_OK);
    assert(result == 12288u);

    g_query_result = VFS_SEEK_DATA_HOLE_ERR_NO_DATA;
    assert(edge_linux_seek_resolve_data_hole(
               &superblock, &inode, 8192, EDGE_LINUX_SEEK_DATA,
               &state) == EDGE_LINUX_SEEK_NO_DATA);
    assert(edge_linux_seek_resolve_data_hole(
               &superblock, &inode, -1, EDGE_LINUX_SEEK_DATA,
               &state) == EDGE_LINUX_SEEK_NO_DATA);

    printf("VFS_SEEK_DATA_HOLE_UNIT_PASS\n");
    return 0;
}
