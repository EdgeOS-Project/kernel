/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vfs/vfs.h"

static const uint8_t source_bytes[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x0f,
};
static uint32_t maximum_chunk;
static int fail_at_offset;
static int stop_at_offset;
static int return_too_much;
static uint32_t read_calls;

static void reset_reader(void) {
    maximum_chunk = UINT32_MAX;
    fail_at_offset = -1;
    stop_at_offset = -1;
    return_too_much = 0;
    read_calls = 0;
}

static int test_read(vfs_superblock_t *sb, vfs_inode_t *inode,
                     uint32_t offset, void *buffer, uint32_t length) {
    uint32_t count;

    (void)sb;
    (void)inode;
    ++read_calls;
    if (return_too_much) return (int)length + 1;
    if (fail_at_offset >= 0 && offset >= (uint32_t)fail_at_offset) return -1;
    if (stop_at_offset >= 0 && offset >= (uint32_t)stop_at_offset) return 0;
    if (offset >= sizeof(source_bytes)) return 0;
    count = (uint32_t)sizeof(source_bytes) - offset;
    if (count > length) count = length;
    if (count > maximum_chunk) count = maximum_chunk;
    memcpy(buffer, source_bytes + offset, count);
    return (int)count;
}

int main(void) {
    filesystem_ops_t operations = {0};
    vfs_superblock_t superblock = {0};
    vfs_inode_t inode = {0};
    uint8_t output[16] = {0};

    operations.read = test_read;
    superblock.ops = &operations;
    inode.mode = VFS_INODE_FILE;
    inode.size = sizeof(source_bytes);

    reset_reader();
    maximum_chunk = 3;
    assert(vfs_read_inode_exact(
               &superblock, &inode, 2, output, 9) == 0);
    assert(memcmp(output, source_bytes + 2, 9) == 0);
    assert(read_calls == 3);

    reset_reader();
    maximum_chunk = 3;
    stop_at_offset = 6;
    assert(vfs_read_inode_exact(
               &superblock, &inode, 0, output, 9) < 0);

    reset_reader();
    maximum_chunk = 3;
    fail_at_offset = 6;
    assert(vfs_read_inode_exact(
               &superblock, &inode, 0, output, 9) < 0);

    reset_reader();
    return_too_much = 1;
    assert(vfs_read_inode_exact(
               &superblock, &inode, 0, output, 4) < 0);

    reset_reader();
    assert(vfs_read_inode_exact(
               &superblock, &inode, sizeof(source_bytes) - 2,
               output, 4) < 0);

    reset_reader();
    assert(vfs_read_inode_exact(
               &superblock, &inode, UINT32_MAX, output, 2) < 0);
    assert(read_calls == 0);

    reset_reader();
    assert(vfs_read_inode_exact(
               &superblock, &inode, 0, 0, 0) == 0);
    assert(read_calls == 0);

    puts("vfs_read_exact_unit: PASS");
    return 0;
}
