/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "vfs/vfs.h"

static unsigned cache_calls, storage_calls;
static uint32_t warm_end;
static int storage_error;
uint32_t kernel_arch_vfs_read_resident(vfs_superblock_t *sb,
                                      const vfs_inode_t *inode,
                                      uint64_t offset, void *out, uint32_t len) {
    (void)sb;
    (void)inode;
    ++cache_calls;
    if (offset >= warm_end) return 0;
    if (len > warm_end - offset) len = (uint32_t)(warm_end - offset);
    memset(out, 0x5a, len);
    return len;
}
static int storage_read(vfs_superblock_t *sb, vfs_inode_t *inode,
                        uint32_t offset, void *out, uint32_t len) {
    (void)sb; (void)inode; (void)offset;
    ++storage_calls;
    if (storage_error) return -5;
    memset(out, 0x31, len);
    return (int)len;
}
static int special_read(vfs_superblock_t *sb, vfs_inode_t *inode,
                        uint64_t identity, uint32_t offset,
                        void *out, uint32_t len) {
    assert(identity == 42);
    return storage_read(sb, inode, offset, out, len);
}
int main(void) {
    filesystem_ops_t ops = {.read = storage_read};
    vfs_superblock_t sb = {.ops = &ops};
    vfs_inode_t inode = {.mode = VFS_INODE_FILE, .size = 13};
    unsigned char out[32];
    warm_end = 4096;
    sb.mount_flags = VFS_MOUNT_READONLY;
    assert(vfs_read_description(&sb, &inode, 42, 0, out, 7) == 7);
    assert(cache_calls == 0 && storage_calls == 1 && out[0] == 0x31);
    sb.runtime_flags = VFS_SUPERBLOCK_IMMUTABLE_DATA;
    memset(out, 0xcc, sizeof(out));
    assert(vfs_read_description(&sb, &inode, 42, 9, out, 20) == 4);
    assert(cache_calls == 1 && storage_calls == 1);
    assert(out[3] == 0x5a && out[4] == 0xcc);
    assert(vfs_read_description(&sb, &inode, 42, 13, out, 7) == 0);
    assert(vfs_read_description(&sb, &inode, 42, UINT32_MAX, out, 7) == 0);
    assert(vfs_read_description(&sb, &inode, 42, 0, 0, 0) == 0);
    assert(vfs_read_description(&sb, &inode, 42, 0, 0, 1) < 0);
    assert(cache_calls == 1 && storage_calls == 1);
    warm_end = 5;
    storage_error = 1;
    assert(vfs_read_description(&sb, &inode, 42, 2, out, 10) == 3);
    assert(storage_calls == 1);
    assert(vfs_read_description(&sb, &inode, 42, 5, out, 8) == -5);
    assert(storage_calls == 2);
    ops.read_description = special_read;
    assert(vfs_read_description(&sb, &inode, 42, 0, out, 3) == -5);
    assert(storage_calls == 3 && cache_calls == 3);
    ops.read_description = 0;
    ops.read = 0;
    assert(vfs_read_description(&sb, &inode, 42, 0, out, 3) < 0);
    assert(cache_calls == 3);
    puts("vfs_resident_read_unit: PASS");
}
