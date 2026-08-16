/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for Linux-compatible EdgeOS loop block devices. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "block/block.h"
#include "block/loop.h"

#define TEST_CACHE_PAGES 8400u
#define TEST_BACKING_BYTES (64u * 1024u)

static uint8_t test_cache_memory[TEST_CACHE_PAGES * 4096u]
    __attribute__((aligned(4096)));
static uint32_t test_cache_next_page;
static uint8_t test_backing_data[TEST_BACKING_BYTES];
static uint32_t test_open_count;
static uint32_t test_close_count;
static uint32_t test_refresh_count;
static uint32_t test_devtmpfs_refresh_count;
static vfs_superblock_t test_superblock;
static vfs_inode_t test_inode;

uint64_t arch_vm_memory_total_bytes(void) {
    return 0;
}

void *arch_vm_reserve_pages(uint64_t page_count) {
    uint8_t *allocation;
    if (!page_count || page_count > TEST_CACHE_PAGES - test_cache_next_page)
        return 0;
    allocation = test_cache_memory +
                 (uint64_t)test_cache_next_page * 4096u;
    test_cache_next_page += (uint32_t)page_count;
    return allocation;
}

int devtmpfs_refresh_block_nodes(void) {
    test_devtmpfs_refresh_count++;
    return 0;
}

static int test_read(vfs_superblock_t *superblock, vfs_inode_t *inode,
                     uint32_t offset, void *output, uint32_t length) {
    uint32_t available;

    assert(superblock == &test_superblock);
    assert(inode->ino == test_inode.ino);
    if (offset >= inode->size) return 0;
    available = inode->size - offset;
    if (length > available) length = available;
    memcpy(output, test_backing_data + offset, length);
    return (int)length;
}

static int test_write(vfs_superblock_t *superblock, vfs_inode_t *inode,
                      uint32_t offset, const void *input, uint32_t length) {
    assert(superblock == &test_superblock);
    assert(inode->ino == test_inode.ino);
    if (offset > inode->size || length > inode->size - offset) return -1;
    memcpy(test_backing_data + offset, input, length);
    return (int)length;
}

static int test_sync_inode(vfs_superblock_t *superblock,
                           const vfs_inode_t *inode, int data_only) {
    assert(superblock == &test_superblock);
    assert(inode->ino == test_inode.ino);
    assert(data_only == 0);
    return 0;
}

int vfs_inode_open(vfs_superblock_t *superblock, const vfs_inode_t *inode) {
    assert(superblock == &test_superblock);
    assert(inode->ino == test_inode.ino);
    test_open_count++;
    return 0;
}

void vfs_inode_close(vfs_superblock_t *superblock,
                     const vfs_inode_t *inode) {
    assert(superblock == &test_superblock);
    assert(inode->ino == test_inode.ino);
    test_close_count++;
}

int vfs_inode_refresh(vfs_superblock_t *superblock, vfs_inode_t *inode) {
    assert(superblock == &test_superblock);
    assert(inode->ino == test_inode.ino);
    inode->size = test_inode.size;
    test_refresh_count++;
    return 0;
}

static int test_resolve_backing(void *context, int32_t descriptor,
                                edge_loop_backing_file_t *backing) {
    uint32_t status_flags = *(uint32_t *)context;

    if (descriptor != 9) return -9;
    memset(backing, 0, sizeof(*backing));
    backing->superblock = &test_superblock;
    backing->inode = test_inode;
    backing->device_number = 1u;
    backing->status_flags = status_flags;
    strcpy(backing->path, "/images/test.ext4");
    return 0;
}

static int test_copy_from_user(void *context, void *destination,
                               uint64_t source, uint64_t length) {
    (void)context;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)length);
    return 0;
}

static int test_copy_to_user(void *context, uint64_t destination,
                             const void *source, uint64_t length) {
    (void)context;
    memcpy((void *)(uintptr_t)destination, source, (size_t)length);
    return 0;
}

static uint64_t test_device_number(uint32_t major, uint32_t minor) {
    return ((uint64_t)(minor & 0xffu)) |
           ((uint64_t)(major & 0xfffu) << 8) |
           ((uint64_t)(minor & ~0xffu) << 12) |
           ((uint64_t)(major & ~0xfffu) << 32);
}

static int64_t test_ioctl(uint64_t device_number, uint32_t command,
                          uint64_t argument, uint32_t *status_flags,
                          int privileged) {
    edge_loop_ioctl_request_t request;

    memset(&request, 0, sizeof(request));
    request.device_number = device_number;
    request.command = command;
    request.argument = argument;
    request.privileged = privileged != 0;
    request.copy_from_user = test_copy_from_user;
    request.copy_to_user = test_copy_to_user;
    request.resolve_context = status_flags;
    request.resolve_backing = test_resolve_backing;
    return edge_loop_ioctl_execute(&request);
}

int main(void) {
    filesystem_ops_t operations;
    edge_loop_config_t configuration;
    edge_loop_info64_t information;
    block_device_t *loop;
    uint8_t buffer[2048];
    uint8_t replacement[1024];
    char sysfs_value[128];
    uint32_t major;
    uint32_t minor;
    uint32_t read_only;
    uint32_t status_flags = 2u;
    uint64_t control = test_device_number(10u, 237u);
    uint64_t loop0 = test_device_number(7u, 0u);
    uint64_t loop1 = test_device_number(7u, 1u);

    memset(&operations, 0, sizeof(operations));
    operations.read = test_read;
    operations.write = test_write;
    operations.sync_inode = test_sync_inode;
    memset(&test_superblock, 0, sizeof(test_superblock));
    test_superblock.ops = &operations;
    memset(&test_inode, 0, sizeof(test_inode));
    test_inode.ino = 77u;
    test_inode.mode = VFS_INODE_FILE | 0600u;
    test_inode.size = TEST_BACKING_BYTES;
    for (uint32_t index = 0; index < TEST_BACKING_BYTES; ++index)
        test_backing_data[index] = (uint8_t)(index ^ (index >> 8));

    block_init();
    edge_loop_initialize();
    assert(edge_loop_is_control_device_number(control));
    assert(edge_loop_is_device_number(loop0));
    assert(test_ioctl(control, EDGE_LOOP_CTL_GET_FREE, 0,
                      &status_flags, 0) == 0);

    memset(&configuration, 0, sizeof(configuration));
    configuration.descriptor = 9u;
    configuration.block_size = 1024u;
    configuration.info.offset = 1024u;
    configuration.info.size_limit = 8192u;
    assert(test_ioctl(loop0, EDGE_LOOP_CONFIGURE,
                      (uint64_t)(uintptr_t)&configuration,
                      &status_flags, 0) == -1);
    assert(test_ioctl(loop0, EDGE_LOOP_CONFIGURE,
                      (uint64_t)(uintptr_t)&configuration,
                      &status_flags, 1) == 0);
    assert(test_open_count == 1u);
    assert(test_devtmpfs_refresh_count == 1u);
    loop = block_find("loop0");
    assert(loop != 0);
    assert(loop->sector_size == 1024u);
    assert(loop->sector_count == 8u);
    assert(block_linux_major_minor(loop, &major, &minor) == 0);
    assert(major == 7u && minor == 0u);
    assert(block_device_size_bytes(loop) == 8192u);
    assert(block_sysfs_path_kind("/sys/block/loop0/ro") ==
           BLOCK_SYSFS_PATH_FILE);
    memset(sysfs_value, 0, sizeof(sysfs_value));
    assert(block_sysfs_read_file("/sys/block/loop0/ro", sysfs_value,
                                 sizeof(sysfs_value)) > 0);
    assert(strcmp(sysfs_value, "0\n") == 0);
    read_only = UINT32_MAX;
    assert(test_ioctl(loop0, 0x125eu,
                      (uint64_t)(uintptr_t)&read_only,
                      &status_flags, 0) == 0);
    assert(read_only == 0u);
    assert(block_sysfs_path_kind("/sys/block/loop0/loop") ==
           BLOCK_SYSFS_PATH_DIR);
    assert(block_sysfs_path_kind(
               "/sys/class/block/loop0/loop/backing_file") ==
           BLOCK_SYSFS_PATH_FILE);
    memset(sysfs_value, 0, sizeof(sysfs_value));
    assert(block_sysfs_read_file(
               "/sys/block/loop0/loop/backing_file",
               sysfs_value, sizeof(sysfs_value)) > 0);
    assert(strcmp(sysfs_value, "/images/test.ext4\n") == 0);

    memset(buffer, 0, sizeof(buffer));
    assert(block_read_sectors(loop, 1u, 2u, buffer) == 0);
    assert(memcmp(buffer, test_backing_data + 2048u, sizeof(buffer)) == 0);
    memset(replacement, 0x5au, sizeof(replacement));
    assert(block_write_sectors(loop, 2u, 1u, replacement) == 0);
    assert(memcmp(test_backing_data + 3072u,
                  replacement, sizeof(replacement)) == 0);
    assert(block_flush(loop) == 0);

    memset(&information, 0, sizeof(information));
    assert(test_ioctl(loop0, EDGE_LOOP_GET_STATUS64,
                      (uint64_t)(uintptr_t)&information,
                      &status_flags, 0) == 0);
    assert(information.number == 0u);
    assert(information.device == 1u);
    assert(information.offset == 1024u);
    assert(information.size_limit == 8192u);
    assert(strcmp((const char *)information.file_name,
                  "/images/test.ext4") == 0);
    assert(test_ioctl(loop0, EDGE_LOOP_SET_DIRECT_IO, 1u,
                      &status_flags, 1) == 0);
    assert(loop->cache_enabled == 0u);
    assert(test_ioctl(loop0, EDGE_LOOP_SET_BLOCK_SIZE, 512u,
                      &status_flags, 1) == 0);
    assert(loop->sector_size == 512u && loop->sector_count == 16u);

    memset(&information, 0, sizeof(information));
    information.offset = 2048u;
    assert(test_ioctl(loop0, EDGE_LOOP_SET_STATUS64,
                      (uint64_t)(uintptr_t)&information,
                      &status_flags, 1) == 0);
    assert(loop->sector_count == (TEST_BACKING_BYTES - 2048u) / 512u);
    test_inode.size = TEST_BACKING_BYTES - 4096u;
    assert(test_ioctl(loop0, EDGE_LOOP_SET_CAPACITY, 0,
                      &status_flags, 1) == 0);
    assert(test_refresh_count == 1u);
    assert(loop->sector_count == (test_inode.size - 2048u) / 512u);

    assert(test_ioctl(loop0, EDGE_LOOP_CLR_FD, 0,
                      &status_flags, 1) == 0);
    assert(block_find("loop0") == 0);
    assert(test_close_count == 1u);
    assert(test_devtmpfs_refresh_count == 2u);

    status_flags = 0u;
    test_inode.size = TEST_BACKING_BYTES;
    assert(test_ioctl(loop1, EDGE_LOOP_SET_FD, 9u,
                      &status_flags, 1) == 0);
    loop = block_find("loop1");
    assert(loop != 0 && loop->ops.write_sectors == 0);
    read_only = UINT32_MAX;
    assert(test_ioctl(loop1, 0x125eu,
                      (uint64_t)(uintptr_t)&read_only,
                      &status_flags, 0) == 0);
    assert(read_only == 1u);
    assert(test_ioctl(loop1, EDGE_LOOP_CLR_FD, 0,
                      &status_flags, 1) == 0);
    assert(test_open_count == 2u && test_close_count == 2u);
    return 0;
}
