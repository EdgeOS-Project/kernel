/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for the shared Linux-compatible device-mapper engine. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "block/block.h"
#include "block/device_mapper.h"
#include "kernel/linux_errno.h"

#define TEST_SECTORS 4096u
#define TEST_IOCTL_BYTES 4096u

typedef struct test_disk {
    uint8_t data[TEST_SECTORS * 512u];
    uint32_t flushes;
} test_disk_t;

static test_disk_t test_disks[2];
static uint32_t test_devtmpfs_refreshes;

uint64_t arch_vm_memory_total_bytes(void) {
    return 0;
}

void *arch_vm_reserve_pages(uint64_t page_count) {
    (void)page_count;
    return 0;
}

int devtmpfs_refresh_block_nodes(void) {
    test_devtmpfs_refreshes++;
    return 0;
}

static int test_disk_read(block_device_t *device, uint32_t lba,
                          uint32_t count, void *output) {
    test_disk_t *disk = (test_disk_t *)device->ctx;
    if (!disk || lba > TEST_SECTORS || count > TEST_SECTORS - lba)
        return -1;
    memcpy(output, disk->data + (uint64_t)lba * 512u,
           (uint64_t)count * 512u);
    return 0;
}

static int test_disk_write(block_device_t *device, uint32_t lba,
                           uint32_t count, const void *input) {
    test_disk_t *disk = (test_disk_t *)device->ctx;
    if (!disk || lba > TEST_SECTORS || count > TEST_SECTORS - lba)
        return -1;
    memcpy(disk->data + (uint64_t)lba * 512u, input,
           (uint64_t)count * 512u);
    return 0;
}

static int test_disk_flush(block_device_t *device) {
    test_disk_t *disk = (test_disk_t *)device->ctx;
    if (!disk) return -1;
    disk->flushes++;
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

static uint32_t test_dm_command(uint32_t number) {
    return 0xc138fd00u | number;
}

static int64_t test_ioctl(uint32_t command, void *buffer, int privileged) {
    edge_dm_ioctl_request_t request;

    memset(&request, 0, sizeof(request));
    request.device_number = test_device_number(
        EDGE_DM_CONTROL_MAJOR, EDGE_DM_CONTROL_MINOR);
    request.command = test_dm_command(command);
    request.argument = (uint64_t)(uintptr_t)buffer;
    request.privileged = privileged != 0;
    request.copy_from_user = test_copy_from_user;
    request.copy_to_user = test_copy_to_user;
    return edge_dm_ioctl_execute(&request);
}

static edge_dm_ioctl_t *test_ioctl_initialize(uint8_t *buffer,
                                               const char *name) {
    edge_dm_ioctl_t *io = (edge_dm_ioctl_t *)buffer;
    memset(buffer, 0, TEST_IOCTL_BYTES);
    io->version[0] = 4u;
    io->version[1] = 50u;
    io->version[2] = 0u;
    io->data_size = TEST_IOCTL_BYTES;
    io->data_start = sizeof(*io);
    if (name) strcpy(io->name, name);
    return io;
}

static uint32_t test_add_target(uint8_t *buffer, uint32_t offset,
                                uint64_t start, uint64_t length,
                                const char *type, const char *parameters,
                                int final) {
    edge_dm_target_spec_t *spec =
        (edge_dm_target_spec_t *)(buffer + offset);
    uint32_t bytes = sizeof(*spec) + (uint32_t)strlen(parameters) + 1u;
    uint32_t aligned = (bytes + 7u) & ~7u;

    memset(spec, 0, aligned);
    spec->sector_start = start;
    spec->length = length;
    spec->next = final ? 0u : aligned;
    strcpy(spec->target_type, type);
    strcpy((char *)(spec + 1), parameters);
    return offset + aligned;
}

int main(void) {
    static const uint8_t linux_xts_zero_sector[32] = {
        0xfb, 0x30, 0x94, 0xe9, 0xa7, 0xd7, 0x7e, 0x65,
        0x84, 0xd4, 0x8c, 0x06, 0x35, 0xa5, 0x9d, 0x88,
        0xd1, 0xe2, 0x0c, 0xf9, 0xaa, 0xfa, 0x36, 0x30,
        0x9d, 0x8e, 0xd8, 0xd2, 0x72, 0xe2, 0x14, 0x75
    };
    uint8_t ioctl_buffer[TEST_IOCTL_BYTES] __attribute__((aligned(8)));
    edge_dm_ioctl_t *io;
    block_ops_t operations;
    block_device_t *mapped;
    uint8_t data[16u * 512u];
    uint8_t replacement[4u * 512u];
    uint32_t major;
    uint32_t minor;
    uint32_t offset;

    memset(&operations, 0, sizeof(operations));
    operations.read_sectors = test_disk_read;
    operations.write_sectors = test_disk_write;
    operations.flush = test_disk_flush;
    for (uint32_t index = 0; index < sizeof(test_disks[0].data); ++index) {
        test_disks[0].data[index] = (uint8_t)(index ^ (index >> 8));
        test_disks[1].data[index] = (uint8_t)(0xa5u ^ index);
    }

    block_init();
    assert(block_register("disk0", 512u, TEST_SECTORS, 0u,
                          &test_disks[0], operations) >= 0);
    assert(block_register("disk1", 512u, TEST_SECTORS, 0u,
                          &test_disks[1], operations) >= 0);
    block_set_cache_enabled(block_find("disk0"), 0);
    block_set_cache_enabled(block_find("disk1"), 0);
    edge_dm_initialize();

    io = test_ioctl_initialize(ioctl_buffer, 0);
    assert(test_ioctl(EDGE_DM_VERSION_CMD, io, 0) == 0);
    assert(io->version[0] == 4u && io->version[1] == 50u);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    strcpy(io->uuid, "edgeos-dm-unit");
    assert(test_ioctl(EDGE_DM_DEV_CREATE_CMD, io, 0) ==
           -EDGE_LINUX_EPERM);
    assert(test_ioctl(EDGE_DM_DEV_CREATE_CMD, io, 1) == 0);
    assert(io->device == test_device_number(EDGE_DM_BLOCK_MAJOR, 0u));
    mapped = block_find("dm-0");
    assert(mapped != 0 && mapped->sector_count == 0u);
    assert(block_linux_major_minor(mapped, &major, &minor) == 0);
    assert(major == EDGE_DM_BLOCK_MAJOR && minor == 0u);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    io->target_count = 1u;
    offset = test_add_target(ioctl_buffer, sizeof(*io), 0u, 64u,
                             "linear", "8:0 8", 1);
    (void)offset;
    assert(test_ioctl(EDGE_DM_TABLE_LOAD_CMD, io, 1) == 0);
    assert((io->flags & EDGE_DM_INACTIVE_PRESENT_FLAG) != 0);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    assert(test_ioctl(EDGE_DM_DEV_SUSPEND_CMD, io, 1) == 0);
    assert(mapped->sector_count == 64u);
    memset(data, 0, sizeof(data));
    assert(block_read_sectors(mapped, 0u, 16u, data) == 0);
    assert(memcmp(data, test_disks[0].data + 8u * 512u,
                  sizeof(data)) == 0);
    memset(replacement, 0x3cu, sizeof(replacement));
    assert(block_write_sectors(mapped, 4u, 4u, replacement) == 0);
    assert(memcmp(test_disks[0].data + 12u * 512u,
                  replacement, sizeof(replacement)) == 0);
    assert(block_flush(mapped) == 0 && test_disks[0].flushes == 1u);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    io->target_count = 3u;
    offset = test_add_target(ioctl_buffer, sizeof(*io), 0u, 8u,
                             "striped", "2 2 8:0 128 8:16 256", 0);
    offset = test_add_target(ioctl_buffer, offset, 8u, 8u,
                             "zero", "", 0);
    test_add_target(ioctl_buffer, offset, 16u, 8u, "error", "", 1);
    assert(test_ioctl(EDGE_DM_TABLE_LOAD_CMD, io, 1) == 0);
    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    assert(test_ioctl(EDGE_DM_DEV_SUSPEND_CMD, io, 1) == 0);
    assert(mapped->sector_count == 24u);
    memset(data, 0xcc, sizeof(data));
    assert(block_read_sectors(mapped, 8u, 8u, data) == 0);
    for (uint32_t index = 0; index < 8u * 512u; ++index)
        assert(data[index] == 0u);
    assert(block_write_sectors(mapped, 8u, 8u, data) == 0);
    assert(block_read_sectors(mapped, 16u, 1u, data) < 0);
    assert(block_read_sectors(mapped, 0u, 2u, data) == 0);
    assert(memcmp(data, test_disks[0].data + 128u * 512u,
                  2u * 512u) == 0);
    assert(block_read_sectors(mapped, 2u, 2u, data) == 0);
    assert(memcmp(data, test_disks[1].data + 256u * 512u,
                  2u * 512u) == 0);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    assert(test_ioctl(EDGE_DM_TABLE_DEPS_CMD, io, 1) == 0);
    assert(*(uint32_t *)(ioctl_buffer + sizeof(*io)) == 2u);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    io->flags = EDGE_DM_STATUS_TABLE_FLAG;
    assert(test_ioctl(EDGE_DM_TABLE_STATUS_CMD, io, 1) == 0);
    assert(io->target_count == 3u);
    assert(strcmp(((edge_dm_target_spec_t *)(ioctl_buffer +
                  sizeof(*io)))->target_type, "striped") == 0);

    io = test_ioctl_initialize(ioctl_buffer, 0);
    assert(test_ioctl(EDGE_DM_LIST_DEVICES_CMD, io, 1) == 0);
    assert(strcmp((char *)(ioctl_buffer + sizeof(*io) + 16u),
                  "mapped-test") == 0);
    io = test_ioctl_initialize(ioctl_buffer, 0);
    assert(test_ioctl(EDGE_DM_LIST_VERSIONS_CMD, io, 1) == 0);
    assert(strcmp((char *)(ioctl_buffer + sizeof(*io) + 16u),
                  "linear") == 0);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    io->target_count = 1u;
    test_add_target(
        ioctl_buffer, sizeof(*io), 0u, 8u, "crypt",
        "aes-xts-plain64 "
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        " 7 8:0 512 1 sector_size:512", 1);
    assert(test_ioctl(EDGE_DM_TABLE_LOAD_CMD, io, 1) == 0);
    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    assert(test_ioctl(EDGE_DM_DEV_SUSPEND_CMD, io, 1) == 0);
    assert(mapped->sector_count == 8u);
    memset(data, 0, 2u * 512u);
    assert(block_write_sectors(mapped, 0u, 2u, data) == 0);
    assert(memcmp(test_disks[0].data + 512u * 512u,
                  linux_xts_zero_sector, sizeof(linux_xts_zero_sector)) == 0);
    for (uint32_t index = 0; index < 2u * 512u; ++index)
        data[index] = (uint8_t)(index * 17u + 3u);
    memcpy(data + 512u, data, 512u);
    assert(block_write_sectors(mapped, 0u, 2u, data) == 0);
    assert(memcmp(test_disks[0].data + 512u * 512u,
                  data, 2u * 512u) != 0);
    assert(memcmp(test_disks[0].data + 512u * 512u,
                  test_disks[0].data + 513u * 512u, 512u) != 0);
    memset(replacement, 0, 2u * 512u);
    assert(block_read_sectors(mapped, 0u, 2u, replacement) == 0);
    assert(memcmp(replacement, data, 2u * 512u) == 0);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    io->flags = EDGE_DM_STATUS_TABLE_FLAG;
    assert(test_ioctl(EDGE_DM_TABLE_STATUS_CMD, io, 1) == 0);
    assert(io->target_count == 1u);
    assert(strcmp(((edge_dm_target_spec_t *)(ioctl_buffer +
                  sizeof(*io)))->target_type, "crypt") == 0);
    assert(strstr((char *)((edge_dm_target_spec_t *)(ioctl_buffer +
                  sizeof(*io)) + 1), "aes-xts-plain64 - 7 8:0 512") != 0);

    io = test_ioctl_initialize(ioctl_buffer, "mapped-test");
    assert(test_ioctl(EDGE_DM_DEV_REMOVE_CMD, io, 1) == 0);
    assert(block_find("dm-0") == 0);
    assert(edge_dm_device_count() == 0u);
    assert(test_devtmpfs_refreshes >= 2u);
    return 0;
}
