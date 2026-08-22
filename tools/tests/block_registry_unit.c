/* SPDX-License-Identifier: MPL-2.0 */
/* Unit tests for dynamic EdgeOS block-device publication. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "block/block.h"

#define TEST_CACHE_PAGES 8400u

static uint8_t test_cache_memory[TEST_CACHE_PAGES * 4096u]
    __attribute__((aligned(4096)));
static uint32_t test_read_calls;
static uint32_t test_last_read_lba;
static uint32_t test_last_read_count;
static uint32_t test_flush_calls;

uint64_t
arch_vm_memory_total_bytes(void)
{
    return 0;
}

void *
arch_vm_reserve_pages(uint64_t page_count)
{
    if (page_count > TEST_CACHE_PAGES)
        return 0;
    return test_cache_memory;
}

static int
test_read(block_device_t *device, uint32_t lba, uint32_t count, void *output)
{
    (void)device;
    test_read_calls++;
    test_last_read_lba = lba;
    test_last_read_count = count;
    for (uint32_t sector = 0; sector < count; ++sector)
        memset((uint8_t *)output + sector * 512u,
               (uint8_t)(lba + sector), 512u);
    return 0;
}

static int
test_write(block_device_t *device, uint32_t lba, uint32_t count,
    const void *input)
{
    (void)device;
    (void)lba;
    (void)count;
    (void)input;
    return 0;
}

static int
test_flush(block_device_t *device)
{
    assert(device != 0);
    test_flush_calls++;
    return 0;
}

int
main(void)
{
    block_ops_t operations = {
        .read_sectors = test_read,
        .write_sectors = test_write,
        .flush = test_flush,
    };
    block_device_t *disk0;
    block_device_t *disk1;
    block_device_t *partition;
    block_io_statistics_t statistics;
    uint32_t major;
    uint32_t minor;
    char long_name[BLOCK_NAME_MAX + 1];
    uint8_t read_buffer[1024];

    memset(long_name, 'x', sizeof(long_name));
    long_name[sizeof(long_name) - 1] = 0;

    block_init();
    assert(block_count() == 0);
    assert(block_register(0, 512, 1024, 0, 0, operations) == -1);
    assert(block_register("", 512, 1024, 0, 0, operations) == -1);
    assert(block_register(long_name, 512, 1024, 0, 0, operations) == -1);
    assert(block_register("disk0", 0, 1024, 0, 0, operations) == -1);

    assert(block_register("disk0", 512, 1024, 0, 0, operations) == 0);
    assert(block_register("disk1", 4096, 2048, 0, 0, operations) == 1);
    assert(block_register("disk0", 512, 1024, 0, 0, operations) == -1);
    assert(block_count() == 2);
    disk0 = block_get(0);
    disk1 = block_get(1);
    assert(disk0 != 0 && disk1 != 0);
    assert(block_linux_major_minor(disk0, &major, &minor) == 0);
    assert(major == 8 && minor == 0);
    assert(block_linux_major_minor(disk1, &major, &minor) == 0);
    assert(major == 8 && minor == 16);
    assert(block_find("disk0") == disk0);
    assert(block_find("disk1") == disk1);
    assert(block_get(2) == 0);
    assert(block_flush(disk0) == 0);
    assert(test_flush_calls == 1);

    assert(block_unregister(disk0) == 0);
    assert(block_count() == 1);
    assert(block_get(0) == disk1);
    assert(block_find("disk0") == 0);
    assert(block_linux_major_minor(disk1, &major, &minor) == 0);
    assert(major == 8 && minor == 16);
    assert(block_unregister(disk0) == -1);

    assert(block_register("disk2", 512, 4096, 0, 0, operations) == 0);
    disk0 = block_get(0);
    assert(disk0 != 0);
    assert(strcmp(disk0->name, "disk2") == 0);
    assert(block_linux_major_minor(disk0, &major, &minor) == 0);
    assert(major == 8 && minor == 0);
    assert(block_get(1) == disk1);
    assert(block_count() == 2);

    assert(block_register("disk2p1", 512, 1024, 256, 0,
        operations) == 2);
    partition = block_get(2);
    assert(partition != 0);
    block_set_cache_parent(partition, disk0, 256);
    assert(block_unregister(disk0) == -1);
    assert(block_resize(disk0, 1279) == -1);
    assert(block_resize(disk0, 1280) == 0);
    assert(disk0->sector_count == 1280);
    assert(block_unregister(partition) == 0);
    assert(block_resize(disk0, 512) == 0);
    assert(disk0->sector_count == 512);
    assert(block_unregister(disk0) == 0);
    assert(block_unregister(disk1) == 0);
    assert(block_count() == 0);
    assert(block_get(0) == 0);

    assert(block_register("cached", 512, 64, 0, 0, operations) == 0);
    disk0 = block_get(0);
    assert(disk0 != 0);
    test_read_calls = 0;
    memset(read_buffer, 0, sizeof(read_buffer));
    assert(block_read_sectors(disk0, 1, 1, read_buffer) == 0);
    assert(test_read_calls == 1);
    assert(test_last_read_lba == 0);
    assert(test_last_read_count == 8);
    assert(block_io_statistics_snapshot(disk0, &statistics) == 0);
    assert(statistics.read_ios == 1u);
    assert(statistics.read_sectors == 8u);
    assert(statistics.in_flight == 0u);
    for (uint32_t index = 0; index < 512u; ++index)
        assert(read_buffer[index] == 1);

    memset(read_buffer, 0, sizeof(read_buffer));
    assert(block_read_sectors(disk0, 2, 2, read_buffer) == 0);
    assert(test_read_calls == 1);
    assert(block_io_statistics_snapshot(disk0, &statistics) == 0);
    assert(statistics.read_ios == 1u);
    assert(statistics.read_sectors == 8u);
    for (uint32_t index = 0; index < 512u; ++index) {
        assert(read_buffer[index] == 2);
        assert(read_buffer[512u + index] == 3);
    }

    memset(read_buffer, 0xa5, 512u);
    assert(block_write_sectors(disk0, 4, 1, read_buffer) == 0);
    assert(block_io_statistics_snapshot(disk0, &statistics) == 0);
    assert(statistics.write_ios == 1u);
    assert(statistics.write_sectors == 1u);
    assert(statistics.in_flight == 0u);

    assert(block_flush(disk0) == 0);
    assert(block_io_statistics_snapshot(disk0, &statistics) == 0);
    assert(statistics.flush_ios == 1u);
    assert(block_unregister(disk0) == 0);

    assert(block_register("parent", 512, 128, 0, 0, operations) == 0);
    disk0 = block_get(0);
    assert(disk0 != 0);
    assert(block_register("parentp1", 512, 64, 3, 0, operations) == 1);
    partition = block_get(1);
    assert(partition != 0);
    block_set_cache_parent(partition, disk0, 3);
    test_read_calls = 0;
    memset(read_buffer, 0, sizeof(read_buffer));
    assert(block_read_sectors(partition, 6, 1, read_buffer) == 0);
    assert(test_read_calls == 1);
    assert(test_last_read_lba == 5);
    assert(test_last_read_count == 8);
    for (uint32_t index = 0; index < 512u; ++index)
        assert(read_buffer[index] == 6);
    assert(block_unregister(partition) == 0);
    assert(block_unregister(disk0) == 0);

    return 0;
}
