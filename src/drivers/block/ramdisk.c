/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS memory-backed block device driver.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include "block/block.h"
#include "drivers/ramdisk.h"

#define RAMDISK_MAX_DEVICES 16u
#define RAMDISK_SECTOR_SIZE 512u

typedef struct {
    uint8_t *base;
    uint64_t size;
    uint8_t writable;
    uint8_t used;
} ramdisk_t;

static ramdisk_t g_ramdisks[RAMDISK_MAX_DEVICES];

static void copy_bytes(uint8_t *destination, const uint8_t *source, uint64_t size) {
    while (size--) *destination++ = *source++;
}

static int ramdisk_transfer_bounds(block_device_t *device, uint32_t lba,
                                   uint32_t count, uint64_t *offset_out,
                                   uint64_t *bytes_out) {
    ramdisk_t *disk;
    uint64_t offset;
    uint64_t bytes;
    if (!device || !device->ctx || !offset_out || !bytes_out) return -1;
    disk = (ramdisk_t *)device->ctx;
    offset = (uint64_t)lba * device->sector_size;
    bytes = (uint64_t)count * device->sector_size;
    if (offset > disk->size || bytes > disk->size - offset) return -1;
    *offset_out = offset;
    *bytes_out = bytes;
    return 0;
}

static int ramdisk_read(block_device_t *device, uint32_t lba, uint32_t count,
                        void *output) {
    ramdisk_t *disk;
    uint64_t offset;
    uint64_t bytes;
    if (!output || ramdisk_transfer_bounds(device, lba, count, &offset, &bytes) < 0)
        return -1;
    disk = (ramdisk_t *)device->ctx;
    copy_bytes((uint8_t *)output, disk->base + offset, bytes);
    return 0;
}

static int ramdisk_write(block_device_t *device, uint32_t lba, uint32_t count,
                         const void *input) {
    ramdisk_t *disk;
    uint64_t offset;
    uint64_t bytes;
    if (!input || ramdisk_transfer_bounds(device, lba, count, &offset, &bytes) < 0)
        return -1;
    disk = (ramdisk_t *)device->ctx;
    if (!disk->writable) return -1;
    copy_bytes(disk->base + offset, (const uint8_t *)input, bytes);
    return 0;
}

int ramdisk_register(const char *name, void *base, uint64_t size, int writable) {
    block_ops_t operations = {0};
    uint64_t sectors;
    uint32_t index;
    if (!name || !base || size < RAMDISK_SECTOR_SIZE) return -1;
    sectors = size / RAMDISK_SECTOR_SIZE;
    if (!sectors || sectors > UINT32_MAX) return -1;
    for (index = 0; index < RAMDISK_MAX_DEVICES; ++index)
        if (!g_ramdisks[index].used) break;
    if (index == RAMDISK_MAX_DEVICES) return -1;
    g_ramdisks[index].base = (uint8_t *)base;
    g_ramdisks[index].size = sectors * RAMDISK_SECTOR_SIZE;
    g_ramdisks[index].writable = writable != 0;
    g_ramdisks[index].used = 1;
    operations.read_sectors = ramdisk_read;
    operations.write_sectors = writable ? ramdisk_write : 0;
    {
        int device_index = block_register(
            name, RAMDISK_SECTOR_SIZE, (uint32_t)sectors, 0,
            &g_ramdisks[index], operations);
        if (device_index < 0) {
            g_ramdisks[index].used = 0;
            return -1;
        }
        block_set_cache_enabled(block_get(device_index), 0);
    }
    return 0;
}
