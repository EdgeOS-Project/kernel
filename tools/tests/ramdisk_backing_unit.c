/* SPDX-License-Identifier: MPL-2.0 */
/* Verify reserved ramdisk backing, shared aliases, and partition bounds. */
#include <assert.h>
#include <stdint.h>
#include "../../src/dev/dev.c"

static block_device_t devices[2];
static int device_count;
static int registration_fails;

int block_register(const char *name, uint32_t sector_size,
                   uint32_t sector_count, uint32_t start_lba,
                   void *ctx, block_ops_t ops) {
    if (registration_fails || device_count == 2) return -1;
    block_device_t *device = &devices[device_count];
    (void)name;
    device->sector_size = sector_size;
    device->sector_count = sector_count;
    device->start_lba = start_lba;
    device->ctx = ctx;
    device->ops = ops;
    return device_count++;
}

block_device_t *block_get(int index) {
    return index >= 0 && index < device_count ? &devices[index] : 0;
}

void block_set_cache_enabled(block_device_t *device, int enabled) {
    assert(device);
    device->cache_enabled = enabled != 0;
}

int main(void) {
    uint8_t backing[2048] = {0};
    uint8_t sector[512] = {0};
    assert(!dev_register_memory_ramdisk("test", 0, 2048, 0));
    assert(!dev_register_memory_ramdisk("test", backing, 511, 0));
    registration_fails = 1;
    assert(!dev_register_memory_ramdisk("test", backing, 2048, 0));
    assert(!g_has_module_ramdisk);
    registration_fails = 0;
    assert(dev_register_memory_ramdisk("test", backing, 2048, 0));
    assert(device_count == 2);
    assert(g_ram_ctx[0].base == backing);
    assert(!devices[0].cache_enabled && !devices[1].cache_enabled);
    sector[0] = 0x5a;
    assert(ram_write(&devices[0], 1, 1, sector) == 0);
    assert(backing[512] == 0x5a);
    backing[512] = 0xa5;
    assert(ram_read(&devices[1], 1, 1, sector) == 0);
    assert(sector[0] == 0xa5);
    assert(ram_read(&devices[0], 3, 1, sector) == 0);
    assert(ram_read(&devices[0], 4, 1, sector) < 0);
    assert(ram_write(&devices[0], 0, UINT32_MAX, sector) < 0);
    g_ram_ctx[0].offset = UINT32_MAX;
    assert(ram_read(&devices[0], 1, 1, sector) < 0);
    assert(ram_write(&devices[0], 1, 1, sector) < 0);
    g_ram_ctx[0].offset = 1;
    assert(ram_read(&devices[0], 2, 1, sector) == 0);
    assert(ram_read(&devices[0], 3, 1, sector) < 0);
    printf("ramdisk_backing_unit: PASS\n");
    return 0;
}
