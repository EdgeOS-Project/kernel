/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS block-device registry and common byte-I/O policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "block/block.h"
#ifdef CONFIG_LOOP_DEVICE
#include "block/loop.h"
#endif
#include "kernel/linux_errno.h"
#include "mm/arch_vm.h"
#include "stdio.h"
#include "string.h"

#define BLOCK_CACHE_PAGE_SIZE 4096u
#define BLOCK_CACHE_WAYS 8u
#define BLOCK_CACHE_MAX_PAGES 65536u
#define BLOCK_CACHE_MIN_PAGES 8192u
#define BLOCK_CACHE_READAHEAD_PAGES 32u

typedef struct block_cache_entry {
    block_device_t *device;
    uint64_t page_index;
    uint32_t age;
    uint8_t valid;
    uint8_t reserved[3];
} block_cache_entry_t;

static block_device_t g_block_devices[BLOCK_MAX_DEVICES];
static int g_block_slots;
static uint8_t g_block_byte_scratch[BLOCK_MAX_SECTOR_SIZE];
static volatile uint32_t g_block_byte_io_lock;
static volatile uint32_t g_block_cache_lock;
static volatile int32_t g_block_cache_state;
static block_cache_entry_t *g_block_cache_entries;
static uint8_t *g_block_cache_data;
static uint8_t *g_block_cache_readahead[BLOCK_MAX_DEVICES];
static volatile int32_t g_block_cache_readahead_state[BLOCK_MAX_DEVICES];
static volatile uint32_t g_block_cache_readahead_locks[BLOCK_MAX_DEVICES];
static uint32_t g_block_cache_pages;
static uint32_t g_block_cache_sets;
static uint32_t g_block_cache_clock;
static uint32_t g_block_cache_generation[BLOCK_MAX_DEVICES];
static uint64_t g_block_cache_last_page[BLOCK_MAX_DEVICES];
static uint8_t g_block_cache_last_page_valid[BLOCK_MAX_DEVICES];
static block_io_policy_begin_fn g_block_io_policy_begin;
static block_io_policy_complete_fn g_block_io_policy_complete;

void block_set_io_policy(block_io_policy_begin_fn begin,
                         block_io_policy_complete_fn complete) {
    g_block_io_policy_begin = begin;
    g_block_io_policy_complete = complete;
}

static void block_io_policy_begin(block_device_t *device, int write,
                                  uint64_t bytes) {
    uint32_t major;
    uint32_t minor;

    if (!g_block_io_policy_begin || !bytes ||
        block_linux_major_minor(device, &major, &minor) < 0)
        return;
    g_block_io_policy_begin(major, minor, write, bytes);
}

static void block_io_policy_complete(block_device_t *device, int write,
                                     uint64_t bytes) {
    uint32_t major;
    uint32_t minor;

    if (!g_block_io_policy_complete || !bytes ||
        block_linux_major_minor(device, &major, &minor) < 0)
        return;
    g_block_io_policy_complete(major, minor, write, bytes);
}

static int block_linux_disk_index_allocate(void) {
    uint8_t used[BLOCK_MAX_DEVICES];

    memset(used, 0, sizeof(used));
    for (int index = 0; index < g_block_slots; ++index) {
        block_device_t *device = &g_block_devices[index];
        if (!device->present || device->start_lba != 0 ||
            strncmp(device->name, "ram", 3) == 0 ||
            device->linux_disk_index < 0 ||
            device->linux_disk_index >= BLOCK_MAX_DEVICES)
            continue;
        used[device->linux_disk_index] = 1;
    }
    for (int index = 0; index < BLOCK_MAX_DEVICES; ++index)
        if (!used[index])
            return index;
    return -1;
}

static void block_cache_lock(void) {
    while (__atomic_exchange_n(&g_block_cache_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_block_cache_lock, __ATOMIC_RELAXED))
            __asm__ volatile("" ::: "memory");
    }
}

static void block_cache_unlock(void) {
    __atomic_store_n(&g_block_cache_lock, 0u, __ATOMIC_RELEASE);
}

static void block_cache_readahead_lock(int device_index) {
    if (device_index < 0 || device_index >= BLOCK_MAX_DEVICES) return;
    while (__atomic_exchange_n(
               &g_block_cache_readahead_locks[device_index], 1u,
               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(
                   &g_block_cache_readahead_locks[device_index],
                   __ATOMIC_RELAXED))
            __asm__ volatile("" ::: "memory");
    }
}

static void block_cache_readahead_unlock(int device_index) {
    if (device_index < 0 || device_index >= BLOCK_MAX_DEVICES) return;
    __atomic_store_n(&g_block_cache_readahead_locks[device_index], 0u,
                     __ATOMIC_RELEASE);
}

static block_device_t *block_cache_device(block_device_t *device,
                                          uint64_t *lba_offset) {
    if (lba_offset) *lba_offset = 0;
    if (!device) return 0;
    if (device->cache_parent && device->cache_parent != device) {
        if (lba_offset) *lba_offset = device->cache_lba_offset;
        return device->cache_parent;
    }
    return device;
}

static int block_cache_device_index(block_device_t *device) {
    if (!device || device < g_block_devices ||
        device >= g_block_devices + BLOCK_MAX_DEVICES)
        return -1;
    return (int)(device - g_block_devices);
}

static uint8_t *block_cache_readahead_buffer(int device_index) {
    int32_t state;
    uint8_t *buffer;

    if (device_index < 0 || device_index >= BLOCK_MAX_DEVICES) return 0;
    state = __atomic_load_n(
        &g_block_cache_readahead_state[device_index], __ATOMIC_ACQUIRE);
    if (state > 0) return g_block_cache_readahead[device_index];
    if (state < 0) return 0;
    if (!__sync_bool_compare_and_swap(
            &g_block_cache_readahead_state[device_index], 0, 2)) {
        while ((state = __atomic_load_n(
                    &g_block_cache_readahead_state[device_index],
                    __ATOMIC_ACQUIRE)) == 2)
            __asm__ volatile("" ::: "memory");
        return state > 0 ? g_block_cache_readahead[device_index] : 0;
    }

    buffer = (uint8_t *)arch_vm_reserve_pages(
        BLOCK_CACHE_READAHEAD_PAGES);
    if (!buffer) {
        __atomic_store_n(&g_block_cache_readahead_state[device_index], -1,
                         __ATOMIC_RELEASE);
        return 0;
    }
    g_block_cache_readahead[device_index] = buffer;
    __atomic_store_n(&g_block_cache_readahead_state[device_index], 1,
                     __ATOMIC_RELEASE);
    return buffer;
}

static uint32_t block_cache_hash(block_device_t *device,
                                 uint64_t page_index) {
    uint64_t value = ((uint64_t)(uintptr_t)device >> 4) ^
                     (page_index * 0x9e3779b97f4a7c15ULL);
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    return (uint32_t)value;
}

static uint32_t block_cache_target_pages(void) {
    uint64_t total = arch_vm_memory_total_bytes();
    uint64_t target = total ? total / 16u / BLOCK_CACHE_PAGE_SIZE :
                              BLOCK_CACHE_MAX_PAGES;
    uint32_t pages = BLOCK_CACHE_MIN_PAGES;

    if (target > BLOCK_CACHE_MAX_PAGES) target = BLOCK_CACHE_MAX_PAGES;
    while ((uint64_t)pages * 2u <= target &&
           pages < BLOCK_CACHE_MAX_PAGES)
        pages <<= 1u;
    return pages;
}

static int block_cache_prepare(void) {
    int32_t state = __atomic_load_n(&g_block_cache_state, __ATOMIC_ACQUIRE);
    uint32_t pages;

    if (state > 0) return 1;
    if (state < 0) return 0;
    if (!__sync_bool_compare_and_swap(&g_block_cache_state, 0, 2)) {
        while ((state = __atomic_load_n(&g_block_cache_state,
                                        __ATOMIC_ACQUIRE)) == 2)
            __asm__ volatile("" ::: "memory");
        return state > 0;
    }

    for (pages = block_cache_target_pages();
         pages >= BLOCK_CACHE_MIN_PAGES; pages >>= 1u) {
        uint64_t metadata_bytes =
            (uint64_t)pages * sizeof(block_cache_entry_t);
        uint64_t metadata_pages =
            (metadata_bytes + BLOCK_CACHE_PAGE_SIZE - 1u) /
            BLOCK_CACHE_PAGE_SIZE;
        uint64_t allocation_pages = metadata_pages + pages;
        uint8_t *memory =
            (uint8_t *)arch_vm_reserve_pages(allocation_pages);
        if (!memory) continue;
        g_block_cache_entries = (block_cache_entry_t *)memory;
        g_block_cache_data = memory + metadata_pages * BLOCK_CACHE_PAGE_SIZE;
        g_block_cache_pages = pages;
        g_block_cache_sets = pages / BLOCK_CACHE_WAYS;
        g_block_cache_clock = 0;
        memset(g_block_cache_entries, 0,
               metadata_pages * BLOCK_CACHE_PAGE_SIZE);
        __atomic_store_n(&g_block_cache_state, 1, __ATOMIC_RELEASE);
        printf("[block-cache] ready pages=%u bytes=%u MiB ways=%u\n",
               pages, pages / 256u, BLOCK_CACHE_WAYS);
        return 1;
    }

    __atomic_store_n(&g_block_cache_state, -1, __ATOMIC_RELEASE);
    printf("[block-cache] unavailable; using direct block I/O\n");
    return 0;
}

static int block_cache_compatible(const block_device_t *device) {
    return device && device->cache_enabled && device->sector_size &&
           device->sector_size <= BLOCK_CACHE_PAGE_SIZE &&
           (BLOCK_CACHE_PAGE_SIZE % device->sector_size) == 0;
}

static int block_cache_find_locked(block_device_t *device,
                                   uint64_t page_index) {
    uint32_t set;
    uint32_t first;
    if (!g_block_cache_sets) return -1;
    set = block_cache_hash(device, page_index) & (g_block_cache_sets - 1u);
    first = set * BLOCK_CACHE_WAYS;
    for (uint32_t way = 0; way < BLOCK_CACHE_WAYS; ++way) {
        block_cache_entry_t *entry = &g_block_cache_entries[first + way];
        if (entry->valid && entry->device == device &&
            entry->page_index == page_index)
            return (int)(first + way);
    }
    return -1;
}

static int block_cache_copy_page(block_device_t *device,
                                 uint64_t page_index, void *output) {
    int slot;
    block_cache_lock();
    slot = block_cache_find_locked(device, page_index);
    if (slot >= 0) {
        g_block_cache_entries[slot].age = ++g_block_cache_clock;
        memcpy(output,
               g_block_cache_data + (uint32_t)slot * BLOCK_CACHE_PAGE_SIZE,
               BLOCK_CACHE_PAGE_SIZE);
    }
    block_cache_unlock();
    return slot >= 0;
}

static int block_cache_copy_sectors(block_device_t *device,
                                    uint64_t page_index,
                                    uint32_t first_sector,
                                    uint32_t sector_count,
                                    uint32_t sector_size,
                                    void *output) {
    int slot;
    uint64_t offset = (uint64_t)first_sector * sector_size;
    uint64_t bytes = (uint64_t)sector_count * sector_size;

    if (!output || offset + bytes > BLOCK_CACHE_PAGE_SIZE)
        return 0;
    block_cache_lock();
    slot = block_cache_find_locked(device, page_index);
    if (slot >= 0) {
        g_block_cache_entries[slot].age = ++g_block_cache_clock;
        memcpy(output,
               g_block_cache_data +
                   (uint32_t)slot * BLOCK_CACHE_PAGE_SIZE + offset,
               bytes);
    }
    block_cache_unlock();
    return slot >= 0;
}

static int block_cache_contains(block_device_t *device,
                                uint64_t page_index) {
    int found;
    block_cache_lock();
    found = block_cache_find_locked(device, page_index) >= 0;
    block_cache_unlock();
    return found;
}

static int block_cache_sequential_access(block_device_t *device,
                                         uint64_t page_index) {
    int device_index = block_cache_device_index(device);
    int sequential = 0;
    if (device_index < 0) return 0;
    block_cache_lock();
    if (g_block_cache_last_page_valid[device_index] &&
        g_block_cache_last_page[device_index] != UINT64_MAX &&
        page_index == g_block_cache_last_page[device_index] + 1u)
        sequential = 1;
    g_block_cache_last_page[device_index] = page_index;
    g_block_cache_last_page_valid[device_index] = 1;
    block_cache_unlock();
    return sequential;
}

static int block_cache_replacement_locked(block_device_t *device,
                                          uint64_t page_index) {
    uint32_t set = block_cache_hash(device, page_index) &
                   (g_block_cache_sets - 1u);
    uint32_t first = set * BLOCK_CACHE_WAYS;
    uint32_t replacement = first;
    uint32_t oldest_distance = 0;

    for (uint32_t way = 0; way < BLOCK_CACHE_WAYS; ++way) {
        uint32_t slot = first + way;
        block_cache_entry_t *entry = &g_block_cache_entries[slot];
        uint32_t distance;
        if (!entry->valid) return (int)slot;
        distance = g_block_cache_clock - entry->age;
        if (distance >= oldest_distance) {
            oldest_distance = distance;
            replacement = slot;
        }
    }
    return (int)replacement;
}

static void block_cache_store_pages(block_device_t *device,
                                    uint64_t first_page,
                                    const uint8_t *input, uint32_t pages,
                                    uint32_t expected_generation) {
    int device_index = block_cache_device_index(device);
    if (device_index < 0) return;
    block_cache_lock();
    if (g_block_cache_generation[device_index] != expected_generation) {
        block_cache_unlock();
        return;
    }
    for (uint32_t page = 0; page < pages; ++page) {
        uint64_t page_index = first_page + page;
        int slot = block_cache_find_locked(device, page_index);
        block_cache_entry_t *entry;
        if (slot < 0)
            slot = block_cache_replacement_locked(device, page_index);
        entry = &g_block_cache_entries[slot];
        memcpy(g_block_cache_data + (uint32_t)slot * BLOCK_CACHE_PAGE_SIZE,
               input + page * BLOCK_CACHE_PAGE_SIZE,
               BLOCK_CACHE_PAGE_SIZE);
        entry->device = device;
        entry->page_index = page_index;
        entry->age = ++g_block_cache_clock;
        entry->valid = 1;
    }
    block_cache_unlock();
}

static void block_cache_write_complete(block_device_t *device,
                                       uint64_t first_byte,
                                       const uint8_t *input,
                                       uint64_t bytes) {
    uint64_t last_byte;
    uint64_t first_page;
    uint64_t last_page;
    int device_index = block_cache_device_index(device);
    if (device_index < 0 || !bytes || !g_block_cache_entries) return;
    last_byte = first_byte + bytes - 1u;
    if (last_byte < first_byte) return;
    first_page = first_byte / BLOCK_CACHE_PAGE_SIZE;
    last_page = last_byte / BLOCK_CACHE_PAGE_SIZE;

    block_cache_lock();
    ++g_block_cache_generation[device_index];
    for (uint64_t page = first_page; page <= last_page; ++page) {
        uint64_t page_start = page * BLOCK_CACHE_PAGE_SIZE;
        uint64_t copy_start = first_byte > page_start ? first_byte : page_start;
        uint64_t page_end = page_start + BLOCK_CACHE_PAGE_SIZE;
        uint64_t write_end = first_byte + bytes;
        uint64_t copy_end = write_end < page_end ? write_end : page_end;
        int slot = block_cache_find_locked(device, page);

        if (copy_start == page_start && copy_end == page_end) {
            block_cache_entry_t *entry;
            if (slot < 0) slot = block_cache_replacement_locked(device, page);
            entry = &g_block_cache_entries[slot];
            memcpy(g_block_cache_data +
                       (uint32_t)slot * BLOCK_CACHE_PAGE_SIZE,
                   input + copy_start - first_byte,
                   BLOCK_CACHE_PAGE_SIZE);
            entry->device = device;
            entry->page_index = page;
            entry->age = ++g_block_cache_clock;
            entry->valid = 1;
        } else if (slot >= 0) {
            memcpy(g_block_cache_data +
                       (uint32_t)slot * BLOCK_CACHE_PAGE_SIZE +
                       copy_start - page_start,
                   input + copy_start - first_byte,
                   copy_end - copy_start);
            g_block_cache_entries[slot].age = ++g_block_cache_clock;
        }
        if (page == UINT64_MAX) break;
    }
    block_cache_unlock();
}

static int block_read_sectors_direct(block_device_t *dev, uint32_t lba,
                                     uint32_t count, void *out) {
    uint32_t done = 0;
    uint8_t *dst = (uint8_t *)out;
    uint32_t max_batch = block_max_transfer_sectors(dev);
    while (done < count) {
        uint32_t chunk = count - done;
        if (chunk > max_batch) chunk = max_batch;
        block_io_policy_begin(dev, 0,
                              (uint64_t)chunk * dev->sector_size);
        if (dev->ops.read_sectors(dev, lba + done, chunk,
                                  dst + done * dev->sector_size) == 0) {
            block_io_policy_complete(
                dev, 0, (uint64_t)chunk * dev->sector_size);
            done += chunk;
            continue;
        }
        if (chunk <= 1) return -1;
        max_batch = chunk / 2;
        if (max_batch == 0) max_batch = 1;
    }
    return 0;
}

void block_init(void) {
    memset(g_block_devices, 0, sizeof(g_block_devices));
    memset(g_block_cache_generation, 0, sizeof(g_block_cache_generation));
    memset(g_block_cache_last_page, 0, sizeof(g_block_cache_last_page));
    memset(g_block_cache_last_page_valid, 0,
           sizeof(g_block_cache_last_page_valid));
    g_block_slots = 0;
    g_block_byte_io_lock = 0;
    g_block_cache_lock = 0;
    memset((void *)g_block_cache_readahead_locks, 0,
           sizeof(g_block_cache_readahead_locks));
    if (g_block_cache_entries)
        memset(g_block_cache_entries, 0,
               (uint64_t)g_block_cache_pages * sizeof(*g_block_cache_entries));
}

int block_register(const char *name, uint32_t sector_size, uint32_t sector_count, uint32_t start_lba, void *ctx, block_ops_t ops) {
    block_device_t *d = 0;
    int active_index = 0;
    int slot;

    if (!name || !name[0] || strlen(name) >= BLOCK_NAME_MAX ||
        !sector_size ||
        sector_size > BLOCK_MAX_SECTOR_SIZE) return -1;
    if (block_find(name)) return -1;
    for (slot = 0; slot < g_block_slots; ++slot) {
        if (!g_block_devices[slot].present) {
            d = &g_block_devices[slot];
            break;
        }
        active_index++;
    }
    if (!d) {
        if (g_block_slots >= BLOCK_MAX_DEVICES) return -1;
        slot = g_block_slots++;
        d = &g_block_devices[slot];
    }
    memset(d, 0, sizeof(*d));
    d->present = 1;
    d->sector_size = sector_size;
    d->sector_count = sector_count;
    d->start_lba = start_lba;
    d->ctx = ctx;
    d->ops = ops;
    d->cache_parent = d;
    d->cache_lba_offset = 0;
    d->max_transfer_sectors = BLOCK_BATCH_MAX_SECTORS;
    d->cache_enabled = 1;
    d->linux_disk_index = -1;
    strncpy(d->name, name, BLOCK_NAME_MAX - 1);
    d->name[BLOCK_NAME_MAX - 1] = 0;
    if (start_lba == 0 && strncmp(name, "ram", 3) != 0 &&
        strncmp(name, "dm-", 3) != 0) {
        d->linux_disk_index = block_linux_disk_index_allocate();
        if (d->linux_disk_index < 0) {
            memset(d, 0, sizeof(*d));
            if (slot == g_block_slots - 1)
                g_block_slots--;
            return -1;
        }
    }
    return active_index;
}

static void block_cache_invalidate_device(block_device_t *device) {
    int device_index = block_cache_device_index(device);

    if (device_index < 0) return;
    block_cache_lock();
    ++g_block_cache_generation[device_index];
    g_block_cache_last_page[device_index] = 0;
    g_block_cache_last_page_valid[device_index] = 0;
    if (g_block_cache_entries) {
        for (uint32_t index = 0; index < g_block_cache_pages; ++index) {
            block_cache_entry_t *entry = &g_block_cache_entries[index];
            if (entry->valid && entry->device == device) {
                memset(entry, 0, sizeof(*entry));
            }
        }
    }
    block_cache_unlock();
}

int block_unregister(block_device_t *device) {
    int slot = block_cache_device_index(device);

    if (slot < 0 || !device->present) return -1;
    for (int index = 0; index < g_block_slots; ++index) {
        block_device_t *candidate = &g_block_devices[index];
        if (candidate->present && candidate != device &&
            candidate->cache_parent == device)
            return -1;
    }
    block_cache_invalidate_device(device);
    memset(device, 0, sizeof(*device));
    while (g_block_slots > 0 &&
           !g_block_devices[g_block_slots - 1].present)
        g_block_slots--;
    return 0;
}

int block_resize(block_device_t *device, uint32_t sector_count) {
    if (!device || !device->present) return -1;
    for (int index = 0; index < g_block_slots; ++index) {
        block_device_t *candidate = &g_block_devices[index];
        if (!candidate->present || candidate == device ||
            candidate->cache_parent != device)
            continue;
        if ((uint64_t)candidate->cache_lba_offset +
            candidate->sector_count > sector_count)
            return -1;
    }
    block_cache_invalidate_device(device);
    device->sector_count = sector_count;
    return 0;
}

void block_set_cache_parent(block_device_t *device, block_device_t *parent,
                            uint32_t lba_offset) {
    if (!device || !parent) return;
    device->cache_parent = parent->cache_parent ? parent->cache_parent : parent;
    device->cache_lba_offset = parent->cache_lba_offset + lba_offset;
    device->max_transfer_sectors = parent->max_transfer_sectors;
    device->cache_enabled = parent->cache_enabled;
}

void block_set_cache_enabled(block_device_t *device, int enabled) {
    if (!device) return;
    device->cache_enabled = enabled != 0;
}

void block_set_max_transfer_sectors(block_device_t *device,
                                    uint32_t max_transfer_sectors) {
    if (!device) return;
    if (!max_transfer_sectors ||
        max_transfer_sectors > BLOCK_BATCH_MAX_SECTORS) {
        max_transfer_sectors = BLOCK_BATCH_MAX_SECTORS;
    }
    device->max_transfer_sectors = max_transfer_sectors;
}

uint32_t block_max_transfer_sectors(const block_device_t *device) {
    uint32_t limit = device ? device->max_transfer_sectors : 0;
    if (!limit || limit > BLOCK_BATCH_MAX_SECTORS)
        limit = BLOCK_BATCH_MAX_SECTORS;
    return limit;
}

block_device_t *block_get(int idx) {
    if (idx < 0) return 0;
    for (int slot = 0; slot < g_block_slots; ++slot) {
        if (!g_block_devices[slot].present) continue;
        if (idx-- == 0) return &g_block_devices[slot];
    }
    return 0;
}

block_device_t *block_find(const char *name) {
    if (!name) return 0;
    for (int i = 0; i < g_block_slots; ++i) {
        if (g_block_devices[i].present &&
            strcmp(g_block_devices[i].name, (char *)name) == 0)
            return &g_block_devices[i];
    }
    return 0;
}

block_device_t *block_find_linux_device(uint64_t device_number) {
    uint32_t wanted_major =
        (uint32_t)((device_number >> 8) & 0xfffu) |
        (uint32_t)((device_number >> 32) & 0xfffff000u);
    uint32_t wanted_minor =
        (uint32_t)(device_number & 0xffu) |
        (uint32_t)((device_number >> 12) & 0xffffff00u);
    for (int index = 0; index < g_block_slots; ++index) {
        block_device_t *candidate = &g_block_devices[index];
        uint32_t major;
        uint32_t minor;
        if (!candidate->present ||
            block_linux_major_minor(candidate, &major, &minor) < 0)
            continue;
        if (major == wanted_major && minor == wanted_minor)
            return candidate;
    }
    return 0;
}

int block_count(void) {
    int count = 0;
    for (int index = 0; index < g_block_slots; ++index) {
        if (g_block_devices[index].present) count++;
    }
    return count;
}

int block_read_sectors(block_device_t *dev, uint32_t lba, uint32_t count, void *out) {
    block_device_t *cache_device;
    uint64_t cache_lba_offset;
    uint64_t absolute_lba;
    uint32_t sectors_per_page;
    uint32_t done = 0;
    uint8_t *dst = (uint8_t *)out;
    if (!dev || !out || !dev->ops.read_sectors || dev->sector_size == 0) return -1;
    if (count == 0) return 0;

    cache_device = block_cache_device(dev, &cache_lba_offset);
    absolute_lba = cache_lba_offset + lba;
    if (!block_cache_compatible(dev) ||
        absolute_lba > UINT32_MAX ||
        !block_cache_prepare())
        return block_read_sectors_direct(dev, lba, count, out);

    sectors_per_page = BLOCK_CACHE_PAGE_SIZE / dev->sector_size;
    while (done < count) {
        uint64_t current_lba = absolute_lba + done;
        uint32_t remaining = count - done;
        if ((current_lba % sectors_per_page) == 0 &&
            remaining >= sectors_per_page) {
            uint64_t page_index = current_lba / sectors_per_page;
            int sequential = block_cache_sequential_access(cache_device,
                                                           page_index);
            int device_index = block_cache_device_index(cache_device);
            uint8_t *readahead =
                block_cache_readahead_buffer(device_index);
            if (block_cache_copy_page(
                    cache_device, page_index,
                    dst + (uint64_t)done * dev->sector_size)) {
                done += sectors_per_page;
                continue;
            }
            if (remaining == sectors_per_page && sequential && readahead) {
                uint64_t logical_lba = (uint64_t)lba + done;
                uint64_t available_sectors =
                    logical_lba < dev->sector_count ?
                    (uint64_t)dev->sector_count - logical_lba : 0;
                uint32_t read_pages =
                    (uint32_t)(available_sectors / sectors_per_page);
                if (read_pages > BLOCK_CACHE_READAHEAD_PAGES)
                    read_pages = BLOCK_CACHE_READAHEAD_PAGES;
                if (read_pages > 1u && device_index >= 0) {
                    uint32_t generation;
                    for (uint32_t page = 1; page < read_pages; ++page) {
                        if (block_cache_contains(cache_device,
                                                 page_index + page)) {
                            read_pages = page;
                            break;
                        }
                    }
                    block_cache_readahead_lock(device_index);
                    if (block_cache_copy_page(
                            cache_device, page_index,
                            dst + (uint64_t)done * dev->sector_size)) {
                        block_cache_readahead_unlock(device_index);
                        done += sectors_per_page;
                        continue;
                    }
                    block_cache_lock();
                    generation = g_block_cache_generation[device_index];
                    block_cache_unlock();
                    if (block_read_sectors_direct(
                            dev, lba + done,
                            read_pages * sectors_per_page,
                            readahead) < 0) {
                        block_cache_readahead_unlock(device_index);
                        return -1;
                    }
                    memcpy(dst + (uint64_t)done * dev->sector_size,
                           readahead,
                           BLOCK_CACHE_PAGE_SIZE);
                    block_cache_store_pages(
                        cache_device, page_index, readahead,
                        read_pages, generation);
                    block_cache_readahead_unlock(device_index);
                    done += sectors_per_page;
                    continue;
                }
            }
            {
                uint32_t run_pages = 1;
                uint32_t maximum_pages = remaining / sectors_per_page;
                uint32_t batch_pages =
                    block_max_transfer_sectors(dev) / sectors_per_page;
                uint32_t generation;
                int device_index = block_cache_device_index(cache_device);
                if (maximum_pages > batch_pages) maximum_pages = batch_pages;
                while (run_pages < maximum_pages &&
                       !block_cache_contains(cache_device,
                                             page_index + run_pages))
                    ++run_pages;
                if (device_index < 0)
                    return block_read_sectors_direct(
                        dev, lba + done, remaining,
                        dst + (uint64_t)done * dev->sector_size);
                block_cache_lock();
                generation = g_block_cache_generation[device_index];
                block_cache_unlock();
                if (block_read_sectors_direct(
                        dev, lba + done, run_pages * sectors_per_page,
                        dst + (uint64_t)done * dev->sector_size) < 0)
                    return -1;
                block_cache_store_pages(
                    cache_device, page_index,
                    dst + (uint64_t)done * dev->sector_size,
                    run_pages, generation);
                done += run_pages * sectors_per_page;
                continue;
            }
        }
        {
            uint32_t partial = sectors_per_page -
                               (uint32_t)(current_lba % sectors_per_page);
            uint32_t first_sector =
                (uint32_t)(current_lba % sectors_per_page);
            uint64_t page_index = current_lba / sectors_per_page;
            uint64_t page_lba = page_index * sectors_per_page;
            uint64_t logical_page_lba;
            int device_index = block_cache_device_index(cache_device);
            uint8_t *readahead =
                block_cache_readahead_buffer(device_index);
            if (partial > remaining) partial = remaining;
            if (block_cache_copy_sectors(
                    cache_device, page_index, first_sector, partial,
                    dev->sector_size,
                    dst + (uint64_t)done * dev->sector_size)) {
                done += partial;
                continue;
            }
            if (page_lba >= cache_lba_offset) {
                uint32_t generation;
                logical_page_lba = page_lba - cache_lba_offset;
                if (readahead && device_index >= 0 &&
                    logical_page_lba <= UINT32_MAX &&
                    logical_page_lba + sectors_per_page <=
                        dev->sector_count) {
                    block_cache_readahead_lock(device_index);
                    if (block_cache_copy_sectors(
                            cache_device, page_index, first_sector, partial,
                            dev->sector_size,
                            dst + (uint64_t)done * dev->sector_size)) {
                        block_cache_readahead_unlock(device_index);
                        done += partial;
                        continue;
                    }
                    block_cache_lock();
                    generation = g_block_cache_generation[device_index];
                    block_cache_unlock();
                    if (block_read_sectors_direct(
                            dev, (uint32_t)logical_page_lba,
                            sectors_per_page,
                            readahead) == 0) {
                        memcpy(
                            dst + (uint64_t)done * dev->sector_size,
                            readahead +
                                (uint64_t)first_sector * dev->sector_size,
                            (uint64_t)partial * dev->sector_size);
                        block_cache_store_pages(
                            cache_device, page_index,
                            readahead, 1, generation);
                        block_cache_readahead_unlock(device_index);
                        done += partial;
                        continue;
                    }
                    block_cache_readahead_unlock(device_index);
                }
            }
            if (block_read_sectors_direct(
                    dev, lba + done, partial,
                    dst + (uint64_t)done * dev->sector_size) < 0)
                return -1;
            done += partial;
        }
    }
    return 0;
}

static int block_write_sectors_direct(block_device_t *dev, uint32_t lba,
                                      uint32_t count, const void *in) {
    uint32_t done = 0;
    const uint8_t *src = (const uint8_t *)in;
    uint32_t max_batch = block_max_transfer_sectors(dev);
    while (done < count) {
        uint32_t chunk = count - done;
        if (chunk > max_batch) chunk = max_batch;
        block_io_policy_begin(dev, 1,
                              (uint64_t)chunk * dev->sector_size);
        if (dev->ops.write_sectors(dev, lba + done, chunk,
                                   src + done * dev->sector_size) == 0) {
            block_io_policy_complete(
                dev, 1, (uint64_t)chunk * dev->sector_size);
            done += chunk;
            continue;
        }
        if (chunk <= 1) return -1;
        max_batch = chunk / 2;
        if (max_batch == 0) max_batch = 1;
    }
    return 0;
}

int block_write_sectors(block_device_t *dev, uint32_t lba, uint32_t count, const void *in) {
    block_device_t *cache_device;
    uint64_t cache_lba_offset;
    uint64_t absolute_lba;
    uint32_t done = 0;
    const uint8_t *src = (const uint8_t *)in;
    if (!dev || !in || !dev->ops.write_sectors || dev->sector_size == 0) {
        printf("[block] write unavailable device=%s present=%d input=%d operation=%d sector_size=%u\n",
               dev ? dev->name : "-", dev ? dev->present : 0, in != 0,
               dev && dev->ops.write_sectors != 0,
               dev ? (unsigned)dev->sector_size : 0u);
        return -1;
    }
    if (count == 0) return 0;
    cache_device = block_cache_device(dev, &cache_lba_offset);
    absolute_lba = cache_lba_offset + lba;
    while (done < count) {
        uint32_t chunk = count - done;
        if (chunk > block_max_transfer_sectors(dev))
            chunk = block_max_transfer_sectors(dev);
        if (block_write_sectors_direct(
                dev, lba + done, chunk,
                src + (uint64_t)done * dev->sector_size) < 0)
            return -1;
        if (g_block_cache_entries && absolute_lba + done <= UINT32_MAX) {
            block_cache_write_complete(
                cache_device,
                (absolute_lba + done) * dev->sector_size,
                src + (uint64_t)done * dev->sector_size,
                (uint64_t)chunk * dev->sector_size);
        }
        done += chunk;
    }
    return 0;
}

int block_flush(block_device_t *dev) {
    if (!dev || !dev->present) return -1;
    if (!dev->ops.flush) return 0;
    return dev->ops.flush(dev);
}

uint64_t block_device_size_bytes(const block_device_t *dev) {
    if (!dev || !dev->present || !dev->sector_size) return 0;
    return (uint64_t)dev->sector_count * (uint64_t)dev->sector_size;
}

static void block_byte_io_lock(void) {
    while (__atomic_exchange_n(&g_block_byte_io_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_block_byte_io_lock, __ATOMIC_RELAXED))
            __asm__ volatile("" ::: "memory");
    }
}

static void block_byte_io_unlock(void) {
    __atomic_store_n(&g_block_byte_io_lock, 0u, __ATOMIC_RELEASE);
}

int64_t block_read_bytes(block_device_t *dev, uint64_t offset, void *out,
                         uint32_t length) {
    uint8_t *destination = (uint8_t *)out;
    uint64_t device_size;
    uint32_t completed = 0;
    uint32_t sector_size;

    if (!dev || !dev->present || (!out && length))
        return -EDGE_LINUX_ENODEV;
    if (!length) return 0;
    if (!dev->ops.read_sectors || !dev->sector_size ||
        dev->sector_size > sizeof(g_block_byte_scratch))
        return -EDGE_LINUX_EIO;
    device_size = block_device_size_bytes(dev);
    if (offset >= device_size) return 0;
    if ((uint64_t)length > device_size - offset)
        length = (uint32_t)(device_size - offset);
    sector_size = dev->sector_size;

    while (completed < length) {
        uint64_t position = offset + completed;
        uint32_t sector_offset = (uint32_t)(position % sector_size);
        uint32_t remaining = length - completed;
        uint32_t lba = (uint32_t)(position / sector_size);
        if (!sector_offset && remaining >= sector_size) {
            uint32_t sectors = remaining / sector_size;
            if (block_read_sectors(dev, lba, sectors,
                                   destination + completed) < 0) {
                return completed ? (int64_t)completed : -EDGE_LINUX_EIO;
            }
            completed += sectors * sector_size;
            continue;
        }
        block_byte_io_lock();
        if (block_read_sectors(dev, lba, 1u, g_block_byte_scratch) < 0) {
            block_byte_io_unlock();
            return completed ? (int64_t)completed : -EDGE_LINUX_EIO;
        }
        {
            uint32_t count = sector_size - sector_offset;
            if (count > remaining) count = remaining;
            memcpy(destination + completed,
                   g_block_byte_scratch + sector_offset, count);
            completed += count;
        }
        block_byte_io_unlock();
    }
    return completed;
}

int64_t block_write_bytes(block_device_t *dev, uint64_t offset,
                          const void *input, uint32_t length) {
    const uint8_t *source = (const uint8_t *)input;
    uint64_t device_size;
    uint32_t completed = 0;
    uint32_t sector_size;

    if (!dev || !dev->present || (!input && length))
        return -EDGE_LINUX_ENODEV;
    if (!length) return 0;
    if (!dev->ops.write_sectors) return -EDGE_LINUX_EROFS;
    if (!dev->sector_size || dev->sector_size > sizeof(g_block_byte_scratch))
        return -EDGE_LINUX_EIO;
    device_size = block_device_size_bytes(dev);
    if (offset >= device_size) return -EDGE_LINUX_ENOSPC;
    if ((uint64_t)length > device_size - offset)
        length = (uint32_t)(device_size - offset);
    sector_size = dev->sector_size;

    while (completed < length) {
        uint64_t position = offset + completed;
        uint32_t sector_offset = (uint32_t)(position % sector_size);
        uint32_t remaining = length - completed;
        uint32_t lba = (uint32_t)(position / sector_size);
        if (!sector_offset && remaining >= sector_size) {
            uint32_t sectors = remaining / sector_size;
            if (block_write_sectors(dev, lba, sectors,
                                    source + completed) < 0) {
                return completed ? (int64_t)completed : -EDGE_LINUX_EIO;
            }
            completed += sectors * sector_size;
            continue;
        }
        block_byte_io_lock();
        if (!dev->ops.read_sectors ||
            block_read_sectors(dev, lba, 1u, g_block_byte_scratch) < 0) {
            block_byte_io_unlock();
            return completed ? (int64_t)completed : -EDGE_LINUX_EIO;
        }
        {
            uint32_t count = sector_size - sector_offset;
            if (count > remaining) count = remaining;
            memcpy(g_block_byte_scratch + sector_offset,
                   source + completed, count);
            if (block_write_sectors(dev, lba, 1u,
                                    g_block_byte_scratch) < 0) {
                block_byte_io_unlock();
                return completed ? (int64_t)completed : -EDGE_LINUX_EIO;
            }
            completed += count;
        }
        block_byte_io_unlock();
    }
    return completed;
}

int block_linux_ioctl_query(const block_device_t *dev, uint32_t command,
                            uint64_t *value, uint32_t *value_size) {
    uint64_t result;
    uint32_t size;
    if (!dev || !dev->present || !value || !value_size)
        return -EDGE_LINUX_EINVAL;
    switch (command) {
        case 0x125eu: /* BLKROGET */
            result = dev->ops.write_sectors ? 0u : 1u;
            size = sizeof(uint32_t);
            break;
        case 0x1260u: /* BLKGETSIZE, measured in 512-byte sectors */
            result = block_device_size_bytes(dev) / 512u;
            size = sizeof(uint64_t);
            break;
        case 0x1263u: /* BLKRAGET */
        case 0x1265u: /* BLKFRAGET */
            result = 0u;
            size = sizeof(uint64_t);
            break;
        case 0x1267u: /* BLKSECTGET */
            result = block_max_transfer_sectors(dev);
            size = sizeof(uint16_t);
            break;
        case 0x1268u: /* BLKSSZGET */
            result = dev->sector_size;
            size = sizeof(uint32_t);
            break;
        case 0x80081270u: /* BLKBSZGET */
            result = dev->sector_size;
            size = sizeof(uint64_t);
            break;
        case 0x80081272u: /* BLKGETSIZE64 */
            result = block_device_size_bytes(dev);
            size = sizeof(uint64_t);
            break;
        case 0x1278u: /* BLKIOMIN */
        case 0x127bu: /* BLKPBSZGET */
            result = dev->sector_size;
            size = sizeof(uint32_t);
            break;
        case 0x1279u: /* BLKIOOPT */
        case 0x127au: /* BLKALIGNOFF */
        case 0x127cu: /* BLKDISCARDZEROES */
            result = 0u;
            size = sizeof(uint32_t);
            break;
        default:
            return -EDGE_LINUX_ENOTTY;
    }
    *value = result;
    *value_size = size;
    return 0;
}

int block_is_partition(const block_device_t *dev) {
    /*
     * EdgeOS registers whole disks at LBA zero and MBR slices with the slice
     * start LBA.  Keep sysfs classification tied to that registration state so
     * userland sees only real kernel block devices.  Do not infer partitions
     * from names alone: ram0 is a disk even though it ends in a digit.
     */
    return dev && dev->present && dev->start_lba != 0;
}

static int block_copy_name(const char *name, char *out, uint32_t max) {
    uint32_t n;
    if (!name || !out || max == 0) return -1;
    n = (uint32_t)strlen(name);
    if (n + 1u > max) return -1;
    memcpy(out, name, n + 1u);
    return 0;
}

static const char *block_strchr_local(const char *s, char c) {
    if (!s) return 0;
    while (*s) {
        if (*s == c) return s;
        ++s;
    }
    return c == 0 ? s : 0;
}

static int block_name_partition_suffix(const char *name, uint32_t *suffix_start, int *partno) {
    int end;
    int start;
    int val = 0;
    if (!name || !suffix_start || !partno) return -1;
    end = (int)strlen(name);
    start = end;
    while (start > 0 && name[start - 1] >= '0' && name[start - 1] <= '9') start--;
    if (start == end) return -1;
    for (int i = start; i < end; ++i) {
        val = val * 10 + (name[i] - '0');
    }
    if (start > 0 && name[start - 1] == 'p') start--;
    *suffix_start = (uint32_t)start;
    *partno = val;
    return 0;
}

int block_partition_parent_name(const block_device_t *dev, char *out, uint32_t max) {
    uint32_t parent_len;
    int partno;
    char parent[BLOCK_NAME_MAX];
    if (!block_is_partition(dev) || !out || max == 0) return -1;
    if (block_name_partition_suffix(dev->name, &parent_len, &partno) < 0) return -1;
    if (parent_len == 0 || parent_len >= sizeof(parent) || parent_len + 1u > max) return -1;
    memcpy(parent, dev->name, parent_len);
    parent[parent_len] = 0;
    if (!block_find(parent)) return -1;
    memcpy(out, parent, parent_len + 1u);
    return 0;
}

int block_partition_number(const block_device_t *dev) {
    uint32_t suffix_start;
    int partno;
    if (!block_is_partition(dev)) return 0;
    if (block_name_partition_suffix(dev->name, &suffix_start, &partno) < 0) return 0;
    return partno;
}

static int block_disk_index(const block_device_t *dev) {
    if (!dev || !dev->present || block_is_partition(dev) ||
        strncmp(dev->name, "ram", 3) == 0 ||
        strncmp(dev->name, "dm-", 3) == 0)
        return -1;
    return dev->linux_disk_index;
}

int block_linux_major_minor(const block_device_t *dev, uint32_t *major, uint32_t *minor) {
    uint32_t maj = 8;
    uint32_t min = 0;
    if (!dev || !major || !minor) return -1;
    if (strncmp(dev->name, "dm-", 3) == 0) {
        int n = 0;
        const char *p = dev->name + 3;
        if (!*p) return -1;
        while (*p >= '0' && *p <= '9') {
            n = n * 10 + (*p - '0');
            ++p;
        }
        if (*p != 0 || n < 0 || n >= 256) return -1;
        maj = 253;
        min = (uint32_t)n;
    } else if (strncmp(dev->name, "loop", 4) == 0) {
        int n = 0;
        const char *p = dev->name + 4;
        if (!*p) return -1;
        while (*p >= '0' && *p <= '9') {
            n = n * 10 + (*p - '0');
            ++p;
        }
        if (*p != 0 || n < 0 || n >= 256) return -1;
        maj = 7;
        min = (uint32_t)n;
    } else if (strncmp(dev->name, "ram", 3) == 0) {
        int n = 0;
        const char *p = dev->name + 3;
        while (*p >= '0' && *p <= '9') {
            n = n * 10 + (*p - '0');
            ++p;
        }
        if (*p != 0) n = 0;
        maj = 1;
        min = (uint32_t)n;
    } else if (block_is_partition(dev)) {
        char parent_name[BLOCK_NAME_MAX];
        block_device_t *parent;
        int disk_idx;
        int partno;
        if (block_partition_parent_name(dev, parent_name, sizeof(parent_name)) < 0) return -1;
        parent = block_find(parent_name);
        disk_idx = block_disk_index(parent);
        if (disk_idx < 0) return -1;
        partno = block_partition_number(dev);
        maj = 8;
        min = (uint32_t)(disk_idx * 16 + (partno > 0 ? partno : 1));
    } else {
        int disk_idx = block_disk_index(dev);
        if (disk_idx < 0) return -1;
        maj = 8;
        min = (uint32_t)(disk_idx * 16);
    }
    *major = maj;
    *minor = min;
    return 0;
}

int block_disk_name_by_index(uint32_t idx, char *out, uint32_t max) {
    uint32_t seen = 0;
    for (int i = 0; i < g_block_slots; ++i) {
        block_device_t *d = &g_block_devices[i];
        if (!d->present) continue;
        if (block_is_partition(d)) continue;
        if (seen++ == idx) return block_copy_name(d->name, out, max);
    }
    return -1;
}

int block_device_name_by_index(uint32_t idx, char *out, uint32_t max) {
    uint32_t seen = 0;
    for (int i = 0; i < g_block_slots; ++i) {
        block_device_t *d = &g_block_devices[i];
        if (!d->present) continue;
        if (seen++ == idx) return block_copy_name(d->name, out, max);
    }
    return -1;
}

int block_partition_name_by_index(const char *disk_name, uint32_t idx, char *out, uint32_t max) {
    uint32_t seen = 0;
    if (!disk_name) return -1;
    for (int i = 0; i < g_block_slots; ++i) {
        block_device_t *d = &g_block_devices[i];
        if (!d->present) continue;
        char parent[BLOCK_NAME_MAX];
        if (!block_is_partition(d)) continue;
        if (block_partition_parent_name(d, parent, sizeof(parent)) < 0) continue;
        if (strcmp(parent, (char *)disk_name) != 0) continue;
        if (seen++ == idx) return block_copy_name(d->name, out, max);
    }
    return -1;
}

static int block_sysfs_append_char(char *buf, uint32_t max, uint32_t *off, char c) {
    if (!buf || !off || *off + 1u >= max) return -1;
    buf[(*off)++] = c;
    buf[*off] = 0;
    return 0;
}

static int block_sysfs_append_lit(char *buf, uint32_t max, uint32_t *off, const char *s) {
    if (!s) return -1;
    while (*s) {
        if (block_sysfs_append_char(buf, max, off, *s++) < 0) return -1;
    }
    return 0;
}

static int block_sysfs_append_u64(char *buf, uint32_t max, uint32_t *off, uint64_t v) {
    char tmp[21];
    int n = 0;
    if (v == 0) return block_sysfs_append_char(buf, max, off, '0');
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        if (block_sysfs_append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int block_sysfs_copy_string(char *out, uint32_t max, const char *s) {
    uint32_t n;
    if (!out || !s) return -1;
    n = (uint32_t)strlen(s);
    if (n > max) n = max;
    memcpy(out, s, n);
    return (int)n;
}

static int block_sysfs_known_disk_file(const char *file, int *is_link) {
    static const char *files[] = {
        "dev", "size", "ro", "removable", "stat", "uevent", "range",
        "alignment_offset", "discard_alignment", "capability"
    };
    if (!file || !is_link) return 0;
    *is_link = 0;
    if (strcmp(file, "subsystem") == 0) {
        *is_link = 1;
        return 1;
    }
    for (uint32_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        if (strcmp(file, files[i]) == 0) return 1;
    }
    return 0;
}

static int block_sysfs_known_part_file(const char *file, int *is_link) {
    static const char *files[] = {
        "dev", "size", "start", "partition", "ro", "stat", "uevent",
        "alignment_offset", "discard_alignment"
    };
    if (!file || !is_link) return 0;
    *is_link = 0;
    if (strcmp(file, "subsystem") == 0) {
        *is_link = 1;
        return 1;
    }
    for (uint32_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        if (strcmp(file, files[i]) == 0) return 1;
    }
    return 0;
}

static int block_sysfs_known_queue_file(const char *file) {
    static const char *files[] = {
        "logical_block_size", "physical_block_size", "hw_sector_size",
        "minimum_io_size", "optimal_io_size", "rotational", "read_ahead_kb",
        "max_sectors_kb", "max_hw_sectors_kb", "scheduler", "write_cache"
    };
    if (!file) return 0;
    for (uint32_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        if (strcmp(file, files[i]) == 0) return 1;
    }
    return 0;
}

static int block_sysfs_split_block_path(const char *path, char *disk, uint32_t disk_max,
                                        const char **rest) {
    static const char prefix[] = "/sys/block/";
    const char *p;
    uint32_t i = 0;
    if (!path || !disk || !rest) return -1;
    if (strncmp(path, prefix, sizeof(prefix) - 1u) != 0) return -1;
    p = path + sizeof(prefix) - 1u;
    if (!*p) return -1;
    while (p[i] && p[i] != '/') {
        if (i + 1u >= disk_max) return -1;
        disk[i] = p[i];
        ++i;
    }
    disk[i] = 0;
    *rest = p + i;
    return 0;
}

static int block_sysfs_class_proxy_path(const char *path, char *out, uint32_t max) {
    static const char prefix[] = "/sys/class/block/";
    const char *p;
    const char *rest;
    char name[BLOCK_NAME_MAX];
    char parent[BLOCK_NAME_MAX];
    block_device_t *dev;
    uint32_t i = 0;
    uint32_t off = 0;
    if (!path || !out || max == 0) return -1;
    if (strncmp(path, prefix, sizeof(prefix) - 1u) != 0) return -1;
    p = path + sizeof(prefix) - 1u;
    while (p[i] && p[i] != '/') {
        if (i + 1u >= sizeof(name)) return -1;
        name[i] = p[i];
        ++i;
    }
    name[i] = 0;
    if (!name[0] || p[i] != '/') return -1;
    dev = block_find(name);
    if (!dev) return -1;
    rest = p + i + 1;
    out[0] = 0;
    if (block_is_partition(dev)) {
        if (block_partition_parent_name(dev, parent, sizeof(parent)) < 0) return -1;
        if (block_sysfs_append_lit(out, max, &off, "/sys/block/") < 0) return -1;
        if (block_sysfs_append_lit(out, max, &off, parent) < 0) return -1;
        if (block_sysfs_append_char(out, max, &off, '/') < 0) return -1;
        if (block_sysfs_append_lit(out, max, &off, name) < 0) return -1;
    } else {
        if (block_sysfs_append_lit(out, max, &off, "/sys/block/") < 0) return -1;
        if (block_sysfs_append_lit(out, max, &off, name) < 0) return -1;
    }
    if (block_sysfs_append_char(out, max, &off, '/') < 0) return -1;
    if (block_sysfs_append_lit(out, max, &off, rest) < 0) return -1;
    return 0;
}

int block_sysfs_path_kind(const char *path) {
    char disk_name[BLOCK_NAME_MAX];
    const char *rest;
    block_device_t *disk;
    char proxy[96];
    if (!path) return BLOCK_SYSFS_PATH_NONE;
    if (strcmp(path, "/sys/block") == 0 || strcmp(path, "/sys/class/block") == 0) {
        return BLOCK_SYSFS_PATH_DIR;
    }
    if (strncmp(path, "/sys/class/block/", 17) == 0) {
        const char *name = path + 17;
        if (*name && !block_strchr_local(name, '/') && block_find(name)) return BLOCK_SYSFS_PATH_LINK;
        if (block_sysfs_class_proxy_path(path, proxy, sizeof(proxy)) == 0) {
            return block_sysfs_path_kind(proxy);
        }
        return BLOCK_SYSFS_PATH_NONE;
    }
    if (block_sysfs_split_block_path(path, disk_name, sizeof(disk_name), &rest) < 0) {
        return BLOCK_SYSFS_PATH_NONE;
    }
    disk = block_find(disk_name);
    if (!disk || block_is_partition(disk)) return BLOCK_SYSFS_PATH_NONE;
    if (*rest == 0) return BLOCK_SYSFS_PATH_DIR;
    if (*rest != '/') return BLOCK_SYSFS_PATH_NONE;
    rest++;
#ifdef CONFIG_LOOP_DEVICE
    if (strcmp(rest, "loop") == 0)
        return edge_loop_sysfs_path_kind(disk_name, "");
    if (strncmp(rest, "loop/", 5) == 0)
        return edge_loop_sysfs_path_kind(disk_name, rest + 5);
#endif
    if (strcmp(rest, "queue") == 0) return BLOCK_SYSFS_PATH_DIR;
    if (strncmp(rest, "queue/", 6) == 0) {
        return block_sysfs_known_queue_file(rest + 6) ? BLOCK_SYSFS_PATH_FILE : BLOCK_SYSFS_PATH_NONE;
    }
    {
        char node[BLOCK_NAME_MAX];
        const char *tail = rest;
        uint32_t i = 0;
        while (tail[i] && tail[i] != '/') {
            if (i + 1u >= sizeof(node)) return BLOCK_SYSFS_PATH_NONE;
            node[i] = tail[i];
            ++i;
        }
        node[i] = 0;
        if (block_find(node) && block_is_partition(block_find(node))) {
            char parent[BLOCK_NAME_MAX];
            block_device_t *part = block_find(node);
            if (block_partition_parent_name(part, parent, sizeof(parent)) == 0 &&
                strcmp(parent, disk_name) == 0) {
                int is_link = 0;
                if (tail[i] == 0) return BLOCK_SYSFS_PATH_DIR;
                if (tail[i] == '/' && block_sysfs_known_part_file(tail + i + 1, &is_link)) {
                    return is_link ? BLOCK_SYSFS_PATH_LINK : BLOCK_SYSFS_PATH_FILE;
                }
            }
        }
    }
    {
        int is_link = 0;
        if (block_sysfs_known_disk_file(rest, &is_link)) {
            return is_link ? BLOCK_SYSFS_PATH_LINK : BLOCK_SYSFS_PATH_FILE;
        }
    }
    return BLOCK_SYSFS_PATH_NONE;
}

static int block_sysfs_format_dev(char *out, uint32_t max, const block_device_t *dev) {
    uint32_t off = 0;
    uint32_t major, minor;
    if (block_linux_major_minor(dev, &major, &minor) < 0) return -1;
    if (block_sysfs_append_u64(out, max, &off, major) < 0) return -1;
    if (block_sysfs_append_char(out, max, &off, ':') < 0) return -1;
    if (block_sysfs_append_u64(out, max, &off, minor) < 0) return -1;
    if (block_sysfs_append_char(out, max, &off, '\n') < 0) return -1;
    return (int)off;
}

static uint64_t block_linux_size512(const block_device_t *dev) {
    if (!dev || dev->sector_size == 0) return 0;
    return ((uint64_t)dev->sector_count * (uint64_t)dev->sector_size) / 512ull;
}

static int block_sysfs_format_size(char *out, uint32_t max, const block_device_t *dev) {
    uint32_t off = 0;
    if (block_sysfs_append_u64(out, max, &off, block_linux_size512(dev)) < 0) return -1;
    if (block_sysfs_append_char(out, max, &off, '\n') < 0) return -1;
    return (int)off;
}

static int block_sysfs_format_uevent(char *out, uint32_t max, const block_device_t *dev) {
    uint32_t off = 0;
    uint32_t major, minor;
    if (block_linux_major_minor(dev, &major, &minor) < 0) return -1;
    if (block_sysfs_append_lit(out, max, &off, "MAJOR=") < 0) return -1;
    if (block_sysfs_append_u64(out, max, &off, major) < 0) return -1;
    if (block_sysfs_append_lit(out, max, &off, "\nMINOR=") < 0) return -1;
    if (block_sysfs_append_u64(out, max, &off, minor) < 0) return -1;
    if (block_sysfs_append_lit(out, max, &off, "\nDEVNAME=") < 0) return -1;
    if (block_sysfs_append_lit(out, max, &off, dev->name) < 0) return -1;
    if (block_sysfs_append_lit(out, max, &off, "\nDEVTYPE=") < 0) return -1;
    if (block_sysfs_append_lit(out, max, &off, block_is_partition(dev) ? "partition\n" : "disk\n") < 0) return -1;
    if (block_is_partition(dev)) {
        if (block_sysfs_append_lit(out, max, &off, "PARTN=") < 0) return -1;
        if (block_sysfs_append_u64(out, max, &off, (uint32_t)block_partition_number(dev)) < 0) return -1;
        if (block_sysfs_append_char(out, max, &off, '\n') < 0) return -1;
    }
    return (int)off;
}

int block_sysfs_read_file(const char *path, char *out, uint32_t max) {
    char disk_name[BLOCK_NAME_MAX];
    char proxy[96];
    const char *rest;
    block_device_t *disk;
    block_device_t *dev = 0;
    const char *file = 0;
    if (!path || !out || max == 0) return -1;
    if (block_sysfs_class_proxy_path(path, proxy, sizeof(proxy)) == 0) {
        return block_sysfs_read_file(proxy, out, max);
    }
    if (block_sysfs_split_block_path(path, disk_name, sizeof(disk_name), &rest) < 0) return -1;
    disk = block_find(disk_name);
    if (!disk || block_is_partition(disk) || *rest != '/') return -1;
    rest++;
#ifdef CONFIG_LOOP_DEVICE
    if (strncmp(rest, "loop/", 5) == 0)
        return edge_loop_sysfs_read_file(
            disk_name, rest + 5, out, max);
#endif
    if (strncmp(rest, "queue/", 6) == 0) {
        file = rest + 6;
        if (strcmp(file, "logical_block_size") == 0 ||
            strcmp(file, "physical_block_size") == 0 ||
            strcmp(file, "hw_sector_size") == 0 ||
            strcmp(file, "minimum_io_size") == 0 ||
            strcmp(file, "optimal_io_size") == 0) {
            uint32_t off = 0;
            if (block_sysfs_append_u64(out, max, &off, disk->sector_size ? disk->sector_size : 512u) < 0) return -1;
            if (block_sysfs_append_char(out, max, &off, '\n') < 0) return -1;
            return (int)off;
        }
        if (strcmp(file, "rotational") == 0) return block_sysfs_copy_string(out, max, "0\n");
        if (strcmp(file, "read_ahead_kb") == 0) return block_sysfs_copy_string(out, max, "128\n");
        if (strcmp(file, "max_sectors_kb") == 0 || strcmp(file, "max_hw_sectors_kb") == 0) {
            uint32_t off = 0;
            uint64_t kilobytes =
                (uint64_t)block_max_transfer_sectors(disk) *
                (disk->sector_size ? disk->sector_size : 512u) / 1024u;
            if (!kilobytes) kilobytes = 1;
            if (block_sysfs_append_u64(out, max, &off, kilobytes) < 0)
                return -1;
            if (block_sysfs_append_char(out, max, &off, '\n') < 0)
                return -1;
            return (int)off;
        }
        if (strcmp(file, "scheduler") == 0) return block_sysfs_copy_string(out, max, "[none]\n");
        if (strcmp(file, "write_cache") == 0) return block_sysfs_copy_string(out, max, "write through\n");
        return -1;
    }
    {
        char node[BLOCK_NAME_MAX];
        const char *tail = rest;
        uint32_t i = 0;
        while (tail[i] && tail[i] != '/') {
            if (i + 1u >= sizeof(node)) return -1;
            node[i] = tail[i];
            ++i;
        }
        node[i] = 0;
        if (tail[i] == '/' && (dev = block_find(node)) != 0 && block_is_partition(dev)) {
            char parent[BLOCK_NAME_MAX];
            if (block_partition_parent_name(dev, parent, sizeof(parent)) < 0 ||
                strcmp(parent, disk_name) != 0) return -1;
            file = tail + i + 1;
        } else {
            dev = disk;
            file = rest;
        }
    }
    if (strcmp(file, "dev") == 0) return block_sysfs_format_dev(out, max, dev);
    if (strcmp(file, "size") == 0) return block_sysfs_format_size(out, max, dev);
    if (strcmp(file, "uevent") == 0) return block_sysfs_format_uevent(out, max, dev);
    if (strcmp(file, "ro") == 0)
        return block_sysfs_copy_string(
            out, max, dev->ops.write_sectors ? "0\n" : "1\n");
    if (strcmp(file, "removable") == 0 ||
        strcmp(file, "alignment_offset") == 0 || strcmp(file, "discard_alignment") == 0 ||
        strcmp(file, "capability") == 0) {
        return block_sysfs_copy_string(out, max, "0\n");
    }
    if (strcmp(file, "range") == 0) return block_sysfs_copy_string(out, max, "16\n");
    if (strcmp(file, "stat") == 0) return block_sysfs_copy_string(out, max, "0 0 0 0 0 0 0 0 0 0 0\n");
    if (block_is_partition(dev) && strcmp(file, "start") == 0) {
        uint32_t off = 0;
        if (block_sysfs_append_u64(out, max, &off, dev->start_lba) < 0) return -1;
        if (block_sysfs_append_char(out, max, &off, '\n') < 0) return -1;
        return (int)off;
    }
    if (block_is_partition(dev) && strcmp(file, "partition") == 0) {
        uint32_t off = 0;
        if (block_sysfs_append_u64(out, max, &off, (uint32_t)block_partition_number(dev)) < 0) return -1;
        if (block_sysfs_append_char(out, max, &off, '\n') < 0) return -1;
        return (int)off;
    }
    return -1;
}

int block_sysfs_readlink(const char *path, char *out, uint32_t max) {
    char target[64];
    char proxy[96];
    uint32_t off = 0;
    if (!path || !out || max == 0) return -1;
    target[0] = 0;
    if (strncmp(path, "/sys/class/block/", 17) == 0) {
        const char *name = path + 17;
        if (!block_find(name) || block_strchr_local(name, '/')) return -1;
        if (block_sysfs_append_lit(target, sizeof(target), &off, "../../block/") < 0) return -1;
        if (block_sysfs_append_lit(target, sizeof(target), &off, name) < 0) return -1;
    } else if (block_sysfs_class_proxy_path(path, proxy, sizeof(proxy)) == 0) {
        return block_sysfs_readlink(proxy, out, max);
    } else if (strncmp(path, "/sys/block/", 11) == 0) {
        if (strstr(path, "/subsystem") == path + strlen(path) - 10) {
            int slash_count = 0;
            for (const char *p = path + 11; *p; ++p) {
                if (*p == '/') slash_count++;
            }
            if (block_sysfs_append_lit(target, sizeof(target), &off,
                                       slash_count > 1 ? "../../../class/block" : "../../class/block") < 0) {
                return -1;
            }
        }
    }
    if (!target[0]) return -1;
    return block_sysfs_copy_string(out, max, target);
}
