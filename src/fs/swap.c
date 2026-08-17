/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux-compatible swap-area storage and accounting.
 */

#include "fs/swap.h"
#include "block/block.h"
#include "fs/cgroupfs.h"
#include "mm/arch_vm.h"
#include "mm/swap_map.h"
#include "mm/statistics.h"
#include "stdio.h"
#include "string.h"
#include "sys/spinlock.h"
#include "vfs/vfs.h"

#ifdef CONFIG_FS_SWAP

#define EDGE_SWAP_MAX_AREAS 8u
#define EDGE_SWAP_PAGE_SIZE 4096u
#define EDGE_SWAP_SIG_OFF 4086u
#define EDGE_SWAP_SIG_LEN 10u
#define EDGE_SWAP_MAX_PAGES_PER_AREA 262144u
#define EDGE_SWAP_ENTRY_VALID (1ull << 63)
#define EDGE_SWAP_ENTRY_AREA_SHIFT 56u
#define EDGE_SWAP_ENTRY_GENERATION_SHIFT 40u
#define EDGE_SWAP_ENTRY_AREA_MASK 0x7fu
#define EDGE_SWAP_ENTRY_GENERATION_MASK 0xffffu
#define EDGE_SWAP_ENTRY_SLOT_MASK 0xffffffffu

#define EDGE_EPERM 1
#define EDGE_ENOENT 2
#define EDGE_EIO 5
#define EDGE_ENOMEM 12
#define EDGE_EBUSY 16
#define EDGE_EINVAL 22
#define EDGE_ENOSYS 38

#define EDGE_SWAP_FLAG_PREFER 0x8000u
#define EDGE_SWAP_FLAG_PRIO_MASK 0x7fffu
#define EDGE_SWAP_FLAG_DISCARD 0x10000u
#define EDGE_SWAP_FLAG_DISCARD_ONCE 0x20000u
#define EDGE_SWAP_FLAG_DISCARD_PAGES 0x40000u
#define EDGE_SWAP_FLAGS_VALID (EDGE_SWAP_FLAG_PREFER | EDGE_SWAP_FLAG_PRIO_MASK | \
                               EDGE_SWAP_FLAG_DISCARD | EDGE_SWAP_FLAG_DISCARD_ONCE | \
                               EDGE_SWAP_FLAG_DISCARD_PAGES)

typedef struct {
    uint16_t generation;
    uint16_t references;
    uint16_t cgroup;
    uint16_t padding;
} edge_swap_slot_t;

typedef struct {
    uint8_t active;
    uint8_t is_block;
    uint8_t draining;
    uint8_t padding;
    int priority;
    char path[VFS_PATH_MAX];
    uint64_t size_bytes;
    uint64_t used_bytes;
    uint32_t page_count;
    uint32_t used_pages;
    uint32_t allocation_hint;
    uint32_t metadata_pages;
    void *metadata;
    uint64_t *bitmap;
    edge_swap_slot_t *slots;
    block_device_t *block_device;
    vfs_superblock_t *superblock;
    vfs_inode_t inode;
} edge_swap_area_t;

static edge_swap_area_t g_swap_areas[EDGE_SWAP_MAX_AREAS];
static spinlock_t g_swap_lock;
static uint8_t g_swap_pager_ready;
static edge_swap_restore_mapping_fn g_swap_restore_mapping;

static void swap_metadata_release(void *metadata, uint32_t page_count) {
    uint8_t *cursor = (uint8_t *)metadata;

    if (!cursor) return;
    for (uint32_t page = 0; page < page_count; ++page)
        arch_vm_free_page(cursor + (uint64_t)page * EDGE_SWAP_PAGE_SIZE);
}

static int swap_metadata_allocate(uint32_t slot_count,
                                  void **metadata_out,
                                  uint32_t *page_count_out,
                                  uint64_t **bitmap_out,
                                  edge_swap_slot_t **slots_out) {
    uint64_t bitmap_words;
    uint64_t bitmap_bytes;
    uint64_t slots_offset;
    uint64_t metadata_bytes;
    uint64_t metadata_pages;
    uint8_t *metadata;

    if (!slot_count || !metadata_out || !page_count_out || !bitmap_out ||
        !slots_out)
        return -EDGE_EINVAL;
    bitmap_words = ((uint64_t)slot_count + 63u) / 64u;
    bitmap_bytes = bitmap_words * sizeof(uint64_t);
    slots_offset = (bitmap_bytes + 7u) & ~7ull;
    metadata_bytes = slots_offset +
                     (uint64_t)slot_count * sizeof(edge_swap_slot_t);
    if (metadata_bytes < slots_offset) return -EDGE_ENOMEM;
    metadata_pages = (metadata_bytes + EDGE_SWAP_PAGE_SIZE - 1u) /
                     EDGE_SWAP_PAGE_SIZE;
    if (!metadata_pages || metadata_pages > UINT32_MAX)
        return -EDGE_ENOMEM;
    metadata = (uint8_t *)arch_vm_alloc_pages(metadata_pages);
    if (!metadata) return -EDGE_ENOMEM;
    memset(metadata, 0, metadata_pages * EDGE_SWAP_PAGE_SIZE);
    *metadata_out = metadata;
    *page_count_out = (uint32_t)metadata_pages;
    *bitmap_out = (uint64_t *)metadata;
    *slots_out = (edge_swap_slot_t *)(metadata + slots_offset);
    return 0;
}

static int swap_append(char *buf, uint32_t max, uint32_t *off, const char *s) {
    uint32_t n;
    if (!buf || !off || !s) return -1;
    n = (uint32_t)strlen(s);
    if (*off + n + 1u > max) return -1;
    memcpy(buf + *off, s, n);
    *off += n;
    buf[*off] = 0;
    return 0;
}

static int swap_append_u64(char *buf, uint32_t max, uint32_t *off, uint64_t v) {
    char tmp[32];
    uint32_t n = 0;
    if (v == 0) tmp[n++] = '0';
    else {
        char rev[32];
        uint32_t r = 0;
        while (v && r < sizeof(rev)) {
            rev[r++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        while (r) tmp[n++] = rev[--r];
    }
    tmp[n] = 0;
    return swap_append(buf, max, off, tmp);
}

static int swap_append_i32(char *buf, uint32_t max, uint32_t *off, int v) {
    if (v < 0) {
        if (swap_append(buf, max, off, "-") < 0) return -1;
        return swap_append_u64(buf, max, off, (uint64_t)(-v));
    }
    return swap_append_u64(buf, max, off, (uint64_t)v);
}

static int swap_signature_valid(const uint8_t *page) {
    if (!page) return 0;
    if (memcmp(page + EDGE_SWAP_SIG_OFF, "SWAPSPACE2", EDGE_SWAP_SIG_LEN) == 0) return 1;
    if (memcmp(page + EDGE_SWAP_SIG_OFF, "SWAP-SPACE", EDGE_SWAP_SIG_LEN) == 0) return 1;
    return 0;
}

static int swap_read_header_from_block(block_device_t *bdev, uint8_t *page) {
    uint32_t sectors;
    if (!bdev || !page || bdev->sector_size == 0 || bdev->sector_size > EDGE_SWAP_PAGE_SIZE) return -EDGE_EINVAL;
    if ((EDGE_SWAP_PAGE_SIZE % bdev->sector_size) != 0) return -EDGE_EINVAL;
    sectors = EDGE_SWAP_PAGE_SIZE / bdev->sector_size;
    if (bdev->sector_count < sectors) return -EDGE_EINVAL;
    if (block_read_sectors(bdev, 0, sectors, page) < 0) return -EDGE_EIO;
    return 0;
}

static int swap_read_header_from_file(vfs_superblock_t *sb, vfs_inode_t *ino, uint8_t *page) {
    if (!sb || !ino || !page || !sb->ops || !sb->ops->read) return -EDGE_EINVAL;
    if (ino->size < EDGE_SWAP_PAGE_SIZE) return -EDGE_EINVAL;
    if (sb->ops->read(sb, ino, 0, page, EDGE_SWAP_PAGE_SIZE) != (int)EDGE_SWAP_PAGE_SIZE) return -EDGE_EIO;
    return 0;
}

static int swap_find_path_locked(const char *path) {
    if (!path) return -1;
    for (uint32_t i = 0; i < EDGE_SWAP_MAX_AREAS; ++i) {
        if (g_swap_areas[i].active && strcmp(g_swap_areas[i].path, path) == 0) return (int)i;
    }
    return -1;
}

static int swap_slot_used(uint32_t area, uint32_t slot) {
    return (g_swap_areas[area].bitmap[slot / 64u] &
            (1ull << (slot % 64u))) != 0;
}

static void swap_slot_set(uint32_t area, uint32_t slot) {
    g_swap_areas[area].bitmap[slot / 64u] |= 1ull << (slot % 64u);
}

static void swap_slot_clear(uint32_t area, uint32_t slot) {
    g_swap_areas[area].bitmap[slot / 64u] &= ~(1ull << (slot % 64u));
}

static uint64_t swap_entry_encode(uint32_t area, uint32_t slot,
                                  uint16_t generation) {
    return EDGE_SWAP_ENTRY_VALID |
           ((uint64_t)area << EDGE_SWAP_ENTRY_AREA_SHIFT) |
           ((uint64_t)generation << EDGE_SWAP_ENTRY_GENERATION_SHIFT) |
           (uint64_t)(slot + 1u);
}

static int swap_entry_decode(uint64_t entry, uint32_t *area_out,
                             uint32_t *slot_out,
                             uint16_t *generation_out) {
    uint32_t area;
    uint32_t encoded_slot;

    if ((entry & EDGE_SWAP_ENTRY_VALID) == 0) return -1;
    area = (uint32_t)((entry >> EDGE_SWAP_ENTRY_AREA_SHIFT) &
                      EDGE_SWAP_ENTRY_AREA_MASK);
    encoded_slot = (uint32_t)(entry & EDGE_SWAP_ENTRY_SLOT_MASK);
    if (area >= EDGE_SWAP_MAX_AREAS || !encoded_slot) return -1;
    if (area_out) *area_out = area;
    if (slot_out) *slot_out = encoded_slot - 1u;
    if (generation_out)
        *generation_out = (uint16_t)(
            (entry >> EDGE_SWAP_ENTRY_GENERATION_SHIFT) &
            EDGE_SWAP_ENTRY_GENERATION_MASK);
    return 0;
}

static int swap_area_write_page(edge_swap_area_t *area,
                                uint32_t slot, const void *page) {
    uint64_t offset = ((uint64_t)slot + 1u) * EDGE_SWAP_PAGE_SIZE;

    if (!area || !page) return -EDGE_EINVAL;
    if (area->is_block)
        return block_write_bytes(area->block_device, offset, page,
                                 EDGE_SWAP_PAGE_SIZE) ==
                       (int64_t)EDGE_SWAP_PAGE_SIZE ? 0 : -EDGE_EIO;
    if (!area->superblock || !area->superblock->ops ||
        !area->superblock->ops->write)
        return -EDGE_EIO;
    return area->superblock->ops->write(
               area->superblock, &area->inode, offset,
               page, EDGE_SWAP_PAGE_SIZE) == (int)EDGE_SWAP_PAGE_SIZE ?
           0 : -EDGE_EIO;
}

static int swap_area_read_page(edge_swap_area_t *area,
                               uint32_t slot, void *page) {
    uint64_t offset = ((uint64_t)slot + 1u) * EDGE_SWAP_PAGE_SIZE;

    if (!area || !page) return -EDGE_EINVAL;
    if (area->is_block)
        return block_read_bytes(area->block_device, offset, page,
                                EDGE_SWAP_PAGE_SIZE) ==
                       (int64_t)EDGE_SWAP_PAGE_SIZE ? 0 : -EDGE_EIO;
    if (!area->superblock || !area->superblock->ops ||
        !area->superblock->ops->read)
        return -EDGE_EIO;
    return area->superblock->ops->read(
               area->superblock, &area->inode, offset,
               page, EDGE_SWAP_PAGE_SIZE) == (int)EDGE_SWAP_PAGE_SIZE ?
           0 : -EDGE_EIO;
}

void swap_register_pager(edge_swap_restore_mapping_fn restore_mapping) {
    uint64_t irq_flags = spin_lock_irqsave(&g_swap_lock);
    g_swap_restore_mapping = restore_mapping;
    g_swap_pager_ready = restore_mapping ? 1u : 0u;
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
}

int swap_enable_path(const char *path, uint32_t flags) {
#ifdef CONFIG_FS_SWAP
    vfs_inode_t ino;
    vfs_superblock_t *sb = 0;
    block_device_t *bdev = 0;
    uint8_t *header_page = 0;
    uint64_t size_bytes = 0;
    uint8_t is_block = 0;
    uint64_t irq_flags;
    uint64_t usable_pages;
    uint32_t page_count;
    void *metadata = 0;
    uint32_t metadata_pages = 0;
    uint64_t *bitmap = 0;
    edge_swap_slot_t *slots = 0;
    int area_slot = -1;

    if (!path || !path[0]) return -EDGE_EINVAL;
    if ((flags & ~EDGE_SWAP_FLAGS_VALID) != 0) return -EDGE_EINVAL;
    irq_flags = spin_lock_irqsave(&g_swap_lock);
    if (!g_swap_pager_ready) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_ENOSYS;
    }
    if (swap_find_path_locked(path) >= 0) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_EBUSY;
    }
    for (uint32_t index = 0; index < EDGE_SWAP_MAX_AREAS; ++index) {
        if (!g_swap_areas[index].active) {
            area_slot = (int)index;
            break;
        }
    }
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    if (area_slot < 0) return -EDGE_ENOMEM;

    if (vfs_resolve(path, &ino, &sb, 0, 0) < 0) return -EDGE_ENOENT;
    header_page = (uint8_t *)arch_vm_alloc_page();
    if (!header_page) return -EDGE_ENOMEM;
    memset(header_page, 0, EDGE_SWAP_PAGE_SIZE);
    if (vfs_inode_get_block_device(&ino, &bdev) == 0 && bdev) {
        int rc = swap_read_header_from_block(bdev, header_page);
        if (rc < 0) {
            arch_vm_free_page(header_page);
            return rc;
        }
        size_bytes = (uint64_t)bdev->sector_size * (uint64_t)bdev->sector_count;
        is_block = 1;
    } else if ((ino.mode & 0xF000u) == VFS_INODE_FILE) {
        int rc = swap_read_header_from_file(sb, &ino, header_page);
        if (rc < 0) {
            arch_vm_free_page(header_page);
            return rc;
        }
        size_bytes = ino.size;
        is_block = 0;
    } else {
        arch_vm_free_page(header_page);
        return -EDGE_EINVAL;
    }

    if (!swap_signature_valid(header_page)) {
        arch_vm_free_page(header_page);
        return -EDGE_EINVAL;
    }
    arch_vm_free_page(header_page);
    if (size_bytes <= EDGE_SWAP_PAGE_SIZE) return -EDGE_EINVAL;
    usable_pages = size_bytes / EDGE_SWAP_PAGE_SIZE - 1u;
    page_count = usable_pages > EDGE_SWAP_MAX_PAGES_PER_AREA ?
                 EDGE_SWAP_MAX_PAGES_PER_AREA : (uint32_t)usable_pages;
    if (!page_count) return -EDGE_EINVAL;
    if (!is_block && vfs_inode_open(sb, &ino) < 0) return -EDGE_EBUSY;
    if (swap_metadata_allocate(page_count, &metadata, &metadata_pages,
                               &bitmap, &slots) < 0) {
        if (!is_block) vfs_inode_close(sb, &ino);
        return -EDGE_ENOMEM;
    }

    irq_flags = spin_lock_irqsave(&g_swap_lock);
    if (g_swap_areas[area_slot].active ||
        swap_find_path_locked(path) >= 0) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        if (!is_block) vfs_inode_close(sb, &ino);
        swap_metadata_release(metadata, metadata_pages);
        return -EDGE_EBUSY;
    }
    memset(&g_swap_areas[area_slot], 0,
           sizeof(g_swap_areas[area_slot]));
    g_swap_areas[area_slot].active = 1u;
    g_swap_areas[area_slot].is_block = is_block;
    g_swap_areas[area_slot].priority =
        (flags & EDGE_SWAP_FLAG_PREFER) ?
        (int)(flags & EDGE_SWAP_FLAG_PRIO_MASK) : -(area_slot + 1);
    g_swap_areas[area_slot].page_count = page_count;
    g_swap_areas[area_slot].size_bytes =
        (uint64_t)page_count * EDGE_SWAP_PAGE_SIZE;
    g_swap_areas[area_slot].metadata = metadata;
    g_swap_areas[area_slot].metadata_pages = metadata_pages;
    g_swap_areas[area_slot].bitmap = bitmap;
    g_swap_areas[area_slot].slots = slots;
    g_swap_areas[area_slot].block_device = bdev;
    g_swap_areas[area_slot].superblock =
        is_block ? 0 : vfs_superblock_stable(sb);
    g_swap_areas[area_slot].inode = ino;
    for (uint32_t index = 0;
         index + 1u < sizeof(g_swap_areas[area_slot].path) && path[index];
         ++index)
        g_swap_areas[area_slot].path[index] = path[index];
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    printf("[swap] enabled %s pages=%u priority=%d\n",
           path, page_count, g_swap_areas[area_slot].priority);
    return 0;
#else
    (void)path;
    (void)flags;
    return -EDGE_EINVAL;
#endif
}

int swap_disable_path(const char *path) {
#ifdef CONFIG_FS_SWAP
    void *metadata;
    uint32_t metadata_pages;
    vfs_superblock_t *close_superblock;
    vfs_inode_t *close_inode;
    uint64_t irq_flags;
    int slot;

    irq_flags = spin_lock_irqsave(&g_swap_lock);
    slot = swap_find_path_locked(path);
    if (slot < 0) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_EINVAL;
    }
    if (g_swap_areas[slot].draining) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_EBUSY;
    }
    g_swap_areas[slot].draining = 1u;
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);

    for (;;) {
        uint64_t swap_entry = 0;
        uint64_t address_space = 0;
        uint64_t address = 0;

        irq_flags = spin_lock_irqsave(&g_swap_lock);
        if (!g_swap_areas[slot].active) {
            spin_unlock_irqrestore(&g_swap_lock, irq_flags);
            return -EDGE_EINVAL;
        }
        for (uint32_t page = 0;
             page < g_swap_areas[slot].page_count; ++page) {
            if (!swap_slot_used((uint32_t)slot, page)) continue;
            swap_entry = swap_entry_encode(
                (uint32_t)slot, page,
                g_swap_areas[slot].slots[page].generation);
            break;
        }
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        if (!swap_entry) break;
        if (!g_swap_restore_mapping ||
            edge_swap_map_find_entry(
                swap_entry, &address_space, &address) < 0 ||
            g_swap_restore_mapping(
                address_space, address, swap_entry) < 0) {
            if (address_space) swap_release_entry(swap_entry);
            irq_flags = spin_lock_irqsave(&g_swap_lock);
            if (g_swap_areas[slot].active)
                g_swap_areas[slot].draining = 0u;
            spin_unlock_irqrestore(&g_swap_lock, irq_flags);
            return -EDGE_ENOMEM;
        }
        swap_release_entry(swap_entry);
    }

    irq_flags = spin_lock_irqsave(&g_swap_lock);
    if (g_swap_areas[slot].used_pages) {
        g_swap_areas[slot].draining = 0u;
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_EBUSY;
    }
    close_superblock = !g_swap_areas[slot].is_block ?
        g_swap_areas[slot].superblock : 0;
    close_inode = close_superblock ? &g_swap_areas[slot].inode : 0;
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    if (close_superblock)
        vfs_inode_close(close_superblock, close_inode);

    irq_flags = spin_lock_irqsave(&g_swap_lock);
    metadata = g_swap_areas[slot].metadata;
    metadata_pages = g_swap_areas[slot].metadata_pages;
    printf("[swap] disabled %s\n", g_swap_areas[slot].path);
    memset(&g_swap_areas[slot], 0, sizeof(g_swap_areas[slot]));
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    swap_metadata_release(metadata, metadata_pages);
    return 0;
#else
    (void)path;
    return -EDGE_EINVAL;
#endif
}

int swap_store_page(uint32_t cgroup_id, const void *page,
                    uint64_t *entry_out) {
    edge_swap_area_t *selected;
    uint64_t irq_flags;
    uint64_t entry;
    int selected_area = -1;
    int selected_priority = (-2147483647 - 1);
    uint32_t selected_slot = 0;
    uint16_t generation;
    uint16_t encoded_cgroup;

    if (!page || !entry_out || cgroup_id >= UINT16_MAX)
        return -EDGE_EINVAL;
    *entry_out = 0;
    irq_flags = spin_lock_irqsave(&g_swap_lock);
    for (uint32_t area = 0; area < EDGE_SWAP_MAX_AREAS; ++area) {
        edge_swap_area_t *candidate = &g_swap_areas[area];
        if (!candidate->active ||
            candidate->draining ||
            candidate->used_pages >= candidate->page_count ||
            candidate->priority < selected_priority)
            continue;
        selected_area = (int)area;
        selected_priority = candidate->priority;
    }
    if (selected_area < 0) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_ENOMEM;
    }
    {
        edge_swap_area_t *area = &g_swap_areas[selected_area];
        uint32_t slot = area->allocation_hint;
        for (uint32_t scanned = 0; scanned < area->page_count; ++scanned) {
            if (slot == area->page_count) slot = 0;
            if (!swap_slot_used((uint32_t)selected_area, slot)) {
                selected_slot = slot;
                break;
            }
            ++slot;
        }
        swap_slot_set((uint32_t)selected_area, selected_slot);
        area->allocation_hint = selected_slot + 1u;
        if (area->allocation_hint == area->page_count)
            area->allocation_hint = 0;
        ++area->used_pages;
        area->used_bytes += EDGE_SWAP_PAGE_SIZE;
        generation = ++area->slots[selected_slot].generation;
        if (!generation)
            generation = ++area->slots[selected_slot].generation;
        area->slots[selected_slot].references = 1u;
        encoded_cgroup = (uint16_t)(cgroup_id + 1u);
        area->slots[selected_slot].cgroup = encoded_cgroup;
        selected = area;
    }
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);

    if (cgroupfs_memory_swap_charge(cgroup_id, EDGE_SWAP_PAGE_SIZE) < 0) {
        irq_flags = spin_lock_irqsave(&g_swap_lock);
        swap_slot_clear((uint32_t)selected_area, selected_slot);
        --g_swap_areas[selected_area].used_pages;
        g_swap_areas[selected_area].used_bytes -= EDGE_SWAP_PAGE_SIZE;
        g_swap_areas[selected_area].slots[selected_slot].references = 0;
        g_swap_areas[selected_area].slots[selected_slot].cgroup = 0;
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_ENOMEM;
    }
    if (swap_area_write_page(selected, selected_slot, page) < 0) {
        cgroupfs_memory_swap_uncharge(cgroup_id, EDGE_SWAP_PAGE_SIZE);
        irq_flags = spin_lock_irqsave(&g_swap_lock);
        swap_slot_clear((uint32_t)selected_area, selected_slot);
        --g_swap_areas[selected_area].used_pages;
        g_swap_areas[selected_area].used_bytes -= EDGE_SWAP_PAGE_SIZE;
        g_swap_areas[selected_area].slots[selected_slot].references = 0;
        g_swap_areas[selected_area].slots[selected_slot].cgroup = 0;
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_EIO;
    }
    entry = swap_entry_encode(
        (uint32_t)selected_area, selected_slot, generation);
    edge_mm_statistics_note_swap_out(1u);
    *entry_out = entry;
    return 0;
}

int swap_load_page(uint64_t entry, void *page, uint32_t *cgroup_id_out) {
    edge_swap_area_t *selected;
    uint64_t irq_flags;
    uint32_t area;
    uint32_t slot;
    uint16_t generation;
    uint16_t encoded_cgroup;

    if (!page || swap_entry_decode(
            entry, &area, &slot, &generation) < 0)
        return -EDGE_EINVAL;
    irq_flags = spin_lock_irqsave(&g_swap_lock);
    if (!g_swap_areas[area].active ||
        slot >= g_swap_areas[area].page_count ||
        !swap_slot_used(area, slot) ||
        g_swap_areas[area].slots[slot].generation != generation ||
        !g_swap_areas[area].slots[slot].references) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_EINVAL;
    }
    selected = &g_swap_areas[area];
    encoded_cgroup = g_swap_areas[area].slots[slot].cgroup;
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    if (swap_area_read_page(selected, slot, page) < 0)
        return -EDGE_EIO;
    if (cgroup_id_out)
        *cgroup_id_out = encoded_cgroup ?
                         (uint32_t)encoded_cgroup - 1u : 0u;
    edge_mm_statistics_note_swap_in(1u);
    return 0;
}

int swap_retain_entry(uint64_t entry) {
    uint64_t irq_flags;
    uint32_t area;
    uint32_t slot;
    uint16_t generation;

    if (swap_entry_decode(entry, &area, &slot, &generation) < 0)
        return -EDGE_EINVAL;
    irq_flags = spin_lock_irqsave(&g_swap_lock);
    if (!g_swap_areas[area].active ||
        slot >= g_swap_areas[area].page_count ||
        !swap_slot_used(area, slot) ||
        g_swap_areas[area].slots[slot].generation != generation ||
        !g_swap_areas[area].slots[slot].references ||
        g_swap_areas[area].slots[slot].references == UINT16_MAX) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return -EDGE_EINVAL;
    }
    ++g_swap_areas[area].slots[slot].references;
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    return 0;
}

uint32_t swap_entry_references(uint64_t entry) {
    uint64_t irq_flags;
    uint32_t area;
    uint32_t slot;
    uint32_t references = 0;
    uint16_t generation;

    if (swap_entry_decode(entry, &area, &slot, &generation) < 0)
        return 0;
    irq_flags = spin_lock_irqsave(&g_swap_lock);
    if (g_swap_areas[area].active &&
        slot < g_swap_areas[area].page_count &&
        swap_slot_used(area, slot) &&
        g_swap_areas[area].slots[slot].generation == generation) {
        references = g_swap_areas[area].slots[slot].references;
    }
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    return references;
}

void swap_release_entry(uint64_t entry) {
    uint64_t irq_flags;
    uint32_t area;
    uint32_t slot;
    uint32_t cgroup_id = 0;
    uint16_t generation;
    uint16_t encoded_cgroup;
    int released = 0;

    if (swap_entry_decode(entry, &area, &slot, &generation) < 0) return;
    irq_flags = spin_lock_irqsave(&g_swap_lock);
    if (!g_swap_areas[area].active ||
        slot >= g_swap_areas[area].page_count ||
        !swap_slot_used(area, slot) ||
        g_swap_areas[area].slots[slot].generation != generation ||
        !g_swap_areas[area].slots[slot].references) {
        spin_unlock_irqrestore(&g_swap_lock, irq_flags);
        return;
    }
    if (--g_swap_areas[area].slots[slot].references == 0) {
        encoded_cgroup = g_swap_areas[area].slots[slot].cgroup;
        g_swap_areas[area].slots[slot].cgroup = 0;
        swap_slot_clear(area, slot);
        --g_swap_areas[area].used_pages;
        g_swap_areas[area].used_bytes -= EDGE_SWAP_PAGE_SIZE;
        if (slot < g_swap_areas[area].allocation_hint)
            g_swap_areas[area].allocation_hint = slot;
        cgroup_id = encoded_cgroup ?
                    (uint32_t)encoded_cgroup - 1u : 0u;
        released = 1;
    }
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    if (released)
        cgroupfs_memory_swap_uncharge(cgroup_id, EDGE_SWAP_PAGE_SIZE);
}

uint64_t swap_total_bytes(void) {
    uint64_t total = 0;
    uint64_t irq_flags = spin_lock_irqsave(&g_swap_lock);
    for (uint32_t i = 0; i < EDGE_SWAP_MAX_AREAS; ++i) {
        if (g_swap_areas[i].active) total += g_swap_areas[i].size_bytes;
    }
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    return total;
}

uint64_t swap_free_bytes(void) {
    uint64_t free_bytes = 0;
    uint64_t irq_flags = spin_lock_irqsave(&g_swap_lock);
    for (uint32_t i = 0; i < EDGE_SWAP_MAX_AREAS; ++i) {
        if (!g_swap_areas[i].active) continue;
        if (g_swap_areas[i].used_bytes < g_swap_areas[i].size_bytes) {
            free_bytes += g_swap_areas[i].size_bytes - g_swap_areas[i].used_bytes;
        }
    }
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    return free_bytes;
}

int swap_proc_snapshot(char *buf, uint32_t max) {
    uint32_t off = 0;
    uint64_t irq_flags;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (swap_append(buf, max, &off, "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n") < 0) return -1;
    irq_flags = spin_lock_irqsave(&g_swap_lock);
    for (uint32_t i = 0; i < EDGE_SWAP_MAX_AREAS; ++i) {
        edge_swap_area_t *a = &g_swap_areas[i];
        if (!a->active) continue;
        if (swap_append(buf, max, &off, a->path) < 0 ||
            swap_append(buf, max, &off, "\t\t\t\t") < 0 ||
            swap_append(buf, max, &off,
                        a->is_block ? "partition" : "file") < 0 ||
            swap_append(buf, max, &off, "\t\t") < 0 ||
            swap_append_u64(buf, max, &off,
                            a->size_bytes / 1024ull) < 0 ||
            swap_append(buf, max, &off, "\t\t") < 0 ||
            swap_append_u64(buf, max, &off,
                            a->used_bytes / 1024ull) < 0 ||
            swap_append(buf, max, &off, "\t\t") < 0 ||
            swap_append_i32(buf, max, &off, a->priority) < 0 ||
            swap_append(buf, max, &off, "\n") < 0) {
            spin_unlock_irqrestore(&g_swap_lock, irq_flags);
            return -1;
        }
    }
    spin_unlock_irqrestore(&g_swap_lock, irq_flags);
    return (int)off;
}

#endif
