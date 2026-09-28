/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS architecture-neutral swapped-page map. */

#include <stdint.h>

#include "fs/swap.h"
#include "mm/swap_map.h"
#include "string.h"
#include "sys/spinlock.h"

#define EDGE_SWAP_MAP_PAGE_SIZE 4096u
#define EDGE_SWAP_MAP_MIN_CAPACITY 16384u
#define EDGE_SWAP_MAP_MAX_CAPACITY 524288u

typedef struct {
    uint64_t address_space;
    uint64_t address;
    uint64_t swap_entry;
    int32_t next_hash;
    int32_t next_free;
    int32_t next_used;
    int32_t previous_used;
    uint8_t used;
    uint8_t padding[7];
} edge_swap_map_entry_t;

static edge_swap_map_entry_t *g_swap_map_entries;
static int32_t *g_swap_map_hash;
static uint32_t g_swap_map_hash_mask;
static int32_t g_swap_map_free_head;
static int32_t g_swap_map_used_head;
static uint32_t g_swap_map_free_count;
static uint32_t g_swap_map_count;
static uint8_t g_swap_map_initialized;
static spinlock_t g_swap_map_lock;

static uint32_t swap_map_hash_capacity(uint32_t capacity) {
    uint32_t buckets = 1u;

    if (capacity < 2u) return 0;
    while (buckets < capacity / 2u) {
        if (buckets > UINT32_MAX / 2u) return 0;
        buckets *= 2u;
    }
    return buckets;
}

uint32_t edge_swap_map_capacity_for_memory(uint64_t memory_pages) {
    uint64_t target = memory_pages / 4u;
    uint32_t capacity = EDGE_SWAP_MAP_MIN_CAPACITY;

    if (target < EDGE_SWAP_MAP_MIN_CAPACITY)
        return EDGE_SWAP_MAP_MIN_CAPACITY;
    if (target > EDGE_SWAP_MAP_MAX_CAPACITY)
        target = EDGE_SWAP_MAP_MAX_CAPACITY;
    while (capacity <= EDGE_SWAP_MAP_MAX_CAPACITY / 2u &&
           (uint64_t)capacity * 2u <= target)
        capacity *= 2u;
    return capacity;
}

uint64_t edge_swap_map_pool_bytes(uint32_t capacity) {
    uint32_t hash_capacity = swap_map_hash_capacity(capacity);
    uint64_t entry_bytes;
    uint64_t hash_bytes;

    if (!hash_capacity || capacity > EDGE_SWAP_MAP_MAX_CAPACITY)
        return 0;
    entry_bytes = (uint64_t)capacity * sizeof(edge_swap_map_entry_t);
    hash_bytes = (uint64_t)hash_capacity * sizeof(int32_t);
    if (entry_bytes > UINT64_MAX - hash_bytes) return 0;
    return entry_bytes + hash_bytes;
}

int edge_swap_map_initialize(void *memory, uint64_t memory_bytes,
                             uint32_t capacity) {
    uint32_t hash_capacity = swap_map_hash_capacity(capacity);
    uint64_t required = edge_swap_map_pool_bytes(capacity);
    uint64_t irq_flags;

    if (!memory || !required || memory_bytes < required) return -1;
    irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    if (g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    g_swap_map_entries = (edge_swap_map_entry_t *)memory;
    g_swap_map_hash = (int32_t *)(g_swap_map_entries + capacity);
    g_swap_map_hash_mask = hash_capacity - 1u;
    memset(memory, 0, (uint32_t)required);
    for (uint32_t index = 0; index < hash_capacity; ++index)
        g_swap_map_hash[index] = -1;
    for (uint32_t index = 0; index < capacity; ++index) {
        g_swap_map_entries[index].next_free =
            index + 1u < capacity ? (int32_t)(index + 1u) : -1;
        g_swap_map_entries[index].next_hash = -1;
        g_swap_map_entries[index].next_used = -1;
        g_swap_map_entries[index].previous_used = -1;
    }
    g_swap_map_free_head = 0;
    g_swap_map_used_head = -1;
    g_swap_map_free_count = capacity;
    g_swap_map_count = 0;
    g_swap_map_initialized = 1u;
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    return 0;
}

static uint32_t swap_map_hash(uint64_t address_space, uint64_t address) {
    uint64_t key = (address_space >> 12) ^
                   ((address >> 12) * 0x9e3779b97f4a7c15ULL);
    key ^= key >> 29;
    key *= 0xbf58476d1ce4e5b9ULL;
    key ^= key >> 31;
    return (uint32_t)key & g_swap_map_hash_mask;
}

static int32_t swap_map_find_locked(uint64_t address_space,
                                    uint64_t address) {
    uint32_t bucket = swap_map_hash(address_space, address);
    int32_t current = g_swap_map_hash[bucket];

    while (current >= 0) {
        edge_swap_map_entry_t *entry =
            &g_swap_map_entries[(uint32_t)current];
        if (entry->used && entry->address_space == address_space &&
            entry->address == address)
            return current;
        current = entry->next_hash;
    }
    return -1;
}

static int32_t swap_map_allocate_locked(void) {
    int32_t slot = g_swap_map_free_head;
    if (slot < 0) return -1;
    g_swap_map_free_head = g_swap_map_entries[(uint32_t)slot].next_free;
    --g_swap_map_free_count;
    memset(&g_swap_map_entries[(uint32_t)slot], 0,
           sizeof(g_swap_map_entries[(uint32_t)slot]));
    g_swap_map_entries[(uint32_t)slot].next_hash = -1;
    g_swap_map_entries[(uint32_t)slot].next_free = -1;
    g_swap_map_entries[(uint32_t)slot].next_used = -1;
    g_swap_map_entries[(uint32_t)slot].previous_used = -1;
    return slot;
}

static uint64_t swap_map_remove_locked(uint32_t slot) {
    edge_swap_map_entry_t *entry = &g_swap_map_entries[slot];
    uint32_t bucket;
    int32_t *link;
    uint64_t swap_entry;

    if (!entry->used) return 0;
    bucket = swap_map_hash(entry->address_space, entry->address);
    link = &g_swap_map_hash[bucket];
    while (*link >= 0) {
        if ((uint32_t)*link == slot) {
            *link = entry->next_hash;
            break;
        }
        link = &g_swap_map_entries[(uint32_t)*link].next_hash;
    }
    swap_entry = entry->swap_entry;
    if (entry->previous_used >= 0)
        g_swap_map_entries[(uint32_t)entry->previous_used].next_used =
            entry->next_used;
    else if (g_swap_map_used_head == (int32_t)slot)
        g_swap_map_used_head = entry->next_used;
    if (entry->next_used >= 0)
        g_swap_map_entries[(uint32_t)entry->next_used].previous_used =
            entry->previous_used;
    memset(entry, 0, sizeof(*entry));
    entry->next_hash = -1;
    entry->next_free = g_swap_map_free_head;
    g_swap_map_free_head = (int32_t)slot;
    ++g_swap_map_free_count;
    --g_swap_map_count;
    return swap_entry;
}

int edge_swap_map_insert(uint64_t address_space, uint64_t address,
                         uint64_t swap_entry) {
    uint64_t irq_flags;
    uint32_t bucket;
    int32_t slot;

    if (!address_space || !swap_entry) return -1;
    address &= ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    if (!g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    if (swap_map_find_locked(address_space, address) >= 0) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    slot = swap_map_allocate_locked();
    if (slot < 0) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    bucket = swap_map_hash(address_space, address);
    g_swap_map_entries[(uint32_t)slot].used = 1u;
    g_swap_map_entries[(uint32_t)slot].address_space = address_space;
    g_swap_map_entries[(uint32_t)slot].address = address;
    g_swap_map_entries[(uint32_t)slot].swap_entry = swap_entry;
    g_swap_map_entries[(uint32_t)slot].next_hash = g_swap_map_hash[bucket];
    g_swap_map_entries[(uint32_t)slot].next_used = g_swap_map_used_head;
    if (g_swap_map_used_head >= 0)
        g_swap_map_entries[(uint32_t)g_swap_map_used_head].previous_used =
            slot;
    g_swap_map_used_head = slot;
    g_swap_map_hash[bucket] = slot;
    ++g_swap_map_count;
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    return 0;
}

int edge_swap_map_acquire(uint64_t address_space, uint64_t address,
                          uint64_t *swap_entry_out) {
    uint64_t irq_flags;
    uint64_t swap_entry;
    int32_t slot;

    if (!address_space || !swap_entry_out) return -1;
    address &= ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    if (!g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    slot = swap_map_find_locked(address_space, address);
    if (slot < 0) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    swap_entry = g_swap_map_entries[(uint32_t)slot].swap_entry;
    if (swap_retain_entry(swap_entry) < 0) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    *swap_entry_out = swap_entry;
    return 0;
}

int edge_swap_map_take(uint64_t address_space, uint64_t address,
                       uint64_t *swap_entry_out) {
    uint64_t irq_flags;
    uint64_t swap_entry;
    int32_t slot;

    if (!address_space || !swap_entry_out) return -1;
    address &= ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    if (!g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    slot = swap_map_find_locked(address_space, address);
    if (slot < 0) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    swap_entry = swap_map_remove_locked((uint32_t)slot);
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    *swap_entry_out = swap_entry;
    return 0;
}

uint32_t edge_swap_map_drop_range(uint64_t address_space, uint64_t start,
                                  uint64_t length) {
    uint32_t dropped = 0;
    uint64_t end;

    if (!address_space || !length || length > UINT64_MAX - start) return 0;
    start &= ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    end = start + length;
    if (end > UINT64_MAX - (EDGE_SWAP_MAP_PAGE_SIZE - 1u))
        end = UINT64_MAX;
    else
        end = (end + EDGE_SWAP_MAP_PAGE_SIZE - 1u) &
              ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    {
        uint64_t irq_flags = spin_lock_irqsave(&g_swap_map_lock);
        int32_t current;
        if (!g_swap_map_initialized) {
            spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
            return 0;
        }
        current = g_swap_map_used_head;
        while (current >= 0) {
            uint32_t slot = (uint32_t)current;
            edge_swap_map_entry_t *entry = &g_swap_map_entries[slot];
            uint64_t swap_entry = 0;
            current = entry->next_used;
            if (entry->address_space == address_space &&
                entry->address >= start && entry->address < end)
                swap_entry = swap_map_remove_locked(slot);
            if (swap_entry) {
                swap_release_entry(swap_entry);
                ++dropped;
            }
        }
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    }
    return dropped;
}

int edge_swap_map_move_range(uint64_t address_space, uint64_t source,
                             uint64_t destination, uint64_t length) {
    uint64_t source_end;
    uint64_t destination_end;
    uint64_t irq_flags;

    if (!address_space || source == destination ||
        length > UINT64_MAX - source || length > UINT64_MAX - destination)
        return source == destination && address_space ? 0 : -1;
    if (!length) return 0;
    source &= ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    destination &= ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    if (length > UINT64_MAX - (EDGE_SWAP_MAP_PAGE_SIZE - 1u)) return -1;
    length = (length + EDGE_SWAP_MAP_PAGE_SIZE - 1u) &
             ~(uint64_t)(EDGE_SWAP_MAP_PAGE_SIZE - 1u);
    source_end = source + length;
    destination_end = destination + length;
    if (source_end < source || destination_end < destination ||
        (destination < source_end && source < destination_end))
        return -1;

    irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    if (!g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    for (int32_t current = g_swap_map_used_head; current >= 0;) {
        edge_swap_map_entry_t *entry =
            &g_swap_map_entries[(uint32_t)current];
        current = entry->next_used;
        if (entry->address_space == address_space &&
            entry->address >= destination &&
            entry->address < destination_end) {
            spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
            return -1;
        }
    }
    for (int32_t current = g_swap_map_used_head; current >= 0;) {
        edge_swap_map_entry_t *entry =
            &g_swap_map_entries[(uint32_t)current];
        uint32_t old_bucket;
        int32_t *link;
        current = entry->next_used;
        if (entry->address_space != address_space ||
            entry->address < source || entry->address >= source_end)
            continue;
        old_bucket = swap_map_hash(entry->address_space, entry->address);
        link = &g_swap_map_hash[old_bucket];
        while (*link >= 0 &&
               &g_swap_map_entries[(uint32_t)*link] != entry)
            link = &g_swap_map_entries[(uint32_t)*link].next_hash;
        if (*link < 0) {
            spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
            return -1;
        }
        *link = entry->next_hash;
        entry->address = destination + (entry->address - source);
        {
            uint32_t new_bucket =
                swap_map_hash(entry->address_space, entry->address);
            entry->next_hash = g_swap_map_hash[new_bucket];
            g_swap_map_hash[new_bucket] =
                (int32_t)(entry - g_swap_map_entries);
        }
    }
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    return 0;
}

int edge_swap_map_find_entry(uint64_t swap_entry,
                             uint64_t *address_space_out,
                             uint64_t *address_out) {
    uint64_t irq_flags;

    if (!swap_entry || !address_space_out || !address_out) return -1;
    irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    if (!g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    for (int32_t current = g_swap_map_used_head; current >= 0;) {
        edge_swap_map_entry_t *entry =
            &g_swap_map_entries[(uint32_t)current];
        current = entry->next_used;
        if (entry->swap_entry != swap_entry) continue;
        if (swap_retain_entry(swap_entry) < 0) {
            spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
            return -1;
        }
        *address_space_out = entry->address_space;
        *address_out = entry->address;
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return 0;
    }
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    return -1;
}

int edge_swap_map_clone_space(uint64_t source_address_space,
                              uint64_t destination_address_space) {
    uint64_t irq_flags;
    uint32_t required = 0;

    if (!source_address_space || !destination_address_space ||
        source_address_space == destination_address_space)
        return -1;
    irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    if (!g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    for (int32_t current = g_swap_map_used_head; current >= 0;) {
        edge_swap_map_entry_t *entry =
            &g_swap_map_entries[(uint32_t)current];
        current = entry->next_used;
        if (entry->address_space == destination_address_space) {
            spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
            return -1;
        }
        if (entry->address_space == source_address_space)
            ++required;
    }
    if (required > g_swap_map_free_count) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return -1;
    }
    for (int32_t source_current = g_swap_map_used_head;
         source_current >= 0;) {
        edge_swap_map_entry_t *source =
            &g_swap_map_entries[(uint32_t)source_current];
        uint32_t bucket;
        int32_t destination_slot;
        source_current = source->next_used;
        if (source->address_space != source_address_space)
            continue;
        if (swap_retain_entry(source->swap_entry) < 0) {
            for (int32_t rollback_current = g_swap_map_used_head;
                 rollback_current >= 0;) {
                uint32_t rollback = (uint32_t)rollback_current;
                edge_swap_map_entry_t *entry =
                    &g_swap_map_entries[rollback];
                uint64_t swap_entry;
                rollback_current = entry->next_used;
                if (entry->address_space != destination_address_space)
                    continue;
                swap_entry = swap_map_remove_locked(rollback);
                swap_release_entry(swap_entry);
            }
            spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
            return -1;
        }
        destination_slot = swap_map_allocate_locked();
        if (destination_slot < 0) {
            swap_release_entry(source->swap_entry);
            spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
            return -1;
        }
        bucket = swap_map_hash(destination_address_space, source->address);
        g_swap_map_entries[(uint32_t)destination_slot] = *source;
        g_swap_map_entries[(uint32_t)destination_slot].address_space =
            destination_address_space;
        g_swap_map_entries[(uint32_t)destination_slot].next_hash =
            g_swap_map_hash[bucket];
        g_swap_map_entries[(uint32_t)destination_slot].next_free = -1;
        g_swap_map_entries[(uint32_t)destination_slot].previous_used = -1;
        g_swap_map_entries[(uint32_t)destination_slot].next_used =
            g_swap_map_used_head;
        if (g_swap_map_used_head >= 0)
            g_swap_map_entries[(uint32_t)g_swap_map_used_head]
                .previous_used = destination_slot;
        g_swap_map_used_head = destination_slot;
        g_swap_map_hash[bucket] = destination_slot;
        ++g_swap_map_count;
    }
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    return 0;
}

void edge_swap_map_release_space(uint64_t address_space) {
    (void)edge_swap_map_drop_range(address_space, 0, UINT64_MAX);
}

uint32_t edge_swap_map_count(void) {
    uint64_t irq_flags = spin_lock_irqsave(&g_swap_map_lock);
    uint32_t count;
    if (!g_swap_map_initialized) {
        spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
        return 0;
    }
    count = g_swap_map_count;
    spin_unlock_irqrestore(&g_swap_map_lock, irq_flags);
    return count;
}
