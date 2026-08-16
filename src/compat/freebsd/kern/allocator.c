/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS page-backed allocator for BSD driver source compatibility.
 *
 * The allocator owns complete page runs supplied by the EdgeOS VM backend.
 * Boundary-tagged blocks are split and coalesced inside each run. The static
 * arena table avoids recursive allocation while still allowing an idle arena
 * to return every page to the VM backend.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compat/freebsd/edgeos/allocator.h"

#ifndef BSD_BRIDGE_HOST_TEST
#include "mm/arch_vm.h"
#include "sys/spinlock.h"
#endif

#define BSD_ALLOCATOR_PAGE_SIZE 4096u
#define BSD_ALLOCATOR_ALIGNMENT 16u
#define BSD_ALLOCATOR_ARENA_PAGES 16u
#define BSD_ALLOCATOR_MAX_ARENAS 128u
#define BSD_ALLOCATOR_BLOCK_MAGIC 0x425344424c4f434bull
#define BSD_ALLOCATOR_FREED_MAGIC 0x4253444652454544ull

typedef struct bsd_allocator_block bsd_allocator_block_t;

struct bsd_allocator_block {
    uint64_t magic;
    size_t capacity;
    size_t requested;
    bsd_allocator_block_t *previous;
    bsd_allocator_block_t *next;
    uint8_t is_free;
    uint8_t reserved[7];
};

typedef struct {
    uint8_t *base;
    uint64_t page_count;
    bsd_allocator_block_t *first;
    uint32_t allocated_blocks;
    uint8_t active;
} bsd_allocator_arena_t;

static bsd_allocator_ops_t g_allocator_ops;
static bsd_allocator_arena_t g_allocator_arenas[BSD_ALLOCATOR_MAX_ARENAS];
static bsd_allocator_stats_t g_allocator_stats;
static uint8_t g_allocator_initialized;

#ifdef BSD_BRIDGE_HOST_TEST
static volatile uint32_t g_allocator_lock;

static uint64_t allocator_lock(void) {
    while (__atomic_test_and_set(&g_allocator_lock, __ATOMIC_ACQUIRE)) {
    }
    return 0;
}

static void allocator_unlock(uint64_t state) {
    (void)state;
    __atomic_clear(&g_allocator_lock, __ATOMIC_RELEASE);
}
#else
static spinlock_t g_allocator_lock;

static uint64_t allocator_lock(void) {
    return spin_lock_irqsave(&g_allocator_lock);
}

static void allocator_unlock(uint64_t state) {
    spin_unlock_irqrestore(&g_allocator_lock, state);
}

static void *allocator_default_allocate_pages(uint64_t page_count,
                                              void *context) {
    (void)context;
    return arch_vm_alloc_pages(page_count);
}

static void allocator_default_release_pages(void *base, uint64_t page_count,
                                            void *context) {
    uint8_t *page = (uint8_t *)base;
    (void)context;
    for (uint64_t index = 0; index < page_count; ++index)
        arch_vm_free_page(page + index * BSD_ALLOCATOR_PAGE_SIZE);
}
#endif

static size_t align_up(size_t value, size_t alignment) {
    size_t mask = alignment - 1u;
    if (value > SIZE_MAX - mask) return 0;
    return (value + mask) & ~mask;
}

static size_t block_header_size(void) {
    return align_up(sizeof(bsd_allocator_block_t), BSD_ALLOCATOR_ALIGNMENT);
}

static int pointer_in_arena(const bsd_allocator_arena_t *arena,
                            const void *pointer) {
    uintptr_t value = (uintptr_t)pointer;
    uintptr_t start = (uintptr_t)arena->base;
    uintptr_t length;
    if (!arena->active ||
        arena->page_count > UINTPTR_MAX / BSD_ALLOCATOR_PAGE_SIZE)
        return 0;
    length = (uintptr_t)arena->page_count * BSD_ALLOCATOR_PAGE_SIZE;
    return value >= start && value - start < length;
}

static bsd_allocator_arena_t *find_arena_locked(const void *pointer) {
    for (uint32_t index = 0; index < BSD_ALLOCATOR_MAX_ARENAS; ++index) {
        if (pointer_in_arena(&g_allocator_arenas[index], pointer))
            return &g_allocator_arenas[index];
    }
    return 0;
}

static bsd_allocator_block_t *allocation_block_locked(
    const void *allocation, bsd_allocator_arena_t **arena_out) {
    bsd_allocator_arena_t *arena;
    bsd_allocator_block_t *block;
    size_t header_size = block_header_size();

    if (!allocation || !header_size) return 0;
    arena = find_arena_locked(allocation);
    if (!arena || (uintptr_t)allocation < (uintptr_t)arena->base + header_size)
        return 0;
    block = (bsd_allocator_block_t *)((uint8_t *)allocation - header_size);
    if (!pointer_in_arena(arena, block) ||
        block->magic != BSD_ALLOCATOR_BLOCK_MAGIC || block->is_free)
        return 0;
    if ((uint8_t *)block + header_size != (const uint8_t *)allocation)
        return 0;
    if (arena_out) *arena_out = arena;
    return block;
}

static bsd_allocator_arena_t *arena_slot_locked(void) {
    for (uint32_t index = 0; index < BSD_ALLOCATOR_MAX_ARENAS; ++index) {
        if (!g_allocator_arenas[index].active)
            return &g_allocator_arenas[index];
    }
    return 0;
}

static bsd_allocator_arena_t *create_arena_locked(size_t capacity) {
    bsd_allocator_arena_t *arena;
    bsd_allocator_block_t *block;
    size_t header_size = block_header_size();
    uint64_t page_count;
    uint64_t bytes;
    void *base;

    if (!header_size || capacity > SIZE_MAX - header_size) return 0;
    bytes = (uint64_t)capacity + header_size;
    if (bytes > UINT64_MAX - (BSD_ALLOCATOR_PAGE_SIZE - 1u)) return 0;
    page_count = (bytes + BSD_ALLOCATOR_PAGE_SIZE - 1u) /
                 BSD_ALLOCATOR_PAGE_SIZE;
    if (page_count < BSD_ALLOCATOR_ARENA_PAGES)
        page_count = BSD_ALLOCATOR_ARENA_PAGES;
    if (page_count > UINT64_MAX / BSD_ALLOCATOR_PAGE_SIZE) return 0;

    arena = arena_slot_locked();
    if (!arena) return 0;
    base = g_allocator_ops.allocate_pages(page_count, g_allocator_ops.context);
    if (!base)
        return 0;
    if (((uintptr_t)base & (BSD_ALLOCATOR_ALIGNMENT - 1u)) != 0) {
        g_allocator_ops.release_pages(base, page_count,
                                      g_allocator_ops.context);
        return 0;
    }

    bytes = page_count * BSD_ALLOCATOR_PAGE_SIZE;
    memset(arena, 0, sizeof(*arena));
    arena->base = (uint8_t *)base;
    arena->page_count = page_count;
    arena->active = 1;

    block = (bsd_allocator_block_t *)base;
    memset(block, 0, sizeof(*block));
    block->magic = BSD_ALLOCATOR_BLOCK_MAGIC;
    block->capacity = (size_t)bytes - header_size;
    block->is_free = 1;
    arena->first = block;
    g_allocator_stats.active_arenas++;
    return arena;
}

static bsd_allocator_block_t *find_free_block_locked(size_t capacity) {
    for (uint32_t arena_index = 0; arena_index < BSD_ALLOCATOR_MAX_ARENAS;
         ++arena_index) {
        bsd_allocator_arena_t *arena = &g_allocator_arenas[arena_index];
        if (!arena->active) continue;
        for (bsd_allocator_block_t *block = arena->first; block;
             block = block->next) {
            if (block->magic == BSD_ALLOCATOR_BLOCK_MAGIC && block->is_free &&
                block->capacity >= capacity)
                return block;
        }
    }
    return 0;
}

static void split_block_locked(bsd_allocator_block_t *block, size_t capacity) {
    size_t header_size = block_header_size();
    size_t remainder;
    bsd_allocator_block_t *next;

    if (!header_size || block->capacity < capacity) return;
    remainder = block->capacity - capacity;
    if (remainder < header_size + BSD_ALLOCATOR_ALIGNMENT) return;

    next = (bsd_allocator_block_t *)((uint8_t *)block + header_size + capacity);
    memset(next, 0, sizeof(*next));
    next->magic = BSD_ALLOCATOR_BLOCK_MAGIC;
    next->capacity = remainder - header_size;
    next->is_free = 1;
    next->previous = block;
    next->next = block->next;
    if (next->next) next->next->previous = next;
    block->next = next;
    block->capacity = capacity;
}

static bsd_allocator_block_t *coalesce_block_locked(
    bsd_allocator_block_t *block) {
    size_t header_size = block_header_size();

    if (block->next && block->next->is_free &&
        block->next->magic == BSD_ALLOCATOR_BLOCK_MAGIC) {
        bsd_allocator_block_t *next = block->next;
        block->capacity += header_size + next->capacity;
        block->next = next->next;
        if (block->next) block->next->previous = block;
        next->magic = BSD_ALLOCATOR_FREED_MAGIC;
    }
    if (block->previous && block->previous->is_free &&
        block->previous->magic == BSD_ALLOCATOR_BLOCK_MAGIC) {
        bsd_allocator_block_t *previous = block->previous;
        previous->capacity += header_size + block->capacity;
        previous->next = block->next;
        if (previous->next) previous->next->previous = previous;
        block->magic = BSD_ALLOCATOR_FREED_MAGIC;
        block = previous;
    }
    return block;
}

static int release_idle_arena_locked(bsd_allocator_arena_t *arena,
                                     void **base_out, uint64_t *pages_out) {
    bsd_allocator_block_t *block;
    size_t header_size = block_header_size();
    uint64_t arena_bytes;

    if (!arena || !arena->active || arena->allocated_blocks != 0)
        return 0;
    block = arena->first;
    arena_bytes = arena->page_count * BSD_ALLOCATOR_PAGE_SIZE;
    if (!block || !block->is_free || block->previous || block->next ||
        block->capacity + header_size != arena_bytes)
        return 0;

    *base_out = arena->base;
    *pages_out = arena->page_count;
    block->magic = BSD_ALLOCATOR_FREED_MAGIC;
    memset(arena, 0, sizeof(*arena));
    if (g_allocator_stats.active_arenas)
        g_allocator_stats.active_arenas--;
    return 1;
}

int bsd_allocator_initialize(const bsd_allocator_ops_t *ops) {
    bsd_allocator_ops_t selected;
    uint64_t state;

    memset(&selected, 0, sizeof(selected));
    if (ops) {
        selected = *ops;
    } else {
#ifdef BSD_BRIDGE_HOST_TEST
        return -1;
#else
        selected.allocate_pages = allocator_default_allocate_pages;
        selected.release_pages = allocator_default_release_pages;
#endif
    }
    if (!selected.allocate_pages || !selected.release_pages) return -1;

    state = allocator_lock();
    if (g_allocator_initialized) {
        allocator_unlock(state);
        return -1;
    }
    memset(g_allocator_arenas, 0, sizeof(g_allocator_arenas));
    memset(&g_allocator_stats, 0, sizeof(g_allocator_stats));
    g_allocator_ops = selected;
    g_allocator_initialized = 1;
    allocator_unlock(state);
    return 0;
}

int bsd_allocator_is_initialized(void) {
    return __atomic_load_n(&g_allocator_initialized, __ATOMIC_ACQUIRE) != 0;
}

int bsd_allocator_wait_for_memory(void) {
    if (!bsd_allocator_is_initialized() || !g_allocator_ops.wait_for_memory)
        return 0;
    return g_allocator_ops.wait_for_memory(g_allocator_ops.context);
}

void bsd_allocator_get_stats(bsd_allocator_stats_t *stats) {
    uint64_t state;
    if (!stats) return;
    state = allocator_lock();
    *stats = g_allocator_stats;
    allocator_unlock(state);
}

void *bsd_kmalloc(size_t size, uint32_t flags) {
    bsd_allocator_block_t *block;
    bsd_allocator_arena_t *arena;
    size_t capacity;
    size_t header_size = block_header_size();
    uint64_t state;
    void *allocation;

    if (!bsd_allocator_is_initialized() || !header_size) return 0;
    if (!size) size = 1;
    capacity = align_up(size, BSD_ALLOCATOR_ALIGNMENT);
    if (!capacity) return 0;

    for (;;) {
        state = allocator_lock();
        block = find_free_block_locked(capacity);
        if (!block) {
            arena = create_arena_locked(capacity);
            block = arena ? arena->first : 0;
        }
        if (block) {
            split_block_locked(block, capacity);
            block->is_free = 0;
            block->requested = size;
            arena = find_arena_locked(block);
            if (!arena) {
                block->is_free = 1;
                allocator_unlock(state);
                return 0;
            }
            arena->allocated_blocks++;
            g_allocator_stats.bytes_in_use += size;
            if (g_allocator_stats.bytes_in_use >
                g_allocator_stats.peak_bytes_in_use)
                g_allocator_stats.peak_bytes_in_use =
                    g_allocator_stats.bytes_in_use;
            g_allocator_stats.allocation_count++;
            allocation = (uint8_t *)block + header_size;
            allocator_unlock(state);
            if (flags & BSD_M_ZERO) memset(allocation, 0, size);
            return allocation;
        }
        g_allocator_stats.failed_allocation_count++;
        allocator_unlock(state);

        if ((flags & BSD_M_WAITOK) == 0 || !g_allocator_ops.wait_for_memory ||
            g_allocator_ops.wait_for_memory(g_allocator_ops.context) <= 0)
            return 0;
    }
}

void *bsd_kmallocarray(size_t count, size_t size, uint32_t flags) {
    if (count && size > SIZE_MAX / count) return 0;
    return bsd_kmalloc(count * size, flags);
}

void *bsd_krealloc(void *allocation, size_t size, uint32_t flags) {
    bsd_allocator_block_t *block;
    size_t old_size;
    size_t capacity;
    uint64_t state;
    void *replacement;

    if (!allocation) return bsd_kmalloc(size, flags);
    if (!size) {
        bsd_kfree(allocation);
        return 0;
    }
    capacity = align_up(size, BSD_ALLOCATOR_ALIGNMENT);
    if (!capacity) return 0;

    state = allocator_lock();
    block = allocation_block_locked(allocation, 0);
    if (!block) {
        allocator_unlock(state);
        return 0;
    }
    old_size = block->requested;
    if (block->capacity >= capacity) {
        split_block_locked(block, capacity);
        if (block->next && block->next->is_free)
            (void)coalesce_block_locked(block->next);
        block->requested = size;
        if (size >= old_size)
            g_allocator_stats.bytes_in_use += size - old_size;
        else
            g_allocator_stats.bytes_in_use -= old_size - size;
        if (g_allocator_stats.bytes_in_use >
            g_allocator_stats.peak_bytes_in_use)
            g_allocator_stats.peak_bytes_in_use =
                g_allocator_stats.bytes_in_use;
        allocator_unlock(state);
        if ((flags & BSD_M_ZERO) && size > old_size)
            memset((uint8_t *)allocation + old_size, 0, size - old_size);
        return allocation;
    }
    allocator_unlock(state);

    replacement = bsd_kmalloc(size, flags);
    if (!replacement) return 0;
    memcpy(replacement, allocation, old_size < size ? old_size : size);
    bsd_kfree(allocation);
    return replacement;
}

void bsd_kfree(void *allocation) {
    bsd_allocator_arena_t *arena;
    bsd_allocator_block_t *block;
    void *release_base = 0;
    uint64_t release_pages = 0;
    uint64_t state;

    if (!allocation || !bsd_allocator_is_initialized()) return;
    state = allocator_lock();
    block = allocation_block_locked(allocation, &arena);
    if (!block) {
        allocator_unlock(state);
        return;
    }
    if (g_allocator_stats.bytes_in_use >= block->requested)
        g_allocator_stats.bytes_in_use -= block->requested;
    else
        g_allocator_stats.bytes_in_use = 0;
    g_allocator_stats.free_count++;
    block->requested = 0;
    block->is_free = 1;
    if (arena->allocated_blocks) arena->allocated_blocks--;
    block = coalesce_block_locked(block);
    (void)block;
    (void)release_idle_arena_locked(arena, &release_base, &release_pages);
    allocator_unlock(state);

    if (release_base)
        g_allocator_ops.release_pages(release_base, release_pages,
                                      g_allocator_ops.context);
}

size_t bsd_kmalloc_usable_size(const void *allocation) {
    bsd_allocator_block_t *block;
    size_t size = 0;
    uint64_t state;
    if (!allocation || !bsd_allocator_is_initialized()) return 0;
    state = allocator_lock();
    block = allocation_block_locked(allocation, 0);
    if (block) size = block->capacity;
    allocator_unlock(state);
    return size;
}
