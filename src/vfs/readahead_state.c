/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent sequential readahead policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "mm/arch_vm.h"
#include "sys/spinlock.h"
#include "vfs/readahead.h"

#define VFS_READAHEAD_BUCKETS 256u
#define VFS_READAHEAD_ALLOCATION_PAGE_SIZE 4096u
#define VFS_READAHEAD_STREAMS_PER_INODE 4u

typedef struct vfs_readahead_state {
    struct vfs_readahead_state *hash_next;
    struct vfs_readahead_state *free_next;
    const void *filesystem_identity;
    uint32_t inode_number;
    uint32_t inode_generation;
    uint64_t next_offsets[VFS_READAHEAD_STREAMS_PER_INODE];
    uint64_t stream_last_used[VFS_READAHEAD_STREAMS_PER_INODE];
    uint64_t last_used;
    uint32_t window_pages[VFS_READAHEAD_STREAMS_PER_INODE];
    uint8_t active;
} vfs_readahead_state_t;

typedef struct vfs_readahead_chunk {
    struct vfs_readahead_chunk *next;
    uint32_t page_count;
    uint32_t entry_count;
    vfs_readahead_state_t entries[];
} vfs_readahead_chunk_t;

static vfs_readahead_state_t *g_readahead_buckets[VFS_READAHEAD_BUCKETS];
static vfs_readahead_state_t *g_readahead_free;
static vfs_readahead_chunk_t *g_readahead_chunks;
static vfs_readahead_allocator_t g_readahead_allocator;
static uint64_t g_readahead_clock;
static uint32_t g_readahead_count;
static volatile uint32_t g_readahead_initialization_state;
static spinlock_t g_readahead_lock;

static void *vfs_readahead_allocate_pages(uint32_t page_count,
                                          void *context) {
    (void)context;
    return arch_vm_alloc_pages(page_count);
}

static void vfs_readahead_release_pages(void *base, uint32_t page_count,
                                        void *context) {
    uint8_t *page = (uint8_t *)base;
    (void)context;
    for (uint32_t index = 0; index < page_count; ++index)
        arch_vm_free_page(page +
                          (uint64_t)index *
                              VFS_READAHEAD_ALLOCATION_PAGE_SIZE);
}

static void vfs_readahead_allocator_ensure(void) {
    if (g_readahead_allocator.allocate_pages &&
        g_readahead_allocator.release_pages)
        return;
    g_readahead_allocator.allocate_pages =
        vfs_readahead_allocate_pages;
    g_readahead_allocator.release_pages =
        vfs_readahead_release_pages;
    g_readahead_allocator.context = 0;
}

static void vfs_readahead_ensure_initialized(void) {
    uint32_t state = __atomic_load_n(
        &g_readahead_initialization_state, __ATOMIC_ACQUIRE);
    if (state == 2u) return;
    if (__sync_bool_compare_and_swap(
            &g_readahead_initialization_state, 0u, 1u)) {
        vfs_readahead_allocator_ensure();
        spinlock_init(&g_readahead_lock);
        __atomic_store_n(&g_readahead_initialization_state, 2u,
                         __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(&g_readahead_initialization_state,
                           __ATOMIC_ACQUIRE) != 2u) {
        __asm__ __volatile__("" ::: "memory");
    }
}

static uint32_t vfs_readahead_hash(const void *filesystem_identity,
                                   uint32_t inode_number,
                                   uint32_t inode_generation) {
    uintptr_t value = (uintptr_t)filesystem_identity;
    value ^= (uintptr_t)inode_number * 2654435761u;
    value ^= (uintptr_t)inode_generation * 2246822519u;
    value ^= value >> 17u;
    return (uint32_t)value & (VFS_READAHEAD_BUCKETS - 1u);
}

static int vfs_readahead_same_inode(
    const vfs_readahead_state_t *state, const void *filesystem_identity,
    const vfs_inode_t *inode) {
    return state && state->active && inode &&
           state->filesystem_identity == filesystem_identity &&
           state->inode_number == inode->ino &&
           state->inode_generation == inode->generation;
}

static vfs_readahead_state_t *vfs_readahead_find_locked(
    const void *filesystem_identity, const vfs_inode_t *inode) {
    uint32_t bucket = vfs_readahead_hash(
        filesystem_identity, inode->ino, inode->generation);
    vfs_readahead_state_t *state = g_readahead_buckets[bucket];
    while (state) {
        if (vfs_readahead_same_inode(
                state, filesystem_identity, inode))
            return state;
        state = state->hash_next;
    }
    return 0;
}

static int vfs_readahead_grow_locked(void) {
    uint32_t bytes = VFS_READAHEAD_ALLOCATION_PAGE_SIZE;
    uint32_t entries =
        (bytes - (uint32_t)sizeof(vfs_readahead_chunk_t)) /
        (uint32_t)sizeof(vfs_readahead_state_t);
    vfs_readahead_chunk_t *chunk;

    if (!entries) return -1;
    chunk = (vfs_readahead_chunk_t *)
        g_readahead_allocator.allocate_pages(
            1u, g_readahead_allocator.context);
    if (!chunk) return -1;
    chunk->next = g_readahead_chunks;
    chunk->page_count = 1u;
    chunk->entry_count = entries;
    g_readahead_chunks = chunk;
    for (uint32_t index = 0; index < entries; ++index) {
        vfs_readahead_state_t *state = &chunk->entries[index];
        state->active = 0;
        state->free_next = g_readahead_free;
        g_readahead_free = state;
    }
    return 0;
}

static vfs_readahead_state_t *vfs_readahead_create_locked(
    const void *filesystem_identity, const vfs_inode_t *inode) {
    vfs_readahead_state_t *state;
    uint32_t bucket;

    if (!g_readahead_free && vfs_readahead_grow_locked() < 0)
        return 0;
    state = g_readahead_free;
    g_readahead_free = state->free_next;
    state->free_next = 0;
    state->filesystem_identity = filesystem_identity;
    state->inode_number = inode->ino;
    state->inode_generation = inode->generation;
    for (uint32_t stream = 0;
         stream < VFS_READAHEAD_STREAMS_PER_INODE; ++stream) {
        state->next_offsets[stream] = UINT64_MAX;
        state->stream_last_used[stream] = 0;
        state->window_pages[stream] = 0;
    }
    state->last_used = ++g_readahead_clock;
    state->active = 1;
    bucket = vfs_readahead_hash(
        filesystem_identity, inode->ino, inode->generation);
    state->hash_next = g_readahead_buckets[bucket];
    g_readahead_buckets[bucket] = state;
    ++g_readahead_count;
    return state;
}

static void vfs_readahead_remove_locked(vfs_readahead_state_t *state) {
    uint32_t bucket;
    vfs_readahead_state_t **link;

    if (!state || !state->active) return;
    bucket = vfs_readahead_hash(
        state->filesystem_identity, state->inode_number,
        state->inode_generation);
    link = &g_readahead_buckets[bucket];
    while (*link && *link != state) link = &(*link)->hash_next;
    if (*link == state) *link = state->hash_next;
    state->active = 0;
    state->hash_next = 0;
    state->free_next = g_readahead_free;
    g_readahead_free = state;
    if (g_readahead_count) --g_readahead_count;
}

uint32_t vfs_readahead_plan(vfs_superblock_t *sb,
                            const vfs_inode_t *inode,
                            uint64_t page_offset,
                            uint32_t maximum_pages) {
    const void *filesystem_identity;
    vfs_readahead_state_t *state;
    uint32_t stream = VFS_READAHEAD_STREAMS_PER_INODE;
    uint32_t window;
    uint64_t flags;

    if (!maximum_pages) return 0;
    if (!sb || !inode ||
        (page_offset & (VFS_READAHEAD_PAGE_SIZE - 1u)))
        return 1u;
    if (maximum_pages > VFS_READAHEAD_MAX_PAGES)
        maximum_pages = VFS_READAHEAD_MAX_PAGES;
    filesystem_identity = vfs_superblock_identity(sb);
    if (!filesystem_identity) return 1u;
    vfs_readahead_ensure_initialized();
    flags = spin_lock_irqsave(&g_readahead_lock);
    state = vfs_readahead_find_locked(filesystem_identity, inode);
    if (!state)
        state = vfs_readahead_create_locked(
            filesystem_identity, inode);
    if (!state) {
        spin_unlock_irqrestore(&g_readahead_lock, flags);
        return 1u;
    }

    for (uint32_t candidate = 0;
         candidate < VFS_READAHEAD_STREAMS_PER_INODE; ++candidate) {
        if (state->window_pages[candidate] &&
            state->next_offsets[candidate] == page_offset) {
            stream = candidate;
            break;
        }
    }
    if (stream < VFS_READAHEAD_STREAMS_PER_INODE) {
        window = state->window_pages[stream] << 1u;
        if (window < state->window_pages[stream] ||
            window > VFS_READAHEAD_MAX_PAGES)
            window = VFS_READAHEAD_MAX_PAGES;
    } else {
        stream = 0;
        for (uint32_t candidate = 0;
             candidate < VFS_READAHEAD_STREAMS_PER_INODE; ++candidate) {
            if (!state->window_pages[candidate]) {
                stream = candidate;
                break;
            }
            if (state->stream_last_used[candidate] <
                state->stream_last_used[stream])
                stream = candidate;
        }
        window = VFS_READAHEAD_MIN_PAGES;
    }
    if (window > maximum_pages) window = maximum_pages;
    if (!window) window = 1u;
    state->window_pages[stream] = window;
    state->next_offsets[stream] =
        page_offset + (uint64_t)window * VFS_READAHEAD_PAGE_SIZE;
    if (state->next_offsets[stream] < page_offset)
        state->next_offsets[stream] = UINT64_MAX;
    state->last_used = ++g_readahead_clock;
    state->stream_last_used[stream] = state->last_used;
    spin_unlock_irqrestore(&g_readahead_lock, flags);
    return window;
}

void vfs_readahead_forget_inode(vfs_superblock_t *sb,
                                const vfs_inode_t *inode) {
    const void *filesystem_identity;
    vfs_readahead_state_t *state;
    uint64_t flags;

    if (!sb || !inode) return;
    filesystem_identity = vfs_superblock_identity(sb);
    if (!filesystem_identity) return;
    vfs_readahead_ensure_initialized();
    flags = spin_lock_irqsave(&g_readahead_lock);
    state = vfs_readahead_find_locked(filesystem_identity, inode);
    if (state) vfs_readahead_remove_locked(state);
    spin_unlock_irqrestore(&g_readahead_lock, flags);
}

uint32_t vfs_readahead_reclaim(uint32_t state_count) {
    uint32_t reclaimed = 0;

    vfs_readahead_ensure_initialized();
    while (reclaimed < state_count) {
        vfs_readahead_state_t *oldest = 0;
        uint64_t flags = spin_lock_irqsave(&g_readahead_lock);
        for (uint32_t bucket = 0; bucket < VFS_READAHEAD_BUCKETS;
             ++bucket) {
            vfs_readahead_state_t *state =
                g_readahead_buckets[bucket];
            while (state) {
                if (!oldest || state->last_used < oldest->last_used)
                    oldest = state;
                state = state->hash_next;
            }
        }
        if (!oldest) {
            spin_unlock_irqrestore(&g_readahead_lock, flags);
            break;
        }
        vfs_readahead_remove_locked(oldest);
        spin_unlock_irqrestore(&g_readahead_lock, flags);
        ++reclaimed;
    }
    return reclaimed;
}

uint32_t vfs_readahead_state_count(void) {
    uint32_t count;
    uint64_t flags;
    vfs_readahead_ensure_initialized();
    flags = spin_lock_irqsave(&g_readahead_lock);
    count = g_readahead_count;
    spin_unlock_irqrestore(&g_readahead_lock, flags);
    return count;
}

int vfs_readahead_runtime_set_allocator(
    const vfs_readahead_allocator_t *allocator) {
    if (!allocator || !allocator->allocate_pages ||
        !allocator->release_pages || g_readahead_chunks)
        return -1;
    g_readahead_allocator = *allocator;
    return 0;
}

void vfs_readahead_runtime_reset(void) {
    vfs_readahead_chunk_t *chunks;
    uint64_t flags;

    vfs_readahead_ensure_initialized();
    flags = spin_lock_irqsave(&g_readahead_lock);
    chunks = g_readahead_chunks;
    g_readahead_chunks = 0;
    g_readahead_free = 0;
    for (uint32_t bucket = 0; bucket < VFS_READAHEAD_BUCKETS;
         ++bucket)
        g_readahead_buckets[bucket] = 0;
    g_readahead_count = 0;
    g_readahead_clock = 0;
    spin_unlock_irqrestore(&g_readahead_lock, flags);

    while (chunks) {
        vfs_readahead_chunk_t *next = chunks->next;
        g_readahead_allocator.release_pages(
            chunks, chunks->page_count,
            g_readahead_allocator.context);
        chunks = next;
    }
}
