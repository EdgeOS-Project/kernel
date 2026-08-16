/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent file page writeback tracking.
 * Copyright (c) EdgeOS Contributors.
 */

#include "mm/arch_vm.h"
#include "sys/spinlock.h"
#include "vfs/page_writeback.h"

#define VFS_PAGE_WRITEBACK_INODE_BUCKETS 256u
#define VFS_PAGE_WRITEBACK_PAGE_BUCKETS 1024u
#define VFS_PAGE_WRITEBACK_ALLOCATION_SIZE 4096u
#define VFS_PAGE_WRITEBACK_SOFT_LIMIT 4096u
#define VFS_PAGE_WRITEBACK_HARD_LIMIT 8192u
#define VFS_PAGE_WRITEBACK_THROTTLE_BUDGET 32u

typedef struct vfs_page_writeback_page vfs_page_writeback_page_t;

typedef struct vfs_page_writeback_inode {
    struct vfs_page_writeback_inode *hash_next;
    struct vfs_page_writeback_inode *free_next;
    vfs_page_writeback_page_t *dirty_head;
    vfs_page_writeback_page_t *dirty_tail;
    const void *filesystem_identity;
    vfs_superblock_t *superblock;
    vfs_inode_t inode;
    uint32_t dirty_count;
    uint64_t error_sequence;
    int writeback_error;
    uint8_t active;
} vfs_page_writeback_inode_t;

struct vfs_page_writeback_page {
    vfs_page_writeback_page_t *hash_next;
    vfs_page_writeback_page_t *free_next;
    vfs_page_writeback_page_t *global_previous;
    vfs_page_writeback_page_t *global_next;
    vfs_page_writeback_page_t *inode_previous;
    vfs_page_writeback_page_t *inode_next;
    vfs_page_writeback_inode_t *owner;
    vfs_page_writeback_callback_t callback;
    void *context;
    uint64_t page_offset;
    uint64_t token;
    uint32_t dirty_generation;
    uint8_t active;
    uint8_t dirty;
    uint8_t writeback;
    uint8_t discard_pending;
};

typedef struct vfs_page_writeback_inode_chunk {
    struct vfs_page_writeback_inode_chunk *next;
    uint32_t entry_count;
    vfs_page_writeback_inode_t entries[];
} vfs_page_writeback_inode_chunk_t;

typedef struct vfs_page_writeback_page_chunk {
    struct vfs_page_writeback_page_chunk *next;
    uint32_t entry_count;
    vfs_page_writeback_page_t entries[];
} vfs_page_writeback_page_chunk_t;

static vfs_page_writeback_inode_t *
    g_writeback_inode_hash[VFS_PAGE_WRITEBACK_INODE_BUCKETS];
static vfs_page_writeback_page_t *
    g_writeback_page_hash[VFS_PAGE_WRITEBACK_PAGE_BUCKETS];
static vfs_page_writeback_inode_t *g_writeback_free_inodes;
static vfs_page_writeback_page_t *g_writeback_free_pages;
static vfs_page_writeback_page_t *g_writeback_dirty_head;
static vfs_page_writeback_page_t *g_writeback_dirty_tail;
static vfs_page_writeback_inode_chunk_t *g_writeback_inode_chunks;
static vfs_page_writeback_page_chunk_t *g_writeback_page_chunks;
static vfs_page_writeback_allocator_t g_writeback_allocator;
static uint32_t g_writeback_dirty_count;
static volatile uint32_t g_writeback_initialization_state;
static spinlock_t g_writeback_lock;

static void *vfs_page_writeback_allocate_pages(uint32_t page_count,
                                                void *context) {
    (void)context;
    return arch_vm_alloc_pages(page_count);
}

static void vfs_page_writeback_release_pages(void *base,
                                              uint32_t page_count,
                                              void *context) {
    uint8_t *page = (uint8_t *)base;
    (void)context;
    for (uint32_t index = 0; index < page_count; ++index)
        arch_vm_free_page(
            page + (uint64_t)index * VFS_PAGE_WRITEBACK_ALLOCATION_SIZE);
}

static void vfs_page_writeback_ensure_initialized(void) {
    uint32_t state = __atomic_load_n(
        &g_writeback_initialization_state, __ATOMIC_ACQUIRE);
    if (state == 2u) return;
    if (__sync_bool_compare_and_swap(
            &g_writeback_initialization_state, 0u, 1u)) {
        if (!g_writeback_allocator.allocate_pages ||
            !g_writeback_allocator.release_pages) {
            g_writeback_allocator.allocate_pages =
                vfs_page_writeback_allocate_pages;
            g_writeback_allocator.release_pages =
                vfs_page_writeback_release_pages;
            g_writeback_allocator.context = 0;
        }
        spinlock_init(&g_writeback_lock);
        __atomic_store_n(&g_writeback_initialization_state, 2u,
                         __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(&g_writeback_initialization_state,
                           __ATOMIC_ACQUIRE) != 2u) {
        __asm__ __volatile__("" ::: "memory");
    }
}

static uint32_t vfs_page_writeback_inode_hash(
    const void *filesystem_identity, uint32_t inode_number,
    uint32_t inode_generation) {
    uintptr_t value = (uintptr_t)filesystem_identity;
    value ^= (uintptr_t)inode_number * 2654435761u;
    value ^= (uintptr_t)inode_generation * 2246822519u;
    value ^= value >> 17u;
    return (uint32_t)value & (VFS_PAGE_WRITEBACK_INODE_BUCKETS - 1u);
}

static uint32_t vfs_page_writeback_page_hash(
    const vfs_page_writeback_inode_t *inode, uint64_t page_offset) {
    uintptr_t value = (uintptr_t)inode;
    value ^= (uintptr_t)(page_offset >> 12u) * 2654435761u;
    value ^= value >> 15u;
    return (uint32_t)value & (VFS_PAGE_WRITEBACK_PAGE_BUCKETS - 1u);
}

static int vfs_page_writeback_grow_inodes_locked(void) {
    uint32_t entries =
        (VFS_PAGE_WRITEBACK_ALLOCATION_SIZE -
         (uint32_t)sizeof(vfs_page_writeback_inode_chunk_t)) /
        (uint32_t)sizeof(vfs_page_writeback_inode_t);
    vfs_page_writeback_inode_chunk_t *chunk;
    if (!entries) return -1;
    chunk = (vfs_page_writeback_inode_chunk_t *)
        g_writeback_allocator.allocate_pages(
            1u, g_writeback_allocator.context);
    if (!chunk) return -1;
    chunk->next = g_writeback_inode_chunks;
    chunk->entry_count = entries;
    g_writeback_inode_chunks = chunk;
    for (uint32_t index = 0; index < entries; ++index) {
        vfs_page_writeback_inode_t *inode = &chunk->entries[index];
        inode->active = 0;
        inode->free_next = g_writeback_free_inodes;
        g_writeback_free_inodes = inode;
    }
    return 0;
}

static int vfs_page_writeback_grow_pages_locked(void) {
    uint32_t entries =
        (VFS_PAGE_WRITEBACK_ALLOCATION_SIZE -
         (uint32_t)sizeof(vfs_page_writeback_page_chunk_t)) /
        (uint32_t)sizeof(vfs_page_writeback_page_t);
    vfs_page_writeback_page_chunk_t *chunk;
    if (!entries) return -1;
    chunk = (vfs_page_writeback_page_chunk_t *)
        g_writeback_allocator.allocate_pages(
            1u, g_writeback_allocator.context);
    if (!chunk) return -1;
    chunk->next = g_writeback_page_chunks;
    chunk->entry_count = entries;
    g_writeback_page_chunks = chunk;
    for (uint32_t index = 0; index < entries; ++index) {
        vfs_page_writeback_page_t *page = &chunk->entries[index];
        page->active = 0;
        page->free_next = g_writeback_free_pages;
        g_writeback_free_pages = page;
    }
    return 0;
}

static vfs_page_writeback_inode_t *vfs_page_writeback_find_inode_locked(
    const void *filesystem_identity, const vfs_inode_t *inode) {
    uint32_t bucket = vfs_page_writeback_inode_hash(
        filesystem_identity, inode->ino, inode->generation);
    vfs_page_writeback_inode_t *state = g_writeback_inode_hash[bucket];
    while (state) {
        if (state->active &&
            state->filesystem_identity == filesystem_identity &&
            state->inode.ino == inode->ino &&
            state->inode.generation == inode->generation)
            return state;
        state = state->hash_next;
    }
    return 0;
}

static vfs_page_writeback_inode_t *vfs_page_writeback_create_inode_locked(
    const void *filesystem_identity, vfs_superblock_t *superblock,
    const vfs_inode_t *inode) {
    vfs_page_writeback_inode_t *state;
    uint32_t bucket;
    if (!g_writeback_free_inodes &&
        vfs_page_writeback_grow_inodes_locked() < 0)
        return 0;
    state = g_writeback_free_inodes;
    g_writeback_free_inodes = state->free_next;
    state->free_next = 0;
    state->dirty_head = 0;
    state->dirty_tail = 0;
    state->filesystem_identity = filesystem_identity;
    state->superblock = superblock;
    state->inode = *inode;
    state->dirty_count = 0;
    state->error_sequence = 0;
    state->writeback_error = 0;
    state->active = 1u;
    bucket = vfs_page_writeback_inode_hash(
        filesystem_identity, inode->ino, inode->generation);
    state->hash_next = g_writeback_inode_hash[bucket];
    g_writeback_inode_hash[bucket] = state;
    return state;
}

static vfs_page_writeback_page_t *vfs_page_writeback_find_page_locked(
    vfs_page_writeback_inode_t *inode, uint64_t page_offset) {
    uint32_t bucket = vfs_page_writeback_page_hash(inode, page_offset);
    vfs_page_writeback_page_t *page = g_writeback_page_hash[bucket];
    while (page) {
        if (page->active && page->owner == inode &&
            page->page_offset == page_offset)
            return page;
        page = page->hash_next;
    }
    return 0;
}

static vfs_page_writeback_page_t *vfs_page_writeback_create_page_locked(
    vfs_page_writeback_inode_t *inode, uint64_t page_offset) {
    vfs_page_writeback_page_t *page;
    uint32_t bucket;
    if (!g_writeback_free_pages &&
        vfs_page_writeback_grow_pages_locked() < 0)
        return 0;
    page = g_writeback_free_pages;
    g_writeback_free_pages = page->free_next;
    page->free_next = 0;
    page->global_previous = 0;
    page->global_next = 0;
    page->inode_previous = 0;
    page->inode_next = 0;
    page->owner = inode;
    page->callback = 0;
    page->context = 0;
    page->page_offset = page_offset;
    page->token = 0;
    page->dirty_generation = 0;
    page->active = 1u;
    page->dirty = 0;
    page->writeback = 0;
    page->discard_pending = 0;
    bucket = vfs_page_writeback_page_hash(inode, page_offset);
    page->hash_next = g_writeback_page_hash[bucket];
    g_writeback_page_hash[bucket] = page;
    return page;
}

static void vfs_page_writeback_link_dirty_locked(
    vfs_page_writeback_page_t *page) {
    vfs_page_writeback_inode_t *inode = page->owner;
    if (page->dirty) return;
    page->dirty = 1u;
    page->global_previous = g_writeback_dirty_tail;
    page->global_next = 0;
    if (g_writeback_dirty_tail)
        g_writeback_dirty_tail->global_next = page;
    else
        g_writeback_dirty_head = page;
    g_writeback_dirty_tail = page;
    page->inode_previous = inode->dirty_tail;
    page->inode_next = 0;
    if (inode->dirty_tail)
        inode->dirty_tail->inode_next = page;
    else
        inode->dirty_head = page;
    inode->dirty_tail = page;
    ++inode->dirty_count;
    ++g_writeback_dirty_count;
}

static void vfs_page_writeback_unlink_dirty_locked(
    vfs_page_writeback_page_t *page) {
    vfs_page_writeback_inode_t *inode;
    if (!page || !page->dirty) return;
    inode = page->owner;
    if (page->global_previous)
        page->global_previous->global_next = page->global_next;
    else
        g_writeback_dirty_head = page->global_next;
    if (page->global_next)
        page->global_next->global_previous = page->global_previous;
    else
        g_writeback_dirty_tail = page->global_previous;
    if (page->inode_previous)
        page->inode_previous->inode_next = page->inode_next;
    else
        inode->dirty_head = page->inode_next;
    if (page->inode_next)
        page->inode_next->inode_previous = page->inode_previous;
    else
        inode->dirty_tail = page->inode_previous;
    page->global_previous = 0;
    page->global_next = 0;
    page->inode_previous = 0;
    page->inode_next = 0;
    page->dirty = 0;
    if (inode->dirty_count) --inode->dirty_count;
    if (g_writeback_dirty_count) --g_writeback_dirty_count;
}

static void vfs_page_writeback_rotate_dirty_locked(
    vfs_page_writeback_page_t *page) {
    if (!page || !page->dirty || page == g_writeback_dirty_tail) return;
    if (page->global_previous)
        page->global_previous->global_next = page->global_next;
    else
        g_writeback_dirty_head = page->global_next;
    if (page->global_next)
        page->global_next->global_previous = page->global_previous;
    page->global_previous = g_writeback_dirty_tail;
    page->global_next = 0;
    if (g_writeback_dirty_tail)
        g_writeback_dirty_tail->global_next = page;
    g_writeback_dirty_tail = page;
    if (!g_writeback_dirty_head) g_writeback_dirty_head = page;
}

static void vfs_page_writeback_remove_inode_if_unused_locked(
    vfs_page_writeback_inode_t *inode) {
    uint32_t bucket;
    vfs_page_writeback_inode_t **link;
    if (!inode || !inode->active || inode->dirty_count ||
        inode->writeback_error)
        return;
    bucket = vfs_page_writeback_inode_hash(
        inode->filesystem_identity, inode->inode.ino,
        inode->inode.generation);
    link = &g_writeback_inode_hash[bucket];
    while (*link && *link != inode) link = &(*link)->hash_next;
    if (*link == inode) *link = inode->hash_next;
    inode->active = 0;
    inode->hash_next = 0;
    inode->free_next = g_writeback_free_inodes;
    g_writeback_free_inodes = inode;
}

static void vfs_page_writeback_remove_page_locked(
    vfs_page_writeback_page_t *page) {
    vfs_page_writeback_inode_t *inode;
    uint32_t bucket;
    vfs_page_writeback_page_t **link;
    if (!page || !page->active) return;
    inode = page->owner;
    vfs_page_writeback_unlink_dirty_locked(page);
    bucket = vfs_page_writeback_page_hash(page->owner, page->page_offset);
    link = &g_writeback_page_hash[bucket];
    while (*link && *link != page) link = &(*link)->hash_next;
    if (*link == page) *link = page->hash_next;
    page->active = 0;
    page->writeback = 0;
    page->discard_pending = 0;
    page->hash_next = 0;
    page->free_next = g_writeback_free_pages;
    g_writeback_free_pages = page;
    vfs_page_writeback_remove_inode_if_unused_locked(inode);
}

int vfs_page_writeback_mark_dirty(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t page_offset, uint64_t token,
    vfs_page_writeback_callback_t callback, void *context) {
    const void *identity;
    vfs_page_writeback_inode_t *inode_state;
    vfs_page_writeback_page_t *page;
    uint32_t dirty_count;
    uint64_t flags;

    if (!superblock || !inode || !callback ||
        (page_offset & (VFS_PAGE_WRITEBACK_PAGE_SIZE - 1u)))
        return VFS_PAGE_WRITEBACK_ERR_INVALID;
    identity = vfs_superblock_identity(superblock);
    if (!identity) return VFS_PAGE_WRITEBACK_ERR_INVALID;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    inode_state = vfs_page_writeback_find_inode_locked(identity, inode);
    if (!inode_state)
        inode_state = vfs_page_writeback_create_inode_locked(
            identity, superblock, inode);
    if (!inode_state) {
        spin_unlock_irqrestore(&g_writeback_lock, flags);
        return VFS_PAGE_WRITEBACK_ERR_IO;
    }
    inode_state->superblock = superblock;
    inode_state->inode = *inode;
    page = vfs_page_writeback_find_page_locked(inode_state, page_offset);
    if (!page)
        page = vfs_page_writeback_create_page_locked(
            inode_state, page_offset);
    if (!page) {
        spin_unlock_irqrestore(&g_writeback_lock, flags);
        return VFS_PAGE_WRITEBACK_ERR_IO;
    }
    page->callback = callback;
    page->context = context;
    page->token = token;
    ++page->dirty_generation;
    if (!page->dirty_generation) ++page->dirty_generation;
    vfs_page_writeback_link_dirty_locked(page);
    dirty_count = g_writeback_dirty_count;
    spin_unlock_irqrestore(&g_writeback_lock, flags);

    if (dirty_count >= VFS_PAGE_WRITEBACK_HARD_LIMIT)
        (void)vfs_page_writeback_run(
            VFS_PAGE_WRITEBACK_THROTTLE_BUDGET);
    return dirty_count >= VFS_PAGE_WRITEBACK_SOFT_LIMIT ? 1 : 0;
}

static int vfs_page_writeback_process_page(
    vfs_page_writeback_page_t *page) {
    vfs_page_writeback_callback_t callback;
    void *context;
    uint64_t token;
    uint32_t generation;
    int result;
    uint64_t flags;

    flags = spin_lock_irqsave(&g_writeback_lock);
    if (!page || !page->active || !page->dirty || page->writeback) {
        spin_unlock_irqrestore(&g_writeback_lock, flags);
        return VFS_PAGE_WRITEBACK_ERR_INVALID;
    }
    page->writeback = 1u;
    callback = page->callback;
    context = page->context;
    token = page->token;
    generation = page->dirty_generation;
    spin_unlock_irqrestore(&g_writeback_lock, flags);

    result = callback ? callback(token, generation, context) :
                        VFS_PAGE_WRITEBACK_DISCARD;

    flags = spin_lock_irqsave(&g_writeback_lock);
    if (!page->active) {
        spin_unlock_irqrestore(&g_writeback_lock, flags);
        return result < 0 ? result : 0;
    }
    page->writeback = 0;
    if (page->discard_pending) {
        vfs_page_writeback_remove_page_locked(page);
    } else if (result < 0) {
        page->owner->writeback_error = result;
        ++page->owner->error_sequence;
        vfs_page_writeback_rotate_dirty_locked(page);
    } else if (result == VFS_PAGE_WRITEBACK_DISCARD) {
        vfs_page_writeback_remove_page_locked(page);
    } else if (result == VFS_PAGE_WRITEBACK_RETAIN ||
               page->dirty_generation != generation) {
        vfs_page_writeback_rotate_dirty_locked(page);
    } else {
        vfs_page_writeback_remove_page_locked(page);
    }
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    return result < 0 ? result : 0;
}

static int vfs_page_writeback_matches_range(
    const vfs_page_writeback_page_t *page, const void *identity,
    const vfs_inode_t *inode, uint64_t offset, uint64_t end) {
    return page && page->active && page->dirty && !page->writeback &&
           page->owner->filesystem_identity == identity &&
           page->owner->inode.ino == inode->ino &&
           page->owner->inode.generation == inode->generation &&
           page->page_offset < end &&
           page->page_offset + VFS_PAGE_WRITEBACK_PAGE_SIZE > offset;
}

uint32_t vfs_page_writeback_run(uint32_t page_budget) {
    uint32_t processed = 0;
    vfs_page_writeback_page_t *current;
    vfs_page_writeback_page_t *stop;
    uint64_t flags;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    current = g_writeback_dirty_head;
    stop = g_writeback_dirty_tail;
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    while (current && processed < page_budget) {
        vfs_page_writeback_page_t *page = current;
        vfs_page_writeback_page_t *next;
        flags = spin_lock_irqsave(&g_writeback_lock);
        next = page->active && page->dirty ? page->global_next : 0;
        if (page->writeback) page = 0;
        spin_unlock_irqrestore(&g_writeback_lock, flags);
        if (page) {
            (void)vfs_page_writeback_process_page(page);
            ++processed;
        }
        if (current == stop) break;
        current = next;
    }
    return processed;
}

int vfs_page_writeback_sync_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length) {
    const void *identity;
    uint64_t end;
    vfs_page_writeback_page_t *current;
    vfs_page_writeback_page_t *stop;
    int status = 0;
    uint64_t flags;

    if (!superblock || !inode) return VFS_PAGE_WRITEBACK_ERR_INVALID;
    identity = vfs_superblock_identity(superblock);
    if (!identity) return VFS_PAGE_WRITEBACK_ERR_INVALID;
    end = length > UINT64_MAX - offset ? UINT64_MAX : offset + length;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    current = g_writeback_dirty_head;
    stop = g_writeback_dirty_tail;
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    while (current) {
        vfs_page_writeback_page_t *page = current;
        vfs_page_writeback_page_t *next;
        flags = spin_lock_irqsave(&g_writeback_lock);
        next = page->active && page->dirty ? page->global_next : 0;
        if (!vfs_page_writeback_matches_range(
                page, identity, inode, offset, end))
            page = 0;
        spin_unlock_irqrestore(&g_writeback_lock, flags);
        if (page && vfs_page_writeback_process_page(page) < 0)
            status = VFS_PAGE_WRITEBACK_ERR_IO;
        if (current == stop) break;
        current = next;
    }
    if (vfs_page_writeback_error(superblock, inode, 1) < 0)
        status = VFS_PAGE_WRITEBACK_ERR_IO;
    return status;
}

int vfs_page_writeback_sync_inode(
    vfs_superblock_t *superblock, const vfs_inode_t *inode) {
    return vfs_page_writeback_sync_range(
        superblock, inode, 0, UINT64_MAX);
}

int vfs_page_writeback_sync_superblock(vfs_superblock_t *superblock) {
    const void *identity;
    vfs_page_writeback_page_t *current;
    vfs_page_writeback_page_t *stop;
    int status = 0;
    uint64_t flags;
    if (!superblock) return VFS_PAGE_WRITEBACK_ERR_INVALID;
    identity = vfs_superblock_identity(superblock);
    if (!identity) return VFS_PAGE_WRITEBACK_ERR_INVALID;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    current = g_writeback_dirty_head;
    stop = g_writeback_dirty_tail;
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    while (current) {
        vfs_page_writeback_page_t *page = current;
        vfs_page_writeback_page_t *next;
        flags = spin_lock_irqsave(&g_writeback_lock);
        next = page->active && page->dirty ? page->global_next : 0;
        if (!page->active || !page->dirty || page->writeback ||
            page->owner->filesystem_identity != identity)
            page = 0;
        spin_unlock_irqrestore(&g_writeback_lock, flags);
        if (page && vfs_page_writeback_process_page(page) < 0)
            status = VFS_PAGE_WRITEBACK_ERR_IO;
        if (current == stop) break;
        current = next;
    }
    flags = spin_lock_irqsave(&g_writeback_lock);
    for (uint32_t bucket = 0;
         bucket < VFS_PAGE_WRITEBACK_INODE_BUCKETS; ++bucket) {
        vfs_page_writeback_inode_t *state =
            g_writeback_inode_hash[bucket];
        while (state) {
            vfs_page_writeback_inode_t *next = state->hash_next;
            if (state->active &&
                state->filesystem_identity == identity &&
                state->writeback_error) {
                status = VFS_PAGE_WRITEBACK_ERR_IO;
                state->writeback_error = 0;
                vfs_page_writeback_remove_inode_if_unused_locked(state);
            }
            state = next;
        }
    }
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    return status;
}

void vfs_page_writeback_forget_token(
    vfs_page_writeback_callback_t callback, void *context,
    uint64_t token) {
    uint64_t flags;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    for (uint32_t bucket = 0; bucket < VFS_PAGE_WRITEBACK_PAGE_BUCKETS;
         ++bucket) {
        vfs_page_writeback_page_t *page = g_writeback_page_hash[bucket];
        while (page) {
            vfs_page_writeback_page_t *next = page->hash_next;
            if (page->active && page->callback == callback &&
                page->context == context && page->token == token) {
                if (page->writeback)
                    page->discard_pending = 1u;
                else
                    vfs_page_writeback_remove_page_locked(page);
            }
            page = next;
        }
    }
    spin_unlock_irqrestore(&g_writeback_lock, flags);
}

void vfs_page_writeback_forget_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length) {
    const void *identity;
    uint64_t end;
    uint64_t flags;
    if (!superblock || !inode) return;
    identity = vfs_superblock_identity(superblock);
    if (!identity) return;
    end = length > UINT64_MAX - offset ? UINT64_MAX : offset + length;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    for (uint32_t bucket = 0; bucket < VFS_PAGE_WRITEBACK_PAGE_BUCKETS;
         ++bucket) {
        vfs_page_writeback_page_t *page = g_writeback_page_hash[bucket];
        while (page) {
            vfs_page_writeback_page_t *next = page->hash_next;
            if (page->active && page->dirty &&
                page->owner->filesystem_identity == identity &&
                page->owner->inode.ino == inode->ino &&
                page->owner->inode.generation == inode->generation &&
                page->page_offset < end &&
                page->page_offset + VFS_PAGE_WRITEBACK_PAGE_SIZE >
                    offset) {
                if (page->writeback)
                    page->discard_pending = 1u;
                else
                    vfs_page_writeback_remove_page_locked(page);
            }
            page = next;
        }
    }
    spin_unlock_irqrestore(&g_writeback_lock, flags);
}

int vfs_page_writeback_error(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    int clear_error) {
    const void *identity;
    vfs_page_writeback_inode_t *state;
    int result = 0;
    uint64_t flags;
    if (!superblock || !inode) return VFS_PAGE_WRITEBACK_ERR_INVALID;
    identity = vfs_superblock_identity(superblock);
    if (!identity) return VFS_PAGE_WRITEBACK_ERR_INVALID;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    state = vfs_page_writeback_find_inode_locked(identity, inode);
    if (state) {
        result = state->writeback_error;
        if (clear_error) {
            state->writeback_error = 0;
            vfs_page_writeback_remove_inode_if_unused_locked(state);
        }
    }
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    return result;
}

uint32_t vfs_page_writeback_dirty_pages(void) {
    uint32_t result;
    uint64_t flags;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    result = g_writeback_dirty_count;
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    return result;
}

void vfs_page_writeback_stat_range(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint64_t offset, uint64_t length,
    uint64_t *dirty_pages, uint64_t *writeback_pages) {
    const void *identity;
    vfs_page_writeback_inode_t *state;
    uint64_t end;
    uint64_t dirty = 0;
    uint64_t writeback = 0;
    uint64_t flags;

    if (dirty_pages) *dirty_pages = 0;
    if (writeback_pages) *writeback_pages = 0;
    if (!superblock || !inode) return;
    identity = vfs_superblock_identity(superblock);
    if (!identity) return;
    end = !length || length > UINT64_MAX - offset ?
          UINT64_MAX : offset + length;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    state = vfs_page_writeback_find_inode_locked(identity, inode);
    if (state) {
        vfs_page_writeback_page_t *page = state->dirty_head;
        while (page) {
            if (page->active && page->dirty &&
                page->page_offset < end &&
                page->page_offset + VFS_PAGE_WRITEBACK_PAGE_SIZE > offset) {
                ++dirty;
                if (page->writeback) ++writeback;
            }
            page = page->inode_next;
        }
    }
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    if (dirty_pages) *dirty_pages = dirty;
    if (writeback_pages) *writeback_pages = writeback;
}

int vfs_page_writeback_should_throttle(void) {
    return vfs_page_writeback_dirty_pages() >=
           VFS_PAGE_WRITEBACK_SOFT_LIMIT;
}

int vfs_page_writeback_runtime_set_allocator(
    const vfs_page_writeback_allocator_t *allocator) {
    if (!allocator || !allocator->allocate_pages ||
        !allocator->release_pages || g_writeback_inode_chunks ||
        g_writeback_page_chunks)
        return -1;
    g_writeback_allocator = *allocator;
    return 0;
}

void vfs_page_writeback_runtime_reset(void) {
    vfs_page_writeback_inode_chunk_t *inode_chunks;
    vfs_page_writeback_page_chunk_t *page_chunks;
    uint64_t flags;
    vfs_page_writeback_ensure_initialized();
    flags = spin_lock_irqsave(&g_writeback_lock);
    inode_chunks = g_writeback_inode_chunks;
    page_chunks = g_writeback_page_chunks;
    g_writeback_inode_chunks = 0;
    g_writeback_page_chunks = 0;
    g_writeback_free_inodes = 0;
    g_writeback_free_pages = 0;
    g_writeback_dirty_head = 0;
    g_writeback_dirty_tail = 0;
    g_writeback_dirty_count = 0;
    for (uint32_t bucket = 0;
         bucket < VFS_PAGE_WRITEBACK_INODE_BUCKETS; ++bucket)
        g_writeback_inode_hash[bucket] = 0;
    for (uint32_t bucket = 0;
         bucket < VFS_PAGE_WRITEBACK_PAGE_BUCKETS; ++bucket)
        g_writeback_page_hash[bucket] = 0;
    spin_unlock_irqrestore(&g_writeback_lock, flags);
    while (page_chunks) {
        vfs_page_writeback_page_chunk_t *next = page_chunks->next;
        g_writeback_allocator.release_pages(
            page_chunks, 1u, g_writeback_allocator.context);
        page_chunks = next;
    }
    while (inode_chunks) {
        vfs_page_writeback_inode_chunk_t *next = inode_chunks->next;
        g_writeback_allocator.release_pages(
            inode_chunks, 1u, g_writeback_allocator.context);
        inode_chunks = next;
    }
}
