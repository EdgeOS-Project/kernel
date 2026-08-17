/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent VFS path cache.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/path_cache.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/spinlock.h"

#define VFS_PATH_CACHE_BUCKET_COUNT 256u
#define VFS_PATH_CACHE_PAGE_SIZE 4096u
#define VFS_PATH_CACHE_RECLAIM_BATCH 16u

typedef struct vfs_path_cache_entry {
    struct vfs_path_cache_entry *next;
    uint32_t page_count;
    uint32_t namespace_id;
    uint32_t path_hash;
    uint32_t superblock_index;
    uint64_t last_used;
    uint8_t miss;
    uint16_t path_length;
    vfs_inode_t inode;
    char path[];
} vfs_path_cache_entry_t;

static vfs_path_cache_entry_t
    *g_vfs_path_cache[VFS_PATH_CACHE_BUCKET_COUNT];
static vfs_path_cache_allocator_t g_vfs_path_cache_allocator;
static uint32_t g_vfs_path_cache_count;
static uint64_t g_vfs_path_cache_clock;
static volatile uint32_t g_vfs_path_cache_initialization_state;
static spinlock_t g_vfs_path_cache_lock;

static void *vfs_path_cache_allocate_pages(uint32_t page_count,
                                           void *context) {
    (void)context;
    return arch_vm_alloc_pages(page_count);
}

static void vfs_path_cache_release_pages(void *base, uint32_t page_count,
                                         void *context) {
    uint8_t *page = (uint8_t *)base;
    (void)context;
    for (uint32_t index = 0; index < page_count; ++index)
        arch_vm_free_page(page + (uint64_t)index * VFS_PATH_CACHE_PAGE_SIZE);
}

static void vfs_path_cache_allocator_ensure(void) {
    if (g_vfs_path_cache_allocator.allocate_pages &&
        g_vfs_path_cache_allocator.release_pages)
        return;
    g_vfs_path_cache_allocator.allocate_pages =
        vfs_path_cache_allocate_pages;
    g_vfs_path_cache_allocator.release_pages =
        vfs_path_cache_release_pages;
    g_vfs_path_cache_allocator.context = 0;
}

static void vfs_path_cache_ensure_initialized(void) {
    uint32_t state = __atomic_load_n(
        &g_vfs_path_cache_initialization_state, __ATOMIC_ACQUIRE);
    if (state == 2u) return;
    if (__sync_bool_compare_and_swap(
            &g_vfs_path_cache_initialization_state, 0u, 1u)) {
        vfs_path_cache_allocator_ensure();
        spinlock_init(&g_vfs_path_cache_lock);
        __atomic_store_n(
            &g_vfs_path_cache_initialization_state, 2u,
            __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(
               &g_vfs_path_cache_initialization_state,
               __ATOMIC_ACQUIRE) != 2u) {
        __asm__ __volatile__("" ::: "memory");
    }
}

static void vfs_path_cache_release_list(vfs_path_cache_entry_t *entry) {
    while (entry) {
        vfs_path_cache_entry_t *next = entry->next;
        g_vfs_path_cache_allocator.release_pages(
            entry, entry->page_count, g_vfs_path_cache_allocator.context);
        entry = next;
    }
}

static int vfs_path_cacheable(const char *path) {
    if (!path || path[0] != '/') return 0;
    if (strcmp(path, "/dev") == 0 ||
        strncmp(path, "/dev/", 5) == 0)
        return 0;
    if (strcmp(path, "/proc") == 0 ||
        strncmp(path, "/proc/", 6) == 0)
        return 0;
    if (strcmp(path, "/sys") == 0 ||
        strncmp(path, "/sys/", 5) == 0)
        return 0;
    return 1;
}

static uint32_t vfs_path_hash(const char *path) {
    uint32_t hash = 2166136261u;
    while (path && *path) {
        hash ^= (uint8_t)*path++;
        hash *= 16777619u;
    }
    return hash;
}

int vfs_path_cache_runtime_set_allocator(
    const vfs_path_cache_allocator_t *allocator) {
    if (!allocator || !allocator->allocate_pages ||
        !allocator->release_pages || g_vfs_path_cache_count)
        return -1;
    g_vfs_path_cache_allocator = *allocator;
    return 0;
}

void vfs_path_cache_runtime_reset(void) {
    vfs_path_cache_entry_t *release = 0;
    uint64_t flags;

    vfs_path_cache_ensure_initialized();
    flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    for (uint32_t bucket = 0; bucket < VFS_PATH_CACHE_BUCKET_COUNT;
         ++bucket) {
        vfs_path_cache_entry_t *entry = g_vfs_path_cache[bucket];
        while (entry) {
            vfs_path_cache_entry_t *next = entry->next;
            entry->next = release;
            release = entry;
            entry = next;
        }
        g_vfs_path_cache[bucket] = 0;
    }
    g_vfs_path_cache_count = 0;
    g_vfs_path_cache_clock = 0;
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
    vfs_path_cache_release_list(release);
}

void vfs_path_cache_invalidate_all(void) {
    vfs_path_cache_entry_t *release = 0;
    uint64_t flags;

    vfs_path_cache_ensure_initialized();
    flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    for (uint32_t bucket = 0; bucket < VFS_PATH_CACHE_BUCKET_COUNT;
         ++bucket) {
        vfs_path_cache_entry_t *entry = g_vfs_path_cache[bucket];
        while (entry) {
            vfs_path_cache_entry_t *next = entry->next;
            entry->next = release;
            release = entry;
            entry = next;
        }
        g_vfs_path_cache[bucket] = 0;
    }
    g_vfs_path_cache_count = 0;
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
    vfs_path_cache_release_list(release);
}

int vfs_path_cache_runtime_lookup(
    const char *absolute_path, uint32_t namespace_id,
    vfs_path_cache_result_t *result) {
    uint32_t hash;
    uint32_t path_length;
    uint64_t flags;
    vfs_path_cache_entry_t *entry;

    if (!result || !vfs_path_cacheable(absolute_path)) return 0;
    vfs_path_cache_ensure_initialized();
    path_length = (uint32_t)strlen(absolute_path);
    if (path_length >= VFS_PATH_MAX) return 0;
    hash = vfs_path_hash(absolute_path);
    flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    entry = g_vfs_path_cache[hash % VFS_PATH_CACHE_BUCKET_COUNT];
    while (entry) {
        if (entry->path_hash == hash &&
            entry->namespace_id == namespace_id &&
            entry->path_length == path_length &&
            strcmp(entry->path, absolute_path) == 0) {
            entry->last_used = ++g_vfs_path_cache_clock;
            result->miss = entry->miss;
            result->superblock_index = entry->superblock_index;
            result->inode = entry->inode;
            spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
            return 1;
        }
        entry = entry->next;
    }
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
    return 0;
}

uint32_t vfs_path_cache_runtime_reclaim(uint32_t entry_count) {
    vfs_path_cache_entry_t *release = 0;
    uint32_t reclaimed = 0;

    vfs_path_cache_ensure_initialized();
    while (reclaimed < entry_count) {
        vfs_path_cache_entry_t **oldest_link = 0;
        uint64_t oldest_use = UINT64_MAX;
        uint64_t flags = spin_lock_irqsave(&g_vfs_path_cache_lock);

        for (uint32_t bucket = 0; bucket < VFS_PATH_CACHE_BUCKET_COUNT;
             ++bucket) {
            vfs_path_cache_entry_t **link = &g_vfs_path_cache[bucket];
            while (*link) {
                if ((*link)->last_used < oldest_use) {
                    oldest_use = (*link)->last_used;
                    oldest_link = link;
                }
                link = &(*link)->next;
            }
        }
        if (!oldest_link) {
            spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
            break;
        }
        vfs_path_cache_entry_t *entry = *oldest_link;
        *oldest_link = entry->next;
        entry->next = release;
        release = entry;
        --g_vfs_path_cache_count;
        ++reclaimed;
        spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
    }
    vfs_path_cache_release_list(release);
    return reclaimed;
}

uint32_t vfs_path_cache_runtime_count(void) {
    uint32_t count;
    vfs_path_cache_ensure_initialized();
    uint64_t flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    count = g_vfs_path_cache_count;
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
    return count;
}

void vfs_path_cache_runtime_store(
    const char *absolute_path, uint32_t namespace_id, int miss,
    const vfs_inode_t *inode, uint32_t superblock_index) {
    uint32_t hash;
    uint32_t path_length;
    uint32_t allocation_size;
    uint32_t page_count;
    uint64_t flags;
    vfs_path_cache_entry_t *entry;
    vfs_path_cache_entry_t *candidate;

    if (!vfs_path_cacheable(absolute_path)) return;
    if (!miss && !inode) return;
    vfs_path_cache_ensure_initialized();
    path_length = (uint32_t)strlen(absolute_path);
    if (path_length >= VFS_PATH_MAX) return;
    hash = vfs_path_hash(absolute_path);
    allocation_size = (uint32_t)sizeof(*candidate) + path_length + 1u;
    page_count = (allocation_size + VFS_PATH_CACHE_PAGE_SIZE - 1u) /
        VFS_PATH_CACHE_PAGE_SIZE;

    flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    entry = g_vfs_path_cache[hash % VFS_PATH_CACHE_BUCKET_COUNT];
    while (entry) {
        if (entry->path_hash == hash &&
            entry->namespace_id == namespace_id &&
            entry->path_length == path_length &&
            strcmp(entry->path, absolute_path) == 0) {
            entry->miss = miss ? 1u : 0u;
            entry->superblock_index = superblock_index;
            entry->last_used = ++g_vfs_path_cache_clock;
            if (!miss) entry->inode = *inode;
            spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
            return;
        }
        entry = entry->next;
    }
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);

    candidate = (vfs_path_cache_entry_t *)
        g_vfs_path_cache_allocator.allocate_pages(
            page_count, g_vfs_path_cache_allocator.context);
    if (!candidate) {
        (void)vfs_path_cache_runtime_reclaim(
            VFS_PATH_CACHE_RECLAIM_BATCH);
        candidate = (vfs_path_cache_entry_t *)
            g_vfs_path_cache_allocator.allocate_pages(
                page_count, g_vfs_path_cache_allocator.context);
    }
    if (!candidate) return;
    memset(candidate, 0, allocation_size);
    candidate->page_count = page_count;
    candidate->namespace_id = namespace_id;
    candidate->path_hash = hash;
    candidate->miss = miss ? 1u : 0u;
    candidate->superblock_index = superblock_index;
    candidate->path_length = (uint16_t)path_length;
    memcpy(candidate->path, absolute_path, path_length + 1u);
    if (!miss) candidate->inode = *inode;

    flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    entry = g_vfs_path_cache[hash % VFS_PATH_CACHE_BUCKET_COUNT];
    while (entry) {
        if (entry->path_hash == hash &&
            entry->namespace_id == namespace_id &&
            entry->path_length == path_length &&
            strcmp(entry->path, absolute_path) == 0) {
            entry->miss = candidate->miss;
            entry->superblock_index = candidate->superblock_index;
            entry->last_used = ++g_vfs_path_cache_clock;
            if (!miss) entry->inode = candidate->inode;
            spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
            candidate->next = 0;
            vfs_path_cache_release_list(candidate);
            return;
        }
        entry = entry->next;
    }
    candidate->last_used = ++g_vfs_path_cache_clock;
    candidate->next =
        g_vfs_path_cache[hash % VFS_PATH_CACHE_BUCKET_COUNT];
    g_vfs_path_cache[hash % VFS_PATH_CACHE_BUCKET_COUNT] = candidate;
    ++g_vfs_path_cache_count;
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
}

void vfs_path_cache_runtime_invalidate_absolute(
    const char *absolute_path) {
    vfs_path_cache_entry_t *release = 0;
    uint32_t hash;
    uint64_t flags;

    if (!vfs_path_cacheable(absolute_path)) return;
    vfs_path_cache_ensure_initialized();
    hash = vfs_path_hash(absolute_path);
    flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    vfs_path_cache_entry_t **link =
        &g_vfs_path_cache[hash % VFS_PATH_CACHE_BUCKET_COUNT];
    while (*link) {
        vfs_path_cache_entry_t *entry = *link;
        if (entry->path_hash == hash &&
            strcmp(entry->path, absolute_path) == 0) {
            *link = entry->next;
            entry->next = release;
            release = entry;
            --g_vfs_path_cache_count;
        } else {
            link = &entry->next;
        }
    }
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
    vfs_path_cache_release_list(release);
}

static int vfs_path_cache_entry_is_at_or_below(
    const char *path, const char *root, uint32_t root_length) {
    if (strncmp(path, root, root_length) != 0) return 0;
    if (root_length == 1u && root[0] == '/') return 1;
    return path[root_length] == 0 || path[root_length] == '/';
}

void vfs_path_cache_runtime_invalidate_subtree(
    const char *absolute_root) {
    vfs_path_cache_entry_t *release = 0;
    uint32_t root_length = 0;
    uint64_t flags;

    if (!absolute_root || absolute_root[0] != '/') return;
    vfs_path_cache_ensure_initialized();
    while (absolute_root[root_length]) ++root_length;
    while (root_length > 1u && absolute_root[root_length - 1u] == '/')
        --root_length;

    flags = spin_lock_irqsave(&g_vfs_path_cache_lock);
    for (uint32_t bucket = 0; bucket < VFS_PATH_CACHE_BUCKET_COUNT;
         ++bucket) {
        vfs_path_cache_entry_t **link = &g_vfs_path_cache[bucket];
        while (*link) {
            vfs_path_cache_entry_t *entry = *link;
            if (vfs_path_cache_entry_is_at_or_below(
                    entry->path, absolute_root, root_length)) {
                *link = entry->next;
                entry->next = release;
                release = entry;
                --g_vfs_path_cache_count;
            } else {
                link = &entry->next;
            }
        }
    }
    spin_unlock_irqrestore(&g_vfs_path_cache_lock, flags);
    vfs_path_cache_release_list(release);
}
