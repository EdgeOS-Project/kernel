/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS mount namespace implementation.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux mount namespaces copy the mount topology while retaining references
 * to the same underlying filesystem objects.  Keeping this storage in common
 * code prevents ARM64 and x86_64 from developing different mount isolation
 * and lifetime behavior.
 */

#include "vfs/mount_namespace.h"
#include "vfs/path_cache.h"
#include "kernel/smp.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/spinlock.h"

#define VFS_MOUNT_NAMESPACE_CPU_SLOTS 64u
#define VFS_MOUNT_NAMESPACE_INLINE_CAPACITY 8u
#define VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY 8u
#define VFS_FILESYSTEM_INSTANCE_INLINE_CAPACITY 8u
#define VFS_FILESYSTEM_INSTANCE_CHUNK_CAPACITY 8u
#define VFS_MOUNT_CHUNK_CAPACITY 4u
#define VFS_MOUNT_ALLOCATION_PAGE_SIZE 4096u
#define VFS_MOUNT_CHUNK_INDEX_CAPACITY \
    (VFS_MOUNT_ALLOCATION_PAGE_SIZE / sizeof(vfs_mount_chunk_t *))
#define VFS_MOUNT_ID_CACHE_CAPACITY \
    (VFS_MOUNT_ALLOCATION_PAGE_SIZE / sizeof(vfs_mount_id_cache_entry_t))
#define VFS_MOUNT_LOOKUP_CACHE_PAGES 16u
#define VFS_MOUNT_LOOKUP_CACHE_CAPACITY 128u
#define VFS_MOUNT_LOOKUP_PATH_CAPACITY 500u

enum {
    VFS_INSTANCE_SHUTDOWN_NONE = 0,
    VFS_INSTANCE_SHUTDOWN_RUNNING,
    VFS_INSTANCE_SHUTDOWN_COMPLETE,
    VFS_INSTANCE_SHUTDOWN_FAILED,
};

/*
 * A mount entry is topology state and is copied by bind mounts and namespace
 * cloning.  Open files and VM mappings instead need an address that remains
 * valid when those wrapper entries move or disappear.  This compact pool
 * provides that stable operation view and owns one backend reference for every
 * mount/open object that acquires it.
 *
 * The filesystem implementations currently expose fewer than 256 independent
 * backing instances in total, while namespace clones and bind mounts reuse an
 * existing entry.  The pool therefore exceeds the real backend capacity
 * without duplicating the 4 KiB mountpoint storage for every namespace slot.
 */
struct vfs_filesystem_instance {
    uint32_t used;
    uint32_t generation;
    uint32_t references;
    uint32_t pending_releases;
    uint32_t shutdown_state;
    vfs_superblock_t stable;
};

typedef struct vfs_filesystem_instance_chunk {
    struct vfs_filesystem_instance_chunk *next;
    uint32_t page_count;
    uint32_t capacity;
    vfs_filesystem_instance_t instances[];
} vfs_filesystem_instance_chunk_t;

struct vfs_mount_chunk {
    struct vfs_mount_chunk *next;
    uint32_t page_count;
    uint32_t capacity;
    uint32_t base_index;
    vfs_superblock_t mounts[];
};

struct vfs_mount_id_cache_entry {
    uint64_t mount_id;
    uint32_t table_index;
    uint32_t reserved;
};

typedef struct vfs_mount_lookup_cache_entry {
    volatile uint32_t lock;
    uint32_t event_generation;
    uint32_t table_index;
    char path[VFS_MOUNT_LOOKUP_PATH_CAPACITY];
} vfs_mount_lookup_cache_entry_t;

struct vfs_mount_lookup_cache {
    vfs_mount_lookup_cache_entry_t entries[
        VFS_MOUNT_LOOKUP_CACHE_CAPACITY];
};

_Static_assert(sizeof(vfs_mount_lookup_cache_t) <=
                   VFS_MOUNT_LOOKUP_CACHE_PAGES *
                       VFS_MOUNT_ALLOCATION_PAGE_SIZE,
               "mount lookup cache must fit in its allocation");

typedef struct vfs_mount_namespace_slot {
    vfs_mount_table_t table;
    uint32_t releasing;
    uint64_t list_id;
    uint32_t owner_user_namespace;
} vfs_mount_namespace_slot_t;

typedef struct vfs_mount_namespace_chunk {
    struct vfs_mount_namespace_chunk *next;
    uint32_t page_count;
    uint32_t capacity;
    vfs_mount_namespace_slot_t slots[];
} vfs_mount_namespace_chunk_t;

struct vfs_mount_root_reference {
    uint64_t references;
    vfs_superblock_t *stable;
    vfs_inode_t inode;
    struct vfs_mount_root_reference *next_free;
};

typedef struct vfs_mount_root_reference_chunk {
    struct vfs_mount_root_reference_chunk *next;
    uint32_t capacity;
    struct vfs_mount_root_reference roots[];
} vfs_mount_root_reference_chunk_t;

typedef struct filesystem_instance_release_action {
    vfs_filesystem_instance_t *instance;
    uint32_t generation;
    void (*callback)(void *private_data);
    void *private_data;
    struct vfs_mount_root_reference *root_reference;
} filesystem_instance_release_action_t;

static vfs_mount_namespace_slot_t
    g_mount_namespaces_inline[VFS_MOUNT_NAMESPACE_INLINE_CAPACITY];
static vfs_mount_namespace_chunk_t *g_mount_namespace_chunks;
static uint32_t g_active_namespace[VFS_MOUNT_NAMESPACE_CPU_SLOTS];
static vfs_filesystem_instance_t
    g_filesystem_instances_inline[VFS_FILESYSTEM_INSTANCE_INLINE_CAPACITY];
static vfs_filesystem_instance_chunk_t *g_filesystem_instance_chunks;
static vfs_mount_root_reference_chunk_t *g_mount_root_reference_chunks;
static struct vfs_mount_root_reference *g_mount_root_reference_free;
static volatile uint32_t g_mount_root_reference_lock;
static uint32_t g_filesystem_instance_generation;
static volatile uint32_t g_mount_namespace_lock;
static vfs_mount_namespace_change_notifier_t g_mount_change_notifier;

static void vfs_mount_table_release_storage(vfs_mount_table_t *table);
static void mount_namespace_lock(void);
static void mount_namespace_unlock(void);

static void mount_root_reference_lock(void) {
    while (__atomic_exchange_n(&g_mount_root_reference_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_mount_root_reference_lock,
                               __ATOMIC_RELAXED))
            spinlock_relax();
    }
}

static void mount_root_reference_unlock(void) {
    __atomic_store_n(&g_mount_root_reference_lock, 0u, __ATOMIC_RELEASE);
}

static uint32_t mount_allocation_page_count(uint64_t byte_count) {
    uint64_t pages;
    if (!byte_count) return 0;
    pages = (byte_count + VFS_MOUNT_ALLOCATION_PAGE_SIZE - 1u) /
        VFS_MOUNT_ALLOCATION_PAGE_SIZE;
    return pages > UINT32_MAX ? 0 : (uint32_t)pages;
}

static void mount_allocation_release(void *allocation, uint32_t page_count) {
    uint8_t *page = (uint8_t *)allocation;
    if (!allocation) return;
    for (uint32_t index = 0; index < page_count; ++index)
        arch_vm_free_page(
            page + (uint64_t)index * VFS_MOUNT_ALLOCATION_PAGE_SIZE);
}

static struct vfs_mount_root_reference *mount_root_reference_allocate(void) {
    struct vfs_mount_root_reference *root;
    vfs_mount_root_reference_chunk_t *chunk;
    uint32_t capacity;

    mount_root_reference_lock();
    root = g_mount_root_reference_free;
    if (root) {
        g_mount_root_reference_free = root->next_free;
        root->next_free = 0;
        mount_root_reference_unlock();
        return root;
    }
    mount_root_reference_unlock();

    chunk = (vfs_mount_root_reference_chunk_t *)arch_vm_alloc_pages(1u);
    if (!chunk) return 0;
    memset(chunk, 0, VFS_MOUNT_ALLOCATION_PAGE_SIZE);
    capacity = (VFS_MOUNT_ALLOCATION_PAGE_SIZE - sizeof(*chunk)) /
        sizeof(chunk->roots[0]);
    if (!capacity) {
        mount_allocation_release(chunk, 1u);
        return 0;
    }
    chunk->capacity = capacity;

    mount_root_reference_lock();
    chunk->next = g_mount_root_reference_chunks;
    g_mount_root_reference_chunks = chunk;
    for (uint32_t index = 1u; index < capacity; ++index) {
        chunk->roots[index].next_free = g_mount_root_reference_free;
        g_mount_root_reference_free = &chunk->roots[index];
    }
    root = &chunk->roots[0];
    mount_root_reference_unlock();
    return root;
}

static void mount_root_reference_release(
    struct vfs_mount_root_reference *root) {
    if (!root) return;
    memset(root, 0, sizeof(*root));
    mount_root_reference_lock();
    root->next_free = g_mount_root_reference_free;
    g_mount_root_reference_free = root;
    mount_root_reference_unlock();
}

static vfs_mount_namespace_slot_t *mount_namespace_slot_at(uint32_t index) {
    vfs_mount_namespace_chunk_t *chunk;

    if (index < VFS_MOUNT_NAMESPACE_INLINE_CAPACITY)
        return &g_mount_namespaces_inline[index];
    index -= VFS_MOUNT_NAMESPACE_INLINE_CAPACITY;
    for (chunk = __atomic_load_n(&g_mount_namespace_chunks,
                                 __ATOMIC_ACQUIRE);
         chunk;
         chunk = __atomic_load_n(&chunk->next, __ATOMIC_ACQUIRE)) {
        if (index < chunk->capacity) return &chunk->slots[index];
        index -= chunk->capacity;
    }
    return 0;
}

static uint32_t mount_namespace_capacity(void) {
    vfs_mount_namespace_chunk_t *chunk;
    uint32_t capacity = VFS_MOUNT_NAMESPACE_INLINE_CAPACITY;

    for (chunk = g_mount_namespace_chunks; chunk; chunk = chunk->next) {
        if (capacity > UINT32_MAX - chunk->capacity) return UINT32_MAX;
        capacity += chunk->capacity;
    }
    return capacity;
}

static int mount_namespace_reserve(uint32_t required_capacity) {
    vfs_mount_namespace_chunk_t **link;
    uint32_t capacity;

    capacity = mount_namespace_capacity();
    while (capacity < required_capacity) {
        uint64_t bytes = sizeof(vfs_mount_namespace_chunk_t) +
            (uint64_t)VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY *
                sizeof(vfs_mount_namespace_slot_t);
        uint32_t pages = mount_allocation_page_count(bytes);
        vfs_mount_namespace_chunk_t *chunk;

        if (!pages) return -1;
        /*
         * The physical allocator may invoke VFS metadata reclaim when a
         * suitably sized contiguous extent is fragmented.  Reclaim acquires
         * this namespace lock, so allocation while holding it deadlocks every
         * CPU once container mount namespaces grow beyond inline storage.
         * Allocate speculatively without the lock and reconcile after taking
         * it again.
         */
        mount_namespace_unlock();
        chunk = (vfs_mount_namespace_chunk_t *)arch_vm_alloc_pages(pages);
        mount_namespace_lock();
        if (!chunk) return -1;
        memset(chunk, 0,
               (uint64_t)pages * VFS_MOUNT_ALLOCATION_PAGE_SIZE);
        chunk->page_count = pages;
        chunk->capacity = VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY;

        capacity = VFS_MOUNT_NAMESPACE_INLINE_CAPACITY;
        link = &g_mount_namespace_chunks;
        while (*link) {
            if (capacity > UINT32_MAX - (*link)->capacity) {
                mount_namespace_unlock();
                mount_allocation_release(chunk, pages);
                mount_namespace_lock();
                return -1;
            }
            capacity += (*link)->capacity;
            link = &(*link)->next;
        }
        if (capacity >= required_capacity) {
            mount_namespace_unlock();
            mount_allocation_release(chunk, pages);
            mount_namespace_lock();
            return 0;
        }
        if (capacity > UINT32_MAX - VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY) {
            mount_namespace_unlock();
            mount_allocation_release(chunk, pages);
            mount_namespace_lock();
            return -1;
        }
        __atomic_store_n(link, chunk, __ATOMIC_RELEASE);
        capacity += chunk->capacity;
    }
    return 0;
}

static void mount_namespace_release_storage(void) {
    vfs_mount_namespace_chunk_t *chunk;
    uint32_t capacity = mount_namespace_capacity();

    for (uint32_t index = 0; index < capacity; ++index) {
        vfs_mount_namespace_slot_t *slot = mount_namespace_slot_at(index);
        if (slot) vfs_mount_table_release_storage(&slot->table);
    }
    chunk = g_mount_namespace_chunks;
    g_mount_namespace_chunks = 0;
    while (chunk) {
        vfs_mount_namespace_chunk_t *next = chunk->next;
        mount_allocation_release(chunk, chunk->page_count);
        chunk = next;
    }
}

vfs_superblock_t *vfs_mount_table_at(vfs_mount_table_t *table,
                                     uint32_t index) {
    vfs_mount_chunk_t *chunk;
    if (!table) return 0;
    if (index < VFS_MOUNT_TABLE_INLINE_CAPACITY)
        return &table->inline_mounts[index];
    uint32_t chunk_number =
        (index - VFS_MOUNT_TABLE_INLINE_CAPACITY) /
        VFS_MOUNT_CHUNK_CAPACITY;
    uint32_t indexed = __atomic_load_n(
        &table->chunk_index_count, __ATOMIC_ACQUIRE);
    if (table->chunk_index && chunk_number < indexed) {
        chunk = __atomic_load_n(
            &table->chunk_index[chunk_number], __ATOMIC_ACQUIRE);
        if (chunk && index >= chunk->base_index &&
            index < chunk->base_index + chunk->capacity)
            return &chunk->mounts[index - chunk->base_index];
    }
    chunk = table->chunk_index && indexed ?
        __atomic_load_n(&table->chunk_index[indexed - 1u],
                        __ATOMIC_ACQUIRE) :
        table->overflow;
    while (chunk && index >= chunk->base_index + chunk->capacity)
        chunk = chunk->next;
    if (chunk && index >= chunk->base_index) {
        return &chunk->mounts[index - chunk->base_index];
    }
    return 0;
}

const vfs_superblock_t *vfs_mount_table_at_const(
    const vfs_mount_table_t *table, uint32_t index) {
    const vfs_mount_chunk_t *chunk;
    if (!table) return 0;
    if (index < VFS_MOUNT_TABLE_INLINE_CAPACITY)
        return &table->inline_mounts[index];
    uint32_t chunk_number =
        (index - VFS_MOUNT_TABLE_INLINE_CAPACITY) /
        VFS_MOUNT_CHUNK_CAPACITY;
    uint32_t indexed = __atomic_load_n(
        &table->chunk_index_count, __ATOMIC_ACQUIRE);
    if (table->chunk_index && chunk_number < indexed) {
        chunk = __atomic_load_n(
            &table->chunk_index[chunk_number], __ATOMIC_ACQUIRE);
        if (chunk && index >= chunk->base_index &&
            index < chunk->base_index + chunk->capacity)
            return &chunk->mounts[index - chunk->base_index];
    }
    chunk = table->chunk_index && indexed ?
        __atomic_load_n(&table->chunk_index[indexed - 1u],
                        __ATOMIC_ACQUIRE) :
        table->overflow;
    while (chunk && index >= chunk->base_index + chunk->capacity)
        chunk = chunk->next;
    if (chunk && index >= chunk->base_index) {
        return &chunk->mounts[index - chunk->base_index];
    }
    return 0;
}

vfs_superblock_t *vfs_mount_table_find_id(vfs_mount_table_t *table,
                                          uint64_t mount_id) {
    vfs_mount_id_cache_entry_t *entry;
    vfs_superblock_t *mount;
    uint32_t low;
    uint32_t high;
    uint32_t slot;

    if (!table || !mount_id) return 0;
    slot = (uint32_t)(mount_id % VFS_MOUNT_ID_CACHE_CAPACITY);
    entry = table->mount_id_cache ? &table->mount_id_cache[slot] : 0;
    if (entry &&
        __atomic_load_n(&entry->mount_id, __ATOMIC_ACQUIRE) == mount_id) {
        uint32_t index = __atomic_load_n(
            &entry->table_index, __ATOMIC_RELAXED);
        mount = index < (uint32_t)table->mount_count ?
            vfs_mount_table_at(table, index) : 0;
        if (mount && mount->mount_id == mount_id) return mount;
    }
    /* Mount IDs increase on append, and removal preserves table order. */
    low = 0;
    high = (uint32_t)table->mount_count;
    while (low < high) {
        uint32_t index = low + (high - low) / 2u;

        mount = vfs_mount_table_at(table, index);
        if (!mount) break;
        if (mount->mount_id < mount_id) {
            low = index + 1u;
            continue;
        }
        if (mount->mount_id > mount_id) {
            high = index;
            continue;
        }
        if (entry) {
            __atomic_store_n(&entry->mount_id, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&entry->table_index, index,
                             __ATOMIC_RELAXED);
            __atomic_store_n(&entry->mount_id, mount_id,
                             __ATOMIC_RELEASE);
        }
        return mount;
    }
    return 0;
}

const vfs_superblock_t *vfs_mount_table_find_id_const(
    const vfs_mount_table_t *table, uint64_t mount_id) {
    return vfs_mount_table_find_id((vfs_mount_table_t *)table, mount_id);
}

static void vfs_mount_table_link_mount(vfs_mount_table_t *table,
                                       vfs_superblock_t *mount) {
    vfs_superblock_t *parent;

    if (!table || !mount || !mount->mount_id) return;
    mount->previous_sibling_mount_id = 0;
    if (!mount->parent_mount_id) {
        if (strcmp(mount->mountpoint, "/") == 0)
            table->root_mount_id = mount->mount_id;
        return;
    }
    parent = vfs_mount_table_find_id(table, mount->parent_mount_id);
    if (!parent) return;
    mount->previous_sibling_mount_id = parent->latest_child_mount_id;
    parent->latest_child_mount_id = mount->mount_id;
}

void vfs_mount_table_link_latest(vfs_mount_table_t *table,
                                 vfs_superblock_t *mount) {
    if (!mount) return;
    mount->latest_child_mount_id = 0;
    vfs_mount_table_link_mount(table, mount);
}

void vfs_mount_table_rebuild_child_links(vfs_mount_table_t *table) {
    vfs_superblock_t *mount;

    if (!table) return;
    table->root_mount_id = 0;
    for (int index = 0; index < table->mount_count; ++index) {
        mount = vfs_mount_table_at(table, (uint32_t)index);
        if (!mount) continue;
        mount->latest_child_mount_id = 0;
        mount->previous_sibling_mount_id = 0;
    }
    for (int index = 0; index < table->mount_count; ++index) {
        mount = vfs_mount_table_at(table, (uint32_t)index);
        if (mount) vfs_mount_table_link_mount(table, mount);
    }
}

int vfs_mount_table_lookup_cache_get(vfs_mount_table_t *table,
                                     const char *path,
                                     uint32_t *table_index) {
    vfs_mount_lookup_cache_t *cache;
    vfs_mount_lookup_cache_entry_t *entry;
    uint32_t hash = 2166136261u;
    uint32_t generation;
    uint64_t length;
    int hit = 0;

    if (!table || !path || !table_index) return 0;
    length = strlen(path);
    if (length >= VFS_MOUNT_LOOKUP_PATH_CAPACITY) return 0;
    cache = __atomic_load_n(&table->mount_lookup_cache, __ATOMIC_ACQUIRE);
    if (!cache) return 0;
    for (uint64_t index = 0; index < length; ++index) {
        hash ^= (uint8_t)path[index];
        hash *= 16777619u;
    }
    entry = &cache->entries[hash % VFS_MOUNT_LOOKUP_CACHE_CAPACITY];
    while (__atomic_exchange_n(&entry->lock, 1u, __ATOMIC_ACQUIRE))
        spinlock_relax();
    generation = __atomic_load_n(
        &table->event_generation, __ATOMIC_ACQUIRE);
    if (entry->event_generation == generation &&
        entry->table_index < (uint32_t)table->mount_count &&
        strcmp(entry->path, path) == 0) {
        *table_index = entry->table_index;
        hit = 1;
    }
    __atomic_store_n(&entry->lock, 0u, __ATOMIC_RELEASE);
    return hit;
}

void vfs_mount_table_lookup_cache_store(vfs_mount_table_t *table,
                                        const char *path,
                                        uint32_t table_index) {
    vfs_mount_lookup_cache_t *cache;
    vfs_mount_lookup_cache_entry_t *entry;
    uint32_t hash = 2166136261u;
    uint64_t length;

    if (!table || !path || table_index >= (uint32_t)table->mount_count)
        return;
    length = strlen(path);
    if (length >= VFS_MOUNT_LOOKUP_PATH_CAPACITY) return;
    cache = __atomic_load_n(&table->mount_lookup_cache, __ATOMIC_ACQUIRE);
    if (!cache) return;
    for (uint64_t index = 0; index < length; ++index) {
        hash ^= (uint8_t)path[index];
        hash *= 16777619u;
    }
    entry = &cache->entries[hash % VFS_MOUNT_LOOKUP_CACHE_CAPACITY];
    while (__atomic_exchange_n(&entry->lock, 1u, __ATOMIC_ACQUIRE))
        spinlock_relax();
    memcpy(entry->path, path, length + 1u);
    entry->table_index = table_index;
    entry->event_generation = __atomic_load_n(
        &table->event_generation, __ATOMIC_ACQUIRE);
    __atomic_store_n(&entry->lock, 0u, __ATOMIC_RELEASE);
}

void vfs_mount_table_lookup_cache_invalidate(vfs_mount_table_t *table) {
    uint32_t generation;

    if (!table) return;
    generation = __atomic_add_fetch(
        &table->event_generation, 1u, __ATOMIC_ACQ_REL);
    if (!generation)
        __atomic_store_n(
            &table->event_generation, 1u, __ATOMIC_RELEASE);
}

static int mount_lookup_path_is_at_or_below(const char *path,
                                             const char *root) {
    uint64_t root_length;

    if (!path || !root || path[0] != '/' || root[0] != '/') return 0;
    root_length = strlen(root);
    while (root_length > 1u && root[root_length - 1u] == '/')
        --root_length;
    if (strncmp(path, root, root_length) != 0) return 0;
    return root_length == 1u || path[root_length] == 0 ||
           path[root_length] == '/';
}

void vfs_mount_table_lookup_cache_invalidate_subtree(
    vfs_mount_table_t *table, const char *path) {
    vfs_mount_lookup_cache_t *cache;
    uint32_t previous;
    uint32_t next;

    if (!table || !path || path[0] != '/') {
        vfs_mount_table_lookup_cache_invalidate(table);
        return;
    }
    previous = __atomic_load_n(
        &table->event_generation, __ATOMIC_ACQUIRE);
    next = previous + 1u;
    if (!next) next = 1u;
    cache = __atomic_load_n(&table->mount_lookup_cache, __ATOMIC_ACQUIRE);
    if (cache) {
        for (uint32_t index = 0;
             index < VFS_MOUNT_LOOKUP_CACHE_CAPACITY; ++index) {
            vfs_mount_lookup_cache_entry_t *entry = &cache->entries[index];

            while (__atomic_exchange_n(&entry->lock, 1u,
                                       __ATOMIC_ACQUIRE))
                spinlock_relax();
            if (entry->event_generation == previous && entry->path[0]) {
                entry->event_generation =
                    mount_lookup_path_is_at_or_below(entry->path, path) ?
                        0u : next;
            }
            __atomic_store_n(&entry->lock, 0u, __ATOMIC_RELEASE);
        }
    }
    __atomic_store_n(&table->event_generation, next, __ATOMIC_RELEASE);
}

void vfs_mount_table_iterator_begin(vfs_mount_table_t *table,
                                    vfs_mount_table_iterator_t *iterator) {
    if (!iterator) return;
    memset(iterator, 0, sizeof(*iterator));
    iterator->table = table;
}

vfs_superblock_t *vfs_mount_table_iterator_next(
    vfs_mount_table_iterator_t *iterator, uint32_t *index_out) {
    vfs_superblock_t *mount;
    uint32_t index;

    if (!iterator || !iterator->table ||
        iterator->table->mount_count < 0 ||
        iterator->index >= (uint32_t)iterator->table->mount_count)
        return 0;
    index = iterator->index++;
    if (index < VFS_MOUNT_TABLE_INLINE_CAPACITY) {
        mount = &iterator->table->inline_mounts[index];
    } else {
        if (!iterator->chunk) {
            iterator->chunk = iterator->table->overflow;
            iterator->chunk_index = 0;
        }
        while (iterator->chunk &&
               iterator->chunk_index >= iterator->chunk->capacity) {
            iterator->chunk = iterator->chunk->next;
            iterator->chunk_index = 0;
        }
        if (!iterator->chunk) return 0;
        mount = &iterator->chunk->mounts[iterator->chunk_index++];
    }
    if (index_out) *index_out = index;
    return mount;
}

static uint32_t vfs_mount_table_capacity(const vfs_mount_table_t *table) {
    const vfs_mount_chunk_t *chunk;
    uint32_t capacity = VFS_MOUNT_TABLE_INLINE_CAPACITY;
    if (!table) return 0;
    if (table->capacity >= VFS_MOUNT_TABLE_INLINE_CAPACITY)
        return table->capacity;
    for (chunk = table->overflow; chunk; chunk = chunk->next) {
        if (capacity > UINT32_MAX - chunk->capacity) return UINT32_MAX;
        capacity += chunk->capacity;
    }
    return capacity;
}

int vfs_mount_table_reserve(vfs_mount_table_t *table,
                            uint32_t required_capacity) {
    vfs_mount_chunk_t **link;
    uint32_t capacity;

    if (!table) return -1;
    capacity = vfs_mount_table_capacity(table);
    if (capacity < required_capacity && !table->chunk_index) {
        vfs_mount_chunk_t **index =
            (vfs_mount_chunk_t **)arch_vm_alloc_pages(1u);
        if (index) {
            memset(index, 0, VFS_MOUNT_ALLOCATION_PAGE_SIZE);
            __atomic_store_n(&table->chunk_index, index,
                             __ATOMIC_RELEASE);
        }
    }
    if (capacity < required_capacity && !table->mount_id_cache) {
        vfs_mount_id_cache_entry_t *cache =
            (vfs_mount_id_cache_entry_t *)arch_vm_alloc_pages(1u);
        if (cache) {
            memset(cache, 0, VFS_MOUNT_ALLOCATION_PAGE_SIZE);
            __atomic_store_n(&table->mount_id_cache, cache,
                             __ATOMIC_RELEASE);
        }
    }
    if (required_capacity > VFS_MOUNT_TABLE_INLINE_CAPACITY &&
        !table->mount_lookup_cache) {
        vfs_mount_lookup_cache_t *cache =
            (vfs_mount_lookup_cache_t *)arch_vm_alloc_pages(
                VFS_MOUNT_LOOKUP_CACHE_PAGES);
        if (cache) {
            memset(cache, 0,
                   VFS_MOUNT_LOOKUP_CACHE_PAGES *
                       VFS_MOUNT_ALLOCATION_PAGE_SIZE);
            __atomic_store_n(&table->mount_lookup_cache, cache,
                             __ATOMIC_RELEASE);
        }
    }
    link = table->overflow_tail ? &table->overflow_tail->next :
                                  &table->overflow;
    /*
     * Four stable wrappers keep lookup chains short while avoiding the large
     * contiguous extents that made namespace growth fail under container
     * memory fragmentation.
     */
    while (capacity < required_capacity) {
        uint64_t bytes = sizeof(vfs_mount_chunk_t) +
            (uint64_t)VFS_MOUNT_CHUNK_CAPACITY * sizeof(vfs_superblock_t);
        uint32_t pages = mount_allocation_page_count(bytes);
        vfs_mount_chunk_t *chunk;
        if (!pages) return -1;
        chunk = (vfs_mount_chunk_t *)arch_vm_alloc_pages(pages);
        if (!chunk) return -1;
        memset(chunk, 0,
               (uint64_t)pages * VFS_MOUNT_ALLOCATION_PAGE_SIZE);
        chunk->page_count = pages;
        chunk->capacity = VFS_MOUNT_CHUNK_CAPACITY;
        chunk->base_index = capacity;
        *link = chunk;
        link = &chunk->next;
        table->overflow_tail = chunk;
        if (table->chunk_index &&
            table->chunk_index_count < VFS_MOUNT_CHUNK_INDEX_CAPACITY) {
            uint32_t index = table->chunk_index_count;
            __atomic_store_n(&table->chunk_index[index], chunk,
                             __ATOMIC_RELEASE);
            __atomic_store_n(&table->chunk_index_count, index + 1u,
                             __ATOMIC_RELEASE);
        }
        if (capacity > UINT32_MAX - chunk->capacity) return -1;
        capacity += chunk->capacity;
    }
    table->capacity = capacity;
    return 0;
}

static void vfs_mount_table_release_storage(vfs_mount_table_t *table) {
    vfs_mount_chunk_t *chunk;
    if (!table) return;
    chunk = table->overflow;
    table->overflow = 0;
    table->overflow_tail = 0;
    if (table->chunk_index)
        mount_allocation_release(table->chunk_index, 1u);
    if (table->mount_id_cache)
        mount_allocation_release(table->mount_id_cache, 1u);
    if (table->mount_lookup_cache)
        mount_allocation_release(table->mount_lookup_cache,
                                 VFS_MOUNT_LOOKUP_CACHE_PAGES);
    table->chunk_index = 0;
    table->chunk_index_count = 0;
    table->mount_id_cache = 0;
    table->mount_lookup_cache = 0;
    table->capacity = 0;
    while (chunk) {
        vfs_mount_chunk_t *next = chunk->next;
        mount_allocation_release(chunk, chunk->page_count);
        chunk = next;
    }
}

char *vfs_mount_path_workspace_allocate(uint32_t path_count,
                                        uint32_t *page_count_out) {
    uint64_t bytes;
    uint32_t pages;
    char *workspace;
    if (!page_count_out || !path_count)
        return 0;
    bytes = (uint64_t)path_count * VFS_PATH_MAX;
    pages = mount_allocation_page_count(bytes);
    if (!pages) return 0;
    workspace = (char *)arch_vm_alloc_pages(pages);
    if (!workspace) return 0;
    memset(workspace, 0,
           (uint64_t)pages * VFS_MOUNT_ALLOCATION_PAGE_SIZE);
    *page_count_out = pages;
    return workspace;
}

void vfs_mount_path_workspace_release(char *workspace,
                                      uint32_t page_count) {
    mount_allocation_release(workspace, page_count);
}

static uint32_t mount_namespace_cpu_slot(void) {
    uint32_t cpu = edge_smp_current_cpu();
    if (cpu >= VFS_MOUNT_NAMESPACE_CPU_SLOTS) cpu = 0;
    return cpu;
}

static void mount_namespace_lock(void) {
    while (__atomic_exchange_n(&g_mount_namespace_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_mount_namespace_lock, __ATOMIC_RELAXED)) {
            spinlock_relax();
        }
    }
}

static void mount_namespace_unlock(void) {
    __atomic_store_n(&g_mount_namespace_lock, 0u, __ATOMIC_RELEASE);
}

static vfs_filesystem_instance_t *filesystem_instance_at(uint32_t index) {
    vfs_filesystem_instance_chunk_t *chunk;

    if (index < VFS_FILESYSTEM_INSTANCE_INLINE_CAPACITY)
        return &g_filesystem_instances_inline[index];
    index -= VFS_FILESYSTEM_INSTANCE_INLINE_CAPACITY;
    for (chunk = g_filesystem_instance_chunks; chunk; chunk = chunk->next) {
        if (index < chunk->capacity) return &chunk->instances[index];
        index -= chunk->capacity;
    }
    return 0;
}

/* g_mount_namespace_lock is held. */
static vfs_filesystem_instance_t *filesystem_instance_grow_locked(void) {
    vfs_filesystem_instance_chunk_t **link;
    vfs_filesystem_instance_chunk_t *chunk;
    uint64_t bytes;
    uint32_t pages;

    bytes = sizeof(*chunk) +
        (uint64_t)VFS_FILESYSTEM_INSTANCE_CHUNK_CAPACITY *
            sizeof(vfs_filesystem_instance_t);
    pages = mount_allocation_page_count(bytes);
    if (!pages) return 0;
    mount_namespace_unlock();
    chunk = (vfs_filesystem_instance_chunk_t *)arch_vm_alloc_pages(pages);
    mount_namespace_lock();
    if (!chunk) return 0;
    memset(chunk, 0,
           (uint64_t)pages * VFS_MOUNT_ALLOCATION_PAGE_SIZE);
    chunk->page_count = pages;
    chunk->capacity = VFS_FILESYSTEM_INSTANCE_CHUNK_CAPACITY;

    link = &g_filesystem_instance_chunks;
    while (*link) link = &(*link)->next;
    *link = chunk;
    return &chunk->instances[0];
}

static void filesystem_instance_release_storage(void) {
    vfs_filesystem_instance_chunk_t *chunk =
        g_filesystem_instance_chunks;

    g_filesystem_instance_chunks = 0;
    while (chunk) {
        vfs_filesystem_instance_chunk_t *next = chunk->next;
        mount_allocation_release(chunk, chunk->page_count);
        chunk = next;
    }
}

static int filesystem_instance_pointer_valid(
    const vfs_filesystem_instance_t *instance) {
    uintptr_t address = (uintptr_t)instance;
    uintptr_t first = (uintptr_t)&g_filesystem_instances_inline[0];
    uintptr_t last = (uintptr_t)&g_filesystem_instances_inline[
        VFS_FILESYSTEM_INSTANCE_INLINE_CAPACITY];
    vfs_filesystem_instance_chunk_t *chunk;

    if (address >= first && address < last &&
        (address - first) % sizeof(g_filesystem_instances_inline[0]) == 0)
        return 1;
    for (chunk = g_filesystem_instance_chunks; chunk; chunk = chunk->next) {
        first = (uintptr_t)&chunk->instances[0];
        last = (uintptr_t)&chunk->instances[chunk->capacity];
        if (address >= first && address < last &&
            (address - first) % sizeof(chunk->instances[0]) == 0)
            return 1;
    }
    return 0;
}

static int filesystem_instance_matches(
    const vfs_filesystem_instance_t *instance, uint32_t generation) {
    return filesystem_instance_pointer_valid(instance) &&
           __atomic_load_n(&instance->used, __ATOMIC_ACQUIRE) &&
           __atomic_load_n(&instance->generation, __ATOMIC_ACQUIRE) ==
               generation &&
           __atomic_load_n(&instance->references, __ATOMIC_ACQUIRE);
}

/* g_mount_namespace_lock is held. */
static vfs_filesystem_instance_t *filesystem_instance_allocate_locked(
    const vfs_superblock_t *source) {
    vfs_filesystem_instance_t *instance = 0;
    uint32_t generation;

    if (!source) return 0;
    for (uint32_t index = 0; ; ++index) {
        vfs_filesystem_instance_t *candidate =
            filesystem_instance_at(index);
        if (!candidate) break;
        if (candidate->used) continue;
        instance = candidate;
        break;
    }
    if (!instance) instance = filesystem_instance_grow_locked();
    if (!instance) return 0;

    generation = ++g_filesystem_instance_generation;
    if (!generation) generation = ++g_filesystem_instance_generation;
    memset(instance, 0, sizeof(*instance));
    instance->used = 1u;
    instance->generation = generation;
    instance->stable = *source;
    instance->stable.root_reference = 0;
    instance->stable.instance = instance;
    instance->stable.instance_generation = generation;
    return instance;
}

/* g_mount_namespace_lock is held. */
static vfs_superblock_t *filesystem_instance_acquire_locked(
    vfs_superblock_t *sb) {
    vfs_filesystem_instance_t *instance;

    if (!sb) return 0;
    instance = sb->instance;
    /*
     * A final backend release runs outside this lock.  A filesystem such as
     * anonymous tmpfs may be acquired again before that callback completes.
     * Reuse the retiring identity in that window: its pending backend
     * reference still keeps fs_private alive, and allocating a second stable
     * identity would make sync/shutdown run twice for one filesystem.
     */
    if (!filesystem_instance_pointer_valid(instance) ||
        !instance->used ||
        instance->generation != sb->instance_generation ||
        (!instance->references && !instance->pending_releases)) {
        instance = filesystem_instance_allocate_locked(sb);
        if (!instance) return 0;
        sb->instance = instance;
        sb->instance_generation = instance->generation;
    }
    if (instance->references == UINT32_MAX) return 0;
    ++instance->references;
    if (instance->stable.retain)
        instance->stable.retain(instance->stable.fs_private);
    return &instance->stable;
}

/*
 * Prepare a release while g_mount_namespace_lock is held.  Backend release
 * callbacks may take filesystem-private locks and must run after dropping the
 * namespace lock.  pending_releases keeps the stable identity unavailable for
 * reuse until every deferred callback has returned.
 */
static int filesystem_instance_release_prepare_locked(
    vfs_superblock_t *sb, filesystem_instance_release_action_t *action) {
    vfs_filesystem_instance_t *instance;

    if (!sb || !action) return -1;
    memset(action, 0, sizeof(*action));
    instance = sb->instance;
    if (!filesystem_instance_matches(instance, sb->instance_generation))
        return -1;
    if (instance->pending_releases == UINT32_MAX) return -1;
    --instance->references;
    ++instance->pending_releases;
    action->instance = instance;
    action->generation = instance->generation;
    action->callback = instance->stable.release;
    action->private_data = instance->stable.fs_private;
    return 0;
}

static void filesystem_instance_release_complete(
    const filesystem_instance_release_action_t *action) {
    vfs_filesystem_instance_t *instance;

    if (!action || !action->instance) return;
    if (action->root_reference &&
        __atomic_sub_fetch(&action->root_reference->references, 1u,
                           __ATOMIC_ACQ_REL) == 0u) {
        struct vfs_mount_root_reference *root = action->root_reference;
        if (root->stable->ops && root->stable->ops->inode_close)
            root->stable->ops->inode_close(root->stable, &root->inode);
        mount_root_reference_release(root);
    }
    if (action->callback) action->callback(action->private_data);

    mount_namespace_lock();
    instance = action->instance;
    if (filesystem_instance_pointer_valid(instance) && instance->used &&
        instance->generation == action->generation &&
        instance->pending_releases) {
        --instance->pending_releases;
        if (!instance->references && !instance->pending_releases) {
            /*
             * Wrapper generations prevent stale pointers from matching a
             * later occupant.  Reuse is delayed until the final backend
             * callback has completed, so private storage cannot be recycled
             * while the stable operation view still identifies it.
             */
            memset(instance, 0, sizeof(*instance));
        }
    }
    mount_namespace_unlock();
}

vfs_superblock_t *vfs_superblock_acquire(vfs_superblock_t *sb) {
    vfs_superblock_t *stable;
    mount_namespace_lock();
    stable = filesystem_instance_acquire_locked(sb);
    mount_namespace_unlock();
    return stable;
}

void vfs_superblock_release(vfs_superblock_t *sb) {
    filesystem_instance_release_action_t action;

    mount_namespace_lock();
    if (filesystem_instance_release_prepare_locked(sb, &action) < 0) {
        mount_namespace_unlock();
        return;
    }
    mount_namespace_unlock();
    filesystem_instance_release_complete(&action);
}

/* Mount roots outlive the descriptor or pathname used to create a bind. */
vfs_superblock_t *vfs_mount_acquire(vfs_superblock_t *sb) {
    vfs_superblock_t *stable = vfs_superblock_acquire(sb);
    struct vfs_mount_root_reference *root;

    if (!stable) return 0;
    if (sb->root_reference) {
        __atomic_add_fetch(&sb->root_reference->references, 1u,
                           __ATOMIC_RELAXED);
        return stable;
    }
    if (!stable->ops || !stable->ops->inode_open) return stable;
    root = mount_root_reference_allocate();
    if (!root) {
        vfs_superblock_release(stable);
        return 0;
    }
    if (stable->ops->inode_open(stable, &sb->root) < 0) {
        mount_root_reference_release(root);
        vfs_superblock_release(stable);
        return 0;
    }
    root->references = 1u;
    root->stable = stable;
    root->inode = sb->root;
    sb->root_reference = root;
    return stable;
}

static int mount_release_prepare_locked(
    vfs_superblock_t *sb, filesystem_instance_release_action_t *action) {
    if (filesystem_instance_release_prepare_locked(sb, action) < 0)
        return -1;
    action->root_reference = sb->root_reference;
    return 0;
}

void vfs_mount_release(vfs_superblock_t *sb) {
    filesystem_instance_release_action_t action;
    mount_namespace_lock();
    if (mount_release_prepare_locked(sb, &action) < 0) {
        mount_namespace_unlock();
        return;
    }
    mount_namespace_unlock();
    filesystem_instance_release_complete(&action);
}

const vfs_superblock_t *vfs_superblock_stable_const(
    const vfs_superblock_t *sb) {
    const vfs_filesystem_instance_t *instance;
    if (!sb) return 0;
    instance = sb->instance;
    if ((uintptr_t)sb >=
            __builtin_offsetof(vfs_filesystem_instance_t, stable) &&
        (uintptr_t)instance ==
            (uintptr_t)sb -
                __builtin_offsetof(vfs_filesystem_instance_t, stable))
        return sb;
    if (!filesystem_instance_matches(instance, sb->instance_generation))
        return sb;
    return &instance->stable;
}

vfs_superblock_t *vfs_superblock_stable(vfs_superblock_t *sb) {
    return (vfs_superblock_t *)vfs_superblock_stable_const(sb);
}

const void *vfs_superblock_identity(const vfs_superblock_t *sb) {
    return vfs_superblock_stable_const(sb);
}

int vfs_filesystem_sync_all(void) {
    int result = 0;

    for (uint32_t index = 0; ; ++index) {
        vfs_filesystem_instance_t *instance =
            filesystem_instance_at(index);
        vfs_superblock_t *stable = 0;

        if (!instance) break;
        mount_namespace_lock();
        if (instance->used && instance->references) {
            stable = filesystem_instance_acquire_locked(
                &instance->stable);
        }
        mount_namespace_unlock();
        if (!stable) continue;
        if (stable->ops && stable->ops->sync &&
            stable->ops->sync(stable) < 0)
            result = -1;
        vfs_superblock_release(stable);
    }
    return result;
}

uint32_t vfs_filesystem_reclaim_metadata(uint32_t page_count) {
    uint32_t reclaimed = 0;

    if (!page_count) return 0;
    for (uint32_t index = 0; reclaimed < page_count; ++index) {
        vfs_filesystem_instance_t *instance =
            filesystem_instance_at(index);
        vfs_superblock_t *stable = 0;

        if (!instance) break;
        mount_namespace_lock();
        if (instance->used && instance->references) {
            stable = filesystem_instance_acquire_locked(
                &instance->stable);
        }
        mount_namespace_unlock();
        if (!stable) continue;
        if (stable->ops && stable->ops->reclaim_metadata) {
            reclaimed += stable->ops->reclaim_metadata(
                stable, page_count - reclaimed);
        }
        vfs_superblock_release(stable);
    }
    return reclaimed;
}

int vfs_filesystem_shutdown_all(void) {
    int result = 0;

    for (uint32_t index = 0; ; ++index) {
        vfs_filesystem_instance_t *instance =
            filesystem_instance_at(index);
        vfs_superblock_t *stable = 0;
        int callback_result = 0;

        if (!instance) break;
        mount_namespace_lock();
        if (!instance->used || !instance->references) {
            mount_namespace_unlock();
            continue;
        }
        if (instance->shutdown_state == VFS_INSTANCE_SHUTDOWN_COMPLETE) {
            mount_namespace_unlock();
            continue;
        }
        if (instance->shutdown_state != VFS_INSTANCE_SHUTDOWN_NONE) {
            result = -1;
            mount_namespace_unlock();
            continue;
        }
        instance->shutdown_state = VFS_INSTANCE_SHUTDOWN_RUNNING;
        stable = filesystem_instance_acquire_locked(&instance->stable);
        mount_namespace_unlock();
        if (!stable) {
            mount_namespace_lock();
            if (instance->used &&
                instance->shutdown_state == VFS_INSTANCE_SHUTDOWN_RUNNING)
                instance->shutdown_state = VFS_INSTANCE_SHUTDOWN_FAILED;
            mount_namespace_unlock();
            result = -1;
            continue;
        }

        if (stable->ops && stable->ops->shutdown)
            callback_result = stable->ops->shutdown(stable);

        mount_namespace_lock();
        if (filesystem_instance_matches(
                instance, stable->instance_generation)) {
            instance->shutdown_state = callback_result < 0 ?
                VFS_INSTANCE_SHUTDOWN_FAILED :
                VFS_INSTANCE_SHUTDOWN_COMPLETE;
        }
        mount_namespace_unlock();
        vfs_superblock_release(stable);
        if (callback_result < 0) result = -1;
    }
    return result;
}

void vfs_mount_namespace_bootstrap(void) {
    mount_namespace_release_storage();
    memset(g_mount_namespaces_inline, 0,
           sizeof(g_mount_namespaces_inline));
    memset(g_active_namespace, 0, sizeof(g_active_namespace));
    filesystem_instance_release_storage();
    memset(g_filesystem_instances_inline, 0,
           sizeof(g_filesystem_instances_inline));
    g_filesystem_instance_generation = 0;
    g_mount_namespaces_inline[0].table.next_peer_group = 1u;
    g_mount_namespaces_inline[0].table.next_mount_id = 1u;
    g_mount_namespaces_inline[0].table.event_generation = 1u;
    g_mount_namespaces_inline[0].list_id = 8u;
    g_mount_namespaces_inline[0].owner_user_namespace = 0u;
    /* The initial kernel task owns this reference. */
    g_mount_namespaces_inline[0].table.references = 1u;
    __atomic_store_n(&g_mount_namespace_lock, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&g_mount_change_notifier, 0, __ATOMIC_RELEASE);
}

vfs_mount_table_t *vfs_mount_namespace_active_table(void) {
    uint32_t namespace_id = __atomic_load_n(
        &g_active_namespace[mount_namespace_cpu_slot()], __ATOMIC_ACQUIRE);
    vfs_mount_namespace_slot_t *slot =
        mount_namespace_slot_at(namespace_id);

    if (!slot ||
        __atomic_load_n(&slot->releasing, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&slot->table.references, __ATOMIC_ACQUIRE))
        slot = &g_mount_namespaces_inline[0];
    return &slot->table;
}

int vfs_mount_namespace_uses_initial_root(void) {
    const vfs_mount_table_t *active = vfs_mount_namespace_active_table();
    const vfs_mount_table_t *initial = &g_mount_namespaces_inline[0].table;
    const vfs_superblock_t *active_root = 0;
    const vfs_superblock_t *initial_root = 0;

    for (int index = 0; index < active->mount_count; ++index) {
        const vfs_superblock_t *mount =
            vfs_mount_table_at_const(active, (uint32_t)index);
        if (mount && !mount->parent_mount_id &&
            strcmp(mount->mountpoint, "/") == 0)
            active_root = mount;
    }
    for (int index = 0; index < initial->mount_count; ++index) {
        const vfs_superblock_t *mount =
            vfs_mount_table_at_const(initial, (uint32_t)index);
        if (mount && !mount->parent_mount_id &&
            strcmp(mount->mountpoint, "/") == 0)
            initial_root = mount;
    }
    return active_root && initial_root &&
           active_root->mount_id == initial_root->mount_id;
}

int vfs_mount_namespace_clone(uint32_t parent_namespace,
                              uint32_t *namespace_out) {
    vfs_mount_table_t *destination;
    const vfs_mount_table_t *parent;
    vfs_mount_namespace_slot_t *destination_slot;
    vfs_mount_namespace_slot_t *parent_slot;
    uint32_t capacity;
    uint32_t namespace_id;
    uint32_t parent_mount_count;
    int reserve_result;
    if (!namespace_out) return -1;

    mount_namespace_lock();
    parent_slot = mount_namespace_slot_at(parent_namespace);
    if (!parent_slot || !parent_slot->table.references ||
        parent_slot->releasing) {
        mount_namespace_unlock();
        return -1;
    }
    capacity = mount_namespace_capacity();
    for (namespace_id = 1;; ++namespace_id) {
        if (namespace_id >= capacity) {
            if (capacity == UINT32_MAX ||
                mount_namespace_reserve(capacity + 1u) < 0) {
                mount_namespace_unlock();
                return -1;
            }
            capacity = mount_namespace_capacity();
        }
        destination_slot = mount_namespace_slot_at(namespace_id);
        if (!destination_slot) {
            mount_namespace_unlock();
            return -1;
        }
        if (destination_slot->table.references ||
            destination_slot->releasing)
            continue;
        destination = &destination_slot->table;
        parent = &parent_slot->table;
        memset(destination, 0, sizeof(*destination));
        destination_slot->releasing = 1u;
        parent_mount_count = (uint32_t)parent->mount_count;
        if (parent->references == UINT32_MAX) {
            destination_slot->releasing = 0;
            mount_namespace_unlock();
            return -1;
        }
        ++parent_slot->table.references;
        mount_namespace_unlock();
        reserve_result = vfs_mount_table_reserve(
            destination, parent_mount_count);
        mount_namespace_lock();
        parent_slot = mount_namespace_slot_at(parent_namespace);
        destination_slot = mount_namespace_slot_at(namespace_id);
        if (!parent_slot || !destination_slot ||
            !parent_slot->table.references ||
            parent_slot->table.mount_count != (int)parent_mount_count) {
            if (parent_slot && parent_slot->table.references)
                --parent_slot->table.references;
            vfs_mount_table_release_storage(destination);
            memset(destination, 0, sizeof(*destination));
            if (destination_slot) destination_slot->releasing = 0;
            mount_namespace_unlock();
            return -1;
        }
        --parent_slot->table.references;
        parent = &parent_slot->table;
        destination = &destination_slot->table;
        if (reserve_result < 0) {
            vfs_mount_table_release_storage(destination);
            memset(destination, 0, sizeof(*destination));
            destination_slot->releasing = 0;
            mount_namespace_unlock();
            return -1;
        }
        destination->mount_count = parent->mount_count;
        destination->next_peer_group = parent->next_peer_group;
        destination->event_generation = parent->event_generation;
        destination->next_mount_id = parent->next_mount_id;
        destination->root_mount_id = parent->root_mount_id;
        destination->references = 1u;
        destination_slot->list_id = 0;
        destination_slot->owner_user_namespace =
            parent_slot->owner_user_namespace;
        for (int mount = 0;
             mount < destination->mount_count; ++mount) {
            vfs_superblock_t *sb =
                vfs_mount_table_at(destination, (uint32_t)mount);
            const vfs_superblock_t *parent_sb =
                vfs_mount_table_at_const(parent, (uint32_t)mount);
            if (!sb || !parent_sb) {
                destination->references = 0;
                destination_slot->releasing = 1u;
                while (mount > 0) {
                    filesystem_instance_release_action_t action;
                    --mount;
                    if (mount_release_prepare_locked(
                            vfs_mount_table_at(
                                destination, (uint32_t)mount),
                            &action) < 0)
                        continue;
                    mount_namespace_unlock();
                    filesystem_instance_release_complete(&action);
                    mount_namespace_lock();
                }
                vfs_mount_table_release_storage(destination);
                memset(destination, 0, sizeof(*destination));
                destination_slot->releasing = 0;
                mount_namespace_unlock();
                return -1;
            }
            *sb = *parent_sb;
            if (!filesystem_instance_acquire_locked(sb)) {
                /*
                 * The namespace has not been published through namespace_out.
                 * Mark it unavailable, then retire each acquired mount one at
                 * a time so backend callbacks run outside the namespace lock
                 * without a large kernel-stack action array.
                 */
                destination->references = 0;
                destination_slot->releasing = 1u;
                while (mount > 0) {
                    filesystem_instance_release_action_t action;
                    --mount;
                    if (mount_release_prepare_locked(
                            vfs_mount_table_at(
                                destination, (uint32_t)mount),
                            &action) < 0)
                        continue;
                    mount_namespace_unlock();
                    filesystem_instance_release_complete(&action);
                    mount_namespace_lock();
                }
                vfs_mount_table_release_storage(destination);
                memset(destination, 0, sizeof(*destination));
                destination_slot->releasing = 0;
                mount_namespace_unlock();
                return -1;
            }
            if (sb->root_reference)
                __atomic_add_fetch(&sb->root_reference->references, 1u,
                                   __ATOMIC_RELAXED);
        }
        destination_slot->releasing = 0;
        *namespace_out = namespace_id;
        mount_namespace_unlock();
        return 0;
    }
}

int vfs_mount_namespace_retain(uint32_t namespace_id) {
    mount_namespace_lock();
    if (vfs_mount_namespace_retain_locked(namespace_id) < 0) {
        mount_namespace_unlock();
        return -1;
    }
    mount_namespace_unlock();
    return 0;
}

int vfs_mount_namespace_retain_locked(uint32_t namespace_id) {
    vfs_mount_namespace_slot_t *slot =
        mount_namespace_slot_at(namespace_id);

    if (!slot || slot->releasing || !slot->table.references ||
        slot->table.references == UINT32_MAX)
        return -1;
    ++slot->table.references;
    return 0;
}

void vfs_mount_namespace_release(uint32_t namespace_id) {
    vfs_mount_namespace_slot_t *slot;
    vfs_mount_table_t *table;

    mount_namespace_lock();
    slot = mount_namespace_slot_at(namespace_id);
    if (!slot || !slot->table.references) {
        mount_namespace_unlock();
        return;
    }
    table = &slot->table;
    --table->references;
    if (!table->references) {
        slot->releasing = 1u;
        while (table->mount_count > 0) {
            filesystem_instance_release_action_t action;
            vfs_superblock_t *sb =
                vfs_mount_table_at(
                    table, (uint32_t)--table->mount_count);
            if (mount_release_prepare_locked(
                    sb, &action) < 0)
                continue;
            mount_namespace_unlock();
            filesystem_instance_release_complete(&action);
            mount_namespace_lock();
        }
        vfs_mount_table_release_storage(table);
        memset(table, 0, sizeof(*table));
        slot->list_id = 0;
        slot->owner_user_namespace = 0;
        /*
         * Slot identifiers are reused.  Retaining cached inode and mount-table
         * indices across reuse can resolve a new container's path through the
         * previous container's filesystem, including exchanging file and
         * directory identities in the persistent content store.
         */
        vfs_path_cache_runtime_invalidate_namespace(namespace_id);
        slot->releasing = 0;
    }
    mount_namespace_unlock();
}

int vfs_mount_namespace_activate(uint32_t namespace_id) {
    vfs_mount_namespace_slot_t *slot =
        mount_namespace_slot_at(namespace_id);
    uint32_t cpu;
    if (!slot || __atomic_load_n(&slot->releasing, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&slot->table.references, __ATOMIC_ACQUIRE)) {
        return -1;
    }
    cpu = mount_namespace_cpu_slot();
    __atomic_store_n(&g_active_namespace[cpu], namespace_id,
                     __ATOMIC_RELEASE);
    return 0;
}

uint32_t vfs_mount_namespace_current(void) {
    return __atomic_load_n(&g_active_namespace[mount_namespace_cpu_slot()],
                           __ATOMIC_ACQUIRE);
}

uint32_t vfs_mount_namespace_event_generation(uint32_t namespace_id) {
    vfs_mount_namespace_slot_t *slot =
        mount_namespace_slot_at(namespace_id);

    if (!slot || __atomic_load_n(&slot->releasing, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&slot->table.references, __ATOMIC_ACQUIRE))
        return 0;
    return __atomic_load_n(
        &slot->table.event_generation,
        __ATOMIC_ACQUIRE);
}

int vfs_mount_namespace_exists(uint32_t namespace_id) {
    vfs_mount_namespace_slot_t *slot =
        mount_namespace_slot_at(namespace_id);

    return slot &&
        !__atomic_load_n(&slot->releasing, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&slot->table.references, __ATOMIC_ACQUIRE);
}

int vfs_mount_namespace_metadata_set(uint32_t namespace_id,
                                     uint64_t list_id,
                                     uint32_t owner_user_namespace) {
    vfs_mount_namespace_slot_t *slot;

    if (!list_id) return -1;
    mount_namespace_lock();
    slot = mount_namespace_slot_at(namespace_id);
    if (!slot || slot->releasing || !slot->table.references) {
        mount_namespace_unlock();
        return -1;
    }
    slot->list_id = list_id;
    slot->owner_user_namespace = owner_user_namespace;
    mount_namespace_unlock();
    return 0;
}

int vfs_mount_namespace_metadata_get(uint32_t namespace_id,
                                     uint64_t *list_id_out,
                                     uint32_t *owner_user_namespace_out) {
    vfs_mount_namespace_slot_t *slot;

    if (!list_id_out) return -1;
    mount_namespace_lock();
    slot = mount_namespace_slot_at(namespace_id);
    if (!slot || slot->releasing || !slot->table.references ||
        !slot->list_id) {
        mount_namespace_unlock();
        return -1;
    }
    *list_id_out = slot->list_id;
    if (owner_user_namespace_out)
        *owner_user_namespace_out = slot->owner_user_namespace;
    mount_namespace_unlock();
    return 0;
}

int vfs_mount_namespace_list_next(uint64_t after_list_id,
                                  uint64_t *list_id_out,
                                  uint32_t *namespace_id_out,
                                  uint32_t *owner_user_namespace_out) {
    uint64_t best_id = UINT64_MAX;
    uint32_t best_namespace = 0;
    uint32_t best_owner = 0;
    uint32_t capacity;

    if (!list_id_out || !namespace_id_out) return -1;
    mount_namespace_lock();
    capacity = mount_namespace_capacity();
    for (uint32_t namespace_id = 0; namespace_id < capacity;
         ++namespace_id) {
        vfs_mount_namespace_slot_t *slot =
            mount_namespace_slot_at(namespace_id);
        if (!slot || slot->releasing || !slot->table.references ||
            slot->list_id <= after_list_id || slot->list_id >= best_id)
            continue;
        best_id = slot->list_id;
        best_namespace = namespace_id;
        best_owner = slot->owner_user_namespace;
    }
    mount_namespace_unlock();
    if (best_id == UINT64_MAX) return 0;
    *list_id_out = best_id;
    *namespace_id_out = best_namespace;
    if (owner_user_namespace_out)
        *owner_user_namespace_out = best_owner;
    return 1;
}

void vfs_mount_namespace_note_change(void) {
    vfs_mount_namespace_change_notifier_t notifier;
    uint32_t namespace_id = vfs_mount_namespace_current();
    vfs_mount_namespace_slot_t *slot =
        mount_namespace_slot_at(namespace_id);

    if (!slot || __atomic_load_n(&slot->releasing, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&slot->table.references, __ATOMIC_ACQUIRE))
        return;
    vfs_mount_table_lookup_cache_invalidate(&slot->table);
    notifier = __atomic_load_n(&g_mount_change_notifier, __ATOMIC_ACQUIRE);
    if (notifier) notifier(namespace_id);
}

void vfs_mount_namespace_note_path_change(const char *path) {
    vfs_mount_namespace_change_notifier_t notifier;
    uint32_t namespace_id = vfs_mount_namespace_current();
    vfs_mount_namespace_slot_t *slot =
        mount_namespace_slot_at(namespace_id);

    if (!slot || __atomic_load_n(&slot->releasing, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&slot->table.references, __ATOMIC_ACQUIRE))
        return;
    vfs_mount_table_lookup_cache_invalidate_subtree(&slot->table, path);
    notifier = __atomic_load_n(&g_mount_change_notifier, __ATOMIC_ACQUIRE);
    if (notifier) notifier(namespace_id);
}

void vfs_mount_namespace_set_change_notifier(
    vfs_mount_namespace_change_notifier_t notifier) {
    __atomic_store_n(&g_mount_change_notifier, notifier, __ATOMIC_RELEASE);
}
