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
#include "kernel/smp.h"
#include "mm/arch_vm.h"
#include "string.h"

#define VFS_MOUNT_NAMESPACE_CPU_SLOTS 64u
#define VFS_MOUNT_NAMESPACE_INLINE_CAPACITY 8u
#define VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY 8u
#define VFS_FILESYSTEM_INSTANCE_INLINE_CAPACITY 8u
#define VFS_FILESYSTEM_INSTANCE_CHUNK_CAPACITY 8u
#define VFS_MOUNT_CHUNK_CAPACITY 8u
#define VFS_MOUNT_ALLOCATION_PAGE_SIZE 4096u

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
    vfs_superblock_t mounts[];
};

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

typedef struct filesystem_instance_release_action {
    vfs_filesystem_instance_t *instance;
    uint32_t generation;
    void (*callback)(void *private_data);
    void *private_data;
} filesystem_instance_release_action_t;

static vfs_mount_namespace_slot_t
    g_mount_namespaces_inline[VFS_MOUNT_NAMESPACE_INLINE_CAPACITY];
static vfs_mount_namespace_chunk_t *g_mount_namespace_chunks;
static uint32_t g_active_namespace[VFS_MOUNT_NAMESPACE_CPU_SLOTS];
static vfs_filesystem_instance_t
    g_filesystem_instances_inline[VFS_FILESYSTEM_INSTANCE_INLINE_CAPACITY];
static vfs_filesystem_instance_chunk_t *g_filesystem_instance_chunks;
static uint32_t g_filesystem_instance_generation;
static volatile uint32_t g_mount_namespace_lock;
static vfs_mount_namespace_change_notifier_t g_mount_change_notifier;

static void vfs_mount_table_release_storage(vfs_mount_table_t *table);

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
    vfs_mount_namespace_chunk_t **link = &g_mount_namespace_chunks;
    uint32_t capacity = VFS_MOUNT_NAMESPACE_INLINE_CAPACITY;

    while (*link) {
        if (capacity > UINT32_MAX - (*link)->capacity) return -1;
        capacity += (*link)->capacity;
        link = &(*link)->next;
    }
    while (capacity < required_capacity) {
        uint64_t bytes = sizeof(vfs_mount_namespace_chunk_t) +
            (uint64_t)VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY *
                sizeof(vfs_mount_namespace_slot_t);
        uint32_t pages = mount_allocation_page_count(bytes);
        vfs_mount_namespace_chunk_t *chunk;

        if (!pages || capacity >
                UINT32_MAX - VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY)
            return -1;
        chunk = (vfs_mount_namespace_chunk_t *)arch_vm_alloc_pages(pages);
        if (!chunk) return -1;
        memset(chunk, 0,
               (uint64_t)pages * VFS_MOUNT_ALLOCATION_PAGE_SIZE);
        chunk->page_count = pages;
        chunk->capacity = VFS_MOUNT_NAMESPACE_CHUNK_CAPACITY;
        __atomic_store_n(link, chunk, __ATOMIC_RELEASE);
        link = &chunk->next;
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
    index -= VFS_MOUNT_TABLE_INLINE_CAPACITY;
    for (chunk = table->overflow; chunk; chunk = chunk->next) {
        if (index < chunk->capacity) return &chunk->mounts[index];
        index -= chunk->capacity;
    }
    return 0;
}

const vfs_superblock_t *vfs_mount_table_at_const(
    const vfs_mount_table_t *table, uint32_t index) {
    const vfs_mount_chunk_t *chunk;
    if (!table) return 0;
    if (index < VFS_MOUNT_TABLE_INLINE_CAPACITY)
        return &table->inline_mounts[index];
    index -= VFS_MOUNT_TABLE_INLINE_CAPACITY;
    for (chunk = table->overflow; chunk; chunk = chunk->next) {
        if (index < chunk->capacity) return &chunk->mounts[index];
        index -= chunk->capacity;
    }
    return 0;
}

static uint32_t vfs_mount_table_capacity(const vfs_mount_table_t *table) {
    const vfs_mount_chunk_t *chunk;
    uint32_t capacity = VFS_MOUNT_TABLE_INLINE_CAPACITY;
    if (!table) return 0;
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
    link = &table->overflow;
    while (*link) link = &(*link)->next;
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
        *link = chunk;
        link = &chunk->next;
        if (capacity > UINT32_MAX - chunk->capacity) return -1;
        capacity += chunk->capacity;
    }
    return 0;
}

static void vfs_mount_table_release_storage(vfs_mount_table_t *table) {
    vfs_mount_chunk_t *chunk;
    if (!table) return;
    chunk = table->overflow;
    table->overflow = 0;
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
            __asm__ __volatile__("" ::: "memory");
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
    vfs_filesystem_instance_chunk_t **link = &g_filesystem_instance_chunks;
    vfs_filesystem_instance_chunk_t *chunk;
    uint64_t bytes;
    uint32_t pages;

    while (*link) link = &(*link)->next;
    bytes = sizeof(*chunk) +
        (uint64_t)VFS_FILESYSTEM_INSTANCE_CHUNK_CAPACITY *
            sizeof(vfs_filesystem_instance_t);
    pages = mount_allocation_page_count(bytes);
    if (!pages) return 0;
    chunk = (vfs_filesystem_instance_chunk_t *)arch_vm_alloc_pages(pages);
    if (!chunk) return 0;
    memset(chunk, 0,
           (uint64_t)pages * VFS_MOUNT_ALLOCATION_PAGE_SIZE);
    chunk->page_count = pages;
    chunk->capacity = VFS_FILESYSTEM_INSTANCE_CHUNK_CAPACITY;
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

const vfs_superblock_t *vfs_superblock_stable_const(
    const vfs_superblock_t *sb) {
    const vfs_filesystem_instance_t *instance;
    if (!sb) return 0;
    instance = sb->instance;
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

int vfs_mount_namespace_clone(uint32_t parent_namespace,
                              uint32_t *namespace_out) {
    vfs_mount_table_t *destination;
    const vfs_mount_table_t *parent;
    vfs_mount_namespace_slot_t *destination_slot;
    vfs_mount_namespace_slot_t *parent_slot;
    uint32_t capacity;
    uint32_t namespace_id;
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
        if (vfs_mount_table_reserve(
                destination, (uint32_t)parent->mount_count) < 0) {
            vfs_mount_table_release_storage(destination);
            mount_namespace_unlock();
            return -1;
        }
        destination->mount_count = parent->mount_count;
        destination->next_peer_group = parent->next_peer_group;
        destination->event_generation = parent->event_generation;
        destination->next_mount_id = parent->next_mount_id;
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
                    if (filesystem_instance_release_prepare_locked(
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
                    if (filesystem_instance_release_prepare_locked(
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
        }
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
            if (filesystem_instance_release_prepare_locked(
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
    uint32_t generation;

    if (!slot || __atomic_load_n(&slot->releasing, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&slot->table.references, __ATOMIC_ACQUIRE))
        return;
    generation = __atomic_add_fetch(
        &slot->table.event_generation, 1u,
        __ATOMIC_ACQ_REL);
    if (!generation)
        __atomic_store_n(
            &slot->table.event_generation, 1u,
            __ATOMIC_RELEASE);
    notifier = __atomic_load_n(&g_mount_change_notifier, __ATOMIC_ACQUIRE);
    if (notifier) notifier(namespace_id);
}

void vfs_mount_namespace_set_change_notifier(
    vfs_mount_namespace_change_notifier_t notifier) {
    __atomic_store_n(&g_mount_change_notifier, notifier, __ATOMIC_RELEASE);
}
