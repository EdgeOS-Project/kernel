/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * In-memory files use a global sparse page map.  File sizes are independent
 * of resident pages, matching the Linux tmpfs and memfd behavior relied on by
 * graphics stacks for large, initially sparse shared-memory buffers.
 */
#include "fs/tmpfs.h"
#include "fs/swap.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "mm/arch_vm.h"
#include "string.h"
#include "sys/boottime.h"

/*
 * A desktop process can keep several isolated Glycin/bubblewrap namespaces
 * alive at once, and each namespace contains multiple tmpfs mounts.  This pool
 * is global across mount namespaces, so it must scale beyond the per-namespace
 * mount-table limit instead of failing valid mounts after a few image loaders.
 */
#define TMPFS_MAX_MOUNTS 128
#define TMPFS_INLINE_NODES 512
/*
 * Linux accepts large nr_inodes values without charging every mount against a
 * global static inode slab.  Keep small mounts inline, while large mounts own
 * reclaimable page-backed metadata.  The implementation limit is intentionally
 * high enough for desktop browser profiles but still bounds kernel metadata.
 */
#define TMPFS_MAX_NODES 32768
#define TMPFS_INLINE_NODE_HASH_SIZE 512
#define TMPFS_MAX_BLOCKS 262144
#define TMPFS_BLOCK_SIZE 4096
#define TMPFS_BLOCK_HASH_SIZE 524288

typedef struct tmpfs_xattr {
    struct tmpfs_xattr *next;
    uint32_t allocation_pages;
    uint32_t name_length;
    uint32_t value_length;
    uint8_t data[];
} tmpfs_xattr_t;

typedef struct {
    uint8_t used;
    uint8_t is_dir;
    uint16_t kind;
    uint32_t generation;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t parent;
    uint32_t size;
    uint32_t atime;
    uint32_t mtime;
    uint32_t ctime;
    uint64_t rdev;
    uint32_t open_references;
    uint32_t anonymous_references;
    uint32_t mapping_references;
    uint32_t seals;
    uint8_t is_memfd;
    tmpfs_xattr_t *xattrs;
    /* Nonzero directory-entry nodes reference the canonical inode index + 1. */
    uint32_t hardlink_target;
    uint32_t directory_hash_next;
    char name[VFS_NAME_MAX];
} tmpfs_node_t;

typedef struct {
    tmpfs_node_t *owner;
    struct tmpfs_state *state;
    uint8_t *data;
    uint64_t swap_entry;
    uint32_t file_page;
    uint32_t hash_next;
    uint32_t free_next;
} tmpfs_block_meta_t;

typedef struct tmpfs_state {
    uint8_t used;
    uint32_t references;
    uint32_t next_generation;
    uint32_t max_nodes;
    uint32_t node_scan_limit;
    uint32_t node_allocation_hint;
    uint32_t node_storage_pages;
    uint32_t node_hash_buckets;
    uint32_t max_blocks;
    uint32_t allocated_blocks;
    uint32_t resident_blocks;
    uint32_t xattr_pages;
    tmpfs_node_t *nodes;
    uint32_t *node_hash;
    tmpfs_node_t inline_nodes[TMPFS_INLINE_NODES];
    uint32_t inline_node_hash[TMPFS_INLINE_NODE_HASH_SIZE];
} tmpfs_state_t;

static tmpfs_state_t g_tmpfs_states[TMPFS_MAX_MOUNTS];
static vfs_superblock_t g_tmpfs_sbs[TMPFS_MAX_MOUNTS];
static tmpfs_state_t g_tmpfs_anonymous_state;
static vfs_superblock_t g_tmpfs_anonymous_sb;
static uint8_t g_tmpfs_block_used[TMPFS_MAX_BLOCKS];
static tmpfs_block_meta_t g_tmpfs_block_meta[TMPFS_MAX_BLOCKS];
static uint32_t g_tmpfs_block_hash[TMPFS_BLOCK_HASH_SIZE];
static uint32_t g_tmpfs_block_free_head;
static uint32_t g_tmpfs_block_next_unused;
static volatile uint32_t g_tmpfs_block_lock;
static volatile uint32_t g_tmpfs_state_lock;
static volatile uint32_t g_tmpfs_xattr_lock;

static void tmpfs_free_file_blocks(tmpfs_state_t *st, tmpfs_node_t *node);
static void tmpfs_states_lock(void);
static void tmpfs_states_unlock(void);
static void tmpfs_unlink_node(tmpfs_state_t *state, uint32_t index);

static void tmpfs_xattrs_lock(void) {
    while (__sync_lock_test_and_set(&g_tmpfs_xattr_lock, 1u)) {
        while (g_tmpfs_xattr_lock) __asm__ volatile("" ::: "memory");
    }
}

static void tmpfs_xattrs_unlock(void) {
    __sync_lock_release(&g_tmpfs_xattr_lock);
}

static void tmpfs_free_xattr_allocation(tmpfs_xattr_t *attribute) {
    uint32_t pages;
    if (!attribute) return;
    pages = attribute->allocation_pages;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page((uint8_t *)attribute +
                          (uint64_t)page * TMPFS_BLOCK_SIZE);
}

static void tmpfs_free_node_xattrs(tmpfs_state_t *state,
                                   tmpfs_node_t *node) {
    tmpfs_xattr_t *attribute;
    if (!state || !node) return;
    tmpfs_xattrs_lock();
    attribute = node->xattrs;
    node->xattrs = 0;
    while (attribute) {
        tmpfs_xattr_t *next = attribute->next;
        if (state->xattr_pages >= attribute->allocation_pages)
            state->xattr_pages -= attribute->allocation_pages;
        else
            state->xattr_pages = 0;
        tmpfs_free_xattr_allocation(attribute);
        attribute = next;
    }
    tmpfs_xattrs_unlock();
}

static uint32_t tmpfs_node_hash_value(uint32_t parent, const char *name) {
    uint32_t hash = 2166136261u ^ parent;
    if (!name) return hash;
    while (*name) {
        hash ^= (uint8_t)*name++;
        hash *= 16777619u;
    }
    return hash;
}

static uint32_t tmpfs_node_hash_bucket(const tmpfs_state_t *st,
                                       uint32_t parent, const char *name) {
    if (!st || !st->node_hash_buckets) return 0;
    return tmpfs_node_hash_value(parent, name) &
           (st->node_hash_buckets - 1u);
}

static void tmpfs_node_hash_insert(tmpfs_state_t *st, uint32_t index) {
    tmpfs_node_t *node;
    uint32_t bucket;
    if (!st || !st->node_hash || index == 0 ||
        index >= st->node_scan_limit)
        return;
    node = &st->nodes[index];
    if (!node->used || node->parent == UINT32_MAX || !node->name[0])
        return;
    bucket = tmpfs_node_hash_bucket(st, node->parent, node->name);
    node->directory_hash_next = st->node_hash[bucket];
    st->node_hash[bucket] = index + 1u;
}

static void tmpfs_node_hash_remove(tmpfs_state_t *st, uint32_t index) {
    tmpfs_node_t *node;
    uint32_t *link;
    uint32_t id;
    if (!st || !st->node_hash || index == 0 ||
        index >= st->node_scan_limit)
        return;
    node = &st->nodes[index];
    if (!node->used || node->parent == UINT32_MAX || !node->name[0])
        return;
    link = &st->node_hash[
        tmpfs_node_hash_bucket(st, node->parent, node->name)];
    id = *link;
    while (id && id <= st->node_scan_limit) {
        tmpfs_node_t *candidate = &st->nodes[id - 1u];
        if (id - 1u == index) {
            *link = candidate->directory_hash_next;
            candidate->directory_hash_next = 0;
            return;
        }
        link = &candidate->directory_hash_next;
        id = *link;
    }
}

static void tmpfs_clear_node(tmpfs_state_t *st, uint32_t index) {
    if (!st || index == 0 || index >= st->node_scan_limit ||
        !st->nodes[index].used)
        return;
    tmpfs_node_hash_remove(st, index);
    tmpfs_free_node_xattrs(st, &st->nodes[index]);
    memset(&st->nodes[index], 0, sizeof(st->nodes[index]));
    if (st->node_allocation_hint < 1u ||
        st->node_allocation_hint >= st->max_nodes ||
        st->nodes[st->node_allocation_hint].used ||
        index < st->node_allocation_hint)
        st->node_allocation_hint = index;
    while (st->node_scan_limit > 1u &&
           !st->nodes[st->node_scan_limit - 1u].used)
        --st->node_scan_limit;
}

/* The caller holds g_tmpfs_state_lock. */
static void tmpfs_release_node_storage(tmpfs_state_t *st) {
    tmpfs_node_t *nodes;
    uint32_t pages;
    if (!st) return;
    nodes = st->nodes;
    pages = st->node_storage_pages;
    memset(st, 0, sizeof(*st));
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page((uint8_t *)nodes +
                          (uint64_t)page * TMPFS_BLOCK_SIZE);
}

/* The caller holds g_tmpfs_state_lock and supplies a cleared state. */
static int tmpfs_allocate_node_storage(tmpfs_state_t *st,
                                       uint32_t requested_nodes) {
    uint32_t node_pages;
    uint32_t hash_pages;
    uint32_t hash_buckets;
    uint32_t total_pages;
    uint64_t node_bytes;
    void *storage;
    if (!st) return -1;
    if (!requested_nodes) requested_nodes = TMPFS_INLINE_NODES;
    if (requested_nodes > TMPFS_MAX_NODES)
        requested_nodes = TMPFS_MAX_NODES;
    if (requested_nodes <= TMPFS_INLINE_NODES) {
        st->nodes = st->inline_nodes;
        st->node_hash = st->inline_node_hash;
        st->node_hash_buckets = TMPFS_INLINE_NODE_HASH_SIZE;
        st->max_nodes = requested_nodes;
        st->node_scan_limit = 1u;
        st->node_allocation_hint = 1u;
        return 0;
    }
    hash_buckets = TMPFS_INLINE_NODE_HASH_SIZE;
    while (hash_buckets < requested_nodes) hash_buckets <<= 1u;
    node_bytes = (uint64_t)requested_nodes * sizeof(tmpfs_node_t);
    node_pages = (uint32_t)(
        (node_bytes + TMPFS_BLOCK_SIZE - 1u) / TMPFS_BLOCK_SIZE);
    hash_pages = (hash_buckets * sizeof(uint32_t) +
                  TMPFS_BLOCK_SIZE - 1u) / TMPFS_BLOCK_SIZE;
    total_pages = node_pages + hash_pages;
    storage = arch_vm_alloc_pages(total_pages);
    if (!storage) return -1;
    memset(storage, 0, (uint64_t)total_pages * TMPFS_BLOCK_SIZE);
    st->nodes = (tmpfs_node_t *)storage;
    st->node_hash = (uint32_t *)((uint8_t *)storage +
                                 (uint64_t)node_pages * TMPFS_BLOCK_SIZE);
    st->node_storage_pages = total_pages;
    st->node_hash_buckets = hash_buckets;
    st->max_nodes = requested_nodes;
    st->node_scan_limit = 1u;
    st->node_allocation_hint = 1u;
    return 0;
}

static filesystem_ops_t g_tmpfs_ops;

static tmpfs_state_t *tmpfs_state(vfs_superblock_t *sb) {
    /*
     * F_GET_SEALS is valid on any descriptor and must return EINVAL when the
     * backing object is not a memfd.  Callers therefore probe this helper with
     * superblocks owned by other filesystems.  Their private pointer has a
     * different layout and must never be interpreted as tmpfs state.
     */
    return sb && sb->ops == &g_tmpfs_ops ?
        (tmpfs_state_t *)sb->fs_private : 0;
}

static void tmpfs_retain(void *private_data) {
    tmpfs_state_t *st = (tmpfs_state_t *)private_data;
    if (st && st->used) (void)__sync_add_and_fetch(&st->references, 1u);
}

static void tmpfs_release(void *private_data) {
    tmpfs_state_t *st = (tmpfs_state_t *)private_data;
    uint32_t references;
    if (!st || !st->used) return;
    for (;;) {
        references = st->references;
        if (!references) return;
        if (__sync_bool_compare_and_swap(&st->references, references,
                                         references - 1u))
            break;
    }
    if (references == 1u) {
        tmpfs_states_lock();
        if (!st->used || st->references) {
            tmpfs_states_unlock();
            return;
        }
        for (uint32_t node = 0; node < st->node_scan_limit; ++node)
            if (st->nodes[node].used) {
                if (!st->nodes[node].is_dir)
                    tmpfs_free_file_blocks(st, &st->nodes[node]);
                tmpfs_free_node_xattrs(st, &st->nodes[node]);
            }
        tmpfs_release_node_storage(st);
        tmpfs_states_unlock();
    }
}

static uint32_t tmpfs_now_sec(void) {
    return (uint32_t)(boottime_realtime_us() / 1000000ull);
}

static int tmpfs_canonical_index(const tmpfs_state_t *state,
                                 uint32_t index) {
    uint32_t target;
    if (!state || index >= state->max_nodes || !state->nodes[index].used)
        return -1;
    target = state->nodes[index].hardlink_target;
    if (!target) return (int)index;
    --target;
    if (target >= state->max_nodes || !state->nodes[target].used ||
        state->nodes[target].hardlink_target)
        return -1;
    return (int)target;
}

static uint32_t tmpfs_node_link_count(const tmpfs_state_t *state,
                                      uint32_t index) {
    uint32_t links = 0;
    if (!state || index >= state->max_nodes || !state->nodes[index].used)
        return 0;
    if (state->nodes[index].parent != UINT32_MAX) ++links;
    for (uint32_t entry = 1; entry < state->node_scan_limit; ++entry)
        if (state->nodes[entry].used &&
            state->nodes[entry].hardlink_target == index + 1u)
            ++links;
    return links;
}

static void tmpfs_fill_inode(tmpfs_state_t *st, uint32_t idx, vfs_inode_t *out) {
    tmpfs_node_t *n;
    uint32_t links;
    int canonical = tmpfs_canonical_index(st, idx);
    if (!st || !out || canonical < 0) return;
    idx = (uint32_t)canonical;
    n = &st->nodes[idx];
    memset(out, 0, sizeof(*out));
    out->ino = idx + 1;
    out->generation = n->generation;
    out->mode = (uint16_t)((n->kind ? n->kind : (n->is_dir ? VFS_INODE_DIR : VFS_INODE_FILE)) |
                           (n->mode & 07777u));
    out->uid = n->uid;
    out->gid = n->gid;
    links = tmpfs_node_link_count(st, idx);
    if (n->is_dir) {
        links = n->parent == UINT32_MAX ? 0u : 2u;
        for (uint32_t child = 1; child < st->node_scan_limit; ++child)
            if (st->nodes[child].used && st->nodes[child].is_dir &&
                st->nodes[child].parent == idx)
                ++links;
    }
    out->nlink = links;
    out->nlink_valid = 1;
    out->size = n->size;
    out->atime = n->atime;
    out->mtime = n->mtime;
    out->ctime = n->ctime;
    out->rdev = n->rdev;
}

static int tmpfs_inode_index(const tmpfs_state_t *st,
                             const vfs_inode_t *inode) {
    if (!st || !inode || inode->ino == 0 || inode->ino > st->max_nodes)
        return -1;
    /*
     * An inode number may be reused after the last open file and mapping are
     * released.  Linux page-cache identity includes the inode generation;
     * accepting an older VFS handle here would let it address the replacement
     * file and could expose stale MAP_SHARED pages to a newly created object.
     */
    if (inode->generation &&
        st->nodes[inode->ino - 1u].generation != inode->generation)
        return -1;
    return (int)(inode->ino - 1);
}

static int tmpfs_find_child(tmpfs_state_t *st, uint32_t parent, const char *name) {
    uint32_t id;
    if (!st || !name) return -1;
    id = st->node_hash[
        tmpfs_node_hash_bucket(st, parent, name)];
    while (id && id <= st->node_scan_limit) {
        tmpfs_node_t *node = &st->nodes[id - 1u];
        if (node->used && node->parent == parent &&
            strcmp(node->name, (char *)name) == 0)
            return (int)(id - 1u);
        id = node->directory_hash_next;
    }
    return -1;
}

static int tmpfs_alloc_node(tmpfs_state_t *st) {
    uint32_t start;
    if (!st) return -1;
    start = st->node_allocation_hint;
    if (start < 1u || start >= st->max_nodes) start = 1u;
    for (uint32_t pass = 0; pass < 2u; ++pass) {
        uint32_t begin = pass == 0 ? start : 1u;
        uint32_t end = pass == 0 ? st->max_nodes : start;
        for (uint32_t i = begin; i < end; ++i) {
            if (st->nodes[i].used) continue;
            memset(&st->nodes[i], 0, sizeof(st->nodes[i]));
            st->nodes[i].used = 1;
            if (!++st->next_generation) ++st->next_generation;
            st->nodes[i].generation = st->next_generation;
            st->node_allocation_hint = i + 1u;
            if (st->node_allocation_hint >= st->max_nodes)
                st->node_allocation_hint = 1u;
            if (st->node_scan_limit <= i)
                st->node_scan_limit = i + 1u;
            return (int)i;
        }
    }
    return -1;
}

static void tmpfs_blocks_lock(void) {
    while (__sync_lock_test_and_set(&g_tmpfs_block_lock, 1u)) {
        while (g_tmpfs_block_lock) __asm__ volatile("" ::: "memory");
    }
}

static void tmpfs_blocks_unlock(void) {
    __sync_lock_release(&g_tmpfs_block_lock);
}

static void tmpfs_states_lock(void) {
    while (__sync_lock_test_and_set(&g_tmpfs_state_lock, 1u)) {
        while (g_tmpfs_state_lock) __asm__ volatile("" ::: "memory");
    }
}

static void tmpfs_states_unlock(void) {
    __sync_lock_release(&g_tmpfs_state_lock);
}

static uint32_t tmpfs_block_bucket(const tmpfs_node_t *owner,
                                   uint32_t file_page) {
    uintptr_t address = (uintptr_t)owner;
    uint32_t mixed = (uint32_t)(address >> 4) ^
                     (uint32_t)(address >> 32) ^
                     file_page * 2654435761u;
    return mixed & (TMPFS_BLOCK_HASH_SIZE - 1u);
}

/* The caller holds g_tmpfs_block_lock.  Block identifiers are one-based. */
static uint32_t tmpfs_find_block_locked(const tmpfs_node_t *owner,
                                        uint32_t file_page) {
    uint32_t id;
    if (!owner) return 0;
    id = g_tmpfs_block_hash[tmpfs_block_bucket(owner, file_page)];
    while (id && id <= TMPFS_MAX_BLOCKS) {
        tmpfs_block_meta_t *meta = &g_tmpfs_block_meta[id - 1u];
        if (g_tmpfs_block_used[id - 1u] && meta->owner == owner &&
            meta->file_page == file_page)
            return id;
        id = meta->hash_next;
    }
    return 0;
}

static int tmpfs_alloc_block_locked(tmpfs_state_t *st, tmpfs_node_t *owner,
                                    uint32_t file_page) {
    uint32_t bucket;
    uint32_t i;
    uint8_t *data;
    if (!st || !owner || st->allocated_blocks >= st->max_blocks) return -1;
    data = (uint8_t *)arch_vm_alloc_page();
    if (!data) return -1;
    /*
     * Linux tmpfs guarantees that newly allocated file bytes read as zero,
     * including pages materialized by fallocate(2).  The architecture page
     * allocator intentionally recycles physical pages without clearing them,
     * so tmpfs must establish that filesystem invariant before publishing the
     * page.  Skipping this exposes stale data and corrupts MAP_SHARED users
     * such as Chromium's persistent-memory allocator.
     */
    memset(data, 0, TMPFS_BLOCK_SIZE);
    if (g_tmpfs_block_free_head) {
        i = g_tmpfs_block_free_head - 1u;
        g_tmpfs_block_free_head = g_tmpfs_block_meta[i].free_next;
    } else if (g_tmpfs_block_next_unused < TMPFS_MAX_BLOCKS) {
        i = g_tmpfs_block_next_unused++;
    } else {
        arch_vm_free_page(data);
        return -1;
    }
    bucket = tmpfs_block_bucket(owner, file_page);
    memset(&g_tmpfs_block_meta[i], 0, sizeof(g_tmpfs_block_meta[i]));
    g_tmpfs_block_used[i] = 1;
    g_tmpfs_block_meta[i].owner = owner;
    g_tmpfs_block_meta[i].state = st;
    g_tmpfs_block_meta[i].data = data;
    g_tmpfs_block_meta[i].file_page = file_page;
    g_tmpfs_block_meta[i].hash_next = g_tmpfs_block_hash[bucket];
    g_tmpfs_block_hash[bucket] = i + 1u;
    ++st->allocated_blocks;
    ++st->resident_blocks;
    return (int)i;
}

static int tmpfs_restore_block_locked(tmpfs_block_meta_t *meta) {
    uint8_t *data;
    uint32_t stored_cgroup;
    uint64_t entry;

    if (!meta) return -1;
    if (meta->data) return 0;
    entry = meta->swap_entry;
    if (!entry || !meta->state) return -1;
    data = (uint8_t *)arch_vm_alloc_page();
    if (!data) return -1;
    if (swap_load_page(entry, data, &stored_cgroup) < 0) {
        arch_vm_free_page(data);
        return -1;
    }
    (void)stored_cgroup;
    meta->data = data;
    meta->swap_entry = 0;
    ++meta->state->resident_blocks;
    swap_release_entry(entry);
    return 0;
}

/* The caller holds g_tmpfs_block_lock. */
static void tmpfs_free_block_locked(uint32_t index) {
    tmpfs_block_meta_t *meta;
    uint8_t *data;
    uint32_t bucket;
    uint32_t *link;
    if (index >= TMPFS_MAX_BLOCKS || !g_tmpfs_block_used[index]) return;
    meta = &g_tmpfs_block_meta[index];
    bucket = tmpfs_block_bucket(meta->owner, meta->file_page);
    link = &g_tmpfs_block_hash[bucket];
    while (*link && *link <= TMPFS_MAX_BLOCKS) {
        if (*link == index + 1u) {
            *link = meta->hash_next;
            break;
        }
        link = &g_tmpfs_block_meta[*link - 1u].hash_next;
    }
    if (meta->state && meta->state->allocated_blocks)
        --meta->state->allocated_blocks;
    if (meta->state && meta->data && meta->state->resident_blocks)
        --meta->state->resident_blocks;
    data = meta->data;
    if (meta->swap_entry) swap_release_entry(meta->swap_entry);
    g_tmpfs_block_used[index] = 0;
    memset(meta, 0, sizeof(*meta));
    meta->free_next = g_tmpfs_block_free_head;
    g_tmpfs_block_free_head = index + 1u;
    if (data) arch_vm_free_page(data);
}

static void tmpfs_free_file_blocks(tmpfs_state_t *st, tmpfs_node_t *n) {
    if (!st || !n) return;
    tmpfs_blocks_lock();
    for (uint32_t i = 0; i < TMPFS_MAX_BLOCKS; ++i)
        if (g_tmpfs_block_used[i] && g_tmpfs_block_meta[i].owner == n)
            tmpfs_free_block_locked(i);
    tmpfs_blocks_unlock();
    n->size = 0;
}

static int tmpfs_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int didx;
    int cidx;
    if (!st || !dir || !name || !out) return -1;
    didx = tmpfs_inode_index(st, dir);
    if (didx < 0 || !st->nodes[didx].used || !st->nodes[didx].is_dir) return -1;
    if (strcmp(name, ".") == 0) {
        tmpfs_fill_inode(st, (uint32_t)didx, out);
        return 0;
    }
    if (strcmp(name, "..") == 0) {
        tmpfs_fill_inode(st, st->nodes[didx].parent, out);
        return 0;
    }
    cidx = tmpfs_find_child(st, (uint32_t)didx, name);
    if (cidx < 0) return -1;
    tmpfs_fill_inode(st, (uint32_t)cidx, out);
    return 0;
}

static int tmpfs_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    tmpfs_state_t *st = tmpfs_state(sb);
    tmpfs_node_t *n;
    int idx = tmpfs_inode_index(st, inode);
    uint32_t done = 0;
    if (!st || !inode || !buf || idx < 0 || !st->nodes[idx].used) return -1;
    n = &st->nodes[idx];
    if (n->is_dir || (n->kind != VFS_INODE_FILE && n->kind != VFS_INODE_LNK)) return -1;
    if (off >= n->size || len == 0) return 0;
    if (off + len < off || off + len > n->size) len = n->size - off;
    while (done < len) {
        uint32_t pos = off + done;
        uint32_t bi = pos / TMPFS_BLOCK_SIZE;
        uint32_t bo = pos % TMPFS_BLOCK_SIZE;
        uint32_t nbytes = TMPFS_BLOCK_SIZE - bo;
        uint32_t block_id;
        if (nbytes > len - done) nbytes = len - done;
        tmpfs_blocks_lock();
        block_id = tmpfs_find_block_locked(n, bi);
        if (block_id == 0 || block_id > TMPFS_MAX_BLOCKS) {
            memset((uint8_t *)buf + done, 0, nbytes);
        } else {
            if (tmpfs_restore_block_locked(
                    &g_tmpfs_block_meta[block_id - 1u]) < 0) {
                tmpfs_blocks_unlock();
                return done ? (int)done : -1;
            }
            memcpy((uint8_t *)buf + done,
                   g_tmpfs_block_meta[block_id - 1u].data + bo, nbytes);
        }
        tmpfs_blocks_unlock();
        done += nbytes;
    }
    n->atime = tmpfs_now_sec();
    inode->atime = n->atime;
    return (int)done;
}

static int tmpfs_write(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, const void *buf, uint32_t len) {
    tmpfs_state_t *st = tmpfs_state(sb);
    tmpfs_node_t *n;
    int idx = tmpfs_inode_index(st, inode);
    uint32_t done = 0;
    if (!st || !inode || (!buf && len) || idx < 0 || !st->nodes[idx].used)
        return -EDGE_LINUX_EIO;
    n = &st->nodes[idx];
    if (n->is_dir) return -EDGE_LINUX_EISDIR;
    if (n->kind != VFS_INODE_FILE && n->kind != VFS_INODE_LNK)
        return -EDGE_LINUX_EINVAL;
    if (len == 0) {
        if (off == 0) tmpfs_free_file_blocks(st, n);
        n->mtime = n->ctime = tmpfs_now_sec();
        inode->size = n->size;
        inode->mtime = n->mtime;
        inode->ctime = n->ctime;
        return 0;
    }
    if ((uint64_t)off + len > UINT32_MAX) len = UINT32_MAX - off;
    if (!len) return -EDGE_LINUX_EFBIG;
    while (done < len) {
        uint32_t pos = off + done;
        uint32_t bi = pos / TMPFS_BLOCK_SIZE;
        uint32_t bo = pos % TMPFS_BLOCK_SIZE;
        uint32_t nbytes = TMPFS_BLOCK_SIZE - bo;
        uint32_t block_id;
        if (nbytes > len - done) nbytes = len - done;
        tmpfs_blocks_lock();
        block_id = tmpfs_find_block_locked(n, bi);
        if (!block_id) {
            int b = tmpfs_alloc_block_locked(st, n, bi);
            if (b < 0) {
                tmpfs_blocks_unlock();
                return done ? (int)done : -EDGE_LINUX_ENOSPC;
            }
            block_id = (uint32_t)b + 1u;
        }
        if (tmpfs_restore_block_locked(
                &g_tmpfs_block_meta[block_id - 1u]) < 0) {
            tmpfs_blocks_unlock();
            return done ? (int)done : -EDGE_LINUX_EIO;
        }
        memcpy(g_tmpfs_block_meta[block_id - 1u].data + bo,
               (const uint8_t *)buf + done, nbytes);
        tmpfs_blocks_unlock();
        done += nbytes;
    }
    if (off + done > n->size) n->size = off + done;
    if (done > 0) n->mtime = n->ctime = tmpfs_now_sec();
    inode->size = n->size;
    inode->mtime = n->mtime;
    inode->ctime = n->ctime;
    return (int)done;
}

static int tmpfs_append(vfs_superblock_t *sb, vfs_inode_t *inode,
                        const void *buf, uint32_t len,
                        uint32_t *offset_out) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int idx = tmpfs_inode_index(st, inode);
    uint32_t offset;
    int result;
    if (!st || !inode || !offset_out || idx < 0 || !st->nodes[idx].used)
        return -1;
    offset = st->nodes[idx].size;
    if (len > UINT32_MAX - offset) return -1;
    result = tmpfs_write(sb, inode, offset, buf, len);
    if (result >= 0) *offset_out = offset;
    return result;
}

static int tmpfs_truncate(vfs_superblock_t *sb, vfs_inode_t *inode,
                          uint32_t length) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int index = tmpfs_inode_index(st, inode);
    tmpfs_node_t *node;
    uint32_t first_free_block;
    if (!st || index < 0 || !st->nodes[index].used ||
        st->nodes[index].is_dir)
        return -1;
    node = &st->nodes[index];
    first_free_block = (length + TMPFS_BLOCK_SIZE - 1u) / TMPFS_BLOCK_SIZE;
    tmpfs_blocks_lock();
    for (uint32_t block = 0; block < TMPFS_MAX_BLOCKS; ++block)
        if (g_tmpfs_block_used[block] &&
            g_tmpfs_block_meta[block].owner == node &&
            g_tmpfs_block_meta[block].file_page >= first_free_block)
            tmpfs_free_block_locked(block);
    if (length && (length % TMPFS_BLOCK_SIZE) && first_free_block) {
        uint32_t id = tmpfs_find_block_locked(node, first_free_block - 1u);
        if (id && id <= TMPFS_MAX_BLOCKS) {
            if (tmpfs_restore_block_locked(
                    &g_tmpfs_block_meta[id - 1u]) < 0) {
                tmpfs_blocks_unlock();
                return -1;
            }
            memset(g_tmpfs_block_meta[id - 1u].data +
                       (length % TMPFS_BLOCK_SIZE), 0,
                   TMPFS_BLOCK_SIZE - (length % TMPFS_BLOCK_SIZE));
        }
    }
    tmpfs_blocks_unlock();
    node->size = length;
    node->mtime = node->ctime = tmpfs_now_sec();
    inode->size = length;
    inode->mtime = node->mtime;
    inode->ctime = node->ctime;
    return 0;
}

static int tmpfs_allocate_or_zero_range(tmpfs_state_t *st,
                                        tmpfs_node_t *node, uint32_t offset,
                                        uint32_t length, int zero_bytes) {
    uint32_t end = offset + length;
    uint32_t page = offset / TMPFS_BLOCK_SIZE;
    uint32_t last_page = (end - 1u) / TMPFS_BLOCK_SIZE;
    tmpfs_blocks_lock();
    while (page <= last_page) {
        uint32_t id = tmpfs_find_block_locked(node, page);
        uint32_t block_start = page * TMPFS_BLOCK_SIZE;
        uint32_t from = offset > block_start ? offset - block_start : 0u;
        uint32_t to = end < block_start + TMPFS_BLOCK_SIZE ?
                      end - block_start : TMPFS_BLOCK_SIZE;
        if (!id) {
            int allocated = tmpfs_alloc_block_locked(st, node, page);
            if (allocated < 0) {
                tmpfs_blocks_unlock();
                return VFS_FALLOCATE_ERR_NOSPC;
            }
            id = (uint32_t)allocated + 1u;
        }
        if (tmpfs_restore_block_locked(
                &g_tmpfs_block_meta[id - 1u]) < 0) {
            tmpfs_blocks_unlock();
            return VFS_FALLOCATE_ERR_NOSPC;
        }
        if (zero_bytes && to > from)
            memset(g_tmpfs_block_meta[id - 1u].data + from, 0, to - from);
        page++;
    }
    tmpfs_blocks_unlock();
    return 0;
}

static int tmpfs_punch_range(tmpfs_node_t *node, uint32_t offset,
                             uint32_t length) {
    uint32_t end = offset + length;
    uint32_t page;
    uint32_t last_page;
    if (offset >= node->size) return 0;
    if (end > node->size) end = node->size;
    page = offset / TMPFS_BLOCK_SIZE;
    last_page = (end - 1u) / TMPFS_BLOCK_SIZE;
    tmpfs_blocks_lock();
    while (page <= last_page) {
        uint32_t id = tmpfs_find_block_locked(node, page);
        uint32_t block_start = page * TMPFS_BLOCK_SIZE;
        uint32_t from = offset > block_start ? offset - block_start : 0u;
        uint32_t to = end < block_start + TMPFS_BLOCK_SIZE ?
                      end - block_start : TMPFS_BLOCK_SIZE;
        if (id && from == 0u && to == TMPFS_BLOCK_SIZE) {
            tmpfs_free_block_locked(id - 1u);
        } else if (id && to > from) {
            if (tmpfs_restore_block_locked(
                    &g_tmpfs_block_meta[id - 1u]) < 0) {
                tmpfs_blocks_unlock();
                return VFS_FALLOCATE_ERR_NOSPC;
            }
            memset(g_tmpfs_block_meta[id - 1u].data + from, 0,
                   to - from);
        }
        page++;
    }
    tmpfs_blocks_unlock();
    return 0;
}

static int tmpfs_fallocate(vfs_superblock_t *sb, vfs_inode_t *inode,
                           uint32_t mode, uint64_t offset64,
                           uint64_t length64) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int index = tmpfs_inode_index(st, inode);
    tmpfs_node_t *node;
    uint32_t offset;
    uint32_t length;
    uint32_t end;
    int rc = 0;
    if (!st || index < 0 || !st->nodes[index].used ||
        st->nodes[index].is_dir || !length64)
        return VFS_FALLOCATE_ERR_INVALID;
    if (offset64 > UINT32_MAX || length64 > UINT32_MAX ||
        offset64 + length64 > UINT32_MAX || offset64 + length64 < offset64)
        return VFS_FALLOCATE_ERR_INVALID;
    offset = (uint32_t)offset64;
    length = (uint32_t)length64;
    end = offset + length;
    node = &st->nodes[index];

    if (mode & VFS_FALLOC_FL_PUNCH_HOLE) {
        if (mode != (VFS_FALLOC_FL_PUNCH_HOLE | VFS_FALLOC_FL_KEEP_SIZE))
            return VFS_FALLOCATE_ERR_UNSUPPORTED;
        rc = tmpfs_punch_range(node, offset, length);
    } else if (mode & VFS_FALLOC_FL_COLLAPSE_RANGE) {
        uint8_t buffer[1024];
        uint32_t source;
        if (mode != VFS_FALLOC_FL_COLLAPSE_RANGE || end > node->size ||
            (offset % TMPFS_BLOCK_SIZE) || (length % TMPFS_BLOCK_SIZE))
            return VFS_FALLOCATE_ERR_INVALID;
        source = end;
        while (source < node->size) {
            uint32_t count = node->size - source;
            int got;
            if (count > sizeof(buffer)) count = sizeof(buffer);
            got = tmpfs_read(sb, inode, source, buffer, count);
            if (got != (int)count ||
                tmpfs_write(sb, inode, source - length, buffer, count) != (int)count)
                return VFS_FALLOCATE_ERR_IO;
            source += count;
        }
        rc = tmpfs_truncate(sb, inode, node->size - length);
    } else if (mode & VFS_FALLOC_FL_INSERT_RANGE) {
        uint8_t buffer[1024];
        uint32_t remaining;
        uint32_t old_size = node->size;
        if (mode != VFS_FALLOC_FL_INSERT_RANGE || offset > old_size ||
            old_size > UINT32_MAX - length || (offset % TMPFS_BLOCK_SIZE) ||
            (length % TMPFS_BLOCK_SIZE))
            return VFS_FALLOCATE_ERR_INVALID;
        remaining = old_size - offset;
        while (remaining) {
            uint32_t count = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
            uint32_t source = offset + remaining - count;
            int got = tmpfs_read(sb, inode, source, buffer, count);
            if (got != (int)count ||
                tmpfs_write(sb, inode, source + length, buffer, count) != (int)count)
                return VFS_FALLOCATE_ERR_IO;
            remaining -= count;
        }
        rc = tmpfs_allocate_or_zero_range(st, node, offset, length, 1);
        if (rc == 0) node->size = old_size + length;
    } else if (mode & VFS_FALLOC_FL_ZERO_RANGE) {
        /* Linux shmem/tmpfs does not implement FALLOC_FL_ZERO_RANGE. */
        return VFS_FALLOCATE_ERR_UNSUPPORTED;
    } else {
        if (mode & ~(VFS_FALLOC_FL_KEEP_SIZE | VFS_FALLOC_FL_UNSHARE_RANGE))
            return VFS_FALLOCATE_ERR_UNSUPPORTED;
        rc = tmpfs_allocate_or_zero_range(st, node, offset, length, 0);
        if (rc == 0 && !(mode & VFS_FALLOC_FL_KEEP_SIZE) && end > node->size)
            node->size = end;
    }

    if (rc < 0) return rc;
    node->mtime = node->ctime = tmpfs_now_sec();
    inode->size = node->size;
    inode->mtime = node->mtime;
    inode->ctime = node->ctime;
    return 0;
}

static int tmpfs_seek_data_hole(vfs_superblock_t *sb,
                                const vfs_inode_t *inode,
                                uint64_t offset, int seek_hole,
                                uint64_t *result) {
    tmpfs_state_t *state = tmpfs_state(sb);
    int index = tmpfs_inode_index(state, inode);
    tmpfs_node_t *node;
    uint64_t page;
    uint64_t last;

    if (!state || index < 0 || !result ||
        !state->nodes[index].used || state->nodes[index].is_dir)
        return VFS_SEEK_DATA_HOLE_ERR_INVALID;
    node = &state->nodes[index];
    if (offset >= node->size)
        return VFS_SEEK_DATA_HOLE_ERR_NO_DATA;
    page = offset / TMPFS_BLOCK_SIZE;
    last = (node->size - 1u) / TMPFS_BLOCK_SIZE;
    tmpfs_blocks_lock();
    while (page <= last) {
        int mapped = page <= UINT32_MAX &&
            tmpfs_find_block_locked(node, (uint32_t)page) != 0;
        if ((seek_hole && !mapped) || (!seek_hole && mapped)) {
            uint64_t page_offset = page * TMPFS_BLOCK_SIZE;
            *result = page_offset < offset ? offset : page_offset;
            tmpfs_blocks_unlock();
            return 0;
        }
        ++page;
    }
    tmpfs_blocks_unlock();
    if (seek_hole) {
        *result = node->size;
        return 0;
    }
    return VFS_SEEK_DATA_HOLE_ERR_NO_DATA;
}

int tmpfs_shared_page(vfs_superblock_t *sb, vfs_inode_t *inode,
                      uint32_t offset, int create, uint64_t *physical_out) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int index = tmpfs_inode_index(st, inode);
    uint32_t block;
    uint32_t id;
    int allocated;
    if (!st || !physical_out || index < 0 || !st->nodes[index].used ||
        st->nodes[index].is_dir || (offset & (TMPFS_BLOCK_SIZE - 1u)))
        return -1;
    block = offset / TMPFS_BLOCK_SIZE;
    if (offset >= st->nodes[index].size) return -1;
    tmpfs_blocks_lock();
    id = tmpfs_find_block_locked(&st->nodes[index], block);
    if (!id && create) {
        allocated = tmpfs_alloc_block_locked(st, &st->nodes[index], block);
        if (allocated < 0) {
            tmpfs_blocks_unlock();
            return -1;
        }
        id = (uint32_t)allocated + 1u;
    }
    if (!id || id > TMPFS_MAX_BLOCKS) {
        tmpfs_blocks_unlock();
        return -1;
    }
    if (tmpfs_restore_block_locked(
            &g_tmpfs_block_meta[id - 1u]) < 0) {
        tmpfs_blocks_unlock();
        return -1;
    }
    *physical_out =
        (uint64_t)(uintptr_t)g_tmpfs_block_meta[id - 1u].data;
    tmpfs_blocks_unlock();
    return 0;
}

__attribute__((weak))
int arch_tmpfs_unmap_shared_page(vfs_superblock_t *sb,
                                 const vfs_inode_t *inode,
                                 uint32_t offset, uint64_t physical) {
    (void)sb;
    (void)inode;
    (void)offset;
    (void)physical;
    return -1;
}

__attribute__((weak))
int arch_tmpfs_shared_page_cgroup(uint64_t physical,
                                  uint32_t *cgroup_id_out) {
    (void)physical;
    (void)cgroup_id_out;
    return -1;
}

uint32_t tmpfs_pageout_range(vfs_superblock_t *sb, vfs_inode_t *inode,
                             uint32_t offset, uint32_t length,
                             uint32_t cgroup_id) {
#ifdef CONFIG_FS_SWAP
    tmpfs_state_t *state = tmpfs_state(sb);
    int inode_index = tmpfs_inode_index(state, inode);
    tmpfs_node_t *node;
    uint64_t end;
    uint32_t reclaimed = 0;

    if (!state || inode_index < 0 || !state->nodes[inode_index].used ||
        state->nodes[inode_index].is_dir || !length ||
        !swap_total_bytes())
        return 0;
    end = (uint64_t)offset + length;
    if (end > UINT32_MAX + UINT64_C(1))
        end = UINT32_MAX + UINT64_C(1);
    node = &state->nodes[inode_index];
    offset &= ~(TMPFS_BLOCK_SIZE - 1u);
    end = (end + TMPFS_BLOCK_SIZE - 1u) &
          ~(uint64_t)(TMPFS_BLOCK_SIZE - 1u);
    tmpfs_blocks_lock();
    for (uint64_t position = offset; position < end;
         position += TMPFS_BLOCK_SIZE) {
        uint32_t block_id = tmpfs_find_block_locked(
            node, (uint32_t)(position / TMPFS_BLOCK_SIZE));
        tmpfs_block_meta_t *meta;
        uint64_t swap_entry;
        uint8_t *data;
        uint32_t page_cgroup;
        int unmapped;

        if (!block_id || block_id > TMPFS_MAX_BLOCKS) continue;
        meta = &g_tmpfs_block_meta[block_id - 1u];
        data = meta->data;
        if (!data || meta->swap_entry) continue;
        if (arch_tmpfs_shared_page_cgroup(
                (uint64_t)(uintptr_t)data, &page_cgroup) == 0 &&
            page_cgroup != cgroup_id)
            continue;
        unmapped = arch_tmpfs_unmap_shared_page(
            sb, inode, (uint32_t)position,
            (uint64_t)(uintptr_t)data);
        if (unmapped <= 0 ||
            arch_tmpfs_shared_page_cgroup(
                (uint64_t)(uintptr_t)data, &page_cgroup) == 0)
            continue;
        if (swap_store_page(cgroup_id, data, &swap_entry) < 0)
            break;
        meta->swap_entry = swap_entry;
        meta->data = 0;
        if (state->resident_blocks) --state->resident_blocks;
        arch_vm_free_page(data);
        ++reclaimed;
    }
    tmpfs_blocks_unlock();
    return reclaimed;
#else
    (void)sb;
    (void)inode;
    (void)offset;
    (void)length;
    (void)cgroup_id;
    return 0;
#endif
}

static int tmpfs_create_node(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, int is_dir, vfs_inode_t *out) {
    tmpfs_state_t *st = tmpfs_state(sb);
    kernel_linux_identity_t identity;
    int didx;
    int idx;
    if (!st || !dir || !name || !name[0] || strlen(name) >= VFS_NAME_MAX)
        return VFS_PATH_ERR_INVALID;
    didx = tmpfs_inode_index(st, dir);
    if (didx < 0 || !st->nodes[didx].used || !st->nodes[didx].is_dir)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    if (tmpfs_find_child(st, (uint32_t)didx, name) >= 0)
        return VFS_PATH_ERR_EXISTS;
    idx = tmpfs_alloc_node(st);
    if (idx < 0) return VFS_PATH_ERR_NO_SPACE;
    st->nodes[idx].is_dir = is_dir ? 1 : 0;
    st->nodes[idx].kind = is_dir ? VFS_INODE_DIR : (uint16_t)(mode & 0xF000u);
    if (st->nodes[idx].kind == 0) st->nodes[idx].kind = VFS_INODE_FILE;
    st->nodes[idx].mode = (uint16_t)(mode & 07777u);
    if (kernel_current_linux_identity(&identity) == 0) {
        st->nodes[idx].uid = identity.fsuid;
        st->nodes[idx].gid = identity.fsgid;
    }
    if (st->nodes[didx].mode & 02000u) {
        st->nodes[idx].gid = st->nodes[didx].gid;
        if (is_dir) st->nodes[idx].mode |= 02000u;
    }
    st->nodes[idx].parent = (uint32_t)didx;
    st->nodes[idx].atime = st->nodes[idx].mtime = st->nodes[idx].ctime = tmpfs_now_sec();
    strncpy(st->nodes[idx].name, name, VFS_NAME_MAX - 1);
    st->nodes[idx].name[VFS_NAME_MAX - 1] = 0;
    tmpfs_node_hash_insert(st, (uint32_t)idx);
    if (out) tmpfs_fill_inode(st, (uint32_t)idx, out);
    return 0;
}

static int tmpfs_create(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    return tmpfs_create_node(sb, dir, name, mode, 0, out);
}

static int tmpfs_mknod(vfs_superblock_t *sb, vfs_inode_t *dir,
                        const char *name, uint16_t mode, uint64_t rdev,
                        vfs_inode_t *out) {
    int result = tmpfs_create_node(sb, dir, name, mode, 0, out);
    int index;
    tmpfs_state_t *state;
    if (result < 0) return result;
    state = tmpfs_state(sb);
    index = tmpfs_inode_index(state, out);
    if (!state || index < 0) return -1;
    state->nodes[index].rdev = rdev;
    out->rdev = rdev;
    return 0;
}

static int tmpfs_mkdir(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    return tmpfs_create_node(sb, dir, name, mode, 1, out);
}

static int tmpfs_symlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name,
                         const char *target, uint16_t mode, vfs_inode_t *out) {
    tmpfs_state_t *state = tmpfs_state(sb);
    vfs_inode_t link;
    uint32_t len;
    int index;
    int result;
    if (!target) return VFS_PATH_ERR_INVALID;
    len = (uint32_t)strlen(target);
    result = tmpfs_create_node(sb, dir, name,
                               (uint16_t)(VFS_INODE_LNK | (mode & 07777u)),
                               0, &link);
    if (result < 0) return result;
    result = len ? tmpfs_write(sb, &link, 0, target, len) : 0;
    if (result != (int)len) {
        index = tmpfs_inode_index(state, &link);
        if (index > 0) tmpfs_unlink_node(state, (uint32_t)index);
        return result == -EDGE_LINUX_ENOSPC ? VFS_PATH_ERR_NO_SPACE :
                                              VFS_PATH_ERR_IO;
    }
    if (out) *out = link;
    return 0;
}

static int tmpfs_readlink(vfs_superblock_t *sb, vfs_inode_t *inode, char *out, uint32_t max) {
    if (!inode || !out || max == 0 || (inode->mode & 0xF000u) != VFS_INODE_LNK) return -1;
    return tmpfs_read(sb, inode, 0, out, max);
}

static void tmpfs_remove_tree(tmpfs_state_t *st, uint32_t idx) {
    if (!st || idx == 0 || idx >= st->max_nodes || !st->nodes[idx].used)
        return;
    if (st->nodes[idx].hardlink_target) {
        tmpfs_clear_node(st, idx);
        return;
    }
    for (uint32_t i = 1; i < st->node_scan_limit; ++i) {
        if (st->nodes[i].used && st->nodes[i].parent == idx) tmpfs_remove_tree(st, i);
    }
    for (uint32_t i = 1; i < st->node_scan_limit; ++i)
        if (st->nodes[i].used &&
            st->nodes[i].hardlink_target == idx + 1u)
            tmpfs_clear_node(st, i);
    tmpfs_free_file_blocks(st, &st->nodes[idx]);
    tmpfs_clear_node(st, idx);
}

static void tmpfs_unlink_node(tmpfs_state_t *state, uint32_t index) {
    tmpfs_node_t *node;
    int canonical;
    if (!state || !index || index >= state->max_nodes ||
        !state->nodes[index].used)
        return;
    node = &state->nodes[index];
    canonical = tmpfs_canonical_index(state, index);
    if (canonical < 0) return;
    if (node->hardlink_target) {
        tmpfs_clear_node(state, index);
        node = &state->nodes[canonical];
        node->ctime = tmpfs_now_sec();
        if (!tmpfs_node_link_count(state, (uint32_t)canonical) &&
            !node->open_references && !node->anonymous_references &&
            !node->mapping_references)
            tmpfs_remove_tree(state, (uint32_t)canonical);
        return;
    }
    if (tmpfs_node_link_count(state, index) <= 1u &&
        !node->open_references && !node->anonymous_references &&
        !node->mapping_references) {
        tmpfs_remove_tree(state, index);
        return;
    }
    tmpfs_node_hash_remove(state, index);
    node->parent = UINT32_MAX;
    memset(node->name, 0, sizeof(node->name));
    node->ctime = tmpfs_now_sec();
}

static int tmpfs_link(vfs_superblock_t *sb, vfs_inode_t *inode,
                      vfs_inode_t *dir, const char *name) {
    tmpfs_state_t *state = tmpfs_state(sb);
    int source;
    int parent;
    int entry;
    uint32_t now;
    if (!state || !inode || !dir || !name || !name[0] ||
        strlen(name) >= VFS_NAME_MAX)
        return VFS_PATH_ERR_INVALID;
    source = tmpfs_inode_index(state, inode);
    parent = tmpfs_inode_index(state, dir);
    if (source <= 0 || parent < 0 ||
        !state->nodes[source].used || state->nodes[source].is_dir ||
        !state->nodes[parent].used || !state->nodes[parent].is_dir)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    if (tmpfs_find_child(state, (uint32_t)parent, name) >= 0)
        return VFS_PATH_ERR_EXISTS;
    if (tmpfs_node_link_count(state, (uint32_t)source) >= 0xffffu)
        return VFS_PATH_ERR_NO_SPACE;
    entry = tmpfs_alloc_node(state);
    if (entry < 0) return VFS_PATH_ERR_NO_SPACE;
    state->nodes[entry].hardlink_target = (uint32_t)source + 1u;
    state->nodes[entry].parent = (uint32_t)parent;
    strncpy(state->nodes[entry].name, name,
            sizeof(state->nodes[entry].name) - 1u);
    tmpfs_node_hash_insert(state, (uint32_t)entry);
    now = tmpfs_now_sec();
    state->nodes[source].ctime = now;
    state->nodes[parent].mtime = state->nodes[parent].ctime = now;
    return 0;
}

static int tmpfs_unlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int didx;
    int idx;
    if (!st || !dir || !name) return -1;
    didx = tmpfs_inode_index(st, dir);
    if (didx < 0 || !st->nodes[didx].used || !st->nodes[didx].is_dir) return -1;
    idx = tmpfs_find_child(st, (uint32_t)didx, name);
    if (idx <= 0) return -1;
    tmpfs_unlink_node(st, (uint32_t)idx);
    st->nodes[didx].mtime = st->nodes[didx].ctime = tmpfs_now_sec();
    return 0;
}

static int tmpfs_directory_has_children(const tmpfs_state_t *state,
                                        uint32_t directory) {
    if (!state || directory >= state->max_nodes) return 1;
    for (uint32_t index = 1; index < state->node_scan_limit; ++index)
        if (state->nodes[index].used &&
            state->nodes[index].parent == directory)
            return 1;
    return 0;
}

static int tmpfs_directory_is_ancestor(const tmpfs_state_t *state,
                                       uint32_t ancestor,
                                       uint32_t directory) {
    if (!state || ancestor >= state->max_nodes ||
        directory >= state->max_nodes)
        return 0;
    for (uint32_t depth = 0; depth < state->node_scan_limit; ++depth) {
        if (directory == ancestor) return 1;
        if (!directory || !state->nodes[directory].used) return 0;
        directory = state->nodes[directory].parent;
    }
    return 1;
}

static int tmpfs_rename(vfs_superblock_t *sb, vfs_inode_t *old_dir,
                        const char *old_name, vfs_inode_t *new_dir,
                        const char *new_name) {
    tmpfs_state_t *state = tmpfs_state(sb);
    int old_parent;
    int new_parent;
    int source;
    int target;
    int source_canonical;
    int target_canonical;
    int source_is_directory;
    uint32_t now;

    if (!state || !old_dir || !new_dir || !old_name || !new_name ||
        !old_name[0] || !new_name[0] ||
        strlen(old_name) >= VFS_NAME_MAX ||
        strlen(new_name) >= VFS_NAME_MAX ||
        strcmp(old_name, ".") == 0 || strcmp(old_name, "..") == 0 ||
        strcmp(new_name, ".") == 0 || strcmp(new_name, "..") == 0)
        return VFS_PATH_ERR_INVALID;

    old_parent = tmpfs_inode_index(state, old_dir);
    new_parent = tmpfs_inode_index(state, new_dir);
    if (old_parent < 0 || new_parent < 0 ||
        !state->nodes[old_parent].used ||
        !state->nodes[new_parent].used ||
        !state->nodes[old_parent].is_dir ||
        !state->nodes[new_parent].is_dir)
        return VFS_PATH_ERR_NOT_DIRECTORY;

    source = tmpfs_find_child(state, (uint32_t)old_parent, old_name);
    if (source <= 0) return VFS_PATH_ERR_NOT_FOUND;
    source_canonical = tmpfs_canonical_index(state, (uint32_t)source);
    if (source_canonical <= 0) return VFS_PATH_ERR_NOT_FOUND;
    if (old_parent == new_parent && strcmp(old_name, new_name) == 0)
        return 0;

    source_is_directory = state->nodes[source_canonical].is_dir != 0;
    if (source_is_directory &&
        tmpfs_directory_is_ancestor(state, (uint32_t)source_canonical,
                                    (uint32_t)new_parent))
        return VFS_PATH_ERR_INVALID;

    target = tmpfs_find_child(state, (uint32_t)new_parent, new_name);
    if (target == source) return 0;
    if (target > 0) {
        int target_is_directory;
        target_canonical = tmpfs_canonical_index(state, (uint32_t)target);
        if (target_canonical < 0) return VFS_PATH_ERR_NOT_FOUND;
        if (target_canonical == source_canonical) return 0;
        target_is_directory = state->nodes[target_canonical].is_dir != 0;
        if (source_is_directory && !target_is_directory)
            return VFS_PATH_ERR_NOT_DIRECTORY;
        if (!source_is_directory && target_is_directory)
            return VFS_PATH_ERR_IS_DIRECTORY;
        if (target_is_directory &&
            tmpfs_directory_has_children(state, (uint32_t)target))
            return VFS_PATH_ERR_NOT_EMPTY;
    }

    /*
     * A tmpfs rename is a metadata transaction.  Remove a compatible target
     * only after all validation has completed, then publish the source under
     * its new parent and name without copying file contents or changing inode
     * identity.
     */
    if (target > 0) tmpfs_unlink_node(state, (uint32_t)target);
    tmpfs_node_hash_remove(state, (uint32_t)source);
    state->nodes[source].parent = (uint32_t)new_parent;
    memset(state->nodes[source].name, 0,
           sizeof(state->nodes[source].name));
    strncpy(state->nodes[source].name, new_name,
            sizeof(state->nodes[source].name) - 1u);
    tmpfs_node_hash_insert(state, (uint32_t)source);
    now = tmpfs_now_sec();
    state->nodes[source_canonical].ctime = now;
    state->nodes[old_parent].mtime = state->nodes[old_parent].ctime = now;
    state->nodes[new_parent].mtime = state->nodes[new_parent].ctime = now;
    return 0;
}

int tmpfs_retain_anonymous(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    vfs_superblock_t *stable = vfs_superblock_acquire(sb);
    tmpfs_state_t *st;
    int idx;
    int result = -1;

    if (!stable) return -1;
    st = tmpfs_state(stable);
    idx = tmpfs_inode_index(st, inode);
    tmpfs_states_lock();
    if (!st || idx <= 0 || !st->nodes[idx].used ||
        st->nodes[idx].parent != UINT32_MAX || st->nodes[idx].name[0])
        goto out;
    if (!st->nodes[idx].anonymous_references ||
        st->nodes[idx].anonymous_references == UINT32_MAX)
        goto out;
    ++st->nodes[idx].anonymous_references;
    result = 0;
out:
    tmpfs_states_unlock();
    if (result < 0) vfs_superblock_release(stable);
    return result;
}

void tmpfs_release_anonymous(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    vfs_superblock_t *stable = vfs_superblock_stable(sb);
    tmpfs_state_t *st = tmpfs_state(stable);
    int idx = tmpfs_inode_index(st, inode);
    tmpfs_states_lock();
    if (!st || idx <= 0 || !st->nodes[idx].used ||
        st->nodes[idx].parent != UINT32_MAX || st->nodes[idx].name[0] ||
        !st->nodes[idx].anonymous_references) {
        tmpfs_states_unlock();
        return;
    }
    if (--st->nodes[idx].anonymous_references == 0 &&
        !st->nodes[idx].open_references &&
        !st->nodes[idx].mapping_references &&
        !tmpfs_node_link_count(st, (uint32_t)idx))
        tmpfs_remove_tree(st, (uint32_t)idx);
    tmpfs_states_unlock();
    vfs_superblock_release(stable);
}

int tmpfs_retain_mapping(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    vfs_superblock_t *stable = vfs_superblock_acquire(sb);
    tmpfs_state_t *state;
    int index;
    int result = -1;

    if (!stable) return -1;
    state = tmpfs_state(stable);
    index = tmpfs_inode_index(state, inode);
    tmpfs_states_lock();
    if (state && index > 0 && state->nodes[index].used &&
        !state->nodes[index].is_dir &&
        state->nodes[index].mapping_references != UINT32_MAX) {
        ++state->nodes[index].mapping_references;
        result = 0;
    }
    tmpfs_states_unlock();
    if (result < 0) vfs_superblock_release(stable);
    return result;
}

void tmpfs_release_mapping(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    vfs_superblock_t *stable = vfs_superblock_stable(sb);
    tmpfs_state_t *state = tmpfs_state(stable);
    int index = tmpfs_inode_index(state, inode);

    tmpfs_states_lock();
    if (state && index > 0 && state->nodes[index].used &&
        state->nodes[index].mapping_references) {
        --state->nodes[index].mapping_references;
        if (!state->nodes[index].mapping_references &&
            !state->nodes[index].open_references &&
            !state->nodes[index].anonymous_references &&
            !tmpfs_node_link_count(state, (uint32_t)index))
            tmpfs_remove_tree(state, (uint32_t)index);
    }
    tmpfs_states_unlock();
    vfs_superblock_release(stable);
}

static int tmpfs_rmdir(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int didx;
    int idx;
    if (!st || !dir || !name) return VFS_PATH_ERR_INVALID;
    didx = tmpfs_inode_index(st, dir);
    if (didx < 0 || !st->nodes[didx].used || !st->nodes[didx].is_dir)
        return VFS_PATH_ERR_NOT_DIRECTORY;
    idx = tmpfs_find_child(st, (uint32_t)didx, name);
    if (idx <= 0) return VFS_PATH_ERR_NOT_FOUND;
    if (!st->nodes[idx].is_dir) return VFS_PATH_ERR_NOT_DIRECTORY;
    for (uint32_t i = 1; i < st->node_scan_limit; ++i)
        if (st->nodes[i].used && st->nodes[i].parent == (uint32_t)idx)
            return VFS_PATH_ERR_NOT_EMPTY;
    tmpfs_unlink_node(st, (uint32_t)idx);
    st->nodes[didx].mtime = st->nodes[didx].ctime = tmpfs_now_sec();
    return 0;
}

static int tmpfs_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int didx = tmpfs_inode_index(st, dir);
    uint32_t seen = 0;
    if (!st || !dir || !name_out || !inode_out || didx < 0 || !st->nodes[didx].used || !st->nodes[didx].is_dir) return -1;
    if (idx == 0) {
        strcpy(name_out, ".");
        tmpfs_fill_inode(st, (uint32_t)didx, inode_out);
        return 0;
    }
    if (idx == 1) {
        strcpy(name_out, "..");
        tmpfs_fill_inode(st, st->nodes[didx].parent, inode_out);
        return 0;
    }
    for (uint32_t i = 1; i < st->node_scan_limit; ++i) {
        if (!st->nodes[i].used || st->nodes[i].parent != (uint32_t)didx) continue;
        if (seen == idx - 2) {
            strncpy(name_out, st->nodes[i].name, VFS_NAME_MAX - 1);
            name_out[VFS_NAME_MAX - 1] = 0;
            tmpfs_fill_inode(st, i, inode_out);
            return 0;
        }
        seen++;
    }
    return -1;
}

static int tmpfs_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    tmpfs_state_t *st = tmpfs_state(sb);
    if (!st || !total_kb || !used_kb) return -1;
    *total_kb = (st->max_blocks * TMPFS_BLOCK_SIZE) / 1024;
    *used_kb = ((st->allocated_blocks + st->xattr_pages) *
                TMPFS_BLOCK_SIZE) / 1024;
    return 0;
}

uint64_t tmpfs_resident_bytes(void) {
    uint64_t used = 0;

    tmpfs_blocks_lock();
    for (uint32_t i = 0; i < TMPFS_MAX_BLOCKS; ++i)
        if (g_tmpfs_block_used[i]) ++used;
    tmpfs_blocks_unlock();
    return used * TMPFS_BLOCK_SIZE;
}

int tmpfs_cachestat(vfs_superblock_t *sb, const vfs_inode_t *inode,
                    uint64_t offset, uint64_t length,
                    uint64_t *resident_pages,
                    uint64_t *swapped_pages) {
    tmpfs_state_t *state = tmpfs_state(sb);
    int index = tmpfs_inode_index(state, inode);
    tmpfs_node_t *node;
    uint64_t first_page;
    uint64_t end;
    uint64_t last_page;
    uint64_t resident = 0;
    uint64_t swapped = 0;

    if (resident_pages) *resident_pages = 0;
    if (swapped_pages) *swapped_pages = 0;
    if (!state || index < 0 || !state->nodes[index].used ||
        state->nodes[index].is_dir)
        return -1;
    node = &state->nodes[index];
    first_page = offset / TMPFS_BLOCK_SIZE;
    end = !length || length > UINT64_MAX - offset ?
          UINT64_MAX : offset + length;
    last_page = end == UINT64_MAX ? UINT64_MAX :
                (end - (end != 0u)) / TMPFS_BLOCK_SIZE;

    tmpfs_blocks_lock();
    for (uint32_t block = 0; block < g_tmpfs_block_next_unused; ++block) {
        const tmpfs_block_meta_t *meta;

        if (!g_tmpfs_block_used[block]) continue;
        meta = &g_tmpfs_block_meta[block];
        if (meta->owner != node || meta->file_page < first_page ||
            meta->file_page > last_page)
            continue;
        if (meta->data)
            ++resident;
        else if (meta->swap_entry)
            ++swapped;
    }
    tmpfs_blocks_unlock();
    if (resident_pages) *resident_pages = resident;
    if (swapped_pages) *swapped_pages = swapped;
    return 0;
}

int tmpfs_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode, uint32_t atime, uint32_t mtime, int set_atime, int set_mtime) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int idx = tmpfs_inode_index(st, inode);
    tmpfs_node_t *n;
    if (!st || idx < 0 || !st->nodes[idx].used) return -1;
    n = &st->nodes[idx];
    /*
     * tmpfs is volatile, but Linux still reports stable per-inode timestamps.
     * OpenRC depends on utimensat(2) taking effect for /run/openrc/deptree;
     * returning success without changing tmpfs mtimes makes it rebuild the
     * service cache forever.
     */
    if (set_atime) n->atime = atime;
    if (set_mtime) n->mtime = mtime;
    n->ctime = tmpfs_now_sec();
    return 0;
}

int tmpfs_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                  uint16_t mode, uint32_t uid, uint32_t gid, uint32_t mask) {
    tmpfs_state_t *st = tmpfs_state(sb);
    int idx = tmpfs_inode_index(st, inode);
    tmpfs_node_t *n;
    if (!st || idx < 0 || !st->nodes[idx].used) return -1;
    n = &st->nodes[idx];
    if (mask & 1u) n->mode = (uint16_t)(mode & 07777u);
    if (mask & 2u) n->uid = uid;
    if (mask & 4u) n->gid = gid;
    n->ctime = tmpfs_now_sec();
    return 0;
}

static char *tmpfs_xattr_name(tmpfs_xattr_t *attribute) {
    return attribute ? (char *)attribute->data : 0;
}

static const char *tmpfs_xattr_const_name(const tmpfs_xattr_t *attribute) {
    return attribute ? (const char *)attribute->data : 0;
}

static void *tmpfs_xattr_value(tmpfs_xattr_t *attribute) {
    return attribute ? attribute->data + attribute->name_length + 1u : 0;
}

static const void *tmpfs_xattr_const_value(
    const tmpfs_xattr_t *attribute) {
    return attribute ? attribute->data + attribute->name_length + 1u : 0;
}

static tmpfs_xattr_t *tmpfs_find_xattr(tmpfs_node_t *node,
                                       const char *name,
                                       tmpfs_xattr_t ***link_out) {
    tmpfs_xattr_t **link;
    if (!node || !name) return 0;
    link = &node->xattrs;
    while (*link) {
        if (strcmp(tmpfs_xattr_const_name(*link), name) == 0) {
            if (link_out) *link_out = link;
            return *link;
        }
        link = &(*link)->next;
    }
    if (link_out) *link_out = link;
    return 0;
}

static tmpfs_xattr_t *tmpfs_allocate_xattr(const char *name,
                                            const void *value,
                                            uint32_t value_length) {
    tmpfs_xattr_t *attribute;
    uint32_t name_length;
    uint32_t pages;
    uint64_t bytes;
    if (!name || (value_length && !value)) return 0;
    name_length = (uint32_t)strlen(name);
    bytes = sizeof(*attribute) + (uint64_t)name_length + 1u + value_length;
    pages = (uint32_t)((bytes + TMPFS_BLOCK_SIZE - 1u) /
                       TMPFS_BLOCK_SIZE);
    attribute = (tmpfs_xattr_t *)arch_vm_alloc_pages(pages);
    if (!attribute) return 0;
    memset(attribute, 0, (uint64_t)pages * TMPFS_BLOCK_SIZE);
    attribute->allocation_pages = pages;
    attribute->name_length = name_length;
    attribute->value_length = value_length;
    memcpy(tmpfs_xattr_name(attribute), name, name_length + 1u);
    if (value_length)
        memcpy(tmpfs_xattr_value(attribute), value, value_length);
    return attribute;
}

static int tmpfs_setxattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                          const char *name, const void *value, uint32_t size,
                          uint32_t flags) {
    tmpfs_state_t *state = tmpfs_state(sb);
    tmpfs_xattr_t *replacement;
    tmpfs_xattr_t *old;
    tmpfs_xattr_t **link = 0;
    tmpfs_node_t *node;
    int index;
    int result = 0;

    if (!state || !inode || !name || !name[0] ||
        (size && !value) || size > VFS_XATTR_VALUE_MAX)
        return VFS_XATTR_ERR_INVALID;
    replacement = tmpfs_allocate_xattr(name, value, size);
    if (!replacement) return VFS_XATTR_ERR_NOSPC;

    tmpfs_xattrs_lock();
    index = tmpfs_inode_index(state, inode);
    if (index < 0 || !state->nodes[index].used) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    index = tmpfs_canonical_index(state, (uint32_t)index);
    if (index < 0) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    node = &state->nodes[index];
    old = tmpfs_find_xattr(node, name, &link);
    if (old && (flags & VFS_XATTR_CREATE)) {
        result = VFS_XATTR_ERR_EXISTS;
        goto out;
    }
    if (!old && (flags & VFS_XATTR_REPLACE)) {
        result = VFS_XATTR_ERR_NO_DATA;
        goto out;
    }
    if ((uint64_t)state->allocated_blocks + state->xattr_pages -
            (old ? old->allocation_pages : 0u) +
            replacement->allocation_pages > state->max_blocks) {
        result = VFS_XATTR_ERR_NOSPC;
        goto out;
    }
    replacement->next = old ? old->next : 0;
    *link = replacement;
    state->xattr_pages += replacement->allocation_pages;
    if (old) {
        state->xattr_pages -= old->allocation_pages;
        tmpfs_free_xattr_allocation(old);
    }
    node->ctime = tmpfs_now_sec();
    replacement = 0;
out:
    tmpfs_xattrs_unlock();
    tmpfs_free_xattr_allocation(replacement);
    return result;
}

static int tmpfs_getxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                          const char *name, void *value, uint32_t size) {
    tmpfs_state_t *state = tmpfs_state(sb);
    tmpfs_xattr_t *attribute;
    int index;
    int result;

    if (!state || !inode || !name || !name[0] || (size && !value))
        return VFS_XATTR_ERR_INVALID;
    tmpfs_xattrs_lock();
    index = tmpfs_inode_index(state, inode);
    if (index < 0 || !state->nodes[index].used) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    index = tmpfs_canonical_index(state, (uint32_t)index);
    if (index < 0) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    attribute = tmpfs_find_xattr(&state->nodes[index], name, 0);
    if (!attribute) {
        result = VFS_XATTR_ERR_NO_DATA;
        goto out;
    }
    if (!value && !size) {
        result = (int)attribute->value_length;
        goto out;
    }
    if (size < attribute->value_length) {
        result = VFS_XATTR_ERR_RANGE;
        goto out;
    }
    if (attribute->value_length)
        memcpy(value, tmpfs_xattr_const_value(attribute),
               attribute->value_length);
    result = (int)attribute->value_length;
out:
    tmpfs_xattrs_unlock();
    return result;
}

static int tmpfs_listxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           char *list, uint32_t size) {
    tmpfs_state_t *state = tmpfs_state(sb);
    tmpfs_xattr_t *attribute;
    uint32_t required = 0;
    uint32_t written = 0;
    int index;
    int result;

    if (!state || !inode || (size && !list))
        return VFS_XATTR_ERR_INVALID;
    tmpfs_xattrs_lock();
    index = tmpfs_inode_index(state, inode);
    if (index < 0 || !state->nodes[index].used) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    index = tmpfs_canonical_index(state, (uint32_t)index);
    if (index < 0) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    for (attribute = state->nodes[index].xattrs; attribute;
         attribute = attribute->next) {
        if (required > VFS_XATTR_VALUE_MAX - attribute->name_length - 1u) {
            result = VFS_XATTR_ERR_RANGE;
            goto out;
        }
        required += attribute->name_length + 1u;
    }
    if (!list && !size) {
        result = (int)required;
        goto out;
    }
    if (size < required) {
        result = VFS_XATTR_ERR_RANGE;
        goto out;
    }
    for (attribute = state->nodes[index].xattrs; attribute;
         attribute = attribute->next) {
        memcpy(list + written, tmpfs_xattr_const_name(attribute),
               attribute->name_length + 1u);
        written += attribute->name_length + 1u;
    }
    result = (int)written;
out:
    tmpfs_xattrs_unlock();
    return result;
}

static int tmpfs_removexattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                             const char *name) {
    tmpfs_state_t *state = tmpfs_state(sb);
    tmpfs_xattr_t *attribute;
    tmpfs_xattr_t **link = 0;
    tmpfs_node_t *node;
    int index;
    int result = 0;

    if (!state || !inode || !name || !name[0])
        return VFS_XATTR_ERR_INVALID;
    tmpfs_xattrs_lock();
    index = tmpfs_inode_index(state, inode);
    if (index < 0 || !state->nodes[index].used) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    index = tmpfs_canonical_index(state, (uint32_t)index);
    if (index < 0) {
        result = VFS_XATTR_ERR_IO;
        goto out;
    }
    node = &state->nodes[index];
    attribute = tmpfs_find_xattr(node, name, &link);
    if (!attribute) {
        result = VFS_XATTR_ERR_NO_DATA;
        goto out;
    }
    *link = attribute->next;
    if (state->xattr_pages >= attribute->allocation_pages)
        state->xattr_pages -= attribute->allocation_pages;
    else
        state->xattr_pages = 0;
    tmpfs_free_xattr_allocation(attribute);
    node->ctime = tmpfs_now_sec();
out:
    tmpfs_xattrs_unlock();
    return result;
}

typedef struct {
    uint32_t inode;
    uint32_t generation;
} tmpfs_export_handle_t;

static int tmpfs_encode_handle(vfs_superblock_t *sb,
                               const vfs_inode_t *inode,
                               uint32_t *handle_type, void *handle,
                               uint32_t *handle_bytes) {
    tmpfs_state_t *state = tmpfs_state(sb);
    tmpfs_export_handle_t value;
    int index = tmpfs_inode_index(state, inode);
    if (!state || index < 0 || !handle_type || !handle_bytes ||
        !state->nodes[index].used)
        return VFS_FILE_HANDLE_ERR_STALE;
    *handle_type = 1u;
    if (*handle_bytes < sizeof(value)) {
        *handle_bytes = sizeof(value);
        return VFS_FILE_HANDLE_ERR_OVERFLOW;
    }
    if (!handle) return VFS_FILE_HANDLE_ERR_INVALID;
    value.inode = inode->ino;
    value.generation = state->nodes[index].generation;
    memcpy(handle, &value, sizeof(value));
    *handle_bytes = sizeof(value);
    return 0;
}

static int tmpfs_decode_handle(vfs_superblock_t *sb, uint32_t handle_type,
                               const void *handle, uint32_t handle_bytes,
                               vfs_inode_t *out) {
    tmpfs_state_t *state = tmpfs_state(sb);
    tmpfs_export_handle_t value;
    int index;
    if (!state || !handle || !out || handle_type != 1u ||
        handle_bytes != sizeof(value))
        return VFS_FILE_HANDLE_ERR_INVALID;
    memcpy(&value, handle, sizeof(value));
    if (!value.inode || value.inode > state->max_nodes)
        return VFS_FILE_HANDLE_ERR_STALE;
    index = (int)value.inode - 1;
    if (!state->nodes[index].used ||
        state->nodes[index].generation != value.generation)
        return VFS_FILE_HANDLE_ERR_STALE;
    tmpfs_fill_inode(state, (uint32_t)index, out);
    return 0;
}

static int tmpfs_getattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                         vfs_inode_t *out) {
    tmpfs_state_t *state = tmpfs_state(sb);
    int index = tmpfs_inode_index(state, inode);
    if (!state || !out || index < 0 || !state->nodes[index].used)
        return -1;
    tmpfs_fill_inode(state, (uint32_t)index, out);
    return 0;
}

static int tmpfs_inode_open(vfs_superblock_t *sb,
                            const vfs_inode_t *inode) {
    tmpfs_state_t *state = tmpfs_state(sb);
    int index = tmpfs_inode_index(state, inode);
    int result = -1;
    tmpfs_states_lock();
    if (state && index >= 0 && state->nodes[index].used &&
        state->nodes[index].open_references != UINT32_MAX) {
        ++state->nodes[index].open_references;
        result = 0;
    }
    tmpfs_states_unlock();
    return result;
}

static void tmpfs_inode_close(vfs_superblock_t *sb,
                              const vfs_inode_t *inode) {
    tmpfs_state_t *state = tmpfs_state(sb);
    int index = tmpfs_inode_index(state, inode);
    tmpfs_states_lock();
    if (state && index >= 0 && state->nodes[index].used &&
        state->nodes[index].open_references) {
        --state->nodes[index].open_references;
        if (!state->nodes[index].open_references &&
            !state->nodes[index].anonymous_references &&
            !state->nodes[index].mapping_references &&
            !tmpfs_node_link_count(state, (uint32_t)index))
            tmpfs_remove_tree(state, (uint32_t)index);
    }
    tmpfs_states_unlock();
}

static filesystem_ops_t g_tmpfs_ops = {
    .lookup = tmpfs_lookup,
    .read = tmpfs_read,
    .write = tmpfs_write,
    .create = tmpfs_create,
    .mkdir = tmpfs_mkdir,
    .symlink = tmpfs_symlink,
    .readlink = tmpfs_readlink,
    .unlink = tmpfs_unlink,
    .link = tmpfs_link,
    .rename = tmpfs_rename,
    .truncate = tmpfs_truncate,
    .readdir = tmpfs_readdir,
    .statfs = tmpfs_statfs,
    .rmdir = tmpfs_rmdir,
    .mknod = tmpfs_mknod,
    .fallocate = tmpfs_fallocate,
    .seek_data_hole = tmpfs_seek_data_hole,
    .encode_handle = tmpfs_encode_handle,
    .decode_handle = tmpfs_decode_handle,
    .inode_open = tmpfs_inode_open,
    .inode_close = tmpfs_inode_close,
    .append = tmpfs_append,
    .setxattr = tmpfs_setxattr,
    .getxattr = tmpfs_getxattr,
    .listxattr = tmpfs_listxattr,
    .removexattr = tmpfs_removexattr,
    .getattr = tmpfs_getattr,
    .settimes = tmpfs_settimes,
    .setattr = tmpfs_setattr,
};

static int tmpfs_initialize_superblock(tmpfs_state_t *st, vfs_superblock_t *sb,
                                       const char *dev, const char *target,
                                       const char *fs_name,
                                       uint16_t root_mode,
                                       uint32_t root_uid,
                                       uint32_t root_gid,
                                       uint32_t max_blocks,
                                       uint32_t max_nodes) {
    memset(st, 0, sizeof(*st));
    if (tmpfs_allocate_node_storage(st, max_nodes) < 0) return -1;
    st->used = 1;
    st->next_generation = 1u;
    st->max_blocks = max_blocks ? max_blocks : TMPFS_MAX_BLOCKS;
    if (st->max_blocks > TMPFS_MAX_BLOCKS)
        st->max_blocks = TMPFS_MAX_BLOCKS;
    st->nodes[0].used = 1;
    st->nodes[0].generation = st->next_generation;
    st->nodes[0].is_dir = 1;
    st->nodes[0].kind = VFS_INODE_DIR;
    st->nodes[0].mode = (uint16_t)(root_mode & 07777u);
    st->nodes[0].uid = root_uid;
    st->nodes[0].gid = root_gid;
    st->nodes[0].parent = 0;
    st->nodes[0].atime = st->nodes[0].mtime = st->nodes[0].ctime = tmpfs_now_sec();
    strcpy(st->nodes[0].name, "/");

    memset(sb, 0, sizeof(*sb));
    strncpy(sb->fs_name, fs_name && fs_name[0] ? fs_name : "tmpfs",
            sizeof(sb->fs_name) - 1);
    sb->fs_name[sizeof(sb->fs_name) - 1] = 0;
    strncpy(sb->dev_name, dev && dev[0] ? dev : "tmpfs", sizeof(sb->dev_name) - 1);
    sb->dev_name[sizeof(sb->dev_name) - 1] = 0;
    strncpy(sb->mountpoint, target, sizeof(sb->mountpoint) - 1);
    sb->mountpoint[sizeof(sb->mountpoint) - 1] = 0;
    tmpfs_fill_inode(st, 0, &sb->root);
    sb->ops = &g_tmpfs_ops;
    sb->fs_private = st;
    sb->retain = tmpfs_retain;
    sb->release = tmpfs_release;
    return 0;
}

int tmpfs_create_anonymous(uint16_t mode, uint32_t initial_seals,
                           vfs_inode_t *out_inode,
                           vfs_superblock_t **out_sb) {
    tmpfs_state_t *st = &g_tmpfs_anonymous_state;
    vfs_superblock_t *sb = &g_tmpfs_anonymous_sb;
    int index;
    if (!out_inode || !out_sb) return -1;
    tmpfs_states_lock();
    if (!st->used &&
        tmpfs_initialize_superblock(st, sb, "memfd", "/", "tmpfs",
                                    0755u, 0u, 0u, TMPFS_MAX_BLOCKS,
                                    TMPFS_INLINE_NODES) < 0) {
        tmpfs_states_unlock();
        return -1;
    }
    index = tmpfs_alloc_node(st);
    if (index < 0) {
        tmpfs_states_unlock();
        return -1;
    }
    st->nodes[index].kind = VFS_INODE_FILE;
    st->nodes[index].mode = (uint16_t)(mode & 07777u);
    st->nodes[index].parent = UINT32_MAX;
    st->nodes[index].anonymous_references = 1u;
    st->nodes[index].seals = initial_seals;
    st->nodes[index].is_memfd = 1u;
    st->nodes[index].atime = st->nodes[index].mtime =
        st->nodes[index].ctime = tmpfs_now_sec();
    {
        vfs_superblock_t *stable = vfs_superblock_acquire(sb);
        if (!stable) {
            tmpfs_clear_node(st, (uint32_t)index);
            tmpfs_states_unlock();
            return -1;
        }
        sb = stable;
    }
    tmpfs_fill_inode(st, (uint32_t)index, out_inode);
    *out_sb = sb;
    tmpfs_states_unlock();
    return 0;
}

int tmpfs_memfd_get_seals(vfs_superblock_t *sb,
                          const vfs_inode_t *inode,
                          uint32_t *seals) {
    tmpfs_state_t *state = tmpfs_state(vfs_superblock_stable(sb));
    int index;
    int result = -1;

    if (!state || !inode || !seals) return -1;
    tmpfs_states_lock();
    index = tmpfs_inode_index(state, inode);
    if (index > 0 && state->nodes[index].used &&
        state->nodes[index].is_memfd) {
        *seals = state->nodes[index].seals;
        result = 0;
    }
    tmpfs_states_unlock();
    return result;
}

int tmpfs_memfd_add_seals(vfs_superblock_t *sb,
                          const vfs_inode_t *inode,
                          uint32_t seals) {
    tmpfs_state_t *state = tmpfs_state(vfs_superblock_stable(sb));
    int index;
    int result = -1;

    if (!state || !inode) return -1;
    tmpfs_states_lock();
    index = tmpfs_inode_index(state, inode);
    if (index > 0 && state->nodes[index].used &&
        state->nodes[index].is_memfd &&
        !(state->nodes[index].seals & 1u)) {
        state->nodes[index].seals |= seals;
        result = 0;
    }
    tmpfs_states_unlock();
    return result;
}

static int tmpfs_parse_unsigned(const char *text, uint32_t base,
                                uint64_t *value_out, const char **end_out) {
    uint64_t value = 0;
    const char *cursor = text;
    int digits = 0;
    if (!text || !value_out || (base != 8u && base != 10u)) return -1;
    while (*cursor) {
        uint32_t digit;
        if (*cursor < '0' || *cursor > '9') break;
        digit = (uint32_t)(*cursor - '0');
        if (digit >= base || value > (UINT64_MAX - digit) / base) return -1;
        value = value * base + digit;
        ++cursor;
        digits = 1;
    }
    if (!digits) return -1;
    *value_out = value;
    if (end_out) *end_out = cursor;
    return 0;
}

static int tmpfs_option_name(const char *option, uint32_t length,
                             const char *name) {
    uint32_t index = 0;
    while (name[index] && index < length && option[index] == name[index])
        ++index;
    return index == length && !name[index];
}

static int tmpfs_parse_options(const char *options, uint16_t *mode_out,
                               uint32_t *uid_out, uint32_t *gid_out,
                               uint32_t *blocks_out, uint32_t *nodes_out) {
    const char *cursor = options;
    uint64_t bytes = (uint64_t)TMPFS_MAX_BLOCKS * TMPFS_BLOCK_SIZE;
    uint64_t nodes = TMPFS_INLINE_NODES;
    uint64_t value;

    if (!mode_out || !uid_out || !gid_out || !blocks_out || !nodes_out)
        return -1;
    *mode_out = 0755u;
    *uid_out = 0u;
    *gid_out = 0u;
    if (!cursor || !*cursor) goto done;
    while (*cursor) {
        const char *name = cursor;
        const char *value_text;
        const char *end;
        uint32_t name_length;
        while (*cursor && *cursor != '=' && *cursor != ',') ++cursor;
        if (*cursor != '=') return -1;
        name_length = (uint32_t)(cursor - name);
        value_text = ++cursor;
        while (*cursor && *cursor != ',') ++cursor;
        end = cursor;
        if (tmpfs_option_name(name, name_length, "mode")) {
            const char *parsed;
            if (tmpfs_parse_unsigned(value_text, 8u, &value, &parsed) < 0 ||
                parsed != end || value > 07777u)
                return -1;
            *mode_out = (uint16_t)value;
        } else if (tmpfs_option_name(name, name_length, "uid") ||
                   tmpfs_option_name(name, name_length, "gid")) {
            const char *parsed;
            if (tmpfs_parse_unsigned(value_text, 10u, &value, &parsed) < 0 ||
                parsed != end || value > UINT32_MAX)
                return -1;
            if (name[0] == 'u') *uid_out = (uint32_t)value;
            else *gid_out = (uint32_t)value;
        } else if (tmpfs_option_name(name, name_length, "size") ||
                   tmpfs_option_name(name, name_length, "nr_inodes")) {
            const char *parsed;
            uint64_t multiplier = 1u;
            if (tmpfs_parse_unsigned(value_text, 10u, &value, &parsed) < 0 ||
                parsed > end)
                return -1;
            if (parsed < end) {
                if (parsed + 1 != end) return -1;
                if (*parsed == 'k' || *parsed == 'K') multiplier = 1024u;
                else if (*parsed == 'm' || *parsed == 'M')
                    multiplier = 1024u * 1024u;
                else if (*parsed == 'g' || *parsed == 'G')
                    multiplier = 1024u * 1024u * 1024u;
                else if (*parsed == '%' &&
                         tmpfs_option_name(name, name_length, "size")) {
                    uint64_t total = arch_vm_memory_total_bytes();
                    if (value > 100u || !total) return -1;
                    bytes = (total / 100u) * value;
                    goto option_done;
                } else {
                    return -1;
                }
            }
            if (value && multiplier > UINT64_MAX / value) return -1;
            value *= multiplier;
            if (tmpfs_option_name(name, name_length, "size")) bytes = value;
            else nodes = value;
        } else {
            return -1;
        }
option_done:
        if (*cursor == ',') {
            ++cursor;
            if (!*cursor) return -1;
        }
    }
done:
    if (!bytes || !nodes) return -1;
    value = (bytes + TMPFS_BLOCK_SIZE - 1u) / TMPFS_BLOCK_SIZE;
    *blocks_out = value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
    *nodes_out = nodes > UINT32_MAX ? UINT32_MAX : (uint32_t)nodes;
    return 0;
}

int tmpfs_mount_type_options(const char *dev, const char *target,
                             const char *fs_name, const char *options) {
    tmpfs_state_t *st = 0;
    vfs_superblock_t *sb = 0;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t max_blocks;
    uint32_t max_nodes;
    int result;
    if (!target) return -1;
    if (tmpfs_parse_options(options, &mode, &uid, &gid,
                            &max_blocks, &max_nodes) < 0)
        return -1;
    tmpfs_states_lock();
    for (uint32_t i = 0; i < TMPFS_MAX_MOUNTS; ++i) {
        /* references==0 is a failed pre-add allocation from an older kernel. */
        if (g_tmpfs_states[i].used && !g_tmpfs_states[i].references) {
            tmpfs_release_node_storage(&g_tmpfs_states[i]);
            memset(&g_tmpfs_sbs[i], 0, sizeof(g_tmpfs_sbs[i]));
        }
        if (!g_tmpfs_states[i].used) {
            st = &g_tmpfs_states[i];
            sb = &g_tmpfs_sbs[i];
            break;
        }
    }
    if (!st || !sb) {
        tmpfs_states_unlock();
        return -1;
    }
    if (tmpfs_initialize_superblock(st, sb, dev, target, fs_name,
                                    mode, uid, gid, max_blocks,
                                    max_nodes) < 0) {
        memset(sb, 0, sizeof(*sb));
        tmpfs_states_unlock();
        return -1;
    }
    result = vfs_add_superblock(sb);
    if (result < 0) {
        /* A full namespace mount table must not permanently consume a slot. */
        tmpfs_release_node_storage(st);
        memset(sb, 0, sizeof(*sb));
    }
    tmpfs_states_unlock();
    return result;
}

int tmpfs_mount_type(const char *dev, const char *target, const char *fs_name) {
    return tmpfs_mount_type_options(dev, target, fs_name, 0);
}

int tmpfs_mount(const char *dev, const char *target) {
    return tmpfs_mount_type(dev, target, "tmpfs");
}
