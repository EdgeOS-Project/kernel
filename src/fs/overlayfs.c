// SPDX-License-Identifier: MPL-2.0
/*
 * Linux-compatible OverlayFS support for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * Follows Linux-visible overlay mount behavior at the VFS boundary while using
 * EdgeOS' existing path-based VFS operations.  Whiteouts created by this file
 * are tracked by the mounted overlay instance so rm/unlink hides lower-layer
 * entries without mutating lowerdir.  Persistent Linux whiteouts still require
 * first-class xattr or char-device support in the upper filesystem.
 */

#include "stdio.h"
#include "string.h"
#include "kernel/task_scratch.h"
#include "mm/arch_vm.h"
#include "sys/scheduler.h"
#include "vfs/vfs.h"

#include <stdint.h>

#define OVERLAY_PAGE_SIZE 4096u
#define OVERLAY_INITIAL_NODES 8u
#define OVERLAY_COPY_BUF 65536u
#define OVERLAY_SCRATCH_PATHS 50
#define OVERLAY_SCRATCH_CONTEXTS 16

typedef struct overlay_node {
    uint8_t used;
    uint8_t upper;
    uint8_t whiteout;
    vfs_inode_t backing;
    char rel[VFS_PATH_MAX];
} overlay_node_t;

typedef struct {
    vfs_superblock_t *superblock;
} overlay_backend_t;

typedef struct overlay_state {
    uint8_t used;
    uint32_t references;
    uint32_t allocation_pages;
    volatile uint32_t operation_lock;
    vfs_superblock_t superblock;
    char lower[VFS_PATH_MAX];
    char upper[VFS_PATH_MAX];
    char work[VFS_PATH_MAX];
    uint32_t lower_count;
    uint32_t lower_backend_pages;
    overlay_backend_t *lower_backends;
    overlay_backend_t upper_backend;
    overlay_backend_t work_backend;
    uint32_t node_capacity;
    uint32_t node_pages;
    overlay_node_t *nodes;
} overlay_state_t;

typedef struct overlay_scratch_context {
    uintptr_t owner;
    overlay_state_t *state;
    uint32_t depth;
    uint32_t allocation_pages;
    struct overlay_scratch_context *next;
    char paths[OVERLAY_SCRATCH_PATHS][VFS_PATH_MAX];
    uint8_t copy_buffer[OVERLAY_COPY_BUF];
} overlay_scratch_context_t;

static overlay_scratch_context_t
    g_overlay_scratch_contexts[OVERLAY_SCRATCH_CONTEXTS];
static overlay_scratch_context_t *g_overlay_dynamic_scratch_contexts;
static volatile uint32_t g_overlay_scratch_context_lock;

typedef struct {
    char *paths;
    uint32_t capacity;
    uint32_t pages;
} overlay_path_stack_t;

static uint32_t overlay_allocation_pages(uint64_t bytes) {
    uint64_t pages;
    if (!bytes) return 0;
    pages = (bytes + OVERLAY_PAGE_SIZE - 1u) / OVERLAY_PAGE_SIZE;
    return pages > UINT32_MAX ? 0 : (uint32_t)pages;
}

static void overlay_allocation_release(void *allocation,
                                       uint32_t pages) {
    uint8_t *base = (uint8_t *)allocation;
    if (!allocation) return;
    for (uint32_t page = 0; page < pages; ++page)
        arch_vm_free_page(base + (uint64_t)page * OVERLAY_PAGE_SIZE);
}

static overlay_state_t *overlay_state_allocate(void) {
    uint32_t pages = overlay_allocation_pages(sizeof(overlay_state_t));
    overlay_state_t *st;
    if (!pages) return 0;
    st = (overlay_state_t *)arch_vm_alloc_pages(pages);
    if (!st) return 0;
    memset(st, 0, (uint64_t)pages * OVERLAY_PAGE_SIZE);
    st->allocation_pages = pages;
    return st;
}

static void overlay_state_destroy(overlay_state_t *st) {
    uint32_t pages;
    if (!st) return;
    for (uint32_t layer = 0;
         st->lower_backends && layer < st->lower_count; ++layer) {
        if (st->lower_backends[layer].superblock)
            vfs_superblock_release(
                st->lower_backends[layer].superblock);
    }
    if (st->upper_backend.superblock)
        vfs_superblock_release(st->upper_backend.superblock);
    if (st->work_backend.superblock)
        vfs_superblock_release(st->work_backend.superblock);
    overlay_allocation_release(st->nodes, st->node_pages);
    overlay_allocation_release(st->lower_backends,
                               st->lower_backend_pages);
    pages = st->allocation_pages;
    memset(st, 0, sizeof(*st));
    overlay_allocation_release(st, pages);
}

static int overlay_node_reserve(overlay_state_t *st,
                                uint32_t required_capacity) {
    overlay_node_t *nodes;
    uint32_t capacity;
    uint32_t pages;
    if (!st) return -1;
    if (required_capacity <= st->node_capacity) return 0;
    capacity = st->node_capacity ? st->node_capacity :
        OVERLAY_INITIAL_NODES;
    while (capacity < required_capacity) {
        if (capacity > UINT32_MAX / 2u) return -1;
        capacity *= 2u;
    }
    pages = overlay_allocation_pages(
        (uint64_t)capacity * sizeof(overlay_node_t));
    if (!pages) return -1;
    nodes = (overlay_node_t *)arch_vm_alloc_pages(pages);
    if (!nodes) return -1;
    memset(nodes, 0, (uint64_t)pages * OVERLAY_PAGE_SIZE);
    if (st->nodes)
        memcpy(nodes, st->nodes,
               (uint64_t)st->node_capacity * sizeof(overlay_node_t));
    overlay_allocation_release(st->nodes, st->node_pages);
    st->nodes = nodes;
    st->node_capacity = capacity;
    st->node_pages = pages;
    return 0;
}

static int overlay_lower_backends_allocate(overlay_state_t *st) {
    uint32_t pages;
    if (!st || !st->lower_count) return -1;
    pages = overlay_allocation_pages(
        (uint64_t)st->lower_count * sizeof(overlay_backend_t));
    if (!pages) return -1;
    st->lower_backends =
        (overlay_backend_t *)arch_vm_alloc_pages(pages);
    if (!st->lower_backends) return -1;
    memset(st->lower_backends, 0,
           (uint64_t)pages * OVERLAY_PAGE_SIZE);
    st->lower_backend_pages = pages;
    return 0;
}

static int overlay_path_stack_reserve(overlay_path_stack_t *stack,
                                      uint32_t required_capacity) {
    uint32_t capacity;
    uint32_t pages;
    char *paths;
    if (!stack) return -1;
    if (required_capacity <= stack->capacity) return 0;
    capacity = stack->capacity ? stack->capacity : 8u;
    while (capacity < required_capacity) {
        if (capacity > UINT32_MAX / 2u) return -1;
        capacity *= 2u;
    }
    pages = overlay_allocation_pages((uint64_t)capacity * VFS_PATH_MAX);
    if (!pages) return -1;
    paths = (char *)arch_vm_alloc_pages(pages);
    if (!paths) return -1;
    memset(paths, 0, (uint64_t)pages * OVERLAY_PAGE_SIZE);
    if (stack->paths)
        memcpy(paths, stack->paths,
               (uint64_t)stack->capacity * VFS_PATH_MAX);
    overlay_allocation_release(stack->paths, stack->pages);
    stack->paths = paths;
    stack->capacity = capacity;
    stack->pages = pages;
    return 0;
}

static char *overlay_path_stack_at(overlay_path_stack_t *stack,
                                   uint32_t index) {
    if (!stack || !stack->paths || index >= stack->capacity) return 0;
    return stack->paths + (uint64_t)index * VFS_PATH_MAX;
}

static void overlay_path_stack_release(overlay_path_stack_t *stack) {
    if (!stack) return;
    overlay_allocation_release(stack->paths, stack->pages);
    memset(stack, 0, sizeof(*stack));
}

static overlay_state_t *overlay_state(vfs_superblock_t *sb) {
    return sb ? (overlay_state_t *)sb->fs_private : 0;
}

static void overlay_operation_lock(overlay_state_t *st) {
    if (!st) return;
    while (__atomic_exchange_n(&st->operation_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        /*
         * Overlay operations can enter a block backend while serialized.
         * That backend may yield until an interrupt completes its request.
         * A waiter must therefore yield as well: spinning here can occupy
         * every CPU and prevent the lock owner from being scheduled again.
         */
        while (__atomic_load_n(&st->operation_lock, __ATOMIC_RELAXED))
            scheduler_yield();
    }
}

static void overlay_operation_unlock(overlay_state_t *st) {
    if (st)
        __atomic_store_n(&st->operation_lock, 0u, __ATOMIC_RELEASE);
}

static uintptr_t overlay_scratch_owner(void) {
    kernel_task_scratch_t *scratch = arch_task_scratch_current();

    return scratch ? (uintptr_t)scratch : 1u;
}

static void overlay_scratch_contexts_lock(void) {
    while (__atomic_exchange_n(&g_overlay_scratch_context_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_overlay_scratch_context_lock,
                               __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void overlay_scratch_contexts_unlock(void) {
    __atomic_store_n(&g_overlay_scratch_context_lock, 0u,
                     __ATOMIC_RELEASE);
}

static int overlay_inode_is_dir(const vfs_inode_t *inode) {
    return inode && ((inode->mode & 0xF000u) == VFS_INODE_DIR);
}

static overlay_scratch_context_t *overlay_scratch_acquire(
    overlay_state_t *st) {
    uintptr_t owner;
    overlay_scratch_context_t *context;
    if (!st) return 0;
    owner = overlay_scratch_owner();
    for (uint32_t index = 0; index < OVERLAY_SCRATCH_CONTEXTS; ++index) {
        context = &g_overlay_scratch_contexts[index];
        if (__atomic_load_n(&context->owner, __ATOMIC_ACQUIRE) != owner ||
            __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) != st)
            continue;
        __atomic_add_fetch(&context->depth, 1u, __ATOMIC_RELAXED);
        return context;
    }
    for (context = __atomic_load_n(&g_overlay_dynamic_scratch_contexts,
                                   __ATOMIC_ACQUIRE);
         context;
         context = __atomic_load_n(&context->next, __ATOMIC_ACQUIRE)) {
        if (__atomic_load_n(&context->owner, __ATOMIC_ACQUIRE) != owner ||
            __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) != st)
            continue;
        __atomic_add_fetch(&context->depth, 1u, __ATOMIC_RELAXED);
        return context;
    }
    for (uint32_t index = 0; index < OVERLAY_SCRATCH_CONTEXTS; ++index) {
        context = &g_overlay_scratch_contexts[index];
        uintptr_t empty = 0;
        if (!__atomic_compare_exchange_n(&context->owner, &empty,
                                         owner, 0, __ATOMIC_ACQ_REL,
                                         __ATOMIC_RELAXED))
            continue;
        __atomic_store_n(&context->state, st, __ATOMIC_RELEASE);
        __atomic_store_n(&context->depth, 1u, __ATOMIC_RELEASE);
        return context;
    }
    for (context = __atomic_load_n(&g_overlay_dynamic_scratch_contexts,
                                   __ATOMIC_ACQUIRE);
         context;
         context = __atomic_load_n(&context->next, __ATOMIC_ACQUIRE)) {
        uintptr_t empty = 0;
        if (!__atomic_compare_exchange_n(&context->owner, &empty,
                                         owner, 0, __ATOMIC_ACQ_REL,
                                         __ATOMIC_RELAXED))
            continue;
        __atomic_store_n(&context->state, st, __ATOMIC_RELEASE);
        __atomic_store_n(&context->depth, 1u, __ATOMIC_RELEASE);
        return context;
    }
    {
        uint32_t pages = overlay_allocation_pages(
            sizeof(overlay_scratch_context_t));
        if (!pages) return 0;
        context = (overlay_scratch_context_t *)arch_vm_alloc_pages(pages);
        if (!context) return 0;
        memset(context, 0, (uint64_t)pages * OVERLAY_PAGE_SIZE);
        context->allocation_pages = pages;
        context->owner = owner;
        context->state = st;
        context->depth = 1u;
        overlay_scratch_contexts_lock();
        context->next = g_overlay_dynamic_scratch_contexts;
        __atomic_store_n(&g_overlay_dynamic_scratch_contexts, context,
                         __ATOMIC_RELEASE);
        overlay_scratch_contexts_unlock();
        return context;
    }
}

static void overlay_scratch_release(overlay_state_t *st,
                                    overlay_scratch_context_t *scratch) {
    if (!st || !scratch) return;
    if (__atomic_load_n(&scratch->state, __ATOMIC_ACQUIRE) != st) return;
    if (__atomic_sub_fetch(&scratch->depth, 1u, __ATOMIC_ACQ_REL) == 0) {
        __atomic_store_n(&scratch->state, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&scratch->owner, 0u, __ATOMIC_RELEASE);
    }
}

static char *overlay_scratch(overlay_state_t *st, uint32_t slot) {
    uintptr_t owner;
    overlay_scratch_context_t *context;
    if (!st || slot >= OVERLAY_SCRATCH_PATHS) return 0;
    owner = overlay_scratch_owner();
    for (uint32_t index = 0; index < OVERLAY_SCRATCH_CONTEXTS; ++index) {
        context = &g_overlay_scratch_contexts[index];
        if (__atomic_load_n(&context->owner, __ATOMIC_ACQUIRE) == owner &&
            __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) == st)
            return context->paths[slot];
    }
    for (context = __atomic_load_n(&g_overlay_dynamic_scratch_contexts,
                                   __ATOMIC_ACQUIRE);
         context;
         context = __atomic_load_n(&context->next, __ATOMIC_ACQUIRE)) {
        if (__atomic_load_n(&context->owner, __ATOMIC_ACQUIRE) == owner &&
            __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) == st)
            return context->paths[slot];
    }
    return 0;
}

static uint8_t *overlay_copy_buffer(overlay_state_t *st) {
    uintptr_t owner;
    overlay_scratch_context_t *context;
    if (!st) return 0;
    owner = overlay_scratch_owner();
    for (uint32_t index = 0; index < OVERLAY_SCRATCH_CONTEXTS; ++index) {
        context = &g_overlay_scratch_contexts[index];
        if (__atomic_load_n(&context->owner, __ATOMIC_ACQUIRE) == owner &&
            __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) == st)
            return context->copy_buffer;
    }
    for (context = __atomic_load_n(&g_overlay_dynamic_scratch_contexts,
                                   __ATOMIC_ACQUIRE);
         context;
         context = __atomic_load_n(&context->next, __ATOMIC_ACQUIRE)) {
        if (__atomic_load_n(&context->owner, __ATOMIC_ACQUIRE) == owner &&
            __atomic_load_n(&context->state, __ATOMIC_ACQUIRE) == st)
            return context->copy_buffer;
    }
    return 0;
}

static void overlay_retain(void *private_data) {
    overlay_state_t *st = (overlay_state_t *)private_data;
    if (st) __atomic_add_fetch(&st->references, 1u, __ATOMIC_RELAXED);
}

static void overlay_release(void *private_data) {
    overlay_state_t *st = (overlay_state_t *)private_data;
    if (!st || !__atomic_load_n(&st->references, __ATOMIC_RELAXED)) return;
    if (__atomic_sub_fetch(&st->references, 1u, __ATOMIC_ACQ_REL) == 0) {
        __atomic_store_n(&st->used, 0u, __ATOMIC_RELEASE);
        overlay_state_destroy(st);
    }
}

static int overlay_path_append(char *dst, uint32_t max, const char *src) {
    uint32_t d;
    if (!dst || !src || max == 0) return -1;
    d = (uint32_t)strlen(dst);
    while (*src) {
        if (d + 1 >= max) return -1;
        dst[d++] = *src++;
    }
    dst[d] = 0;
    return 0;
}

static int overlay_join(char *out, uint32_t max, const char *base, const char *rel) {
    if (!out || !base || !rel || max == 0) return -1;
    out[0] = 0;
    if (overlay_path_append(out, max, base) < 0) return -1;
    if (strcmp(out, "/") != 0 && rel[0] && overlay_path_append(out, max, "/") < 0) return -1;
    if (overlay_path_append(out, max, rel) < 0) return -1;
    return 0;
}

static int overlay_backend_relative(const overlay_backend_t *backend,
                                    const char *path, char *relative,
                                    uint32_t capacity) {
    const char *mountpoint;
    uint32_t mount_length;
    const char *suffix;
    if (!backend || !backend->superblock || !path || path[0] != '/' ||
        !relative || capacity < 2u)
        return -1;
    mountpoint = backend->superblock->mountpoint;
    mount_length = (uint32_t)strlen(mountpoint);
    if (mount_length == 1u && mountpoint[0] == '/') {
        suffix = path;
    } else {
        if (strncmp(path, mountpoint, mount_length) != 0 ||
            (path[mount_length] && path[mount_length] != '/'))
            return -1;
        suffix = path + mount_length;
        if (!suffix[0]) suffix = "/";
    }
    if ((uint32_t)strlen(suffix) >= capacity) return -1;
    strcpy(relative, suffix);
    return 0;
}

static int overlay_backend_parent(overlay_state_t *st,
                                  const overlay_backend_t *backend,
                                  const char *path, vfs_inode_t *parent,
                                  char *leaf);

static int overlay_backend_resolve(overlay_state_t *st,
                                   const overlay_backend_t *backend,
                                   const char *path, vfs_inode_t *inode) {
    char *relative;
    vfs_inode_t parent;
    char leaf[VFS_NAME_MAX];
    if (!st || !backend || !backend->superblock || !inode) return -1;
    relative = overlay_scratch(st, 49);
    if (!relative ||
        overlay_backend_relative(backend, path, relative,
                                 VFS_PATH_MAX) < 0)
        return -1;
    if (strcmp(relative, "/") == 0) {
        *inode = backend->superblock->root;
        return 0;
    }
    if (!backend->superblock->ops || !backend->superblock->ops->lookup ||
        overlay_backend_parent(st, backend, path, &parent, leaf) < 0)
        return -1;
    return backend->superblock->ops->lookup(backend->superblock, &parent,
                                            leaf, inode);
}

static int overlay_backend_capture(const char *path,
                                   overlay_backend_t *backend,
                                   vfs_inode_t *inode) {
    vfs_superblock_t *superblock = 0;
    vfs_superblock_t *stable;
    if (!path || !backend || !inode ||
        vfs_resolve(path, inode, &superblock, 0, 0) < 0 || !superblock)
        return -1;
    stable = vfs_superblock_acquire(superblock);
    if (!stable) return -1;
    backend->superblock = stable;
    return 0;
}

static int overlay_backend_pread(overlay_state_t *st,
                                 const overlay_backend_t *backend,
                                 const char *path, uint32_t offset,
                                 void *buffer, uint32_t length) {
    vfs_inode_t inode;
    if (!backend || !backend->superblock || !backend->superblock->ops ||
        !backend->superblock->ops->read ||
        overlay_backend_resolve(st, backend, path, &inode) < 0)
        return -1;
    if (offset >= inode.size) return 0;
    if (length > inode.size - offset) length = inode.size - offset;
    return backend->superblock->ops->read(
        backend->superblock, &inode, offset, buffer, length);
}

static int overlay_backend_readlink(overlay_state_t *st,
                                    const overlay_backend_t *backend,
                                    const char *path, char *target,
                                    uint32_t capacity) {
    vfs_inode_t inode;
    if (!backend || !backend->superblock || !backend->superblock->ops ||
        !backend->superblock->ops->readlink ||
        overlay_backend_resolve(st, backend, path, &inode) < 0)
        return -1;
    return backend->superblock->ops->readlink(
        backend->superblock, &inode, target, capacity);
}

static int overlay_backend_parent(overlay_state_t *st,
                                  const overlay_backend_t *backend,
                                  const char *path, vfs_inode_t *parent,
                                  char *leaf) {
    char *relative;
    char *slash;
    uint32_t leaf_length;
    if (!st || !backend || !backend->superblock || !path || !parent ||
        !leaf)
        return -1;
    relative = overlay_scratch(st, 48);
    if (!relative ||
        overlay_backend_relative(backend, path, relative, VFS_PATH_MAX) < 0)
        return -1;
    slash = relative + strlen(relative);
    while (slash > relative && slash[-1] != '/') --slash;
    if (*slash == 0) return -1;
    leaf_length = (uint32_t)strlen(slash);
    if (leaf_length == 0 || leaf_length >= VFS_NAME_MAX) return -1;
    memcpy(leaf, slash, leaf_length + 1u);
    if (slash == relative) {
        relative[0] = '/';
        relative[1] = 0;
    } else if (slash == relative + 1) {
        relative[1] = 0;
    } else {
        slash[-1] = 0;
    }
    return vfs_resolve_superblock_path(backend->superblock, relative,
                                       parent);
}

static int overlay_backend_create(overlay_state_t *st,
                                  const overlay_backend_t *backend,
                                  const char *path, uint16_t mode,
                                  int existing_ok, vfs_inode_t *out) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_inode_t created;
    char leaf[VFS_NAME_MAX];
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops || !backend->superblock->ops->create)
        return -1;
    if (overlay_backend_resolve(st, backend, path, &existing) == 0) {
        if (!existing_ok) return -1;
        if (out) *out = existing;
        return 0;
    }
    if (overlay_backend_parent(st, backend, path, &parent, leaf) < 0 ||
        backend->superblock->ops->create(backend->superblock, &parent, leaf,
                                         mode, &created) < 0)
        return -1;
    if (out) *out = created;
    return 0;
}

static int overlay_backend_mkdir(overlay_state_t *st,
                                 const overlay_backend_t *backend,
                                 const char *path, uint16_t mode,
                                 int existing_ok, vfs_inode_t *out) {
    vfs_inode_t existing;
    vfs_inode_t parent;
    vfs_inode_t created;
    char leaf[VFS_NAME_MAX];
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops || !backend->superblock->ops->mkdir)
        return -1;
    if (overlay_backend_resolve(st, backend, path, &existing) == 0) {
        if (!existing_ok || !overlay_inode_is_dir(&existing)) return -1;
        if (out) *out = existing;
        return 0;
    }
    if (overlay_backend_parent(st, backend, path, &parent, leaf) < 0 ||
        backend->superblock->ops->mkdir(
            backend->superblock, &parent, leaf,
            (uint16_t)(VFS_INODE_DIR | (mode & 07777u)), &created) < 0)
        return -1;
    if (out) *out = created;
    return 0;
}

static int overlay_backend_symlink(overlay_state_t *st,
                                   const overlay_backend_t *backend,
                                   const char *target, const char *path,
                                   vfs_inode_t *out) {
    vfs_inode_t parent;
    vfs_inode_t created;
    char leaf[VFS_NAME_MAX];
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops || !backend->superblock->ops->symlink ||
        overlay_backend_parent(st, backend, path, &parent, leaf) < 0 ||
        backend->superblock->ops->symlink(backend->superblock, &parent, leaf,
                                          target, 0777u, &created) < 0)
        return -1;
    if (out) *out = created;
    return 0;
}

static int overlay_backend_mknod(overlay_state_t *st,
                                 const overlay_backend_t *backend,
                                 const char *path, uint16_t mode,
                                 uint64_t rdev, vfs_inode_t *out) {
    vfs_inode_t parent;
    vfs_inode_t created;
    char leaf[VFS_NAME_MAX];
    int result;
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops ||
        overlay_backend_parent(st, backend, path, &parent, leaf) < 0)
        return -1;
    if ((mode & 0xf000u) == VFS_INODE_FILE &&
        backend->superblock->ops->create)
        result = backend->superblock->ops->create(
            backend->superblock, &parent, leaf, mode, &created);
    else if (backend->superblock->ops->mknod)
        result = backend->superblock->ops->mknod(
            backend->superblock, &parent, leaf, mode, rdev, &created);
    else if (backend->superblock->ops->create)
        result = backend->superblock->ops->create(
            backend->superblock, &parent, leaf, mode, &created);
    else
        return -1;
    if (result < 0) return -1;
    if (out) *out = created;
    return 0;
}

static int overlay_backend_remove(overlay_state_t *st,
                                  const overlay_backend_t *backend,
                                  const char *path, int directory) {
    vfs_inode_t parent;
    char leaf[VFS_NAME_MAX];
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops ||
        overlay_backend_parent(st, backend, path, &parent, leaf) < 0)
        return -1;
    if (directory) {
        if (!backend->superblock->ops->rmdir) return -1;
        return backend->superblock->ops->rmdir(
            backend->superblock, &parent, leaf);
    }
    if (!backend->superblock->ops->unlink) return -1;
    return backend->superblock->ops->unlink(
        backend->superblock, &parent, leaf);
}

static int overlay_backend_rename(overlay_state_t *st,
                                  const overlay_backend_t *backend,
                                  const char *old_path,
                                  const char *new_path) {
    vfs_inode_t old_parent;
    vfs_inode_t new_parent;
    char old_leaf[VFS_NAME_MAX];
    char new_leaf[VFS_NAME_MAX];
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops || !backend->superblock->ops->rename ||
        overlay_backend_parent(st, backend, old_path, &old_parent,
                               old_leaf) < 0 ||
        overlay_backend_parent(st, backend, new_path, &new_parent,
                               new_leaf) < 0)
        return -1;
    return backend->superblock->ops->rename(
        backend->superblock, &old_parent, old_leaf, &new_parent, new_leaf);
}

static int overlay_backend_link(overlay_state_t *st,
                                const overlay_backend_t *backend,
                                const char *source_path,
                                const char *destination_path) {
    vfs_inode_t source;
    vfs_inode_t parent;
    char leaf[VFS_NAME_MAX];
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops || !backend->superblock->ops->link ||
        overlay_backend_resolve(st, backend, source_path, &source) < 0 ||
        overlay_inode_is_dir(&source) ||
        overlay_backend_parent(st, backend, destination_path, &parent,
                               leaf) < 0)
        return -1;
    return backend->superblock->ops->link(
        backend->superblock, &source, &parent, leaf);
}

static int overlay_backend_readdir(overlay_state_t *st,
                                   const overlay_backend_t *backend,
                                   const char *path, uint32_t index,
                                   char *name, vfs_inode_t *inode) {
    vfs_inode_t directory;
    if (!st || !backend || !backend->superblock ||
        !backend->superblock->ops || !backend->superblock->ops->readdir ||
        overlay_backend_resolve(st, backend, path, &directory) < 0 ||
        !overlay_inode_is_dir(&directory))
        return -1;
    return backend->superblock->ops->readdir(
        backend->superblock, &directory, index, name, inode);
}

static int overlay_ensure_upper_dirs(overlay_state_t *st, const char *rel) {
    char *cur;
    char *full;
    uint32_t len;
    if (!st || !rel) return -1;
    cur = overlay_scratch(st, 0);
    full = overlay_scratch(st, 1);
    cur[0] = 0;
    len = (uint32_t)strlen(rel);
    for (uint32_t i = 0; i < len; ++i) {
        if (rel[i] != '/') continue;
        if (i >= VFS_PATH_MAX) return -1;
        memcpy(cur, rel, i);
        cur[i] = 0;
        if (overlay_join(full, VFS_PATH_MAX, st->upper, cur) < 0) return -1;
        if (overlay_backend_mkdir(st, &st->upper_backend, full, 0755u, 1,
                                  0) < 0)
            return -1;
    }
    return 0;
}

static int overlay_lower_count(const overlay_state_t *st) {
    return st ? (int)st->lower_count : 0;
}

static int overlay_lower_base(const overlay_state_t *st, int layer,
                              char *out, uint32_t out_len) {
    const char *start;
    const char *end;
    uint32_t len;
    int current = 0;
    if (!st || layer < 0 || !out || out_len == 0) return -1;
    start = st->lower;
    while (current < layer) {
        while (*start && *start != ':') start++;
        if (!*start) return -1;
        start++;
        current++;
    }
    end = start;
    while (*end && *end != ':') end++;
    len = (uint32_t)(end - start);
    if (len == 0 || len >= out_len) return -1;
    memcpy(out, start, len);
    out[len] = 0;
    return 0;
}

static int overlay_lower_underlying(overlay_state_t *st, const char *rel,
                                    int layer, vfs_inode_t *ino,
                                    char *full_out) {
    char *base;
    char *full;
    if (!st || !rel) return -1;
    base = overlay_scratch(st, 2);
    full = overlay_scratch(st, 3);
    if (overlay_lower_base(st, layer, base, VFS_PATH_MAX) < 0 ||
        overlay_join(full, VFS_PATH_MAX, base, rel) < 0) return -1;
    if ((uint32_t)layer >= st->lower_count ||
        overlay_backend_resolve(st, &st->lower_backends[layer],
                                full, ino) < 0)
        return -1;
    if (full_out) strcpy(full_out, full);
    return 0;
}

static int overlay_underlying(overlay_state_t *st, const char *rel, int upper,
                              vfs_inode_t *ino, char *full_out,
                              int *lower_layer_out) {
    char *full;
    if (!st || !rel) return -1;
    full = overlay_scratch(st, 4);
    if (upper) {
        if (overlay_join(full, VFS_PATH_MAX, st->upper, rel) < 0 ||
            overlay_backend_resolve(st, &st->upper_backend,
                                    full, ino) < 0)
            return -1;
        if (full_out) strcpy(full_out, full);
        if (lower_layer_out) *lower_layer_out = -1;
        return 0;
    }
    for (int layer = 0; layer < overlay_lower_count(st); ++layer) {
        if (overlay_lower_underlying(st, rel, layer, ino, full_out) == 0) {
            if (lower_layer_out) *lower_layer_out = layer;
            return 0;
        }
    }
    return -1;
}

static overlay_node_t *overlay_find_node(overlay_state_t *st, const char *rel) {
    if (!st || !rel) return 0;
    for (uint32_t i = 1; i < st->node_capacity; ++i) {
        if (st->nodes[i].used && strcmp(st->nodes[i].rel, rel) == 0) return &st->nodes[i];
    }
    return 0;
}

static int overlay_whiteout_path(overlay_state_t *st, const char *rel,
                                 char *out, uint32_t out_len) {
    char *parent;
    const char *name = rel;
    uint32_t cut = 0;
    uint32_t length;
    if (!st || !rel || !rel[0] || !out) return -1;
    parent = overlay_scratch(st, 5);
    length = (uint32_t)strlen(rel);
    for (uint32_t index = 0; index < length; ++index) {
        if (rel[index] == '/') cut = index + 1u;
    }
    parent[0] = 0;
    if (cut) {
        if (cut - 1u >= VFS_PATH_MAX) return -1;
        memcpy(parent, rel, cut - 1u);
        parent[cut - 1u] = 0;
        name = rel + cut;
    }
    if (overlay_join(out, out_len, st->upper, parent) < 0 ||
        (strcmp(out, "/") != 0 && overlay_path_append(out, out_len, "/") < 0) ||
        overlay_path_append(out, out_len, ".wh.") < 0 ||
        overlay_path_append(out, out_len, name) < 0)
        return -1;
    return 0;
}

static int overlay_is_whiteout(overlay_state_t *st, const char *rel) {
    overlay_node_t *node = overlay_find_node(st, rel);
    char *marker;
    if (!st) return 0;
    marker = overlay_scratch(st, 6);
    if (node && node->whiteout) return 1;
    {
        vfs_inode_t inode;
        return overlay_whiteout_path(st, rel, marker, VFS_PATH_MAX) == 0 &&
               overlay_backend_resolve(st, &st->upper_backend,
                                       marker, &inode) == 0;
    }
}

static void overlay_clear_whiteout(overlay_state_t *st, const char *rel) {
    overlay_node_t *node = overlay_find_node(st, rel);
    char *marker;
    if (!st) return;
    marker = overlay_scratch(st, 6);
    if (node && node->whiteout) node->used = 0;
    if (overlay_whiteout_path(st, rel, marker, VFS_PATH_MAX) == 0)
        (void)overlay_backend_remove(st, &st->upper_backend, marker, 0);
}

static void overlay_forget_node(overlay_state_t *st, const char *rel) {
    overlay_node_t *node = overlay_find_node(st, rel);
    if (node) node->used = 0;
}

static int overlay_mark_whiteout(overlay_state_t *st, const char *rel) {
    int free_idx = -1;
    overlay_node_t *node;
    char *marker;
    if (!st || !rel || !rel[0]) return -1;
    marker = overlay_scratch(st, 6);
    node = overlay_find_node(st, rel);
    if (!node) {
        for (uint32_t i = 1; i < st->node_capacity; ++i) {
            if (!st->nodes[i].used) {
                free_idx = (int)i;
                break;
            }
        }
        if (free_idx < 0) {
            uint32_t old_capacity = st->node_capacity;
            if (old_capacity >= (uint32_t)INT32_MAX ||
                overlay_node_reserve(st, old_capacity + 1u) < 0)
                return -1;
            free_idx = (int)old_capacity;
        }
        node = &st->nodes[free_idx];
    }
    memset(node, 0, sizeof(*node));
    node->used = 1;
    node->upper = 1;
    node->whiteout = 1;
    strncpy(node->rel, rel, sizeof(node->rel) - 1);
    if (overlay_ensure_upper_dirs(st, rel) < 0 ||
        overlay_whiteout_path(st, rel, marker, VFS_PATH_MAX) < 0 ||
        overlay_backend_create(st, &st->upper_backend, marker,
                               VFS_INODE_FILE | 0600u, 1, 0) < 0)
        return -1;
    return 0;
}

static int overlay_directory_is_opaque(overlay_state_t *st,
                                       const char *rel) {
    char *directory;
    char *marker;
    if (!st || !rel) return 0;
    directory = overlay_scratch(st, 7);
    marker = overlay_scratch(st, 8);
    if (
        overlay_join(directory, VFS_PATH_MAX, st->upper, rel) < 0 ||
        overlay_join(marker, VFS_PATH_MAX, directory,
                     ".wh..wh..opq") < 0)
        return 0;
    {
        vfs_inode_t inode;
        return overlay_backend_resolve(st, &st->upper_backend,
                                       marker, &inode) == 0;
    }
}

static int overlay_alloc_node(overlay_state_t *st, const char *rel, int upper, const vfs_inode_t *src) {
    int free_idx = -1;
    if (!st || !rel || !src) return -1;
    for (uint32_t i = 1; i < st->node_capacity; ++i) {
        if (st->nodes[i].used && strcmp(st->nodes[i].rel, rel) == 0) {
            st->nodes[i].upper = upper ? 1 : 0;
            st->nodes[i].whiteout = 0;
            st->nodes[i].backing = *src;
            return (int)i;
        }
        if (!st->nodes[i].used && free_idx < 0) free_idx = (int)i;
    }
    if (free_idx < 0) {
        uint32_t old_capacity = st->node_capacity;
        if (old_capacity >= (uint32_t)INT32_MAX ||
            overlay_node_reserve(st, old_capacity + 1u) < 0)
            return -1;
        free_idx = (int)old_capacity;
    }
    memset(&st->nodes[free_idx], 0, sizeof(st->nodes[free_idx]));
    st->nodes[free_idx].used = 1;
    st->nodes[free_idx].upper = upper ? 1 : 0;
    st->nodes[free_idx].whiteout = 0;
    st->nodes[free_idx].backing = *src;
    strncpy(st->nodes[free_idx].rel, rel, sizeof(st->nodes[free_idx].rel) - 1);
    return free_idx;
}

static void overlay_fill_inode(uint32_t idx, const overlay_node_t *node, vfs_inode_t *out) {
    if (!node || !out) return;
    *out = node->backing;
    out->ino = idx + 1;
}

static int overlay_lookup_path(overlay_state_t *st, const char *rel, vfs_inode_t *out) {
    vfs_inode_t ino;
    int idx;
    if (!st || !rel || !out) return -1;
    if (!rel[0]) {
        overlay_fill_inode(0, &st->nodes[0], out);
        return 0;
    }
    if (overlay_is_whiteout(st, rel)) return -1;
    if (overlay_underlying(st, rel, 1, &ino, 0, 0) == 0) {
        idx = overlay_alloc_node(st, rel, 1, &ino);
        if (idx < 0) return -1;
        overlay_fill_inode((uint32_t)idx, &st->nodes[idx], out);
        return 0;
    }
    {
        char *parent = overlay_scratch(st, 9);
        uint32_t length = (uint32_t)strlen(rel);
        uint32_t cut = 0;
        for (uint32_t index = 0; index < length; ++index)
            if (rel[index] == '/') cut = index;
        parent[0] = 0;
        if (cut) {
            memcpy(parent, rel, cut);
            parent[cut] = 0;
        }
        if (overlay_directory_is_opaque(st, parent)) return -1;
    }
    if (overlay_underlying(st, rel, 0, &ino, 0, 0) == 0) {
        idx = overlay_alloc_node(st, rel, 0, &ino);
        if (idx < 0) return -1;
        overlay_fill_inode((uint32_t)idx, &st->nodes[idx], out);
        return 0;
    }
    return -1;
}

static int overlay_inode_index(const overlay_state_t *st,
                               const vfs_inode_t *inode) {
    if (!st || !inode || inode->ino == 0 ||
        inode->ino > st->node_capacity || inode->ino > INT32_MAX)
        return -1;
    return (int)(inode->ino - 1);
}

static int overlay_lookup(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, vfs_inode_t *out) {
    overlay_state_t *st = overlay_state(sb);
    overlay_node_t *d;
    int didx;
    char *rel;
    if (!st || !dir || !name || !out) return -1;
    rel = overlay_scratch(st, 10);
    didx = overlay_inode_index(st, dir);
    if (didx < 0 || !st->nodes[didx].used) return -1;
    d = &st->nodes[didx];
    if (strcmp(name, ".") == 0) {
        overlay_fill_inode((uint32_t)didx, d, out);
        return 0;
    }
    if (strcmp(name, "..") == 0) return overlay_lookup_path(st, "", out);
    rel[0] = 0;
    if (d->rel[0] && overlay_path_append(rel, VFS_PATH_MAX, d->rel) < 0) return -1;
    if (rel[0] && overlay_path_append(rel, VFS_PATH_MAX, "/") < 0) return -1;
    if (overlay_path_append(rel, VFS_PATH_MAX, name) < 0) return -1;
    return overlay_lookup_path(st, rel, out);
}

static int overlay_copy_up(overlay_state_t *st, const char *rel) {
    char *lower;
    char *upper;
    char *link_target;
    vfs_inode_t lower_inode;
    vfs_inode_t upper_inode;
    vfs_superblock_t *upper_sb;
    uint8_t *copy_buffer;
    uint32_t offset = 0;
    int lower_layer = -1;
    if (!st || !rel) return -1;
    lower = overlay_scratch(st, 11);
    upper = overlay_scratch(st, 12);
    link_target = overlay_scratch(st, 13);
    copy_buffer = overlay_copy_buffer(st);
    if (!lower || !upper || !link_target || !copy_buffer) return -1;
    if (overlay_underlying(st, rel, 1, &upper_inode, 0, 0) == 0) return 0;
    if (overlay_underlying(st, rel, 0, &lower_inode, lower,
                           &lower_layer) < 0)
        return -1;
    upper_sb = st->upper_backend.superblock;
    if (overlay_ensure_upper_dirs(st, rel) < 0) return -1;
    if (overlay_join(upper, VFS_PATH_MAX, st->upper, rel) < 0) return -1;
    if (overlay_inode_is_dir(&lower_inode)) {
        if (overlay_backend_mkdir(st, &st->upper_backend, upper,
                                  lower_inode.mode & 07777u, 0,
                                  &upper_inode) < 0)
            return -1;
    } else if ((lower_inode.mode & 0xf000u) == VFS_INODE_LNK) {
        int length = overlay_backend_readlink(
            st, &st->lower_backends[lower_layer], lower, link_target,
            VFS_PATH_MAX - 1u);
        if (length < 0 || length >= VFS_PATH_MAX) return -1;
        link_target[length] = 0;
        if (overlay_backend_symlink(st, &st->upper_backend, link_target,
                                    upper, &upper_inode) < 0)
            return -1;
    } else if ((lower_inode.mode & 0xf000u) != VFS_INODE_FILE) {
        if (overlay_backend_mknod(st, &st->upper_backend, upper,
                                  lower_inode.mode, lower_inode.rdev,
                                  &upper_inode) < 0)
            return -1;
    } else {
        if (overlay_backend_create(st, &st->upper_backend, upper,
                                   VFS_INODE_FILE | 0600u, 0,
                                   &upper_inode) < 0 ||
            !upper_sb->ops || !upper_sb->ops->write) return -1;
        while (offset < lower_inode.size) {
            uint32_t amount = lower_inode.size - offset;
            int count;
            if (amount > OVERLAY_COPY_BUF) amount = OVERLAY_COPY_BUF;
            count = overlay_backend_pread(
                st, &st->lower_backends[lower_layer], lower, offset,
                copy_buffer, amount);
            if (count <= 0 ||
                upper_sb->ops->write(upper_sb, &upper_inode, offset,
                                     copy_buffer, (uint32_t)count) != count)
                return -1;
            offset += (uint32_t)count;
            upper_inode.size = offset;
        }
    }
    if (overlay_backend_resolve(st, &st->upper_backend, upper,
                                &upper_inode) < 0 || !upper_sb)
        return -1;
    if ((lower_inode.mode & 0xf000u) != VFS_INODE_LNK) {
        (void)vfs_inode_setattr(upper_sb, &upper_inode, lower_inode.mode,
                                lower_inode.uid, lower_inode.gid,
                                VFS_SETATTR_MODE | VFS_SETATTR_UID |
                                VFS_SETATTR_GID);
        (void)vfs_inode_utimens(upper_sb, &upper_inode,
                                lower_inode.atime, lower_inode.mtime, 1, 1);
    }
    return 0;
}

static int overlay_read(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, void *buf, uint32_t len) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    int lower_layer = -1;
    char *full;
    vfs_inode_t backing_inode;
    const overlay_backend_t *backend;
    if (!st || idx < 0 || !st->nodes[idx].used || !buf) return -1;
    full = overlay_scratch(st, 14);
    if (overlay_underlying(st, st->nodes[idx].rel, 1, &backing_inode,
                           full, 0) == 0)
        backend = &st->upper_backend;
    else if (overlay_underlying(st, st->nodes[idx].rel, 0,
                                &backing_inode, full, &lower_layer) == 0)
        backend = &st->lower_backends[lower_layer];
    else
        return -1;
    return overlay_backend_pread(st, backend, full, off, buf, len);
}

static int overlay_write(vfs_superblock_t *sb, vfs_inode_t *inode, uint32_t off, const void *buf, uint32_t len) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    char *full;
    vfs_inode_t updated;
    vfs_superblock_t *upper_sb;
    int count;
    if (!st || idx < 0 || !st->nodes[idx].used || (!buf && len)) return -1;
    full = overlay_scratch(st, 15);
    upper_sb = st->upper_backend.superblock;
    if (overlay_copy_up(st, st->nodes[idx].rel) < 0) return -1;
    if (overlay_join(full, VFS_PATH_MAX, st->upper, st->nodes[idx].rel) < 0) return -1;
    if (overlay_backend_resolve(st, &st->upper_backend, full, &updated) < 0 ||
        !upper_sb ||
        !upper_sb->ops || !upper_sb->ops->write) return -1;
    count = upper_sb->ops->write(upper_sb, &updated, off, buf, len);
    if (count < 0) return -1;
    if (overlay_underlying(st, st->nodes[idx].rel, 1, &updated, 0, 0) == 0) {
        st->nodes[idx].upper = 1;
        st->nodes[idx].backing = updated;
        inode->size = updated.size;
    }
    return count;
}

static int overlay_create(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    overlay_state_t *st = overlay_state(sb);
    int didx = overlay_inode_index(st, dir);
    char *rel;
    char *full;
    vfs_inode_t created;
    if (!st || didx < 0 || !name || !out) return -1;
    rel = overlay_scratch(st, 16);
    full = overlay_scratch(st, 17);
    rel[0] = 0;
    if (st->nodes[didx].rel[0] && overlay_path_append(rel, VFS_PATH_MAX, st->nodes[didx].rel) < 0) return -1;
    if (rel[0] && overlay_path_append(rel, VFS_PATH_MAX, "/") < 0) return -1;
    if (overlay_path_append(rel, VFS_PATH_MAX, name) < 0) return -1;
    if (overlay_ensure_upper_dirs(st, rel) < 0) return -1;
    if (overlay_join(full, VFS_PATH_MAX, st->upper, rel) < 0) return -1;
    if ((mode & 0xF000u) == VFS_INODE_DIR) {
        if (overlay_backend_mkdir(st, &st->upper_backend, full,
                                  mode & 07777u, 0, &created) < 0)
            return -1;
    } else if (overlay_backend_create(st, &st->upper_backend, full,
                                      (uint16_t)(VFS_INODE_FILE |
                                                 (mode & 07777u)),
                                      0, &created) < 0) {
        return -1;
    }
    (void)vfs_inode_setattr(st->upper_backend.superblock, &created,
                            mode, created.uid, created.gid,
                            VFS_SETATTR_MODE);
    overlay_clear_whiteout(st, rel);
    return overlay_lookup_path(st, rel, out);
}

static int overlay_mkdir(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name, uint16_t mode, vfs_inode_t *out) {
    return overlay_create(sb, dir, name, (uint16_t)(VFS_INODE_DIR | (mode & 07777u)), out);
}

static int overlay_symlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name,
                           const char *target, uint16_t mode, vfs_inode_t *out) {
    overlay_state_t *st = overlay_state(sb);
    int didx = overlay_inode_index(st, dir);
    char *rel;
    char *full;
    if (!st || didx < 0 || !name || !target) return -1;
    rel = overlay_scratch(st, 18);
    full = overlay_scratch(st, 19);
    rel[0] = 0;
    if (st->nodes[didx].rel[0] && overlay_path_append(rel, VFS_PATH_MAX, st->nodes[didx].rel) < 0) return -1;
    if (rel[0] && overlay_path_append(rel, VFS_PATH_MAX, "/") < 0) return -1;
    if (overlay_path_append(rel, VFS_PATH_MAX, name) < 0) return -1;
    if (overlay_ensure_upper_dirs(st, rel) < 0) return -1;
    if (overlay_join(full, VFS_PATH_MAX, st->upper, rel) < 0) return -1;
    if (overlay_backend_symlink(st, &st->upper_backend, target, full,
                                0) < 0)
        return -1;
    (void)mode;
    overlay_clear_whiteout(st, rel);
    return overlay_lookup_path(st, rel, out);
}

static int overlay_readlink(vfs_superblock_t *sb, vfs_inode_t *inode, char *out, uint32_t max) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    int lower_layer = -1;
    char *full;
    vfs_inode_t backing_inode;
    const overlay_backend_t *backend;
    if (!st || idx < 0 || !st->nodes[idx].used) return -1;
    full = overlay_scratch(st, 20);
    if (overlay_underlying(st, st->nodes[idx].rel, 1, &backing_inode,
                           full, 0) == 0)
        backend = &st->upper_backend;
    else if (overlay_underlying(st, st->nodes[idx].rel, 0,
                                &backing_inode, full, &lower_layer) == 0)
        backend = &st->lower_backends[lower_layer];
    else
        return -1;
    return overlay_backend_readlink(st, backend, full, out, max);
}

static int overlay_unlink(vfs_superblock_t *sb, vfs_inode_t *dir, const char *name) {
    overlay_state_t *st = overlay_state(sb);
    int didx = overlay_inode_index(st, dir);
    char *rel;
    char *full;
    vfs_inode_t upper_ino;
    vfs_inode_t lower_ino;
    int have_upper;
    int have_lower;
    if (!st || didx < 0 || !name) return -1;
    rel = overlay_scratch(st, 21);
    full = overlay_scratch(st, 22);
    rel[0] = 0;
    if (st->nodes[didx].rel[0] && overlay_path_append(rel, VFS_PATH_MAX, st->nodes[didx].rel) < 0) return -1;
    if (rel[0] && overlay_path_append(rel, VFS_PATH_MAX, "/") < 0) return -1;
    if (overlay_path_append(rel, VFS_PATH_MAX, name) < 0) return -1;
    if (overlay_join(full, VFS_PATH_MAX, st->upper, rel) < 0) return -1;
    if (overlay_is_whiteout(st, rel)) return -1;
    have_upper = overlay_underlying(st, rel, 1, &upper_ino, 0, 0) == 0;
    have_lower = overlay_underlying(st, rel, 0, &lower_ino, 0, 0) == 0;
    if (!have_upper && !have_lower) return -1;
    if (have_upper &&
        overlay_backend_remove(st, &st->upper_backend, full, 0) < 0)
        return -1;
    if (have_lower) return overlay_mark_whiteout(st, rel);
    overlay_forget_node(st, rel);
    return 0;
}

static int overlay_child_rel(const overlay_node_t *dir, const char *name,
                             char *rel, uint32_t rel_len) {
    if (!dir || !dir->used || !name || !name[0] || !rel || rel_len == 0)
        return -1;
    rel[0] = 0;
    if (dir->rel[0] && overlay_path_append(rel, rel_len, dir->rel) < 0)
        return -1;
    if (rel[0] && overlay_path_append(rel, rel_len, "/") < 0)
        return -1;
    return overlay_path_append(rel, rel_len, name);
}

static int overlay_readdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                           uint32_t idx, char *name_out,
                           vfs_inode_t *inode_out);

static int overlay_mknod(vfs_superblock_t *sb, vfs_inode_t *dir,
                         const char *name, uint16_t mode, uint64_t rdev,
                         vfs_inode_t *out) {
    overlay_state_t *st = overlay_state(sb);
    int didx = overlay_inode_index(st, dir);
    char *rel;
    char *full;
    if (!st) return -1;
    rel = overlay_scratch(st, 23);
    full = overlay_scratch(st, 24);
    if (!st || didx < 0 || !out ||
        overlay_child_rel(&st->nodes[didx], name, rel, VFS_PATH_MAX) < 0 ||
        overlay_ensure_upper_dirs(st, rel) < 0 ||
        overlay_join(full, VFS_PATH_MAX, st->upper, rel) < 0 ||
        overlay_backend_mknod(st, &st->upper_backend, full, mode, rdev,
                              0) < 0)
        return -1;
    overlay_clear_whiteout(st, rel);
    return overlay_lookup_path(st, rel, out);
}

static int overlay_link(vfs_superblock_t *sb, vfs_inode_t *inode,
                        vfs_inode_t *dir, const char *name) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    int didx = overlay_inode_index(st, dir);
    char *source;
    char *rel;
    char *destination;
    if (!st) return -1;
    source = overlay_scratch(st, 25);
    rel = overlay_scratch(st, 26);
    destination = overlay_scratch(st, 27);
    if (!st || idx < 0 || didx < 0 ||
        overlay_copy_up(st, st->nodes[idx].rel) < 0 ||
        overlay_child_rel(&st->nodes[didx], name, rel, VFS_PATH_MAX) < 0 ||
        overlay_ensure_upper_dirs(st, rel) < 0 ||
        overlay_join(source, VFS_PATH_MAX, st->upper,
                     st->nodes[idx].rel) < 0 ||
        overlay_join(destination, VFS_PATH_MAX, st->upper, rel) < 0 ||
        overlay_backend_link(st, &st->upper_backend, source,
                             destination) < 0)
        return -1;
    overlay_clear_whiteout(st, rel);
    overlay_forget_node(st, rel);
    return 0;
}

static int overlay_rmdir(vfs_superblock_t *sb, vfs_inode_t *dir,
                         const char *name) {
    overlay_state_t *st = overlay_state(sb);
    int didx = overlay_inode_index(st, dir);
    char *rel;
    char *full;
    vfs_inode_t upper_inode;
    vfs_inode_t lower_inode;
    int have_upper;
    int have_lower;
    vfs_inode_t merged;
    int node_idx;
    char child[VFS_NAME_MAX];
    vfs_inode_t child_inode;
    if (!st) return -1;
    rel = overlay_scratch(st, 28);
    full = overlay_scratch(st, 29);
    if (!st || didx < 0 ||
        overlay_child_rel(&st->nodes[didx], name, rel, VFS_PATH_MAX) < 0 ||
        overlay_lookup_path(st, rel, &merged) < 0 ||
        !overlay_inode_is_dir(&merged))
        return -1;
    node_idx = overlay_inode_index(st, &merged);
    if (node_idx < 0 ||
        overlay_readdir(sb, &merged, 2, child, &child_inode) == 0)
        return -1;
    have_upper = overlay_underlying(st, rel, 1, &upper_inode, 0, 0) == 0;
    have_lower = overlay_underlying(st, rel, 0, &lower_inode, 0, 0) == 0;
    if (overlay_join(full, VFS_PATH_MAX, st->upper, rel) < 0) return -1;
    if (have_upper &&
        overlay_backend_remove(st, &st->upper_backend, full, 1) < 0)
        return -1;
    overlay_forget_node(st, rel);
    return have_lower ? overlay_mark_whiteout(st, rel) : 0;
}

static int overlay_materialize_tree(overlay_state_t *st, const char *rel) {
    overlay_path_stack_t stack;
    uint32_t pending = 1;
    int result = -1;
    memset(&stack, 0, sizeof(stack));
    if (!st || !rel || strlen(rel) >= VFS_PATH_MAX ||
        overlay_path_stack_reserve(&stack, 1u) < 0)
        goto out;
    strcpy(overlay_path_stack_at(&stack, 0), rel);
    while (pending) {
        char *current = overlay_scratch(st, 30);
        vfs_inode_t visible;
        strcpy(current, overlay_path_stack_at(&stack, --pending));
        if (overlay_lookup_path(st, current, &visible) < 0 ||
            overlay_copy_up(st, current) < 0)
            goto out;
        if (!overlay_inode_is_dir(&visible)) continue;
        for (int layer = 0; layer < overlay_lower_count(st); ++layer) {
            char *lower_dir = overlay_scratch(st, 31);
            if (overlay_lower_underlying(st, current, layer, 0,
                                         lower_dir) < 0)
                continue;
            for (uint32_t index = 2; ; ++index) {
                char name[VFS_NAME_MAX];
                char *child_rel;
                vfs_inode_t child_inode;
                if (overlay_backend_readdir(
                        st, &st->lower_backends[layer], lower_dir, index,
                        name, &child_inode) < 0)
                    break;
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
                    strncmp(name, ".wh.", 4) == 0)
                    continue;
                if (overlay_path_stack_reserve(&stack, pending + 1u) < 0)
                    goto out;
                child_rel = overlay_path_stack_at(&stack, pending);
                child_rel[0] = 0;
                if ((current[0] && overlay_path_append(child_rel,
                            VFS_PATH_MAX, current) < 0) ||
                    (child_rel[0] && overlay_path_append(child_rel,
                            VFS_PATH_MAX, "/") < 0) ||
                    overlay_path_append(child_rel, VFS_PATH_MAX, name) < 0)
                    goto out;
                if (!overlay_is_whiteout(st, child_rel)) pending++;
            }
        }
    }
    result = 0;
out:
    overlay_path_stack_release(&stack);
    return result;
}

static int overlay_rename(vfs_superblock_t *sb, vfs_inode_t *old_dir,
                          const char *old_name, vfs_inode_t *new_dir,
                          const char *new_name) {
    overlay_state_t *st = overlay_state(sb);
    int old_didx = overlay_inode_index(st, old_dir);
    int new_didx = overlay_inode_index(st, new_dir);
    char *old_rel;
    char *new_rel;
    char *old_upper;
    char *new_upper;
    vfs_inode_t lower_inode;
    int had_lower;
    if (!st) return -1;
    old_rel = overlay_scratch(st, 32);
    new_rel = overlay_scratch(st, 33);
    old_upper = overlay_scratch(st, 34);
    new_upper = overlay_scratch(st, 35);
    if (!st || old_didx < 0 || new_didx < 0 ||
        overlay_child_rel(&st->nodes[old_didx], old_name,
                          old_rel, VFS_PATH_MAX) < 0 ||
        overlay_child_rel(&st->nodes[new_didx], new_name,
                          new_rel, VFS_PATH_MAX) < 0)
        return -1;
    had_lower = overlay_underlying(st, old_rel, 0, &lower_inode, 0, 0) == 0;
    if (overlay_materialize_tree(st, old_rel) < 0 ||
        overlay_ensure_upper_dirs(st, new_rel) < 0 ||
        overlay_join(old_upper, VFS_PATH_MAX, st->upper, old_rel) < 0 ||
        overlay_join(new_upper, VFS_PATH_MAX, st->upper, new_rel) < 0 ||
        overlay_backend_rename(st, &st->upper_backend, old_upper,
                               new_upper) < 0)
        return -1;
    overlay_clear_whiteout(st, new_rel);
    overlay_forget_node(st, old_rel);
    overlay_forget_node(st, new_rel);
    return had_lower ? overlay_mark_whiteout(st, old_rel) : 0;
}

static int overlay_readdir(vfs_superblock_t *sb, vfs_inode_t *dir, uint32_t idx, char *name_out, vfs_inode_t *inode_out) {
    overlay_state_t *st = overlay_state(sb);
    int didx = overlay_inode_index(st, dir);
    char *upath;
    uint32_t seen = 0;
    if (!st || didx < 0 || !name_out || !inode_out) return -1;
    upath = overlay_scratch(st, 36);
    if (idx == 0) {
        strcpy(name_out, ".");
        overlay_fill_inode((uint32_t)didx, &st->nodes[didx], inode_out);
        return 0;
    }
    if (idx == 1) {
        strcpy(name_out, "..");
        overlay_fill_inode(0, &st->nodes[0], inode_out);
        return 0;
    }
    if (overlay_join(upath, VFS_PATH_MAX, st->upper,
                     st->nodes[didx].rel) < 0) return -1;
    for (int pass = -1; pass < overlay_lower_count(st); ++pass) {
        char *lbase = overlay_scratch(st, 37);
        char *lpath = overlay_scratch(st, 38);
        const char *base = upath;
        const overlay_backend_t *backend = &st->upper_backend;
        if (pass >= 0 &&
            overlay_directory_is_opaque(st, st->nodes[didx].rel))
            break;
        if (pass >= 0) {
            if (overlay_lower_base(st, pass, lbase, VFS_PATH_MAX) < 0 ||
                overlay_join(lpath, VFS_PATH_MAX, lbase,
                             st->nodes[didx].rel) < 0) return -1;
            base = lpath;
            backend = &st->lower_backends[pass];
        }
        for (uint32_t i = 2; ; ++i) {
            char child[VFS_NAME_MAX];
            vfs_inode_t child_ino;
            int dup = 0;
            char *rel = overlay_scratch(st, 39);
            if (overlay_backend_readdir(st, backend, base, i, child,
                                        &child_ino) < 0)
                break;
            if (strcmp(child, ".") == 0 || strcmp(child, "..") == 0) continue;
            if (strncmp(child, ".wh.", 4) == 0) continue;
            rel[0] = 0;
            if (st->nodes[didx].rel[0] && overlay_path_append(rel, VFS_PATH_MAX, st->nodes[didx].rel) < 0) return -1;
            if (rel[0] && overlay_path_append(rel, VFS_PATH_MAX, "/") < 0) return -1;
            if (overlay_path_append(rel, VFS_PATH_MAX, child) < 0) return -1;
            if (overlay_is_whiteout(st, rel)) continue;
            if (pass >= 0) {
                char *upper_child = overlay_scratch(st, 40);
                vfs_inode_t duplicate_inode;
                if (overlay_join(upper_child, VFS_PATH_MAX, upath, child) == 0 &&
                    overlay_backend_resolve(st, &st->upper_backend,
                                            upper_child,
                                            &duplicate_inode) == 0)
                    dup = 1;
                for (int earlier = 0; !dup && earlier < pass; ++earlier) {
                    char *earlier_base = overlay_scratch(st, 41);
                    char *earlier_dir = overlay_scratch(st, 42);
                    char *earlier_child = overlay_scratch(st, 43);
                    if (overlay_lower_base(st, earlier, earlier_base,
                                           VFS_PATH_MAX) == 0 &&
                        overlay_join(earlier_dir, VFS_PATH_MAX,
                                     earlier_base, st->nodes[didx].rel) == 0 &&
                        overlay_join(earlier_child, VFS_PATH_MAX,
                                     earlier_dir, child) == 0 &&
                        overlay_backend_resolve(
                            st, &st->lower_backends[earlier], earlier_child,
                            &duplicate_inode) == 0)
                        dup = 1;
                }
            }
            if (dup) continue;
            if (seen++ == idx - 2) {
                strcpy(name_out, child);
                return overlay_lookup_path(st, rel, inode_out);
            }
        }
    }
    return -1;
}

static int overlay_statfs(vfs_superblock_t *sb, uint32_t *total_kb, uint32_t *used_kb) {
    overlay_state_t *st = overlay_state(sb);
    vfs_superblock_t *upper_sb;
    if (!st || !total_kb || !used_kb) return -1;
    upper_sb = st->upper_backend.superblock;
    if (!upper_sb || !upper_sb->ops || !upper_sb->ops->statfs) return -1;
    return upper_sb->ops->statfs(upper_sb, total_kb, used_kb);
}

static int overlay_upper_inode(overlay_state_t *st, overlay_node_t *node,
                               vfs_inode_t *inode_out,
                               vfs_superblock_t **sb_out) {
    char *full;
    if (!st || !node || !node->used || !inode_out || !sb_out) return -1;
    full = overlay_scratch(st, 44);
    if (overlay_copy_up(st, node->rel) < 0 ||
        overlay_join(full, VFS_PATH_MAX, st->upper, node->rel) < 0 ||
        overlay_backend_resolve(st, &st->upper_backend, full,
                                inode_out) < 0)
        return -1;
    *sb_out = st->upper_backend.superblock;
    node->upper = 1;
    node->backing = *inode_out;
    return 0;
}

static int overlay_truncate(vfs_superblock_t *sb, vfs_inode_t *inode,
                            uint32_t length) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t upper_inode;
    vfs_superblock_t *upper_sb = 0;
    if (!st || idx < 0 ||
        overlay_upper_inode(st, &st->nodes[idx], &upper_inode,
                            &upper_sb) < 0 ||
        !upper_sb->ops || !upper_sb->ops->truncate ||
        upper_sb->ops->truncate(upper_sb, &upper_inode, length) < 0)
        return -1;
    upper_inode.size = length;
    st->nodes[idx].backing = upper_inode;
    inode->size = length;
    return 0;
}

static int overlay_fallocate(vfs_superblock_t *sb, vfs_inode_t *inode,
                             uint32_t mode, uint64_t offset,
                             uint64_t length) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t upper_inode;
    vfs_superblock_t *upper_sb = 0;
    if (!st || idx < 0 ||
        overlay_upper_inode(st, &st->nodes[idx], &upper_inode,
                            &upper_sb) < 0 ||
        !upper_sb->ops || !upper_sb->ops->fallocate)
        return -1;
    return upper_sb->ops->fallocate(upper_sb, &upper_inode, mode,
                                    offset, length);
}

static int overlay_setxattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                            const char *name, const void *value,
                            uint32_t size, uint32_t flags) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t upper_inode;
    vfs_superblock_t *upper_sb = 0;
    if (!st || idx < 0 ||
        overlay_upper_inode(st, &st->nodes[idx], &upper_inode,
                            &upper_sb) < 0 ||
        !upper_sb->ops || !upper_sb->ops->setxattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return upper_sb->ops->setxattr(upper_sb, &upper_inode, name,
                                   value, size, flags);
}

static int overlay_visible_inode(overlay_state_t *st, overlay_node_t *node,
                                 vfs_inode_t *inode_out,
                                 vfs_superblock_t **sb_out) {
    char *full;
    int lower_layer = -1;
    if (!st || !node || !node->used || !inode_out || !sb_out) return -1;
    full = overlay_scratch(st, 45);
    if (overlay_underlying(st, node->rel, 1, inode_out, full, 0) == 0) {
        *sb_out = st->upper_backend.superblock;
        return 0;
    }
    if (overlay_underlying(st, node->rel, 0, inode_out, full,
                           &lower_layer) < 0 || lower_layer < 0)
        return -1;
    *sb_out = st->lower_backends[lower_layer].superblock;
    return *sb_out ? 0 : -1;
}

static int overlay_getxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                            const char *name, void *value, uint32_t size) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t visible_inode;
    vfs_superblock_t *visible_sb = 0;
    if (!st || idx < 0 ||
        overlay_visible_inode(st, &st->nodes[idx], &visible_inode,
                              &visible_sb) < 0 ||
        !visible_sb->ops || !visible_sb->ops->getxattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return visible_sb->ops->getxattr(visible_sb, &visible_inode, name,
                                     value, size);
}

static int overlay_listxattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                             char *list, uint32_t size) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t visible_inode;
    vfs_superblock_t *visible_sb = 0;
    if (!st || idx < 0 ||
        overlay_visible_inode(st, &st->nodes[idx], &visible_inode,
                              &visible_sb) < 0 ||
        !visible_sb->ops || !visible_sb->ops->listxattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return visible_sb->ops->listxattr(visible_sb, &visible_inode, list, size);
}

static int overlay_removexattr(vfs_superblock_t *sb, vfs_inode_t *inode,
                               const char *name) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t upper_inode;
    vfs_superblock_t *upper_sb = 0;
    if (!st || idx < 0 ||
        overlay_upper_inode(st, &st->nodes[idx], &upper_inode,
                            &upper_sb) < 0 ||
        !upper_sb->ops || !upper_sb->ops->removexattr)
        return VFS_XATTR_ERR_UNSUPPORTED;
    return upper_sb->ops->removexattr(upper_sb, &upper_inode, name);
}

static int overlay_getattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           vfs_inode_t *out) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t visible_inode;
    vfs_superblock_t *visible_sb = 0;
    if (!st || idx < 0 || !out ||
        overlay_visible_inode(st, &st->nodes[idx], &visible_inode,
                              &visible_sb) < 0)
        return -1;
    if (visible_sb->ops && visible_sb->ops->getattr &&
        visible_sb->ops->getattr(visible_sb, &visible_inode,
                                 &visible_inode) < 0)
        return -1;
    st->nodes[idx].backing = visible_inode;
    overlay_fill_inode((uint32_t)idx, &st->nodes[idx], out);
    return 0;
}

static int overlay_settimes(vfs_superblock_t *sb, const vfs_inode_t *inode,
                            uint32_t atime, uint32_t mtime,
                            int set_atime, int set_mtime) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t upper_inode;
    vfs_superblock_t *upper_sb = 0;
    if (!st || idx < 0 ||
        overlay_upper_inode(st, &st->nodes[idx], &upper_inode,
                            &upper_sb) < 0 ||
        !upper_sb->ops || !upper_sb->ops->settimes)
        return -1;
    return upper_sb->ops->settimes(upper_sb, &upper_inode, atime, mtime,
                                   set_atime, set_mtime);
}

static int overlay_setattr(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           uint16_t mode, uint32_t uid, uint32_t gid,
                           uint32_t valid) {
    overlay_state_t *st = overlay_state(sb);
    int idx = overlay_inode_index(st, inode);
    vfs_inode_t upper_inode;
    vfs_superblock_t *upper_sb = 0;
    int result;
    if (!st || idx < 0 ||
        overlay_upper_inode(st, &st->nodes[idx], &upper_inode,
                            &upper_sb) < 0 ||
        !upper_sb->ops || !upper_sb->ops->setattr)
        return -1;
    result = upper_sb->ops->setattr(upper_sb, &upper_inode, mode, uid, gid,
                                    valid);
    if (result == 0) {
        if (valid & VFS_SETATTR_MODE) upper_inode.mode = mode;
        if (valid & VFS_SETATTR_UID) upper_inode.uid = uid;
        if (valid & VFS_SETATTR_GID) upper_inode.gid = gid;
        st->nodes[idx].backing = upper_inode;
    }
    return result;
}

static int overlay_sync(vfs_superblock_t *sb) {
    overlay_state_t *st = overlay_state(sb);
    vfs_superblock_t *upper_sb;
    if (!st) return -1;
    upper_sb = st->upper_backend.superblock;
    if (!upper_sb || !upper_sb->ops) return -1;
    /*
     * The public operation wrapper already serializes this call.  Taking the
     * same non-recursive lock here deadlocks every fsync on an overlay inode,
     * including systemd's first durable write to /etc/machine-id on a live
     * root.  Keep the helper lock-neutral like the other overlay helpers.
     */
    return upper_sb->ops->sync ? upper_sb->ops->sync(upper_sb) : 0;
}

#define OVERLAY_SERIALIZED_BEGIN(sb_value, state_name)                         \
    overlay_state_t *state_name = overlay_state(sb_value);                    \
    overlay_scratch_context_t *scratch_context;                               \
    int result;                                                               \
    if (!state_name) return -1;                                               \
    scratch_context = overlay_scratch_acquire(state_name);                    \
    if (!scratch_context) return -1;                                          \
    overlay_operation_lock(state_name)

#define OVERLAY_SERIALIZED_END(state_name)                                    \
    overlay_operation_unlock(state_name);                                    \
    overlay_scratch_release(state_name, scratch_context);                     \
    return result

static int overlay_lookup_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                             const char *name, vfs_inode_t *out) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_lookup(sb, dir, name, out);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_read_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                           uint32_t off, void *buf, uint32_t len) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_read(sb, inode, off, buf, len);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_write_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                            uint32_t off, const void *buf, uint32_t len) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_write(sb, inode, off, buf, len);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_create_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                             const char *name, uint16_t mode,
                             vfs_inode_t *out) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_create(sb, dir, name, mode, out);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_mkdir_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                            const char *name, uint16_t mode,
                            vfs_inode_t *out) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_mkdir(sb, dir, name, mode, out);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_symlink_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                              const char *name, const char *target,
                              uint16_t mode, vfs_inode_t *out) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_symlink(sb, dir, name, target, mode, out);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_readlink_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                               char *out, uint32_t max) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_readlink(sb, inode, out, max);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_unlink_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                             const char *name) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_unlink(sb, dir, name);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_rename_op(vfs_superblock_t *sb, vfs_inode_t *old_dir,
                             const char *old_name, vfs_inode_t *new_dir,
                             const char *new_name) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_rename(sb, old_dir, old_name, new_dir, new_name);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_truncate_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                               uint32_t length) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_truncate(sb, inode, length);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_readdir_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                              uint32_t idx, char *name_out,
                              vfs_inode_t *inode_out) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_readdir(sb, dir, idx, name_out, inode_out);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_statfs_op(vfs_superblock_t *sb, uint32_t *total_kb,
                             uint32_t *used_kb) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_statfs(sb, total_kb, used_kb);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_sync_op(vfs_superblock_t *sb) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_sync(sb);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_link_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                           vfs_inode_t *dir, const char *name) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_link(sb, inode, dir, name);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_rmdir_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                            const char *name) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_rmdir(sb, dir, name);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_mknod_op(vfs_superblock_t *sb, vfs_inode_t *dir,
                            const char *name, uint16_t mode, uint64_t rdev,
                            vfs_inode_t *out) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_mknod(sb, dir, name, mode, rdev, out);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_fallocate_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                                uint32_t mode, uint64_t offset,
                                uint64_t length) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_fallocate(sb, inode, mode, offset, length);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_setxattr_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                               const char *name, const void *value,
                               uint32_t size, uint32_t flags) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_setxattr(sb, inode, name, value, size, flags);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_getxattr_op(vfs_superblock_t *sb,
                               const vfs_inode_t *inode, const char *name,
                               void *value, uint32_t size) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_getxattr(sb, inode, name, value, size);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_listxattr_op(vfs_superblock_t *sb,
                                const vfs_inode_t *inode, char *list,
                                uint32_t size) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_listxattr(sb, inode, list, size);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_removexattr_op(vfs_superblock_t *sb, vfs_inode_t *inode,
                                  const char *name) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_removexattr(sb, inode, name);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_getattr_op(vfs_superblock_t *sb,
                              const vfs_inode_t *inode, vfs_inode_t *out) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_getattr(sb, inode, out);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_settimes_op(vfs_superblock_t *sb,
                               const vfs_inode_t *inode, uint32_t atime,
                               uint32_t mtime, int set_atime,
                               int set_mtime) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_settimes(sb, inode, atime, mtime,
                              set_atime, set_mtime);
    OVERLAY_SERIALIZED_END(st);
}

static int overlay_setattr_op(vfs_superblock_t *sb,
                              const vfs_inode_t *inode, uint16_t mode,
                              uint32_t uid, uint32_t gid, uint32_t valid) {
    OVERLAY_SERIALIZED_BEGIN(sb, st);
    result = overlay_setattr(sb, inode, mode, uid, gid, valid);
    OVERLAY_SERIALIZED_END(st);
}

static filesystem_ops_t g_overlay_ops = {
    .lookup = overlay_lookup_op,
    .read = overlay_read_op,
    .write = overlay_write_op,
    .create = overlay_create_op,
    .mkdir = overlay_mkdir_op,
    .symlink = overlay_symlink_op,
    .readlink = overlay_readlink_op,
    .unlink = overlay_unlink_op,
    .rename = overlay_rename_op,
    .truncate = overlay_truncate_op,
    .readdir = overlay_readdir_op,
    .statfs = overlay_statfs_op,
    .sync = overlay_sync_op,
    .link = overlay_link_op,
    .rmdir = overlay_rmdir_op,
    .mknod = overlay_mknod_op,
    .fallocate = overlay_fallocate_op,
    .setxattr = overlay_setxattr_op,
    .getxattr = overlay_getxattr_op,
    .listxattr = overlay_listxattr_op,
    .removexattr = overlay_removexattr_op,
    .getattr = overlay_getattr_op,
    .settimes = overlay_settimes_op,
    .setattr = overlay_setattr_op
};

static int overlay_option_value(const char *opts, const char *key, char *out, uint32_t out_len) {
    uint32_t key_len;
    if (!opts || !key || !out || out_len == 0) return -1;
    key_len = (uint32_t)strlen(key);
    for (const char *p = opts; *p;) {
        const char *start = p;
        const char *eq;
        const char *end;
        while (*p && *p != ',') p++;
        end = p;
        if (*p == ',') p++;
        eq = start;
        while (eq < end && *eq != '=') eq++;
        if (eq < end && (uint32_t)(eq - start) == key_len && memcmp(start, key, key_len) == 0) {
            uint32_t len = (uint32_t)(end - eq - 1);
            if (len == 0 || len >= out_len) return -1;
            memcpy(out, eq + 1, len);
            out[len] = 0;
            return 0;
        }
    }
    return -1;
}

int overlayfs_mount(const char *dev, const char *target) {
    overlay_state_t *st;
    vfs_superblock_t *sb;
    vfs_inode_t lower_root;
    vfs_inode_t upper_root;
    vfs_inode_t work_root;
    overlay_scratch_context_t *scratch_context;
    const char *failure = "unknown";
    if (!dev || !target) return -1;
    st = overlay_state_allocate();
    if (!st) return -1;
    sb = &st->superblock;
    scratch_context = overlay_scratch_acquire(st);
    if (!scratch_context) {
        overlay_state_destroy(st);
        return -1;
    }
    if (overlay_option_value(dev, "lowerdir", st->lower, sizeof(st->lower)) < 0 ||
        overlay_option_value(dev, "upperdir", st->upper, sizeof(st->upper)) < 0) {
        printf("[overlayfs] mount requires lowerdir= and upperdir= options\n");
        failure = "options";
        goto failed;
    }
    if (overlay_option_value(dev, "workdir", st->work, sizeof(st->work)) < 0)
        st->work[0] = 0;
    st->lower_count = 1u;
    for (const char *cursor = st->lower; *cursor; ++cursor) {
        if (*cursor == ':') {
            if (st->lower_count == UINT32_MAX) {
                failure = "lower-count";
                goto failed;
            }
            ++st->lower_count;
        }
    }
    if (overlay_lower_backends_allocate(st) < 0) {
        failure = "lower-storage";
        goto failed;
    }
    {
        int lower_count = overlay_lower_count(st);
        if (lower_count == 0) {
            failure = "lower-count";
            goto failed;
        }
        for (int layer = 0; layer < lower_count; ++layer) {
            char *lower = overlay_scratch(st, 46);
            if (overlay_lower_base(st, layer, lower, VFS_PATH_MAX) < 0 ||
                overlay_backend_capture(
                    lower, &st->lower_backends[layer], &lower_root) < 0 ||
                !overlay_inode_is_dir(&lower_root)) {
                failure = "lower";
                goto failed;
            }
        }
    }
    if (overlay_backend_capture(st->upper, &st->upper_backend,
                                &upper_root) < 0 ||
        !overlay_inode_is_dir(&upper_root)) {
        failure = "upper";
        goto failed;
    }
    if (st->work[0]) {
        char *internal_work = overlay_scratch(st, 47);
        if (overlay_backend_capture(st->work, &st->work_backend,
                                    &work_root) < 0 ||
            !overlay_inode_is_dir(&work_root) ||
            overlay_join(internal_work, VFS_PATH_MAX, st->work,
                         "work") < 0) {
            failure = "work";
            goto failed;
        }
        if (overlay_backend_resolve(st, &st->work_backend, internal_work,
                                    &work_root) < 0 &&
            overlay_backend_mkdir(st, &st->work_backend, internal_work,
                                  0700u, 0, &work_root) < 0) {
            failure = "work-internal";
            goto failed;
        }
    }

    if (overlay_node_reserve(st, 1u) < 0) {
        failure = "node-storage";
        goto failed;
    }
    st->used = 1;
    st->nodes[0].used = 1;
    st->nodes[0].upper = 1;
    st->nodes[0].backing.mode = VFS_INODE_DIR | 0755;
    st->nodes[0].rel[0] = 0;

    memset(sb, 0, sizeof(*sb));
    strcpy(sb->fs_name, "overlay");
    strncpy(sb->dev_name, "overlay", sizeof(sb->dev_name) - 1);
    strncpy(sb->mountpoint, target, sizeof(sb->mountpoint) - 1);
    overlay_fill_inode(0, &st->nodes[0], &sb->root);
    sb->ops = &g_overlay_ops;
    sb->fs_private = st;
    sb->retain = overlay_retain;
    sb->release = overlay_release;
    printf("[overlayfs] mounted lower=%s upper=%s target=%s\n", st->lower, st->upper, target);
    {
        int result = vfs_add_superblock(sb);
        overlay_scratch_release(st, scratch_context);
        if (result < 0 && !st->references) {
            st->used = 0;
            overlay_state_destroy(st);
        }
        return result;
    }
failed:
    printf("[overlayfs] mount failed at %s\n", failure);
    overlay_scratch_release(st, scratch_context);
    overlay_state_destroy(st);
    return -1;
}
