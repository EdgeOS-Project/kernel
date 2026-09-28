/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS pre-mount superblock pathname resolver.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/vfs.h"
#include "string.h"
#include "mm/arch_vm.h"
#include "sys/spinlock.h"

#define VFS_RESOLVE_PAGE_SIZE 4096u
#define VFS_RESOLVE_STATIC_CONTEXTS 4u

typedef struct vfs_superblock_resolve_workspace {
    char path[VFS_PATH_MAX];
    char next[VFS_PATH_MAX];
    char walked[VFS_PATH_MAX];
    char target[VFS_PATH_MAX];
} vfs_superblock_resolve_workspace_t;

typedef struct vfs_superblock_resolve_context {
    volatile uint32_t in_use;
    uint32_t allocation_pages;
    struct vfs_superblock_resolve_context *next;
    vfs_superblock_resolve_workspace_t workspace;
} vfs_superblock_resolve_context_t;

static vfs_superblock_resolve_context_t
    g_static_contexts[VFS_RESOLVE_STATIC_CONTEXTS];
static vfs_superblock_resolve_context_t *g_dynamic_contexts;
static volatile uint32_t g_context_list_lock;

static uint32_t resolve_allocation_pages(uint64_t bytes) {
    uint64_t pages;
    if (!bytes) return 0;
    pages = (bytes + VFS_RESOLVE_PAGE_SIZE - 1u) /
        VFS_RESOLVE_PAGE_SIZE;
    return pages > UINT32_MAX ? 0 : (uint32_t)pages;
}

static void resolve_context_list_lock(void) {
    while (__atomic_exchange_n(&g_context_list_lock, 1u,
                               __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_context_list_lock,
                               __ATOMIC_RELAXED))
            spinlock_relax();
    }
}

static void resolve_context_list_unlock(void) {
    __atomic_store_n(&g_context_list_lock, 0u, __ATOMIC_RELEASE);
}

static int resolve_context_claim(vfs_superblock_resolve_context_t *context) {
    uint32_t available = 0;
    if (!context) return 0;
    return __atomic_compare_exchange_n(&context->in_use, &available, 1u, 0,
                                       __ATOMIC_ACQ_REL,
                                       __ATOMIC_RELAXED);
}

static vfs_superblock_resolve_context_t *resolve_context_acquire(void) {
    vfs_superblock_resolve_context_t *context;

    for (uint32_t index = 0; index < VFS_RESOLVE_STATIC_CONTEXTS; ++index) {
        context = &g_static_contexts[index];
        if (resolve_context_claim(context)) return context;
    }
    for (context = __atomic_load_n(&g_dynamic_contexts,
                                   __ATOMIC_ACQUIRE);
         context;
         context = __atomic_load_n(&context->next, __ATOMIC_ACQUIRE)) {
        if (resolve_context_claim(context)) return context;
    }

    {
        uint32_t pages = resolve_allocation_pages(sizeof(*context));
        if (!pages) return 0;
        context = (vfs_superblock_resolve_context_t *)
            arch_vm_alloc_pages(pages);
        if (!context) {
            /* A context may have become reusable while allocation ran. */
            for (uint32_t index = 0;
                 index < VFS_RESOLVE_STATIC_CONTEXTS; ++index) {
                if (resolve_context_claim(&g_static_contexts[index]))
                    return &g_static_contexts[index];
            }
            for (context = __atomic_load_n(&g_dynamic_contexts,
                                           __ATOMIC_ACQUIRE);
                 context;
                 context = __atomic_load_n(&context->next,
                                           __ATOMIC_ACQUIRE)) {
                if (resolve_context_claim(context)) return context;
            }
            return 0;
        }
        memset(context, 0,
               (uint64_t)pages * VFS_RESOLVE_PAGE_SIZE);
        context->allocation_pages = pages;
        context->in_use = 1u;
        resolve_context_list_lock();
        context->next = g_dynamic_contexts;
        __atomic_store_n(&g_dynamic_contexts, context,
                         __ATOMIC_RELEASE);
        resolve_context_list_unlock();
        return context;
    }
}

static void resolve_context_release(
    vfs_superblock_resolve_context_t *context) {
    if (!context) return;
    __atomic_store_n(&context->in_use, 0u, __ATOMIC_RELEASE);
}

static int path_append(char *destination, const char *source) {
    uint32_t length;
    if (!destination || !source) return -1;
    length = (uint32_t)strlen(destination);
    while (*source) {
        if (length + 1u >= VFS_PATH_MAX) return -1;
        destination[length++] = *source++;
    }
    destination[length] = 0;
    return 0;
}

static int normalize_absolute(const char *input, char *output) {
    uint32_t input_offset = 0;
    uint32_t output_length = 1;

    if (!input || input[0] != '/' || !output) return -1;
    output[0] = '/';
    output[1] = 0;
    while (input[input_offset]) {
        uint32_t start;
        uint32_t length;
        while (input[input_offset] == '/') ++input_offset;
        if (!input[input_offset]) break;
        start = input_offset;
        while (input[input_offset] && input[input_offset] != '/')
            ++input_offset;
        length = input_offset - start;
        if (length == 1u && input[start] == '.') continue;
        if (length == 2u && input[start] == '.' && input[start + 1u] == '.') {
            if (output_length > 1u) {
                while (output_length > 1u &&
                       output[output_length - 1u] != '/')
                    --output_length;
                if (output_length > 1u) --output_length;
                output[output_length] = 0;
            }
            continue;
        }
        if (length >= VFS_NAME_MAX) return -1;
        if (output_length > 1u) {
            if (output_length + 1u >= VFS_PATH_MAX) return -1;
            output[output_length++] = '/';
        }
        if (output_length + length >= VFS_PATH_MAX) return -1;
        for (uint32_t index = 0; index < length; ++index)
            output[output_length++] = input[start + index];
        output[output_length] = 0;
    }
    return 0;
}

static int resolve_with_workspace(
    vfs_superblock_t *superblock, const char *path,
    vfs_inode_t *out_inode,
    vfs_superblock_resolve_workspace_t *workspace) {
    uint32_t followed_links = 0;

    if (!workspace || normalize_absolute(path, workspace->path) < 0)
        return -1;
    for (;;) {
        const char *cursor = workspace->path + 1;
        vfs_inode_t current = superblock->root;
        int restart = 0;

        strcpy(workspace->walked, "/");
        while (*cursor) {
            char component[VFS_NAME_MAX];
            const char *remainder;
            uint32_t component_length = 0;

            while (*cursor == '/') ++cursor;
            if (!*cursor) break;
            while (*cursor && *cursor != '/') {
                if (component_length + 1u >= sizeof(component)) return -1;
                component[component_length++] = *cursor++;
            }
            component[component_length] = 0;
            while (*cursor == '/') ++cursor;
            remainder = cursor;

            if (superblock->ops->lookup(superblock, &current,
                                        component, &current) < 0)
                return -1;
            if ((current.mode & 0xf000u) == VFS_INODE_LNK) {
                int target_length;
                if (!superblock->ops->readlink || ++followed_links > 40u)
                    return -1;
                target_length = superblock->ops->readlink(
                    superblock, &current, workspace->target,
                    VFS_PATH_MAX - 1u);
                if (target_length < 0 || target_length >= VFS_PATH_MAX)
                    return -1;
                workspace->target[target_length] = 0;
                if (workspace->target[0] == '/') {
                    strncpy(workspace->next, workspace->target,
                            VFS_PATH_MAX - 1u);
                    workspace->next[VFS_PATH_MAX - 1u] = 0;
                } else {
                    strcpy(workspace->next, workspace->walked);
                    if (strcmp(workspace->next, "/") != 0 &&
                        path_append(workspace->next, "/") < 0)
                        return -1;
                    if (path_append(workspace->next,
                                    workspace->target) < 0)
                        return -1;
                }
                if (*remainder) {
                    if (strcmp(workspace->next, "/") != 0 &&
                        path_append(workspace->next, "/") < 0)
                        return -1;
                    if (path_append(workspace->next, remainder) < 0)
                        return -1;
                }
                if (normalize_absolute(workspace->next,
                                       workspace->path) < 0)
                    return -1;
                restart = 1;
                break;
            }
            if (*remainder && (current.mode & 0xf000u) != VFS_INODE_DIR)
                return -1;
            if (strcmp(workspace->walked, "/") != 0 &&
                path_append(workspace->walked, "/") < 0)
                return -1;
            if (path_append(workspace->walked, component) < 0) return -1;
        }
        if (restart) continue;
        *out_inode = current;
        return 0;
    }
}

int vfs_resolve_superblock_path(vfs_superblock_t *superblock,
                                const char *path,
                                vfs_inode_t *out_inode) {
    vfs_superblock_resolve_context_t *context;
    int result;
    if (!superblock || !superblock->ops || !superblock->ops->lookup ||
        !path || path[0] != '/' || !out_inode)
        return -1;
    memset(out_inode, 0, sizeof(*out_inode));
    context = resolve_context_acquire();
    if (!context) return -1;
    result = resolve_with_workspace(superblock, path, out_inode,
                                    &context->workspace);
    resolve_context_release(context);
    return result;
}
