/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS pre-mount superblock pathname resolver.
 * Copyright (c) EdgeOS Contributors.
 */

#include "vfs/vfs.h"
#include "string.h"

typedef struct vfs_superblock_resolve_workspace {
    char path[VFS_PATH_MAX];
    char next[VFS_PATH_MAX];
    char walked[VFS_PATH_MAX];
    char target[VFS_PATH_MAX];
} vfs_superblock_resolve_workspace_t;

static vfs_superblock_resolve_workspace_t g_workspace;
static volatile uint32_t g_workspace_lock;

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

static int resolve_locked(vfs_superblock_t *superblock, const char *path,
                          vfs_inode_t *out_inode) {
    uint32_t followed_links = 0;

    if (normalize_absolute(path, g_workspace.path) < 0) return -1;
    for (;;) {
        const char *cursor = g_workspace.path + 1;
        vfs_inode_t current = superblock->root;
        int restart = 0;

        strcpy(g_workspace.walked, "/");
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
                    superblock, &current, g_workspace.target,
                    VFS_PATH_MAX - 1u);
                if (target_length < 0 || target_length >= VFS_PATH_MAX)
                    return -1;
                g_workspace.target[target_length] = 0;
                if (g_workspace.target[0] == '/') {
                    strncpy(g_workspace.next, g_workspace.target,
                            VFS_PATH_MAX - 1u);
                    g_workspace.next[VFS_PATH_MAX - 1u] = 0;
                } else {
                    strcpy(g_workspace.next, g_workspace.walked);
                    if (strcmp(g_workspace.next, "/") != 0 &&
                        path_append(g_workspace.next, "/") < 0)
                        return -1;
                    if (path_append(g_workspace.next, g_workspace.target) < 0)
                        return -1;
                }
                if (*remainder) {
                    if (strcmp(g_workspace.next, "/") != 0 &&
                        path_append(g_workspace.next, "/") < 0)
                        return -1;
                    if (path_append(g_workspace.next, remainder) < 0)
                        return -1;
                }
                if (normalize_absolute(g_workspace.next,
                                       g_workspace.path) < 0)
                    return -1;
                restart = 1;
                break;
            }
            if (*remainder && (current.mode & 0xf000u) != VFS_INODE_DIR)
                return -1;
            if (strcmp(g_workspace.walked, "/") != 0 &&
                path_append(g_workspace.walked, "/") < 0)
                return -1;
            if (path_append(g_workspace.walked, component) < 0) return -1;
        }
        if (restart) continue;
        *out_inode = current;
        return 0;
    }
}

int vfs_resolve_superblock_path(vfs_superblock_t *superblock,
                                const char *path,
                                vfs_inode_t *out_inode) {
    int result;
    if (!superblock || !superblock->ops || !superblock->ops->lookup ||
        !path || path[0] != '/' || !out_inode)
        return -1;
    memset(out_inode, 0, sizeof(*out_inode));
    while (__sync_lock_test_and_set(&g_workspace_lock, 1u))
        __asm__ __volatile__("" ::: "memory");
    result = resolve_locked(superblock, path, out_inode);
    __sync_lock_release(&g_workspace_lock);
    return result;
}
