/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent filesystem-context helpers.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/fs_context.h"

#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "vfs/vfs.h"

static uint32_t kernel_fs_string_length(const char *text) {
    uint32_t length = 0;
    if (!text) return 0;
    while (text[length]) ++length;
    return length;
}

int kernel_fs_context_copy_path(char *destination, uint32_t capacity,
                                const char *source) {
    uint32_t length;
    if (!destination || !source || !capacity)
        return -EDGE_LINUX_EINVAL;
    length = kernel_fs_string_length(source);
    if (length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
    for (uint32_t index = 0; index <= length; ++index)
        destination[index] = source[index];
    return 0;
}

int kernel_fs_path_is_beneath(const char *root, const char *path) {
    uint32_t length;
    if (!root || !root[0] || (root[0] == '/' && !root[1])) return 1;
    if (!path) return 0;
    length = kernel_fs_string_length(root);
    for (uint32_t index = 0; index < length; ++index)
        if (path[index] != root[index]) return 0;
    return path[length] == 0 || path[length] == '/';
}

int kernel_fs_path_normalize(const char *base, const char *path,
                             char *output, uint32_t capacity) {
    uint32_t output_length = 1u;
    if (!path || !output || capacity < 2u)
        return -EDGE_LINUX_EINVAL;
    if (path[0] != '/' && (!base || base[0] != '/'))
        return -EDGE_LINUX_EINVAL;

    output[0] = '/';
    output[1] = 0;
    for (uint32_t pass = 0; pass < 2u; ++pass) {
        const char *source = pass == 0u ? base : path;
        uint32_t position = 0;
        if ((path[0] == '/' && pass == 0u) || (!source && pass == 0u))
            continue;
        if (!source) return -EDGE_LINUX_EINVAL;
        while (source[position]) {
            uint32_t start;
            uint32_t length;
            while (source[position] == '/') ++position;
            if (!source[position]) break;
            start = position;
            while (source[position] && source[position] != '/') ++position;
            length = position - start;
            if (length == 1u && source[start] == '.') continue;
            if (length == 2u && source[start] == '.' &&
                source[start + 1u] == '.') {
                if (output_length > 1u) {
                    while (output_length > 1u &&
                           output[output_length - 1u] != '/')
                        --output_length;
                    if (output_length > 1u) --output_length;
                }
                output[output_length] = 0;
                continue;
            }
            if (output_length > 1u) {
                if (output_length + 1u >= capacity)
                    return -EDGE_LINUX_ENAMETOOLONG;
                output[output_length++] = '/';
            }
            if (length >= capacity - output_length)
                return -EDGE_LINUX_ENAMETOOLONG;
            for (uint32_t index = 0; index < length; ++index)
                output[output_length++] = source[start + index];
            output[output_length] = 0;
        }
    }
    return 0;
}

static int kernel_fs_apply_root(const char *root, const char *virtual_path,
                                char *output, uint32_t capacity) {
    uint32_t root_length;
    uint32_t virtual_length;
    uint32_t position = 0;
    if (!root || !root[0]) root = "/";
    if (!virtual_path || virtual_path[0] != '/')
        return -EDGE_LINUX_EINVAL;
    if (root[0] == '/' && !root[1])
        return kernel_fs_context_copy_path(output, capacity, virtual_path);

    root_length = kernel_fs_string_length(root);
    virtual_length = kernel_fs_string_length(virtual_path);
    if (root_length + (virtual_length > 1u ? virtual_length : 0u) >=
        capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    while (root[position]) {
        output[position] = root[position];
        ++position;
    }
    if (virtual_length > 1u) {
        for (uint32_t index = 0; index <= virtual_length; ++index)
            output[position + index] = virtual_path[index];
    } else {
        output[position] = 0;
    }
    return 0;
}

int kernel_current_fs_snapshot(char *cwd, uint32_t cwd_capacity,
                               char *root, uint32_t root_capacity) {
    if (!cwd || !root) return -EDGE_LINUX_EIO;
    if (!cwd_capacity || !root_capacity) return -EDGE_LINUX_EINVAL;
    return kernel_arch_current_fs_snapshot(
        cwd, cwd_capacity, root, root_capacity);
}

static int kernel_current_fs_set_location(const char *path, int set_root) {
    if (!path || path[0] != '/') return -EDGE_LINUX_EINVAL;
    if (kernel_fs_string_length(path) >= VFS_PATH_MAX)
        return -EDGE_LINUX_ENAMETOOLONG;
    return kernel_arch_current_fs_set_location(path, set_root);
}

int kernel_current_fs_set_cwd(const char *path) {
    return kernel_current_fs_set_location(path, 0);
}

int kernel_current_fs_set_root(const char *path) {
    return kernel_current_fs_set_location(path, 1);
}

int kernel_current_fs_unshare(void) {
    return kernel_arch_current_fs_unshare();
}

uint16_t kernel_current_umask(void) {
    kernel_linux_identity_t identity;
    kernel_proc_task_view_t view;
    uint16_t mask = 0;

    if (kernel_current_linux_identity(&identity) < 0) return 0;
    if (kernel_proc_task_view_get(identity.global_tid, &view) == 0 &&
        view.state != KERNEL_PROC_TASK_ZOMBIE)
        mask = view.umask;
    return (uint16_t)(mask & 0777u);
}

uint16_t kernel_current_umask_set(uint16_t mask) {
    uint16_t previous = 0;
    (void)kernel_arch_current_umask_commit(
        (uint16_t)(mask & 0777u), &previous);
    return (uint16_t)(previous & 0777u);
}

int kernel_fs_path_resolve(const char *root, const char *base,
                           const char *path, char *scratch,
                           uint32_t scratch_capacity, char *output,
                           uint32_t output_capacity) {
    const char *virtual_base;
    uint32_t root_length;
    int status;
    if (!root || !root[0]) root = "/";
    if (!base || !base[0]) base = "/";
    if (!path || !path[0]) return -EDGE_LINUX_ENOENT;
    if (!scratch || !output || scratch == output)
        return -EDGE_LINUX_EINVAL;

    if (path[0] == '/') {
        status = kernel_fs_path_normalize(
            0, path, scratch, scratch_capacity);
        return status < 0 ? status : kernel_fs_apply_root(
            root, scratch, output, output_capacity);
    }

    if (!kernel_fs_path_is_beneath(root, base))
        return kernel_fs_path_normalize(
            base, path, output, output_capacity);

    root_length = kernel_fs_string_length(root);
    virtual_base = root_length > 1u ? base + root_length : base;
    if (!virtual_base[0]) virtual_base = "/";
    status = kernel_fs_path_normalize(
        virtual_base, path, scratch, scratch_capacity);
    return status < 0 ? status : kernel_fs_apply_root(
        root, scratch, output, output_capacity);
}

int kernel_fs_cwd_make_visible(const char *root, char *cwd,
                               uint32_t capacity) {
    static const char unreachable[] = "(unreachable)";
    uint32_t root_length;
    uint32_t cwd_length;
    uint32_t prefix_length = sizeof(unreachable) - 1u;
    if (!cwd || !capacity || cwd[0] != '/')
        return -EDGE_LINUX_EINVAL;
    if (!root || !root[0] || (root[0] == '/' && !root[1]))
        return 0;

    root_length = kernel_fs_string_length(root);
    cwd_length = kernel_fs_string_length(cwd);
    if (kernel_fs_path_is_beneath(root, cwd)) {
        if (cwd_length == root_length) {
            if (capacity < 2u) return -EDGE_LINUX_ENAMETOOLONG;
            cwd[0] = '/';
            cwd[1] = 0;
            return 0;
        }
        for (uint32_t index = root_length;
             index <= cwd_length; ++index)
            cwd[index - root_length] = cwd[index];
        return 0;
    }

    if (prefix_length + cwd_length >= capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    for (uint32_t index = cwd_length + 1u; index > 0u; --index)
        cwd[prefix_length + index - 1u] = cwd[index - 1u];
    for (uint32_t index = 0; index < prefix_length; ++index)
        cwd[index] = unreachable[index];
    return 0;
}
