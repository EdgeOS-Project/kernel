/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared VFS open policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/inotify.h"
#include "kernel/linux_errno.h"
#include "kernel/vfs_runtime.h"

static int g_failures;
static char g_paths[4][256];
static char g_prepared_path[256];
static char g_installed_path[256];
static char g_notified_path[256];
static int g_resolve_at_result;
static int g_search_result;
static int g_prepare_result;
static int g_target_present;
static int g_target_has_superblock;
static int g_permission_result;
static int g_permission_calls;
static int g_permission_mask;
static int g_create_result;
static int g_create_calls;
static uint16_t g_created_mode;
static char g_created_leaf[VFS_NAME_MAX];
static int g_sync_result;
static int g_cache_invalidations;
static int g_truncate_result;
static int g_truncate_calls;
static int g_magic_handled;
static int64_t g_magic_result;
static int g_magic_calls;
static int g_special_handled;
static int64_t g_special_result;
static int g_special_calls;
static int g_install_result;
static int g_install_calls;
static int g_install_unlink;
static int g_unlink_calls;
static int g_unlink_result;
static uint16_t g_umask;
static uint32_t g_notify_masks[4];
static int g_notify_calls;
static vfs_inode_t g_target_inode;
static vfs_inode_t g_parent_inode;
static vfs_inode_t g_created_inode;
static vfs_superblock_t g_superblock;
static vfs_superblock_t g_canonical_superblock;
static filesystem_ops_t g_ops;
static char g_canonical_path[256];
static char g_resolution_symlink_path[256];
static int g_canonical_result;
static int g_canonical_cross_mount;
static int g_cached_result;
static int g_cached_negative;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static int mock_create(vfs_superblock_t *superblock, vfs_inode_t *directory,
                       const char *name, uint16_t mode, vfs_inode_t *out) {
    expect_true("create superblock", superblock == &g_superblock);
    expect_true("create parent", directory && directory->ino == 2u);
    ++g_create_calls;
    g_created_mode = mode;
    strncpy(g_created_leaf, name, sizeof(g_created_leaf) - 1u);
    g_created_leaf[sizeof(g_created_leaf) - 1u] = 0;
    if (g_create_result < 0) return g_create_result;
    *out = g_created_inode;
    return 0;
}

static int mock_unlink_operation(vfs_superblock_t *superblock,
                                 vfs_inode_t *directory,
                                 const char *name) {
    (void)superblock;
    (void)directory;
    (void)name;
    return 0;
}

int kernel_vfs_current_mount_scratch(kernel_vfs_mount_scratch_t *scratch) {
    if (!scratch) return -EDGE_LINUX_EIO;
    scratch->source = g_paths[0];
    scratch->target = g_paths[1];
    scratch->data = g_paths[2];
    scratch->workspace = g_paths[3];
    scratch->capacity = sizeof(g_paths[0]);
    return 0;
}

int arch_vfs_current_context(kernel_vfs_current_context_t *context) {
    if (!context) return -1;
    memset(context, 0, sizeof(*context));
    context->root = "/";
    context->cwd = "/sandbox";
    return 0;
}

int kernel_vfs_resolve_fd(int32_t descriptor,
                          kernel_vfs_target_t *target) {
    (void)descriptor;
    (void)target;
    return -EDGE_LINUX_EBADF;
}

uint32_t vfs_mount_flags_for_path(const char *path) {
    (void)path;
    return 0;
}

int kernel_vfs_resolve_at_path(int32_t directory, const char *path,
                               char *output, uint32_t capacity) {
    (void)directory;
    expect_true("resolve-at source", path && strcmp(path, "input") == 0);
    if (g_resolve_at_result < 0) return g_resolve_at_result;
    if (strlen(g_prepared_path) + 1u > capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(output, g_prepared_path, strlen(g_prepared_path) + 1u);
    return 0;
}

int vfs_path_search_check(const char *path, char *scratch,
                          uint32_t capacity, int include_final) {
    (void)scratch;
    (void)capacity;
    expect_true("search canonical path",
                strcmp(path, g_prepared_path) == 0);
    expect_true("search excludes final", include_final == 0);
    return g_search_result;
}

int64_t kernel_vfs_open_magic_fd(
    const kernel_vfs_open_request_t *request, const char *path,
    int *handled) {
    (void)request;
    ++g_magic_calls;
    expect_true("magic canonical path",
                strcmp(path, g_prepared_path) == 0);
    *handled = g_magic_handled;
    return g_magic_result;
}

int arch_vfs_metadata_path_prepare(const char *path, int nofollow,
                                   char *output, uint32_t capacity) {
    (void)nofollow;
    expect_true("prepare canonical path", strcmp(path, "/resolved") == 0);
    if (g_prepare_result < 0) return g_prepare_result;
    if (strlen(g_prepared_path) + 1u > capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(output, g_prepared_path, strlen(g_prepared_path) + 1u);
    return 0;
}

static int path_is_staging(const char *path) {
    return strncmp(path, "/tmpdir/.edgeos-tmp-", 20u) == 0;
}

int vfs_resolve(const char *path, vfs_inode_t *inode,
                vfs_superblock_t **superblock, vfs_inode_t *parent,
                char *leaf) {
    (void)parent;
    (void)leaf;
    if (strcmp(path, "/") == 0 || strcmp(path, "/tmpdir") == 0 ||
        strcmp(path, "/sandbox") == 0) {
        *inode = g_parent_inode;
        if (superblock) *superblock = &g_superblock;
        return 0;
    }
    if (path_is_staging(path)) return -1;
    if (strcmp(path, g_prepared_path) != 0 || !g_target_present)
        return -1;
    *inode = g_target_inode;
    if (superblock)
        *superblock = g_target_has_superblock ? &g_superblock : 0;
    return 0;
}

int vfs_resolve_nofollow(const char *path, vfs_inode_t *inode,
                         vfs_superblock_t **superblock) {
    if (g_resolution_symlink_path[0] &&
        strcmp(path, g_resolution_symlink_path) == 0) {
        memset(inode, 0, sizeof(*inode));
        inode->ino = 91u;
        inode->mode = VFS_INODE_LNK | 0777u;
        if (superblock) *superblock = &g_superblock;
        return 0;
    }
    return vfs_resolve(path, inode, superblock, 0, 0);
}

int vfs_resolve_canonical(const char *path, char *resolved,
                          uint32_t resolved_capacity,
                          vfs_inode_t *inode,
                          vfs_superblock_t **superblock) {
    uint32_t length;
    if (g_canonical_result < 0) return g_canonical_result;
    if (strcmp(path, "/sandbox") == 0) {
        length = (uint32_t)strlen("/sandbox");
        if (!resolved || length >= resolved_capacity) return -1;
        memcpy(resolved, "/sandbox", length + 1u);
        if (inode) *inode = g_parent_inode;
        if (superblock) *superblock = &g_superblock;
        return 0;
    }
    length = (uint32_t)strlen(g_canonical_path);
    if (!resolved || length >= resolved_capacity) return -1;
    memcpy(resolved, g_canonical_path, length + 1u);
    if (inode) *inode = g_target_inode;
    if (superblock) {
        *superblock = g_canonical_cross_mount ?
            &g_canonical_superblock : &g_superblock;
    }
    return 0;
}

int vfs_resolve_canonical_rooted(const char *path, const char *root,
                                 char *resolved,
                                 uint32_t resolved_capacity,
                                 vfs_inode_t *inode,
                                 vfs_superblock_t **superblock) {
    (void)root;
    return vfs_resolve_canonical(
        path, resolved, resolved_capacity, inode, superblock);
}

int vfs_resolve_cached(const char *path, vfs_inode_t *inode,
                       vfs_superblock_t **superblock, int *negative) {
    if (!g_cached_result) return 0;
    if (negative) *negative = g_cached_negative;
    if (g_cached_negative) return 1;
    return vfs_resolve_nofollow(path, inode, superblock) == 0;
}

int vfs_permission_check(const vfs_inode_t *inode, int access_mask) {
    (void)inode;
    ++g_permission_calls;
    g_permission_mask = access_mask;
    return g_permission_result;
}

int vfs_sync_mutation_if_required(vfs_superblock_t *superblock,
                                  int namespace_mutation) {
    expect_true("sync superblock", superblock == &g_superblock);
    expect_true("sync namespace mutation", namespace_mutation == 1);
    return g_sync_result;
}

void vfs_path_cache_invalidate_all(void) {
    ++g_cache_invalidations;
}

uint16_t kernel_current_umask(void) {
    return g_umask;
}

int kernel_vfs_open_access_mask(const kernel_vfs_open_request_t *request,
                                int newly_created) {
    int mask = 0;
    if (!request || newly_created ||
        (request->flags & KERNEL_VFS_OPEN_PATH))
        return 0;
    if (request->access_mode == KERNEL_VFS_OPEN_READ_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE)
        mask |= 4;
    if (request->access_mode == KERNEL_VFS_OPEN_WRITE_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE ||
        (request->flags & KERNEL_VFS_OPEN_TRUNCATE))
        mask |= 2;
    return mask;
}

int kernel_vfs_truncate_target(kernel_vfs_target_t *target,
                               uint32_t length) {
    expect_true("truncate target", target && target->inode);
    expect_true("truncate length", length == 0u);
    ++g_truncate_calls;
    return g_truncate_result;
}

int64_t arch_vfs_open_special(
    const kernel_vfs_open_request_t *request, const char *path,
    int *handled) {
    (void)request;
    ++g_special_calls;
    expect_true("special canonical path",
                strcmp(path, g_prepared_path) == 0);
    *handled = g_special_handled;
    return g_special_result;
}

int vfs_unlink(const char *path) {
    ++g_unlink_calls;
    expect_true("unlink staging path", path_is_staging(path));
    return g_unlink_result;
}

int arch_vfs_open_install_regular(
    const kernel_vfs_open_request_t *request, const char *path,
    const vfs_inode_t *inode, vfs_superblock_t *superblock,
    int unlink_after_open) {
    (void)request;
    expect_true("install inode", inode && inode->ino != 0u);
    expect_true("install superblock",
                superblock ==
                    (g_target_has_superblock ? &g_superblock : 0));
    ++g_install_calls;
    g_install_unlink = unlink_after_open;
    strncpy(g_installed_path, path, sizeof(g_installed_path) - 1u);
    g_installed_path[sizeof(g_installed_path) - 1u] = 0;
    if (g_install_result < 0) return g_install_result;
    if (unlink_after_open && vfs_unlink(path) < 0)
        return -EDGE_LINUX_EIO;
    return g_install_result;
}

void arch_vfs_notify_path(const char *path, uint32_t mask) {
    if (g_notify_calls < (int)(sizeof(g_notify_masks) /
                               sizeof(g_notify_masks[0])))
        g_notify_masks[g_notify_calls] = mask;
    ++g_notify_calls;
    strncpy(g_notified_path, path, sizeof(g_notified_path) - 1u);
    g_notified_path[sizeof(g_notified_path) - 1u] = 0;
}

static kernel_vfs_open_request_t request_make(void) {
    kernel_vfs_open_request_t request;
    memset(&request, 0, sizeof(request));
    request.directory = -100;
    request.path = "input";
    request.access_mode = KERNEL_VFS_OPEN_READ_ONLY;
    return request;
}

static void reset_state(void) {
    memset(g_paths, 0, sizeof(g_paths));
    memset(g_prepared_path, 0, sizeof(g_prepared_path));
    memset(g_installed_path, 0, sizeof(g_installed_path));
    memset(g_notified_path, 0, sizeof(g_notified_path));
    memset(g_created_leaf, 0, sizeof(g_created_leaf));
    memset(g_notify_masks, 0, sizeof(g_notify_masks));
    memset(&g_target_inode, 0, sizeof(g_target_inode));
    memset(&g_parent_inode, 0, sizeof(g_parent_inode));
    memset(&g_created_inode, 0, sizeof(g_created_inode));
    memset(&g_superblock, 0, sizeof(g_superblock));
    memset(&g_canonical_superblock, 0, sizeof(g_canonical_superblock));
    memset(&g_ops, 0, sizeof(g_ops));
    memset(g_canonical_path, 0, sizeof(g_canonical_path));
    memset(g_resolution_symlink_path, 0,
           sizeof(g_resolution_symlink_path));
    memcpy(g_prepared_path, "/prepared", sizeof("/prepared"));
    g_resolve_at_result = 0;
    g_search_result = 0;
    g_prepare_result = 0;
    g_target_present = 1;
    g_target_has_superblock = 1;
    g_permission_result = 0;
    g_permission_calls = 0;
    g_permission_mask = 0;
    g_create_result = 0;
    g_create_calls = 0;
    g_created_mode = 0;
    g_sync_result = 0;
    g_cache_invalidations = 0;
    g_truncate_result = 0;
    g_truncate_calls = 0;
    g_magic_handled = 0;
    g_magic_result = 0;
    g_magic_calls = 0;
    g_special_handled = 0;
    g_special_result = 0;
    g_special_calls = 0;
    g_install_result = 17;
    g_install_calls = 0;
    g_install_unlink = 0;
    g_unlink_calls = 0;
    g_unlink_result = 0;
    g_umask = 0022u;
    g_notify_calls = 0;
    g_canonical_result = 0;
    g_canonical_cross_mount = 0;
    g_cached_result = 1;
    g_cached_negative = 0;
    memcpy(g_canonical_path, "/sandbox/input", sizeof("/sandbox/input"));
    g_target_inode.ino = 11u;
    g_target_inode.mode = VFS_INODE_FILE | 0644u;
    g_parent_inode.ino = 2u;
    g_parent_inode.mode = VFS_INODE_DIR | 0777u;
    g_created_inode.ino = 12u;
    g_created_inode.mode = VFS_INODE_FILE | 0644u;
    g_ops.create = mock_create;
    g_ops.unlink = mock_unlink_operation;
    g_superblock.ops = &g_ops;
    g_superblock.mount_id = 1u;
    g_canonical_superblock.mount_id = 2u;
}

static void test_resolution_constraints(void) {
    kernel_vfs_open_request_t request;

    reset_state();
    memcpy(g_prepared_path, "/sandbox/input",
           sizeof("/sandbox/input"));
    request = request_make();
    request.resolve_flags = 0x08u;
    expect_true("beneath canonical path",
                kernel_vfs_open_at(&request) == 17);

    reset_state();
    memcpy(g_prepared_path, "/sandbox/input",
           sizeof("/sandbox/input"));
    memcpy(g_paths[0], "input", sizeof("input"));
    request = request_make();
    request.path = g_paths[0];
    request.resolve_flags = 0x08u;
    expect_true("beneath preserves aliased request path",
                kernel_vfs_open_at(&request) == 17);

    reset_state();
    request = request_make();
    request.resolve_flags = 0x08u;
    memcpy(g_canonical_path, "/outside/input",
           sizeof("/outside/input"));
    expect_true("beneath symlink escape",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EXDEV);

    reset_state();
    request = request_make();
    request.path = "link/entry";
    request.resolve_flags = 0x04u;
    memcpy(g_resolution_symlink_path, "/sandbox/link",
           sizeof("/sandbox/link"));
    expect_true("no symlinks component",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ELOOP);

    reset_state();
    request = request_make();
    request.path = "/proc/self/fd/7";
    request.resolve_flags = 0x02u;
    expect_true("no proc magic links",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ELOOP);

    reset_state();
    request = request_make();
    request.resolve_flags = 0x01u;
    g_canonical_cross_mount = 1;
    expect_true("no cross mount canonical path",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EXDEV);

    reset_state();
    memcpy(g_prepared_path, "/sandbox/input",
           sizeof("/sandbox/input"));
    request = request_make();
    request.path = "/input";
    request.resolve_flags = 0x10u;
    expect_true("in-root absolute path",
                kernel_vfs_open_at(&request) == 17);

    reset_state();
    memcpy(g_prepared_path, "/sandbox/input",
           sizeof("/sandbox/input"));
    request = request_make();
    request.path = "../../input";
    request.resolve_flags = 0x10u;
    expect_true("in-root clamps parent traversal",
                kernel_vfs_open_at(&request) == 17);

    reset_state();
    memcpy(g_prepared_path, "/sandbox/target",
           sizeof("/sandbox/target"));
    memcpy(g_canonical_path, "/sandbox/target",
           sizeof("/sandbox/target"));
    request = request_make();
    request.path = "/absolute-link";
    request.resolve_flags = 0x10u;
    expect_true("in-root rebases absolute symlink",
                kernel_vfs_open_at(&request) == 17);

    reset_state();
    memcpy(g_prepared_path, "/sandbox/input",
           sizeof("/sandbox/input"));
    request = request_make();
    request.resolve_flags = 0x20u;
    expect_true("cached path hit",
                kernel_vfs_open_at(&request) == 17);

    reset_state();
    request = request_make();
    request.resolve_flags = 0x20u;
    g_cached_result = 0;
    expect_true("cached path miss",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EAGAIN);

    reset_state();
    request = request_make();
    request.resolve_flags = 0x20u;
    g_cached_negative = 1;
    expect_true("cached negative path",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ENOENT);
}

static void test_existing_and_validation(void) {
    kernel_vfs_open_request_t request;

    reset_state();
    request = request_make();
    request.access_mode = KERNEL_VFS_OPEN_READ_WRITE;
    expect_true("existing open",
                kernel_vfs_open_at(&request) == 17);
    expect_true("existing access mask",
                g_permission_calls == 1 && g_permission_mask == 6);
    expect_true("existing install",
                g_install_calls == 1 &&
                strcmp(g_installed_path, "/prepared") == 0);
    expect_true("existing open notification",
                g_notify_calls == 1 &&
                g_notify_masks[0] == KERNEL_INOTIFY_OPEN);

    reset_state();
    request = request_make();
    g_resolve_at_result = -EDGE_LINUX_EBADF;
    expect_true("resolve-at error",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EBADF);
    reset_state();
    request = request_make();
    g_search_result = -EDGE_LINUX_EACCES;
    expect_true("search error",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EACCES);
    reset_state();
    request = request_make();
    g_permission_result = -1;
    expect_true("permission error",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EACCES);

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_PATH;
    g_target_has_superblock = 0;
    g_target_inode.mode = VFS_INODE_DIR | 0755u;
    expect_true("path synthetic inode",
                kernel_vfs_open_at(&request) == 17 &&
                g_install_calls == 1);

    reset_state();
    request = request_make();
    g_target_has_superblock = 0;
    expect_true("ordinary synthetic inode rejected",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ENOENT &&
                g_install_calls == 0);
}

static void test_create_and_exclusive(void) {
    kernel_vfs_open_request_t request;

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_CREATE;
    request.mode = 0677u;
    g_target_present = 0;
    memcpy(g_prepared_path, "/created", sizeof("/created"));
    expect_true("create open",
                kernel_vfs_open_at(&request) == 17);
    expect_true("create mode and leaf",
                g_create_calls == 1 &&
                g_created_mode == (VFS_INODE_FILE | 0655u) &&
                strcmp(g_created_leaf, "created") == 0);
    expect_true("create notifications",
                g_notify_calls == 2 &&
                g_notify_masks[0] == KERNEL_INOTIFY_CREATE &&
                g_notify_masks[1] == KERNEL_INOTIFY_OPEN);
    expect_true("create cache invalidated",
                g_cache_invalidations == 1);

    reset_state();
    request = request_make();
    request.flags =
        KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE;
    expect_true("exclusive existing",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EEXIST &&
                g_install_calls == 0);

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_CREATE;
    g_target_present = 0;
    memcpy(g_prepared_path, "/created", sizeof("/created"));
    g_create_result = VFS_PATH_ERR_NO_SPACE;
    expect_true("create error mapped",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ENOSPC);
}

static void test_symlink_directory_and_truncate(void) {
    kernel_vfs_open_request_t request;

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_NOFOLLOW;
    g_target_inode.mode = VFS_INODE_LNK | 0777u;
    expect_true("nofollow symlink",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ELOOP);

    reset_state();
    request = request_make();
    request.flags =
        KERNEL_VFS_OPEN_NOFOLLOW | KERNEL_VFS_OPEN_PATH;
    g_target_inode.mode = VFS_INODE_LNK | 0777u;
    expect_true("path nofollow symlink",
                kernel_vfs_open_at(&request) == 17);

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_DIRECTORY;
    expect_true("directory required",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ENOTDIR);

    reset_state();
    request = request_make();
    request.access_mode = KERNEL_VFS_OPEN_WRITE_ONLY;
    g_target_inode.mode = VFS_INODE_DIR | 0755u;
    expect_true("writable directory",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EISDIR);

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_TRUNCATE;
    request.access_mode = KERNEL_VFS_OPEN_WRITE_ONLY;
    expect_true("truncate success",
                kernel_vfs_open_at(&request) == 17 &&
                g_truncate_calls == 1);
    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_TRUNCATE;
    request.access_mode = KERNEL_VFS_OPEN_WRITE_ONLY;
    g_truncate_result = -EDGE_LINUX_EIO;
    expect_true("truncate error",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EIO &&
                g_install_calls == 0);
}

static void test_magic_and_special(void) {
    kernel_vfs_open_request_t request;

    reset_state();
    request = request_make();
    g_magic_handled = 1;
    g_magic_result = 29;
    expect_true("magic open",
                kernel_vfs_open_at(&request) == 29 &&
                g_special_calls == 0 && g_install_calls == 0);

    reset_state();
    request = request_make();
    g_magic_result = -EDGE_LINUX_ESRCH;
    expect_true("magic error",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_ESRCH &&
                g_special_calls == 0);

    reset_state();
    request = request_make();
    g_special_handled = 1;
    g_special_result = 31;
    expect_true("special open",
                kernel_vfs_open_at(&request) == 31 &&
                g_install_calls == 0);
    expect_true("special notification",
                g_notify_calls == 1 &&
                g_notify_masks[0] == KERNEL_INOTIFY_OPEN);
}

static void test_tmpfile(void) {
    kernel_vfs_open_request_t request;

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_TMPFILE;
    memcpy(g_prepared_path, "/tmpdir", sizeof("/tmpdir"));
    g_target_inode = g_parent_inode;
    expect_true("tmpfile read-only",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EINVAL);

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_TMPFILE;
    request.access_mode = KERNEL_VFS_OPEN_READ_WRITE;
    request.mode = 0677u;
    memcpy(g_prepared_path, "/tmpdir", sizeof("/tmpdir"));
    g_target_inode = g_parent_inode;
    expect_true("tmpfile open",
                kernel_vfs_open_at(&request) == 17);
    expect_true("tmpfile create",
                g_create_calls == 1 &&
                g_created_mode == (VFS_INODE_FILE | 0655u) &&
                strncmp(g_created_leaf, ".edgeos-tmp-", 12u) == 0);
    expect_true("tmpfile anonymous install",
                g_install_calls == 1 && g_install_unlink == 1 &&
                g_unlink_calls == 1);
    expect_true("tmpfile no path notification", g_notify_calls == 0);

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_TMPFILE;
    request.access_mode = KERNEL_VFS_OPEN_READ_WRITE;
    memcpy(g_prepared_path, "/tmpdir", sizeof("/tmpdir"));
    g_target_inode = g_parent_inode;
    g_ops.unlink = 0;
    expect_true("tmpfile unsupported",
                kernel_vfs_open_at(&request) ==
                    -EDGE_LINUX_EOPNOTSUPP);

    reset_state();
    request = request_make();
    request.flags = KERNEL_VFS_OPEN_TMPFILE;
    request.access_mode = KERNEL_VFS_OPEN_READ_WRITE;
    memcpy(g_prepared_path, "/tmpdir", sizeof("/tmpdir"));
    g_target_inode = g_parent_inode;
    g_install_result = -EDGE_LINUX_EMFILE;
    expect_true("tmpfile install cleanup",
                kernel_vfs_open_at(&request) == -EDGE_LINUX_EMFILE &&
                g_unlink_calls == 1);
}

int main(void) {
    test_resolution_constraints();
    test_existing_and_validation();
    test_create_and_exclusive();
    test_symlink_directory_and_truncate();
    test_magic_and_special();
    test_tmpfile();
    if (g_failures) return 1;
    puts("vfs_open_unit: PASS");
    return 0;
}
