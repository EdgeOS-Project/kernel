/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent current-task VFS policy test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/inotify.h"
#include "kernel/linux_errno.h"
#include "kernel/vfs_runtime.h"

static int g_failures;
static int g_context_available = 1;
static char g_paths[4][64];
static uint8_t g_xattr[128];
static char g_resolved[64];
static const char *g_expected_root = "/sandbox";
static const char *g_expected_base = "/sandbox/work";
static char *g_search_scratch;
static int g_search_result;
static int g_resolve_result;
static int g_nofollow_calls;
static const char *g_notify_paths[4];
static uint32_t g_notify_masks[4];
static uint32_t g_notify_count;
static const char *g_move_old;
static const char *g_move_new;
static vfs_superblock_t g_superblock;
static uint32_t g_mount_namespace = 7u;
static int g_mount_namespace_available = 1;
static int g_pivot_result;
static uint32_t g_rebased_namespace;
static const char *g_rebased_root;
static const char *g_rebased_old;
static int g_truncate_result;
static uint32_t g_truncate_length;
static uint32_t g_truncate_prepare_old_length;
static uint32_t g_truncate_prepare_new_length;
static uint32_t g_truncate_commit_old_length;
static uint32_t g_truncate_commit_new_length;
static int g_fs_snapshot_result;
static int g_fd_resolve_result;
static vfs_inode_t g_directory_inode;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

int arch_vfs_current_context(kernel_vfs_current_context_t *context) {
    if (!g_context_available || !context) return -1;
    context->root = "/sandbox";
    context->cwd = "/sandbox/work";
    for (uint32_t index = 0; index < 4u; ++index)
        context->paths[index] = g_paths[index];
    context->path_capacity = sizeof(g_paths[0]);
    context->xattr = g_xattr;
    context->xattr_capacity = sizeof(g_xattr);
    return 0;
}

int kernel_current_fs_snapshot(char *cwd, uint32_t cwd_capacity,
                               char *root, uint32_t root_capacity) {
    if (g_fs_snapshot_result < 0) return g_fs_snapshot_result;
    if (!cwd || !root || cwd_capacity < sizeof("/sandbox/work") ||
        root_capacity < sizeof("/sandbox"))
        return -EDGE_LINUX_EINVAL;
    strcpy(cwd, "/sandbox/work");
    strcpy(root, "/sandbox");
    return 0;
}

int kernel_vfs_resolve_fd(int32_t descriptor, kernel_vfs_target_t *target) {
    if (g_fd_resolve_result < 0) return g_fd_resolve_result;
    if (descriptor != 5 || !target) return -EDGE_LINUX_EBADF;
    memset(target, 0, sizeof(*target));
    target->inode = &g_directory_inode;
    target->resolved_path = "/sandbox/base";
    return 0;
}

void arch_vfs_notify_path(const char *path, uint32_t mask) {
    if (g_notify_count < 4u) {
        g_notify_paths[g_notify_count] = path;
        g_notify_masks[g_notify_count] = mask;
    }
    ++g_notify_count;
}

void arch_vfs_notify_move(const char *old_path, const char *new_path) {
    g_move_old = old_path;
    g_move_new = new_path;
}

int arch_vfs_current_mount_namespace(uint32_t *namespace_id) {
    if (!g_mount_namespace_available || !namespace_id) return -1;
    *namespace_id = g_mount_namespace;
    return 0;
}

void arch_vfs_rebase_mount_namespace_paths(
    uint32_t namespace_id, const char *new_root, const char *put_old) {
    g_rebased_namespace = namespace_id;
    g_rebased_root = new_root;
    g_rebased_old = put_old;
}

void arch_vfs_rebase_mount_move_paths(
    uint32_t namespace_id, const char *source, const char *target) {
    (void)namespace_id;
    (void)source;
    (void)target;
}

int arch_vfs_truncate_prepare(vfs_superblock_t *superblock,
                              const vfs_inode_t *inode,
                              uint32_t old_length, uint32_t new_length) {
    expect_true("truncate prepare superblock", superblock == &g_superblock);
    expect_true("truncate prepare inode", inode != 0);
    g_truncate_prepare_old_length = old_length;
    g_truncate_prepare_new_length = new_length;
    return 0;
}

void arch_vfs_truncate_commit(vfs_superblock_t *superblock,
                              const vfs_inode_t *inode,
                              uint32_t old_length, uint32_t new_length) {
    expect_true("truncate commit superblock", superblock == &g_superblock);
    expect_true("truncate commit inode", inode != 0);
    g_truncate_commit_old_length = old_length;
    g_truncate_commit_new_length = new_length;
}

int kernel_fs_path_resolve(const char *root, const char *base,
                           const char *path, char *scratch,
                           uint32_t scratch_capacity, char *output,
                           uint32_t output_capacity) {
    (void)path;
    expect_true("resolver root", strcmp(root, g_expected_root) == 0);
    expect_true("resolver cwd", strcmp(base, g_expected_base) == 0);
    expect_true("resolver scratch capacity", scratch_capacity >= 64u);
    expect_true("resolver output capacity", output_capacity >= 16u);
    strcpy(output, "/sandbox/result");
    strcpy(g_resolved, output);
    return scratch ? 0 : -EDGE_LINUX_EINVAL;
}

int vfs_path_search_check(const char *path, char *scratch,
                          uint32_t scratch_capacity, int include_final) {
    expect_true("search resolved path",
                strcmp(path, "/sandbox/result") == 0);
    expect_true("search capacity", scratch_capacity == sizeof(g_paths[0]));
    expect_true("search excludes final", include_final == 0);
    g_search_scratch = scratch;
    return g_search_result;
}

int vfs_resolve(const char *path, vfs_inode_t *out_inode,
                vfs_superblock_t **out_superblock,
                vfs_inode_t *out_parent, char *leaf) {
    (void)out_parent;
    (void)leaf;
    expect_true("follow resolve path",
                strcmp(path, "/sandbox/result") == 0);
    if (g_resolve_result < 0) return g_resolve_result;
    out_inode->mode = VFS_INODE_FILE;
    *out_superblock = &g_superblock;
    return 0;
}

int vfs_resolve_nofollow(const char *path, vfs_inode_t *out_inode,
                         vfs_superblock_t **out_superblock) {
    ++g_nofollow_calls;
    return vfs_resolve(path, out_inode, out_superblock, 0, 0);
}

int vfs_pivot_root(const char *new_root, const char *put_old) {
    expect_true("pivot new root", strcmp(new_root, "/new") == 0);
    expect_true("pivot put old", strcmp(put_old, "/new/old") == 0);
    return g_pivot_result;
}

uint32_t vfs_mount_flags_for_path(const char *path) {
    (void)path;
    return 0;
}

int vfs_truncate_inode(vfs_superblock_t *superblock, vfs_inode_t *inode,
                       uint32_t new_size) {
    expect_true("truncate superblock", superblock == &g_superblock);
    expect_true("truncate inode", inode != 0);
    g_truncate_length = new_size;
    if (g_truncate_result == 0) inode->size = new_size;
    return g_truncate_result;
}

static void test_path_error_policy(void) {
    expect_true("path success", kernel_vfs_path_result(0) == 0);
    expect_true("path busy",
                kernel_vfs_path_result(VFS_PATH_ERR_BUSY) ==
                    -EDGE_LINUX_EBUSY);
    expect_true("path not empty",
                kernel_vfs_path_result(VFS_PATH_ERR_NOT_EMPTY) ==
                    -EDGE_LINUX_ENOTEMPTY);
    expect_true("path cross device",
                kernel_vfs_path_result(VFS_PATH_ERR_CROSS_DEVICE) ==
                    -EDGE_LINUX_EXDEV);
    expect_true("path is directory",
                kernel_vfs_path_result(VFS_PATH_ERR_IS_DIRECTORY) ==
                    -EDGE_LINUX_EISDIR);
    expect_true("path not directory",
                kernel_vfs_path_result(VFS_PATH_ERR_NOT_DIRECTORY) ==
                    -EDGE_LINUX_ENOTDIR);
    expect_true("path not found",
                kernel_vfs_path_result(VFS_PATH_ERR_NOT_FOUND) ==
                    -EDGE_LINUX_ENOENT);
    expect_true("path exists",
                kernel_vfs_path_result(VFS_PATH_ERR_EXISTS) ==
                    -EDGE_LINUX_EEXIST);
    expect_true("path invalid",
                kernel_vfs_path_result(VFS_PATH_ERR_INVALID) ==
                    -EDGE_LINUX_EINVAL);
    expect_true("path access",
                kernel_vfs_path_result(VFS_PATH_ERR_ACCESS) ==
                    -EDGE_LINUX_EACCES);
    expect_true("path no space",
                kernel_vfs_path_result(VFS_PATH_ERR_NO_SPACE) ==
                    -EDGE_LINUX_ENOSPC);
    expect_true("path io",
                kernel_vfs_path_result(VFS_PATH_ERR_IO) ==
                    -EDGE_LINUX_EIO);
    expect_true("path unknown",
                kernel_vfs_path_result(-99) == -EDGE_LINUX_EIO);
}

static void test_scratch_policy(void) {
    kernel_vfs_xattr_scratch_t xattr;
    kernel_vfs_mount_scratch_t mount;

    expect_true("xattr scratch",
                kernel_vfs_current_xattr_scratch(&xattr) == 0 &&
                xattr.path == g_paths[0] &&
                xattr.path_capacity == sizeof(g_paths[0]) &&
                xattr.value == g_xattr &&
                xattr.value_capacity == sizeof(g_xattr));
    expect_true("mount scratch",
                kernel_vfs_current_mount_scratch(&mount) == 0 &&
                mount.source == g_paths[0] &&
                mount.target == g_paths[1] &&
                mount.data == g_paths[2] &&
                mount.workspace == g_paths[3] &&
                mount.capacity == sizeof(g_paths[0]));
    g_context_available = 0;
    expect_true("missing context maps to io error",
                kernel_vfs_current_xattr_scratch(&xattr) ==
                    -EDGE_LINUX_EIO);
    g_context_available = 1;
}

static void test_path_policy(void) {
    kernel_vfs_target_t target;
    char output[64];

    g_expected_root = "/sandbox";
    g_expected_base = "/sandbox/work";
    expect_true("resolve current path",
                kernel_vfs_resolve_current_path(
                    "result", output, sizeof(output)) == 0 &&
                strcmp(output, "/sandbox/result") == 0);
    expect_true("empty path",
                kernel_vfs_resolve_path("", 0, &target) ==
                    -EDGE_LINUX_ENOENT);
    g_search_result = -EDGE_LINUX_EACCES;
    expect_true("search error preserved",
                kernel_vfs_resolve_path("result", 0, &target) ==
                    -EDGE_LINUX_EACCES);
    g_search_result = 0;
    g_resolve_result = 0;
    expect_true("follow path",
                kernel_vfs_resolve_path("result", 0, &target) == 0 &&
                target.inode == &target.inode_storage &&
                target.superblock == &g_superblock &&
                strcmp(target.resolved_path, g_resolved) == 0 &&
                g_search_scratch == g_paths[2]);
    g_nofollow_calls = 0;
    expect_true("nofollow path",
                kernel_vfs_resolve_path("result", 1, &target) == 0 &&
                g_nofollow_calls == 1);
    g_resolve_result = -1;
    expect_true("missing target",
                kernel_vfs_resolve_path("result", 0, &target) ==
                    -EDGE_LINUX_ENOENT);
}

static void test_at_path_policy(void) {
    char output[64];

    g_fs_snapshot_result = 0;
    g_fd_resolve_result = 0;
    memset(&g_directory_inode, 0, sizeof(g_directory_inode));
    g_directory_inode.mode = VFS_INODE_DIR;
    g_expected_root = "/sandbox";
    g_expected_base = "/sandbox/work";
    expect_true("resolve at cwd",
                kernel_vfs_resolve_at_path(
                    EDGE_LINUX_AT_FDCWD, "result", output,
                    sizeof(output)) == 0 &&
                strcmp(output, "/sandbox/result") == 0);

    g_expected_base = "/sandbox/base";
    expect_true("resolve at directory",
                kernel_vfs_resolve_at_path(
                    5, "result", output, sizeof(output)) == 0 &&
                strcmp(output, "/sandbox/result") == 0);

    strcpy(g_paths[0], "result");
    expect_true("resolve at aliased input",
                kernel_vfs_resolve_at_path(
                    5, g_paths[0], g_paths[3],
                    sizeof(g_paths[3])) == 0 &&
                strcmp(g_paths[3], "/sandbox/result") == 0);

    g_directory_inode.mode = VFS_INODE_FILE;
    expect_true("resolve at non-directory",
                kernel_vfs_resolve_at_path(
                    5, "result", output, sizeof(output)) ==
                    -EDGE_LINUX_ENOTDIR);
    g_directory_inode.mode = VFS_INODE_DIR;
    g_fd_resolve_result = -EDGE_LINUX_EBADF;
    expect_true("resolve at bad descriptor",
                kernel_vfs_resolve_at_path(
                    5, "result", output, sizeof(output)) ==
                    -EDGE_LINUX_EBADF);
    g_fd_resolve_result = 0;
}

static void test_notification_policy(void) {
    g_notify_count = 0;
    kernel_vfs_notify_create("", 1);
    expect_true("empty notification ignored", g_notify_count == 0u);

    kernel_vfs_notify_create("/directory", 1);
    kernel_vfs_notify_attrib("/source");
    kernel_vfs_notify_link("/source", "/destination");
    expect_true("create directory mask",
                g_notify_count == 4u &&
                g_notify_masks[0] ==
                    (KERNEL_INOTIFY_CREATE | KERNEL_INOTIFY_ISDIR));
    expect_true("attribute mask",
                g_notify_masks[1] == KERNEL_INOTIFY_ATTRIB);
    expect_true("link masks",
                g_notify_masks[2] == KERNEL_INOTIFY_ATTRIB &&
                g_notify_masks[3] == KERNEL_INOTIFY_CREATE);

    g_notify_count = 0;
    kernel_vfs_notify_remove("/directory", 1);
    expect_true("remove directory mask",
                g_notify_count == 1u &&
                g_notify_masks[0] ==
                    (KERNEL_INOTIFY_DELETE |
                     KERNEL_INOTIFY_DELETE_SELF |
                     KERNEL_INOTIFY_ISDIR));
    kernel_vfs_notify_rename("/old", "/new");
    expect_true("rename backend",
                strcmp(g_move_old, "/old") == 0 &&
                strcmp(g_move_new, "/new") == 0);
}

static void test_pivot_and_truncate_policy(void) {
    kernel_vfs_target_t target;
    char rebased[64];

    g_mount_namespace_available = 1;
    g_pivot_result = 0;
    g_rebased_namespace = 0;
    expect_true("pivot root",
                kernel_vfs_pivot_root("/new", "/new/old") == 0 &&
                g_rebased_namespace == g_mount_namespace &&
                strcmp(g_rebased_root, "/new") == 0 &&
                strcmp(g_rebased_old, "/new/old") == 0);
    g_pivot_result = -1;
    expect_true("pivot backend error",
                kernel_vfs_pivot_root("/new", "/new/old") ==
                    -EDGE_LINUX_EINVAL);
    g_mount_namespace_available = 0;
    expect_true("pivot missing task",
                kernel_vfs_pivot_root("/new", "/new/old") ==
                    -EDGE_LINUX_EINVAL);
    g_mount_namespace_available = 1;

    expect_true("pivot path below new root",
                kernel_vfs_rebase_pivot_path(
                    "/new", "/new/old", "/new/usr", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/usr") == 0);
    expect_true("pivot exact new root",
                kernel_vfs_rebase_pivot_path(
                    "/new", "/new/old", "/new", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/") == 0);
    expect_true("pivot old tree path",
                kernel_vfs_rebase_pivot_path(
                    "/new", "/new/old", "/etc", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/old/etc") == 0);
    expect_true("pivot detached old tree path",
                kernel_vfs_rebase_pivot_path(
                    "/new", "/new", "/etc", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/.edgeos-pivot-old/etc") == 0);
    expect_true("pivot fs root follows new root",
                kernel_vfs_rebase_pivot_fs_location(
                    "/new", "/new/old", "/", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/") == 0);
    expect_true("pivot path capacity",
                kernel_vfs_rebase_pivot_path(
                    "/new", "/new/old", "/etc", rebased, 4u) ==
                    -EDGE_LINUX_ENAMETOOLONG);
    expect_true("move path below source",
                kernel_vfs_rebase_move_path(
                    "/newroot", "/", "/newroot/usr", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/usr") == 0);
    expect_true("move exact source",
                kernel_vfs_rebase_move_path(
                    "/newroot", "/", "/newroot", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/") == 0);
    expect_true("move unrelated path",
                kernel_vfs_rebase_move_path(
                    "/newroot", "/", "/run", rebased,
                    sizeof(rebased)) == 0 &&
                strcmp(rebased, "/run") == 0);

    memset(&target, 0, sizeof(target));
    target.superblock = &g_superblock;
    target.inode = &target.inode_storage;
    target.resolved_path = "/file";
    target.inode->size = 31u;
    g_truncate_result = 0;
    g_truncate_commit_new_length = 0;
    g_notify_count = 0;
    expect_true("truncate target",
                kernel_vfs_truncate_target(&target, 19u) == 0 &&
                g_truncate_length == 19u &&
                g_truncate_prepare_old_length == 31u &&
                g_truncate_prepare_new_length == 19u &&
                g_truncate_commit_old_length == 31u &&
                g_truncate_commit_new_length == 19u &&
                g_notify_count == 1u &&
                strcmp(g_notify_paths[0], "/file") == 0 &&
                g_notify_masks[0] == KERNEL_INOTIFY_MODIFY);
    expect_true("truncate explicit path",
                kernel_vfs_truncate_path("/other", &target, 23u) == 0 &&
                g_truncate_prepare_old_length == 19u &&
                g_truncate_commit_new_length == 23u &&
                g_notify_count == 2u &&
                strcmp(g_notify_paths[1], "/other") == 0);
    g_truncate_result = VFS_TRUNCATE_ERR_UNSUPPORTED;
    expect_true("truncate unsupported",
                kernel_vfs_truncate_target(&target, 1u) ==
                    -EDGE_LINUX_EINVAL);
    g_truncate_result = -1;
    expect_true("truncate io error",
                kernel_vfs_truncate_target(&target, 1u) ==
                    -EDGE_LINUX_EIO);
}

int main(void) {
    test_path_error_policy();
    test_scratch_policy();
    test_path_policy();
    test_at_path_policy();
    test_notification_policy();
    test_pivot_and_truncate_policy();
    if (g_failures) return 1;
    puts("vfs_context_unit: PASS");
    return 0;
}
