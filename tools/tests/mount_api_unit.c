/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent descriptor mount API unit test. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/linux_mount.h"
#include "kernel/linux_errno.h"
#include "kernel/mount_api.h"

static int mount_calls;
static int setattr_calls;
static int reentry_object;
static int reentry_observed;
static int resolved_bind_calls;
static uint64_t captured_flags;
static char captured_source[4096];
static char captured_target[4096];
static char captured_filesystem[64];
static char captured_options[4096];

static vfs_superblock_t detached_tmpfs;
static int detached_creations;
static int resolved_lookup_calls;

static int resolved_lookup(vfs_superblock_t *superblock,
                           vfs_inode_t *directory, const char *name,
                           vfs_inode_t *out) {
    if (superblock != &detached_tmpfs || directory->ino != 41u ||
        strcmp(name, "systemd") != 0)
        return -1;
    ++resolved_lookup_calls;
    memset(out, 0, sizeof(*out));
    out->ino = 42u;
    out->mode = VFS_INODE_DIR | 0755u;
    return 0;
}

int tmpfs_create_detached(const char *device, const char *options,
                           vfs_superblock_t **superblock_out) {
    (void)device;
    ++detached_creations;
    memset(&detached_tmpfs, 0, sizeof(detached_tmpfs));
    detached_tmpfs.root.mode = VFS_INODE_DIR | 0700u;
    snprintf(detached_tmpfs.fs_name, sizeof(detached_tmpfs.fs_name), "tmpfs");
    snprintf(captured_filesystem, sizeof(captured_filesystem), "tmpfs");
    snprintf(captured_options, sizeof(captured_options), "%s", options ? options : "");
    *superblock_out = &detached_tmpfs;
    return 0;
}

int tmpfs_reconfigure_detached(vfs_superblock_t *superblock, const char *options) {
    (void)options;
    return superblock == &detached_tmpfs ? 0 : -EDGE_LINUX_EINVAL;
}

int vfs_resolve(const char *path, vfs_inode_t *inode, vfs_superblock_t **superblock,
                 vfs_inode_t *parent, char *name) {
    (void)path; (void)superblock; (void)parent; (void)name;
    memset(inode, 0, sizeof(*inode));
    inode->mode = VFS_INODE_DIR | 0755u;
    return 0;
}

void *arch_vm_alloc_page(void) {
    return calloc(1u, 4096u);
}

void arch_vm_free_page(void *page) {
    free(page);
}

vfs_superblock_t *vfs_superblock_acquire(vfs_superblock_t *superblock) {
    return superblock;
}

void vfs_superblock_release(vfs_superblock_t *superblock) {
    (void)superblock;
}

int vfs_bind_mount_resolved(const char *source,
                            vfs_superblock_t *source_superblock,
                            const vfs_inode_t *source_inode,
                            uint32_t source_propagation,
                            const char *target,
                            const vfs_inode_t *target_inode,
                            int recursive) {
    (void)source;
    (void)source_superblock;
    (void)source_inode;
    (void)source_propagation;
    (void)target;
    (void)target_inode;
    (void)recursive;
    ++resolved_bind_calls;
    captured_flags = source_superblock->mount_flags;
    return 0;
}

int64_t kernel_linux_mount(char *source, char *target,
                           const char *filesystem, uint64_t flags,
                           const char *data, char *workspace,
                           uint32_t workspace_capacity) {
    (void)workspace;
    (void)workspace_capacity;
    ++mount_calls;
    captured_flags = flags;
    snprintf(captured_source, sizeof(captured_source), "%s",
             source ? source : "");
    snprintf(captured_target, sizeof(captured_target), "%s",
             target ? target : "");
    snprintf(captured_filesystem, sizeof(captured_filesystem), "%s",
             filesystem ? filesystem : "");
    snprintf(captured_options, sizeof(captured_options), "%s",
             data ? data : "");
    if (reentry_object > 0 &&
        kernel_mount_api_retain(reentry_object) == 0) {
        reentry_observed = 1;
        kernel_mount_api_release(reentry_object);
    }
    return 0;
}

int64_t kernel_linux_mount_setattr(const char *target, uint64_t attr_set,
                                   uint64_t attr_clear,
                                   uint64_t propagation, int recursive) {
    (void)target;
    (void)attr_set;
    (void)attr_clear;
    (void)propagation;
    (void)recursive;
    ++setattr_calls;
    return 0;
}

static int check(int condition, const char *name) {
    if (condition) return 0;
    fprintf(stderr, "FAIL: %s\n", name);
    return 1;
}

int main(void) {
    char workspace[4096];
    char target[] = "/mnt/new";
    int context;
    int mount;
    int picked;
    int picked_tree;
    int resolved_tree;
    int tree;
    vfs_inode_t resolved_source_inode = {.mode = VFS_INODE_FILE | 0600u};
    vfs_inode_t resolved_target_inode = {.mode = VFS_INODE_FILE | 0600u};
    filesystem_ops_t resolved_ops;
    int failures = 0;

    failures += check(
        kernel_mount_api_filesystem_supported("tmpfs"),
        "tmpfs registration");
    failures += check(
        kernel_mount_api_filesystem_supported("squashfs"),
        "squashfs registration");
    failures += check(
        kernel_mount_api_filesystem_supported("erofs"),
        "erofs registration");
    failures += check(
        kernel_mount_api_filesystem_supported("xfs"),
        "xfs registration");
    failures += check(
        kernel_mount_api_filesystem_supported("btrfs"),
        "btrfs registration");
    failures += check(
        !kernel_mount_api_filesystem_supported("missingfs"),
        "unknown filesystem rejection");

    context = kernel_mount_api_context_create("tmpfs");
    failures += check(context > 0, "context allocation");
    failures += check(
        kernel_mount_api_context_configure(
            context, KERNEL_MOUNT_API_SET_STRING,
            "size", "16m", 0, workspace, sizeof(workspace)) == 0,
        "string configuration");
    failures += check(
        kernel_mount_api_context_configure(
            context, KERNEL_MOUNT_API_SET_FLAG,
            "nosuid", 0, 0, workspace, sizeof(workspace)) ==
            -EDGE_LINUX_EINVAL,
        "VFS flag rejection");
    failures += check(
        kernel_mount_api_context_configure(
            context, KERNEL_MOUNT_API_CREATE,
            0, 0, 0, workspace, sizeof(workspace)) == 0,
        "context creation command");
    mount = kernel_mount_api_context_mount(
        context, EDGE_LINUX_MOUNT_ATTR_NOEXEC);
    failures += check(mount > 0, "detached mount allocation");
    {
        vfs_superblock_t *root_superblock = 0;
        vfs_inode_t root_inode;
        failures += check(detached_creations == 1 && mount_calls == 0,
                          "filesystem created before namespace attachment");
        failures += check(kernel_mount_api_root(mount, &root_superblock, &root_inode) == 0 &&
                          root_superblock == &detached_tmpfs &&
                          (root_inode.mode & 0xf000u) == VFS_INODE_DIR,
                          "detached descriptor retains a real directory root");
    }
    failures += check(
        kernel_mount_api_mount_attach(
            mount, target, workspace, sizeof(workspace)) == 0,
        "detached mount attachment");
    failures += check(mount_calls == 0 && resolved_bind_calls == 1,
                      "attachment reuses the detached filesystem");
    failures += check(strcmp(captured_filesystem, "tmpfs") == 0,
                      "new mount filesystem");
    failures += check(strcmp(captured_options, "size=16m") == 0,
                      "new mount options");
    failures += check(
        (captured_flags & (EDGE_LINUX_MS_RDONLY |
                           EDGE_LINUX_MS_NOEXEC)) ==
            EDGE_LINUX_MS_NOEXEC,
        "new mount attributes");

    resolved_bind_calls = 0;
    setattr_calls = 0;
    tree = kernel_mount_api_tree_open("/mnt/source", 1, 1);
    failures += check(tree > 0, "tree clone allocation");
    reentry_object = tree;
    failures += check(
        kernel_mount_api_mount_setattr(
            tree, EDGE_LINUX_MOUNT_ATTR_NOSUID, 0, 0, 1) == 0,
        "tree clone attributes");
    failures += check(
        kernel_mount_api_mount_attach(
            tree, target, workspace, sizeof(workspace)) == 0,
        "tree clone attachment");
    failures += check(
        (captured_flags & (EDGE_LINUX_MS_BIND | EDGE_LINUX_MS_REC)) ==
            (EDGE_LINUX_MS_BIND | EDGE_LINUX_MS_REC),
        "recursive bind flags");
    failures += check(setattr_calls == 1, "tree attribute application");
    failures += check(reentry_observed, "attachment lock boundary");
    reentry_object = 0;

    memset(&resolved_ops, 0, sizeof(resolved_ops));
    resolved_ops.lookup = resolved_lookup;
    detached_tmpfs.ops = &resolved_ops;
    resolved_source_inode.ino = 41u;
    resolved_source_inode.mode = VFS_INODE_DIR | 0755u;
    resolved_tree = kernel_mount_api_tree_open_resolved(
        "/run", &detached_tmpfs,
        &resolved_source_inode, VFS_MOUNT_PRIVATE, 1, 0);
    failures += check(resolved_tree > 0, "resolved file tree allocation");
    {
        char resolved_path[VFS_PATH_MAX];
        vfs_superblock_t *child_superblock = 0;
        vfs_inode_t child_inode;
        failures += check(
            kernel_mount_api_resolve_relative(
                resolved_tree, "systemd", 1, resolved_path,
                sizeof(resolved_path), &child_superblock,
                &child_inode) == 0 &&
            child_superblock == &detached_tmpfs &&
            child_inode.ino == 42u && resolved_lookup_calls == 1 &&
            strcmp(resolved_path, "/run/systemd") == 0,
            "resolved mount descriptor child lookup");
    }
    failures += check(
        kernel_mount_api_mount_attach_resolved(
            resolved_tree, target, &resolved_target_inode,
            workspace, sizeof(workspace)) == 0,
        "resolved file tree attachment");
    failures += check(resolved_bind_calls == 1,
                      "resolved file bind without path lookup");

    picked_tree = kernel_mount_api_tree_open("/mnt/source", 0, 0);
    failures += check(picked_tree > 0, "tree pick source allocation");
    picked = kernel_mount_api_context_pick_object(picked_tree);
    failures += check(picked > 0, "descriptor context pick");
    failures += check(
        kernel_mount_api_context_configure(
            picked, KERNEL_MOUNT_API_SET_FLAG,
            "noatime", 0, 0, workspace, sizeof(workspace)) ==
            -EDGE_LINUX_EINVAL,
        "picked VFS flag rejection");
    failures += check(
        kernel_mount_api_context_configure(
            picked, KERNEL_MOUNT_API_RECONFIGURE,
            0, 0, 0, workspace, sizeof(workspace)) == 0,
        "picked context reconfigure");
    failures += check(strcmp(captured_target, "/mnt/source") == 0,
                      "picked descriptor path");
    failures += check(
        (captured_flags & (EDGE_LINUX_MS_REMOUNT |
                           EDGE_LINUX_MS_NOATIME)) ==
            EDGE_LINUX_MS_REMOUNT,
        "picked descriptor remount flags");

    failures += check(kernel_mount_api_retain(tree) == 0,
                      "object retain");
    kernel_mount_api_release(tree);
    kernel_mount_api_release(tree);
    kernel_mount_api_release(picked);
    kernel_mount_api_release(picked_tree);
    kernel_mount_api_release(resolved_tree);
    kernel_mount_api_release(mount);
    kernel_mount_api_release(context);
    failures += check(kernel_mount_api_retain(tree) < 0,
                      "object final release");

    if (!failures) puts("mount_api_unit: PASS");
    return failures ? 1 : 0;
}
