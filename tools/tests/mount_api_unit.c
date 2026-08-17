/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-independent descriptor mount API unit test. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/linux_mount.h"
#include "kernel/mount_api.h"

static int mount_calls;
static int setattr_calls;
static uint64_t captured_flags;
static char captured_source[4096];
static char captured_target[4096];
static char captured_filesystem[64];
static char captured_options[4096];

void *arch_vm_alloc_page(void) {
    return calloc(1u, 4096u);
}

void arch_vm_free_page(void *page) {
    free(page);
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
    int tree;
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
            "ro", 0, 0, workspace, sizeof(workspace)) == 0,
        "flag configuration");
    failures += check(
        kernel_mount_api_context_configure(
            context, KERNEL_MOUNT_API_CREATE,
            0, 0, 0, workspace, sizeof(workspace)) == 0,
        "context creation command");
    mount = kernel_mount_api_context_mount(
        context, EDGE_LINUX_MOUNT_ATTR_NOEXEC);
    failures += check(mount > 0, "detached mount allocation");
    failures += check(
        kernel_mount_api_mount_attach(
            mount, target, workspace, sizeof(workspace)) == 0,
        "detached mount attachment");
    failures += check(mount_calls == 1, "new mount call count");
    failures += check(strcmp(captured_filesystem, "tmpfs") == 0,
                      "new mount filesystem");
    failures += check(strcmp(captured_options, "size=16m") == 0,
                      "new mount options");
    failures += check(
        (captured_flags & (EDGE_LINUX_MS_RDONLY |
                           EDGE_LINUX_MS_NOEXEC)) ==
            (EDGE_LINUX_MS_RDONLY | EDGE_LINUX_MS_NOEXEC),
        "new mount attributes");

    tree = kernel_mount_api_tree_open("/mnt/source", 1, 1);
    failures += check(tree > 0, "tree clone allocation");
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

    picked_tree = kernel_mount_api_tree_open("/mnt/source", 0, 0);
    failures += check(picked_tree > 0, "tree pick source allocation");
    picked = kernel_mount_api_context_pick_object(picked_tree);
    failures += check(picked > 0, "descriptor context pick");
    failures += check(
        kernel_mount_api_context_configure(
            picked, KERNEL_MOUNT_API_SET_FLAG,
            "noatime", 0, 0, workspace, sizeof(workspace)) == 0,
        "picked context flag");
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
            (EDGE_LINUX_MS_REMOUNT | EDGE_LINUX_MS_NOATIME),
        "picked descriptor remount flags");

    failures += check(kernel_mount_api_retain(tree) == 0,
                      "object retain");
    kernel_mount_api_release(tree);
    kernel_mount_api_release(tree);
    kernel_mount_api_release(picked);
    kernel_mount_api_release(picked_tree);
    kernel_mount_api_release(mount);
    kernel_mount_api_release(context);
    failures += check(kernel_mount_api_retain(tree) < 0,
                      "object final release");

    if (!failures) puts("mount_api_unit: PASS");
    return failures ? 1 : 0;
}
