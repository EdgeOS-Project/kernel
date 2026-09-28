/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared VFS metadata policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_syscall.h"
#include "kernel/namespaces.h"
#include "kernel/process_runtime.h"
#include "kernel/vfs_runtime.h"

static int g_failures;
static char g_paths[4][128];
static int g_resolve_at_result;
static int g_search_result;
static int g_resolve_result;
static int g_magic_handled;
static int g_special_handled;
static int g_prepare_calls;
static int g_magic_calls;
static int g_metadata_calls;
static int g_readlink_result;
static int g_last_nofollow;
static vfs_inode_t g_inode;
static vfs_superblock_t g_superblock;

const char *edge_namespace_name(edge_namespace_kind_t kind) {
    (void)kind;
    return 0;
}

int arch_proc_namespace_inode(int32_t pid, uint32_t kind,
                              uint64_t *inode_out) {
    (void)pid;
    (void)kind;
    (void)inode_out;
    return -1;
}

void kernel_file_metadata_initialize(kernel_file_metadata_t *metadata,
                                     uint16_t mode, uint64_t size) {
    memset(metadata, 0, sizeof(*metadata));
    metadata->mode = mode;
    metadata->size = size;
    metadata->blocks = (size + 511u) / 512u;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
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

int kernel_vfs_resolve_at_path(int32_t directory, const char *path,
                               char *output, uint32_t capacity) {
    (void)directory;
    (void)path;
    if (g_resolve_at_result < 0) return g_resolve_at_result;
    if (capacity < sizeof("/resolved")) return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(output, "/resolved", sizeof("/resolved"));
    return 0;
}

int vfs_path_search_check(const char *path, char *scratch,
                          uint32_t capacity, int include_final) {
    (void)scratch;
    (void)capacity;
    expect_true("search path", strcmp(path, "/resolved") == 0);
    expect_true("search final excluded", include_final == 0);
    return g_search_result;
}

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    if (!identity) return -1;
    memset(identity, 0, sizeof(*identity));
    identity->global_tgid = 7;
    return 0;
}

int edge_linux_current_magic_fd_metadata(
    const char *path, const kernel_linux_identity_t *identity,
    kernel_file_metadata_t *metadata, int *handled) {
    ++g_magic_calls;
    expect_true("magic path", strcmp(path, "/resolved") == 0);
    expect_true("magic identity", identity && identity->global_tgid == 7);
    *handled = g_magic_handled;
    if (*handled) metadata->inode = 0x55u;
    return 0;
}

int arch_vfs_metadata_path_prepare(const char *path, int nofollow,
                                   char *output, uint32_t capacity) {
    ++g_prepare_calls;
    g_last_nofollow = nofollow;
    if (capacity < sizeof("/prepared")) return -EDGE_LINUX_ENAMETOOLONG;
    expect_true("prepare path", strcmp(path, "/resolved") == 0);
    memcpy(output, "/prepared", sizeof("/prepared"));
    return 0;
}

int vfs_resolve(const char *path, vfs_inode_t *inode,
                vfs_superblock_t **superblock, vfs_inode_t *parent,
                char *leaf) {
    (void)parent;
    (void)leaf;
    expect_true("resolve path", strcmp(path, "/prepared") == 0);
    if (g_resolve_result < 0) return g_resolve_result;
    *inode = g_inode;
    *superblock = &g_superblock;
    return 0;
}

int vfs_resolve_nofollow(const char *path, vfs_inode_t *inode,
                         vfs_superblock_t **superblock) {
    return vfs_resolve(path, inode, superblock, 0, 0);
}

int arch_vfs_special_path_metadata(
    const char *path, vfs_superblock_t *superblock,
    const vfs_inode_t *inode, kernel_file_metadata_t *metadata,
    int *handled) {
    (void)superblock;
    expect_true("special path", strcmp(path, "/prepared") == 0);
    if (g_resolve_result < 0)
        expect_true("special missing inode", inode == 0);
    *handled = g_special_handled;
    if (*handled) metadata->inode = 0x66u;
    return 0;
}

void kernel_file_metadata_from_inode(vfs_superblock_t *superblock,
                                     const vfs_inode_t *inode,
                                     kernel_file_metadata_t *metadata) {
    ++g_metadata_calls;
    expect_true("metadata superblock", superblock == &g_superblock);
    metadata->mode = inode->mode;
    metadata->inode = inode->ino;
    metadata->size = inode->size;
    metadata->blocks = (inode->size + 511u) / 512u;
}

int arch_vfs_readlink_path(const char *path, char *target,
                           uint32_t capacity) {
    (void)target;
    (void)capacity;
    expect_true("readlink path", strcmp(path, "/prepared") == 0);
    return g_readlink_result;
}

static void reset_state(void) {
    memset(g_paths, 0, sizeof(g_paths));
    memset(&g_inode, 0, sizeof(g_inode));
    memset(&g_superblock, 0, sizeof(g_superblock));
    g_resolve_at_result = 0;
    g_search_result = 0;
    g_resolve_result = 0;
    g_magic_handled = 0;
    g_special_handled = 0;
    g_prepare_calls = 0;
    g_magic_calls = 0;
    g_metadata_calls = 0;
    g_readlink_result = -EDGE_LINUX_EINVAL;
    g_last_nofollow = -1;
    g_inode.mode = VFS_INODE_FILE | 0644u;
    g_inode.ino = 42u;
    g_inode.size = 17u;
}

static void test_validation_and_errors(void) {
    kernel_file_metadata_t metadata;

    reset_state();
    expect_true("null path",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, 0, 0, &metadata) ==
                    -EDGE_LINUX_EFAULT);
    expect_true("empty path",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, "", 0, &metadata) ==
                    -EDGE_LINUX_ENOENT);
    g_resolve_at_result = -EDGE_LINUX_EBADF;
    expect_true("at error preserved",
                kernel_vfs_metadata_at(9, "file", 0, &metadata) ==
                    -EDGE_LINUX_EBADF);
    g_resolve_at_result = 0;
    g_search_result = -EDGE_LINUX_EACCES;
    expect_true("search error preserved",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, "file", 0, &metadata) ==
                    -EDGE_LINUX_EACCES);
}

static void test_magic_and_special_paths(void) {
    kernel_file_metadata_t metadata;

    reset_state();
    memset(&metadata, 0, sizeof(metadata));
    g_magic_handled = 1;
    expect_true("magic descriptor metadata",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, "magic", 0, &metadata) == 0 &&
                metadata.inode == 0x55u && g_prepare_calls == 0);

    reset_state();
    memset(&metadata, 0, sizeof(metadata));
    g_resolve_result = -1;
    g_special_handled = 1;
    expect_true("special missing path metadata",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, "device", 1, &metadata) == 0 &&
                metadata.inode == 0x66u && g_magic_calls == 0 &&
                g_last_nofollow == 1);

    reset_state();
    g_resolve_result = -1;
    expect_true("missing path",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, "missing", 0, &metadata) ==
                    -EDGE_LINUX_ENOENT);
}

static void test_inode_and_symlink_metadata(void) {
    kernel_file_metadata_t metadata;

    reset_state();
    memset(&metadata, 0, sizeof(metadata));
    expect_true("regular inode metadata",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, "file", 0, &metadata) == 0 &&
                metadata.inode == 42u && metadata.size == 17u &&
                g_metadata_calls == 1);

    reset_state();
    memset(&metadata, 0, sizeof(metadata));
    g_inode.mode = VFS_INODE_LNK | 0777u;
    g_inode.size = 0;
    g_readlink_result = 9;
    expect_true("nofollow symlink size",
                kernel_vfs_metadata_at(
                    EDGE_LINUX_AT_FDCWD, "link", 1, &metadata) == 0 &&
                metadata.size == 9u && metadata.blocks == 1u &&
                g_magic_calls == 0 && g_last_nofollow == 1);
}

int main(void) {
    test_validation_and_errors();
    test_magic_and_special_paths();
    test_inode_and_symlink_metadata();
    if (g_failures) return 1;
    puts("vfs_metadata_unit: PASS");
    return 0;
}
