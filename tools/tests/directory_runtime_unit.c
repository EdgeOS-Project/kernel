/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS shared directory runtime unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/directory_runtime.h"
#include "kernel/linux_errno.h"

static int g_failures;
static uint8_t g_user[256];
static int g_copy_failure;
static int g_special_handled;
static int64_t g_special_result;
static int g_open_result;
static uint32_t g_entry_index;
static uint32_t g_commits;
static uint32_t g_finishes;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static int copy_to_user(void *context, uint64_t destination,
                        const void *source, uint64_t size) {
    (void)context;
    if (g_copy_failure || destination > sizeof(g_user) ||
        size > sizeof(g_user) - destination)
        return -1;
    memcpy(g_user + destination, source, (size_t)size);
    return 0;
}

int64_t arch_vfs_special_getdents64(
    const kernel_vfs_getdents_request_t *request, int *handled) {
    (void)request;
    *handled = g_special_handled;
    return g_special_result;
}

int arch_vfs_directory_open(int32_t descriptor,
                            kernel_vfs_directory_cursor_t *cursor) {
    expect_true("open descriptor", descriptor == 7);
    if (g_open_result < 0) return g_open_result;
    cursor->opaque = &g_entry_index;
    cursor->offset = g_entry_index;
    return 0;
}

int arch_vfs_directory_next(kernel_vfs_directory_cursor_t *cursor,
                            kernel_vfs_directory_entry_t *entry) {
    static const char *names[] = { "alpha", "beta" };
    uint32_t index;

    if (!cursor || cursor->opaque != &g_entry_index) return -EDGE_LINUX_EIO;
    index = (uint32_t)cursor->offset;
    if (index >= 2u) return 0;
    memset(entry, 0, sizeof(*entry));
    entry->inode.ino = 100u + index;
    entry->inode.mode = index ? VFS_INODE_DIR : VFS_INODE_FILE;
    entry->next_offset = index + 1u;
    memcpy(entry->name, names[index], strlen(names[index]) + 1u);
    return 1;
}

void arch_vfs_directory_commit(
    kernel_vfs_directory_cursor_t *cursor,
    const kernel_vfs_directory_entry_t *entry) {
    cursor->offset = entry->next_offset;
    ++g_commits;
}

void arch_vfs_directory_finish(kernel_vfs_directory_cursor_t *cursor) {
    if (!cursor || cursor->opaque != &g_entry_index) return;
    g_entry_index = (uint32_t)cursor->offset;
    ++g_finishes;
}

static kernel_vfs_getdents_request_t request_with_capacity(
    uint64_t capacity) {
    kernel_vfs_getdents_request_t request;
    memset(&request, 0, sizeof(request));
    request.descriptor = 7;
    request.capacity = capacity;
    request.copy_to_user = copy_to_user;
    return request;
}

static void reset_state(void) {
    memset(g_user, 0, sizeof(g_user));
    g_copy_failure = 0;
    g_special_handled = 0;
    g_special_result = 0;
    g_open_result = 0;
    g_entry_index = 0;
    g_commits = 0;
    g_finishes = 0;
}

static void test_records_and_cursor(void) {
    kernel_vfs_getdents_request_t request =
        request_with_capacity(sizeof(g_user));
    struct edge_linux_dirent64 *first;
    struct edge_linux_dirent64 *second;
    int64_t result;

    reset_state();
    result = kernel_vfs_getdents(&request);
    first = (struct edge_linux_dirent64 *)(void *)g_user;
    second = (struct edge_linux_dirent64 *)(void *)
        (g_user + first->d_reclen);
    expect_true("two records",
                result == first->d_reclen + second->d_reclen &&
                first->d_ino == 100u && first->d_off == 1 &&
                first->d_type == 8u &&
                strcmp(first->d_name, "alpha") == 0 &&
                second->d_ino == 101u && second->d_off == 2 &&
                second->d_type == 4u &&
                strcmp(second->d_name, "beta") == 0 &&
                g_commits == 2u && g_finishes == 1u);
}

static void test_native_records_and_dtype_tail(void) {
    kernel_vfs_getdents_request_t request =
        request_with_capacity(sizeof(g_user));
    struct edge_linux_dirent *first;
    struct edge_linux_dirent *second;
    int64_t result;

    reset_state();
    request.format = KERNEL_VFS_DIRENT_NATIVE64;
    result = kernel_vfs_getdents(&request);
    first = (struct edge_linux_dirent *)(void *)g_user;
    second = (struct edge_linux_dirent *)(void *)
        (g_user + first->d_reclen);
    expect_true("native records",
                result == first->d_reclen + second->d_reclen &&
                first->d_ino == 100u && first->d_off == 1 &&
                strcmp(first->d_name, "alpha") == 0 &&
                g_user[first->d_reclen - 1u] == 8u &&
                second->d_ino == 101u && second->d_off == 2 &&
                strcmp(second->d_name, "beta") == 0 &&
                g_user[first->d_reclen + second->d_reclen - 1u] == 4u &&
                g_commits == 2u && g_finishes == 1u);
}

static void test_partial_and_error_policy(void) {
    kernel_vfs_getdents_request_t request = request_with_capacity(32u);
    int64_t result;

    reset_state();
    result = kernel_vfs_getdents(&request);
    expect_true("partial buffer",
                result == 32 && g_entry_index == 1u && g_commits == 1u &&
                g_finishes == 1u);

    reset_state();
    request.capacity = 8u;
    expect_true("record too small",
                kernel_vfs_getdents(&request) ==
                    -EDGE_LINUX_EINVAL &&
                g_commits == 0u && g_finishes == 1u);

    reset_state();
    request.capacity = sizeof(g_user);
    g_copy_failure = 1;
    expect_true("copy fault",
                kernel_vfs_getdents(&request) ==
                    -EDGE_LINUX_EFAULT &&
                g_commits == 0u && g_entry_index == 0u &&
                g_finishes == 1u);

    reset_state();
    g_open_result = -EDGE_LINUX_EBADF;
    expect_true("open error",
                kernel_vfs_getdents(&request) ==
                    -EDGE_LINUX_EBADF && g_finishes == 0u);
}

static void test_special_policy(void) {
    kernel_vfs_getdents_request_t request =
        request_with_capacity(sizeof(g_user));

    reset_state();
    g_special_handled = 1;
    g_special_result = 37;
    expect_true("special result",
                kernel_vfs_getdents(&request) == 37 &&
                g_commits == 0u && g_finishes == 0u);
}

static void test_dtype_policy(void) {
    expect_true("directory dtype",
                kernel_vfs_mode_to_dtype(VFS_INODE_DIR) == 4u);
    expect_true("file dtype",
                kernel_vfs_mode_to_dtype(VFS_INODE_FILE) == 8u);
    expect_true("symlink dtype",
                kernel_vfs_mode_to_dtype(VFS_INODE_LNK) == 10u);
    expect_true("character dtype",
                kernel_vfs_mode_to_dtype(VFS_INODE_CHR) == 2u);
    expect_true("block dtype",
                kernel_vfs_mode_to_dtype(VFS_INODE_BLK) == 6u);
    expect_true("fifo dtype",
                kernel_vfs_mode_to_dtype(VFS_INODE_FIFO) == 1u);
    expect_true("socket dtype",
                kernel_vfs_mode_to_dtype(VFS_INODE_SOCK) == 12u);
    expect_true("unknown dtype",
                kernel_vfs_mode_to_dtype(0u) == 0u);
}

static int test_readdir(vfs_superblock_t *superblock, vfs_inode_t *directory,
                        uint32_t index, char *name, vfs_inode_t *inode) {
    (void)superblock;
    (void)directory;
    (void)index;
    (void)name;
    (void)inode;
    return -1;
}

static int test_readdir_dirent(vfs_superblock_t *superblock,
                               vfs_inode_t *directory, uint32_t index,
                               char *name, uint32_t *inode_number,
                               uint16_t *mode) {
    (void)superblock;
    (void)directory;
    if (index != 3u) return -1;
    strcpy(name, "fast");
    *inode_number = 77u;
    *mode = VFS_INODE_LNK;
    return 0;
}

static void test_fast_dirent_policy(void) {
    filesystem_ops_t operations;
    vfs_superblock_t superblock;
    vfs_inode_t directory;
    vfs_inode_t inode;
    char name[VFS_NAME_MAX];

    memset(&operations, 0, sizeof(operations));
    operations.readdir = test_readdir;
    operations.readdir_dirent = test_readdir_dirent;
    memset(&superblock, 0, sizeof(superblock));
    superblock.ops = &operations;
    memset(&directory, 0, sizeof(directory));
    memset(&inode, 0xff, sizeof(inode));
    expect_true("fast dirent selected",
                vfs_readdir_dirent(
                    &superblock, &directory, 3u, name, &inode) == 0 &&
                strcmp(name, "fast") == 0 && inode.ino == 77u &&
                inode.mode == VFS_INODE_LNK && inode.size == 0u);
}

static void test_device_directory_backend_policy(void) {
    filesystem_ops_t operations;
    vfs_superblock_t superblock;

    memset(&operations, 0, sizeof(operations));
    operations.readdir = test_readdir;
    memset(&superblock, 0, sizeof(superblock));
    superblock.ops = &operations;

    strcpy(superblock.mountpoint, "/dev");
    expect_true("mounted dev root uses backend",
                kernel_vfs_device_directory_uses_backing_readdir(
                    "/dev", &superblock));
    expect_true("mounted dev child uses backend",
                kernel_vfs_device_directory_uses_backing_readdir(
                    "/dev/input", &superblock));

    strcpy(superblock.mountpoint, "/dev/pts");
    expect_true("nested device mount uses backend",
                kernel_vfs_device_directory_uses_backing_readdir(
                    "/dev/pts", &superblock));
    expect_true("unrelated device mount does not own path",
                !kernel_vfs_device_directory_uses_backing_readdir(
                    "/dev/input", &superblock));

    strcpy(superblock.mountpoint, "/");
    expect_true("root filesystem keeps device fallback",
                !kernel_vfs_device_directory_uses_backing_readdir(
                    "/dev", &superblock));
    strcpy(superblock.mountpoint, "/device");
    expect_true("component boundary",
                !kernel_vfs_device_directory_uses_backing_readdir(
                    "/dev", &superblock));
    superblock.ops = 0;
    expect_true("missing readdir keeps fallback",
                !kernel_vfs_device_directory_uses_backing_readdir(
                    "/dev", &superblock));
}

int main(void) {
    test_records_and_cursor();
    test_native_records_and_dtype_tail();
    test_partial_and_error_policy();
    test_special_policy();
    test_dtype_policy();
    test_fast_dirent_policy();
    test_device_directory_backend_policy();
    if (g_failures) return 1;
    puts("directory_runtime_unit: PASS");
    return 0;
}
