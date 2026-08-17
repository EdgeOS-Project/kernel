/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent VFS descriptor policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/linux_errno.h"
#include "kernel/linux_seek.h"
#include "kernel/vfs_runtime.h"

static int g_failures;
static int g_resolve_calls;
static int g_install_calls;
static int g_metadata_calls;
static int g_sync_calls;
static int g_describe_calls;
static int g_fallocate_calls;
static int g_fallocate_inode_calls;
static int g_fallocate_prepare_calls;
static int g_fallocate_commit_calls;
static int g_fallocate_result;
static int g_truncate_calls;
static int g_seek_calls;
static int g_target_was_zero;
static int g_description_was_zero;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static int bytes_are_zero(const void *value, uint32_t size) {
    const uint8_t *bytes = value;
    for (uint32_t index = 0; index < size; ++index)
        if (bytes[index]) return 0;
    return 1;
}

int arch_vfs_resolve_fd(int32_t descriptor, kernel_vfs_target_t *target) {
    ++g_resolve_calls;
    g_target_was_zero = bytes_are_zero(target, sizeof(*target));
    target->path_only = descriptor;
    return 11;
}

int arch_vfs_install_inode_descriptor(
    vfs_superblock_t *superblock, const vfs_inode_t *inode,
    uint32_t status_flags, uint32_t descriptor_flags,
    int linkable_zero_link_inode) {
    ++g_install_calls;
    return superblock && inode && status_flags == 1u &&
           descriptor_flags == 2u && linkable_zero_link_inode == 3 ?
           12 : -1;
}

int arch_vfs_metadata_fd(
    int32_t descriptor, kernel_file_metadata_t *metadata) {
    (void)metadata;
    ++g_metadata_calls;
    return descriptor == 4 ? 13 : -1;
}

int arch_vfs_sync_descriptor(
    int32_t descriptor, kernel_vfs_sync_operation_t operation) {
    ++g_sync_calls;
    return descriptor == 5 && operation == KERNEL_VFS_SYNC_RANGE ? 14 : -1;
}

int arch_vfs_describe_descriptor(
    int32_t descriptor, kernel_vfs_descriptor_t *description) {
    ++g_describe_calls;
    g_description_was_zero =
        bytes_are_zero(description, sizeof(*description));
    description->identity = (uint64_t)descriptor;
    return 15;
}

int arch_vfs_fallocate_descriptor(
    int32_t descriptor, uint32_t mode, uint64_t offset, uint64_t length) {
    ++g_fallocate_calls;
    return descriptor == 7 && mode == 8u && offset == 9u && length == 10u ?
           16 : -1;
}

int arch_vfs_fallocate_prepare(
    vfs_superblock_t *superblock, const vfs_inode_t *inode, uint32_t mode,
    uint64_t offset, uint64_t length) {
    ++g_fallocate_prepare_calls;
    return superblock && inode && mode == 18u && offset == 19u &&
           length == 20u ? 0 : -1;
}

void arch_vfs_fallocate_commit(
    vfs_superblock_t *superblock, const vfs_inode_t *inode, uint32_t mode,
    uint64_t offset, uint64_t length) {
    if (superblock && inode && mode == 18u && offset == 19u && length == 20u)
        ++g_fallocate_commit_calls;
}

int vfs_fallocate_inode(vfs_superblock_t *superblock, vfs_inode_t *inode,
                        uint32_t mode, uint64_t offset, uint64_t length) {
    ++g_fallocate_inode_calls;
    if (!superblock || !inode || mode != 18u || offset != 19u ||
        length != 20u)
        return -1;
    return g_fallocate_result;
}

int arch_vfs_truncate_descriptor(int32_t descriptor, uint32_t length) {
    ++g_truncate_calls;
    return descriptor == 11 && length == 12u ? 17 : -1;
}

edge_linux_seek_result_t arch_vfs_seek_descriptor(
    int32_t descriptor, int64_t displacement, uint32_t whence,
    uint64_t *result) {
    ++g_seek_calls;
    *result = 18u;
    return descriptor == 13 && displacement == -14 &&
           whence == EDGE_LINUX_SEEK_END ?
           EDGE_LINUX_SEEK_OK : EDGE_LINUX_SEEK_INTERNAL;
}

static void test_descriptor_contracts(void) {
    kernel_vfs_target_t target;
    kernel_file_metadata_t metadata;
    kernel_vfs_descriptor_t description;
    vfs_superblock_t superblock;
    vfs_inode_t inode;

    memset(&target, 0xa5, sizeof(target));
    expect_true("resolve null output",
                kernel_vfs_resolve_fd(1, 0) == -EDGE_LINUX_EBADF &&
                g_resolve_calls == 0);
    expect_true("resolve negative descriptor",
                kernel_vfs_resolve_fd(-1, &target) == -EDGE_LINUX_EBADF &&
                g_resolve_calls == 0);
    expect_true("resolve dispatch and initialize",
                kernel_vfs_resolve_fd(2, &target) == 11 &&
                g_resolve_calls == 1 && g_target_was_zero &&
                target.path_only == 2);

    memset(&superblock, 0, sizeof(superblock));
    memset(&inode, 0, sizeof(inode));
    expect_true("install null superblock",
                kernel_vfs_install_inode_descriptor(
                    0, &inode, 1, 2, 3) == -EDGE_LINUX_EINVAL &&
                g_install_calls == 0);
    expect_true("install null inode",
                kernel_vfs_install_inode_descriptor(
                    &superblock, 0, 1, 2, 3) == -EDGE_LINUX_EINVAL &&
                g_install_calls == 0);
    expect_true("install dispatch",
                kernel_vfs_install_inode_descriptor(
                    &superblock, &inode, 1, 2, 3) == 12 &&
                g_install_calls == 1);

    expect_true("metadata null output",
                kernel_vfs_metadata_fd(4, 0) == -EDGE_LINUX_EBADF &&
                g_metadata_calls == 0);
    expect_true("metadata negative descriptor",
                kernel_vfs_metadata_fd(-1, &metadata) ==
                    -EDGE_LINUX_EBADF &&
                g_metadata_calls == 0);
    expect_true("metadata dispatch",
                kernel_vfs_metadata_fd(4, &metadata) == 13 &&
                g_metadata_calls == 1);

    expect_true("sync negative descriptor",
                kernel_vfs_sync_descriptor(
                    -1, KERNEL_VFS_SYNC_FILE) == -EDGE_LINUX_EBADF &&
                g_sync_calls == 0);
    expect_true("sync invalid operation",
                kernel_vfs_sync_descriptor(
                    5, (kernel_vfs_sync_operation_t)0) ==
                    -EDGE_LINUX_EINVAL &&
                g_sync_calls == 0);
    expect_true("sync dispatch",
                kernel_vfs_sync_descriptor(
                    5, KERNEL_VFS_SYNC_RANGE) == 14 &&
                g_sync_calls == 1);

    memset(&description, 0xa5, sizeof(description));
    expect_true("describe null output",
                kernel_vfs_describe_descriptor(6, 0) ==
                    -EDGE_LINUX_EBADF &&
                g_describe_calls == 0);
    expect_true("describe negative descriptor",
                kernel_vfs_describe_descriptor(-1, &description) ==
                    -EDGE_LINUX_EBADF &&
                g_describe_calls == 0);
    expect_true("describe dispatch and initialize",
                kernel_vfs_describe_descriptor(6, &description) == 15 &&
                g_describe_calls == 1 && g_description_was_zero &&
                description.identity == 6u);
}

static void test_mutation_and_seek_contracts(void) {
    vfs_superblock_t superblock;
    vfs_inode_t inode;
    uint64_t result = 0;

    memset(&superblock, 0, sizeof(superblock));
    memset(&inode, 0, sizeof(inode));

    expect_true("fallocate negative descriptor",
                kernel_vfs_fallocate_descriptor(-1, 8, 9, 10) ==
                    -EDGE_LINUX_EBADF &&
                g_fallocate_calls == 0);
    expect_true("fallocate dispatch",
                kernel_vfs_fallocate_descriptor(7, 8, 9, 10) == 16 &&
                g_fallocate_calls == 1);
    expect_true("fallocate inode rejects missing target",
                kernel_vfs_fallocate_inode_transaction(
                    0, &inode, 18, 19, 20) == -EDGE_LINUX_EINVAL &&
                g_fallocate_prepare_calls == 0);
    g_fallocate_result = 0;
    expect_true("fallocate inode shared transaction",
                kernel_vfs_fallocate_inode_transaction(
                    &superblock, &inode, 18, 19, 20) == 0 &&
                g_fallocate_prepare_calls == 1 &&
                g_fallocate_inode_calls == 1 &&
                g_fallocate_commit_calls == 1);
    g_fallocate_result = VFS_FALLOCATE_ERR_NOSPC;
    expect_true("fallocate inode shared error translation",
                kernel_vfs_fallocate_inode_transaction(
                    &superblock, &inode, 18, 19, 20) ==
                    -EDGE_LINUX_ENOSPC &&
                g_fallocate_prepare_calls == 2 &&
                g_fallocate_inode_calls == 2 &&
                g_fallocate_commit_calls == 1);

    expect_true("truncate negative descriptor",
                kernel_vfs_truncate_descriptor(-1, 12) ==
                    -EDGE_LINUX_EBADF &&
                g_truncate_calls == 0);
    expect_true("truncate dispatch",
                kernel_vfs_truncate_descriptor(11, 12) == 17 &&
                g_truncate_calls == 1);

    expect_true("seek null output",
                kernel_vfs_seek_descriptor(
                    13, -14, EDGE_LINUX_SEEK_END, 0) ==
                    EDGE_LINUX_SEEK_BAD_DESCRIPTOR &&
                g_seek_calls == 0);
    expect_true("seek negative descriptor",
                kernel_vfs_seek_descriptor(
                    -1, -14, EDGE_LINUX_SEEK_END, &result) ==
                    EDGE_LINUX_SEEK_BAD_DESCRIPTOR &&
                g_seek_calls == 0);
    expect_true("seek dispatch",
                kernel_vfs_seek_descriptor(
                    13, -14, EDGE_LINUX_SEEK_END, &result) ==
                    EDGE_LINUX_SEEK_OK &&
                result == 18u && g_seek_calls == 1);
}

int main(void) {
    test_descriptor_contracts();
    test_mutation_and_seek_contracts();
    if (g_failures) return 1;
    puts("vfs_descriptor_policy_unit: PASS");
    return 0;
}
