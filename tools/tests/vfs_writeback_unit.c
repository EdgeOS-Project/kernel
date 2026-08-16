/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Host-side tests for architecture-independent VFS durability policy.
 */

#include <stdint.h>

#include "vfs/mount_namespace.h"
#include "vfs/vfs.h"

extern int printf(const char *format, ...);

#define CHECK(condition)                                                    \
    do {                                                                    \
        if (!(condition)) {                                                 \
            printf("vfs_writeback_unit: %s:%d: %s\n",                      \
                   __func__, __LINE__, #condition);                         \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static vfs_mount_table_t g_table;
static filesystem_ops_t g_operations;
static uint64_t g_now_us;
static int g_filesystem_sync_result;
static int g_sync_result;
static int g_sync_calls;
static int g_sync_inode_calls;
static int g_sync_inode_data_only;
static int g_writeback_calls[8];
static uint32_t g_page_writeback_calls;

uint32_t vfs_page_writeback_run(uint32_t page_budget) {
    CHECK(page_budget == 32u);
    ++g_page_writeback_calls;
    return page_budget;
}

vfs_superblock_t *vfs_mount_table_at(vfs_mount_table_t *table,
                                     uint32_t index) {
    return table && index < VFS_MOUNT_TABLE_INLINE_CAPACITY ?
        &table->inline_mounts[index] : 0;
}

uint64_t boottime_monotonic_us(void) {
    return g_now_us;
}

vfs_mount_table_t *vfs_mount_namespace_active_table(void) {
    return &g_table;
}

int vfs_filesystem_sync_all(void) {
    return g_filesystem_sync_result;
}

static int test_sync(vfs_superblock_t *sb) {
    (void)sb;
    ++g_sync_calls;
    return g_sync_result;
}

static int test_sync_inode(vfs_superblock_t *sb, const vfs_inode_t *inode,
                           int data_only) {
    (void)sb;
    (void)inode;
    ++g_sync_inode_calls;
    g_sync_inode_data_only = data_only;
    return g_sync_result;
}

static int test_writeback(vfs_superblock_t *sb) {
    int index = -1;
    for (int candidate = 0; candidate < g_table.mount_count; ++candidate) {
        if (vfs_mount_table_at(&g_table, (uint32_t)candidate) == sb) {
            index = candidate;
            break;
        }
    }

    if (index >= 0 && index < 8)
        ++g_writeback_calls[index];
    return 0;
}

static void bytes_zero(void *destination, uint64_t size) {
    uint8_t *bytes = (uint8_t *)destination;

    while (size) {
        *bytes++ = 0;
        --size;
    }
}

static void reset_policy_state(void) {
    bytes_zero(&g_table, sizeof(g_table));
    bytes_zero(&g_operations, sizeof(g_operations));
    bytes_zero(g_writeback_calls, sizeof(g_writeback_calls));
    g_filesystem_sync_result = 0;
    g_sync_result = 0;
    g_sync_calls = 0;
    g_sync_inode_calls = 0;
    g_sync_inode_data_only = -1;
    g_page_writeback_calls = 0;
}

static int test_mutation_sync_policy(void) {
    vfs_superblock_t superblock;

    bytes_zero(&superblock, sizeof(superblock));
    superblock.ops = &g_operations;
    g_operations.sync = test_sync;

    CHECK(vfs_sync_mutation_if_required(0, 0) == 0);
    CHECK(vfs_sync_mutation_if_required(&superblock, 0) == 0);
    CHECK(g_sync_calls == 0);

    superblock.mount_flags = VFS_MOUNT_DIRSYNC;
    CHECK(vfs_sync_mutation_if_required(&superblock, 0) == 0);
    CHECK(g_sync_calls == 0);
    CHECK(vfs_sync_mutation_if_required(&superblock, 1) == 0);
    CHECK(g_sync_calls == 1);

    superblock.mount_flags = VFS_MOUNT_SYNCHRONOUS;
    CHECK(vfs_sync_mutation_if_required(&superblock, 0) == 0);
    CHECK(g_sync_calls == 2);

    g_sync_result = -1;
    CHECK(vfs_sync_mutation_if_required(&superblock, 1) == -1);
    CHECK(g_sync_calls == 3);

    superblock.ops = 0;
    CHECK(vfs_sync_mutation_if_required(&superblock, 1) == 0);
    return 0;
}

static int test_explicit_sync_policy(void) {
    vfs_superblock_t superblock;
    vfs_inode_t inode;

    bytes_zero(&superblock, sizeof(superblock));
    bytes_zero(&inode, sizeof(inode));
    superblock.ops = &g_operations;
    g_operations.sync = test_sync;
    g_operations.sync_inode = test_sync_inode;
    g_sync_result = 0;
    g_sync_calls = 0;
    g_sync_inode_calls = 0;
    g_sync_inode_data_only = -1;

    CHECK(vfs_sync_inode(0, &inode, 0) == -1);
    CHECK(vfs_sync_inode(&superblock, 0, 0) == -1);
    CHECK(vfs_sync_inode(&superblock, &inode, 7) == 0);
    CHECK(g_sync_inode_calls == 1);
    CHECK(g_sync_inode_data_only == 1);
    CHECK(g_sync_calls == 0);

    g_operations.sync_inode = 0;
    CHECK(vfs_sync_inode(&superblock, &inode, 0) == 0);
    CHECK(g_sync_calls == 1);

    g_operations.sync = 0;
    CHECK(vfs_sync_inode(&superblock, &inode, 0) == 0);

    g_filesystem_sync_result = -1;
    CHECK(vfs_sync_all() == -1);
    g_filesystem_sync_result = 0;
    CHECK(vfs_sync_all() == 0);
    return 0;
}

static int test_writeback_cadence(void) {
    g_operations.writeback = test_writeback;
    g_table.mount_count = 3;
    vfs_mount_table_at(&g_table, 0u)->ops = &g_operations;
    vfs_mount_table_at(&g_table, 1u)->ops = 0;
    vfs_mount_table_at(&g_table, 2u)->ops = &g_operations;

    g_now_us = 100u;
    vfs_writeback_poll();
    CHECK(g_writeback_calls[0] == 0);
    CHECK(g_writeback_calls[2] == 0);

    g_now_us = 5000099u;
    vfs_writeback_poll();
    CHECK(g_writeback_calls[0] == 0);
    CHECK(g_writeback_calls[2] == 0);

    g_now_us = 5000100u;
    vfs_writeback_poll();
    CHECK(g_writeback_calls[0] == 1);
    CHECK(g_writeback_calls[1] == 0);
    CHECK(g_writeback_calls[2] == 1);
    CHECK(g_page_writeback_calls == 1u);

    vfs_writeback_poll();
    CHECK(g_writeback_calls[0] == 1);
    CHECK(g_writeback_calls[2] == 1);

    g_now_us = 10000100u;
    vfs_writeback_poll();
    CHECK(g_writeback_calls[0] == 2);
    CHECK(g_writeback_calls[2] == 2);
    CHECK(g_page_writeback_calls == 2u);
    return 0;
}

int main(void) {
    reset_policy_state();
    if (test_mutation_sync_policy() ||
        test_explicit_sync_policy() ||
        test_writeback_cadence())
        return 1;
    printf("VFS_WRITEBACK_UNIT_PASS\n");
    return 0;
}
