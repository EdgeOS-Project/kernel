/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent persistent boot log writer.
 * Copyright (c) EdgeOS Contributors.
 *
 * Console output begins before the root filesystem exists. The bootlog ring
 * therefore remains the source of truth until kernel_boot_log_start() can
 * create the requested file. Later writes are drained from the same absolute
 * ring position in bounded chunks from process or idle context.
 */

#include "kernel/boot_logfile.h"

#include <stdint.h>

#include "console.h"
#include "kernel/boot_log_policy.h"
#include "sys/bootlog.h"
#include "sys/boottime.h"
#include "vfs/vfs.h"

#define BOOT_LOG_FLUSH_INTERVAL_US 250000ull
#define BOOT_LOG_SYNC_INTERVAL_US 2000000ull
#define BOOT_LOG_WRITE_CHUNK 4096u

enum boot_log_file_state {
    BOOT_LOG_FILE_UNCONFIGURED = 0,
    BOOT_LOG_FILE_DISABLED,
    BOOT_LOG_FILE_WAITING,
    BOOT_LOG_FILE_ACTIVE,
    BOOT_LOG_FILE_FAILED
};

static kernel_boot_log_policy_t g_boot_log_policy;
static uint64_t g_boot_log_position;
static uint64_t g_boot_log_next_flush_us;
static uint64_t g_boot_log_next_sync_us;
static volatile int g_boot_log_flush_busy;
static int g_boot_log_file_state;
static int g_boot_log_policy_status;
static char g_boot_log_chunk[BOOT_LOG_WRITE_CHUNK];
static vfs_inode_t g_boot_log_inode;
static vfs_superblock_t *g_boot_log_superblock;

static int boot_log_flush(int force_sync) {
    uint64_t position;
    uint64_t next;
    uint64_t now;
    int wrote = 0;

    if (g_boot_log_file_state != BOOT_LOG_FILE_ACTIVE) return 0;
    if (!__sync_bool_compare_and_swap(&g_boot_log_flush_busy, 0, 1))
        return 0;

    position = g_boot_log_position;
    next = bootlog_next_offset();
    while (position < next) {
        uint64_t before = position;
        uint64_t available = next - position;
        uint32_t wanted = available > sizeof(g_boot_log_chunk) ?
            (uint32_t)sizeof(g_boot_log_chunk) : (uint32_t)available;
        uint32_t offset = 0;
        int append_result;
        int count = bootlog_read_from(
            &position, g_boot_log_chunk, wanted);

        if (count <= 0) break;
        append_result = vfs_append_write(
            0, g_boot_log_superblock, &g_boot_log_inode,
            g_boot_log_chunk, (uint32_t)count, &offset);
        if (append_result != count ||
            vfs_sync_mutation_if_required(
                g_boot_log_superblock, 0) < 0) {
            g_boot_log_position = before;
            g_boot_log_file_state = BOOT_LOG_FILE_FAILED;
            __sync_lock_release(&g_boot_log_flush_busy);
            bootlog_stage("bootlog: persistent file write failed");
            return -1;
        }
        g_boot_log_position = position;
        vfs_path_cache_invalidate(g_boot_log_policy.file_path);
        wrote = 1;
        next = bootlog_next_offset();
    }

    now = boottime_monotonic_us();
    if (wrote &&
        (force_sync || !g_boot_log_next_sync_us ||
         now >= g_boot_log_next_sync_us)) {
        (void)vfs_sync_all();
        g_boot_log_next_sync_us = now + BOOT_LOG_SYNC_INTERVAL_US;
    }
    g_boot_log_next_flush_us = now + BOOT_LOG_FLUSH_INTERVAL_US;
    __sync_lock_release(&g_boot_log_flush_busy);
    return 0;
}

int kernel_boot_log_configure(void) {
    g_boot_log_policy_status =
        kernel_boot_log_policy_load(&g_boot_log_policy);
    if (console_kernel_log_set_level(
            g_boot_log_policy.console_loglevel) < 0) {
        g_boot_log_policy.console_loglevel = 7;
        (void)console_kernel_log_set_level(7);
        g_boot_log_policy_status = -1;
    }
    g_boot_log_position = 0;
    g_boot_log_next_flush_us = 0;
    g_boot_log_next_sync_us = 0;
    g_boot_log_flush_busy = 0;
    g_boot_log_superblock = 0;
    g_boot_log_file_state = g_boot_log_policy.file_enabled ?
        BOOT_LOG_FILE_WAITING : BOOT_LOG_FILE_DISABLED;
    return g_boot_log_policy_status;
}

int kernel_boot_log_start(void) {
    if (g_boot_log_file_state == BOOT_LOG_FILE_UNCONFIGURED)
        (void)kernel_boot_log_configure();
    if (g_boot_log_file_state == BOOT_LOG_FILE_DISABLED) return 0;
    if (g_boot_log_file_state != BOOT_LOG_FILE_WAITING) return -1;

    if (vfs_write_file(g_boot_log_policy.file_path, "", 0) < 0 ||
        vfs_resolve(g_boot_log_policy.file_path, &g_boot_log_inode,
                    &g_boot_log_superblock, 0, 0) < 0 ||
        !g_boot_log_superblock ||
        (g_boot_log_inode.mode & 0xf000u) != VFS_INODE_FILE ||
        vfs_inode_open(g_boot_log_superblock, &g_boot_log_inode) < 0) {
        g_boot_log_file_state = BOOT_LOG_FILE_FAILED;
        bootlog_stage("bootlog: cannot create persistent file");
        return -1;
    }

    g_boot_log_position = bootlog_first_offset();
    g_boot_log_file_state = BOOT_LOG_FILE_ACTIVE;
    bootlog_stage("bootlog: persistent file enabled");
    return boot_log_flush(1);
}

void kernel_boot_log_poll(void) {
    uint64_t now;

    if (g_boot_log_file_state != BOOT_LOG_FILE_ACTIVE) return;
    now = boottime_monotonic_us();
    if (g_boot_log_next_flush_us && now < g_boot_log_next_flush_us) return;
    (void)boot_log_flush(0);
}

void kernel_boot_log_flush_now(void) {
    (void)boot_log_flush(1);
}
