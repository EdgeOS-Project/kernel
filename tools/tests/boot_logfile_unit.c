/* SPDX-License-Identifier: MPL-2.0 */
/* Persistent boot log writer tests. */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "kernel/boot_command_line.h"
#include "kernel/boot_logfile.h"
#include "vfs/vfs.h"

static char test_ring[8192];
static uint64_t test_ring_length;
static char test_file[8192];
static uint32_t test_file_length;
static uint64_t test_now_us;
static int test_console_level;
static int test_sync_count;
static vfs_superblock_t test_superblock;

int console_kernel_log_set_level(int level) {
    test_console_level = level;
    return level >= 1 && level <= 8 ? 0 : -1;
}

void bootlog_stage(const char *message) {
    size_t length = strlen(message);

    assert(test_ring_length + length + 1u < sizeof(test_ring));
    memcpy(test_ring + test_ring_length, message, length);
    test_ring_length += length;
    test_ring[test_ring_length++] = '\n';
}

uint64_t bootlog_first_offset(void) {
    return 0;
}

uint64_t bootlog_next_offset(void) {
    return test_ring_length;
}

int bootlog_read_from(uint64_t *position, void *buffer, uint32_t length) {
    uint64_t available;

    if (!position || !buffer) return -1;
    if (*position >= test_ring_length) return 0;
    available = test_ring_length - *position;
    if ((uint64_t)length > available) length = (uint32_t)available;
    memcpy(buffer, test_ring + *position, length);
    *position += length;
    return (int)length;
}

uint64_t boottime_monotonic_us(void) {
    return test_now_us;
}

int vfs_write_file(const char *path, const char *buffer, uint32_t length) {
    (void)buffer;
    assert(strcmp(path, "/edgeos-boot.log") == 0);
    test_file_length = length;
    return (int)length;
}

int vfs_resolve(const char *path, vfs_inode_t *inode,
                vfs_superblock_t **superblock, vfs_inode_t *parent,
                char *leaf) {
    (void)parent;
    (void)leaf;
    assert(strcmp(path, "/edgeos-boot.log") == 0);
    assert(inode);
    inode->mode = VFS_INODE_FILE | 0644u;
    inode->size = test_file_length;
    if (superblock) *superblock = &test_superblock;
    return 0;
}

int vfs_inode_open(vfs_superblock_t *superblock, const vfs_inode_t *inode) {
    assert(superblock == &test_superblock);
    assert(inode);
    return 0;
}

int vfs_append_write(const char *path, vfs_superblock_t *superblock,
                     vfs_inode_t *inode, const void *buffer, uint32_t length,
                     uint32_t *offset) {
    (void)path;
    assert(superblock == &test_superblock);
    assert(inode);
    assert(test_file_length + length < sizeof(test_file));
    memcpy(test_file + test_file_length, buffer, length);
    if (offset) *offset = test_file_length;
    test_file_length += length;
    inode->size = test_file_length;
    return (int)length;
}

int vfs_sync_mutation_if_required(vfs_superblock_t *superblock,
                                  int directory_mutation) {
    assert(superblock == &test_superblock);
    assert(!directory_mutation);
    return 0;
}

void vfs_path_cache_invalidate(const char *path) {
    assert(strcmp(path, "/edgeos-boot.log") == 0);
}

int vfs_sync_all(void) {
    ++test_sync_count;
    return 0;
}

int main(void) {
    static const char early[] = "early kernel record\n";
    static const char late[] = "late kernel record\n";

    memcpy(test_ring, early, sizeof(early) - 1u);
    test_ring_length = sizeof(early) - 1u;
    kernel_boot_command_line_set(
        "loglevel=8 logfile=/edgeos-boot.log");
    assert(kernel_boot_log_configure() == 0);
    assert(test_console_level == 8);
    assert(kernel_boot_log_start() == 0);
    assert(test_sync_count == 1);
    assert(test_file_length > sizeof(early) - 1u);
    assert(memcmp(test_file, early, sizeof(early) - 1u) == 0);

    memcpy(test_ring + test_ring_length, late, sizeof(late) - 1u);
    test_ring_length += sizeof(late) - 1u;
    test_now_us += 300000u;
    kernel_boot_log_poll();
    assert(test_file_length >=
           sizeof(early) + sizeof(late) - 2u);
    assert(memcmp(test_file + test_file_length - (sizeof(late) - 1u),
                  late, sizeof(late) - 1u) == 0);
    return 0;
}
