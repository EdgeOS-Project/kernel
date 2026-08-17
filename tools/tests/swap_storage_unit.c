/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS swap storage unit test. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "block/block.h"
#include "fs/swap.h"
#include "vfs/vfs.h"

#define TEST_PAGE_SIZE 4096u
#define TEST_STORAGE_PAGES 4u

static uint8_t g_storage[TEST_PAGE_SIZE * TEST_STORAGE_PAGES];
static filesystem_ops_t g_ops;
static vfs_superblock_t g_superblock;
static vfs_inode_t g_inode;
static int g_failures;
static int g_charge_failure;
static uint32_t g_charge_cgroup;
static uint64_t g_charge_bytes;
static uint64_t g_uncharge_bytes;
static uint64_t g_swap_in_pages;
static uint64_t g_swap_out_pages;
static uint8_t g_metadata[TEST_PAGE_SIZE * 8u];
static uint8_t g_metadata_used;
static uint64_t g_mapped_entry;
static uint32_t g_restore_calls;

static int restore_swap_mapping(uint64_t address_space, uint64_t address,
                                uint64_t swap_entry) {
    if (address_space != 0x1000u || address != 0x2000u ||
        swap_entry != g_mapped_entry)
        return -1;
    ++g_restore_calls;
    g_mapped_entry = 0;
    swap_release_entry(swap_entry);
    return 0;
}

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

static int storage_read(vfs_superblock_t *sb, vfs_inode_t *inode,
                        uint32_t offset, void *buffer, uint32_t length) {
    (void)sb;
    (void)inode;
    if ((uint64_t)offset + length > sizeof(g_storage)) return -1;
    memcpy(buffer, g_storage + offset, length);
    return (int)length;
}

static int storage_write(vfs_superblock_t *sb, vfs_inode_t *inode,
                         uint32_t offset, const void *buffer,
                         uint32_t length) {
    (void)sb;
    (void)inode;
    if ((uint64_t)offset + length > sizeof(g_storage)) return -1;
    memcpy(g_storage + offset, buffer, length);
    return (int)length;
}

int vfs_resolve(const char *path, vfs_inode_t *out_inode,
                vfs_superblock_t **out_sb, vfs_inode_t *out_parent,
                char *leaf) {
    (void)out_parent;
    (void)leaf;
    if (!path || strcmp(path, "/swapfile") != 0) return -1;
    *out_inode = g_inode;
    *out_sb = &g_superblock;
    return 0;
}

int vfs_inode_get_block_device(const vfs_inode_t *inode,
                               block_device_t **out) {
    (void)inode;
    if (out) *out = 0;
    return -1;
}

int vfs_inode_open(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    (void)sb;
    (void)inode;
    return 0;
}

void vfs_inode_close(vfs_superblock_t *sb, const vfs_inode_t *inode) {
    (void)sb;
    (void)inode;
}

vfs_superblock_t *vfs_superblock_stable(vfs_superblock_t *sb) {
    return sb;
}

int64_t block_read_bytes(block_device_t *device, uint64_t offset,
                         void *output, uint32_t length) {
    (void)device;
    (void)offset;
    (void)output;
    (void)length;
    return -1;
}

int64_t block_write_bytes(block_device_t *device, uint64_t offset,
                          const void *input, uint32_t length) {
    (void)device;
    (void)offset;
    (void)input;
    (void)length;
    return -1;
}

int block_read_sectors(block_device_t *device, uint32_t lba,
                       uint32_t count, void *output) {
    (void)device;
    (void)lba;
    (void)count;
    (void)output;
    return -1;
}

int cgroupfs_memory_swap_charge(uint32_t cgroup_id, uint64_t bytes) {
    g_charge_cgroup = cgroup_id;
    g_charge_bytes += bytes;
    return g_charge_failure ? -1 : 0;
}

void cgroupfs_memory_swap_uncharge(uint32_t cgroup_id, uint64_t bytes) {
    g_charge_cgroup = cgroup_id;
    g_uncharge_bytes += bytes;
}

void edge_mm_statistics_note_swap_in(uint64_t pages) {
    g_swap_in_pages += pages;
}

void edge_mm_statistics_note_swap_out(uint64_t pages) {
    g_swap_out_pages += pages;
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    if (!page_count || page_count > 8u || g_metadata_used) return 0;
    g_metadata_used = 1u;
    memset(g_metadata, 0, sizeof(g_metadata));
    return g_metadata;
}

void *arch_vm_alloc_page(void) {
    return arch_vm_alloc_pages(1u);
}

void arch_vm_free_page(void *page) {
    uint8_t *cursor = (uint8_t *)page;

    if (cursor >= g_metadata && cursor < g_metadata + sizeof(g_metadata))
        g_metadata_used = 0u;
}

int edge_swap_map_find_entry(uint64_t swap_entry,
                             uint64_t *address_space_out,
                             uint64_t *address_out) {
    if (!g_mapped_entry || swap_entry != g_mapped_entry ||
        !address_space_out || !address_out ||
        swap_retain_entry(swap_entry) < 0)
        return -1;
    *address_space_out = 0x1000u;
    *address_out = 0x2000u;
    return 0;
}

static void initialize_storage(void) {
    memset(g_storage, 0, sizeof(g_storage));
    memset(&g_ops, 0, sizeof(g_ops));
    memset(&g_superblock, 0, sizeof(g_superblock));
    memset(&g_inode, 0, sizeof(g_inode));
    g_ops.read = storage_read;
    g_ops.write = storage_write;
    g_superblock.ops = &g_ops;
    g_inode.mode = VFS_INODE_FILE | 0600u;
    g_inode.size = sizeof(g_storage);
    memcpy(g_storage + TEST_PAGE_SIZE - 10u, "SWAPSPACE2", 10u);
}

int main(void) {
    uint8_t input[TEST_PAGE_SIZE];
    uint8_t output[TEST_PAGE_SIZE];
    char snapshot[512];
    uint64_t entry = 0;
    uint64_t rejected_entry = 0;
    uint64_t migrated_entry = 0;
    uint32_t cgroup_id = 0;

    initialize_storage();
    memset(input, 0x5a, sizeof(input));
    expect_true("pager gate",
                swap_enable_path("/swapfile", 0u) == -38);
    swap_register_pager(restore_swap_mapping);
    expect_true("enable swap file",
                swap_enable_path("/swapfile", 0u) == 0);
    expect_true("usable capacity excludes header",
                swap_total_bytes() == 3u * TEST_PAGE_SIZE &&
                swap_free_bytes() == 3u * TEST_PAGE_SIZE);
    expect_true("store page",
                swap_store_page(7u, input, &entry) == 0 && entry != 0 &&
                g_charge_cgroup == 7u &&
                g_charge_bytes == TEST_PAGE_SIZE &&
                g_swap_out_pages == 1u);
    expect_true("used capacity",
                swap_free_bytes() == 2u * TEST_PAGE_SIZE);
    expect_true("stored entry has one reference",
                swap_entry_references(entry) == 1u);
    memset(output, 0, sizeof(output));
    expect_true("load page",
                swap_load_page(entry, output, &cgroup_id) == 0 &&
                cgroup_id == 7u && memcmp(input, output, sizeof(input)) == 0 &&
                g_swap_in_pages == 1u);
    expect_true("retain entry", swap_retain_entry(entry) == 0 &&
                swap_entry_references(entry) == 2u);
    swap_release_entry(entry);
    expect_true("first release retains shared entry",
                swap_load_page(entry, output, 0) == 0 &&
                swap_entry_references(entry) == 1u);
    swap_release_entry(entry);
    expect_true("final release invalidates entry",
                swap_load_page(entry, output, 0) < 0 &&
                swap_entry_references(entry) == 0u &&
                swap_free_bytes() == 3u * TEST_PAGE_SIZE &&
                g_uncharge_bytes == TEST_PAGE_SIZE);
    g_charge_failure = 1;
    expect_true("cgroup swap maximum rejects store",
                swap_store_page(9u, input, &rejected_entry) < 0 &&
                rejected_entry == 0 &&
                swap_free_bytes() == 3u * TEST_PAGE_SIZE);
    g_charge_failure = 0;
    expect_true("proc swap snapshot",
                swap_proc_snapshot(snapshot, sizeof(snapshot)) > 0 &&
                strstr(snapshot, "/swapfile") != 0 &&
                strstr(snapshot, "file") != 0);
    expect_true("store page for swapoff migration",
                swap_store_page(12u, input, &migrated_entry) == 0 &&
                migrated_entry != 0);
    g_mapped_entry = migrated_entry;
    expect_true("swapoff migrates resident mapping",
                swap_disable_path("/swapfile") == 0 &&
                swap_total_bytes() == 0u && !g_metadata_used &&
                !g_mapped_entry && g_restore_calls == 1u);
    if (g_failures) return 1;
    puts("swap_storage_unit: PASS");
    return 0;
}
