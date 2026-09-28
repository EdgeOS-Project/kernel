/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise metadata cache growth, reuse, eviction, and directory completeness. */
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#define STDIO_H
#define STRING_H
#ifndef EXT4_TEST_SOURCE
#define EXT4_TEST_SOURCE "../../src/fs/ext4/ext4.c"
#endif
#include EXT4_TEST_SOURCE

static unsigned pages_live;
static unsigned pages_limit = 100000;
static unsigned allocations;
static ext4_fs_t *expected_reader_wait;
static unsigned reader_waits;
static uint32_t write_order[16];
static unsigned write_count;
static unsigned flush_count;
static int track_writes;

uintptr_t kernel_current_context_token(void) { return 1; }
uint64_t boottime_monotonic_us(void) { return 1000; }
int kernel_runtime_contention_begin(void) {
    assert(expected_reader_wait && "Metadata readers must not wait for unrelated readers");
    return 1;
}
void kernel_runtime_contention_end(int released) { assert(released == 1); }
void kernel_runtime_contention_wait(volatile uint32_t *word, uint32_t observed) {
    assert(expected_reader_wait && word == &expected_reader_wait->parallel_readers);
    assert(observed == 1 && *word == 1);
    ++reader_waits;
    *word = 0;
}
void kernel_runtime_contention_notify(void) {}

void *arch_vm_alloc_page(void) {
    void *page;
    if (pages_live >= pages_limit) return 0;
    page = calloc(1, 4096);
    if (page) { ++pages_live; ++allocations; }
    return page;
}
void *arch_vm_alloc_pages(uint64_t count) {
    assert(count == 1);
    return arch_vm_alloc_page();
}
void arch_vm_free_page(void *page) {
    assert(page && pages_live);
    --pages_live;
    free(page);
}
int kernel_current_pid(void) { return 1; }
const char *kernel_current_comm(void) { return "metadata-cache-test"; }
#ifdef __aarch64__
uint32_t edgeos_arm64_page_lifecycle(
    uint64_t physical, uint64_t *last_free_caller,
    uint64_t *last_alloc_caller) {
    (void)physical;
    if (last_free_caller) *last_free_caller = 0;
    if (last_alloc_caller) *last_alloc_caller = 0;
    return 1;
}
#endif
int block_read_sectors(block_device_t *dev, uint32_t lba, uint32_t count, void *out) {
    (void)dev; (void)lba; (void)count; (void)out;
    assert(!"Unexpected disk read: the fixture is resident");
    return -1;
}
int block_write_sectors(block_device_t *dev, uint32_t lba, uint32_t count, const void *in) {
    (void)dev; (void)count; (void)in;
    if (track_writes) {
        assert(write_count < sizeof(write_order) / sizeof(write_order[0]));
        if (lba / 8u == 22u) assert(flush_count == 1);
        else assert(flush_count == 0);
        write_order[write_count++] = lba / 8u;
        return 0;
    }
    assert(!"Read-only fixture must not write");
    return -1;
}
int block_flush(block_device_t *dev) {
    (void)dev;
    assert(track_writes);
    ++flush_count;
    return 0;
}

static void directory_publish_order(void) {
    static ext4_fs_t fs;
    static block_device_t device;
    const uint32_t blocks[] = {10, 11, 20, 21, 22};
    device.sector_size = 512;
    fs.bdev = &device;
    fs.block_size = 4096;
    fs.pending_allocation_count = 1;
    fs.pending_allocations[0].bitmap_block = 10;
    fs.pending_allocations[0].descriptor_block = 11;
    fs.pending_directory_count = 1;
    fs.pending_directories[0].data_block = 20;
    fs.pending_directories[0].first_inode_block = 21;
    fs.pending_directories[0].last_inode_block = 21;
    for (unsigned i = 0; i < 5; ++i) {
        fs.block_cache[i].valid = 1;
        fs.block_cache[i].dirty = 1;
        fs.block_cache[i].block = blocks[i];
        fs.block_cache[i].age = i + 1;
    }
    track_writes = 1;
    assert(block_cache_flush_slot(&fs, 4) == 0);
    assert(write_count == 5 && flush_count == 1);
    for (unsigned i = 0; i < 5; ++i) assert(write_order[i] == blocks[i]);
    assert(!fs.pending_allocation_count && !fs.pending_directory_count);
    track_writes = 0;
}

static void repeated_names_across_inode_groups(void) {
    static unsigned buckets[EXT4_LOOKUP_CACHE_BUCKETS];
    unsigned longest = 0;

    /* Real ext4 directory inode numbers often share their low bits. */
    for (uint32_t group = 0; group < 4096; ++group) {
        uint32_t bucket = lookup_cache_bucket((group << 16) | 1u, "config");
        unsigned length = ++buckets[bucket];
        if (length > longest) longest = length;
    }
    printf("repeated_name_max_chain=%u\n", longest);
    assert(longest < 16);
}

static void growth_and_reuse(void) {
    static ext4_fs_t fs;
    ext4_inode_t in = {.mode = 0100644}, out;
    char name[32];
    unsigned before;
    clock_t start = clock();
    for (uint32_t i = 1; i <= 20000; ++i) {
        snprintf(name, sizeof(name), "entry-%u", i);
        assert(lookup_cache_store(&fs, 2, name, i, 0, 77, i));
        inode_cache_store(&fs, i, &in);
    }
    printf("populate_20000_cpu_ms=%.3f\n", 1000.0 * (clock() - start) / CLOCKS_PER_SEC);
    start = clock();
    for (uint32_t i = 1; i <= 20000; ++i) {
        uint32_t ino = 0, offset = 0;
        int miss = 1;
        snprintf(name, sizeof(name), "entry-%u", i);
        assert(lookup_cache_find(&fs, 2, name, &ino, &miss, 0, &offset));
        assert(ino == i && !miss && offset == i);
        assert(inode_cache_lookup(&fs, i, &out) && out.mode == in.mode);
    }
    printf("lookup_20000_cpu_ms=%.3f\n", 1000.0 * (clock() - start) / CLOCKS_PER_SEC);
    /* Free holes in old full pages and ensure insertion reuses them. */
    before = allocations;
    for (uint32_t i = 1; i <= 1000; i += 4) {
        snprintf(name, sizeof(name), "entry-%u", i);
        lookup_cache_invalidate(&fs, 2, name);
        inode_cache_invalidate(&fs, i);
    }
    for (uint32_t i = 1; i <= 1000; i += 4) {
        snprintf(name, sizeof(name), "replacement-%u", i);
        assert(lookup_cache_store(&fs, 2, name, i, 0, 88, i));
        inode_cache_store(&fs, i, &in);
    }
    assert(allocations == before);
    assert(fs.lookup_cache_count == 20000 && fs.inode_cache_count == 20000);
    while (lookup_cache_reclaim_page(&fs)) {}
    while (inode_cache_reclaim_page(&fs)) {}
    assert(!fs.lookup_cache_count && !fs.inode_cache_count && !pages_live);
    for (uint32_t bucket = 0; bucket < EXT4_LOOKUP_CACHE_BUCKETS; ++bucket)
        assert(fs.lookup_cache[bucket] == 0);
    /* Reusing a fully reclaimed cache must not follow freed page links. */
    assert(lookup_cache_store(&fs, 2, "new", 3, 0, 1, 0));
    inode_cache_store(&fs, 3, &in);
    ext4_dynamic_state_release(&fs);
    assert(!pages_live);
}

static void eviction_during_scan(void) {
    static ext4_fs_t fs;
    static block_device_t device;
    vfs_superblock_t sb = {.fs_private = &fs};
    vfs_inode_t dir = {.ino = 2, .mode = VFS_INODE_DIR | 0755}, out;
    ext4_inode_t directory = {.mode = 0040755, .size_lo = 4096};
    ext4_inode_t file = {.mode = 0100644};
    device.sector_size = 512;
    fs.bdev = &device;
    fs.block_size = 4096;
    fs.desc_size = sizeof(ext4_bgdesc_t);
    fs.sb.magic = 0xef53;
    fs.sb.inodes_count = 100;
    fs.sb.inodes_per_group = fs.sb.blocks_per_group = 100;
    fs.sb.inode_size = sizeof(ext4_inode_t);
    g_ext4_mounts = &fs;
    directory.block[0] = 77;
    inode_cache_store(&fs, 2, &directory);
    inode_cache_store(&fs, 3, &file);
    fs.block_cache[0].valid = 1;
    fs.block_cache[0].block = 77;
    for (uint32_t i = 0; i < 64; ++i) {
        ext4_dirent_t *de = (void *)(fs.block_cache[0].data + i * 64);
        de->inode = 3;
        de->rec_len = 64;
        de->name_len = 4;
        de->file_type = 1;
        snprintf((char *)de->name, 5, "n%03u", i);
    }
    /* Allow exactly one name-cache page, forcing eviction mid-scan. */
    pages_limit = pages_live + 1;
    assert(ext4_lookup(&sb, &dir, "n063", &out) == 0 && out.ino == 3);
    assert(ext4_lookup(&sb, &dir, "n000", &out) == 0 && out.ino == 3);
    assert(!directory_index_is_complete(&fs, 2, 4096));
    assert(ext4_lookup(&sb, &dir, "absent", &out) < 0);
    pages_limit = 100000;
    lookup_cache_invalidate_all(&fs);
    /* An admitted reader may keep unrelated disk I/O in flight. */
    fs.parallel_readers = 1;
    assert(ext4_lookup_locked(&sb, &dir, "n063", &out) == 0);
    assert(directory_index_is_complete(&fs, 2, 4096));
    assert(ext4_lookup_locked(&sb, &dir, "n000", &out) == 0);
    assert(ext4_lookup_locked(&sb, &dir, "absent", &out) < 0);
    assert(fs.parallel_readers == 1 && !reader_waits && !fs.op_lock);
    /* Reference acquisition and attributes do not mutate file data. */
    file.links_count = 1;
    inode_cache_store(&fs, 3, &file);
    assert(ext4_getattr_locked(&sb, &out, &out) == 0);
    assert(ext4_inode_open_locked(&sb, &out) == 0);
    ext4_open_inode_entry_t *entry = ext4_open_inode_entry(&fs, 3, 0);
    assert(entry && entry->references == 1);
    file.links_count = 0;
    inode_cache_store(&fs, 3, &file);
    assert(ext4_inode_open_locked(&sb, &out) == 0);
    assert(entry->references == 2);
    entry->references = UINT32_MAX;
    assert(ext4_inode_open_locked(&sb, &out) < 0);
    assert(entry->references == UINT32_MAX);
    entry->references = 0;
    assert(ext4_inode_open_locked(&sb, &out) < 0);
    assert(fs.parallel_readers == 1 && !reader_waits && !fs.op_lock);
    /* Writers must still wait before changing the reader's metadata. */
    expected_reader_wait = &fs;
    ext4_op_lock_named(&fs, "writer", 0);
    assert(reader_waits == 1 && !fs.parallel_readers && fs.op_lock);
    ext4_op_unlock(&fs);
    expected_reader_wait = 0;
    ext4_dynamic_state_release(&fs);
    g_ext4_mounts = 0;
    assert(!pages_live);
    pages_limit = 0;
    assert(!lookup_cache_store(&fs, 2, "oom", 3, 0, 1, 0));
    inode_cache_store(&fs, 3, &file);
    assert(!inode_cache_lookup(&fs, 3, &file));
    pages_limit = 100000;
}

int main(void) {
    directory_publish_order();
    repeated_names_across_inode_groups();
    growth_and_reuse();
    eviction_during_scan();
    puts("ext4_metadata_cache_unit: PASS");
    return 0;
}
