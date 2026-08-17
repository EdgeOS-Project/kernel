/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

extern void *calloc(unsigned long count, unsigned long size);
extern void free(void *allocation);

#define SYS_SPINLOCK_H
typedef struct {
    volatile uint32_t v;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    lock->v = 0;
}

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (__sync_lock_test_and_set(&lock->v, 1u)) {
    }
    return 0;
}

static inline void spin_unlock_irqrestore(
    spinlock_t *lock, uint64_t flags) {
    (void)flags;
    __sync_lock_release(&lock->v);
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    return calloc((unsigned long)page_count, 4096u);
}

void arch_vm_free_page(void *page) {
    (void)page;
}

static void *test_allocate_pages(uint32_t page_count, void *context) {
    (void)context;
    return calloc((unsigned long)page_count, 4096u);
}

static void test_release_pages(void *base, uint32_t page_count,
                               void *context) {
    (void)page_count;
    (void)context;
    free(base);
}

#include "../../src/vfs/path_cache.c"

static vfs_inode_t test_inode(uint32_t inode_number) {
    vfs_inode_t inode = {0};
    inode.ino = inode_number;
    inode.mode = VFS_INODE_FILE | 0644u;
    return inode;
}

static void expect_hit(
    const char *path, uint32_t namespace_id, uint32_t inode_number) {
    vfs_path_cache_result_t result = {0};
    assert(vfs_path_cache_runtime_lookup(
        path, namespace_id, &result));
    assert(!result.miss);
    assert(result.inode.ino == inode_number);
}

static void expect_miss(const char *path, uint32_t namespace_id) {
    vfs_path_cache_result_t result = {0};
    assert(!vfs_path_cache_runtime_lookup(
        path, namespace_id, &result));
}

int main(void) {
    vfs_path_cache_allocator_t allocator = {
        test_allocate_pages,
        test_release_pages,
        0,
    };
    vfs_inode_t usr_tool = test_inode(11);
    vfs_inode_t usr_library = test_inode(12);
    vfs_inode_t usr_boundary = test_inode(13);
    vfs_inode_t home_file = test_inode(14);
    vfs_inode_t other_namespace = test_inode(15);

    assert(vfs_path_cache_runtime_set_allocator(&allocator) == 0);
    vfs_path_cache_runtime_store(
        "/early/config", 1, 0, &usr_tool, 1);
    expect_hit("/early/config", 1, 11);
    vfs_path_cache_runtime_reset();
    expect_miss("/early/config", 1);
    vfs_path_cache_runtime_store(
        "/usr/bin/tool", 1, 0, &usr_tool, 1);
    vfs_path_cache_runtime_store(
        "/usr/lib/library", 1, 0, &usr_library, 1);
    vfs_path_cache_runtime_store(
        "/usrbin/tool", 1, 0, &usr_boundary, 1);
    vfs_path_cache_runtime_store(
        "/home/user/file", 1, 0, &home_file, 1);
    vfs_path_cache_runtime_store(
        "/usr/share/data", 2, 0, &other_namespace, 1);

    vfs_path_cache_runtime_invalidate_subtree("/usr/");
    expect_miss("/usr/bin/tool", 1);
    expect_miss("/usr/lib/library", 1);
    expect_miss("/usr/share/data", 2);
    expect_hit("/usrbin/tool", 1, 13);
    expect_hit("/home/user/file", 1, 14);

    vfs_path_cache_runtime_invalidate_subtree("/home/user/file");
    expect_miss("/home/user/file", 1);
    expect_hit("/usrbin/tool", 1, 13);

    vfs_path_cache_runtime_store(
        "/home/user/file", 1, 0, &home_file, 1);
    vfs_path_cache_runtime_invalidate_subtree("/");
    expect_miss("/home/user/file", 1);
    expect_miss("/usrbin/tool", 1);

    for (uint32_t index = 0; index < 3000u; ++index) {
        char path[64];
        vfs_inode_t inode = test_inode(100u + index);
        snprintf(path, sizeof(path), "/dynamic/cache/%u", index);
        vfs_path_cache_runtime_store(path, 7u, 0, &inode, 3u);
    }
    assert(vfs_path_cache_runtime_count() == 3000u);
    expect_hit("/dynamic/cache/0", 7u, 100u);
    expect_hit("/dynamic/cache/2999", 7u, 3099u);
    assert(vfs_path_cache_runtime_reclaim(1000u) == 1000u);
    assert(vfs_path_cache_runtime_count() == 2000u);
    vfs_path_cache_invalidate_all();
    assert(vfs_path_cache_runtime_count() == 0u);

    puts("vfs_path_cache_unit: PASS");
    return 0;
}
