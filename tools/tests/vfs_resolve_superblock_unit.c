/* SPDX-License-Identifier: MPL-2.0 */
/* Recursive and concurrent pre-mount superblock resolver test. */

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vfs/vfs.h"

#define TEST_THREADS 24u

typedef struct {
    vfs_superblock_t *nested;
    uint32_t recursive;
} test_filesystem_t;

static pthread_mutex_t g_barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_barrier_condition = PTHREAD_COND_INITIALIZER;
static uint32_t g_barrier_arrivals;
static uint32_t g_page_allocations;

void *arch_vm_alloc_pages(uint64_t page_count) {
    void *allocation = calloc((size_t)page_count, 4096u);
    if (allocation)
        __atomic_add_fetch(&g_page_allocations, 1u, __ATOMIC_RELAXED);
    return allocation;
}

void arch_vm_free_page(void *page) {
    (void)page;
}

static void barrier_wait(void) {
    assert(pthread_mutex_lock(&g_barrier_lock) == 0);
    ++g_barrier_arrivals;
    if (g_barrier_arrivals == TEST_THREADS) {
        assert(pthread_cond_broadcast(&g_barrier_condition) == 0);
    } else {
        while (g_barrier_arrivals < TEST_THREADS)
            assert(pthread_cond_wait(&g_barrier_condition,
                                     &g_barrier_lock) == 0);
    }
    assert(pthread_mutex_unlock(&g_barrier_lock) == 0);
}

static int test_lookup(vfs_superblock_t *superblock, vfs_inode_t *directory,
                       const char *name, vfs_inode_t *out) {
    test_filesystem_t *filesystem;
    (void)directory;
    if (!superblock || !name || !out) return -1;
    filesystem = (test_filesystem_t *)superblock->fs_private;
    if (!filesystem) return -1;

    if (filesystem->recursive && strcmp(name, "nested") == 0) {
        vfs_inode_t nested;
        barrier_wait();
        if (!filesystem->nested ||
            vfs_resolve_superblock_path(filesystem->nested,
                                        "/deep/item", &nested) < 0)
            return -1;
        *out = nested;
        out->ino += 100u;
        return 0;
    }
    if (strcmp(name, "deep") == 0) {
        memset(out, 0, sizeof(*out));
        out->ino = 2u;
        out->mode = VFS_INODE_DIR;
        return 0;
    }
    if (strcmp(name, "item") == 0) {
        memset(out, 0, sizeof(*out));
        out->ino = 77u;
        out->mode = VFS_INODE_FILE;
        return 0;
    }
    return -1;
}

static void *resolve_thread(void *argument) {
    vfs_superblock_t *superblock = (vfs_superblock_t *)argument;
    vfs_inode_t inode;
    assert(vfs_resolve_superblock_path(superblock, "/nested", &inode) == 0);
    assert(inode.ino == 177u);
    assert(inode.mode == VFS_INODE_FILE);
    return 0;
}

int main(void) {
    filesystem_ops_t operations;
    test_filesystem_t outer_filesystem;
    test_filesystem_t inner_filesystem;
    vfs_superblock_t outer;
    vfs_superblock_t inner;
    pthread_t threads[TEST_THREADS];
    vfs_inode_t inode;

    memset(&operations, 0, sizeof(operations));
    memset(&outer_filesystem, 0, sizeof(outer_filesystem));
    memset(&inner_filesystem, 0, sizeof(inner_filesystem));
    memset(&outer, 0, sizeof(outer));
    memset(&inner, 0, sizeof(inner));
    operations.lookup = test_lookup;
    outer.ops = &operations;
    inner.ops = &operations;
    outer.root.mode = VFS_INODE_DIR;
    inner.root.mode = VFS_INODE_DIR;
    outer_filesystem.nested = &inner;
    outer_filesystem.recursive = 1u;
    outer.fs_private = &outer_filesystem;
    inner.fs_private = &inner_filesystem;

    assert(vfs_resolve_superblock_path(&inner, "/deep/item", &inode) == 0);
    assert(inode.ino == 77u);
    for (uint32_t index = 0; index < TEST_THREADS; ++index)
        assert(pthread_create(&threads[index], 0, resolve_thread,
                              &outer) == 0);
    for (uint32_t index = 0; index < TEST_THREADS; ++index)
        assert(pthread_join(threads[index], 0) == 0);
    assert(g_page_allocations > 0u);

    puts("vfs_resolve_superblock_unit: PASS");
    return 0;
}
