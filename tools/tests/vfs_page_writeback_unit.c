/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side tests for shared file page writeback tracking. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define SYS_SPINLOCK_H
typedef struct { volatile uint32_t value; } spinlock_t;

static inline void spinlock_init(spinlock_t *lock) { lock->value = 0; }
static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (__sync_lock_test_and_set(&lock->value, 1u)) { }
    return 0;
}
static inline void spin_unlock_irqrestore(spinlock_t *lock,
                                          uint64_t flags) {
    (void)flags;
    __sync_lock_release(&lock->value);
}

void *arch_vm_alloc_pages(uint64_t page_count) {
    return calloc((size_t)page_count, 4096u);
}
void arch_vm_free_page(void *page) { (void)page; }

static void *test_allocate_pages(uint32_t page_count, void *context) {
    (void)context;
    return calloc((size_t)page_count, 4096u);
}
static void test_release_pages(void *base, uint32_t page_count,
                               void *context) {
    (void)page_count;
    (void)context;
    free(base);
}

#include "../../src/vfs/page_writeback.c"

const void *vfs_superblock_identity(const vfs_superblock_t *superblock) {
    return superblock ? superblock->fs_private : 0;
}

typedef struct test_backend {
    vfs_superblock_t *superblock;
    vfs_inode_t *inode;
    uint32_t calls[16];
    int results[16];
    int redirty_token;
    int discard_token;
} test_backend_t;

static int test_writeback(uint64_t token, uint32_t generation,
                          void *context) {
    test_backend_t *backend = (test_backend_t *)context;
    uint32_t index = (uint32_t)token;
    (void)generation;
    assert(index < 16u);
    ++backend->calls[index];
    if (backend->redirty_token == (int)index) {
        backend->redirty_token = -1;
        assert(vfs_page_writeback_mark_dirty(
                   backend->superblock, backend->inode,
                   (uint64_t)index * 4096u, token,
                   test_writeback, backend) >= 0);
    }
    if (backend->discard_token == (int)index) {
        backend->discard_token = -1;
        vfs_page_writeback_forget_token(
            test_writeback, backend, token);
    }
    return backend->results[index];
}

static vfs_inode_t test_inode(uint32_t number, uint32_t generation) {
    vfs_inode_t inode = {0};
    inode.ino = number;
    inode.generation = generation;
    inode.mode = VFS_INODE_FILE | 0644u;
    inode.size = 16u * 4096u;
    return inode;
}

int main(void) {
    vfs_page_writeback_allocator_t allocator = {
        test_allocate_pages, test_release_pages, 0,
    };
    int first_identity;
    int second_identity;
    vfs_superblock_t first = {0};
    vfs_superblock_t second = {0};
    vfs_inode_t inode = test_inode(7u, 3u);
    vfs_inode_t other_inode = test_inode(8u, 1u);
    test_backend_t backend = {0};

    first.fs_private = &first_identity;
    second.fs_private = &second_identity;
    backend.superblock = &first;
    backend.inode = &inode;
    backend.redirty_token = -1;
    backend.discard_token = -1;
    assert(vfs_page_writeback_runtime_set_allocator(&allocator) == 0);

    assert(vfs_page_writeback_mark_dirty(
               &first, &inode, 0u, 0u, test_writeback, &backend) == 0);
    assert(vfs_page_writeback_mark_dirty(
               &first, &inode, 4096u, 1u, test_writeback, &backend) == 0);
    assert(vfs_page_writeback_mark_dirty(
               &first, &other_inode, 8192u, 2u,
               test_writeback, &backend) == 0);
    assert(vfs_page_writeback_dirty_pages() == 3u);
    {
        uint64_t dirty = 0;
        uint64_t writeback = 0;
        vfs_page_writeback_stat_range(
            &first, &inode, 4096u, 4096u, &dirty, &writeback);
        assert(dirty == 1u);
        assert(writeback == 0u);
        vfs_page_writeback_stat_range(
            &first, &inode, 0, 0, &dirty, &writeback);
        assert(dirty == 2u);
        assert(writeback == 0u);
    }

    assert(vfs_page_writeback_sync_range(
               &first, &inode, 4096u, 4096u) == 0);
    assert(backend.calls[0] == 0u && backend.calls[1] == 1u &&
           backend.calls[2] == 0u);
    assert(vfs_page_writeback_dirty_pages() == 2u);

    backend.results[0] = VFS_PAGE_WRITEBACK_RETAIN;
    assert(vfs_page_writeback_run(32u) == 2u);
    assert(backend.calls[0] == 1u && backend.calls[2] == 1u);
    assert(vfs_page_writeback_dirty_pages() == 1u);
    assert(vfs_page_writeback_run(32u) == 1u);
    assert(backend.calls[0] == 2u);

    backend.results[0] = VFS_PAGE_WRITEBACK_COMPLETE;
    backend.redirty_token = 0;
    assert(vfs_page_writeback_run(1u) == 1u);
    assert(vfs_page_writeback_dirty_pages() == 1u);
    assert(vfs_page_writeback_run(1u) == 1u);
    assert(vfs_page_writeback_dirty_pages() == 0u);

    backend.results[3] = VFS_PAGE_WRITEBACK_ERR_IO;
    assert(vfs_page_writeback_mark_dirty(
               &first, &inode, 3u * 4096u, 3u,
               test_writeback, &backend) == 0);
    assert(vfs_page_writeback_run(1u) == 1u);
    assert(vfs_page_writeback_error(&first, &inode, 0) ==
           VFS_PAGE_WRITEBACK_ERR_IO);
    assert(vfs_page_writeback_sync_inode(&first, &inode) ==
           VFS_PAGE_WRITEBACK_ERR_IO);
    assert(vfs_page_writeback_error(&first, &inode, 0) == 0);

    backend.results[3] = VFS_PAGE_WRITEBACK_DISCARD;
    assert(vfs_page_writeback_run(1u) == 1u);
    assert(vfs_page_writeback_dirty_pages() == 0u);

    assert(vfs_page_writeback_mark_dirty(
               &second, &inode, 4u * 4096u, 4u,
               test_writeback, &backend) == 0);
    assert(vfs_page_writeback_sync_superblock(&first) == 0);
    assert(backend.calls[4] == 0u);
    vfs_page_writeback_forget_token(test_writeback, &backend, 4u);
    assert(vfs_page_writeback_dirty_pages() == 0u);

    assert(vfs_page_writeback_mark_dirty(
               &first, &inode, 5u * 4096u, 5u,
               test_writeback, &backend) == 0);
    vfs_page_writeback_forget_range(
        &first, &inode, 5u * 4096u, 4096u);
    assert(vfs_page_writeback_dirty_pages() == 0u);

    backend.discard_token = 6;
    assert(vfs_page_writeback_mark_dirty(
               &first, &inode, 6u * 4096u, 6u,
               test_writeback, &backend) == 0);
    assert(vfs_page_writeback_run(1u) == 1u);
    assert(vfs_page_writeback_dirty_pages() == 0u);

    vfs_page_writeback_runtime_reset();
    printf("VFS_PAGE_WRITEBACK_UNIT_PASS\n");
    return 0;
}
