/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side tests for the shared VFS sequential readahead state machine. */

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

static inline void spin_unlock_irqrestore(spinlock_t *lock,
                                          uint64_t flags) {
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

#include "../../src/vfs/readahead_state.c"

const void *vfs_superblock_identity(const vfs_superblock_t *sb) {
    return sb ? (const void *)sb : 0;
}

static vfs_inode_t test_inode(uint32_t number, uint32_t generation) {
    vfs_inode_t inode = {0};
    inode.ino = number;
    inode.generation = generation;
    inode.mode = VFS_INODE_FILE | 0644u;
    return inode;
}

int main(void) {
    vfs_readahead_allocator_t allocator = {
        test_allocate_pages,
        test_release_pages,
        0,
    };
    vfs_superblock_t first_superblock = {0};
    vfs_superblock_t second_superblock = {0};
    vfs_inode_t inode = test_inode(7u, 3u);
    vfs_inode_t reused = test_inode(7u, 4u);
    vfs_inode_t large_window = test_inode(8u, 1u);

    assert(vfs_readahead_runtime_set_allocator(&allocator) == 0);
    assert(vfs_readahead_plan(
               &first_superblock, &inode, 0u, 32u) == 16u);
    assert(vfs_readahead_plan(
               &first_superblock, &inode, 16u * 4096u, 32u) == 32u);
    assert(vfs_readahead_plan(
               &first_superblock, &inode, 48u * 4096u, 32u) == 32u);
    assert(vfs_readahead_plan(
               &first_superblock, &inode, 200u * 4096u, 32u) == 16u);
    assert(vfs_readahead_plan(
               &first_superblock, &inode, 216u * 4096u, 6u) == 6u);
    assert(vfs_readahead_plan(
               &first_superblock, &large_window, 0u, 64u) == 16u);
    assert(vfs_readahead_plan(
               &first_superblock, &large_window,
               16u * 4096u, 64u) == 32u);
    assert(vfs_readahead_plan(
               &first_superblock, &large_window,
               48u * 4096u, 64u) == 64u);
    assert(vfs_readahead_plan(
               &first_superblock, &large_window,
               256u * 4096u, 64u) == 16u);
    assert(vfs_readahead_plan(
               &first_superblock, &large_window,
               112u * 4096u, 64u) == 64u);
    assert(vfs_readahead_plan(
               &first_superblock, &large_window,
               272u * 4096u, 64u) == 32u);
    vfs_readahead_forget_inode(&first_superblock, &large_window);

    assert(vfs_readahead_plan(
               &first_superblock, &reused, 0u, 32u) == 16u);
    assert(vfs_readahead_plan(
               &second_superblock, &inode, 0u, 32u) == 16u);
    assert(vfs_readahead_state_count() == 3u);

    vfs_readahead_forget_inode(&first_superblock, &inode);
    assert(vfs_readahead_state_count() == 2u);
    assert(vfs_readahead_plan(
               &first_superblock, &inode, 216u * 4096u, 32u) == 16u);

    for (uint32_t index = 0; index < 200u; ++index) {
        vfs_inode_t candidate = test_inode(100u + index, 1u);
        assert(vfs_readahead_plan(
                   &first_superblock, &candidate, 0u, 32u) == 16u);
    }
    assert(vfs_readahead_state_count() == 203u);
    assert(vfs_readahead_reclaim(50u) == 50u);
    assert(vfs_readahead_state_count() == 153u);

    vfs_readahead_runtime_reset();
    assert(vfs_readahead_state_count() == 0u);
    printf("VFS_READAHEAD_STATE_UNIT_PASS\n");
    return 0;
}
