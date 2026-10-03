/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define USER_PAGE_SIZE 4096u
static uint32_t g_user_mmap_backing_ready_pages = 8;
static uint32_t g_user_mmap_backing_alloc_hint;
static uint64_t g_user_mmap_backing_phys[8];
static uint8_t g_user_mmap_backing_used[8];
static uint16_t g_user_mmap_backing_refcnt[8];
static uint32_t generations[8];
static uint32_t *g_user_mmap_backing_generation = generations;
static uint32_t g_user_mmap_backing_generation_entries = 8;
static uint64_t g_user_mmap_backing_allocations;
static uint64_t g_user_mmap_backing_allocation_failures;
static int g_user_mmap_backing_lock;
static uint8_t memory[8 * USER_PAGE_SIZE];

static uint64_t spin_lock_irqsave(int *lock) { assert(!*lock); *lock = 1; return 0; }
static void spin_unlock_irqrestore(int *lock, uint64_t flags) {
    (void)flags; assert(*lock); *lock = 0;
}
static int bitmap_test_idx(uint8_t *bits, uint32_t count, uint32_t i) {
    assert(i < count); return bits[i];
}
static void bitmap_set_idx(uint8_t *bits, uint32_t count, uint32_t i) {
    assert(i < count); bits[i] = 1;
}
static int mmap_backing_phys_reserved(uint64_t physical) { (void)physical; return 0; }
static uint8_t *sparse_mmap_backing_ptr(int index) { return memory + index * USER_PAGE_SIZE; }

#include "contiguous_backing.inc"

int main(void) {
    for (unsigned i = 0; i < 8; ++i) g_user_mmap_backing_phys[i] = (i + 1) * USER_PAGE_SIZE;
    memset(g_user_mmap_backing_used, 1, sizeof(g_user_mmap_backing_used));
    memset(memory, 0x5a, sizeof(memory));
    for (unsigned i = 2; i < 6; ++i) g_user_mmap_backing_used[i] = 0;
    g_user_mmap_backing_alloc_hint = 4;
    assert(process_user_mmap_alloc_contiguous_backing_pages(4) == memory + 2 * USER_PAGE_SIZE);
    for (unsigned i = 2; i < 6; ++i) {
        assert(g_user_mmap_backing_used[i] && g_user_mmap_backing_refcnt[i] == 1);
        assert(generations[i] == 1 && memory[i * USER_PAGE_SIZE] == 0);
    }
    assert(memory[0] == 0x5a && memory[7 * USER_PAGE_SIZE] == 0x5a);
    assert(g_user_mmap_backing_allocations == 4);
    assert(!process_user_mmap_alloc_contiguous_backing_pages(1));
    assert(g_user_mmap_backing_allocation_failures == 1);
    memset(g_user_mmap_backing_used, 0, sizeof(g_user_mmap_backing_used));
    g_user_mmap_backing_phys[4] += USER_PAGE_SIZE;
    assert(!process_user_mmap_alloc_contiguous_backing_pages(8));
    assert(!g_user_mmap_backing_lock);
    puts("contiguous_backing_unit: PASS");
}
