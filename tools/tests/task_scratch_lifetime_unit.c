/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define STRING_H
#include "../../src/kernel/task_scratch.c"

static struct {
    uint8_t *base;
    uint64_t pages;
    uint64_t released;
} allocations[8];
static uint64_t live_pages;
static int fail_allocation;

void *arch_vm_alloc_pages(uint64_t pages) {
    if (fail_allocation) return 0;
    for (unsigned i = 0; i < 8; ++i) {
        if (allocations[i].base) continue;
        allocations[i].base = malloc(pages * EDGE_PAGE_SIZE);
        assert(allocations[i].base);
        memset(allocations[i].base, 0xa5, pages * EDGE_PAGE_SIZE);
        allocations[i].pages = pages;
        allocations[i].released = 0;
        live_pages += pages;
        return allocations[i].base;
    }
    abort();
}

void arch_vm_free_page(void *page) {
    for (unsigned i = 0; i < 8; ++i) {
        if (!allocations[i].base) continue;
        uintptr_t base = (uintptr_t)allocations[i].base;
        uintptr_t address = (uintptr_t)page;
        if (address < base || address >= base + allocations[i].pages * EDGE_PAGE_SIZE)
            continue;
        assert(address == base + allocations[i].released * EDGE_PAGE_SIZE);
        ++allocations[i].released;
        --live_pages;
        if (allocations[i].released == allocations[i].pages) {
            free(allocations[i].base);
            allocations[i].base = 0;
        }
        return;
    }
    abort();
}

void *arch_vm_alloc_mapped_pages(uint64_t pages) {
    return arch_vm_alloc_pages(pages);
}

void arch_vm_free_mapped_pages(void *memory, uint64_t pages) {
    if (!memory) return;
    for (uint64_t i = 0; i < pages; ++i)
        arch_vm_free_page((uint8_t *)memory + i * EDGE_PAGE_SIZE);
}

static void assert_zero(const void *memory, size_t bytes) {
    const uint8_t *data = memory;
    for (size_t i = 0; i < bytes; ++i) assert(data[i] == 0);
}

int main(void) {
    kernel_task_scratch_t *table[2];
    kernel_task_wait_scratch_t *wait_table[2];
    assert(kernel_task_scratch_pool_bytes(2) == sizeof(table));
    assert(kernel_task_wait_scratch_pool_bytes(2) == sizeof(wait_table));
    assert(kernel_task_scratch_pool_initialize(table, sizeof(table) - 1, 2) < 0);
    assert(kernel_task_scratch_pool_initialize(table, sizeof(table), 2) == 0);
    assert(kernel_task_wait_scratch_pool_initialize(wait_table, sizeof(wait_table), 2) == 0);
    assert(live_pages == 0);
    assert(!kernel_task_scratch_space(2));
    assert(!kernel_task_wait_scratch_space(2));
    fail_allocation = 1;
    assert(!kernel_task_scratch_space(0));
    assert(!kernel_task_wait_scratch_space(0));
    assert(live_pages == 0);
    fail_allocation = 0;
    for (unsigned round = 0; round < 100; ++round) {
        kernel_task_scratch_t *first = kernel_task_scratch_space(0);
        assert(first && kernel_task_scratch_space(0) == first);
        assert_zero(first, sizeof(*first));
        memset(first->path_scratch, 0x37, sizeof(first->path_scratch));
        kernel_task_scratch_t *second = kernel_task_scratch_space(1);
        assert(second && second != first);
        assert_zero(second, sizeof(*second));
        fail_allocation = 1;
        assert(!kernel_task_wait_scratch_space(0));
        fail_allocation = 0;
        kernel_task_wait_scratch_t *wait = kernel_task_wait_scratch_space(1);
        assert(wait && kernel_task_wait_scratch_space(1) == wait);
        assert_zero(wait, sizeof(*wait));
        kernel_task_scratch_release(0);
        kernel_task_scratch_release(0);
        assert(kernel_task_scratch_space(1) == second);
        kernel_task_scratch_release(1);
        kernel_task_scratch_release(2);
        assert(live_pages == 0);
    }
    puts("task_scratch_lifetime_unit: PASS");
    printf("scratch bytes per task: %zu; wait scratch bytes per task: %zu\n",
           sizeof(kernel_task_scratch_t), sizeof(kernel_task_wait_scratch_t));
    return 0;
}
