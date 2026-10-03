/* SPDX-License-Identifier: MPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "kernel/task_stack.h"

static uint8_t *allocation;
static uint64_t allocated_pages;
static uint64_t released_pages;
static int fail_allocation;

void *arch_vm_alloc_mapped_pages(uint64_t pages) {
    if (fail_allocation) return 0;
    assert(!allocation);
    allocation = malloc(pages * EDGE_PAGE_SIZE);
    assert(allocation);
    allocated_pages = pages;
    released_pages = 0;
    return allocation;
}

void arch_vm_free_mapped_pages(void *address, uint64_t pages) {
    assert(allocation && address == allocation && pages == allocated_pages);
    released_pages += pages;
    free(allocation);
    allocation = 0;
}

int main(void) {
    const uint64_t bytes = 128u * 1024u;
    kernel_task_stack_cache_t cache = {0};
    assert(!kernel_task_stack_allocate(0));
    assert(!kernel_task_stack_allocate(EDGE_PAGE_SIZE - 1));
    fail_allocation = 1;
    assert(!kernel_task_stack_allocate(bytes));
    assert(!allocation);
    fail_allocation = 0;
    for (unsigned round = 0; round < 100; ++round) {
        uint8_t *stack = kernel_task_stack_allocate(bytes);
        uint64_t base = (uint64_t)(uintptr_t)stack;
        assert(stack && allocated_pages == 32);
        assert(kernel_task_stack_contains(stack, bytes, base));
        assert(kernel_task_stack_contains(stack, bytes, base + bytes - 1));
        assert(!kernel_task_stack_contains(stack, bytes, base - 1));
        assert(!kernel_task_stack_contains(stack, bytes, base + bytes));
        assert(!kernel_task_stack_contains(stack, bytes, UINT64_MAX));
        assert(!kernel_task_stack_contains(0, bytes, 0));
        stack[0] = 0x37;
        stack[bytes - 1] = 0xa5;
        kernel_task_stack_release(stack, bytes);
        assert(!allocation && released_pages == allocated_pages);
        kernel_task_stack_release(0, bytes);
    }
    {
        uint8_t *stack = kernel_task_stack_cache_allocate(&cache, bytes);
        assert(stack && cache.count == 0);
        kernel_task_stack_cache_release(&cache, stack, bytes);
        assert(cache.count == 1 && !released_pages);
        fail_allocation = 1;
        assert(kernel_task_stack_cache_allocate(&cache, bytes) == stack);
        assert(cache.count == 0);
        fail_allocation = 0;
        kernel_task_stack_release(stack, bytes);
        assert(!allocation && released_pages == allocated_pages);
    }
    puts("task_stack_lifetime_unit: PASS");
    return 0;
}
