/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_TASK_STACK_H
#define EDGEOS_KERNEL_TASK_STACK_H

#include <stdint.h>
#include "mm/arch_vm.h"

#define KERNEL_TASK_STACK_CACHE_CAPACITY 32u

typedef struct kernel_task_stack_cache {
    volatile uint32_t lock;
    uint32_t count;
    void *stacks[KERNEL_TASK_STACK_CACHE_CAPACITY];
} kernel_task_stack_cache_t;

/* The caller owns the slot exclusively and does not hold a scheduler lock.
 * Release only after the scheduler has retired all contexts using the stack. */
static inline void *kernel_task_stack_allocate(uint64_t bytes) {
    if (!bytes || bytes % EDGE_PAGE_SIZE) return 0;
    return arch_vm_alloc_mapped_pages(bytes / EDGE_PAGE_SIZE);
}

static inline void kernel_task_stack_release(void *base, uint64_t bytes) {
    if (!base) return;
    arch_vm_free_mapped_pages(base, bytes / EDGE_PAGE_SIZE);
}

/*
 * Keep released stacks intact so short-lived process bursts do not fragment
 * the physical backing pool into runs smaller than a kernel stack.  The cache
 * is deliberately bounded: it preserves enough hot stacks for package hooks
 * and browser helpers while retaining predictable low-memory behavior.
 */
static inline void *kernel_task_stack_cache_allocate(
        kernel_task_stack_cache_t *cache, uint64_t bytes) {
    void *stack = 0;

    if (!cache) return kernel_task_stack_allocate(bytes);
    while (__atomic_exchange_n(&cache->lock, 1u, __ATOMIC_ACQUIRE)) {}
    if (cache->count) {
        --cache->count;
        stack = cache->stacks[cache->count];
        cache->stacks[cache->count] = 0;
    }
    __atomic_store_n(&cache->lock, 0u, __ATOMIC_RELEASE);
    return stack ? stack : kernel_task_stack_allocate(bytes);
}

static inline void kernel_task_stack_cache_release(
        kernel_task_stack_cache_t *cache, void *base, uint64_t bytes) {
    int retained = 0;

    if (!base) return;
    if (cache) {
        while (__atomic_exchange_n(&cache->lock, 1u, __ATOMIC_ACQUIRE)) {}
        if (cache->count < KERNEL_TASK_STACK_CACHE_CAPACITY) {
            cache->stacks[cache->count++] = base;
            retained = 1;
        }
        __atomic_store_n(&cache->lock, 0u, __ATOMIC_RELEASE);
    }
    if (!retained) kernel_task_stack_release(base, bytes);
}

static inline int kernel_task_stack_contains(const void *base, uint64_t bytes,
                                            uint64_t pointer) {
    uint64_t start = (uint64_t)(uintptr_t)base;
    return base && pointer >= start && pointer - start < bytes;
}

#endif
